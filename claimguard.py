#!/usr/bin/env python3
"""ClaimGuard — claim-vs-signed-artifact integrity checker.

Verifies a GSPC board's site_attestation (Ed25519 over RFC 8785 canonical
JSON), payload completeness, and whether natural-language claims are supported
by the signed board. Measurement, not certification.

Usage:
  python claimguard.py check --board board.json --claim "16 measured axes"
  python claimguard.py check --live --claim "jail separation resolved"
  python claimguard.py check --live
  python claimguard.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from canonical import canonicalize

BOARD_DID_KEY = "did:web:csoai.org#board-attestation-1"
DID_URL = "https://csoai.org/.well-known/did.json"
LIVE_BOARD_URL = "https://councilof.ai/api/gspc"
UA = "CSOAI-ClaimGuard/1.0"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


@dataclass
class Finding:
    status: Status
    code: str
    message: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    board_axes: int | None = None
    measured_axes: int | None = None
    public_count: str | None = None

    @property
    def ok(self) -> bool:
        return not any(f.status == Status.FAIL for f in self.findings)

    def add(self, status: Status, code: str, message: str) -> None:
        self.findings.append(Finding(status, code, message))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "board_axes": self.board_axes,
            "measured_axes": self.measured_axes,
            "public_count": self.public_count,
            "findings": [
                {"status": f.status.value, "code": f.code, "message": f.message}
                for f in self.findings
            ],
        }


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def fetch_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except Exception:
        # Some sandboxes block urllib; curl often still works.
        out = subprocess.check_output(
            ["curl", "-sS", "-A", UA, url], timeout=30
        )
        return json.loads(out.decode())


def load_board(path: str | None = None, *, live: bool = False) -> dict[str, Any]:
    if live or path in (None, "-", "live"):
        return fetch_json(LIVE_BOARD_URL)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def resolve_board_pubkey(board: dict[str, Any], *, offline_x: str | None = None) -> bytes:
    att = board.get("site_attestation") or {}
    x = offline_x or att.get("public_key_x")
    if not x:
        raise ValueError("no public_key_x on site_attestation and no offline key")
    return _b64url_decode(x)


def verify_site_attestation(
    board: dict[str, Any], *, pubkey: bytes | None = None
) -> Finding:
    att = board.get("site_attestation")
    if not isinstance(att, dict):
        return Finding(Status.FAIL, "attestation.missing", "site_attestation absent")
    if att.get("error"):
        return Finding(
            Status.FAIL, "attestation.error", f"site_attestation error: {att['error']}"
        )
    sig_hex = att.get("sig")
    if not sig_hex:
        return Finding(Status.FAIL, "attestation.no_sig", "site_attestation.sig missing")
    payload = {k: v for k, v in board.items() if k != "site_attestation"}
    body = canonicalize(payload)
    try:
        pk = Ed25519PublicKey.from_public_bytes(pubkey or resolve_board_pubkey(board))
        pk.verify(bytes.fromhex(sig_hex), body)
    except Exception as e:
        return Finding(
            Status.FAIL,
            "attestation.invalid",
            f"Ed25519 verify failed over RFC8785 canonical payload: {e}",
        )
    return Finding(
        Status.PASS,
        "attestation.valid",
        f"site_attestation verified ({att.get('signer', BOARD_DID_KEY)})",
    )


def check_payload_complete(board: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    totals = board.get("totals") or {}
    axes = board.get("axes")
    if not isinstance(axes, list) or not axes:
        out.append(Finding(Status.FAIL, "payload.axes_empty", "axes[] empty or missing"))
    else:
        out.append(
            Finding(Status.PASS, "payload.axes_present", f"axes[] has {len(axes)} rows")
        )
    if not totals:
        out.append(Finding(Status.FAIL, "payload.totals_missing", "totals missing"))
    else:
        for key in ("axes", "measured_axes", "quotable_axes", "public_count"):
            if key not in totals:
                out.append(
                    Finding(Status.FAIL, f"payload.totals.{key}", f"totals.{key} missing")
                )
        if totals.get("axes") == 0:
            out.append(Finding(Status.FAIL, "payload.axes_zero", "totals.axes is 0"))
        # Empty-result / mutated-result guard (the session failure mode)
        for ax in axes or []:
            if not isinstance(ax, dict):
                continue
            if ax.get("status") == "MEASURED" and ax.get("accuracy") is None and ax.get("n") is None:
                out.append(
                    Finding(
                        Status.FAIL,
                        "payload.measured_empty",
                        f"axis {ax.get('axis')} MEASURED but has no accuracy/n",
                    )
                )
    if "site_attestation" not in board:
        out.append(
            Finding(Status.FAIL, "payload.no_attestation_field", "site_attestation field missing")
        )
    return out


# Claims that must not be made against the living board without support.
CLAIM_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\b16\s+(measured\s+)?axes?\b", re.I),
        "claim.sixteen_axes",
        "Board is 14 quotable slots (+2 in-lane honesty-only). Never claim 16 measured axes.",
    ),
    (
        re.compile(r"\b15\s+(measured\s+)?axes?\b", re.I),
        "claim.fifteen_axes",
        "Public ruling is 13 measured of 14 quotable — not 15 axes.",
    ),
    (
        re.compile(r"\b(elo|éelo)\s+league\b|\bpublic\s+elo\b|\belo\s+ranking\b", re.I),
        "claim.elo_league",
        "GSPC public ranking is Wilson+McNemar, not Elo. Elo league is not on /api/gspc.",
    ),
    (
        re.compile(r"jail.{0,40}separat(ion|ed).{0,20}(resolved|pass|done)", re.I),
        "claim.jail_separation",
        "jail separation is UNTESTED on the living board until McNemar runs.",
    ),
    (
        re.compile(r"\bcertif(y|ied|ication)\b", re.I),
        "claim.certification",
        "Measurement, not certification — certification language is unsupported.",
    ),
]


def check_claims(board: dict[str, Any], claims: list[str]) -> list[Finding]:
    out: list[Finding] = []
    totals = board.get("totals") or {}
    axes_by_id = {
        a.get("axis"): a for a in (board.get("axes") or []) if isinstance(a, dict)
    }
    for claim in claims:
        text = claim.strip()
        if not text:
            continue
        matched = False
        for pat, code, msg in CLAIM_RULES:
            if pat.search(text):
                matched = True
                # jail separation special-case: only FAIL if board says UNTESTED
                if code == "claim.jail_separation":
                    jail = axes_by_id.get("jail") or {}
                    if jail.get("separation") == "UNTESTED":
                        out.append(Finding(Status.FAIL, code, f"{msg} Claim: {text!r}"))
                    else:
                        out.append(
                            Finding(
                                Status.WARN,
                                code,
                                f"jail separation is {jail.get('separation')}; still review claim: {text!r}",
                            )
                        )
                else:
                    out.append(Finding(Status.FAIL, code, f"{msg} Claim: {text!r}"))
        # numeric axis count must match totals
        m = re.search(r"\b(\d+)\s+quotable\s+axes?\b", text, re.I)
        if m and totals.get("quotable_axes") is not None:
            matched = True
            n = int(m.group(1))
            if n != int(totals["quotable_axes"]):
                out.append(
                    Finding(
                        Status.FAIL,
                        "claim.quotable_mismatch",
                        f"Claimed {n} quotable axes; board totals.quotable_axes={totals['quotable_axes']}",
                    )
                )
            else:
                out.append(
                    Finding(Status.PASS, "claim.quotable_match", f"quotable axes claim matches ({n})")
                )
        if not matched:
            out.append(
                Finding(
                    Status.WARN,
                    "claim.unchecked",
                    f"No rule matched; human review: {text!r}",
                )
            )
    return out


def audit(
    board: dict[str, Any],
    claims: list[str] | None = None,
    *,
    skip_sig: bool = False,
) -> Report:
    report = Report()
    totals = board.get("totals") or {}
    report.board_axes = totals.get("axes")
    report.measured_axes = totals.get("measured_axes")
    report.public_count = totals.get("public_count")

    if not skip_sig:
        report.findings.append(verify_site_attestation(board))
    else:
        report.add(Status.WARN, "attestation.skipped", "signature check skipped")

    report.findings.extend(check_payload_complete(board))
    if claims:
        report.findings.extend(check_claims(board, claims))
    return report


def _self_test() -> int:
    """Prove mutation breaks the signature — the product demo."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    board = {
        "schema": "csoai.gspc-axes/0.5",
        "totals": {
            "axes": 14,
            "measured_axes": 13,
            "quotable_axes": 14,
            "public_count": "13 measured of 14 quotable",
        },
        "axes": [
            {"axis": "governance", "status": "MEASURED", "accuracy": 0.7, "n": 10},
            {"axis": "jail", "status": "MEASURED", "separation": "UNTESTED", "n": 71},
        ],
    }
    sig = key.sign(canonicalize(board)).hex()
    x = base64.urlsafe_b64encode(pub).decode().rstrip("=")
    signed = dict(board)
    signed["site_attestation"] = {
        "signer": BOARD_DID_KEY,
        "alg": "Ed25519",
        "sig": sig,
        "public_key_x": x,
    }
    r1 = audit(signed, claims=["14 quotable axes"])
    assert r1.ok, r1.to_dict()

    # Post-hoc mutation (session failure mode)
    mutated = json.loads(json.dumps(signed))
    mutated["totals"]["axes"] = 16
    r2 = audit(mutated, claims=["16 measured axes"])
    assert not r2.ok, "mutation must fail"
    codes = {f.code for f in r2.findings if f.status == Status.FAIL}
    assert "attestation.invalid" in codes
    assert "claim.sixteen_axes" in codes

    # Jail separation overclaim
    r3 = audit(signed, claims=["jail separation resolved"])
    assert any(f.code == "claim.jail_separation" and f.status == Status.FAIL for f in r3.findings)

    print("SELF-TEST PASS — signature holds; mutation + overclaims FAIL as required")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="claimguard")
    p.add_argument("--self-test", action="store_true")
    sub = p.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="Audit a board (+ optional claims)")
    c.add_argument("--board", help="Path to board JSON")
    c.add_argument("--live", action="store_true", help="Fetch https://councilof.ai/api/gspc")
    c.add_argument("--claim", action="append", default=[], help="Claim text (repeatable)")
    c.add_argument("--claims-file", help="File with one claim per line")
    c.add_argument("--json", action="store_true", help="Emit JSON report")
    c.add_argument("--skip-sig", action="store_true")
    args = p.parse_args(argv)

    if args.self_test or args.cmd is None and getattr(args, "self_test", False):
        if args.self_test:
            return _self_test()

    if args.cmd != "check":
        p.print_help()
        return 2

    board = load_board(args.board, live=args.live or not args.board)
    claims = list(args.claim)
    if args.claims_file:
        with open(args.claims_file, encoding="utf-8") as f:
            claims.extend(line.strip() for line in f if line.strip())
    report = audit(board, claims, skip_sig=args.skip_sig)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(
            f"ClaimGuard {'PASS' if report.ok else 'FAIL'} · "
            f"axes={report.board_axes} measured={report.measured_axes} · "
            f"{report.public_count}"
        )
        for f in report.findings:
            print(f"  [{f.status.value}] {f.code}: {f.message}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
