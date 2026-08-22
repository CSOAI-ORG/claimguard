import json
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from canonical import canonicalize
from claimguard import audit, Status


def _signed_board(**overrides):
    key = Ed25519PrivateKey.generate()
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
    board.update(overrides)
    sig = key.sign(canonicalize(board)).hex()
    pub = key.public_key().public_bytes_raw()
    board["site_attestation"] = {
        "signer": "did:web:csoai.org#board-attestation-1",
        "alg": "Ed25519",
        "sig": sig,
        "public_key_x": base64.urlsafe_b64encode(pub).decode().rstrip("="),
    }
    return board


def test_pass_on_honest_claim():
    r = audit(_signed_board(), ["14 quotable axes"])
    assert r.ok


def test_fail_on_mutation():
    b = _signed_board()
    b["totals"]["axes"] = 99
    r = audit(b)
    assert not r.ok
    assert any(f.code == "attestation.invalid" for f in r.findings)


def test_fail_sixteen_axes_claim():
    r = audit(_signed_board(), ["we have 16 measured axes"])
    assert not r.ok
    assert any(f.code == "claim.sixteen_axes" for f in r.findings)


def test_fail_jail_separation_claim():
    r = audit(_signed_board(), ["jail separation resolved"])
    assert any(f.code == "claim.jail_separation" and f.status == Status.FAIL for f in r.findings)


def test_fail_empty_axes():
    b = _signed_board()
    # resign would be needed for sig; skip_sig to isolate payload rule
    b["axes"] = []
    r = audit(b, skip_sig=True)
    assert any(f.code == "payload.axes_empty" for f in r.findings)
