"""RFC 8785 (JSON Canonicalization Scheme) — full implementation.

This is the estate's provenance primitive: a deterministic byte serialisation so
that the same logical object always hashes and signs to the same value, on any
machine, in any language. It is a faithful port of the hardened implementation
that shipped in ``a2a-signed-receipts`` (UTF-16 key sort, ES6 number
serialisation, RFC 8785 string escaping incl. surrogate-pair handling).

Why this and not ``json.dumps(sort_keys=True, separators=(",", ":"))``?
For every real-world receipt in the estate (keys are ASCII identifiers, values
are strings / small numbers / bools / nested objects) the two are **byte
identical**, so signatures produced by the legacy consumers cross-verify against
this library. The only theoretical divergence is key ordering when a *key*
contains an astral-plane character (U+10000+): naive ``json.dumps`` sorts by
Unicode code point, RFC 8785 mandates UTF-16 code-unit order. This module
follows the RFC. No estate payload uses astral-plane keys, so in practice there
is no observable difference — the RFC is simply the more correct rule.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["canonicalize"]

_ESC_SHORT = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}

_EXP_RE = re.compile(r"^([0-9.-]+)[eE]([+-]?)([0-9]+)$")


def _utf16_units(s: str) -> list[int]:
    """Code units as ES6 UTF-16 sees them (astral chars -> surrogate pair).

    RFC 8785 §3.2.3 sorts object keys by their UTF-16 code units, not by Unicode
    code point. They differ only for astral-plane characters.
    """
    out: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            out.append(0xD800 + (cp >> 10))
            out.append(0xDC00 + (cp & 0x3FF))
        else:
            out.append(cp)
    return out


def _esc_str(s: str) -> str:
    """RFC 8785 string escaping.

    Short forms for ``\\b \\t \\n \\f \\r``, ``\\uXXXX`` for other C0 control
    characters, surrogate-pair escapes for astral characters — i.e. exactly
    ECMAScript ``JSON.stringify`` semantics, which the IETF JCS interop suite
    tests against.
    """
    out: list[str] = []
    for ch in s:
        if ch in _ESC_SHORT:
            out.append(_ESC_SHORT[ch])
            continue
        cp = ord(ch)
        if cp < 0x20:
            out.append("\\u%04x" % cp)
        elif cp > 0xFFFF:
            cp -= 0x10000
            out.append("\\u%04x\\u%04x" % (0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF)))
        else:
            out.append(ch)
    return "".join(out)


def _num(n: float | int) -> str:
    """ES6 ``Number.prototype.toString`` serialisation (RFC 8785 §3.2.2.3)."""
    if isinstance(n, bool):  # bool is a subclass of int — reject it as a number
        raise TypeError("bool is not a JSON number")
    if isinstance(n, int):
        if abs(n) > 2**53:
            raise ValueError(
                f"integer {n} exceeds the JCS safe-integer domain (|n| <= 2^53)"
            )
        return str(n)
    if n != n or n in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity are not valid JSON numbers")
    # ES6 shortest round-trip: no -0, exponent with sign and no leading zeros.
    if n == 0:
        return "0"  # also normalises -0.0
    s = repr(n)
    m = _EXP_RE.match(s)
    if m:
        mant, sign, exp = m.groups()
        return f"{mant}e{sign}{int(exp)}"
    return s


def canonicalize(obj: Any) -> bytes:
    """Serialise ``obj`` to its RFC 8785 canonical UTF-8 byte string.

    Accepts the JSON data model: ``dict`` (string keys), ``list``, ``str``,
    ``int``, ``float``, ``bool``, and ``None``. Raises ``TypeError`` for any
    other type (e.g. tuples, sets, bytes, custom objects) so that a non-JSON
    value can never be silently signed.
    """
    if obj is None:
        return b"null"
    if obj is True:
        return b"true"
    if obj is False:
        return b"false"
    if isinstance(obj, str):
        return b'"' + _esc_str(obj).encode("utf-8") + b'"'
    if isinstance(obj, (int, float)):
        return _num(obj).encode("ascii")
    if isinstance(obj, list):
        return b"[" + b",".join(canonicalize(v) for v in obj) + b"]"
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise TypeError(f"object keys must be strings, got {type(k).__name__}")
        items = sorted(obj.items(), key=lambda kv: _utf16_units(kv[0]))
        return (
            b"{"
            + b",".join(
                b'"' + _esc_str(k).encode("utf-8") + b'":' + canonicalize(v)
                for k, v in items
            )
            + b"}"
        )
    raise TypeError(f"cannot canonicalise {type(obj).__name__}")
