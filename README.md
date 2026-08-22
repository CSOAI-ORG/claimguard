# ClaimGuard

**The receipt for your claims.** Verifies a signed GSPC board's Ed25519 `site_attestation`, payload completeness, and whether natural-language claims are supported by the board.

Measurement, not certification. CSOAI Ltd (UK 16939677).

## Why it exists

Session failure mode: mutate a signed result after signing, or claim "16 measured axes" / "jail separation resolved" when the living board says otherwise. ClaimGuard fails those deterministically — including when we make them.

## Usage

```bash
pip install cryptography
python claimguard.py --self-test
python claimguard.py check --live
python claimguard.py check --live --claim "16 measured axes"
```

Exit `0` = PASS, `1` = FAIL.

Living board: https://councilof.ai/api/gspc

MIT © CSOAI Ltd
