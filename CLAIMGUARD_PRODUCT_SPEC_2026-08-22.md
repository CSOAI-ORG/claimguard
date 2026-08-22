# ClaimGuard product spec — 2026-08-22

## Problem
Signed-evidence pipelines share a failure mode: post-hoc mutation of a signed
board, or marketing claims that the signed board does not support. We hit both
in one week (fake jail “separation resolved”; overstated guardrail deltas).

## Product
Deterministic auditor: signature → payload completeness → claim support.
One CLI / one MCP tool / one CI gate. Truthy only when all FAIL findings are empty.

## Demo that matters
Self-test signs a board, mutates `totals.axes` after sign, proves verify fails
and “16 measured axes” fails. The tool auditing its author.

## Surfaces
| Surface | Status |
|---|---|
| CLI `claimguard.py` | Landed this repo |
| CI gate | `.github/workflows/claimguard.yml` |
| MCP `claimguard.check` | Next |
| Council Ledger Integrity tile | Next |

## Non-goals
Not certification. Not remediation. Not a substitute for McNemar / bank publication.
