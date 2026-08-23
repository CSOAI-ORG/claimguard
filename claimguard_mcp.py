#!/usr/bin/env python3
"""claimguard_mcp.py — ClaimGuard as an MCP server (agent-native distribution).

Exposes the claim-vs-signed-artifact checker over MCP so any agent can
audit a claim against a signed measurement board without a CLI.

    python3 claimguard_mcp.py                 # stdio MCP server
    python3 claimguard_mcp.py --self-test     # prove tools/list + call work

Protocol (minimal, tool-list + call, JSON-RPC 2.0 over stdio):
    {"jsonrpc":"2.0","id":1,"method":"tools/list"}
    {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check","arguments":{"board":...,"claim":...}}}
"""
from __future__ import annotations
import json, sys
from claimguard import main as claimguard_main  # reuse the linter

TOOLS = [
    {
        "name": "check",
        "description": "Verify a signed measurement board against a public claim. "
                       "Checks signature validity (Ed25519 over RFC-8785 canonical JSON), "
                       "payload completeness, and whether the claim is supported. "
                       "Deterministic — never a model opinion. Measurement, not certification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "board": {"type": "string", "description": "Path or URL to the signed board JSON (or 'LIVE' for /api/gspc)"},
                "claim": {"type": "string", "description": "The natural-language claim to audit"},
            },
            "required": ["board"],
        },
    },
]


def handle(req: dict) -> dict:
    m = req.get("method")
    if m == "tools/list":
        return {"jsonrpc": "2.0", "id": req.get("id"), "result": {"tools": TOOLS}}
    if m == "tools/call":
        name = (req.get("params") or {}).get("name")
        if name != "check":
            return {"jsonrpc": "2.0", "id": req.get("id"),
                    "error": {"code": -32601, "message": f"unknown tool: {name}"}}
        args = (req.get("params") or {}).get("arguments") or {}
        board = str(args.get("board", "LIVE"))
        claim = str(args.get("claim", ""))
        # run the checker; capture output
        import io, contextlib
        buf = io.StringIO()
        argv = ["check"]  # argparse expects subcommand first (sys.argv[1:])
        if board.lower() in ("live", "LIVE", "--live"):
            argv += ["--live"]
        elif board and board not in ("board.json", ""):
            argv += ["--board", board]
        if claim:
            argv += ["--claim", claim]
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                claimguard_main(argv)
                ok = True
            except SystemExit as e:
                ok = (e.code == 0)
            except Exception as e:
                buf.write(f"\nERROR: {e}\n")
                ok = False
        return {"jsonrpc": "2.0", "id": req.get("id"),
                "result": {"content": [{"type": "text", "text": buf.getvalue()}],
                           "isError": not ok}}
    return {"jsonrpc": "2.0", "id": req.get("id"),
            "error": {"code": -32601, "message": f"method not found: {m}"}}


def _self_test() -> int:
    # tools/list
    r = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert "check" in str(r), "tools/list failed"
    # tools/call check (LIVE, no claim -> deterministic check runs)
    r2 = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "check", "arguments": {"board": "LIVE", "claim": ""}}})
    ok_call = isinstance(r2.get("result", {}).get("content"), list) and len(r2["result"]["content"]) > 0
    print("MCP tools/list:", "OK")
    print("MCP tools/call check:", "OK" if ok_call else "FAIL")
    print("MCP SELF-TEST:", "PASS" if ok_call else "FAIL")
    return 0 if ok_call else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    # stdio loop
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        print(json.dumps(handle(req)), flush=True)
