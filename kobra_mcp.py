#!/usr/bin/env python3
"""
KOBRA MCP server — exposes KOBRA suite as MCP tools over stdio.
Lets an MCP client (Claude Desktop, Hermes, Cursor, etc.) drive the scanner.

Setup:
  pip install mcp
  python3 kobra_mcp.py
Then point your MCP client at this script.
"""
import subprocess
import json
import os
from mcp.server import Server
import mcp.types as types

APP = os.path.dirname(os.path.abspath(__file__))
# Prefer the installed binary in PATH; fall back to local build.
import shutil
_KOBRA_BIN = shutil.which("kobra") or os.path.join(APP, "kobra")
KOBRA = _KOBRA_BIN
ORCH = os.path.join(APP, "kobra-orchestrator.py")
CHAIN = os.path.join(APP, "chain.py")
API = os.path.join(APP, "api_breaker.py")
CLOUD = os.path.join(APP, "cloud_breaker.py")
CTF = os.path.join(APP, "ctf_solver.py")


def _run(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return f"[error] {e}"


server = Server("kobra-mcp")


@server.list_tools()
async def list_tools():
    return [
        types.Tool(
            name="scan_target",
            description="Run KOBRA scanner on a target. mode: stealth|normal|crazy. crazy = full-disclosure aggressive.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL or domain"},
                    "mode": {"type": "string", "enum": ["stealth", "normal", "crazy"], "default": "crazy"},
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="run_orchestrator",
            description="Full pipeline: recon (subfinder/naabu/gau/subjs) -> KOBRA -> nuclei -> ffuf -> dalfox -> report.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "mode": {"type": "string", "enum": ["stealth", "normal", "crazy"], "default": "crazy"},
                    "out": {"type": "string", "default": "engagement"},
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="chain_report",
            description="Compose attack chains from a report.json (XSS->ATO, SSRF->cloud, etc).",
            inputSchema={
                "type": "object",
                "properties": {"report": {"type": "string", "description": "path to report.json"}},
                "required": ["report"],
            },
        ),
        types.Tool(
            name="api_break",
            description="Break REST/GraphQL API: IDOR, mass-assign, JWT, auth bypass.",
            inputSchema={
                "type": "object",
                "properties": {
                    "base": {"type": "string"},
                    "endpoints": {"type": "string", "description": "comma-sep paths e.g. /user/1,/order/5"},
                },
                "required": ["base"],
            },
        ),
        types.Tool(
            name="cloud_enum",
            description="Enumerate cloud misconfig (AWS/Azure/GCP metadata endpoints).",
            inputSchema={
                "type": "object",
                "properties": {
                    "provider": {"type": "string", "enum": ["aws", "azure", "gcp", "all"]},
                    "host": {"type": "string"},
                },
                "required": ["provider"],
            },
        ),
        types.Tool(
            name="ctf_payloads",
            description="Generate CTF payloads for a challenge type.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ctype": {"type": "string", "enum": ["sqli", "xss", "ssti", "traversal", "jwt", "protopoll", "cmdi", "deser"]},
                },
                "required": ["ctype"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name, arguments):
    if name == "scan_target":
        t = arguments["target"]
        m = arguments.get("mode", "crazy")
        out = _run(f"{KOBRA} -t '{t}' -m {m} -j -o {APP}/mcp_scan.json", timeout=300)
        return [types.TextContent(type="text", text=out[-4000:])]
    if name == "run_orchestrator":
        t = arguments["target"]
        m = arguments.get("mode", "crazy")
        out = _run(f"python3 {ORCH} --target '{t}' --out {arguments.get('out','engagement')} -m {m}", timeout=400)
        return [types.TextContent(type="text", text=out[-4000:])]
    if name == "chain_report":
        rep = arguments["report"]
        out = _run(f"python3 {CHAIN} --report {rep} --out {rep}.chains.md", timeout=60)
        return [types.TextContent(type="text", text=out)]
    if name == "api_break":
        base = arguments["base"]
        eps = arguments.get("endpoints", "/user/1")
        out = _run(f"python3 {API} --base {base} --endpoints {eps} --out {APP}/mcp_api.jsonl", timeout=120)
        return [types.TextContent(type="text", text=out)]
    if name == "cloud_enum":
        prov = arguments["provider"]
        host = arguments.get("host", "")
        out = _run(f"python3 {CLOUD} --provider {prov} --host '{host}' --out {APP}/mcp_cloud.jsonl", timeout=60)
        return [types.TextContent(type="text", text=out)]
    if name == "ctf_payloads":
        ctype = arguments["ctype"]
        out = _run(f"python3 {CTF} --type {ctype}", timeout=30)
        return [types.TextContent(type="text", text=out)]
    return [types.TextContent(type="text", text="[unknown tool]")]


if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server
    async def _main():
        async with stdio_server() as (r, w):
            await server.run(r, w, server.create_initialization_options())
    asyncio.run(_main())
