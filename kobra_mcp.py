#!/usr/bin/env python3
"""
KOBRA v4.4.0 MCP server — exposes FULL KOBRA suite as MCP tools over stdio.
Supports ALL v4.4.0 features: 5 lessons from real-world CF filter + AI gateway + DNS pivot + auth flow + origin probe + v4.3.0 auth-aware + stack-specific payloads + v4.2.0 SPA fallback + v4.1.0 suites (nuclei compat, IDOR, tech fingerprint, SARIF,
screenshots, passive proxy, wordlist fuzzing, diff scan, cross-target chain, watch mode.

Setup:
  pip install mcp
  python3 kobra_mcp.py
Then point your MCP client at this script.
"""
import subprocess
import json
import os
import shutil
from mcp.server import Server
import mcp.types as types

APP = os.path.dirname(os.path.abspath(__file__))
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


def _build_scan_cmd(args):
    """Build KOBRA CLI command from MCP tool arguments."""
    t = args["target"]
    m = args.get("mode", "crazy")
    cmd = f"{KOBRA} -t '{t}' -m {m} --no-confirm -j"

    # Output options
    out_file = args.get("output", f"{APP}/mcp_scan.json")
    cmd += f" -o {out_file}"
    if args.get("html"):
        cmd += f" --html {args['html']}"
    if args.get("md"):
        cmd += f" --md {args['md']}"
    if args.get("sarif"):
        cmd += f" --sarif {args['sarif']}"
    if args.get("poc_dir"):
        cmd += f" --poc-dir {args['poc_dir']}"

    # Auth options
    if args.get("cookie"):
        cmd += f" --cookie '{args['cookie']}'"
    if args.get("header"):
        cmd += f" --header '{args['header']}'"
    if args.get("auth"):
        cmd += f" --auth '{args['auth']}'"
    if args.get("auth2"):
        cmd += f" --auth2 '{args['auth2']}'"

    # Template/plugin options
    if args.get("template_dir"):
        cmd += f" --template-dir {args['template_dir']}"
    if args.get("nuclei_dir"):
        cmd += f" --nuclei-dir {args['nuclei_dir']}"
    if args.get("plugin_dir"):
        cmd += f" --plugin-dir {args['plugin_dir']}"
    if args.get("wordlist"):
        cmd += f" --wordlist {args['wordlist']}"

    # Browser options
    if args.get("browser"):
        cmd += " --browser"
    if args.get("screenshot_dir"):
        cmd += f" --screenshot-dir {args['screenshot_dir']}"

    # Diff options
    if args.get("diff_baseline"):
        cmd += f" --diff-baseline {args['diff_baseline']}"

    # Webhook options
    if args.get("slack_webhook"):
        cmd += f" --slack-webhook '{args['slack_webhook']}'"
    if args.get("discord_webhook"):
        cmd += f" --discord-webhook '{args['discord_webhook']}'"
    if args.get("webhook"):
        cmd += f" --webhook '{args['webhook']}'"

    # Misc
    if args.get("engagement"):
        cmd += f" --engagement '{args['engagement']}'"
    if args.get("timeout"):
        cmd += f" --timeout {args['timeout']}"
    if args.get("concurrency"):
        cmd += f" -c {args['concurrency']}"
    if args.get("recon"):
        cmd += " -R"
    if args.get("simple"):
        cmd += " --simple"
    if args.get("triage"):
        cmd += " --triage"

    return cmd


server = Server("kobra-mcp")


@server.list_tools()
async def list_tools():
    return [
        types.Tool(
            name="scan_target",
            description="Run KOBRA v3.3 scanner on target(s). Supports ALL features: auth, IDOR, nuclei templates, wordlist, browser, screenshots, SARIF, diff, webhooks. mode: stealth|normal|crazy.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL(s), comma-separated for multi-target"},
                    "mode": {"type": "string", "enum": ["stealth", "normal", "crazy"], "default": "crazy"},
                    "output": {"type": "string", "description": "JSON output file path"},
                    "html": {"type": "string", "description": "HTML dashboard output path"},
                    "md": {"type": "string", "description": "Markdown report output path"},
                    "sarif": {"type": "string", "description": "SARIF report output path (GitHub Security)"},
                    "poc_dir": {"type": "string", "description": "PoC scripts output directory"},
                    "cookie": {"type": "string", "description": "Cookie string for authenticated scan"},
                    "header": {"type": "string", "description": "Custom headers: 'Key: Val, Key2: Val2'"},
                    "auth": {"type": "string", "description": "Auto-login: 'url|body'"},
                    "auth2": {"type": "string", "description": "Second auth for IDOR: 'url|body'"},
                    "template_dir": {"type": "string", "description": "KOBRA template directory"},
                    "nuclei_dir": {"type": "string", "description": "Nuclei YAML templates directory"},
                    "plugin_dir": {"type": "string", "description": "JSON plugin directory"},
                    "wordlist": {"type": "string", "description": "Custom wordlist file for fuzzing"},
                    "browser": {"type": "boolean", "description": "Enable headless browser scan"},
                    "screenshot_dir": {"type": "string", "description": "Screenshot evidence directory"},
                    "diff_baseline": {"type": "string", "description": "Previous scan JSON for diff comparison"},
                    "slack_webhook": {"type": "string", "description": "Slack webhook URL"},
                    "discord_webhook": {"type": "string", "description": "Discord webhook URL"},
                    "webhook": {"type": "string", "description": "Generic webhook URL"},
                    "engagement": {"type": "string", "description": "Engagement name"},
                    "timeout": {"type": "integer", "description": "Request timeout seconds"},
                    "concurrency": {"type": "integer", "description": "Concurrency level"},
                    "recon": {"type": "boolean", "description": "Run recon first"},
                    "simple": {"type": "boolean", "description": "Bahasa Indonesia simple output"},
                    "triage": {"type": "boolean", "description": "AI Triage: auto-validate FP, suggest fixes"},
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="idor_scan",
            description="Multi-session IDOR scan. Login as 2 users, compare responses across 24+ endpoints. Requires auth + auth2.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL"},
                    "auth": {"type": "string", "description": "User A login: 'url|body'"},
                    "auth2": {"type": "string", "description": "User B login: 'url|body'"},
                    "mode": {"type": "string", "enum": ["stealth", "normal", "crazy"], "default": "crazy"},
                },
                "required": ["target", "auth", "auth2"],
            },
        ),
        types.Tool(
            name="diff_scan",
            description="Scan and compare against a previous baseline. Highlights NEW and RESOLVED findings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "baseline": {"type": "string", "description": "Path to previous scan JSON"},
                    "mode": {"type": "string", "enum": ["stealth", "normal", "crazy"], "default": "crazy"},
                    "output": {"type": "string", "description": "Save current results to this JSON"},
                },
                "required": ["target", "baseline"],
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
        cmd = _build_scan_cmd(arguments)
        out = _run(cmd, timeout=600)
        return [types.TextContent(type="text", text=out[-6000:])]

    if name == "idor_scan":
        t = arguments["target"]
        m = arguments.get("mode", "crazy")
        auth = arguments["auth"]
        auth2 = arguments["auth2"]
        out_file = f"{APP}/mcp_idor.json"
        cmd = f"{KOBRA} -t '{t}' -m {m} --no-confirm -j -o {out_file} --auth '{auth}' --auth2 '{auth2}'"
        out = _run(cmd, timeout=600)
        return [types.TextContent(type="text", text=out[-6000:])]

    if name == "diff_scan":
        t = arguments["target"]
        m = arguments.get("mode", "crazy")
        baseline = arguments["baseline"]
        out_file = arguments.get("output", f"{APP}/mcp_diff_current.json")
        cmd = f"{KOBRA} -t '{t}' -m {m} --no-confirm -j -o {out_file} --diff-baseline {baseline}"
        out = _run(cmd, timeout=600)
        return [types.TextContent(type="text", text=out[-6000:])]

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
