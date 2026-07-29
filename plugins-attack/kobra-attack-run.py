#!/usr/bin/env python3
"""
KOBRA Attack Layer Runner
Loads plugins from ~/.local/share/kobra/plugins/exploit/*.json
Executes them against target. Pure stdlib, no install needed.

Usage: python3 kobra-attack-run.py <target-url> [plugin-name]
"""

import json
import os
import subprocess
import sys
import time
import hashlib
from pathlib import Path

PLUGIN_DIR = Path.home() / ".local/share/kobra/plugins/exploit"
OUTPUT_BASE = Path("/tmp/kobra-attack")


def load_plugins(filter_name=None):
    plugins = []
    if not PLUGIN_DIR.exists():
        return plugins
    for f in sorted(PLUGIN_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            if filter_name and not f.stem.startswith(filter_name):
                continue
            data["_file"] = str(f)
            plugins.append(data)
        except json.JSONDecodeError as e:
            print(f"  [parse-fail] {f}: {e}", file=sys.stderr)
    return plugins


def substitute(text, target, engagement, output_dir):
    return (text
            .replace("{target}", target)
            .replace("{engagement_id}", engagement)
            .replace("{output_dir}", str(output_dir)))


def run_plugin(plugin, target, engagement_id, output_base):
    name = plugin.get("name", plugin.get("_file", "unknown"))
    print(f"\n[PLUGIN] {name}")
    
    config = plugin.get("config", {})
    binary = config.get("binary", "echo")
    args = config.get("args", [])
    timeout = config.get("timeout_secs", 300)
    
    plugin_output_dir = output_base / name
    plugin_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Substitute template vars in each arg
    rendered = [substitute(str(a), target, engagement_id, plugin_output_dir) for a in args]
    
    print(f"  binary:   {binary}")
    print(f"  args:     {len(rendered)} parameters")
    print(f"  timeout:  {timeout}s")
    print(f"  output:   {plugin_output_dir}")
    
    cmd = [binary] + rendered
    stdout_log = plugin_output_dir / "stdout.log"
    stderr_log = plugin_output_dir / "stderr.log"
    
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        result = subprocess.run(
            cmd,
            cwd=str(plugin_output_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout_log.write_text(result.stdout)
        stderr_log.write_text(result.stderr)
        exit_code = result.returncode
        success = exit_code == 0
        status = "OK" if success else f"exit {exit_code}"
    except subprocess.TimeoutExpired:
        stderr_log.write_text(f"Timeout after {timeout}s")
        status = "TIMEOUT"
        exit_code = -1
        success = False
    except FileNotFoundError:
        stderr_log.write_text(f"Binary not found: {binary}")
        status = f"binary-missing:{binary}"
        exit_code = -1
        success = False
    
    print(f"  status:   {status}")
    if success:
        print(f"  artifact: {stdout_log} ({stdout_log.stat().st_size if stdout_log.exists() else 0} bytes)")
    
    # Evidence entry
    evidence = {
        "name": name,
        "target": target,
        "engagement_id": engagement_id,
        "timestamp": started_at,
        "binary": binary,
        "args_count": len(rendered),
        "exit_code": exit_code,
        "success": success,
        "status": status,
        "output_dir": str(plugin_output_dir),
        "stdout_size": stdout_log.stat().st_size if stdout_log.exists() else 0,
        "stderr_size": stderr_log.stat().st_size if stderr_log.exists() else 0,
    }
    
    # Hash chain
    evidence_path = output_base / "evidence.jsonl"
    prev_hash = ""
    if evidence_path.exists():
        for line in evidence_path.read_text().splitlines()[-1:]:
            try:
                prev = json.loads(line)
                prev_hash = hashlib.sha256((prev.get("hash_chain", "") + json.dumps(prev)).encode()).hexdigest()[:16]
            except json.JSONDecodeError:
                pass
    evidence["hash_chain"] = prev_hash
    evidence["hash_self"] = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()[:16]
    
    with evidence_path.open("a") as f:
        f.write(json.dumps(evidence) + "\n")
    
    return success


def main():
    if len(sys.argv) < 2:
        # Help mode
        print("KOBRA Attack Layer v4.4.1")
        print(f"Usage: {sys.argv[0]} <target-url> [plugin-name]")
        print(f"Plugin dir: {PLUGIN_DIR}")
        print(f"\nAvailable plugins:")
        for p in load_plugins():
            print(f"  - {p.get('name', '?')}")
            print(f"    {p.get('description', 'no desc')[:80]}")
            print(f"    category: {p.get('category', '?')}")
        print(f"\nOptional deps: sqlmap, nuclei, ffuf, interactsh")
        sys.exit(0 if PLUGIN_DIR.exists() else 1)
    
    target = sys.argv[1]
    plugin_filter = sys.argv[2] if len(sys.argv) > 2 else None
    
    engagement_id = time.strftime("%Y%m%d-%H%M%S") + "-" + hashlib.md5(target.encode()).hexdigest()[:8]
    output_dir = OUTPUT_BASE / engagement_id
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 60)
    print("KOBRA Attack Layer v4.4.1")
    print(f"Target:      {target}")
    print(f"Engagement:  {engagement_id}")
    print(f"Output:      {output_dir}")
    print(f"Filter:      {plugin_filter or '(all)'}")
    print("=" * 60)
    
    plugins = load_plugins(plugin_filter)
    if not plugins:
        print(f"No plugins found (filter: {plugin_filter})")
        sys.exit(1)
    
    results = []
    for plugin in plugins:
        results.append(run_plugin(plugin, target, engagement_id, output_dir))
    
    # Final state
    state = {
        "engagement_id": engagement_id,
        "target": target,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "plugins_attempted": len(plugins),
        "plugins_succeeded": sum(results),
        "evidence_chain": str(output_dir / "evidence.jsonl"),
        "output_dir": str(output_dir),
    }
    (output_dir / "state.json").write_text(json.dumps(state, indent=2))
    
    print(f"\nResults:  {state['plugins_succeeded']}/{state['plugins_attempted']} succeeded")
    print(f"Output:   {output_dir}")
    print(f"Evidence: {output_dir}/evidence.jsonl")


if __name__ == "__main__":
    main()
