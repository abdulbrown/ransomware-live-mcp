"""Launch the server as a real subprocess and speak raw MCP JSON-RPC to it.

This is transport-level proof the server starts and handshakes, independent of
any MCP client library. Exits non-zero on failure.

Usage:  python scripts/launch_check.py
"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Deliberately NOT the project directory: an MCP host launches the server from
# whatever directory it happens to be in, so the server must resolve its .env
# without help from the cwd. Running from here is what proves that.
NEUTRAL_CWD = tempfile.gettempdir()


def frame(obj: dict) -> bytes:
    return (json.dumps(obj) + "\n").encode("utf-8")


def _reader(stream, sink: queue.Queue) -> None:
    for line in iter(stream.readline, b""):
        line = line.strip()
        if line:
            try:
                sink.put(json.loads(line))
            except json.JSONDecodeError:
                pass


def collect(proc, wanted_ids: set[int], timeout: float = 90.0) -> dict[int, dict]:
    """Read responses while keeping stdin open, as a real MCP host does.

    Closing stdin makes the server exit, which would abort any in-flight tool
    call, so we never close it until we have what we came for.
    """
    sink: queue.Queue = queue.Queue()
    threading.Thread(target=_reader, args=(proc.stdout, sink), daemon=True).start()

    seen: dict[int, dict] = {}
    deadline = time.monotonic() + timeout
    while wanted_ids - set(seen) and time.monotonic() < deadline:
        try:
            message = sink.get(timeout=0.5)
        except queue.Empty:
            if proc.poll() is not None:
                break
            continue
        if "id" in message:
            seen[message["id"]] = message
    return seen


def main() -> int:
    print(f"       launching from a neutral cwd: {NEUTRAL_CWD}")
    proc = subprocess.Popen(
        [sys.executable, "-m", "ransomware_live_mcp.server"],
        cwd=NEUTRAL_CWD,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    request = b"".join(
        [
            frame(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "launch-check", "version": "0"},
                    },
                }
            ),
            frame({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            frame({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            frame(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "validate_api_key", "arguments": {}},
                }
            ),
        ]
    )

    try:
        proc.stdin.write(request)
        proc.stdin.flush()
        by_id = collect(proc, wanted_ids={1, 2, 3})
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    stderr = proc.stderr.read() or b""

    init = by_id.get(1)
    if not init or "result" not in init:
        print("[FAIL] no initialize result")
        print(stderr.decode("utf-8", errors="replace")[-2000:])
        return 1
    info = init["result"].get("serverInfo", {})
    print(f"[ok]   handshake: {info.get('name')} v{info.get('version')} "
          f"(protocol {init['result'].get('protocolVersion')})")

    listed = by_id.get(2)
    if not listed or "result" not in listed:
        print("[FAIL] tools/list did not return a result")
        print(stderr.decode("utf-8", errors="replace")[-2000:])
        return 1

    tools = listed["result"].get("tools", [])
    print(f"[ok]   tools/list returned {len(tools)} tools")

    problems = []
    for tool in tools:
        if not tool.get("description"):
            problems.append(f"{tool['name']}: no description")
        if "inputSchema" not in tool:
            problems.append(f"{tool['name']}: no inputSchema")
        if not tool.get("annotations", {}).get("readOnlyHint"):
            problems.append(f"{tool['name']}: not marked read-only")
    if problems:
        print("[FAIL] " + "; ".join(problems))
        return 1
    print("[ok]   every tool has a description, input schema and read-only hint")

    # A tool call must always come back as a JSON-RPC result. If an error can
    # escape as UnexpectedToolError it tears down the session, and tools/list
    # above would not have been answered either.
    called = by_id.get(3)
    if not called or "result" not in called:
        detail = (called or {}).get("error", "no response - the session died")
        print(f"[FAIL] tools/call validate_api_key returned no result: {detail}")
        print(stderr.decode("utf-8", errors="replace")[-2000:])
        return 1

    text = "".join(c.get("text", "") for c in called["result"].get("content", []))
    if called["result"].get("isError"):
        if "RANSOMWARE_LIVE_API_KEY" in text:
            # Expected when no key is configured. The point of this check is
            # that the server answered and stayed alive rather than crashing.
            print("[ok]   no API key configured; server returned a clean error and survived")
            print("       (configure .env and re-run to verify live API access)")
        else:
            print(f"[FAIL] validate_api_key errored unexpectedly: {text[:200]}")
            return 1
    else:
        print("[ok]   validate_api_key succeeded from a foreign cwd (.env resolved correctly)")

    for tool in sorted(tools, key=lambda t: t["name"]):
        params = ", ".join(tool.get("inputSchema", {}).get("properties", {}))
        print(f"       - {tool['name']}({params})")

    print("[ok]   launch check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
