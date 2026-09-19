"""Post-install self-test.

Verifies the server imports, registers its tools, and -- if an API key is
configured -- that the key is valid and a live call succeeds.

Usage:  python scripts/selftest.py
"""

from __future__ import annotations

import asyncio
import os
import sys

from dotenv import load_dotenv

load_dotenv()

from ransomware_live_mcp.client import ApiError  # noqa: E402
from ransomware_live_mcp.server import _client, mcp  # noqa: E402


async def main() -> int:
    tools = await mcp.list_tools()
    print(f"[ok]   server imported, {len(tools)} tools registered")
    undocumented = [t.name for t in tools if not t.description]
    if undocumented:
        print(f"[FAIL] tools missing descriptions: {undocumented}")
        return 1

    if not os.getenv("RANSOMWARE_LIVE_API_KEY"):
        print("[warn] RANSOMWARE_LIVE_API_KEY not set - skipping live API checks.")
        print("       Add your key to .env, then re-run this self-test.")
        print("[ok]   offline self-test passed")
        return 0

    try:
        identity = await _client.get("/validate", use_cache=False)
        print(f"[ok]   API key valid: {identity}")

        stats = await _client.get("/stats")
        print(f"[ok]   /stats reachable: {stats}")

        victims = await _client.get("/victims/recent", {"order": "discovered"})
        count = len(victims) if isinstance(victims, list) else "n/a"
        print(f"[ok]   /victims/recent returned {count} records")
    except ApiError as exc:
        print(f"[FAIL] live API check failed: {exc}")
        return 1
    finally:
        await _client.aclose()

    print("[ok]   full self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
