"""Exercise every tool against the live API through the real MCP call path.

Unlike `selftest.py` (which calls the HTTP client directly) this goes through
`MCPServer.call_tool`, so argument schemas, validation and result serialisation
are all covered. Requires a valid RANSOMWARE_LIVE_API_KEY.

Usage:  python scripts/live_check.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

from dotenv import load_dotenv

load_dotenv()
logging.disable(logging.INFO)

from ransomware_live_mcp.server import _client, mcp  # noqa: E402

PASS, FAIL = 0, 0


def _structured(result):
    """Unwrap a tool result.

    MCP 2.x returns a CallToolResult carrying `structured_content`; MCP 1.x
    returned a (content, structured_result) tuple. Accept either.
    """
    content = getattr(result, "structured_content", None)
    if content is not None:
        return content
    if isinstance(result, tuple) and len(result) == 2:
        return result[1]
    return result


def _is_error(result) -> bool:
    return bool(getattr(result, "is_error", False))


def _error_text(result) -> str:
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text:
            return text.splitlines()[0]
    return "rejected"


def summarize(value, width: int = 150) -> str:
    text = json.dumps(value, default=str, ensure_ascii=False)
    return text if len(text) <= width else text[: width - 3] + "..."


async def check(name: str, args: dict, expect=None) -> object:
    global PASS, FAIL
    try:
        raw = await mcp.call_tool(name, args)
    except Exception as exc:  # noqa: BLE001 - this is the failure report
        FAIL += 1
        print(f"[FAIL] {name}({summarize(args, 60)}) raised {type(exc).__name__}: {exc}")
        return None

    if _is_error(raw):
        FAIL += 1
        print(f"[FAIL] {name}: tool reported an error: {_error_text(raw)[:160]}")
        return None

    data = _structured(raw)

    if expect is not None:
        ok, why = expect(data)
        if not ok:
            FAIL += 1
            print(f"[FAIL] {name}: {why}")
            print(f"       got: {summarize(data, 300)}")
            return data

    PASS += 1
    print(f"[ok]   {name:<26} {summarize(data)}")
    return data


def has_results(minimum: int = 1):
    def _check(data):
        if not isinstance(data, dict):
            return False, f"expected a dict, got {type(data).__name__}"
        results = data.get("results")
        if not isinstance(results, list):
            return False, f"no 'results' list (keys: {list(data)})"
        if len(results) < minimum:
            return False, f"expected >= {minimum} results, got {len(results)}"
        return True, ""

    return _check


def nonempty_list_under(key: str):
    def _check(data):
        value = data.get(key) if isinstance(data, dict) else None
        if not isinstance(value, list):
            return False, f"'{key}' is not a list (keys: {list(data) if isinstance(data, dict) else data})"
        if not value:
            return False, f"'{key}' is empty"
        return True, ""

    return _check


def victims_are_identified(data):
    """The search endpoint's legacy field names must be normalised away."""
    ok, why = has_results(1)(data)
    if not ok:
        return ok, why
    first = data["results"][0]
    for legacy in ("post_title", "group_name", "published"):
        if legacy in first:
            return False, f"legacy field '{legacy}' leaked through normalisation"
    if not first.get("victim"):
        return False, f"victim name missing (keys: {list(first)})"
    if not first.get("group"):
        return False, f"group missing (keys: {list(first)})"
    return True, ""


async def main() -> int:
    print("== account & overview ==")
    await check("validate_api_key", {})
    await check("get_stats", {})

    print("\n== groups ==")
    groups = await check("list_groups", {"limit": 3}, has_results(3))
    await check("list_sectors", {}, nonempty_list_under("sectors"))

    group_name = "lockbit3"
    if isinstance(groups, dict) and groups.get("results"):
        group_name = groups["results"][0].get("group", group_name)
    await check("get_group", {"group_name": "lockbit3"})

    print("\n== victims ==")
    recent = await check("get_recent_victims", {"limit": 2}, has_results(1))
    await check(
        "search_victims", {"q": "hospital", "limit": 2}, victims_are_identified
    )
    await check(
        "filter_victims", {"group": "lockbit3", "limit": 2}, has_results(1)
    )

    if isinstance(recent, dict) and recent.get("results"):
        vid = recent["results"][0].get("id")
        if vid:
            await check("get_victim", {"victim_id": vid})
        sample = recent["results"][0]
        built = _structured(
            await mcp.call_tool(
                "build_victim_id",
                {"victim_name": sample.get("victim", ""), "group_name": sample.get("group", "")},
            )
        )
        match = built.get("victim_id") == vid
        print(f"[{'ok' if match else 'warn'}]   build_victim_id round-trips to the live id: {match}")

    print("\n== iocs / yara / notes ==")
    await check("list_ioc_groups", {}, nonempty_list_under("groups"))
    await check("get_group_iocs", {"group": "lockbit3"})
    yara = await check("list_yara_groups", {}, nonempty_list_under("groups"))
    if isinstance(yara, dict) and yara.get("groups"):
        await check("get_yara_rules", {"group": yara["groups"][0]["group"]})
    notes = await check("list_ransomnote_groups", {}, nonempty_list_under("groups"))
    if isinstance(notes, dict) and notes.get("groups"):
        # Their group list contains junk entries (e.g. ".git") with a nonzero
        # count but no readable notes, so pick a real one to exercise the chain.
        candidates = [
            entry["group"]
            for entry in notes["groups"]
            if entry.get("ransomnotes_count", 0) > 0 and not entry["group"].startswith(".")
        ]
        for g in candidates[:5]:
            listed = _structured(await mcp.call_tool("list_group_ransomnotes", {"group": g}))
            if isinstance(listed, dict) and listed.get("notes"):
                print(f"[ok]   list_group_ransomnotes    {summarize(listed)}")
                globals()["PASS"] += 1
                first = listed["notes"][0]
                note_name = first.get("name") if isinstance(first, dict) else first
                await check("get_ransomnote", {"group": g, "note_name": note_name})
                break
        else:
            globals()["FAIL"] += 1
            print("[FAIL] no group yielded a readable ransom note to fetch")

    print("\n== negotiations ==")
    negs = await check("list_negotiation_groups", {}, nonempty_list_under("groups"))
    if isinstance(negs, dict) and negs.get("groups"):
        g = negs["groups"][0]["group"]
        chats = await check("list_group_negotiations", {"group": g})
        if isinstance(chats, dict) and chats.get("chats"):
            chat = chats["chats"][0]
            chat_id = chat.get("id") if isinstance(chat, dict) else chat
            await check("get_negotiation", {"group": g, "chat_id": str(chat_id)})

    print("\n== press / filings / csirt ==")
    await check("get_recent_press", {"limit": 2}, has_results(1))
    await check("search_press", {"year": "2024", "month": "03", "limit": 2})
    await check("get_sec_8k_filings", {"year": "2025", "limit": 2}, has_results(1))
    await check("get_csirt_contacts", {"country": "FR"}, nonempty_list_under("contacts"))

    print("\n== input validation (should be rejected) ==")
    for name, args in [
        ("filter_victims", {}),
        ("filter_victims", {"year": "2024"}),
        ("search_victims", {}),
        ("search_press", {"month": "03"}),
    ]:
        try:
            raw = await mcp.call_tool(name, args)
        except Exception as exc:  # noqa: BLE001
            globals()["PASS"] += 1
            print(f"[ok]   {name} rejected: {str(exc).splitlines()[0][:110]}")
            continue
        if _is_error(raw):
            globals()["PASS"] += 1
            print(f"[ok]   {name} rejected: {_error_text(raw)[:110]}")
        else:
            globals()["FAIL"] += 1
            print(f"[FAIL] {name}({args}) was accepted but should have been rejected")

    await _client.aclose()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
