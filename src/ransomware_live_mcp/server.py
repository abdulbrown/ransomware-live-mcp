"""MCP server exposing ransomware.live PRO threat intelligence.

Read-only. Every tool maps to a documented GET endpoint on
https://api-pro.ransomware.live (OpenAPI: /swagger.json).
"""

from __future__ import annotations

import functools
import inspect
import os
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__
from .client import ApiError, RansomwareLiveClient
from .formatting import (
    DEFAULT_LIMIT,
    as_list,
    decode_victim_id,
    encode_victim_id,
    normalize_victim,
    paginate,
    slim_press,
    slim_victims,
    strip_envelope,
)

# An MCP host launches this server from an arbitrary working directory, so the
# bare cwd search that load_dotenv() does by default is not enough on its own.
# Precedence: real environment > .env in the cwd > .env next to the project.
# load_dotenv never overwrites an already-set variable, so order gives that.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv()
load_dotenv(_PROJECT_ROOT / ".env")

mcp = MCPServer(
    "ransomware-live",
    version=__version__,
    instructions=(
        "Threat intelligence on ransomware groups, their victims, leak-site "
        "activity, IOCs, YARA rules, ransom notes and negotiation chats, from "
        "ransomware.live. Use `list_groups` and `list_sectors` to discover valid "
        "filter values before filtering. Victim listings are paginated: pass "
        "`offset` from a previous response's `next_offset` to page onward, and "
        "`full=true` only when the enrichment fields are actually needed."
    ),
)

_client = RansomwareLiveClient()

# Every tool here is a read-only GET against a third-party API.
_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)


def readonly_tool(**kwargs: Any):
    """Register a tool, tagging it read-only so clients can auto-approve it.

    Also converts our own ApiError into the SDK's ToolError. An exception the
    SDK does not recognise is wrapped as UnexpectedToolError, which tears down
    the stdio session -- so a missing API key or a 404 would cost the client
    all 25 tools instead of returning one actionable message. ToolError is
    reported to the caller and leaves the session running.
    """

    def decorator(fn):
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def wrapper(*args: Any, **kw: Any):
                try:
                    return await fn(*args, **kw)
                except ApiError as exc:
                    raise ToolError(str(exc)) from exc

        else:

            @functools.wraps(fn)
            def wrapper(*args: Any, **kw: Any):
                try:
                    return fn(*args, **kw)
                except ApiError as exc:
                    raise ToolError(str(exc)) from exc

        return mcp.tool(annotations=_READ_ONLY, **kwargs)(wrapper)

    return decorator


def _order(order: str | None) -> str | None:
    if order is None:
        return None
    if order not in ("discovered", "attacked"):
        raise ApiError("`order` must be either 'discovered' or 'attacked'.")
    return order


# --------------------------------------------------------------------------
# Account & overview
# --------------------------------------------------------------------------


@readonly_tool()
async def validate_api_key() -> dict[str, Any]:
    """Check that the configured RANSOMWARE_LIVE_API_KEY is valid and active.

    Returns the client identifier tied to the key. Run this first when any
    other tool reports an authentication failure.
    """
    result = await _client.get("/validate", use_cache=False)
    return {"valid": True, "base_url": _client.base_url, "response": result}


@readonly_tool()
async def get_stats() -> dict[str, Any]:
    """Get platform-wide totals: victim count, tracked group count, press entry
    count, and the timestamp of the most recently discovered victim.

    Useful as a cheap freshness check before running larger queries.
    """
    return strip_envelope(await _client.get("/stats"))


# --------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------


@readonly_tool()
async def list_groups(limit: int = DEFAULT_LIMIT, offset: int = 0) -> dict[str, Any]:
    """List all tracked ransomware groups alphabetically with victim counts.

    Each entry has `group` (the lowercase name used by every other tool),
    `altname`, and `victims`. Call this to resolve a group name before using
    `get_group`, `get_group_iocs`, `get_yara_rules` and similar.
    """
    return paginate(as_list(await _client.get("/groups")), limit, offset)


@readonly_tool()
async def get_group(group_name: str) -> dict[str, Any]:
    """Get a full intelligence profile for one ransomware group.

    Includes background description, first/last seen dates, victim count, known
    leak-site URLs (Tor and clearweb), MITRE ATT&CK TTPs, exploited CVEs with
    CVSS scores, tools and malware used, and flags for whether negotiation
    chats and ransom notes are on file.

    Args:
        group_name: Group name, case-insensitive (e.g. "lockbit3", "blackcat", "clop").
    """
    return strip_envelope(await _client.get(f"/groups/{group_name.strip().lower()}"))


@readonly_tool()
async def list_sectors() -> dict[str, Any]:
    """List every victim sector/industry value with a victim count per sector.

    The `sector` values returned here are the valid inputs for the `sector`
    filter on `search_victims` and `filter_victims`.
    """
    return {"sectors": as_list(await _client.get("/listsectors"))}


# --------------------------------------------------------------------------
# Victims
# --------------------------------------------------------------------------


@readonly_tool()
async def get_recent_victims(
    order: Literal["discovered", "attacked"] = "discovered",
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    full: bool = False,
) -> dict[str, Any]:
    """Get the 100 most recent active ransomware victims.

    Args:
        order: "discovered" (when ransomware.live first saw the leak-site
            listing) or "attacked" (estimated attack date).
        limit: Max records to return (1-200).
        offset: Skip this many records; use `next_offset` from a prior call.
        full: Return every enrichment field (screenshot URL, infostealer data,
            press link, permalink) instead of the slimmed core fields.
    """
    data = await _client.get("/victims/recent", {"order": _order(order)})
    return paginate(slim_victims(data, full), limit, offset)


@readonly_tool()
async def search_victims(
    q: str | None = None,
    group: str | None = None,
    sector: str | None = None,
    country: str | None = None,
    order: Literal["discovered", "attacked"] = "discovered",
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    full: bool = False,
) -> dict[str, Any]:
    """Free-text search across victim organisation names and website domains.

    `q` is matched case-insensitively as a substring of both the victim name
    and the website. The other filters narrow further with AND logic.

    Args:
        q: Keyword, e.g. "hospital", "university", "acme".
        group: Exact group name, case-insensitive (see `list_groups`).
        sector: Exact sector name (see `list_sectors`).
        country: ISO 3166-1 alpha-2 country code, e.g. "US", "FR", "DE".
        order: Sort by "discovered" or "attacked".
        limit: Max records to return (1-200).
        offset: Skip this many records; use `next_offset` from a prior call.
        full: Include all enrichment fields.
    """
    if not any([q, group, sector, country]):
        raise ApiError("Provide at least one of: q, group, sector, country.")
    data = await _client.get(
        "/victims/search",
        {
            "q": q,
            "group": group,
            "sector": sector,
            "country": country.upper() if country else None,
            "order": _order(order),
        },
    )
    return paginate(slim_victims(data, full), limit, offset)


@readonly_tool()
async def filter_victims(
    group: str | None = None,
    sector: str | None = None,
    country: str | None = None,
    year: str | None = None,
    month: str | None = None,
    date: Literal["discovered", "attacked"] = "discovered",
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    full: bool = False,
) -> dict[str, Any]:
    """Filter the full victim database by group, sector, country and date.

    At least one filter is required, and all filters combine with AND logic.
    `year` cannot be used alone: the API rejects it unless `month` is also set.
    Use this rather than `search_victims` when you want an exact-match slice
    (e.g. every LockBit victim, or all US healthcare victims in June 2024).

    Args:
        group: Exact group name, case-insensitive (see `list_groups`).
        sector: Exact sector name (see `list_sectors`).
        country: ISO 3166-1 alpha-2 country code, e.g. "US".
        year: 4-digit year, e.g. "2024". Must be paired with `month`.
        month: 2-digit month, e.g. "06". Requires `year`.
        date: Which date field to filter on, "discovered" or "attacked".
        limit: Max records to return (1-200).
        offset: Skip this many records; use `next_offset` from a prior call.
        full: Include all enrichment fields.
    """
    if not any([group, sector, country, year, month]):
        raise ApiError(
            "At least one filter is required: group, sector, country, or year+month."
        )
    if year and not month:
        raise ApiError("`year` must be combined with `month` (e.g. year='2024', month='06').")
    if month and not year:
        raise ApiError("`month` requires `year`.")

    data = await _client.get(
        "/victims/",
        {
            "group": group,
            "sector": sector,
            "country": country.upper() if country else None,
            "year": year,
            "month": month,
            "date": _order(date),
        },
    )
    return paginate(slim_victims(data, full), limit, offset)


@readonly_tool()
async def get_victim(victim_id: str) -> dict[str, Any]:
    """Get the full enriched record for one victim by its Base64 ID.

    The ID is Base64 of "victim_name@group_name" and appears as the `id` field
    in every victim listing. If you only have the names, use
    `build_victim_id` first. Returns 404 if the listing was taken down.

    Args:
        victim_id: Base64-encoded victim ID from a listing's `id` field.
    """
    # This endpoint still returns the legacy post_title/group_name spelling.
    return normalize_victim(strip_envelope(await _client.get(f"/victim/{victim_id}")))


@readonly_tool()
def build_victim_id(victim_name: str, group_name: str) -> dict[str, Any]:
    """Construct the Base64 victim ID for `get_victim` from the two names.

    Offline helper; makes no API call. The names must match the API's values
    exactly, so prefer reusing an `id` from a listing when you have one.

    Args:
        victim_name: Victim organisation name as listed (the `victim` field).
        group_name: Ransomware group name (the `group` field).
    """
    victim_id = encode_victim_id(victim_name, group_name)
    return {"victim_id": victim_id, "source": f"{victim_name}@{group_name}"}


@readonly_tool()
def decode_victim_identifier(victim_id: str) -> dict[str, Any]:
    """Decode a Base64 victim ID back into its victim and group names.

    Offline helper; makes no API call.

    Args:
        victim_id: Base64-encoded victim ID.
    """
    return decode_victim_id(victim_id)


# --------------------------------------------------------------------------
# Indicators, YARA, ransom notes
# --------------------------------------------------------------------------


@readonly_tool()
async def list_ioc_groups(ioc_type: str | None = None) -> dict[str, Any]:
    """List ransomware groups that have IOCs on file, with per-type counts.

    Common IOC types: md5, sha256, ip, domain, email, btc, url.

    Args:
        ioc_type: Only return groups holding this IOC type, e.g. "ip".
    """
    return {"groups": as_list(await _client.get("/iocs", {"type": ioc_type}))}


@readonly_tool()
async def get_group_iocs(group: str, ioc_type: str | None = None) -> dict[str, Any]:
    """Get indicators of compromise for one ransomware group, grouped by type.

    Args:
        group: Group name, e.g. "lockbit3".
        ioc_type: Return only this type (md5, sha256, ip, domain, email, btc,
            url) to keep the response small.
    """
    return {
        "group": group,
        "iocs": strip_envelope(
            await _client.get(f"/iocs/{group.strip().lower()}", {"type": ioc_type})
        ),
    }


@readonly_tool()
async def list_yara_groups() -> dict[str, Any]:
    """List ransomware groups that have YARA detection rules, with rule counts."""
    return {"groups": as_list(await _client.get("/yara"))}


@readonly_tool()
async def get_yara_rules(group: str) -> dict[str, Any]:
    """Get every YARA rule for a group, each with `filename` and full rule text.

    The returned content is ready to feed to a YARA scanner.

    Args:
        group: Group name, e.g. "lockbit3", "blackcat".
    """
    return {"group": group, "rules": as_list(await _client.get(f"/yara/{group.strip().lower()}"))}


@readonly_tool()
async def list_ransomnote_groups() -> dict[str, Any]:
    """List ransomware groups that have ransom notes on file, with note counts."""
    return {"groups": as_list(await _client.get("/ransomnotes"))}


@readonly_tool()
async def list_group_ransomnotes(group: str) -> dict[str, Any]:
    """List the ransom note identifiers available for one group.

    Pass a returned name to `get_ransomnote` to read its content.

    Args:
        group: Group name, e.g. "lockbit3", "clop".
    """
    return {
        "group": group,
        "notes": as_list(await _client.get(f"/ransomnotes/{group.strip().lower()}")),
    }


@readonly_tool()
async def get_ransomnote(group: str, note_name: str) -> dict[str, Any]:
    """Get the full text of one ransom note.

    Args:
        group: Group name, e.g. "lockbit3".
        note_name: Note identifier from `list_group_ransomnotes`, without
            file extension.
    """
    return strip_envelope(await _client.get(f"/ransomnotes/{group.strip().lower()}/{note_name}"))


# --------------------------------------------------------------------------
# Negotiations
# --------------------------------------------------------------------------


@readonly_tool()
async def list_negotiation_groups() -> dict[str, Any]:
    """List ransomware groups with leaked negotiation chat logs, and chat counts."""
    return {"groups": as_list(await _client.get("/negotiations"))}


@readonly_tool()
async def list_group_negotiations(group: str) -> dict[str, Any]:
    """List negotiation chats for a group with ransom and outcome metadata.

    Each entry carries `id` (pass to `get_negotiation`), `message_count`,
    `initialransom`, `negotiatedransom`, and `paid`.

    Args:
        group: Group name, e.g. "lockbit3".
    """
    return {
        "group": group,
        "chats": as_list(await _client.get(f"/negotiations/{group.strip().lower()}")),
    }


@readonly_tool()
async def get_negotiation(group: str, chat_id: str) -> dict[str, Any]:
    """Get the full message thread and ransom metadata for one negotiation chat.

    These threads can be long. Prefer `list_group_negotiations` first to read
    ransom amounts and outcomes without pulling every message.

    Args:
        group: Group name, e.g. "lockbit3".
        chat_id: Chat ID from `list_group_negotiations`, e.g. "20240517".
    """
    return strip_envelope(await _client.get(f"/negotiations/{group.strip().lower()}/{chat_id}"))


# --------------------------------------------------------------------------
# Press, disclosures, incident response contacts
# --------------------------------------------------------------------------


@readonly_tool()
async def get_recent_press(
    country: str | None = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    full: bool = False,
) -> dict[str, Any]:
    """Get the 100 most recent tracked cyberattack press entries.

    Entries are enriched with infostealer data and linked to a ransomware
    victim record where the domain matches.

    Args:
        country: ISO 3166-1 alpha-2 country code to narrow before taking the top 100.
        limit: Max records to return (1-200).
        offset: Skip this many records; use `next_offset` from a prior call.
        full: Include all enrichment fields.
    """
    data = await _client.get("/press/recent", {"country": country.upper() if country else None})
    return paginate(slim_press(data, full), limit, offset)


@readonly_tool()
async def search_press(
    year: str | None = None,
    month: str | None = None,
    country: str | None = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    full: bool = False,
) -> dict[str, Any]:
    """Search all tracked cyberattack press entries by year, month and country.

    Results are sorted newest first.

    Args:
        year: 4-digit year, e.g. "2024".
        month: 2-digit month, e.g. "03". Requires `year`.
        country: ISO 3166-1 alpha-2 country code, e.g. "FR".
        limit: Max records to return (1-200).
        offset: Skip this many records; use `next_offset` from a prior call.
        full: Include all enrichment fields.
    """
    if month and not year:
        raise ApiError("`month` requires `year`.")
    data = await _client.get(
        "/press/all",
        {"year": year, "month": month, "country": country.upper() if country else None},
    )
    return paginate(slim_press(data, full), limit, offset)


@readonly_tool()
async def get_sec_8k_filings(
    ticker: str | None = None,
    cik: str | None = None,
    year: str | None = None,
    month: str | None = None,
    include_item_105: bool = True,
    include_item_801: bool = True,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    """Get SEC Form 8-K filings disclosing cybersecurity incidents.

    Covers Item 1.05 (Material Cybersecurity Incidents, mandatory since Dec
    2023) and Item 8.01 (Other Events, used for such disclosures before that).

    Args:
        ticker: Stock ticker, uppercase, e.g. "MSFT".
        cik: SEC CIK code, e.g. "0001234567".
        year: 4-digit filing year, e.g. "2025".
        month: 2-digit filing month, e.g. "06". Requires `year`.
        include_item_105: Include Item 1.05 filings.
        include_item_801: Include Item 8.01 filings.
        limit: Max records to return (1-200).
        offset: Skip this many records; use `next_offset` from a prior call.
    """
    if month and not year:
        raise ApiError("`month` requires `year`.")
    if not include_item_105 and not include_item_801:
        raise ApiError("At least one of include_item_105 / include_item_801 must be true.")
    data = await _client.get(
        "/8k",
        {
            "ticker": ticker.upper() if ticker else None,
            "cik": cik,
            "year": year,
            "month": month,
            "item105": str(include_item_105).lower(),
            "item801": str(include_item_801).lower(),
        },
    )
    return paginate(as_list(data), limit, offset)


@readonly_tool()
async def get_csirt_contacts(country: str) -> dict[str, Any]:
    """Get national CSIRT/CERT incident-response contacts for a country.

    Sourced from ENISA (EU) and FIRST (global). Use this to find who to notify
    when triaging a confirmed incident.

    Args:
        country: ISO 3166-1 country code, alpha-2 ("FR") or alpha-3 ("FRA").
    """
    return {
        "country": country.upper(),
        "contacts": as_list(await _client.get(f"/csirt/{country.strip().upper()}")),
    }


def main() -> None:
    """Entry point for the stdio MCP server."""
    if not os.getenv("RANSOMWARE_LIVE_API_KEY"):
        # Not fatal: the host may inject the key into the environment itself.
        # Tools raise a clear MissingApiKey error if it is genuinely absent.
        pass
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
