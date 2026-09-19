"""Response shaping helpers.

Two facts about the live API drive this module, both confirmed against
api-pro.ransomware.live rather than taken from the docs:

1. Every response is an envelope dict, not a bare list, and the key holding
   the payload varies by endpoint (`victims`, `groups`, `sectors`, `results`,
   `forms`, ...). Each envelope also echoes the caller's account in `client`.
2. Endpoints disagree on victim field names. `/victims/recent` returns the
   modern `victim` / `group` / `attackdate`, while `/victims/search` still
   returns the legacy `post_title` / `group_name` / `published`. We normalise
   to the modern names so every tool reports one consistent schema.

Victim and press listings also run to thousands of records carrying nested
infostealer blobs, so list tools paginate and slim by default.
"""

from __future__ import annotations

import base64
from typing import Any, Iterable, Sequence

MAX_LIMIT = 200
DEFAULT_LIMIT = 50

# Envelope keys that hold the actual payload list, in priority order.
_PAYLOAD_KEYS = (
    "victims",
    "groups",
    "sectors",
    "results",
    "forms",
    "press",
    "chats",
    "notes",
    "rules",
    "iocs",
    "contacts",
    "data",
    "items",
)

# Envelope metadata that is noise once the payload is extracted. `client`
# echoes the API account identity back on every single response.
_ENVELOPE_NOISE = ("client",)

# Legacy -> canonical victim field names.
_VICTIM_ALIASES = {
    "post_title": "victim",
    "group_name": "group",
    "published": "attackdate",
}

# Core victim fields kept when full=False.
_VICTIM_CORE = (
    "victim",
    "group",
    "country",
    "activity",
    "website",
    "attackdate",
    "discovered",
    "ransom",
    "data_size",
    "id",
)

# Core press fields kept when full=False.
_PRESS_CORE = (
    "title",
    "date",
    "victim",
    "domain",
    "country",
    "url",
    "summary",
    "ransomware",
)


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    return max(1, min(int(limit), MAX_LIMIT))


def paginate(
    items: Sequence[Any],
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Slice `items` and describe the slice so the caller can page onward."""
    total = len(items)
    limit = clamp_limit(limit)
    offset = max(0, int(offset or 0))
    window = list(items[offset : offset + limit])
    next_offset = offset + len(window)
    result: dict[str, Any] = {
        "total_matching": total,
        "returned": len(window),
        "offset": offset,
        "results": window,
    }
    if next_offset < total:
        result["next_offset"] = next_offset
        result["more_available"] = True
        result["hint"] = f"Call again with offset={next_offset} for the next page."
    else:
        result["more_available"] = False
    return result


def as_list(payload: Any) -> list[Any]:
    """Pull the payload list out of an API envelope.

    Falls back to the first list-valued entry, so a new or renamed envelope
    key degrades to working rather than to silently returning nothing.
    """
    if isinstance(payload, list):
        return payload
    if payload is None:
        return []
    if isinstance(payload, dict):
        for key in _PAYLOAD_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                return value
        for key, value in payload.items():
            if key not in _ENVELOPE_NOISE and isinstance(value, list):
                return value
        return [payload]
    return [payload]


def strip_envelope(payload: Any) -> Any:
    """Drop redundant envelope metadata from a single-object response."""
    if isinstance(payload, dict):
        return {k: v for k, v in payload.items() if k not in _ENVELOPE_NOISE}
    return payload


def normalize_victim(record: Any) -> Any:
    """Rename legacy victim fields to their modern equivalents."""
    if not isinstance(record, dict):
        return record
    out = dict(record)
    for legacy, canonical in _VICTIM_ALIASES.items():
        if legacy in out:
            value = out.pop(legacy)
            out.setdefault(canonical, value)
    return out


def _slim(record: Any, keep: Iterable[str]) -> Any:
    if not isinstance(record, dict):
        return record
    slimmed = {k: record[k] for k in keep if k in record}
    # Surface the presence of dropped enrichment without inlining it.
    if record.get("infostealer"):
        slimmed["has_infostealer_data"] = True
    if record.get("press"):
        slimmed["has_press_coverage"] = True
    if record.get("screenshot"):
        slimmed["has_screenshot"] = True
    return slimmed or record


def slim_victims(records: Any, full: bool = False) -> list[Any]:
    normalized = [normalize_victim(r) for r in as_list(records)]
    if full:
        return normalized
    return [_slim(r, _VICTIM_CORE) for r in normalized]


def slim_press(records: Any, full: bool = False) -> list[Any]:
    records = as_list(records)
    if full:
        return records
    return [_slim(r, _PRESS_CORE) for r in records]


def encode_victim_id(victim_name: str, group_name: str) -> str:
    """Build the Base64 victim ID the API uses: base64('post_title@group_name')."""
    raw = f"{victim_name}@{group_name}".encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def decode_victim_id(victim_id: str) -> dict[str, str]:
    """Inverse of `encode_victim_id`; best-effort, returns the raw value on failure."""
    try:
        padded = victim_id + "=" * (-len(victim_id) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - malformed IDs are user input, not a bug
        return {"victim_id": victim_id, "decoded": None}
    name, _, group = decoded.rpartition("@")
    return {
        "victim_id": victim_id,
        "decoded": decoded,
        "victim": name or decoded,
        "group": group or None,
    }
