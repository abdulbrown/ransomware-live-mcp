"""Offline tests: no network, no API key required."""

from __future__ import annotations

import pytest

from ransomware_live_mcp.formatting import (
    MAX_LIMIT,
    as_list,
    clamp_limit,
    decode_victim_id,
    encode_victim_id,
    normalize_victim,
    paginate,
    slim_press,
    slim_victims,
    strip_envelope,
)
from ransomware_live_mcp.server import mcp


async def test_all_tools_register():
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    expected = {
        "validate_api_key",
        "get_stats",
        "list_groups",
        "get_group",
        "list_sectors",
        "get_recent_victims",
        "search_victims",
        "filter_victims",
        "get_victim",
        "build_victim_id",
        "decode_victim_identifier",
        "list_ioc_groups",
        "get_group_iocs",
        "list_yara_groups",
        "get_yara_rules",
        "list_ransomnote_groups",
        "list_group_ransomnotes",
        "get_ransomnote",
        "list_negotiation_groups",
        "list_group_negotiations",
        "get_negotiation",
        "get_recent_press",
        "search_press",
        "get_sec_8k_filings",
        "get_csirt_contacts",
    }
    assert expected <= names, f"missing tools: {expected - names}"


async def test_every_tool_has_a_description():
    for tool in await mcp.list_tools():
        assert tool.description, f"{tool.name} has no description"


def test_victim_id_roundtrip():
    victim_id = encode_victim_id("AcmeCorp", "acmegroup")
    assert victim_id == "QWNtZUNvcnBAYWNtZWdyb3Vw"
    decoded = decode_victim_id(victim_id)
    assert decoded["victim"] == "AcmeCorp"
    assert decoded["group"] == "acmegroup"


def test_decode_tolerates_garbage():
    assert decode_victim_id("!!!not-base64!!!")["victim_id"] == "!!!not-base64!!!"


def test_pagination_reports_next_page():
    items = list(range(120))
    page = paginate(items, limit=50, offset=0)
    assert page["returned"] == 50
    assert page["total_matching"] == 120
    assert page["next_offset"] == 50
    assert page["more_available"] is True

    last = paginate(items, limit=50, offset=100)
    assert last["returned"] == 20
    assert last["more_available"] is False
    assert "next_offset" not in last


def test_pagination_past_the_end_is_empty_not_an_error():
    page = paginate([1, 2, 3], limit=10, offset=99)
    assert page["results"] == []
    assert page["more_available"] is False


@pytest.mark.parametrize(
    ("given", "expected"),
    [(None, 50), (0, 1), (-5, 1), (10, 10), (10_000, MAX_LIMIT)],
)
def test_limit_is_clamped(given, expected):
    assert clamp_limit(given) == expected


def test_slimming_drops_bulk_but_flags_it():
    record = {
        "victim": "Acme",
        "group": "lockbit3",
        "country": "US",
        "activity": "Manufacturing",
        "website": "acme.example",
        "attackdate": "2024-06-01",
        "discovered": "2024-06-02",
        "id": "abc",
        "screenshot": "https://images.example/x.png",
        "infostealer": {"employees": 3},
        "press": "https://news.example/a",
        "permalink": "https://www.ransomware.live/id/abc",
    }
    slim = slim_victims([record])[0]
    assert "screenshot" not in slim
    assert "infostealer" not in slim
    assert slim["has_infostealer_data"] is True
    assert slim["has_screenshot"] is True
    assert slim["victim"] == "Acme"

    assert slim_victims([record], full=True)[0] == record


def test_slimming_handles_wrapped_payloads():
    assert slim_victims({"victims": [{"victim": "A", "group": "g"}]}) == [
        {"victim": "A", "group": "g"}
    ]
    assert slim_victims(None) == []


# --- envelope handling -----------------------------------------------------
# The live API wraps every payload and the key differs per endpoint. These
# shapes were captured from api-pro.ransomware.live, not from the docs.


@pytest.mark.parametrize(
    ("envelope", "expected_len"),
    [
        ({"client": "x", "count": 2, "victims": [1, 2]}, 2),
        ({"client": "x", "count": 3, "groups": [1, 2, 3]}, 3),
        ({"client": "x", "count": 1, "sectors": [1]}, 1),
        ({"client": "x", "filters": {}, "results": [1, 2]}, 2),
        ({"client": "x", "filters": {}, "count": 4, "forms": [1, 2, 3, 4]}, 4),
    ],
)
def test_as_list_unwraps_every_known_envelope_key(envelope, expected_len):
    assert len(as_list(envelope)) == expected_len


def test_as_list_falls_back_to_first_list_on_unknown_key():
    # A renamed envelope key should degrade to working, not to returning nothing.
    assert as_list({"client": "x", "count": 2, "brand_new_key": [1, 2]}) == [1, 2]


def test_as_list_never_mistakes_the_client_echo_for_payload():
    assert as_list({"client": ["not", "payload"], "groups": [1]}) == [1]


def test_strip_envelope_drops_the_account_echo():
    assert strip_envelope({"client": "me@example.com", "stats": {"victims": 1}}) == {
        "stats": {"victims": 1}
    }


# --- legacy field names ----------------------------------------------------
# /victims/recent returns victim/group/attackdate; /victims/search still
# returns post_title/group_name/published for the same records.


def test_legacy_victim_fields_are_normalized():
    legacy = {
        "post_title": "Acme",
        "group_name": "lockbit3",
        "published": "2024-06-01",
        "country": "US",
    }
    assert normalize_victim(legacy) == {
        "victim": "Acme",
        "group": "lockbit3",
        "attackdate": "2024-06-01",
        "country": "US",
    }


def test_search_shaped_records_keep_victim_and_group_after_slimming():
    search_payload = {
        "client": "x",
        "count": 1,
        "victims": [
            {
                "id": "abc",
                "post_title": "St Mary Hospital",
                "group_name": "lockbit3",
                "published": "2024-06-01",
                "discovered": "2024-06-02",
                "country": "US",
                "activity": "Healthcare",
                "website": "stmary.example",
            }
        ],
    }
    slim = slim_victims(search_payload)[0]
    assert slim["victim"] == "St Mary Hospital"
    assert slim["group"] == "lockbit3"
    assert slim["attackdate"] == "2024-06-01"


def test_modern_field_wins_if_both_spellings_are_present():
    record = {"victim": "Modern", "post_title": "Legacy"}
    assert normalize_victim(record)["victim"] == "Modern"


def test_press_slimming_keeps_the_real_press_fields():
    record = {
        "date": "2024-06-01",
        "victim": "Acme",
        "domain": "acme.example",
        "country": "FR",
        "title": "Acme hit by ransomware",
        "url": "https://news.example/a",
        "summary": "Short summary",
        "ransomware": "lockbit3",
        "description": "a very long description " * 50,
        "infostealer": {"employees": 2},
    }
    slim = slim_press([record])[0]
    assert slim["domain"] == "acme.example"
    assert slim["summary"] == "Short summary"
    assert slim["ransomware"] == "lockbit3"
    assert "description" not in slim
    assert slim["has_infostealer_data"] is True
