# ransomware-live-mcp

An [MCP](https://modelcontextprotocol.io) server exposing the
[ransomware.live](https://www.ransomware.live) PRO threat-intelligence API to
any MCP client: ransomware groups and their TTPs, victims, IOCs, YARA rules,
ransom notes, leaked negotiation chats, press coverage, SEC 8-K cyber
disclosures, and national CSIRT contacts.

**25 tools, all read-only.** Every tool maps to a documented `GET` endpoint on
`https://api-pro.ransomware.live`.

Built for defensive use: threat hunting, detection engineering, incident
response, third-party risk and tabletop exercises.

Works on **macOS, Linux and Windows**.

---

## Quick start

```bash
git clone https://github.com/abdulbrown/ransomware-live-mcp.git
cd ransomware-live-mcp
uv venv
uv pip install -e ".[dev]"
cp .env.example .env          # then paste your key into .env
```

Then [register it with your MCP client](#4-register-with-your-mcp-client).

Full detail below.

---

## 1. Requirements

- **Python 3.10+**
- An **MCP client** — Claude Code, Claude Desktop, or any other
- A **free ransomware.live PRO API key**

### Get and enable your API key

The key is **free**. Every user needs their own — keys are personal and should
never be shared or committed.

1. Go to **[my.ransomware.live](https://my.ransomware.live)**.
2. **Register** with an email address and confirm it. The confirmation link
   activates the account; the key will not authenticate until you do this.
3. Sign in to the dashboard and **generate / copy your API key**. It looks like
   a UUID (36 characters, in the form
   `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
4. Paste it into `.env` — see [step 3](#3-add-your-api-key) below.
5. **Verify it is enabled** before wiring it into a client:

   ```bash
   <PYTHON> scripts/selftest.py
   ```

   A working key prints `[ok] API key valid:` followed by the account
   identifier tied to it. You can also check it directly:

   ```bash
   curl https://api-pro.ransomware.live/validate -H "X-API-KEY: your-key-here"
   # {"status": "valid", "client": "you@example.com"}
   ```

Once registered, the key is authenticated by sending it as an `X-API-KEY`
header on every request — this server handles that for you.

#### Which API tier this uses

ransomware.live offers several tiers. This server targets **API PRO**:

| Tier | Auth | Limit | Used here |
| --- | --- | --- | --- |
| API v1 | none | deprecated | no |
| API v2 | none | 1 req/min per endpoint | no |
| **API PRO** | **`X-API-KEY`** | **500,000 calls/month** | **yes** |
| API PRO+ | key | in development | no |

PRO is free but key-gated, and is the only tier exposing group intelligence
(TTPs, CVEs), negotiations, YARA rules and ransom notes. A fair use policy
applies; exceeding the quota returns HTTP 429, which this server retries with
backoff.

#### What the key unlocks

23 of the 25 tools call the API and require the key. Only `build_victim_id` and
`decode_victim_identifier` work offline. If the key is missing or invalid,
every API tool returns one clear error message and the server stays running —
it does not crash the session.

## 2. Install

<details open>
<summary><b>macOS / Linux</b></summary>

```bash
git clone https://github.com/abdulbrown/ransomware-live-mcp.git
cd ransomware-live-mcp

# with uv (recommended):
uv venv
uv pip install -e ".[dev]"

# or with plain venv + pip:
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Your Python interpreter is at `.venv/bin/python`.

</details>

<details open>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
git clone https://github.com/abdulbrown/ransomware-live-mcp.git
cd ransomware-live-mcp

# with uv (recommended):
uv venv
uv pip install -e ".[dev]"

# or with plain venv + pip:
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Your Python interpreter is at `.venv\Scripts\python.exe`.

</details>

> Throughout this README, `<PYTHON>` means the interpreter path for your
> platform: `.venv/bin/python` on macOS/Linux, `.venv\Scripts\python.exe` on
> Windows.

Verify the install before going further — this works **without** an API key:

```bash
<PYTHON> -m pytest -q
```

Expect `32 passed`.

## 3. Add your API key

Copy the example file and paste your key into it:

```bash
# macOS / Linux
cp .env.example .env
```
```powershell
# Windows
Copy-Item .env.example .env
```

Edit `.env`:

```ini
RANSOMWARE_LIVE_API_KEY=your-key-here
```

`.env` is gitignored and will never be committed. The server resolves it
relative to its own install location, not the working directory, so it works no
matter where your MCP client launches it from.

Confirm the key works:

```bash
<PYTHON> scripts/selftest.py
```

Expected output ends with `[ok] full self-test passed`. If you have not added a
key yet it exits cleanly and tells you so, rather than failing cryptically.

## 4. Register with your MCP client

Every MCP client spawns the interpreter directly, so **you must use an absolute
path** to the venv Python. Get it with:

```bash
# macOS / Linux
echo "$(pwd)/.venv/bin/python"
```
```powershell
# Windows
(Resolve-Path .\.venv\Scripts\python.exe).Path
```

### Claude Code

```bash
# macOS / Linux
claude mcp add ransomware-live --scope user -- /ABSOLUTE/PATH/TO/ransomware-live-mcp/.venv/bin/python -m ransomware_live_mcp.server
```
```powershell
# Windows
claude mcp add ransomware-live --scope user -- C:\ABSOLUTE\PATH\TO\ransomware-live-mcp\.venv\Scripts\python.exe -m ransomware_live_mcp.server
```

`--scope user` makes it available in every project; drop the flag to scope it to
the current project only.

Confirm it connected:

```bash
claude mcp list
```

You should see `ransomware-live: ... - ✓ Connected`. The tools become available
in **new** sessions, so restart any session you already have open.

To remove it later: `claude mcp remove ransomware-live --scope user`

### Claude Desktop

Edit your `claude_desktop_config.json`:

| Platform | Location |
| --- | --- |
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` |

You can also reach it from the app: **Settings → Developer → Edit Config**.

<details open>
<summary><b>macOS config</b></summary>

```json
{
  "mcpServers": {
    "ransomware-live": {
      "command": "/Users/you/code/ransomware-live-mcp/.venv/bin/python",
      "args": ["-m", "ransomware_live_mcp.server"]
    }
  }
}
```

</details>

<details open>
<summary><b>Windows config</b></summary>

Backslashes must be escaped in JSON:

```json
{
  "mcpServers": {
    "ransomware-live": {
      "command": "C:\\Users\\you\\code\\ransomware-live-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "ransomware_live_mcp.server"]
    }
  }
}
```

</details>

**Restart Claude Desktop completely** after editing — quit the app, don't just
close the window. The tools appear under the tools icon in the chat input.

### Any other MCP client

The server speaks MCP over **stdio**. Point your client at:

- **command:** the absolute path to `<PYTHON>`
- **args:** `["-m", "ransomware_live_mcp.server"]`

### Passing the key inline instead of using `.env`

Any client that supports an `env` block can supply the key directly:

```json
{
  "mcpServers": {
    "ransomware-live": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["-m", "ransomware_live_mcp.server"],
      "env": { "RANSOMWARE_LIVE_API_KEY": "your-key-here" }
    }
  }
}
```

`.env` is usually preferable — it keeps your key out of client config files,
which are easy to sync, screenshot or share by accident.

### Running it directly

```bash
<PYTHON> -m ransomware_live_mcp.server
```

It will sit and wait for a client on stdin. That is correct behaviour, not a
hang.

## 5. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `✗ Failed to connect` in `claude mcp list` | Wrong interpreter path. It must be the absolute path to the venv Python, not `python` or a system install. |
| Every tool returns "No API key configured" | `.env` missing or key not filled in. Run `<PYTHON> scripts/selftest.py` to confirm. |
| `API key rejected (403)` | Key is wrong or inactive. Verify at [my.ransomware.live](https://my.ransomware.live). |
| `ModuleNotFoundError: ransomware_live_mcp` | The client is using a different interpreter than the one you installed into. Re-check the absolute path. |
| Tools don't appear in Claude Code | They only load in **new** sessions. Restart the session. |
| Tools don't appear in Claude Desktop | Quit and relaunch the app entirely; closing the window is not enough. |
| Windows: `running scripts is disabled` | PowerShell execution policy. Use `.\.venv\Scripts\python.exe` directly instead of activating. |

---

## Tools

| Tool | Endpoint | Purpose |
| --- | --- | --- |
| `validate_api_key` | `/validate` | Confirm the key is active |
| `get_stats` | `/stats` | Victim/group/press totals and last update |
| `list_groups` | `/groups` | All tracked groups with victim counts |
| `get_group` | `/groups/{name}` | Full profile: TTPs, CVEs, tools, leak sites |
| `list_sectors` | `/listsectors` | Valid `sector` filter values |
| `get_recent_victims` | `/victims/recent` | 100 newest victims |
| `search_victims` | `/victims/search` | Free-text search on name/website |
| `filter_victims` | `/victims/` | Exact filter by group/sector/country/date |
| `get_victim` | `/victim/{id}` | One enriched victim record |
| `build_victim_id` | — | Offline: names → Base64 victim ID |
| `decode_victim_identifier` | — | Offline: Base64 victim ID → names |
| `list_ioc_groups` | `/iocs` | Groups holding IOCs, by type |
| `get_group_iocs` | `/iocs/{group}` | IOC values for a group |
| `list_yara_groups` | `/yara` | Groups with YARA rules |
| `get_yara_rules` | `/yara/{group}` | Full YARA rule text |
| `list_ransomnote_groups` | `/ransomnotes` | Groups with ransom notes |
| `list_group_ransomnotes` | `/ransomnotes/{group}` | Note identifiers |
| `get_ransomnote` | `/ransomnotes/{group}/{note}` | Note content |
| `list_negotiation_groups` | `/negotiations` | Groups with leaked chats |
| `list_group_negotiations` | `/negotiations/{group}` | Chats + ransom amounts/outcome |
| `get_negotiation` | `/negotiations/{group}/{id}` | Full message thread |
| `get_recent_press` | `/press/recent` | 100 newest cyberattack press entries |
| `search_press` | `/press/all` | Press by year/month/country |
| `get_sec_8k_filings` | `/8k` | SEC 8-K Item 1.05 / 8.01 cyber disclosures |
| `get_csirt_contacts` | `/csirt/{country}` | National CERT/CSIRT contacts |

All 25 are annotated `readOnlyHint`, so clients can auto-approve them without
prompting on every call.

## Use cases

Once registered, ask your client in plain language. The examples below are
grouped by what the API key actually unlocks, with real figures observed
against the live API.

### 1. Threat landscape monitoring

> *"What's the current ransomware landscape summary?"*
> *"Which groups have been most active this month?"*

**Tools:** `get_stats`, `list_groups`, `get_recent_victims`

A single `get_stats` call is the cheapest freshness check — it returns total
victims, tracked groups, press entries and the timestamp of the most recent
leak-site listing. `list_groups` returns every tracked group with a victim
count, which is also how you resolve the exact group name other tools expect.

### 2. Adversary profiling and vulnerability prioritisation

> *"Profile the Akira ransomware group — TTPs, exploited CVEs, and tooling."*
> *"Which ransomware groups exploit vulnerabilities in my edge devices?"*

**Tools:** `get_group`

The richest endpoint. For one group you get a full MITRE ATT&CK mapping
(Initial Access → Impact), the **CVEs that group is known to exploit with CVSS
scores**, categorised tooling (RMM abuse, exfiltration, credential theft),
and known leak-site URLs.

This turns a patch backlog into a threat-informed queue: Akira's list includes
SonicWall `CVE-2024-40766`, Veeam `CVE-2024-40711` and Fortinet
`CVE-2022-40684` — all CVSS 9.8, all internet-facing. Cross-reference against
your own edge inventory and the patch order writes itself.

### 3. Detection engineering

> *"Pull YARA rules and hash IOCs for Qilin and write them to ./rules/."*
> *"Get Akira's IP indicators for my blocklist."*

**Tools:** `list_yara_groups`, `get_yara_rules`, `list_ioc_groups`,
`get_group_iocs`

`get_yara_rules` returns complete `.yar` rule text ready for a scanner.
`get_group_iocs` returns indicators grouped by type — use the `ioc_type`
filter (`md5`, `sha256`, `ip`, `domain`, `email`, `btc`, `tox`, `session`) to
keep responses small, since some groups hold hundreds of hashes.

Check coverage before you pull: `list_ioc_groups` shows the per-type breakdown,
so you can see that a group is hash-heavy and network-light before assuming an
IP blocklist gives you meaningful coverage.

### 4. Third-party and supply chain risk

> *"Have any of these vendors appeared on a leak site? [domain list]"*
> *"Show UK healthcare ransomware victims from the last year."*

**Tools:** `search_victims`, `filter_victims`, `list_sectors`, `get_victim`

`search_victims` substring-matches both the organisation name **and** the
website domain, so you can paste a vendor domain list straight in.
`filter_victims` does exact-match slicing by group, sector, country and date —
filtering to UK healthcare returns 65 victims, paginated.

Use `list_sectors` first to get valid sector values; it also returns victim
counts per sector, which is a quick relative-risk picture on its own.

### 5. Incident response

> *"I found a ransom note called README0apt on a host — which group is this?"*
> *"Who do I notify for a ransomware incident in Germany?"*

**Tools:** `list_ransomnote_groups`, `list_group_ransomnotes`,
`get_ransomnote`, `get_csirt_contacts`, `get_group`

Ransom notes give you attribution from an artefact you'd actually recover from
a compromised machine. Once attributed, `get_group` tells you that actor's
typical initial access and exfiltration tooling — i.e. where else to look.

`get_csirt_contacts` returns national CERT/CSIRT contacts from ENISA and FIRST.
Worth resolving *before* you need it, not during an incident.

### 6. Ransom negotiation preparation and tabletop exercises

> *"Analyze Akira's negotiation history — what do victims actually pay?"*

**Tools:** `list_negotiation_groups`, `list_group_negotiations`,
`get_negotiation`

The most unusual dataset here: leaked negotiation transcripts with ransom
amounts and outcomes. Aggregating Akira's 76 chats:

| Metric | Value |
| --- | --- |
| Confirmed paid | 27 / 76 (36%) |
| Median discount off initial demand | 57% |
| Median initial demand | $400,000 |
| Median settled amount | $140,000 |
| Largest demand observed | $10,000,000 |
| Longest negotiation | 170 messages ($1.7M → $225k) |

`list_group_negotiations` gives amounts and outcomes without pulling every
message, so prefer it for aggregate analysis; use `get_negotiation` when you
want the actual transcript for a tabletop.

**Interpret with care:** this is only the subset of negotiations that *leaked*,
which skews toward cases that went badly or public. Treat the payment rate as a
property of that sample, not a market-wide figure.

### 7. Executive reporting and regulatory tracking

> *"Which public companies filed SEC 8-K Item 1.05 cyber disclosures in 2025?"*
> *"What ransomware activity hit our sector this quarter?"*

**Tools:** `get_sec_8k_filings`, `get_recent_press`, `search_press`,
`list_sectors`

`get_sec_8k_filings` covers SEC Form 8-K cyber disclosures — Item 1.05
(Material Cybersecurity Incidents, mandatory since December 2023) and Item 8.01.
Set `include_item_801=false` for mandatory material incidents only. Each result
carries company, ticker, CIK, filing date and a direct EDGAR link.

Press endpoints add journalistic coverage cross-linked to leak-site victims
where the domain matches, which is useful for the "has this become public yet?"
question.

---

## Notes on responses

The live API departs from its own documentation in two ways this server
smooths over, both confirmed against `api-pro.ransomware.live`:

- **Envelopes.** Every response is a wrapper dict (`{client, count, victims}`,
  `{client, count, groups}`, `{client, filters, count, forms}`, ...), not the
  bare list the docs imply. Tools unwrap it, and drop the `client` field that
  echoes your account identity back on every single response.
- **Two spellings for victim fields.** `/victims/recent` returns `victim` /
  `group` / `attackdate`, while `/victims/search` and `/victim/{id}` still
  return the legacy `post_title` / `group_name` / `published`. Everything is
  normalised to the modern names, so all tools report one schema.

Victim and press listings can run to thousands of records, so those tools
paginate and slim by default:

- `limit` defaults to 50, max 200. Page onward with the `next_offset` value the
  response hands back.
- Pass `full=true` for the enrichment fields (screenshot URL, infostealer data,
  press link, permalink). When omitted, the response still flags
  `has_infostealer_data` / `has_press_coverage` / `has_screenshot`.

GET responses are cached in memory for 5 minutes, and HTTP 429 / 5xx are
retried with exponential backoff honouring `Retry-After`.

### Known limitations

- `get_group` and unfiltered `get_group_iocs` return large payloads and are not
  paginated. A single group profile can run to several thousand tokens; some
  groups hold hundreds of hashes. Use the `ioc_type` filter to narrow.
- Upstream data quality is uneven and passed through faithfully: some group
  entries are artefacts (e.g. `.git`), ransom amounts appear as `"N/A"`, `""`
  or `null` in the same field, and `country` is sometimes blank.
- There is no monthly quota tracking. The cache reduces repeat calls but is
  per-process and does not survive a restart.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `RANSOMWARE_LIVE_API_KEY` | — | Required. PRO API key |
| `RANSOMWARE_LIVE_BASE_URL` | `https://api-pro.ransomware.live` | API base |
| `RANSOMWARE_LIVE_CACHE_TTL` | `300` | Cache lifetime, seconds (`0` disables) |
| `RANSOMWARE_LIVE_TIMEOUT` | `30` | Per-request timeout, seconds |

Precedence: real environment variables > `.env` in the working directory >
`.env` beside the package.

## Tests

```bash
<PYTHON> -m pytest -q             # 32 offline tests, no key needed
<PYTHON> scripts/launch_check.py  # stdio JSON-RPC handshake
<PYTHON> scripts/selftest.py      # key validation + a few live calls
<PYTHON> scripts/live_check.py    # all 25 tools against the live API
```

`launch_check.py` spawns the server as a real subprocess from an unrelated
working directory and speaks raw MCP JSON-RPC to it, proving both the transport
and the `.env` resolution work independently of any client library.
`live_check.py` goes through `MCPServer.call_tool`, covering argument schemas
and validation as well as the HTTP layer.

Only `pytest` runs without an API key; the other three make live calls.

### Gotchas if you extend this

- The API's WAF returns `403 {"message": "Invalid API key"}` — not a 429 or a
  block page — for requests carrying the default `python-httpx/*` User-Agent,
  **even with a valid key**. The client always sends its own User-Agent.
- The server exits on stdin EOF, which is correct MCP behaviour. Test harnesses
  using `subprocess.communicate()` will close stdin and abort any in-flight tool
  call; hold stdin open instead.
- **Raise `ToolError`, never a bare exception.** The SDK wraps an unrecognised
  exception as `UnexpectedToolError`, which tears down the stdio session — one
  failing call costs the client all 25 tools. The `readonly_tool` decorator
  converts `ApiError` to `ToolError` centrally, so a missing key or a 404
  returns one actionable message and the session stays up. Any new failure mode
  should go through `ApiError`.
- This targets **MCP SDK 2.x**, where `FastMCP` was renamed `MCPServer`. Most
  tutorials still show the 1.x import.

## Security

- `.env` is gitignored and no key is committed to this repository.
- The server is strictly read-only — it issues `GET` requests and exposes no
  tool that writes, deletes, or sends data anywhere.
- Responses may contain ransom note text, leaked negotiation transcripts and
  victim organisation names. Handle accordingly.

## License

MIT — see [LICENSE](LICENSE).

Data is supplied by [ransomware.live](https://www.ransomware.live) under its
own terms; observe its fair use policy. This project is not affiliated with or
endorsed by ransomware.live.
