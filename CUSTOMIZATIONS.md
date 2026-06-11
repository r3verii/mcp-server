# Customizations (fork of PortSwigger/mcp-server)

Personal fork of the official **Burp Suite MCP Server** extension, kept separate from upstream.
It adds tools and fixes for an AI-assisted bug-bounty / pentest workflow, where the AI client
(Claude) must read Burp data **precisely** and go straight to the point instead of dumping huge
amounts of traffic.

- `origin`  → this fork (`r3verii/mcp-server`), branch `main` = upstream + the commits below.
- `upstream` → `PortSwigger/mcp-server`, for selective updates (see *Updating from upstream*).

## Guiding idea: **index → detail, never dump**

Every "read" capability comes as a **compact index tool** (id/method/host/path/status/sizes,
**no bodies**) plus a **fetch-by-id/index tool** for the full request/response. So you can scan
thousands of items cheaply, then pull only the few you need. The server also ships a usage
manual (MCP `instructions`) that teaches the client this workflow automatically.

## What changed vs upstream (commit by commit)

| Area | Change |
|------|--------|
| **Truncation** | `maxItemLength` setting (default **100000**, was a hard-coded **5000**) in the MCP *Advanced Options*. Fixes responses being cut off because the request (with big cookies) was serialized first. `<= 0` disables truncation. |
| **Organizer read** | `list_organizer_items` (compact index, `newestFirst`) + `get_organizer_items_by_id(ids)`. |
| **Site map** | `get_site_map(prefix?)` — compact index of the discovered attack surface. |
| **Organizer write-back** | `send_to_organizer` (sends a request + its live response, optional note; respects scope/approval), `set_organizer_item_notes`, `set_organizer_item_highlight`. |
| **Proxy history** | `list_proxy_http_history(hostFilter?, newestFirst?)` + `get_proxy_http_history_by_index(indices)`. |
| **Repeater/Intruder** | `get_repeater_traffic`, `get_intruder_traffic` (captured via a single `HttpHandler` into a 1000-entry ring buffer) + `get_captured_exchange_by_id(ids)`. |
| **Server instructions** | A usage manual sent at `initialize`, plus reworded bulk-tool descriptions that point at the index tools. |
| **Review fixes** | Scope check (`HttpRequestSecurity`) added to `send_to_organizer`; summaries made resilient to `MalformedRequestException`; captured-traffic tools gated behind data-access approval. |

## New MCP tools (quick reference)

- `list_organizer_items` / `get_organizer_items_by_id`
- `get_site_map`
- `send_to_organizer`, `set_organizer_item_notes`, `set_organizer_item_highlight`
- `list_proxy_http_history` / `get_proxy_http_history_by_index`
- `get_repeater_traffic`, `get_intruder_traffic` / `get_captured_exchange_by_id`

Order helpers: every history/traffic list tool (proxy HTTP history, organizer, WebSocket history,
Repeater/Intruder traffic, and the `*_regex` variants) takes `newestFirst=true` (latest first;
e.g. `newestFirst=true, count=10` = the last 10). The reported `index` for proxy history is the
**absolute** position, valid for `get_proxy_http_history_by_index` in any order.

## Known limits (upstream Montoya API, NOT fixable in this fork)

- **Organizer collections** are not exposed by Montoya → use item **notes/status** as ad-hoc
  collections (the index shows both; filter on them).
- **Repeater tabs / Intruder attacks already open** cannot be read. Only traffic that flows
  through Repeater/Intruder **after the extension is loaded** is captured (re-Send to capture).
- **Proxy history has no stable id** in Montoya → the index uses the **absolute position**.

## Building

- **JDK 21 required** (matches CI). Gradle 9.2.0 fails to compile the Kotlin DSL on JDK 23/25.
- Use a **clean `GRADLE_USER_HOME`** — the machine default may point into Scoop's Gradle and
  version-mismatch the Kotlin DSL cache.
- A persistent toolchain (JDK 21 + Gradle home) is kept under `external/.toolchain/` so it
  survives Temp cleanups.
- Run `test` and `embedProxyJar` **separately** — together they trip a Gradle 9 task-validation
  error (`embedProxyJar` ↔ `compileTestJava`).

```powershell
$env:JAVA_HOME       = "<repo>\external\.toolchain\jdk21\jdk-21.0.11+10"
$env:GRADLE_USER_HOME = "<repo>\external\.toolchain\gradle-home"
.\gradlew.bat test --no-daemon
.\gradlew.bat embedProxyJar --no-daemon   # -> build\libs\burp-mcp-all.jar
```

## Loading in Burp

Extensions → Add → Java → `build\libs\burp-mcp-all.jar` → restart the MCP server in the *MCP*
tab → reconnect the MCP client so it re-reads the tool list and the server instructions.

## Updating from upstream (you decide what to take)

```bash
git fetch upstream
git log --oneline main..upstream/main    # see what's new
git merge upstream/main                   # take everything (resolve conflicts), OR
git cherry-pick <sha>                     # take only selected commits
git push origin main
```

Conflicts are most likely in `Tools.kt` (e.g. `truncateIfNeeded`) and `serialization.kt`. Keep
your version or merge by hand. Do **not** use GitHub's "Sync fork → Discard commits": it would
wipe these customizations.
