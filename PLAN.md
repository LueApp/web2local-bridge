# web2local improvement plan

## What we're protecting / leaning into

The daemon already has:
- DNS-rebind guard (Host header check, daemon.py:904)
- Reflective CORS with `Access-Control-Allow-Private-Network: true`
- Whitelist / graylist / approval dialog
- SHA-256-verified script deploy
- Per-PID process registry with log tailing

The three gaps and three unique opportunities below are ordered by impact.

---

## Priority 1 — Per-origin trust handshake (security)

**Problem:** Any page on `null` origin (file://) or any localhost port can try
execution endpoints. An unknown origin hits a 403 from `_classify`, which is
correct, but there is no active prompt to the user — the site just silently
fails. This means users must manually add origins via the config UI before any
site works, and there is no "first time this site connects" moment.

**What to build:**
- `/handshake` endpoint: any origin may POST `{ "origin": "..." }`.
  Daemon enqueues a Tk dialog: "Site X wants to connect to web2local.
  Trust it for this session / always (graylist) / always (whitelist) / no."
- "Session" trust is stored in an in-memory set `_session_trusted`, not
  written to config.json. Daemon restarts clear it.
- Origin validation: reject `Origin: null` (file://) unless user explicitly
  approves in the handshake dialog.
- `client.js` gets a `requestAccess({ level: "session"|"graylist"|"whitelist" })`
  method that calls `/handshake` and surfaces the result to the page.

**Files:** `daemon.py` (_classify, do_POST, new _session_trusted set, new Tk
dialog), `website/client.js` (new requestAccess method).

---

## Priority 2 — /processes UI page in index.html (unique differentiator)

**Problem:** Process registry exists in the daemon but the only way to see it
is via the API. The index.html demo section has a partial process card UI
but it lives inside the demo section, not as a standalone live panel.

**What to build:**
- "Processes" nav tab in `index.html` that shows a live table/card list of
  all running processes (auto-refreshes every 3 s).
- Each card shows: PID, command, origin, started_at, a "Stop" button, and a
  "Logs" toggle that inline-tails the last 200 lines.
- "Logs" auto-refreshes every 2 s when open.
- Empty state: "No processes running."
- No daemon changes needed — uses existing `/ps`, `/stop`, `/logs?pid=` APIs.

**Files:** `website/index.html` (new section + JS).

---

## Priority 3 — README reframing as "MCP for webpages" (positioning)

**Problem:** The current page headline is generic. The key differentiator —
SHA-256-verified script deploy + process registry + human approval, all
reachable by a plain webpage without an extension — is not front-and-center.

**What to build:**
- New hero tagline: "MCP for webpages — any site can run local scripts, with
  your approval."
- Above-the-fold comparison: "Unlike webhook servers (no approval), MCP
  (LLM-only), and browser extensions (extension required), web2local is the
  only bridge where a static webpage can deploy, run, and monitor local
  scripts — with a native approval dialog and SHA-256 verification."
- Deploy section elevated to top of feature list with the hash/idempotency
  story explained.
- Small "deployed scripts" registry table in the UI (list files in AGENTS_DIR
  with their hash prefix, filename, and which origin deployed them).

**Files:** `website/index.html`, `daemon.py` (add `/agents` GET endpoint).

---

## Bonus — Origin flood protection (security, low effort)

**Problem:** A malicious page can POST to `/handshake` or graylist endpoints
in a tight loop, spamming the approval dialog until the user fat-fingers Allow.

**What to build:**
- Per-origin rate limit: if an origin enqueues >3 dialogs within 60 s,
  auto-deny all further requests from that origin for 5 min and log
  `FLOOD_BLOCKED`.
- A simple `_flood_tracker: dict[origin, list[timestamp]]` protected by a lock.

**Files:** `daemon.py` (_request_approval, _request_deploy_approval).

---

## Bonus — Deployed-scripts manifest per origin

**Problem:** There is no way to see "what has site X deployed on my machine?"
without grepping AGENTS_DIR manually.

**What to build:**
- `~/.config/web2local/agents.json`: maintained by _deploy_write. Each entry:
  `{sha256, filename, dest_path, origin, deployed_at}`.
- `/agents` GET endpoint returns this list (filtered to still-existing files).
- Shown in the Processes UI as a second tab "Deployed scripts" with a "Delete"
  button (removes the file and the agents.json entry).

**Files:** `daemon.py` (_deploy_write, new /agents endpoint),
`website/index.html` (new tab).

---

## Implementation order

1. [x] Write this plan
2. [ ] Priority 2: /processes UI (no daemon changes, immediate win)
3. [ ] Bonus: flood protection (tiny, pure daemon, good safety net before P1)
4. [ ] Priority 1: /handshake + session trust (daemon + client)
5. [ ] Bonus: /agents manifest + deployed scripts UI
6. [ ] Priority 3: README reframing + /agents in index.html
