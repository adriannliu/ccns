# Phish-Blocker — Agent Handoff (June 2026)

Copy this doc (or point agents at `AGENTS.md` + this file) before coding. B2C hackathon project: AI phone screener that detects scam calls, interrogates suspicious callers, blocks/flags repeat offenders, and cold-transfers legit callers to the resident.

---

## Current status

**Working on real Twilio calls:** inbound SIP → LiveKit agent screens conversation → live dashboard updates → PASS transfers to resident → BLOCK/CHALLENGE saves caller to blocklist → repeat callers auto-rejected.

| Area | Status |
|---|---|
| Live screening + Moss tactic retrieval | Shipped |
| Dashboard (Live + History tabs) | Shipped |
| Contact allowlist fast-path (PASS + transfer) | Shipped |
| Scam blocklist + History management | Shipped |
| SIP cold transfer on PASS | Shipped — verify on your trunk |
| Auto-hangup on sustained high score | Shipped |
| Console call summaries | Shipped (no Twilio SMS) |

---

## Hard constraints (do not reverse)

1. **No acoustic / voice-clone detection** — 8 kHz phone audio; detect scam intent from *conversation* only.
2. **Interrogation is core** — verification questions legit callers answer; scammers deflect.
3. **B2C / local demo** — no carrier integration, no enterprise multi-tenant.
4. **Dashboard = aiohttp** (`dashboard.py`), not FastAPI.
5. **Agent = LiveKit worker** (`python -m phish_blocker.agent dev`), not a web service.
6. **Code style:** Allman/BSD braces, minimal comments, state what's tested vs. assumed.

---

## Stack

| Layer | Tech |
|---|---|
| Telephony | Twilio number → TwiML Bin → LiveKit SIP |
| Agent | `livekit-agents ~=1.5`, `AgentServer`, `@server.rtc_session(agent_name="agent-py")` |
| Speech | AWS Bedrock **Nova Sonic 2** (`aws.realtime.RealtimeModel.with_nova_sonic_2`) |
| VAD | Silero |
| Scam tactics | Moss semantic retrieval (`moss_tactics.py`, 30 tactics in `data/scam_tactics.jsonl`) |
| Dashboard | aiohttp + vanilla JS WebSocket |
| Data stores | `data/contacts.json`, `data/blocklist.json` (local JSON, not SQLite) |

---

## Call flow (priority order)

```
Inbound PSTN call
  → LiveKit room, SIP participant
  → Read sip.phoneNumber

  1. contacts.json match?     → PASS + cold SIP REFER to RESIDENT_PHONE (no agent)
  2. blocklist.json match?      → instant BLOCK + delete_room (no agent)
  3. else ScreeningAgent        → converse, Moss + LLM tools
       → block/challenge        → write blocklist.json + History tab
       → sustained high score   → auto BLOCK + hangup + blocklist write
       → pass                   → handoff speech + cold transfer
```

**Contacts beat blocklist** if a number is in both files.

---

## Repo map

```
ccns/
├── AGENTS.md                    # short agent entry point
├── docs/handoff.md              # this file
└── phish-blocker/
    ├── phish_blocker/
    │   ├── agent.py             # ScreeningAgent, fast-paths, LLM tools
    │   ├── transfer.py          # SIP REFER cold transfer
    │   ├── contacts.py          # allowlist load/lookup/add
    │   ├── blocklist.py         # flagged numbers record/lookup/remove/reject
    │   ├── hangup.py            # auto-block, record blocklist, goodbye, delete_room
    │   ├── moss_tactics.py      # Moss retrieval + scam score
    │   ├── corpus.py            # scam_tactics.jsonl loader
    │   ├── notify.py            # console summaries + hangup thresholds
    │   ├── dashboard.py         # aiohttp server + REST + WebSocket
    │   └── bus.py               # agent → POST /ingest
    ├── static/index.html        # dashboard UI (Live | History tabs)
    ├── data/
    │   ├── contacts.json        # known safe callers
    │   ├── blocklist.json       # flagged/blocked callers + reasons
    │   └── scam_tactics.jsonl
    └── scripts/
        ├── build_moss_index.py
        ├── demo_dashboard.py    # offline UI replay
        └── demo_scripts.md
```

---

## Key modules

### `agent.py`
- **`CallState`:** `scam_score`, `signals`, `caller_id`, `recommendation`, `reason`, `elevated_turns`, `blocklist_recorded`, etc.
- **Tools:** `flag_scam_signal(label, confidence)`, `set_recommendation(pass|challenge|block, reason)`
- **Blocklist writes:** `challenge` → `_record_flagged()`; `block` → `hangup.py` → `_record_blocklist()`
- **Requires `caller_id`** from `sip.phoneNumber` for blocklist writes; skips if missing

### `blocklist.py`
- `record(phone, recommendation, reason, scam_score, signals)` — upsert to `data/blocklist.json`
- `lookup(phone)` / `remove(phone)` / `list_history()`
- `reject_repeat_caller()` — fast-path for repeat inbound calls

### `contacts.py`
- `lookup(phone)` — allowlist fast-path
- `add(phone, name, relationship)` — used when user "Mark as Safe + allowlist" in History tab

### `transfer.py`
- `maybe_transfer_call()` on PASS — handoff speech then `transfer_sip_participant()`
- Targets: `+1...`, `tel:+1...`, `sip:+1...@TWILIO_PSTN_DOMAIN`
- Needs `RESIDENT_PHONE`; `TWILIO_PSTN_DOMAIN` required for most Twilio PSTN transfers

### `hangup.py`
- Triggers on explicit `block` OR score ≥ `HANGUP_SCORE_THRESHOLD` (0.66) for `HANGUP_EXCHANGES_REQUIRED` (2) elevated turns
- Records blocklist, speaks goodbye, shuts down session, `delete_room()`

### `moss_tactics.py`
- Score = `max(prior, best_confidence + corroboration)`; corroboration +0.05/category (cap 0.15)
- `flag_scam_signal` still uses `max(score, confidence)` — does not accumulate per repeated signal

---

## Dashboard

### Tabs
- **Live Screening** — transcript, threat gauge, tactic chips, verdict, transfer status
- **History** — full-page grid of flagged numbers from `blocklist.json`

### REST API
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/history` | List all blocklist entries |
| DELETE | `/api/history` | Body: `{"phone": "+1..."}` — remove from blocklist |
| POST | `/api/history/verify` | Body: `{"phone", "add_to_contacts?", "name?"}` — mark safe, optional allowlist |

### WebSocket events (`/ws`, also via POST `/ingest`)
| Event | Notes |
|---|---|
| `call_start` | `caller_id`, `contact`, `blocklist_hit` |
| `transcript` | `role`, `text` |
| `signal` | Moss/LLM hit + `scam_score` |
| `verdict` | `recommendation`, `reason`, `scam_score` |
| `transfer` | `status`: initiated \| connected \| failed |
| `history_entry` | new/updated blocklist row |
| `history_removed` | phone removed from blocklist |

---

## Environment variables

```
LIVEKIT_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
MOSS_PROJECT_ID, MOSS_PROJECT_KEY, MOSS_INDEX_NAME, MOSS_MODEL_ID
DASHBOARD_PORT, DASHBOARD_INGEST_URL
NOTIFY_SCORE_THRESHOLD=0.66
HANGUP_SCORE_THRESHOLD=0.66
HANGUP_EXCHANGES_REQUIRED=2
RESIDENT_PHONE=+1XXXXXXXXXX
TWILIO_PSTN_DOMAIN=mytrunk.pstn.twilio.com
TRANSFER_ENABLED=true
```

---

## Run locally

```bash
cd phish-blocker
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # fill keys; enable Nova Sonic 2 in Bedrock

# Terminal 1
python -m phish_blocker.dashboard    # http://localhost:8080

# Terminal 2
python -m phish_blocker.agent dev

# One-time Moss index
python scripts/build_moss_index.py

# Offline dashboard demo
python scripts/demo_dashboard.py
```

**Telephony:** Twilio number → TwiML Bin → LiveKit SIP URI. Inbound trunk + dispatch rule via `lk` CLI. **Trunk creds must match TwiML Bin.** Enable Call Transfers + PSTN transfers on Twilio Elastic SIP trunk.

---

## Tested vs. assumed

| | |
|---|---|
| **Tested** | Dashboard pipeline, Moss retrieval, History tab, blocklist record/remove API |
| **Tested** | Real Twilio inbound screening (per team) |
| **Assumed — verify live** | SIP REFER transfer to `RESIDENT_PHONE` |
| **Assumed — verify live** | `sip.phoneNumber` present on inbound SIP (required for blocklist) |
| **Assumed — verify live** | Blocklist repeat-caller fast-path on real calls |
| **Assumed — verify live** | Auto-hangup after sustained elevated score |

**#1 blocklist failure mode:** caller ID missing → calls block on dashboard but `data/blocklist.json` stays empty.

---

## Demo script (~2 min)

1. **Scam call** — IRS/gift-card script → score climbs → BLOCK → appears in History tab.
2. **Repeat scammer** — same number calls again → instant BLOCK (no agent).
3. **Accidental flag** — History → Mark as Safe (optionally add to contacts).
4. **Known contact** — number in `contacts.json` → silent PASS + transfer.
5. **Unknown legit** — brief screen → PASS → transfer.

---

## Open / next work

1. **Additive scam score** — score plateaus on repeated signals; hangup covers persistence partially.
2. **Known-contact banner** on Live tab when `call_start.contact` is set.
3. **SIP/telephony hardening** — transfer failures, caller ID edge cases, exact `lk` CLI checklist.
4. **Smarter claim-based interrogation** — dynamic verification per caller story.
5. **Optional Twilio SMS alerts** (removed; console summary only today).
6. **Blocklist polish** — export CSV, bulk clear, incident detail view.

---

## Files to read first

1. `AGENTS.md` — constraints + repo map
2. `phish_blocker/agent.py` — all call logic
3. `phish_blocker/blocklist.py` + `contacts.py` — fast-path symmetry
4. `phish_blocker/transfer.py` — telephony risk area
5. `static/index.html` — dashboard tabs + History UX
6. `phish_blocker/dashboard.py` — REST endpoints

---

## Agent instructions

- Read this file before non-trivial changes.
- Do not add FastAPI, voice biometrics, or carrier APIs.
- Prefer extending existing JSON stores (`contacts.json`, `blocklist.json`) over new DB layers for demo scope.
- Always note tested vs. assumed in PRs/commits.
- Telephony changes need a real-call test plan.
