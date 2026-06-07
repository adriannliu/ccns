# Phish-Blocker — Implementer Handoff

A conversational-AI phone-call screener for a hackathon. An inbound call is intercepted by
an AI agent that screens the caller, detects scam/vishing signals in real time,
interrogates suspicious callers, cold-transfers verified callers to the resident, and
renders a live PASS/CHALLENGE/BLOCK verdict on a dashboard.

**Status (June 2026):** MVP plus post-MVP features shipped — real Twilio calls, Moss retrieval,
contact fast-path, SIP cold transfer on PASS, auto-hangup on sustained risk, upgraded dashboard.
See [Tested vs. assumed](#tested-vs-assumed) for what still needs live validation.

## Hard constraints (do not reverse)

- **No acoustic/voice-clone detection.** Phone audio is 8 kHz mu-law; detect scam intent from the
  *conversation* only (urgency, authority impersonation, payment demands, refusal to verify identity).
- **Interrogation is the core feature.** On scam signals, ask a verification question a legit caller
  answers instantly but a scammer can't, and note if they deflect.
- **B2C/local demo only.** No carrier integration, no enterprise dashboard.
- **Dashboard server is aiohttp** (`dashboard.py`), not FastAPI/uvicorn.
- **Agent is a LiveKit worker** (`python -m phish_blocker.agent dev`), not a web service — no inbound port.
- Code style: **Allman/BSD braces**, **minimal comments**, **correctness first** — always state what is
  tested vs. assumed.

## Stack

| Layer | Technology |
|---|---|
| Telephony | Twilio number + TwiML Bin → LiveKit SIP |
| Agent runtime | `livekit-agents ~=1.5` |
| Speech model | AWS Bedrock **Nova Sonic 2** (`aws.realtime.RealtimeModel.with_nova_sonic_2`) |
| VAD | Silero |
| Scam tactic retrieval | **Moss** (`moss_tactics.py`, 30-tactic corpus in `data/scam_tactics.jsonl`) |
| Dashboard | aiohttp + vanilla JS WebSocket |
| Alerts | Console call summary when score crosses threshold (`notify.py`) |
| Transfer | LiveKit SIP REFER cold transfer (`transfer.py`) |
| Contacts | Local JSON allowlist (`contacts.py`, `data/contacts.json`) |

## Data flow

```
Caller
  → Twilio (TwiML Bin → SIP)
  → LiveKit inbound trunk + dispatch rule → room
  → agent.py entrypoint
      ├─ known caller ID in contacts.json? → PASS + cold transfer (no agent)
      └─ else ScreeningAgent joins
          ├─ per caller turn: Moss retrieval (moss_tactics.py)
          ├─ LLM tools: flag_scam_signal() / set_recommendation()
          ├─ sustained high score → hangup.py (auto BLOCK + goodbye + delete_room)
          ├─ PASS → transfer.py (handoff speech + SIP REFER → RESIDENT_PHONE)
          └─ elevated score → notify.py console summary
  → bus.py POST /ingest → dashboard.py /ws → static/index.html
```

## Repo map

```
ccns/
├── AGENTS.md
├── docs/
│   ├── handoff.md          # this file
│   └── objection-ai.md     # separate venture notes, NOT phish-blocker
└── phish-blocker/
    ├── phish_blocker/
    │   ├── agent.py        # ScreeningAgent, contact fast-path, tools
    │   ├── transfer.py     # SIP REFER cold transfer on PASS
    │   ├── contacts.py     # JSON contacts lookup (E.164 normalize)
    │   ├── hangup.py       # Auto-block + goodbye + room teardown
    │   ├── moss_tactics.py # Moss retrieval + scam score
    │   ├── corpus.py       # loads data/scam_tactics.jsonl
    │   ├── notify.py       # Console summaries + hangup thresholds
    │   ├── dashboard.py    # aiohttp: /, /ws, /ingest, /static
    │   ├── bus.py          # HTTP POST to dashboard /ingest
    │   └── ssl_certs.py    # cert bundle for Moss HTTPS
    ├── static/index.html   # live dashboard (transcript, score ring, transfer status)
    ├── data/
    │   ├── contacts.json   # known callers allowlist
    │   ├── scam_tactics.jsonl
    │   └── SOURCES.md
    ├── scripts/
    │   ├── build_moss_index.py
    │   ├── bench_retrieval.py
    │   ├── demo_dashboard.py   # replay scam script to /ingest
    │   ├── demo_scripts.md
    │   └── verify_aws.py
    ├── pyproject.toml
    └── .env.example
```

## Key implementation details

### `agent.py` — ScreeningAgent

- **`CallState`:** `scam_score`, `signals[]`, `seen_tactics`, `recommendation`, `reason`,
  `alert_sent`, `hangup_started`, `elevated_turns`, `transfer_started`
- **Contact fast-path** (`_try_contact_fastpath`): before agent starts, reads
  `sip.phoneNumber` from SIP participant → `contacts.lookup()` → PASS verdict + `transfer_contact_call()`
- **`screen_caller_text(text)`:** Moss retrieval with `prior=state.scam_score`; deduped tactic signals;
  tracks `elevated_turns` when score ≥ hangup threshold
- **`flag_scam_signal(label, confidence)`:** `score = max(current, confidence)` — does not accumulate
- **`set_recommendation(pass|challenge|block)`:** pushes verdict; `pass` → transfer; `block` → hangup;
  `challenge` → console summary if threshold met
- **Shutdown callback:** prints console summary on call end if suspicious

### `transfer.py` — Cold transfer

- Enabled when `RESIDENT_PHONE` is set and `TRANSFER_ENABLED` is not false
- On PASS: handoff speech → `job_ctx.transfer_sip_participant()` tries `+1...`, `tel:+1...`,
  optional `sip:+1...@TWILIO_PSTN_DOMAIN` → session shutdown
- Known contacts: silent transfer (no agent speech)
- Dashboard events: `type: "transfer"`, `status: initiated | connected | failed`

### `contacts.py` — Allowlist

- Loads `data/contacts.json`; normalizes phones to E.164
- `lookup(number)` → `Contact | None`
- CLI: `python -m phish_blocker.contacts [number]`

### `hangup.py` — Auto-hangup

- Triggers when `recommendation == "block"` OR score ≥ `HANGUP_SCORE_THRESHOLD` (default 0.66)
  for `HANGUP_EXCHANGES_REQUIRED` (default 2) consecutive elevated caller turns
- Goodbye speech → `session.shutdown()` → `job_ctx.delete_room()`
- Forces verdict to BLOCK if triggered by score alone

### `moss_tactics.py` — Scoring

- Confirmed match: red-flag keyword hit + semantic score ≥ 0.45
- Score = `max(prior, best_confidence + corroboration)`; corroboration +0.05 per distinct category (cap 0.15)
- Prior never drops mid-call; repeated same-confidence LLM signals do not add

### `notify.py` — Console summaries

- Prints formatted summary to stdout when score ≥ `NOTIFY_SCORE_THRESHOLD` or verdict is block/challenge
- **No Twilio SMS** in current code

### Dashboard events

| Event | Payload highlights |
|---|---|
| `call_start` | optional `caller_id`, `contact` (known-contact fast-path) |
| `transcript` | `role`, `text` |
| `signal` | `label`, `confidence`, `scam_score`, `explanation` |
| `verdict` | `recommendation`, `reason`, `scam_score` |
| `transfer` | `status`, `to`, `reason`, `error` |

Dashboard handles transfer status in the verdict panel. Known-contact banner on `call_start` is not yet rendered.

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
TWILIO_PSTN_DOMAIN=          # optional, for SIP URI transfer target
TRANSFER_ENABLED=true        # set false to disable transfer
```

## Run (local)

```bash
cd phish-blocker
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env

python -m phish_blocker.dashboard          # terminal 1 → http://localhost:8080
python -m phish_blocker.agent dev          # terminal 2 → LiveKit worker
```

- `agent.py` is a worker, not a web service: no uvicorn, no inbound port.
- Telephony must be set up before a real call connects.
- Moss index: `python scripts/build_moss_index.py`
- Dashboard-only demo: `python scripts/demo_dashboard.py`

## Telephony setup (do first — riskiest part)

Follow LiveKit's "Inbound calls via Twilio" guide:

1. Twilio: buy a voice-capable number; create a TwiML Bin pointing at the LiveKit SIP URI.
2. LiveKit (`lk` CLI): create an inbound trunk + dispatch rule. **Trunk username/password must match
   the TwiML Bin** — the #1 reason a call connects to nothing.
3. Set `RESIDENT_PHONE` and test cold transfer (SIP REFER) on a real call.
4. Run both processes, call the number, confirm screening + transfer behavior.

## Tested vs. assumed

| Status | Item |
|---|---|
| **Tested** | Dashboard pipeline (agent event → bus → /ingest → /ws → browser) |
| **Tested** | Real Twilio inbound calls; agent screens and detects scams |
| **Tested** | Moss retrieval (with creds/index) |
| **Tested** | Dashboard UI replay via `demo_dashboard.py` |
| **Assumed / verify on real call** | SIP REFER cold transfer to `RESIDENT_PHONE` |
| **Assumed / verify on real call** | Contact fast-path via `sip.phoneNumber` attribute |
| **Assumed / verify on real call** | Auto-hangup after sustained elevated score |
| **Not built** | Scam caller blocklist database (see open items) |
| **Not built** | Additive score escalation / `score_update` events |
| **Not built** | Dashboard known-contact banner, contacts CRUD UI |

## Open build items

### Near-term polish

1. Dashboard: show known-contact banner when `call_start.contact` is set.
2. Validate SIP REFER transfer end-to-end on production Twilio trunk.
3. Additive scam score bumps for repeated signals/deflections (optional; hangup partially covers persistence).
4. Update `AGENTS.md` repo map to match current modules.

### Planned: scam caller blocklist

**Goal:** When a call is BLOCKED (or auto-hung-up), persist the caller's phone number to a
local user-accessible database with metadata the user can review later.

**Suggested shape:**

```json
{
  "phone": "+15551234567",
  "blocked_at": "2026-06-07T14:32:00Z",
  "reason": "Pressed for gift cards and refused case reference.",
  "scam_score": 0.95,
  "signals": ["IRS gift-card payment demand", "refused verification"],
  "recommendation": "block"
}
```

**Design notes for implementer:**

- Storage: `data/blocked_numbers.json` or SQLite (`data/scam_log.db`) — mirror `contacts.py` patterns
- Write trigger: `hangup.py` and/or `set_recommendation("block")` in `agent.py`
- Caller ID source: same `sip.phoneNumber` attribute used by contact fast-path
- Dedup: update `last_seen` / append to `incidents[]` if number already blocked
- User access: dashboard "Blocked callers" panel and/or CLI `python -m phish_blocker.blocklist list`
- Future: auto-reject inbound calls from blocklist numbers (fast-path BLOCK before agent)
- Privacy: local-only, no cloud sync (fits B2C demo constraint)

### Other backlog

1. Smarter claim-based interrogation challenges.
2. Optional Twilio SMS alerts (restored alongside console summary).
3. Concrete LiveKit-inbound-Twilio checklist with exact `lk` CLI commands.

## Demo scripts

**Scam (~60s) → BLOCK** (`scripts/demo_scripts.md`):

1. IRS officer, back taxes, arrest warrant
2. Gift cards, stay on the line
3. Refuses case number → block + auto-hangup

**Legit (~30s) → PASS + transfer:**

1. Dave confirming lunch Tuesday — brief screen, pass, cold transfer

**Known contact:** call from number in `data/contacts.json` → silent pass + transfer

**Offline dashboard:** `python scripts/demo_dashboard.py`

## Files to read before coding

1. `AGENTS.md` — constraints and repo map
2. `phish_blocker/agent.py` — call logic, fast-path, tools
3. `phish_blocker/transfer.py` — SIP REFER transfer
4. `phish_blocker/contacts.py` — allowlist pattern (reuse for blocklist)
5. `phish_blocker/hangup.py` — block trigger hook point for blocklist writes
6. `phish_blocker/moss_tactics.py` — scoring model
