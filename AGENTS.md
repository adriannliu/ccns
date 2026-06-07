# Agent guide

Hackathon workspace for voice-native AI agents. Active project: **phish-blocker** — a
conversational call screener that detects scam intent, interrogates suspicious callers,
cold-transfers verified callers to the resident, and streams a live PASS/CHALLENGE/BLOCK
verdict to a dashboard.

Full implementer context (stack, data flow, tested vs. assumed, telephony, open items):
**[docs/handoff.md](./docs/handoff.md)**

## Repo map

```
ccns/
├── phish-blocker/              # main project
│   ├── phish_blocker/
│   │   ├── agent.py           # ScreeningAgent, contact fast-path, tools
│   │   ├── transfer.py        # SIP REFER cold transfer on PASS
│   │   ├── contacts.py        # Local JSON contacts allowlist
│   │   ├── hangup.py          # Auto-block + goodbye + room teardown
│   │   ├── moss_tactics.py    # Moss retrieval + scam score
│   │   ├── corpus.py          # Scam tactic corpus loader
│   │   ├── notify.py          # Console call summaries + hangup thresholds
│   │   ├── dashboard.py       # aiohttp server, /ws broadcast, /ingest
│   │   └── bus.py             # agent → dashboard HTTP bridge
│   ├── static/index.html      # live dashboard UI
│   ├── data/
│   │   ├── contacts.json      # known callers (E.164)
│   │   └── scam_tactics.jsonl
│   └── scripts/
│       ├── build_moss_index.py
│       ├── demo_dashboard.py  # replay scam script to dashboard (no agent)
│       └── demo_scripts.md
├── docs/
│   ├── handoff.md             # deep spec — read before non-trivial changes
│   └── objection-ai.md        # separate venture notes, not phish-blocker code
└── README.md
```

## Hard constraints (do not reverse)

- **No acoustic/voice-clone detection.** Phone audio is 8 kHz mu-law; detect scam intent
  from the *conversation* only (urgency, authority impersonation, payment demands, refusal
  to verify identity).
- **Interrogation is the core feature.** On scam signals, ask verification questions a legit
  caller answers instantly but a scammer deflects.
- **B2C/local demo only.** No carrier integration, no enterprise dashboard.
- **Dashboard server is aiohttp** (`dashboard.py`), not FastAPI/uvicorn.
- **Agent is a LiveKit worker** (`python -m phish_blocker.agent dev`), not a web service — no inbound port, no tunnel for the call path.
- **Code style:** Allman/BSD braces, minimal comments (only when non-obvious), correctness first — always state what is tested vs. assumed.

## Data flow

```
Caller → Twilio (TwiML Bin → SIP) → LiveKit trunk + dispatch → room
  → contact fast-path? (sip.phoneNumber in data/contacts.json) → PASS + cold transfer
  → else agent.py screens
      → per caller turn: Moss retrieval (moss_tactics.py)
      → tools: flag_scam_signal / set_recommendation
      → sustained high score → hangup.py (auto BLOCK)
      → PASS → transfer.py (SIP REFER → RESIDENT_PHONE)
  → bus.py POSTs to dashboard /ingest → /ws → browser
```

Moss is **wired** (`moss_tactics.py`). Fetch real Moss docs before changing index or retrieval behavior.

## Run locally

```bash
cd phish-blocker
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # LIVEKIT_*, AWS_*, MOSS_*, DASHBOARD_*, RESIDENT_PHONE
```

Two terminals:

1. `python -m phish_blocker.dashboard` → http://localhost:8080
2. `python -m phish_blocker.agent dev` → LiveKit worker

**Also useful:**

- `python scripts/build_moss_index.py` — one-time Moss index build
- `python scripts/demo_dashboard.py` — dashboard-only scam replay
- `python -m phish_blocker.agent console --text` — no telephony

Telephony (Twilio number + TwiML Bin + LiveKit inbound trunk + dispatch rule) must be set up
before a real call connects. Trunk credentials must match the TwiML Bin — #1 failure mode.
Set `RESIDENT_PHONE` and test SIP REFER transfer on a real call. See handoff.md for the full checklist.

## What is tested

- **Tested:** dashboard pipeline (agent event → bus → /ingest → /ws → browser).
- **Tested:** real Twilio inbound calls; agent screens and detects scams.
- **Tested:** Moss retrieval (with creds/index).
- **Tested:** dashboard UI replay via `demo_dashboard.py`.
- **Assumed / verify on real call:** SIP REFER cold transfer to `RESIDENT_PHONE`.
- **Assumed / verify on real call:** contact fast-path via `sip.phoneNumber`.

If `AgentServer` / `@server.rtc_session()` errors on install, check the installed
`livekit-agents` version's quickstart — entry-point boilerplate is the likely drift.

## Open build items

1. **Scam caller blocklist** — persist blocked numbers locally with reason/score/signals; user-facing list in dashboard or CLI; optional future auto-reject fast-path. See handoff.md.
2. Dashboard known-contact banner on `call_start.contact`.
3. Additive scam score bumps for repeated signals/deflections (hangup partially covers persistence today).
4. Smarter claim-based interrogation challenges.
5. Concrete LiveKit-inbound-Twilio checklist with exact `lk` CLI commands.
