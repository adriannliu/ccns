# Agent guide

Hackathon workspace for voice-native AI agents. Active project: **phish-blocker** — a
conversational call screener that detects scam intent, interrogates suspicious callers,
and streams a live PASS/CHALLENGE/BLOCK verdict to a dashboard.

Full implementer context (stack, data flow, tested vs. assumed, telephony, open items):
**[docs/handoff.md](./docs/handoff.md)**

## Repo map

```
ccns/
├── phish-blocker/           # main project
│   ├── phish_blocker/
│   │   ├── agent.py        # LiveKit screening agent + function tools
│   │   ├── dashboard.py    # aiohttp server, /ws broadcast, /ingest
│   │   └── bus.py          # agent → dashboard HTTP bridge
│   └── static/index.html   # live dashboard UI
├── docs/
│   ├── handoff.md          # deep spec — read before non-trivial changes
│   └── objection-ai.md     # separate venture notes, not phish-blocker code
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
- **Agent is a LiveKit worker** (`agent.py dev`), not a web service — no inbound port, no tunnel for the call path.
- **Code style:** Allman/BSD braces, minimal comments (only when non-obvious), correctness first — always state what is tested vs. assumed.

## Data flow

```
Caller → Twilio (TwiML Bin → SIP) → LiveKit trunk + dispatch → room
  → agent.py screens, calls flag_scam_signal / set_recommendation tools
  → bus.py POSTs to dashboard /ingest → /ws → browser
```

Moss (semantic tactic retrieval) is planned but **not yet wired** — fetch real Moss docs before integrating.

## Run locally

```bash
cd phish-blocker
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # LIVEKIT_*, OPENAI_API_KEY, DASHBOARD_*
```

Two terminals:

1. `python -m phish_blocker.dashboard` → http://localhost:8080
2. `python -m phish_blocker.agent dev` → LiveKit worker

Telephony (Twilio number + TwiML Bin + LiveKit inbound trunk + dispatch rule) must be set up
before a real call connects. Trunk credentials must match the TwiML Bin — #1 failure mode.
See handoff.md for the full checklist.

## What is tested

- **Tested:** dashboard pipeline (agent event → bus → /ingest → /ws → browser).
- **Not tested (needs creds / external services):** LiveKit agent against cloud, Twilio↔LiveKit SIP, Moss.

If `AgentServer` / `@server.rtc_session()` errors on install, check the installed
`livekit-agents` version's quickstart — entry-point boilerplate is the likely drift.

## Open build items

1. Twilio + LiveKit telephony wiring (do first).
2. Wire Moss `moss_retrieve_tactics` into `agent.py` (read Moss docs first).
3. Smarter claim-based interrogation challenges.
4. Concrete LiveKit-inbound-Twilio checklist with exact `lk` CLI commands.
