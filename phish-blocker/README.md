# Phish-Blocker

AI call screener built on LiveKit Agents + Twilio SIP + OpenAI Realtime.
An inbound call is screened by a conversational agent that detects scam signals,
interrogates suspicious callers, and renders a live verdict on a dashboard.

## Structure

```
phish-blocker/
├── phish_blocker/       # Python package
│   ├── agent.py         # LiveKit screening agent
│   ├── dashboard.py     # aiohttp server + WebSocket broadcast
│   └── bus.py           # agent → dashboard event bridge
├── static/
│   └── index.html       # live dashboard UI
├── pyproject.toml
├── requirements.txt
└── .env.example
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # fill in LiveKit + OpenAI keys
```

## Run (two terminals)

1. `python -m phish_blocker.dashboard` — open http://localhost:8080
2. `python -m phish_blocker.agent dev` — starts the LiveKit agent worker

## Telephony (do this FIRST, hour one — it's the riskiest part)

Follow LiveKit's "Inbound calls via Twilio" guide:

- Buy a Twilio number.
- Create a TwiML Bin pointing at your LiveKit SIP URI.
- Create a LiveKit inbound trunk + dispatch rule (LiveKit CLI: `lk sip ...`).
- Call the number; the agent should answer.

De-risk this before touching the prompt or dashboard. If the call doesn't connect, nothing else matters.

## Demo script (~90s)

1. One sentence of stakes: a cloned-voice "IRS" / "grandchild in trouble" call.
2. Teammate calls the number live and plays the scammer.
   Agent screens → dashboard lights up → score climbs → agent asks a verification
   question → scammer deflects → verdict flips to BLOCK.
3. Second live call: a normal caller ("it's Dave confirming Tuesday") → low score → PASS.
   The contrast is the pitch.

## Demo-day risks

- Venue WiFi is hostile to realtime audio. Bring a phone hotspot; test on it.
- Warm the pipeline with one throwaway call before presenting (cold start is slow).
- Twilio trial accounts add a preamble and restrict numbers — upgrade/verify beforehand.
- Stay on the conversational-intent story. Phone audio is 8kHz; do NOT claim acoustic deepfake detection.
