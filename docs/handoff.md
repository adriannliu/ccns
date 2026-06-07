# Phish-Blocker — Implementer Handoff

A conversational-AI phone-call screener for a hackathon. An inbound call is intercepted by
an AI agent that screens the caller, detects scam/vishing signals in real time,
interrogates suspicious callers, and renders a live PASS/CHALLENGE/BLOCK verdict on a
dashboard. Legit callers pass through.

## Hard constraints (do not reverse)

- **No acoustic/voice-clone detection.** Phone audio is 8kHz mu-law; reliable synthetic-voice
  detection is not feasible here. Detect scam intent from the *conversation* only
  (urgency, authority impersonation, payment demands - gift cards/wire/crypto/OTP codes,
  refusal to verify identity).
- **Interrogation is the core feature.** On scam signals, the agent asks a verification
  question a legit caller answers instantly but a scammer can't (e.g. "last four digits of
  the account you're calling about?") and notes if they deflect.
- **B2C/local demo only.** No carrier integration, no enterprise dashboard.
- Code style: **Allman/BSD braces**, **no new comments** unless asked, **correctness first** -
  always state what is tested vs. assumed.

## Stack

- **Twilio** - phone number + PSTN->SIP. TwiML Bin forwards the call to the LiveKit SIP URI.
- **LiveKit Agents (Python, `livekit-agents ~=1.x`)** - agent runtime. Inbound trunk +
  dispatch rule (created via `lk` CLI) route the SIP call into a room; the agent worker joins.
- **OpenAI Realtime API** - speech-to-speech model (current choice). Alternative: STT(Deepgram)
  -> LLM -> TTS(Cartesia/ElevenLabs) pipeline, same slot, more control + cleaner transcript.
- **Moss** (moss.dev) - sub-10ms semantic retrieval (NOT a voice framework; complements
  LiveKit). Planned: index known scam tactics; agent calls it per suspicious turn to back the
  scoring. Not yet wired. Build against Moss's real LiveKit/Python docs - fetch them, don't guess.
- **aiohttp** - dashboard server (`dashboard.py`), NOT FastAPI/uvicorn (aiohttp is already
  async with its own server). Agent posts events to it over HTTP via `bus.py`.

## Data flow

```
Caller -> Twilio (TwiML Bin -> SIP) -> LiveKit trunk+dispatch -> LiveKit room
  -> agent.py worker joins, screens
  -> per turn: OpenAI Realtime handles speech; agent reasons; (planned) Moss matches tactics
  -> agent calls tools flag_scam_signal(label, confidence) / set_recommendation(rec, reason)
  -> bus.py POSTs to dashboard /ingest -> dashboard broadcasts over /ws -> browser updates
```

## Code state - dir `/home/claude/phish-blocker/` (also in `/mnt/user-data/outputs/`, and `phish-blocker.zip`)

- `agent.py` - `ScreeningAgent(Agent)`: screening+interrogation instructions; `@function_tool`s
  `flag_scam_signal(label, confidence)` and `set_recommendation(recommendation, reason)`.
  Uses `AgentServer` + `@server.rtc_session()` + `AgentSession` +
  `openai.realtime.RealtimeModel(voice="alloy")` + `silero.VAD`. Streams transcript via the
  `conversation_item_added` event. Posts events through `bus.py`.
- `bus.py` - `push(event)` POSTs JSON to `DASHBOARD_INGEST_URL` (default `http://localhost:8080/ingest`).
- `dashboard.py` - aiohttp app: `/` page, `/ws` broadcast, `/ingest` (POST->rebroadcast), `/static`.
  Env `DASHBOARD_PORT` (default 8080).
- `static/index.html` - vanilla JS dashboard over WebSocket: transcript, score gauge, signal
  chips, verdict banner; auto-reconnects.
- `requirements.txt` - `livekit-agents[openai,silero]~=1.0`, `aiohttp`, `python-dotenv`.
- `.env.example` - LIVEKIT_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET, OPENAI_API_KEY,
  DASHBOARD_PORT, DASHBOARD_INGEST_URL.

### Tested vs. assumed
- **Tested end-to-end:** dashboard pipeline (agent event -> `bus` -> `/ingest` -> `/ws` -> browser),
  verified with a scripted scam call + screenshot.
- **Not tested (no creds / external services / unwritten):** the LiveKit agent running against
  LiveKit Cloud + OpenAI; the Twilio<->LiveKit SIP wiring; the Moss integration. The LiveKit
  API was written to current `~=1.x` docs - if `AgentServer`/`@server.rtc_session()` throws on
  install, check the installed version's quickstart (entry-point boilerplate is the likely drift).

### Known weakness
- Scoring in `flag_scam_signal` is naive (`min(1.0, max(score, conf, score+0.15))`). Demo-fine,
  not defensible. Upgrade via Moss retrieval (match against tactic corpus) and/or claim-based
  interrogation challenges (bank->account digits, relative->shared detail, IRS->case number).

## Run (local)

```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill keys
python dashboard.py          # terminal 1 -> http://localhost:8080
python agent.py dev          # terminal 2 -> LiveKit worker (outbound only, no inbound port)
```
- `agent.py` is a worker, not a web service: no uvicorn, no inbound port, no tunnel.
- Telephony (below) must be set up before a real call connects.
- No tunnel needed for the call (Twilio<->LiveKit talk in the cloud). Tunnel the dashboard
  (`ngrok http 8080`) only if judges open it on their own devices.

## Telephony setup (do first - riskiest part)

Follow LiveKit's "Inbound calls via Twilio" guide:
1. Twilio: buy a voice-capable number; create a TwiML Bin pointing at the LiveKit SIP URI.
2. LiveKit (`lk` CLI): create an inbound trunk + a dispatch rule that drops callers into a
   room and dispatches the agent. **Trunk username/password must match the TwiML Bin** - the
   #1 reason a call connects to nothing.
3. Run both processes, call the number, confirm the agent answers.

## Open build items

1. Get accounts/keys: Twilio, LiveKit Cloud (free tier OK), OpenAI, Moss.
2. Twilio number + TwiML Bin; LiveKit trunk + dispatch rule (credentials must match).
3. Wire Moss `moss_retrieve_tactics` tool into `agent.py` (fetch real Moss docs first).
4. (High value) smarter claim-based interrogation challenges.
5. Confirm whether the hackathon is Moss-affiliated (changes how central Moss is).
6. Immediate next deliverable offered but not produced: a concrete LiveKit-inbound-Twilio
   checklist with exact `lk` CLI commands.