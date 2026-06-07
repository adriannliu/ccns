# Phish-Blocker

AI call screener built on LiveKit Agents + Twilio SIP + Amazon Nova Sonic (Bedrock).
An inbound call is screened by a conversational agent that detects scam signals,
interrogates suspicious callers, cold-transfers verified callers to the resident,
and renders a live verdict on a dashboard.

## What it does

- **Screens unknown callers** — conversational agent asks who is calling and why
- **Detects scam intent** — Moss semantic retrieval + LLM `flag_scam_signal` (conversation only, no voice biometrics)
- **Interrogates suspicious callers** — claim-specific verification questions; deflection is a strong signal
- **Auto-hangup persistent scammers** — sustained high score across multiple turns triggers BLOCK + goodbye
- **Transfers verified callers** — PASS verdict → SIP REFER cold transfer to `RESIDENT_PHONE`
- **Known-contact fast-path** — caller ID in `data/contacts.json` → silent PASS + immediate transfer (no agent)
- **Scam blocklist** — flagged numbers saved to `data/blocklist.json` with reason; repeat callers auto-blocked
- **History tab** — full-page flagged-number list; Mark as Safe, remove, or add to contacts allowlist
- **Live dashboard** — transcript, scam score, tactic chips, verdict, transfer status

## Structure

```
phish-blocker/
├── phish_blocker/
│   ├── agent.py         # ScreeningAgent, contact fast-path, tools
│   ├── transfer.py      # SIP REFER cold transfer on PASS
│   ├── contacts.py      # Local JSON contacts allowlist
│   ├── blocklist.py     # Flagged scammer numbers + repeat-caller reject
│   ├── hangup.py        # Auto-block + goodbye + room teardown
│   ├── moss_tactics.py  # Moss retrieval + scam score
│   ├── corpus.py        # Scam tactic corpus loader
│   ├── notify.py        # Console call summaries + hangup thresholds
│   ├── dashboard.py     # aiohttp: /ws, /ingest, /api/history
│   ├── bus.py           # agent → dashboard event bridge
│   └── ssl_certs.py     # cert bundle for Moss HTTPS
├── static/
│   └── index.html       # dashboard UI (Live | History tabs)
├── data/
│   ├── contacts.json    # known callers (E.164 phone → name)
│   ├── blocklist.json   # flagged/blocked numbers + reasons
│   └── scam_tactics.jsonl
├── scripts/
│   ├── build_moss_index.py
│   ├── demo_dashboard.py   # replay scam script to dashboard (no agent)
│   ├── demo_scripts.md
│   ├── bench_retrieval.py  # Moss latency/accuracy bench
│   └── verify_aws.py       # Bedrock/Nova Sonic cred check
├── pyproject.toml
└── .env.example
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # fill in LiveKit + AWS + Moss keys
```

Enable **Nova Sonic 2** in the AWS Bedrock console before running the agent.

## Run (two terminals)

1. `python -m phish_blocker.dashboard` — open http://localhost:8080
2. `python -m phish_blocker.agent dev` — starts the LiveKit agent worker

**Moss index (one-time):** `python scripts/build_moss_index.py`

**Dashboard-only demo (no agent):** `python scripts/demo_dashboard.py`

**Console demo (no telephony):** `python -m phish_blocker.agent console --text`

## Telephony (do this FIRST — riskiest part)

Follow LiveKit's "Inbound calls via Twilio" guide:

- Buy a Twilio voice number.
- Create a TwiML Bin pointing at your LiveKit SIP URI.
- Create a LiveKit inbound trunk + dispatch rule (`lk sip ...`).
- **Trunk credentials must match the TwiML Bin** — #1 failure mode.
- Set `RESIDENT_PHONE` in `.env` and test cold transfer on a real call.

Set `TWILIO_PSTN_DOMAIN` (Elastic SIP trunk termination domain, e.g. `mytrunk.pstn.twilio.com`) — required for most Twilio PSTN transfers. Enable **Call Transfers** and **PSTN transfers** on the trunk.

## Contacts allowlist

Edit `data/contacts.json`:

```json
[
  { "name": "Dave", "phone": "+14155551234", "relationship": "friend" }
]
```

Phone numbers are normalized to E.164. Known callers bypass the agent entirely and are cold-transferred to `RESIDENT_PHONE`. Caller ID can be spoofed — this is a convenience layer, not authentication.

## Scam blocklist

Blocked and challenged calls are saved to `data/blocklist.json` with phone number, reason, scam score, and matched signals. Open the dashboard **History** tab to review flagged numbers.

| API | Purpose |
|---|---|
| `GET /api/history` | List all entries |
| `DELETE /api/history` | Remove from blocklist (`{"phone": "+1..."}`) |
| `POST /api/history/verify` | Mark as safe; optional `add_to_contacts` + `name` |

In the UI: **Mark as Safe** (remove + optional allowlist), **Remove Only**. Repeat callers are **instantly rejected** (no agent).

Requires `sip.phoneNumber` on inbound SIP — if missing, calls block on dashboard but nothing is saved.

Inspect or test lookup:

```bash
python -m phish_blocker.blocklist +15551234567
cat data/blocklist.json
```

Contacts take priority: a number in both lists will PASS, not block.

## Demo script (~90s)

1. **Stakes:** AI screens calls so scam callers never reach you; legit callers get through.
2. **Scam call (live):** Teammate plays IRS/gift-card script → score climbs → BLOCK → number saved to History.
3. **Repeat scammer:** Same number calls again → instant BLOCK, no screening.
4. **Known contact:** Call from a number in `contacts.json` → instant PASS + transfer (no screening).
5. **Unknown legit caller:** "Dave confirming lunch Tuesday" → brief screen → PASS → transfer.

**Offline UI rehearsal:** run `demo_dashboard.py` while the dashboard is open.

## Demo-day risks

- Venue WiFi is hostile to realtime audio — bring a phone hotspot.
- Warm the pipeline with one throwaway call before presenting (cold start is slow).
- Twilio trial accounts add a preamble and restrict numbers — upgrade/verify beforehand.
- Test SIP REFER transfer to `RESIDENT_PHONE` before demo day.
- Stay on the conversational-intent story. Phone audio is 8 kHz; do NOT claim acoustic deepfake detection.

## Docs

Full implementer context: [docs/handoff.md](../docs/handoff.md)
