Agent Handoff Brief
Mission
Phish-Blocker is a B2C/local-demo AI phone screener. Inbound PSTN calls hit a Twilio number, route via SIP into LiveKit, and are answered by a conversational agent that:
Screens the caller with light conversation
Detects scam/vishing intent from conversation only (not audio biometrics)
Interrogates suspicious callers with claim-specific verification questions
Streams a live PASS / CHALLENGE / BLOCK verdict + scam score to a browser dashboard
MVP status (as of June 2026): Working end-to-end on real Twilio calls. Agent converses, Moss-backed tactic retrieval fires, dashboard updates live, BLOCK triggers optional SMS alert. Not yet implemented: actual call transfer on PASS, local contacts allowlist, or escalating scam score for persistent scammers.

Hard Constraints (Do Not Reverse)
Constraint
Rationale
No acoustic / voice-clone detection
Phone audio is 8 kHz mu-law; unreliable for synthetic-voice detection
Interrogation is the core feature
Ask verification questions legit callers answer instantly; scammers deflect
B2C / local demo only
No carrier integration, no enterprise multi-tenant dashboard
Dashboard = aiohttp (dashboard.py)
Not FastAPI/uvicorn
Agent = LiveKit worker (python -m phish_blocker.agent dev)
No inbound HTTP port; no tunnel needed for call path
Code style: Allman/BSD braces, minimal comments
Correctness first; always label tested vs. assumed


Architecture & Data Flow
Caller
 → Twilio (TwiML Bin → SIP URI)
 → LiveKit inbound trunk + dispatch rule
 → LiveKit room
 → agent.py worker joins (ScreeningAgent)
     ├─ per caller turn: Moss semantic retrieval (moss_tactics.py)
     ├─ LLM tools: flag_scam_signal(), set_recommendation()
     └─ on BLOCK: optional Twilio SMS (notify.py)
 → bus.py POST /ingest
 → dashboard.py WebSocket /ws
 → static/index.html (live transcript, score gauge, signal chips, verdict)
Stack (current — differs from older handoff.md):
Layer
Technology
Telephony
Twilio number + TwiML Bin → LiveKit SIP
Agent runtime
livekit-agents ~=1.5
Speech model
AWS Bedrock Nova Sonic 2 (aws.realtime.RealtimeModel.with_nova_sonic_2) — not OpenAI Realtime
VAD
Silero
Scam tactic retrieval
Moss (moss_tactics.py, 30-tactic corpus in data/scam_tactics.jsonl)
Dashboard
aiohttp + vanilla JS WebSocket
Alerts
Twilio SMS on BLOCK (optional NOTIFY_ON_CHALLENGE)


Repo Map (Actual)
ccns/
├── AGENTS.md                          # agent guide (entry point for coding agents)
├── docs/
│   ├── handoff.md                     # deep spec (partially stale — see deltas below)
│   └── objection-ai.md                # separate venture notes, NOT phish-blocker
└── phish-blocker/
   ├── phish_blocker/
   │   ├── agent.py                   # ScreeningAgent, CallState, tools, Moss hook
   │   ├── bus.py                     # HTTP POST to dashboard /ingest
   │   ├── dashboard.py               # aiohttp: /, /ws, /ingest, /static
   │   ├── moss_tactics.py            # Moss retrieval + scam score computation
   │   ├── corpus.py                  # loads data/scam_tactics.jsonl
   │   ├── notify.py                  # Twilio SMS on block/challenge
   │   └── ssl_certs.py               # cert bundle for Moss HTTPS
   ├── static/index.html              # live dashboard UI
   ├── data/
   │   ├── scam_tactics.jsonl         # 30 indexed scam tactics
   │   └── SOURCES.md
   ├── scripts/
   │   ├── build_moss_index.py        # index corpus into Moss
   │   ├── bench_retrieval.py         # latency/accuracy bench
   │   ├── demo_scripts.md            # console demo scripts
   │   └── verify_aws.py
   ├── pyproject.toml
   └── .env.example

Key Implementation Details
agent.py — ScreeningAgent
CallState: scam_score, signals[], seen_tactics (dedup), recommendation, reason, alert_sent
screen_caller_text(text): runs on every caller utterance; calls retrieve_tactics(text, prior=state.scam_score); pushes Moss signal events (deduped by tactic_id)
flag_scam_signal(label, confidence): LLM tool; score = min(1.0, max(current, confidence)) — does not accumulate
set_recommendation(pass|challenge|block, reason): sets verdict, pushes to dashboard; on block sends SMS via notify.py
Verdict "pass" today = label only — agent does not transfer the call anywhere
moss_tactics.py — Scoring
Confirmed match requires red-flag keyword hit + semantic score ≥ 0.45
Score = max(prior, best_confidence + corroboration) where corroboration caps at +0.15 across distinct categories
Prior is respected (score never drops mid-call) but repeated signals don't add much if confidence is already high
dashboard.py + static/index.html
Events: call_start, transcript, signal, verdict
Dashboard resets on call_start; score gauge updates from signal and verdict events
No contacts UI, no transfer status, no score history graph
notify.py
Sends Twilio SMS to NOTIFY_PHONE_NUMBER on BLOCK (and optionally CHALLENGE)
Requires TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_SMS_FROM

Environment Variables (.env.example)
LIVEKIT_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
MOSS_PROJECT_ID, MOSS_PROJECT_KEY, MOSS_INDEX_NAME, MOSS_MODEL_ID
DASHBOARD_PORT, DASHBOARD_INGEST_URL
TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_SMS_FROM, NOTIFY_PHONE_NUMBER

Run Locally
cd phish-blocker
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # fill keys
# Terminal 1
python -m phish_blocker.dashboard    # http://localhost:8080
# Terminal 2
python -m phish_blocker.agent dev    # LiveKit worker
# Moss index (one-time)
python scripts/build_moss_index.py
# Console demo (no telephony)
python -m phish_blocker.agent console --text
Telephony prerequisite: Twilio number → TwiML Bin → LiveKit SIP URI. LiveKit inbound trunk + dispatch rule via lk CLI. Trunk credentials must match TwiML Bin — #1 failure mode.

Tested vs. Assumed
Status
Item
Tested
Dashboard pipeline: agent event → bus → /ingest → /ws → browser
Tested
Real Twilio inbound calls; agent screens and detects scams (per user)
Tested
Moss retrieval wired (if creds/index present)
Assumed / needs verification
Call transfer mechanics (not built)
Assumed / needs verification
Caller ID extraction from LiveKit SIP participant (not used in code today)
Assumed / needs verification
SMS alerts in production Twilio account
Not built
Contacts database / allowlist
Not built
Escalating scam score for persistent callers


Deltas from docs/handoff.md (Stale Sections)
The handoff doc was written at an earlier milestone. Key drift:
LLM is AWS Nova Sonic 2, not OpenAI Realtime
Moss is wired (moss_tactics.py, corpus, build scripts) — no longer "planned"
SMS alerts exist (notify.py)
livekit-agents ~=1.5 with AgentServer + @server.rtc_session(agent_name="agent-py")
Scoring is more sophisticated than the handoff's "naive max" note, but still non-accumulating for repeated signals

Next Build Items (Priority Order — User Request)
1. Call Transfer on PASS
Goal: When the agent verifies a caller as legitimate (set_recommendation("pass", ...)), actually connect them to the resident's real phone — not just label the verdict.
Current gap: set_recommendation("pass") only pushes a dashboard event. The caller stays on the line with the AI screener indefinitely.
Design questions for implementer:
What is the resident's target number? (RESIDENT_PHONE env var?)
Transfer mechanism: Twilio <Dial> REST API vs. LiveKit SIP REFER vs. adding resident as SIP participant to the room?
Does the agent announce the transfer ("Connecting you now") before bridging?
Does the agent disconnect after transfer?
Should CHALLENGE ever transfer, or only PASS?
2. Local Contacts Allowlist
Goal: User-maintained local contact database. If inbound caller ID matches a known contact, auto-pass (skip or minimize screening).
Current gap: No contacts module, no caller ID lookup, no fast-path in entrypoint().
Design questions:
Storage: SQLite (~/.phish-blocker/contacts.db) vs. JSON (data/contacts.json)?
Match key: E.164 phone number from SIP/Twilio participant attributes?
UX: dashboard contacts panel vs. CLI import (CSV/vCard) vs. both?
Spoofing risk: document that caller ID can be faked; contacts = convenience not security
Should known contacts still appear on dashboard as instant PASS with reason "known contact: Dave"?
3. Escalating Scam Score for Persistent Callers
Goal: As a flagged call continues and the caller persists (repeated deflection, escalating pressure, multiple tactic hits), scam score should climb — not plateau after the first high-confidence signal.
Current gap:
flag_scam_signal: max(score, confidence) — flat if confidence ≤ current score
Moss: max(prior, ...) — prior helps but no per-turn persistence bonus
No tracking of verification attempts, deflection count, or call duration
Design questions:
Accumulation model: additive (score += conf * 0.3) vs. multiplicative vs. tiered thresholds?
Persistence signals: auto-detect repeated deflection vs. new LLM tool flag_persistence()?
Should score ever decay if caller becomes cooperative mid-call?
Dashboard: show score trajectory (sparkline) or just current value?
Auto-escalate verdict: score > 0.8 for 3 turns → force block?

Suggested Implementation Order
Phase A — Contacts fast-path     (low telephony risk, high demo value)
Phase B — Escalating score       (pure agent logic, no telephony risk)
Phase C — Call transfer on PASS  (highest telephony risk, do last with test number)
Contacts and score escalation improve the demo without touching the SIP bridge. Transfer is the riskiest piece and should be validated on a throwaway Twilio setup.

Demo Scripts (from scripts/demo_scripts.md)
Scam (~60s) → BLOCK: IRS officer, gift cards, refuses case number
Legit (~30s) → PASS: Dave confirming lunch Tuesday

Files to Read Before Coding
AGENTS.md — constraints and repo map
docs/handoff.md — telephony checklist (verify against LiveKit 1.5 docs)
phish_blocker/agent.py — all call logic lives here
phish_blocker/moss_tactics.py — scoring model to extend
LiveKit docs: inbound Twilio SIP, SIP participant attributes, call transfer

Ideation: Your Three Features
1. Transfer verified callers through
What "pass" should mean in a real product: The screener is a gate, not the destination. Today the gate opens in the dashboard but the caller never gets through.
Approach options:
Approach
Pros
Cons
A. Twilio REST <Dial> after screening
Familiar, well-documented; resident phone is just a number
Requires Twilio Call SID; may need to re-architect so Twilio stays in control of the PSTN leg
B. LiveKit SIP transfer (REFER)
Keeps everything in the LiveKit room model
Less documented; needs SIP trunk support
C. Add resident as room participant
Agent stays in room briefly for warm handoff
Resident needs SIP/phone bridge into LiveKit; more moving parts
D. Two-stage TwiML
Twilio routes to screener first, then webhook redirects to resident on PASS signal
Requires agent → Twilio callback on verdict; async coordination

Recommended for hackathon demo: Start with A or D — configure RESIDENT_PHONE in .env, add a transfer_call() function tool the agent invokes on PASS, use Twilio's API to bridge the active call. Agent says one sentence ("You check out — connecting you now"), then triggers transfer and leaves the room.
UX details to decide:
Warm transfer (agent introduces) vs. cold transfer
What happens on BLOCK — agent hangs up? plays a message? silent disconnect?
Dashboard event: type: "transfer" with status initiated | connected | failed

2. Local contacts database
What it solves: Screening every call adds latency and friction. Your mom shouldn't have to convince an AI she's your mom.
Minimal viable design:
data/contacts.json   (or SQLite)
[
 { "name": "Dave", "phone": "+15551234567", "relationship": "friend" },
 { "name": "Mom",  "phone": "+15559876543", "relationship": "family" }
]
Flow:
call_start
 → extract caller ID from SIP participant attributes (LiveKit JobContext / room participants)
 → normalize to E.164
 → lookup in contacts store
 → if match:
      set_recommendation("pass", "Known contact: Dave")
      optionally skip LLM screening entirely OR do 1-turn confirm ("Hi Dave, connecting you")
      optionally auto-transfer (depends on Feature 1)
 → if no match:
      normal screening path
Important caveats to document:
Caller ID spoofing is trivial — contacts are a convenience layer, not authentication
Some carriers send no caller ID — those always go through full screening
Consider a trusted: true flag vs. screen_lightly: true for edge cases
UX for managing contacts:
Fastest: JSON file + example in repo; user edits manually
Better demo: Dashboard sidebar "Contacts" with add/remove form
Import: python -m phish_blocker.contacts import contacts.csv

3. Escalating scam score for persistent callers
The problem today: A scammer who hits 0.85 on turn 2 and keeps pressuring for 5 more turns stays at 0.85. The dashboard looks flat even as the call gets worse.
Scoring model ideas:
Model A — Additive accumulation (simplest)
new_score = min(1.0, current + confidence * weight)
weight = 0.25 for repeat category, 0.4 for new category
Model B — Persistence multiplier
Track: deflection_count, verification_attempts, turns_since_first_signal
bonus = min(0.3, deflection_count * 0.08 + extra_signals * 0.05)
score = min(1.0, base_score + bonus)
Model C — Time pressure
If scam_score > 0.4 and call_duration > 90s: +0.1
If caller repeats payment demand after deflection: +0.15
Model D — LLM-driven persistence tool
flag_persistence(behavior: "repeated deflection" | "escalating threats" | "ignoring verification")
→ adds structured +0.1–0.2 bump with label shown on dashboard
Recommended hybrid: Extend CallState with deflection_count, signal_count, first_signal_turn. Update both flag_scam_signal and compute_scam_score to use additive bumps with a cap. Add auto-block threshold: if score >= 0.9 and deflection_count >= 2 → recommend block.
Dashboard enhancement: Emit type: "score_update" with { scam_score, delta, reason } so the gauge animates upward and chips show why it climbed ("3rd deflection +0.12").
What to avoid: Score decay mid-call — once suspicious, stay suspicious unless the caller gives verifiable proof (then maybe a small downward adjustment, but that's complex for a demo).

Suggested Build Sequence for Opus
Phase
Feature
Touch points
Risk
1
Contacts allowlist
New contacts.py, agent.py entrypoint, optional dashboard panel
Low
2
Escalating score
agent.py CallState, moss_tactics.py compute_scam_score, dashboard chips
Low
3
Transfer on PASS
agent.py new tool, Twilio API integration, .env vars, dashboard transfer status
High

Each phase should ship with a console demo path (agent console --text) before testing on real Twilio calls.

