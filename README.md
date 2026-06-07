# ccns

Hackathon workspace for voice-native AI agent projects.

## Projects

### [phish-blocker](./phish-blocker/)

AI call screener built on LiveKit Agents + Twilio SIP + OpenAI Realtime. Screens inbound calls for scam signals, interrogates suspicious callers, and renders a live verdict on a dashboard.

```bash
cd phish-blocker
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # fill in LiveKit + OpenAI keys
```

Run the dashboard and agent in separate terminals — see [phish-blocker/README.md](./phish-blocker/README.md) for full setup.

## Docs

- [Objection.ai venture playbook](./docs/objection-ai.md) — architecture notes for a voice-native sales simulation platform
