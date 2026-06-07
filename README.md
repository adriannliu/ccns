# ccns

Hackathon workspace for voice-native AI agent projects.

## Projects

### [phish-blocker](./phish-blocker/)

AI call screener: LiveKit Agents + Twilio SIP + AWS Nova Sonic. Screens inbound calls for scam intent (conversation only), cold-transfers verified callers, maintains a local blocklist with History tab, and auto-rejects repeat flagged numbers.

```bash
cd phish-blocker
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # LiveKit + AWS + Moss + RESIDENT_PHONE
```

Run the dashboard and agent in separate terminals — see [phish-blocker/README.md](./phish-blocker/README.md) for full setup.

## Docs

- [Phish-Blocker agent handoff](./docs/handoff.md) — full implementer spec for coding agents
- [Objection.ai venture playbook](./docs/objection-ai.md) — separate venture notes, not phish-blocker code
