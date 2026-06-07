import asyncio
import logging
import os
from dataclasses import dataclass, field

from dotenv import load_dotenv
from livekit.agents import (
    Agent,
    AgentServer,
    AgentSession,
    JobContext,
    RunContext,
    cli,
    function_tool,
)
from livekit.plugins import aws, silero

from phish_blocker import bus
from phish_blocker.moss_tactics import init_moss, retrieve_tactics

load_dotenv()
logger = logging.getLogger("phish-blocker")

SCREENING_INSTRUCTIONS = """
You are an AI call screener answering on behalf of the user. You are NOT the user.
Your job: find out who is calling and what they want, then decide whether the call
is safe to pass through or whether it is a likely scam.

Behavior:
- Open politely: greet, say you are screening calls for the user, ask who is calling
  and what it is regarding. Keep turns short and natural, like a real assistant.
- Listen for scam signals: urgency or time pressure, authority impersonation (IRS,
  bank, police, a relative in trouble), demands for payment via gift cards, wire,
  crypto, or one-time codes, requests for passwords or account numbers, and refusal
  to identify themselves or verify who they are.
- Whenever you notice such a signal, call flag_scam_signal with a short label and your
  confidence. Call it every time a new signal appears.
- If the caller seems suspicious, INTERROGATE: ask a specific verification question a
  legitimate caller could answer instantly but a scammer cannot (for example, the last
  four digits of the account they claim to be calling about, or a detail only the real
  party would know). Note in your reasoning whether they answer or deflect.
- Once you are confident, call set_recommendation with "pass", "challenge", or "block"
  and a one-sentence reason.
- Never reveal personal information about the user. Never confirm details the caller
  is trying to fish for. If they push for sensitive info, that itself is a strong signal.
"""


@dataclass
class CallState:
    scam_score: float = 0.0
    signals: list[dict] = field(default_factory=list)
    seen_tactics: set = field(default_factory=set)
    recommendation: str = "pass"
    reason: str = ""


class ScreeningAgent(Agent):
    def __init__(self) -> None:
        super().__init__(instructions=SCREENING_INSTRUCTIONS)
        self.state = CallState()

    async def on_enter(self):
        self.session.generate_reply()

    async def screen_caller_text(self, text: str):
        result = await retrieve_tactics(text, prior=self.state.scam_score)
        self.state.scam_score = result.scam_score

        event = result.to_signal_event()
        if event is None:
            return

        top = result.top_match
        if top.tactic_id in self.state.seen_tactics:
            return
        self.state.seen_tactics.add(top.tactic_id)
        self.state.signals.append({"label": top.label, "confidence": top.confidence})
        await bus.push(event)

    @function_tool
    async def flag_scam_signal(
        self,
        context: RunContext,
        label: str,
        confidence: float,
    ):
        """Record a detected scam signal and update the running score.

        Args:
            label: Short name for the signal, e.g. "gift card payment demand".
            confidence: How confident you are this is a scam signal, 0.0 to 1.0.
        """
        confidence = max(0.0, min(1.0, confidence))
        self.state.signals.append({"label": label, "confidence": confidence})
        self.state.scam_score = min(1.0, max(self.state.scam_score, confidence))
        await bus.push(
            {
                "type": "signal",
                "label": label,
                "confidence": confidence,
                "scam_score": self.state.scam_score,
            }
        )
        return {"ok": True, "scam_score": self.state.scam_score}

    @function_tool
    async def set_recommendation(
        self,
        context: RunContext,
        recommendation: str,
        reason: str,
    ):
        """Set the final verdict for the call.

        Args:
            recommendation: One of "pass", "challenge", or "block".
            reason: One short sentence explaining the verdict.
        """
        if recommendation not in ("pass", "challenge", "block"):
            recommendation = "challenge"
        self.state.recommendation = recommendation
        self.state.reason = reason
        await bus.push(
            {
                "type": "verdict",
                "recommendation": recommendation,
                "reason": reason,
                "scam_score": self.state.scam_score,
            }
        )
        return {"ok": True}


server = AgentServer()


@server.rtc_session()
async def entrypoint(ctx: JobContext):
    agent = ScreeningAgent()

    await init_moss()

    region = os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION")
    llm_kwargs = {
        "voice": "matthew",
        "turn_detection": "MEDIUM",
        "tool_choice": "auto",
    }
    if region:
        llm_kwargs["region"] = region

    session = AgentSession(
        vad=silero.VAD.load(),
        llm=aws.realtime.RealtimeModel.with_nova_sonic_2(**llm_kwargs),
    )

    @session.on("conversation_item_added")
    def _on_item(ev):
        item = ev.item
        text = getattr(item, "text_content", None) or ""
        if not text:
            return
        role = "agent" if item.role == "assistant" else "caller"
        asyncio.create_task(
            bus.push({"type": "transcript", "role": role, "text": text})
        )
        if role == "caller":
            asyncio.create_task(agent.screen_caller_text(text))

    await bus.push({"type": "call_start"})
    await session.start(agent=agent, room=ctx.room)


if __name__ == "__main__":
    cli.run_app(server)
