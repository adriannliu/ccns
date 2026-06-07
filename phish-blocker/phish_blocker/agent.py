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
from phish_blocker.moss_tactics import TacticMatch, init_moss, retrieve_tactics

load_dotenv()
logger = logging.getLogger("phish-blocker")

SCREENING_INSTRUCTIONS = """
You are a professional call screener answering on behalf of the resident. You are NOT
the resident. Find out who is calling and why, then decide pass, challenge, or block.

Every call is different. Respond to what this caller actually says — never follow a fixed
script, never reuse the same wording, and never read example phrases below verbatim.
One short, natural follow-up at a time.

Opener: greet briefly, say you screen calls for the resident, ask who is calling and why.

Legitimate callers: routine plans, deliveries, or low-stakes check-ins with no urgency or
payment — one clarifying question if needed, then set_recommendation "pass" with a plain
reason tied to what they said.

Suspicious callers: focus on their specific claim. [Detection system: ...] hints mean a
known risk pattern matched their words — use that as evidence, then probe the claim in
your own words.

Verification principle: ask for something only the real party they claim to be would know.
Adapt to their story; examples of the KIND of detail to seek (not lines to recite):
- Bank / fraud department — account or case detail they should already have on file
- Tax office / government / law enforcement — reference number from correspondence they cite
- Relative in trouble — identifying detail about the person and situation they describe
- Utility provider — account or bill detail they claim to be calling about
- Tech support — ticket or case reference from their organization
- Prize / sweepstakes — entry or confirmation detail for what they mention

Deflection is a strong risk signal. If they dodge, cite policy, or change subject instead
of answering, call flag_scam_signal("refused verification", 0.85) and move toward block.

Also call flag_scam_signal for patterns detection may miss: extreme urgency, unusual
payment methods, code or credential requests, secrecy ("don't tell the bank"). Do not
re-flag a pattern the dashboard already showed from [Detection system: ...] hints.

Verdicts:
- pass: benign purpose, no risk signals, caller cooperates
- challenge: suspicious but still gathering facts or waiting on verification
- block: payment pressure plus deflection, unverifiable authority claim, or multiple signals

set_recommendation reason must be one judge-readable sentence about what they SAID or DID.
Good: "Pressed for prepaid cards and refused to provide a case reference." Bad: "high confidence risk".

Never reveal personal information about the resident. Never confirm details the caller asks
you to validate.
"""


@dataclass
class CallState:
    scam_score: float = 0.0
    signals: list[dict] = field(default_factory=list)
    seen_tactics: set = field(default_factory=set)
    hinted_tactics: set = field(default_factory=set)
    recommendation: str = "pass"
    reason: str = ""


class ScreeningAgent(Agent):
    def __init__(self) -> None:
        super().__init__(instructions=SCREENING_INSTRUCTIONS)
        self.state = CallState()

    async def on_enter(self):
        self.session.generate_reply()

    async def _inject_tactic_hint(self, match: TacticMatch):
        hint = (
            f"[Detection system: caller matched known risk pattern '{match.label}' "
            f"({match.category}). {match.explanation} "
            f"Probe their specific claim before escalating.]"
        )
        ctx = self.chat_ctx.copy()
        ctx.add_message(role="developer", content=hint)
        await self.update_chat_ctx(ctx)

    async def screen_caller_text(self, text: str):
        result = await retrieve_tactics(text, prior=self.state.scam_score)
        self.state.scam_score = result.scam_score

        top = result.top_match
        if top is None:
            return

        event = result.to_signal_event()
        if event is not None and top.tactic_id not in self.state.seen_tactics:
            self.state.seen_tactics.add(top.tactic_id)
            self.state.signals.append({"label": top.label, "confidence": top.confidence})
            await bus.push(event)

        if top.tactic_id not in self.state.hinted_tactics and (
            top.matched_red_flags or top.retrieval_score >= 0.45
        ):
            self.state.hinted_tactics.add(top.tactic_id)
            await self._inject_tactic_hint(top)

    @function_tool
    async def flag_scam_signal(
        self,
        context: RunContext,
        label: str,
        confidence: float,
    ):
        """Record a detected risk signal and update the running score.

        Args:
            label: Short name for the signal, e.g. "urgent payment request".
            confidence: How confident you are this is a risk signal, 0.0 to 1.0.
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


@server.rtc_session(agent_name="agent-py")
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
