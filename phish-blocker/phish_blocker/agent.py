import asyncio
import logging
import os
from dataclasses import dataclass, field

from dotenv import load_dotenv
from livekit import rtc
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

from phish_blocker import blocklist, bus, contacts
from phish_blocker.moss_tactics import init_moss, retrieve_tactics
from phish_blocker.hangup import maybe_hangup_call
from phish_blocker.notify import hangup_threshold, send_call_summary
from phish_blocker.transfer import (
    maybe_transfer_call,
    transfer_contact_call,
    transfer_enabled,
)

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

Suspicious callers: focus on their specific claim and probe it in your own words.

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

Also call flag_scam_signal for patterns you notice: extreme urgency, unusual payment
methods, code or credential requests, secrecy ("don't tell the bank").

Verdicts:
- pass: benign purpose, no risk signals, caller cooperates — they will be connected to the resident
- challenge: suspicious but still gathering facts or waiting on verification
- block: payment pressure plus deflection, unverifiable authority claim, or multiple signals

set_recommendation reason must be one judge-readable sentence about what they SAID or DID.
Good: "Pressed for prepaid cards and refused to provide a case reference." Bad: "high confidence risk".

Never reveal personal information about the resident. Never confirm details the caller asks
you to validate.

Voice output (critical):
- You are on a phone call. Speak in plain conversational sentences only.
- Never read JSON, code, markdown, bracketed notes, bullet lists, or tool output aloud.
- Never mention detection systems, tactic IDs, scores, or internal notes to the caller.
- Keep each reply to one or two short sentences.
"""


@dataclass
class CallState:
    scam_score: float = 0.0
    signals: list[dict] = field(default_factory=list)
    seen_tactics: set = field(default_factory=set)
    recommendation: str = "pass"
    reason: str = ""
    caller_id: str | None = None
    alert_sent: bool = False
    hangup_started: bool = False
    elevated_turns: int = 0
    transfer_started: bool = False
    blocklist_recorded: bool = False


class ScreeningAgent(Agent):
    def __init__(self, job_ctx: JobContext | None = None, caller_id: str | None = None) -> None:
        super().__init__(instructions=SCREENING_INSTRUCTIONS)
        self.state = CallState(caller_id=caller_id)
        self._job_ctx = job_ctx

    async def on_enter(self):
        self.session.generate_reply()

    async def maybe_send_summary(self, trigger: str):
        if self.state.alert_sent:
            return
        sent = await send_call_summary(
            scam_score=self.state.scam_score,
            signals=list(self.state.signals),
            recommendation=self.state.recommendation,
            reason=self.state.reason,
            trigger=trigger,
        )
        if sent:
            self.state.alert_sent = True

    async def _record_flagged(self):
        if self.state.blocklist_recorded:
            return
        entry = blocklist.record(
            self.state.caller_id,
            recommendation=self.state.recommendation,
            reason=self.state.reason,
            scam_score=self.state.scam_score,
            signals=list(self.state.signals),
        )
        if entry is None:
            return
        self.state.blocklist_recorded = True
        await bus.push({"type": "history_entry", "entry": entry})

    async def maybe_hangup(self, trigger: str):
        await maybe_hangup_call(
            session=self.session,
            job_ctx=self._job_ctx,
            state=self.state,
            trigger=trigger,
            send_summary=self.maybe_send_summary,
        )

    def _track_elevated_turn(self):
        if self.state.scam_score >= hangup_threshold():
            self.state.elevated_turns += 1
        else:
            self.state.elevated_turns = 0

    async def maybe_transfer(self, trigger: str):
        await maybe_transfer_call(
            session=self.session,
            job_ctx=self._job_ctx,
            state=self.state,
            trigger=trigger,
        )

    async def screen_caller_text(self, text: str):
        prior = self.state.scam_score
        result = await retrieve_tactics(text, prior=prior)
        self.state.scam_score = result.scam_score
        self._track_elevated_turn()

        top = result.top_match
        if top is not None:
            event = result.to_signal_event()
            if event is not None and top.tactic_id not in self.state.seen_tactics:
                self.state.seen_tactics.add(top.tactic_id)
                self.state.signals.append(
                    {"label": top.label, "confidence": top.confidence}
                )
                await bus.push(event)

        await self.maybe_hangup("threshold")

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
        await self.maybe_hangup("threshold")
        return "Recorded."

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

        if recommendation == "block":
            await self.maybe_hangup("threshold")
        elif recommendation == "challenge":
            await self._record_flagged()
            await self.maybe_send_summary("threshold")
        elif recommendation == "pass":
            await self.maybe_transfer("threshold")
        else:
            await self.maybe_send_summary("threshold")
        return "Verdict set."


server = AgentServer()


async def _wait_sip_participant(ctx: JobContext) -> rtc.RemoteParticipant | None:
    if ctx.is_fake_job():
        return None
    try:
        return await ctx.wait_for_participant(
            kind=rtc.ParticipantKind.PARTICIPANT_KIND_SIP,
        )
    except Exception as e:
        logger.warning("no SIP participant: %s", e)
        return None


def _caller_id(participant: rtc.RemoteParticipant | None) -> str | None:
    if participant is None:
        return None
    return participant.attributes.get("sip.phoneNumber")


async def _try_contact_fastpath(
    ctx: JobContext,
    participant: rtc.RemoteParticipant,
) -> bool:
    if not transfer_enabled():
        return False

    number = _caller_id(participant)
    contact = contacts.lookup(number)
    if contact is None:
        return False

    logger.info("known contact %s (%s); fast-path PASS + transfer", contact.name, number)
    await bus.push({"type": "call_start", "caller_id": number, "contact": contact.name})
    await bus.push(
        {
            "type": "verdict",
            "recommendation": "pass",
            "reason": f"Known contact: {contact.name}",
            "scam_score": 0.0,
        }
    )

    await transfer_contact_call(
        job_ctx=ctx,
        participant=participant,
        contact_name=contact.name,
    )
    return True


async def _try_blocklist_fastpath(
    ctx: JobContext,
    participant: rtc.RemoteParticipant,
) -> bool:
    number = _caller_id(participant)
    entry = blocklist.lookup(number)
    if entry is None:
        return False

    return await blocklist.reject_repeat_caller(ctx, participant, entry)


@server.rtc_session(agent_name="agent-py")
async def entrypoint(ctx: JobContext):
    await init_moss()

    participant = await _wait_sip_participant(ctx)
    caller_id = _caller_id(participant)

    if participant is not None and await _try_contact_fastpath(ctx, participant):
        return
    if participant is not None and await _try_blocklist_fastpath(ctx, participant):
        return

    agent = ScreeningAgent(job_ctx=ctx, caller_id=caller_id)

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

    async def _on_call_end():
        await agent.maybe_send_summary("hangup")

    ctx.add_shutdown_callback(_on_call_end)

    await bus.push({"type": "call_start", "caller_id": caller_id})
    await session.start(agent=agent, room=ctx.room)


if __name__ == "__main__":
    cli.run_app(server)
