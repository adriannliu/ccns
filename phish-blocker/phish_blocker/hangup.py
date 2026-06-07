import logging

from livekit.agents import JobContext

from phish_blocker import blocklist, bus
from phish_blocker.notify import _default_reason, should_hangup
from phish_blocker.scam_handling import begin as begin_scam_handling

logger = logging.getLogger("phish-blocker.hangup")

_GOODBYE = (
    "This call cannot be connected. In one brief, polite, natural turn, say that you "
    "are ending the call, that if this is an emergency the host will reach back out, "
    "wish them a good day, and say goodbye. Do not mention scores, systems, or tools."
)


async def _record_blocklist(state) -> None:
    if getattr(state, "blocklist_recorded", False):
        return
    caller_id = getattr(state, "caller_id", None)
    entry = blocklist.record(
        caller_id,
        recommendation="block",
        reason=state.reason,
        scam_score=state.scam_score,
        signals=list(state.signals),
    )
    if entry is None:
        return
    state.blocklist_recorded = True
    await bus.push({"type": "history_entry", "entry": entry})


async def maybe_hangup_call(
    *,
    session,
    job_ctx: JobContext | None,
    state,
    trigger: str,
    send_summary,
    force: bool = False,
) -> None:
    if state.hangup_started:
        return
    if not force and not should_hangup(
        state.scam_score,
        state.recommendation,
        state.elevated_turns,
    ):
        return

    state.hangup_started = True
    logger.info(
        "auto hang-up triggered (%s score=%.2f elevated_turns=%d)",
        trigger,
        state.scam_score,
        state.elevated_turns,
    )

    if state.recommendation != "block":
        state.recommendation = "block"
        if not state.reason:
            state.reason = _default_reason(state.signals, state.scam_score)
        await bus.push(
            {
                "type": "verdict",
                "recommendation": "block",
                "reason": state.reason,
                "scam_score": state.scam_score,
            }
        )

    await begin_scam_handling(
        trigger=trigger,
        caller_id=getattr(state, "caller_id", None),
        reason=state.reason,
        scam_score=state.scam_score,
    )

    await _record_blocklist(state)
    await send_summary(trigger)

    try:
        handle = session.generate_reply(
            instructions=_GOODBYE,
            allow_interruptions=False,
        )
        await handle
    except Exception as e:
        logger.warning("goodbye speech failed: %s", e)

    try:
        session.shutdown()
    except Exception as e:
        logger.warning("session shutdown failed: %s", e)

    if job_ctx is not None and not job_ctx.is_fake_job():
        try:
            await job_ctx.delete_room()
        except Exception as e:
            logger.warning("delete_room failed: %s", e)
