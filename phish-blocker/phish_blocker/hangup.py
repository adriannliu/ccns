import asyncio
import inspect
import logging

from livekit.agents import JobContext

from phish_blocker import blocklist, bus
from phish_blocker.notify import _default_reason, min_caller_turns, should_hangup
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

    # Give the caller a few chances to justify themselves before a score-driven
    # hang-up. A forced trigger (confirmed scam tactic or confident signal) is a
    # definitive detection and ends the call immediately, bypassing this guard.
    if not force and getattr(state, "caller_turns", 0) < min_caller_turns():
        logger.info(
            "hang-up deferred (%s): caller_turns=%d < min=%d",
            trigger,
            getattr(state, "caller_turns", 0),
            min_caller_turns(),
        )
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

    await _speak_goodbye(session)

    try:
        session.shutdown()
    except Exception as e:
        logger.warning("session shutdown failed: %s", e)

    if job_ctx is not None and not job_ctx.is_fake_job():
        try:
            await job_ctx.delete_room()
        except Exception as e:
            logger.warning("delete_room failed: %s", e)


async def _speak_goodbye(session) -> None:
    """Deliver the goodbye and wait for it to fully play out before teardown.

    The realtime model may already be answering the caller's last turn, so we
    interrupt that first, then speak the goodbye and drain so the audio is not
    cut off when the room is deleted.
    """
    try:
        res = session.interrupt()
        if inspect.isawaitable(res):
            await res
    except Exception as e:
        logger.debug("interrupt before goodbye: %s", e)

    try:
        handle = session.generate_reply(
            instructions=_GOODBYE,
            allow_interruptions=False,
        )
        await handle
    except Exception as e:
        logger.warning("goodbye speech failed: %s", e)
        return

    # Let the final audio frames flush out to the caller before we hang up.
    try:
        await asyncio.wait_for(session.drain(), timeout=15)
    except Exception as e:
        logger.debug("drain after goodbye: %s", e)
