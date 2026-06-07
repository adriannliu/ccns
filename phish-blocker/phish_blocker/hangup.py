import logging

from livekit.agents import JobContext

from phish_blocker import bus
from phish_blocker.notify import _default_reason, should_hangup

logger = logging.getLogger("phish-blocker.hangup")

_GOODBYE = (
    "This call cannot be connected. Say one brief polite sentence that you are "
    "ending the call and say goodbye. Do not mention scores, systems, or tools."
)


async def maybe_hangup_call(
    *,
    session,
    job_ctx: JobContext | None,
    state,
    trigger: str,
    send_summary,
) -> None:
    if state.hangup_started:
        return
    if not should_hangup(
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
