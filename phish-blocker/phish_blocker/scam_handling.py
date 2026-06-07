import logging

from phish_blocker import bus

logger = logging.getLogger("phish-blocker.scam_handling")


async def begin(
    *,
    trigger: str,
    caller_id: str | None = None,
    reason: str | None = None,
    scam_score: float = 0.0,
    repeat_caller: bool = False,
) -> None:
    """Enter scam handling after a block verdict. Extend for alerts, IVR, etc.

    call_end is emitted from agent.py shutdown / fast-path exits — not here.
    """
    logger.info(
        "scam handling started (trigger=%s caller=%s repeat=%s)",
        trigger,
        caller_id,
        repeat_caller,
    )
    await bus.push(
        {
            "type": "call_ending",
            "trigger": trigger,
            "caller_id": caller_id,
            "reason": reason,
            "scam_score": scam_score,
            "repeat_caller": repeat_caller,
        }
    )
