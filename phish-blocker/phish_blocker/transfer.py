import logging
import os
import re

from livekit import rtc
from livekit.agents import JobContext

from phish_blocker import bus

logger = logging.getLogger("phish-blocker.transfer")

_HANDOFF = (
    "The caller has been verified as legitimate. Say one brief sentence that you are "
    "connecting them now and say goodbye. Do not mention scores, systems, or tools."
)


def _enabled() -> bool:
    if os.getenv("TRANSFER_ENABLED", "true").lower() in ("0", "false", "no"):
        return False
    return bool(resident_phone())


def transfer_enabled() -> bool:
    return _enabled()


def resident_phone() -> str | None:
    raw = os.getenv("RESIDENT_PHONE", "").strip()
    if not raw:
        return None
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return None
    if raw.startswith("+"):
        return f"+{digits}"
    if len(digits) == 10:
        return f"+1{digits}"
    return f"+{digits}"


async def maybe_transfer_call(
    *,
    session,
    job_ctx: JobContext | None,
    state,
    trigger: str,
) -> None:
    if state.transfer_started:
        return
    if state.recommendation != "pass":
        return
    if not _enabled():
        return
    if job_ctx is None or job_ctx.is_fake_job():
        logger.info("transfer skipped (%s: console or no job context)", trigger)
        return

    phone = resident_phone()
    if phone is None:
        return

    state.transfer_started = True
    logger.info("pass transfer starting (%s -> %s)", trigger, phone)

    await bus.push(
        {
            "type": "transfer",
            "status": "initiated",
            "to": phone,
            "reason": state.reason,
        }
    )

    try:
        handle = session.generate_reply(
            instructions=_HANDOFF,
            allow_interruptions=False,
        )
        await handle
    except Exception as e:
        logger.warning("handoff speech failed: %s", e)

    try:
        participant = await job_ctx.wait_for_participant(
            kind=rtc.ParticipantKind.PARTICIPANT_KIND_SIP,
        )
    except Exception as e:
        logger.warning("could not find SIP participant: %s", e)
        await bus.push({"type": "transfer", "status": "failed", "error": str(e)})
        state.transfer_started = False
        return

    try:
        await job_ctx.transfer_sip_participant(
            participant,
            phone,
            play_dialtone=True,
        )
    except Exception as e:
        logger.warning("SIP transfer failed: %s", e)
        await bus.push({"type": "transfer", "status": "failed", "error": str(e)})
        state.transfer_started = False
        return

    await bus.push({"type": "transfer", "status": "connected", "to": phone})
    logger.info("SIP transfer initiated for %s", participant.identity)

    try:
        session.shutdown()
    except Exception as e:
        logger.warning("session shutdown after transfer failed: %s", e)


async def transfer_contact_call(
    *,
    job_ctx: JobContext,
    participant: rtc.RemoteParticipant,
    contact_name: str,
) -> bool:
    if not _enabled():
        return False

    phone = resident_phone()
    if phone is None:
        return False

    logger.info("known-contact transfer starting (%s -> %s)", contact_name, phone)
    await bus.push(
        {
            "type": "transfer",
            "status": "initiated",
            "to": phone,
            "reason": f"Known contact: {contact_name}",
        }
    )

    try:
        await job_ctx.transfer_sip_participant(
            participant,
            phone,
            play_dialtone=True,
        )
    except Exception as e:
        logger.warning("contact SIP transfer failed: %s", e)
        await bus.push({"type": "transfer", "status": "failed", "error": str(e)})
        return False

    await bus.push({"type": "transfer", "status": "connected", "to": phone})
    logger.info("contact SIP transfer initiated for %s", participant.identity)
    return True
