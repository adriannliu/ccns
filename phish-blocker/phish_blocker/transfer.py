import asyncio
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


def _pstn_domain() -> str | None:
    raw = os.getenv("TWILIO_PSTN_DOMAIN", "").strip()
    if not raw:
        return None
    return raw.removeprefix("sip:").split(";")[0]


def transfer_attempts(phone: str) -> list[tuple[str, bool]]:
    attempts: list[tuple[str, bool]] = [
        (f"tel:{phone}", True),
        (phone, True),
        (f"tel:{phone}", False),
        (phone, False),
    ]
    domain = _pstn_domain()
    if domain:
        sip_targets = [
            f"sip:{phone}@{domain};transport=udp",
            f"sip:{phone}@{domain}",
        ]
        for target in sip_targets:
            attempts.append((target, True))
            attempts.append((target, False))
    return attempts


def _failure_hint() -> str:
    if _pstn_domain():
        return (
            "On Twilio: Elastic SIP Trunk → enable Call Transfers and PSTN transfers."
        )
    return (
        "Twilio usually needs a Termination domain: trunk → Termination → set a SIP "
        "domain (yields name.pstn.twilio.com), add TWILIO_PSTN_DOMAIN to .env, and "
        "enable Call Transfers + PSTN transfers on the trunk."
    )


def _caller_participant(job_ctx: JobContext) -> rtc.RemoteParticipant | None:
    for participant in job_ctx.room.remote_participants.values():
        if participant.kind == rtc.ParticipantKind.PARTICIPANT_KIND_SIP:
            return participant
    return None


async def _ensure_call_active(
    job_ctx: JobContext,
    participant: rtc.RemoteParticipant,
    timeout: float = 10.0,
) -> bool:
    # transfer_sip_participant (SIP REFER) is rejected with "can't transfer non
    # established call" until sip.callStatus is "active". The screening path makes
    # the call active implicitly when AgentSession publishes audio; the contact
    # fast-path has no session, so it must answer the call here first.
    if participant.attributes.get("sip.callStatus") == "active":
        return True

    await job_ctx.connect()

    try:
        source = rtc.AudioSource(24000, 1)
        track = rtc.LocalAudioTrack.create_audio_track("transfer-answer", source)
        options = rtc.TrackPublishOptions(source=rtc.TrackSource.SOURCE_MICROPHONE)
        await job_ctx.room.local_participant.publish_track(track, options)
    except Exception as e:
        logger.warning("answer publish_track failed: %s", e)

    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if participant.attributes.get("sip.callStatus") == "active":
            return True
        await asyncio.sleep(0.1)

    logger.warning(
        "SIP call not active before transfer (status=%s)",
        participant.attributes.get("sip.callStatus"),
    )
    return False


async def _cold_transfer(
    job_ctx: JobContext,
    participant: rtc.RemoteParticipant,
    phone: str,
) -> tuple[str | None, list[str]]:
    errors: list[str] = []
    attrs = dict(participant.attributes)
    logger.info(
        "cold transfer participant=%s attrs=%s targets=%s",
        participant.identity,
        attrs,
        [t for t, _ in transfer_attempts(phone)],
    )

    for target, play_dialtone in transfer_attempts(phone):
        try:
            await job_ctx.transfer_sip_participant(
                participant,
                target,
                play_dialtone=play_dialtone,
            )
            logger.info(
                "cold transfer ok for %s via %s (dialtone=%s)",
                participant.identity,
                target,
                play_dialtone,
            )
            return target, errors
        except Exception as e:
            msg = f"{target} dialtone={play_dialtone}: {e}"
            errors.append(msg)
            logger.warning("cold transfer attempt failed (%s)", msg)

    if errors:
        logger.warning("all cold transfer attempts failed: %s", "; ".join(errors))
    return None, errors


def _format_failure(errors: list[str]) -> str:
    detail = errors[-1] if errors else "unknown error"
    if len(errors) > 1:
        detail = f"{detail} (+{len(errors) - 1} other attempts)"
    return f"{detail}. {_failure_hint()}"


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
    logger.info("pass cold transfer starting (%s -> %s)", trigger, phone)

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

    participant = _caller_participant(job_ctx)
    if participant is None:
        try:
            participant = await job_ctx.wait_for_participant(
                kind=rtc.ParticipantKind.PARTICIPANT_KIND_SIP,
            )
        except Exception as e:
            logger.warning("could not find SIP participant: %s", e)
            await bus.push({"type": "transfer", "status": "failed", "error": str(e)})
            state.transfer_started = False
            return

    target, errors = await _cold_transfer(job_ctx, participant, phone)
    if target is None:
        await bus.push(
            {
                "type": "transfer",
                "status": "failed",
                "error": _format_failure(errors),
                "attempts": errors,
            }
        )
        state.transfer_started = False
        return

    await bus.push(
        {
            "type": "transfer",
            "status": "connected",
            "to": phone,
            "via": target,
        }
    )

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

    logger.info("known-contact cold transfer (%s -> %s)", contact_name, phone)
    await bus.push(
        {
            "type": "transfer",
            "status": "initiated",
            "to": phone,
            "reason": f"Known contact: {contact_name}",
        }
    )

    await _ensure_call_active(job_ctx, participant)

    target, errors = await _cold_transfer(job_ctx, participant, phone)
    if target is None:
        await bus.push(
            {
                "type": "transfer",
                "status": "failed",
                "error": _format_failure(errors),
                "attempts": errors,
            }
        )
        return False

    await bus.push(
        {
            "type": "transfer",
            "status": "connected",
            "to": phone,
            "via": target,
        }
    )
    return True
