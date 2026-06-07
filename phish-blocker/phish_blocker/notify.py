import logging
import os

import aiohttp

logger = logging.getLogger("phish-blocker.notify")

_TWILIO_API = "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
_SMS_MAX = 1500


def _configured() -> bool:
    required = (
        "TWILIO_ACCOUNT_SID",
        "TWILIO_AUTH_TOKEN",
        "TWILIO_SMS_FROM",
        "NOTIFY_PHONE_NUMBER",
    )
    missing = [k for k in required if not os.getenv(k, "").strip()]
    if missing:
        logger.debug("SMS notify skipped; missing env: %s", ", ".join(missing))
        return False
    return True


def _format_body(
    recommendation: str,
    reason: str,
    scam_score: float,
    signals: list[dict],
) -> str:
    pct = round(scam_score * 100)
    title = "BLOCKED" if recommendation == "block" else "FLAGGED"
    lines = [
        f"Phish-Blocker: call {title} (risk {pct}%)",
        "",
        reason.strip() or "No summary provided.",
    ]
    labels = []
    for sig in signals:
        label = sig.get("label")
        if not label or label in labels:
            continue
        labels.append(label)
        conf = sig.get("confidence")
        if isinstance(conf, (int, float)):
            lines.append(f"- {label} ({round(conf * 100)}%)")
        else:
            lines.append(f"- {label}")
        if len(labels) >= 5:
            break

    body = "\n".join(lines).strip()
    if len(body) > _SMS_MAX:
        body = body[: _SMS_MAX - 1] + "…"
    return body


async def send_screening_alert(
    recommendation: str,
    reason: str,
    scam_score: float,
    signals: list[dict],
) -> bool:
    if recommendation not in ("block", "challenge"):
        return False

    notify_challenge = os.getenv("NOTIFY_ON_CHALLENGE", "").lower() in (
        "1",
        "true",
        "yes",
    )
    if recommendation == "challenge" and not notify_challenge:
        return False

    if not _configured():
        return False

    account_sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
    from_number = os.getenv("TWILIO_SMS_FROM", "").strip()
    to_number = os.getenv("NOTIFY_PHONE_NUMBER", "").strip()
    body = _format_body(recommendation, reason, scam_score, signals)

    url = _TWILIO_API.format(sid=account_sid)
    payload = {"To": to_number, "From": from_number, "Body": body}
    auth = aiohttp.BasicAuth(account_sid, auth_token)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                data=payload,
                auth=auth,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status in (200, 201):
                    logger.info("SMS alert sent to %s (%s)", to_number, recommendation)
                    return True
                text = await resp.text()
                logger.warning(
                    "Twilio SMS failed status=%s body=%s", resp.status, text[:300]
                )
    except Exception as e:
        logger.warning("Twilio SMS error: %s", e)

    return False
