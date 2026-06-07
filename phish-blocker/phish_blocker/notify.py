import logging
import os

import aiohttp

logger = logging.getLogger("phish-blocker.notify")

_TWILIO_API = "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
_SMS_MAX = 1500
_DEFAULT_THRESHOLD = 0.66


def score_threshold() -> float:
    raw = os.getenv("NOTIFY_SCORE_THRESHOLD", str(_DEFAULT_THRESHOLD))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_THRESHOLD
    return max(0.0, min(1.0, value))


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


def _infer_recommendation(scam_score: float, recommendation: str) -> str:
    if recommendation in ("block", "challenge", "pass"):
        if recommendation != "pass":
            return recommendation
    if scam_score >= 0.85:
        return "block"
    if scam_score >= score_threshold():
        return "challenge"
    return "pass"


def _default_reason(signals: list[dict], scam_score: float) -> str:
    if not signals:
        pct = round(scam_score * 100)
        return f"Call screening ended with risk score {pct}%."
    top = max(signals, key=lambda s: s.get("confidence", 0))
    label = top.get("label", "suspicious activity")
    return f"Flagged for {label} and related risk signals."


def _format_body(
    recommendation: str,
    reason: str,
    scam_score: float,
    signals: list[dict],
    trigger: str,
) -> str:
    pct = round(scam_score * 100)
    if recommendation == "block":
        title = "BLOCKED"
    elif recommendation == "challenge":
        title = "FLAGGED"
    else:
        title = "SCREENED"

    when = "during the call" if trigger == "threshold" else "after the call ended"
    lines = [
        f"Phish-Blocker: call {title} (risk {pct}%) — alert sent {when}.",
        "",
        reason.strip() or _default_reason(signals, scam_score),
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


def should_notify(
    scam_score: float,
    recommendation: str,
    signals: list[dict],
    trigger: str,
) -> bool:
    threshold = score_threshold()
    if scam_score >= threshold:
        return True
    if recommendation in ("block", "challenge"):
        return True
    if trigger == "hangup" and signals and scam_score >= threshold * 0.5:
        return True
    return False


async def send_call_summary(
    scam_score: float,
    signals: list[dict],
    recommendation: str = "pass",
    reason: str = "",
    trigger: str = "threshold",
) -> bool:
    if not should_notify(scam_score, recommendation, signals, trigger):
        return False

    if not _configured():
        return False

    rec = _infer_recommendation(scam_score, recommendation)
    summary_reason = reason.strip() or _default_reason(signals, scam_score)
    body = _format_body(rec, summary_reason, scam_score, signals, trigger)

    account_sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
    from_number = os.getenv("TWILIO_SMS_FROM", "").strip()
    to_number = os.getenv("NOTIFY_PHONE_NUMBER", "").strip()

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
                    logger.info(
                        "SMS summary sent to %s (trigger=%s score=%.2f)",
                        to_number,
                        trigger,
                        scam_score,
                    )
                    return True
                text = await resp.text()
                logger.warning(
                    "Twilio SMS failed status=%s body=%s", resp.status, text[:300]
                )
    except Exception as e:
        logger.warning("Twilio SMS error: %s", e)

    return False
