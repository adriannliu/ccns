import logging
import os

logger = logging.getLogger("phish-blocker.notify")

_DEFAULT_THRESHOLD = 0.66
_DEFAULT_HANGUP_EXCHANGES = 2
# Caller turns that must elapse before ANY score-driven hang-up. Gives the caller
# a few chances to justify themselves before detection can end the call.
_DEFAULT_MIN_CALLER_TURNS = 3
# Hard ceiling on interrogation length. Once the caller has had this many genuine
# exchanges, the screener stops asking questions and commits to a verdict — block
# (hang up) if the running score is at/above the hang-up threshold, otherwise pass
# (forward). Keeps calls short instead of letting the screener probe indefinitely.
_DEFAULT_DECISION_CAP = 2


def _parse_threshold(raw: str | None, fallback: float) -> float:
    if not raw:
        return fallback
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return fallback
    return max(0.0, min(1.0, value))


def score_threshold() -> float:
    return _parse_threshold(
        os.getenv("NOTIFY_SCORE_THRESHOLD"),
        _DEFAULT_THRESHOLD,
    )


def hangup_threshold() -> float:
    return _parse_threshold(
        os.getenv("HANGUP_SCORE_THRESHOLD"),
        score_threshold(),
    )


def hangup_exchanges_required() -> int:
    raw = os.getenv("HANGUP_EXCHANGES_REQUIRED")
    if not raw:
        return _DEFAULT_HANGUP_EXCHANGES
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return _DEFAULT_HANGUP_EXCHANGES


def min_caller_turns() -> int:
    raw = os.getenv("HANGUP_MIN_CALLER_TURNS")
    if not raw:
        return _DEFAULT_MIN_CALLER_TURNS
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return _DEFAULT_MIN_CALLER_TURNS


def decision_cap() -> int:
    raw = os.getenv("DECISION_MAX_EXCHANGES")
    if not raw:
        return _DEFAULT_DECISION_CAP
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return _DEFAULT_DECISION_CAP


def should_hangup(
    scam_score: float,
    recommendation: str,
    elevated_turns: int,
) -> bool:
    if recommendation == "block":
        return True
    # An explicit "pass" is the screener's judgement that the caller is legitimate;
    # the score heuristic must never override it and tear down a call that is about
    # to be connected.
    if recommendation == "pass":
        return False
    return (
        scam_score >= hangup_threshold()
        and elevated_turns >= hangup_exchanges_required()
    )


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


def _format_summary(
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
        f"PhishBowl: call {title} (risk {pct}%) — summary {when}",
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

    return "\n".join(lines).strip()


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

    rec = _infer_recommendation(scam_score, recommendation)
    summary_reason = reason.strip() or _default_reason(signals, scam_score)
    body = _format_summary(rec, summary_reason, scam_score, signals, trigger)

    banner = "=" * 60
    print(f"\n{banner}\n{body}\n{banner}\n", flush=True)
    logger.info("call summary printed to console (trigger=%s score=%.2f)", trigger, scam_score)
    return True
