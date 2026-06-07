import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from phish_blocker.contacts import normalize
from phish_blocker.scam_handling import begin as begin_scam_handling

logger = logging.getLogger("phish-blocker.blocklist")

_BLOCKLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "blocklist.json"


@dataclass
class BlockedEntry:
    phone: str
    first_flagged_at: str
    last_flagged_at: str
    flag_count: int
    recommendation: str
    reason: str
    scam_score: float
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "phone": self.phone,
            "first_flagged_at": self.first_flagged_at,
            "last_flagged_at": self.last_flagged_at,
            "flag_count": self.flag_count,
            "recommendation": self.recommendation,
            "reason": self.reason,
            "scam_score": round(self.scam_score, 3),
            "signals": list(self.signals),
        }


_by_phone: dict[str, BlockedEntry] = {}
_loaded = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _signal_labels(signals: list[dict]) -> list[str]:
    labels: list[str] = []
    for sig in signals:
        label = sig.get("label")
        if not label or label in labels:
            continue
        labels.append(label)
        if len(labels) >= 5:
            break
    return labels


def _save() -> None:
    rows = sorted(
        _by_phone.values(),
        key=lambda e: e.last_flagged_at,
        reverse=True,
    )
    _BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_BLOCKLIST_PATH, "w", encoding="utf-8") as f:
        json.dump([e.to_dict() for e in rows], f, indent=2)
        f.write("\n")


def load_blocklist(path: Path | str | None = None) -> dict[str, BlockedEntry]:
    global _by_phone, _loaded
    blocklist_path = Path(path) if path is not None else _BLOCKLIST_PATH

    by_phone: dict[str, BlockedEntry] = {}
    try:
        with open(blocklist_path, encoding="utf-8") as f:
            rows = json.load(f)
    except FileNotFoundError:
        logger.info("blocklist file not found: %s (starting empty)", blocklist_path)
        rows = []
    except json.JSONDecodeError as e:
        logger.warning("blocklist JSON invalid: %s", e)
        rows = []

    for row in rows:
        key = normalize(row.get("phone"))
        if key is None:
            continue
        by_phone[key] = BlockedEntry(
            phone=key,
            first_flagged_at=row.get("first_flagged_at") or _now_iso(),
            last_flagged_at=row.get("last_flagged_at") or _now_iso(),
            flag_count=max(1, int(row.get("flag_count") or 1)),
            recommendation=row.get("recommendation") or "block",
            reason=row.get("reason") or "Flagged as suspicious.",
            scam_score=float(row.get("scam_score") or 0.0),
            signals=list(row.get("signals") or []),
        )

    _by_phone = by_phone
    _loaded = True
    logger.info("Loaded %d blocked numbers from %s", len(by_phone), blocklist_path)
    return by_phone


def lookup(number: str | None) -> BlockedEntry | None:
    if not _loaded:
        load_blocklist()
    key = normalize(number)
    if key is None:
        return None
    return _by_phone.get(key)


def list_history() -> list[dict]:
    if not _loaded:
        load_blocklist()
    rows = sorted(_by_phone.values(), key=lambda e: e.last_flagged_at, reverse=True)
    return [e.to_dict() for e in rows]


def remove(number: str | None) -> dict | None:
    key = normalize(number)
    if key is None:
        return None
    if not _loaded:
        load_blocklist()
    entry = _by_phone.pop(key, None)
    if entry is None:
        return None
    _save()
    logger.info("blocklist removed %s", key)
    return entry.to_dict()


def record(
    number: str | None,
    *,
    recommendation: str,
    reason: str,
    scam_score: float,
    signals: list[dict] | None = None,
) -> dict | None:
    if recommendation not in ("block", "challenge"):
        return None

    key = normalize(number)
    if key is None:
        logger.warning("blocklist record skipped: no caller phone")
        return None

    if not _loaded:
        load_blocklist()

    now = _now_iso()
    labels = _signal_labels(signals or [])
    clean_reason = reason.strip() or "Flagged as suspicious."

    existing = _by_phone.get(key)
    if existing is None:
        entry = BlockedEntry(
            phone=key,
            first_flagged_at=now,
            last_flagged_at=now,
            flag_count=1,
            recommendation=recommendation,
            reason=clean_reason,
            scam_score=scam_score,
            signals=labels,
        )
    else:
        entry = BlockedEntry(
            phone=key,
            first_flagged_at=existing.first_flagged_at,
            last_flagged_at=now,
            flag_count=existing.flag_count + 1,
            recommendation=recommendation,
            reason=clean_reason,
            scam_score=max(existing.scam_score, scam_score),
            signals=labels or existing.signals,
        )

    _by_phone[key] = entry
    _save()
    logger.info(
        "blocklist recorded %s (%s, count=%d)",
        key,
        recommendation,
        entry.flag_count,
    )
    return entry.to_dict()


async def reject_repeat_caller(job_ctx, participant, entry: BlockedEntry) -> bool:
    from phish_blocker import bus

    reason = f"Previously flagged: {entry.reason}"
    logger.info("blocklist fast-path BLOCK %s (flag_count=%d)", entry.phone, entry.flag_count)

    await bus.push(
        {
            "type": "call_start",
            "caller_id": entry.phone,
            "blocklist_hit": True,
        }
    )
    await bus.push(
        {
            "type": "verdict",
            "recommendation": "block",
            "reason": reason,
            "scam_score": entry.scam_score,
        }
    )

    await begin_scam_handling(
        trigger="repeat_caller",
        caller_id=entry.phone,
        reason=reason,
        scam_score=entry.scam_score,
        repeat_caller=True,
    )

    updated = record(
        entry.phone,
        recommendation="block",
        reason=reason,
        scam_score=entry.scam_score,
        signals=[{"label": s} for s in entry.signals],
    )
    if updated is not None:
        await bus.push({"type": "history_entry", "entry": updated})

    try:
        await job_ctx.delete_room()
    except Exception as e:
        logger.warning("blocklist reject delete_room failed: %s", e)
        return False

    return True


if __name__ == "__main__":
    import sys

    load_blocklist()
    entries = list_history()
    print(f"Loaded {len(entries)} flagged numbers from {_BLOCKLIST_PATH}")
    for e in entries:
        print(f"  {e['phone']}  {e['recommendation']}  {e['reason'][:60]}")

    if len(sys.argv) > 1:
        q = sys.argv[1]
        print(f"lookup({q!r}) -> {lookup(q)}")
