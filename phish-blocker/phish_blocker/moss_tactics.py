import logging
import os
import re
import time
from dataclasses import dataclass

from phish_blocker.corpus import Tactic, load_tactics

logger = logging.getLogger("phish-blocker.moss")

DEFAULT_INDEX = os.getenv("MOSS_INDEX_NAME", "scam-tactics")
DEFAULT_MODEL = os.getenv("MOSS_MODEL_ID", "moss-minilm")
DEFAULT_ALPHA = 0.6
DEFAULT_TOP_K = 5

SEM_THRESHOLD = 0.45
SEVERITY_FLOOR = 0.6
KEYWORD_FULL_CONF_AT = 2
CORROBORATION_PER_CATEGORY = 0.05
CORROBORATION_CAP = 0.15

_STOPWORDS = {
    "the", "a", "an", "your", "you", "to", "of", "and", "or", "is", "are",
    "in", "on", "for", "me", "my", "i", "it", "they", "them", "this", "that",
    "with", "be", "will", "we", "us", "up", "do", "if", "so", "no", "by", "at",
}


@dataclass
class TacticMatch:
    tactic_id: str
    label: str
    category: str
    subcategory: str
    retrieval_score: float
    severity: float
    matched_red_flags: list[str]
    source: str
    text: str
    confidence: float
    explanation: str


@dataclass
class RetrievalResult:
    query: str
    matches: list[TacticMatch]
    scam_score: float
    latency_ms: float
    prior: float = 0.0

    @property
    def top_match(self) -> TacticMatch | None:
        return self.matches[0] if self.matches else None

    def to_signal_event(self) -> dict | None:
        top = self.top_match
        if top is None:
            return None
        return {
            "type": "signal",
            "label": top.label,
            "confidence": round(top.confidence, 3),
            "scam_score": round(self.scam_score, 3),
            "tactic_id": top.tactic_id,
            "explanation": top.explanation,
        }


_client = None
_tactics_by_id: dict[str, Tactic] = {}


def _tokenize(text: str) -> set[str]:
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    return {t for t in tokens if t not in _STOPWORDS and len(t) > 1}


def matched_red_flags(caller_text: str, red_flags: list[str]) -> list[str]:
    lowered = caller_text.lower()
    caller_tokens = _tokenize(caller_text)
    hits = []
    for phrase in red_flags:
        phrase_lower = phrase.lower()
        if phrase_lower in lowered:
            hits.append(phrase)
            continue
        sig_tokens = _tokenize(phrase)
        if sig_tokens and len(sig_tokens & caller_tokens) / len(sig_tokens) >= 0.6:
            hits.append(phrase)
    return hits


def _build_match(caller_text: str, tactic: Tactic, retrieval_score: float) -> TacticMatch:
    hits = matched_red_flags(caller_text, tactic.red_flags)
    keyword_conf = min(1.0, len(hits) / KEYWORD_FULL_CONF_AT)
    confidence = tactic.severity * (SEVERITY_FLOOR + (1.0 - SEVERITY_FLOOR) * keyword_conf)

    if hits:
        flags = ", ".join(f'"{h}"' for h in hits)
        explanation = (
            f"Matched known scam tactic '{tactic.label}' ({tactic.source}); "
            f"caller used red-flag phrasing: {flags}."
        )
    else:
        explanation = (
            f"Semantically resembles known scam tactic '{tactic.label}' "
            f"({tactic.source}), but no explicit red-flag phrasing detected."
        )

    return TacticMatch(
        tactic_id=tactic.id,
        label=tactic.label,
        category=tactic.category,
        subcategory=tactic.subcategory,
        retrieval_score=round(retrieval_score, 4),
        severity=tactic.severity,
        matched_red_flags=hits,
        source=tactic.source,
        text=tactic.text,
        confidence=round(confidence, 4),
        explanation=explanation,
    )


def compute_scam_score(matches: list[TacticMatch], prior: float = 0.0) -> float:
    confirmed = [
        m for m in matches
        if m.matched_red_flags and m.retrieval_score >= SEM_THRESHOLD
    ]
    if not confirmed:
        return prior

    best = max(confirmed, key=lambda m: m.confidence)
    distinct_categories = {m.category for m in confirmed}
    corroboration = min(
        CORROBORATION_CAP,
        CORROBORATION_PER_CATEGORY * (len(distinct_categories) - 1),
    )
    return min(1.0, max(prior, best.confidence + corroboration))


async def init_moss(index: str | None = None, model_id: str | None = None) -> bool:
    global _client, _tactics_by_id

    _tactics_by_id = {t.id: t for t in load_tactics()}

    project_id = os.getenv("MOSS_PROJECT_ID")
    project_key = os.getenv("MOSS_PROJECT_KEY")
    if not project_id or not project_key:
        logger.warning("MOSS_PROJECT_ID/MOSS_PROJECT_KEY not set; retrieval disabled.")
        return False

    try:
        from moss import MossClient
    except ImportError:
        logger.warning("moss SDK not installed; retrieval disabled.")
        return False

    index_name = index or DEFAULT_INDEX
    try:
        _client = MossClient(project_id, project_key)
        await _client.load_index(index_name)
    except Exception as e:
        logger.warning("Failed to load Moss index '%s': %s", index_name, e)
        _client = None
        return False

    logger.info("Moss ready: index '%s', %d tactics", index_name, len(_tactics_by_id))
    return True


async def retrieve_tactics(
    caller_text: str,
    prior: float = 0.0,
    top_k: int = DEFAULT_TOP_K,
    alpha: float = DEFAULT_ALPHA,
    index: str | None = None,
) -> RetrievalResult:
    if not caller_text or not caller_text.strip():
        return RetrievalResult(caller_text, [], prior, 0.0, prior)

    if _client is None:
        return RetrievalResult(caller_text, [], prior, 0.0, prior)

    from moss import QueryOptions

    index_name = index or DEFAULT_INDEX
    start = time.perf_counter()
    try:
        results = await _client.query(
            index_name, caller_text, QueryOptions(top_k=top_k, alpha=alpha)
        )
    except Exception as e:
        logger.warning("Moss query failed: %s", e)
        return RetrievalResult(caller_text, [], prior, 0.0, prior)
    latency_ms = (time.perf_counter() - start) * 1000.0

    matches: list[TacticMatch] = []
    for doc in results.docs:
        tactic = _tactics_by_id.get(doc.id)
        if tactic is None:
            continue
        matches.append(_build_match(caller_text, tactic, doc.score))

    matches.sort(key=lambda m: m.confidence, reverse=True)
    scam_score = compute_scam_score(matches, prior)

    return RetrievalResult(
        query=caller_text,
        matches=matches,
        scam_score=scam_score,
        latency_ms=latency_ms,
        prior=prior,
    )
