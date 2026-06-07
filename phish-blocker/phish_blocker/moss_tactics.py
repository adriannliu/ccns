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

def _env_float(name: str, fallback: float, lo: float = 0.0, hi: float = 1.0) -> float:
    raw = os.getenv(name)
    if not raw:
        return fallback
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return fallback
    return max(lo, min(hi, value))


# Semantic relevance (Moss retrieval score) drives the score. Below SEM_THRESHOLD a
# tactic is treated as irrelevant; at/above SEM_FULL_RELEVANCE it counts as a full match.
# The ramp between maps raw retrieval scores onto a 0..1 relevance weight. Both are
# tunable via env to match the scale your Moss index returns.
SEM_THRESHOLD = _env_float("MOSS_SEM_THRESHOLD", 0.45)
SEM_FULL_RELEVANCE = _env_float("MOSS_SEM_FULL_RELEVANCE", 0.75)
# Guard against an inverted or degenerate ramp (floor must sit below the ceiling).
if SEM_FULL_RELEVANCE <= SEM_THRESHOLD:
    SEM_FULL_RELEVANCE = min(1.0, SEM_THRESHOLD + 0.01)
# Explicit red-flag phrasing corroborates a semantic match but is never required.
KEYWORD_FULL_CONF_AT = 2
KEYWORD_BONUS = _env_float("MOSS_KEYWORD_BONUS", 0.15)
CORROBORATION_PER_CATEGORY = 0.05
CORROBORATION_CAP = 0.15

# A single caller turn that merely touches a scam topic (e.g. saying "gift card")
# is suspicion, not proof — a legit caller can mention the same topic. Cap how far
# one turn of passive retrieval can move the score so it lands in the "suspicious"
# band, never instantly "critical". Real scams reveal themselves over multiple
# turns (payment demand + deflection + urgency), which then accumulate past the cap.
SEM_TURN_CAP = _env_float("MOSS_SEM_TURN_CAP", 0.45)

# Semantic relevance alone (the caller talks about a bank, a delivery, money) is
# topic-adjacency, not evidence of a scam — a legitimate caller hits the same
# tactics. Without the caller's own red-flag phrasing, cap the *accumulated* score
# here so it stays in the "suspicious" band: below the hang-up threshold and below
# the dashboard's HIGH/CRITICAL levels. Literal red-flag phrasing, multiple turns
# of it, or an explicit flag_scam_signal are what escalate past this ceiling.
PASSIVE_SCORE_CEILING = _env_float("MOSS_PASSIVE_SCORE_CEILING", 0.45)

# Moss returns a nearest neighbour for ANY query, so unrelated chatter (a basketball
# game) still scores above SEM_THRESHOLD against some tactic and would otherwise show
# up as a spurious "risk factor". A semantic-only match (the caller used NONE of the
# tactic's red-flag phrasing) must clear this much-higher relevance bar before it is
# treated as evidence at all; below it the match is dropped as noise — no signal chip,
# no score movement. Real red-flag phrasing bypasses this gate entirely.
SEM_SIGNAL_RELEVANCE = _env_float("MOSS_SEM_SIGNAL_RELEVANCE", 0.6)

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
        if top is None or top.confidence <= 0.0:
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


def _semantic_relevance(retrieval_score: float) -> float:
    """Map a raw Moss retrieval score onto a 0..1 relevance weight."""
    if retrieval_score <= SEM_THRESHOLD:
        return 0.0
    if retrieval_score >= SEM_FULL_RELEVANCE:
        return 1.0
    return (retrieval_score - SEM_THRESHOLD) / (SEM_FULL_RELEVANCE - SEM_THRESHOLD)


def _build_match(caller_text: str, tactic: Tactic, retrieval_score: float) -> TacticMatch:
    hits = matched_red_flags(caller_text, tactic.red_flags)

    # Confidence is driven by how strongly the caller's words semantically match this
    # tactic, scaled by its severity. Explicit red-flag phrasing only nudges it upward.
    relevance = _semantic_relevance(retrieval_score)
    keyword_conf = min(1.0, len(hits) / KEYWORD_FULL_CONF_AT)

    # A red-flag "hit" is only evidence when the caller's turn is also at least
    # topically related to this tactic. Short, generic red-flag phrases collide with
    # innocuous chatter — "buy cards" hits a caller buying basketball cards, "numbers
    # on the back" hits a jersey number — and would otherwise surface a spurious gift-
    # card risk factor on a benign call. When Moss puts the turn below the relevance
    # floor (retrieval_score <= SEM_THRESHOLD, so relevance == 0), the overlap is
    # coincidental token noise: drop it. A genuine gift-card demand is BOTH semantically
    # close to the tactic AND uses its phrasing, so this never suppresses a real signal.
    if relevance <= 0.0:
        hits = []
        keyword_conf = 0.0

    # Drop weak topic-overlap with no red-flag phrasing: it is nearest-neighbour noise
    # (e.g. small talk faintly matching a tech-support tactic), not evidence. Zeroing
    # relevance here removes it from both the score and the dashboard signal feed.
    if not hits and relevance < SEM_SIGNAL_RELEVANCE:
        relevance = 0.0

    match_strength = min(1.0, relevance + KEYWORD_BONUS * keyword_conf)
    confidence = tactic.severity * match_strength

    if hits:
        flags = ", ".join(f'"{h}"' for h in hits)
        explanation = (
            f"Matched known scam tactic '{tactic.label}' ({tactic.source}); "
            f"caller used red-flag phrasing: {flags}."
        )
    else:
        explanation = (
            f"Caller's words semantically match known scam tactic '{tactic.label}' "
            f"({tactic.source}) without verbatim red-flag phrasing."
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
    # Any semantically relevant tactic contributes, whether or not the caller used a
    # literal red-flag phrase. Confidence already reflects semantic match strength.
    relevant = [
        m for m in matches
        if m.retrieval_score >= SEM_THRESHOLD and m.confidence > 0.0
    ]
    if not relevant:
        return prior

    best = max(relevant, key=lambda m: m.confidence)
    distinct_categories = {m.category for m in relevant}
    corroboration = min(
        CORROBORATION_CAP,
        CORROBORATION_PER_CATEGORY * (len(distinct_categories) - 1),
    )

    # Bound this turn's evidence: one passive topic match (or even several within a
    # single turn) cannot by itself push past the cap into "critical". Matching
    # multiple distinct categories at once raises the ceiling via corroboration.
    turn_evidence = min(SEM_TURN_CAP + corroboration, best.confidence + corroboration)

    # Accumulate with diminishing returns toward 1.0 so repeated signals and
    # deflections across turns escalate to a confident verdict, while a single
    # mention stays in the suspicious band and lets the screener interrogate first.
    accumulated = prior + turn_evidence * (1.0 - prior)
    score = min(1.0, max(prior, accumulated))

    # Topic-adjacency without the caller's own red-flag phrasing must not ratchet a
    # legitimate call into HIGH/CRITICAL turn after turn. Hold the running score at
    # the passive ceiling unless a prior turn already escalated it on real evidence
    # (red-flag phrasing or an explicit flag_scam_signal), which we never undo.
    has_red_flags = any(m.matched_red_flags for m in relevant)
    if not has_red_flags:
        score = min(score, max(prior, PASSIVE_SCORE_CEILING))

    return score


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
