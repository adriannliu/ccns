import json
from dataclasses import dataclass, field
from pathlib import Path

_CORPUS_PATH = Path(__file__).resolve().parent.parent / "data" / "scam_tactics.jsonl"

_REQUIRED_METADATA = ("category", "red_flags", "source", "severity")


@dataclass
class Tactic:
    id: str
    text: str
    label: str
    category: str
    subcategory: str
    red_flags: list[str]
    source: str
    severity: float
    metadata: dict = field(default_factory=dict)


def to_moss_metadata(tactic: "Tactic") -> dict[str, str]:
    return {
        "label": tactic.label,
        "category": tactic.category,
        "subcategory": tactic.subcategory,
        "red_flags": ", ".join(tactic.red_flags),
        "source": tactic.source,
        "severity": f"{tactic.severity:.3f}",
    }


def parse_moss_metadata(metadata: dict) -> dict:
    red_flags = metadata.get("red_flags", "")
    try:
        severity = float(metadata.get("severity", 0.0))
    except (TypeError, ValueError):
        severity = 0.0
    return {
        "category": metadata.get("category", ""),
        "subcategory": metadata.get("subcategory", ""),
        "red_flags": [f.strip() for f in red_flags.split(",") if f.strip()],
        "source": metadata.get("source", ""),
        "severity": severity,
    }


def _validate(row: dict, line_no: int) -> None:
    if "id" not in row or not row["id"]:
        raise ValueError(f"line {line_no}: missing 'id'")
    if "text" not in row or not row["text"]:
        raise ValueError(f"line {line_no}: tactic '{row.get('id')}' missing 'text'")

    meta = row.get("metadata", {})
    for key in _REQUIRED_METADATA:
        if key not in meta:
            raise ValueError(f"line {line_no}: tactic '{row['id']}' missing metadata.{key}")

    severity = meta["severity"]
    if not isinstance(severity, (int, float)) or not 0.0 <= severity <= 1.0:
        raise ValueError(f"line {line_no}: tactic '{row['id']}' severity must be 0.0-1.0")


def load_tactics(path: Path | str | None = None) -> list[Tactic]:
    corpus_path = Path(path) if path is not None else _CORPUS_PATH
    tactics: list[Tactic] = []
    seen_ids: set[str] = set()

    with open(corpus_path, encoding="utf-8") as f:
        for line_no, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue

            row = json.loads(line)
            _validate(row, line_no)

            tactic_id = row["id"]
            if tactic_id in seen_ids:
                raise ValueError(f"line {line_no}: duplicate tactic id '{tactic_id}'")
            seen_ids.add(tactic_id)

            meta = row["metadata"]
            tactics.append(
                Tactic(
                    id=tactic_id,
                    text=row["text"],
                    label=meta.get("label", tactic_id),
                    category=meta["category"],
                    subcategory=meta.get("subcategory", ""),
                    red_flags=list(meta.get("red_flags", [])),
                    source=meta["source"],
                    severity=float(meta["severity"]),
                    metadata=meta,
                )
            )

    return tactics


if __name__ == "__main__":
    loaded = load_tactics()
    by_category: dict[str, int] = {}
    for t in loaded:
        by_category[t.category] = by_category.get(t.category, 0) + 1

    print(f"Loaded {len(loaded)} tactics from {_CORPUS_PATH}")
    for category, count in sorted(by_category.items()):
        print(f"  {category}: {count}")
