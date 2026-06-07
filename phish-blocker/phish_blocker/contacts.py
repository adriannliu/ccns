import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("phish-blocker.contacts")

_CONTACTS_PATH = Path(__file__).resolve().parent.parent / "data" / "contacts.json"


@dataclass
class Contact:
    name: str
    phone: str
    relationship: str = ""


def normalize(number: str | None) -> str | None:
    if not number:
        return None
    digits = re.sub(r"[^\d]", "", number)
    if not digits:
        return None
    if number.strip().startswith("+"):
        return "+" + digits
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    return "+" + digits


_by_number: dict[str, Contact] = {}
_loaded = False


def load_contacts(path: Path | str | None = None) -> dict[str, Contact]:
    global _by_number, _loaded
    contacts_path = Path(path) if path is not None else _CONTACTS_PATH

    by_number: dict[str, Contact] = {}
    try:
        with open(contacts_path, encoding="utf-8") as f:
            rows = json.load(f)
    except FileNotFoundError:
        logger.warning("contacts file not found: %s", contacts_path)
        rows = []

    for row in rows:
        key = normalize(row.get("phone"))
        if key is None:
            continue
        by_number[key] = Contact(
            name=row.get("name", "Unknown"),
            phone=key,
            relationship=row.get("relationship", ""),
        )

    _by_number = by_number
    _loaded = True
    logger.info("Loaded %d contacts from %s", len(by_number), contacts_path)
    return by_number


def lookup(number: str | None) -> Contact | None:
    if not _loaded:
        load_contacts()
    key = normalize(number)
    if key is None:
        return None
    return _by_number.get(key)


def _save() -> None:
    rows = [
        {
            "name": c.name,
            "phone": c.phone,
            "relationship": c.relationship,
        }
        for c in sorted(_by_number.values(), key=lambda c: c.name.lower())
    ]
    _CONTACTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_CONTACTS_PATH, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
        f.write("\n")


def list_contacts() -> list[dict]:
    if not _loaded:
        load_contacts()
    return [
        {"name": c.name, "phone": c.phone, "relationship": c.relationship}
        for c in sorted(_by_number.values(), key=lambda c: c.name.lower())
    ]


def remove(number: str | None) -> dict | None:
    if not _loaded:
        load_contacts()
    key = normalize(number)
    if key is None:
        return None
    contact = _by_number.pop(key, None)
    if contact is None:
        return None
    _save()
    logger.info("contacts removed %s", key)
    return {"name": contact.name, "phone": contact.phone, "relationship": contact.relationship}


def add(
    number: str,
    name: str,
    relationship: str = "",
) -> dict | None:
    key = normalize(number)
    if key is None:
        return None
    if not _loaded:
        load_contacts()

    clean_name = name.strip() or "Unknown"
    contact = Contact(name=clean_name, phone=key, relationship=relationship.strip())
    _by_number[key] = contact
    _save()
    logger.info("contacts added %s (%s)", key, clean_name)
    return {"name": contact.name, "phone": contact.phone, "relationship": contact.relationship}


if __name__ == "__main__":
    import sys

    load_contacts()
    print(f"Loaded {len(_by_number)} contacts from {_CONTACTS_PATH}")
    for c in _by_number.values():
        print(f"  {c.phone}  {c.name} ({c.relationship})")

    if len(sys.argv) > 1:
        q = sys.argv[1]
        print(f"lookup({q!r}) -> {lookup(q)}")
