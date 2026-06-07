# Scam-Tactic Corpus — Sources & Provenance

The corpus (`scam_tactics.jsonl`) is the defensible backbone of the scoring system:
each detected signal can cite a known scam tactic instead of relying on an opaque
LLM confidence score. Every tactic card is a third-person *description* of a pattern
(not a verbatim scammer quote), so Moss embeds the meaning and we avoid baking toxic
phrasing in literally.

## Document schema

Each line in `scam_tactics.jsonl` is one tactic card:

```json
{
  "id": "irs-gift-card-payment-02",
  "text": "Caller poses as an IRS agent and instructs you to pay a tax bill ...",
  "metadata": {
    "category": "authority_impersonation",
    "subcategory": "irs",
    "red_flags": ["gift cards", "tax bill", "card number and PIN"],
    "source": "IRS - How taxpayers can protect themselves from gift card scams",
    "severity": 0.97
  }
}
```

- `text` — what Moss embeds and matches against caller utterances.
- `category` / `subcategory` — grouping for the dashboard and metadata filtering.
- `red_flags` — concrete keywords that help hybrid (keyword + semantic) search.
- `source` — provenance for the claim, so a verdict is auditable.
- `severity` — base weight (0.0–1.0) feeding the retrieval-grounded score.

## Categories covered

| category | subcategories |
|---|---|
| `authority_impersonation` | irs, ssa, government, law_enforcement |
| `payment_method` | gift_card, wire_transfer, cryptocurrency, payment_app, cash_courier |
| `family_emergency` | grandparent (bail, secrecy, name-fishing, lawyer relay) |
| `bank_impersonation` | fraud_department, safe_account |
| `credential_phishing` | otp_code, personal_info, login |
| `tech_support` | fake_popup, remote_access, refund_scam |
| `prize_lottery` | advance_fee |
| `utility` | shutoff_threat |
| `package_delivery` | fake_order |
| `tactic` | urgency, secrecy, refusal_to_verify, spoofing |

## Primary sources

All phrasing was paraphrased from official consumer-protection guidance:

- **FTC — Consumer Advice**
  - Hang up on unexpected calls saying you owe back taxes (2026)
  - Never move your money to "protect it." That's a scam
  - Got a call about fraud activity on your bank account?
  - What's a verification code and why would someone ask me for it?
  - Scammers Use Fake Emergencies To Steal Your Money
  - Family Emergency Imposter Scams (video transcript: "I'm in jail ... please don't tell anyone")
  - How To Avoid a Scam / How To Avoid a Government Impersonation Scam
  - Seemingly urgent security messages could lead to tech support scams (2025)
  - How to spot a government impersonator scam
- **IRS**
  - Beware of scammers posing as the IRS
  - How taxpayers can protect themselves from gift card scams
  - Dirty Dozen tax scams for 2026
- **Microsoft Support / Security Blog**
  - Protect yourself from tech support scams
  - Tech support scams persist with increasingly crafty techniques
    (fake "Critical alert from Microsoft ... call us immediately" pop-up text)
- **USAGov** — Imposter scams overview
- **ACE (Advocacy Centre for the Elderly)** — Grandparent Scheme

## Moss metadata constraint

Moss `DocumentInfo` metadata is `dict[str, str]` — values must be strings (no lists,
numbers, or nested dicts). The corpus on disk keeps rich types (`red_flags` as a list,
`severity` as a float) for readability; `corpus.to_moss_metadata()` serializes them for
indexing (`red_flags` → comma-joined string, `severity` → `"0.970"`), and
`corpus.parse_moss_metadata()` reverses it when reading query results in Phase 4.

## Validating / extending the corpus

```bash
cd phish-blocker
python -m phish_blocker.corpus   # prints tactic count per category, fails on a bad row
```

To add a tactic: append one JSON object per line to `scam_tactics.jsonl` with a unique
`id` and the required metadata fields. Keep `text` a neutral third-person description.
