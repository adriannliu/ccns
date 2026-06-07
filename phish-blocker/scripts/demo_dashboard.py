import argparse
import asyncio
import json
import os

import aiohttp

DEFAULT_URL = os.getenv("DASHBOARD_INGEST_URL", "http://localhost:8080/ingest")

SCRIPT = [
    {"type": "call_start"},
    {"type": "transcript", "role": "agent", "text": "Hi, I'm screening calls for the resident. Who's calling and what is it regarding?"},
    {"type": "transcript", "role": "caller", "text": "This is Officer Daniels with the IRS. You owe back taxes and there's a warrant out for your arrest."},
    {"type": "signal", "label": "IRS back-taxes arrest threat", "confidence": 0.95, "scam_score": 0.62,
     "tactic_id": "irs-back-taxes-arrest-01",
     "explanation": "Matched known scam tactic 'IRS back-taxes arrest threat' (IRS - Beware of scammers posing as the IRS); caller used red-flag phrasing: \"owe back taxes\", \"warrant\", \"arrest\"."},
    {"type": "transcript", "role": "agent", "text": "The IRS contacts people by mail first. Can you give me the case number so I can verify?"},
    {"type": "transcript", "role": "caller", "text": "No time for that. You must pay immediately with gift cards from Walmart and read me the numbers on the back."},
    {"type": "signal", "label": "IRS gift-card payment demand", "confidence": 0.97, "scam_score": 0.88,
     "tactic_id": "irs-gift-card-payment-02",
     "explanation": "Matched known scam tactic 'IRS gift-card payment demand' (IRS - How taxpayers can protect themselves from gift card scams); caller used red-flag phrasing: \"gift cards\", \"Walmart\", \"numbers on the back\"."},
    {"type": "transcript", "role": "caller", "text": "And do not hang up or tell anyone, stay on the line with me right now."},
    {"type": "signal", "label": "Urgency / time pressure", "confidence": 0.70, "scam_score": 0.95,
     "tactic_id": "tactic-urgency-time-pressure-27",
     "explanation": "Matched known scam tactic 'Urgency / time pressure' (FTC - How To Avoid a Scam); caller used red-flag phrasing: \"don't hang up\", \"stay on the line\", \"right now\"."},
    {"type": "verdict", "recommendation": "block", "scam_score": 0.95,
     "reason": "Caller impersonated the IRS, threatened arrest, and demanded gift-card payment — all documented scam tactics."},
    {"type": "history_entry", "entry": {
        "phone": "+15551234567",
        "first_flagged_at": "2026-06-07T12:00:00+00:00",
        "last_flagged_at": "2026-06-07T12:00:00+00:00",
        "flag_count": 1,
        "recommendation": "block",
        "reason": "Caller impersonated the IRS, threatened arrest, and demanded gift-card payment — all documented scam tactics.",
        "scam_score": 0.95,
        "signals": ["IRS back-taxes arrest threat", "IRS gift-card payment demand", "Urgency / time pressure"],
    }},
]


async def main(url: str, delay: float) -> None:
    async with aiohttp.ClientSession() as s:
        for event in SCRIPT:
            await s.post(url, data=json.dumps(event))
            tag = event.get("type")
            extra = event.get("label") or event.get("role") or event.get("recommendation") or ""
            print(f"-> {tag:10} {extra}")
            await asyncio.sleep(delay)
    print("\nDemo complete. Open http://localhost:8080 to watch (run this while the page is open).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay a scripted scam call to the dashboard.")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--delay", type=float, default=1.6, help="Seconds between events.")
    args = parser.parse_args()
    asyncio.run(main(args.url, args.delay))
