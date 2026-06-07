# Demo scripts — use with `python -m phish_blocker.agent console --text`

Run dashboard first: `python -m phish_blocker.dashboard`

## Scam call (~60s) — expect BLOCK

1. **Caller:** Hi, this is Officer Martinez with the IRS. You owe back taxes and there is a warrant for your arrest unless you pay today.
2. **Caller:** You need to buy Apple gift cards and read me the numbers on the back. Stay on the line.
3. **Caller:** I can't give you a case number, that's confidential for security reasons.

Expect: Moss flags IRS tactics, agent asks for case number, deflection → block.

## Legit call (~30s) — expect PASS

1. **Caller:** Hey, it's Dave — just confirming we're still on for lunch Tuesday at noon.
2. **Caller:** No payment or anything, just wanted to confirm the time.

Expect: low score, brief screen, pass.
