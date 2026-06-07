import argparse
import asyncio
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
from moss import MossClient, QueryOptions

load_dotenv()

DEFAULT_INDEX = "scam-tactics"
DEFAULT_ALPHA = 0.7
DEFAULT_TOP_K = 3
DEFAULT_ITERS = 50
LATENCY_TARGET_MS = 10.0

BENCH_QUERIES = [
    ("you owe back taxes, pay in gift cards", "irs-gift-card-payment-02"),
    ("there is a warrant out for your arrest if you don't pay now", "police-arrest-warrant-06"),
    ("your social security number has been suspended", "ssa-number-suspended-04"),
    ("your grandson is in jail and needs bail money", "family-grandparent-bail-12"),
    ("please don't tell mom and dad about this", "family-dont-tell-anyone-13"),
    ("this is your bank fraud department, we saw suspicious activity", "bank-fraud-dept-suspicious-16"),
    ("move your money to a safe account to protect it", "bank-move-money-safe-account-17"),
    ("read me the verification code we just texted you", "credential-otp-verification-code-18"),
    ("your computer is infected, call this number now", "tech-popup-virus-call-number-21"),
    ("let me remote into your computer to fix it", "tech-remote-access-22"),
    ("you won the lottery but must pay a fee to claim it", "prize-lottery-fee-24"),
    ("buy gift cards at walmart and read me the numbers on the back", "payment-gift-card-codes-07"),
    ("wire the money through western union right away", "payment-wire-transfer-08"),
    ("we will shut off your electricity unless you pay immediately", "utility-shutoff-25"),
]


def _build_client() -> MossClient:
    project_id = os.getenv("MOSS_PROJECT_ID")
    project_key = os.getenv("MOSS_PROJECT_KEY")
    if not project_id or not project_key:
        raise SystemExit(
            "MOSS_PROJECT_ID and MOSS_PROJECT_KEY must be set (see .env.example)."
        )
    return MossClient(project_id, project_key)


async def _time_query(client, index, query, top_k, alpha):
    start = time.perf_counter()
    results = await client.query(index, query, QueryOptions(top_k=top_k, alpha=alpha))
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return results, elapsed_ms


async def run(index: str, alpha: float, top_k: int, iters: int) -> None:
    client = _build_client()

    print(f"Loading index '{index}'...")
    await client.load_index(index)

    await _time_query(client, index, BENCH_QUERIES[0][0], top_k, alpha)

    all_latencies: list[float] = []
    rank1_hits = 0
    topk_hits = 0

    print(f"\nRunning {len(BENCH_QUERIES)} queries x {iters} iters "
          f"(top_k={top_k}, alpha={alpha})\n")
    header = f"{'lat(ms)':>8}  {'rank1':>5}  {'top3':>4}  {'score':>6}  query -> match"
    print(header)
    print("-" * len(header))

    for query, expected_id in BENCH_QUERIES:
        per_query_latencies: list[float] = []
        results = None
        for _ in range(iters):
            results, elapsed_ms = await _time_query(client, index, query, top_k, alpha)
            per_query_latencies.append(elapsed_ms)

        all_latencies.extend(per_query_latencies)
        docs = results.docs if results else []
        ids = [d.id for d in docs]

        rank1 = bool(docs) and ids[0] == expected_id
        in_topk = expected_id in ids
        rank1_hits += int(rank1)
        topk_hits += int(in_topk)

        median_ms = statistics.median(per_query_latencies)
        top_score = docs[0].score if docs else 0.0
        top_id = ids[0] if ids else "(none)"
        mark1 = "OK" if rank1 else ".."
        markk = "OK" if in_topk else ".."
        print(f"{median_ms:8.2f}  {mark1:>5}  {markk:>4}  {top_score:6.3f}  "
              f"\"{query[:42]}\" -> {top_id}")

    p50 = statistics.median(all_latencies)
    p95 = sorted(all_latencies)[int(len(all_latencies) * 0.95) - 1]
    fastest = min(all_latencies)
    slowest = max(all_latencies)
    total = len(BENCH_QUERIES)

    print("\n=== Summary ===")
    print(f"queries:            {total}")
    print(f"rank-1 correct:     {rank1_hits}/{total}")
    print(f"top-{top_k} correct:      {topk_hits}/{total}")
    print(f"latency p50:        {p50:.2f} ms")
    print(f"latency p95:        {p95:.2f} ms")
    print(f"latency min/max:    {fastest:.2f} / {slowest:.2f} ms")
    print(f"<{LATENCY_TARGET_MS:.0f}ms target (p50):  "
          f"{'PASS' if p50 < LATENCY_TARGET_MS else 'FAIL'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Moss scam-tactic retrieval.")
    parser.add_argument("--index", default=os.getenv("MOSS_INDEX_NAME", DEFAULT_INDEX))
    parser.add_argument("--alpha", type=float, default=DEFAULT_ALPHA)
    parser.add_argument("--top-k", type=int, default=DEFAULT_TOP_K)
    parser.add_argument("--iters", type=int, default=DEFAULT_ITERS)
    args = parser.parse_args()

    asyncio.run(
        run(index=args.index, alpha=args.alpha, top_k=args.top_k, iters=args.iters)
    )


if __name__ == "__main__":
    main()
