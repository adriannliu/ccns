import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import phish_blocker  # noqa: F401 — installs SSL cert bundle for Moss HTTPS

from dotenv import load_dotenv
from moss import DocumentInfo, MossClient, QueryOptions

from phish_blocker.corpus import load_tactics, to_moss_metadata

load_dotenv()

DEFAULT_INDEX = "scam-tactics"
DEFAULT_MODEL = "moss-minilm"

SMOKE_QUERY = "you owe back taxes, pay in gift cards"


def _build_client() -> MossClient:
    project_id = os.getenv("MOSS_PROJECT_ID")
    project_key = os.getenv("MOSS_PROJECT_KEY")
    if not project_id or not project_key:
        raise SystemExit(
            "MOSS_PROJECT_ID and MOSS_PROJECT_KEY must be set (see .env.example)."
        )
    return MossClient(project_id, project_key)


async def _index_exists(client: MossClient, name: str) -> bool:
    try:
        existing = await client.list_indexes()
    except Exception:
        return False
    return any(getattr(info, "name", None) == name for info in existing)


async def build(index_name: str, model_id: str, rebuild: bool, verify: bool) -> None:
    tactics = load_tactics()
    docs = [
        DocumentInfo(id=t.id, text=t.text, metadata=to_moss_metadata(t))
        for t in tactics
    ]
    print(f"Loaded {len(docs)} tactics from the corpus.")

    client = _build_client()

    if await _index_exists(client, index_name):
        if not rebuild:
            raise SystemExit(
                f"Index '{index_name}' already exists. Re-run with --rebuild to replace it."
            )
        print(f"Deleting existing index '{index_name}'...")
        await client.delete_index(index_name)

    print(f"Creating index '{index_name}' with model '{model_id}'...")
    await client.create_index(index_name, docs, model_id)
    print(f"Created index '{index_name}' with {len(docs)} tactics.")

    if verify:
        await _verify(client, index_name)


async def _verify(client: MossClient, index_name: str) -> None:
    print(f"\nLoading '{index_name}' and running a smoke query...")
    await client.load_index(index_name)
    results = await client.query(
        index_name, SMOKE_QUERY, QueryOptions(top_k=3, alpha=0.7)
    )

    print(f'  query: "{SMOKE_QUERY}"')
    if not results.docs:
        raise SystemExit("Smoke query returned no matches; corpus or index is wrong.")

    for rank, doc in enumerate(results.docs, start=1):
        print(f"  {rank}. {doc.id}  score={doc.score:.3f}")
        print(f"     {doc.text[:90]}...")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the Moss scam-tactic index.")
    parser.add_argument(
        "--index",
        default=os.getenv("MOSS_INDEX_NAME", DEFAULT_INDEX),
        help="Index name (default: env MOSS_INDEX_NAME or 'scam-tactics').",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("MOSS_MODEL_ID", DEFAULT_MODEL),
        help="Embedding model: moss-minilm (fast) or moss-mediumlm (accurate).",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Delete and recreate the index if it already exists.",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip the load + smoke-query verification step.",
    )
    args = parser.parse_args()

    asyncio.run(
        build(
            index_name=args.index,
            model_id=args.model,
            rebuild=args.rebuild,
            verify=not args.no_verify,
        )
    )


if __name__ == "__main__":
    main()
