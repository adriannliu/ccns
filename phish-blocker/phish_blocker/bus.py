import json
import logging
import os

import aiohttp

logger = logging.getLogger("phish-blocker.bus")
_INGEST_URL = os.getenv("DASHBOARD_INGEST_URL", "http://localhost:8080/ingest")


async def push(event: dict):
    try:
        async with aiohttp.ClientSession() as s:
            await s.post(_INGEST_URL, data=json.dumps(event), timeout=aiohttp.ClientTimeout(total=2))
    except Exception as e:
        logger.warning("dashboard push failed: %s", e)
