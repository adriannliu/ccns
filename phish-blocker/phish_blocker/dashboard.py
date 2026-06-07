import asyncio
import json
import logging
import os
from pathlib import Path

from aiohttp import WSMsgType, web

logger = logging.getLogger("phish-blocker.dashboard")

_clients: set[web.WebSocketResponse] = set()
_lock = asyncio.Lock()
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


async def push(event: dict):
    msg = json.dumps(event)
    async with _lock:
        dead = []
        for ws in _clients:
            try:
                await ws.send_str(msg)
            except ConnectionError:
                dead.append(ws)
        for ws in dead:
            _clients.discard(ws)


async def _ws_handler(request: web.Request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    async with _lock:
        _clients.add(ws)
    try:
        async for msg in ws:
            if msg.type == WSMsgType.ERROR:
                break
    finally:
        async with _lock:
            _clients.discard(ws)
    return ws


async def _index(request: web.Request):
    return web.FileResponse(STATIC_DIR / "index.html")


async def _ingest(request: web.Request):
    event = await request.json()
    await push(event)
    return web.json_response({"ok": True})


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", _index)
    app.router.add_get("/ws", _ws_handler)
    app.router.add_post("/ingest", _ingest)
    app.router.add_static("/static", STATIC_DIR)
    return app


async def run():
    app = build_app()
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.getenv("DASHBOARD_PORT", "8080"))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    logger.info("dashboard on http://localhost:%d", port)
    await asyncio.Event().wait()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
