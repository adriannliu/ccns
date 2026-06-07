import asyncio
import json
import logging
import os
from pathlib import Path

from aiohttp import WSMsgType, web

from phish_blocker import blocklist, contacts

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


async def _history(request: web.Request):
    return web.json_response({"entries": blocklist.list_history()})


async def _history_remove(request: web.Request):
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"ok": False, "error": "invalid JSON"}, status=400)

    phone = body.get("phone")
    removed = blocklist.remove(phone)
    if removed is None:
        return web.json_response({"ok": False, "error": "not found"}, status=404)

    await push({"type": "history_removed", "phone": removed["phone"]})
    return web.json_response({"ok": True, "removed": removed})


async def _history_verify(request: web.Request):
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"ok": False, "error": "invalid JSON"}, status=400)

    phone = body.get("phone")
    removed = blocklist.remove(phone)
    if removed is None:
        return web.json_response({"ok": False, "error": "not found"}, status=404)

    contact = None
    if body.get("add_to_contacts"):
        name = (body.get("name") or "").strip()
        if not name:
            return web.json_response(
                {"ok": False, "error": "name required when add_to_contacts is true"},
                status=400,
            )
        contact = contacts.add(
            phone,
            name=name,
            relationship=body.get("relationship") or "",
        )

    await push({"type": "history_removed", "phone": removed["phone"]})
    if contact is not None:
        await push({"type": "contact_added", "contact": contact})
    return web.json_response({"ok": True, "removed": removed, "contact": contact})


async def _contacts_list(request: web.Request):
    return web.json_response({"contacts": contacts.list_contacts()})


async def _contacts_add(request: web.Request):
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"ok": False, "error": "invalid JSON"}, status=400)

    name = (body.get("name") or "").strip()
    if not name:
        return web.json_response({"ok": False, "error": "name required"}, status=400)

    contact = contacts.add(
        body.get("phone"),
        name=name,
        relationship=body.get("relationship") or "",
    )
    if contact is None:
        return web.json_response({"ok": False, "error": "invalid phone"}, status=400)

    await push({"type": "contact_added", "contact": contact})
    return web.json_response({"ok": True, "contact": contact})


async def _contacts_remove(request: web.Request):
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"ok": False, "error": "invalid JSON"}, status=400)

    removed = contacts.remove(body.get("phone"))
    if removed is None:
        return web.json_response({"ok": False, "error": "not found"}, status=404)

    await push({"type": "contact_removed", "phone": removed["phone"]})
    return web.json_response({"ok": True, "removed": removed})


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", _index)
    app.router.add_get("/ws", _ws_handler)
    app.router.add_get("/api/history", _history)
    app.router.add_delete("/api/history", _history_remove)
    app.router.add_post("/api/history/verify", _history_verify)
    app.router.add_get("/api/contacts", _contacts_list)
    app.router.add_post("/api/contacts", _contacts_add)
    app.router.add_delete("/api/contacts", _contacts_remove)
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
