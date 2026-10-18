import ipaddress
import logging
import os
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import config, sidecars
from .db import conn, hash_password, lock, verify_password

_log_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(_log_dir, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(os.path.join(_log_dir, "app.log"))],
)
log = logging.getLogger("app")
sessions: dict[str, dict] = {}


@asynccontextmanager
async def lifespan(_app):
    sidecars.start_internal(config.INTERNAL_PORT)
    sidecars.start_analytics(config.ANALYTICS_PORT)
    log.info("clean-python-fastapi listening on http://%s:%s", config.HOST, config.PORT)
    yield


app = FastAPI(lifespan=lifespan)

# --- login rate limit: 5 attempts / 60s per client IP + username -------------------------
_WINDOW, _MAX = 60.0, 5
_hits: dict[str, tuple[float, int]] = {}
_hits_lock = threading.Lock()


def login_limit(request: Request, username: str = Form(...)) -> None:
    key = f"{request.client.host}:{username.lower()}"
    now = time.monotonic()
    with _hits_lock:
        start, count = _hits.get(key, (now, 0))
        if now - start > _WINDOW:
            start, count = now, 0
        count += 1
        _hits[key] = (start, count)
    if count > _MAX:
        raise HTTPException(status_code=429, detail="too many attempts", headers={"Retry-After": str(int(_WINDOW))})


def current_user(authorization: str = Header(default="")) -> dict:
    user = sessions.get(authorization.removeprefix("Bearer ").strip())
    if not user:
        raise HTTPException(status_code=401, detail="unauthenticated")
    return user


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/login", dependencies=[Depends(login_limit)])
def login(username: str = Form(...), password: str = Form(...)):
    with lock:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        log.info("login failed user=%s", username[:64])
        raise HTTPException(status_code=401, detail="invalid credentials")
    log.info("login ok user=%s", row["username"])
    token = secrets.token_hex(24)
    sessions[token] = {"id": row["id"], "username": row["username"]}
    return {"token": token}


class Registration(BaseModel):
    username: str
    password: str
    email: str


@app.post("/api/register", status_code=201)
def register(body: Registration):
    with lock:
        try:
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (body.username, body.email, hash_password(body.password)),
            )
        except Exception:
            raise HTTPException(status_code=409, detail="username taken")
    return {"id": cur.lastrowid}


@app.get("/api/messages/{message_id}")
def get_message(message_id: int, user: dict = Depends(current_user)):
    # ownership enforced in the query itself
    with lock:
        row = conn.execute(
            "SELECT id, body FROM messages WHERE id = ? AND owner_id = ?", (message_id, user["id"])
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    return dict(row)


@app.get("/api/search")
def search(q: str = ""):
    escaped = q[:100].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    with lock:
        rows = conn.execute(
            "SELECT id, name, price FROM items WHERE name LIKE ? ESCAPE '\\'", (f"%{escaped}%",)
        ).fetchall()
    return [dict(r) for r in rows]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _is_public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


@app.get("/api/fetch-preview")
def fetch_preview(url: str, user: dict = Depends(current_user)):
    # https only, explicit hostname allowlist, and the resolved address must be public
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or (u.hostname or "").lower() not in config.PREVIEW_ALLOWED_HOSTS or not _is_public(u.hostname):
        return JSONResponse({"error": "host not allowed"}, status_code=403)
    try:
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(url, timeout=3) as r:
            return {"status": r.status, "preview": r.read(500).decode(errors="replace")}
    except Exception:
        return JSONResponse({"error": "fetch failed"}, status_code=502)


@app.delete("/api/account")
def delete_account(user: dict = Depends(current_user)):
    with lock:
        conn.execute("DELETE FROM messages WHERE owner_id = ?", (user["id"],))
        conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    for tok in [t for t, s in sessions.items() if s["id"] == user["id"]]:
        del sessions[tok]
    log.info("account deleted user_id=%s", user["id"])
    return {"status": "deleted"}


@app.get("/privacy", response_class=HTMLResponse)
def privacy():
    return """<!doctype html><html><head><title>Privacy Policy</title></head><body>
<h1>Privacy Policy</h1>
<p>We never share data with third parties. Your account details and messages stay on our servers and
this service sends no analytics or usage events to anyone else.</p>
<p>When you delete your account, your profile, credentials, sessions and messages are deleted immediately.</p>
</body></html>"""
