import json
import logging
import os
import secrets
import threading
import urllib.request
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, Header, HTTPException
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
    sidecars.start_analytics(config.ANALYTICS_PORT)  # local stand-in for a third-party analytics vendor
    log.info("vuln-python-fastapi listening on http://%s:%s", config.HOST, config.PORT)
    yield


app = FastAPI(lifespan=lifespan)


def track(event: str, **props) -> None:
    """Fire-and-forget product analytics event."""
    def _send():
        try:
            req = urllib.request.Request(
                config.ANALYTICS_URL,
                data=json.dumps({"event": event, **props}).encode(),
                headers={"content-type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=2).read()
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


def current_user(authorization: str = Header(default="")) -> dict:
    user = sessions.get(authorization.removeprefix("Bearer ").strip())
    if not user:
        raise HTTPException(status_code=401, detail="unauthenticated")
    return user


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    log.info("login attempt user=%s password=%s", username, password)
    with lock:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = secrets.token_hex(24)
    sessions[token] = {"id": row["id"], "username": row["username"]}
    track("login", user_id=row["id"], username=row["username"], email=row["email"])
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
    track("signup", user_id=cur.lastrowid, username=body.username, email=body.email)
    return {"id": cur.lastrowid}


@app.get("/api/messages/{message_id}")
def get_message(message_id: int, user: dict = Depends(current_user)):
    with lock:
        row = conn.execute("SELECT id, owner_id, body FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    return dict(row)


@app.get("/api/search")
def search(q: str = ""):
    try:
        with lock:
            rows = conn.execute(f"SELECT id, name, price FROM items WHERE name LIKE '%{q}%'").fetchall()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return [dict(r) for r in rows]


@app.get("/api/fetch-preview")
def fetch_preview(url: str, user: dict = Depends(current_user)):
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return {"status": r.status, "preview": r.read(500).decode(errors="replace")}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)


@app.delete("/api/account")
def delete_account(user: dict = Depends(current_user)):
    log.info("account deletion requested user_id=%s", user["id"])
    return {"status": "deleted"}


@app.get("/privacy", response_class=HTMLResponse)
def privacy():
    return """<!doctype html><html><head><title>Privacy Policy</title></head><body>
<h1>Privacy Policy</h1>
<p>We never share data with third parties. Your account details and messages stay on our servers.</p>
<p>When you delete your account, all of your personal data is permanently erased.</p>
</body></html>"""
