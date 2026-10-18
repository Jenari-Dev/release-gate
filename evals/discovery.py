#!/usr/bin/env python3
"""Discovery-mode planning for the eval harness.

Guided mode (``FIXTURE_PLANS`` in run_evals.py) hands each fixture its bug
locations: the IDOR endpoint, who owns which record, the SSRF target and canary,
the coupon code. Discovery mode gets none of that. It is given only what a real
operator would type for any target:

    port, start command, and seeded test credentials (a seeded test DB is
    allowed by SKILL principle 3).

From those plus the attack surface that ``extract_routes.py`` recovers from the
code, it plans the dynamic tests itself:

  * login shape (form vs json, token field) is probed, not declared;
  * test users come from the app's own signup route where one exists, else the
    seeded fallback;
  * object-level authorization is checked by learning each user's *own* ids from
    a collection endpoint and then trying to read ids that user does not own
    (no answer key, no hand-fed owner map);
  * SSRF is pointed at a canary listener the harness starts itself;
  * the SQL-injection error probe targets whatever open query endpoint exists.

Anything the surface does not let it plan (a single-use coupon with no creatable
code, an analytics sink whose address is not a documented input) stays
NOT-TESTED or SUSPECTED and is scored that way. A miss is a miss.

This module contains NO fixture-specific endpoint paths, canary strings or coupon
codes; ``tests/test_discovery_no_literals.py`` fails if any creep in. The only
per-target knobs are passed in by the caller.
"""
from __future__ import annotations

import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Convention vocabularies (name heuristics, not endpoint literals).
LOGIN_PATH_RE = re.compile(r"(^|/)(login|log-?in|signin|sign-?in|session|auth|authenticate|token)s?$", re.I)
SIGNUP_PATH_RE = re.compile(r"(^|/)(register|signup|sign-?up|users|accounts|join)s?$", re.I)
USERNAME_FIELD_RE = re.compile(r"^(username|user|login|email|handle|account)$", re.I)
PASSWORD_FIELD_RE = re.compile(r"^(password|passwd|pass|pwd|secret)$", re.I)
EMAIL_FIELD_RE = re.compile(r"^(email|mail|e_?mail)$", re.I)
TOKEN_LIKE_RE = re.compile(r"^[A-Za-z0-9._-]{16,}$")
ID_LIKE = re.compile(r"id$|^id", re.I)

TIMEOUT = 8


# --------------------------------------------------------------------------- http

def _req(method, url, *, headers=None, data=None, ctype=None):
    r = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    if ctype:
        r.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(r, timeout=TIMEOUT) as resp:  # noqa: S310 (loopback)
            return resp.status, resp.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(16384).decode("utf-8", "replace") if e.fp else "")
    except (urllib.error.URLError, OSError) as e:
        return 0, f"<transport error: {type(e).__name__}>"


# --------------------------------------------------------------------------- route selection

def _auth_routes(routes, method):
    return [r for r in routes if r["method"] == method and r.get("auth_required") is True]


def find_login(routes) -> dict | None:
    cands = [r for r in routes if r["method"] == "POST" and LOGIN_PATH_RE.search(r["path"])
             and r.get("auth_required") is not True]
    # prefer the one that reads a password-shaped body field
    cands.sort(key=lambda r: 0 if any(PASSWORD_FIELD_RE.match(b) for b in r.get("body_params", [])) else 1)
    return cands[0] if cands else None


def find_signup(routes) -> dict | None:
    cands = [r for r in routes if r["method"] == "POST" and SIGNUP_PATH_RE.search(r["path"])
             and r.get("auth_required") is not True]
    # a signup route is not the login route
    cands = [r for r in cands if not LOGIN_PATH_RE.search(r["path"])]
    return cands[0] if cands else None


def find_object_endpoints(routes) -> list[dict]:
    """Auth-required GET endpoints with exactly one id-like path param."""
    out = []
    for r in _auth_routes(routes, "GET"):
        pp = r.get("path_params", [])
        if len(pp) == 1 and ID_LIKE.search(pp[0]):
            out.append(r)
    return out


def find_collection_for(item: dict, routes) -> dict | None:
    """A sibling auth GET with no path param whose path is the item's parent."""
    parent = item["path"].rsplit("/", 1)[0] or "/"
    for r in _auth_routes(routes, "GET"):
        if not r.get("path_params") and r["path"] == parent:
            return r
    return None


def find_url_fetch(routes) -> dict | None:
    """Any endpoint with a url-shaped query param (SSRF surface)."""
    from extract_routes import URL_PARAM_RE  # type: ignore
    for r in routes:
        for q in r.get("query_params", []) + r.get("body_params", []):
            if URL_PARAM_RE.match(q):
                return {"route": r, "param": q}
    return None


def find_query_endpoint(routes) -> dict | None:
    """An open GET with a free-text query param (injection error probe surface)."""
    for r in routes:
        if r["method"] == "GET" and r.get("auth_required") is not True and r.get("query_params"):
            return {"route": r, "param": r["query_params"][0]}
    return None


def find_delete_self(routes) -> dict | None:
    for r in routes:
        if r["method"] == "DELETE" and r.get("auth_required") is True and not r.get("path_params"):
            return r
    return None


# --------------------------------------------------------------------------- login / users

def probe_login_shape(base: str, login_route: dict, username: str, password: str):
    """Return (encoding, token_field) that produces a 2xx + token, or None.

    Tries json then form; reads the response for a token-shaped value. No shape
    is declared up front — this is how a real run would learn it."""
    path = login_route["path"]
    url = base.rstrip("/") + path
    user_field = next((b for b in login_route.get("body_params", []) if USERNAME_FIELD_RE.match(b)), "username")
    pass_field = next((b for b in login_route.get("body_params", []) if PASSWORD_FIELD_RE.match(b)), "password")
    payload = {user_field: username, pass_field: password}
    for enc in ("json", "form"):
        if enc == "json":
            st, body = _req("POST", url, data=json.dumps(payload).encode(), ctype="application/json")
        else:
            st, body = _req("POST", url, data=urllib.parse.urlencode(payload).encode(),
                            ctype="application/x-www-form-urlencoded")
        if st // 100 == 2:
            field = _token_field(body)
            if field:
                return {"encoding": enc, "token_field": field, "path": path,
                        "user_field": user_field, "pass_field": pass_field}
    return None


def _token_field(body: str) -> str | None:
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    for k, v in obj.items():
        if isinstance(v, str) and TOKEN_LIKE_RE.match(v):
            return k
    return None


def login(base: str, shape: dict, username: str, password: str) -> str | None:
    url = base.rstrip("/") + shape["path"]
    payload = {shape["user_field"]: username, shape["pass_field"]: password}
    if shape["encoding"] == "json":
        st, body = _req("POST", url, data=json.dumps(payload).encode(), ctype="application/json")
    else:
        st, body = _req("POST", url, data=urllib.parse.urlencode(payload).encode(),
                        ctype="application/x-www-form-urlencoded")
    if st // 100 != 2:
        return None
    try:
        return json.loads(body).get(shape["token_field"])
    except (json.JSONDecodeError, AttributeError):
        return None


def register_user(base: str, signup: dict, username: str, password: str) -> bool:
    """Create a user through the app's own signup route (json then form)."""
    url = base.rstrip("/") + signup["path"]
    body_fields = signup.get("body_params", []) or ["username", "password", "email"]
    payload = {}
    for f in body_fields:
        if USERNAME_FIELD_RE.match(f):
            payload[f] = username
        elif PASSWORD_FIELD_RE.match(f):
            payload[f] = password
        elif EMAIL_FIELD_RE.match(f):
            payload[f] = f"{username}@discovery.test"
    if not payload:
        payload = {"username": username, "password": password, "email": f"{username}@discovery.test"}
    for enc in ("json", "form"):
        if enc == "json":
            st, _ = _req("POST", url, data=json.dumps(payload).encode(), ctype="application/json")
        else:
            st, _ = _req("POST", url, data=urllib.parse.urlencode(payload).encode(),
                         ctype="application/x-www-form-urlencoded")
        if st // 100 == 2:
            return True
    return False


def build_principals(base: str, routes, seeded: list[tuple[str, str]]):
    """Return (shape, principals). Principals come from signup where possible,
    else from the seeded fallback credentials. Each carries its observed token."""
    login_route = find_login(routes)
    if not login_route:
        return None, []
    signup = find_signup(routes)
    created: list[dict] = []
    shape = None

    if signup:
        for i in range(2):
            uname = f"disc_{secrets.token_hex(4)}"
            pw = "Disc-" + secrets.token_hex(6)
            if register_user(base, signup, uname, pw):
                if shape is None:
                    shape = probe_login_shape(base, login_route, uname, pw)
                if shape:
                    tok = login(base, shape, uname, pw)
                    if tok:
                        created.append({"name": uname, "username": uname, "password": pw, "token": tok})
    if len(created) < 2 and seeded:
        for uname, pw in seeded:
            if shape is None:
                shape = probe_login_shape(base, login_route, uname, pw)
            if shape:
                tok = login(base, shape, uname, pw)
                created.append({"name": uname, "username": uname, "password": pw, "token": tok})
    return shape, created


# --------------------------------------------------------------------------- ownership

def observe_owned_ids(base: str, collection: dict, token: str | None) -> list:
    """Learn the ids a principal owns by reading their own collection endpoint."""
    url = base.rstrip("/") + collection["path"]
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    st, body = _req("GET", url, headers=headers)
    if st // 100 != 2:
        return []
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []
    rows = obj if isinstance(obj, list) else obj.get("items") if isinstance(obj, dict) else None
    ids = []
    if isinstance(rows, list):
        for r in rows:
            if isinstance(r, dict):
                for k, v in r.items():
                    if ID_LIKE.search(k) and isinstance(v, (int, str)):
                        ids.append(v)
                        break
            elif isinstance(r, (int, str)):
                ids.append(r)
    return ids


def build_authz_spec(base: str, routes, principals: list[dict], shape: dict | None):
    """Build an authz_matrix spec with OBSERVED ownership (from collection
    endpoints). Returns (spec_or_None, mode) where mode is 'observed' when we
    learned real owner->id mappings, or 'weak' when we could only enumerate."""
    items = find_object_endpoints(routes)
    if not items or len(principals) < 1:
        return None, "none"
    resources = []
    observed = False
    for item in items:
        coll = find_collection_for(item, routes)
        owned: dict[str, list] = {}
        if coll:
            for p in principals:
                ids = observe_owned_ids(base, coll, p.get("token"))
                if ids:
                    owned[p["name"]] = ids
                    observed = True
        if not owned:
            # no collection to learn ownership from: enumerate a small id range,
            # attributed to no one, so the matrix can only reach SUSPECTED, not EXPLOITED.
            owned = {principals[0]["name"]: list(range(1, 6))}
        # authz_matrix substitutes the literal placeholder `{id}`; normalise the one
        # path param (`:name` or `{name}`) to `{id}` so substitution happens.
        norm = re.sub(r":([A-Za-z_]\w*)|\{[A-Za-z_]\w*\}", "{id}", item["path"])
        resources.append({"endpoint": f"{item['method']} {norm}", "owned": owned, "public": False})
    if not shape:
        return None, "none"
    spec = {
        "base_url": base,
        "login": {"path": shape["path"], "method": "POST", "encoding": shape["encoding"],
                  "token_field": shape["token_field"]},
        "users": [{"name": p["name"], "username": p["username"], "password": p["password"]} for p in principals],
        "resources": resources,
    }
    return spec, ("observed" if observed else "weak")


# --------------------------------------------------------------------------- plan

def build_plan(base: str, routes: list[dict], seeded: list[tuple[str, str]]) -> dict:
    """The full discovery plan: what was found and how each dynamic test will run.
    Pure planning + observation; no answer-key input."""
    shape, principals = build_principals(base, routes, seeded)
    authz_spec, authz_mode = build_authz_spec(base, routes, principals, shape)
    return {
        "login_shape": shape,
        "principals": [{k: v for k, v in p.items() if k != "token"} for p in principals],
        "_principals_full": principals,
        "authz_spec": authz_spec,
        "authz_mode": authz_mode,
        "url_fetch": find_url_fetch(routes),
        "query_endpoint": find_query_endpoint(routes),
        "signup": find_signup(routes),
        "delete_self": find_delete_self(routes),
        "n_routes": len(routes),
    }
