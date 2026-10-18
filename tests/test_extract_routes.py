"""Tests for the framework-semantic route extractor.

These use small inline source snippets (not the fixtures) so they assert on the
parsing logic itself: method/path recovery, auth inference from middleware /
dependency names, path and query/body param extraction, and OpenAPI security.
"""
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "release-gate" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import extract_routes as er  # noqa: E402


def _routes(result):
    return {(r["method"], r["path"]): r for r in result["routes"]}


# --------------------------------------------------------------------------- express

def test_express_method_path_and_auth(tmp_path):
    (tmp_path / "r.js").write_text(
        "const express = require('express');\n"
        "const router = express.Router();\n"
        "router.get('/widgets/:id', requireAuth, (req, res) => {\n"
        "  const x = req.query.detail; res.json({id: req.params.id});\n"
        "});\n"
        "router.get('/public', (req, res) => res.send('hi'));\n"
        "router.post('/things', verifyToken, (req, res) => {\n"
        "  const { name, qty } = req.body; res.json({});\n"
        "});\n"
    )
    r = _routes(er.extract(tmp_path))
    assert r[("GET", "/widgets/:id")]["auth_required"] is True
    assert r[("GET", "/widgets/:id")]["path_params"] == ["id"]
    assert "detail" in r[("GET", "/widgets/:id")]["query_params"]
    assert r[("GET", "/public")]["auth_required"] is False
    assert r[("POST", "/things")]["auth_required"] is True
    assert set(r[("POST", "/things")]["body_params"]) == {"name", "qty"}
    assert "express" in er.extract(tmp_path)["frameworks"]


def test_express_ignores_node_modules(tmp_path):
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("router.get('/should-not-appear', (req,res)=>{})\n")
    (tmp_path / "app.js").write_text("router.get('/real', (req,res)=>{})\n")
    r = _routes(er.extract(tmp_path))
    assert ("GET", "/real") in r
    assert ("GET", "/should-not-appear") not in r


# --------------------------------------------------------------------------- fastapi

def test_fastapi_depends_auth_and_params(tmp_path):
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI, Depends, Header\n"
        "from pydantic import BaseModel\n"
        "app = FastAPI()\n"
        "class Reg(BaseModel):\n    username: str\n    password: str\n"
        "def current_user(authorization: str = Header(default='')):\n    ...\n"
        "@app.get('/items/{item_id}')\n"
        "def get_item(item_id: int, user: dict = Depends(current_user)):\n    ...\n"
        "@app.get('/open')\n"
        "def open_ep(q: str = ''):\n    ...\n"
        "@app.post('/signup', status_code=201)\n"
        "def signup(body: Reg):\n    ...\n"
    )
    r = _routes(er.extract(tmp_path))
    assert r[("GET", "/items/{item_id}")]["auth_required"] is True
    assert r[("GET", "/items/{item_id}")]["path_params"] == ["item_id"]
    assert r[("GET", "/open")]["auth_required"] is False
    assert "q" in r[("GET", "/open")]["query_params"]
    # a custom (CapWord) annotation is a body model, not a query param
    assert "body" in r[("POST", "/signup")]["body_params"]
    assert "body" not in r[("POST", "/signup")]["query_params"]


def test_fastapi_non_auth_depends_is_not_auth(tmp_path):
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n"
        "def paginator(limit: int = 10):\n    ...\n"
        "@app.get('/list')\n"
        "def listing(p = Depends(paginator)):\n    ...\n"
    )
    r = _routes(er.extract(tmp_path))
    # 'paginator' does not match the auth vocabulary -> open
    assert r[("GET", "/list")]["auth_required"] is False


# --------------------------------------------------------------------------- flask

def test_flask_methods_and_decorator_auth(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@login_required\n"
        "@app.route('/admin/<int:uid>', methods=['GET','POST'])\n"
        "def admin(uid):\n    ...\n"
    )
    r = _routes(er.extract(tmp_path))
    assert ("GET", "/admin/{uid}") in r
    assert ("POST", "/admin/{uid}") in r
    assert r[("GET", "/admin/{uid}")]["auth_required"] is True
    assert r[("GET", "/admin/{uid}")]["path_params"] == ["uid"]


# --------------------------------------------------------------------------- openapi

def test_openapi_security(tmp_path):
    import json
    (tmp_path / "openapi.json").write_text(json.dumps({
        "openapi": "3.0.0",
        "paths": {
            "/secure/{id}": {"get": {"security": [{"bearer": []}],
                                     "parameters": [{"name": "id", "in": "path"},
                                                    {"name": "verbose", "in": "query"}]}},
            "/open": {"get": {}},
        },
    }))
    r = _routes(er.extract(tmp_path))
    assert r[("GET", "/secure/{id}")]["auth_required"] is True
    assert r[("GET", "/secure/{id}")]["path_params"] == ["id"]
    assert "verbose" in r[("GET", "/secure/{id}")]["query_params"]
    assert r[("GET", "/open")]["auth_required"] is False


# --------------------------------------------------------------------------- url param surface

def test_url_param_regex_matches_ssrf_shapes():
    assert er.URL_PARAM_RE.match("url")
    assert er.URL_PARAM_RE.match("callback")
    assert er.URL_PARAM_RE.match("image_url")
    assert not er.URL_PARAM_RE.match("username")
    assert not er.URL_PARAM_RE.match("id")


def test_empty_project(tmp_path):
    result = er.extract(tmp_path)
    assert result["n_routes"] == 0
    assert result["routes"] == []
    assert result["frameworks"] == []
