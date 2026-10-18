"""data_inventory_scan: static, evidence-backed draft inventory. No network, nothing executed.

Synthetic apps live in tests/data/inventory/. The eval fixtures under evals/fixtures/ are
used too when they are present in the checkout (their expectations come from reading
their source, not from their answer keys).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import data_inventory_scan as dis
import rglib

REPO = Path(__file__).resolve().parent.parent
DATA = Path(__file__).resolve().parent / "data" / "inventory"
FIXTURES = REPO / "evals" / "fixtures"
SCRIPT = Path(dis.__file__)


def write(root: Path, rel: str, content: str = "") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def by_name(items: list[dict], key: str = "name") -> dict[str, dict]:
    return {i[key]: i for i in items}


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


@pytest.fixture(scope="module")
def inv_all() -> dict:
    return dis.scan(DATA)


def app(name: str) -> dict:
    return dis.scan(DATA / name)


# --------------------------------------------------------------------------- classifier

@pytest.mark.parametrize("name,expected", [
    ("email", "contact"), ("phone_number", "contact"), ("shippingAddress", "contact"), ("zip_code", "contact"),
    ("username", "identifier"), ("user_id", "identifier"), ("ownerId", "identifier"), ("display_name", "identifier"),
    ("password", "credential"), ("password_hash", "credential"), ("accessToken", "credential"), ("api_key", "credential"),
    ("card_number", "financial"), ("iban", "financial"), ("balance", "financial"),
    ("latitude", "location"), ("lng", "location"), ("client_ip", "location"), ("ip_address", "location"),
    ("user_agent", "device-telemetry"), ("deviceId", "device-telemetry"),
    ("body", "content"), ("comment", "content"), ("bio", "content"), ("message", "content"),
    ("dob", "other"), ("birth_date", "other"), ("age", "other"),
    ("ssn", "sensitive"), ("diagnosis", "sensitive"), ("is_minor", "children"),
])
def test_classify_by_name(name, expected):
    assert dis.classify(name)[0] == expected


@pytest.mark.parametrize("name", [
    "price", "items", "page_size", "max_age", "created_at", "message_id", "token_count", "csrf_token", "language",
    "skip", "passenger", "pass_through", "ipsum", "tripod", "serialVersionUID", "content_hash", "email_verified",
    "card_id", "last_review",
])
def test_classify_rejects_non_personal_names(name):
    assert dis.classify(name) is None


def test_plain_id_and_name_need_a_user_like_table():
    assert dis.classify("id", "users")[0] == "identifier"
    assert dis.classify("id", "items") is None
    assert dis.classify("name", "customer_profiles")[0] == "identifier"
    assert dis.classify("name", "products") is None


def test_password_hash_stays_a_credential_but_other_hashes_are_not():
    assert dis.classify("password_hash")[0] == "credential"
    assert dis.classify("token_hash")[0] == "credential"
    assert dis.classify("ip_hash")[0] == "location"                          # pseudonymous, still personal
    assert dis.classify("body_hash") is None


def test_env_var_schemas_are_not_request_fields(tmp_path):
    write(tmp_path, "env.ts", "const env = z.object({ SESSION_SECRET: z.string(), CONTACT_EMAIL: z.string() });\n"
                              "const body = z.object({ email: z.string().email() });\n")
    assert set(by_name(dis.scan(tmp_path)["fields"])) == {"request.email"}


def test_sensitive_kinds_are_reported():
    assert dis.classify("diagnosis") == ("sensitive", "health")
    assert dis.classify("passport_number") == ("sensitive", "government-id")


# --------------------------------------------------------------------------- schema + provenance

def test_all_data_apps_validate_against_schema(inv_all):
    assert rglib.validate(inv_all, "data-inventory") == []
    for name in ("node-app", "py-app", "web", "generic"):
        assert rglib.validate(app(name), "data-inventory") == [], name


def test_every_entry_has_real_file_line_provenance(inv_all):
    entries = [e for sec in ("fields", "third_parties", "client_storage", "stores", "log_sinks") for e in inv_all[sec]]
    n = 0
    for e in entries + [{"provenance": v} for v in (inv_all.get("rights") or {}).values()]:
        prov = e["provenance"]
        assert prov["source"] == "code" and prov["refs"], e
        for ref in prov["refs"]:
            path, _, line = ref.rpartition(":")
            f = DATA / path
            assert f.is_file(), ref
            assert 1 <= int(line) <= len(f.read_text().splitlines()) + 1, ref
            assert not Path(path).is_absolute() and ".." not in Path(path).parts, ref
            n += 1
    assert n > 40


def test_confirmed_by_user_is_false_and_nothing_judgemental_is_invented(inv_all):
    assert inv_all["confirmed_by_user"] is False
    for f in inv_all["fields"]:
        assert "purposes" not in f and "lawful_basis" not in f
    for t in inv_all["third_parties"]:
        assert t["role"] == "unknown" and "transfer_region" not in t
    assert all(s["encrypted_at_rest"] == "unknown" for s in inv_all["stores"])


# --------------------------------------------------------------------------- fields

def test_sql_columns_alter_and_constraints():
    f = by_name(app("web")["fields"])
    assert f["customers.email"]["classification"] == "contact"
    assert f["customers.ssn"]["classification"] == "sensitive" and f["customers.ssn"]["sensitive_kind"] == "government-id"
    assert f["customers.card_number"]["classification"] == "financial"
    assert f["customers.latitude"]["classification"] == "location"
    assert f["customers.user_agent"]["classification"] == "device-telemetry"
    assert f["customers.health_notes"]["sensitive_kind"] == "health"          # via ALTER TABLE ... ADD COLUMN
    assert f["customers.id"]["classification"] == "identifier"                # id of a user-like table
    assert "customers.created_at" not in f
    assert not any(k.split(".")[-1] in ("fk_other", "UNIQUE") for k in f)     # constraints are not columns
    assert f["customers.ssn"]["provenance"]["refs"] == ["schema.sql:5"]


def test_comments_never_create_fields(inv_all):
    names = set(by_name(inv_all["fields"]))
    assert "customers.passport" not in names                                    # -- comment in schema.sql
    assert "form.ssn" not in names                                              # <!-- --> comment in index.html
    assert "user.phone" not in names                                            # // comment in user.js
    assert "accounts.nickname" not in names                                     # # comment in models.py


def test_mongoose_schema_fields_and_dob_note():
    f = by_name(app("node-app")["fields"])
    assert f["user.email"]["collected_via"] == ["model"]
    assert f["user.fullName"]["classification"] == "identifier"
    assert f["user.lastLoginIp"]["classification"] == "location"
    assert "user.theme" not in f
    assert "children" in f["user.dateOfBirth"]["provenance"]["note"]


def test_express_request_body_destructuring_and_properties():
    f = by_name(app("node-app")["fields"])
    assert f["request.email"]["collected_via"] == ["api-body"]
    assert f["request.fullName"]["classification"] == "identifier"
    assert f["request.dateOfBirth"]["classification"] == "other"
    assert f["request.ip"]["classification"] == "location"
    assert "request.plan" not in f and "request.marketingOptIn" not in f


def test_python_orm_pydantic_dataclass_and_type_hints():
    f = by_name(app("py-app")["fields"])
    assert f["accounts.email"]["classification"] == "contact"                   # __tablename__ wins over class name
    assert f["accounts.password_hash"]["classification"] == "credential"
    assert f["accounts.last_seen_ip"]["classification"] == "location"
    assert f["Profile.contact"]["classification"] == "contact"                  # EmailStr annotation, name says nothing
    assert f["Profile.bio"]["classification"] == "content"
    assert f["Payment.iban"]["classification"] == "financial"                   # dataclass
    assert "Profile.page_size" not in f
    assert f["form.email"]["collected_via"] == ["form"]                         # flask request.form[...]
    assert f["form.token"]["classification"] == "credential"


def test_html_inputs_use_name_type_and_skip_csrf():
    f = by_name(app("web")["fields"])
    assert f["form.contact_email"]["classification"] == "contact"
    assert f["form.full_name"]["classification"] == "identifier"
    assert f["form.pw"]["classification"] == "credential"                       # only type="password" says so
    assert f["form.birthday"]["classification"] == "other"
    assert f["form.message"]["classification"] == "content"
    assert "form.csrf_token" not in f and "form.coupon" not in f
    assert f["form.pw"]["collected_via"] == ["form"]


def test_prisma_and_go_structs():
    f = by_name(app("generic")["fields"])
    assert f["Patient.diagnosis"]["sensitive_kind"] == "health"
    assert f["Patient.email"]["classification"] == "contact"
    assert "Patient.posts" not in f                                             # relation, not a scalar
    assert f["Customer.passport_number"]["sensitive_kind"] == "government-id"  # json tag name, not Go field name
    assert f["Customer.email"]["classification"] == "contact"


def test_used_in_code_false_only_when_no_other_reference():
    node = by_name(app("node-app")["fields"])
    assert node["user.email"]["used_in_code"] is True                           # read in routes.js
    assert node["user.phoneNumber"]["used_in_code"] is False
    assert "no other reference" in node["user.phoneNumber"]["provenance"]["note"]
    assert "used_in_code" not in node["analytics.signup.email"]                 # an outbound event, not stored data


def test_retention_defaults_to_none_defined_unless_retention_code_exists(tmp_path):
    write(tmp_path, "db.sql", "CREATE TABLE users (id INT, email TEXT);")
    assert by_name(dis.scan(tmp_path)["fields"])["users.email"]["retention"] == "none defined"
    write(tmp_path, "job.py", "def purge_old(days):\n    pass\n")
    assert "retention" not in by_name(dis.scan(tmp_path)["fields"])["users.email"]   # something exists: do not claim "none"


# --------------------------------------------------------------------------- analytics + third parties

def test_analytics_events_js_and_python_with_data_sent():
    node = app("node-app")
    assert by_name(node["fields"])["analytics.signup.email"]["collected_via"] == ["analytics-event"]
    ph = by_name(app("py-app")["third_parties"], "host")["posthog.com"]
    assert ph["vendor"] == "PostHog" and ph["data_sent"] == ["analytics.signed_up.email"]
    assert ph["provenance"]["refs"] == ["views.py:1"]


def test_gtag_in_app_js_links_to_script_tag_in_html(inv_all):
    ga = by_name(inv_all["third_parties"], "host")["www.googletagmanager.com"]
    assert ga["vendor"] == "Google Analytics / Tag Manager"
    assert "analytics.purchase.email" in ga["data_sent"]
    cookies = {c["name"]: c for c in inv_all["client_storage"] if c["mechanism"] == "cookie"}
    assert cookies["_ga"]["set_by"] == "third-party" and cookies["_ga"]["necessity"] == "analytics"
    assert "not observed at runtime" in cookies["_ga"]["provenance"]["note"]


def test_html_third_parties_skip_links_meta_canonical_and_comments():
    hosts = set(by_name(app("web")["third_parties"], "host"))
    assert hosts == {"www.googletagmanager.com", "fonts.googleapis.com", "forms.mailer-vendor.io"}


def test_form_action_host_receives_the_form_fields():
    t = by_name(app("web")["third_parties"], "host")["forms.mailer-vendor.io"]
    assert set(t["data_sent"]) == {"form.contact_email", "form.full_name", "form.pw", "form.birthday", "form.message"}


def test_sdk_import_creates_third_party_with_note():
    t = by_name(app("node-app")["third_parties"], "host")["api.stripe.com"]
    assert t["vendor"] == "Stripe" and "SDK import" in t["provenance"]["note"]


def test_hosts_in_python_and_js_strings_and_placeholders(tmp_path):
    write(tmp_path, "client.py", 'import requests\nrequests.get("https://api.weather-vendor.io/v1?q=1")\n'
                                 'DOC = "https://www.w3.org/2001/XMLSchema"\nX = "https://example.com/a"\n'
                                 'Y = "https://api.example.test/x"\nZ = "http://localhost:8000/health"\n')
    write(tmp_path, "net.js", "fetch(`https://${region}.cdn.edge-vendor.net/x`);\nfetch('https://hooks.pager-vendor.com/h');\n")
    hosts = set(by_name(dis.scan(tmp_path)["third_parties"], "host"))
    assert hosts == {"api.weather-vendor.io", "hooks.pager-vendor.com"}


def test_loopback_hosts_only_when_they_look_like_analytics(tmp_path):
    write(tmp_path, "cfg.py", 'API = "http://127.0.0.1:8000/api"\nTRACKER_URL = f"http://127.0.0.1:{PORT}/collect"\nPORT = 3999\n')
    hosts = by_name(dis.scan(tmp_path)["third_parties"], "host")
    assert list(hosts) == ["127.0.0.1:3999"]
    assert "analytics" in hosts["127.0.0.1:3999"]["purpose"]
    assert "loopback" in hosts["127.0.0.1:3999"]["provenance"]["note"]


def test_credentials_in_urls_are_never_recorded(tmp_path):
    write(tmp_path, "db.py", 'DSN = "postgres://admin:s3cretpw@db.managed-pg.io:5432/app"\n')
    text = yaml.safe_dump(dis.scan(tmp_path))
    assert "s3cretpw" not in text and "admin" not in text
    assert "db.managed-pg.io" in text


# --------------------------------------------------------------------------- client storage

def test_client_storage_mechanisms_names_and_expiry():
    cs = {(c["mechanism"], c["name"]): c for c in app("node-app")["client_storage"]}
    assert cs[("cookie", "sid")]["expiry"] == "maxAge=3600000" and cs[("cookie", "sid")]["necessity"] == "strictly-necessary"
    assert cs[("cookie", "prefs")]["necessity"] == "functional"
    assert cs[("cookie", "lang")]["expiry"].startswith("session")        # the document.cookie string's max-age is not parsed
    assert cs[("localStorage", "theme")]["set_by"] == "first-party"
    assert ("sessionStorage", "cart") in cs
    py = {(c["mechanism"], c["name"]): c for c in app("py-app")["client_storage"]}
    assert py[("cookie", "remember_me")]["expiry"] == "max_age=2592000"
    assert ("cookie", "session") in py                                   # flask session[...] =


def test_dynamic_storage_keys_are_resolved_or_flagged(tmp_path):
    write(tmp_path, "a.js", "const KEY = 'consent_v2';\nlocalStorage.setItem(KEY, '1');\nsessionStorage.setItem(someVar, '1');\n")
    names = {c["name"] for c in dis.scan(tmp_path)["client_storage"]}
    assert "consent_v2" in names and "<dynamic: someVar>" in names


def test_cookie_option_object_form(tmp_path):
    write(tmp_path, "c.ts", "cookies.set({ name: 'csrf', value: tok });\nres.cookie({ ...opts, value: tok });\n")
    names = {c["name"] for c in dis.scan(tmp_path)["client_storage"]}
    assert names == {"csrf", "<dynamic: cookie options object>"}


def test_set_cookie_header_string_and_indexeddb(tmp_path):
    write(tmp_path, "s.py", 'self.send_header("Set-Cookie", f"_trk_uid={uid}; Path=/; Max-Age=31536000")\n')
    write(tmp_path, "i.js", "const req = indexedDB.open('offline-cache', 1);\n")
    cs = {(c["mechanism"], c["name"]): c for c in dis.scan(tmp_path)["client_storage"]}
    assert cs[("cookie", "_trk_uid")]["expiry"] == "Max-Age=31536000"
    assert cs[("cookie", "_trk_uid")]["necessity"] == "analytics"
    assert ("indexedDB", "offline-cache") in cs


# --------------------------------------------------------------------------- stores, logs, rights

def test_stores_detected_with_memory_and_file_names(tmp_path):
    stores = {(s["kind"], s["name"]) for s in dis.scan(DATA)["stores"]}
    assert {("database", "mongodb"), ("object-storage", "s3"), ("database", "postgresql")} <= stores
    write(tmp_path, "db.js", "const { DatabaseSync } = require('node:sqlite');\nnew DatabaseSync(':memory:');\n"
                              "const fs = require('fs');\nfs.writeFileSync('exports/report.csv', 'a');\n")
    got = {(s["kind"], s["name"]) for s in dis.scan(tmp_path)["stores"]}
    assert ("database", "sqlite (in-memory)") in got and ("file", "exports/report.csv") in got


def test_log_sinks_need_personal_data_and_flag_credentials():
    logs = by_name(dis.scan(DATA)["log_sinks"], "location")
    js, py = logs["node-app/src/routes.js:14"], logs["py-app/views.py:11"]
    assert js["fields_logged"] == ["email", "ip"] and js["contains_credential"] is False
    assert py["fields_logged"] == ["token", "email"] and py["contains_credential"] is True
    assert "generic/server.go:12" in logs
    assert len(logs) == 3                                                # statements with no personal data are not sinks


def test_log_prose_is_not_mistaken_for_a_credential(tmp_path):
    write(tmp_path, "a.py", 'log.info("invalid password policy loaded")\nlog.info("retry failed: %s", err)\n'
                            'log.error("login for %s with password=%s", user, password)\n')
    sinks = dis.scan(tmp_path)["log_sinks"]
    assert [s["location"] for s in sinks] == ["a.py:3"]
    assert sinks[0]["contains_credential"] is True


def test_deletion_right_needs_an_erase_operation(tmp_path):
    write(tmp_path, "fake.py", '@app.delete("/api/account")\ndef delete_account(user=Depends(cur)):\n    log.info("requested")\n    return {"status": "deleted"}\n')
    assert "rights" not in dis.scan(tmp_path)                            # route exists, nothing is erased
    write(tmp_path, "real.py", 'def delete_account(user):\n    conn.execute("DELETE FROM users WHERE id = ?", (user.id,))\n')
    d = dis.scan(tmp_path)["rights"]["deletion"]
    assert d["refs"] == ["real.py:2"] and "not verified" in d["note"]


def test_name_only_deletion_is_reported_outside_rights(tmp_path):
    write(tmp_path, "fake.py", '@app.delete("/api/account")\ndef delete_account():\n    return {"status": "deleted"}\n')
    inv, meta = dis.scan_project(tmp_path)
    assert "rights" not in inv
    assert meta["rights_name_only"]["deletion"] == ["fake.py:1", "fake.py:2"]


def test_orm_delete_counts_only_near_a_deletion_handler(tmp_path):
    write(tmp_path, "a.js", "function cleanupCache() { Cache.deleteMany({}); }\n")
    assert "rights" not in dis.scan(tmp_path)
    assert dis.scan(DATA / "node-app")["rights"]["deletion"]["refs"] == ["src/routes.js:22"]
    assert dis.scan(DATA / "py-app")["rights"]["deletion"]["refs"] == ["views.py:20"]


def test_other_rights_are_found_by_name_with_a_caveat(tmp_path):
    write(tmp_path, "r.py", '@app.get("/me/export")\ndef export_my_data(): ...\n\n@app.patch("/me")\ndef update_profile(): ...\n')
    r = dis.scan(tmp_path)["rights"]
    assert set(r) == {"access_export", "correction"}
    assert "not verified" in r["access_export"]["note"]


# --------------------------------------------------------------------------- walking / limits

def test_skipped_dirs_tests_big_binary_minified_and_symlinks(tmp_path):
    shutil.copytree(DATA / "web", tmp_path / "w")
    root = tmp_path / "w"
    for skipped in ("node_modules/lib/x.js", "venv/lib/y.py", ".git/hooks/z.js", "dist/bundle.js", "build/out.js",
                    "vendor/pkg/v.py", ".release-gate/old.js", "tests/spec_a.js", "__tests__/b.js", "fixtures/f.py"):
        write(root, skipped, "const password = req.body.password;\nlocalStorage.setItem('leak', 1);\n")
    write(root, ".myenv/pyvenv.cfg", "home = /usr\n")                    # a virtualenv with an unusual name
    write(root, ".myenv/lib/m.py", "def f(request):\n    return request.form['password']\n")
    write(root, "app.test.js", "const password = req.body.password;\n")
    write(root, "big.js", "// x\n" + "const a = 1;\n" * 90_000 + "localStorage.setItem('big', 1);\n")
    (root / "bin.js").write_bytes(b"localStorage.setItem('bin', 1);\x00\x01\x02")
    write(root, "min.js", "var a=" + "x" * 30_000 + ";localStorage.setItem('min', 1);\n")
    write(root, "app.min.js", "localStorage.setItem('named_min', 1);\n")
    outside = tmp_path / "outside"
    write(outside, "o.js", "localStorage.setItem('sym_target', 1);\n")
    os.symlink(outside, root / "linked")
    os.symlink(outside / "o.js", root / "linked.js")
    inv, meta = dis.scan_project(root)
    text = json.dumps(inv)
    for leaked in ("leak", "form.password", "request.password", '"big"', '"bin"', '"min"', "named_min", "sym_target"):
        assert leaked not in text, leaked
    assert {c["name"] for c in inv["client_storage"]} <= {"_ga", "_gid"}      # only what index.html's GA script implies
    assert meta["skipped_large"] == 1 and meta["skipped_binary"] == 1 and meta["skipped_minified"] == 1


def test_include_tests_flag_scans_test_dirs(tmp_path):
    write(tmp_path, "tests/a.js", "localStorage.setItem('in_tests', 1);\n")
    assert dis.scan(tmp_path)["client_storage"] == []
    assert [c["name"] for c in dis.scan(tmp_path, include_tests=True)["client_storage"]] == ["in_tests"]


def test_scan_is_deterministic_and_read_only(tmp_path):
    shutil.copytree(DATA, tmp_path / "p")
    snap = lambda: sorted((str(p.relative_to(tmp_path)), p.stat().st_mtime_ns) for p in (tmp_path / "p").rglob("*") if p.is_file())  # noqa: E731
    before = snap()
    a, b = dis.scan(tmp_path / "p"), dis.scan(tmp_path / "p")
    a.pop("generated_at"), b.pop("generated_at")
    assert a == b
    assert before == snap()
    assert not (tmp_path / "p" / ".release-gate").exists()               # the library call writes nothing


def test_broken_files_do_not_abort_the_scan(tmp_path):
    write(tmp_path, "bad.py", "def (:\n  nonsense")
    write(tmp_path, "ok.sql", "CREATE TABLE users (id INT, email TEXT);")
    write(tmp_path, "weird.js", "const x = `unterminated ${ ;\nreq.body.email;\n")
    inv, meta = dis.scan_project(tmp_path)
    assert "users.email" in by_name(inv["fields"])
    assert any("could not parse Python: bad.py" in w for w in meta["warnings"])


def test_empty_project_yields_a_valid_empty_inventory(tmp_path):
    inv = dis.scan(tmp_path)
    assert rglib.validate(inv, "data-inventory") == []
    assert all(inv[k] == [] for k in ("fields", "third_parties", "client_storage", "stores", "log_sinks"))


def test_secret_shaped_strings_never_reach_the_draft(tmp_path):
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    write(tmp_path, "cfg.py", f'AWS_KEY = "{key}"\nlog.info("using %s", AWS_KEY)\nlog.info("token=%s", "{key}")\n')
    write(tmp_path, "app.js", f"const t = '{key}';\nlocalStorage.setItem('{key}', 1);\n")
    text = yaml.safe_dump(dis.scan(tmp_path))
    assert rglib.find_secrets(text) == [] and key not in text


# --------------------------------------------------------------------------- CLI

def test_cli_writes_default_location_and_validates(tmp_path):
    shutil.copytree(DATA / "py-app", tmp_path / "p")
    r = run_cli(str(tmp_path / "p"))
    assert r.returncode == 0, r.stderr
    inv = yaml.safe_load((tmp_path / "p" / ".release-gate" / "data-inventory.yaml").read_text())
    assert rglib.validate(inv, "data-inventory") == []
    assert inv["confirmed_by_user"] is False
    assert "data inventory draft written" in r.stdout and "a human must review" in r.stdout


def test_cli_json_out_and_bad_args(tmp_path):
    out = tmp_path / "elsewhere" / "inv.yaml"
    r = run_cli(str(DATA / "web"), "--out", str(out), "--json")
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout)
    assert payload["counts"]["fields"] == len(payload["inventory"]["fields"]) > 5
    assert payload["scan"]["files_scanned"] == 2
    assert out.is_file() and not (DATA / "web" / ".release-gate").exists()
    assert run_cli(str(tmp_path / "missing")).returncode == 2
    assert run_cli().returncode == 2


def test_cli_refuses_to_overwrite_user_edits_without_merge_flag(tmp_path):
    shutil.copytree(DATA / "web", tmp_path / "p")
    out = tmp_path / "p" / ".release-gate" / "data-inventory.yaml"
    assert run_cli(str(tmp_path / "p")).returncode == 0
    assert run_cli(str(tmp_path / "p")).returncode == 0                  # a pure scan output may be regenerated
    inv = yaml.safe_load(out.read_text())
    inv["confirmed_by_user"] = True
    out.write_text(yaml.safe_dump(inv))
    r = run_cli(str(tmp_path / "p"))
    assert r.returncode == 3 and "--merge-existing" in r.stderr
    assert yaml.safe_load(out.read_text())["confirmed_by_user"] is True   # untouched
    out.write_text("fields: [unclosed")
    assert run_cli(str(tmp_path / "p")).returncode == 3                   # unparsable: never clobbered


def test_merge_keeps_user_entries_and_annotations(tmp_path):
    shutil.copytree(DATA / "node-app", tmp_path / "p")
    out = tmp_path / "p" / ".release-gate" / "data-inventory.yaml"
    assert run_cli(str(tmp_path / "p")).returncode == 0
    inv = yaml.safe_load(out.read_text())
    f = by_name(inv["fields"])
    f["user.email"]["purposes"] = ["account login"]
    f["user.email"]["lawful_basis"] = "contract"
    f["request.fullName"]["classification"] = "contact"                   # a user correction ...
    f["request.fullName"]["provenance"] = {"source": "user", "note": "display name shown to others"}   # ... recorded as user
    inv["fields"].append({"name": "orders.delivery_note", "classification": "content", "provenance": {"source": "user", "note": "added by hand"}})
    inv["fields"].append({"name": "ghost.col", "classification": "contact", "purposes": ["x"],
                          "provenance": {"source": "code", "refs": ["old.js:1"]}})      # gone from code, but annotated
    inv["fields"].append({"name": "ghost.plain", "classification": "contact", "provenance": {"source": "code", "refs": ["old.js:2"]}})
    t = by_name(inv["third_parties"], "host")["api.stripe.com"]
    t["role"], t["transfer_region"], t["purpose"] = "processor", "US", "card payments"
    inv["confirmed_by_user"] = True
    out.write_text(yaml.safe_dump(inv))

    r = run_cli(str(tmp_path / "p"), "--merge-existing", "--json")
    assert r.returncode == 0, r.stderr
    merged = yaml.safe_load(out.read_text())
    assert rglib.validate(merged, "data-inventory") == []
    mf = by_name(merged["fields"])
    assert mf["user.email"]["purposes"] == ["account login"] and mf["user.email"]["lawful_basis"] == "contract"
    assert mf["request.fullName"]["classification"] == "contact" and mf["request.fullName"]["provenance"]["source"] == "user"
    assert mf["orders.delivery_note"]["provenance"]["source"] == "user"
    assert "not found by the latest scan" in mf["ghost.col"]["provenance"]["note"] and mf["ghost.col"]["purposes"] == ["x"]
    assert "ghost.plain" not in mf                                        # unannotated stale entries are dropped
    mt = by_name(merged["third_parties"], "host")["api.stripe.com"]
    assert (mt["role"], mt["transfer_region"], mt["purpose"]) == ("processor", "US", "card payments")
    assert merged["confirmed_by_user"] is False                           # the code-derived set changed: needs re-review
    report = json.loads(r.stdout)["merge"]
    assert report["kept_user_entries"] >= 2 and report["dropped_stale"] == 1 and report["kept_stale"] == 1


def test_merge_keeps_confirmation_when_the_code_set_is_unchanged(tmp_path):
    shutil.copytree(DATA / "web", tmp_path / "p")
    out = tmp_path / "p" / ".release-gate" / "data-inventory.yaml"
    assert run_cli(str(tmp_path / "p")).returncode == 0
    inv = yaml.safe_load(out.read_text())
    inv["confirmed_by_user"] = True
    out.write_text(yaml.safe_dump(inv))
    assert run_cli(str(tmp_path / "p"), "--merge-existing").returncode == 0
    assert yaml.safe_load(out.read_text())["confirmed_by_user"] is True


def test_merge_without_an_existing_file_is_a_plain_scan(tmp_path):
    shutil.copytree(DATA / "web", tmp_path / "p")
    assert run_cli(str(tmp_path / "p"), "--merge-existing").returncode == 0


# --------------------------------------------------------------------------- eval fixtures (when present)

needs_fixtures = pytest.mark.skipif(not (FIXTURES / "vuln-python-fastapi").is_dir(), reason="evals/fixtures not in this checkout")


@needs_fixtures
def test_fixture_vuln_python_fastapi():
    inv, meta = dis.scan_project(FIXTURES / "vuln-python-fastapi")
    f = by_name(inv["fields"])
    assert f["users.email"]["classification"] == "contact" and f["users.password_hash"]["classification"] == "credential"
    assert f["Registration.password"]["collected_via"] == ["api-body"]      # pydantic model used as a request body
    assert f["form.password"]["collected_via"] == ["form"]                  # Form(...)
    third = by_name(inv["third_parties"], "host")
    assert list(third) == ["127.0.0.1:3163"]                                # the analytics stand-in, port resolved from config
    assert {"analytics.login.email", "analytics.signup.email", "analytics.login.username"} <= set(third["127.0.0.1:3163"]["data_sent"])
    sinks = by_name(inv["log_sinks"], "location")
    assert sinks["app/main.py:67"]["contains_credential"] is True           # login logs the password
    assert "rights" not in inv                                              # DELETE /api/account erases nothing
    assert meta["rights_name_only"]["deletion"][0].startswith("app/main.py:")


@needs_fixtures
def test_fixture_clean_python_fastapi_has_deletion_and_no_third_party():
    inv = dis.scan(FIXTURES / "clean-python-fastapi")
    assert inv["third_parties"] == []
    assert inv["rights"]["deletion"]["refs"]
    assert all(not s["contains_credential"] for s in inv["log_sinks"])


@needs_fixtures
def test_fixture_vuln_node_express():
    inv = dis.scan(FIXTURES / "vuln-node-express")
    f = by_name(inv["fields"])
    assert f["users.password_hash"]["classification"] == "credential" and f["users.balance"]["classification"] == "financial"
    assert f["request.password"]["collected_via"] == ["api-body"] and f["request.username"]["classification"] == "identifier"
    assert f["request.body"]["classification"] == "content"                 # (req.body || {}).body
    sinks = by_name(inv["log_sinks"], "location")
    assert sinks["src/routes/auth.js:11"]["fields_logged"] == ["password", "username"]
    assert sinks["src/routes/auth.js:11"]["contains_credential"] is True
    assert {(s["kind"], s["name"]) for s in inv["stores"]} == {("database", "sqlite (in-memory)"), ("file", "logs/app.log")}
    assert inv["third_parties"] == [] and inv["client_storage"] == []
    assert "node_modules" not in json.dumps(inv)


@needs_fixtures
def test_fixture_static_trackers_vuln_and_clean():
    v = dis.scan(FIXTURES / "vuln-static-trackers")
    assert [t["host"] for t in v["third_parties"]] == ["127.0.0.1:3155"]
    assert v["third_parties"][0]["provenance"]["refs"][-1] == "site/index.html:8"
    cs = by_name(v["client_storage"])
    assert cs["_trk_uid"]["necessity"] == "analytics" and cs["_trk_uid"]["expiry"] == "Max-Age=31536000"
    assert cs["consent"]["mechanism"] == "localStorage"
    c = dis.scan(FIXTURES / "clean-static-trackers")
    assert "127.0.0.1:3156" in {t["host"] for t in c["third_parties"]}      # statically present; consent gating is a runtime question
    for fx in ("vuln-static-trackers", "clean-static-trackers", "vuln-node-express", "clean-node-express", "clean-python-fastapi"):
        assert rglib.validate(dis.scan(FIXTURES / fx), "data-inventory") == [], fx
