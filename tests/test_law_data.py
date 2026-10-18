"""Structural checks for the curated legal reference data in references/law/*.yaml.

These tests do not judge whether a legal statement is correct. They enforce the
honesty guarantees: official domains only, every item traceable, a verification
date, and the "rules change, verify against the official source" header.
"""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest
import yaml

LAW_DIR = Path(__file__).resolve().parents[1] / "skills" / "release-gate" / "references" / "law"

EXPECTED_IDS = {
    "gdpr", "uk-gdpr", "eprivacy", "ccpa-cpra", "us-state-privacy",
    "coppa", "appi", "pipeda", "lgpd", "au-privacy-act",
}

# Official government / legislature / regulator domains only. A host matches if it
# equals an entry or is a subdomain of it.
ALLOWED_DOMAINS = {
    # EU
    "eur-lex.europa.eu", "europa.eu",
    # UK
    "legislation.gov.uk", "ico.org.uk",
    # California
    "oag.ca.gov", "cppa.ca.gov", "leginfo.legislature.ca.gov",
    # US federal
    "ecfr.gov", "ftc.gov", "govinfo.gov", "federalregister.gov",
    # US states (legislature / attorney general / department sites)
    "law.lis.virginia.gov", "portal.ct.gov", "cga.ct.gov", "doj.state.or.us",
    "oregonlegislature.gov", "capitol.texas.gov", "statutes.capitol.texas.gov",
    "texasattorneygeneral.gov", "leg.colorado.gov", "coag.gov", "le.utah.gov",
    "commerce.utah.gov",
    # Japan
    "ppc.go.jp", "elaws.e-gov.go.jp", "japaneselawtranslation.go.jp",
    # Canada
    "laws-lois.justice.gc.ca", "priv.gc.ca",
    # Brazil
    "planalto.gov.br", "gov.br",
    # Australia
    "legislation.gov.au", "oaic.gov.au",
}

ALLOWED_PREDICATE_KEYS = {
    "jurisdictions_any", "children_under_13", "directed_at_children", "features_any",
}
ALLOWED_JURISDICTIONS = {
    "worldwide", "eu-eea", "uk", "us-ca", "us-other", "japan", "canada", "brazil", "australia",
}
ALLOWED_FEATURES = {
    "accounts", "payments", "ugc", "messaging", "ai_features", "analytics", "sends_email",
}

REQUIRED_TOP_KEYS = {
    "id", "name", "short_name", "jurisdiction", "source_url", "last_verified",
    "applicability", "obligations", "breach_notification", "user_rights",
    "consent", "children", "not_covered", "lawyer_questions",
}
# Sections that hold a list of items, each of which must carry its own source_url.
ITEM_SECTIONS = ("obligations", "breach_notification", "user_rights", "consent", "children")
SECTION_REQUIRED_KEYS = {
    "obligations": {"id", "summary", "check", "source_url"},
    "breach_notification": {"id", "summary", "deadline", "source_url"},
    "user_rights": {"id", "summary", "source_url"},
    "consent": {"id", "summary", "source_url"},
    "children": {"id", "summary", "source_url"},
}

LAW_FILES = sorted(LAW_DIR.glob("*.yaml"))


def _host_allowed(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    return any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS)


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _is_iso_date(value) -> bool:
    if isinstance(value, dt.datetime):
        return False
    if isinstance(value, dt.date):
        return True
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            dt.date.fromisoformat(value)
            return True
        except ValueError:
            return False
    return False


def _all_items(data: dict):
    """Yield (location, item) for every item that must carry a source_url."""
    for section in ITEM_SECTIONS:
        for item in data.get(section) or []:
            yield f"{section}/{item.get('id')}", item
    for trig in (data.get("applicability") or {}).get("triggers") or []:
        yield f"applicability.triggers/{trig.get('id')}", trig
    if data.get("penalties_note"):
        yield "penalties_note", data["penalties_note"]


def test_law_directory_has_expected_files():
    assert LAW_DIR.is_dir(), f"missing {LAW_DIR}"
    found = {p.stem for p in LAW_FILES}
    assert EXPECTED_IDS <= found, f"missing regimes: {sorted(EXPECTED_IDS - found)}"
    assert (LAW_DIR / "README.md").is_file()


@pytest.mark.parametrize("path", LAW_FILES, ids=lambda p: p.name)
def test_yaml_loads_and_has_required_keys(path):
    data = _load(path)
    assert isinstance(data, dict), f"{path.name} did not load to a mapping"
    missing = REQUIRED_TOP_KEYS - data.keys()
    assert not missing, f"{path.name} missing keys: {sorted(missing)}"
    assert data["id"] == path.stem, f"{path.name}: id {data['id']!r} must match file name"
    for key in ("name", "short_name", "jurisdiction"):
        assert isinstance(data[key], str) and data[key].strip(), f"{path.name}: {key} empty"
    triggers = (data["applicability"] or {}).get("triggers")
    assert isinstance(triggers, list) and triggers, f"{path.name}: applicability.triggers must be a non-empty list"
    for section in ITEM_SECTIONS:
        assert isinstance(data[section], list), f"{path.name}: {section} must be a list"
    assert len(data["obligations"]) >= 4, f"{path.name}: expected at least 4 obligations"
    assert isinstance(data["not_covered"], list) and data["not_covered"], f"{path.name}: not_covered must list what was left out"
    assert isinstance(data["lawyer_questions"], list) and data["lawyer_questions"], f"{path.name}: lawyer_questions missing"


@pytest.mark.parametrize("path", LAW_FILES, ids=lambda p: p.name)
def test_section_items_have_required_keys(path):
    data = _load(path)
    for section, required in SECTION_REQUIRED_KEYS.items():
        for item in data[section]:
            missing = required - item.keys()
            assert not missing, f"{path.name}: {section}/{item.get('id')} missing {sorted(missing)}"
            assert isinstance(item["summary"], str) and item["summary"].strip()
    for trig in data["applicability"]["triggers"]:
        for key in ("id", "description", "source_url"):
            assert trig.get(key), f"{path.name}: trigger {trig.get('id')} missing {key}"


@pytest.mark.parametrize("path", LAW_FILES, ids=lambda p: p.name)
def test_source_urls_are_https_and_official(path):
    data = _load(path)
    urls = [("file", data["source_url"])]
    for where, item in _all_items(data):
        assert item.get("source_url"), f"{path.name}: {where} has no source_url"
        urls.append((where, item["source_url"]))
    for where, url in urls:
        assert isinstance(url, str), f"{path.name}: {where} source_url not a string"
        assert url.startswith("https://"), f"{path.name}: {where} source_url is not https: {url}"
        assert _host_allowed(url), f"{path.name}: {where} source_url not on the official allow-list: {url}"


@pytest.mark.parametrize("path", LAW_FILES, ids=lambda p: p.name)
def test_last_verified_is_iso_date(path):
    data = _load(path)
    assert _is_iso_date(data["last_verified"]), f"{path.name}: last_verified must be an ISO date (YYYY-MM-DD), got {data['last_verified']!r}"
    value = data["last_verified"]
    if isinstance(value, str):
        value = dt.date.fromisoformat(value)
    assert value <= dt.date.today(), f"{path.name}: last_verified is in the future"


@pytest.mark.parametrize("path", LAW_FILES, ids=lambda p: p.name)
def test_header_comment_carries_verify_statement(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    header = []
    for line in lines:
        if line.startswith("#"):
            header.append(line.lower())
        else:
            break
    text = " ".join(header)
    assert len(header) >= 2, f"{path.name}: expected a header comment of at least two lines"
    assert "curated by release-gate from official sources only" in text, f"{path.name}: header must say curated from official sources only"
    assert "rules change" in text and "verify against the official source" in text, (
        f"{path.name}: header must carry the 'rules change, verify against the official source' statement"
    )


def test_ids_are_unique():
    seen_files = {}
    for path in LAW_FILES:
        data = _load(path)
        assert data["id"] not in seen_files, f"duplicate regime id {data['id']} in {path.name} and {seen_files[data['id']]}"
        seen_files[data["id"]] = path.name
        for section in ITEM_SECTIONS:
            ids = [item["id"] for item in data[section]]
            dupes = {i for i in ids if ids.count(i) > 1}
            assert not dupes, f"{path.name}: duplicate ids in {section}: {sorted(dupes)}"
        trig_ids = [t["id"] for t in data["applicability"]["triggers"]]
        assert len(trig_ids) == len(set(trig_ids)), f"{path.name}: duplicate trigger ids"


@pytest.mark.parametrize("path", LAW_FILES, ids=lambda p: p.name)
def test_config_predicates_use_known_keys(path):
    data = _load(path)
    for trig in data["applicability"]["triggers"]:
        pred = trig.get("config_predicate")
        if pred is None:
            continue
        assert isinstance(pred, dict), f"{path.name}: {trig['id']} config_predicate must be a mapping"
        unknown = set(pred) - ALLOWED_PREDICATE_KEYS
        assert not unknown, f"{path.name}: {trig['id']} unknown predicate keys {sorted(unknown)}"
        if "jurisdictions_any" in pred:
            assert set(pred["jurisdictions_any"]) <= ALLOWED_JURISDICTIONS, f"{path.name}: {trig['id']} unknown jurisdiction"
        if "features_any" in pred:
            assert set(pred["features_any"]) <= ALLOWED_FEATURES, f"{path.name}: {trig['id']} unknown feature"
        for flag in ("children_under_13", "directed_at_children"):
            if flag in pred:
                assert isinstance(pred[flag], bool)


def test_allow_list_has_no_non_official_hosts():
    # Guard against someone adding a commercial or community host to the allow-list.
    banned = ("wikipedia", "iapp", "gdpr.eu", "termly", "osano", "cookiebot", "law.cornell", "blog", "medium.com")
    for domain in ALLOWED_DOMAINS:
        assert not any(b in domain for b in banned), f"non-official domain in allow-list: {domain}"
