"""policy_consistency: denial claims vs inventory, with clean-twin false-positive guards."""
import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "skills" / "release-gate" / "scripts" / "policy_consistency.py"
spec = importlib.util.spec_from_file_location("policy_consistency", SCRIPT)
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)
sys.path.insert(0, str(SCRIPT.parent))
import rglib  # noqa: E402


def inv(fields=None, third_parties=None, client_storage=None, rights=None):
    return {"schema_version": 1, "generated_at": rglib.now_iso(), "fields": fields or [],
            "third_parties": third_parties or [], "client_storage": client_storage or [],
            "stores": [], "log_sinks": [], **({"rights": rights} if rights else {})}


TELEMETRY_TP = [{"host": "track.example.com", "role": "subprocessor",
                 "purpose": "analytics/telemetry egress", "provenance": {"source": "code", "refs": ["a.py:1"]}}]
USER_FETCH_TP = [{"host": "<dynamic-egress>", "role": "unknown",
                  "purpose": "outbound request with a non-literal URL", "provenance": {"source": "code", "refs": ["a.py:9"]}}]


def test_no_share_claim_flagged_when_telemetry_present():
    pol = "We never share your data with third parties or analytics vendors."
    out = pc.check_claims(pol, "privacy.html", inv(third_parties=TELEMETRY_TP))
    assert any(f["category"] == "policy-mismatch" and f["evidence_class"] == "TOOL-CONFIRMED" for f in out)
    assert all(rglib.validate(f, "finding") == [] for f in out)


def test_no_share_claim_not_flagged_for_user_fetch_only():
    # a user-supplied URL fetch (SSRF/preview feature) is not data sharing
    pol = "We never share your data with third parties."
    assert pc.check_claims(pol, "privacy.html", inv(third_parties=USER_FETCH_TP)) == []


def test_conditional_tracking_disclosure_not_flagged():
    # the clean twin: tracking only after consent is a truthful disclosure, not a denial
    pol = ("We use an analytics service that sets a tracking cookie. It loads only after you click Accept. "
           "If you click Reject, no analytics script is loaded and no tracking cookie is set.")
    assert pc.check_claims(pol, "privacy.html", inv(third_parties=TELEMETRY_TP)) == []


def test_blanket_no_tracking_claim_flagged_suspected():
    pol = "We do not use trackers, analytics or advertising cookies."
    out = pc.check_claims(pol, "privacy.html", inv(third_parties=TELEMETRY_TP))
    assert out and out[0]["evidence_class"] == "SUSPECTED"  # needs the cookie audit to confirm/refute


def test_deletion_claim_flagged_when_no_impl_but_not_when_present():
    pol = "When you delete your account, all of your personal data is permanently erased."
    flagged = pc.check_claims(pol, "privacy.html", inv())
    assert flagged and flagged[0]["category"] == "policy-mismatch" and flagged[0]["evidence_class"] == "SUSPECTED"
    has_del = inv(rights={"deletion": {"source": "code", "refs": ["app.py:1"]}})
    assert pc.check_claims(pol, "privacy.html", has_del) == []


def test_clean_policy_with_no_denials_is_silent():
    pol = "We collect your email to run your account and we use an analytics service with your consent."
    assert pc.check_claims(pol, "privacy.html", inv(fields=[{"name": "email", "classification": "contact",
            "provenance": {"source": "code", "refs": ["a.py:1"]}}], third_parties=TELEMETRY_TP)) == []
