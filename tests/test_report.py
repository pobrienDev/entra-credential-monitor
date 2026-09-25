import csv
import json
from datetime import datetime, timedelta, timezone

from credmon.classify import classify
from credmon.collect import CERTIFICATE, SAML_CERTIFICATE, SECRET, CollectResult, Credential
from credmon.config import Config
from credmon.report import load_json, render_summary, write_reports

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def cred(name, days, obj=None, cred_type=SECRET, lifetime_days=None, excluded=False, display=None):
    obj = obj or f"obj-{name}"
    end = NOW + timedelta(days=days)
    return Credential(
        object_type="servicePrincipal" if cred_type == SAML_CERTIFICATE else "application",
        object_id=obj,
        app_id=f"app-{obj}",
        display_name=display or obj,
        cred_type=cred_type,
        key_id=f"key-{name}",
        name=name,
        start=end - timedelta(days=lifetime_days) if lifetime_days else None,
        end=end,
        thumbprint="ABCD" if cred_type != SECRET else None,
        excluded=excluded,
    )


def sample():
    records = [
        cred("prod-2025", 4, display="hr-sync"),
        cred("CN=Toolkit", 23, cred_type=SAML_CERTIFICATE, display="SAML Toolkit"),
        cred("payroll-crt", 56, cred_type=CERTIFICATE, display="payroll-export"),
        cred("old-key", 2, obj="reporting", display="reporting-api"),
        cred("new-key", 300, obj="reporting", display="reporting-api"),
        cred("forever", 697, lifetime_days=730, display="legacy-connector"),
        cred("accepted", 1, excluded=True, display="risk|accepted"),
        cred("dead", -3, display="zombie"),
    ]
    stats = CollectResult(credentials=records, applications_scanned=14, saml_service_principals_scanned=3)
    return classify(records, Config(), NOW), stats


def test_summary_markdown_structure_and_order():
    records, stats = sample()
    md = render_summary(records, stats, NOW)

    assert md.startswith("## Credential expiry report · 2026-10-05 12:00 UTC\n")
    assert "Scanned 14 applications and 3 SAML service principals · 8 credentials" in md
    assert "**expired** 1 · **critical** 2 · **warning** 1 · **notice** 1 · **cleanup** 1 · **ok** 2 · **hygiene** 1" in md

    rows = [l for l in md.splitlines() if l.startswith("| ") and not l.startswith("| Status")]
    statuses = [r.split("|")[1].strip() for r in rows]
    assert statuses == ["EXPIRED", "CRITICAL*", "CRITICAL", "WARNING", "NOTICE", "CLEANUP", "HYGIENE", "OK"]
    # Healthy rows are folded away; HYGIENE is not healthy.
    assert "<details>" in md and "<summary>1 healthy credential</summary>" in md
    assert md.index("HYGIENE") < md.index("<details>")
    assert "| HYGIENE | legacy-connector | Secret | forever | 2028-09-01 | 697 |" in md
    assert "| WARNING | SAML Toolkit | SAML cert | CN=Toolkit | 2026-10-28 | 23 |" in md
    assert "risk\\|accepted" in md  # pipes escaped so the table doesn't break
    assert "excluded via" in md


def test_summary_when_nothing_needs_attention():
    records = classify([cred("fine", 200)], Config(), NOW)
    md = render_summary(records, CollectResult(applications_scanned=1), NOW)
    assert "Nothing needs attention." in md
    assert "<summary>1 healthy credential</summary>" in md


def test_summary_when_empty():
    md = render_summary([], CollectResult(), NOW)
    assert "No credentials found." in md
    assert "<details>" not in md


def test_write_reports_creates_three_consistent_files(tmp_path):
    records, stats = sample()
    paths = write_reports(records, stats, NOW, tmp_path / "report")

    assert {p.name for p in (tmp_path / "report").iterdir()} == {"summary.md", "credentials.csv", "credentials.json"}

    with open(paths.csv, newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["status"] for r in rows] == [c.status for c in records]
    assert rows[0]["display_name"] == "zombie" and rows[0]["days"] == "-3"
    assert set(rows[0]) == {
        "status", "days", "object_type", "object_id", "app_id", "display_name", "cred_type",
        "key_id", "name", "start", "end", "thumbprint", "long_lived", "excluded",
    }

    payload = json.loads(paths.json.read_text())
    assert payload["generated_at"] == "2026-10-05T12:00:00+00:00"
    assert payload["scanned"] == {"applications": 14, "saml_service_principals": 3, "first_party_skipped": 0}
    assert payload["counts"]["critical"] == 2
    assert [c["name"] for c in payload["credentials"]] == [c.name for c in records]
    assert payload["credentials"][0]["end"] == "2026-10-02T12:00:00+00:00"

    # Nothing that could leak a secret, in any file.
    for p in (paths.summary, paths.csv, paths.json):
        text = p.read_text().lower()
        assert "hint" not in text and "secrettext" not in text


def test_json_round_trip(tmp_path):
    records, stats = sample()
    paths = write_reports(records, stats, NOW, tmp_path)

    loaded, meta = load_json(paths.json)

    assert [c.to_dict() for c in loaded] == [c.to_dict() for c in records]
    assert loaded[0].end.tzinfo is not None
    assert meta["scanned"]["applications"] == 14
    assert {c.uid for c in loaded} == {c.uid for c in records}
