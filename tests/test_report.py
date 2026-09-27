import csv
import json
from datetime import datetime, timedelta, timezone

from credmon.classify import classify
from credmon.collect import CERTIFICATE, SAML_CERTIFICATE, SECRET, CollectResult, Credential, Owner
from credmon.config import Config
from credmon.report import load_json, render_summary, write_reports

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def cred(name, days, obj=None, cred_type=SECRET, lifetime_days=None, excluded=False, display=None, owners=()):
    obj = obj or f"obj-{name}"
    end = NOW + timedelta(days=days)
    return Credential(
        owners=tuple(owners),
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
        "key_id", "name", "start", "end", "thumbprint", "owners", "long_lived", "excluded", "unowned",
    }

    payload = json.loads(paths.json.read_text())
    assert payload["generated_at"] == "2026-10-05T12:00:00+00:00"
    assert payload["scanned"] == {"applications": 14, "saml_service_principals": 3, "first_party_skipped": 0, "owners_looked_up": False, "unowned_objects": 0}
    assert payload["counts"]["critical"] == 2
    assert [c["name"] for c in payload["credentials"]] == [c.name for c in records]
    assert payload["credentials"][0]["end"] == "2026-10-02T12:00:00+00:00"

    # Nothing that could leak a secret, in any file.
    for p in (paths.summary, paths.csv, paths.json):
        text = p.read_text().lower()
        assert "hint" not in text and "secrettext" not in text


def test_owner_column_appears_only_when_looked_up():
    owner = Owner(id="1", display_name="Pat Example", user_principal_name="pat@example.test")
    records = classify([cred("a", 2, owners=[owner]), cred("b", 3)], Config(), NOW)
    records[1].unowned = True  # collect() sets this when owners were looked up and none exist

    without = render_summary(records, CollectResult(credentials=records, owners_looked_up=False), NOW)
    assert "Owners" not in without and "unowned" not in without.lower()

    with_owners = render_summary(records, CollectResult(credentials=records, owners_looked_up=True), NOW)
    assert "| Status | App | Type | Name | Expires | Days | Owners |" in with_owners
    assert "| 2 | Pat Example |" in with_owners
    assert "| 3 | _none_ |" in with_owners
    assert "**1** object with credentials but no owners" in with_owners


def test_unowned_finding_section_and_json(tmp_path):
    owner = Owner(id="1", display_name="Pat Example")
    records = classify(
        [
            cred("a", 2, obj="hr-sync", owners=[owner]),
            cred("b", 40, obj="payroll"),
            cred("c", 5, obj="payroll"),
            cred("d", 300, obj="legacy", cred_type=SAML_CERTIFICATE, excluded=True),
        ],
        Config(),
        NOW,
    )
    for r in records:
        r.unowned = not r.owners
    stats = CollectResult(credentials=records, owners_looked_up=True)

    findings = stats.unowned_findings()
    assert [(f.display_name, f.credential_count, f.excluded) for f in findings] == [("payroll", 2, False), ("legacy", 1, True)]
    assert findings[0].soonest_end == NOW + timedelta(days=5)

    md = render_summary(records, stats, NOW)
    assert "**2** objects with credentials but no owners. See the finding below." in md
    assert "### Finding: unowned objects" in md
    assert "| App | payroll | 2 | 2026-10-10 |" in md
    assert "| SP | legacy* | 1 | 2027-08-01 |" in md

    paths = write_reports(records, stats, NOW, tmp_path)
    payload = json.loads(paths.json.read_text())
    assert [f["display_name"] for f in payload["findings"]["unowned_objects"]] == ["payroll", "legacy"]
    assert payload["findings"]["unowned_objects"][0]["soonest_end"] == "2026-10-10T12:00:00+00:00"
    with open(paths.csv, newline="") as fh:
        rows = {r["display_name"]: r["unowned"] for r in csv.DictReader(fh)}
    assert rows == {"hr-sync": "False", "payroll": "True", "legacy": "True"}


def test_no_unowned_section_when_owners_not_looked_up():
    records = classify([cred("a", 2)], Config(), NOW)
    md = render_summary(records, CollectResult(credentials=records, owners_looked_up=False), NOW)
    assert "Finding" not in md and "no owners" not in md


def test_csv_and_json_carry_owners(tmp_path):
    owner = Owner(id="1", display_name="Pat Example", user_principal_name="pat@example.test")
    records = classify([cred("a", 2, owners=[owner])], Config(), NOW)
    paths = write_reports(records, CollectResult(credentials=records, owners_looked_up=True), NOW, tmp_path)

    with open(paths.csv, newline="") as fh:
        row = next(csv.DictReader(fh))
    assert row["owners"] == "Pat Example <pat@example.test>"
    payload = json.loads(paths.json.read_text())
    assert payload["scanned"]["unowned_objects"] == 0
    assert payload["credentials"][0]["owners"][0]["user_principal_name"] == "pat@example.test"


def test_json_round_trip(tmp_path):
    records, stats = sample()
    paths = write_reports(records, stats, NOW, tmp_path)

    loaded, meta = load_json(paths.json)

    assert [c.to_dict() for c in loaded] == [c.to_dict() for c in records]
    assert loaded[0].end.tzinfo is not None
    assert meta["scanned"]["applications"] == 14
    assert {c.uid for c in loaded} == {c.uid for c in records}
