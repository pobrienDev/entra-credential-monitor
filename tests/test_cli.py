import json

import pytest
import responses

from credmon import cli
from credmon.cli import build_parser, main
from credmon.graph import GRAPH
from tests.conftest import load_fixture

CONFIG = """
thresholds:
  critical_days: 7
  warning_days: 30
  notice_days: 60
tenant_id: 6c3eca84-802c-4606-869d-c1b7c87d8320
fail_on: FAIL_ON
"""


def test_scan_defaults():
    args = build_parser().parse_args(["scan"])
    assert args.command == "scan"
    assert args.config == "config.yaml"
    assert args.format == "files"
    assert args.out == "report"


def test_notify_defaults():
    args = build_parser().parse_args(["notify"])
    assert args.report == "report/credentials.json"


@pytest.fixture
def graph(monkeypatch, session):
    """Mock Graph with the fixtures and make the CLI use a pre-authenticated session."""
    monkeypatch.setattr(cli, "get_session", lambda: session)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        page1 = load_fixture("applications_page1.json")
        rsps.get(f"{GRAPH}/applications", json=page1)
        rsps.get(page1["@odata.nextLink"], json=load_fixture("applications_page2.json"))
        rsps.get(f"{GRAPH}/servicePrincipals", json=load_fixture("service_principals.json"))
        yield rsps


NOW = "2026-10-05T12:00:00Z"  # payroll prod-2025 is 4 days out: critical


def write_config(tmp_path, fail_on="critical"):
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG.replace("FAIL_ON", fail_on))
    return str(path)


def test_scan_files_writes_reports_and_fails_on_critical(tmp_path, graph, capsys):
    rc = main(["scan", "--config", write_config(tmp_path), "--out", str(tmp_path / "out"), "--now", NOW])

    assert rc == 1
    err = capsys.readouterr().err
    assert "Scanned 3 applications and 1 SAML service principals · 5 credentials" in err
    assert "fail_on=critical" in err
    payload = json.loads((tmp_path / "out" / "credentials.json").read_text())
    assert len(payload["credentials"]) == 5
    assert payload["generated_at"] == "2026-10-05T12:00:00+00:00"
    assert payload["counts"] == {"expired": 0, "critical": 1, "warning": 0, "notice": 1, "cleanup": 1, "ok": 2, "hygiene": 1}
    assert (tmp_path / "out" / "summary.md").read_text().startswith("## Credential expiry report")
    assert (tmp_path / "out" / "credentials.csv").exists()


def test_scan_exit_zero_when_fail_on_never(tmp_path, graph):
    assert main(["scan", "--config", write_config(tmp_path, "never"), "--out", str(tmp_path / "out"), "--now", NOW]) == 0


def test_scan_table_prints_rows(tmp_path, graph, capsys):
    rc = main(["scan", "--config", write_config(tmp_path, "never"), "--format", "table", "--now", NOW])

    assert rc == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("Status")
    assert "Microsoft Entra SAML Toolkit" in out
    assert "SAML cert" in out
    assert out.count("\n") == 2 + 5  # header, rule, five credentials
    assert "CuH" not in out and "fhx" not in out  # hints never printed


def test_scan_rejects_bad_config(tmp_path, graph):
    bad = tmp_path / "config.yaml"
    bad.write_text("fail_on: sometimes\n")
    with pytest.raises(ValueError, match="fail_on"):
        main(["scan", "--config", str(bad)])
