import json
from datetime import datetime, timedelta, timezone

import pytest
import responses

from credmon.classify import CLEANUP, CRITICAL, EXPIRED, OK, WARNING
from credmon.collect import SAML_CERTIFICATE, SECRET, Credential
from credmon.notify import (
    LABEL,
    GitHubIssues,
    OpenIssue,
    apply_actions,
    client_from_env,
    issue_body,
    issue_title,
    parse_markers,
    plan_actions,
    sync,
)

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
API = "https://api.github.com/repos/o/r"


def cred(name, status, days=2, obj=None, cred_type=SECRET, excluded=False, thumbprint=None):
    obj = obj or f"obj-{name}"
    return Credential(
        object_type="servicePrincipal" if cred_type == SAML_CERTIFICATE else "application",
        object_id=obj,
        app_id=f"app-{obj}",
        display_name=obj,
        cred_type=cred_type,
        key_id=f"key-{name}",
        name=name,
        start=None,
        end=NOW + timedelta(days=days),
        thumbprint=thumbprint,
        days=days,
        status=status,
        excluded=excluded,
    )


def open_issue(c, number=1, status=None):
    return OpenIssue(number=number, title=issue_title(c), uid=c.uid, status=status or c.status)


# ------------------------------------------------------------------ content


def test_markers_round_trip():
    c = cred("prod", CRITICAL, thumbprint="ABCD")
    body = issue_body(c, NOW)
    assert parse_markers(body) == (c.uid, CRITICAL)
    assert "| Thumbprint | `ABCD` |" in body
    assert "expires in 2 days" in body
    assert "Certificates & secrets" in body
    assert "ApplicationMenuBlade" in body


def test_body_without_thumbprint_and_expired():
    c = cred("prod", EXPIRED, days=-3)
    body = issue_body(c, NOW)
    assert "Thumbprint" not in body
    assert "**obj-prod** has a secret named `prod` that expired" in body
    assert "| Status | **EXPIRED** as of 2026-10-05 12:00 UTC |" in body


def test_saml_body_has_saml_steps_and_link():
    c = cred("CN=x", CRITICAL, cred_type=SAML_CERTIFICATE, thumbprint="FF")
    body = issue_body(c, NOW)
    assert "SAML Certificates" in body
    assert "ManagedAppMenuBlade" in body


def test_title_has_no_day_count():
    c = cred("prod", CRITICAL, days=2)
    assert issue_title(c) == 'CRITICAL: obj-prod secret "prod" expires 2026-10-07'


def test_parse_markers_tolerates_garbage():
    assert parse_markers(None) == (None, None)
    assert parse_markers("hello") == (None, None)
    assert parse_markers("<!-- credmon:uid=a:b -->") == ("a:b", None)


# ------------------------------------------------------------------ planning


def kinds(actions):
    return sorted((a.kind, a.record.name if a.record else a.issue.number) for a in actions if a.kind != "noop")


def test_creates_for_critical_and_expired_only():
    records = [cred("crit", CRITICAL), cred("dead", EXPIRED, days=-1), cred("warn", WARNING, days=20),
               cred("ok", OK, days=200), cred("old", CLEANUP)]
    assert kinds(plan_actions(records, [])) == [("create", "crit"), ("create", "dead")]


def test_excluded_never_gets_an_issue():
    assert plan_actions([cred("crit", CRITICAL, excluded=True)], []) == []


def test_existing_issue_same_severity_is_noop():
    c = cred("crit", CRITICAL)
    actions = plan_actions([c], [open_issue(c)])
    assert [a.kind for a in actions] == ["noop"]
    assert "still critical" in actions[0].reason


def test_existing_issue_severity_changed_is_update():
    c = cred("crit", EXPIRED, days=-1)
    actions = plan_actions([c], [open_issue(c, status=CRITICAL)])
    assert [(a.kind, a.reason) for a in actions] == [("update", "severity critical -> expired")]


def test_rotated_credential_closes_issue():
    c = cred("old", CLEANUP)
    actions = plan_actions([c], [open_issue(c, status=CRITICAL)])
    assert [(a.kind, a.reason) for a in actions] == [("close", "credential is now cleanup")]


def test_removed_credential_closes_issue():
    gone = cred("gone", CRITICAL)
    actions = plan_actions([], [open_issue(gone)])
    assert [(a.kind, a.reason) for a in actions] == [("close", "credential no longer exists")]


def test_newly_excluded_credential_closes_issue():
    c = cred("crit", CRITICAL, excluded=True)
    actions = plan_actions([c], [open_issue(c)])
    assert [(a.kind, a.reason) for a in actions] == [("close", "app is now excluded via exclude_app_ids")]


def test_issue_without_marker_is_left_alone():
    stray = OpenIssue(number=9, title="manual", uid=None, status=None)
    actions = plan_actions([], [stray])
    assert [a.kind for a in actions] == ["noop"]


def test_duplicate_issues_only_first_is_managed():
    c = cred("crit", CRITICAL)
    first, second = open_issue(c, number=1), open_issue(c, number=2)
    actions = plan_actions([c], [first, second])
    assert [(a.kind, a.issue.number) for a in actions] == [("noop", 2), ("noop", 1)]
    assert "duplicate of #1" in actions[0].reason


def test_one_scan_can_create_update_and_close_together():
    new = cred("new", CRITICAL)
    worse = cred("worse", EXPIRED, days=-2)
    fixed = cred("fixed", OK, days=300)
    actions = plan_actions(
        [new, worse, fixed],
        [open_issue(worse, 1, status=CRITICAL), open_issue(fixed, 2, status=CRITICAL)],
    )
    assert kinds(actions) == [("close", "fixed"), ("create", "new"), ("update", "worse")]


# ------------------------------------------------------------------ apply / HTTP


@pytest.fixture
def gh():
    return GitHubIssues(repo="o/r", token="t", api="https://api.github.com")


def test_dry_run_makes_no_requests(gh):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        result = apply_actions(plan_actions([cred("crit", CRITICAL)], []), gh, NOW, dry_run=True)
        assert result.count("create") == 1
        assert len(rsps.calls) == 0


@responses.activate
def test_create_flow_ensures_label_and_posts_issue(gh):
    responses.get(f"{API}/labels/{LABEL}", status=404)
    responses.post(f"{API}/labels", json={"name": LABEL})
    responses.post(f"{API}/issues", json={"number": 42})

    apply_actions(plan_actions([cred("crit", CRITICAL)], []), gh, NOW)

    created = json.loads(responses.calls[2].request.body)
    assert created["labels"] == [LABEL]
    assert created["title"].startswith("CRITICAL: obj-crit")
    assert "<!-- credmon:uid=obj-crit:key-crit -->" in created["body"]
    assert responses.calls[2].request.headers["Authorization"] == "Bearer t"


@responses.activate
def test_update_flow_patches_and_comments(gh):
    c = cred("crit", EXPIRED, days=-1)
    responses.get(f"{API}/labels/{LABEL}", json={"name": LABEL})
    responses.patch(f"{API}/issues/7", json={})
    responses.post(f"{API}/issues/7/comments", json={})

    apply_actions(plan_actions([c], [open_issue(c, 7, status=CRITICAL)]), gh, NOW)

    patched = json.loads(responses.calls[1].request.body)
    assert patched["title"].startswith("EXPIRED:")
    assert "<!-- credmon:status=expired -->" in patched["body"]
    comment = json.loads(responses.calls[2].request.body)["body"]
    assert "**critical** → **expired**" in comment


@responses.activate
def test_close_flow_comments_then_closes(gh):
    c = cred("old", CLEANUP)
    responses.get(f"{API}/labels/{LABEL}", json={"name": LABEL})
    responses.post(f"{API}/issues/3/comments", json={})
    responses.patch(f"{API}/issues/3", json={})

    apply_actions(plan_actions([c], [open_issue(c, 3, status=CRITICAL)]), gh, NOW)

    assert "Resolved: credential is now cleanup" in json.loads(responses.calls[1].request.body)["body"]
    assert json.loads(responses.calls[2].request.body) == {"state": "closed", "state_reason": "completed"}


@responses.activate
def test_noop_only_run_makes_no_writes(gh):
    c = cred("crit", CRITICAL)
    responses.get(f"{API}/issues", json=[{"number": 1, "title": "t", "body": issue_body(c, NOW)}])

    result = sync([c], gh, NOW)

    assert result.count("noop") == 1
    assert len(responses.calls) == 1  # only the list call


@responses.activate
def test_list_open_issues_paginates_and_skips_pull_requests(gh):
    c = cred("crit", CRITICAL)
    page1 = [{"number": i, "title": "t", "body": f"<!-- credmon:uid=u{i} --><!-- credmon:status=critical -->"} for i in range(100)]
    page2 = [
        {"number": 200, "title": "real", "body": issue_body(c, NOW)},
        {"number": 201, "title": "a PR", "body": issue_body(c, NOW), "pull_request": {}},
        {"number": 202, "title": "manual", "body": "no marker"},
    ]
    responses.get(f"{API}/issues", json=page1, match=[responses.matchers.query_param_matcher({"state": "open", "labels": LABEL, "per_page": "100", "page": "1"})])
    responses.get(f"{API}/issues", json=page2, match=[responses.matchers.query_param_matcher({"state": "open", "labels": LABEL, "per_page": "100", "page": "2"})])

    issues = gh.list_open_issues()

    assert len(issues) == 102
    assert issues[100].uid == c.uid and issues[100].status == CRITICAL
    assert issues[101].uid is None


@responses.activate
def test_http_error_raises(gh):
    responses.get(f"{API}/issues", status=403, json={"message": "Resource not accessible by integration"})
    with pytest.raises(RuntimeError, match="403"):
        gh.list_open_issues()


def test_client_from_env_requires_token_and_repo():
    with pytest.raises(SystemExit, match="GH_TOKEN and GH_REPO"):
        client_from_env({})
    with pytest.raises(SystemExit, match="GH_REPO"):
        client_from_env({"GH_TOKEN": "x"})
    c = client_from_env({"GITHUB_TOKEN": "x", "GITHUB_REPOSITORY": "o/r"})
    assert c.repo == "o/r"
