"""Open, update and close GitHub issues so each alertable credential has exactly one.

Rules (see the project plan, Phase 5):

* critical or expired, no open issue  -> open one labelled ``credential-expiry``
* open issue exists                   -> update only if the severity changed
* credential gone, healthy or rotated -> comment "resolved" and close it
* warning, notice, cleanup, excluded  -> report only, never an issue

Each issue body carries hidden markers so the credential is matched by its stable
id, never by title. The built-in ``GITHUB_TOKEN`` is enough when the workflow
grants ``issues: write``.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime

import requests

from credmon.classify import ALERTABLE
from credmon.collect import SAML_CERTIFICATE, Credential
from credmon.report import type_label

log = logging.getLogger(__name__)

LABEL = "credential-expiry"
LABEL_COLOR = "d93f0b"
LABEL_DESCRIPTION = "Opened and closed automatically by credmon"
UID_MARKER = "<!-- credmon:uid={uid} -->"
STATUS_MARKER = "<!-- credmon:status={status} -->"
MARKER_RE = re.compile(r"<!--\s*credmon:(uid|status)=([^\s>]+)\s*-->")
GITHUB_API = "https://api.github.com"


@dataclass
class OpenIssue:
    number: int
    title: str
    uid: str | None
    status: str | None


@dataclass
class Action:
    kind: str  # "create" | "update" | "close" | "noop"
    record: Credential | None = None
    issue: OpenIssue | None = None
    reason: str = ""

    def describe(self) -> str:
        who = self.record.display_name if self.record else (self.issue.title if self.issue else "?")
        num = f" #{self.issue.number}" if self.issue else ""
        return f"{self.kind:<6}{num} {who}: {self.reason}".rstrip()


@dataclass
class SyncResult:
    actions: list[Action] = field(default_factory=list)

    def count(self, kind: str) -> int:
        return sum(1 for a in self.actions if a.kind == kind)


# --------------------------------------------------------------------------- content


def parse_markers(body: str | None) -> tuple[str | None, str | None]:
    found = dict(MARKER_RE.findall(body or ""))
    return found.get("uid"), found.get("status")


def issue_title(c: Credential) -> str:
    return f"{c.status.upper()}: {c.display_name} {type_label(c).lower()} \"{c.name}\" expires {c.end:%Y-%m-%d}"


def _portal_link(c: Credential) -> str:
    if c.object_type == "servicePrincipal":
        return (
            f"https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SignOn"
            f"/objectId/{c.object_id}/appId/{c.app_id}"
        )
    return (
        f"https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials"
        f"/appId/{c.app_id}"
    )


def issue_body(c: Credential, now: datetime) -> str:
    when = "expired" if c.days is not None and c.days < 0 else f"expires in {c.days} day{'s' if c.days != 1 else ''}"
    if c.cred_type == SAML_CERTIFICATE:
        steps = (
            "1. Open the enterprise application's **Single sign-on** page (link below).\n"
            "2. Under **SAML Certificates**, edit and create a **new certificate**, then make it **active**.\n"
            "3. Download the new certificate or metadata and upload it to the application's SAML settings.\n"
            "4. Confirm sign-in works, then delete the old certificate in Entra.\n"
        )
    else:
        steps = (
            "1. Open the app registration's **Certificates & secrets** page (link below).\n"
            f"2. Create a new {type_label(c).lower()} and update every place the old one is used.\n"
            "3. Confirm the app authenticates with the new credential.\n"
            "4. Delete the old credential. This issue closes automatically once it is gone or replaced.\n"
        )
    lines = [
        f"**{c.display_name}** has a {type_label(c).lower()} named `{c.name}` that {when} "
        f"(**{c.end:%Y-%m-%d %H:%M} UTC**).",
        "",
        "| | |",
        "|---|---|",
        f"| Object | {c.object_type} `{c.object_id}` |",
        f"| App ID | `{c.app_id}` |",
        f"| Credential | {type_label(c)} `{c.key_id}` |",
    ]
    if c.thumbprint:
        lines.append(f"| Thumbprint | `{c.thumbprint}` |")
    lines += [
        f"| Status | **{c.status.upper()}** as of {now:%Y-%m-%d %H:%M} UTC |",
        "",
        "### What to do",
        "",
        steps.rstrip(),
        "",
        f"[Open in Entra admin center]({_portal_link(c)})",
        "",
        "<sub>Opened by credmon. It updates this issue only when the severity changes and closes it "
        "automatically when the credential is rotated or removed.</sub>",
        "",
        UID_MARKER.format(uid=c.uid),
        STATUS_MARKER.format(status=c.status),
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- planning


def plan_actions(records: list[Credential], open_issues: list[OpenIssue]) -> list[Action]:
    """Decide what to do. Pure function: no HTTP, fully testable."""
    alertable = {c.uid: c for c in records if c.status in ALERTABLE and not c.excluded}
    by_uid: dict[str, OpenIssue] = {}
    actions: list[Action] = []

    for issue in open_issues:
        if issue.uid is None:
            actions.append(Action("noop", issue=issue, reason="no credmon marker, left alone"))
            continue
        if issue.uid in by_uid:
            actions.append(Action("noop", issue=issue, reason=f"duplicate of #{by_uid[issue.uid].number}, left alone"))
            continue
        by_uid[issue.uid] = issue

    for uid, c in alertable.items():
        issue = by_uid.get(uid)
        if issue is None:
            actions.append(Action("create", record=c, reason=f"{c.status}, no open issue"))
        elif issue.status != c.status:
            actions.append(Action("update", record=c, issue=issue, reason=f"severity {issue.status} -> {c.status}"))
        else:
            actions.append(Action("noop", record=c, issue=issue, reason=f"still {c.status}"))

    current = {c.uid: c for c in records}
    for uid, issue in by_uid.items():
        if uid in alertable:
            continue
        c = current.get(uid)
        if c is None:
            reason = "credential no longer exists"
        elif c.excluded:
            reason = "app is now excluded via exclude_app_ids"
        else:
            reason = f"credential is now {c.status}"
        actions.append(Action("close", record=c, issue=issue, reason=reason))

    return actions


# --------------------------------------------------------------------------- GitHub client


class GitHubIssues:
    def __init__(self, repo: str, token: str, session: requests.Session | None = None, api: str = GITHUB_API):
        self.repo = repo
        self.api = api.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    def _url(self, path: str) -> str:
        return f"{self.api}/repos/{self.repo}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        resp = self.session.request(method, self._url(path), timeout=30, **kwargs)
        if resp.status_code >= 400:
            raise RuntimeError(f"GitHub {method} {path} failed: {resp.status_code} {resp.text[:300]}")
        return resp

    def ensure_label(self) -> None:
        resp = self.session.get(self._url(f"labels/{LABEL}"), timeout=30)
        if resp.status_code == 404:
            self._request("POST", "labels", json={"name": LABEL, "color": LABEL_COLOR, "description": LABEL_DESCRIPTION})
        elif resp.status_code >= 400:
            raise RuntimeError(f"GitHub GET labels/{LABEL} failed: {resp.status_code}")

    def list_open_issues(self) -> list[OpenIssue]:
        out: list[OpenIssue] = []
        page = 1
        while True:
            resp = self._request("GET", "issues", params={"state": "open", "labels": LABEL, "per_page": 100, "page": page})
            items = resp.json()
            for it in items:
                if "pull_request" in it:
                    continue
                uid, status = parse_markers(it.get("body"))
                out.append(OpenIssue(number=it["number"], title=it["title"], uid=uid, status=status))
            if len(items) < 100:
                return out
            page += 1

    def create_issue(self, title: str, body: str) -> int:
        return self._request("POST", "issues", json={"title": title, "body": body, "labels": [LABEL]}).json()["number"]

    def update_issue(self, number: int, title: str, body: str) -> None:
        self._request("PATCH", f"issues/{number}", json={"title": title, "body": body})

    def comment(self, number: int, body: str) -> None:
        self._request("POST", f"issues/{number}/comments", json={"body": body})

    def close_issue(self, number: int) -> None:
        self._request("PATCH", f"issues/{number}", json={"state": "closed", "state_reason": "completed"})


# --------------------------------------------------------------------------- apply


def apply_actions(actions: list[Action], client: GitHubIssues | None, now: datetime, dry_run: bool = False) -> SyncResult:
    result = SyncResult(actions=actions)
    writes = [a for a in actions if a.kind != "noop"]
    if dry_run or client is None:
        for a in actions:
            log.info("dry-run %s", a.describe())
        return result
    if writes:
        client.ensure_label()
    for a in writes:
        if a.kind == "create":
            number = client.create_issue(issue_title(a.record), issue_body(a.record, now))
            log.info("opened #%s for %s", number, a.record.display_name)
        elif a.kind == "update":
            client.update_issue(a.issue.number, issue_title(a.record), issue_body(a.record, now))
            client.comment(a.issue.number, f"Severity changed: **{a.issue.status}** → **{a.record.status}** as of {now:%Y-%m-%d %H:%M} UTC.")
            log.info("updated #%s: %s", a.issue.number, a.reason)
        elif a.kind == "close":
            client.comment(a.issue.number, f"Resolved: {a.reason} as of {now:%Y-%m-%d %H:%M} UTC. Closing automatically.")
            client.close_issue(a.issue.number)
            log.info("closed #%s: %s", a.issue.number, a.reason)
    return result


def sync(records: list[Credential], client: GitHubIssues | None, now: datetime, dry_run: bool = False) -> SyncResult:
    open_issues = client.list_open_issues() if client is not None else []
    return apply_actions(plan_actions(records, open_issues), client, now, dry_run=dry_run)


def client_from_env(env: dict[str, str] | None = None) -> GitHubIssues:
    env = os.environ if env is None else env
    token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")
    repo = env.get("GH_REPO") or env.get("GITHUB_REPOSITORY")
    missing = [n for n, v in (("GH_TOKEN", token), ("GH_REPO", repo)) if not v]
    if missing:
        raise SystemExit(f"credmon notify: set {' and '.join(missing)} (owner/repo)")
    return GitHubIssues(repo=repo, token=token)
