"""Write Markdown, CSV and JSON reports from classified credentials.

All three come from the same records so they never disagree. The Markdown goes
into the GitHub Actions run summary; the JSON feeds ``credmon notify``.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from credmon import __version__
from credmon.classify import OK, summarize
from credmon.collect import Credential, CollectResult

TYPE_LABELS = {"secret": "Secret", "certificate": "Certificate", "saml_certificate": "SAML cert"}
CSV_FIELDS = [
    "status", "days", "object_type", "object_id", "app_id", "display_name",
    "cred_type", "key_id", "name", "start", "end", "thumbprint", "owners", "long_lived", "excluded", "unowned",
]
SUMMARY_MD = "summary.md"
CREDENTIALS_CSV = "credentials.csv"
CREDENTIALS_JSON = "credentials.json"


@dataclass(frozen=True)
class ReportPaths:
    summary: Path
    csv: Path
    json: Path


def display_status(c: Credential) -> str:
    """Label for humans. HYGIENE shows only when nothing more urgent applies."""
    if c.status == OK and c.long_lived:
        return "HYGIENE"
    label = (c.status or OK).upper()
    if c.excluded:
        label += "*"
    return label


def type_label(c: Credential) -> str:
    return TYPE_LABELS.get(c.cred_type, c.cred_type)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _owners_cell(c: Credential, looked_up: bool) -> str:
    if not looked_up:
        return ""
    if not c.owners:
        return "_none_"
    return _md_escape(", ".join(o.display_name or o.user_principal_name or o.mail or o.id for o in c.owners))


def _md_table(records: list[Credential], owners: bool = False) -> str:
    head = "| Status | App | Type | Name | Expires | Days |" + (" Owners |" if owners else "")
    rule = "|--------|-----|------|------|---------|-----:|" + ("--------|" if owners else "")
    lines = [head, rule]
    for c in records:
        row = (
            f"| {display_status(c)} | {_md_escape(c.display_name)} | {type_label(c)} "
            f"| {_md_escape(c.name)} | {c.end:%Y-%m-%d} | {c.days} |"
        )
        if owners:
            row += f" {_owners_cell(c, True)} |"
        lines.append(row)
    return "\n".join(lines)


def render_summary(records: list[Credential], stats: CollectResult, now: datetime) -> str:
    counts = summarize(records)
    attention = [c for c in records if c.status != OK or c.long_lived]
    healthy = [c for c in records if c.status == OK and not c.long_lived]

    parts = [
        f"## Credential expiry report · {now:%Y-%m-%d %H:%M} UTC",
        "",
        f"Scanned {stats.applications_scanned} applications and "
        f"{stats.saml_service_principals_scanned} SAML service principals · "
        f"{len(records)} credentials",
        "",
        " · ".join(f"**{k}** {v}" for k, v in counts.items() if v) or "No credentials found.",
        "",
    ]
    unowned = stats.unowned_findings()
    if unowned:
        parts += [
            f"**{len(unowned)}** object{'s' if len(unowned) != 1 else ''} with credentials "
            "but no owners. See the finding below.",
            "",
        ]
    if attention:
        parts += [_md_table(attention, owners=stats.owners_looked_up), ""]
    else:
        parts += ["Nothing needs attention.", ""]
    if healthy:
        parts += [
            "<details>",
            f"<summary>{len(healthy)} healthy credential{'s' if len(healthy) != 1 else ''}</summary>",
            "",
            _md_table(healthy, owners=stats.owners_looked_up),
            "",
            "</details>",
            "",
        ]
    if unowned:
        parts += [
            "### Finding: unowned objects",
            "",
            "These objects hold live credentials but have no owners, so nobody is accountable for rotating them. "
            "Assign an owner under **Owners** on each app registration or enterprise application.",
            "",
            "| Object | App | Credentials | Soonest expiry |",
            "|--------|-----|------------:|----------------|",
            *(
                f"| {'App' if f.object_type == 'application' else 'SP'} | {_md_escape(f.display_name)}"
                f"{'*' if f.excluded else ''} | {f.credential_count} | {f.soonest_end:%Y-%m-%d} |"
                for f in unowned
            ),
            "",
        ]
    if any(c.excluded for c in records):
        parts += ["\\* excluded via `exclude_app_ids`: reported but never alerted.", ""]
    parts += [
        f"<sub>credmon {__version__} · rotation detection marks superseded credentials as CLEANUP · "
        "HYGIENE marks secrets with lifetimes over the configured limit</sub>",
    ]
    return "\n".join(parts) + "\n"


def write_csv(records: list[Credential], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for c in records:
            row = c.to_dict()
            row["owners"] = c.owners_text
            writer.writerow(row)


def write_json(records: list[Credential], stats: CollectResult, now: datetime, path: Path) -> None:
    payload = {
        "generated_at": now.isoformat(),
        "credmon_version": __version__,
        "scanned": {
            "applications": stats.applications_scanned,
            "saml_service_principals": stats.saml_service_principals_scanned,
            "first_party_skipped": stats.first_party_skipped,
            "owners_looked_up": stats.owners_looked_up,
            "unowned_objects": stats.unowned_objects,
        },
        "counts": summarize(records),
        "findings": {"unowned_objects": [f.to_dict() for f in stats.unowned_findings()]},
        "credentials": [c.to_dict() for c in records],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_json(path: str | Path) -> tuple[list[Credential], dict]:
    """Read credentials.json back. Returns (records, metadata)."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    records = [Credential.from_dict(d) for d in payload.get("credentials", [])]
    meta = {k: v for k, v in payload.items() if k != "credentials"}
    return records, meta


def write_reports(records: list[Credential], stats: CollectResult, now: datetime, out_dir: str | Path) -> ReportPaths:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = ReportPaths(out / SUMMARY_MD, out / CREDENTIALS_CSV, out / CREDENTIALS_JSON)
    paths.summary.write_text(render_summary(records, stats, now), encoding="utf-8")
    write_csv(records, paths.csv)
    write_json(records, stats, now, paths.json)
    return paths
