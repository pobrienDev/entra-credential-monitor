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
    "cred_type", "key_id", "name", "start", "end", "thumbprint", "long_lived", "excluded",
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


def _md_table(records: list[Credential]) -> str:
    lines = [
        "| Status | App | Type | Name | Expires | Days |",
        "|--------|-----|------|------|---------|-----:|",
    ]
    for c in records:
        lines.append(
            f"| {display_status(c)} | {_md_escape(c.display_name)} | {type_label(c)} "
            f"| {_md_escape(c.name)} | {c.end:%Y-%m-%d} | {c.days} |"
        )
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
    if attention:
        parts += [_md_table(attention), ""]
    else:
        parts += ["Nothing needs attention.", ""]
    if healthy:
        parts += [
            "<details>",
            f"<summary>{len(healthy)} healthy credential{'s' if len(healthy) != 1 else ''}</summary>",
            "",
            _md_table(healthy),
            "",
            "</details>",
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
            writer.writerow(c.to_dict())


def write_json(records: list[Credential], stats: CollectResult, now: datetime, path: Path) -> None:
    payload = {
        "generated_at": now.isoformat(),
        "credmon_version": __version__,
        "scanned": {
            "applications": stats.applications_scanned,
            "saml_service_principals": stats.saml_service_principals_scanned,
            "first_party_skipped": stats.first_party_skipped,
        },
        "counts": summarize(records),
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
