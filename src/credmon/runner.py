"""One scan, start to finish, shared by the CLI and the Azure Function."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from credmon.classify import classify, should_fail, summarize
from credmon.collect import CollectResult, Credential, collect
from credmon.config import Config
from credmon.graph import get_session
from credmon.report import ReportPaths, write_reports


@dataclass
class ScanResult:
    records: list[Credential]
    stats: CollectResult
    now: datetime
    paths: ReportPaths | None
    failed: bool  # any non-excluded credential at or above config.fail_on

    @property
    def counts(self) -> dict[str, int]:
        counts = summarize(self.records)
        if self.stats.owners_looked_up:
            counts["unowned"] = self.stats.unowned_objects
        return counts

    def headline(self) -> str:
        s = self.stats
        line = (
            f"Scanned {s.applications_scanned} applications and "
            f"{s.saml_service_principals_scanned} SAML service principals · "
            f"{len(self.records)} credentials"
        )
        if s.first_party_skipped:
            line += f" · skipped {s.first_party_skipped} first-party"
        return line


def run_scan(
    config: Config,
    now: datetime | None = None,
    out_dir: str | Path | None = None,
    session=None,
) -> ScanResult:
    """Collect, classify and (optionally) write reports. Pure orchestration."""
    now = now or datetime.now(timezone.utc)
    session = session or get_session()
    stats = collect(session, config)
    records = classify(stats.credentials, config, now)
    paths = write_reports(records, stats, now, out_dir) if out_dir is not None else None
    return ScanResult(records=records, stats=stats, now=now, paths=paths, failed=should_fail(records, config))
