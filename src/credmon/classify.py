"""Days remaining, severity, rotation detection and the long-lived secret flag.

``now`` is always passed in rather than read from the clock, so every test is
deterministic and every report in one run shares a single timestamp.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta

from credmon.collect import SECRET, Credential
from credmon.config import Config, Thresholds

EXPIRED = "expired"
CRITICAL = "critical"
WARNING = "warning"
NOTICE = "notice"
CLEANUP = "cleanup"
OK = "ok"

# Lower rank is more severe. Used for sorting and for fail_on.
SEVERITY_RANK = {EXPIRED: 0, CRITICAL: 1, WARNING: 2, NOTICE: 3, CLEANUP: 4, OK: 5}
ALERTABLE = frozenset({EXPIRED, CRITICAL})


def days_remaining(end: datetime, now: datetime) -> int:
    """Whole days until ``end``; negative once expired. Floors, so 6.9 days is 6."""
    return math.floor((end - now).total_seconds() / 86400)


def severity(days: int, t: Thresholds) -> str:
    """Thresholds are inclusive: exactly ``critical`` days left is critical."""
    if days < 0:
        return EXPIRED
    if days <= t.critical:
        return CRITICAL
    if days <= t.warning:
        return WARNING
    if days <= t.notice:
        return NOTICE
    return OK


def mark_rotated(records: list[Credential], healthy_days: int) -> None:
    """Downgrade superseded credentials to cleanup.

    If an object already has a newer credential of the same type with more than
    ``healthy_days`` remaining, an expiring or expired sibling was probably
    rotated. It is a leftover to delete, not an emergency.
    """
    groups: dict[tuple[str, str], list[Credential]] = defaultdict(list)
    for r in records:
        groups[(r.object_id, r.cred_type)].append(r)
    for group in groups.values():
        best = max(r.days for r in group)
        if best <= healthy_days:
            continue
        for r in group:
            if r.days != best and r.status in (EXPIRED, CRITICAL, WARNING):
                r.status = CLEANUP


def classify(records: list[Credential], config: Config, now: datetime) -> list[Credential]:
    """Fill in days, status and long_lived on every record and return them sorted."""
    long_lived = timedelta(days=config.long_lived_secret_days)
    for r in records:
        r.days = days_remaining(r.end, now)
        r.status = severity(r.days, config.thresholds)
        r.long_lived = r.cred_type == SECRET and r.start is not None and r.end - r.start > long_lived
    healthy_days = config.rotation_healthy_days
    if healthy_days is None:
        healthy_days = config.thresholds.warning
    mark_rotated(records, healthy_days)
    records.sort(key=lambda r: (SEVERITY_RANK[r.status], r.days, r.display_name.lower(), r.name.lower()))
    return records


def should_fail(records: list[Credential], config: Config) -> bool:
    """True when any non-excluded credential is at or above the fail_on level."""
    if config.fail_on == "never":
        return False
    limit = SEVERITY_RANK[config.fail_on]
    return any(not r.excluded and SEVERITY_RANK[r.status] <= limit for r in records)


def summarize(records: list[Credential]) -> dict[str, int]:
    """Count of records per status, in severity order, plus hygiene findings."""
    counts = dict.fromkeys(SEVERITY_RANK, 0)
    for r in records:
        counts[r.status] += 1
    counts["hygiene"] = sum(r.long_lived for r in records)
    return counts
