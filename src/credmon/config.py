"""Load and validate config.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

SEVERITY_ORDER = ["expired", "critical", "warning", "notice", "never"]


@dataclass(frozen=True)
class Thresholds:
    critical: int = 7
    warning: int = 30
    notice: int = 60

    def __post_init__(self) -> None:
        if not (0 <= self.critical <= self.warning <= self.notice):
            raise ValueError("thresholds must satisfy 0 <= critical <= warning <= notice")


@dataclass(frozen=True)
class Config:
    thresholds: Thresholds = field(default_factory=Thresholds)
    long_lived_secret_days: int = 365
    rotation_healthy_days: int | None = None  # defaults to thresholds.warning
    include_saml_certificates: bool = True
    tenant_id: str | None = None
    exclude_app_ids: tuple[str, ...] = ()
    fail_on: str = "critical"

    def __post_init__(self) -> None:
        if self.fail_on not in SEVERITY_ORDER:
            raise ValueError(f"fail_on must be one of {SEVERITY_ORDER}, got {self.fail_on!r}")

    @classmethod
    def from_dict(cls, raw: dict) -> "Config":
        t = raw.get("thresholds") or {}
        return cls(
            thresholds=Thresholds(
                critical=int(t.get("critical_days", 7)),
                warning=int(t.get("warning_days", 30)),
                notice=int(t.get("notice_days", 60)),
            ),
            long_lived_secret_days=int(raw.get("long_lived_secret_days", 365)),
            rotation_healthy_days=(
                int(raw["rotation_healthy_days"]) if raw.get("rotation_healthy_days") is not None else None
            ),
            include_saml_certificates=bool(raw.get("include_saml_certificates", True)),
            tenant_id=(str(raw["tenant_id"]) if raw.get("tenant_id") else None),
            exclude_app_ids=tuple(str(a) for a in (raw.get("exclude_app_ids") or [])),
            fail_on=str(raw.get("fail_on", "critical")),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return cls.from_dict(raw)
