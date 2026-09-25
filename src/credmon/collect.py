"""Fetch applications and SAML service principals, normalise every credential.

Graph returns metadata only. Secret values are never returned after creation, and
the ``hint`` field (first characters of a secret) is deliberately never copied.
"""

from __future__ import annotations

import base64
import binascii
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from credmon.config import Config
from credmon.graph import GRAPH, get_all

log = logging.getLogger(__name__)

APP_FIELDS = "id,appId,displayName,passwordCredentials,keyCredentials"
SP_FIELDS = (
    "id,appId,displayName,preferredSingleSignOnMode,"
    "passwordCredentials,keyCredentials,appOwnerOrganizationId"
)

SECRET = "secret"
CERTIFICATE = "certificate"
SAML_CERTIFICATE = "saml_certificate"


@dataclass
class Credential:
    object_type: str  # "application" or "servicePrincipal"
    object_id: str
    app_id: str
    display_name: str
    cred_type: str  # SECRET, CERTIFICATE or SAML_CERTIFICATE
    key_id: str
    name: str
    start: datetime | None
    end: datetime
    thumbprint: str | None = None
    # Filled in by classify
    days: int | None = None
    status: str | None = None
    long_lived: bool = False
    excluded: bool = False

    @property
    def uid(self) -> str:
        """Stable identity for a credential across runs."""
        return f"{self.object_id}:{self.key_id}"


@dataclass
class CollectResult:
    credentials: list[Credential] = field(default_factory=list)
    applications_scanned: int = 0
    saml_service_principals_scanned: int = 0
    first_party_skipped: int = 0


def parse_graph_datetime(value: str | None) -> datetime | None:
    """Parse Graph ISO 8601 timestamps into aware UTC datetimes.

    Graph may return up to seven fractional-second digits; Python accepts six.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, rest = text.split(".", 1)
        frac = rest
        tz = ""
        for sep in ("+", "-"):
            if sep in rest:
                frac, tzpart = rest.split(sep, 1)
                tz = sep + tzpart
                break
        text = f"{head}.{frac[:6].ljust(6, '0')}{tz}"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def thumbprint_from_key_identifier(value: str | None) -> str | None:
    """Graph's customKeyIdentifier is base64 of the certificate thumbprint bytes."""
    if not value:
        return None
    try:
        return base64.b64decode(value, validate=True).hex().upper()
    except (binascii.Error, ValueError):
        return value


def _credential(obj: dict, object_type: str, raw: dict, cred_type: str) -> Credential | None:
    end = parse_graph_datetime(raw.get("endDateTime"))
    if end is None:
        log.warning("Skipping credential without endDateTime on %s", obj.get("displayName"))
        return None
    return Credential(
        object_type=object_type,
        object_id=obj["id"],
        app_id=obj.get("appId", ""),
        display_name=obj.get("displayName") or "(unnamed)",
        cred_type=cred_type,
        key_id=raw["keyId"],
        name=raw.get("displayName") or "(unnamed)",
        start=parse_graph_datetime(raw.get("startDateTime")),
        end=end,
        thumbprint=thumbprint_from_key_identifier(raw.get("customKeyIdentifier")),
    )


def normalize_application(app: dict) -> list[Credential]:
    """One record per client secret and per certificate on an application object."""
    out: list[Credential] = []
    for raw in app.get("passwordCredentials") or []:
        if c := _credential(app, "application", raw, SECRET):
            out.append(c)
    for raw in app.get("keyCredentials") or []:
        if c := _credential(app, "application", raw, CERTIFICATE):
            out.append(c)
    return out


def normalize_saml_service_principal(sp: dict) -> list[Credential]:
    """Collapse each SAML signing certificate into one record.

    Entra exposes one signing certificate as a Sign key, a Verify key and a
    password credential, all sharing a customKeyIdentifier (thumbprint) and end
    date. The Sign key's keyId is used as the stable identity.
    """
    groups: dict[str, list[dict]] = defaultdict(list)
    for raw in list(sp.get("keyCredentials") or []) + list(sp.get("passwordCredentials") or []):
        group_key = raw.get("customKeyIdentifier") or raw.get("endDateTime") or raw["keyId"]
        groups[group_key].append(raw)

    out: list[Credential] = []
    for entries in groups.values():
        canonical = next(
            (e for e in entries if e.get("usage") == "Sign"),
            next((e for e in entries if "usage" in e), entries[0]),
        )
        if c := _credential(sp, "servicePrincipal", canonical, SAML_CERTIFICATE):
            out.append(c)
    return out


def collect(session, config: Config) -> CollectResult:
    """Scan the tenant and return every credential of interest."""
    result = CollectResult()

    for app in get_all(session, f"{GRAPH}/applications", {"$select": APP_FIELDS, "$top": "999"}):
        result.applications_scanned += 1
        result.credentials.extend(normalize_application(app))

    if config.include_saml_certificates:
        for sp in get_all(session, f"{GRAPH}/servicePrincipals", {"$select": SP_FIELDS, "$top": "999"}):
            if sp.get("preferredSingleSignOnMode") != "saml":
                continue
            owner = sp.get("appOwnerOrganizationId")
            if config.tenant_id and owner and owner != config.tenant_id:
                result.first_party_skipped += 1
                continue
            result.saml_service_principals_scanned += 1
            result.credentials.extend(normalize_saml_service_principal(sp))

    excluded = set(config.exclude_app_ids)
    for c in result.credentials:
        c.excluded = c.app_id in excluded

    return result
