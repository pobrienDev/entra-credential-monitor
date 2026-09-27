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
OWNERS_EXPAND = "owners($select=id,displayName,userPrincipalName,mail)"

SECRET = "secret"
CERTIFICATE = "certificate"
SAML_CERTIFICATE = "saml_certificate"


@dataclass(frozen=True)
class Owner:
    id: str
    display_name: str | None = None
    user_principal_name: str | None = None
    mail: str | None = None
    kind: str = "user"  # user, servicePrincipal, ...

    @property
    def label(self) -> str:
        """Best human label available: name plus UPN when both exist, else whatever we have."""
        name = self.display_name
        contact = self.user_principal_name or self.mail
        if name and contact:
            return f"{name} <{contact}>"
        return name or contact or self.id

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "display_name": self.display_name,
            "user_principal_name": self.user_principal_name,
            "mail": self.mail,
            "kind": self.kind,
        }

    @classmethod
    def from_graph(cls, raw: dict) -> "Owner":
        kind = (raw.get("@odata.type") or "#microsoft.graph.directoryObject").rsplit(".", 1)[-1]
        return cls(
            id=raw["id"],
            display_name=raw.get("displayName"),
            user_principal_name=raw.get("userPrincipalName"),
            mail=raw.get("mail"),
            kind=kind,
        )

    @classmethod
    def from_dict(cls, d: dict) -> "Owner":
        return cls(
            id=d["id"],
            display_name=d.get("display_name"),
            user_principal_name=d.get("user_principal_name"),
            mail=d.get("mail"),
            kind=d.get("kind", "user"),
        )


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
    owners: tuple[Owner, ...] = ()
    # Filled in by classify
    days: int | None = None
    status: str | None = None
    long_lived: bool = False
    excluded: bool = False
    unowned: bool = False  # owners were looked up and none exist

    @property
    def uid(self) -> str:
        """Stable identity for a credential across runs."""
        return f"{self.object_id}:{self.key_id}"

    @property
    def owners_text(self) -> str:
        return "; ".join(o.label for o in self.owners)

    def to_dict(self) -> dict:
        """JSON-safe representation. Never includes a secret value or hint."""
        return {
            "status": self.status,
            "days": self.days,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "app_id": self.app_id,
            "display_name": self.display_name,
            "cred_type": self.cred_type,
            "key_id": self.key_id,
            "name": self.name,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat(),
            "thumbprint": self.thumbprint,
            "owners": [o.to_dict() for o in self.owners],
            "long_lived": self.long_lived,
            "excluded": self.excluded,
            "unowned": self.unowned,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Credential":
        return cls(
            object_type=d["object_type"],
            object_id=d["object_id"],
            app_id=d.get("app_id", ""),
            display_name=d["display_name"],
            cred_type=d["cred_type"],
            key_id=d["key_id"],
            name=d["name"],
            start=parse_graph_datetime(d.get("start")),
            end=parse_graph_datetime(d["end"]),
            thumbprint=d.get("thumbprint"),
            owners=tuple(Owner.from_dict(o) for o in d.get("owners") or []),
            days=d.get("days"),
            status=d.get("status"),
            long_lived=bool(d.get("long_lived", False)),
            excluded=bool(d.get("excluded", False)),
            unowned=bool(d.get("unowned", False)),
        )


@dataclass
class CollectResult:
    credentials: list[Credential] = field(default_factory=list)
    applications_scanned: int = 0
    saml_service_principals_scanned: int = 0
    first_party_skipped: int = 0
    owners_looked_up: bool = False

    @property
    def unowned_objects(self) -> int:
        """Objects that have credentials but no owners: a common audit finding."""
        return len(self.unowned_findings())

    def unowned_findings(self) -> list["UnownedObject"]:
        """One finding per object that has credentials but no owners, soonest expiry first."""
        if not self.owners_looked_up:
            return []
        by_object: dict[str, list[Credential]] = {}
        for c in self.credentials:
            if c.unowned:
                by_object.setdefault(c.object_id, []).append(c)
        findings = [
            UnownedObject(
                object_type=creds[0].object_type,
                object_id=object_id,
                app_id=creds[0].app_id,
                display_name=creds[0].display_name,
                credential_count=len(creds),
                soonest_end=min(c.end for c in creds),
                excluded=all(c.excluded for c in creds),
            )
            for object_id, creds in by_object.items()
        ]
        findings.sort(key=lambda f: (f.soonest_end, f.display_name.lower()))
        return findings


@dataclass(frozen=True)
class UnownedObject:
    object_type: str
    object_id: str
    app_id: str
    display_name: str
    credential_count: int
    soonest_end: datetime
    excluded: bool = False

    def to_dict(self) -> dict:
        return {
            "object_type": self.object_type,
            "object_id": self.object_id,
            "app_id": self.app_id,
            "display_name": self.display_name,
            "credential_count": self.credential_count,
            "soonest_end": self.soonest_end.isoformat(),
            "excluded": self.excluded,
        }


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


def _owners(obj: dict) -> tuple[Owner, ...]:
    return tuple(Owner.from_graph(o) for o in obj.get("owners") or [] if o.get("id"))


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
        owners=_owners(obj),
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
    result = CollectResult(owners_looked_up=config.lookup_owners)
    app_params = {"$select": APP_FIELDS, "$top": "999"}
    sp_params = {"$select": SP_FIELDS, "$top": "999"}
    if config.lookup_owners:
        app_params["$expand"] = OWNERS_EXPAND
        sp_params["$expand"] = OWNERS_EXPAND

    for app in get_all(session, f"{GRAPH}/applications", app_params):
        result.applications_scanned += 1
        result.credentials.extend(normalize_application(app))

    if config.include_saml_certificates:
        for sp in get_all(session, f"{GRAPH}/servicePrincipals", sp_params):
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
        c.unowned = config.lookup_owners and not c.owners

    return result
