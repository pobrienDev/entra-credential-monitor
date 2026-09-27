from datetime import datetime, timezone

import responses

from credmon.collect import (
    CERTIFICATE,
    SAML_CERTIFICATE,
    SECRET,
    collect,
    normalize_application,
    normalize_saml_service_principal,
    parse_graph_datetime,
    thumbprint_from_key_identifier,
)
from credmon.config import Config
from credmon.graph import GRAPH
from tests.conftest import load_fixture

TENANT = "6c3eca84-802c-4606-869d-c1b7c87d8320"


def test_parse_graph_datetime_handles_z_and_fractions():
    assert parse_graph_datetime("2026-09-30T04:00:00Z") == datetime(2026, 9, 30, 4, tzinfo=timezone.utc)
    assert parse_graph_datetime("2026-09-25T16:56:17.32Z") == datetime(2026, 9, 25, 16, 56, 17, 320000, tzinfo=timezone.utc)
    seven = parse_graph_datetime("2026-11-30T00:00:00.1234567Z")
    assert seven == datetime(2026, 11, 30, 0, 0, 0, 123456, tzinfo=timezone.utc)
    assert parse_graph_datetime(None) is None


def test_thumbprint_decodes_base64():
    assert thumbprint_from_key_identifier("3q2+7w==") == "DEADBEEF"
    assert thumbprint_from_key_identifier(None) is None
    assert thumbprint_from_key_identifier("not base64!") == "not base64!"


def test_normalize_application_one_record_per_credential():
    app = load_fixture("applications_page2.json")["value"][0]
    records = normalize_application(app)

    assert [(r.cred_type, r.name) for r in records] == [(SECRET, "prod-2025"), (CERTIFICATE, "CN=payroll-crt")]
    secret = records[0]
    assert secret.object_type == "application"
    assert secret.object_id == app["id"]
    assert secret.app_id == app["appId"]
    assert secret.display_name == "payroll-export"
    assert secret.key_id == "a0000000-0000-4000-8000-000000000003"
    assert secret.end == datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
    assert secret.start == datetime(2024, 10, 9, 12, tzinfo=timezone.utc)
    assert records[1].thumbprint == "DEADBEEF"


def test_normalize_application_without_credentials_is_empty():
    app = load_fixture("applications_page1.json")["value"][1]
    assert normalize_application(app) == []


def test_saml_sign_verify_password_collapse_to_one_row():
    sp = load_fixture("service_principals.json")["value"][0]
    records = normalize_saml_service_principal(sp)

    assert len(records) == 1
    cert = records[0]
    assert cert.cred_type == SAML_CERTIFICATE
    assert cert.object_type == "servicePrincipal"
    assert cert.key_id == "c0000000-0000-4000-8000-000000000002"  # the Sign key
    assert cert.name == "CN=Microsoft Azure Federated SSO Certificate"
    assert cert.end == datetime(2029, 9, 25, 17, 32, 32, tzinfo=timezone.utc)
    assert cert.thumbprint == "952686135B87AC5FCBCC448077FBF4A7D798023F7A56E5937DA679A20BD84A2A"


def test_saml_two_certificates_stay_two_rows():
    sp = load_fixture("service_principals.json")["value"][0]
    extra = dict(sp["keyCredentials"][1], keyId="c0000000-0000-4000-8000-00000000ffff",
                 customKeyIdentifier="AAAA", endDateTime="2027-01-01T00:00:00Z")
    sp = dict(sp, keyCredentials=sp["keyCredentials"] + [extra])

    records = normalize_saml_service_principal(sp)

    assert sorted(r.key_id for r in records) == [
        "c0000000-0000-4000-8000-000000000002",
        "c0000000-0000-4000-8000-00000000ffff",
    ]


@responses.activate
def test_collect_end_to_end(session):
    page1 = load_fixture("applications_page1.json")
    responses.get(f"{GRAPH}/applications", json=page1)
    responses.get(page1["@odata.nextLink"], json=load_fixture("applications_page2.json"))
    responses.get(f"{GRAPH}/servicePrincipals", json=load_fixture("service_principals.json"))
    config = Config(tenant_id=TENANT, exclude_app_ids=("10000000-0000-4000-8000-000000000003",))

    result = collect(session, config)

    assert result.applications_scanned == 3
    assert result.saml_service_principals_scanned == 1
    assert result.first_party_skipped == 1
    names = sorted((r.display_name, r.name) for r in result.credentials)
    assert names == [
        ("Microsoft Entra SAML Toolkit", "CN=Microsoft Azure Federated SSO Certificate"),
        ("payroll-export", "CN=payroll-crt"),
        ("payroll-export", "prod-2025"),
        ("seed-rotated", "new-secret"),
        ("seed-rotated", "old-secret"),
    ]
    assert {r.display_name for r in result.credentials if r.excluded} == {"payroll-export"}
    # The secret hint must never survive normalisation.
    assert not any(hasattr(r, "hint") for r in result.credentials)
    # $select and $top were sent on the first application request.
    first = responses.calls[0].request.url
    assert "%24select=id%2CappId" in first and "%24top=999" in first


@responses.activate
def test_collect_skips_service_principals_when_disabled(session):
    responses.get(f"{GRAPH}/applications", json={"value": []})

    result = collect(session, Config(include_saml_certificates=False))

    assert result.credentials == []
    assert len(responses.calls) == 1


def test_owners_are_normalised_from_expanded_graph_response():
    app = load_fixture("applications_page2.json")["value"][0]
    records = normalize_application(app)

    owners = records[0].owners
    assert [o.kind for o in owners] == ["user", "servicePrincipal"]
    assert owners[0].label == "Pat Example <pat@example.test>"
    assert owners[1].label == "deploy-bot"
    assert records[0].owners_text == "Pat Example <pat@example.test>; deploy-bot"
    assert records[1].owners == owners  # both credentials on the app share them


def test_owner_label_falls_back_to_upn_then_id():
    from credmon.collect import Owner

    assert Owner(id="x", user_principal_name="u@t").label == "u@t"
    assert Owner(id="x").label == "x"


@responses.activate
def test_collect_requests_owner_expansion_and_counts_unowned(session):
    page1 = load_fixture("applications_page1.json")
    responses.get(f"{GRAPH}/applications", json=page1)
    responses.get(page1["@odata.nextLink"], json=load_fixture("applications_page2.json"))
    responses.get(f"{GRAPH}/servicePrincipals", json=load_fixture("service_principals.json"))

    result = collect(session, Config(tenant_id=TENANT))

    assert "%24expand=owners%28%24select%3Did%2CdisplayName%2CuserPrincipalName%2Cmail%29" in responses.calls[0].request.url
    assert "%24expand=owners" in responses.calls[2].request.url
    assert result.owners_looked_up is True
    assert result.unowned_objects == 1  # seed-rotated has credentials and no owners
    assert {r.display_name for r in result.credentials if r.unowned} == {"seed-rotated"}
    finding = result.unowned_findings()[0]
    assert (finding.display_name, finding.credential_count) == ("seed-rotated", 2)
    saml = next(r for r in result.credentials if r.cred_type == SAML_CERTIFICATE)
    assert saml.owners[0].label == "idadmin@example.test"


@responses.activate
def test_collect_skips_owner_expansion_when_disabled(session):
    responses.get(f"{GRAPH}/applications", json={"value": []})
    responses.get(f"{GRAPH}/servicePrincipals", json={"value": []})

    result = collect(session, Config(lookup_owners=False))

    assert "expand" not in responses.calls[0].request.url
    assert result.owners_looked_up is False
    assert result.unowned_objects == 0
    assert result.unowned_findings() == []


def test_owners_survive_json_round_trip():
    app = load_fixture("applications_page2.json")["value"][0]
    c = normalize_application(app)[0]
    from credmon.collect import Credential

    back = Credential.from_dict(c.to_dict())
    assert back.owners == c.owners
