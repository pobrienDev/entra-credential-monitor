from datetime import datetime, timedelta, timezone

import pytest

from credmon.classify import (
    CLEANUP,
    CRITICAL,
    EXPIRED,
    NOTICE,
    OK,
    WARNING,
    classify,
    days_remaining,
    mark_rotated,
    severity,
    should_fail,
    summarize,
)
from credmon.collect import CERTIFICATE, SAML_CERTIFICATE, SECRET, Credential
from credmon.config import Config, Thresholds

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
T = Thresholds()  # 7 / 30 / 60


def cred(name="c", days=100.0, obj=None, cred_type=SECRET, lifetime_days=None, excluded=False, key_id=None):
    """A credential on its own object unless ``obj`` groups it with siblings."""
    obj = obj or f"obj-{name}"
    end = NOW + timedelta(days=days)
    start = end - timedelta(days=lifetime_days) if lifetime_days is not None else None
    return Credential(
        object_type="application",
        object_id=obj,
        app_id=f"app-{obj}",
        display_name=obj,
        cred_type=cred_type,
        key_id=key_id or f"key-{name}",
        name=name,
        start=start,
        end=end,
        excluded=excluded,
    )


def test_days_remaining_floors():
    assert days_remaining(NOW + timedelta(days=6, hours=23), NOW) == 6
    assert days_remaining(NOW + timedelta(days=7), NOW) == 7
    assert days_remaining(NOW, NOW) == 0
    assert days_remaining(NOW - timedelta(seconds=1), NOW) == -1
    assert days_remaining(NOW - timedelta(days=3), NOW) == -3


@pytest.mark.parametrize(
    "days,expected",
    [
        (-1, EXPIRED),
        (0, CRITICAL),
        (7, CRITICAL),   # exactly at the critical threshold
        (8, WARNING),
        (30, WARNING),   # exactly at the warning threshold
        (31, NOTICE),
        (60, NOTICE),    # exactly at the notice threshold
        (61, OK),
        (1095, OK),
    ],
)
def test_severity_thresholds_are_inclusive(days, expected):
    assert severity(days, T) == expected


def test_severity_uses_configured_thresholds():
    t = Thresholds(critical=3, warning=10, notice=20)
    assert severity(3, t) == CRITICAL
    assert severity(4, t) == WARNING
    assert severity(20, t) == NOTICE
    assert severity(21, t) == OK


def test_classify_fills_days_and_status_and_sorts_by_severity_then_days():
    records = [cred("ok", 100), cred("warn", 20), cred("crit", 2), cred("gone", -5), cred("notice", 45)]

    out = classify(records, Config(), NOW)

    assert [(r.name, r.days, r.status) for r in out] == [
        ("gone", -5, EXPIRED),
        ("crit", 2, CRITICAL),
        ("warn", 20, WARNING),
        ("notice", 45, NOTICE),
        ("ok", 100, OK),
    ]


def test_rotation_downgrades_old_secret_when_healthy_sibling_exists():
    old = cred("old", 2, obj="app")
    new = cred("new", 364, obj="app")
    out = classify([old, new], Config(), NOW)

    assert {r.name: r.status for r in out} == {"old": CLEANUP, "new": OK}


def test_rotation_ignores_sibling_of_different_type():
    secret = cred("old-secret", 2, obj="app", cred_type=SECRET)
    certificate = cred("new-cert", 364, obj="app", cred_type=CERTIFICATE)
    out = classify([secret, certificate], Config(), NOW)

    assert {r.name: r.status for r in out} == {"old-secret": CRITICAL, "new-cert": OK}


def test_rotation_ignores_sibling_on_different_object():
    a = cred("old", 2, obj="app-a")
    b = cred("new", 364, obj="app-b")
    out = classify([a, b], Config(), NOW)

    assert {r.name: r.status for r in out} == {"old": CRITICAL, "new": OK}


def test_rotation_requires_sibling_beyond_healthy_days():
    old = cred("old", 2, obj="app")
    also_soon = cred("also-soon", 25, obj="app")  # warning, not healthy
    out = classify([old, also_soon], Config(), NOW)

    assert {r.name: r.status for r in out} == {"old": CRITICAL, "also-soon": WARNING}


def test_rotation_healthy_days_is_configurable():
    old = cred("old", 2, obj="app")
    newer = cred("newer", 40, obj="app")
    strict = Config(rotation_healthy_days=90)
    lenient = Config(rotation_healthy_days=35)

    assert classify([cred("old", 2, obj="app"), cred("newer", 40, obj="app")], strict, NOW)[0].status == CRITICAL
    assert {r.name: r.status for r in classify([old, newer], lenient, NOW)}["old"] == CLEANUP


def test_expired_credential_with_replacement_is_cleanup():
    out = classify([cred("dead", -10, obj="app"), cred("live", 300, obj="app")], Config(), NOW)
    assert {r.name: r.status for r in out} == {"dead": CLEANUP, "live": OK}


def test_saml_certificate_rotation_on_service_principal():
    old = cred("old-cert", 5, obj="sp", cred_type=SAML_CERTIFICATE)
    new = cred("new-cert", 1000, obj="sp", cred_type=SAML_CERTIFICATE)
    out = classify([old, new], Config(), NOW)
    assert {r.name: r.status for r in out} == {"old-cert": CLEANUP, "new-cert": OK}


def test_mark_rotated_handles_single_credential():
    r = cred("solo", 2)
    r.days, r.status = 2, CRITICAL
    assert mark_rotated([r], 30)[0].status == CRITICAL


def test_long_lived_secret_flag():
    forever = cred("forever", 697, lifetime_days=730)
    yearly = cred("yearly", 100, lifetime_days=365)
    long_cert = cred("cert", 900, cred_type=CERTIFICATE, lifetime_days=1095)
    no_start = cred("no-start", 100)

    out = classify([forever, yearly, long_cert, no_start], Config(), NOW)
    flags = {r.name: r.long_lived for r in out}

    assert flags == {"forever": True, "yearly": False, "cert": False, "no-start": False}
    assert {r.name: r.status for r in out}["forever"] == OK  # hygiene, not an expiry alert


def test_long_lived_threshold_is_configurable():
    out = classify([cred("s", 100, lifetime_days=200)], Config(long_lived_secret_days=180), NOW)
    assert out[0].long_lived is True


@pytest.mark.parametrize(
    "fail_on,statuses,expected",
    [
        ("critical", [CRITICAL], True),
        ("critical", [EXPIRED], True),
        ("critical", [WARNING], False),
        ("warning", [WARNING], True),
        ("notice", [NOTICE], True),
        ("notice", [OK], False),
        ("expired", [CRITICAL], False),
        ("never", [EXPIRED], False),
        ("critical", [CLEANUP], False),
    ],
)
def test_should_fail(fail_on, statuses, expected):
    records = []
    for i, s in enumerate(statuses):
        r = cred(f"r{i}")
        r.status = s
        records.append(r)
    assert should_fail(records, Config(fail_on=fail_on)) is expected


def test_should_fail_ignores_excluded():
    r = cred("accepted", 1, excluded=True)
    r.status = CRITICAL
    assert should_fail([r], Config(fail_on="critical")) is False


def test_summarize_counts():
    out = classify(
        [cred("a", -1), cred("b", 2), cred("c", 20), cred("d", 100, lifetime_days=800), cred("e", 2, obj="x"), cred("f", 400, obj="x")],
        Config(),
        NOW,
    )
    counts = summarize(out)
    assert counts == {"expired": 1, "critical": 1, "warning": 1, "notice": 0, "cleanup": 1, "ok": 2, "hygiene": 1}
