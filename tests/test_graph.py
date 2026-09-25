import re

import pytest
import requests
import responses

from credmon.graph import GRAPH, get_all
from tests.conftest import load_fixture

APPS_URL = f"{GRAPH}/applications"


@responses.activate
def test_pager_follows_next_link(session):
    page1 = load_fixture("applications_page1.json")
    page2 = load_fixture("applications_page2.json")
    responses.get(APPS_URL, json=page1)
    responses.get(page1["@odata.nextLink"], json=page2)

    items = list(get_all(session, APPS_URL, {"$select": "id", "$top": "999"}))

    assert [i["displayName"] for i in items] == ["seed-rotated", "no-credentials-app", "payroll-export"]
    assert len(responses.calls) == 2
    # The nextLink already carries the query string; params must not be re-applied.
    assert responses.calls[1].request.url == page1["@odata.nextLink"]


@responses.activate
def test_pager_retries_on_429_with_retry_after(session):
    sleeps = []
    responses.get(APPS_URL, status=429, headers={"Retry-After": "3"})
    responses.get(APPS_URL, json={"value": [{"id": "ok"}]})

    items = list(get_all(session, APPS_URL, sleep=sleeps.append))

    assert items == [{"id": "ok"}]
    assert sleeps == [3.0]


@responses.activate
def test_pager_retries_on_connection_error(session):
    sleeps = []
    responses.get(APPS_URL, body=requests.ConnectionError("boom"))
    responses.get(APPS_URL, json={"value": [{"id": "ok"}]})

    items = list(get_all(session, APPS_URL, sleep=sleeps.append))

    assert items == [{"id": "ok"}]
    assert sleeps == [1.0]  # 2**0 backoff when no Retry-After


@responses.activate
def test_pager_gives_up_after_max_retries(session):
    for _ in range(3):
        responses.get(APPS_URL, status=503)

    with pytest.raises(RuntimeError, match="kept failing"):
        list(get_all(session, APPS_URL, max_retries=3, sleep=lambda _: None))


@responses.activate
def test_pager_raises_on_client_error(session):
    responses.get(APPS_URL, status=403, json={"error": {"code": "Authorization_RequestDenied"}})

    with pytest.raises(requests.HTTPError):
        list(get_all(session, APPS_URL, sleep=lambda _: None))
