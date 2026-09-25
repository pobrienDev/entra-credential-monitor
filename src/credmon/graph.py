"""Microsoft Graph session and paging with retry/backoff.

Locally the token comes from your ``az login`` session. In GitHub Actions it comes
from the OIDC-federated ``azure/login`` step. DefaultAzureCredential handles both.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator

import requests

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPE = "https://graph.microsoft.com/.default"
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

log = logging.getLogger(__name__)


def get_session(credential=None) -> requests.Session:
    """Return a requests session with a bearer token for Microsoft Graph."""
    if credential is None:
        from azure.identity import DefaultAzureCredential

        credential = DefaultAzureCredential()
    token = credential.get_token(SCOPE).token
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"
    session.headers["Accept"] = "application/json"
    return session


def _retry_delay(resp: requests.Response | None, attempt: int) -> float:
    if resp is not None:
        header = resp.headers.get("Retry-After")
        if header:
            try:
                return max(0.0, float(header))
            except ValueError:
                pass
    return float(2**attempt)


def get_all(
    session: requests.Session,
    url: str,
    params: dict | None = None,
    max_retries: int = 5,
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[dict]:
    """Yield every item across all pages, retrying throttled and failed requests.

    Retries on 429 and 5xx (honouring Retry-After) and on connection errors or
    timeouts. ``sleep`` is injectable so tests run instantly.
    """
    while url:
        resp: requests.Response | None = None
        for attempt in range(max_retries):
            try:
                resp = session.get(url, params=params, timeout=30)
            except (requests.ConnectionError, requests.Timeout) as exc:
                log.warning("Graph request failed (%s), retrying: %s", exc.__class__.__name__, url)
                resp = None
                sleep(_retry_delay(None, attempt))
                continue
            if resp.status_code in RETRY_STATUSES:
                log.warning("Graph returned %s, retrying: %s", resp.status_code, url)
                sleep(_retry_delay(resp, attempt))
                continue
            resp.raise_for_status()
            break
        else:
            raise RuntimeError(f"Graph request kept failing after {max_retries} attempts: {url}")

        data = resp.json()
        yield from data.get("value", [])
        url = data.get("@odata.nextLink")
        params = None  # nextLink already carries the query string
