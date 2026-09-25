import json
from pathlib import Path

import pytest
import requests

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def session() -> requests.Session:
    s = requests.Session()
    s.headers["Authorization"] = "Bearer test"
    return s
