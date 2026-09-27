"""Azure Functions variant of the monitor: a daily timer with a managed identity.

The other correct answer to "run it with no secrets". The Function App's
system-assigned identity holds the two read-only Graph permissions and writes
the reports to a blob container using identity-based access, so nothing here
has a key or a token to leak or expire.

Notification is deliberately not included: posting to GitHub from Azure would
need a token, which would be the first secret in the design. Use the GitHub
Actions variant for issues, or read `reports/latest/credentials.json` from
whatever you already alert with.
"""

from __future__ import annotations

import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, ContentSettings

from credmon.config import Config
from credmon.graph import get_session
from credmon.runner import run_scan

app = func.FunctionApp()
log = logging.getLogger("credmon.function")

CONFIG_PATH = Path(__file__).parent / "config.yaml"
CONTENT_TYPES = {".md": "text/markdown", ".csv": "text/csv", ".json": "application/json"}


def upload_reports(out_dir: Path, now: datetime) -> list[str]:
    """Copy the three report files to <container>/<yyyy>/<mm>/<dd>/ and <container>/latest/."""
    account = os.environ["CREDMON_STORAGE_ACCOUNT"]
    container = os.environ.get("CREDMON_REPORTS_CONTAINER", "reports")
    client = BlobServiceClient(f"https://{account}.blob.core.windows.net", credential=DefaultAzureCredential())
    container_client = client.get_container_client(container)
    written = []
    for path in sorted(out_dir.iterdir()):
        data = path.read_bytes()
        settings = ContentSettings(content_type=CONTENT_TYPES.get(path.suffix, "application/octet-stream"))
        for prefix in (now.strftime("%Y/%m/%d"), "latest"):
            name = f"{prefix}/{path.name}"
            container_client.upload_blob(name, data, overwrite=True, content_settings=settings)
            written.append(name)
    return written


@app.timer_trigger(schedule="0 0 12 * * *", arg_name="timer", run_on_startup=False, use_monitor=True)
def credential_scan(timer: func.TimerRequest) -> None:
    if timer.past_due:
        log.warning("Timer is past due; running now.")
    config = Config.load(os.environ.get("CREDMON_CONFIG", CONFIG_PATH))
    now = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory() as tmp:
        result = run_scan(config, now=now, out_dir=tmp, session=get_session(DefaultAzureCredential()))
        written = upload_reports(Path(tmp), now)
    log.info("%s", result.headline())
    log.info("counts %s", " ".join(f"{k}={v}" for k, v in result.counts.items() if v))
    log.info("uploaded %d blobs, latest at latest/summary.md", len(written))
    if result.failed:
        # Surface in Application Insights as a failure without crashing the host:
        # the timer would otherwise retry, and a retry can't fix an expiring secret.
        log.error("credmon: credentials at or above fail_on=%s", config.fail_on)
