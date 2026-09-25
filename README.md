# entra-credential-monitor

Read-only monitor for Microsoft Entra app credentials. It scans every app registration
and SAML enterprise app in a tenant, reads the expiry of each client secret and certificate,
classifies them by severity, and reports anything expiring soon. It runs daily in GitHub
Actions using OIDC workload identity federation, so there are no stored secrets.

Work in progress. Phases are tracked in the project plan.

## Permission

`credmon` needs exactly one Microsoft Graph application permission: `Application.Read.All`.
It cannot change anything, and Graph never returns secret values, so the tool never sees one.

## Local run

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
az login --allow-no-subscriptions --tenant <tenant-id>
credmon scan --format table      # print to the terminal
credmon scan --out report        # write report/summary.md, credentials.csv, credentials.json
```

The exit code is 1 when any credential is at or above the `fail_on` level in `config.yaml`.

## Tests

```bash
pytest -q
```

Graph is mocked with sanitised fixtures under `tests/fixtures/`; no tenant access is needed.
