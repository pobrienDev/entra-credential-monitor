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
credmon scan --format table
```
