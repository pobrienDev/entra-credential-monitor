#!/usr/bin/env bash
# Package the function and zip-deploy it with a remote build. No Core Tools needed.
#   ./deploy.sh                          # installs credmon from the repo's main branch
#   CREDMON_REF=v1.1.0 ./deploy.sh       # or from a tag / branch / commit
set -euo pipefail
cd "$(dirname "$0")"
CREDMON_REF="${CREDMON_REF:-main}"

RG=$(terraform -chdir=terraform output -raw resource_group_name)
APP=$(terraform -chdir=terraform output -raw function_app_name)

# Single source of truth for thresholds: ship the repo's config.yaml with the function.
cp ../config.yaml config.yaml
build=$(mktemp -d)
trap 'rm -rf config.yaml credmon-function.zip "$build"' EXIT
cp function_app.py host.json config.yaml "$build"/
sed "s#entra-credential-monitor@main#entra-credential-monitor@${CREDMON_REF}#" requirements.txt > "$build/requirements.txt"

(cd "$build" && zip -q -r "$OLDPWD/credmon-function.zip" function_app.py host.json requirements.txt config.yaml)
az functionapp deployment source config-zip \
  --resource-group "$RG" --name "$APP" --src credmon-function.zip --build-remote true --output none \
  || true  # the CLI's post-deploy health probe can fail while the host restarts; the deployment itself is checked below

# The azurerm provider injects a key-based AzureWebJobsStorage connection string on
# every apply, with an empty key because shared keys are disabled. The host prefers it
# over AzureWebJobsStorage__accountName and fails auth, so remove it if present.
if az functionapp config appsettings list -g "$RG" -n "$APP" --query "[?name=='AzureWebJobsStorage']" -o tsv | grep -q .; then
  az functionapp config appsettings delete -g "$RG" -n "$APP" --setting-names AzureWebJobsStorage --output none
  echo "removed key-based AzureWebJobsStorage setting (identity-based access stays)"
fi

# Verify through the SCM (Kudu) API with the CLI's own Entra token. The ARM deployments
# endpoint appends an HTML error page to its JSON on Flex apps, which breaks --query.
token=$(az account get-access-token --query accessToken -o tsv)
status=$(curl -sf -H "Authorization: Bearer $token" "https://${APP}.scm.azurewebsites.net/api/deployments/latest" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("status"), d.get("complete"))')
unset token
[ "$status" = "4 True" ] || { echo "deployment status/complete: $status (expected: 4 True)"; exit 1; }
echo "deployed to $APP"
