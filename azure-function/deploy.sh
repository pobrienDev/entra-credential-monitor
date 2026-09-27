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
  --resource-group "$RG" --name "$APP" --src credmon-function.zip --build-remote true --output none
echo "deployed to $APP"
