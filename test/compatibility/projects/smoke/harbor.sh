#!/usr/bin/env bash
set -euo pipefail

kubectl_fixture=(kubectl --namespace "${K6_NAMESPACE:?}")
scratch=$(mktemp -d)
registry=127.0.0.1:5444
"${kubectl_fixture[@]}" port-forward --address=127.0.0.1 service/harbor 5444:80 >"$scratch/forward.log" 2>&1 &
forward_pid=$!
trap 'kill "$forward_pid" 2>/dev/null || true; wait "$forward_pid" 2>/dev/null || true; rm -rf -- "$scratch"' EXIT

for attempt in $(seq 1 60); do
  if ! kill -0 "$forward_pid" 2>/dev/null; then
    cat "$scratch/forward.log" >&2
    exit 1
  fi
  if rg -q 'Forwarding from 127.0.0.1:5444' "$scratch/forward.log"; then break; fi
  sleep 1
done
rg -q 'Forwarding from 127.0.0.1:5444' "$scratch/forward.log"
health=""
for attempt in $(seq 1 30); do
  if health=$(curl -fsS --noproxy 127.0.0.1 --max-time 5 "http://$registry/api/v2.0/health") &&
     jq -e '.status == "healthy"' <<< "$health" >/dev/null; then
    break
  fi
  sleep 2
done
jq -e '.status == "healthy"' <<< "$health" >/dev/null

export HELM_REGISTRY_CONFIG="$scratch/registry.json"
password=$("${kubectl_fixture[@]}" get secret k6-harbor-admin -o 'jsonpath={.data.HARBOR_ADMIN_PASSWORD}' | base64 -d)
[[ -n "$password" ]]
helm registry login "$registry" --username admin --password-stdin --plain-http <<< "$password"
unset password

mkdir -p "$scratch/chart/templates" "$scratch/pulled"
cat >"$scratch/chart/Chart.yaml" <<'YAML'
apiVersion: v2
name: k6-harbor-smoke
version: 0.1.0
YAML
cat >"$scratch/chart/templates/configmap.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: k6-harbor-smoke
data:
  marker: harbor-k6
YAML
helm package "$scratch/chart" --destination "$scratch"
helm push "$scratch/k6-harbor-smoke-0.1.0.tgz" "oci://$registry/library" --plain-http
helm pull "oci://$registry/library/k6-harbor-smoke" --version 0.1.0 --plain-http --destination "$scratch/pulled"
cmp "$scratch/k6-harbor-smoke-0.1.0.tgz" "$scratch/pulled/k6-harbor-smoke-0.1.0.tgz"
