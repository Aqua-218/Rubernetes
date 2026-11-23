#!/usr/bin/env bash
set -euo pipefail

namespace="${K6_NAMESPACE:?}-smoke"
kubectl_fixture=(kubectl --namespace "$namespace")

cleanup() {
  local result=$?
  trap - EXIT
  kubectl delete namespace "$namespace" --timeout=2m || result=1
  exit "$result"
}

helm test kyverno --namespace "$K6_NAMESPACE" --timeout 3m
kubectl create namespace "$namespace"
trap cleanup EXIT
"${kubectl_fixture[@]}" apply -f - <<'YAML'
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: k6-require-fixture-label
spec:
  background: false
  rules:
  - name: require-fixture-label
    match:
      any:
      - resources:
          kinds: [ConfigMap]
    validate:
      failureAction: Enforce
      message: K6 fixture label required
      pattern:
        metadata:
          labels:
            k6-fixture: "true"
YAML

"${kubectl_fixture[@]}" wait --for=condition=Ready policy/k6-require-fixture-label --timeout=90s
denial=""
for attempt in $(seq 1 60); do
  if denial=$("${kubectl_fixture[@]}" create configmap rejected --dry-run=server 2>&1); then
    sleep 1
  elif [[ "$denial" == *"K6 fixture label required"* ]]; then
    break
  else
    echo "$denial" >&2
    exit 1
  fi
done
[[ "$denial" == *"K6 fixture label required"* ]]

"${kubectl_fixture[@]}" create configmap accepted --dry-run=client -o json |
  jq '.metadata.labels["k6-fixture"]="true"' |
  "${kubectl_fixture[@]}" create --dry-run=server -f - -o json |
  jq -e '.metadata.labels["k6-fixture"] == "true"'
