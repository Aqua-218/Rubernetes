#!/usr/bin/env bash
set -euo pipefail

template=constrainttemplate/k8srequiredlabels
constraint=k8srequiredlabels.constraints.gatekeeper.sh/k6-required-label
generated_crd=crd/k8srequiredlabels.constraints.gatekeeper.sh
test_namespace="$K6_NAMESPACE-smoke"
existing_crd=$(kubectl get "$generated_crd" --ignore-not-found -o name)
test -z "$existing_crd"
kubectl create namespace "$test_namespace"
template_created=false
cleanup() {
  if "$template_created"; then
    if [[ -n $(kubectl get "$generated_crd" --ignore-not-found -o name) ]]; then
      kubectl delete "$constraint" --ignore-not-found --wait --timeout=90s
    fi
    kubectl delete "$template" --cascade=foreground --ignore-not-found --wait --timeout=90s
  fi
  kubectl delete namespace "$test_namespace" --ignore-not-found --wait --timeout=90s
}
trap cleanup EXIT
kubectl create -f test/compatibility/projects/smoke/gatekeeper.yml
template_created=true
kubectl wait "$template" --for=jsonpath='{.status.created}'=true --timeout=2m
kubectl apply -f - <<YAML
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: k6-required-label
spec:
  match:
    scope: Namespaced
    namespaces: ["$test_namespace"]
    kinds:
      - apiGroups: [""]
        kinds: ["ConfigMap"]
  parameters:
    labels: ["k6-smoke"]
YAML

api=(kubectl -n "$test_namespace" --request-timeout=5s)
for ((attempt=0; attempt<40; attempt++)); do
  if output=$("${api[@]}" create configmap k6-smoke-denied --dry-run=server 2>&1); then
    sleep 2
  elif [[ "$output" == *k6-required-label*"you must provide labels:"*k6-smoke* ]]; then
    printf '%s\n' "$output"
    "${api[@]}" create configmap k6-smoke-allowed --dry-run=client -o json |
      "${api[@]}" label --local -f - k6-smoke=present -o json |
      "${api[@]}" create --dry-run=server -f -
    break
  else
    printf '%s\n' "$output" >&2
    exit 1
  fi
done
test "$attempt" -lt 40
trap - EXIT
cleanup
