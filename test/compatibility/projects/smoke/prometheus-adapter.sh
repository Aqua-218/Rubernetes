#!/usr/bin/env bash
set -euo pipefail

kubectl wait apiservice/v1beta1.custom.metrics.k8s.io --for=condition=Available --timeout=2m
metric="/apis/custom.metrics.k8s.io/v1beta1/namespaces/$K6_NAMESPACE/pods/k6-prometheus/k6_health"
for ((attempt=0; attempt<20; attempt++)); do
  if observation=$(kubectl get --raw "$metric" --request-timeout=5s) &&
    jq -e '.items | any(.describedObject.name == "k6-prometheus" and .value == "1")' <<<"$observation"; then
    printf '%s\n' "$observation"
    exit 0
  fi
  sleep 3
done
exit 1
