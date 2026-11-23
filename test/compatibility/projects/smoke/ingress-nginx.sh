#!/usr/bin/env bash
set -euo pipefail

kubectl -n "$K6_NAMESPACE" apply -f test/compatibility/projects/smoke/ingress-nginx.yml
kubectl -n "$K6_NAMESPACE" rollout status deployment/k6-http --timeout=2m
path="/api/v1/namespaces/$K6_NAMESPACE/services/http:ingress-nginx-controller:80/proxy/"
for ((attempt=0; attempt<30; attempt++)); do
  if response=$(kubectl --request-timeout=5s get --raw "$path" 2>/dev/null) && [[ $response == *"It works!"* ]]; then
    printf '%s\n' "$response"
    exit 0
  fi
  sleep 2
done
kubectl --request-timeout=5s get --raw "$path"
exit 1
