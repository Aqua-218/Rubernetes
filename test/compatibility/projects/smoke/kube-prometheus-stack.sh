#!/usr/bin/env bash
set -euo pipefail

query="/api/v1/namespaces/$K6_NAMESPACE/services/http:kube-prometheus-stack-prometheus:9090/proxy/api/v1/query?query=up"
for ((attempt=0; attempt<60; attempt++)); do
  if response=$(kubectl get --raw "$query" --request-timeout=5s) &&
    ruby -rjson -e '
      body = JSON.parse(STDIN.read)
      samples = body.dig("data", "result") || []
      abort unless body["status"] == "success" && samples.any? { |sample| sample.dig("value", 1) == "1" }' <<<"$response"; then
    printf '%s\n' "$response"
    exit 0
  fi
  ruby -e 'sleep 3'
done
exit 1
