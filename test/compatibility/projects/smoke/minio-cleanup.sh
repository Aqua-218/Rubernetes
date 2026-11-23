#!/usr/bin/env bash
set -euo pipefail

api=(kubectl --namespace "${K6_NAMESPACE:?}")
claims=()
volumes=()
for i in 0 1 2 3; do
  claim=data$i-k6-smoke-pool-0-0
  volume=$("${api[@]}" get "pvc/$claim" --ignore-not-found -o jsonpath='{.spec.volumeName}')
  claims+=("pvc/$claim")
  [[ -z "$volume" ]] || volumes+=("pv/$volume")
done
"${api[@]}" delete tenant/k6-smoke --ignore-not-found --cascade=foreground --wait --timeout=3m
"${api[@]}" delete "${claims[@]}" --ignore-not-found --wait --timeout=2m
if (( ${#volumes[@]} )); then
  kubectl wait --for=delete "${volumes[@]}" --timeout=2m
fi
