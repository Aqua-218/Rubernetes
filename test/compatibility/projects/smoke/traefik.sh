#!/usr/bin/env bash
set -euo pipefail

kubectl -n "$K6_NAMESPACE" apply -f test/compatibility/projects/smoke/traefik.yml
kubectl -n "$K6_NAMESPACE" rollout status deployment/whoami --timeout=3m

# Connect to the chart's web entrypoint from the test runner, including when
# the cluster is remote and has no externally advertised load balancer IP.
work=$(mktemp -d)
kubectl -n "$K6_NAMESPACE" port-forward --address=127.0.0.1 service/traefik :80 >"$work/forward.log" 2>&1 &
forward=$!
cleanup() {
  kill "$forward" 2>/dev/null || true
  wait "$forward" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
for ((i=0; i<60; i++)); do
  port=$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) ->.*/\1/p' "$work/forward.log")
  [[ -n "$port" ]] && break
  kill -0 "$forward" 2>/dev/null || break
  sleep 1
done
if [[ -z "$port" ]]; then
  cat "$work/forward.log" >&2
  exit 1
fi

curl --noproxy '*' --fail --silent --show-error --retry 20 --retry-all-errors --retry-delay 1 \
  --max-time 5 --retry-max-time 90 -H 'Host: whoami.localhost' "http://127.0.0.1:$port/" -o "$work/response"
tr -d '\r' <"$work/response" >"$work/headers"
if ! grep -Eq '^Hostname: whoami-' "$work/headers" || ! grep -Fxq 'X-Forwarded-Host: whoami.localhost' "$work/headers"; then
  cat "$work/headers" >&2
  exit 1
fi
cat "$work/headers"
