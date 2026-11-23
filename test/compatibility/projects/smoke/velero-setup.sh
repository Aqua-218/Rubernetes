#!/usr/bin/env bash
set -euo pipefail

kubectl create namespace "$K6_NAMESPACE" --dry-run=client -o json | kubectl apply -f -
api=(kubectl -n "$K6_NAMESPACE")
access_key=$(openssl rand -hex 12)
secret_key=$(openssl rand -hex 24)
printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$access_key" "$secret_key" |
  "${api[@]}" create secret generic velero-k6-s3 --from-env-file=/dev/stdin
printf '[default]\naws_access_key_id=%s\naws_secret_access_key=%s\n' "$access_key" "$secret_key" |
  "${api[@]}" create secret generic velero-k6-credentials --from-file=cloud=/dev/stdin
"${api[@]}" apply -f test/compatibility/projects/smoke/velero-s3.yml
"${api[@]}" wait --for=condition=Ready pod/k6-s3 --timeout=3m
