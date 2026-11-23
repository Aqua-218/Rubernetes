#!/usr/bin/env bash
set -euo pipefail

api=(kubectl -n "$K6_NAMESPACE")
velero=("${api[@]}" exec deployment/velero -- /velero --namespace "$K6_NAMESPACE")
"${api[@]}" wait backupstoragelocation/default --for=jsonpath='{.status.phase}'=Available --timeout=3m
"${api[@]}" create configmap k6-smoke --from-literal=message=backup-and-restore
"${api[@]}" label configmap k6-smoke app.kubernetes.io/part-of=k6-smoke
"${velero[@]}" backup create k6-smoke --include-namespaces "$K6_NAMESPACE" --include-resources=configmaps \
  --selector=app.kubernetes.io/part-of=k6-smoke --snapshot-volumes=false
"${api[@]}" wait backup/k6-smoke --for=jsonpath='{.status.phase}'=Completed --timeout=3m
"${api[@]}" delete configmap k6-smoke --wait
"${velero[@]}" restore create k6-smoke --from-backup=k6-smoke
"${api[@]}" wait restore/k6-smoke --for=jsonpath='{.status.phase}'=Completed --timeout=3m
test "$("${api[@]}" get configmap k6-smoke -o jsonpath='{.data.message}')" = backup-and-restore

# Velero runs the restore's finalizer and removes backup data from the bucket.
# Clean up these test objects while the controller and object store are live.
"${velero[@]}" restore delete k6-smoke --confirm
"${api[@]}" wait restore/k6-smoke --for=delete --timeout=3m
"${velero[@]}" backup delete k6-smoke --confirm
"${api[@]}" wait backup/k6-smoke --for=delete --timeout=3m
