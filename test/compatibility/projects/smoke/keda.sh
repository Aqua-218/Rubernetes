#!/usr/bin/env bash
set -euo pipefail

api=(kubectl -n "$K6_NAMESPACE")
image=registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9
"${api[@]}" create deployment k6-smoke --image="$image" --replicas=0 -- sleep 86400
start=$(date -u -d '2 minutes ago' '+%-M %-H * * *')
end=$(date -u -d '30 minutes' '+%-M %-H * * *')
"${api[@]}" apply -f - <<YAML
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: k6-smoke
spec:
  scaleTargetRef:
    name: k6-smoke
  minReplicaCount: 0
  maxReplicaCount: 2
  pollingInterval: 5
  triggers:
  - type: cron
    metadata:
      timezone: UTC
      start: "$start"
      end: "$end"
      desiredReplicas: "2"
YAML
"${api[@]}" wait scaledobject/k6-smoke --for=condition=Ready --timeout=2m
"${api[@]}" wait deployment/k6-smoke --for=jsonpath='{.status.readyReplicas}'=2 --timeout=4m
"${api[@]}" get scaledobject k6-smoke -o json |
  jq -e '[.status.conditions[] | select(.status == "True") | .type] | contains(["Ready", "Active"])'
