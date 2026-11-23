#!/usr/bin/env bash
set -euo pipefail

api=(kubectl -n "$K6_NAMESPACE")
workflow=$("${api[@]}" create -f test/compatibility/projects/smoke/argo-workflows.yml -o jsonpath='{.metadata.name}')
"${api[@]}" wait "workflow/$workflow" --for=jsonpath='{.status.phase}'=Succeeded --timeout=5m
pod=$("${api[@]}" get pod -l "workflows.argoproj.io/workflow=$workflow" -o jsonpath='{.items[0].metadata.name}')
"${api[@]}" logs "$pod" -c main | grep -Fx 'hello world'
