#!/usr/bin/env bash
# 90-pod burst benchmark against a live Rubernetes cluster.
#
#   KUBECONFIG=<root>/<profile>/kubeconfig benchmarks/runtime/pod_burst.sh [label]
#
# Creates PODS (default 90) pause Pods as DEPLOYMENTS (default 3) Deployments
# in namespace NS (default perf-burst), reports the wall time until every Pod
# is Running, then deletes the namespace and reports the wall time until the
# Pods are gone.  ROOT=<cluster root dir> adds the per-worker on-disk state
# sizes (runtime journal, network ledger, pod/log dirs) to the report so
# growth across churn rounds is visible.  Every number is printed as one
# "burst <label> key=value ..." line for easy grepping.
set -euo pipefail
KUBECTL=${KUBECTL:-$(dirname "$0")/../../build/tools/kubectl-v1.36.2}
PODS=${PODS:-90}
DEPLOYMENTS=${DEPLOYMENTS:-3}
NS=${NS:-perf-burst}
IMAGE=${IMAGE:-registry.k8s.io/pause:3.10}
TIMEOUT=${TIMEOUT:-300}
LABEL=${1:-run}
per=$((PODS / DEPLOYMENTS))

k() { "$KUBECTL" "$@"; }
now() { date +%s.%N; }

k delete namespace "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true
k create namespace "$NS" >/dev/null

manifest=$(mktemp)
for i in $(seq 1 "$DEPLOYMENTS"); do
  cat >>"$manifest" <<YAML
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: burst-$i, namespace: $NS}
spec:
  replicas: $per
  selector: {matchLabels: {app: burst-$i}}
  template:
    metadata: {labels: {app: burst-$i}}
    spec:
      terminationGracePeriodSeconds: 1
      containers: [{name: pause, image: $IMAGE}]
YAML
done

# PROF_PID=<agent pid> toggles that agent's StackProf sampler (SIGUSR2, see
# lib/rubernetes/bootstrap/shutdown.rb) around the start phase and again
# around the teardown phase, giving one dump per phase.
prof() { [ -n "${PROF_PID:-}" ] && kill -USR2 "$PROF_PID" 2>/dev/null || true; }
t0=$(now)
prof
k apply -f "$manifest" >/dev/null
first_running=""
deadline=$(( $(date +%s) + TIMEOUT ))
while :; do
  running=$(k get pods -n "$NS" --no-headers 2>/dev/null | awk '$3=="Running"' | wc -l)
  if [ -z "$first_running" ] && [ "$running" -gt 0 ]; then first_running=$(now); fi
  [ "$running" -ge "$PODS" ] && break
  [ "$(date +%s)" -gt "$deadline" ] && { echo "burst $LABEL TIMEOUT running=$running"; exit 1; }
  sleep 0.2
done
t1=$(now)
prof
start_wall=$(echo "$t1 - $t0" | bc)
first=$(echo "${first_running:-$t1} - $t0" | bc)

t2=$(now)
prof
k delete namespace "$NS" --wait=false >/dev/null
while [ "$(k get pods -n "$NS" --no-headers 2>/dev/null | wc -l)" -gt 0 ]; do
  [ "$(date +%s)" -gt $((deadline + TIMEOUT)) ] && { echo "burst $LABEL DELETE-TIMEOUT"; exit 1; }
  sleep 0.2
done
t3=$(now)
prof
delete_wall=$(echo "$t3 - $t2" | bc)
while k get namespace "$NS" >/dev/null 2>&1; do sleep 0.2; done
rm -f "$manifest"

sizes=""
if [ -n "${ROOT:-}" ]; then
  for w in "$ROOT"/runtime/worker-*; do
    n=$(basename "$w")
    j=$(stat -c %s "$w/ledger.jsonl" 2>/dev/null || echo 0)
    nl=$(stat -c %s "$ROOT/network/$n/state.json.ledger.wal" 2>/dev/null || echo 0)
    ns=$(stat -c %s "$ROOT/network/$n/state.json" 2>/dev/null || echo 0)
    st=$(stat -c %s "$w/ledger.jsonl.node-state.json" 2>/dev/null || echo 0)
    pd=$(ls "$w/pods" 2>/dev/null | wc -l)
    ld=$(ls "$w/log" 2>/dev/null | wc -l)
    sizes="$sizes $n:journal=$j,netwal=$nl,netstate=$ns,nodestate=$st,poddirs=$pd,logdirs=$ld"
  done
  for c in "$ROOT"/data/control-*; do
    sizes="$sizes $(basename "$c"):raft=$(du -sk "$c" | cut -f1)k"
  done
fi
printf 'burst %s pods=%s start=%.2fs first_running=%.2fs delete=%.2fs%s\n' "$LABEL" "$PODS" "$start_wall" "$first" "$delete_wall" "$sizes"
