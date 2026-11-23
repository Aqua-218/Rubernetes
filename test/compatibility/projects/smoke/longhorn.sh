#!/usr/bin/env bash
set -euo pipefail

api=(kubectl --namespace "${K6_NAMESPACE:?}")
# The driver deployer creates these workloads asynchronously after Helm is ready.
kubectl wait --for=create csidriver/driver.longhorn.io --timeout=10m
for workload in daemonset/longhorn-csi-plugin deployment/csi-provisioner; do
  "${api[@]}" wait --for=create "$workload" --timeout=10m
  "${api[@]}" rollout status "$workload" --timeout=15m
done
# The CSI endpoints can be ready while Longhorn is still pulling its engine.
# Both components must be usable on the node before a replica can be scheduled.
"${api[@]}" wait engineimages.longhorn.io -l longhorn.io/component=engine-image \
  --for=create --for=jsonpath='{.status.state}'=deployed --timeout=15m
"${api[@]}" wait instancemanagers.longhorn.io -l longhorn.io/data-engine=v1 \
  --for=create --for=jsonpath='{.status.currentState}'=running --timeout=15m

claim=
pod=
volume=

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$pod" ]]; then
    "${api[@]}" delete "$pod" --ignore-not-found --wait --timeout=2m || status=1
  fi
  if [[ -n "$claim" ]]; then
    if [[ -z "$volume" ]]; then
      volume=$("${api[@]}" get "$claim" --ignore-not-found -o jsonpath='{.spec.volumeName}') || status=1
    fi
    "${api[@]}" delete "$claim" --ignore-not-found --wait --timeout=2m || status=1
  fi
  if [[ -n "$volume" ]]; then
    kubectl wait --for=delete "pv/$volume" --timeout=3m || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
claim=$("${api[@]}" create -f - -o name <<'YAML'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  generateName: k6-longhorn-
spec:
  storageClassName: longhorn
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
YAML
)

run_pod() {
  pod=$("${api[@]}" create -f - -o name <<YAML
apiVersion: v1
kind: Pod
metadata:
  generateName: k6-$1-
spec:
  restartPolicy: Never
  containers:
    - name: io
      image: registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9
      command: ["sh", "-ec", "$2"]
      volumeMounts: [{name: data, mountPath: /data}]
  volumes:
    - name: data
      persistentVolumeClaim: {claimName: ${claim#*/}}
YAML
)
  "${api[@]}" wait --for=jsonpath='{.status.phase}'=Succeeded "$pod" --timeout=5m
}

run_pod writer 'echo persisted > /data/message'
"${api[@]}" delete "$pod" --wait --timeout=2m
pod=
run_pod reader 'cat /data/message'
"${api[@]}" logs "$pod" | ruby -e 'data = STDIN.binmode.read; abort "Longhorn readback differed from the bytes written" unless data == "persisted\n"; STDOUT.write(data)'
volume=$("${api[@]}" get "$claim" -o jsonpath='{.spec.volumeName}')
[[ -n "$volume" ]]
