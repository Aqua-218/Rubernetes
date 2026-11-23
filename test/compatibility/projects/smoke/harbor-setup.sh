#!/usr/bin/env bash
set -euo pipefail

kubectl_fixture=(kubectl --namespace "${K6_NAMESPACE:?}")
password="K6-harbor-$(openssl rand -hex 20)"
"${kubectl_fixture[@]}" create -f - <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: k6-harbor-admin
stringData:
  HARBOR_ADMIN_PASSWORD: "$password"
YAML
unset password

for claim in database redis registry trivy jobservice; do
  "${kubectl_fixture[@]}" create -f - <<YAML
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: k6-harbor-$claim
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
YAML
done

# The in-tree hostPath provisioner leaves these dedicated directories
# root-owned. The chart's applications keep their stock non-root UIDs.
"${kubectl_fixture[@]}" create -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: k6-harbor-permissions
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
  - name: permissions
    image: registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9
    command: ["/bin/sh", "-ec"]
    args:
    - |
      chown 999:999 /fixture/database /fixture/redis
      chown 10000:10000 /fixture/registry /fixture/trivy /fixture/jobservice
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
    volumeMounts:
    - {name: database, mountPath: /fixture/database}
    - {name: redis, mountPath: /fixture/redis}
    - {name: registry, mountPath: /fixture/registry}
    - {name: trivy, mountPath: /fixture/trivy}
    - {name: jobservice, mountPath: /fixture/jobservice}
  volumes:
  - name: database
    persistentVolumeClaim: {claimName: k6-harbor-database}
  - name: redis
    persistentVolumeClaim: {claimName: k6-harbor-redis}
  - name: registry
    persistentVolumeClaim: {claimName: k6-harbor-registry}
  - name: trivy
    persistentVolumeClaim: {claimName: k6-harbor-trivy}
  - name: jobservice
    persistentVolumeClaim: {claimName: k6-harbor-jobservice}
YAML
"${kubectl_fixture[@]}" wait --for=jsonpath='{.status.phase}'=Succeeded pod/k6-harbor-permissions --timeout=3m
# RWO volumes can be shared by several Pods on the same node.
node=$("${kubectl_fixture[@]}" get pod k6-harbor-permissions -o 'jsonpath={.spec.nodeName}')
hostname=$(kubectl get node "$node" -o 'jsonpath={.metadata.labels.kubernetes\.io/hostname}')
[[ -n "$hostname" ]]
placement="database.internal.nodeSelector.kubernetes\\.io/hostname=$hostname,redis.internal.nodeSelector.kubernetes\\.io/hostname=$hostname"
placement+=",registry.nodeSelector.kubernetes\\.io/hostname=$hostname,trivy.nodeSelector.kubernetes\\.io/hostname=$hostname"
placement+=",jobservice.nodeSelector.kubernetes\\.io/hostname=$hostname"
"${kubectl_fixture[@]}" create configmap k6-harbor-fixture --from-literal="placement=$placement"
