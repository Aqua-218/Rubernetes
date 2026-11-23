#!/usr/bin/env bash
set -euo pipefail

kubectl_fixture=(kubectl --namespace "${K6_NAMESPACE:?}")
fixture=$(mktemp -d)

cleanup() {
  local result=$?
  trap - EXIT
  "${kubectl_fixture[@]}" delete helmrelease k6-flux-release --ignore-not-found --timeout=2m || result=1
  local remaining
  if remaining=$("${kubectl_fixture[@]}" get configmap k6-flux-installed --ignore-not-found -o name); then
    if [[ -n "$remaining" ]]; then
      echo "Flux HelmRelease cleanup left $remaining" >&2
      result=1
    fi
  else
    result=1
  fi
  "${kubectl_fixture[@]}" delete helmrepository/k6-flux-source service/k6-flux-charts pod/k6-flux-charts \
    configmap/k6-flux-charts networkpolicy/k6-flux-charts --ignore-not-found --timeout=2m || result=1
  rm -rf -- "$fixture"
  exit "$result"
}
trap cleanup EXIT

mkdir -p "$fixture/chart/templates" "$fixture/repository"
cat >"$fixture/chart/Chart.yaml" <<'YAML'
apiVersion: v2
name: flux-smoke
version: 0.1.0
YAML
cat >"$fixture/chart/templates/configmap.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: k6-flux-installed
data:
  controller: flux-helm-controller
YAML
helm package "$fixture/chart" --destination "$fixture/repository"
repository_url="http://k6-flux-charts.$K6_NAMESPACE.svc.cluster.local:8080"
helm repo index "$fixture/repository" --url "$repository_url"
"${kubectl_fixture[@]}" create configmap k6-flux-charts --from-file="$fixture/repository"

"${kubectl_fixture[@]}" apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: k6-flux-charts
  labels:
    app.kubernetes.io/name: k6-flux-charts
spec:
  containers:
  - name: charts
    image: registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9
    command: ["/bin/busybox", "httpd", "-f", "-p", "8080", "-h", "/repo"]
    readinessProbe:
      httpGet:
        path: /index.yaml
        port: 8080
    volumeMounts:
    - name: chart
      mountPath: /repo
      readOnly: true
  volumes:
  - name: chart
    configMap:
      name: k6-flux-charts
---
apiVersion: v1
kind: Service
metadata:
  name: k6-flux-charts
spec:
  selector:
    app.kubernetes.io/name: k6-flux-charts
  ports:
  - port: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k6-flux-charts
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: k6-flux-charts
  policyTypes: [Ingress]
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: source-controller
    ports:
    - port: 8080
YAML
"${kubectl_fixture[@]}" wait --for=condition=Ready pod/k6-flux-charts --timeout=2m

"${kubectl_fixture[@]}" apply -f - <<YAML
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: k6-flux-source
spec:
  interval: 1m
  url: $repository_url
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: k6-flux-release
spec:
  interval: 1m
  chart:
    spec:
      chart: flux-smoke
      version: 0.1.0
      sourceRef:
        kind: HelmRepository
        name: k6-flux-source
YAML
"${kubectl_fixture[@]}" wait --for=condition=Ready helmrepository/k6-flux-source helmrelease/k6-flux-release --timeout=3m
actual=$("${kubectl_fixture[@]}" get configmap k6-flux-installed -o 'jsonpath={.data.controller}')
[[ "$actual" == "flux-helm-controller" ]]
