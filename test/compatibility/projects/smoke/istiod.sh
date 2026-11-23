#!/usr/bin/env bash
set -euo pipefail

api=(kubectl -n "$K6_NAMESPACE")
kubectl wait "mutatingwebhookconfiguration/istio-sidecar-injector-$K6_NAMESPACE" \
  --for=jsonpath='{.webhooks[0].clientConfig.caBundle}' --timeout=2m
"${api[@]}" apply -f test/compatibility/projects/smoke/istiod.yml
for deployment in curl httpbin; do
  "${api[@]}" rollout status "deployment/$deployment" --timeout=4m
  "${api[@]}" get pods -l "app=$deployment" -o json | ruby -rjson -e '
    pods = JSON.parse(STDIN.read).fetch("items")
    abort "No Pods were found for the injected Deployment" if pods.empty?
    pods.each do |pod|
      running = Array(pod.dig("status", "containerStatuses")) + Array(pod.dig("status", "initContainerStatuses"))
      abort "istio-proxy did not become Ready" unless running.any? { |status| status["name"] == "istio-proxy" && status["ready"] }
    end'
done
"${api[@]}" exec deployment/curl -c curl -- curl --fail --silent --show-error --max-time 15 'http://httpbin:8000/get?k6=mesh' |
  ruby -rjson -e 'abort "httpbin did not echo the mesh request" unless Array(JSON.parse(STDIN.read).dig("args", "k6")) == ["mesh"]'

"${api[@]}" wait pod/k6-plaintext --for=condition=Ready --timeout=2m
test "$("${api[@]}" get pod k6-plaintext -o jsonpath='{.spec.containers[*].name}')" = curl
if plaintext=$("${api[@]}" exec pod/k6-plaintext -- curl --fail --silent --show-error --verbose --max-time 5 \
  'http://httpbin:8000/get?k6=plaintext' 2>&1); then
  printf '%s\n' 'Plaintext unexpectedly reached the strict mTLS workload.' >&2
  exit 1
fi
printf '%s\n' "$plaintext"
if [[ "$plaintext" != *"connection to httpbin"* || ( "$plaintext" != *"curl: (56)"* && "$plaintext" != *"curl: (52)"* ) ]]; then
  printf '%s\n' "$plaintext" >&2
  exit 1
fi
