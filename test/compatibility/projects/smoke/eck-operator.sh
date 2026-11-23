#!/usr/bin/env bash
set -euo pipefail

api=(kubectl -n "$K6_NAMESPACE")
"${api[@]}" apply -f test/compatibility/projects/smoke/eck-operator.yml
"${api[@]}" wait elasticsearch/k6-smoke --for=jsonpath='{.status.availableNodes}'=1 --timeout=8m
pod=k6-smoke-es-default-0
service=k6-smoke-es-http."$K6_NAMESPACE".svc
password=$("${api[@]}" get secret k6-smoke-es-elastic-user -o jsonpath='{.data.elastic}' | base64 -d)
request() {
  printf 'machine %s login elastic password %s\n' "$service" "$password" |
    "${api[@]}" exec -i "$pod" -c elasticsearch -- curl --fail --silent --show-error --max-time 30 \
      --cacert /usr/share/elasticsearch/config/http-certs/ca.crt --netrc-file /dev/stdin "$@" "https://$service:9200/messages/_doc/1"
}

request -X PUT -H 'Content-Type: application/json' --data '{"message":"hello"}' | jq -e '.result == "created" or .result == "updated"'
request | jq -e '._source.message == "hello"'
