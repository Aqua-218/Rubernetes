#!/usr/bin/env bash
set -euo pipefail

namespace="${K6_NAMESPACE:?}"
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
umask 077
hostname="vault-agent-injector-svc.$namespace.svc"

openssl req -x509 -nodes -newkey rsa:2048 -days 1 -subj "/CN=$hostname" \
  -addext "subjectAltName=DNS:$hostname" \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$fixture/tls.key" -out "$fixture/tls.crt" >/dev/null 2>&1
kubectl create namespace "$namespace"
kubectl --namespace "$namespace" create secret generic k6-vault-injector-tls \
  --from-file=tls.key="$fixture/tls.key" --from-file=tls.crt="$fixture/tls.crt" --from-file=ca.crt="$fixture/tls.crt"
