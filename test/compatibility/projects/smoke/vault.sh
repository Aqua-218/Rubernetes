#!/usr/bin/env bash
set -euo pipefail

namespace="${K6_NAMESPACE:?}"
kubectl_fixture=(kubectl --namespace "$namespace")
vault_server=("${kubectl_fixture[@]}" exec --stdin vault-0 --)

helm test vault --namespace "$namespace" --timeout 3m
initialized=$("${vault_server[@]}" vault operator init -key-shares=1 -key-threshold=1 -format=json)
unseal_key=$(jq -er '.unseal_keys_b64[0]' <<< "$initialized")
root_token=$(jq -er '.root_token' <<< "$initialized")
unset initialized

"${vault_server[@]}" /bin/sh -ec 'IFS= read -r key; vault operator unseal "$key" >/dev/null' <<< "$unseal_key"
unset unseal_key
observed=$("${vault_server[@]}" /bin/sh -ec '
  IFS= read -r VAULT_TOKEN
  export VAULT_TOKEN
  vault secrets enable -path=k6 kv-v2 >/dev/null
  vault kv put k6/fixture marker=vault-k6 >/dev/null
  vault kv get -field=marker k6/fixture
' <<< "$root_token")
unset root_token
[[ "$observed" == "vault-k6" ]]

mutated=$("${kubectl_fixture[@]}" create --dry-run=server -o json -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: k6-vault-injected
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/agent-inject-secret-fixture: k6/data/fixture
    vault.hashicorp.com/role: fixture
spec:
  containers:
  - name: app
    image: hashicorp/vault:2.0.4
YAML
)
jq -e 'any(.spec.containers[]; .name == "vault-agent") and any(.spec.initContainers[]; .name == "vault-agent-init")' <<< "$mutated"
