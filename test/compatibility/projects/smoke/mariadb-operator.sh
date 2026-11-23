#!/usr/bin/env bash
set -euo pipefail

kubectl_fixture=(kubectl --namespace "${K6_NAMESPACE:?}")
image=mariadb:11.8.8@sha256:24e76fcec8c003a0362d0dd53f4806e7e79458d7fdeaf47437760e19496f5a9c
claim=storage-k6-mariadb-0

configure_hostpath_permissions() {
  "${kubectl_fixture[@]}" wait --for=create "pvc/$claim" --timeout=2m
  "${kubectl_fixture[@]}" wait --for=jsonpath='{.status.phase}'=Bound "pvc/$claim" --timeout=2m
  local pvc volume node
  pvc=$("${kubectl_fixture[@]}" get "pvc/$claim" -o json)
  volume=$(kubectl get pv "$(jq -er '.spec.volumeName' <<< "$pvc")" -o json)
  jq -e '.spec.hostPath != null' <<< "$volume" >/dev/null || return 0

  # The in-tree hostPath plugin does not apply fsGroup to the provisioned
  # directory. Mount only the database fixture's own claim on the same node.
  jq -e --arg uid "$(jq -er '.metadata.uid' <<< "$pvc")" '.spec.claimRef.uid == $uid' <<< "$volume" >/dev/null
  "${kubectl_fixture[@]}" wait --for=condition=PodScheduled pod/k6-mariadb-0 --timeout=2m
  node=$("${kubectl_fixture[@]}" get pod/k6-mariadb-0 -o 'jsonpath={.spec.nodeName}')
  "${kubectl_fixture[@]}" create -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: k6-mariadb-volume-permissions
spec:
  nodeName: $node
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
  - name: permissions
    image: $image
    command: ["/bin/sh", "-ec", "chown 999:999 /fixture-data"]
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
    volumeMounts:
    - name: storage
      mountPath: /fixture-data
  volumes:
  - name: storage
    persistentVolumeClaim:
      claimName: $claim
YAML
  "${kubectl_fixture[@]}" wait --for=jsonpath='{.status.phase}'=Succeeded pod/k6-mariadb-volume-permissions --timeout=2m
  "${kubectl_fixture[@]}" delete pod/k6-mariadb-volume-permissions --timeout=2m
}

"${kubectl_fixture[@]}" apply -f - <<YAML
apiVersion: k8s.mariadb.com/v1alpha1
kind: MariaDB
metadata:
  name: k6-mariadb
spec:
  image: $image
  replicas: 1
  username: fixture
  passwordSecretKeyRef:
    name: k6-mariadb-user
    key: password
    generate: true
  database: fixture
  port: 3306
  updateStrategy:
    type: RollingUpdate
  storage:
    size: 1Gi
YAML

configure_hostpath_permissions
"${kubectl_fixture[@]}" wait --for=condition=Ready mariadb/k6-mariadb --timeout=4m
"${kubectl_fixture[@]}" wait --for=create secret/k6-mariadb-user --timeout=2m
password=$("${kubectl_fixture[@]}" get secret/k6-mariadb-user -o 'jsonpath={.data.password}' | base64 -d)
[[ -n "$password" ]]

query() {
  { printf '%s\n' "$password"; cat; } | "${kubectl_fixture[@]}" exec -i pod/k6-mariadb-0 -- /bin/sh -ec '
    IFS= read -r MYSQL_PWD
    export MYSQL_PWD
    exec mariadb --host=k6-mariadb --ssl-ca="$TLS_CA_CERT_PATH" --ssl-verify-server-cert \
      --user=fixture --batch --skip-column-names fixture
  '
}

observed=""
for attempt in $(seq 1 60); do
  if observed=$(query <<< 'SELECT 1' 2>&1) && [[ "$observed" == 1 ]]; then break; fi
  sleep 1
done
if [[ "$observed" != 1 ]]; then
  echo "$observed" >&2
  exit 1
fi

actual=$(query <<'SQL'
CREATE TABLE fixture_checks (value VARCHAR(64) NOT NULL);
INSERT INTO fixture_checks VALUES ('mariadb-k6');
SELECT value FROM fixture_checks;
SQL
)
unset password
[[ "$actual" == "mariadb-k6" ]]
