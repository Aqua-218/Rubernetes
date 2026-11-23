#!/usr/bin/env bash
set -euo pipefail

api=(kubectl --namespace "${K6_NAMESPACE:?}")
password=$(openssl rand -hex 24)
printf 'export MINIO_ROOT_USER=k6-smoke\nexport MINIO_ROOT_PASSWORD=%s\n' "$password" |
  "${api[@]}" create secret generic k6-minio-config --from-file=config.env=/dev/stdin
"${api[@]}" create -f test/compatibility/projects/smoke/minio-tenant.yml
"${api[@]}" wait --for=create pod/k6-smoke-pool-0-0 --timeout=3m
"${api[@]}" wait --for=condition=Ready pod/k6-smoke-pool-0-0 --timeout=6m

image=docker.io/curlimages/curl:8.14.1@sha256:9a1ed35addb45476afa911696297f8e115993df459278ed036182dd2cd22b67b
"${api[@]}" run k6-s3-client --restart=Never --image="$image" --command -- sleep 900
"${api[@]}" wait --for=condition=Ready pod/k6-s3-client --timeout=3m
endpoint="http://minio.$K6_NAMESPACE.svc"
"${api[@]}" exec k6-s3-client -- curl --fail --silent --show-error --retry 40 --retry-all-errors --retry-delay 2 \
  --retry-max-time 100 --max-time 3 "$endpoint/minio/health/ready"

s3() {
  printf 'user = "k6-smoke:%s"\n' "$password" |
    "${api[@]}" exec -i k6-s3-client -- curl --config - --aws-sigv4 aws:amz:us-east-1:s3 --fail --show-error --silent --max-time 20 "$@"
}
bucket="$endpoint/k6-smoke"
s3 -X PUT "$bucket"
s3 -X PUT --data-binary 'hello from Rubernetes' "$bucket/message"
test "$(s3 "$bucket/message")" = 'hello from Rubernetes'
