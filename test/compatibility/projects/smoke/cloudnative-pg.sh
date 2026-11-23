#!/usr/bin/env bash
set -euo pipefail

api=(kubectl -n "$K6_NAMESPACE")
for kind in mutating validating; do
  kubectl wait "${kind}webhookconfiguration/cnpg-${kind}-webhook-configuration" \
    --for=jsonpath='{.webhooks[0].clientConfig.caBundle}' --timeout=2m
done
"${api[@]}" apply -f test/compatibility/projects/smoke/cloudnative-pg.yml
"${api[@]}" wait cluster.postgresql.cnpg.io/k6-smoke --for=condition=Ready --timeout=6m
result=$("${api[@]}" exec k6-smoke-1 -c postgres -- psql --dbname=app --no-psqlrc --tuples-only --no-align \
  --set=ON_ERROR_STOP=1 --command="CREATE TABLE IF NOT EXISTS messages (body text); TRUNCATE messages; INSERT INTO messages VALUES ('k6-cnpg-message');" \
  --command='SELECT body FROM messages;' --quiet)
test "$result" = k6-cnpg-message
