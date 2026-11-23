#!/usr/bin/env bash
set -euo pipefail

api=(kubectl -n "$K6_NAMESPACE")
"${api[@]}" apply -f test/compatibility/projects/smoke/strimzi-kafka-operator.yml
"${api[@]}" wait kafka/k6-smoke --for=condition=Ready --timeout=6m
pod=$("${api[@]}" get pods -l strimzi.io/name=k6-smoke-kafka -o jsonpath='{.items[0].metadata.name}')
broker=k6-smoke-kafka-bootstrap:9092
"${api[@]}" exec "$pod" -c kafka -- /opt/kafka/bin/kafka-topics.sh --bootstrap-server "$broker" \
  --create --if-not-exists --topic k6-smoke --partitions 1 --replication-factor 1
printf '%s\n' 'k6-kafka-message' |
  "${api[@]}" exec -i "$pod" -c kafka -- /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server "$broker" \
    --topic k6-smoke --producer-property delivery.timeout.ms=30000
message=$("${api[@]}" exec "$pod" -c kafka -- /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server "$broker" \
  --topic k6-smoke --from-beginning --max-messages 1 --timeout-ms 30000)
test "$message" = k6-kafka-message
