#!/usr/bin/env bash
# Runs pod_burst.sh ROUNDS times (default 4 = 360 Pods through the cluster)
# so degradation with accumulated on-disk state shows up round by round.
set -euo pipefail
ROUNDS=${ROUNDS:-4}
for r in $(seq 1 "$ROUNDS"); do
  "$(dirname "$0")/pod_burst.sh" "churn-$r"
done
