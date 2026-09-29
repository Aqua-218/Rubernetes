#!/usr/bin/env bash
# One hydrophone conformance round against a cluster brought up by
# cluster.rb, run inside the instance's network namespace.
#
#   tools/conformance/round.sh <netns> <profile-root> <output-dir> [--parallel N] [--focus REGEX] [--skip REGEX]
#
# Without --focus the round is the full [Conformance] suite (--conformance);
# with --focus hydrophone refuses --conformance, so the focused re-run of a
# fix is a different run identity and never replaces a full round's result.
# Results are read from <output-dir>/junit_01.xml, never from hydrophone's
# stdout (see conformance-par4-result-2026-09-17 in memory: the log follow
# stream can replay the whole log thousands of times).  Start it detached:
#
#   setsid nohup tools/conformance/round.sh lanes6 /srv/rbn-lanes/linux-amd64-ipv6-native \
#       /srv/rbn-lanes/rounds/ipv6-01 --parallel 4 > /srv/rbn-lanes/rounds/ipv6-01.out 2>&1 &
set -uo pipefail
here=$(cd "$(dirname "$0")/../.." && pwd)
netns=$1; root=$2; out=$3; shift 3
parallel=4; focus=""; skip=""
while [ $# -gt 0 ]; do
  case "$1" in
    --parallel) parallel=$2; shift 2 ;;
    --focus) focus=$2; shift 2 ;;
    --skip) skip=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$out"
kubeconfig="$root/kubeconfig"
# The same digest references the K1 lane passes (tools/conformance/lock.rb).
conformance_image=$(ruby -e 'require "'"$here"'/tools/conformance/lock"; L=Conformance::Lock; puts L.reference_by_digest(L.kubernetes.fetch("conformance_image"))')
busybox_image=$(ruby -e 'require "'"$here"'/tools/conformance/lock"; L=Conformance::Lock; puts L.reference_by_digest(L.support_images.fetch("busybox"))')
[ -n "$conformance_image" ] && [ -n "$busybox_image" ] || { echo "could not resolve pinned images" >&2; exit 1; }
hydrophone=$here/build/conformance/bin/hydrophone
exec_ns=("$here/tools/conformance/netns_env.sh" exec "$netns" --)

echo "round start $(date -u +%FT%TZ) profile=$root parallel=$parallel focus=${focus:-<conformance>} skip=${skip:-<none>}"
"${exec_ns[@]}" "$hydrophone" --kubeconfig "$kubeconfig" --cleanup >/dev/null 2>&1
args=(--kubeconfig "$kubeconfig" --conformance-image "$conformance_image" --busybox-image "$busybox_image"
      --parallel "$parallel" --output-dir "$out")
if [ -n "$focus" ]; then args+=(--focus "$focus"); else args+=(--conformance); fi
[ -n "$skip" ] && args+=(--skip "$skip")
# hydrophone's stdout is a log follow of the conformance Pod; keep only its
# tail so a broken follow stream cannot fill the disk.
"${exec_ns[@]}" "$hydrophone" "${args[@]}" 2>&1 | tail -c 20000000 > "$out/hydrophone.tail.log"
status=${PIPESTATUS[0]}
echo "round end $(date -u +%FT%TZ) hydrophone_exit=$status"
junit="$out/junit_01.xml"
if [ -f "$junit" ]; then
  python3 - "$junit" <<'EOF'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
suites = root.iter("testsuite") if root.tag != "testsuite" else [root]
tests = failures = skipped = 0
failed = []
for s in suites:
    tests += int(s.get("tests", 0)); failures += int(s.get("failures", 0)); skipped += int(s.get("skipped", 0))
    for c in s.iter("testcase"):
        if c.find("failure") is not None or c.find("error") is not None:
            failed.append(c.get("name"))
print(f"junit: tests={tests} failures={failures} skipped={skipped} ran={tests-skipped} passed={tests-skipped-failures}")
for name in failed:
    print("FAILED:", name)
EOF
else
  echo "no junit report in $out"
fi
