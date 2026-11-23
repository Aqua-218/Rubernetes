#!/usr/bin/env bash
set -euo pipefail

# The VM starts from its initramfs. Its dedicated ext4 root is vda and
# a new 12 GiB virtio disk with serial RBNROOKDATA is vdb. The launcher
# verifies vdb's serial and labels worker-0 before running the corpus.
ns="${K6_NAMESPACE:?}"
disk=/dev/vdb
api=(kubectl --namespace "$ns")
[[ "$ns" == rook-ceph ]]

verify_guest_disk() {
  [[ "$(cat /sys/class/dmi/id/sys_vendor)" == QEMU ]]
  [[ -b "$disk" && "$(cat /sys/class/block/vdb/serial)" == RBNROOKDATA ]]
  [[ "$("${api[@]}" get nodes -l k6.rubernetes.io/rook-disk=RBNROOKDATA -o name)" == node/worker-0 ]]
}

verify_blank_disk() {
  local mounts signatures
  mounts=$(lsblk --noheadings --raw --output MOUNTPOINT "$disk")
  signatures=$(lsblk --noheadings --raw --output FSTYPE "$disk")
  [[ -z "$mounts" && -z "$signatures" ]]
  [[ "$(lsblk --noheadings --raw --output TYPE "$disk")" == disk ]]
}

toolbox() {
  "${api[@]}" exec deployment/rook-ceph-tools -- "$@"
}

delete_csi_operator_resources() {
  local resource scope
  for resource in operatorconfigs drivers clientprofiles clientprofilemappings cephconnections; do
    resource="$resource.csi.ceph.io"
    scope=$(kubectl get crd "$resource" --ignore-not-found -o jsonpath='{.spec.scope}')
    [[ -n "$scope" ]] || continue
    [[ "$scope" == Namespaced ]]
    "${api[@]}" delete "$resource" --all --ignore-not-found --wait --timeout=5m
  done
}

case "${1:-smoke}" in
  preflight)
    verify_guest_disk
    udevadm control --ping
    # ceph-volume reads the whole block inventory before applying the device selection.
    [[ "$(udevadm info --query=property --property=ID_SERIAL --value --name=/dev/vda)" == RBNK6ROOT ]]
    [[ "$(udevadm info --query=property --property=ID_SERIAL --value --name="$disk")" == RBNROOKDATA ]]
    verify_blank_disk
    ;;
  smoke)
    verify_guest_disk
    "${api[@]}" create -f test/compatibility/projects/smoke/rook-ceph-cluster.yml
    "${api[@]}" wait --for=jsonpath='{.status.phase}'=Ready cephcluster/k6-rook --timeout=15m
    "${api[@]}" wait --for=condition=Available deployment/rook-ceph-osd-0 --timeout=5m
    "${api[@]}" create -f test/compatibility/projects/smoke/rook-ceph-toolbox.yml
    "${api[@]}" rollout status deployment/rook-ceph-tools --timeout=5m
    "${api[@]}" wait --for=jsonpath='{.status.phase}'=Ready cephblockpool/k6-rook-pool --timeout=5m

    # Quickstart verifies the cluster through the toolbox. Allow a newly
    # created pool to finish activating its placement groups first.
    for ((attempt=0; attempt<24; attempt++)); do
      status=$(toolbox ceph status --format json)
      if ruby -rjson -e '
        status = JSON.parse(STDIN.read)
        health = status.fetch("health")
        checks = health.fetch("checks").keys
        # The pinned cluster-test sample mutes these legacy key policy warnings.
        expected_warnings = %w[AUTH_INSECURE_KEYS_ALLOWED AUTH_INSECURE_KEYS_CREATABLE]
        healthy = (checks - expected_warnings).empty? &&
          (health["status"] == "HEALTH_OK" || (health["status"] == "HEALTH_WARN" && !checks.empty?))
        osds = status.fetch("osdmap").values_at("num_osds", "num_up_osds", "num_in_osds")
        placement = status.fetch("pgmap")
        groups = placement.fetch("num_pgs")
        clean_groups = placement.fetch("pgs_by_state").sum do |group|
          group["state_name"] == "active+clean" ? group.fetch("count") : 0
        end
        exit 1 unless healthy && status.fetch("quorum_names").one? && status.dig("mgrmap", "available") == true &&
          osds == [1, 1, 1] && groups.positive? && clean_groups == groups
        puts ["Ceph", health["status"], *checks].join(" ")
      ' <<<"$status"; then
        break
      fi
      if (( attempt == 23 )); then echo "$status" >&2; exit 1; fi
      ruby -e 'sleep 5'
    done
    toolbox /bin/bash -ceu '
      directory=$(mktemp -d)
      trap "rm -rf -- \"$directory\"" EXIT
      printf %s "rook ceph reads its own writes" > "$directory/input"
      rados -p k6-rook-pool put k6-test "$directory/input"
      rados -p k6-rook-pool get k6-test "$directory/output"
      cmp "$directory/input" "$directory/output"
      rados -p k6-rook-pool rm k6-test
      printf "%s\n" "Verified RADOS write, read and delete on k6-rook-pool"
    '
    ;;
  cleanup)
    "${api[@]}" delete deployment/rook-ceph-tools --ignore-not-found --wait --timeout=5m
    pool_crd=$(kubectl get crd cephblockpools.ceph.rook.io --ignore-not-found -o name)
    if [[ -n "$pool_crd" ]]; then
      "${api[@]}" delete cephblockpool/k6-rook-pool --ignore-not-found --wait --timeout=5m
    fi
    cluster_crd=$(kubectl get crd cephclusters.ceph.rook.io --ignore-not-found -o name)
    existing=
    if [[ -n "$cluster_crd" ]]; then
      existing=$("${api[@]}" get cephcluster/k6-rook --ignore-not-found -o name)
    fi
    if [[ -n "$existing" ]]; then
      verify_guest_disk
      "${api[@]}" get "$existing" -o json | ruby -rjson -e '
        spec = JSON.parse(STDIN.read).fetch("spec")
        storage = spec.fetch("storage")
        nodes = storage.fetch("nodes")
        # Rook serializes the default false useAllNodes flag with omitempty.
        abort("unexpected Ceph storage selection") unless spec["dataDirHostPath"] == "/var/lib/rook-k6" &&
          storage.fetch("useAllNodes", false) == false && storage.fetch("useAllDevices") == false &&
          nodes.map { |node| [node["name"], node.fetch("devices").map { |device| device["name"] }] } == [["worker-0", ["vdb"]]]
      '
      daemon_nodes=$("${api[@]}" get pods -l 'app in (rook-ceph-mon,rook-ceph-mgr,rook-ceph-osd)' \
        -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | ruby -e 'puts STDIN.readlines.uniq.sort')
      "${api[@]}" patch "$existing" --type=merge -p '{"spec":{"cleanupPolicy":{"confirmation":"yes-really-destroy-data"}}}'
      "${api[@]}" delete "$existing" --wait --timeout=10m
      # The pinned teardown guide waits for the operator's host cleanup jobs before Helm uninstall.
      while IFS= read -r node; do
        [[ -n "$node" ]] || continue
        [[ "$node" =~ ^worker-[0-2]$ ]]
        job="job/cluster-cleanup-job-$node"
        "${api[@]}" wait --for=create "$job" --timeout=5m
        "${api[@]}" wait --for=condition=Complete "$job" --timeout=10m
      done <<<"$daemon_nodes"
      udevadm trigger --subsystem-match=block --sysname-match=vdb --action=change
      udevadm settle --timeout=20
      verify_blank_disk
    fi
    delete_csi_operator_resources
    ;;
  *) exit 2 ;;
esac
