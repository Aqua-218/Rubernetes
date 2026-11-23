#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUBERNETES_K6_CILIUM_GUEST:-}" != "$(cat /proc/sys/kernel/random/boot_id)" ]] ||
   [[ "$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)" != QEMU ]] ||
   [[ "${KUBECONFIG:-}" != /srv/k6-cilium/kubeconfig ]]; then
  printf '%s\n' 'Cilium requires its dedicated QEMU guest and external CNI fixture' >&2
  exit 1
fi

api=(kubectl -n "$K6_NAMESPACE")
release=(helm --namespace "$K6_NAMESPACE")
image=registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9

case "$1" in
  ready)
    "${api[@]}" rollout status deployment/cilium-operator --timeout=4m
    "${api[@]}" rollout status daemonset/cilium --timeout=4m
    "${api[@]}" rollout status daemonset/cilium-envoy --timeout=4m
    "${api[@]}" exec daemonset/cilium -c cilium-agent -- cilium-dbg status --brief
    ;;
  traffic)
    evidence=${RUBERNETES_K6_CILIUM_EVIDENCE:?}
    endpoint_file="$evidence/cilium-endpoints.json"
    traffic_log="$evidence/cilium-traffic.log"
    "${api[@]}" run k6-cilium-server --image="$image" --labels=app=k6-cilium-server --restart=Never \
      --port=8080 --command -- sh -c 'mkdir -p /www && echo cilium-k6 > /www/index.html && exec httpd -f -p 8080 -h /www'
    "${api[@]}" run k6-cilium-client --image="$image" --restart=Never --command -- sleep 86400
    "${api[@]}" expose pod k6-cilium-server --name=k6-cilium-service --port=8080 --target-port=8080
    "${api[@]}" wait --for=condition=Ready pod/k6-cilium-server pod/k6-cilium-client --timeout=3m
    server_ip=$("${api[@]}" get pod k6-cilium-server -o jsonpath='{.status.podIP}')
    client_ip=$("${api[@]}" get pod k6-cilium-client -o jsonpath='{.status.podIP}')
    service_ip=$("${api[@]}" get service k6-cilium-service -o jsonpath='{.spec.clusterIP}')
    "${api[@]}" exec daemonset/cilium -c cilium-agent -- cilium-dbg endpoint list -o json >"$endpoint_file"
    ruby -rjson -ripaddr -e '
      endpoints = JSON.parse(File.read(ARGV.shift))
      pool = IPAddr.new("10.244.0.0/16")
      ARGV.each do |address|
        abort "unexpected Cilium IP #{address}" unless pool.include?(address)
        ready = endpoints.any? do |endpoint|
          status = endpoint.fetch("status")
          status["state"] == "ready" && status.dig("networking", "addressing").to_a.any? { |item| item["ipv4"] == address }
        end
        abort "Cilium has no ready endpoint for #{address}" unless ready
        puts "Cilium endpoint #{address} ready"
      end
    ' "$endpoint_file" "$server_ip" "$client_ip" >"$traffic_log"
    for address in "$server_ip" "$service_ip"; do
      response=$("${api[@]}" exec pod/k6-cilium-client -- wget -T 10 -qO- "http://$address:8080")
      [[ "$response" == cilium-k6 ]]
      printf 'Cilium workload returned %s from %s\n' "$response" "$address" >>"$traffic_log"
    done
    cat "$traffic_log"
    ;;
  cleanup)
    "${api[@]}" delete pod k6-cilium-client k6-cilium-server --ignore-not-found --wait --timeout=2m
    "${api[@]}" delete service k6-cilium-service --ignore-not-found --wait --timeout=2m
    ;;
  rollback)
    "${release[@]}" rollback cilium 1 --wait --timeout 15m
    ;;
  release-cni-state)
    kubectl delete ciliumnodes.cilium.io worker-0 --ignore-not-found --wait --timeout=1m
    evidence=${RUBERNETES_K6_CILIUM_EVIDENCE:?}
    endpoint_file="$evidence/cilium-endpoints.json"
    traffic_log="$evidence/cilium-traffic.log"
    if [[ -f "$endpoint_file" && -f "$traffic_log" ]]; then
      identities=$(ruby -rjson -e '
        endpoints, log = ARGV.map { |path| File.read(path) }
        ips = log.scan(/^Cilium endpoint (\d+\.\d+\.\d+\.\d+) ready$/).flatten
        endpoints = JSON.parse(endpoints)
        ids = endpoints.filter_map do |endpoint|
          status = endpoint.fetch("status")
          next unless status.dig("external-identifiers", "cni-attachment-id")
          next unless status.dig("networking", "addressing").to_a.any? { |row| ips.include?(row["ipv4"]) }

          id = status.dig("identity", "id")
          id if id.is_a?(Integer) && id >= 256
        end
        puts ids.uniq
      ' "$endpoint_file" "$traffic_log")
      if [[ -n "$identities" ]]; then
        mapfile -t ids <<<"$identities"
        kubectl delete ciliumidentities.cilium.io "${ids[@]}" --ignore-not-found --wait --timeout=1m
      fi
    fi
    ;;
  *)
    exit 2
    ;;
esac
