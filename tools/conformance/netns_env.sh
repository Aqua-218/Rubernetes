#!/usr/bin/env bash
# Dedicated network namespace for one conformance cluster instance.
#
#   tools/conformance/netns_env.sh up   <name> [--v4 <n>] [--v6 <hex>]
#   tools/conformance/netns_env.sh down <name>
#   tools/conformance/netns_env.sh exec <name> -- <command...>
#
# The namespace gets a veth uplink to the host (IPv4 10.250.<n>.0/30 and IPv6
# fd00:1a:<hex>::/64), a default route through it, forwarding enabled, and a
# resolv.conf of its own (/etc/netns/<name>/resolv.conf) because the host's
# 127.0.0.53 stub resolver is unreachable from inside.  Pod traffic leaving
# the namespace is masqueraded to the uplink address inside it, and the host
# masquerades the uplink out, so Pods reach the internet while the bridges,
# nftables tables, node ports and Pod routes stay invisible to the host's own
# k3s and to other instances.  `--route CIDR` (optional, one instance at a
# time) additionally routes a cluster CIDR from the host into the namespace
# for host-side debugging; the conformance runner itself runs inside.
#
# `exec` enters the namespace with `ip netns exec`, which replaces /sys with
# a fresh sysfs (so the namespace's own /sys/class/net shows) -- that hides
# the host's cgroup2 mount, which the node agents need, so it is mounted
# again before the command runs.
set -euo pipefail

usage() { echo "usage: $0 {up|down|exec} <name> [options]" >&2; exit 2; }

command_name=${1:-}; name=${2:-}
[ -n "$command_name" ] && [ -n "$name" ] || usage
shift 2

v4_index=${NETNS_V4_INDEX:-0}
v6_hex=${NETNS_V6_HEX:-e5}
cidrs=()
while [ $# -gt 0 ]; do
  case "$1" in
    --v4) v4_index=$2; shift 2 ;;
    --v6) v6_hex=$2; shift 2 ;;
    --route) cidrs+=("$2"); shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

host_if="${name}h"
ns_if="uplink"
v4_host="10.250.${v4_index}.1"; v4_ns="10.250.${v4_index}.2"; v4_net="10.250.${v4_index}.0/30"
v6_host="fd00:1a:${v6_hex}::1"; v6_ns="fd00:1a:${v6_hex}::2"; v6_net="fd00:1a:${v6_hex}::/64"

rule() { # rule <iptables|ip6tables> [-t table] <chain> <match...>: add unless present
  local bin=$1 table=(); shift
  if [ "$1" = "-t" ]; then table=(-t "$2"); shift 2; fi
  "$bin" "${table[@]}" -C "$@" 2>/dev/null || "$bin" "${table[@]}" -I "$@"
}
unrule() {
  local bin=$1 table=(); shift
  if [ "$1" = "-t" ]; then table=(-t "$2"); shift 2; fi
  "$bin" "${table[@]}" -D "$@" 2>/dev/null || true
}

case "$command_name" in
  up)
    ip netns list | grep -qx "$name" && { echo "netns $name already exists" >&2; exit 1; }
    ip netns add "$name"
    ip link add "$host_if" type veth peer name "$ns_if" netns "$name"
    ip addr add "$v4_host/30" dev "$host_if"
    ip -6 addr add "$v6_host/64" dev "$host_if"
    ip link set "$host_if" up
    ip netns exec "$name" ip link set lo up
    ip netns exec "$name" ip addr add "$v4_ns/30" dev "$ns_if"
    ip netns exec "$name" ip -6 addr add "$v6_ns/64" dev "$ns_if"
    ip netns exec "$name" ip link set "$ns_if" up
    # Duplicate-address detection on the host side of the link takes about a
    # second; a command entering the namespace right away would find the
    # IPv6 uplink tentative.
    sleep 1.5
    ip netns exec "$name" ip route add default via "$v4_host" dev "$ns_if"
    ip netns exec "$name" ip -6 route add default via "$v6_host" dev "$ns_if"
    ip netns exec "$name" sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
      net.ipv6.conf.default.forwarding=1 net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
    # Pods carry no NAT of their own (the node routes them, as a CNI bridge
    # does), so whatever leaves the namespace through the uplink is
    # masqueraded to the uplink address here.  The host then only ever sees
    # the /30 and the ULA /64, and two instances never need conflicting
    # host routes for the same Pod CIDRs.
    ip netns exec "$name" iptables  -t nat -A POSTROUTING -o "$ns_if" -j MASQUERADE
    ip netns exec "$name" ip6tables -t nat -A POSTROUTING -o "$ns_if" -j MASQUERADE
    # The host forwards for the namespace and NATs it out; the FORWARD
    # policy here is DROP (docker), so explicit accepts are required.
    sysctl -q -w net.ipv6.conf.all.forwarding=1 net.ipv6.conf."$host_if".forwarding=1
    rule iptables  FORWARD -i "$host_if" -j ACCEPT
    rule iptables  FORWARD -o "$host_if" -j ACCEPT
    rule ip6tables FORWARD -i "$host_if" -j ACCEPT
    rule ip6tables FORWARD -o "$host_if" -j ACCEPT
    rule iptables  -t nat POSTROUTING ! -o "$host_if" -m comment --comment "netns-$name" -s "$v4_net" -j MASQUERADE
    rule ip6tables -t nat POSTROUTING ! -o "$host_if" -m comment --comment "netns-$name" -s "$v6_net" -j MASQUERADE
    for cidr in "${cidrs[@]}"; do
      case "$cidr" in
        *:*) ip -6 route replace "$cidr" via "$v6_ns" dev "$host_if"
             rule ip6tables -t nat POSTROUTING ! -o "$host_if" -m comment --comment "netns-$name" -s "$cidr" -j MASQUERADE ;;
        *)   ip route replace "$cidr" via "$v4_ns" dev "$host_if"
             rule iptables  -t nat POSTROUTING ! -o "$host_if" -m comment --comment "netns-$name" -s "$cidr" -j MASQUERADE ;;
      esac
    done
    mkdir -p "/etc/netns/$name"
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions edns0\n' > "/etc/netns/$name/resolv.conf"
    echo "netns $name up: uplink $v4_ns/$v6_ns via host $host_if ($v4_host/$v6_host)"
    ;;
  down)
    for cidr in "${cidrs[@]}"; do
      case "$cidr" in
        *:*) ip -6 route del "$cidr" 2>/dev/null || true
             unrule ip6tables -t nat POSTROUTING ! -o "$host_if" -m comment --comment "netns-$name" -s "$cidr" -j MASQUERADE ;;
        *)   ip route del "$cidr" 2>/dev/null || true
             unrule iptables  -t nat POSTROUTING ! -o "$host_if" -m comment --comment "netns-$name" -s "$cidr" -j MASQUERADE ;;
      esac
    done
    unrule iptables  -t nat POSTROUTING ! -o "$host_if" -m comment --comment "netns-$name" -s "$v4_net" -j MASQUERADE
    unrule ip6tables -t nat POSTROUTING ! -o "$host_if" -m comment --comment "netns-$name" -s "$v6_net" -j MASQUERADE
    unrule iptables  FORWARD -i "$host_if" -j ACCEPT
    unrule iptables  FORWARD -o "$host_if" -j ACCEPT
    unrule ip6tables FORWARD -i "$host_if" -j ACCEPT
    unrule ip6tables FORWARD -o "$host_if" -j ACCEPT
    ip link delete "$host_if" 2>/dev/null || true
    ip netns delete "$name" 2>/dev/null || true
    rm -rf "/etc/netns/$name"
    echo "netns $name down"
    ;;
  exec)
    [ $# -gt 0 ] || usage
    exec ip netns exec "$name" sh -c 'mountpoint -q /sys/fs/cgroup || mount -t cgroup2 cgroup2 /sys/fs/cgroup; exec "$@"' _ "$@"
    ;;
  *) usage ;;
esac
