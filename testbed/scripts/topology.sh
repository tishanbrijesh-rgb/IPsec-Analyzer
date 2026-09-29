#!/usr/bin/env bash
# Isolated two-peer Linux network topology. Requires CAP_NET_ADMIN.
set -euo pipefail

client_ns=sih4-client
server_ns=sih4-server

require_tools() {
  [[ "$(uname -s)" == Linux ]] || { echo "Linux is required" >&2; exit 1; }
  command -v ip >/dev/null || { echo "iproute2 is required" >&2; exit 1; }
  [[ "$(id -u)" == 0 ]] || { echo "Run as root in an isolated lab" >&2; exit 1; }
}

exists() { ip netns list | grep -Eq "^$1( |$)"; }

down() {
  # These fixed names are reserved for this script only.
  if exists "$client_ns"; then ip netns del "$client_ns"; fi
  if exists "$server_ns"; then ip netns del "$server_ns"; fi
}

up() {
  if exists "$client_ns" || exists "$server_ns"; then
    echo "A Phase 4 namespace already exists; use status or down" >&2
    exit 1
  fi
  trap 'down' ERR
  ip netns add "$client_ns"
  ip netns add "$server_ns"
  ip link add sih4c type veth peer name sih4s
  ip link set sih4c netns "$client_ns"
  ip link set sih4s netns "$server_ns"
  ip -n "$client_ns" addr add 198.51.100.2/32 dev sih4c
  ip -n "$server_ns" addr add 203.0.113.2/32 dev sih4s
  ip -n "$client_ns" -6 addr add 2001:db8:1::2/128 dev sih4c
  ip -n "$server_ns" -6 addr add 2001:db8:2::2/128 dev sih4s
  ip -n "$client_ns" link set lo up
  ip -n "$server_ns" link set lo up
  ip -n "$client_ns" link set sih4c up
  ip -n "$server_ns" link set sih4s up
  ip -n "$client_ns" route add 203.0.113.2/32 dev sih4c
  ip -n "$server_ns" route add 198.51.100.2/32 dev sih4s
  ip -n "$client_ns" -6 route add 2001:db8:2::2/128 dev sih4c
  ip -n "$server_ns" -6 route add 2001:db8:1::2/128 dev sih4s
  ip -n "$client_ns" link add sih4-inner type dummy
  ip -n "$server_ns" link add sih4-inner type dummy
  ip -n "$client_ns" addr add 10.1.0.1/24 dev sih4-inner
  ip -n "$server_ns" addr add 10.2.0.1/24 dev sih4-inner
  ip -n "$client_ns" -6 addr add 2001:db8:10:1::1/64 dev sih4-inner
  ip -n "$server_ns" -6 addr add 2001:db8:10:2::1/64 dev sih4-inner
  ip -n "$client_ns" link set sih4-inner up
  ip -n "$server_ns" link set sih4-inner up
  ip -n "$client_ns" route add 10.2.0.0/24 via 203.0.113.2 dev sih4c
  ip -n "$server_ns" route add 10.1.0.0/24 via 198.51.100.2 dev sih4s
  ip -n "$client_ns" -6 route add 2001:db8:10:2::/64 via 2001:db8:2::2 dev sih4c
  ip -n "$server_ns" -6 route add 2001:db8:10:1::/64 via 2001:db8:1::2 dev sih4s
  trap - ERR
  status
}

status() {
  ip netns list | grep -E '^sih4-(client|server)( |$)' || true
}

require_tools
case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "Usage: $0 {up|status|down}" >&2; exit 2 ;;
esac
