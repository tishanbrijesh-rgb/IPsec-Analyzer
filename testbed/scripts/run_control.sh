#!/usr/bin/env bash
# Separate non-VPN control capture on the isolated outer link.
set -euo pipefail

[[ $# == 1 && "$1" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || { echo "Usage: $0 <run-id>" >&2; exit 2; }
[[ "$(uname -s)" == Linux && "$(id -u)" == 0 ]] || { echo "Linux root is required" >&2; exit 1; }
project_dir=$(cd "$(dirname "$0")/../.." && pwd)
cd "$project_dir"
run_dir="$project_dir/testbed/generated/$1"
[[ ! -e "$run_dir" ]] || { echo "Run directory already exists" >&2; exit 1; }
mkdir -m 700 "$run_dir"

capture_pid=''
topology_up=0
cleanup() {
  if [[ -n "$capture_pid" ]]; then
    kill "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
  fi
  if [[ "$topology_up" == 1 ]]; then
    bash testbed/scripts/topology.sh down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

bash testbed/scripts/topology.sh up > "$run_dir/topology.log"
topology_up=1
ip netns exec sih4-client tcpdump --immediate-mode -i sih4c -s 0 -U \
  -w "$run_dir/control.pcap" 'icmp and host 198.51.100.2 and host 203.0.113.2' \
  > "$run_dir/tcpdump.log" 2>&1 &
capture_pid=$!
sleep 1
ip netns exec sih4-client ping -c 3 -W 2 -I 198.51.100.2 203.0.113.2 \
  > "$run_dir/ping.log" 2>&1
sleep 1
kill "$capture_pid"
wait "$capture_pid" 2>/dev/null || true
capture_pid=''
PYTHONPATH=src python3 -m testbed.scripts.register_control \
  "$run_dir/control.pcap" "$run_dir/control_record.json"
