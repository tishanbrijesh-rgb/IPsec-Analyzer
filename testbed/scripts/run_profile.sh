#!/usr/bin/env bash
# One isolated strongSwan run and one synthetic traffic profile.
set -euo pipefail

[[ $# -ge 2 && $# -le 5 ]] || { echo "Usage: $0 <profile> <run-id> [seed] [scenario] [--live-check]" >&2; exit 2; }
profile=$1
run_id=$2
seed=${3:-0}
scenario=${4:-modern-tunnel}
live_check=${5:-}
[[ -z "$live_check" || "$live_check" == --live-check ]] || { echo "Unknown option: $live_check" >&2; exit 2; }
case "$profile" in
  icmp|voip-like|video-like|messaging-like|email-like|web-like) ;;
  *) echo "Unknown profile" >&2; exit 2 ;;
esac
[[ "$run_id" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || { echo "Invalid run ID" >&2; exit 2; }
[[ "$seed" =~ ^(0|[1-9][0-9]{0,6})$ ]] && (( seed <= 1000000 )) || { echo "Invalid seed" >&2; exit 2; }
case "$scenario" in modern-tunnel|modern-transport|modern-v6-tunnel|modern-udp-encap|cbc-no-pfs) ;; *) echo "Invalid scenario" >&2; exit 2 ;; esac
[[ "$(uname -s)" == Linux && "$(id -u)" == 0 ]] || { echo "Linux root is required" >&2; exit 1; }

project_dir=$(cd "$(dirname "$0")/../.." && pwd)
cd "$project_dir"
run_dir="$project_dir/testbed/generated/$run_id"
[[ ! -e "$run_dir" ]] || { echo "Run directory already exists" >&2; exit 1; }

capture_pid=''
live_pid=''
server_pid=''
topology_up=0
cleanup() {
  if [[ -n "$live_pid" ]]; then
    wait "$live_pid" 2>/dev/null || true
  fi
  if [[ -n "$capture_pid" ]]; then
    kill "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ "$topology_up" == 1 ]]; then
    bash testbed/scripts/peers.sh stop "$run_dir" >/dev/null 2>&1 || true
    bash testbed/scripts/topology.sh down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 testbed/scripts/generate_scenario.py "$scenario" --output "$run_dir" >/dev/null
if [[ "$live_check" == --live-check ]]; then
  {
    printf 'utc_time: '; date -u +'%Y-%m-%dT%H:%M:%SZ'
    printf 'host: '; hostname
    printf 'kernel: '; uname -a
    printf 'python: '; python3 --version
    printf 'tcpdump: '; tcpdump --version
    printf 'cpu: '; awk -F: '/^model name/{gsub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo
    printf 'memory_kib: '; sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\) kB/\1/p' /proc/meminfo
  } > "$run_dir/live-host.txt"
fi
bash testbed/scripts/topology.sh up >/dev/null
topology_up=1
bash testbed/scripts/peers.sh start "$run_dir" > "$run_dir/start.log" 2>&1
capture_filter='ip and (udp port 500 or udp port 4500 or proto 50 or proto 51)'
if [[ "$scenario" == modern-v6-tunnel ]]; then
  capture_filter='ip6 and (udp port 500 or udp port 4500 or proto 50 or proto 51)'
fi
ip netns exec sih4-client tcpdump --immediate-mode -i sih4c -s 0 -U -w "$run_dir/outer.pcap" \
  "$capture_filter" \
  > "$run_dir/tcpdump.log" 2>&1 &
capture_pid=$!
if [[ "$live_check" == --live-check ]]; then
  ip netns exec sih4-client env PYTHONPATH=src python3 -m ipsec_analyzer.ingestion.live \
    --interface sih4c --seconds 20 --max-packets 1000 \
    > "$run_dir/live-result.json" 2> "$run_dir/live-error.log" &
  live_pid=$!
fi
sleep 1
ip netns exec sih4-client swanctl --initiate --uri unix:///run/sih4-client/charon.vici \
  --child protected > "$run_dir/initiate.log" 2>&1

target=10.2.0.1
source=10.1.0.1
if [[ "$scenario" == modern-transport ]]; then
  target=203.0.113.2
  source=198.51.100.2
fi
if [[ "$scenario" == modern-v6-tunnel ]]; then
  target=2001:db8:10:2::1
  source=2001:db8:10:1::1
fi
if [[ "$profile" != icmp ]]; then
  ip netns exec sih4-server python3 testbed/traffic/generate.py serve "$profile" \
    --address "$target" --seed "$seed" > "$run_dir/receiver.log" 2>&1 &
  server_pid=$!
  sleep 1
fi
ip netns exec sih4-client python3 testbed/traffic/generate.py send "$profile" \
  --address "$target" --source "$source" --seed "$seed" --record "$run_dir/traffic_record.json" \
  > "$run_dir/sender.log" 2>&1
if [[ -n "$server_pid" ]]; then
  wait "$server_pid"
  server_pid=''
fi
sleep 2
kill "$capture_pid"
wait "$capture_pid" 2>/dev/null || true
capture_pid=''
if [[ -n "$live_pid" ]]; then
  if ! wait "$live_pid"; then
    cat "$run_dir/live-error.log" >&2
    echo "Bounded live capture failed" >&2
    exit 1
  fi
  live_pid=''
fi
bash testbed/scripts/peers.sh status "$run_dir" > "$run_dir/sa-status.log" 2>&1
PYTHONPATH=src python3 -m testbed.scripts.register_capture "$run_dir" \
  "$run_dir/outer.pcap" --capture-point 'outer client interface'
if [[ "$live_check" == --live-check ]]; then
  PYTHONPATH=src python3 -m testbed.scripts.verify_live_parity \
    "$run_dir/live-result.json" "$run_dir/outer.pcap" \
    > "$run_dir/live-parity.json"
  cat "$run_dir/live-parity.json"
fi
