#!/usr/bin/env bash
# Start/stop the two strongSwan instances in the Phase 4 namespaces.
set -euo pipefail

usage() { echo "Usage: $0 {start|status|stop} <generated-run-directory>" >&2; exit 2; }
[[ $# == 2 ]] || usage
action=$1
run_dir=$(realpath "$2")
[[ -d "$run_dir" ]] || { echo "Run directory not found" >&2; exit 1; }
[[ "$(uname -s)" == Linux && "$(id -u)" == 0 ]] || { echo "Linux root is required" >&2; exit 1; }

socket_for() { echo "unix:///run/sih4-$1/charon.vici"; }

stop_peer() {
  local peer=$1 pid_file="$run_dir/$1.daemon.pid" pid
  [[ -f "$pid_file" ]] || return 0
  pid=$(cat "$pid_file")
  if [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]]; then
    if tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q '/usr/sbin/charon-systemd'; then
      kill "$pid" 2>/dev/null || true
    fi
  fi
  rm -f -- "$pid_file"
}

case "$action" in
  start)
    command -v swanctl >/dev/null || { echo "swanctl is required" >&2; exit 1; }
    command -v charon-systemd >/dev/null || { echo "charon-systemd is required" >&2; exit 1; }
    for peer in client server; do
      [[ -f "$run_dir/$peer.conf" && -f "$run_dir/$peer.strongswan.conf" ]] || {
        echo "Missing generated $peer configuration" >&2; exit 1;
      }
      [[ ! -f "$run_dir/$peer.daemon.pid" ]] || { echo "$peer daemon already recorded" >&2; exit 1; }
      mkdir -p "/run/sih4-$peer"
      chmod 700 "/run/sih4-$peer"
      [[ ! -e "/run/sih4-$peer/charon.vici" ]] || { echo "$peer VICI socket already exists" >&2; exit 1; }
    done
    trap 'stop_peer client; stop_peer server' ERR
    for peer in client server; do
      nohup ip netns exec "sih4-$peer" env STRONGSWAN_CONF="$run_dir/$peer.strongswan.conf" \
        /usr/sbin/charon-systemd > "$run_dir/$peer.daemon.log" 2>&1 < /dev/null &
      echo "$!" > "$run_dir/$peer.daemon.pid"
      ready=0
      for _ in {1..40}; do
        if [[ -S "/run/sih4-$peer/charon.vici" ]]; then ready=1; break; fi
        sleep 0.25
      done
      [[ "$ready" == 1 ]] || { echo "$peer daemon did not open VICI socket; see daemon log" >&2; exit 1; }
      ip netns exec "sih4-$peer" swanctl --load-all --uri "$(socket_for "$peer")" \
        --file "$run_dir/$peer.conf" --noprompt
    done
    trap - ERR
    ;;
  status)
    for peer in client server; do
      echo "$peer:"
      ip netns exec "sih4-$peer" swanctl --list-sas --uri "$(socket_for "$peer")"
    done
    ;;
  stop)
    stop_peer client
    stop_peer server
    for peer in client server; do
      socket="/run/sih4-$peer/charon.vici"
      if [[ -S "$socket" ]] && ! ip netns exec "sih4-$peer" swanctl --stats \
          --uri "$(socket_for "$peer")" >/dev/null 2>&1; then
        rm -f -- "$socket"
      fi
    done
    ;;
  *) usage ;;
esac
