#!/usr/bin/env bash
# Reproducible, sequential Phase 4 lab batch. Never runs namespaces in parallel.
set -euo pipefail
cd "$(dirname "$0")/../.."
for profile in voip-like video-like messaging-like email-like web-like icmp; do
  for index in 1 2 3 4 5; do
    name=${profile%-like}
    run_id=$(printf 'phase4-%s-%02d' "$name" "$index")
    if [[ -f "testbed/generated/$run_id/dataset_record.json" ]]; then
      echo "already registered $run_id"
      continue
    fi
    case "$index" in
      1|4) scenario=modern-tunnel ;;
      2) scenario=modern-transport ;;
      3|5) scenario=cbc-no-pfs ;;
    esac
    seed=$((100 + index))
    bash testbed/scripts/run_profile.sh "$profile" "$run_id" "$seed" "$scenario"
    echo "registered $run_id $scenario seed=$seed"
  done
done
