#!/usr/bin/env bash

set -u
set -o pipefail

usage() {
  echo "Usage: $0 -<seconds>"
  echo "Example: $0 -15"
  exit 1
}

if [[ $# -ne 1 ]]; then
  usage
fi

INTERVAL="${1#-}"

if ! [[ "$INTERVAL" =~ ^[1-9][0-9]*$ ]]; then
  echo "Error: interval must be a positive number of seconds."
  usage
fi

CHECKPOINT="uk_aq_dropbox:LIVE/R2_history_backup/_ops/checkpoints/r2_history_backup_state_v2.json"

trap 'echo; echo "Stopped."; exit 0' INT TERM

while true; do
  echo
  echo "============================================================"
  date '+%a %d %b %Y %H:%M:%S %Z'
  echo "============================================================"

  if ! rclone cat "$CHECKPOINT" |
    jq '{
      updated_at,
      observation_index_units:
        (.index_tree_units.observations_timeseries_v2.units | length),
      binding_index_units:
        (.index_tree_units.timeseries_binding_v2.units | length)
    }'
  then
    echo "Checkpoint check failed."
  fi

  echo
  echo "Checking again in ${INTERVAL} seconds. Press Ctrl-C to stop."
  sleep "$INTERVAL"
done