#!/usr/bin/env bash
# Submit a batch of CyberGym tasks using DSH agent.
# Mirrors submit-batch.sh but uses the DSH launch script.
#
# Usage:
#   ./submit-batch-dsh.sh --task-list ../tasks/regression-10-easy.txt --experiment cybergym-dsh-v1
set -euo pipefail

export HTTPS_PROXY="${HTTPS_PROXY:-http://10.2.32.57:3128}"
export HTTP_PROXY="${HTTP_PROXY:-http://10.2.32.57:3128}"

OC="${OC:-oc}"
NS="${NS:-factory-pipeline}"
MAX_CONCURRENT="${MAX_CONCURRENT:-400}"
EXPERIMENT="${EXPERIMENT:-cybergym-dsh-v1}"
TASK_TIMEOUT="${TASK_TIMEOUT:-16200}"
TASK_LIST=""
POLL_INTERVAL="${POLL_INTERVAL:-60}"
JOB_PREFIX="${JOB_PREFIX:-cgdsh}"
LAUNCH_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/launch-cybergym-dsh.sh"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --task-list)       TASK_LIST="$2"; shift 2 ;;
    --experiment)      EXPERIMENT="$2"; shift 2 ;;
    --timeout)         TASK_TIMEOUT="$2"; shift 2 ;;
    --max-concurrent)  MAX_CONCURRENT="$2"; shift 2 ;;
    --prefix)          JOB_PREFIX="$2"; shift 2 ;;
    *) echo "Unknown flag: $1" >&2; exit 1 ;;
  esac
done

[ -z "$TASK_LIST" ] && { echo "ERROR: --task-list required" >&2; exit 1; }
[ -f "$TASK_LIST" ] || { echo "ERROR: task list not found: $TASK_LIST" >&2; exit 1; }
[ -f "$LAUNCH_SCRIPT" ] || { echo "ERROR: launch script not found at $LAUNCH_SCRIPT" >&2; exit 1; }

TOTAL=$(wc -l < "$TASK_LIST")
echo "=== DSH CyberGym Batch Submission ==="
echo "Script: $LAUNCH_SCRIPT"
echo "Tasks: $TOTAL  Max concurrent: $MAX_CONCURRENT  Timeout: ${TASK_TIMEOUT}s"
echo "Experiment: $EXPERIMENT"
echo ""

count_active_jobs() {
  local n
  n=$($OC -n "$NS" get jobs -l "cybergym/experiment=$EXPERIMENT" --no-headers 2>/dev/null | awk '$3=="0/1"' | wc -l)
  echo "${n:-0}"
}

SUBMITTED=0; SKIPPED=0

while IFS= read -r task_id; do
  [ -z "$task_id" ] && continue
  task_id=$(echo "$task_id" | tr -d '\r')
  SAFE_ID="${task_id//[:\/]/_}"
  JOB_NAME="${JOB_PREFIX}-${SAFE_ID}"
  JOB_NAME=$(echo "$JOB_NAME" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | head -c 63 | sed 's/-*$//')

  if $OC -n "$NS" get job "$JOB_NAME" &>/dev/null; then
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  while true; do
    ACTIVE=$(count_active_jobs)
    if [ "$ACTIVE" -lt "$MAX_CONCURRENT" ]; then break; fi
    echo "[$(date +%H:%M:%S)] Active: $ACTIVE/$MAX_CONCURRENT — waiting (submitted=$SUBMITTED, total=$TOTAL)"
    sleep "$POLL_INTERVAL"
  done

  TASK_TIMEOUT="$TASK_TIMEOUT" EXPERIMENT="$EXPERIMENT" JOB_PREFIX="$JOB_PREFIX" \
    bash "$LAUNCH_SCRIPT" "$task_id" \
      --timeout "$TASK_TIMEOUT" --experiment "$EXPERIMENT" --prefix "$JOB_PREFIX" 2>&1 | tail -1

  SUBMITTED=$((SUBMITTED + 1))
  (( SUBMITTED % 10 == 0 )) && echo "[$(date +%H:%M:%S)] Progress: submitted=$SUBMITTED skipped=$SKIPPED total=$TOTAL"
done < "$TASK_LIST"

echo ""
echo "=== Submission complete ==="
echo "Submitted: $SUBMITTED  Skipped: $SKIPPED  Total: $TOTAL"
