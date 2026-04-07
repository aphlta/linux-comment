#!/usr/bin/env bash
set -euo pipefail

# Why: standard A/B execution reduces human bias and missing metadata.

if [ "$#" -lt 5 ]; then
  echo "Usage: $0 <out_dir> <label_a> <cmd_a> <label_b> <cmd_b>"
  exit 1
fi

OUT_DIR="$1"
LABEL_A="$2"
CMD_A="$3"
LABEL_B="$4"
CMD_B="$5"

mkdir -p "${OUT_DIR}"
echo "label,start_ts,end_ts,exit_code" > "${OUT_DIR}/ab_summary.csv"

run_case() {
  local label="$1"
  local cmd="$2"
  local start end rc
  start="$(date +%s)"
  set +e
  sh -c "${cmd}" > "${OUT_DIR}/${label}.log" 2>&1
  rc=$?
  set -e
  end="$(date +%s)"
  echo "${label},${start},${end},${rc}" >> "${OUT_DIR}/ab_summary.csv"
}

run_case "${LABEL_A}" "${CMD_A}"
run_case "${LABEL_B}" "${CMD_B}"

echo "[INFO] A/B run completed: ${OUT_DIR}"
