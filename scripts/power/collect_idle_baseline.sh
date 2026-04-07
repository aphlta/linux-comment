#!/usr/bin/env bash
set -euo pipefail

# Portable idle-power baseline collector for x86, ARM, and Android targets.
# Designed to work on custom/proprietary SoCs without platform-specific knowledge.
# Usage: collect_idle_baseline.sh [output_dir] [duration_sec] [--android]

OUT_DIR="${1:-idle_baseline_$(date +%Y%m%d_%H%M%S)}"
DURATION_SEC="${2:-600}"
ANDROID=0
[ "${3:-}" = "--android" ] && ANDROID=1

mkdir -p "${OUT_DIR}"

echo "[INFO] Output directory: ${OUT_DIR}"
echo "[INFO] Duration (sec): ${DURATION_SEC}"
echo "[INFO] Android mode: ${ANDROID}"

# ── 0. System identity ──────────────────────────────────────────────
{
  echo "==== system ===="
  uname -a
  echo
  echo "==== cmdline ===="
  cat /proc/cmdline
  echo
  echo "==== cpu topology ===="
  for cpu in /sys/devices/system/cpu/cpu[0-9]*/; do
    id=$(basename "$cpu")
    cluster=$(cat "${cpu}topology/cluster_id" 2>/dev/null || echo "?")
    core=$(cat "${cpu}topology/core_id" 2>/dev/null || echo "?")
    online=$(cat "${cpu}online" 2>/dev/null || echo "?")
    echo "${id}: cluster=${cluster} core=${core} online=${online}"
  done
  echo
  echo "==== cpufreq policies ===="
  for policy in /sys/devices/system/cpu/cpufreq/policy*/; do
    [ -d "$policy" ] || continue
    echo "$(basename "$policy"): cpus=$(cat "${policy}/related_cpus") governor=$(cat "${policy}/scaling_governor") range=$(cat "${policy}/cpuinfo_min_freq")-$(cat "${policy}/cpuinfo_max_freq")kHz"
  done
} > "${OUT_DIR}/system_info.txt"

# ── 1. Snapshot helper — captures cpuidle counters for ALL cpus ─────
snapshot_cpuidle() {
  local tag="$1"
  local dest="${OUT_DIR}/cpuidle_${tag}"
  mkdir -p "$dest"
  for cpu in /sys/devices/system/cpu/cpu[0-9]*/cpuidle; do
    [ -d "$cpu" ] || continue
    local cpu_id
    cpu_id=$(basename "$(dirname "$cpu")")
    for state in ${cpu}/state*/; do
      local s_id
      s_id=$(basename "$state")
      {
        echo "name=$(cat "${state}/name" 2>/dev/null)"
        echo "usage=$(cat "${state}/usage" 2>/dev/null)"
        echo "time=$(cat "${state}/time" 2>/dev/null)"
        echo "latency=$(cat "${state}/latency" 2>/dev/null)"
        echo "residency=$(cat "${state}/residency" 2>/dev/null)"
        echo "disable=$(cat "${state}/disable" 2>/dev/null)"
      } > "${dest}/${cpu_id}_${s_id}.txt"
    done
  done
}

# ── 2. Snapshot helper — devfreq (GPU / DDR / interconnect) ─────────
snapshot_devfreq() {
  local tag="$1"
  local dest="${OUT_DIR}/devfreq_${tag}.txt"
  if [ -d /sys/class/devfreq ]; then
    for dev in /sys/class/devfreq/*/; do
      [ -d "$dev" ] || continue
      echo "$(basename "$dev"): governor=$(cat "${dev}/governor" 2>/dev/null) cur_freq=$(cat "${dev}/cur_freq" 2>/dev/null)"
    done > "$dest"
  fi
}

# ── 3. Snapshot helper — power domain summary ──────────────────────
snapshot_pm_genpd() {
  local tag="$1"
  if [ -f /sys/kernel/debug/pm_genpd/pm_genpd_summary ]; then
    cp /sys/kernel/debug/pm_genpd/pm_genpd_summary "${OUT_DIR}/pm_genpd_${tag}.txt" 2>/dev/null || true
  fi
}

# ── 4. Before snapshots ────────────────────────────────────────────
echo "[INFO] Taking 'before' snapshots..."
snapshot_cpuidle "before"
snapshot_devfreq "before"
snapshot_pm_genpd "before"

if [ -f /sys/kernel/debug/wakeup_sources ]; then
  cat /sys/kernel/debug/wakeup_sources > "${OUT_DIR}/wakeup_sources_before.txt" || true
fi

cp /proc/interrupts "${OUT_DIR}/interrupts_before.txt" 2>/dev/null || true

if [ "$ANDROID" -eq 1 ]; then
  dumpsys power > "${OUT_DIR}/dumpsys_power_before.txt" 2>/dev/null || true
  dumpsys batterystats > "${OUT_DIR}/batterystats_before.txt" 2>/dev/null || true
fi

# ── 5. Main trace collection (duration = DURATION_SEC) ─────────────
if command -v trace-cmd >/dev/null 2>&1; then
  echo "[INFO] Collecting trace-cmd power events for ${DURATION_SEC}s..."
  trace-cmd record -o "${OUT_DIR}/power_trace.dat" \
    -e power -e irq -e timer \
    sleep "${DURATION_SEC}" || true
elif [ -d /sys/kernel/debug/tracing ]; then
  echo "[INFO] trace-cmd not found, falling back to ftrace..."
  TRACE=/sys/kernel/debug/tracing
  echo 0 > "${TRACE}/tracing_on"
  echo > "${TRACE}/trace"
  echo 1 > "${TRACE}/events/power/enable" 2>/dev/null || true
  echo 1 > "${TRACE}/events/irq/enable" 2>/dev/null || true
  echo 1 > "${TRACE}/events/timer/enable" 2>/dev/null || true
  echo 1 > "${TRACE}/tracing_on"
  sleep "${DURATION_SEC}"
  echo 0 > "${TRACE}/tracing_on"
  cat "${TRACE}/trace" > "${OUT_DIR}/ftrace_raw.txt"
  echo 0 > "${TRACE}/events/power/enable" 2>/dev/null || true
  echo 0 > "${TRACE}/events/irq/enable" 2>/dev/null || true
  echo 0 > "${TRACE}/events/timer/enable" 2>/dev/null || true
else
  echo "[WARN] No tracing available, sleeping only" | tee -a "${OUT_DIR}/warnings.txt"
  sleep "${DURATION_SEC}"
fi

# ── 6. x86-specific tools (skipped gracefully on ARM) ──────────────
if command -v powertop >/dev/null 2>&1; then
  echo "[INFO] Collecting powertop report..."
  powertop --time=20 --csv="${OUT_DIR}/powertop.csv" || true
fi

if command -v turbostat >/dev/null 2>&1; then
  echo "[INFO] Collecting turbostat snapshot..."
  turbostat --quiet --show Core,CPU,Avg_MHz,Bzy_MHz,PkgWatt,CorWatt,RAMWatt \
    --interval 5 --num_iterations 12 > "${OUT_DIR}/turbostat.txt" || true
fi

# ── 7. After snapshots ────────────────────────────────────────────
echo "[INFO] Taking 'after' snapshots..."
snapshot_cpuidle "after"
snapshot_devfreq "after"
snapshot_pm_genpd "after"

if [ -f /sys/kernel/debug/wakeup_sources ]; then
  cat /sys/kernel/debug/wakeup_sources > "${OUT_DIR}/wakeup_sources_after.txt" || true
fi

cp /proc/interrupts "${OUT_DIR}/interrupts_after.txt" 2>/dev/null || true

if [ "$ANDROID" -eq 1 ]; then
  dumpsys power > "${OUT_DIR}/dumpsys_power_after.txt" 2>/dev/null || true
  dumpsys batterystats > "${OUT_DIR}/batterystats_after.txt" 2>/dev/null || true
fi

# ── 8. Summary ─────────────────────────────────────────────────────
echo "[INFO] Baseline collection completed: ${OUT_DIR}"
echo "[INFO] Contents:"
find "${OUT_DIR}" -type f | sort
