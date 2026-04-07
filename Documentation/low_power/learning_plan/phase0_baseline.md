# Phase 0 - Baseline and Observation Checklist

## Why this phase matters

Most low-power failures come from weak baselines, not weak ideas.  
If your baseline is unstable, every optimization result is noise.

## Platform Observation Checklist

### 1) Kernel and PM feature visibility

- Record kernel version: `uname -a`
- Record command line: `cat /proc/cmdline`
- Confirm CPU topology (cluster / big.LITTLE / DynamIQ layout):
  - Read `topology/cluster_id`, `topology/core_id` for each cpu
- Confirm CPU idle states **for every cluster** (not just cpu0):
  - `ls /sys/devices/system/cpu/cpu*/cpuidle/`
  - Read each `state*/name`, `usage`, `time`, `latency`, `residency`, `disable`
- Confirm CPU frequency policy (ARM SoCs have multiple policies):
  - `ls /sys/devices/system/cpu/cpufreq/policy*/`
  - Read `scaling_governor`, `related_cpus`, `cpuinfo_min_freq`, `cpuinfo_max_freq`
- Confirm devfreq devices (GPU / DDR / interconnect):
  - `ls /sys/class/devfreq/`
  - Read `governor`, `cur_freq`, `available_frequencies`
- Confirm power domain state:
  - `cat /sys/kernel/debug/pm_genpd/pm_genpd_summary`

### 2) Wakeup source inventory

- Collect wakeup source counters:
  - `cat /sys/kernel/debug/wakeup_sources` (if available)
- Record interrupt counts before/after: `cat /proc/interrupts`
- Record active timers and periodic jobs:
  - `systemd timers`, cron jobs, telemetry agents
  - (Android) `dumpsys power` for wakelocks, `dumpsys alarm` for alarm manager
- Freeze nonessential background services before baseline run.
  - (Android) Airplane mode + force-stop non-essential apps

### 3) Thermal and throttling guardrails

- Track thermal zone temperatures:
  - `cat /sys/class/thermal/thermal_zone*/temp`
  - (Android) `dumpsys thermalservice`
- Track throttling events if platform exports counters.
- Keep ambient conditions stable across A/B tests.

### 4) Measurement discipline

- Use fixed run duration (10 min for idle baseline).
- Use at least 3 repeated runs per scenario.
- Keep test image, config, and workload version pinned.
- Measurement tools by platform:
  - x86: `powertop`, `turbostat`, RAPL
  - ARM/embedded: external power meter, board INA sensor, fuel gauge (`/sys/class/power_supply/battery/current_now`)
  - All platforms: `trace-cmd` or raw ftrace, `cpuidle` residency delta

## Idle Baseline Report Template

## Header

- Device:
- Board/SoC:
- Kernel commit:
- Config diff:
- Test date/time:
- Ambient temperature:

## Scenario

- Scenario name: `idle_10min_screen_off` (example)
- Preconditions:
  - Airplane mode / network off (or explicitly documented)
  - No user interaction
  - Fixed governor and PM policy

## Data Sources

- `powertop` summary (if x86)
- `turbostat` package/core C-state (if x86)
- `trace-cmd` power events
- `cpuidle` residency counters before/after run
- Platform power rail reading (if external meter available)

## Results Table

| Run | Avg Power (mW) | Peak Power (mW) | Deep Idle Residency (%) | Wakeups/s | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| Mean | | | | | |

## Interpretation

- Top wakeup contributor:
- Is deep idle blocked? (yes/no + evidence)
- Is thermal throttling present? (yes/no + evidence)

## Action Items

- [ ] Fix top 1 wakeup source
- [ ] Repeat baseline under same conditions
- [ ] Compare delta against acceptance threshold

## Acceptance Criteria

- Idle mean power variance across runs <= 5%.
- Wakeup source ranking is stable across repeated runs.
- Data can be reproduced by another engineer using same script.
