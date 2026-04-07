# Linux Low Power Expert Execution Kit

## Purpose

This directory implements the 6-month Linux low-power expert plan with
hands-on assets, templates, and scripts.

## Directory Map

- `phase0_baseline.md`: Platform observation checklist + idle baseline template.
- `phase1_cpu_pm.md`: `cpuidle`/`cpufreq` study guide + experiment playbook.
- `phase2_runtime_pm.md`: Runtime PM pattern library and device audit method.
- `phase3_system_sleep.md`: Suspend/resume regression SOP and triage flow.
- `phase4_platform_optimization.md`: End-to-end optimization project blueprint.
- `phase5_upstream_output.md`: Upstream contribution and public output package.
- `../../../scripts/power/*.sh`: Automation scripts for measurement and regression.

## How To Use

1. Start with `phase0_baseline.md` and run `../../../scripts/power/collect_idle_baseline.sh`.
2. Follow each phase document in order, keeping weekly evidence in a logbook.
3. Use one branch per optimization attempt, and preserve A/B results.
4. Treat every conclusion as invalid until it is reproduced 3 times.

## Expected Deliverables

- Reproducible measurement workflow (script + report).
- CPU PM tuning handbook and known anti-patterns.
- Runtime PM issue pattern library across at least 2 devices.
- Suspend/resume regression script and troubleshooting SOP.
- One end-to-end optimization report with regression evidence.
- One patch/RFC draft and one public technical write-up.
