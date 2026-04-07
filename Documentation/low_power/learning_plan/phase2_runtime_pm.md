# Phase 2 - Runtime PM Pattern Library

## Why this phase matters

System idle power is often dominated by devices that look "mostly idle" but
never fully suspend. Runtime PM closes this gap at device granularity.

## Device Selection Strategy

Pick 2-3 from:

- network (Wi-Fi/Ethernet)
- storage (NVMe/UFS/eMMC)
- I/O (USB/UART/SPI)

## Audit Workflow

1. Identify runtime PM sysfs path for each device.
2. Capture `runtime_status`, `runtime_active_time`, `runtime_suspended_time`.
3. Measure functional KPI (throughput/latency/error rate) before changes.
4. Tune autosuspend delay in small steps.
5. Re-measure both power and functionality.

## Common Problem Patterns

### Pattern A: Half-active forever

- Symptom: device toggles frequently, never reaches sustained suspended state.
- Root cause candidates:
  - periodic polling timer
  - aggressive health-check task
  - unresolved IRQ storm
- Mitigation:
  - reduce polling frequency
  - gate timer in idle windows
  - fix noisy interrupt source

### Pattern B: Autosuspend too aggressive

- Symptom: power improves but I/O latency spikes.
- Why: device repeatedly reinitializes for short bursts.
- Mitigation: increase autosuspend delay to match burst interval.

### Pattern C: Missing runtime put path

- Symptom: `runtime_status=active` for long windows.
- Why: driver error path forgets `pm_runtime_put*`.
- Mitigation: audit probe/remove/error labels and balanced get/put logic.

## Output Template

- Device:
- Baseline power:
- Baseline KPI:
- Change:
- Post-change power:
- Post-change KPI:
- Regression risk:
- Decision (accept/reject):
