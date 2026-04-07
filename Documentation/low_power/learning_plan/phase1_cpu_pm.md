# Phase 1 - CPU Low Power Tuning Handbook (v1)

## Why this phase matters

CPU power behavior is a control loop, not a static knob.  
Without understanding the loop inputs (load, wakeups, scheduler), governor
tuning often makes latency worse and power unchanged.

## Core Concepts

- `cpuidle`: decides which idle state to enter based on predicted sleep time.
- `cpufreq`: decides operating frequency/voltage under workload pressure.
- Scheduler interaction: runnable tasks, migration, and tick behavior decide
  whether deep idle is reachable.

## Experiment Matrix (minimum)

### Workload A: pure idle

- Goal: maximize deep idle residency.
- Watch: wakeups/s, deepest C-state time, average power.

### Workload B: periodic wakeup

- Example: wake every 10ms/50ms/100ms.
- Goal: identify residency collapse threshold.

### Workload C: burst interactive

- Example: bursty CPU every 200ms.
- Goal: evaluate power-latency tradeoff under response constraints.

## Recommended A/B Knobs

- `cpuidle` governor (if switchable)
- `cpufreq` governor (`schedutil`, `performance`, `powersave`)
- PM QoS constraints (latency ceiling)
- Tick behavior (`nohz`) in controlled kernels

## Data You Must Capture

- Power average and peak (external meter preferred)
- P95/P99 latency for interactive tasks
- C-state residency distribution
- Frequency residency distribution
- Wakeup source top-N

## Three common anti-patterns (theory saves power, practice does not)

1. Forcing low frequency under burst load:
   - Why it fails: longer execution time can increase total energy.
2. Chasing deepest C-state while wakeups are noisy:
   - Why it fails: frequent exits dominate energy and latency.
3. Tuning one governor in isolation:
   - Why it fails: scheduler migration/timer behavior cancels governor gains.

## Weekly Deliverable for this phase

- A report with:
  - workload matrix
  - A/B result tables
  - one rejected hypothesis and why it was wrong
  - one accepted optimization with reproducible evidence
