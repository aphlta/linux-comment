# Phase 3 - System Sleep Troubleshooting SOP

## Why this phase matters

Suspend/resume failures are high-severity because they break both battery life
and reliability. You need a deterministic triage path, not ad-hoc debugging.

## Regression SOP

### 1) Pre-check

- Verify wakeup source policy (`/proc/acpi/wakeup` on supported systems).
- Verify no critical background write job is running.
- Record baseline boot count and dmesg tail.

### 2) Automated loop test

- Run N cycles (`N >= 100` for confidence).
- For each cycle record:
  - suspend entry timestamp
  - resume timestamp
  - resume latency
  - wakeup reason
  - success/failure

### 3) Failure triage

- If fail before suspend entry:
  - inspect blockers in PM notifier/device callbacks.
- If fail during suspend:
  - inspect last device suspended and pending IRQ/timer.
- If fail during resume:
  - inspect first resumed device and timeout path.

## Evidence Checklist

- dmesg excerpt for failed cycle
- wakeup source delta from previous cycle
- PM trace (if enabled) around failure window
- device runtime PM state before suspend

## Exit Criteria

- 100-cycle success rate >= 99%
- no resume latency outlier above target threshold
- at least one known historical failure reproduced and root-caused
