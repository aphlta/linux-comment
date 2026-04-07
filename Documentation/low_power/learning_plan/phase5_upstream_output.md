# Phase 5 - Upstream and Expert Output Package

## Why this phase matters

Expert level means your optimization logic survives peer review and can be
transferred to others through high-quality artifacts.

## Upstream Readiness Checklist

- Problem statement has reproducible steps.
- Impact is quantified (power/perf/stability).
- Root cause includes code-path evidence.
- Fix rationale explains why this approach is safe.
- Regression plan covers functional and performance checks.

## Patch/RFC Template

### Subject

`[PATCH/RFC] subsystem: concise fix title`

### Body structure

1. Problem in production terms.
2. Root cause with call-path evidence.
3. Why the proposed fix is correct.
4. Validation matrix and observed deltas.
5. Risks and fallback.

## Public Technical Output Package

- One long-form article:
  - background, constraints, failed hypotheses, accepted fix
- One internal sharing deck:
  - before/after plots and lessons learned
- One casebook entry:
  - issue pattern, detection signal, proof chain, mitigation

## Graduation Criteria

- At least one patch/RFC draft reviewed by peers.
- One public or internal deep-dive talk delivered.
- Casebook entry reused by another engineer to solve a related issue.
