# Deep Idle 进不去：一页排障图

目标：把“深 idle 进不去”的问题在一次会诊里收敛到 1–2 条可验证假设。

## 0. 先把现象分类

- A：几乎不进深态（深态 `usage/time` 基本不涨）
- B：进深态但“睡得碎”（驻留短、频繁被打断）
- C：驻留很好但功耗不降（域没关/互连没降/外设常开/测量噪声）

推荐入口：团队分桶与路径见 [arm_android_runbook/02_phase1_classify.md](arm_android_runbook/02_phase1_classify.md)

## 1. 最小证据包（先固化现场）

- 采集脚本：[`scripts/power/collect_idle_baseline.sh`](../../scripts/power/collect_idle_baseline.sh)
- 必备对照：`cpuidle_before/after`、`interrupts_before/after`、`wakeup_sources_before/after`、`pm_genpd_before/after`（若可用）

## 2. 排障主干（从便宜到昂贵）

### 2.1 Wakeup 风暴？（最常见）

- 看 `wakeup_sources` Top offender 是否集中
- 看 `/proc/interrupts` 差分是否集中在某些 IRQ
- 有风暴：先按 Runbook 的 wakeup 三板斧处理

入口：见 [arm_android_runbook/03_phase2_localize.md](arm_android_runbook/03_phase2_localize.md)

### 2.2 Timer / tick 条件不成立？（Ping-pong / 未对齐）

- `timer`/`hrtimer` 事件是否持续唤醒
- cluster 内多个 CPU 的定时器是否对齐

### 2.3 QoS 约束卡住？

- CPU latency / device latency 是否被强制拉高
- 参考：见 [pm_qos_playbook.md](pm_qos_playbook.md)

### 2.4 设备没睡（runtime PM 不成立）

- 证据：runtime PM usage_count、autosuspend 配置、设备 activity
- 辅助脚本：[`scripts/power/runtime_pm_audit.sh`](../../scripts/power/runtime_pm_audit.sh)

### 2.5 电源域条件不满足（genpd 不下电）

- 看 `pm_genpd_summary`：域状态、设备依赖、阻塞项
- 参考：见 [genpd_debug_guide.md](genpd_debug_guide.md)

## 3. 输出格式（一次会诊的最小闭环）

- 现象分类：A/B/C
- 排除项：wakeup/timer/QoS/runtime PM/genpd（按顺序写）
- 结论假设：最多 2 条
- 验证计划：A/B 或禁用对照（必须可回归）
