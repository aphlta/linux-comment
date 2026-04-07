# ARM + Android 新手机功耗/性能分析与调优 Runbook

本目录提供一套可复制到多款 ARM + Android 手机平台的团队流程，用于从“基线建立 → 问题分桶 → 定位归因 → A/B 实验 → 调优落地 → 验收与回归”完整闭环。

## 前置条件（默认版）

- 设备可用 `userdebug/root`
- 可读 debugfs：`/sys/kernel/debug/`
- 具备外部功耗仪/可编程电源或等价高精度测量链路
- 目标 KPI：平衡（待机/续航与体验/抖动都纳入验收）

## 快速开始（团队统一入口）

1. Phase 0：跑基线采集（屏幕熄灭 idle 10min 先做 3 次，方差稳定再进入调优）
   - 采集脚本：[collect_idle_baseline.sh](../../../scripts/power/collect_idle_baseline.sh)
   - 基线方法与报告模板参考：[phase0_baseline.md](../learning_plan/phase0_baseline.md)
2. Phase 1：按判据分桶
   - [02_phase1_classify.md](02_phase1_classify.md)
3. Phase 2：沿定位路径收敛到“可证据化”的根因
   - [03_phase2_localize.md](03_phase2_localize.md)
4. Phase 3：按实验矩阵做 A/B
   - [04_phase3_experiments.md](04_phase3_experiments.md)
5. Phase 4：按调优动作库落地（先治 wakeup，再谈 governor/状态表）
   - [05_phase4_tuning_playbook.md](05_phase4_tuning_playbook.md)
6. Phase 5：验收 + 回归守护
   - [06_phase5_acceptance_and_regression.md](06_phase5_acceptance_and_regression.md)

## 决策树（先分流，避免盲调）

把问题优先归到一个桶，后续路径与证据链固定。

1. 现象：深 idle 进不去（或几乎不驻留）
   - 入口：[02_phase1_classify.md](02_phase1_classify.md) 桶 A
   - 常见根因：PM QoS 约束、tick/nohz 不成立、设备未 runtime suspend、domain 条件不满足
2. 现象：深 idle 进得去但“睡得碎”（平均驻留短、频繁被打断）
   - 入口：桶 B
   - 常见根因：wakeup 风暴（IRQ/timer/alarm/job），导致 `time/usage` 明显小于 `residency`
3. 现象：深 idle residency 很好但功耗不降
   - 入口：桶 C
   - 常见根因：电源域未真关、devfreq/互连未降档、外设常开、测量链路/场景噪声
4. 现象：功耗没降且体验抖动变大
   - 入口：桶 D
   - 常见根因：cpuidle 深睡导致调度 util 更 bursty，cpufreq（如 schedutil）跟随/振荡行为变化；需要联动看 idle、频率与唤醒链

## 输出物（统一留痕）

- 团队角色与输出物规范：[00_roles_and_artifacts.md](00_roles_and_artifacts.md)
- 标准报告模板：[report_template.md](templates/report_template.md)
- 外部功耗仪测量记录模板：[measurement_log_template.md](templates/measurement_log_template.md)
- 推荐 trace 事件集合（最小/深挖/抖动）：[trace_event_sets.md](tools/trace_event_sets.md)

## 参考（内核机制文档）

- cpuidle：[cpuidle.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/cpuidle.rst)
- cpufreq：[cpufreq.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/cpufreq.rst)
- 电流形态与时间轴对齐：[08_soc_lp_lab_instruments_debug_zh.md](../tech_evolution/08_soc_lp_lab_instruments_debug_zh.md)
