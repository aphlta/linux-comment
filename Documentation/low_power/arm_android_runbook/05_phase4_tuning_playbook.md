# 05 - Phase 4：调优动作库（先治 wakeup，再谈 governor/状态表）

本章不是“教科书”，而是面向 ARM + Android 手机项目的可执行调优动作库：每个动作都有适用场景、证据要求、常见副作用与验收指标。默认遵循收益/风险排序。

## 4.1 Tier 0：先做噪声治理（否则所有结论都不稳定）

- 固定测试温度与供电条件（外部功耗仪参数可复现）
- 固定 Android 场景前置条件（网络/屏幕/后台服务）
- 用 A→B→A’ 验证场景稳定性（见 [04_phase3_experiments.md](04_phase3_experiments.md)）

## 4.2 Tier 1：wakeup 治理（最常见、收益最大）

### 4.2.1 周期性唤醒（timer/alarm/job）

适用：

- 桶 B（睡得碎），或 wakeup/s 明显偏高

动作方向：

- 合并/延后周期任务（把“分散唤醒”变成“批处理窗口”）
- 减少无意义心跳/轮询

证据：

- `/proc/interrupts` delta 与 trace 的 timer/irq 事件明显下降
- 深 idle 平均驻留变长（`delta_time/delta_usage` 上升）

副作用：

- 后台任务延迟上升，需要白名单与业务约束

### 4.2.2 IRQ 风暴/抖动（网络/输入/GPIO）

适用：

- `/proc/interrupts` Top offender 明确，且增量远高于其他 IRQ

动作方向：

- 网络：中断合并、NAPI 参数、扫描/keepalive 策略调整
- GPIO：硬件消抖/软件消抖、修触发类型、避免浮空
- IRQ affinity：把 burst 集中到少数 CPU，给其他 CPU 创造长空闲窗口

证据：

- IRQ 增量下降；trace 上 wakeup 来源更集中/更少
- 深 idle residency 上升且平均驻留上升

副作用：

- 过度绑核可能影响峰值性能或热分布，需要结合热与负载均衡评估

## 4.3 Tier 2：深睡链路修复（tick/nohz、timer 兜底、domain 条件）

适用：

- 桶 A（深睡不可达）或 “深睡驻留很低但系统并不忙”

动作方向（按常见性）：

1. 检查是否被周期 tick 或高频 timer 打断（tick/nohz 条件）
2. 确认深睡所需的时钟事件设备兜底是否成立（例如 broadcast timer 思路）
3. 检查共享域/cluster 深睡的门槛（是否需要多核同时满足、是否存在常驻活动 CPU）

证据：

- 深 state `rejected` 降低
- trace 中 idle 选择更深且驻留更长

副作用：

- 深睡修复可能带来唤醒延迟上升，需要在 Balanced KPI 下验证体验侧指标

## 4.4 Tier 3：设备侧 runtime PM 与系统级资源（devfreq/genpd）

适用：

- 桶 A/B：设备活动导致频繁唤醒或阻塞深睡
- 桶 C：residency 好但功耗不降，怀疑互连/DDR/GPU 未降档或电源域未关

动作方向：

- 确保设备在空闲时进入 runtime suspend，减少 IRQ/轮询/总线活动
- 检查 devfreq 设备是否能进入低频/idle governor
- 检查 genpd 电源域是否能进入 off/retention（平台可观测时）

证据：

- wakeup_sources/interrupts 明显下降
- devfreq `cur_freq` 下探或更稳定
- genpd summary 显示域进入预期状态

副作用：

- 过激 autosuspend 会增加 resume 频率或增加尾延迟，需要配合 A/B 验证

## 4.5 Tier 4：cpuidle × cpufreq × 调度联动（桶 D 的主战场）

适用：

- 功耗没降且体验抖动变大
- trace 显示：深 idle 退出后频率/负载跟随存在振荡或过冲

核心原则：

- 不允许只调 cpuidle 或只调 cpufreq；必须同时看 `cpu_idle`、`cpu_frequency` 与 `sched` 事件
- 优先把 wakeup 降下来，让深睡变长驻留；否则深睡越深越“碎”，越容易引入抖动

常用策略（按“先控制副作用”排序）：

1. 关键业务期限制深 idle（QoS/策略），换确定性
2. 限制频率上限或改善 DVFS 跟随，降低频率振荡
3. 限制后台 util 峰值（uclamp/cgroup），减少频率过冲与 burst

证据：

- “idle exit → cpu_frequency → sched_wakeup/switch” 的时间线对照，解释体验侧改善来自哪里
- 功耗与体验指标同时满足门槛

参考机制文档：

- cpuidle：[cpuidle.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/cpuidle.rst)
- cpufreq：[cpufreq.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/cpufreq.rst)
