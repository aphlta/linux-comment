# 02 - Phase 1：问题分桶（分类即收敛一半）

本章把功耗/性能问题优先归到 4 个桶，每个桶给出“判据 → 必要证据 → 下一步定位入口”。先分桶的价值是：避免盲目调参、避免只优化一个子系统引入副作用。

## 1. 输入（来自 Phase 0 的基线包）

- 外部功耗仪结果：平均功耗、分位数（若有）
- cpuidle：每 CPU 每 state 的 `usage/time/latency/residency/rejected`
- cpufreq：policy/governor/range、（如可得）time_in_state
- wakeup：`/sys/kernel/debug/wakeup_sources`、`/proc/interrupts` before/after
- trace：`power:cpu_idle`、`power:cpu_frequency`、`irq:*`、`timer:*`（最小集）
- Android：`dumpsys power`、`batterystats`

## 2. 四类问题桶

### A 桶：深 idle 进不去（或几乎不驻留）

**判据（满足任意一条即可入桶）**

- 深 state（通常为最高 index）`usage` 近似为 0，或 `time` 占比很低
- `rejected` 明显偏高（尤其深 state）

**常见根因假设（先从高概率开始）**

- PM QoS/延迟约束导致 governor 过滤深 state
- tick/nohz 条件不成立（周期 tick 或高频 timer）
- 设备未 runtime suspend，导致持续活动或高频唤醒
- 共享电源域/cluster 条件不满足（domain state 需要多核协同）

**下一步入口**

- 定位路径：[03_phase2_localize.md](03_phase2_localize.md)（先查 QoS/定时器/设备活动）

### B 桶：深 idle 进得去但“睡得碎”（不划算）

**判据**

- 深 state 平均驻留 `time/usage` 显著小于 `residency`（目标驻留）
- wakeup/s 高，或 trace 显示频繁从深 state 退出又立刻回去

**典型根因**

- IRQ/timer/alarm/job 过密，把空闲窗口切碎
- 网络/传感器/输入子系统存在 burst 唤醒

**下一步入口**

- 优先治理 wakeup（Top offender）：[03_phase2_localize.md](03_phase2_localize.md) 的“wakeup 三板斧”
- A/B 实验矩阵：[04_phase3_experiments.md](04_phase3_experiments.md)

### C 桶：深 idle residency 很好，但功耗不降（或降幅异常小）

**判据**

- 深 idle `time` 占比高且平均驻留满足 `residency`
- 外部功耗仪显示功耗仍高或降幅不符合预期

**典型根因**

- 电源域未真关（逻辑状态进入但 rail 漏电/域常开）
- devfreq/互连/DDR 没降档（系统级功耗仍高）
- 外设常开（时钟/regulator 未关、频繁 DMA/轮询）
- 测量链路/场景噪声（USB 偷电、量程切换、温度漂移）

**下一步入口**

- 先做“交叉验证”：genpd summary、devfreq snapshot、硬件电流形态对齐
- 定位路径：[03_phase2_localize.md](03_phase2_localize.md)

### D 桶：功耗没降且体验抖动变大（或延迟变差）

**判据**

- 功耗未达标，同时出现：音频/触控/网络/动画的卡顿或 P99 延迟上升
- trace 显示：从较深 idle 退出后频率/负载跟随出现振荡或过冲

**典型根因**

- 深 idle 导致调度器看到的 util 更 bursty，cpufreq（如 schedutil）跟随行为变化
- 频繁进出深 idle 叠加 DVFS 延迟，形成“双重惩罚”

**下一步入口**

- 必须联动分析：idle 进出 + cpu_frequency + sched_wakeup/switch（抖动集）
- 进入实验矩阵做“禁深睡/限频/限 util”对照：[04_phase3_experiments.md](04_phase3_experiments.md)

## 3. 统一结论句式（避免口水战）

每个桶的结论都必须写成：

- 直接原因：X（证据：文件路径/trace 时间段/计数器差分）
- 根因：Y（证据：交叉验证 + 复现方式）
- 为什么现在才发生：Z（版本差异/配置差异/场景差异）
- 下一步动作：A/B/C（责任人 + 验收指标）
