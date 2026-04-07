# Case: menu governor 在 PM QoS 约束下导致 tick 常开（功耗浪费）

## 技术背景

`cpuidle` 的 `menu` governor 会在每次进入 idle 前预测可睡时长并选择 C-state，同时通过 `stop_tick` 建议是否停止 scheduler tick（NOHZ idle）。

- `stop_tick` 由 `menu_select()` 回传给 idle loop，最终在 `cpuidle_idle_call()` 里决定走 `tick_nohz_idle_stop_tick()` 还是 `tick_nohz_idle_retain_tick()`。
- PM QoS latency constraint（例如用户态打开 `/dev/cpu_dma_latency` 或框架层交互 hint）会限制可选 state 的 `exit_latency`。

相关代码：
- `menu_select()`：[menu.c](file:///home/alex/linux-stable/drivers/cpuidle/governors/menu.c#L213-L377)
- stop/retain tick 的决策点：[idle.c](file:///home/alex/linux-stable/kernel/sched/idle.c#L218-L229)

## 触发条件

- 某 CPU 长时间空闲（可睡超过一个 tick 周期），但该 CPU 上存在 PM QoS latency constraint。
- `menu` 因 latency constraint 只能选择浅态（target_residency 落在 tick 边界附近）。

## 现象描述

- 即使 CPU 长时间空闲，tick 仍然周期性触发（NOHZ 没有生效）。
- 表现为：
  - 低功耗场景（息屏/静置）功耗明显偏高。
  - `wakeup_sources`/`/proc/interrupts` 中 timer 相关计数持续增长。
  - trace 中 `tick_stop success=0` 或者根本不尝试 stop tick。

## 调试手段

- 证据包：使用 `scripts/power/collect_idle_baseline.sh` 抓取 `cpuidle`/`interrupts`/`wakeup_sources` 与 trace。
- 观测 tick stop：tracefs 中打开 `timer:tick_stop` 事件并查看 `success` 与 `dependency`。
- 观测 QoS：
  - 用户态：是否有进程持有 `/dev/cpu_dma_latency`。
  - 内核态：定位 `cpu_latency_qos_*` 的请求来源。

## 分析思路

1. 先证明“CPU 其实很闲”：`cpuidle` 深态驻留少但 `wakeup_sources` 并不高，timer 中断却很多。
2. 再证明“被 QoS 限制”：所选 state 的 `exit_latency` 被 latency_req 卡住，导致选择浅态。
3. 最后证明“tick 常开是浪费而非必须”：当预测 idle 明显超过 tick 周期时，保持 tick 常开只会制造额外唤醒。

## 修复要点（历史修复）

commit `32b91ca15353`（"cpuidle: menu: Allow tick to be stopped if PM QoS is used"）修复了该类浪费：

- 在存在 PM QoS 约束时，允许在预测 idle 超过 tick 边界时停止 tick。
- 避免 “QoS + 长 idle” 场景下 tick 永久常开。

## 参考与定位

- 修复 commit：`32b91ca15353`
- 关键逻辑位置：`menu_select()` 中与 `stop_tick`/`predicted_ns < TICK_NSEC` 相关分支
