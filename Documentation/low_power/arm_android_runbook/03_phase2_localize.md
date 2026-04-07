# 03 - Phase 2：定位归因（Android → 内核 → 硬件时间轴）

Phase 2 的目标是把问题收敛为“可证据化的根因”，并明确下一步该做哪个 A/B 实验验证。

本章推荐顺序固定为：Android 框架侧 → 内核侧计数器 → trace 时间线 → 硬件电流形态对齐。

## 2.1 Android 侧：先找“系统为什么不睡/为什么总醒”

### dumpsys power（睡眠状态与 wakelock 线索）

关注点：

- 当前是否进入合适的 idle/Doze 状态（不同 Android 版本字段不同，以关键状态是否稳定为准）
- 是否存在持续持锁的 wakelock（尤其是 PARTIAL_WAKE_LOCK 类）
- 场景 A/B 的对比：before/after 是否一致地反映“更易睡/更少醒”

建议把 dumpsys 输出作为证据链的一部分，和内核 wakeup/trace 对齐。

脚本采集：使用 [collect_idle_baseline.sh](../../../scripts/power/collect_idle_baseline.sh) 的 `--android` 模式。

### dumpsys batterystats（谁在贡献唤醒）

关注点：

- 唤醒来源的排序是否稳定（Top 3）
- 是否有 alarm/job 过密导致周期性唤醒

输出同样要放进报告包，避免“口头判断”。

## 2.2 内核侧：wakeup 三板斧（最快锁定 Top offender）

### (1) wakeup_sources（如果存在）

路径：`/sys/kernel/debug/wakeup_sources`

常用判读：

- event count 明显增长的 source 优先可疑
- active_time/total_time 异常高，说明它经常保持活跃

注意：不同平台/版本字段不完全一致，但“谁的计数增长最快”是稳定判据。

### (2) /proc/interrupts before/after 差分

差分思路：

- 计算每个 IRQ 在采集窗口内的增量
- Top 1/Top 3 基本能锁定“是谁把 CPU 叫醒”

典型映射：

- WLAN/BT：网络扫描、keepalive、RX/TX burst
- GPIO：抖动、浮空、触发类型错误
- timer：周期性任务/系统心跳

### (3) cpuidle residency（判断“睡不深”还是“睡得碎”）

路径：`/sys/devices/system/cpu/cpu*/cpuidle/state*/`

关键计算：

- 深 idle residency（%）：用 `time` 的 before/after 差分得到占比
- 平均驻留：`avg_residency = delta_time / delta_usage`
  - 若明显小于该 state 的 `residency`（目标驻留），典型是“睡得碎”（桶 B）

参考：cpuidle sysfs 字段说明见 [cpuidle.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/cpuidle.rst)

## 2.3 trace 时间线：把“谁叫醒 → 醒后发生了什么”串起来

### 事件集合选择

不要一开始就全开事件。按问题桶选择事件集：

- 最小集（基线/唤醒归因）：`power` + `irq` + `timer`
- 抖动/体验集（桶 D 必开）：在最小集基础上加 `sched`（wakeup/switch）

建议统一引用事件集合文档：[trace_event_sets.md](tools/trace_event_sets.md)

### 判读套路（固定问题句式）

用时间线回答三句话：

1. CPU 从哪个 idle state 退出？退出频率多不多？
2. 是哪个 IRQ/timer 触发的唤醒？是否集中在少数来源？
3. 唤醒后 CPU 频率如何变化？是否存在频率振荡/过冲？任务是否在短窗口内集中运行？

典型模式与含义：

- “频繁从深 state 退出，马上又回去”：深睡被切碎，优先治理 wakeup（桶 B）
- “退出深 state 后频率迅速拉满并来回抖”：cpuidle×cpufreq×调度联动问题（桶 D）

## 2.4 硬件电流形态对齐：验证“真的省电了吗”

当出现以下现象，必须把功耗仪波形/平均功耗拉进证据链：

- residency 很好但功耗不降（桶 C）
- 某次优化让 wakeup 降了，但功耗没变化（可能是 rail/互连/外设仍高）

推荐做法：

- 用功耗仪导出 I-t 曲线（CSV）并记录采样参数（见模板）
- 用固定触发点对齐软件事件（UART 时间戳、已知工作负载边界）

参考：对齐方法见 [08_soc_lp_lab_instruments_debug_zh.md](../tech_evolution/08_soc_lp_lab_instruments_debug_zh.md)

## 2.5 本阶段输出（写进 report.md 的证据清单）

- Top 3 wakeup 贡献者（给出 interrupts delta + wakeup_sources + trace 三者证据）
- 深 idle residency 与平均驻留（至少最深 state）
- 若涉及体验抖动：给出 “idle exit → cpu_frequency → sched_wakeup/switch” 的关键时间片段解释
- 下一步要做的 A/B 实验选择（链接到 Phase 3）
