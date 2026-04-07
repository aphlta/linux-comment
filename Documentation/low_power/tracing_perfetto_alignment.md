# Tracing → Perfetto 对齐指南（最小事件集）

目标：把“内核侧功耗证据”与“用户态体验/场景时间轴”对齐，便于 A/B 解释与复盘。

## 1. 最小事件集（可先跑起来）

- `power`：cpuidle/cpufreq/suspend 相关事件
- `irq`：中断唤醒相关
- `timer`：定时器唤醒相关

Runbook 建议事件集见：
- [arm_android_runbook/tools/trace_event_sets.md](arm_android_runbook/tools/trace_event_sets.md)

## 2. 采集方式建议

### 2.1 内核侧（trace-cmd / ftrace）

- 统一入口：[`scripts/power/collect_idle_baseline.sh`](../../scripts/power/collect_idle_baseline.sh)
- 输出：`power_trace.dat` 或 `ftrace_raw.txt`

### 2.2 Android 用户态（Perfetto）

- 目标：把用户态场景开始/结束点、关键服务状态，与内核 trace 同时段对齐
- 建议：固定一个“场景标记”方式（例如 log marker / sysfs 打点），便于 cross-correlation

## 3. 时间轴对齐方法（工程化）

推荐优先级：

1. 同时采集同一时钟源的 marker（最稳）
2. 用“明显事件”对齐（屏幕 on/off、充电插拔、wifi 开关）
3. 用统计特征对齐（不推荐，误差大）

## 4. 输出物模板

- perfetto trace（用户态）
- power trace（内核态）
- 证据包目录名与场景标签：见 [evidence_package_spec.md](evidence_package_spec.md)
- 结论表：A/B 对比项、差异解释、回归策略
