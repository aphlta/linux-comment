# Trace 事件集合（ARM + Android）

本文件用于统一团队在不同问题类型下应采集哪些 trace 事件，避免“要么不够、要么全开炸数据”。默认工具为 trace-cmd；缺失时退化到 raw ftrace。

参考机制文档：

- ftrace 总览：[ftrace.rst](file:///home/alex/linux-stable/Documentation/trace/ftrace.rst)
- power 事件：[events-power.rst](file:///home/alex/linux-stable/Documentation/trace/events-power.rst)

## 集合 S0：最小集（基线/唤醒归因）

适用：

- Phase 0 基线采集
- 桶 A/B 的初步归因（睡不深/睡得碎）

事件组：

- `power`（包含 cpu_idle、cpu_frequency 等 power 相关事件）
- `irq`
- `timer`

对应脚本默认行为：

- [collect_idle_baseline.sh](../../../../scripts/power/collect_idle_baseline.sh) 默认 `trace-cmd record -e power -e irq -e timer`

## 集合 S1：抖动/体验集（桶 D 必开）

适用：

- “功耗没降 + 抖动变大/延迟变差”
- 需要解释 cpuidle×cpufreq×调度联动时

事件组：

- S0 全部
- `sched`（至少需要 wakeup/switch，用于看唤醒链与运行窗口）

判读目标：

- 从某个 idle state 退出的瞬间，是否出现频率过冲/振荡
- 唤醒链是否集中爆发（util 更 bursty）

## 集合 S2：深挖集（定位设备侧/PM 流程时使用）

适用：

- 桶 C：residency 好但功耗不降（怀疑电源域/设备 PM 路径）
- 某设备 runtime PM 行为异常（频繁 suspend/resume）

事件组（按需选择，不建议无脑全开）：

- S0 或 S1
- 设备 PM 回调相关事件（若平台/内核启用）
- 相关子系统事件（例如 regulator/clk/devfreq 相关 tracepoints，取决于内核配置）

## 数据量与采集窗口建议

- 基线：10 分钟窗口通常足够；若 wakeup 稀疏可适当延长
- 抖动：可缩短窗口但要覆盖“用户感知卡顿”的周期事件
- 深挖：优先缩短窗口并只开必要事件，避免影响系统行为
