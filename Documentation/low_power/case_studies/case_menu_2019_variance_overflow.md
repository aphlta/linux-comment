# Case: menu governor 在方差计算中溢出（预测置信度崩坏）

## 技术背景

`menu` governor 的 `get_typical_interval()` 会对最近 idle 间隔样本做平均/方差/离群点处理，以判断是否存在可重复模式，并给出更“像人类直觉”的预测。

如果方差计算溢出，离群点判定与“是否有高置信预测”的逻辑会崩坏，导致预测失真。

相关代码：
- `get_typical_interval()`：[menu.c](file:///home/alex/linux-stable/drivers/cpuidle/governors/menu.c)

## 触发条件

- 样本集中出现极大间隔（例如某些长时间停顿或时间源异常），导致 `diff * diff` 超过 `int64_t` 能表达的范围。

## 现象描述

- 预测出现极端值：
  - 误判成超长 idle，导致选深态后立刻被打断（jank/latency 上升）。
  - 或误判为无置信预测，退化为只信 timer，造成策略抖动。

## 调试手段

- trace：观察 `cpu_idle` 进入/退出与真实驻留时间与预测是否严重不匹配。
- 样本观测：在 debug 版本里打印/导出最近 intervals，检查是否出现异常大值。

## 分析思路

1. 把问题限定为“统计计算异常”而非 timer 输入：比较 `get_typical_interval()` 输出与 `next_timer_ns`。
2. 检查是否存在单点异常巨大样本，使方差计算溢出并污染阈值更新。
3. 修复策略通常是：限制输入阈值、在不影响选态的前提下丢弃过远的样本。

## 修复要点（历史修复）

commit `814b8797f986`（"cpuidle: menu: Avoid overflows when computing variance"）通过调整阈值与离群点丢弃策略，避免 `diff^2` 溢出导致的预测崩坏。

## 参考与定位

- 修复 commit：`814b8797f986`
