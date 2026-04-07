# Case: menu 的离群点只剔除高端导致方差无法收敛（预测退化）

## 技术背景

`get_typical_interval()` 为了提高预测置信度，需要剔除离群点（outliers）并降低样本方差。

如果只剔除高端离群点（大值），但离群点实际出现在低端（小值），则方差仍然很大，算法会频繁判定“无法高置信预测”，导致预测退化。

## 触发条件

- 负载模式中混入大量极短 idle（例如 bursty wakeup），且它们在样本里成为低端离群点。
- 仅剔除高端无法降低方差。

## 现象描述

- `get_typical_interval()` 经常放弃预测，导致 `menu_select()` 主要依赖 `next_timer_ns`。
- 行为表现为：选态更“抖”，对历史重复模式不敏感。

## 调试手段

- 对照 `predicted_ns` 来源：比较 `get_typical_interval()` 输出与 `next_timer_ns` 在一段时间内的波动。
- 若有条件，导出 intervals 样本并观察离群点分布（高端/低端）。

## 分析思路

1. 先确认“预测退化”来自离群点处理：样本方差无法收敛导致返回 sentinel。
2. 检查离群点位置：是否集中在低端。
3. 修复方向：同时考虑两端离群点，按距离平均值的大小剔除。

## 修复要点（历史修复）

commit `8de7606f0fe2`（"cpuidle: menu: Eliminate outliers on both ends of the sample set"）将离群点剔除改为“两端一起处理”，提升形成有效预测的概率。

## 参考与定位

- 修复 commit：`8de7606f0fe2`
