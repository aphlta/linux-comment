# Case: menu 在放弃高置信预测时丢弃了仍然有用的信息（过度依赖 next timer）

## 技术背景

`get_typical_interval()` 在无法形成高置信预测时，历史上会直接返回 `UINT_MAX`，意味着下一次 `menu_select()` 几乎完全依赖 `next_timer_ns`（“只信 timer，不信历史样本”）。

但即使无法形成“精确预测”，最近样本仍可能提供一个重要信息：**上界**（最近观察到的最大 idle 间隔）。

## 触发条件

- 样本中存在离群点导致置信度不足，但在剔除离群点后仍保留了足够数量的样本。
- 继续返回 `UINT_MAX` 会让预测退化为纯 timer，导致策略更抖。

## 现象描述

- `menu` 对“最近历史上限”失明：在一些场景下会选得过深或过浅，抖动加重。
- 预测收敛变慢：大量场景看起来像“只靠 next timer”，对重复模式不敏感。

## 调试手段

- 对照 `predicted_ns` 与 `next_timer_ns`：如果长期几乎相等，说明退化为“只信 timer”。
- 若能导出 intervals，检查剔除离群点后样本数量是否仍然足够（例如 >= 50%）。

## 分析思路

1. 识别“放弃预测”路径：`get_typical_interval()` 返回 sentinel。
2. 证明仍有价值的信息：剔除离群点后样本量足够大，且最大值可作为上界。
3. 修复方向：在样本量足够时返回最大值而非 `UINT_MAX`，避免信息完全丢失。

## 修复要点（历史修复）

commit `85975daeaa4d`（"cpuidle: menu: Avoid discarding useful information"）在剔除离群点后若样本量仍足够（例如 >= 50%），返回当前最大 recent interval 作为上界，而不是直接返回 `UINT_MAX`。

## 参考与定位

- 修复 commit：`85975daeaa4d`
