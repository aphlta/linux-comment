# Case: menu 在短 idle 场景下频繁调用 tick_nohz_get_sleep_length 带来开销

## 技术背景

`tick_nohz_get_sleep_length()` 会执行一系列 NOHZ 判定与 next event 计算。随着 NOHZ 功能复杂化（依赖项/边界条件增加），该调用的成本可能上升。

如果在“短 idle 高频出现”的场景（刷网页、动画帧间隙）每次都调用，会造成 idle entry 开销偏大，影响能效与抖动。

相关代码：
- `menu_select()` 里调用 `tick_nohz_get_sleep_length()`：[menu.c](file:///home/alex/linux-stable/drivers/cpuidle/governors/menu.c#L227-L248)

## 触发条件

- 负载导致大量短 idle（预测值本就很小）。
- 系统 NOHZ 判定路径较重（平台/配置差异）。

## 现象描述

- perf 里看到 `tick_nohz_get_sleep_length()` 或其下游成为热点。
- 交互场景下 idle 入口更贵，造成微抖或能耗上升。

## 调试手段

- `perf record`/`perf top` 观察 `menu_select()` 与 NOHZ 路径的 CPU 占比。
- ftrace function_graph（若可用）观测一次 idle entry 的调用栈耗时。

## 分析思路

1. 把场景分成两类：短 idle 高频 vs 长 idle 低频。
2. 对短 idle 高频场景，优先靠统计预测（`get_typical_interval()`）即可，不必每次计算 next timer。
3. 仅在预测值足够大（潜在能睡很久）时，再调用 NOHZ 进一步精炼。

## 修复要点（历史优化）

commit `5484e31bbbff`（"cpuidle: menu: Skip tick_nohz_get_sleep_length() call in some cases"）重排了 `menu_select()`：

- 先用历史统计估算 `predicted_ns`。
- 只有当 `predicted_ns > RESIDENCY_THRESHOLD_NS` 时才调用 `tick_nohz_get_sleep_length()` 来 refine。

## 参考与定位

- 相关 commit：`5484e31bbbff`
