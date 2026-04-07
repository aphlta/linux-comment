# Case: next timer 非常近时 menu 的无谓计算与副作用

## 技术背景

当 next timer 比第二个 idle state（state[1]）的 `target_residency` 更近，或者 PM QoS latency 比 state[1] 的 `exit_latency` 更小，则无论如何都只能选 state[0]。

如果此时仍进行完整预测与选态计算，不但浪费 CPU 时间，还可能更新错误的 bucket/correction factor（污染下一轮）。

相关代码：
- 早返回条件：`data->next_timer_ns < drv->states[1].target_residency_ns` 或 `latency_req < drv->states[1].exit_latency_ns`：[menu.c](file:///home/alex/linux-stable/drivers/cpuidle/governors/menu.c#L261-L272)

## 触发条件

- 工作负载带来极短定时器（例如高频 hrtimer、周期任务）。
- 或交互场景下 QoS latency 被压得极小。

## 现象描述

- CPU idle 路径额外开销增加（尤其在高频短 idle 的场景里）。
- 预测统计被短周期噪声污染，导致后续选态更抖。

## 调试手段

- perf/ftrace：观察 idle 入口开销（`menu_select()` 热点）、短 idle 频率。
- 计时对比：在打开/关闭相关补丁或参数下对比 idle entry/exit 的成本。

## 分析思路

1. 先判断是否处于“无条件只能选 state0”的窗口：next timer 极近或 latency_req 极小。
2. 若是，则进一步确认 `menu_select()` 是否还在做大量计算（不该做）。
3. 修复方向：在 bucket 合法更新后尽早返回，避免污染与浪费。

## 修复要点（历史修复）

commit `8b007ebec9a5`（"cpuidle: menu: Avoid computations for very close timers"）引入了“在确定 bucket 后早返回 state0”策略，避免无谓计算与副作用。

## 参考与定位

- 修复 commit：`8b007ebec9a5`
