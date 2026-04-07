# Case: menu governor 遇到负的 sleep length（时间计算边界）

## 技术背景

`menu_select()` 通过 `tick_nohz_get_sleep_length(&delta_tick)` 获取“距离最近 timer 的时间”，用于生成 `data->next_timer_ns` 并进一步修正 `predicted_ns`。

相关代码：
- `tick_nohz_get_sleep_length()`：[tick-sched.c](file:///home/alex/linux-stable/kernel/time/tick-sched.c#L1328-L1371)
- `menu_select()` 调用点：[menu.c](file:///home/alex/linux-stable/drivers/cpuidle/governors/menu.c#L227-L248)

## 触发条件

- 在某些时间源边界/极端竞态下，NOHZ 提供的“可睡时长”出现负值（例如 next event 已过期、时间基准切换/校正导致差值为负）。
- 预测路径没有对负值做防御时，会把 `predicted_ns`、bucket/correction 的输入污染。

## 现象描述

- 选态异常：频繁选到不合理的 state（过浅或过深），并伴随功耗/延迟异常。
- 统计异常：`menu` 的 correction factor/bucket 更新被污染，后续预测持续抖动。

## 调试手段

- trace：抓 `power:cpu_idle`、timer 事件，并对照 `next_hrtimer`/next event 的时间序列。
- 日志/断言：观察是否出现 "sleep length" 相关的异常值（有的版本会有 debug 输出）。
- 对照验证：禁用 NOHZ（或强制 retain tick）观察现象是否消失。

## 分析思路

1. 先确认异常来自“输入为负”：在出现抖动的窗口里对照 `tick_nohz_get_sleep_length()` 相关值。
2. 再确认影响链路：负值进入 `data->next_timer_ns` 后影响 bucket 与 correction factor，从而影响选态。
3. 最后做防御：负值归零或走保守分支。

## 修复要点（历史修复）

commit `060e3535adf5`（"cpuidle: menu: Take negative \"sleep length\" values into account"）增加了防御：

- 检查 `tick_nohz_get_sleep_length()` 返回值，若为负则将 `delta/delta_tick` 置 0。
- 在 tick 已停场景下更直接使用已知 next timer 值，避免出现负差。

## 参考与定位

- 修复 commit：`060e3535adf5`
