# 2013：Coupled cpuidle 中 poke 与 safe state 的竞态（丢唤醒）

## 1. 提交基础信息

- **Commit ID**：`9e19b73c30a5fa42a53583a1f7817dd857126156`
- **标题**：`cpuidle: coupled: fix race condition between pokes and safe state`
- **作者**：Colin Cross（Google）；报告来自 Marvell 等 coupled 平台实践
- **涉及子系统**：`drivers/cpuidle/coupled.c`
- **关键词**：coupled idle、poke、lost wakeup、`local_irq_disable`

## 2. 背景信息

- **Coupled cpuidle**：多核需要 **协同**进入/退出更深的共享空闲状态；一核可能向另一核发 **poke** 以打破等待。
- **Safe state**：在复杂握手过程中，CPU 可能先进入一个 **安全的浅 idle**，以保证可中断/可同步。
- **丢唤醒的经典模式**：等待方在检查条件与清除事件标志之间存在窗口，若通知恰落在窗口内，则 **通知被吃掉**，等待方永远等不到。

**为何极其危险**：一核可能在 **关中断** 的 busy-wait 中自旋，另一核已进入 deep idle；若无外部中断路由，系统可表现为 **整体挂死**。

## 3. 故障现象

- 在启用 **coupled cpuidle** 的 ARM SoC 上，极低概率或特定负载下 **系统挂死** 或 **某 CPU 不再前进**。
- 与 **多核同时 idle**、**IPI/poke** 时序强相关；加打印可能改变时序（海森堡特征）。

## 4. 复现手法

1. 内核配置启用 **coupled cpuidle** 相关驱动与硬件平台（历史上 Marvell 等案例）。
2. 多线程负载 + 频繁 idle 切换（如 `hackbench`、`stress-ng`）长时间压测。
3. 降低日志、关闭部分调试以保留竞态窗口（否则可能被 printk 隐式屏障“治好”）。

## 5. 调试方法

- **静态分析 `while` 循环**：检查 **条件判断 → 清除 poke → 进入 safe state** 是否可被 poke 插入。
- **审查 `cpuidle_coupled_clear_pokes()` 返回值语义**：若把“是否需重调度”和“是否清除了 poke”混为一谈，极易掩盖丢唤醒。
- **硬件跟踪/_JTAG**（极端情况）：一核停在关中断循环、另一核 deep C-state。

## 6. 解决办法

- 重新定义 **clear_pokes** 的语义：**返回是否实际清除了 pending poke**；`need_resched()` 由调用方单独处理。
- 在等待循环中：若本轮清除了 poke，**`continue` 重新评估 while 条件**，避免在 **条件已假** 的情况下仍进入错误状态。

**修复原理**：保证 **poke 的清除与条件检查**之间的原子性（逻辑上），使 **通知绝不会在“已决定前进”与“进入安全状态”之间静默丢失**。

## 7. 经验总结

- **多核 idle 握手**是内核里最微妙的时序之一：**标志位语义、关中断区间、IPI 送达**必须三位一体设计。
- 对 **“清除事件 + 检查条件”** 的代码，默认假设存在并发插入，用 **重试循环** 或 **单一顺序点** 收口。
