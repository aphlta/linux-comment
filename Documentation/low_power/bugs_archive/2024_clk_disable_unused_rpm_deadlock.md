# 2024：`clk_disable_unused()` 持 `prepare_lock` 调用 runtime resume 与 deferred probe 死锁

## 1. 提交基础信息

- **Commit ID**：`e581cf5d216289ef292d1a4036d53ce90e122469`
- **标题**：`clk: Get runtime PM before walking tree during disable_unused`
- **作者**：Stephen Boyd（Google）；问题由 Doug Anderson 等推动
- **涉及子系统**：Common Clock Framework（CCF）、**`prepare_lock`**、runtime PM、Qualcomm 显示（MDSS）等
- **关键词**：`clk_disable_unused`、`deferred_probe`、`clk_pm_runtime_get`

## 2. 背景信息

- **CCF** 为协调 `clk_prepare/unprepare` 使用全局 **`prepare_lock`**。
- **带 runtime PM 的 clock provider** 在 **遍历/操作时钟树**时可能需要 **`rpm_resume`** 以访问硬件。
- **启动早期 initcall** `clk_disable_unused()` 若 **先持 `prepare_lock`** 再 **rpm_resume**，可能与 **deferred probe work** 路径 **颠倒锁序**：probe 侧 **`rpm_resume` 已进行** 又需 **`clk_prepare()` → 拿 `prepare_lock`** → 互等。

**为何在 sc7180 Chromebook 易显式化**：显示栈 deferred probe 与 clock disable_unused 时序耦合紧，hung task 超时可观测。

## 3. 故障现象

- **启动阶段 hung task**（如 120s），**PID 1** 卡在 `clk_disable_unused`，**kworker** 卡在显示驱动 `runtime_resume` → `clk_prepare`。
- 系统 **长时间无法完成启动** 或 **极慢**。

## 4. 复现手法

1. Qualcomm sc7180（或类似）平台 + 对应内核版本窗口。
2. 冷启动多次；若有时序敏感，可通过 **延迟存储子系统** 或 **调整 initcall 顺序**（仅调试）放大窗口。
3. 观察 **hung task** 两个栈是否呈 **ABBA**。

## 5. 调试方法

- **hung task 报告**对比两线程栈：一方 **`clk_prepare_lock`**，另一方 **`rpm_resume`**。
- **理解补丁结构**：先 **`clk_pm_runtime_get_all()`**（**不持 prepare_lock**）把相关 provider **唤醒**，再持锁遍历。

## 6. 解决办法

- 维护全局 **`clk_rpm_list`**（受 **`clk_rpm_list_lock`** 保护），记录需 runtime PM 的 clock。
- **`clk_disable_unused()`**：
  1. **无 prepare_lock** 下 **`clk_pm_runtime_get_all()`** 全部 get；
  2. **`clk_prepare_lock()`** 安全遍历 disable；
  3. 解锁后 **`clk_pm_runtime_put_all()`**。

**修复原理**：避免在 **不可睡眠/全局锁** 内进入 **可能 schedule 的 runtime PM**；先把 PM 侧带到 **一致 active**，再操作时钟树。

## 7. 经验总结

- **initcall 级别全局锁 + 设备模型 runtime PM** 极易 ABBA：**全局遍历**与 **per-device 状态机**要分层。
- **“先 rpm 再持全局锁”** 是 CCF 与 PM 结合后的常见范式。
