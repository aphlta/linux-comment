# 2019：S2idle 控制流反复 noirq suspend/resume 导致深度省电失败

## 1. 提交基础信息

- **Commit ID**：`56b991849009f5def0443bfb2f48c8321d888e15`
- **标题**：`PM: sleep: Simplify suspend-to-idle control flow`
- **作者**：Rafael J. Wysocki（Intel）
- **涉及子系统**：`kernel/power/suspend.c`、ACPI s2idle、设备 IRQ 阶段
- **关键词**：`s2idle_loop`、`noirq`、`EC GPE`、`rearm_wake_irq`

## 2. 背景信息

- **S2idle（suspend-to-idle / S0ix）** 依赖 **平台固件 + ACPI + 设备低功耗状态** 协同；目标是 **浅睡但极省电**。
- 旧设计中，在 **已处于 suspended 逻辑** 时仍可能 **多次走 noirq suspend/resume**，使部分设备进入 **无法再次进入深度平台状态** 的中间态。
- **EC（嵌入式控制器）虚假唤醒** 若驱动完整 noirq resume 链，会 **反复抬升功耗平面**。

**为何用户感知强**：笔电“睡眠”后 **电池仍快速下降**，测温/功耗计显示 **未进入预期 Package C-state / S0ix residency**。

## 3. 故障现象

- **Modern Standby** 类机器睡眠 **功耗偏高**、**续航差**；部分平台 **几乎无法进入深度 S0ix**。
- 可能与 **EC 中断风暴** 或 **首轮 noirq 阶段即 wakeup** 相关。

## 4. 复现手法

1. Intel 笔记本，启用 **s2idle**（`/sys/power/mem_sleep` 含 `s2idle`）。
2. 闭合盖子或 `rtcwake` 定时唤醒，睡眠期间用 **功耗计**或 **Intel RAPL / sysfs residency** 统计。
3. 对比补丁前后：**平台 C-state 驻留**、**电池斜率**。

## 5. 调试方法

- **`/sys/kernel/debug/pmc_core`（若可用）**、**turbostat**、**powertop** 观察 **PCx/Cx**。
- **ACPI debug**：追踪 **SCI/GPE** 是否在睡眠环内被错误放大。
- **理解控制流**：阅读 `s2idle_loop()` 补丁，确认 **noirq 阶段是否单点进出**。

## 6. 解决办法

- **重构 `s2idle_loop()`**：
  - **noirq suspend** 在循环 **前** 执行 **一次**；**noirq resume** 在循环 **后** 执行 **一次**。
  - 循环内专注 **唤醒判定与平台 `->wake` 回调**（可直接 dispatch EC GPE），配合 **`rearm_wake_irq()`** 重装 ACPI SCI。
  - 删除不再需要的 **`acpi_s2idle_sync()`** 一类全局回调路径（见补丁说明）。

**修复原理**：避免 **在浅睡循环中反复扰动设备 IRQ 阶段状态机**；把 **“深度电源闸门”** 与 **“唤醒事件处理”** 解耦。

## 7. 经验总结

- **S0ix 排障要同时看：内核控制流、ACPI 表、EC 行为**；单看驱动往往不够。
- **“能唤醒”不等于“应用完整 resume 链”**——后者可能破坏下一轮的 **idle residency**。
