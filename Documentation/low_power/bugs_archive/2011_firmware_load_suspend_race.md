# 2011：固件加载与 usermodehelper 禁用之间的 TOCTOU 竞态

## 1. 提交基础信息

- **Commit ID**：`b298d289c79211508f11cb50749b0d1d54eb244a`
- **标题**：`PM / Sleep: Fix freezer failures due to racy usermodehelper_is_disabled()`
- **作者**：Srivatsa S. Bhat
- **涉及子系统**：`kernel/kmod.c`、`drivers/base/firmware_class.c`、PM sleep
- **关键词**：`usermodehelper`、`firmware`、TOCTOU、task freezer

## 2. 背景信息

- **固件加载**常通过 **usermodehelper**（如 `/sbin/firmware_helper` 或等价机制）在用户空间完成；内核侧会等待该路径结束。
- **Suspend 准备阶段**会 **禁用 usermodehelper** 并冻结任务，避免睡眠过程中再派生用户进程。
- **TOCTOU（检查与使用的时间窗）**：若线程 A 在检查“helper 未禁用”之后、真正发起固件请求之前，线程 B 完成了 suspend 准备并禁用 helper + 冻结用户空间，则 A 可能**永远等待一个永远不会完成的用户空间响应**。

**为何与低功耗强相关**：失败表现为 **“Freezing of tasks failed”** 或 suspend 间歇失败，直接阻断系统进入低功耗状态。

## 3. 故障现象

- x86（及其他使用固件加载框架的平台）上 **suspend/hibernate 间歇性失败**。
- 日志中可见与 **任务冻结超时**、固件请求卡住相关的线索；微码/固件重载场景更易触发。

## 4. 复现手法

1. 使用会在运行期触发 **firmware reload/request** 的驱动（如某些 x86 微码路径、或热插拔后重 init 的设备）。
2. 与 **手动或自动 suspend** 并发压测（脚本循环 `suspend` + 设备 reset）。
3. 多 CPU 下更容易放大窗口：**一条 CPU 在做固件路径，另一条在做 suspend 准备**。

## 5. 调试方法

- **冻结失败时**查看最后未冻结的任务栈：是否卡在 `request_firmware*` 等待路径。
- **对照 mail list / commit message**：该问题在社区讨论中常被归结为 `usermodehelper_disabled` 缺乏同步。
- **stress**：`while true; do echo mem > /sys/power/state; done` 与固件触发脚本并行。

## 6. 解决办法

- 引入 **读写信号量（或等价同步）** 保护 `usermodehelper` 的禁用/启用与固件加载路径：
  - **suspend 侧**在禁用时走 **写锁**（独占）。
  - **固件加载侧**在发起可能依赖用户空间的路径时持 **读锁**，保证与禁用操作互斥。

**修复原理**：消除“检查后、使用前”窗口，使 **“是否允许走 usermodehelper”** 与 **“真正发起请求”** 成为原子语义上的同一段临界区。

## 7. 经验总结

- **PM 准备阶段的全局开关**（`usermodehelper`、内存压缩、cgroup freeze）必须与所有异步入口 **用统一规则串行化**。
- 看到 **freezer 超时**，不要只查用户进程，也要查 **内核线程是否在等用户空间**。
