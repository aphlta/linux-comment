# 2010：MMC/SD 在 suspend/resume 期间插拔导致系统挂死

## 1. 提交基础信息

- **Commit ID**：`4c2ef25fe0b847d2ae818f74758ddb0be1c27d8e`
- **标题**：`mmc: fix all hangs related to mmc/sd card insert/removal during suspend/resume`
- **作者**：Maxim Levitsky
- **涉及子系统**：`drivers/mmc/core`（MMC 核心）、PM sleep 路径
- **关键词**：`del_gendisk`、`mmc_suspend_host`、进程冻结（freezer）、PM notifier

## 2. 背景信息

- **System suspend 的典型顺序**：在真正让硬件睡眠前，内核会冻结用户空间与大量内核线程，以保证文件系统与设备状态一致。
- **`del_gendisk()` 的隐含假设**：移除块设备节点时，可能触发与用户空间、块层、同步相关的路径；**若用户空间已被冻结**，这些路径可能永远无法完成。
- **未开启 `CONFIG_MMC_UNSAFE_RESUME` 时**：内核倾向于在 suspend 路径中更“激进”地处理卡移除，以规避 resume 后状态不一致——但这与 freezer 的时序发生冲突。

**为何这是低功耗相关故障**：问题只出现在**进入/退出系统睡眠**的路径上；根因是“睡眠流程中能否安全地做需要用户空间配合的操作”。

## 3. 故障现象

- 在 **suspend 或 resume 过程中**插入/拔出 MMC/SD 卡时，系统**完全挂死**（无响应、需硬重启）。
- 表现为块设备层或 MMC 子系统在移除磁盘时阻塞，与“任务已冻结”叠加后形成**单向等待**。

## 4. 复现手法

1. 使用未配置 `CONFIG_MMC_UNSAFE_RESUME` 的内核（或等价行为）。
2. 在笔记本/开发板上使能 MMC/SD 槽。
3. 触发 **suspend** 或 **resume** 的同时（或紧挨着的窗口内）**插拔**存储卡。
4. 复现率与时机相关：越靠近 freezer 生效窗口，越容易触发。

## 5. 调试方法

- **从症状反推**：若 hang 点落在 `mmc_suspend_host()` → `remove`/`del_gendisk` 一类路径，且同期有 freezer 日志，优先怀疑**睡眠阶段与用户空间依赖**冲突。
- **启用 PM 调试**：`pm_debug_messages`、`echo test > /sys/power/pm_test`（若平台支持）观察卡在哪一阶段。
- **锁与等待链**：用 `sysrq-w`（若可用）打印阻塞任务栈，确认是否在等待用户空间或块层完成某操作。

## 6. 解决办法

- **把“需要与用户空间/块层完整交互”的卡移除逻辑移出 suspend 回调**，改到 **PM notifier**（如 `PM_SUSPEND_PREPARE` / `PM_HIBERNATION_PREPARE`）阶段执行——此时用户空间**尚未被冻结**，`del_gendisk()` 等调用更安全。
- 在准备进入睡眠时设置 **`rescan_disable`**、**取消 detect work**，避免冻结期间工作队列仍在跑检测逻辑。

**修复原理**：保证“会阻塞在跨子系统/用户空间边界上的操作”发生在 **freezer 之前**，suspend 回调里只做与硬件电源状态直接相关的最小集。

## 7. 经验总结

- **凡是 suspend 路径里调用可能 sync、通知用户空间、或依赖 udev 的路径，都要重新审计**。
- **PM notifier 与 device suspend 回调的时序**是电源管理排障的高频考点：前者更早、后者更晚。
