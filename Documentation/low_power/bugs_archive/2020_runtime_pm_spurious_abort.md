# 2020：共享 ACPI 电源资源下误把 runtime resume 当 wakeup，导致 suspend 中止

## 1. 提交基础信息

- **Commit ID**：`e3eb6e8fba65094328b8dca635d00de74ba75b45`
- **标题**：`PM: sleep: core: Fix the handling of pending runtime resume requests`
- **作者**：Rafael J. Wysocki（报告来自 Intel 的 Utkarsh H Patel）
- **涉及子系统**：`drivers/base/power/main.c`（system suspend 核心）
- **关键词**：`pm_runtime_barrier`、`pm_wakeup_event`、ACPI power resource

## 2. 背景信息

- **多个设备可共享同一 ACPI power resource**：一设备 **runtime resume** 可能 **级联** 使同资源上的其他设备出现 **pending runtime resume**。
- **`pm_runtime_barrier()`** 用于在 system suspend 前 **排空 runtime PM 队列**，本身 **不蕴含**“发生了用户可见唤醒事件”。
- 旧逻辑若写为：**barrier 返回真且 `device_may_wakeup`** → **`pm_wakeup_event()`**，会把 **纯粹的电源依赖链抖动** 误判为 **唤醒**，从而 **中止 suspend**。

**为何难查**：现象是 **“没碰键盘却睡不下去/马上醒”**，极易误判为 **用户空间守护进程** 或 **USB 设备**。

## 3. 故障现象

- **Suspend 随机失败** 或 **刚睡即醒**；dmesg 可能出现 **wakeup 计数增加** 而无真实物理唤醒源。
- 多出现在 **Intel 平台、多设备共享 ACPI 资源** 的配置上。

## 4. 复现手法

1. 找出共享 **ACPI power resource** 的设备组（ACPI sysfs / `lspci -vv`）。
2. 在 suspend 前制造 **其一设备的 runtime 活动**（如短暂 IO）。
3. 循环 `systemctl suspend` 或 `echo mem > /sys/power/state`，统计失败率。

## 5. 调试方法

- **`/sys/kernel/debug/wakeup_sources`** 与 **dmesg `PM:`** 行对照：谁是 **last wakeup**。
- **开启 `pm_debug_messages`**，观察是否在 **无物理中断** 时仍记录 wakeup。
- **代码审阅 `__device_suspend()`**：定位 `pm_runtime_barrier` 与 `pm_wakeup_event` 的组合。

## 6. 解决办法

- **删除**错误的：
  - `if (pm_runtime_barrier(dev) && device_may_wakeup(dev)) pm_wakeup_event(dev, 0);`
- **保留**：
  - `pm_runtime_barrier(dev);` **仅同步**，不推断唤醒。

**修复原理**：**“pending runtime resume”** 只说明 **电源引用/异步请求** 状态，不是 **唤醒语义**；二者必须在模型上分离。

## 7. 经验总结

- **System PM 与 Runtime PM 的语义叠加**时，避免 **用 A 的副作用推导 B 的事件**。
- 排 **假唤醒** 时先问：**是 IRQ？还是 runtime 级联？**
