# 2015：系统睡眠期间 Thermal 子系统状态失配（风扇/温控异常）

## 1. 提交基础信息

- **Commit ID**：`ff140fea847e1c2002a220571ab106c2456ed252`
- **标题**：`Thermal: handle thermal zone device properly during system sleep`
- **作者**：Zhang Rui、Chen Yu（Intel）等
- **涉及子系统**：`drivers/thermal/thermal_core.c`、ACPI fan 平台驱动交互
- **关键词**：`thermal_zone_device_update`、`in_suspend`、PM notifier

## 2. 背景信息

- **Thermal 框架**周期性或在事件驱动下更新温区、调节 **cooling device**（风扇、CPU 限频等）。
- **Suspend/resume** 过程中，传感器读数、设备可达性、**ACPI 通用 PM domain** 对风扇的自动上电等，都会使“框架认为的状态”和“硬件真实状态”短暂不一致。
- 先前将风扇等设备挂到 **genpd** 后，resume 可能出现 **硬件已转、thermal 核心不知情** 的错位（与相关 ACPI 变更回归相关）。

**为何属于低功耗/电源故障**：用户从睡眠唤醒后感知为 **风扇狂转/不转、噪声异常、过热风险**，本质是 **电源状态迁移后的策略未重建**。

## 3. 故障现象

- **Resume 后**风扇 **持续高速** 或 **长期不转**；温控策略与温度读数 **脱节**。
- 关联社区 bug 讨论（如 Bugzilla #78201、#91411 等，详见 commit 引用）。

## 4. 复现手法

1. 笔记本或台式 ACPI 平台，启用 **thermal + ACPI fan**。
2. 多次 **S3/S4** 或 **s2idle** 循环，唤醒后立即观察风扇与 `sensors`。
3. 在 suspend 前刻意制造 **温度变化**（负载→空闲），唤醒后对比策略是否重置。

## 5. 调试方法

- **对比 suspend 前后**：`thermal_zone` sysfs、`/sys/class/thermal/*` 的 `temp`、`policy`、`trip` 是否一致。
- **在 `thermal_zone_device_update()` 加 trace**（注意 printk 对时序影响）：是否在 `in_suspend` 窗口仍更新冷却设备。
- **审阅 PM domain 与 fan resume 顺序**：设备已 active 但 thermal 仍持旧状态 → 指向本类 bug。

## 6. 解决办法

- 引入 **`in_suspend` 原子标志** + **PM notifier**：
  - **`PM_SUSPEND_PREPARE`**：置位，期间 **`thermal_zone_device_update()` 直接返回**，避免对半睡眠设备下发冷却命令。
  - **`PM_POST_SUSPEND`**：清标志，**遍历所有温区**：`thermal_zone_device_reset()` + `thermal_zone_device_update()`，**重建完整热管理视图**。

**修复原理**：把“睡眠边界”视为 **全局一致点**：边界内 **禁止增量更新**，边界后 **强制全量 reconcile**。

## 7. 经验总结

- **任何跨 suspend 的轮询子系统**都需要明确：**哪些读数在 resume 后立即无效**。
- **框架状态 + 设备 PM domain** 同时存在时，要定义 **谁是真相源（source of truth）**，否则必出现“resume 后各说各话”。
