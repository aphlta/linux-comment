# 2014：ACPI cpuidle 与 CPU 热插拔锁的 AB-BA 死锁

## 1. 提交基础信息

- **Commit ID**：`6726655dfdd2dc60c035c690d9f10cb69d7ea075`
- **标题**：`ACPI / cpuidle: fix deadlock between cpuidle_lock and cpu_hotplug.lock`
- **作者**：Jiri Kosina
- **涉及子系统**：`drivers/acpi/processor_idle.c`、cpuidle 核心、CPU hotplug
- **关键词**：`cpuidle_pause_and_lock`、`get_online_cpus`、`cpu_hotplug`

## 2. 背景信息

- **ACPI 处理器 C-state 变更**（如 `_CST` 变化）会通过工作队列回调进入 cpuidle，需 **暂停 cpuidle** 并重建状态。
- **CPU 热插拔/上线流程**需要 **cpu_hotplug** 互斥，并在某些路径上 **触碰 cpuidle**。
- 若路径 1 先拿 **A 锁**再拿 **B 锁**，路径 2 相反，即经典 **AB-BA**。

**为何在电源管理场景突出**：suspend/resume、CPU 上线、ACPI 通知往往在短时间内交错，死锁表现为 **整机无声卡死**。

## 3. 故障现象

- 在 **CPU 热插拔**或 **从 suspend 恢复 CPU** 等场景下系统 **随机死锁**。
- 可能无明确日志；与 **ACPI 通知刷新 C-states** 并发时更易出现。

## 4. 复现手法

1. 开启 ACPI 与 cpuidle；使用支持 **处理器对象动态变化** 或频繁 **offline/online CPU** 的测试脚本。
2. 与 **suspend 循环**交错：`while true; do echo 0 > /sys/devices/system/cpu/cpuN/online; ...`（谨慎在非生产环境操作）。
3. 在 **lockdep** 开启的内核上，可能以 **潜在死锁** 报告形式复现，而不必真死锁。

## 5. 调试方法

- **CONFIG_PROVE_LOCKING=y**：lockdep 报告 **inversion** 时，记录两条链的加锁顺序。
- **确认涉及函数**：`acpi_processor_cst_has_changed()` 一类路径是否在 `cpuidle_pause_and_lock()` 与 `get_online_cpus()` 间顺序错误。

## 6. 解决办法

- 在 **`acpi_processor_cst_has_changed()`** 中 **调整锁顺序**：先 **`get_online_cpus()`**，再 **`cpuidle_pause_and_lock()`**；释放时对称。
- 使全系统对该锁对的使用遵循 **唯一全局顺序**。

**修复原理**：死锁的必要条件是 **循环等待**；打破环只需 **规定全内核唯一的加锁顺序** 并修正违规点。

## 7. 经验总结

- **cpuidle 与 hotplug** 是长期耦合点：任何新特性引入“第二把锁”时，应用 **lockdep 做一次全顺序审计**。
- **小补丁（数行）也可能修复高危死锁**——说明问题在**序**不在量。
