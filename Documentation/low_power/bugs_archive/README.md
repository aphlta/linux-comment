# Linux 低功耗复杂故障案例库（2010–2025）

本目录收录 **每年一个** 与 Linux 内核**电源管理 / 低功耗**相关的**真实、复杂**故障案例。每个案例均绑定上游主线（或稳定分支回合）中的**具体 commit**，便于对照源码与 `git show`。

## 文档目的

- **现象**：把“用户/测试能观察到什么”说清楚，避免与根因混为一谈。
- **背景**：说明涉及的子系统契约（system PM、runtime PM、cpuidle、ACPI、总线/时钟等），解释**为何**这类设计容易踩坑。
- **复现**：给出可操作的触发条件与步骤；注明**概率性**与平台相关性。
- **调试**：列出常用工具与推理路径（lockdep、hung_task、ftrace、功耗计、日志等）。
- **解决**：概括补丁思路与**不变量**（锁序、生命周期、屏障、引用计数）。

## 案例索引（按年份）

| 年份 | 文件 | Commit | 一句话 |
|------|------|--------|--------|
| 2010 | [2010_mmc_suspend_deadlock.md](2010_mmc_suspend_deadlock.md) | `4c2ef25fe0b8` | Suspend 路径与用户空间冻结冲突导致 MMC 挂死 |
| 2011 | [2011_firmware_load_suspend_race.md](2011_firmware_load_suspend_race.md) | `b298d289c792` | 固件加载与 usermodehelper 禁用的 TOCTOU 竞态 |
| 2012 | [2012_pci_d3cold_unbind_deadlock.md](2012_pci_d3cold_unbind_deadlock.md) | `90b5c1d7c45e` | D3cold 下 unbind 与 `pci_walk_bus` 锁嵌套死锁 |
| 2013 | [2013_cpuidle_coupled_lost_wakeup.md](2013_cpuidle_coupled_lost_wakeup.md) | `9e19b73c30a5` | Coupled cpuidle poke 与 safe state 竞态丢唤醒 |
| 2014 | [2014_acpi_cpuidle_hotplug_deadlock.md](2014_acpi_cpuidle_hotplug_deadlock.md) | `6726655dfdd2` | `cpuidle_lock` 与 CPU 热插拔锁 AB-BA |
| 2015 | [2015_thermal_suspend_resume_stale.md](2015_thermal_suspend_resume_stale.md) | `ff140fea847e` | 睡眠前后热区状态与冷却设备不同步 |
| 2016 | [2016_intel_hwp_msr_gp_fault.md](2016_intel_hwp_msr_gp_fault.md) | `f9f4872df6e1` | HWP MSR 在非目标 CPU 上读取触发 #GP |
| 2017 | [2017_x86_suspend_segment_restore.md](2017_x86_suspend_segment_restore.md) | `7ee18d677989` | x86 resume 段/描述符恢复顺序错误致挂死 |
| 2018 | [2018_nouveau_runtime_pm_deadlock.md](2018_nouveau_runtime_pm_deadlock.md) | `3e1a12754d4d` | Nouveau 热插拔 work 与 runtime PM 循环等待 |
| 2019 | [2019_s2idle_noirq_loop_power_drain.md](2019_s2idle_noirq_loop_power_drain.md) | `56b991849009` | S2idle 控制流导致 noirq 反复与深度省电失败 |
| 2020 | [2020_runtime_pm_spurious_abort.md](2020_runtime_pm_spurious_abort.md) | `e3eb6e8fba65` | 共享电源资源下误报 wakeup 中止 suspend |
| 2021 | [2021_cpuidle_psci_genpd_refcount.md](2021_cpuidle_psci_genpd_refcount.md) | `a2bd7be12b9e` | 禁用 runtime PM 前 CPU 仍在 idle 破坏 genpd 计数 |
| 2022 | [2022_ufs_scsi_suspend_deadlock.md](2022_ufs_scsi_suspend_deadlock.md) | `7029e2151a7c` | UFS suspend 与 SCSI error handler 互锁 |
| 2023 | [2023_interconnect_rpm_reclaim_deadlock.md](2023_interconnect_rpm_reclaim_deadlock.md) | `af42269c3523` | interconnect 带宽路径与 reclaim 锁域交叉 |
| 2024 | [2024_clk_disable_unused_rpm_deadlock.md](2024_clk_disable_unused_rpm_deadlock.md) | `e581cf5d2162` | `clk_disable_unused` 持锁下 runtime resume 死锁 |
| 2025 | [2025_rpm_autosuspend_off_by_one.md](2025_rpm_autosuspend_off_by_one.md) | `40d3b40dce37` | autosuspend 定时器边界条件致永久不再挂起 |

## 按故障类型分类

| 类型 | 案例年份 |
|------|----------|
| **死锁 / 锁序（AB-BA）** | 2010, 2012, 2014, 2018, 2022, 2023, 2024 |
| **竞态 / TOCTOU / 丢唤醒** | 2011, 2013, 2020 |
| **状态不一致 / 生命周期** | 2015, 2021 |
| **硬件寄存器访问契约** | 2016 |
| **架构级恢复顺序** | 2017 |
| **控制流 / 平台深度休眠** | 2019 |
| **边界条件 / 定时器** | 2025 |

## 共性分析方法（SOP 摘要）

1. **先分层**：区分 symptom 属于 system suspend、runtime PM、cpuidle、还是设备驱动私有路径。
2. **再定型**：死锁用 lockdep / 双栈；挂起用 `sysrq-w`、hung_task；功耗用功率计 + `powertop` / trace event。
3. **锁与 reclaim**：凡在持锁路径上可能 `kmalloc`→reclaim→再拿别的子系统锁，优先怀疑**锁域过大**或**需拆锁**。
4. **System PM 与 Runtime PM 交界**：`dpm_suspend_late`、禁用 runtime PM、`pm_runtime_barrier` 等节点是高频雷区；对照 `Documentation/power/`。

## 与本仓库其他资料的关系

- 深度单案写作风格可参考根目录 `Heisenbug_Analysis_*.md`。
- 低功耗学习计划与更多案例骨架见 [`../learning_plan/`](../learning_plan/)。

## 使用说明

- 在对应内核树中：`git show <commit>` 查看完整补丁与讨论线索。
- 稳定分支用户请用 `git describe --contains <commit>` 或发行版 changelog 确认是否已回合。
