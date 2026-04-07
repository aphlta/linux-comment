# Linux 低功耗/电源管理文件索引

这份索引面向阅读与定位，按“系统睡眠（system-wide）/设备电源管理（device PM）/性能点管理（DVFS）/约束与唤醒”四条主线把内核里的文档与核心源码文件串起来。

## 建议阅读顺序（从全局到局部）

1. 系统睡眠：先理解 `/sys/power/state` 触发后发生了什么，再看设备回调编排（DPM），最后落到平台/驱动如何实现
2. 唤醒与约束：wakeup source 与 PM QoS 是“为什么睡不下去/为什么不能太深睡”的关键
3. Runtime PM：理解设备级 autosuspend、usage_count 与 state machine，连接到具体驱动的 `.runtime_suspend/.runtime_resume`
4. DVFS：OPP/regulator/clk 与 cpufreq/devfreq 如何拼起来，频点切换与时序安全约束在哪里保证
5. 电源域：genpd 如何把“设备依赖关系”变成“域上下电顺序”，与 runtime/system sleep 双线打通

## System Sleep / Hibernate（系统睡眠/休眠）

- **Docs**
  - [suspend-flows.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/suspend-flows.rst)
  - [sleep-states.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/sleep-states.rst)
  - [system-wide.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/system-wide.rst)
  - [freezing-of-tasks.rst](file:///home/alex/linux-stable/Documentation/power/freezing-of-tasks.rst)
  - [suspend-and-interrupts.rst](file:///home/alex/linux-stable/Documentation/power/suspend-and-interrupts.rst)
  - [swsusp.rst](file:///home/alex/linux-stable/Documentation/power/swsusp.rst)
  - [userland-swsusp.rst](file:///home/alex/linux-stable/Documentation/power/userland-swsusp.rst)
  - [swsusp-and-swap-files.rst](file:///home/alex/linux-stable/Documentation/power/swsusp-and-swap-files.rst)
  - [s2ram.rst](file:///home/alex/linux-stable/Documentation/power/s2ram.rst)
- **Core code（系统睡眠主流程与 sysfs 接口）**
  - [suspend.c](file:///home/alex/linux-stable/kernel/power/suspend.c)
  - [hibernate.c](file:///home/alex/linux-stable/kernel/power/hibernate.c)
  - [main.c](file:///home/alex/linux-stable/kernel/power/main.c)
  - [process.c](file:///home/alex/linux-stable/kernel/power/process.c)
  - [autosleep.c](file:///home/alex/linux-stable/kernel/power/autosleep.c)
- **关键入口（定位主干调用链）**
  - 挂起主入口：[pm_suspend](file:///home/alex/linux-stable/kernel/power/suspend.c#L623)
  - 进入某个 sleep state 的编排：[enter_state](file:///home/alex/linux-stable/kernel/power/suspend.c#L565)
  - 休眠主入口：[hibernate](file:///home/alex/linux-stable/kernel/power/hibernate.c#L750)
  - `/sys/power/state` 写入入口：[state_store](file:///home/alex/linux-stable/kernel/power/main.c#L718)
  - `/sys/power/disk` 写入入口：[disk_store](file:///home/alex/linux-stable/kernel/power/hibernate.c#L1176)

## Device PM Core（系统睡眠阶段设备回调编排：DPM）

- **负责什么**
  - 把所有 device 组织成 dpm_list，在系统 suspend/resume 阶段按顺序调用各设备的 `dev_pm_ops`（以及 domain/bus/class/type 的组合优先级）
- **Docs**
  - [devices.rst](file:///home/alex/linux-stable/Documentation/driver-api/pm/devices.rst)
  - [types.rst](file:///home/alex/linux-stable/Documentation/driver-api/pm/types.rst)
- **Core code**
  - [power/main.c](file:///home/alex/linux-stable/drivers/base/power/main.c)
  - [generic_ops.c](file:///home/alex/linux-stable/drivers/base/power/generic_ops.c)
  - [common.c](file:///home/alex/linux-stable/drivers/base/power/common.c)
- **关键入口**
  - 设备进入 PM 跟踪链：[device_pm_add](file:///home/alex/linux-stable/drivers/base/power/main.c#L125)
  - suspend 阶段回调编排：[dpm_suspend](file:///home/alex/linux-stable/drivers/base/power/main.c#L1759)
  - resume 阶段回调编排：[dpm_resume](file:///home/alex/linux-stable/drivers/base/power/main.c#L1033)

## Runtime PM（设备运行时按需省电）

- **负责什么**
  - 设备在系统运行过程中“闲时自动关/用时自动开”，与驱动 `.runtime_suspend/.runtime_resume` 对接
- **Docs**
  - [runtime_pm.rst](file:///home/alex/linux-stable/Documentation/power/runtime_pm.rst)
  - [sysfs-devices-power](file:///home/alex/linux-stable/Documentation/ABI/testing/sysfs-devices-power)
- **Core code**
  - [runtime.c](file:///home/alex/linux-stable/drivers/base/power/runtime.c)
  - [pm_runtime.h](file:///home/alex/linux-stable/include/linux/pm_runtime.h)
- **关键入口**
  - 状态机核心：[\_\_pm_runtime_suspend](file:///home/alex/linux-stable/drivers/base/power/runtime.c#L1132) / [\_\_pm_runtime_resume](file:///home/alex/linux-stable/drivers/base/power/runtime.c#L1168) / [\_\_pm_runtime_idle](file:///home/alex/linux-stable/drivers/base/power/runtime.c#L1094)
  - 驱动最常用同步获取：[pm_runtime_get_sync](file:///home/alex/linux-stable/include/linux/pm_runtime.h#L435)
  - 启用 runtime PM：[pm_runtime_enable](file:///home/alex/linux-stable/drivers/base/power/runtime.c#L1540)
  - autosuspend 延时：[pm_runtime_set_autosuspend_delay](file:///home/alex/linux-stable/drivers/base/power/runtime.c#L1774)

## Wakeup Sources / WakeIRQ（唤醒源与唤醒 IRQ）

- **负责什么**
  - 解释“为什么系统/设备不能睡”“是谁把系统唤醒”，并提供统一的计数与控制接口
- **Docs**
  - [sysfs-power](file:///home/alex/linux-stable/Documentation/ABI/testing/sysfs-power)
  - [sysfs-devices-power](file:///home/alex/linux-stable/Documentation/ABI/testing/sysfs-devices-power)
- **Core code**
  - [wakeup.c](file:///home/alex/linux-stable/drivers/base/power/wakeup.c)
  - [wakeirq.c](file:///home/alex/linux-stable/drivers/base/power/wakeirq.c)
  - [wakelock.c](file:///home/alex/linux-stable/kernel/power/wakelock.c)
  - [pm_wakeup.h](file:///home/alex/linux-stable/include/linux/pm_wakeup.h)
- **关键入口**
  - 注册/注销唤醒源：[wakeup_source_register](file:///home/alex/linux-stable/drivers/base/power/wakeup.c#L214) / [wakeup_source_unregister](file:///home/alex/linux-stable/drivers/base/power/wakeup.c#L239)
  - 保持唤醒/允许睡眠：[__pm_stay_awake](file:///home/alex/linux-stable/drivers/base/power/wakeup.c#L606) / [__pm_relax](file:///home/alex/linux-stable/drivers/base/power/wakeup.c#L723)
  - 报告唤醒事件：[pm_wakeup_ws_event](file:///home/alex/linux-stable/drivers/base/power/wakeup.c#L793)
  - sysfs wakelock 入口：[pm_wake_lock](file:///home/alex/linux-stable/kernel/power/wakelock.c#L206) / [pm_wake_unlock](file:///home/alex/linux-stable/kernel/power/wakelock.c#L254)

## PM QoS（延迟/性能约束：限制能睡多深、允许多慢响应）

- **Docs**
  - [pm_qos_interface.rst](file:///home/alex/linux-stable/Documentation/power/pm_qos_interface.rst)
  - [sysfs-devices-power](file:///home/alex/linux-stable/Documentation/ABI/testing/sysfs-devices-power)
- **Core code**
  - [kernel qos.c](file:///home/alex/linux-stable/kernel/power/qos.c)
  - [device qos.c](file:///home/alex/linux-stable/drivers/base/power/qos.c)
- **关键入口**
  - CPU latency QoS：[cpu_latency_qos_add_request](file:///home/alex/linux-stable/kernel/power/qos.c#L269) / [cpu_latency_qos_update_request](file:///home/alex/linux-stable/kernel/power/qos.c#L295) / [cpu_latency_qos_remove_request](file:///home/alex/linux-stable/kernel/power/qos.c#L321)
  - 设备 QoS：[dev_pm_qos_add_request](file:///home/alex/linux-stable/drivers/base/power/qos.c#L389) / [dev_pm_qos_update_request](file:///home/alex/linux-stable/drivers/base/power/qos.c#L464) / [dev_pm_qos_remove_request](file:///home/alex/linux-stable/drivers/base/power/qos.c#L511)
  - 暴露 sysfs 约束：[dev_pm_qos_expose_latency_limit](file:///home/alex/linux-stable/drivers/base/power/qos.c#L699) / [dev_pm_qos_expose_flags](file:///home/alex/linux-stable/drivers/base/power/qos.c#L775)

## OPP / Regulator（DVFS：频点表与供电）

- **负责什么**
  - OPP 描述“频率/电压/功耗能力点”，regulator 提供“如何把电压拉到目标值”的抽象
- **Docs**
  - OPP：[opp.rst](file:///home/alex/linux-stable/Documentation/power/opp.rst)
  - Regulator：[regulator.rst](file:///home/alex/linux-stable/Documentation/power/regulator/regulator.rst) / [consumer.rst](file:///home/alex/linux-stable/Documentation/power/regulator/consumer.rst) / [overview.rst](file:///home/alex/linux-stable/Documentation/power/regulator/overview.rst)
- **Core code（OPP）**
  - [opp/core.c](file:///home/alex/linux-stable/drivers/opp/core.c)
  - [opp/of.c](file:///home/alex/linux-stable/drivers/opp/of.c)
- **关键入口（OPP）**
  - 从 DT 装载表：[dev_pm_opp_of_add_table](file:///home/alex/linux-stable/drivers/opp/of.c#L1193)
  - 切换频点（通常联动 regulator/clk）：[dev_pm_opp_set_rate](file:///home/alex/linux-stable/drivers/opp/core.c#L1349)
  - 查找邻近频点：[dev_pm_opp_find_freq_ceil](file:///home/alex/linux-stable/drivers/opp/core.c#L724) / [dev_pm_opp_find_freq_floor](file:///home/alex/linux-stable/drivers/opp/core.c#L778)
- **Core code（Regulator）**
  - [regulator/core.c](file:///home/alex/linux-stable/drivers/regulator/core.c)
- **关键入口（Regulator）**
  - 获取/使能/失能：[regulator_get](file:///home/alex/linux-stable/drivers/regulator/core.c#L2354) / [regulator_enable](file:///home/alex/linux-stable/drivers/regulator/core.c#L2966) / [regulator_disable](file:///home/alex/linux-stable/drivers/regulator/core.c#L3078)
  - 电压/电流约束：[regulator_set_voltage](file:///home/alex/linux-stable/drivers/regulator/core.c#L4231) / [regulator_get_voltage](file:///home/alex/linux-stable/drivers/regulator/core.c#L4558) / [regulator_set_current_limit](file:///home/alex/linux-stable/drivers/regulator/core.c#L4589)
  - 注册 provider：[regulator_register](file:///home/alex/linux-stable/drivers/regulator/core.c#L5724)

## cpufreq / cpuidle / devfreq（CPU 频率、CPU 空闲态、设备 DVFS）

- **Docs**
  - cpufreq：[cpufreq.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/cpufreq.rst) / [cpufreq_drivers.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/cpufreq_drivers.rst)
  - cpuidle：[cpuidle.rst](file:///home/alex/linux-stable/Documentation/admin-guide/pm/cpuidle.rst) / [driver-api cpuidle.rst](file:///home/alex/linux-stable/Documentation/driver-api/pm/cpuidle.rst)
- **Core code**
  - cpufreq：[cpufreq.c](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c)
  - cpuidle：[driver.c](file:///home/alex/linux-stable/drivers/cpuidle/driver.c) / [cpuidle.c](file:///home/alex/linux-stable/drivers/cpuidle/cpuidle.c)
  - devfreq：[devfreq.c](file:///home/alex/linux-stable/drivers/devfreq/devfreq.c)
- **关键入口**
  - cpufreq：driver 注册 [cpufreq_register_driver](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L2973)，governor 注册 [cpufreq_register_governor](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L2566)
  - cpuidle：driver 注册 [cpuidle_register_driver](file:///home/alex/linux-stable/drivers/cpuidle/driver.c#L269)，设备注册 [cpuidle_register_device](file:///home/alex/linux-stable/drivers/cpuidle/cpuidle.c#L667)
  - devfreq：挂设备 [devfreq_add_device](file:///home/alex/linux-stable/drivers/devfreq/devfreq.c#L803)，governor 注册 [devfreq_add_governor](file:///home/alex/linux-stable/drivers/devfreq/devfreq.c#L1271)

## genpd（Generic Power Domains：电源域）

- **负责什么**
  - 用通用框架表达“设备依赖关系 -> 电源域上下电顺序”，同时支持 runtime PM 与 system sleep 两条路径
- **Docs**
  - DT binding：[power_domain.txt](file:///home/alex/linux-stable/Documentation/devicetree/bindings/power/power_domain.txt)
  - device/domain 组合优先级与回调覆盖关系：[devices.rst](file:///home/alex/linux-stable/Documentation/driver-api/pm/devices.rst)
- **Core code**
  - [pmdomain/core.c](file:///home/alex/linux-stable/drivers/pmdomain/core.c)
  - [pmdomain/governor.c](file:///home/alex/linux-stable/drivers/pmdomain/governor.c)
  - [pm_domain.h](file:///home/alex/linux-stable/include/linux/pm_domain.h)
- **关键入口**
  - domain 初始化：[pm_genpd_init](file:///home/alex/linux-stable/drivers/pmdomain/core.c#L2277)
  - 绑定/解绑设备：[pm_genpd_add_device](file:///home/alex/linux-stable/drivers/pmdomain/core.c#L1868) / [pm_genpd_remove_device](file:///home/alex/linux-stable/drivers/pmdomain/core.c#L1934)
  - DT consumer 绑定：[of_genpd_add_device](file:///home/alex/linux-stable/drivers/pmdomain/core.c#L2747)
  - 设备侧 attach：[genpd_dev_pm_attach](file:///home/alex/linux-stable/drivers/pmdomain/core.c#L3085)
  - 域级上下电：[genpd_power_on](file:///home/alex/linux-stable/drivers/pmdomain/core.c#L952) / [genpd_power_off](file:///home/alex/linux-stable/drivers/pmdomain/core.c#L856)
  - 域对接系统睡眠：[dev_pm_genpd_suspend](file:///home/alex/linux-stable/drivers/pmdomain/core.c#L1667) / [dev_pm_genpd_resume](file:///home/alex/linux-stable/drivers/pmdomain/core.c#L1681)

