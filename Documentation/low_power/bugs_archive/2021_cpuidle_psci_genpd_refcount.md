# 2021：System suspend 禁用 runtime PM 前 CPU 仍在 idle，破坏 cpuidle-psci + genpd

## 1. 提交基础信息

- **Commit ID**：`a2bd7be12b9edab5736a9a95bceccfbdf7520fdd`
- **标题**：`PM: sleep: Fix runtime PM based cpuidle support`
- **作者**：Ulf Hansson（Linaro）；诊断来自 Qualcomm 的 Maulik Shah
- **涉及子系统**：`drivers/base/power/main.c`、**cpuidle-psci**、**Generic Power Domains（genpd）**
- **关键词**：`dpm_suspend_late`、`wake_up_all_idle_cpus`、`pm_runtime_disable`

## 2. 背景信息

- 在部分 **ARM/SoC** 上，**CPU idle** 通过 **cpuidle-psci** 与 **genpd + runtime PM** 管理 **共享 idle 状态**（跨 cluster / 电源域）。
- **`dpm_suspend_late()`** 会 **禁用设备的 runtime PM**，若此时某 CPU **仍停留在 idle 路径**且持有 **domain 的 put 语义**，后续再尝试 `pm_runtime_get_sync()` 等会 **失败**，导致 **引用计数/电源域状态**与真实硬件不一致。

**为何是一行修复却极重要**：问题不在“算错数”，而在 **全局阶段切换与 per-CPU idle 状态**未对齐。

## 3. 故障现象

- **Suspend 不稳定**：可能失败、hang，或 **resume 后功耗异常**。
- **genpd summary / debugfs** 可能显示 **usage count** 异常（视平台调试手段而定）。

## 4. 复现手法

1. 使用 **cpuidle-psci + genpd** 绑定的平台（如部分 Qualcomm 参考设计）。
2. 高负载后立刻 **system suspend**，使部分 CPU 概率停在 deep idle。
3. 反复压测 **suspend/resume**；与 **big.LITTLE 调度** 交错更易触发。

## 5. 调试方法

- **开启 genpd debug**（若可用）与 **runtime PM 统计**：对比 suspend 前后 **usage count**。
- **在 `dpm_suspend_late` 前后打 trace event**：`rpm`、`cpu_idle`。
- **审阅调用顺序**：`device_prepare` 已 bump usage 前，是否所有 CPU 已 **退出 idle 所需的 runtime 契约**。

## 6. 解决办法

- 在 **`dpm_suspend_late()` 起始**加入 **`wake_up_all_idle_cpus()`**：
  - **先** 把所有 idle CPU **踢出 idle**，使其完成 **cpuidle-psci 侧需要的 runtime get 路径**；
  - **再** 走后续 **disable runtime PM** 等阶段。

**修复原理**：在 **关闭 runtime PM 机制**之前，保证系统不处于依赖该机制的中间态（**CPU 在 idle 域内**）。

## 7. 经验总结

- **任何“全局禁用某子系统”前**，先问：**谁还在用这个子系统完成状态迁移？**
- **CPU idle 不是“与设备 PM 无关”**——现代 SoC 上常 **强耦合**。
