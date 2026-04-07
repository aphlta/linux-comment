# 2016：intel_pstate 在非目标 CPU 上读 HWP MSR 触发 #GP

## 1. 提交基础信息

- **Commit ID**：`f9f4872df6e1801572949f8a370c886122d4b6da`
- **标题**：`cpufreq: intel_pstate: Fix unsafe HWP MSR access`
- **作者**：Srinivas Pandruvada（Intel）
- **涉及子系统**：`drivers/cpufreq/intel_pstate.c`、x86 MSR
- **关键词**：`MSR_HWP_CAPABILITIES`、`MSR_PM_ENABLE`、`rdmsrl_on_cpu`、HWP（Hardware P-states）

## 2. 背景信息

- **Intel HWP（Speed Shift）** 通过一组 MSR 描述/请求硬件 P-state 范围。
- **硬件契约**：在读 **`MSR_HWP_CAPABILITIES`（0x771）** 前，通常需在同一逻辑 CPU 上先确保 **`MSR_PM_ENABLE`** 等前置状态正确；且能力寄存器与 **每 CPU 上下文**相关。
- 使用 **`rdmsrl()`** 表示 **在当前 CPU** 读 MSR；若代码运行在 **与 `policy->cpu` 不一致** 的 CPU 上，可能读到 **未使能 HWP 的上下文**，触发 **#GP** 或 “unchecked MSR access” 警告。

**为何与低功耗直接相关**：问题出在 **cpufreq 初始化/上线路径**，可导致 **大 CPU 数服务器启动失败** 或 **调频子系统异常**。

## 3. 故障现象

- dmesg 出现 **unchecked MSR access** / **GP fault**，调用栈指向 `intel_pstate_hwp_set` 等路径。
- **超多核系统**（例如上百逻辑 CPU）上更易触发：初始化任务迁移 CPU 放大窗口。

## 4. 复现手法

1. 支持 HWP 的 Intel 平台 + 多核。
2. 使用当时版本存在 bug 的内核，启用 `intel_pstate`。
3. 冷启动或反复 **offline/online** 大范围 CPU，使 `cpufreq_online` 在不同 CPU 上执行。

## 5. 调试方法

- **dmesg + stack trace**：定位到具体 `rdmsrl` 行。
- **对照 Intel SDM**：确认 **HWP 相关 MSR 的 scope 与使能顺序**。
- **单步/CPU 亲和**：将 `cpufreq` 相关 kthread 绑核验证假设：绑定到 `policy->cpu` 后问题消失。

## 6. 解决办法

- 将 **`rdmsrl(MSR_HWP_CAPABILITIES, ...)`** 改为 **`rdmsrl_on_cpu(cpu, MSR_HWP_CAPABILITIES, ...)`**，并放入 **`for_each_cpu` 循环内**，对每个 CPU **各自读取能力**。

**修复原理**：**MSR 的硬件语义是 per-logical-processor** 时，内核必须 **在目标 CPU 上执行 RDMSR**，不能用“当前 CPU”凑合。

## 7. 经验总结

- **所有“策略属于 CPU N，但代码跑在 CPU M”** 的 MSR/MMIO 访问都要审计。
- 排障口诀：**policy->cpu vs smp_processor_id()** 不一致 → 高危。
