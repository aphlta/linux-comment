# 技术演进：ARM / Android 低功耗技术演进与内核代码索引

## 目的

本目录按**时间线**整理与低功耗相关的**主线 Linux 内核**代码位置、核心抽象与典型数据流，并标注 Android / 用户态栈中**不在内核树内**的部分，便于从「行业概念」跳到「可读源码」。

**与执行套件的关系**：`../learning_plan/` 侧重学习计划与案例；本目录侧重**按年代技术主题**的**代码地图 + 原理导读**，二者互补。

## 全流程 SOP（新手机功耗性能）

- [手机功耗性能分析全流程_SOP.md](../SOPs/手机功耗性能分析全流程_SOP.md)：ARM + Android 新机型功耗与性能分析、调优的端到端团队流程（环境准备、基线、CPU/设备/休眠/Framework、闭环与回归、CI/KPI）。

## 文档索引

| 文档 | 时期 | 主题（行业侧） | 内核侧重 |
|------|------|----------------|----------|
| [01_2010-2012_clock_dvfs_suspend.md](01_2010-2012_clock_dvfs_suspend.md) | 2010–2012 | 时钟 / DVFS / Suspend | CCF、cpufreq、OPP、系统休眠、Runtime PM |
| [02_2013-2015_biglittle_eas_psci.md](02_2013-2015_biglittle_eas_psci.md) | 2013–2015 | big.LITTLE / EAS / PSCI | 异构切换、能耗模型、固件电源、cpuidle |
| [03_2016-2017_schedutil_dynamiq_scmi.md](03_2016-2017_schedutil_dynamiq_scmi.md) | 2016–2017 | schedutil / DynamIQ / SCMI | 调度驱动调频、DSU PMU、固件协议栈 |
| [04_2018-2019_display_vrr_trace.md](04_2018-2019_display_vrr_trace.md) | 2018–2019 | SurfaceFlinger / Systrace / VRR | DRM VRR 属性、trace、ftrace 基础 |
| [05_2020-2021_perfhint_ltpo_adpf.md](05_2020-2021_perfhint_ltpo_adpf.md) | 2020–2021 | PerformanceHint / LTPO / ADPF | uclamp、PM QoS、PSR/自刷新、devfreq |
| [06_2022-2023_gamemode_wifi7.md](06_2022-2023_gamemode_wifi7.md) | 2022–2023 | GameMode / Wi‑Fi 7 | mac80211 EHT、省电；游戏模式多在 Framework |
| [07_2024-2025_agent_npu_ar.md](07_2024-2025_agent_npu_ar.md) | 2024–2025 | Agent / MoE / AR | `drivers/accel`、DMA-BUF、与用户态 AI 边界 |
| [08_soc_lp_lab_instruments_debug_zh.md](08_soc_lp_lab_instruments_debug_zh.md) | 通用 | 实验室仪器与调试方法 | 电测实操、ftrace/wakeup 等与内核问题对齐（非年代专题） |

## 使用说明

1. 先读对应年代的 **「内核代码地图」**，再按 **「代码阅读指引」** 打开具体文件。
2. 主线树版本以当前工作区为准（如 `v6.15.x`）；历史目录（如 `arch/arm/mach-*`）可能已迁移到 DT-only，文档中会注明**演进关系**。
3. Android 专有名词（ADPF、GameMode 等）在文档中单独说明**内核侧可挂钩点**，避免误以为内核内有同名模块。

## 相关资源

- [../learning_plan/README.md](../learning_plan/README.md)：低功耗专家执行套件与阶段文档。
- [../annual_reports/](../annual_reports/)：按年背景叙事，可与本目录交叉阅读。
- [../arm_android_runbook/README.md](../arm_android_runbook/README.md)：团队跑流程用的可执行 Runbook（与本目录互补）。
- [../kernel_pm_map.md](../kernel_pm_map.md)：PM/低功耗相关内核文档与核心代码入口索引。
