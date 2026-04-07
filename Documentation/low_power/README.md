# Low Power / Power Management 文档索引

本目录用于把工作区内新增的低功耗相关内容统一归档，并给出从“入门 → 跑流程 → 读源码 → 做实验 → 产出报告”的导航。

## Start Here（推荐入口）

- 新机功耗/性能全流程 SOP：[手机功耗性能分析全流程_SOP.md](SOPs/手机功耗性能分析全流程_SOP.md)
- 团队可执行 Runbook：[arm_android_runbook/README.md](arm_android_runbook/README.md)
- 6 个月执行套件（阶段学习 + 实验 + 产出）：[learning_plan/README.md](learning_plan/README.md)
- 证据包规范（脚本输出与报告对齐）：[evidence_package_spec.md](evidence_package_spec.md)
- PM/低功耗术语表：[glossary.md](glossary.md)
- Deep idle 一页排障图：[deep_idle_triage_onepager.md](deep_idle_triage_onepager.md)
- PM QoS 实战与排障：[pm_qos_playbook.md](pm_qos_playbook.md)
- genpd 调试手册：[genpd_debug_guide.md](genpd_debug_guide.md)
- Tracing→Perfetto 对齐指南：[tracing_perfetto_alignment.md](tracing_perfetto_alignment.md)

## Kernel PM 代码地图

- 内核文档与核心代码入口索引（带跳转链接）：[kernel_pm_map.md](kernel_pm_map.md)
- cpufreq/DVFS/OPP 参考（已放在内核原目录）：[cpufreq_dvfs_opp_reference.md](../cpu-freq/cpufreq_dvfs_opp_reference.md)

## 知识库与专题

- 技术演进与代码走读（按年代主题）：[tech_evolution/README.md](tech_evolution/README.md)
- 核心概念（原理与笔记）：[core_concepts/README.md](core_concepts/README.md)
- 平台专题（RK3588）：[rk3588/README.md](rk3588/README.md)
- 硬件规格/架构资料（GIC 等）：[hardware_specs/README.md](hardware_specs/README.md)

## 案例库

- 复杂故障年鉴（2010–2025，每年一例）：[bugs_archive/README.md](bugs_archive/README.md)
- 低功耗专家案例（驱动/子系统深挖）：[case_studies/README.md](case_studies/README.md)
- Heisenbugs / Posted-Write / 屏障类深度解析：[heisenbugs/](heisenbugs/)
- 叙事型“年度工作报告”（用于构建历史与背景）：[annual_reports/README.md](annual_reports/README.md)

## 自动化脚本

- 测量/回归脚本目录：[scripts/power/README.md](../../../scripts/power/README.md)
