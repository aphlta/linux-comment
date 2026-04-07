# 功耗/性能分析报告模板（ARM + Android）

## 0. 摘要（TL;DR）

- 设备/版本：
- 场景：
- 结论一句话：
- 直接原因：
- 根因：
- 采取动作：
- 验收结果（功耗/体验）：

## 1. 背景与目标

- KPI 取向：平衡（待机/续航 + 体验/抖动）
- 本次关注指标：
  - 功耗：
  - 体验：

## 2. 场景定义（必须可复现）

- 场景名称：
- 持续时间：
- 前置条件冻结：
  - 网络：
  - 屏幕：
  - 充电/供电：
  - 温度：
  - 后台服务/应用：

## 3. 数据源（文件路径 + 采集方式）

### 3.1 基线采集包

- 采集脚本：[collect_idle_baseline.sh](../../../../scripts/power/collect_idle_baseline.sh)
- 输出目录：
- system_info：
- cpuidle before/after：
- interrupts before/after：
- wakeup_sources before/after：
- genpd/devfreq（如有）：
- trace：
- Android dumpsys：

### 3.2 外部功耗仪数据

- 原始数据文件：
- 采样率/量程/触发/供电电压：
- 环境温度：
- 记录模板：[measurement_log_template.md](measurement_log_template.md)

## 4. 结果（必须有表格）

### 4.1 核心结果表（A/B/回滚）

| Run | 版本/配置 | Avg Power (mW) | Wakeup/s | Deep Idle Residency (%) | Deep Avg Residency | Top Offender | 体验指标（P99/卡顿） |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | | | | | | | |
| A2 | | | | | | | |
| A3 | | | | | | | |
| B1 | | | | | | | |
| B2 | | | | | | | |
| B3 | | | | | | | |
| A’1 | | | | | | | |

### 4.2 证据片段（关键截图/关键时间段说明）

- interrupts delta 的 Top 3：
- wakeup_sources 的 Top 3：
- trace 时间线关键片段（时间戳范围 + 解释）：

## 5. 分析与归因（必须写清“直接原因/根因”）

- 问题分桶：A/B/C/D
- 直接原因（现象层）：
- 根因（机制层）：
- 为什么现在才发生（版本/配置/场景变化）：

## 6. 采取动作与实现点

- 动作 1：
  - 目的：
  - 修改点：
  - 预期影响：
- 动作 2：

## 7. 风险与副作用（必须写）

- 风险 1：
- 风险 2：

## 8. 验收结论与下一步

- 是否通过验收：
- 未通过项：
- 下一步行动项（责任人/截止条件/复验方式）：
