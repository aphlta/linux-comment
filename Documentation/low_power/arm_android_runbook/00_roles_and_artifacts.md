# 00 - 团队角色与输出物规范（ARM + Android）

本章用于“约束团队怎么做”：明确谁负责什么、必须产出什么、结论如何留证据、如何组织数据包，确保跨人/跨平台可复现与可审计。

## 角色与职责

### 系统功耗 Owner（牵头/裁决）

- 定义 KPI：待机功耗、关键交互抖动/延迟、温升/限频风险、A/B 阈值
- 决定场景集合：基线场景 + 业务场景（以及每个场景的前置条件冻结）
- 评审证据链：任何结论必须具备“数据源 + 时间窗口 + 采集方式 + 复现步骤”
- 组织跨团队协作：Android framework、内核/驱动、硬件测量、测试/自动化

### Android Framework/应用侧负责人

- 治理唤醒源（wakelock/alarm/job/网络心跳），提供可控开关与 A/B 方案
- 给出“业务侧可接受”的体验约束（例如音频/触控/网络延迟门槛）
- 输出证据：`dumpsys power`、`batterystats`、（可选）`dumpsys alarm`/`jobscheduler` 的对比与解释

### 内核/驱动负责人

- 负责 cpuidle/cpufreq、tick/nohz、wakeup IRQ、runtime PM、devfreq/genpd 的可观测性与问题修复
- 输出证据：cpuidle residency、/proc/interrupts delta、wakeup_sources、trace-cmd 时间线归因

### 测试/自动化负责人

- 固化场景脚本与重复运行策略（至少 3 次重复 + 方差检查）
- 负责数据包归档、对比分析（前后 diff、阈值告警）

### 硬件测量负责人（功耗仪/电源/板载传感器）

- 定义测量链路与接线规范，确保“测量不改变被测对象”
- 输出证据：外部功耗仪原始数据（I-t 曲线/CSV）、采样率/量程/触发/温度等参数记录
- 与软件时间轴对齐：把电流形态与 trace 时间戳对齐（参考 [08_soc_lp_lab_instruments_debug_zh.md](../tech_evolution/08_soc_lp_lab_instruments_debug_zh.md)）

## 输出物清单（每个场景必交）

### 必交：报告包目录

每次实验（一个场景的一次 A/B 对比）输出一个目录，至少包含：

- `system_info.txt`：内核版本、cmdline、拓扑、cpufreq policy/governor、相关开关摘要
- `cpuidle_before/` 与 `cpuidle_after/`：每 CPU 每 state 的 `usage/time/latency/residency/disable`
- `interrupts_before.txt` 与 `interrupts_after.txt`：用于差分定位 top IRQ
- `wakeup_sources_before.txt` 与 `wakeup_sources_after.txt`（若可用）
- `pm_genpd_before/after.txt`（若可用）与 `devfreq_before/after.txt`（若可用）
- Android 模式下：
  - `dumpsys_power_before/after.txt`
  - `batterystats_before/after.txt`
- trace：
  - `power_trace.dat`（trace-cmd 输出）或 `ftrace_raw.txt`
- `report.md`：按模板填写的结论报告

建议使用统一采集入口脚本：[collect_idle_baseline.sh](../../../scripts/power/collect_idle_baseline.sh)

### 必交：report.md（结论必须可追溯）

`report.md` 必须包含：

- 场景与前置条件（网络/屏幕/温度/充电状态/后台服务）
- 数据源列表（每一项附文件路径）
- 结果表（至少：平均功耗、wakeup/s、深 idle residency、top offender）
- 结论句式（示例）：
  - “本次功耗未降的直接原因是 X（证据：…），根因是 Y（证据：…）”
  - “体验抖动来自 Z（证据：idle exit latency + cpu_frequency 振荡时间线）”
- 下一步行动项（Owner 负责闭环）

## 证据规范（禁止无证据结论）

- 任何“谁导致功耗/抖动”的结论必须给出：
  - 可复现步骤（如何得到同样的 trace/计数器）
  - 至少一个主证据（trace/计数器/功耗仪曲线）+ 一个辅证据（另一维度交叉验证）
- 禁止用“推测/感觉”作为根因；不允许单次 run 直接下结论
