# 证据包规范（脚本输出与报告对齐）

目标：让 A/B 对比、回归与复盘不依赖“口述”，而是依赖可保存、可复现的证据包（数据 + 元信息 + 环境快照）。

## 1. 基线采集证据包：idle baseline

采集脚本：[`scripts/power/collect_idle_baseline.sh`](../../scripts/power/collect_idle_baseline.sh)

### 输出目录命名

- 默认：`idle_baseline_YYYYMMDD_HHMMSS`
- 建议加上场景标签（手工重命名即可）：`idle_baseline_YYYYMMDD_HHMMSS_screenoff_wifi_on`

### 关键输出文件

- `system_info.txt`：uname、cmdline、CPU 拓扑、cpufreq policy 概览
- `cpuidle_before/` 与 `cpuidle_after/`：每 CPU、每 state 的 name/usage/time/latency/residency/disable 快照
- `devfreq_before.txt` 与 `devfreq_after.txt`：devfreq governor 与当前频率
- `pm_genpd_before.txt` 与 `pm_genpd_after.txt`：`pm_genpd_summary`（若 debugfs 可用）
- `wakeup_sources_before.txt` 与 `wakeup_sources_after.txt`：wakeup source 计数（若可用）
- `interrupts_before.txt` 与 `interrupts_after.txt`：`/proc/interrupts`
- `power_trace.dat`：trace-cmd 采集（若系统有 trace-cmd）
- `ftrace_raw.txt`：ftrace 兜底采集（无 trace-cmd 但有 tracing 时）
- `warnings.txt`：采集过程的降级/缺失信息（如 tracing 不可用）

### Android 模式补充输出

当使用 `--android` 时：

- `dumpsys_power_before.txt` / `dumpsys_power_after.txt`
- `batterystats_before.txt` / `batterystats_after.txt`

## 2. 与报告模板对齐

建议在每次实验（A/B/A'）都保存证据包，并在报告里记录以下关联字段：

- 证据包目录名（或归档路径）
- 采集时长（`DURATION_SEC`）
- 场景标签（屏幕/网络/外设/温度等关键变量）

推荐使用 Runbook 模板固化字段：
- 报告模板：[report_template.md](arm_android_runbook/templates/report_template.md)
- 测量记录模板：[measurement_log_template.md](arm_android_runbook/templates/measurement_log_template.md)
