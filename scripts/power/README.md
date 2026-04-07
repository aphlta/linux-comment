# power scripts

本目录提供低功耗相关的测量、审计与回归脚本，配合 `Documentation/low_power/` 下的 SOP/Runbook 使用。

## 脚本索引

- [collect_idle_baseline.sh](collect_idle_baseline.sh)：基线采集（可作为统一入口产出数据包）
- [ab_test_runner.sh](ab_test_runner.sh)：A/B 测试跑批骨架（场景与变量由调用方约束）
- [runtime_pm_audit.sh](runtime_pm_audit.sh)：Runtime PM 侧的设备审计（定位“设备没睡”类问题）
- [suspend_resume_regression.sh](suspend_resume_regression.sh)：Suspend/Resume 回归与守护
- [run_cpuidle_cpufreq_experiments.sh](run_cpuidle_cpufreq_experiments.sh)：cpuidle/cpufreq 联动实验辅助

## 推荐配套阅读

- 总索引：[Documentation/low_power/README.md](../../Documentation/low_power/README.md)
- 团队 Runbook：[Documentation/low_power/arm_android_runbook/README.md](../../Documentation/low_power/arm_android_runbook/README.md)
- 执行套件：[Documentation/low_power/learning_plan/README.md](../../Documentation/low_power/learning_plan/README.md)
