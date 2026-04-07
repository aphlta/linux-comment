# 01 - Phase 0：基线与可重复性（ARM + Android 手机）

Phase 0 的目标是把“噪声”压到可控范围，建立可复现的基线包。没有稳定基线，任何优化都可能是幻觉。

本章在 [phase0_baseline.md](../learning_plan/phase0_baseline.md) 的通用清单之上，补充 Android 手机项目必需的约束与做法。

## 0.1 基线场景集合（Balanced KPI 的最小集合）

至少定义以下 3 类场景，并且为每类场景写清楚“前置条件冻结”：

1. `idle_10min_screen_off`：熄屏静置 10 分钟（先做这个）
2. `idle_10min_screen_on`：亮屏静置 10 分钟（固定亮度/刷新率/常亮策略）
3. `typical_standby_30min`：典型待机 30 分钟（网络状态明确：Wi-Fi/蜂窝/飞行模式）

可选业务场景（按产品形态选择）：

- 音频后台播放（抖动敏感）
- 弱网保活（wakeup 与 DVFS 敏感）
- 相机预览（热/性能敏感）

## 0.2 前置条件冻结（Android 侧必须写进测试用例）

每次 run 必须记录并尽可能固定：

- 网络：飞行模式/仅 Wi-Fi/蜂窝；是否允许扫描；是否连接 AP
- 屏幕：亮度、刷新率、Always-On Display、触控采样率（若可见）
- 充电：是否插线；外部功耗仪供电电压；USB 是否同时连接数据线
- 温度：环境温度 + 起测温度区间；是否刚跑过高负载
- 后台：测试前是否 force-stop 非必要应用；是否关闭遥测/日志/同步

## 0.3 测量纪律（外部功耗仪/电源）

### 重复与方差门槛

- 每个场景至少 3 次重复 run
- 若平均功耗方差 > 5%（或你们自定义阈值），停止进入调优阶段，先治理噪声源

### 必记参数（用于复现与排查“测量链路问题”）

使用模板记录（建议直接拷贝填写）：[measurement_log_template.md](templates/measurement_log_template.md)

要点：

- 采样率/滤波/量程策略（自动换挡可能引入盲区）
- 接线方式与线损（线长/线径/接触电阻）
- 供电电压与电流限值
- 是否存在旁路供电（例如 USB 偷电）

## 0.4 统一采集入口（脚本 + 输出包）

推荐统一用脚本生成基线包（含 Android dumpsys 与 trace）：

- 采集脚本：[collect_idle_baseline.sh](../../../scripts/power/collect_idle_baseline.sh)
- 采集内容概览：系统信息、cpuidle counters（before/after）、devfreq、pm_genpd、wakeup_sources、/proc/interrupts、trace（power/irq/timer）、Android dumpsys

### 输出包验收清单（跑完就检查）

- 是否存在 `cpuidle_before/` 与 `cpuidle_after/`，且每个 CPU 都有 state 文件
- 是否存在 `interrupts_before/after.txt`，可用于差分
- 是否存在 `power_trace.dat` 或 `ftrace_raw.txt`
- Android 模式下是否存在 `dumpsys_power_*` 与 `batterystats_*`

## 0.5 基线必算指标（写进 report.md 的 Results 表）

至少写这 5 个：

1. 平均功耗（mW）：来自外部功耗仪
2. wakeup/s（或等价指标）：来自 powertop/trace/dumpsys 之一，注明来源
3. 深 idle residency（%）：从 cpuidle `time` 差分计算
4. 深 idle 平均驻留（`time/usage`）：用于判断“睡得碎不碎”
5. Top offender（唤醒贡献者）：/proc/interrupts delta + wakeup_sources + trace 三者交叉确认

## 0.6 基线失败的常见原因与处理

1. 温度漂移：起测温度差异大导致 leakage 差异
2. 后台服务不稳定：周期任务/同步/定位/遥测导致 wakeup 排名变化
3. 网络状态不一致：Wi-Fi 扫描、蜂窝寻呼、弱信号重试
4. 测量链路问题：USB 偷电、量程切换、线损导致设备端电压变化
