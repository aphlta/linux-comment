# 06 - Phase 5：验收与回归守护（把优化变成工程能力）

本章把“什么时候算优化成功”与“如何防止回退”固化成团队流程。目标是：任何后续版本迭代都能自动发现功耗/抖动回退，并能快速定位到责任域。

## 5.1 Balanced KPI 的验收框架

### 待机/续航侧（功耗主 KPI）

至少对以下场景给出门槛（具体数值由产品与竞品目标确定）：

- `idle_10min_screen_off`：平均功耗（mW）与方差（重复 3 次）
- `typical_standby_30min`：平均功耗（mW）与关键唤醒源稳定性

推荐验收项：

- 平均功耗下降达到目标（或不高于基线 + 容忍阈值）
- 重复 run 方差 ≤ 5%
- wakeup/s 与 Top offender 排名稳定
- 深 idle residency 与平均驻留达到预期（避免“睡得碎”）

### 体验/抖动侧（性能主 KPI）

选择 1~2 个最能代表用户体验的指标做硬门槛：

- P99 唤醒延迟（或等价“从 idle exit 到业务可运行”的时间指标）
- 关键交互卡顿计数（音频 glitch、触控响应、网络 RTT 尾部等）

验收原则：

- 功耗优化不允许显著恶化体验指标（设置明确上限）
- 若为“体验优先场景”启用了 QoS/限制深睡，应在报告中明确策略生效范围与白名单

## 5.2 最小回归集（建议 2~3 个场景起步）

建议每个平台至少保留：

1. `idle_10min_screen_off`：作为“基础健康度”守护
2. 一个产品关键业务场景（例如音频后台/弱网保活/消息收发）
3. （可选）一个热敏感场景（长时间中负载）用于监控限频带来的功耗/性能漂移

每个场景回归至少输出：

- 平均功耗（mW）与重复方差
- 深 idle residency（%）与深 state 平均驻留
- wakeup/s 或等价“唤醒密度”指标
- Top offender（interrupts delta + wakeup_sources）

## 5.3 回归数据的留痕与审计

### 目录与命名规范

建议统一目录命名：

- `device/<device_name>/<scenario>/<yyyyMMdd_HHmm>/<baseline_or_change>/`

并将每次 run 的报告包完整归档（包括 trace 与外部功耗仪原始数据）。

### 证据必须可追溯

每一个阈值告警都必须能回答：

- 回退发生在哪个场景？
- 哪个指标触发？
- Top offender 是谁？（证据文件在哪里）
- 需要哪个责任域介入（Android/framework、内核/驱动、硬件/测量）

## 5.4 回归告警的推荐阈值（默认建议，可按项目调整）

- 平均功耗回退：> +5%（同场景、同环境约束）
- wakeup/s 回退：> +20% 或 Top offender 出现新成员且贡献显著
- 深 idle residency 回退：> -10%（或深 state 平均驻留显著下降）
- 体验指标回退：P99 延迟超过门槛或卡顿计数超阈

## 5.5 与基线采集脚本的对接

建议回归采集统一沿用：

- [collect_idle_baseline.sh](../../../scripts/power/collect_idle_baseline.sh)

并以 [report_template.md](templates/report_template.md) 固化输出字段，便于自动化解析与比对。
