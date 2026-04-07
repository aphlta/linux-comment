# stmmac EEE SW Timer 1Hz 频繁唤醒故障复盘（培训版）

| 字段 | 内容 |
|---|---|
| 文档编号 | LP-INC-CASE11 |
| 适用内核 | Linux `v5.17-rc2` 起包含修复（见“永久修复”） |
| 适用模块 | `drivers/net/ethernet/stmicro/stmmac/` |
| 故障类型 | 周期性定时器导致的 Spurious Wakeups / Idle 破坏 |
| 上游修复提交 | `c74ead223deb88bdf18af8c772d7ca5a9b6c3c2b` |
| 标题 | `net: stmmac: reduce unnecessary wakeups from eee sw timer` |
| 作者/日期 | Jisheng Zhang / 2022-01-23 |
| 文档版本 | v1.0 |
| 最后更新 | 2026-04-04 |
| 维护人 | （填入） |
| 审阅人 | （填入） |

## 0. 摘要

在启用 EEE（Energy Efficient Ethernet）且采用软件定时器控制 LPI（Low Power Idle）进入的场景中，`stmmac` 驱动存在“无条件重启 EEE 控制定时器”的逻辑，导致即便 TX 已成功进入 LPI，系统仍出现稳定的 `1 wakeup/s`。该周期性唤醒会显著抬高系统基线唤醒率，破坏深度 CPU Idle/电源域关断机会，造成待机功耗上升与续航劣化。

永久修复通过“仅在尚未成功进入 LPI（或 TX 队列仍繁忙）时才重启定时器”的方式消除无意义的周期性唤醒。

## 1) 故障背景与影响范围

### 1.1 背景

EEE 旨在降低链路空闲时的 PHY/MAC 功耗。对部分平台，`stmmac` 使用软件定时器周期性检查 TX 是否空闲，并在满足条件后切换到 LPI。

### 1.2 影响范围（技术维度）

- 受影响模块：`stmmac` 的 EEE 软件控制路径（SW timer）。
- 触发条件（典型）：
  - 以太网设备支持 EEE 且被启用。
  - 使用 SW timer 控制 LPI（而非纯硬件自动进入）。
  - 业务层可能处于“网络空闲”或“低吞吐”，更容易长期停留在 LPI。
- 表现：系统维持稳定周期唤醒（典型 `1Hz`），即使网络 TX 已无待处理工作。

### 1.3 影响范围（业务维度）

- 待机/息屏功耗抬升：周期性唤醒会阻碍 CPU cluster 进入更深 C-state，进而影响整机待机电流。
- 体验风险：深睡命中率下降，可能伴随温升/续航/待机时长劣化。
- 可靠性风险：频繁唤醒使得“低功耗路径”被更多次执行，放大竞态/锁竞争等潜在问题暴露概率。

### 1.4 严重性评估建议

| 维度 | 建议阈值 | 说明 |
|---|---:|---|
| `Wakeups/s`（息屏空闲） | > 50 需关注 | 不同平台差异大，建议以基线对比为主 |
| 固定周期唤醒（如 1Hz） | 发现即处理 | 高度可疑，通常是软件定时器/轮询 |
| C-state 深度占比下降 | > 10% 需关注 | 需结合平台支持的 cpuidle states |

## 2) 故障发生时间线及关键日志/截图

本案例基于上游缺陷与修复提交进行培训复盘。若用于内部真实事故复盘，请在下表补齐“现场时间点、版本号、设备型号、采集日志与截图”。

### 2.1 上游时间线（可验证）

| 时间（UTC+8） | 事件 | 证据 |
|---|---|---|
| 2022-01-23 | 上游提交修复 | `c74ead223deb88bdf18af8c772d7ca5a9b6c3c2b` |
| 2022-xx-xx | 进入主线版本 | `v5.17-rc2` 起包含（可用 `git tag --contains` 验证） |

### 2.2 内部事故时间线模板（需填充）

| 时间 | 事件 | 负责人 | 关键证据（日志/截图/链接） |
|---|---|---|---|
| T0 | 监控告警：待机功耗回归 | （填入） | （填入） |
| T0+1h | 复现确认：息屏 `wakeups/s` 异常 | （填入） | powertop 截图、Perfetto trace |
| T0+2h | 定位：`stmmac` EEE SW timer 1Hz 唤醒 | （填入） | ftrace/BPF 统计、`ethtool --show-eee` |
| T0+4h | 临时规避：禁用 EEE 或 SW timer | （填入） | 配置变更记录 |
| T0+1d | 永久修复：回合入/回合入上游补丁 | （填入） | 提交号、合入分支 |
| T0+2d | 回归测试通过 & 关闭告警 | （填入） | 测试报告 |

### 2.3 关键日志/截图清单（建议采集）

**现场截图（建议）**

- powertop：Overview 页面的 `Wakeups/s` 与 Top Wakeups。
- CPU idle：`/sys/devices/system/cpu/cpuidle/`（或平台特定）统计页。
- Perfetto：`sched_wakeup`、`irq_handler_entry/exit`、`timer` 相关轨迹。

**现场日志（建议）**

- `dmesg -T`（包含网卡驱动初始化与 EEE 配置）。
- `ethtool --show-eee ethX`（EEE 是否启用，是否 active）。
- `/proc/interrupts`（确认是否存在与网卡相关的 IRQ 持续增长）。
- ftrace：
  - `timer:timer_expire_entry` / `timer:timer_expire_exit`
  - `irq:irq_handler_entry` / `irq:irq_handler_exit`
  - `power:cpu_idle`（若平台开启）

**示例：powertop 采集方式（参考）**

```bash
powertop --time=60 --html=powertop_idle_60s.html
```

## 3) 技术根因与业务根因的逐层剖析

### 3.1 技术根因（直接原因）

缺陷点：EEE 控制定时器回调在“已成功进入 LPI”时仍然持续 `mod_timer()`，造成周期性唤醒。

上游修复提交的信息（原文要点）：

- “SW timer cause `1 wakeup/s` even if the TX has successfully entered EEE.”
- “Only calling `mod_timer()` if we haven't successfully entered EEE.”

**修复前（问题模式，逻辑示意）**

```text
timer_cb():
  try_enter_lpi()
  mod_timer(+1s)   # 无条件重启 -> 永久 1Hz 唤醒
```

**修复后（正确模式，逻辑示意）**

```text
timer_cb():
  if (tx_busy || lpi_not_entered_yet)
     mod_timer(+1s)
  else
     stop_rearming  # 已在 LPI，无需周期唤醒
```

对应代码变更文件：

- `drivers/net/ethernet/stmicro/stmmac/stmmac_main.c`

### 3.2 技术根因（系统层放大机制）

周期性唤醒的代价不止是“执行一次回调”，它会引发一连串系统级连锁反应：

1. `tick_nohz`/cpuidle 预测被打断，深度 idle state 的驻留时间（residency）被稀释。
2. 对支持 OSI 的平台：genpd CPU governor 会基于 `next_hrtimer` 等最短唤醒约束进行裁决，稳定 1Hz 会显著降低电源域断电机会。
3. 即使单次唤醒开销较小，长时间待机场景会线性积累为显著的电量损耗。

### 3.3 业务根因（过程/管理层）

| 类别 | 典型问题 | 建议治理 |
|---|---|---|
| 需求层 | “开启 EEE 必然省电”的假设未验证 | 引入 SoT（Source of Truth）功耗基线与回归门禁 |
| 设计层 | SW timer 方案缺少“进入成功后停止轮询”的设计约束 | 设计评审加入“长驻低功耗态禁止周期轮询”检查项 |
| 测试层 | 没有覆盖“网络空闲长期待机”场景的持续时长测试 | 引入 8h/24h 待机场景 + 唤醒源排名 |
| 监控层 | 只监控平均功耗，不监控“周期性唤醒特征” | 增加 0.5–2Hz 周期唤醒检测与告警 |

## 4) 临时修复与永久修复的完整步骤

### 4.1 临时修复（线上止血）

目标：在不升级内核的前提下快速降低唤醒率，恢复待机功耗。

**方案 A：禁用 EEE（优先级最高，风险最低）**

```bash
ethtool --set-eee eth0 eee off
ethtool --show-eee eth0
```

适用：业务允许牺牲少量链路空闲功耗，换取系统级深睡收益。

**方案 B：驱动/平台侧关闭 EEE SW timer（如平台支持配置项）**

- 具体开关因 SoC/板级适配不同而不同，可能是 device tree property、模块参数或 Kconfig。
- 若已有产品化开关，请在此处填写：
  - 配置项：`（填入）`
  - 生效方式：`（填入）`
  - 回滚方式：`（填入）`

**方案 C：CPU Hotplug/调度隔离（仅应急）**

当唤醒主要集中于某类 IRQ 或仅在特定 cluster 影响显著时，可临时通过隔离策略降低影响面，但不建议作为长期方案。

### 4.2 永久修复（代码级修复）

目标：从根因消除无意义的周期性唤醒。

**方案：回合入上游修复提交**

1. 确认当前分支是否已包含修复：

```bash
git tag --contains c74ead223deb88bdf18af8c772d7ca5a9b6c3c2b | head
```

2. 若未包含，进行 backport：

```bash
git cherry-pick -x c74ead223deb88bdf18af8c772d7ca5a9b6c3c2b
```

3. 冲突处理（如有）：重点检查 `stmmac` EEE 相关逻辑是否等价；避免将“仅在未成功进入 LPI 时 rearm timer”的语义破坏。

4. 代码审查要点：

- 是否仍存在周期性 `mod_timer()` 在“已经进入 LPI”情况下被执行。
- 是否会在 TX 恢复忙碌时重新启用检查（避免功能回退）。
- 定时器生命周期：关闭/卸载路径是否 `del_timer_sync` / `timer_delete_sync` 配套。

## 5) 验证测试方法与结果

### 5.1 验证目标

- 消除 `1 wakeup/s` 特征。
- 待机场景 `Wakeups/s` 显著下降（相对基线）。
- EEE 功能不回退：在网络空闲时仍可进入 LPI；在 TX 活跃时不误入 LPI。

### 5.2 测试方法（建议组合）

**方法 A：powertop 对比（推荐）**

1. Bug 版本：息屏、断网/静默业务条件下采集 60s。
2. Fix 版本：相同条件再采集 60s。
3. 对比 `Wakeups/s` 与 Top Wakeups 中是否存在稳定 1Hz 计时器来源。

**方法 B：ftrace 观察定时器回调频率**

参考流程（示意）：

```bash
echo 0 > /sys/kernel/tracing/tracing_on
echo nop > /sys/kernel/tracing/current_tracer
echo 1 > /sys/kernel/tracing/events/timer/timer_expire_entry/enable
echo 1 > /sys/kernel/tracing/events/timer/timer_expire_exit/enable
echo 1 > /sys/kernel/tracing/tracing_on
sleep 60
echo 0 > /sys/kernel/tracing/tracing_on
cat /sys/kernel/tracing/trace | grep -i stmmac | head
```

注意：不同版本 trace 文本中可能不直接包含函数名；可结合 `available_filter_functions` 或使用 BPF kprobe。

**方法 C：EEE 状态验证**

```bash
ethtool --show-eee eth0
```

关注字段：EEE 是否启用、是否 active、是否进入 LPI（取决于驱动输出）。

### 5.3 结果记录模板（需填充）

| 项目 | 修复前 | 修复后 | 结论 |
|---|---:|---:|---|
| `Wakeups/s`（60s 平均） | （填入） | （填入） | 下降/持平 |
| 周期性 1Hz 特征 | 有/无 | 有/无 | 必须消失 |
| EEE 功能（空闲进入 LPI） | 正常/异常 | 正常/异常 | 不得回退 |
| 网络吞吐/稳定性 | 正常/异常 | 正常/异常 | 不得回退 |

## 6) 后续监控与告警优化方案

### 6.1 监控指标建议

- `Wakeups/s`（息屏/待机场景，按机型/版本分桶）。
- 周期性唤醒检测：频谱在 `0.5–2Hz` 区间的尖峰（典型软件定时器/轮询）。
- 关键电源域指标：cluster 进入深 idle 的占比、平均 residency。

### 6.2 告警策略建议

- 相对基线告警：同机型同版本对比上一个稳定版本，超过阈值触发。
- 规则告警：检测到稳定周期（如 1Hz）且持续超过 N 分钟。
- 黑白名单：允许少数系统服务在特定场景产生周期唤醒，但需显式登记。

### 6.3 自动归因建议

- Top wakeup source 自动汇总：定时器回调、irq 号、进程名、CPU 亲和性。
- 关联配置快照：EEE/网卡省电策略、irq affinity、cpuidle/cpufreq governor。

## 7) 同类故障排查 SOP 与应急手册

### 7.1 快速 SOP（15–30 分钟定位）

```mermaid
flowchart TD
  A[发现待机功耗/唤醒率回归] --> B[确认场景一致: 息屏/网络空闲/相同版本配置]
  B --> C[powertop/Perfetto: 是否存在稳定周期唤醒(0.5–2Hz)]
  C -->|是| D[定位来源: timer vs irq]
  D --> E1[若 timer: ftrace/BPF 找到回调符号/模块]
  D --> E2[若 irq: /proc/interrupts + irq affinity]
  E1 --> F1[检查是否为驱动轮询/保活定时器]
  F1 --> G1[应急: 关闭该功能开关(EEE/轮询)或延迟/合并定时器]
  E2 --> F2[应急: 迁移 IRQ 到忙核/唤醒核, 或禁用不必要 wake IRQ]
  G1 --> H[回归验证: wakeups/s + C-state]
  F2 --> H
```

### 7.2 应急手册（面向线上）

- 首选止血：关闭 EEE（或对应省电特性）并记录变更。
- 若必须保留 EEE：降低 SW timer 触发频率或改为“进入成功后停轮询”（需要代码改动）。
- 禁止线上高频 cpu hotplug 来回切换（易引入卡顿与额外风险）。

### 7.3 排查 Checklist（同类问题通用）

- 是否存在无条件 `mod_timer()` / `queue_delayed_work()` 形成固定周期？
- 是否缺少“成功进入低功耗态后停止轮询”的状态机分支？
- 是否用 `hrtimer` 精确定时做“非关键轮询”（应使用 slack/range 或 deferrable timer）？
- 是否正确使用 `PM QoS` 约束（避免因过严约束导致永不关电）？
- IRQ affinity 是否导致空闲核被持续打断？

## 8) 培训方案（对象、时长、考核、交付格式）

### 8.1 培训对象

- SoC/平台 BSP 工程师（低功耗、网络驱动方向）。
- Kernel 驱动开发与性能功耗测试工程师。
- 质量/自动化测试团队（负责功耗回归门禁）。

### 8.2 时长与课程结构（建议 90 分钟）

| 环节 | 时长 | 内容 |
|---|---:|---|
| 背景与现象 | 15m | EEE/LPI 基础、1Hz 唤醒对系统深睡影响 |
| 根因走读 | 25m | `stmmac` EEE SW timer 状态机与修复思路 |
| 工具与定位 | 25m | powertop、ftrace/BPF、Perfetto 的组合打法 |
| 修复与验证 | 15m | 临时止血与 backport 规范，回归用例 |
| 讨论与问答 | 10m | 扩展到“所有轮询类定时器”的治理 |

### 8.3 考核方式（建议）

- 现场实操：给定一个“固定周期唤醒”样本 trace，要求 30 分钟内定位到模块与触发点。
- 书面测验：5 题选择 + 2 题简答（围绕 timer 合并、deferrable、IRQ affinity）。
- 交付物：提交一份复盘摘要（1 页）+ 一份 SOP 执行记录（含证据链）。

### 8.4 交付格式与版本控制

- Wiki：本 Markdown 可直接发布，保留“文档编号/版本/维护人”。
- PDF：建议使用 `pandoc` 从 Markdown 生成并归档。
  - 生成命令示例：`pandoc case11_stmmac_eee_timer_wakeup.md -o case11_stmmac_eee_timer_wakeup.pdf`
- PPT：建议用 Marp/Reveal.js 从 Markdown 生成（或抽取“摘要/时间线/图表/Checklist”四页模板）。
  - Marp 示例：`marp case11_stmmac_eee_timer_wakeup.md --pdf`

## 附录 A：上游修复提交（引用）

- 提交：`c74ead223deb88bdf18af8c772d7ca5a9b6c3c2b`
- 标题：`net: stmmac: reduce unnecessary wakeups from eee sw timer`
- 关键改动：仅在未进入 EEE/LPI 时才重启 EEE 控制定时器。

