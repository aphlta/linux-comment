# PM QoS 实战与排障

本章目标：当系统“睡不下去/唤醒延迟异常/性能被强行拉高”时，快速判断是否被 QoS 约束卡住，并定位是谁在持有约束。

## 1. 你需要先问清楚的三个问题

- 现象是“进不去深 idle”（C-state 不深）还是“进得去但功耗不降”？
- 是 system sleep（`mem/s2idle`）问题，还是 runtime 场景（屏幕灭/用户态 idle）问题？
- 约束是“CPU latency”类（影响 cpuidle 深度），还是“device latency/flags”类（影响设备/域关电）？

## 2. 常见 QoS 入口（读者定位用）

### 2.1 CPU latency QoS

- 内核接口：`cpu_latency_qos_add_request()` / `cpu_latency_qos_update_request()`
- 典型持有者：音频、显示、交互类（低延迟需求）、部分厂商策略模块

### 2.2 Device PM QoS

- 内核接口：`dev_pm_qos_add_request()` / `dev_pm_qos_update_request()`
- 常见形态：限制设备进入深度低功耗、或暴露 sysfs 以供用户态设置

### 2.3 用户态接口

- 典型 sysfs：
  - `/dev/cpu_dma_latency`（传统接口，会影响 CPU idle latency 约束）
  - 设备节点 `power/*` 相关（不同平台差异大）

## 3. 快速自检流程（10 分钟内给出结论）

### 3.1 先用“证据包”固化现场

- 用脚本抓一份 before/after：[`scripts/power/collect_idle_baseline.sh`](../../scripts/power/collect_idle_baseline.sh)
- 同时留存：`/proc/interrupts`、`wakeup_sources`、`pm_genpd_summary`（若可用）

### 3.2 判断是否存在 QoS 约束痕迹

- 观测点（经验）：
  - 深 idle state 的 `usage/time` 几乎不增长，但 wakeup 并不高
  - system sleep（尤其 s2idle）阶段出现“回环忙”等现象
  - 排除 wakeup 风暴后，仍然不进深态

### 3.3 定位“谁在持有”

按优先级从“最可能/最便宜”开始：

- 用户态：是否有进程打开了 `/dev/cpu_dma_latency`
- 内核侧：找 QoS request 创建/更新的调用点

## 4. 定位手段（工程化）

### 4.1 ftrace / trace-cmd

建议自定义一组 trace 关注点：

- `power` / `irq` / `timer`（基线）
- 若平台支持：增加 QoS 相关 tracepoint（视内核版本/配置）

### 4.2 “从代码反推持有者”的定位路径

当你知道约束类型，但不知道模块：

- 全局搜索 `cpu_latency_qos_add_request` / `dev_pm_qos_add_request`
- 再看对应模块是否暴露了用户态开关

## 5. 输出结论的模板

结论应满足：可复现、可验证、可回归。

- 约束类型：CPU latency / device latency / flags
- 持有者：进程/驱动/策略模块
- 证据：证据包目录名 + trace 片段 + 对比数据
- 修复方式：删除/收敛/按场景动态更新 + 回归守护
