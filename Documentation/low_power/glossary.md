# PM / Low Power 术语表（工作用）

本表用于统一文档与讨论中的用词，减少“同词异义/异词同义”。

## System Sleep（系统级睡眠）

- `suspend-to-idle` / `s2idle`：轻量系统睡眠形态，平台不一定真正断电，常依赖设备 runtime PM 与 tick/nohz 条件。
- `suspend-to-RAM` / `mem`：典型深睡形态，平台侧进入更深的低功耗（通常涉及 PSCI/固件/电源域断电）。
- `hibernate`：写镜像到存储后断电，恢复时再读回。

## Runtime PM（设备运行时省电）

- `runtime_suspend` / `runtime_resume`：设备在系统运行过程中按需关/开。
- `autosuspend`：延迟自动进入 runtime_suspend 的机制。
- `usage_count`：runtime PM 引用计数，通常必须与 get/put 成对。

## CPU Idle / CPUFreq

- `cpuidle`：CPU 空闲态框架与 governor，决定进哪个 C-state。
- `cpufreq`：CPU 频率框架与 governor，决定跑哪个 OPP/频点。
- `residency`：进入某个 idle state 的最小驻留阈值（过短会不划算）。
- `latency`：退出 idle state 的唤醒延迟。

## genpd / Power Domain

- `genpd`：通用电源域框架，把设备依赖表达为域的上下电顺序。
- `pm_genpd_summary`：debugfs 汇总，常用于判断“域为什么没关”。

## Wakeup

- `wakeup source`：统一的唤醒事件计数与控制抽象，用于解释“是谁不让睡/是谁唤醒”。
- `wakeirq`：将设备 IRQ 作为 wakeup IRQ 绑定的一种机制。
- `IRQ affinity`：中断亲和性，配置不当会造成空闲核被持续唤醒。

## QoS / 约束

- `PM QoS`：延迟/性能约束接口，会限制能进入多深的省电状态。
