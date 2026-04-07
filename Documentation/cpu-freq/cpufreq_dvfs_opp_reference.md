# CPUFreq / OPP / DVFS 参考手册（Linux 5.15+）

面向：SoC/BSP/内核驱动/低功耗工程师  
范围：Linux 5.15+ 主线内核通用机制（cpufreq 核心、governor、OPP、regulator、CCF、thermal、QoS、trace）  

本文件目标：可直接并入文档仓库，作为 cpufreq/OPP/DVFS 的“产品级”参考文档，覆盖原理、数据结构、接口、关键路径、调试与测试方法。

---

## 0. 术语与边界

- **DVFS**：动态电压频率调整，常见约束是“升频先升压、降频先降频后降压”。
- **OPP（Operating Performance Points）**：离散的“性能点”集合，至少包含频率与电压，还可扩展为带宽、性能等级、时延等属性。
- **cpufreq**：CPU 频率调节子系统，向用户空间暴露 policy/governor/sysfs，并与调度器（schedutil）协作。
- **Regulator**：电压调节框架，负责与 PMIC/电源管理固件通信。
- **CCF（Common Clock Framework）**：时钟树框架，CPU/cluster/PLL 的频率切换最终落在 clk_set_rate/clk_round_rate。
- **genpd / PM domain**：电源域框架；与 OPP 的“performance state（opp-level）”可耦合。

边界说明：
- 本文聚焦 **cpufreq 与 OPP 框架** 的主线机制。ACPI 平台的 P-state 往往通过 CPPC/PSS 等接口实现，**不使用 DT OPP bindings**（见 §1.2 的 ACPI 说明）。
- Android/厂商内核可能存在 interactive/boost 等扩展 trace 或 governor。Linux 5.15 主线常用 tracepoint 是 `power:cpu_frequency` 与 `power:cpu_frequency_limits`（见 §6.2）。

---

## 1. 核心原理

### 1.1 频率-电压-功耗三角关系与硅器件基础

CPU 动态功耗（主导项）近似：

- 动态功耗：`P_dyn ≈ α · C · V^2 · f`
  - `α`：活动因子（翻转概率），与 workload/微结构有关
  - `C`：等效电容（与工艺/单元库/布局相关）
  - `V`：电压（通常是 VDD_CPU / VDD_CORE）
  - `f`：时钟频率
- 泄漏功耗：`P_leak` 与 `V`、`T`（温度）强相关，且在先进工艺与高温下占比显著上升。

物理约束（决定“OPP 表为什么是离散而不是连续”）：
- **时序闭合**：对给定工艺角（PVT）与目标频率 `f`，存在最低可用电压 `Vmin(f, PVT)`，过低会导致 setup/hold 违例。
- **电源完整性（IR drop / di/dt）**：频率与负载变化引入电流瞬态，电压轨需要留 margin（这解释了 `opp-microvolt` 可能是 `<target min max>` 三元组）。
- **PLL/时钟树锁定与分频器**：频率切换具有不可忽略的延迟（`clock-latency-ns`），并可能受上游时钟共享约束。

DVFS 的基本安全序（在 OPP/driver 中必须遵守）：
- **升频（f↑）**：先升压（V↑）再升频（f↑）
- **降频（f↓）**：先降频（f↓）再降压（V↓）

OPP 框架在通用实现里明确按“先电后钟/先钟后电”的顺序组织操作：  
见 OPP 核心 `_set_opp()` 的 scaling_up/scaling_down 分支：[core.c](file:///home/alex/linux-stable/drivers/opp/core.c#L1232-L1336)

#### 检查清单（原理）
- DVFS 升降序是否满足“升压先于升频、降频先于降压”
- 是否为 IR drop/温度/老化留足电压 margin（Vmin/Vmax/容差）
- 是否评估 PLL 锁定、时钟切换与 regulator settling 的最坏时延

### 1.2 OPP 表数据结构与 DT/ACPI 定义规范

#### 1.2.1 关键数据结构（OPP 内核侧）

- **struct dev_pm_opp**：单个 OPP 实例（频率、电压、带宽、level、required_opps 等）  
  位置：[opp.h](file:///home/alex/linux-stable/drivers/opp/opp.h#L108-L134)
- **struct opp_table**：设备 OPP 表（OPP 列表、共享/独占、DT 节点、clks/regulators/ICC、current_opp 等）  
  位置：[opp.h](file:///home/alex/linux-stable/drivers/opp/opp.h#L206-L250)
- OPP 对外 API 头文件：[pm_opp.h](file:///home/alex/linux-stable/include/linux/pm_opp.h)
- OPP 文档（原理与 API 综述）：[opp.rst](file:///home/alex/linux-stable/Documentation/power/opp.rst)

#### 1.2.2 DeviceTree：OPP v2 bindings（推荐）

主线推荐使用 `operating-points-v2`（OPP v2），典型结构：

- CPU 节点引用 OPP 表：`operating-points-v2 = <&cpu_opp_table>;`
- OPP 表节点：`compatible = "operating-points-v2";`
- 每个 OPP 子节点中常见属性：
  - `opp-hz`：频率（64-bit）
  - `opp-microvolt`：电压，可为 `<target>` 或 `<target min max>`  
  - `clock-latency-ns`：时钟切换时延（用于调度/频率切换延迟建模）
  - `turbo-mode`：turbo OPP 标记
  - `opp-suspend`：挂起（suspend）优选 OPP
  - `opp-supported-hw`：按芯片版本/熔丝/工艺 bin 过滤
  - `opp-shared`：CPU 之间共享 DVFS 状态（通常对应同一 policy/cluster）

Bindings 参考（含多种示例与约束语义）：  
[opp-v2.yaml](file:///home/alex/linux-stable/Documentation/devicetree/bindings/opp/opp-v2.yaml)

OPP v1（旧式 `operating-points` 矩阵）仅用于兼容：  
[opp-v1.yaml](file:///home/alex/linux-stable/Documentation/devicetree/bindings/opp/opp-v1.yaml)

OPP v2 的解析入口：  
`dev_pm_opp_of_add_table()`：[of.c](file:///home/alex/linux-stable/drivers/opp/of.c#L1177-L1213)

#### 1.2.3 ACPI：OPP 的位置与替代机制

在 ACPI 生态中，CPU 性能状态通常通过：
- **CPPC**（Continuous Performance Control）/AMD-Pstate/Intel-Pstate
- **PSS**（传统 ACPI P-states）

这类路径一般不依赖 DT OPP bindings；因此“OPP 表在 ACPI 中的定义”通常不表现为 `operating-points-v2` 的 schema，而由 ACPI 固件对象与 cpufreq driver（如 amd-pstate、intel_pstate、cppc_cpufreq）实现性能域控制。

参考文档（ACPI/CPPC sysfs）：[cppc_sysfs.rst](file:///home/alex/linux-stable/Documentation/admin-guide/acpi/cppc_sysfs.rst)

#### 检查清单（OPP 定义）
- DT 是否使用 OPP v2（`operating-points-v2`），并为 CPU 节点正确引用
- OPP 条目是否包含电压与 `clock-latency-ns`（若平台具备显著切换时延）
- 是否正确声明 `opp-shared`（共享 policy/cluster）或独立切换模式
- 是否使用 `opp-supported-hw` 按 bin/版本过滤，避免不可达 OPP

### 1.3 cpufreq 与 OPP 框架的耦合接口

cpufreq 与 OPP 的典型耦合关系：
- cpufreq core/governor 负责决定目标频率（policy/负载/调度器驱动）
- 平台 cpufreq driver 负责“把频率变更落地到硬件”
- 落地通常需要同时操作 clock 与 regulator（DVFS），OPP 框架提供“由频率索引 OPP、按安全序执行调压/调频”的通用基础设施

关键 API：
- cpufreq driver 注册：
  - `cpufreq_register_driver()`：[cpufreq_register_driver](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L3000-L3064)
- OPP 表注册（DT）：
  - `dev_pm_opp_of_add_table()`：[dev_pm_opp_of_add_table](file:///home/alex/linux-stable/drivers/opp/of.c#L1177-L1213)
  - CPU 批量：`dev_pm_opp_of_cpumask_add_table()`：[dev_pm_opp_of_cpumask_add_table](file:///home/alex/linux-stable/drivers/opp/of.c#L1244-L1287)
- OPP 运行期切换（适用于非 CPU 设备；CPU 多由 driver 自己串联 regulator/clk 或通过平台封装）：
  - `dev_pm_opp_set_rate()` / `dev_pm_opp_set_opp()`：[dev_pm_opp_set_rate](file:///home/alex/linux-stable/drivers/opp/core.c#L1338-L1414)

建议实践（CPU 路径）：
- CPU cpufreq driver 通常维护 `cpufreq_frequency_table`，并在 `->target_index()` 中按 index 找频率，再通过 OPP API 找电压并执行 DVFS（示例见 i.MX6）：  
  [imx6q_set_target](file:///home/alex/linux-stable/drivers/cpufreq/imx6q-cpufreq.c#L60-L107)

---

## 2. governor 算法剖析

### 2.1 performance/powersave、userspace、ondemand、conservative、schedutil

#### 2.1.1 performance / powersave

- **performance**：将 policy 频率钳制到 `policy->max`（或尽可能高），强调性能一致性与最低延迟。
- **powersave**：将 policy 频率钳制到 `policy->min`（或尽可能低），强调静态节能与热/噪声控制。

它们本质是“极端策略”，用于：
- 基线性能/功耗测量（对比其他 governor）
- 规避调频抖动（对实时/音视频场景）

#### 2.1.2 userspace

- **userspace**：由用户空间写入目标频率（`scaling_setspeed`）驱动变更。  
  sysfs 写入路径：`store_scaling_setspeed()` → `__cpufreq_driver_target()`  
  见：[store_scaling_setspeed](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L950-L966)，[cpufreq_set](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq_userspace.c#L31-L47)

适用：
- 工厂测试/实验场景、确定性调频需求
- 与用户空间功耗策略协作（Android/embedded 常见）

#### 2.1.3 ondemand / conservative（DBS：周期采样型）

二者都基于周期性采样（sampling_rate）与 CPU “忙碌度（busy%）”估计：
- 公共 load 计算在 `dbs_update()`：通过 idle time 与 elapsed time 推出 `load = busy%`；并支持 ignore_nice、io_is_busy 等修正。  
  见：[dbs_update](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq_governor.c#L114-L231)

**ondemand**（激进升频）：
- 若 `load > up_threshold`：直接升到 max（或受 powersave_bias 影响）
- 否则按比例计算 `freq_next = min_f + load*(max_f-min_f)/100`  
  见：[od_update](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq_ondemand.c#L131-L170)

**conservative**（渐进升降）：
- 超过 `up_threshold`：按 `freq_step`（max 的百分比）逐步上升
- 低于 `down_threshold` 且达到 `sampling_down_factor` 周期：按 `freq_step` 逐步下降  
  见：[cs_dbs_update](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq_conservative.c#L58-L145)

DBS 的关键特性：
- 采样窗口与 TICK/NOHZ 交互复杂，突发负载会触发“复用 prev_load”的保护逻辑，以避免被误判为低负载（减少延迟尖刺）。  
  见 `dbs_update()` 中“idle_time > 2*sampling_rate 复用 prev_load”的分支：[cpufreq_governor.c](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq_governor.c#L181-L207)

#### 2.1.4 schedutil（调度器驱动型）

schedutil 以调度器的 util/capacity 模型为输入，按“util 比例映射”计算目标频率。

关键公式（见内联函数与实现注释）：
- util→freq 映射：`map_util_freq(util, ref_freq, cap) = ref_freq * util / cap`  
  [sched/cpufreq.h](file:///home/alex/linux-stable/include/linux/sched/cpufreq.h#L26-L35)
- util headroom：`map_util_perf(util) = util + util/4`（等效 1.25 倍）  
  [sched/cpufreq.h](file:///home/alex/linux-stable/include/linux/sched/cpufreq.h#L32-L35)
- `get_next_freq()` 注释明确给出：在 freq-invariant 情况下 `next_freq = C * max_freq * util / max`（C≈1.25），否则 `next_freq = C * curr_freq * util_raw / max`。  
  见：[get_next_freq](file:///home/alex/linux-stable/kernel/sched/cpufreq_schedutil.c#L169-L205)

IOWait boost：
- 调度器可通过 flags 传入 `SCHED_CPUFREQ_IOWAIT`，sugov 对 IO 唤醒做短期 boost 并逐步衰减。  
  见：[sugov_iowait_boost/apply](file:///home/alex/linux-stable/kernel/sched/cpufreq_schedutil.c#L236-L353)

fast_switch：
- 若 driver 支持 fast_switch，schedutil 可在调度路径调用 `cpufreq_driver_fast_switch()`（RCU-sched 读侧临界区，不可睡眠）。  
  见：[cpufreq_driver_fast_switch 注释](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L2219-L2236)，[schedutil fast_switch 调用](file:///home/alex/linux-stable/kernel/sched/cpufreq_schedutil.c#L520-L535)

#### 检查清单（governor 选择）
- 需要确定性与最小抖动：performance/powersave/userspace
- 需要快速响应突发负载并与 EAS 协作：schedutil
- 需要简单可调且不依赖 util 模型：ondemand/conservative（注意采样参数与 NOHZ 行为）

### 2.2 负载计算模型与频率映射公式

这一节需要区分两类 governor 的输入数据来源。

#### 2.2.1 DBS（ondemand/conservative）：idle-time 采样 → busy%

在每个 sampling 周期：
- 获取 `cur_idle_time` 与 `update_time`
- 计算 `time_elapsed = update_time - prev_update_time`
- 计算 `idle_time = cur_idle_time - prev_cpu_idle`（并修正异常回退）
- 得到 `load = 100 * (time_elapsed - idle_time) / time_elapsed`

I/O wait 的权重控制：
- `io_is_busy=1` 时，DBS 将 iowait 视为“busy”（不把 iowait 计入 idle），用于更激进地提升频率以缩短 IO completion latency。  
  见注释与 `io_busy` 处理：[cpufreq_governor.c](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq_governor.c#L128-L136)

#### 2.2.2 schedutil：调度器 util/capacity → 频率

schedutil 的关键变量：
- `util`：有效 CPU utilization（融合 CFS boost/rt/dl 等，以及 `map_util_perf` headroom）
- `max_cap`：arch_scale_cpu_capacity() 给出的最大容量（big.LITTLE/异构下不同 CPU 不同 cap）
- `ref_freq`：由 `arch_scale_freq_ref()` 或 max_freq 推导（必要时加 25% margin）  
  见：[get_capacity_ref_freq](file:///home/alex/linux-stable/kernel/sched/cpufreq_schedutil.c#L143-L167)

核心映射：
- `raw = map_util_freq(util, ref_freq, max_cap)`
- `next = cpufreq_driver_resolve_freq(policy, raw)`（按 driver 离散频点取整）  
  见：[get_next_freq](file:///home/alex/linux-stable/kernel/sched/cpufreq_schedutil.c#L191-L205)

#### 检查清单（负载与映射）
- DBS：sampling_rate 是否过大导致响应滞后，过小导致抖动与切换开销增大
- DBS：io_is_busy 是否适配平台（并非所有平台都希望把 iowait 当 busy）
- schedutil：arch_scale_freq_invariant 与容量模型是否正确（否则 util→freq 映射失真）

### 2.3 big.LITTLE / DynamIQ / 异构多核适配差异

#### 2.3.1 policy 颗粒度：每 CPU 还是每 cluster

cpufreq policy 的 `policy->cpus` 代表“同步调频域”（共享时钟与电压的 CPU 集合）：
- DT OPP v2 的 `opp-shared` 通常表示“CPU 在同一 OPP 域同步切换”
- 也可能出现“同一 OPP 表但独立切换”（不含 opp-shared），常见于每核独立供电/独立时钟的设计

实践建议：
- 对 cluster 共享 PLL/电压域的 SoC：使用 `opp-shared` 并让 `policy->cpus` 对齐硬件域
- 对 per-core DVFS（少见）：避免误用 `opp-shared`，否则会造成不必要的同步与切换开销

#### 2.3.2 schedutil/EAS 与异构 CPU 容量

在 big.LITTLE/DynamIQ 下：
- util/capacity 的对齐是关键：小核 `max_cap` 低，大核 `max_cap` 高
- schedutil 的 `map_util_freq(util, ref_freq, max_cap)` 会自然体现容量差异
- EAS（Energy Aware Scheduling）依赖 Energy Model（EM）与 OPP/功耗表，将“任务放在哪个 CPU”与“CPU 跑多快”共同优化

关联点：
- EM 常由 OPP 表推导并用于调度器能耗估计（注意：EM 是“估算模型”，不是测量结果）
- thermal/cpufreq_cooling 也会引用 EM 进行 power allocator（见 §7.1）

#### 2.3.3 DBS governor 在异构上的局限

ondemand/conservative 的 load 基于“busy%”，并不知道“同样 busy% 在大核与小核上的绝对性能差异”，因此：
- 同样 busy% 下，选频策略可能导致：
  - 小核过高频仍不够性能（延迟上升）
  - 大核频率不必要偏高（功耗上升）
- 在启用 EAS 的系统中，通常更推荐 schedutil。

#### 检查清单（异构适配）
- `policy->cpus` 是否与硬件 DVFS 域一致（cluster/per-core）
- 是否启用/校准 freq-invariant 与容量模型（否则 schedutil 会偏离预期）
- EAS 系统优先考虑 schedutil + EM + thermal 共同闭环

---

## 3. 电压域协同（DVFS）

### 3.1 Regulator 框架与 PMIC 通信协议（I2C/SPI/SCMI）

典型数据流：

```
cpufreq governor/policy
  -> cpufreq driver (target_index/fast_switch)
     -> regulator_* (设置电压)
        -> PMIC driver
           -> I2C/SPI bus 或固件接口
```

几种常见实现形态：
- **I2C/SPI PMIC**：regulator 驱动通过 I2C/SPI 写 PMIC 寄存器调压（最常见）。
- **SCMI 电源/性能域**：在部分平台上，Linux 通过 SCMI 将 DVFS 委托给固件，cpufreq driver/opp 或直接通过 SCMI perf/power domain 设置性能状态。  
  cpufreq SCMI driver 参考：[scmi-cpufreq.c](file:///home/alex/linux-stable/drivers/cpufreq/scmi-cpufreq.c)

系统级约束（工程上必须关注）：
- 若 cpufreq 调压依赖 I2C/SPI 控制器，系统 suspend 时需确保“先冻结 cpufreq，再让 I2C/SPI 控制器休眠”，否则可能在调频路径访问已休眠总线导致死锁（见 cpufreq_suspend 的体系设计，平台实现需自检）。

### 3.2 电压时序约束（settling time、clock-latency、voltage-tolerance）

#### 3.2.1 电压设置接口与容差

OPP 框架对 regulator 的通用设置为 triplet：
- `regulator_set_voltage_triplet(min, target, max)`  
  见 OPP 核心 `_set_opp_voltage()`：[core.c](file:///home/alex/linux-stable/drivers/opp/core.c#L966-L989)

DT `opp-microvolt = <target min max>` 的意义：
- target：期望电压
- min/max：允许 PMIC/电源域在容差内选择合适值（包含 margin 与 IR drop 预留）

#### 3.2.2 频率切换的时延建模

切换总时延至少包含：
- **电压变化**：PMIC/电源域的电压 ramp + settling
- **时钟变化**：PLL re-lock、父子时钟切换、分频器更新

OPP 框架提供通用接口读取最大时延（供 governor/调度器/驱动使用）：
- `dev_pm_opp_get_max_clock_latency()` / `dev_pm_opp_get_max_volt_latency()` / `dev_pm_opp_get_max_transition_latency()`  
  声明见：[pm_opp.h](file:///home/alex/linux-stable/include/linux/pm_opp.h#L123-L127)

DT 的 `clock-latency-ns` 是最常见的“时钟切换延迟”输入，schedutil 也会参考 policy 的 transition delay（与 driver/平台参数相关）。

### 3.3 CCF 与 PLL 锁定过程对切换延迟的影响

CPU 频率切换在硬件侧通常涉及：
- PLL 倍频参数重编程与锁定等待
- 切换 CPU 时钟父源（临时切到安全时钟）
- 更新分频器、门控与电压域配合

平台 driver 往往在 `->target_index()` 内实现“安全切换序列”，例如 i.MX6 在升频前先升压，并在 PLL 重编程时做父时钟切换以保证连续性：  
[imx6q_set_target（升压先于调频 + PLL 切换流程）](file:///home/alex/linux-stable/drivers/cpufreq/imx6q-cpufreq.c#L87-L119)

工程建议：
- 将 PLL 锁定与父源切换最坏时延计入 `clock-latency-ns`
- 对共享上游 PLL 的场景，确保“共享域同步调频”或在 CCF/平台层做仲裁（避免多个 consumer 在不同约束下竞争同一 PLL）

#### 检查清单（DVFS 时序）
- regulator 设置是否使用 triplet/容差，是否满足 PMIC 能力与 board 限制
- 切换序列是否覆盖 PLL 锁定/父源切换/分频器更新
- `clock-latency-ns` 是否反映最坏时延（含锁定与软件路径开销）

---

## 4. 切换流程与上下文同步

### 4.1 cpufreq_driver->target_index() 调用链（mutex、cpu_hotplug、RCU）

cpufreq 的“发起切换”来源主要有三类：
- sysfs/userspace 写入目标频率（userspace governor）
  - `store_scaling_setspeed()` → `__cpufreq_driver_target()`  
    [store_scaling_setspeed](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L950-L966)
- DBS governor（ondemand/conservative）工作线程中调用 `__cpufreq_driver_target()`
  - 如 `dbs_freq_increase()` / `cs_dbs_update()` 内部调用  
    [cpufreq_ondemand.c](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq_ondemand.c#L115-L129)，[cpufreq_conservative.c](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq_conservative.c#L114-L140)
- schedutil（调度器驱动）
  - fast_switch：调度路径 `cpufreq_driver_fast_switch()`  
    [schedutil fast_switch](file:///home/alex/linux-stable/kernel/sched/cpufreq_schedutil.c#L520-L535)
  - 否则 deferred work：work 线程调用 `__cpufreq_driver_target()`  
    [sugov_work](file:///home/alex/linux-stable/kernel/sched/cpufreq_schedutil.c#L540-L564)

cpufreq core 的统一入口：
- `__cpufreq_driver_target()`：解析频点、选择 driver 回调（target 或 target_index），并触发 transition begin/end（取决于 flags）  
  [__cpufreq_driver_target](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L2394-L2434)

到 `driver->target_index()` 的路径（典型）：

```
caller (userspace/dbs/schedutil work)
  -> __cpufreq_driver_target(policy, target_freq, relation)
     -> (resolve/round/limits)
     -> __target_index(policy, idx)
        -> cpufreq_freq_transition_begin()
        -> driver->target_index(policy, idx)
        -> cpufreq_freq_transition_end()
```

对应代码：
- `__target_index()` 包裹 begin/end，并支持 intermediate 频率：  
  [__target_index](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L2334-L2392)
- transition 串行化与等待：  
  [cpufreq_freq_transition_begin](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L415-L447)，[cpufreq_freq_transition_end](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L449-L468)

并发与锁要点（按层次）：
- **policy->rwsem**：保护 policy 属性读取/更新，sysfs show/store 自动持锁；结构性变更（online/offline）走写锁。  
  [cpufreq sysfs show/store](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L1024-L1056)
- **policy->transition_lock + transition_wait**：避免并发切换；begin 会等待前一轮切换完成。  
  [transition begin/end](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L415-L468)
- **CPU hotplug 同步**：driver 注册/注销与 online/offline 通过 cpuhp 协作，并用 `cpus_read_lock()` 防止并发热插拔破坏状态一致性。  
  [cpufreq_register_driver](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L3000-L3064)
- **RCU（fast_switch）**：fast_switch 允许在 RCU-sched 读侧临界区调用，不可睡眠，且与 transition notifier 存在互斥约束（见 §4.2）。  
  [cpufreq_driver_fast_switch 注释](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L2219-L2236)

#### 检查清单（切换链路）
- 是否明确区分 `cpufreq_driver_target()`（带 policy->rwsem）与 `__cpufreq_driver_target()`（不加锁）
- driver->target_index 是否可睡眠、是否会访问可能在 suspend 中关闭的总线/时钟
- 是否评估 fast_switch 路径的限制（不可睡眠、不可触发阻塞 notifier）

### 4.2 频率变更通知链（CPUFREQ_TRANSITION_NOTIFIER）的响应动作

cpufreq 提供两类 notifier：
- **Transition notifier**：`CPUFREQ_TRANSITION_NOTIFIER`，事件 `CPUFREQ_PRECHANGE/POSTCHANGE`  
  常用于“频率变化对时间/容量/功耗模型的联动更新”
- **Policy notifier**：`CPUFREQ_POLICY_NOTIFIER`，事件 `CPUFREQ_CREATE_POLICY/REMOVE_POLICY`

接口定义：
- [cpufreq notifier 常量与 API](file:///home/alex/linux-stable/include/linux/cpufreq.h#L511-L546)

Transition notifier 的实现与调用链：
- 调用 `srcu_notifier_call_chain(&cpufreq_transition_notifier_list, PRE/POST, freqs)`  
  [cpufreq_notify_transition](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L341-L400)

fast_switch 与 notifier 的互斥约束：
- 由于 fast_switch 发生在调度路径，不能执行可能睡眠/耗时的 notifier 链，因此 cpufreq core 对“启用 fast_switch”与“注册 transition notifier”做互斥检查。  
  [cpufreq_register_notifier 互斥逻辑](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L2128-L2172)，[cpufreq_enable_fast_switch 拒绝并打印 notifier](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L491-L520)

典型响应点（示例）：
- 时间基准：x86 TSC 会注册 cpufreq notifier 以处理频率变化对时钟源的影响：  
  [tsc.c](file:///home/alex/linux-stable/arch/x86/kernel/tsc.c)
- 拓扑/容量：架构拓扑可能更新容量/频率相关信息：  
  [arch_topology.c](file:///home/alex/linux-stable/drivers/base/arch_topology.c)

主线 tracepoint（与用户空间观测强相关）：
- `power:cpu_frequency` / `power:cpu_frequency_limits`  
  定义见：[power.h](file:///home/alex/linux-stable/include/trace/events/power.h#L204-L220)，文档见：[events-power.rst](file:///home/alex/linux-stable/Documentation/trace/events-power.rst#L18-L47)

关于“cpufreq_interactive_boost”：
- Linux 5.15 主线内核中未包含该 trace/event 名称；若在 Android common 或厂商树中存在，应以该树为准。
- 主线环境建议用 `power:cpu_frequency`、schedutil 的 iowait boost 行为与 QoS/thermal 事件联合分析（见 §6.2、§7.2）。

#### 检查清单（notifier）
- 是否需要 transition notifier（时间基准/容量/外设联动）并评估与 fast_switch 的冲突
- PRE/POST 阶段是否有严格的时序要求（例如必须在 POST 才更新某些依赖当前频率的缓存）

### 4.3 跨 cluster 同步与电源域（pd）的级联状态机

跨 cluster 的同步问题通常分为两类：

#### 4.3.1 共享电压域/共享 PLL 的跨 cluster 同步

当多个 CPU cluster 共享某个上游资源（电压 rail 或 PLL）：
- 需要在平台层建立仲裁与约束合并（最保守是取更高的电压/更低的频率约束）
- DT 层可以通过 OPP 表与 `opp-shared` 表达“共享 DVFS 域”，但跨 cluster 的共享并不总能用单个 `opp-shared` 直接描述，往往需要平台驱动/电源域框架参与

#### 4.3.2 PM domain 性能等级（opp-level）与 required-opps 级联

OPP 框架不仅能设置 clk/regulator，还可以：
- 通过 `dev_pm_domain_set_performance_state(dev, level)` 请求 PM domain 性能状态  
  见 `_set_opp_level()`：[core.c](file:///home/alex/linux-stable/drivers/opp/core.c#L1112-L1131)
- 通过 required-opps 先后顺序实现“依赖域”的联动（升频前先把依赖域拉到足够性能）  
  `_set_opp()` 在 scaling_up 时会先调用 `_set_required_opps(..., up=true)`，scaling_down 时在调频后再降依赖域。  
  [core.c](file:///home/alex/linux-stable/drivers/opp/core.c#L1262-L1326)

这对典型 SoC 的“CPU ↔ L3/DSU ↔ interconnect ↔ memory”协同非常关键：
- CPU 提升频率可能需要更高的 DSU/L3/NoC 性能状态与带宽
- 降频时可在 CPU 降下来后再逐步释放依赖域资源

#### 检查清单（跨域同步）
- 是否存在共享 rail/PLL 的跨 cluster 资源，需要仲裁合并约束
- 是否使用 opp-level/required-opps 建模“依赖域级联”，并保证升降序一致
- 是否评估切换对 interconnect/带宽的联动（OPP 的 bandwidth 字段与 ICC）

---

## 5. 性能与功耗测量

### 5.1 perf stat、powercap、energy_model 获取能耗数据

#### 5.1.1 perf stat（性能计数与间接指标）

典型命令（按场景选择事件）：

```bash
perf stat -a -d -- sleep 5
perf stat -C 0 --per-core -e cycles,instructions,branches,branch-misses,cache-misses -- sleep 5
```

注意：
- perf 提供的是性能计数，能耗需结合平台能量计量（RAPL/INA/PMIC/SoC energy counter）或外部功耗仪。

#### 5.1.2 powercap（典型用于 x86 RAPL）

```bash
ls -R /sys/class/powercap 2>/dev/null | head
```

若系统具备 RAPL，可通过 energy_uj 读取能量累积并计算功耗（ΔE/Δt）。

#### 5.1.3 energy_model（EM：能耗估算模型）

EM 是调度器/thermal power allocator 使用的“功耗估算表”，并非测量值：
- 可用于对比不同 OPP 的“相对能耗趋势”
- 可用于 EAS/thermal 决策一致性检查

关联实现与使用点：
- EM 框架：[energy_model.c](file:///home/alex/linux-stable/kernel/power/energy_model.c)
- thermal/cpufreq_cooling 读取 EM perf state（RCU 保护）：  
  [cpufreq_cooling.c](file:///home/alex/linux-stable/drivers/thermal/cpufreq_cooling.c#L89-L120)

#### 检查清单（测量数据源）
- 是否拥有真实能量计量（RAPL/SoC counter/外部仪表）
- perf 事件是否与 workload 相关（避免用不敏感指标推断功耗）
- 是否明确区分“EM 估算”与“真实测量”

### 5.2 吞吐量-延迟-功耗三维评估矩阵与阈值

建议建立统一的三维指标矩阵（每个场景一张表），并定义可接受阈值：

| 场景 | 吞吐量（例如 ops/s） | 延迟（P50/P95/P99） | 平均功耗（W） | 峰值功耗（W） | 温度峰值（°C） |
|---|---:|---:|---:|---:|---:|
| UI/交互 |  |  |  |  |  |
| 编译/后台 |  |  |  |  |  |
| 网络/IO |  |  |  |  |  |
| 音视频 |  |  |  |  |  |

阈值策略（示例方法论）：
- 延迟：对交互路径定义 P95/P99 的硬阈值（例如 P99 < X ms）
- 吞吐：对批处理定义最低吞吐阈值（例如 ops/s ≥ baseline 的 Y%）
- 功耗：对散热能力设定持续功耗上限（例如 steady-state ≤ TDP 或壳温目标）

### 5.3 governor 回归测试方案（cyclictest/hackbench/sysbench）

目标：验证 governor/DVFS 改动没有引入：
- 延迟抖动扩大（尤其是实时/音频/控制场景）
- 频率切换异常（过度抖动/切换失败/卡频）
- 功耗/温度超限（热失控或过早降频）

建议组合：

#### 5.3.1 cyclictest（调度延迟）

```bash
cyclictest -p95 -m -n -i 1000 -l 100000
```

关注：
- P99/P99.9 延迟
- 在不同 governor 与 QoS/thermal 条件下的稳定性

#### 5.3.2 hackbench（CFS 压力与上下文切换）

```bash
hackbench -s 512 -l 10000
```

关注：
- 吞吐变化与频率变化是否符合预期
- schedutil 下 util 估计是否导致频率震荡

#### 5.3.3 sysbench（CPU/内存混合）

```bash
sysbench cpu --threads=$(nproc) --time=30 run
```

关注：
- 能耗与性能的 Pareto 前沿是否改善

#### 检查清单（回归方案）
- 每次改动是否覆盖“交互短任务 + 长任务 + IO 任务 + 热限制”四类场景
- 是否记录频率 trace、功耗/能量数据与温度曲线，形成可对比基线
- 是否覆盖多 policy（多 cluster）与热插拔/idle 组合路径

---

## 6. 调试与故障排查

### 6.1 sysfs 节点验证（可用频率、当前 governor、stats）

常用路径：

- policy 级（推荐）：
  - `/sys/devices/system/cpu/cpufreq/policyX/`
  - `scaling_governor`、`scaling_min_freq`、`scaling_max_freq`
  - `scaling_cur_freq`、`cpuinfo_{min,max}_freq`
  - `scaling_available_frequencies`（并非所有 driver 提供）
  - `related_cpus` / `affected_cpus`（policy 范围）
- CPU 级：
  - `/sys/devices/system/cpu/cpuX/cpufreq/`

统计信息（若启用 cpufreq-stats）：
- `/sys/devices/system/cpu/cpuX/cpufreq/stats/`：`time_in_state`、`total_trans`、`trans_table`  
  文档见：[cpufreq-stats.rst](file:///home/alex/linux-stable/Documentation/cpu-freq/cpufreq-stats.rst)

快速检查命令：

```bash
for p in /sys/devices/system/cpu/cpufreq/policy*; do
  echo "== $p =="
  cat $p/scaling_governor
  cat $p/scaling_min_freq $p/scaling_max_freq $p/scaling_cur_freq
  cat $p/related_cpus 2>/dev/null || true
  cat $p/affected_cpus 2>/dev/null || true
done
```

### 6.2 trace events 与 ftrace 抓取切换时序

主线 5.15 推荐使用 power 子系统 tracepoint：
- `power:cpu_frequency`
- `power:cpu_frequency_limits`

tracepoint 文档：[events-power.rst](file:///home/alex/linux-stable/Documentation/trace/events-power.rst)

示例（trace-cmd）：

```bash
trace-cmd record -e power:cpu_frequency -e power:cpu_frequency_limits -- sleep 5
trace-cmd report | head -n 50
```

示例（ftrace）：

```bash
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo nop > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/events/power/cpu_frequency/enable
echo 1 > /sys/kernel/debug/tracing/events/power/cpu_frequency_limits/enable
echo 1 > /sys/kernel/debug/tracing/tracing_on
sleep 5
echo 0 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace | head -n 100
```

切换时序图（典型 sync driver，core 代发通知）：

```
time ->

caller
  __cpufreq_driver_target()
    __target_index()
      cpufreq_freq_transition_begin()
        notifier PRECHANGE
      driver->target_index()
        (V change, settle)
        (PLL reprogram, lock)
        (clk switch)
      cpufreq_freq_transition_end()
        notifier POSTCHANGE
        trace_cpu_frequency()
```

### 6.3 常见异常与修复步骤

#### 6.3.1 -EPROBE_DEFER

含义：
- 依赖资源尚未就绪（regulator/clock/interconnect/firmware channel 等）

典型触发点：
- OPP 表解析时找不到 regulator 或 ICC path，返回 `-EPROBE_DEFER`  
  OPP 初始化过程中对 ICC path 有 defer 分支：[core.c](file:///home/alex/linux-stable/drivers/opp/core.c#L1504-L1514)

处理建议：
- 确认 DT 中 `cpu-supply`、clock provider、interconnect provider 的 probe 顺序与依赖
- 对可选资源，确认驱动是否容忍 `-ENODEV` 并降级运行

#### 6.3.2 -EBUSY

常见含义：
- 目标频率/电压变更被资源占用或被 QoS/thermal 限制拒绝

排查步骤：
- 检查 `scaling_min_freq/scaling_max_freq` 是否被锁死（QoS/thermal）
- 检查是否存在 cpufreq_cooling 对 max freq 的限制（见 §7.1）
- 检查平台 driver 是否在切换窗口内拒绝并发切换（transition_ongoing）

#### 6.3.3 OPP 表缺失/无可用 OPP

症状：
- cpufreq driver probe 失败或频率表为空
- 日志出现 “couldn't find opp table” 或 “failed to find OPP for freq”

排查步骤：
- DT：CPU 节点是否设置 `operating-points-v2` 指向 OPP 表
- OPP 表：是否存在 `opp-hz/opp-microvolt`，是否被 `opp-supported-hw` 全部过滤
- 电源：`cpu-supply` 指向的 regulator 是否存在且可用

#### 6.3.4 电压跌落/不稳定（voltage droop）

症状：
- 负载跃迁时死机/重启/异常机器检查
- 日志可能出现 regulator 报错、PLL lock timeout、WHEA/MCE 等（依架构而定）

修复路径（从最可能到最基础）：
- 增加 OPP 电压 margin（提高 target 或调整 min/max）
- 校准 PMIC ramp rate 与 regulator settling，确保时序满足
- 检查电源树、去耦电容、layout 与 IR drop（需要硬件协同）
- 降低最高 OPP（禁用 turbo 或移除不可达 OPP）

#### 检查清单（故障排查）
- 是否先从 sysfs policy 限制与 thermal/QoS 入手排除“人为锁频”
- 是否对 OPP 的可达性做了平台 bin/温度/电源能力校验
- 是否用 trace 还原“PRE→硬件切换→POST”的完整时序

---

## 7. 安全与可靠性

### 7.1 thermal zone 与 cpufreq_cooling 联动

热管理常见闭环：
- thermal zone 监测温度
- thermal governor（如 power_allocator）计算可用功耗预算
- cpufreq_cooling 将功耗预算映射为“限制最高频率/性能状态”

cpufreq_cooling 使用：
- `freq_qos_request` 将限制注入 cpufreq policy（对 max_freq 施加约束）  
  `struct cpufreq_cooling_device` 中包含 `freq_qos_request qos_req`：  
  [cpufreq_cooling_device](file:///home/alex/linux-stable/drivers/thermal/cpufreq_cooling.c#L52-L79)
- EM（Energy Model）将频率映射到功耗估算（用于 power_allocator）  
  [cpu_freq_to_power](file:///home/alex/linux-stable/drivers/thermal/cpufreq_cooling.c#L106-L120)

工程要点：
- thermal 限制常通过 QoS 进入 cpufreq core，因此表现为 `scaling_max_freq` 下降
- 调试时必须同时查看 thermal 与 cpufreq QoS 约束

### 7.2 cpu-freq-qos 防止频率被锁死

频率 QoS 用于对 cpufreq policy 施加“最小/最大频率”约束，来源可能包括：
- thermal/cooling
- 用户空间策略守护进程
- 驱动内部策略（例如某些 device 依赖 CPU 最低性能）

cpufreq core 在 policy create/remove 时会安装/移除 QoS request 并发送 policy notifier：  
[cpufreq.c 相关片段](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c#L1401-L1539)

建议实践（产品级）：
- 为关键场景（看门狗/音频/实时控制）定义“最低频率/最低性能”的 QoS 保护
- 为防止误锁频，建立：
  - QoS request 的可观测性（debugfs/trace）
  - 异常检测：长时间 stuck 在 min/max、transition 失败次数上升

### 7.3 A/B OPP 表在 OTA 升级时的回滚策略

主线内核不提供“OPP 表 A/B 双镜像”的通用框架；产品实现通常在“固件/启动链”解决：

推荐策略：
- 将 OPP 表放在 **DTB/DTBO**（或 firmware 表）中，并由 bootloader 选择 slot：
  - Slot A：已验证的 OPP
  - Slot B：新 OPP（可能更激进或为新版本硅修正）
- OTA 升级后：
  - 先以 B slot 启动并运行自检（性能/稳定性/温度/电压）
  - 若失败或 watchdog 触发回滚条件，则 bootloader 回退到 A

工程细节建议：
- 自检应覆盖：高负载（max OPP）、突发负载、低温/高温边界、IO 干扰与 suspend/resume
- 回滚条件应由 bootloader/安全监控实现，避免用户空间被锁死导致无法回滚

#### 检查清单（安全可靠性）
- thermal 限制是否通过 QoS 正确反映到 cpufreq policy
- 是否存在 QoS “锁死”风险与观测手段（可定位是谁施加约束）
- OPP 更新是否具备启动链回滚（而非仅依赖用户空间）

---

## 8. 实战示例

### 8.1 为 ARM64 SoC 添加自定义 OPP 表（DT 片段与参数）

目标：为某 cluster 定义 OPP 表，包含 `opp-hz`、`opp-microvolt`、`clock-latency-ns`，并通过 `cpu-supply` 绑定 regulator。

示例补丁（仅示意，节点名/时钟/电源需按平台替换）：

```diff
diff --git a/arch/arm64/boot/dts/vendor/soc.dtsi b/arch/arm64/boot/dts/vendor/soc.dtsi
index 000000000000..111111111111 100644
--- a/arch/arm64/boot/dts/vendor/soc.dtsi
+++ b/arch/arm64/boot/dts/vendor/soc.dtsi
@@ -1,6 +1,62 @@
 / {
+	cpu_opp_table: opp-table {
+		compatible = "operating-points-v2";
+		opp-shared;
+
+		opp-600000000 {
+			opp-hz = /bits/ 64 <600000000>;
+			opp-microvolt = <800000 780000 820000>;
+			clock-latency-ns = <300000>;
+		};
+
+		opp-1200000000 {
+			opp-hz = /bits/ 64 <1200000000>;
+			opp-microvolt = <950000 930000 980000>;
+			clock-latency-ns = <350000>;
+		};
+
+		opp-1800000000 {
+			opp-hz = /bits/ 64 <1800000000>;
+			opp-microvolt = <1050000 1030000 1080000>;
+			clock-latency-ns = <400000>;
+			turbo-mode;
+		};
+	};
 };

diff --git a/arch/arm64/boot/dts/vendor/board.dts b/arch/arm64/boot/dts/vendor/board.dts
index 222222222222..333333333333 100644
--- a/arch/arm64/boot/dts/vendor/board.dts
+++ b/arch/arm64/boot/dts/vendor/board.dts
@@ -1,6 +1,12 @@
 &cpu0 {
+	cpu-supply = <&vdd_cpu>;
+	operating-points-v2 = <&cpu_opp_table>;
 };
```

说明：
- `opp-microvolt` 三元组为 `target/min/max`，建议按电源设计与 IR drop 留 margin
- `clock-latency-ns` 应覆盖“最坏 PLL 锁定 + 父源切换 + 软件路径”时延
- `opp-shared` 表示该 OPP 表对应共享 DVFS 域（cluster 同步）

### 8.2 内核模块动态注册/注销 OPP 并验证频率-电压对应

目标：展示运行期添加动态 OPP（调试/实验用途），并验证 OPP 库可以检索到对应电压。

注意：
- 动态 OPP 通常用于非 CPU 设备或特殊实验；CPU 的 cpufreq driver 往往在 probe 阶段建立表并依赖频率表一致性。
- 动态修改 CPU OPP 可能需要同步更新 cpufreq 频率表（否则 governor 仍按旧表选频）。

示例模块（最小化演示，需按目标设备替换 `dev_name` 查找方式）：

```c
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pm_opp.h>

static char *dev_name = "soc:demo-device";
module_param(dev_name, charp, 0444);

static struct device *demo_dev;

static int __init demo_opp_init(void)
{
	struct dev_pm_opp_data data = {
		.turbo = false,
		.level = OPP_LEVEL_UNSET,
		.freq = 400000000,
		.u_volt = 850000,
	};
	struct dev_pm_opp *opp;
	unsigned long f = data.freq;
	int ret;

	demo_dev = bus_find_device_by_name(&platform_bus_type, NULL, dev_name);
	if (!demo_dev)
		return -ENODEV;

	ret = dev_pm_opp_add_dynamic(demo_dev, &data);
	if (ret)
		return ret;

	opp = dev_pm_opp_find_freq_exact(demo_dev, f, true);
	if (IS_ERR(opp))
		return PTR_ERR(opp);

	pr_info("opp: freq=%lu Hz volt=%lu uV\n", f, dev_pm_opp_get_voltage(opp));
	dev_pm_opp_put(opp);

	return 0;
}

static void __exit demo_opp_exit(void)
{
	if (!demo_dev)
		return;
	dev_pm_opp_remove(demo_dev, 400000000);
	put_device(demo_dev);
}

module_init(demo_opp_init);
module_exit(demo_opp_exit);
MODULE_LICENSE("GPL");
```

验证建议：
- dmesg 检查 `opp: freq=... volt=...`
- 若目标设备有 clock/regulator 配置，可进一步调用 `dev_pm_opp_set_rate()` 做联动切换（非 CPU 设备更常见）

### 8.3 基于 schedutil 的 EAS 集成步骤与效果对比

EAS 集成需要三类输入正确：
- **容量模型**：arch_scale_cpu_capacity、freq-invariant util（否则 util→freq 与任务放置会偏离）
- **Energy Model（EM）**：为每个 perf state 提供 power 估算（常由 OPP/平台生成）
- **cpufreq governor**：通常选 schedutil，并确保 policy/cluster 定义正确

集成步骤（高层）：
- 启用相关配置（见 §9.2）
- 确保 OPP 表包含合理的频率-电压点（并能推导 power）
- 验证 schedutil 的 util→freq 映射是否随负载线性变化（用 trace 观察）
- 在同样 workload 下对比：
  - schedutil + EAS：任务更倾向于在能效更好的 CPU 上运行，并选择更合适的频点
  - ondemand/conservative：更偏“拉高频率”而不是“搬迁任务”

功耗对比柱状图（示例模板，填入你的测量值）：

| 场景 | governor | 平均功耗 (W) | P95 延迟 (ms) | 吞吐量 (ops/s) |
|---|---|---:|---:|---:|
| hackbench | ondemand |  |  |  |
| hackbench | schedutil |  |  |  |
| sysbench | ondemand |  |  |  |
| sysbench | schedutil |  |  |  |

柱状图（文本化示意）：

```
Power (W)
ondemand  : ###########
schedutil : ########
```

#### 检查清单（实战落地）
- DT OPP v2 是否完备（电压/时延/共享域/硬件过滤）
- driver->target_index 是否遵循 DVFS 安全序并考虑 PLL 锁定
- schedutil 下 util→freq 映射是否合理（无频繁抖动/无长期 stuck）
- EAS/EM 是否与实际能耗趋势一致（至少方向一致）

---

## 9. 交付标准

### 9.1 Linux 5.15+ API 合规性

本文涉及的关键 API 在本树中可直接定位：
- cpufreq core：`drivers/cpufreq/cpufreq.c`  
  [cpufreq.c](file:///home/alex/linux-stable/drivers/cpufreq/cpufreq.c)
- schedutil：`kernel/sched/cpufreq_schedutil.c`  
  [cpufreq_schedutil.c](file:///home/alex/linux-stable/kernel/sched/cpufreq_schedutil.c)
- OPP：`drivers/opp/` 与 `include/linux/pm_opp.h`  
  [opp core.c](file:///home/alex/linux-stable/drivers/opp/core.c)，[pm_opp.h](file:///home/alex/linux-stable/include/linux/pm_opp.h)

### 9.2 内核配置项（建议基线）

以下为常见必选/强相关配置（按平台裁剪）：

- CPUFreq：
  - `CONFIG_CPU_FREQ`
  - `CONFIG_CPU_FREQ_STAT`（stats）
  - `CONFIG_CPU_FREQ_GOV_PERFORMANCE`
  - `CONFIG_CPU_FREQ_GOV_POWERSAVE`
  - `CONFIG_CPU_FREQ_GOV_USERSPACE`
  - `CONFIG_CPU_FREQ_GOV_ONDEMAND`
  - `CONFIG_CPU_FREQ_GOV_CONSERVATIVE`
  - `CONFIG_CPU_FREQ_GOV_SCHEDUTIL`
- OPP/DVFS：
  - `CONFIG_PM_OPP`
  - `CONFIG_REGULATOR`
  - `CONFIG_COMMON_CLK`
  - `CONFIG_INTERCONNECT`（若使用 OPP bandwidth/ICC）
- Thermal：
  - `CONFIG_THERMAL`
  - `CONFIG_CPU_THERMAL`
  - `CONFIG_THERMAL_GOV_POWER_ALLOCATOR`（若使用 power allocator）
- EAS/EM（视内核与平台特性）：
  - `CONFIG_ENERGY_MODEL`

### 9.3 图表要求（本文件内提供的模板）

- OPP 表结构图：见 §1.2/§3（结构体与数据流）
- 频率切换时序图：见 §6.2
- 功耗对比柱状图：见 §8.3（表格 + 文本化柱状图模板）

### 9.4 全文审计检查清单（用于实现完整性）

- **OPP 定义**
  - DT 使用 OPP v2，CPU 节点正确引用 `operating-points-v2`
  - OPP 条目具备 `opp-hz`、`opp-microvolt`，必要时提供 triplet 与 `clock-latency-ns`
  - 正确使用 `opp-shared`/`opp-supported-hw`/`opp-suspend`/`turbo-mode`
- **DVFS 安全**
  - 升频先升压、降频先降频后降压（driver 与 OPP 框架一致）
  - PLL/时钟切换最坏时延被纳入 latency 评估
- **并发与上下文**
  - 调用 `__cpufreq_driver_target()` 的路径具备必要的 policy 序列化
  - fast_switch 路径不触发阻塞操作，不与 transition notifier 冲突
  - 热插拔/挂起恢复路径下不访问已休眠依赖总线
- **可观测性**
  - sysfs policy 节点可读（governor/cur/min/max/related/affected）
  - trace 具备 `power:cpu_frequency` 与 `power:cpu_frequency_limits`
  - cpufreq-stats 可用时能输出 time_in_state/total_trans/trans_table
- **热与 QoS**
  - thermal/cpufreq_cooling 可正确限制频率上限并可定位来源
  - QoS request 不会长期误锁频且具备排查手段
- **测试与回归**
  - 建立吞吐-延迟-功耗矩阵并维护基线
  - cyclictest/hackbench/sysbench 覆盖交互/长任务/IO/热限制场景

