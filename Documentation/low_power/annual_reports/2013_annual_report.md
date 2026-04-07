# 2013 年度工作报告：SoC 低功耗优化（中级 · 小组长）

| 项目 | 信息 |
|------|------|
| 年份 | 2013 |
| 角色 | **中级工程师**，**功耗优化小组组长**，**带 2 名新人** |
| 所属部门 | SoC 原厂 BSP 部门 |
| SoC 平台 | Cortex-A7 四核 / **big.LITTLE（Cortex-A15 + A7）** |
| 制程工艺 | 28nm |
| 内核版本 | Linux 3.4 — 3.10 |
| Android 版本 | Android 4.2 — 4.4 |
| 产品形态 | 中端四核 A7、旗舰 big.LITTLE 手机 |

---

## 一、行业背景与技术环境

2013 年 **big.LITTLE** 从概念进入量产：**A7 与 A15 的能效比悬殊**（本年度内部实测归纳约 **1:3** 功耗量级，随负载与电压点变化），软件上需在 **IKS（In-Kernel Switcher）**、**GTS（Global Task Scheduling）**、**Cluster Migration** 等路线中做取舍与实现。

**ARM PSCI** 成为 CPU idle/off 的标准固件接口；**ATF（ARM Trusted Firmware）** 在旗舰平台落地，内核侧需从「直接写 CP15/平台寄存器」迁移到 **smc 调用**。**Thermal** 子系统与 **Governor** 成为防止「峰值性能烧机」的标配。

```
2013 旗舰功耗软件栈（示意）

  Framework / HAL
        │
        ▼
  Kernel: cpufreq / cpuidle / thermal / runtime PM
        │
        ├── PSCI ──► ATF / ROM
        ├── MCPM / b.L 调度适配层
        └── CCI-400 配置与 idle
```

---

## 二、核心工作内容

### 2.1 big.LITTLE 软件方案评估与 IKS 实现

**评估维度（内部矩阵）：**

| 方案 | 优点 | 风险/成本 |
|------|------|-----------|
| IKS | 对现有调度器侵入相对小；可快速落地 | 虚拟核视角；复杂场景需仔细处理迁移 |
| GTS | 更细粒度 per-task 迁移 | 调度器改动大；验证周期长 |
| Cluster Migration | 实现相对集中 | 簇间迁移延迟与锁竞争敏感 |

**年度决策：** 首版量产采用 **IKS**，完成 **虚拟核配对**（logical CPU 与 physical big/LITTLE 映射）、**inbound/outbound** 切换路径优化。

**性能目标：** 核间迁移路径 **< 20 μs**（平台计数器统计 P50，内部基准测试环境）。

**CCI-400：** 配置 snoop、端口使能、与 **DVM / barrier** 相关序列，保证 **big ↔ LITTLE** 迁移时 **一致性可见**。

**MCPM 层：** 适配 **Multi-Cluster Power Management** 钩子，与 **cpu_pm**、**idle**、**hotplug** 统一。

**切换路径 ASCII：**

```
任务负载上升
     │
     ▼
┌─────────────────┐
│ outbound: A7 上 │  保存必要上下文、停本地 tick、刷 cache 子集
│ 上下文冻结      │
└────────┬────────┘
         ▼
┌─────────────────┐
│ inbound: A15 上 │  恢复执行、重建 GIC 亲和、调整 cpufreq 策略
│ 恢复运行        │
└─────────────────┘
```

---

### 2.2 PSCI 初始化接入与 cpuidle 改造

**接入接口：** `CPU_ON`、`CPU_OFF`、`CPU_SUSPEND`、`SYSTEM_SUSPEND` 等，与 ATF 提供的 **power state id** 表对齐。

**改造要点：** cpuidle **不再直接** 操作平台休眠寄存器，而改为 **PSCI 调用**（`arm_cpuidle_suspend` 一类路径的抽象），便于 **多 SoC 复用** 与 **安全监控**。

**概念代码（说明意图，非具体 SoC）：**

```c
/*
 * 原因：固件统一掌握簇电源、CCI、部分 GIC 状态；内核只描述「意图」，
 * 避免内核与 TrustZone 世界争抢电源寄存器。
 */
static int bl_enter_idle(struct cpuidle_device *dev,
			 struct cpuidle_driver *drv, int index)
{
	struct psci_power_state state = drv->states[index].driver_data;

	return psci_cpu_suspend(state);
}
```

**ATF 集成：** 与安全团队联合定义 **non-secure → secure** 调用约定、异常级别切换与 **return address** 处理。

---

### 2.3 Thermal 框架：zone driver、trip、cooling

**交付：**

- **thermal zone driver**：SoC 内置传感器 + 外置 NTC（若板级有）；
- **4 个 trip point**：**75 / 85 / 95 / 105°C**（可配置滞后）；
- **cooling device**：CPU、GPU **DVFS 限频**；
- **governor**：`step_wise` + **hysteresis**，抑制温度在阈值附近震荡导致的频率抖动。

**trip 动作表：**

| Trip (°C) | 动作示例 |
|-----------|----------|
| 75 | 通知、记录；可选轻限频 |
| 85 | CPU 降一档 OPP |
| 95 | CPU+GPU 联合限频；用户态提示 |
| 105 | 激进限频 / 紧急日志 |

**效果归纳：** 在相同散热结构下，**可持续运行频率**（不触顶热节流前）平均提升约 **25%**（内部长时间游戏压测口径）。

---

### 2.4 Runtime PM 推广第一轮：培训与四大模块改造

**组织工作：** 作为小组长，编写 **培训文档**（驱动自检清单、autosuspend 延迟建议、`rpm` 与 **genpd** 交互说明），组内 **2 名新人** 分别认领子模块改造与用例回归。

**改造模块：**

| 模块 | 策略要点 |
|------|----------|
| Display | 亮屏保持 active；灭屏后延迟 autosuspend |
| GPU | 与 big.LITTLE / OPP 联动；避免频繁 suspend 抖动 |
| Video | 解码会话期间 hold；空闲窗口关闭硬件时钟 |
| Camera | pipeline 多设备 refcount；错误路径 put 对称 |

**亮屏待机：** 四模块改造后，典型 **亮屏待机电流** 相对基线 **降低约 25%**（同亮度、同网络、实验室固定脚本）。

**autosuspend 策略示例：**

```text
原因：delay 过短 → 频繁 resume 能耗高；过长 → 外设漏电久。
推荐：按设备唤醒成本与漏电斜率折中，Display 往往最长，Sensor 较短。
```

---

## 三、技术成长与团队管理

| 维度 | 2012 末 | 2013 末 |
|------|---------|---------|
| 技术深度 | genpd/CCF | **PSCI + ATF + b.L + Thermal** |
| 技术广度 | BSP 为主 | **跨安全固件、GPU、多媒体驱动** |
| 角色 | 骨干 + 带 1 人 | **组长 + 带 2 人**：任务排期、风险上报、客户对接 |
| 影响力 | 组内 | **部门级培训、Runtime PM 规范初版** |

**管理笔记：** 新人 A 适合 **结构化任务**（接口对照表）；新人 B 适合 **调试型任务**（示波器 + ftrace）——配对互补，减少单点瓶颈。

---

## 四、踩坑与根因摘要

| 现象 | 根因（简述） | 对策 |
|------|----------------|------|
| big.LITTLE 切换后浮点异常 | **VFP/NEON 未保存** | 补齐上下文；对照 ARM ABI 与内核 `kernel_neon` 约束 |
| 偶发总线 hang | **CCI 端口使能时序** 与 cluster 上下电交错 | 与硬件同事固化顺序；固件侧增加握手 |
| IRQ 错核或丢失 | **GIC remapping** 在迁移中未更新 | GIC driver 与 b.L 迁移钩子联合 patch |
| 温度跳变导致误限频 | **传感器噪声 + 无滞后** | trip hysteresis + 软件滤波（IIR/中值） |

---

## 五、关键数字（年度 KPI 对齐）

| 指标 | 数值 |
|------|------|
| A7 vs A15 功耗比（典型计算负载，内部测试） | **约 1:3** |
| Thermal 策略下可持续频率 | **+25%**（相对无 thermal 优化的粗暴限频策略） |
| Runtime PM 第一轮覆盖模块 | **Display / GPU / Video / Camera** |
| 亮屏待机优化 | **约 -25%** |
| 关闭相关 Bug | **63** |
| 团队规模 | **本人 + 2 名新人** |

---

## 六、遗留问题与展望

1. **GTS** 路线仍在预研，与 **scheduler** 主线融合需长期投入。
2. **PSCI** 与 **平台专用低功耗模式**（DDR 自刷新深度）仍存在 **固件-内核-驱动** 三角扯皮。
3. **Runtime PM** 仅完成第一轮，音频、传感器、杂项 IO 仍大量遗留。
4. **EAS（Energy Aware Scheduling）** 已在社区发酵，为 2014+ 调度与功耗联合优化埋伏笔。

---

## 附录 A：big.LITTLE 簇关系 ASCII

```
         ┌──────────────────┐
         │   CCI-400 FABRIC  │
         └───┬──────────┬───┘
             │          │
      ┌──────▼───┐  ┌───▼──────┐
      │ A15      │  │ A7       │
      │ cluster  │  │ cluster  │
      │ (big)    │  │ (LITTLE) │
      └──────────┘  └──────────┘
```

## 附录 B：PSCI 与 idle 调用链（抽象）

```
cpuidle_idle_call()
    └── bl_enter_idle()
            └── psci_cpu_suspend(state)
                    └── smc → ATF
                            └── 硬件: cluster / CPU power down
```

## 附录 C：Thermal 与 cpufreq 交互表

| 组件 | 职责 |
|------|------|
| thermal zone | 读温度、触发 trip |
| cooling device | 限频、限流 |
| cpufreq | 执行 OPP 变更 |

## 附录 D：PSCI 标准功能与内核映射（教学用）

> 下列名称遵循 ARM PSCI 语义分类，**具体 function id 以平台固件发布说明为准**。

| 能力分类 | 典型用途 | 内核侧关联 |
|----------|----------|------------|
| CPU_ON | 上电并启动目标核 | `__cpu_up` 路径 |
| CPU_OFF | 本核关闭 | `cpu_shutdown` |
| CPU_SUSPEND | 核级 idle/off | `cpuidle` / `suspend` |
| SYSTEM_SUSPEND | 整机睡眠 | `suspend_finish` 前后与 ATF 协调 |
| AFFINITY_INFO | 查询核在线状态 | hotplug 状态机校验 |

## 附录 E：Runtime PM 培训文档目录（实际交付结构）

```
low_power_runtime_pm/
├── 01_concepts.md          # usage_count、autosuspend、idle 回调
├── 02_checklist.md         # 驱动改造自检表
├── 03_genpd_rpm.md         # 与 power domain 的 refcount 叠加
├── 04_debugging.md         # rpm_summary、tracepoint、常见死锁
└── labs/
    ├── display_rpm.txt     # 四大模块参考补丁片段索引
    └── gpu_rpm.txt
```

## 附录 F：2013 小组工作拆分（组长视角）

| 成员 | 主要交付 | 风险缓冲 |
|------|----------|----------|
| 新人 A | Display/Video 的 rpm 改造与用例 | 本人评审 DMA fence 与 suspend 顺序 |
| 新人 B | Camera/GPU 的 rpm + 回归脚本 | 本人兜底 big.LITTLE 切换竞态 |
| 本人 | PSCI、IKS、Thermal、ATF 接口 | 客户 escalations、锁顺序终裁 |

---

*文档说明：20μs、1:3、25% 等均为内部测试环境典型值；PSCI 函数编号与 ATF 版本因平台而异，此处不绑定具体芯片。*
