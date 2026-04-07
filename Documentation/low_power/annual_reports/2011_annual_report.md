# 2011 年度工作报告：SoC 低功耗优化（第二年）

| 项目 | 信息 |
|------|------|
| 年份 | 2011 |
| 角色 | 低功耗优化工程师（第二年） |
| 所属部门 | SoC 原厂 BSP 部门 |
| SoC 平台 | Cortex-A8 → Cortex-A9 双核过渡 |
| 制程工艺 | 45nm — 40nm |
| 内核版本 | Linux 2.6.35 — 3.0 |
| Android 版本 | Android 2.3 (Gingerbread) — 3.x (Honeycomb/ICS 预研) |
| 产品形态 | 双核手机参考设计、7" 平板 |

---

## 一、行业背景与技术环境

2011 年「双核」成为营销关键词，**SMP 下的 idle、hotplug、锁与缓存一致性** 成为 BSP 功耗工作的主战场。
内核侧 **cpuidle 子系统** 在 ARM 上逐步可用；Android 仍大量依赖 **wakelock**，同时内核社区推动 **wakeup source**
抽象，为日后与 Android 电源管理对齐埋下伏笔。

**行业侧要点：**

- **big.LITTLE 尚未普及**，但双核 A9 + MPCore 已让「关核省电」成为可行产品特性。
- **Regulator 框架** 在内核中成熟，从「驱动里直接 I2C 改电压」迁移到 `regulator_ops` 成为技术债清理方向。
- **平板形态** 带来更大电池与更长亮屏时间，**亮屏 idle** 与 **视频场景** 功耗指标权重上升。

```
2011 双核功耗软件栈（示意）

  CPU0/CPU1
      │
      ├── cpufreq (per-policy 或 shared，视平台)
      ├── cpu hotplug (optional product feature)
      ├── cpuidle (C1/C2/C3 状态机)
      └── SCU + snoop / L2 一致性
```

---

## 二、核心工作内容

### 2.1 双核 CPU Hotplug：cpu_die / cpu_kill、SGI 唤醒与自研 governor

**目标：** 在轻载时关闭 CPU1 降低漏电与簇内互连活动；负载上升时快速拉起，避免「迟钝」与「抖动」。

**实现要点：**

1. **平台 `cpu_die` / `cpu_kill`**：配合 bootrom/ROM 或 PMIC 电源轨策略，确保目标核时钟/电源安全切断。
2. **SGI 唤醒**：在线核向离线核发送软件中断，配合 **boot address** 寄存器完成二次启动路径。
3. **自研 hotplug governor**：基于 **负载阈值 + 滞后（hysteresis）**，避免在阈值附近频繁插拔。

**滞后状态机（概念代码）：**

```c
/*
 * 原因：若仅用单一阈值，负载在阈值附近抖动会导致 cpu_up/cpu_down 风暴，
 * 引发调度延迟尖峰与用户可感知的卡顿；滞后双阈值是经典控制论手段。
 */
#define LOAD_ON		30	/* 平均负载 > 30% 持续 N 个采样 → 拉核 */
#define LOAD_OFF	12	/* 平均负载 < 12% 持续 M 个采样 → 杀核 */
#define SAMPLE_HZ	5

static void hotplug_tick(struct work_struct *work)
{
	unsigned int avg = get_avg_load();

	if (!cpu1_online && avg > LOAD_ON)
		cpu_up(1);
	else if (cpu1_online && avg < LOAD_OFF)
		cpu_down(1);
}
```

**效果（实验板统计）：**

| 场景 | 优化前（双核常开） | 优化后（hotplug） | 备注 |
|------|-------------------|-------------------|------|
| 亮屏静态桌面 idle | 基准 | **约 -35% 功耗** | 含互连/缓存活动下降 |
| 浏览器滚动 | 持平或略好 | 略增插拔开销 | 通过滞后抑制抖动 |

---

### 2.2 SCU 电源管理：last man standing

**问题：** 共享 L2 / SCU 区域在 **仅一核在线** 与 **双核在线** 之间切换时，若过早关闭共享资源，另一核仍可能访问，导致 **undefined behavior**。

**方案：** **Last man standing** ——仅当 **最后一个** 即将离线的核确认无其他核依赖共享资源时，才执行 SCU/L2 侧的 retention/off 流程。

**原子计数器 + 临界区（示意）：**

```c
/*
 * 原因：last-man 判断与 cpu_down 路径上的其他并发可能交错；必须用原子计数
 * 描述「仍需要 SCU 全功能在线的核数」，并在降为 0 时由最后离开者执行收尾。
 */
static atomic_t scu_users = ATOMIC_INIT(0);

void scu_power_hint_online(void)
{
	atomic_inc(&scu_users);
}

void scu_power_hint_offline(void)
{
	if (atomic_dec_and_test(&scu_users))
		platform_scu_enter_retention();
}
```

**踩坑：** **spinlock 保护 last-man** 与 **CPU 离线流程中禁止睡眠** 的约束冲突，需仔细拆分可在 atomic 路径完成的部分与必须延后到安全上下文的部分（见第四节）。

---

### 2.3 引入 cpuidle：C1 / C2 / C3 与 ARM 汇编上下文

**三级 idle 状态定义（平台相关命名可能不同）：**

| 状态 | 硬件语义 | 退出延迟 | 功耗 |
|------|-----------|----------|------|
| C1 | WFI，CPU 时钟门控 | 低 | 中 |
| C2 | CPU retention（部分上下文保留） | 中 | 较低 |
| C3 | CPU power down（更多状态丢失） | 高 | 最低 |

**ARM 汇编侧（高度简化，仅说明职责）：**

```text
/* 原因：深度 idle 会关闭部分时钟域；返回 WFI 后需恢复 banked/spurious 状态，
 * 并与 GIC/tick 设备约定好唤醒源。具体指令序列因核与 SoC 而异。
 */
ENTRY(cpu_enter_c3)
	bl	save_critical_context
	bl	platform_flush_l1	/* 顺序敏感：见踩坑 */
	wfi
	bl	restore_critical_context
	ret
ENDPROC(cpu_enter_c3)
```

---

### 2.4 Regulator 框架迁移：8 BUCK + 15 LDO

**背景：** 2010 年散落在各驱动的 I2C 写 PMIC 需收敛到 **regulator consumer** 模型，便于 DVFS、驱动 probe 失败回滚与电压域审计。

**交付：**

| 类型 | 数量 | 说明 |
|------|------|------|
| BUCK | 8 | CPU/GPU/DDR/IO 等大电流轨 |
| LDO | 15 | PLL、模拟、RF 前端辅助等 |
| 迁移驱动 | 全平台关键路径 | `regulator_get` + `regulator_set_voltage` |

**消费者示例（示意）：**

```c
/*
 * 原因：通过 regulator 核心统一电压引用计数，避免重复 set 与竞态；
 * 并为后续 sleep 时的「约束电压」打基础。
 */
cpu_reg = devm_regulator_get(dev, "varm");
ret = regulator_set_voltage(cpu_reg, 1000000, 1250000);
```

---

### 2.5 Wakelock 与 Wakeup Source 对接

**工作：** 在 3.0 内核预研分支上，将 Android 侧 **wakelock** 统计与内核 **wakeup source** 事件对齐，减少「内核已睡、Android 认为仍醒」的双轨不一致。

**对接示意：**

```
Android: wake_lock_active()
        │
        ▼
Kernel:  wakeup_source active 位 + expire 机制
        │
        ▼
pm_wakeup_pending() / autosleep 决策路径
```

---

## 三、技术成长与能力沉淀

| 维度 | 2010 末 | 2011 末 |
|------|---------|---------|
| CPU 视角 | 单核 DVFS | SMP + hotplug + cpuidle 状态机 |
| 框架思维 | 私有 clk/pmic | regulator + 主线 idle 模型 |
| 并发与一致性 | 初步 | **L1 flush 顺序、last-man 原子性** 实战 |
| Android 协同 | suspend 为主 | wakelock / ws 双栈对齐 |

---

## 四、踩坑与根因摘要

| 现象 | 根因（简述） | 对策 |
|------|----------------|------|
| 深度 idle 后时间漂移 | **定时器时钟源在 C3 路径被误关** | 区分 always-on 时钟；cpuidle driver 与 clock 团队联合评审 |
| 偶发数据损坏 | **L1 cache flush 顺序** 与 DMA/一致性假设不符 | 对照 ARM TRM 与平台 note；在 enter 路径加 barrier |
| last-man 死锁或挂起 | **spinlock 范围过大** 或 在 offline 回调中阻塞 | 缩小锁粒度；把可睡眠操作移出 atomic 上下文 |
| hotplug 抖动 | 单阈值 + 瞬时负载尖峰 | **双阈值滞后** + 采样平滑 |

---

## 五、关键数字（年度 KPI 对齐）

| 指标 | 数值 |
|------|------|
| 关闭的功耗/电源管理相关 Bug | **42** |
| 底电流（同参考板、同配置） | **2.8 mA → 2.2 mA** |
| 亮屏 idle 功耗（静态桌面） | **降低约 35%**（hotplug + cpuidle 叠加） |
| Regulator 轨统计 | **8 BUCK + 15 LDO** |
| cpuidle 状态级数 | **3**（C1/C2/C3） |

---

## 六、遗留问题与下一年展望

1. **Hotplug 与调度器的协同**：后续需关注 **scheduler 负载迁移** 与 **plug 时机** 的配合（为 2012 四核做铺垫）。
2. **cpuidle 与 tickless**：`NO_HZ` 全量开启后，**idle 选中逻辑** 与 **next event** 的交互需长期回归。
3. **GIC 虚拟化/安全扩展** 预研：部分客户开始谈 TrustZone 与安全世界切换对电源的影响。
4. **四核 SoC 已在 tape-out 路线**：power domain、cluster idle、CCF 迁移将在 2012 成为主线。

---

## 附录 A：双核电源状态 ASCII 拓扑

```
        ┌─────────────────┐
        │   CPU0  online   │
        └────────┬────────┘
                 │
        ┌────────┴────────┐
        │      SCU        │◄── last man standing 决策点
        └────────┬────────┘
                 │
        ┌────────┴────────┐
        │   CPU1 on/off   │
        └─────────────────┘
```

## 附录 B：术语速查

| 术语 | 说明 |
|------|------|
| SGI | Software Generated Interrupt |
| SCU | Snoop Control Unit |
| WS | Wakeup Source |

---

*文档说明：具体寄存器与平台汇编已脱敏；数值为实验板统计量级，非单一客户承诺值。*
