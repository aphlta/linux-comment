# 2012 年度工作报告：SoC 低功耗优化（第三年 · 带新人）

| 项目 | 信息 |
|------|------|
| 年份 | 2012 |
| 角色 | 低功耗优化工程师（第三年），**带 1 名新人** |
| 所属部门 | SoC 原厂 BSP 部门 |
| SoC 平台 | Cortex-A9 四核 |
| 制程工艺 | 40nm — 28nm |
| 内核版本 | Linux 3.0 — 3.4 |
| Android 版本 | Android 4.0 (ICS) — 4.1 |
| 产品形态 | 四核手机/平板旗舰参考设计 |

---

## 一、行业背景与技术环境

2012 年 **四核** 成为安卓旗舰标配，**功耗域（Power Domain）** 从「整个 CPU 一块」细分为 **cluster、子系统、外设** 多域控制。
主线内核 **Common Clock Framework（CCF）** 与 **Generic Power Domain（genpd）** 成为 BSP 向上游与向内一致性的关键抓手。

**Android 4.x** 引入 **Project Butter（黄油计划）** 强调 60fps 与 VSYNC，**合成与渲染路径负载上升**，对 **GPU/DDR idle** 提出更高要求——功耗优化必须与 **流畅度** 联合验收。

**行业侧要点：**

- **Device Tree** 逐步取代大量 board file，功耗相关绑定（clock、regulator、power-domain）需前置设计。
- **28nm** 漏电进一步凸显，**off 态** 比「低频跑」更有吸引力，**power gating** 从可选变为必选。

```
2012 BSP 功耗技术栈演进

  2010-2011              2012
  ─────────────────────────────────────
  私有 clk      →       CCF (100+ 节点迁移)
  手写 suspend  →       genpd + 拓扑化 PD
  board-*.c     →       DTSI + 板级 DTS
```

---

## 二、核心工作内容

### 2.1 四核 SoC 功耗域拓扑与 cluster 电源管理

**交付：** **8 个 power domain** 的拓扑图、上电顺序、依赖关系与软件状态机；**CPU cluster** 三级语义：

| Cluster 状态 | 行为摘要 |
|--------------|----------|
| Active | 全核可运行，L2/SCU 全功能 |
| Retention | 低漏电保持，快速唤醒 |
| Off | 最大省电，恢复路径最长 |

**Last-man / First-man 协议（软件侧示意）：**

```c
/*
 * 原因：四核共享 cluster 资源时，必须保证「最后一个离开者」关闭共享域、
 * 「第一个到达者」完成上电与隔离解除，否则会出现核已跑但 L2 未就绪的竞态。
 */
static DEFINE_MUTEX(cluster_pm_lock);
static int cluster_online_cpus; /* 由 cpuhp 状态机维护 */

static void cluster_last_man(void)
{
	mutex_lock(&cluster_pm_lock);
	if (--cluster_online_cpus == 0)
		pd_cluster_power_off();
	mutex_unlock(&cluster_pm_lock);
}

static void cluster_first_man(void)
{
	mutex_lock(&cluster_pm_lock);
	if (cluster_online_cpus++ == 0)
		pd_cluster_power_on();
	mutex_unlock(&cluster_pm_lock);
}
```

**带新人分工：** 新人负责 PD 台账与 DTS 属性核对；本人负责 **cpuhp 回调与锁顺序** 评审及客户问题兜底。

---

### 2.2 Common Clock Framework 迁移：100+ 节点

**范围：** 将 2010-2011 年私有 `clk_*` 实现迁移为 CCF 的 `clk_hw` 体系，覆盖 **PLL / gate / mux / divider**。

**实现类型对照：**

| CCF 操作集 | 硬件语义 |
|------------|----------|
| `pll_ops` | PLL 锁定、旁路、展频（若支持） |
| `gate_ops` | 时钟门控寄存器 bit |
| `mux_ops` | 多路选择器 |
| `div_ops` | 分频比配置 |

**迁移统计：**

| 项 | 数量 |
|----|------|
| 迁移时钟节点 | **100+** |
| 回归用例（boot/显示/存储/相机） | 平台定义全套 |

**依赖环检测（踩坑关联）：** CCF `clk_prepare_enable` 若存在 **循环依赖**，会在运行时或 boot 阶段暴露；迁移时使用 **临时 DAG 图** 与 `clk_summary`  sysfs 互证。

---

### 2.3 Generic Power Domain（genpd）接入与 GPU 域

**交付：** 将 8 个硬件 PD 映射为 `struct generic_pm_domain`，实现：

- `.power_on` / `.power_off` 回调；
- **power good 等待**（轮询或中断）；
- **隔离（isolation）与复位序列** 与硬件手册一致。

**GPU power domain 收益：**

| 场景 | 优化前 | 优化后 | 节省 |
|------|--------|--------|------|
| 亮屏 idle（无 GL 负载） | GPU 域常开漏电 | 域关闭 + 恢复路径优化 | **约 200 mW** |

**genpd 注册片段（概念）：**

```c
/*
 * 原因：genpd 统一了「设备 runtime」与「域级 refcount」的语义，
 * 避免每个驱动重复实现 power_on/off 与 parent 依赖。
 */
static int gpu_pd_power_on(struct generic_pm_domain *domain)
{
	deassert_reset(GPU);
	disable_clamp(GPU);
	wait_power_good(GPU, TIMEOUT_US);
	return 0;
}

static struct generic_pm_domain gpu_pd_domain = {
	.name = "pd_gpu",
	.power_off = gpu_pd_power_off,
	.power_on = gpu_pd_power_on,
};
```

---

### 2.4 Device Tree 迁移：DTSI + 板级 DTS

**功耗相关绑定要点：**

- `clocks` / `clock-names` 与 CCF `of_clk` 匹配；
- `power-domains` / `power-domain-names` 与 genpd `of_genpd_add_provider`；
- `vmmc-supply`、`vdd-x-supply` 等与 regulator 映射。

**结构示意：**

```
soc.dtsi          ← SoC 级默认：PD、CCF、CPU 节点
    │
    ├── board-a.dts    ← 板级：PMIC 轨、GPIO 偏置
    └── board-b.dts
```

---

### 2.5 Android Project Butter 对功耗的影响分析

**结论摘要（内部汇报用）：**

| Butter 相关变化 | 负载影响 | 功耗对策 |
|-----------------|----------|----------|
| VSYNC 对齐渲染 | 合成路径更规律 | 便于 **cpuidle 预测**；但 idle 片段变短 |
| 三重缓冲 | DDR 带宽略增 | **DDR 自刷新策略** 与 **带宽 governor** 预研 |
| 60fps 目标 | CPU/GPU 峰值更高 | **interactive governor** 参数与 **GPU OPP** 联动 |

---

## 三、技术成长与带教沉淀

| 维度 | 2011 末 | 2012 末 |
|------|---------|---------|
| 架构视角 | 双核 hotplug | **四核 PD 拓扑 + CCF + genpd** |
| 上游对齐 | 零散 patch | **可讲清楚的 DT + PM 绑定规范** |
| 团队协作 | 个人主力 | **1 名新人培养**：任务拆分、代码评审、on-call 轮换 |
| 文档 | 内部笔记 | **PD 顺序图 + 迁移 checklist** |

**带新人方法小结：** 先让新人做 **台账型工作**（节点统计、DTS diff），本人锁定 **锁顺序与硬件时序**；每周一次 **复盘会** 对照客户 bug 列表。

---

## 四、踩坑与根因摘要

| 现象 | 根因（简述） | 对策 |
|------|----------------|------|
| resume 后随机用户态崩溃 | **L2 flush 不完整** 或 与 cluster off 路径不协调 | 对照 ARM errata；在 power_on 路径强制一致性序列 |
| 中断风暴或挂死 | **GIC distributor 状态** 在 PD 切换中丢失 | GIC 子系统与 PD 顺序联合评审；必要时保留 always-on 域 |
| boot 卡住或 clk 警告 | **clock 依赖环** | DOT 画图拆环；延迟 `clk_prepare` 或 调整父节点 |
| GPU 域恢复花屏 | **隔离/复位时序** 与 clock enable 顺序 | 硬件 FAE 联合示波器验证 |

---

## 五、关键数字（年度 KPI 对齐）

| 指标 | 数值 |
|------|------|
| CCF 迁移时钟节点 | **100+** |
| Power Domain 数量 | **8** |
| GPU PD 省电（典型亮屏 idle） | **约 200 mW** |
| Cluster 级 idle 功耗 | **降低约 60%**（相对四核全常开基线） |
| 关闭相关 Bug | **56** |
| 团队 | **本人 + 1 名新人** |

---

## 六、遗留问题与下一年展望

1. **big.LITTLE 与 cluster 迁移** 已在路线图，2013 需对接 **PSCI、MCPM、CCI** 等机制。
2. **genpd 与 runtime PM 的默认策略** 尚未在全驱动推广，存在「域已关、设备仍以为开」的边角。
3. **CCI-400 / 总线 idle** 与 **DDR 低功耗模式** 的协同仍依赖平台专用补丁，主线化程度不足。
4. **温度与功耗联合约束** 尚未系统化，为 2013 **Thermal** 框架引入埋下需求。

---

## 附录 A：8 PD 拓扑 ASCII 示意（抽象）

```
              ┌──────────────┐
              │   PD_TOP     │
              └──────┬───────┘
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
  ┌─────────┐  ┌───────────┐  ┌─────────┐
  │ PD_CPU  │  │  PD_BUS   │  │ PD_DDR  │
  │ cluster │  │  /interc. │  │ phy/ref │
  └────┬────┘  └───────────┘  └─────────┘
       │
   ┌───┴───┐
   ▼       ▼
 PD_PERIPH  PD_GPU  ...（其余域省略）
```

## 附录 B：CCF 迁移检查表（摘录）

| 检查项 | 说明 |
|--------|------|
| `CLK_SET_RATE_PARENT` | 是否需向上传播 |
| `clk_prepare` 睡眠 | 是否在 atomic 路径误用 |
| `assigned-clocks` | 板级覆盖是否与 OPP 一致 |

---

*文档说明：PD 命名与硬件域编号已抽象；200mW/60% 等为实验板典型值，非合同担保。*
