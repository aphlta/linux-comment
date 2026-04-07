# 2014 年度工作报告：ARMv8 与 big.LITTLE 低功耗平台化

| 项目 | 信息 |
|------|------|
| 年份 | 2014 |
| 角色 | 高级低功耗优化工程师 |
| SoC 平台 | Cortex-A53 四核 / A57+A53 big.LITTLE（ARMv8 64-bit） |
| 制程工艺 | 28nm / 20nm |
| 内核版本 | Linux 3.10 → 3.18 |
| Android 版本 | Android 4.4 KitKat → 5.0 Lollipop |
| 产品形态 | 首批 AArch64 旗舰手机、平板 |

---

## 一、行业背景与技术环境

2014 年是 **ARM 64 位（AArch64）在消费类 SoC 上量产元年**。苹果 A7 已先行一年，Android 阵营亟需完成从 ARMv7 到 ARMv8 的整条软件栈迁移。与此同时，**big.LITTLE** 从「大小核切换（IKS）」走向 **GTS（Global Task Scheduling，全局任务调度）**，调度器与 cpufreq 需要感知每颗 CPU 的算力与功耗差异。

**关键行业事件：**

- ARMv8-A 架构普及：31 个通用寄存器、系统寄存器替代 CP15、异常模型与 AArch32 双态共存。
- **PSCI（Power State Coordination Interface）** 成为 ARM 官方固件与内核协同标准，取代大量平台私有休眠入口。
- **GICv3** 规范发布：affinity routing、System Register 访问接口，为后续 GICv4/ITS 铺路。
- Android 5.0 Lollipop：**ART** 默认、**JobScheduler** 引入，系统层开始具备「可编排的后台任务」能力。
- DDR3/LPDDR3 主流向更高频率档演进，片内带宽与功耗矛盾在重载场景下凸显。

**对低功耗工程师的含义：** 工作重心从「单核调频 + 简单 idle」升级为 **固件（ATF/PSCI）— 中断控制器（GIC）— 调度/cpuidle — 总线/DDR** 的纵向打通。

---

## 二、核心工作内容

### 2.1 ARMv8（AArch64）电源管理移植

**目标：** 在 AArch64 下复现并增强 ARMv7 上的 suspend、cpuidle、hotplug 行为，且符合 ARM 标准固件接口。

**寄存器与 ABI 变化（工程要点）：**

| 对比项 | ARMv7 | ARMv8 AArch64 |
|--------|--------|----------------|
| GPR 数量 | 16（含 PC 特殊处理） | 31（x0–x30）+ SP/PC 独立 |
| 系统控制 | CP15 为主 | **系统寄存器**（SCTLR_ELx、ACTLR 等） |
| 休眠入口 | 平台 SMC/自定义 | **PSCI** `CPU_SUSPEND` / `SYSTEM_SUSPEND` |
| 中断控制器 | GICv2 MMIO 为主 | GICv3 affinity + **ICC_*_EL1** |

**ARM64 cpuidle 从零实现（经 PSCI）：**  
idle 驱动不再直接写平台寄存器「睡下去」，而是通过 PSCI 告知固件目标状态，由 **EL3/Secure monitor** 与电源域硬件协同。这样可在多 SoC 上复用同一套内核逻辑，**原因：把平台差异收敛到 `plat_psci_ops` 与设备树**，降低维护成本。

```c
/*
 * 示意：通过 PSCI 进入 CPU 级低功耗状态。
 * 原因：ARMv8 推荐由固件统一处理簇级一致性、掉电顺序与 GIC 握手，
 *       避免内核与各 BSP 各自实现导致 race 与不可移植。
 */
static int psci_enter_idle(struct cpuidle_device *dev,
			   struct cpuidle_driver *drv, int index)
{
	struct cpuidle_state *st = &drv->states[index];
	u32 fn = psci_function_id_cpu_suspend;
	u64 pstate = st->exit_latency; /* 平台将 latency/residency 编码进 pstate */

	return psci_ops.cpu_suspend(pstate, virt_to_phys(cpu_resume));
}
```

**GICv3 适配要点：**

- **Affinity routing：** SPI/PPI 的目标 CPU 与路由表与 GICv2 不同，需在 DT 与驱动中正确描述 `redistributor`。
- **System Register interface：** 在 EL1 使用 `ICC_SRE_EL1` 等使能 SRE，否则仍走 MMIO 旧路径，延迟与功耗均差。
- 与 cpuidle 联调时，需验证 **wake IRQ 在目标核上的 pending 行为**，避免 spurious wakeup。

**ATF 深度参与（`plat_psci_ops`）：**  
实现 `cpu_on` / `cpu_off` / `suspend` / `affinity_info` 等平台钩子，与 PMIC、时钟、复位树对齐。**原因：PSCI 语义固定，平台差异全部落在此处**，便于内核侧保持主线化。

---

### 2.2 big.LITTLE GTS 实现与功耗对比

**工作摘要：**

1. **全核可见调度：** 所有 CPU 同时在线，由调度器根据负载选择 big 或 LITTLE，而非 IKS 的「整簇切换」。
2. **CPU capacity：** 通过设备树 **`capacity-dmips-mhz`** 向调度器声明每核相对算力，使 wakeup 与负载均衡走向「能效最优核」。
3. **独立 cluster 调频：** big 与 LITTLE 各自 cpufreq 策略与 OPP 表，避免一锅粥调频拖垮能效。

**设备树片段示例（说明 capacity 语义）：**

```dts
/*
 * capacity-dmips-mhz：归一化算力/频率比，供调度器估算「同等算力下谁更省电」。
 * 原因：无此属性时，内核易把 A57 与 A53 视为同构，导致小核过载或大核空转。
 */
cpus {
	cpu0 { capacity-dmips-mhz = <1024>; }; /* LITTLE */
	cpu1 { capacity-dmips-mhz = <1024>; };
	cpu2 { capacity-dmips-mhz = <1024>; };
	cpu3 { capacity-dmips-mhz = <1024>; };
	cpu4 { capacity-dmips-mhz = <2048>; }; /* big */
	cpu5 { capacity-dmips-mhz = <2048>; };
};
```

**与 IKS 对比（内部实验室，相同工作负载集）：**

| 指标 | IKS（簇切换） | GTS（全局调度） | 说明 |
|------|----------------|-----------------|------|
| 典型功耗 | 基准 | **降低 13%–20%** | 多任务下更少不必要的大核拉起 |
| 多任务吞吐 | 基准 | **约 +60%** | 可并行使用 big+LITTLE |
| 实现复杂度 | 较低 | 高 | 需调度器、cpufreq、cpuidle 全栈配合 |

---

### 2.3 DDR 频率调节（devfreq）

**框架：** Linux **devfreq**，根据带宽利用率与场景 hint 在多个 OPP 间切换。

**实现要点：**

- 自研 SoC **devfreq 驱动**：注册 `devfreq_dev_profile`，提供 `target`/`get_cur_freq`/`get_dev_status`。
- **4 个 DDR OPP：** 200 / 400 / 533 / 800 MHz（示例值，按硅片实测稳定性裁剪）。
- **带宽计数器：** 从 MC/NoC 硬件计数器读取近期吞吐量，换算利用率。
- **场景感知 hint：** 视频播放、相机预览等通过 `devfreq_notifier` 或平台接口临时抬高地板频率，退出后释放。

**OPP 与实测功耗（单平台典型值，用于内部分析）：**

| OPP (MHz) | 相对带宽 | 相对 DDR 功耗（仪测） |
|-----------|----------|------------------------|
| 200 | 1.0× | 1.0× |
| 400 | ~2× | ~1.45× |
| 533 | ~2.7× | ~1.78× |
| 800 | ~4× | ~2.35× |

**成果：** 在综合场景下 **DDR 子系统动态功耗降低约 35%**（相对「恒高频率」策略），卡顿类回归通过 UI 与帧时间监控兜底。

---

### 2.4 Android Lollipop 适配

| 工作项 | 内容 | 备注 |
|--------|------|------|
| JobScheduler | 与内核唤醒对齐，减少无序闹钟唤醒 | 为 Doze 时代打基础 |
| ART 功耗评估 | 对比 Dalvik：**整机省电约 10%–15%**（视应用 mix） | JIT/AOT 与更优内联 |
| batterystats | 协助增强 `dumpsys batterystats` 维度 | 便于归因 CPU/DDR/wakelock |

---

## 三、踩坑与遗留问题

### 3.1 典型踩坑

1. **Cache 维护指令语义变化**  
   AArch64 上 `DC CIVAC` 与 `DC CVAC` 等对 PoC/PoU 的行为与 ARMv7 习惯不同，错误使用会导致 **use-after-free 式一致性 bug** 或性能回退。**原因：架构明确区分「无效化到 PoC」与「清理到 PoC」**，必须与 DMA 方向严格配对。

2. **GICv3 `ICC_SRE_EL3` 遗漏**  
   若 EL3 未使能 SRE，内核侧以为可走 sysreg 路径，实际仍 fallback 或 fault。**原因：三级异常等级各自有 SRE 使能位**，联调需 checklist。

3. **`__pa_symbol` 与 vmalloc/线性映射边界**  
   AArch64 内核镜像与 load 地址关系与 32 位内核不同，错误 `__pa` 会导致 **resume 跳错物理地址**。**原因：链接脚本与 KASLR 预研交织**，需严格使用官方宏与注释说明的适用场景。

### 3.2 遗留问题

- 部分 **DDR OPP** 在低温与高温 corner 下稳定性余量不足，需下一年与 PMIC DVFS 联动收紧。
- **GTS + interactive governor** 在突发触摸场景偶发大核晚起，已记录为交互路径优化 backlog。
- GICv3 + 多簇 **IPI 延迟** 与 idle 深度存在权衡，最深 C-state 未默认全开。

---

## 四、技术成长与方法论

- 系统掌握 **ARMv8 异常等级、PSCI、ATF 启动链**，能从 oops 反推到固件与 DT 配置错误。
- 建立 **「调度器 capacity — cpufreq — cpuidle — 硬件电源域」** 四维联调方法论。
- 开始将 **功耗数据与 A/B 实验** 绑定发布标准，减少「感觉省电」式结论。

---

## 五、关键数字汇总

| 指标 | 数值 |
|------|------|
| 交付代码量（内核 + ATF，约） | **5000 行** |
| GTS vs IKS 功耗 | **降低 13%–20%** |
| DDR devfreq 动态功耗 | **降低约 35%** |
| cpuidle 状态数（平台） | **5 个** |
| 年度闭环 Bug | **78 个** |

---

## 六、测试与验证矩阵（节选）

为降低 AArch64 首次商用的风险，建立分层验证：**单元（驱动自测）→ 压力（sched stress）→ 场景（Monkey/UI）→ 仪测（PowerMonitor）**。

| 层级 | 典型用例 | 通过标准 |
|------|----------|----------|
| cpuidle | `stress-ng --cpu 0` + 空闲穿插 | 无 lockup，退出延迟 < SLA |
| PSCI | 反复 `suspend/resume` 1000 次 | 无挂死、无文件系统损坏 |
| GICv3 | 高 IPI + 网络 IRQ | 无 lost interrupt 统计异常 |
| DDR devfreq | 视频 720p/1080p 播放 | 帧掉 < 0.5%，DDR 切换无 underrun |
| GTS | 浏览器 + 后台下载 | big 核占用与文档化模型一致 |

**仪测与软件计数器对齐：**  
同步抓取 `/sys/devices/system/cpu/cpu*/cpuidle/state*` 驻留时间、`time_in_state`、DDR 当前频率，与外部功耗仪做皮尔逊相关分析，**原因：确保优化在整机层面可复现**，避免仅盯单模块计数器。

---

## 七、协作与文档输出

- 与 **BSP/固件** 联合输出《PSCI 状态编码与 PMIC 时序》一页纸，减少跨部门沟通成本。
- 向应用与 Framework 团队提供 **《Lollipop 后台约束与唤醒预算》** 简报，解释 JobScheduler 与内核 wakelock 的边界。
- 代码评审强调：**任何 touch PSCI/GIC 的补丁必须附带 cpuidle 与 suspend 双路径测试结果**，避免「只测亮屏」类疏漏。

---

## 八、个人技术成长（细化）

| 能力维度 | 2014 年收获 |
|----------|-------------|
| 架构 | 能独立阅读 ARM DDI 与 TRM 中与 power/reset 相关章节并映射到 Linux 子系统 |
| 调试 | 熟练使用 ftrace `power:` 事件、dynamic debug、JTAG 最后一跳辅助 |
| 沟通 | 推动「功耗数字必须带测试场景与样本量」在组内成为默认要求 |

---

## 九、总结与展望

2014 年完成了从 **32 位到 64 位**、从 **IKS 到 GTS** 的两大转型，低功耗工作正式与 **固件标准（PSCI/ATF）** 和 **Android 系统行为（ART/JobScheduler）** 强耦合。下一年工作将自然延伸到 **EAS、IPA 与更精细的 EM** 预研，以及与 **Android 6.0 Doze** 的衔接。

**自我评价：** 在架构迁移期承担了「内核—固件—中断—内存子系统」横向拉通角色，交付节奏紧、问题密度高，但为团队后续 **3.x→4.x 主线跟进** 打下了可复用的平台基线。

---

## 十、附录：cpuidle 状态命名与驻留（示例）

下列为说明性示例，便于与 PM、测试对齐口径（非绑定具体芯片）。

| state | 名称（示例） | 退出延迟 (µs) | 目标 residency (µs) | 说明 |
|-------|----------------|-----------------|---------------------|------|
| 0 | WFI | ~1 | 0 | 浅睡，仅 CPU |
| 1 | C1 | ~10 | 100 | 时钟门控加深 |
| 2 | C2 | ~80 | 500 | 含部分逻辑掉电 |
| 3 | C3 | ~200 | 2000 | 簇级协调 |
| 4 | OFF | ~2000 | 10000 | 核电源门控，经 PSCI |

**原因：** `target_residency` 与 `exit_latency` 必须来自 **硅前仿真 + 硅后仪测** 的并集；低估 residency 会导致「睡不深」，高估则伤响应与交互体验。

---

## 十一、合规与安全备注

AArch64 迁移期间同步关注 **指针与大小端假设** 在驱动中的遗留；任何与休眠相关的汇编路径经 **PXN/PAN 与 KASLR 预研** 评审，避免为省电引入安全回退。该部分与 SEC 团队双周同步，2014 年未引入已知 CVE 级回归。

---

*（报告完）*

