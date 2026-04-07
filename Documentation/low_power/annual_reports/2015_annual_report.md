# 2015 年度工作报告：EAS 预研、IPA 与 Android 深度休眠

| 项目 | 信息 |
|------|------|
| 年份 | 2015 |
| 角色 | 高级工程师 / 功耗优化组 Tech Lead |
| 团队规模 | **5 人**（分工：调度/热/DDR/Framework 接口） |
| SoC 平台 | Cortex-A72 + A53 big.LITTLE |
| 制程工艺 | 28nm / **16nm FinFET** |
| 内核版本 | Linux 3.18 → 4.1 |
| Android 版本 | Android 5.0 Lollipop → 6.0 Marshmallow |
| 产品形态 | 全金属机身旗舰、快充初普及 |

---

## 一、行业背景与技术环境

2015 年手机 SoC 进入 **16nm FinFET** 量产窗口，漏电相对平面工艺下降，但 **动态功耗密度** 与 **热节流** 矛盾加剧。ARM 与 Linaro 推动 **EAS（Energy Aware Scheduling）** 将「能效模型」引入 CFS，使调度决策显式考虑 **每 OPP 能耗**。与此同时，Google 在 Android 6.0 引入 **Doze** 与 **App Standby**，系统级 idle 优化从内核向上延伸到 Framework。

**关键趋势：**

- big.LITTLE 调度从 GTS 走向 **「能量最优放置」** 的可行工程化。
- **IPA（Intelligent Power Allocation）** 在移动 GPU/CPU 争用功耗封顶时出现。
- **Runtime PM** 从「试点几个驱动」进入「外设全覆盖」阶段。
- 热管理从单纯 **温度阈值** 走向 **功耗估计 + EM（Electrical Model）**。

---

## 二、核心工作内容

### 2.1 EAS 预研与初步集成

**路径：** 自 ARM/Linaro 获取 **out-of-tree EAS patch**，在 4.1 基线上做移植与 SoC 参数化。

**Energy Model 建立：**

- 对 **每个 OPP** 实测 **动态功耗** 与 **漏电（leakage）** 分量（温箱 + 仪测 + 软件负载）。
- 将结果写入调度器可读表（随内核版本演进，形态为 EM 表或 DT 绑定）。

**调度钩子（概念）：**  
在 `select_task_rq_fair` 路径上增加 **能量估计**，在 `find_energy_efficient_cpu` 中选择 **完成同等算力所需能量最小** 的 CPU。**原因：纯算力均衡在 big.LITTLE 上往往不是能效最优**，EAS 用模型显式折衷。

```c
/*
 * 示意：能量估计使用 per-CPU 的 util 与 EM 表查询。
 * 原因：将「迁移带来的能耗变化」量化，避免大核被频繁试探性拉起。
 */
static int find_energy_efficient_cpu(struct task_struct *p, int prev_cpu)
{
	/* 伪代码：遍历 allowed mask，计算 energy = f(util, freq, em_table) */
	return best_energy_cpu; /* 由 EM + PELT/util 信号驱动 */
}
```

**测试：** LISA、rt-app 合成负载 + 真实应用 mix（社交、浏览器、游戏轻载）。

**结果（内部基准）：**

| 场景类型 | vs 基线（GTS + ondemand/interactive） |
|----------|----------------------------------------|
| 轻负载（阅读/待机滑动） | **功耗降低约 34%** |
| 混合日常（多应用切换） | **功耗降低约 24%** |

---

### 2.2 IPA（Intelligent Power Allocation）集成

**动机：** SoC 有 **CPU + GPU 总功耗预算**（受限于 skin temperature 与 PMIC 能力），阶梯式 `step_wise` thermal governor 响应慢、振荡大。

**方案：** 采用 **PID 控制器** 替代 `step_wise`，按 **贡献权重** 在 CPU 簇与 GPU 间分配功率额度。

**直觉：** 当游戏 GPU 占用高时，**提高 GPU 权重** 可保帧；当可 offload 到 CPU 时则反向调节。**原因：同一热预算下，边际帧率对功率的敏感度 CPU/GPU 不同**，PID + 权重比固定分档更平滑。

**设备树配置示例（说明性）：**

```dts
/*
 * IPA 相关节点：定义控制器增益与设备贡献比例。
 * 原因：不同机型散热与屏幕亮度策略不同，需可 OTA 调整的参数面。
 */
thermal-zones {
	soc_thermal: soc-thermal {
		polling-delay-passive = <100>;
		trips {
			skin_alert: trip-point-0 {
				temperature = <42000>;
				hysteresis = <2000>;
				type = "passive";
			};
		};
		cooling-maps {
			map0 {
				cooling-device = <&ipa_cdev 850 850 850>;
				contribution = <1024>;
			};
		};
	};
};
```

**游戏场景：** 同画质设定下，平均帧率由 **约 45 fps 提升至约 52 fps**（约 **+15%**），同时热节流触发次数下降。

---

### 2.3 Android Doze 模式适配

**工作：** 理清 **Doze 状态机**（idle、maintenance window、whitelist）、Alarm 对齐与 **resume 路径** 性能。

**maintenance window：** 在深度 doze 间插入短暂维护窗，合并网络与同步，需与内核 **timer slack、RTC alarm** 行为一致。

**resume 速度优化：** 灭屏唤醒路径从 **约 800ms 缩短至约 350ms**（驱动与 Framework 并行初始化、减少不必要的 full scan）。

**成果：** 实验室灭屏待机场景 **功耗降低约 38%**（相对未适配 Doze 的基线构建）。

| 子项 | 手段 |
|------|------|
| Alarm 批处理 | 与 JobScheduler 窗口对齐 |
| 网络 | 维护窗内集中收发 |
| Sensor | 非关键 sensor 延迟上报 |
| Resume | 关键路径并行化、延迟非关键服务 |

---

### 2.4 Runtime PM 第二轮推广

**覆盖模块（8 个）：** USB、EMMC、WiFi、Audio、I2C、SPI、UART、DMA。

**共性工作：**

- 为每类设备补齐 **`runtime_suspend`/`runtime_resume`** 与 **autosuspend_delay** 默认值。
- 与 **genpd** 联动：子设备休眠触发父域级联，避免孤岛时钟/电源域泄漏。

**典型坑：** **USB parent-child 依赖** — hub 未 suspend 时子设备无法真正省电；需梳理 `pm_runtime_set_active` 与 `rpm_link`。**原因：USB 拓扑是树形 PM 依赖**，与简单「单设备 RPM」不同。

**亮屏 idle：** 外设 RPM 全覆盖后，**亮屏静止 idle 功耗降低约 15%**（同亮度、同网络条件下）。

---

## 三、踩坑与根因分析

### 3.1 EM leakage 不准 → 高温决策错误

漏电模型在 **高温 corner** 下若沿用室温标定，会 **低估静置功耗**，导致 IPA/EAS 以为仍有余量，实际已触皮温。**对策：** leakage 按温度分段拟合 + 产线抽样回归。

### 3.2 EAS 过激使用小核 → 掉帧

轻载下 EAS 倾向小核，但 **触摸后短时 burst** 需快速上大核；参数过激进会出现 **UI jank**。**对策：** 引入交互 boost 与 **prefer_idle** 类启发式，与产品共同定义 SLA。

### 3.3 EAS 与 interactive governor 冲突

interactive 基于 **采样与 hispeed**，与 EAS 的 **placement** 决策在时间上错位，可能出现 **频繁迁移 + 频繁升频**。**对策：** 推动实验分支统一使用 **schedfreq/schedutil 方向**（为 2016 铺路）或限定 EAS 与 conservative 组合做 A/B。

---

## 四、团队管理与协作

- **5 人小组** 周会固定「数字闭环」：每个优化必须带仪测或标准化脚本结果。
- 与 **热设计/结构** 共享 skin 模型与 IPA 日志，缩短「体感烫」类问题定位周期。
- 实习生承担 LISA 用例维护，释放核心同学做调度器主线 merge。

---

## 五、技术成长

- 深入理解 **EM 表、PID、thermal cooling device** 的耦合与稳定性分析（Nyquist 直觉 + 实测调参）。
- 掌握 **Android 6.0 电源状态机** 与内核 **autosleep/wakelock** 的边界。
- Tech Lead 技能：**任务拆解、风险清单、跨组 SLA**。

---

## 六、关键数字汇总

| 指标 | 数值 |
|------|------|
| EAS 混合场景功耗 | **降低约 24%** |
| EAS 轻载 | **降低约 34%** |
| IPA 游戏帧率 | **45 → 52 fps（约 +15%）** |
| Doze 灭屏待机 | **降低约 38%** |
| Resume 延迟 | **800ms → 350ms** |
| Runtime PM 覆盖模块 | **8 个** |
| 年度闭环 Bug | **85 个** |

---

## 七、遗留问题与下年输入

- EAS **主线化** 仍依赖社区节奏，out-of-tree 分支 merge 成本高。
- IPA PID 参数 **按 SKU/地区** 仍需可配置矩阵，避免「一台调好、另一台振荡」。
- **WiFi/BT 共 PCIe** 场景下 RPM 顺序与唤醒源登记需持续加固。

---

## 八、测试资产与自动化（节选）

| 资产名 | 用途 |
|--------|------|
| `eas_sanity.sh` | 每日构建后轻载 + 仪测门槛 |
| `ipa_step_response.py` | PID 阶跃响应与超调量记录 |
| `doze_cycle_monkey.monkey` | Doze 进出压测脚本 |

**原因：** 2015 年调度/热/系统休眠交织，**无自动化则回归周期扛不住** 周迭代。

---

## 九、附录：功耗归因表（混合场景示例）

| 子系统 | 优化前占比 | 主要手段 | 优化后占比（趋势） |
|--------|------------|----------|---------------------|
| CPU big | 28% | EAS + IPA | 22% |
| CPU LITTLE | 18% | EAS | 20%（总功耗降，占比可能上升） |
| GPU | 15% | IPA 权重 | 14% |
| DDR | 12% | 继承 devfreq | 11% |
| 外设 | 20% | RPM 推广 | 17% |
| 其他 | 7% | — | 6% |

*注：占比为内部同场景仪测分解示意，非绝对通用比例。*

---

## 十、总结

2015 年在 **调度能效（EAS）**、**热预算分配（IPA）**、**系统休眠（Doze）**、**外设 RPM** 四条线上同时推进，个人角色从 **单点专家** 转为 **5 人组 Tech Lead**。关键经验：**任何「智能」策略都必须有标定数据与失败兜底**，否则在量产分散性面前极易翻车。

---

## 十一、自我评价与展望

在 **EAS 未主线** 的前提下完成可演示、可量产的集成，风险意识与分支管理是年度最大收获。2016 年将重点转向 **schedutil/PELT**、**Doze on the Go** 与 **PCIe ASPM** 等更贴近硬件接口的优化，并持续收敛 thermal 与调度参数的平台化配置。

---

## 十二、附录：PID 参数调参记录（示意）

| 参数 | 初值 | 稳定后范围 | 说明 |
|------|------|------------|------|
| Kp | 1.2 | 0.8–1.5 | 过大导致功率振荡，过小响应慢 |
| Ki | 0.05 | 0.02–0.08 | 消除稳态误差，需防 windup |
| Kd | 0.1 | 0–0.2 | 抑制超调，传感器噪声大时需限幅 |

**原因：** IPA 回路同时受 **游戏负载突变** 与 **环境温度慢变** 驱动，单一 PID 需在「阶跃游戏启动」与「室外高温爬升」两类测试下折衷；记录表便于跨项目复用。

---

## 十三、风险管理清单（年度复盘）

1. **分支漂移：** EAS patch 与主线 4.1 差异每季度评估一次 merge 成本。  
2. **仪测环境：** 统一 25℃ 基准室与 35℃ 压力室，避免结论不可比。  
3. **竞品对标：** 每季度更新一款竞品机的同场景 idle 与游戏功耗曲线，防止「自我感动式」优化。  
4. **合规：** Doze 白名单策略与厂商预装应用审计，避免破坏用户可感知的后台约束一致性。  

---

## 十四、术语速查（新人 onboard）

| 术语 | 一句话解释 |
|------|------------|
| EAS | 在 CFS 中引入能量模型，选核时显式考虑能效 |
| EM | Energy Model：OPP 级功耗与性能表 |
| IPA | 在热预算下智能分配 CPU/GPU 功率 |
| Doze | Android 6 深度 idle：批处理闹钟与网络 |
| genpd | 通用电源域：设备树描述域依赖与 idle 状态 |
| RPM | Runtime PM：按需休眠外设 |

---

*（报告完）*
