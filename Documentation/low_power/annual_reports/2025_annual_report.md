# 2025 年度工作报告：Android 系统性能与功耗优化

| 项目 | 信息 |
|------|------|
| 年份 | 2025 (截至 Q1) |
| 角色 | 首席系统架构师 / AI 功耗 & 下一代计算平台方向负责人 |
| 所属部门 | Android 系统部 / 性能功耗与 AI 组（28 人） |
| SoC 平台 | Next-gen ARMv9 / Qualcomm Oryon Gen 2 |
| 制程工艺 | 3nm (2nd gen) / 2nm (试产) |
| 内核版本 | Linux 6.6 / 6.12 (Android LTS) |
| Android 版本 | Android 15 → 16 (Baklava, preview) |
| 产品形态 | AI 手机、AR 眼镜、端侧 Agent 设备 |

---

## 一、行业背景与技术环境

2025 年端侧 AI 从 "功能" 升级为 "Agent"。AI 不再只是被动调用的工具，而是
主动感知环境、规划任务、调用 APP 的智能体。这对功耗管理带来了根本性的范式变化。

**关键行业事件：**
- AI Agent 成为行业焦点：手机 AI 可以主动操作 APP、安排日程、处理邮件
- Qualcomm Snapdragon 8 Elite 2 预告（Oryon Gen 2, 2nm）
- ARM 发布 Cortex-X5 + CSS (Compute Sub-System) 解决方案
- Android 16 (Baklava) Developer Preview: 新的 AI 集成 API
- Apple Intelligence 2.0 加深端侧 AI 集成
- Meta Orion AR 眼镜 / Apple Vision Pro 2 推动空间计算
- 2nm 工艺开始试产（TSMC N2, Samsung 2nm GAA）

**性能与功耗领域进展：**
- ADPF 持续增强：支持 AI workload 标记
- Android 16 引入 "AI Power Budget" 概念
- MoE (Mixture of Experts) 模型降低端侧推理功耗
- Always-Sensing 模式（环境感知 AI 持续运行）
- 跨设备 AI 推理（手机-耳机-眼镜协同）

---

## 二、核心工作内容

### 2.1 AI Agent 功耗管理 — 全新范式

**背景：** AI Agent 主动执行任务（如自动回复邮件、预订餐厅、整理照片），其行为不可预测，
传统的 "场景识别 → 策略匹配" 模式失效。

**具体工作：**

1. **Agent 功耗模式分析**
   ```
   传统 AI 功能 (被动调用):
   用户按钮 → 触发推理 → 返回结果 → 释放资源
   功耗模式: 脉冲式, 可预测
   
   AI Agent (主动执行):
   Agent 持续监听 → 感知到事件(新邮件) → 规划动作序列
   → 调用 APP A (打开邮件) → 分析内容 → 调用 APP B (日历)
   → 创建日程 → 调用 APP C (导航) → 预查路线
   → 生成通知给用户
   
   功耗模式: 连续式, 不可预测, 涉及多个 APP 和多次推理
   ```

2. **AI Power Budget 框架**
   ```java
   /* Android 16 概念: 为 AI Agent 分配功耗预算 */
   class AiPowerBudgetManager {
       // AI 功耗预算基于电池剩余和用户偏好
       long getAvailableBudgetMw() {
           int batteryPercent = getBatteryLevel();
           
           if (batteryPercent > 50) return 500;  // 500mW 预算
           if (batteryPercent > 20) return 300;   // 紧缩预算
           if (batteryPercent > 10) return 100;   // 最低预算
           return 0;  // 低电量禁止 Agent
       }
       
       // Agent 每个 action 消耗预算
       boolean requestBudget(String agentId, long estimatedMw, long durationMs) {
           long remaining = getAvailableBudgetMw();
           
           if (estimatedMw > remaining) {
               // 超预算 → 降级执行 (小模型/低精度)
               suggestDegradedExecution(agentId);
               return false;
           }
           
           allocateBudget(agentId, estimatedMw, durationMs);
           return true;
       }
   }
   ```

3. **Agent 任务链功耗优化**
   ```
   未优化的 Agent 任务链:
   [推理1] → 等待 → [打开APP] → 等待 → [推理2] → 等待 → [操作APP]
   每个环节之间 CPU/NPU 频繁上下电 → 开关功耗浪费大
   
   优化后:
   [推理1 + 预加载APP] → [推理2 + 操作APP]  (pipeline 并行)
   减少等待间隙 → NPU 保持在稳定工作状态 → 避免频繁上下电
   
   效果: 同样任务链总功耗降低 25%, 延迟降低 40%
   ```

4. **Agent 优先级与中断**
   - 用户主动交互时，Agent 自动降低优先级（减少 CPU/NPU 抢占）
   - Agent 在充电时可以执行更多后台任务（功耗预算放大 3x）
   - Agent 的任务可以被延迟到 WiFi 环境执行（避免 5G 高功耗）

---

### 2.2 MoE (Mixture of Experts) 模型功耗优化

**背景：** MoE 架构只激活模型的部分参数（如 Mixtral 8x7B 每次只用 2 个 expert），
大幅降低了端侧推理功耗。

**具体工作：**

1. **MoE vs Dense 模型功耗对比**
   ```
   Dense 模型 (Llama 2 7B, INT4):
   - 每次推理激活全部 7B 参数
   - DDR 读取: ~100MB/token
   - 功耗: 2.0W (优化后)
   - 速度: 18 tok/s
   
   MoE 模型 (类 Mixtral, 总 14B 但每次用 4B, INT4):
   - 每次推理只激活 2/8 expert (4B 参数)
   - DDR 读取: ~60MB/token (仅读取活跃 expert)
   - 功耗: 1.4W
   - 速度: 22 tok/s
   - 质量: 接近 14B Dense 模型
   
   能效对比:
   Dense 7B:  18/2.0 = 9.0 tok/J
   MoE 14B:   22/1.4 = 15.7 tok/J (+74%)
   ```

2. **MoE Expert 预加载优化**
   ```
   MoE 的问题: Router 决定使用哪个 expert 后才能加载
   → 如果 expert 不在 cache 中 → DDR 冷读 → 延迟增加
   
   优化: Expert 预测与预加载
   - 统计每个 token position 的 expert 使用分布
   - 预加载最可能被使用的 expert 到 NPU SRAM
   - 命中率: ~85%
   
   效果:
   - 冷读 miss: 每次 +3ms 延迟 + 额外 DDR 功耗
   - 预加载后: 85% 命中 → 平均延迟降低 2.5ms
   ```

3. **MoE 的 DDR 访问模式优化**
   - Expert 参数在 DDR 中的布局优化（按 expert 分组，而非按层分组）
   - 利用 DDR burst 访问模式（连续地址读取效率高 2x）
   - DDR 带宽利用率从 60% 提升到 **82%**

---

### 2.3 AR 眼镜功耗管理预研

**背景：** AR 眼镜的电池容量极小（~300mAh, vs 手机 5000mAh），但需要运行 display + camera + AI，
功耗约束极端严格。

**具体工作：**

1. **AR 眼镜功耗预算**
   ```
   电池: 300mAh × 3.8V = 1.14Wh
   目标续航: 2 小时
   → 总功耗预算: 570mW (极其紧张)
   
   功耗分配:
   ├── Display (microLED/OLED): 120mW (21%)
   ├── Camera (环境感知): 80mW (14%)
   ├── AP (Android + AI): 200mW (35%)
   ├── Connectivity (BT/WiFi): 60mW (11%)
   ├── Audio (骨传导): 30mW (5%)
   ├── Sensors (IMU/ToF): 30mW (5%)
   └── 其他 (PMIC/misc): 50mW (9%)
   
   AP 200mW 预算要运行:
   - Android OS + SystemUI
   - 环境感知 AI (物体检测/文字识别)
   - UI 渲染 (HUD 界面)
   → 比手机的 CPU 功耗低 10x, 对每一行代码都需要功耗意识
   ```

2. **AR 专用 Android 精简方案**
   ```
   Full Android: ~1.5W idle (手机)
   
   AR Android (精简后):
   - 去除不需要的系统服务 (Telephony/SMS/MMS → 通过手机代理)
   - SystemUI 极度精简 (只保留 HUD overlay)
   - SurfaceFlinger 降频运行 (30Hz 足够，MicroLED 残影小)
   - Background app 限制为 0 (任何后台 APP 立即冻结)
   - Zygote 内存优化 (减少常驻 daemon)
   
   目标: Android idle 功耗 < 100mW
   ```

3. **手机-眼镜 AI 推理卸载**
   ```
   轻量任务 → 眼镜端处理 (MCU/DSP):
   - 文字识别 (OCR, 小模型)
   - 手势识别 (IMU 数据)
   
   中等任务 → 眼镜 AP 处理:
   - UI 渲染
   - 导航 AR overlay
   
   重任务 → 卸载到手机:
   - 物体识别 (大模型)
   - 实时翻译 (LLM)
   - 场景理解 (多模态模型)
   
   通信: BLE 5.3 低功耗链路 (< 10mW)
   ```

---

### 2.4 2nm 工艺功耗特性预评估

**具体工作：**

1. **2nm GAA (Gate-All-Around) vs 3nm FinFET**
   ```
   预期改善：
   - 同性能功耗降低: 25-30%
   - 同功耗性能提升: 10-15%
   - 漏电改善: 40% (GAA 栅极控制力更强)
   
   对功耗管理的影响:
   - 漏电改善 → idle 功耗更低 → deep idle 的收益相对减小
   - 动态功耗仍由 CV²f 决定 → DVFS 仍然重要
   - GAA 工艺 corner 变化 → OPP 表需要重新 characterize
   ```

2. **2nm 对端侧 AI 的意义**
   - 同样功耗预算下 NPU 算力提升 30% → 可以跑更大的模型
   - 或者同样模型功耗降低 25% → 续航改善
   - 预计 2026 年量产的 SoC 将可以在手机上流畅运行 30B+ 模型

---

### 2.5 十五年工作回顾与方法论沉淀

**具体工作：**

1. **功耗优化方法论总结**
   ```
   15 年经验凝练为 "四步法":
   
   Step 1: MEASURE (量)
   - 没有测量就没有优化
   - 工具: 功耗仪 + Perfetto + eBPF + Battery Historian
   
   Step 2: ATTRIBUTE (归因)
   - 找到功耗的根因，而不是表象
   - 方法: 逐模块关闭/功耗分解/Wakeup Source 审计
   
   Step 3: OPTIMIZE (优)
   - 选择 ROI 最高的优化点
   - 原则: 先关(不需要的)→再降(频率/电压)→再优(算法/路径)
   
   Step 4: REGRESS (守)
   - 优化成果必须通过 CI 守护
   - 任何 > 3% 的功耗退化必须在 3 天内修复
   ```

2. **跨层优化思维模型**
   ```
   APP 层:     "不做无用功" — 减少后台活动、适配 Dark Mode
   Framework:  "精确控制" — 场景识别、ADPF、刷新率管理
   HAL:        "标准桥接" — Power HAL、Thermal HAL
   Kernel:     "高效执行" — EAS、cpuidle、Runtime PM
   Firmware:   "安全兜底" — PSCI、SCMI、ATF
   Hardware:   "物理基础" — 工艺、电压域、Power Gating
   
   最大的功耗浪费通常在最上层 (APP/Framework)
   最难的功耗优化通常在最下层 (Kernel/Firmware/Hardware)
   最有效的功耗优化是跨层协同
   ```

---

## 三、技术成长与认知

### 十五年核心能力演进

| 时期 | 核心能力 | 主战场 |
|------|---------|--------|
| 2010-2012 | 时钟/DVFS/Suspend | 内核驱动 |
| 2013-2015 | big.LITTLE/EAS/PSCI | 内核调度/固件 |
| 2016-2017 | schedutil/DynamIQ/SCMI | 内核框架/协议 |
| 2018-2019 | SurfaceFlinger/Systrace/VRR | Android Framework |
| 2020-2021 | PerformanceHint/LTPO/ADPF | Framework-HAL |
| 2022-2023 | GameMode/LLM/WiFi7 | Framework-AI |
| 2024-2025 | Agent/MoE/AR | AI-全栈 |

### 2025 年认知
- AI Agent 让功耗管理从 "响应式" 变为 "预测式" — 需要预测 Agent 的下一步行为
- MoE 证明了模型架构本身就是功耗优化的杠杆 — 不只是硬件和系统软件的事
- AR 眼镜把功耗约束推到极限 — 570mW 跑整个 Android + AI
- 15 年下来，功耗优化的本质没变：**让不需要工作的东西停下来，让需要工作的东西高效完成**

### 年度关键数字 (截至 Q1)
| 指标 | 数值 |
|------|------|
| Agent 任务链功耗降低 | 25% |
| MoE 模型能效提升 | 74% (vs Dense) |
| AR Android idle 功耗目标 | < 100mW |
| Expert 预加载命中率 | 85% |
| DDR 带宽利用率 | 60% → 82% |

---

## 四、未来展望

1. **端侧 Agent 生态**：AI Agent 将成为手机 OS 的核心，功耗管理必须与之共生
2. **2nm/1.4nm 工艺**：工艺进步带来的功耗红利在减少，软件优化的价值在增加
3. **空间计算 (AR/VR/MR)**：超低功耗约束催生全新的系统架构
4. **异构计算标准化**：CPU/GPU/NPU/DSP 的统一功耗管理框架
5. **可持续计算**：功耗优化不仅是用户体验问题，也是地球环境问题

---

> **回望 15 年**：从 2010 年用万用表量 ARM11 的底电流，到 2025 年为 AI Agent 设计功耗预算框架。
> 硬件从 65nm 演进到 3nm，内核从 2.6.32 演进到 6.6，Android 从 Eclair 演进到 Baklava。
> 但核心命题始终未变：**在有限的能量下，提供最好的体验。**
