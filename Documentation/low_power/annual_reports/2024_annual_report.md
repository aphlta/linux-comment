# 2024 年度工作报告：Android 系统性能与功耗优化

| 项目 | 信息 |
|------|------|
| 年份 | 2024 |
| 角色 | 首席系统架构师 / 端侧 AI × 功耗 方向负责人 |
| 所属部门 | Android 系统部 / 性能功耗与 AI 组（25 人） |
| SoC 平台 | ARMv9.2 Cortex-X925+A725+A520 |
| 制程工艺 | 3nm (TSMC N3E) |
| 内核版本 | Linux 6.1 / 6.6 (Android LTS) |
| Android 版本 | Android 14 → 15 |
| 产品形态 | AI 旗舰手机、折叠屏、端侧多模态 AI |

---

## 一、行业背景与技术环境

2024 年端侧 AI 从概念走向产品化。Galaxy AI、Gemini Nano、Apple Intelligence
使端侧大模型成为手机标配功能。对功耗团队而言，这意味着 AI 推理功耗从偶尔触发变为持续存在。

**关键行业事件：**
- Samsung Galaxy S24 系列发布 "Galaxy AI"（端侧翻译、通话摘要、图片编辑）
- Google Gemini Nano 集成到 Pixel 8 Pro / 9 系列
- Apple Intelligence 发布（iOS 18 + A17 Pro / M 系列）
- Qualcomm Snapdragon 8 Elite (Oryon CPU, 3nm) — 自研核取代 Cortex
- MediaTek Dimensity 9400 (全大核 second gen)
- Android 15：Private Space、Predictive Back 完善、Health Connect 增强
- Linux 6.6 成为新的 Android LTS

**性能与功耗领域进展：**
- ADPF 3.0：支持 GPU work duration report、多 session 协调
- Android 15 增强了 APP 电池优化（更智能的 Restricted bucket）
- Qualcomm Oryon 自研核改变了 ARM 标准核的功耗 baseline
- 端侧模型从 7B 向 13B+ 发展，需要更大内存和带宽
- Always-on AI（后台持续运行的 AI 功能）成为新的功耗挑战

---

## 二、核心工作内容

### 2.1 Always-on AI 功耗管理框架

**背景：** Galaxy AI 的 "实时翻译"、"通话摘要"、"相机场景检测" 等功能需要 AI 模型持续运行，
功耗管理不再是 "推理结束就释放"，而是 "如何在持续推理中维持可接受的功耗"。

**具体工作：**

1. **Always-on AI 功耗分级**
   ```
   AI 功能分级 (按功耗和延迟要求)：
   
   Tier 0 — Always Active (< 50mW, 实时响应)
   ├── 语音唤醒词检测 (Hey Google / Hi Bixby)
   ├── 手势识别 (隔空操作)
   └── 运行在 DSP/Sensor Hub 上，不唤醒 AP
   
   Tier 1 — Background Continuous (50-300mW, 秒级响应)
   ├── 通话实时翻译 (ASR + MT + TTS pipeline)
   ├── 实时字幕
   └── 运行在 NPU 低功耗模式，AP 低频
   
   Tier 2 — On-demand Burst (300mW-3W, 秒级完成)
   ├── 图片编辑 AI (擦除物体/风格化)
   ├── 文本摘要生成
   └── NPU 全速 + 大核 + 高带宽 DDR
   
   Tier 3 — Heavy Compute (3W+, 分钟级)
   ├── Stable Diffusion 端侧生图
   ├── 大模型长对话
   └── 全资源占用，需要 thermal 管理
   ```

2. **Tier 1 持续推理的功耗优化**
   ```java
   /* 通话实时翻译的功耗优化框架 */
   class RealtimeTranslationPowerManager {
       // ASR (语音识别) + MT (机器翻译) + TTS (语音合成) 三段 pipeline
       
       void optimizePipeline() {
           // 1. VAD (Voice Activity Detection) 门控
           //    - 检测到静默时暂停整个 pipeline
           //    - 静默占通话时间的 40-60%
           //    → 功耗节省 40-60%
           enableVoiceActivityDetection();
           
           // 2. ASR 使用轻量模型
           //    - 短句 (<10 words) 用 tiny model (NPU 低频)
           //    - 长句 (>10 words) 用 standard model
           enableAdaptiveModelSelection();
           
           // 3. TTS 使用缓存
           //    - 常见短语 ("你好","谢谢") 使用预合成音频
           //    → 避免 TTS 模型推理
           enableTtsCache();
           
           // 4. DDR 带宽优化
           //    - Pipeline 各阶段错开执行
           //    - 避免 ASR + MT 同时访问 DDR
           enablePipelineStaging();
       }
   }
   ```

3. **效果**
   | AI 功能 | 基线功耗 | 优化后 | 节省 |
   |---------|---------|-------|------|
   | 通话翻译 (持续) | 850mW | 380mW | **55%** |
   | 实时字幕 | 620mW | 290mW | **53%** |
   | 相机场景检测 | 450mW | 210mW | **53%** |
   | 语音助手待命 | 180mW | 45mW (DSP) | **75%** |

---

### 2.2 ADPF 3.0 / GPU Work Duration

**背景：** ADPF 3.0 将 PerformanceHint 扩展到 GPU 维度，GPU 也可以根据实际工作量动态调频。

**具体工作：**

1. **GPU Work Duration Report**
   ```
   之前 (ADPF 2.0):
   - APP 只上报 CPU 工作时长
   - GPU 的调频由 GPU 驱动独立决策（基于 busy/idle 采样）
   - 问题：GPU 驱动无法知道 "这帧需要在 16.67ms 内完成"
   
   ADPF 3.0:
   - APP 额外上报 GPU 工作时长
   - Power HAL 同时调控 CPU 和 GPU 的频率
   - GPU 也参与 target/actual 闭环控制
   
   APP 每帧上报:
   {
       cpu_duration: 6ms,
       gpu_duration: 10ms,    // ← 新增
       target_duration: 16.67ms,
   }
   
   Power HAL 决策:
   - CPU 有 10ms 余量 → 降频
   - GPU 只有 6ms 余量 → 可以适度降频但不能太低
   ```

2. **CPU-GPU 联合功耗优化**
   ```cpp
   void PowerHintSession::reportWorkDurations(
       int64_t cpuDurationNs, int64_t gpuDurationNs) {
       
       double cpuRatio = (double)cpuDurationNs / targetNs_;
       double gpuRatio = (double)gpuDurationNs / targetNs_;
       
       // 瓶颈在 GPU → boost GPU, relax CPU
       if (gpuRatio > cpuRatio && gpuRatio > 0.8) {
           adjustGpuFreq(+10%);
           adjustCpuUclamp(-10%);
       }
       // 瓶颈在 CPU → boost CPU, relax GPU
       else if (cpuRatio > gpuRatio && cpuRatio > 0.8) {
           adjustCpuUclamp(+10%);
           adjustGpuFreq(-10%);
       }
       // 两者都有余量 → 都降
       else if (cpuRatio < 0.5 && gpuRatio < 0.5) {
           adjustCpuUclamp(-20%);
           adjustGpuFreq(-20%);
       }
   }
   ```

3. **效果**
   | 游戏 | 无 GPU hint | 有 GPU hint | 功耗节省 |
   |------|-----------|-----------|---------|
   | 原神 60fps | 4.1W | 3.5W | **15%** |
   | 崩铁 60fps | 3.6W | 3.1W | **14%** |
   | 王者 120fps | 3.0W | 2.6W | **13%** |

---

### 2.3 Qualcomm Oryon 自研核适配

**背景：** Snapdragon 8 Elite 使用 Qualcomm 自研的 Oryon 核替代 ARM Cortex，
性能和功耗特性完全不同，需要重新校准所有策略。

**具体工作：**

1. **Oryon vs Cortex 能效对比**
   ```
   Oryon 特点：
   - 宽发射（8-wide decode）vs Cortex X4 (6-wide)
   - 更大的 L2 cache (12MB vs 2MB)
   - 更高的 IPC，同频性能高 20-30%
   
   功耗特性：
   - 低频能效远优于 Cortex (大 L2 cache 减少 DDR 访问)
   - 高频功耗更高 (宽前端功耗大)
   - 最低频率仍然比 Cortex A520 高 (没有超低功耗核)
   
   Oryon@1.0GHz: 50mW (vs X4@1.0GHz: 80mW, A520@1.0GHz: 30mW)
   Oryon@3.0GHz: 1.5W (vs X4@3.0GHz: 1.2W)
   Oryon@4.3GHz: 4.5W (峰值)
   ```

2. **Energy Model 重新校准**
   - 全部 OPP 点重新实测功耗
   - EAS Energy Model 重新注册
   - 发现 Oryon 在 1.5-2.5GHz 区间的能效最优 → 调度器倾向于在此区间运行

3. **util_clamp / cgroup 策略重新调优**
   ```
   Oryon 策略 (vs 传统 ARM 策略):
   
   传统 ARM:
   - 后台 uclamp_max=30% → 确保只在小核运行
   
   Oryon (无小核):
   - 后台 uclamp_max=25% → 确保 Oryon 运行在最低频
   - 后台 cpu.max=20% → 限制 CPU 时间配额
   - 组合效果：后台任务以最低频快速执行完毕
   ```

---

### 2.4 Android 15 功耗管理新特性适配

**具体工作：**

1. **Private Space 功耗隔离**
   - Android 15 的 Private Space 是一个独立的用户空间
   - 锁定 Private Space 后，其中的 APP 应完全停止（等同于关机用户）
   - 实现：Private Space 锁定时冻结所有关联进程 + 释放 wakelock

2. **Predictive Back 动画优化**
   - Predictive Back 在返回手势时预览上一个页面
   - 需要同时渲染两个 Activity 的 surface → GPU 负载翻倍
   - 优化：使用 SurfaceControl transaction 而非完整渲染
   - 预览使用缩略图而非实时渲染

3. **更智能的 Restricted Bucket**
   ```
   Android 15 Restricted Bucket 增强:
   - 自动识别 "装死" APP（申请了通知权限但从不发通知，实际在后台挖矿/广告）
   - 基于 ML 模型判断 APP 是否真的有用户价值
   - 无用户价值的 APP 自动进入 Restricted → 几乎无 CPU/网络配额
   
   SoC 侧配合:
   - 为 ML 判断模型提供功耗特征数据（每个 UID 的 CPU/GPU/DDR 使用量）
   - 高功耗但低用户交互的 APP 权重更高
   ```

---

### 2.5 LPDDR5T 功耗管理

**具体工作：**

1. **LPDDR5T vs LPDDR5**
   | 特性 | LPDDR5 | LPDDR5T |
   |------|--------|---------|
   | 最高速率 | 6400Mbps | 9600Mbps |
   | 带宽 (双通道) | 51.2 GB/s | 76.8 GB/s |
   | 电压 | 1.05V | 1.05V |
   | 高速功耗 | 850mW | 1200mW |

2. **LLM 推理受益分析**
   ```
   LPDDR5T 对 LLM Decode 阶段的影响:
   - DDR 带宽提升 50% → Decode 速度从 18 tok/s 提升到 24 tok/s
   - 但 DDR 功耗也增加 40%
   - 净能效: 24/1200 = 20 tok/J vs 18/850 = 21 tok/J
   → 能效基本持平，但速度更快（用户体验更好）
   
   策略：
   - LLM 推理时锁定高频 DDR (速度优先)
   - 非 LLM 场景保持 devfreq 动态调节
   ```

3. **LPDDR5T 的更多频率档位利用**
   - LPDDR5T 支持更多中间频率点
   - 更精细的 devfreq 可以找到每个场景的最优频率
   - 综合 DDR 功耗降低 **8%**（vs 使用较少频率档位）

---

## 三、技术成长与认知

### 核心技能拓展
1. **Always-on AI 功耗架构** — 持续推理场景的功耗管理
2. **ADPF 3.0 / GPU hint** — CPU+GPU 联合功耗优化
3. **自研核适配** — Qualcomm Oryon 的全新功耗特性
4. **端侧多模态 AI** — 语音+视觉+文本的组合推理功耗
5. **LPDDR5T** — 新一代内存的功耗特性

### 认知转变
- Always-on AI 是 "持续在线" 设备的未来 — 功耗管理必须适应 "永不停歇" 的 AI
- ADPF GPU hint 补全了功耗闭环的最后一块 — CPU+GPU 联合优化效果显著
- 自研核打破了 ARM 标准核的假设 — Energy Model/策略都需要重新来过
- AI 功耗管理不是新学科，是 "计算功耗" + "带宽功耗" + "调度策略" 的组合

### 年度关键数字
| 指标 | 数值 |
|------|------|
| 通话翻译持续功耗降低 | 55% |
| ADPF GPU hint 游戏功耗节省 | 13-15% |
| Always-on AI 语音唤醒功耗 | < 45mW |
| LLM 推理速度 (LPDDR5T) | 24 tok/s |
| 综合 DDR 功耗降低 | 8% |
| 修复 Bug 数 | 130 |

---

## 四、遗留问题与下年计划

1. **端侧 Agent**：AI Agent 会主动调用 APP/API，功耗模式完全不可预测
2. **3nm+ 工艺功耗墙**：工艺缩小带来的功耗改善越来越小
3. **AR/MR 功耗**：AR 眼镜/MR 设备的功耗约束极端严格
4. **Satellite AI**：卫星通信 + AI 的组合场景
5. **学习计划**：MoE 模型推理优化、2nm 工艺特性、AR/MR 功耗管理
