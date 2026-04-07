# 2023 年度工作报告：Android 系统性能与功耗优化

| 项目 | 信息 |
|------|------|
| 年份 | 2023 |
| 角色 | 首席系统架构师 / 端侧 AI 功耗方向负责人 |
| 所属部门 | Android 系统部 / 性能功耗与 AI 组（22 人） |
| SoC 平台 | ARMv9.2 Cortex-X4+A720+A520 |
| 制程工艺 | 3nm (TSMC N3E) / 4nm (Samsung 4LPX) |
| 内核版本 | Linux 5.15 / 6.1 (Android LTS) |
| Android 版本 | Android 13 → 14 |
| 产品形态 | 旗舰手机、折叠屏、AI 手机 |

---

## 一、行业背景与技术环境

2023 年是端侧 AI 爆发元年。ChatGPT 引爆全球 AI 热潮后，手机厂商争相将大语言模型
部署到端侧。端侧 LLM 推理的功耗挑战成为全新课题。

**关键行业事件：**
- ChatGPT 热潮席卷全球，端侧 AI 成为手机差异化卖点
- Qualcomm Snapdragon 8 Gen 3 (X4+A720+A520, 4nm) 强调 AI 性能
- Google Tensor G3 进一步强化端侧 ML
- MediaTek Dimensity 9300 全大核设计引发功耗争议
- Android 14：Health Connect、Credential Manager、partial screen sharing
- Samsung Galaxy AI 发布（端侧翻译、文本摘要）
- Apple A17 Pro (3nm) 支持 Ray Tracing

**性能与功耗领域进展：**
- ADPF 进一步增强：支持 GPU 和 thermal 的联合调控
- Android 14 增强了 APP 后台限制（cached app 冻结更激进）
- NNAPI (Neural Networks API) 功耗优化成为焦点
- Linux 6.1 成为新的 Android LTS
- Power HAL 增加 session tag (游戏/UI/ML 标记)

---

## 二、核心工作内容

### 2.1 端侧 LLM 推理功耗优化

**背景：** 在手机上运行 7B 参数的 LLM（如 Llama 2 7B 量化版），是前所未有的功耗挑战。

**具体工作：**

1. **端侧 LLM 功耗剖析**
   ```
   Llama 2 7B (INT4 量化) 在旗舰 SoC 上的推理功耗：
   
   Prefill 阶段 (处理输入 prompt):
   ├── NPU: 1.8W (矩阵乘法主力)
   ├── CPU: 0.6W (tokenizer + 数据搬运)
   ├── DDR: 0.8W (模型权重从 DRAM 加载)
   ├── GPU: 0.1W (部分算子 fallback)
   └── 其他: 0.3W
   总计: ~3.6W, 速度: ~120 tokens/s
   
   Decode 阶段 (逐 token 生成):
   ├── NPU: 0.9W (每次只算一个 token 的 attention)
   ├── CPU: 0.3W
   ├── DDR: 1.2W (KV cache 不断增长，DDR 带宽压力大)
   ├── GPU: 0.1W
   └── 其他: 0.2W
   总计: ~2.7W, 速度: ~15 tokens/s
   
   关键发现：Decode 阶段 DDR 功耗 > NPU 功耗（带宽瓶颈）
   ```

2. **DDR 带宽优化 — LLM 最大的功耗杠杆**
   ```
   LLM Decode 阶段的内存访问模式：
   - 模型权重: 3.5GB (INT4 量化后)
   - KV Cache: 每个 token ~0.5MB × sequence_length
   - 每生成一个 token 需要读取 ~100MB 数据
   - 15 tokens/s → DDR 带宽 ~1.5GB/s（持续读取）
   
   DDR 功耗与带宽的关系：
   1.5GB/s @ LPDDR5 → 需要 DDR 运行在 1600MHz → 420mW
   
   优化策略：
   1. 模型权重预加载到 SRAM (如果 NPU 有足够 SRAM) → 减少 DDR 访问
   2. KV Cache 压缩 (GQA, MQA) → 减少 cache 大小
   3. Speculative decoding → 减少 decode 步数
   4. DDR 频率锁定在最优带宽点（避免 devfreq 频繁切换）
   ```

3. **NPU/CPU/GPU 协同调度**
   ```java
   /* LLM 推理的异构调度策略 */
   class LlmInferenceScheduler {
       void scheduleLayer(NNLayer layer) {
           switch (layer.type) {
               case ATTENTION:
                   // Attention 层：NPU 最高效
                   dispatchToNpu(layer);
                   break;
               case FFN:
                   // FFN 层：NPU 或 GPU 均可
                   if (npuUtilization > 80%)
                       dispatchToGpu(layer);  // NPU 忙时用 GPU
                   else
                       dispatchToNpu(layer);
                   break;
               case EMBEDDING:
                   // Embedding lookup：CPU 更高效(随机访问)
                   dispatchToCpu(layer);
                   break;
               case SOFTMAX:
                   // Softmax：CPU 够用(计算量小)
                   dispatchToCpu(layer);
                   break;
           }
       }
   }
   ```

4. **LLM 会话级功耗管理**
   - 短对话（< 50 tokens）：全速推理，快速完成
   - 长对话（> 200 tokens）：检测 thermal headroom，必要时降低推理速度
   - 后台推理（如摘要生成）：通过 ADPF POWER_EFFICIENCY hint 限制在小核+低频 NPU

5. **效果**
   | 优化 | Decode 速度 | 功耗 | 能效 |
   |------|-----------|------|------|
   | 基线 | 15 tok/s | 2.7W | 5.6 tok/J |
   | DDR 优化 | 15 tok/s | 2.2W | 6.8 tok/J (+22%) |
   | KV Cache 压缩 | 18 tok/s | 2.3W | 7.8 tok/J (+39%) |
   | 全优化 | 18 tok/s | 2.0W | **9.0 tok/J (+61%)** |

---

### 2.2 MediaTek Dimensity 9300 全大核功耗适配

**背景：** 联发科 Dimensity 9300 采用激进的全大核设计（4×X4 + 4×A720，无小核），
打破了传统三丛集架构，功耗管理面临范式变化。

**具体工作：**

1. **全大核 vs 传统三丛集**
   ```
   传统 (8 Gen 3):  1×X4(3.3G) + 3×A720(3.2G) + 4×A520(2.3G)
   全大核 (D9300):   4×X4(3.25G) + 4×A720(2.0G)
   
   问题：
   - 没有小核 → 轻负载也只能用 A720（比 A520 功耗高 40%）
   - 4 个 X4 → 重负载时峰值功耗极高
   - 功耗地板（最低频率）比传统架构高
   
   X4@600MHz 功耗: ~65mW (vs A520@400MHz: ~15mW)
   A720@600MHz 功耗: ~40mW (vs A520@400MHz: ~15mW)
   → idle 态功耗地板高了 2-3x
   ```

2. **Framework 层应对策略**
   ```
   策略重心：既然没有小核，就让大核尽快完成工作然后 power down
   
   "Race to Idle" 策略:
   - 后台任务不再限频（小核限频的逻辑不适用）
   - 改为限制后台任务的 CPU 时间（time-in-state 限制）
   - 通过 cgroup cpu.max 限制后台 CPU 配额
   
   # 后台 cgroup: 每 100ms 周期只允许使用 20ms CPU 时间
   echo "20000 100000" > /dev/cpuctl/background/cpu.max
   
   效果：后台任务快速执行完毕 → CPU 立即回到 idle → power down
   ```

3. **全大核的 idle 功耗优化**
   - 激进的 cpuidle 配置：idle 100μs 即进入 power down（传统为 500μs）
   - ADPF 配合：PerformanceHint 完成后立即 reset uclamp → 不 hold 高频

4. **效果**
   - 全大核方案在轻负载下功耗仍高于三丛集 **15-20%**
   - 但重负载下性能优势 **30%+**（所有核都是大核）
   - 通过 "Race to Idle" 策略将轻负载功耗差距缩小到 **8%**

---

### 2.3 Android 14 Cached App 冻结增强

**背景：** Android 14 更激进地冻结后台 APP（cached app freezer），需要评估对性能和功耗的影响。

**具体工作：**

1. **Cached App Freezer 机制**
   ```
   Android 14 增强：
   - 后台 APP 进入 cached 状态后 10 秒即冻结（之前 60 秒）
   - 冻结使用 SIGSTOP → cgroup freezer → 进程完全停止
   - 冻结后的 APP 不消耗任何 CPU 时间
   - 解冻通过 SIGCONT → 恢复执行
   
   对功耗的影响：
   - cached APP 的 CPU 使用从 ~5% 降至 0%
   - 系统总后台 CPU 使用降低 30%
   - 系统更频繁地进入 deep idle（无后台打扰）
   ```

2. **冻结时机优化**
   ```java
   /* 自定义冻结策略：不同 APP 不同冻结延迟 */
   int getFreezeDelay(ProcessRecord app) {
       // IM 类 APP (微信/WhatsApp): 延迟冻结 (保证消息推送)
       if (isImApp(app)) return 30_000;  // 30 秒
       
       // 音乐类 APP (已停止播放): 正常冻结
       if (isMediaApp(app) && !isPlayingAudio(app)) return 10_000;
       
       // 导航类 APP: 不冻结 (保持后台定位)
       if (isNavigationApp(app)) return Integer.MAX_VALUE;
       
       // 其他: 激进冻结
       return 5_000;  // 5 秒
   }
   ```

3. **效果**
   - 后台 CPU 使用降低：**30%**
   - 灭屏待机功耗降低：**10%**
   - 注意事项：过度冻结会导致 APP 恢复时的冷启动延迟

---

### 2.4 Wi-Fi 7 (802.11be) 功耗评估

**具体工作：**

1. **Wi-Fi 7 新特性功耗影响**

   | Wi-Fi 7 特性 | 功耗影响 | 说明 |
   |-------------|---------|------|
   | MLO (Multi-Link Operation) | +30% idle 功耗 | 多链路需要同时维持 |
   | 320MHz 信道 | +20% 传输功耗 | 更宽信道 = 更多射频功率 |
   | 4K QAM | +5% 处理功耗 | 更复杂的调制解调 |
   | Multi-RU | -10% 传输功耗 | 更高效的频谱利用 |
   | TWT (Target Wake Time) 增强 | -25% idle 功耗 | 更精确的休眠调度 |

2. **MLO 功耗管理策略**
   ```
   Wi-Fi 7 MLO 使设备可以同时在 2.4G + 5G + 6GHz 上通信
   但同时维持 3 条链路的功耗 = 3× 单链路
   
   策略：
   - 高吞吐场景 (下载/视频): 启用 MLO → 多链路聚合
   - 低吞吐场景 (聊天/邮件): 只保持一条最优链路
   - 待机: 单链路 TWT 模式 → 功耗最低
   
   通过 ConnectivityService 动态控制 MLO 策略
   ```

3. **效果**
   - Wi-Fi 7 智能 MLO 管理：待机功耗与 Wi-Fi 6 持平
   - 高吞吐场景：带宽提升 2x，功耗仅增加 30%（能效提升 50%）

---

### 2.5 跨设备功耗协同 (手机-平板-手表)

**具体工作：**

1. **协同场景**
   ```
   场景：用户佩戴手表 + 携带手机
   
   传统模式：
   - 手表独立检测运动 → 手表 GPS + 传感器持续工作
   - 手机独立推送通知 → 手机每次推送都亮屏
   
   协同模式：
   - 手表负责运动检测 (已经在手腕上) → 手机 GPS 关闭
   - 通知先到手表震动 → 手机不亮屏
   - 手机负责 AI 推理 (算力强) → 手表只做轻量传感器
   
   总功耗降低估算: ~15%
   ```

2. **技术实现**
   - 通过 Companion Device Manager 感知配对设备在线状态
   - 通知分流：手表在线时，手机的通知延迟显示或静默
   - 传感器卸载：手表提供心率/运动数据，手机不重复采集

---

## 三、技术成长与认知

### 核心技能拓展
1. **端侧 LLM 功耗优化** — 大模型推理的功耗特性分析
2. **异构 AI 推理调度** — NPU/GPU/CPU 协同策略
3. **全大核架构适配** — 无小核场景的功耗管理策略
4. **Wi-Fi 7 MLO** — 新一代无线连接的功耗管理
5. **跨设备协同** — 多设备功耗全局优化

### 认知转变
- LLM 让 "DDR 带宽功耗" 成为最大瓶颈 — 计算功耗反而是次要的
- 全大核方案证明 "Race to Idle" 可能比 "Run on Little" 更高效
- 端侧 AI 是功耗管理的下一个十年的主旋律
- 跨设备协同打破了 "单设备功耗优化" 的思维局限

### 年度关键数字
| 指标 | 数值 |
|------|------|
| LLM 推理能效提升 | 61% (tok/J) |
| 全大核功耗差距缩小 | 20% → 8% |
| Cached App Freezer 后台 CPU 降低 | 30% |
| 灭屏待机功耗降低 | 10% |
| Wi-Fi 7 MLO 能效提升 | 50% |
| 修复 Bug 数 | 120 |

---

## 四、遗留问题与下年计划

1. **更大的端侧模型**：13B/70B 模型端侧部署的功耗可行性
2. **Always-on AI**：相机实时 AI 检测场景的功耗管理
3. **卫星通信功耗**：卫星通信发射功耗极高（数瓦级），需要精确管理
4. **Android 15 预研**：新的功耗管理 API 和 AI 集成
5. **学习计划**：Transformer 推理优化、LPDDR5T 特性、3nm 工艺功耗特性
