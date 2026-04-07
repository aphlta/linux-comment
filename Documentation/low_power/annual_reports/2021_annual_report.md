# 2021 年度工作报告：Android 系统性能与功耗优化

| 项目 | 信息 |
|------|------|
| 年份 | 2021 |
| 角色 | 首席系统架构师（性能与功耗） |
| 所属部门 | Android 系统部 / 性能与功耗组（18 人） |
| SoC 平台 | ARMv9 Cortex-X2+A710+A510 |
| 制程工艺 | 4nm |
| 内核版本 | Linux 5.10 (Android LTS) → 5.15 |
| Android 版本 | Android 11 → 12 |
| 产品形态 | 旗舰手机、折叠屏三代、平板(大屏回归) |

---

## 一、行业背景与技术环境

2021 年 Android 12 是近年来最大的一次 UI 重设计（Material You），对渲染管线
和功耗管理带来全面挑战。PerformanceHint API 开启了 APP-系统功耗协商的新纪元。

**关键行业事件：**
- Android 12: **Material You** 动态主题、**PerformanceHint API**、隐私仪表盘
- Google Tensor G1 (Google 首款自研 SoC) — 强调 ML 优先
- ARM 发布 ARMv9 (Cortex-X2, A710, A510)
- Samsung Galaxy Z Fold3/Flip3 折叠屏成为主流品类
- Android 12L 大屏适配（平板/折叠屏优化）
- LTPO 2.0 量产（1-120Hz 连续可变）

**性能与功耗领域进展：**
- PerformanceHint API 标准化了 APP 与系统的性能协商
- AIDL Power HAL 替代 HIDL Power HAL
- Android 12 的 WindowManager 进一步模块化
- RenderEngine 从 OpenGL ES 迁移到 Skia (HWUI 统一)
- LTPO 使动态刷新率从离散档位变为连续调节

---

## 二、核心工作内容

### 2.1 PerformanceHint API 全栈实现

**背景：** PerformanceHint 是 Android 12 最重要的性能功耗 API，让 APP 可以直接告诉系统自己的性能需求。

**具体工作：**

1. **API 全栈架构**
   ```
   APP 层 (NDK/Java)
   ├── APerformanceHintManager_createSession(tids[], targetNs)
   ├── APerformanceHintSession_reportActualWorkDuration(actualNs)
   └── APerformanceHintSession_updateTargetWorkDuration(targetNs)
        ↓
   Framework 层 (PerformanceHintService)
   ├── 管理所有 Session 的生命周期
   ├── 汇总 actual/target ratio
   └── 调用 Power HAL
        ↓
   Power HAL (AIDL, SoC 实现)
   ├── createHintSession() → 创建内核控制上下文
   ├── updateTargetWorkDuration() → 设置目标
   ├── reportActualWorkDuration() → 接收反馈
   └── 内部决策逻辑 → 调整 uclamp / 频率 / CPU 选择
        ↓
   内核层
   ├── util_clamp (per-task 约束)
   ├── cpufreq/schedutil (频率调节)
   └── cpuset (核心绑定)
   ```

2. **Power HAL 决策算法**
   ```cpp
   /* ADPF (Android Dynamic Performance Framework) 决策核心 */
   void PowerHintSession::reportActualWorkDuration(int64_t actual_ns) {
       double ratio = (double)actual_ns / target_ns_;
       
       /*
        * PID 控制器：根据实际/目标比值调整 boost 级别
        * 而不是简单的 if-else 阈值判断
        */
       double error = ratio - 1.0;  // 正值=超时, 负值=提前完成
       integral_ += error;
       double derivative = error - prev_error_;
       
       double output = Kp * error + Ki * integral_ + Kd * derivative;
       prev_error_ = error;
       
       /* 将 PID 输出映射到 uclamp 值 */
       int uclamp_min = base_uclamp_ + (int)(output * 1024);
       uclamp_min = std::clamp(uclamp_min, 0, 1024);
       
       /* 应用到 session 中的所有线程 */
       for (int tid : session_tids_) {
           set_task_uclamp_min(tid, uclamp_min);
       }
   }
   ```

3. **游戏引擎集成**
   - 与 Unity / Unreal 引擎团队合作，在渲染循环中集成 PerformanceHint
   - Unity 集成示例：
     ```csharp
     /* Unity 渲染循环中上报实际帧时间 */
     void OnEndOfFrame() {
         long actualDuration = frameEndTime - frameStartTime;
         performanceHintSession.ReportActualWorkDuration(actualDuration);
     }
     ```
   - 关键发现：**30fps 锁帧游戏受益最大**（之前系统以为需要 60fps 的性能）

4. **效果验证**

   | 游戏 | 无 Hint 功耗 | 有 Hint 功耗 | FPS | 节省 |
   |------|-----------|-----------|-----|------|
   | 原神 (60fps) | 4.2W | 3.9W | 60 → 60 | 7% |
   | 原神 (30fps) | 3.0W | 2.1W | 30 → 30 | **30%** |
   | 王者荣耀 (60fps) | 2.8W | 2.5W | 60 → 60 | 11% |
   | 和平精英 (40fps) | 2.5W | 1.9W | 40 → 40 | **24%** |
   | Chrome 滚动 | 0.5W | 0.4W | 60 → 60 | 20% |

---

### 2.2 LTPO 2.0 连续可变刷新率

**背景：** LTPO 2.0 屏幕支持 1Hz-120Hz 无级变速，比之前的离散档位（60/90/120）更精细。

**具体工作：**

1. **LTPO 刷新率控制架构**
   ```
   之前 (离散档位):
   DisplayManager 决策 → SurfaceFlinger setDesiredMode → HWC mode switch
   可选: 60Hz / 90Hz / 120Hz

   LTPO (连续可变):
   SurfaceFlinger 根据内容帧率实时调整 → HWC 直接设置 VFP (Vertical Front Porch)
   范围: 1Hz ~ 120Hz，精度 1Hz
   
   关键变化：决策从 "选档位" 变为 "选帧率"
   ```

2. **内容感知帧率决策**
   ```java
   /* SurfaceFlinger 中的帧率决策逻辑 */
   int decideContentFrameRate() {
       int maxContentFps = 0;
       
       for (Layer layer : visibleLayers) {
           if (layer.hasFramePending()) {
               int layerFps = layer.getDesiredFrameRate();
               maxContentFps = Math.max(maxContentFps, layerFps);
           }
       }
       
       // 无内容更新 → 降到最低 (1Hz)
       if (maxContentFps == 0) return 1;
       
       // 触摸操作中 → 至少 120Hz
       if (isTouchActive()) return 120;
       
       // 动画播放中 → 匹配动画帧率
       if (isAnimating()) return 120;
       
       // 内容帧率为准 → 视频 24/30fps, 游戏 30/60fps
       return maxContentFps;
   }
   ```

3. **1Hz 静态内容省电**
   - 当屏幕显示静态内容（如阅读、锁屏时钟）时降至 1Hz
   - 1Hz vs 60Hz 的 display 功耗对比：
   
   | 刷新率 | Panel 功耗 | GPU 功耗 | SF 功耗 | 总计 |
   |--------|-----------|---------|--------|------|
   | 120Hz | 220mW | 200mW | 35mW | 455mW |
   | 60Hz | 180mW | 120mW | 20mW | 320mW |
   | 10Hz | 130mW | 15mW | 3mW | 148mW |
   | 1Hz | 110mW | ~0mW | ~0mW | 110mW |

4. **LTPO 切换抖动问题**
   - 问题：某些场景在 59Hz-60Hz 之间频繁切换，导致视觉闪烁
   - 修复：增加 hysteresis（滞后区间）
     ```
     升档: 需要连续 3 帧内容帧率 > 当前刷新率
     降档: 需要连续 10 帧内容帧率 < 当前刷新率
     → 升快降慢，避免抖动
     ```

**产出：**
- LTPO 帧率控制框架
- 亮屏 AOD (Always-on Display) 功耗降至 **110mW**（1Hz 模式）
- 综合日常使用 display 功耗降低 **30%**

---

### 2.3 Material You 渲染性能优化

**背景：** Android 12 的 Material You 引入大量动态效果（动态取色、涟漪动画、圆角裁剪），
增加了 GPU 渲染负担。

**具体工作：**

1. **Material You 渲染开销分析**
   ```
   新增渲染开销（vs Android 11）：
   ├── 动态取色 (WallpaperColors): 启动时一次性计算, ~50ms
   ├── 涟漪效果 (RippleDrawable): 每次点击 +2ms GPU 时间
   ├── 窗口圆角 (RoundedCorner): 持续 +1ms GPU 时间/帧
   ├── 模糊效果 (BackdropFilter): 通知栏展开时 +3ms GPU 时间/帧
   └── 过度绘制增加: 多层半透明叠加 +15% overdraw
   
   总影响: 平均帧渲染时间增加 2-3ms, GPU 功耗增加 ~15%
   ```

2. **优化措施**
   - **模糊效果缓存**：对通知栏背景模糊做 bitmap cache，不用每帧重新计算
   - **涟漪效果简化**：低电量模式下关闭涟漪动画
   - **圆角优化**：使用 HWC overlay 的硬件圆角替代 GPU 裁剪
   - **过度绘制治理**：优化 SystemUI 的 view hierarchy，减少半透明层

3. **效果**
   - GPU 功耗回到 Android 11 水平（+15% → +3%）
   - 帧渲染时间开销：+2-3ms → +0.5ms

---

### 2.4 折叠屏大屏性能与功耗

**背景：** Galaxy Z Fold3 推动折叠屏成为主流品类，Android 12L 开始关注大屏体验。

**具体工作：**

1. **分屏模式功耗管理**
   ```
   折叠屏展开 + 分屏模式：
   左半屏: APP A (如视频播放)
   右半屏: APP B (如聊天)
   
   问题：两个 APP 都以 120fps 渲染 → GPU 负载翻倍
   
   优化策略：
   - 视频 APP: 限制到内容帧率 (24/30fps)
   - 聊天 APP: 限制到 60fps (文字场景不需要 120)
   - 只有用户交互的半屏保持高帧率
   - 非交互半屏自动降帧
   ```

2. **大屏 SurfaceFlinger 合成优化**
   - 内屏展开分辨率 2208×1768 (vs 普通手机 2400×1080)
   - 像素数增加 80% → GPU 合成负载增加 80%
   - 优化：优先使用 HWC overlay（SoC 的 HWC 支持 6-8 层硬件合成）
   - 确保分屏模式下两个 APP 的 surface 分别走 HWC overlay

3. **屏幕切换功耗过渡**
   - 折叠/展开时的功耗尖峰：两块屏同时活跃的 100ms 内功耗达 4W
   - 优化：错开两块屏的 enable/disable 时序，减少重叠窗口
   - 过渡期功耗尖峰：4W → 2.8W

---

### 2.5 AIDL Power HAL 3.0 重构

**背景：** Android 迁移到 AIDL HAL，Power HAL 需要从 HIDL 2.0 重构为 AIDL 3.0。

**具体工作：**

1. **AIDL Power HAL 新增能力**
   ```aidl
   interface IPower {
       /* 传统 Power Hint（保留兼容） */
       void setMode(Mode type, boolean enabled);
       void setBoost(Boost type, int durationMs);
       
       /* 新增：PerformanceHint Session 管理 */
       IPowerHintSession createHintSession(
           int tgid, int uid, in int[] threadIds,
           long targetDurationNanos);
       
       /* 新增：获取首选频率目标 */
       long getHintSessionPreferredRate();
   }
   
   interface IPowerHintSession {
       void updateTargetWorkDuration(long targetDurationNanos);
       void reportActualWorkDuration(in WorkDuration[] durations);
       void pause();
       void resume();
       void close();
       void sendHint(SessionHint hint);  /* POWER_EFFICIENCY, CPU_LOAD_UP, etc. */
   }
   ```

2. **Session 生命周期管理**
   - Session 绑定到 APP 进程生命周期
   - APP 被 kill 时自动清理 session（避免资源泄漏）
   - 支持 session pause/resume（APP 后台时暂停 hint）

3. **多 Session 冲突解决**
   - 同一线程可能被多个 session 包含
   - uclamp 取所有 session 中的最大 min 和最小 max
   - 前台 session 优先级高于后台 session

---

## 三、技术成长与认知

### 核心技能拓展
1. **PerformanceHint API** — APP 与系统的标准化性能协商
2. **LTPO 控制** — 连续可变刷新率的全栈实现
3. **Material You** — 新设计语言的渲染性能分析
4. **AIDL HAL** — Android HAL 层的新架构
5. **大屏/折叠屏** — 多窗口多 display 的性能管理

### 认知转变
- PerformanceHint 是 **"APP 说了算"** 的转折点 — 系统不再猜测 APP 需要什么
- LTPO 实现了 "只在需要时刷新" 的理想状态 — 1Hz 彻底改变了 AOD 功耗
- Material You 证明了 **UI 设计决策直接影响功耗** — 设计师需要有功耗意识
- 折叠屏的分屏模式是 Framework 层功耗管理的最复杂场景

### 年度关键数字
| 指标 | 数值 |
|------|------|
| PerformanceHint 30fps 游戏节省 | 30% |
| LTPO 日常 display 功耗降低 | 30% |
| AOD 功耗 (1Hz) | 110mW |
| Material You GPU 开销 | +15% → +3% |
| 折叠屏过渡功耗尖峰 | 4W → 2.8W |
| 修复 Bug 数 | 110 |

---

## 四、遗留问题与下年计划

1. **ADPF 2.0**：PerformanceHint 的增强版本，支持更多 hint 类型
2. **GPU 功耗精细化**：Mali/Adreno GPU 的 per-frame DVFS
3. **Thread-level 能效分析**：基于 Perfetto 的 per-thread 功耗归因
4. **Wear OS 3.0**：Google 与 Samsung 合作的新 Wear OS 的功耗管理
5. **学习计划**：Vulkan 渲染管线功耗特性、Android 13 新 API、Ray Tracing 功耗
