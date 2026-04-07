# 2020 年度工作报告：Android 系统性能与功耗优化

| 项目 | 信息 |
|------|------|
| 年份 | 2020 |
| 角色 | 技术专家 / 性能与功耗架构师 |
| 所属部门 | Android 系统部 / 性能与功耗组（15 人） |
| SoC 平台 | 1+3+4 三丛集 (Cortex-X1 + A78 + A55) |
| 制程工艺 | 5nm EUV |
| 内核版本 | Linux 5.4 (Android LTS) → 5.10 |
| Android 版本 | Android 10 → 11 |
| 产品形态 | 5G 旗舰手机、折叠屏二代 |

---

## 一、行业背景与技术环境

2020 年疫情改变了手机使用场景：视频通话激增、在线教育/办公成为常态。
长时间使用下的功耗与发热成为用户首要投诉。三丛集 SoC 的调度策略
需要在 Framework 层做深度适配。

**关键行业事件：**
- COVID-19 疫情：Zoom/Teams/钉钉视频会议使用量暴涨 10x
- Apple M1 发布 — ARM 进入桌面/笔记本，能效标杆
- Qualcomm Snapdragon 888 (1+3+4, X1+A78+A55, 5nm)
- Android 11：Conversation notifications、Bubbles、one-time permissions
- LTPO OLED 屏幕开始量产（Samsung S21 Ultra 预告）
- Perfetto 全面替代 Systrace 成为追踪标准

**性能与功耗领域进展：**
- Android 11 增强 WindowManager Shell（SystemUI 模块化）
- GKI (Generic Kernel Image) 开始推进，内核定制空间缩小
- 120Hz 高刷全面铺开到中端机
- AIDL HAL 逐步替代 HIDL HAL

---

## 二、核心工作内容

### 2.1 视频通话场景全栈功耗治理

**背景：** 疫情使视频通话从"偶尔用"变成"每天用2小时"，30分钟通话掉电15%成为最大投诉。

**具体工作：**

1. **视频通话全栈功耗剖析**
   ```
   Perfetto 追踪 + 功耗仪同步测量，得到逐模块功耗：
   
   总功耗 2.8W 的分解：
   ├── [Framework 层可控]
   │   ├── SurfaceFlinger 合成: 150mW (5%)
   │   │   → 视频通话时有 camera preview + remote video + UI 三层
   │   ├── APP 渲染 (GPU): 180mW (6%)
   │   │   → 远程视频解码后的缩放和色彩转换
   │   ├── CPU (Framework + APP): 380mW (14%)
   │   │   → 包含大量 Binder 调用 (MediaCodec/Camera/Audio)
   │   └── 刷新率: 120Hz → 完全不需要 (视频 30fps 足够)
   │
   ├── [HAL/内核层可控]
   │   ├── Camera ISP: 350mW (13%)
   │   ├── Video Encoder: 280mW (10%)
   │   ├── Video Decoder: 200mW (7%)
   │   ├── Audio DSP: 80mW (3%)
   │   └── DDR 带宽: 180mW (6%)
   │
   └── [Modem 层]
       └── 5G 数据传输: 550mW (20%)
   ```

2. **Framework 层优化措施**

   | 优化项 | 方法 | 节省 |
   |--------|------|------|
   | 刷新率降至 30Hz | 视频通话场景识别 → 自动切换 30fps | 150mW |
   | 减少 SF 合成层数 | 视频通话时隐藏不必要的 system overlay | 30mW |
   | CPU 调度约束 | util_clamp 限制在 A55+A78, 不用 X1 | 120mW |
   | Binder 调用聚合 | Camera/Codec 的状态查询从 per-frame 改为 per-second | 40mW |
   | GPU 合成优化 | 视频层走 HWC overlay 而非 GPU 合成 | 60mW |

3. **场景自动识别引擎**
   ```java
   /* 在 SystemServer 中实现场景识别服务 */
   public class SceneDetectionService extends SystemService {
       /* 视频通话场景识别条件 */
       boolean isVideoCall() {
           return hasFrontCamera()           // 前置摄像头开启
               && hasMediaCodecEncoder()      // 视频编码器活跃
               && hasMediaCodecDecoder()      // 视频解码器活跃
               && hasAudioRecord()            // 麦克风录音中
               && hasAudioTrack();            // 扬声器播放中
       }
       
       void onSceneChanged(Scene scene) {
           switch (scene) {
               case VIDEO_CALL:
                   applyRefreshRate(30);
                   applyPowerProfile(POWER_PROFILE_VIDEO_CALL);
                   applyThermalProfile(THERMAL_PROFILE_SUSTAINED);
                   break;
               case GAMING:
                   applyRefreshRate(120);
                   applyPowerProfile(POWER_PROFILE_GAMING);
                   break;
               case READING:
                   applyRefreshRate(60);
                   applyPowerProfile(POWER_PROFILE_LIGHT);
                   break;
           }
       }
   }
   ```

4. **效果**
   - 视频通话总功耗：**2.8W → 2.1W (25% 降低)**
   - 30 分钟通话掉电：**15% → 11%**
   - 设备表面温度：**42°C → 38°C**

---

### 2.2 三丛集 (1+3+4) 的 Framework 层调度策略

**背景：** Cortex-X1 超大核功耗极高（单核满载 1.2W），必须在 Framework 层精确控制哪些线程可以使用它。

**具体工作：**

1. **线程分级体系设计**
   ```
   Android 进程/线程分级 → CPU 映射：
   
   ┌─────────────────────────────────────────────┐
   │ Tier 0 (X1 超大核): 只有这些线程可用         │
   │  • APP 的 UI 主线程 (触摸响应时)              │
   │  • APP 冷启动的 classloader 线程              │
   │  • 游戏引擎主渲染线程                         │
   │  • Camera preview pipeline 关键线程           │
   ├─────────────────────────────────────────────┤
   │ Tier 1 (A78 大核): 高优先级任务               │
   │  • APP 的 RenderThread                        │
   │  • SurfaceFlinger 主线程                      │
   │  • Audio 低延迟线程                           │
   │  • 前台 APP 的 Worker 线程                    │
   ├─────────────────────────────────────────────┤
   │ Tier 2 (A55 小核): 一切其他任务               │
   │  • 后台 APP 的所有线程                        │
   │  • 系统服务非关键线程                          │
   │  • GC 线程                                    │
   │  • ContentProvider 查询                       │
   └─────────────────────────────────────────────┘
   ```

2. **通过 cgroup + util_clamp 实现**
   ```bash
   # cpuctl cgroup 配置
   # Tier 0: top-app RT 线程
   echo 768 > /dev/cpuctl/top-app/cpu.uclamp.min    # 75% → 保证大核
   echo 1024 > /dev/cpuctl/top-app/cpu.uclamp.max
   
   # Tier 1: foreground
   echo 128 > /dev/cpuctl/foreground/cpu.uclamp.min  # 12.5% → 中核以上
   echo 819 > /dev/cpuctl/foreground/cpu.uclamp.max   # 80%
   
   # Tier 2: background
   echo 0 > /dev/cpuctl/background/cpu.uclamp.min
   echo 307 > /dev/cpuctl/background/cpu.uclamp.max   # 30% → 仅小核
   ```

3. **X1 利用率监控与告警**
   - 开发内部工具监控 X1 的 per-thread 使用情况
   - 如果后台线程跑在 X1 上，自动生成告警并调整 cgroup
   - 日常目标：X1 利用率 < 15%（大部分时间应该 power down）

4. **效果**
   - 综合场景功耗降低 **12%**（vs 无分级策略）
   - X1 日均利用率从 35% 降至 **13%**
   - UI 流畅度保持不变（99th percentile frame time < 16ms）

---

### 2.3 WindowManager / SystemUI 性能优化

**背景：** Android 11 对 WindowManager 做了模块化重构（WM Shell），需要确保重构不引入性能退化。

**具体工作：**

1. **窗口动画性能审计**
   ```
   APP 启动动画 (startingWindow → app 窗口过渡):
   Android 10: 平均 280ms, 99th = 450ms
   Android 11 (重构后初始): 平均 320ms, 99th = 580ms ← 退化
   
   原因分析 (Perfetto):
   - WM Shell 模块化增加了一层 IPC（从 system_server 到 SystemUI 进程）
   - 动画开始的 Binder 调用增加了 15ms
   - 动画帧的 SurfaceControl 操作增加了 transaction 开销
   ```

2. **优化措施**
   - 将高频动画操作从 Binder IPC 改为 shared memory 通信
   - APP 启动动画的 SurfaceControl transaction 做批量提交（batching）
   - 预创建 starting window surface（减少首帧延迟）

3. **通知栏下拉性能优化**
   ```
   通知栏下拉 (shade expansion) 性能分析：
   - 当通知 > 20 条时，展开动画出现明显卡顿
   - 原因：RecyclerView 在展开过程中做 onBindViewHolder，触发大量 ImageView 加载
   
   优化：
   - 预渲染前 5 条通知的 View
   - 对通知图标做 bitmap cache
   - 展开动画期间暂停非可见通知的 bind
   
   效果：
   - 通知栏展开帧率：48fps → 58fps（20 条通知场景）
   ```

4. **PIP (Picture-in-Picture) 功耗优化**
   - PIP 窗口独立合成层，持续消耗 GPU
   - 优化：PIP 内容静止 > 2 秒时，冻结 surface 更新
   - 节省 GPU 功耗 40mW

---

### 2.4 GKI (Generic Kernel Image) 适配与功耗影响评估

**背景：** Google 推进 GKI，SoC 厂商不能再自由修改内核，功耗定制空间缩小。

**具体工作：**

1. **GKI 对功耗优化的影响**
   ```
   之前（完全可定制内核）：
   - 可以自由修改 scheduler、cpufreq、cpuidle
   - 可以添加私有的功耗优化 patch
   - 可以定制 power domain 策略
   
   GKI 之后：
   - 核心内核代码由 Google 维护，不能修改
   - SoC 厂商只能通过 vendor module (KMI) 扩展
   - 功耗优化必须通过标准接口（sysfs、debugfs、vendor hooks）
   
   影响评估：
   - 80% 的功耗优化可以通过标准接口实现（参数调优）
   - 15% 需要通过 vendor hooks 实现
   - 5% 无法在 GKI 框架内实现 → 需要提交上游 patch
   ```

2. **功耗优化从内核迁移到 Framework**
   - 之前在内核中做的任务放置优化 → 现在通过 cgroup/util_clamp 在 Framework 控制
   - 之前在内核中做的 DDR 调频 hint → 现在通过 Power HAL 场景触发
   - 之前直接修改 schedutil 参数 → 现在通过 sysfs 在 init.rc 中配置

3. **Vendor Hook 使用**
   ```c
   /* GKI vendor hook 示例：在调度器路径中插入厂商逻辑 */
   /* 不修改内核源码，通过 module 注册 hook */
   register_trace_android_rvh_select_task_rq_fair(
       vendor_select_task_rq_fair_hook, NULL);
   
   static void vendor_select_task_rq_fair_hook(void *data,
       struct task_struct *p, int prev_cpu, int sd_flag,
       int wake_flags, int *new_cpu)
   {
       /* 自定义任务放置逻辑：后台任务强制小核 */
       if (task_is_background(p))
           *new_cpu = find_little_core_cpu();
   }
   ```

**产出：**
- GKI 功耗影响评估报告
- 内核功耗优化向 Framework/HAL 迁移方案
- 12 个 vendor hook 的使用案例

---

### 2.5 Battery Historian 自动化分析平台

**具体工作：**

1. **自动化流水线**
   ```
   每日 Daily Build → 自动测试 → 自动分析 → 自动报告
   
   [测试机] → bugreport → [服务器] Battery Historian 解析
                                    → Perfetto trace 解析
                                    → 自动生成报告
                                    → 与前一天数据对比
                                    → 功耗退化 > 5% 自动告警
   ```

2. **关键监控指标**

   | 指标 | 阈值 | 告警方式 |
   |------|------|---------|
   | 灭屏待机电流 (mA) | > 5mA | 红色告警 |
   | 灭屏每小时唤醒次数 | > 50 | 黄色告警 |
   | 前台 APP Jank 率 | > 5% | 黄色告警 |
   | APP 冷启动时间 | > 1000ms | 黄色告警 |
   | GPU 合成 fallback 率 | > 15% | 黄色告警 |
   | 单次 wakelock > 60s | 任何出现 | 红色告警 |

3. **效果**
   - 功耗退化从 "用户投诉后才发现" 变为 "次日自动发现"
   - 退化修复周期从 **2 周缩短至 3 天**

---

## 三、技术成长与认知

### 核心技能拓展
1. **场景识别引擎** — 根据系统状态自动切换功耗策略
2. **三丛集调度策略** — Framework 层的线程分级与 CPU 映射
3. **WM Shell / SystemUI** — Android 窗口管理器的性能分析
4. **GKI 适配** — 内核定制空间缩小后的功耗优化策略转变
5. **自动化功耗 CI** — 功耗回归的工程化管理

### 认知转变
- GKI 倒逼功耗优化从内核层向 Framework 层迁移 — 这是不可逆的趋势
- **场景化 > 通用优化**：视频通话一个场景的优化就抵得上一年的通用优化
- Apple M1 证明了软硬件深度协同的极致能效 — SoC 厂商需要更深的 Framework 参与
- 自动化 CI 是功耗工作从 "救火" 到 "预防" 的关键

### 年度关键数字
| 指标 | 数值 |
|------|------|
| 视频通话功耗降低 | 2.8W → 2.1W (25%) |
| X1 日均利用率 | 35% → 13% |
| 综合功耗降低 | 12% |
| WM 动画退化修复 | 320ms → 260ms |
| 功耗退化修复周期 | 2 周 → 3 天 |
| Vendor Hook 使用 | 12 个 |
| 修复 Bug 数 | 105 |

---

## 四、遗留问题与下年计划

1. **LTPO 屏幕适配**：LTPO 支持 1-120Hz 连续可变，Framework 需要深度适配
2. **PerformanceHint API**：Android 12 即将引入，需要 SoC 侧 HAL 实现
3. **Material You 动态主题**：渲染开销对功耗的影响评估
4. **可穿戴平台**：Wear OS 的功耗约束完全不同（mW 级总功耗）
5. **学习计划**：Android 12 新 API、LTPO 驱动技术、Wear OS 架构
