# 2022 年度工作报告：Android 系统性能与功耗优化

| 项目 | 信息 |
|------|------|
| 年份 | 2022 |
| 角色 | 首席系统架构师（性能与功耗）/ 技术委员会成员 |
| 所属部门 | Android 系统部 / 性能与功耗组（20 人） |
| SoC 平台 | ARMv9 Cortex-X3+A715+A510 (refresh) |
| 制程工艺 | 4nm (2nd gen) / 3nm (试产) |
| 内核版本 | Linux 5.10 / 5.15 (Android LTS) |
| Android 版本 | Android 12L → 13 |
| 产品形态 | 旗舰手机、折叠屏、平板(大屏生态) |

---

## 一、行业背景与技术环境

2022 年大屏生态回归：Android 平板复兴、折叠屏普及、桌面模式探索。
Android 13 在功耗管理精细度上再进一步。ADPF (Android Dynamic Performance Framework)
从实验走向成熟。

**关键行业事件：**
- Android 13：per-app language、notification permissions、更细粒度的媒体权限
- Android 12L/13 大屏优化：Taskbar、split-screen 改进
- Qualcomm Snapdragon 8 Gen 2 (X3+A715+A510, 4nm TSMC) — 夺回能效王座
- Google Tensor G2（强调 AI 功耗优化）
- Apple A16 (4nm) / M2 持续拉高能效标杆
- 折叠屏全面普及（Fold4/Flip4/小米MIX Fold2/vivo X Fold）
- Ray Tracing 开始进入移动 GPU (Immortalis-G715)

**性能与功耗领域进展：**
- ADPF 增加 SessionHint (CPU_LOAD_UP/DOWN, POWER_EFFICIENCY)
- Android 13 引入 GAME_MODE API（游戏性能/省电模式）
- Foreground Service Type 强制声明（限制前台服务滥用）
- Per-app battery usage 更精确（归因到 UID 级别）
- GPU DVFS 开始被纳入 ADPF 体系

---

## 二、核心工作内容

### 2.1 ADPF 2.0 / Game Mode 全栈实现

**背景：** Android 13 的 ADPF 增强和 Game Mode API 是性能功耗管理的重大升级。

**具体工作：**

1. **Game Mode API 架构**
   ```java
   /* Android 13 Game Mode：让用户选择游戏运行模式 */
   
   // 三种游戏模式：
   GAME_MODE_STANDARD     // 默认：平衡性能和功耗
   GAME_MODE_PERFORMANCE  // 性能模式：最高帧率，不考虑功耗
   GAME_MODE_BATTERY      // 省电模式：降帧率降分辨率
   
   /* SoC 侧不同模式下的策略 */
   GameModeConfig {
       PERFORMANCE: {
           maxRefreshRate: 120,
           renderingScale: 1.0,
           cpuBoostLevel: HIGH,
           gpuFreqMin: MAX * 0.8,
           thermalProfile: PERFORMANCE,
       },
       BATTERY: {
           maxRefreshRate: 60,
           renderingScale: 0.75,     // 降低渲染分辨率 25%
           cpuBoostLevel: NONE,
           gpuFreqMax: MAX * 0.6,
           thermalProfile: POWER_SAVE,
       }
   }
   ```

2. **ADPF SessionHint 扩展**
   ```cpp
   /* 新增的 SessionHint 类型及 SoC 侧响应 */
   void PowerHintSession::sendHint(SessionHint hint) {
       switch (hint) {
           case SessionHint::CPU_LOAD_UP:
               /* APP 预告下一帧负载将增加(如场景切换) */
               boost_uclamp_min(+20%);
               break;
           case SessionHint::CPU_LOAD_DOWN:
               /* APP 预告下一帧负载将降低 */
               reduce_uclamp_min(-20%);
               break;
           case SessionHint::CPU_LOAD_RESET:
               /* 恢复到 PID 控制器计算的值 */
               reset_to_pid_output();
               break;
           case SessionHint::POWER_EFFICIENCY:
               /* APP 不关心延迟，只求省电 (如后台AI推理) */
               force_little_cores();
               set_uclamp_max(30%);
               break;
       }
   }
   ```

3. **GPU DVFS 纳入 ADPF 体系**
   - 之前 GPU DVFS 完全由 GPU 驱动独立决策
   - 现在 ADPF 可以向 GPU 发送 hint：
     ```
     PerformanceHint target = 16.67ms (60fps)
     Actual GPU 渲染时间 = 8ms
     → GPU 有 50% 余量 → 降低 GPU 频率
     → GPU 功耗降低 30%
     ```
   - 实现：通过 Power HAL 向 GPU devfreq 注入 freq_qos 约束

4. **效果**

   | 游戏 | Standard | Performance | Battery | Battery 节省 |
   |------|---------|------------|---------|------------|
   | 原神 | 3.8W/55fps | 4.5W/60fps | 2.2W/30fps | **42%** |
   | 王者荣耀 | 2.5W/60fps | 2.9W/60fps | 1.6W/40fps | **36%** |
   | 崩坏: 星穹铁道 | 3.2W/50fps | 3.8W/60fps | 1.9W/30fps | **41%** |

---

### 2.2 大屏生态性能与功耗

**背景：** Android 平板复兴 + 折叠屏普及 + 桌面模式探索，大屏场景的性能功耗管理成为新战场。

**具体工作：**

1. **Taskbar 性能优化**
   ```
   Android 12L 引入底部 Taskbar（类似 PC 任务栏）
   
   性能问题：
   - Taskbar 是一个持续可见的 overlay → SurfaceFlinger 每帧都要合成
   - 加上 APP 窗口 + 导航栏 + 状态栏 → 4-5 层合成
   - 大屏分辨率高 (2560×1600) → GPU 合成开销大
   
   优化：
   - Taskbar 使用 HWC overlay（零 GPU 开销）
   - Taskbar 内容不变时标记为 "frozen surface"
   - Taskbar 图标使用 hardware bitmap 缓存
   
   效果：Taskbar 增加的 GPU 功耗从 40mW → 5mW
   ```

2. **桌面模式 (Desktop Mode) 功耗管理**
   ```
   桌面模式特点：
   - 多个自由窗口 (freeform windows) 同时显示
   - 外接显示器 + 键鼠操作
   - 类似 PC 的使用场景，但运行在手机 SoC 上
   
   功耗挑战：
   - 多窗口 = 多个独立渲染的 APP surface
   - 外接 4K 显示器 = 极高的合成分辨率
   - 持续运行 (非手机的间歇性使用模式)
   
   策略：
   - 只有获得焦点的窗口以 60fps 渲染，其他降至 15fps
   - 非可见窗口 (被覆盖) 完全停止渲染
   - 外接显示器使用 HWC 直接输出 (bypass SurfaceFlinger 合成)
   - CPU 策略切换到 "sustained performance" 模式
   ```

3. **平板分屏模式功耗优化**
   - 平板上分屏比折叠屏更常见（屏幕更大，分屏更实用）
   - 实现 "活跃侧优先" 策略：用户正在交互的一侧给足性能，另一侧节能
   - 效果：分屏模式功耗降低 **18%**

---

### 2.3 Foreground Service 治理

**背景：** 部分 APP 滥用前台服务规避 Android 的后台限制，持续消耗 CPU 和电量。

**具体工作：**

1. **Android 13 FGS Type 强制声明**
   ```xml
   <!-- APP 必须声明前台服务类型 -->
   <service android:name=".MusicService"
       android:foregroundServiceType="mediaPlayback" />
   
   <!-- 允许的类型：
       camera, connectedDevice, dataSync, health,
       location, mediaPlayback, mediaProjection,
       microphone, phoneCall, remoteMessaging,
       shortService, specialUse, systemExempted
   -->
   ```

2. **SoC 侧前台服务功耗监控**
   ```java
   /* 监控前台服务的 CPU 使用 */
   class ForegroundServiceMonitor {
       void onFgsStarted(int uid, String serviceType) {
           // 开始监控该 UID 的 CPU 时间
           startCpuTimeTracking(uid);
       }
       
       void periodicCheck() {
           for (FgsInfo fgs : activeForegroundServices) {
               long cpuTimeMs = getCpuTime(fgs.uid);
               
               if (fgs.type == "dataSync" && cpuTimeMs > 5 * 60 * 1000) {
                   // dataSync 类型的 FGS 运行超过 5 分钟
                   // 限制 CPU 到小核
                   applyCpuRestriction(fgs.uid, LITTLE_CORES_ONLY);
               }
               
               if (fgs.type == "mediaPlayback" && !isAudioActive(fgs.uid)) {
                   // 声明了 mediaPlayback 但实际没有音频输出
                   // 可能是滥用 → 上报 anomaly
                   reportAnomaly(fgs.uid, "FGS_TYPE_MISMATCH");
               }
           }
       }
   }
   ```

3. **效果**
   - 前台服务滥用 APP 识别率：**85%**
   - 后台 CPU 使用降低：**15%**
   - 灭屏待机功耗降低：**5%**（减少了后台 FGS 的持续 CPU 使用）

---

### 2.4 Per-UID 功耗归因精细化

**背景：** Android 的 Battery Usage 页面需要更准确地归因到每个 APP。

**具体工作：**

1. **UID 级功耗模型**
   ```
   APP 功耗 = CPU 功耗 + GPU 功耗 + 网络功耗 + 传感器功耗 + 唤醒功耗
   
   CPU 功耗:
   - 从 /proc/uid_cputime/ 读取每个 UID 的 CPU 时间
   - 乘以对应频率下的功耗系数（来自 Energy Model）
   - 区分前台/后台时间（后台时间归入"浪费"）
   
   GPU 功耗:
   - 从 GPU driver 获取每个 context (UID) 的 GPU 时间
   - 乘以对应频率下的 GPU 功耗系数
   
   网络功耗:
   - 从 /proc/uid_stat/ 读取 TX/RX 字节数
   - 乘以网络类型的功耗系数 (WiFi vs 4G vs 5G)
   
   唤醒功耗:
   - 从 wakeup_sources 统计每个 UID 导致的系统唤醒次数
   - 每次唤醒 = 固定的功耗惩罚
   ```

2. **power_profile.xml 精确校准**
   ```xml
   <!-- 为 SoC 校准功耗模型参数 -->
   <device name="Android">
       <!-- CPU 每个 cluster 每个频率的功耗 (mA) -->
       <array name="cpu.core_speeds.cluster0">
           <value>400000</value>
           <value>800000</value>
           <value>1400000</value>
           <value>1800000</value>
       </array>
       <array name="cpu.core_power.cluster0">
           <value>15</value>   <!-- 400MHz: 15mA -->
           <value>35</value>   <!-- 800MHz: 35mA -->
           <value>85</value>   <!-- 1.4GHz: 85mA -->
           <value>150</value>  <!-- 1.8GHz: 150mA -->
       </array>
       
       <!-- GPU 功耗 -->
       <array name="gpu.core_speeds">
           <value>200000000</value>
           <value>500000000</value>
           <value>800000000</value>
       </array>
       <array name="gpu.core_power">
           <value>25</value>
           <value>120</value>
           <value>350</value>
       </array>
       
       <!-- 网络功耗 -->
       <item name="wifi.active">180</item>    <!-- mA -->
       <item name="wifi.scan">120</item>
       <item name="radio.active">250</item>   <!-- 4G -->
       <item name="radio.active.5g">450</item> <!-- 5G -->
   </device>
   ```

3. **效果**
   - 功耗归因准确度从 **±25%** 提升到 **±8%**
   - 用户可以清楚看到每个 APP 的真实功耗贡献
   - 为 APP 开发者提供了优化方向

---

### 2.5 Thermal HAL 2.0 与 Framework 联动

**具体工作：**

1. **Thermal Headroom API**
   ```java
   /* Android 12+ Thermal Headroom API：
    * APP 可以查询当前温度距离 throttling 还有多远 */
   PowerManager pm = getSystemService(PowerManager.class);
   float headroom = pm.getThermalHeadroom(10);
   // headroom = 0.0 → 即将 throttle
   // headroom = 1.0 → 完全安全
   
   /* 游戏引擎利用 headroom 主动降负 */
   if (headroom < 0.3f) {
       // 距离 throttle 很近 → 主动降低画质
       setRenderingScale(0.8f);
       setTargetFPS(30);
   } else if (headroom > 0.7f) {
       // 温度安全 → 可以提高画质
       setRenderingScale(1.0f);
       setTargetFPS(60);
   }
   ```

2. **SoC Thermal HAL 实现**
   - 实时上报多个 thermal zone 温度
   - 提供 headroom 计算（基于当前温度、趋势、散热能力）
   - 与 Power HAL 联动：温度高时自动降低 PerformanceHint 的 boost 幅度

3. **效果**
   - 游戏主动降质 + Thermal HAL：长时间游戏帧率方差降低 **50%**
   - 用户感知从 "突然卡顿" 变为 "渐进降质"

---

## 三、技术成长与认知

### 核心技能拓展
1. **ADPF 2.0 / Game Mode** — 游戏场景的全栈优化
2. **大屏/桌面模式** — 多窗口多 display 的复杂功耗管理
3. **FGS 治理** — Android 安全/功耗策略的交叉领域
4. **功耗归因** — Per-UID 精细化功耗建模
5. **Thermal Headroom** — 温度感知的应用协同

### 认知转变
- Game Mode 让用户也参与了功耗决策 — 不再只是系统自动判断
- 大屏生态证明 Android 的性能功耗管理需要适应 "PC-like" 使用模式
- 功耗归因的准确性直接影响用户信任和 APP 生态的健康
- Thermal 管理从 "被动保护" 演进为 "主动协商"

### 年度关键数字
| 指标 | 数值 |
|------|------|
| Game Mode Battery 模式功耗节省 | 36-42% |
| Taskbar GPU 功耗 | 40mW → 5mW |
| 分屏模式功耗降低 | 18% |
| FGS 滥用识别率 | 85% |
| 功耗归因精度 | ±25% → ±8% |
| 游戏帧率方差降低(Thermal) | 50% |
| 修复 Bug 数 | 115 |

---

## 四、遗留问题与下年计划

1. **on-device AI 功耗**：大模型推理开始在端侧运行（Stable Diffusion 等）
2. **Wi-Fi 7 功耗评估**：802.11be 的新特性功耗影响
3. **卫星通信功耗**：部分手机开始支持卫星通信
4. **跨设备协同**：手机-平板-手表的功耗协同管理
5. **学习计划**：端侧 LLM 推理、Wi-Fi 7 MLO、UWB 功耗
