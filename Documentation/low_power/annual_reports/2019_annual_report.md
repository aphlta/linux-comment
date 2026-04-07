# 2019 年度工作报告 — 资深系统工程师（性能与功耗）/ 技术专家

**姓名 / 部门**：系统平台部 · 性能与功耗方向  
**汇报周期**：2019-01-01 ~ 2019-12-31  
**SoC 平台**：Cortex-A77 + Cortex-A55（DynamIQ），集成 5G Modem，7nm EUV  
**软件栈**：Linux 4.14 / 4.19；Android 9.0（Pie）→ Android 10（Q）  
**角色定位**：资深系统工程师 / 技术专家，负责高刷显示功耗、启动性能、系统级 trace 体系与 5G 协同功耗架构。

---

## 一、行业背景与年度主题

2019 年旗舰机 **120Hz 高刷屏** 与 **5G 商用** 叠加，功耗模型从「CPU/GPU 峰值」扩展到 **显示子系统固定成本 + Modem 寻呼/射频突发 + 热限功率回退**。Android 10 引入 **Dark Mode、后台启动限制、分区存储** 等变化，要求性能与功耗团队具备 **Framework + Display + Connectivity + Thermal** 的横向拉通能力。

| 驱动力 | 对工程落地的要求 |
|--------|------------------|
| 高刷新率 | VRR / 动态刷新率与 SF/HWC 协同，避免「为流畅牺牲续航」 |
| 5G NSA/SA | 灭屏回落、智能切换、与温控联动 |
| 可观测性 | 从 Systrace 快照走向 **长时间、可查询** 的 trace（Perfetto） |

**本年度个人主题**：在 2018 年 Framework 主战场基础上，建立 **显示功耗与 Modem 功耗的「全栈协同」**，并把分析能力升级为 **SQL 化 + 自动化触发**。

---

## 二、技术成长与协作边界

### 2.1 能力演进

```
  2018                          2019
+-------------+               +------------------+
| SF/Jank/PMS |  ---------->  | VRR + 冷启动全链路 |
| Binder 优化  |               | Perfetto + 5G 协同 |
+-------------+               +------------------+
```

- **显示**：从固定 60Hz 分析扩展到 **模式切换、逐场景功耗分解、与触摸/动画联动策略**。  
- **性能**：从单点启动优化扩展到 **fork → dex → 首帧** 的分段归因与平台化能力（USAP、IO prefetch 等）。  
- **工具**：建设 **Perfetto SQL 查询库**（30+ 条），支撑功耗与卡顿联合分析。

### 2.2 协作角色

与 **显示驱动、面板厂、Modem 协议栈、热设计** 建立联合指标：**日常续航（mAh/h）**、**灭屏电流**、**5G 附着态功耗**、**热节流后的用户体验**（帧率/亮度/modem 档位）。

---

## 三、核心工作内容

### 3.1 120Hz 高刷屏功耗管理 — 动态刷新率（VRR）

**问题陈述**：恒定 120Hz 时，显示与 SF 合成链路基耗显著上升；恒定 60Hz 又损失高刷红利。需要在 **电量状态、内容类型、交互强度** 之间做可解释切换。

#### 3.1.1 60Hz vs 120Hz 功耗分解（同亮度、同静态壁纸、实验室均值）

| 功耗项 | 60Hz（mW，示例） | 120Hz（mW，示例） | 备注 |
|--------|------------------|-------------------|------|
| 面板 + TCON 基础 | 420 | 520 | 刷新率线性项主导 |
| SF + HWC 合成 | 95 | 168 | present 频率翻倍 |
| GPU（轻载 UI） | 55 | 82 | 合成路径负载上升 |
| **合计（相对增量）** | **基线 100%** | **约 +28%** | 用于 VRR 目标函数输入 |

**原因**：分解表用于与产品对齐「可接受的 120Hz 覆盖时长」，并为策略阈值提供 **量化依据**。

#### 3.1.2 动态切换策略（Java 示例）

```java
// 原因：把「规则」集中在单一策略类，便于 A/B 与日志归因；避免散落各业务各写一套。
public final class DynamicRefreshRatePolicy {

    public int decideRefreshRate(Context ctx, SceneSignals s) {
        // 1) 低电量：优先续航
        if (s.batteryLevel <= 20 && !s.isCharging) {
            return 60; // 降低面板与 SF 固定成本
        }
        // 2) 全屏视频播放：与内容帧率对齐（常见 24/30fps）
        if (s.isFullscreenVideo && s.videoFps <= 30) {
            return 60;
        }
        // 3) 无触摸 + 无动画：避免空转 120Hz
        if (!s.hasTouch && !s.hasRunningAnimation) {
            return 60;
        }
        // 4) 列表快速滑动：保证体验
        if (s.scrollVelocityPxPerSec > THRESHOLD_FAST_SCROLL) {
            return 120;
        }
        // 5) 默认：平衡档
        return s.preferHighRefresh ? 120 : 90;
    }

    public void applyViaSurfaceFlinger(IDisplayManager dm, int hz) {
        // 通过 DisplayManager / SurfaceFlinger 接口下发模式规格（具体 API 依平台扩展）
        // setDesiredDisplayModeSpecs：将「首选模式 + 允许组 + 切换原因」一次性下发，
        // 减少频繁切换带来的抖动与额外功耗。
        dm.setDesiredDisplayModeSpecs(buildSpecsForHz(hz));
    }
}
```

**综合结果**：在 **典型日用混合场景**（社交 + 浏览器 + 视频 + 游戏各占比固定）下，相对「恒定 120Hz」策略，**综合日常功耗降低约 22%**，主观流畅度通过 **触摸/滚动窗口** 保持。

---

### 3.2 APP 冷启动全链路优化

#### 3.2.1 全链路耗时模型（ASCII）

```
 startActivity()
      |
      v
  AMS/Binder -----> fork Zygote -----> bindApplication
      |                    |                  |
      |                    v                  v
      |              USAP 预热(可选)      dex/verify/class init
      |                    |                  |
      +--------------------+------------------v
                         Activity.onCreate
                              |
                              v
                    首帧 Choreographer
```

#### 3.2.2 分段耗时示例（Top 50 APP 聚合，P50，单位 ms）

| 阶段 | 优化前 P50 | 优化后 P50 | 主要手段 |
|------|------------|------------|----------|
| AMS → fork | 28 | 22 | 减少启动路径冗余校验、Binder 批量化 |
| fork → bindApplication | 95 | 61 | USAP、Zygote 预热、IO 亲和 |
| dex/verify | 210 | 140 | 编译策略、懒加载、类预加载白名单 |
| onCreate → 首帧 | 180 | 120 | 布局异步化、资源预取、CPU boost 精准化 |
| **总 P50** | **513** | **343** | — |

**关键结果**：**Top 50 第三方应用冷启动耗时提升约 39%**（以「首帧可见」为终点）；通过缩短 **CPU 高压持有时长** 与 **磁盘突发**，**启动过程能耗降低约 30%**（同仪器测量条件下）。

---

### 3.3 Android 10 Dark Mode 功耗优化

#### 3.3.1 OLED 像素功耗模型（简化）

```
  P_pixel ≈ k * (R^gamma + G^gamma + B^gamma)
```

深色 UI 降低平均像素激发，**屏幕子系统**成为最大受益方。

#### 3.3.2 Light vs Dark 量化（实验室：固定亮度条、固定页面滑动脚本）

| 模式 | 平均面板电流（相对） | 说明 |
|------|----------------------|------|
| Light 主题 | 100% | 高亮大面积背景 |
| Dark 主题 | **27%**（屏幕省电 **约 73%**） | 与壁纸/素材对比度强相关 |

#### 3.3.3 Force Dark 与 GPU 开销

- **问题**：全局 Force Dark 可能引入额外 **离屏与 overdraw**。  
- **手段**：对 WebView/三方控件做 **分层白名单**；对高成本 View 关闭 Force Dark，改用 **主题资源**。

#### 3.3.4 低电量联动

当 `batteryLevel <= 15` 且非充电：

- 默认切 **Dark Mode** + 限制 **非关键动画**；  
- 与 VRR 策略叠加后，**系统级可测功耗（同压测脚本）降低约 35%**（相对 Light + 高刷全开基线）。

---

### 3.4 Perfetto 追踪体系建设

#### 3.4.1 Systrace vs Perfetto（对比表）

| 维度 | Systrace（legacy） | Perfetto |
|------|---------------------|----------|
| 数据模型 | 片段化 atrace | 统一 protobuf trace |
| 时长 | 通常较短 | 支持长时间采集 |
| 查询 | 人工目视 | **SQL** 聚合 |
| 功耗联合 | 需多工具拼接 | sched/ftrace/power 同源 |

#### 3.4.2 功耗分析 SQL 查询库（示例 3 则）

```sql
-- 查询 1：CPU 频率驻留分布（原因：判断是否存在「长期钉在高频」的异常线程）
SELECT cpu, freq_khz, SUM(dur_ns)/1e9 AS sec
FROM sched_frequency
GROUP BY cpu, freq_khz
ORDER BY sec DESC;

-- 查询 2：Jank 帧（原因：把超过 vsync 周期的帧与主线程切片关联）
SELECT
  ts,
  frame_latency_ms,
  process_name,
  thread_name
FROM android_frames
WHERE jank_type IS NOT NULL
  AND frame_latency_ms > 16.7
ORDER BY ts;

-- 查询 3：wakeup source 排行（原因：对接内核 suspend 与 irq 唤醒归因）
SELECT
  waker_upid,
  COUNT(*) AS wakeups
FROM instant_events
WHERE name = 'suspend_resume'
GROUP BY waker_upid
ORDER BY wakeups DESC
LIMIT 20;
```

**年度建设**：沉淀 **30+ SQL 查询**（CPU、帧、唤醒、Binder、modem 侧占位事件），接入 CI 夜间采样。

#### 3.4.3 长时间追踪配置（protobuf 片段）

```protobuf
# perfetto_config_long_trace.pbtxt（示例）
# 原因：长 trace 必须限制 buffer 与数据源，避免磁盘打满与丢事件。
buffers {
  size_kb: 131072
  fill_policy: RING_BUFFER
}
data_sources {
  config {
    name: "linux.ftrace"
    ftrace_config {
      ftrace_events: "power/suspend_resume"
      ftrace_events: "sched/sched_switch"
      buffer_size_kb: 4096
    }
  }
}
data_sources {
  config {
    name: "android.surfaceflinger.frametimeline"
  }
}
duration_ms: 3600000
```

#### 3.4.4 Jank 触发器

- 定义 **帧超时 + 主线程 slice 重叠** 为触发条件，自动 **环形缓存前 N 秒** 并上传脱敏 trace。  
- 与线上灰度 **崩溃/ANR** 解耦，专注 **可重现性能回归**。

---

### 3.5 5G 场景全栈功耗协同

#### 3.5.1 5G–WiFi 智能切换（ConnectivityService 规则思路）

| 场景 | 规则摘要 | 原因 |
|------|----------|------|
| 高吞吐下载 | 5G 与 WiFi 并存时优先 WiFi（信号稳定） | 降低 modem PA 功耗 |
| VoLTE/语音 | 锁定蜂窝路径，禁止乒乓 | 避免频繁 RRC |
| 弱 WiFi | 及时回落蜂窝，但加 **迟滞** | 防止边界振荡 |

#### 3.5.2 灭屏 5G → 4G 回落

- 与 modem 团队定义 **灭屏定时器 + 业务豁免**（例如后台大文件下载可延迟回落）。  
- 实验室电流：**灭屏 5G 空闲态 modem 相关功耗降低约 55%**（相对保持 5G 常驻策略）。

#### 3.5.3 Thermal 联动 modem 功率

```
  Skin Temp 上升
        |
        v
  ThermalEngine --+--> CPU/GPU 限频
                  |
                  +--> Modem 最大发射功率 / MIMO 层数降级
```

**原因**：若不联动，CPU 已节流而 modem 仍高功率，会导致 **整机热失控** 与 **用户体验断崖**。

---

## 四、关键数字与质量结果（2019）

| 指标 | 结果 |
|------|------|
| VRR 相对恒定 120Hz 日常综合 | **降低约 22%** |
| Top 50 APP 冷启动 | **提升约 39%** |
| Dark Mode 屏幕电流（实验室脚本） | **降低约 73%** |
| 灭屏 5G→4G modem 相关功耗 | **降低约 55%** |
| Perfetto SQL 查询库 | **30+ 条** |
| 年度闭环缺陷 | **92 个 Bug** |

---

## 五、复盘与下一年方向（简述）

- **复盘**：高刷与 5G 同时上线时，**指标冲突**（流畅 vs 热 vs 续航）需要更早的 **联合仿真**。  
- **方向**：将 **SQL 查询库** 与 **发布门禁** 绑定；探索 **Scheduler + 显示 + Modem** 的统一 Hint 仲裁。

---

*文档版本：v1.0 · 仅供内部年度复盘使用*
