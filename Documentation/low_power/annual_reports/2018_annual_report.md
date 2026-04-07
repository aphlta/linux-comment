# 2018 年度工作报告 — 高级系统工程师（性能与功耗）

**姓名 / 部门**：系统平台部 · 性能与功耗方向  
**汇报周期**：2018-01-01 ~ 2018-12-31  
**SoC 平台**：Cortex-A76 + Cortex-A55（DynamIQ 大小核），7nm FinFET  
**软件栈**：Linux 4.9 / 4.14 / 4.19；Android 8.1（Oreo）→ Android 9.0（Pie）  
**角色定位**：高级系统工程师，主导终端侧性能与功耗基线建设与问题闭环。

---

## 一、行业背景与年度主题

2018 年智能手机竞争从「跑分峰值」转向「日常流畅 + 续航可预期」。7nm 与 DynamIQ 带来峰值算力跃升，但 **GUI 合成路径变长、多核调度复杂、后台唤醒链增多**，使得单纯内核侧 `cpuidle`/`cpufreq` 调优难以解释用户可感知的卡顿与夜间耗电。

行业侧可见趋势包括：

| 维度 | 2017 及以前典型做法 | 2018 行业共识 |
|------|---------------------|---------------|
| 分析工具 | `ftrace` / `systrace` 片段化 | 端到端 Systrace + 功耗归因（Historian） |
| 功耗主因 | 内核唤醒与 idle 泄漏 | Framework 调度 + 图形管线 + Binder 风暴 |
| 产品指标 | 实验室待机小时数 | 真实场景「灭屏到深睡」时延、Jank 率 |

**本年度个人主题**：从 **纯内核功耗主战场** 迁移到 **Android Framework / HAL / 图形栈主战场**，保留内核能力作为「底座」，把优化闭环建立在 **可观测、可量化、可回归** 的 Framework 指标上。

---

## 二、工作栈转型：从内核到 Framework

### 2.1 转型前（2017 年底及以前）

```
[ App ] ---- 少量可见 ---- [ Framework ]
                |
                v
         [ Kernel: cpufreq/cpuidle/wakeup ]
                |
                v
            [ Hardware ]
```

工作重点：`wakeup_sources`、`autosleep` 路径、`sched` 参数、DDR 自刷新窗口等。

### 2.2 转型后（2018 主战场）

```
[ App UI Thread ] --> [ RenderThread ] --> [ BufferQueue ]
        |                      |
        v                      v
 [ Choreographer/Vsync ]   [ GPU/Upload ]
        |
        v
 [ SurfaceFlinger ] --> [ HWC Composer ] --> [ Display Panel ]
        |
        +--> [ PowerManagerService / Alarm / Job ] --> [ Suspend ]
```

**原因说明**：用户感知的「卡」多数发生在 **帧提交与合成** 阶段；夜间耗电常与 **灭屏后 Framework 服务、Binder 事务风暴、HAL 交互** 绑定。继续在纯内核侧「盲调」收益递减，必须把 **Systrace 上的帧边界** 与 **PowerManager 状态机** 纳入同一套方法论。

### 2.3 技术成长摘要

| 能力域 | 2017 基线 | 2018 达成 |
|--------|-----------|-----------|
| 图形栈 | 了解基本合成概念 | 独立完成 SF/HWC/BQ 全链路分析与 Jank 分类 |
| 功耗 | 内核 suspend 路径 | PMS 状态机 + Wakelock 审计 + Screen-off 分级 |
| 工具 | 手工抓 trace | Historian 自动化 + 指标看板雏形 |
| 协同 | 与驱动同事单点沟通 | 与显示/多媒体/Modem 联合制定 Power HAL 映射 |

---

## 三、核心工作内容

### 3.1 SurfaceFlinger 与渲染管线性能分析

**目标**：建立「从 App 到像素」的图形管线全景，并把 Systrace 上的异常模式沉淀为可复用的分类法。

#### 3.1.1 管线全景（ASCII）

```
  APP (UI)                RT (EGL/Skia)           SF              HWC
+-----------+   post    +-----------+  dequeue   +---------+    +--------+
| onDraw    | --------> | draw      | ---------> | latch   | -> | compose|
| traversal |  Choreo   | flush     |  acquire   | present |    | layer  |
+-----------+   vsync   +-----------+  release   +---------+    +--------+
     |                       |                      |
     +---- Jank 根因常出现在 RT/SF 边界与 GPU 回退路径 ----+
```

#### 3.1.2 Systrace 深度分析方法论

- 以 **Choreographer#doFrame → RenderThread → dequeueBuffer → SurfaceFlinger#handleMessageRefresh → presentDisplay** 为主轴对齐时间线。  
- 对 **GPU 合成失败回退**（client composition / GLES 路径）单独统计，与 HWC 能力、Layer 类型、Transform、Protected Content 对齐。

#### 3.1.3 六类 Jank 模式及年度样本占比（实验室 + 小批量用户遥测聚合）

| 编号 | Jank 模式 | 典型 Systrace 特征 | 2018 样本占比 |
|------|-----------|-------------------|---------------|
| J1 | UI 线程长事务阻塞 | `traversal` / `layout` 超阈值 | 22% |
| J2 | RenderThread 重绘/上传 | `DrawFrame` 长尾 | 18% |
| J3 | Buffer 供需失衡 | `dequeueBuffer` 等待、`BufferQueue` stall | 15% |
| J4 | SF 合成拥塞 | `handleMessageRefresh` 连续超时 | 12% |
| J5 | GPU 回退导致合成路径变长 | `GLES` 路径占比升高 | 21% |
| J6 | Vsync 相位漂移/跳帧 | `vsync-app` 与 `sf` 错位 | 12% |

**关键结果**：通过 Layer 降载、HWC 能力补齐、不可见 Surface 及时销毁、以及针对 protected layer 的策略调整，**GPU fallback 率由约 25% 降至约 8%**（同基准场景：主屏滑动 + 视频小窗 + 通知栏下拉）。

#### 3.1.4 指标与 Jank 率

在统一基准（60Hz、固定路由、固定亮度）下，**端到端 Jank 率（>16.67ms 帧占比）较年初基线下降约 30%**。该结果与 J5 占比下降强相关。

---

### 3.2 PowerManagerService 深度定制

**目标**：缩短 **灭屏 → 真正进入 suspend** 的路径，并把「屏幕关闭后系统仍在忙什么」结构化。

#### 3.2.1 核心状态机（逻辑示意）

```
                    goToSleep()
                         |
                         v
              +---------------------+
              |  updatePowerState()  |<----+
              +---------------------+     |
                         |                |
              +----------+----------+     |
              |                     |     |
              v                     v     |
        (屏幕关闭)            (唤醒锁/用户活动) --+
              |
              v
        进入 doze/suspend 候选
              |
              v
           suspend()
```

**原因**：`goToSleep` 只表示「策略上允许睡眠」；真正能否 `suspend` 取决于 `updatePowerState` 对 **wake lock、用户活动、proximity、充电状态、Dream** 等的综合判断。优化必须落在 **状态迁移的时序与冗余唤醒** 上。

#### 3.2.2 Wakelock 审计

- 建立 **灭屏后 Top N 持锁模块** 周报：PARTIAL_WAKE_LOCK、FULL_WAKE_LOCK（遗留路径）等。  
- 与 AlarmManager、JobScheduler、GNSS、Sensor 服务联合整改 **「灭屏仍高频持锁」** 的默认策略。

#### 3.2.3 灭屏到 suspend 延迟优化

| 阶段 | 优化前（典型 P50） | 优化后（典型 P50） | 手段摘要 |
|------|-------------------|-------------------|----------|
| 屏幕关闭 → 首批后台收敛 | ~400 ms | ~220 ms | 提前取消非关键动画回调、合并亮度动画 |
| 后台 Job 触发节流 | ~350 ms | ~180 ms | 与 JobScheduler 协同：screen-off 窗口合并 |
| 传感器/网络轮询退避 | ~250 ms | ~50 ms | HAL 层采样率联动 PMS 状态 |
| **合计（灭屏→suspend 就绪）** | **~1000 ms** | **~450 ms** | 多项叠加，以 Systrace + wakeup 统计交叉验证 |

#### 3.2.4 Screen-off 场景四级分级

| 级别 | 名称 | 策略要点 |
|------|------|----------|
| L0 | 用户主动灭屏 | 标准 doze 进入，允许延迟告警合并 |
| L1 | Proximity 通话灭屏 | 禁止误触高采样传感器，modem 侧策略单独表 |
| L2 | AOD / 低亮显示 | 限制 SF 刷新、降低合成频率（与产品定义绑定） |
| L3 | 充电 + 亮屏锁 | 放宽部分 Job，但仍审计 PARTIAL 锁 |

---

### 3.3 Android 9.0 Adaptive Battery 全栈集成

**工作范围**：App Standby Buckets、`UsageStatsService` 数据消费、Historian 自动化回归。

#### 3.3.1 Rare Bucket 额外限制（策略示例，Java 伪代码）

```java
// 原因：Rare 应用若仍允许高频 Alarm/Job，会吞噬「自适应电池」的理论收益。
// 在 StandbyController 扩展点增加「Rare 附加节流」，与官方 bucket 语义对齐。
void applyRareBucketExtraRestrictions(String packageName, int bucket) {
    if (bucket != STANDBY_BUCKET_RARE) {
        return;
    }
    // 合并重复 Alarm：将 minInterval 提升到产品定义阈值（示例）
    alarmPolicy.raiseMinInterval(packageName, /* minMs */ 15 * 60_000);
    // Job：禁止在 doze 浅睡窗口内的「非豁免」任务突发
    jobPolicy.throttleNonExemptJobs(packageName, JobThrottleMode.SCREEN_OFF);
}
```

#### 3.3.2 UsageStatsService 数据利用

- 将 **前台时长、交互次数、最后使用时刻** 作为 bucket 迁移的辅助信号，降低「误杀高频工具类 App」的投诉率。  
- 与云端列表（可选）做 **灰度**：对系统应用与白名单包跳过 Rare 附加限制。

#### 3.3.3 Battery Historian 自动化（bash 片段）

```bash
#!/bin/bash
# 原因：Historian 手工跑易遗漏「基线前后」对比；自动化保证每周同一套场景。
set -euo pipefail
BUGREPORT_DIR=/data/qa/bugreports
OUT_DIR=/data/qa/historian_out/$(date +%Y%m%d)
mkdir -p "$OUT_DIR"
for z in "$BUGREPORT_DIR"/*.zip; do
  docker run --rm -v "$BUGREPORT_DIR":/br:ro -v "$OUT_DIR":/out historian \
    --input "/br/$(basename "$z")" --output "/out/$(basename "$z" .zip).html"
done
# 后续：解析 wakeup、partial wake、job 聚合写入内网看板（略）
```

---

### 3.4 Binder 通信性能优化

**目标**：降低灭屏后 **高频小事务** 带来的 CPU 唤醒与调度抖动。

#### 3.4.1 灭屏 Top 5 高频 Binder（示例归类）

| 排名 | 调用簇 | 典型服务端 | 优化思路 |
|------|--------|------------|----------|
| 1 | 状态轮询型 | 传感器/网络状态缓存 | cache + 事件驱动 |
| 2 | 配置频繁读 | Settings Provider | 批量读、内存缓存 |
| 3 | 小粒度统计 | 统计与埋点服务 | 聚合上报 |
| 4 | 图形相关查询 | SF/HWC 信息查询 | 降频、合并 |
| 5 | 电源相关查询 | PMS/BatteryService | 状态位打包一次返回 |

#### 3.4.2 调用聚合与对齐（C 侧思想示例）

```c
/*
 * 原因：Binder 每次事务都有内核态切换与调度成本；
 * 将「连续 N 次只读相同 key」合并为一次批量 IPC，可显著降低事务数。
 */
struct batched_settings_request {
    int num_keys;
    const char *keys[MAX_KEYS];
};

int settings_get_many(struct batched_settings_request *req, struct value *out) {
    /* 一次 TRANSACTION，返回紧凑数组；调用方在 Java 层做短期 mem cache */
    return binder_transact(BATCH_GET_SETTINGS, req, out);
}
```

**年度结果（灭屏压力测试 8h）**：

| 指标 | 优化前 | 优化后 |
|------|--------|--------|
| Binder 事务数（归一化） | 100% | **~60%**（**减少约 40%**） |
| 灭屏待机平均电流 | 基线 | **约 -8%** |

---

### 3.5 Power HAL 2.0 架构设计

**目标**：把 **PowerHint** 从「各模块各自理解」收敛为 **CPU/GPU/DDR 可执行策略表**，便于芯片平台落地与回归。

#### 3.5.1 六种 PowerHint 映射表（摘要）

| PowerHint | 典型触发 | CPU 策略 | GPU 策略 | DDR 策略 |
|-----------|----------|----------|----------|----------|
| INTERACTION | 触摸、滑动开始 | 短 boost + 提频台阶 | 提 GPU 最小频率 | 维持中等带宽 |
| LAUNCH | 冷启动 | 较长 boost + 大核亲和 | 预热 shader cache | IO 带宽优先 |
| GAME | 游戏会话（可选） | sustained 性能档 | sustained GPU | 高带宽 |
| VIDEO_DECODE | 硬解播放 | 能效档 | 固定较低档 | 按管线带宽 |
| VIDEO_ENCODE | 录像 | 性能档 + 限温 | 中等 | 高 |
| DISPLAY_INACTIVE | 灭屏/AOD | 快速收频 | 快速 idle | 自刷新/低功耗 |

**原因**：没有映射表的 HAL 往往出现 **Hint 互斥、平台默认覆盖、温控后行为不可解释**；表驱动 + 优先级规则使日志可读、问题可二分。

---

## 四、关键数字与质量结果（2018）

| 指标 | 结果 |
|------|------|
| GPU fallback 率 | **25% → 8%** |
| 灭屏 → suspend 延迟（P50） | **1 s → 450 ms** |
| Binder 事务（灭屏场景） | **减少约 40%** |
| Jank 率（统一基准） | **降低约 30%** |
| 年度闭环缺陷 | **95 个 Bug**（含 Framework/HAL/驱动协同） |

---

## 五、不足与 2019 展望

- **不足**：Systrace 对长稳场景仍偏「快照」；跨团队 Hint 冲突需更强 **全局仲裁**。  
- **展望**：引入 **120Hz / 高刷** 与 **更系统的 trace 基础设施**（为后续 Perfetto 铺路）；冷启动与 **5G 功耗** 将成为新的全栈课题。

---

*文档版本：v1.0 · 仅供内部年度复盘使用*
