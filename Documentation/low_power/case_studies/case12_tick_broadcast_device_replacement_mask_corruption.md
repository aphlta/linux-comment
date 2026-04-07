# tick/broadcast：oneshot 模式下 broadcast 设备替换导致定时器“丢唤醒/卡顿”故障复盘（培训版）

| 字段 | 内容 |
|---|---|
| 文档编号 | LP-INC-CASE12 |
| 适用内核 | Linux `v6.4` 起包含修复（见“永久修复”） |
| 适用模块 | `kernel/time/tick-broadcast.c`（tick broadcast / clockevents） |
| 故障类型 | broadcast 状态机污染导致 next_event 未更新（Timer Stall / Hung Task） |
| 上游修复提交 | `f9d36cf445ffff0b913ba187a3eff78028f9b1fb` |
| 标题 | `tick/broadcast: Make broadcast device replacement work correctly` |
| 作者/日期 | Thomas Gleixner / 2023-05-06 |
| Reported-by | Victor Hassan `<victor@allwinnertech.com>` |
| 关联缺陷提交（Fixes） | `9c336c9935cf`（late registered broadcast device oneshot 初始化） |
| 文档版本 | v1.0 |
| 最后更新 | 2026-04-06 |
| 维护人 | （填入） |
| 审阅人 | （填入） |

## 0. 摘要

本案例分析上游提交 `f9d36cf445ff` 修复的一个“稀有但破坏性极强”的时间子系统问题：当系统已经处于 NOHZ/HIGHRES 的 oneshot 模式运行时，如果运行中发生 broadcast clockevent 设备替换（replacement/late init 被选为新的 broadcast），旧实现会在 oneshot setup 路径中错误地把“通用 broadcast mask（资格集合）”合并进“oneshot broadcast mask（运行态集合）”，造成 oneshot mask 被污染。

污染后，部分 CPU 在后续进入 idle（尝试将本地 next_event 交给 broadcast）时会错误地认为自己已经处在 oneshot broadcast 管理之下，从而跳过“必要时重编程 broadcast next_event”的关键动作，导致 broadcast 设备保持一个过晚的到期点。若该到期点很远，将引发定时器迟迟不触发、调度/超时推进停滞、hung task detector 等异常。

该提交同时修复了 replacement 场景下“新 broadcast 设备可能未被及时 arm，导致已 idle 的 CPU 的到期事件不准时投递”的问题。

## 1) 技术背景：tick broadcast / oneshot / mask 语义

### 1.1 业务动机：本地 timer 不可用时，必须有公共唤醒源

当 CPU 进入某些深 idle state 会导致本地 clockevent（如 per-cpu arch timer / LAPIC timer）停止或无法作为唤醒源时，内核必须把该 CPU 的下一次到期事件交接给一个可用的 broadcast 计时器设备（可能由某个仍醒着的 CPU 承担、或全局计时器承担），以保证定时器到期能把 CPU 拉起来。

这个“交接/托管”动作在 oneshot 模式下大致体现为：如果该 CPU 的 `dev->next_event` 早于 broadcast 设备当前编程的 `bc->next_event`，则应把 broadcast 设备重编程到更早的时间点。

### 1.2 periodic vs oneshot（NOHZ/HIGHRES 常见组合）

- periodic：按固定 tick 周期触发（jiffies tick），用于周期性调度/时间推进。
- oneshot：不再固定周期，而是每次编程到“最近的下一次真正需要触发的到期点”，常见于 NOHZ + highres timers 的配置。

### 1.3 两类 mask：资格集合 vs 运行态集合（本案的核心）

tick broadcast 子系统维护多个 CPU mask，其中最容易被误用的是：

- `tick_broadcast_mask`：更像“该 CPU 启用了/需要 broadcast 支持”的资格集合，bit 具有一定粘性，通常只在显式 disable 时清理。典型读写点：`tick_broadcast_control()`（见下文引用）。
- `tick_broadcast_oneshot_mask`：oneshot broadcast 的运行态集合，表示“当前处于 oneshot broadcast 管理之下（通常正在 idle 中需要广播唤醒）”的 CPU。

本案正是因为在 replacement 场景下把资格集合误并入运行态集合，导致运行态集合被污染，进而影响后续的进入/退出决策。

## 2) 故障触发条件（为什么难复现）

要同时满足以下条件才容易稳定触发：

- 系统已经处于 `tick_broadcast_device.mode == TICKDEV_MODE_ONESHOT`（常见于启用 NOHZ/HIGHRES，或者系统切到 oneshot tick 模式）。
- 运行中发生 broadcast clockevent 设备替换：
  - 更高 rating 的 clockevent 设备在启动后期才注册（late registered），被选为 broadcast；
  - 或已有 broadcast 设备被替换为另一个设备。
- replacement 发生后，broadcast 设备 `bc->next_event` 恰好落在一个较远的未来，且被污染的 CPU 又恰好需要一个更早的 next_event 才能准时唤醒。

本案最初由 Allwinner 平台报告，反映其 clockevent/broadcast 的注册时序更容易出现“系统已 oneshot 但 broadcast 设备仍可能发生 replacement”的组合。

## 3) 表象（Symptoms）：你会看到什么

### 3.1 外部症状

- 随机或阶段性“卡顿/停滞”：某些超时明显延长、工作队列/软中断推进变慢、用户态表现为系统间歇性冻结。
- 触发 hung task detector（尤其当某些等待依赖超时推进时）。
- 从“时间推进”的角度看，像是“某些 CPU 没有按预期收到定时器到期驱动的唤醒”。

### 3.2 内部症状（时间子系统视角）

- 某 CPU 的本地 tick device（`td->evtdev`）的 `next_event` 明显更早，但 broadcast 设备（`bc`）当前编程的 `bc->next_event` 却更晚（甚至很远）。
- 该 CPU 在后续进入 idle 时未触发对 broadcast 的重编程，从而持续“错过更早的到期点”。

## 4) 根因剖析：两个问题叠加

本提交修复了两个独立但相关的问题。理解它们需要同时把握：

- oneshot 进入路径里“是否第一次加入 oneshot broadcast mask”的判定；
- oneshot setup 路径里“是否应该把 periodic mask 并入 oneshot mask”的语义。

### 4.1 问题 1：oneshot mask 污染导致跳过重编程 broadcast next_event

#### 4.1.1 关键路径：进入 oneshot broadcast 时只有“首次”才会比较并重编程

在 CPU 进入 oneshot broadcast 管理时，关键逻辑位于：

- [___tick_broadcast_oneshot_control()](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L796-L932) 的 ENTER 分支：
  - 通过 `cpumask_test_and_set_cpu(cpu, tick_broadcast_oneshot_mask)` 判断是否第一次加入 oneshot mask；
  - 只有“第一次加入”（bit 原本为 0）才会进入重编程逻辑：
    - 若 `dev->next_event < bc->next_event`，调用 [tick_broadcast_set_event()](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L651-L659) 重编程 broadcast 设备（对应 [tick-broadcast.c:L846-L862](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L846-L862)）。

因此，一旦某 CPU 的 oneshot mask bit 被提前置位，它后续真正进入深 idle 时就会绕过“比较 next_event 并重编程”的流程。

#### 4.1.2 污染的来源：replacement 时误把 `tick_broadcast_mask` OR 进 `tick_broadcast_oneshot_mask`

在切换 tick 模式时，broadcast 设备需要做 oneshot setup：

- [tick_broadcast_setup_oneshot()](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L1021-L1121)

在“从 periodic 切到 oneshot”的场景，确实需要把 `tick_broadcast_mask` 合并进 `tick_broadcast_oneshot_mask`，目的是：让仍在等 periodic broadcast 的 CPU 能在下一个 tick 被唤醒。

但在“broadcast 设备替换（replacement）且系统已经 oneshot”的场景，这个 OR 是错误的：`tick_broadcast_mask` 的 bit 有粘性，它可能包含“此刻并不 idle、但启用了 broadcast”的 CPU。若把这些 CPU 塞进 oneshot mask，会让它们后续进入 idle 时误判为“已经 setup”，从而跳过更新 broadcast 到期点。

该提交通过引入 `from_periodic` 参数把语义拆开，明确：

- 仅当 `from_periodic == true`（真正 periodic→oneshot 切换）时才允许 OR；
- replacement 场景必须保持 oneshot mask 不动。

这段结论在代码注释中写得非常直白（建议逐句读）：

- [tick_broadcast_setup_oneshot():L1068-L1079](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L1068-L1079)

### 4.2 问题 2：replacement 时新 broadcast 设备未及时 arm

第二个问题更像“时序正确性/兜底”问题：

- replacement 发生在 oneshot 模式下时，新设备可能处于 shutdown 状态；
- 若此时 `tick_broadcast_oneshot_mask` 非空（已经有 CPU 在 idle 等广播唤醒），但新设备未被编程，就无法保证这些 CPU 的到期事件准时投递。

本提交采用一个非常直接的兜底策略：

- 在 replacement 场景下，如果 oneshot mask 非空，则把 broadcast 设备编程为“立即过期”的事件（`nexttick` 保持为 0，落在过去），迫使 clockevent 层立刻触发一次；
- 这次立即触发会进入 [tick_handle_oneshot_broadcast()](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L690-L768)，重新扫描所有相关 CPU 的 `next_event` 并据此设置真正最早到期点，从而恢复一致性。

对应代码与注释：

- [tick_broadcast_setup_oneshot():L1103-L1120](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L1103-L1120)

## 5) 调试与排查：现场如何确认是否命中该类问题

本节给出“无侵入观测 → 轻量跟踪 → 深入定位”的三层方法。建议优先从无侵入观测开始。

### 5.1 无侵入观测：/proc 视角的一致性检查

**(1) `/proc/timer_list`：对比 broadcast next_event 与 per-cpu next_event**

关注两类信息：

- broadcast 设备（clockevent）的 `next_event`；
- 每个 CPU tick device 的 `next_event`。

若观察到“某 CPU 的本地 `next_event` 明显更早，但 broadcast `next_event` 却很远”，高度可疑。

**(2) `/proc/timer_list`：对比 `tick_broadcast_mask` vs `tick_broadcast_oneshot_mask`**

经验判断：

- `tick_broadcast_oneshot_mask` 更像“当前处于 idle、需要广播唤醒”的集合；
- 若 oneshot mask 长时间包含明显繁忙的 CPU（或包含异常多 CPU），可能说明 mask 被污染或状态机未正确清理。

### 5.2 轻量跟踪：确认是否“跳过 tick_broadcast_set_event()”

要证明“CPU 进入 idle 时没有把更早的到期点转交给 broadcast”，核心是证明下面这段逻辑被绕过：

- [___tick_broadcast_oneshot_control() ENTER 重编程段](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L830-L863)

可用的跟踪策略（按可用性选择）：

- ftrace function graph / function tracer：观察 `___tick_broadcast_oneshot_control()` 被调用时是否进到 `tick_broadcast_set_event()`；
- tracepoint 组合：`timer:*` + `irq:*` + `power:cpu_idle`，配合时间线判断“该 CPU 是否按期被 broadcast 唤醒”。

### 5.3 深入定位：确认是否发生 broadcast device replacement

该故障高度依赖 replacement，因此要在日志/跟踪中找到 replacement 的证据：

- 关注 broadcast clockevent 的安装与替换路径，例如：
  - [tick_install_broadcast_device()](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L163-L204)
  - `tick_device_uses_broadcast()` 调用 `tick_broadcast_setup_oneshot(bc, false)`（replacement 语义）可在同文件中找到调用点。

若能在 replacement 后紧接着观察到 oneshot mask 的异常变化，基本可以闭环。

## 6) 复现思路（最小化触发模型）

本问题的“最小复现模型”不是某个具体驱动，而是一个事件序列：

1. 系统进入 oneshot 模式（NOHZ/HIGHRES 生效）。
2. 在系统运行中，注册一个新的 clockevent 设备（rating 更高），触发 broadcast device replacement。
3. replacement 后，保证至少存在一个 CPU：
   - 会进入需要 broadcast 的 idle（本地 timer 停止/不可用），并且其 `dev->next_event` 早于当前 `bc->next_event`；
   - 同时其 oneshot mask bit 在 replacement 时被污染置位（修复前）。
4. 观察到 CPU 进入 idle 后未触发 `tick_broadcast_set_event()`，并最终出现长时间不唤醒/超时推进异常。

## 7) 临时规避（Workarounds）与永久修复

### 7.1 临时规避（针对现场救火，不保证适用于所有系统）

该问题属于内核时间子系统 bug，规避策略依赖系统场景，常见方向：

- 避免 broadcast device replacement（例如确保关键 clockevent 设备更早初始化/内建而非 late init）；
- 对问题版本回合入上游补丁 `f9d36cf445ff`（推荐）；
- 若平台允许，临时降低/禁用导致 replacement 的 clockevent 设备选择（需要平台/架构侧评估，不建议作为长期方案）。

### 7.2 永久修复（推荐）

上游修复提交：

- `f9d36cf445ffff0b913ba187a3eff78028f9b1fb`

进入主线版本：

- `v6.4` 起包含（可用 `git tag --contains f9d36cf445ff` 验证）。

修复要点：

- `tick_broadcast_setup_oneshot()` 引入 `from_periodic` 分支，仅在 periodic→oneshot 切换时 OR mask；
- replacement 场景下，如果 oneshot mask 非空，则 arm 新 broadcast 设备“立即过期”以强制重新评估 next_event。

## 8) 验证与回归：如何确认修复生效

建议从“状态一致性”出发建立验证标准：

- replacement 发生前后：
  - `tick_broadcast_oneshot_mask` 不应异常膨胀（不应包含明显忙碌 CPU）。
- CPU 进入需要 broadcast 的 idle 时：
  - 若其本地 `next_event` 早于 broadcast `next_event`，应观察到 broadcast 被重编程（函数跟踪或 timer_list 的 next_event 变化）。
- 压力测试：
  - 复现环境下，修复前可见的 stall/hung task 在修复后消失；
  - 结合 NOHZ/HIGHRES 与平台 idle state 的常规回归（长时间运行、热插拔/驱动加载等触发 replacement 的场景）。

## 9) 关键代码索引（建议走读顺序）

1. oneshot setup：从语义分离理解本案修复
   - [tick_broadcast_setup_oneshot()](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L1021-L1121)
2. oneshot enter/exit：理解“为什么 mask 污染会导致跳过重编程”
   - [___tick_broadcast_oneshot_control()](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L796-L932)
   - [tick_broadcast_set_event()](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L651-L659)
3. oneshot broadcast handler：理解“立即过期触发重新评估”的工作方式
   - [tick_handle_oneshot_broadcast()](file:///home/alex/linux-stable/kernel/time/tick-broadcast.c#L690-L768)

