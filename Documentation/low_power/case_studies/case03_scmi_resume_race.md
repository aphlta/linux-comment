# 案例三：SCMI 电源控制 Resume 竞态条件

| 项目 | 信息 |
|------|------|
| Commit | `9a0658d3991e6c82df87584b253454842f22f965` |
| 作者 | Peng Fan (NXP) |
| 影响版本 | 使用 SCMI 电源管理的 ARM 平台 |
| 子系统 | Firmware / ARM SCMI / System Sleep |
| 严重性 | 中 — 间歇性功能失效，不会崩溃 |

## 1. 故障现象

在使用 SCMI（System Control and Management Interface）协议的 ARM 平台上，
出现以下**间歇性**问题：

- 系统在外部 SCMI agent（如 SCP 固件）的 suspend 通知下成功进入第一次睡眠
- 睡眠期间，另一个 SCMI agent 发送第二次 suspend 通知，将系统唤醒
- 系统唤醒后，**无法响应新的 suspend 请求**——第二次 suspend 通知被静默丢弃
- 系统保持 active 状态，不再响应后续的 SCMI suspend 命令
- 必须手动重启或等待其他事件才能恢复正常的 suspend 功能

**关键特征**：
- 仅在**多 SCMI agent** 环境中出现（如 SCP + AP + 另一个处理器）
- 时序敏感——两次 suspend 通知间隔越短越容易触发
- 不会导致系统崩溃，但功耗控制策略失效

## 2. 复现手法

### 环境要求
- ARM SoC 平台，使用 SCMI 协议与 SCP（System Control Processor）通信
- 至少两个 SCMI agent 可以发起 system power 状态变更
- 典型平台：NXP i.MX9 系列、ARM Juno 等

### 复现步骤

```bash
# 此 bug 需要固件侧的配合，纯软件复现较困难
# 以下是原理层面的复现思路：

# 1. Agent A 发送 SYSTEM_POWER_STATE_SET (SUSPEND) 通知
#    → Linux SCMI driver 收到通知
#    → scmi_userspace_notifier() 检查 sc->state == SCMI_SYSPOWER_IDLE
#    → 条件满足，调度 suspend_work
#    → suspend_work 调用 pm_suspend(PM_SUSPEND_MEM)
#    → 系统进入 S3 睡眠

# 2. 系统在睡眠状态中...

# 3. Agent B 发送第二次 SYSTEM_POWER_STATE_SET (SUSPEND) 通知
#    → 此通知作为唤醒源，将系统从 S3 唤醒
#    → resume 流程开始：
#       → device_resume() 执行各设备的 .resume() 回调
#       → 中断被重新使能
#       → SCMI 中断触发 scmi_userspace_notifier()  ← 关键时间点！
#       → 检查 sc->state，但此时仍为 SCMI_SYSPOWER_SUSPEND（未重置！）
#       → 条件不满足，通知被丢弃
#       → ... 之后 thaw_processes() 执行 ...
#       → ... suspend_work 的 pm_suspend() 返回 ...
#       → sc->state = SCMI_SYSPOWER_IDLE （太迟了！通知已丢失）
```

### 模拟复现的方法

```bash
# 如果无法控制固件行为，可以通过以下方式验证修复：

# 1. 在 scmi_userspace_notifier() 中添加调试打印
# 2. 在 resume 路径的不同阶段检查 sc->state 的值
# 3. 使用 ftrace 追踪状态变化的时序

# 注入延迟来扩大竞态窗口（仅调试用）：
# 在 scmi_suspend_work_func 的 pm_suspend() 返回后添加 msleep()
```

## 3. 分析思路

### 第一步：理解 SCMI 电源状态机

```
                    ┌─────────────┐
                    │  IDLE       │
      正常态 ──────→│  (可接受     │←──── resume 后应立即回到此态
                    │   suspend)  │
                    └──────┬──────┘
                           │ 收到 suspend 通知
                           ▼
                    ┌─────────────┐
                    │  SUSPEND    │
                    │  (正在执行   │
                    │   suspend)  │
                    └──────┬──────┘
                           │ pm_suspend() 执行
                           ▼
                    ┌─────────────┐
                    │  SLEEPING   │
                    │  (系统睡眠中) │
                    └──────┬──────┘
                           │ 唤醒
                           ▼
                    ┌─────────────┐
                    │ 应回到 IDLE  │
                    │ 但旧代码延迟 │ ← Bug：状态恢复太迟
                    │ 设置 IDLE    │
                    └─────────────┘
```

### 第二步：分析 resume 时序

Linux suspend/resume 的阶段顺序：

```
suspend 阶段（向下）：                resume 阶段（向上）：
  freeze_processes()                    dpm_resume_early()
  → dpm_suspend()                       → dpm_resume()        ← 设备 .resume() 回调
    → dpm_suspend_late()                  → thaw_processes()   ← 进程解冻
      → dpm_suspend_noirq()                 → pm_suspend() 返回
        → [系统睡眠]
```

**竞态窗口**：

```
时间线
  │
  ├── dpm_resume() 阶段
  │     └── 各设备的 .resume() 执行
  │         └── 中断控制器恢复 → SCMI 中断现在可以触发了
  │              └── 如果此时 Agent B 的通知到达：
  │                   scmi_userspace_notifier() 被调用
  │                   检查 sc->state → 仍为 SUSPEND → 丢弃通知 ← Bug!
  │
  ├── thaw_processes() ← 进程解冻
  │
  ├── pm_suspend() 返回到 suspend_work
  │     └── sc->state = SCMI_SYSPOWER_IDLE  ← 旧代码在这里才设置！太迟了！
  │
  └── 系统回到正常运行
```

### 第三步：确认根因

**旧代码的状态恢复位置**：

```c
// 旧代码：在 workqueue 函数中设置
static void scmi_suspend_work_func(struct work_struct *work)
{
    struct scmi_syspower_conf *sc = container_of(...);
    pm_suspend(PM_SUSPEND_MEM);  // 这里会阻塞直到完整的 suspend→resume 完成
    sc->state = SCMI_SYSPOWER_IDLE;  // 在 pm_suspend 返回后才设置！
}
```

问题：`pm_suspend()` 返回意味着整个 resume 流程已经完成，包括 `thaw_processes()`。
但 SCMI 中断在 `dpm_resume()` 阶段就已恢复，比 `thaw_processes()` 更早。
在这个时间窗口内收到的通知会因为状态不是 IDLE 而被忽略。

## 4. 分析工具

### ftrace 事件追踪（最关键）
```bash
# 追踪 suspend/resume 各阶段的时序
echo 1 > /sys/kernel/debug/tracing/events/power/suspend_resume/enable

# 追踪 SCMI 相关事件
echo 1 > /sys/kernel/debug/tracing/events/scmi/enable

# 追踪中断恢复时机
echo 1 > /sys/kernel/debug/tracing/events/irq/irq_handler_entry/enable

# 追踪 workqueue 事件
echo 1 > /sys/kernel/debug/tracing/events/workqueue/enable
```

### pm_debug_messages
```bash
echo 1 > /sys/power/pm_debug_messages
# 输出每个设备 suspend/resume 的详细时序
# 帮助确认中断恢复和进程解冻的先后顺序
```

### 内核动态打印（dynamic debug）
```bash
# 启用 SCMI power control 模块的调试输出
echo 'module scmi_power_control +p' > /sys/kernel/debug/dynamic_debug/control

# 在关键路径添加状态值的打印
```

### suspend_stats
```bash
cat /sys/power/suspend_stats/*
# 查看 suspend 成功/失败统计，确认是否存在 suspend 请求丢失
```

### 添加自定义 tracepoint
```c
// 如果标准 trace 不够，在关键位置添加 trace_printk()
static int scmi_userspace_notifier(...) {
    trace_printk("scmi notifier: state=%d\n", sc->state);
    ...
}
```

## 5. 解决思路

### 修复策略

将状态恢复从 workqueue 函数移到**设备的 `.resume()` 回调**中：

```c
// 新增 resume 回调
static int scmi_system_power_resume(struct device *dev)
{
    struct scmi_syspower_conf *sc = dev_get_drvdata(dev);
    sc->state = SCMI_SYSPOWER_IDLE;
    return 0;
}

static const struct dev_pm_ops scmi_system_power_pmops = {
    SET_SYSTEM_SLEEP_PM_OPS(NULL, scmi_system_power_resume)
};

// 简化 work function
static void scmi_suspend_work_func(struct work_struct *work)
{
    pm_suspend(PM_SUSPEND_MEM);
    // 不再在这里设置状态——由 .resume() 回调处理
}
```

**为什么这样修复？**

`.resume()` 回调在 `dpm_resume()` 阶段执行，这是在中断恢复之后、进程解冻之前。
确保了在任何 SCMI 通知可能到达之前，状态已经被正确设置为 IDLE。

### 修复的完整变更

除了 resume 回调，还需要：

```c
// 在 probe 中保存 driver data，供 resume 回调使用
static int scmi_syspower_probe(struct scmi_device *sdev)
{
    ...
    sc->dev = &sdev->dev;
    dev_set_drvdata(&sdev->dev, sc);  // 新增：保存私有数据指针
    ...
}

// 注册 PM ops
static struct scmi_driver scmi_system_power_driver = {
    .driver = {
        .pm = &scmi_system_power_pmops,  // 新增：关联 PM 操作
    },
    .name = "scmi-system-power",
    .probe = scmi_syspower_probe,
    ...
};
```

## 6. 相关背景知识

### SCMI（System Control and Management Interface）

SCMI 是 ARM 定义的一个标准协议，用于 AP（Application Processor）与
SCP（System Control Processor）之间的通信：

```
┌──────────────┐     SCMI Protocol      ┌──────────────┐
│     AP       │ ◄──────────────────────► │     SCP      │
│  (Linux)     │    Mailbox / SMT        │  (Firmware)  │
│              │                         │              │
│  Agent 0     │                         │  平台电源管理  │
└──────────────┘                         └──────────────┘
        ▲                                       ▲
        │                                       │
        │          ┌──────────────┐             │
        └──────────│   Agent 1    │─────────────┘
                   │ (其他处理器)  │
                   └──────────────┘
```

SCMI System Power 协议允许 agent 请求系统级电源状态变更（如 suspend/shutdown）。

### Linux Suspend/Resume 阶段详解

```
完整的 suspend→resume 流程：

[用户空间]  pm_suspend(PM_SUSPEND_MEM)
    │
    ├── freeze_processes()          进程冻结
    ├── dpm_suspend_start()
    │   ├── device .prepare()       设备准备
    │   └── device .suspend()       设备挂起
    ├── dpm_suspend_late()
    │   └── device .suspend_late()  晚期设备挂起
    ├── dpm_suspend_noirq()
    │   └── device .suspend_noirq() 关中断后的设备挂起
    ├── [平台进入低功耗]
    │
    │   ~~~ 系统睡眠中 ~~~
    │
    ├── [唤醒事件发生]
    ├── dpm_resume_noirq()
    │   └── device .resume_noirq()  关中断状态的设备恢复
    ├── dpm_resume_early()
    │   └── device .resume_early()  早期设备恢复
    ├── dpm_resume()
    │   ├── device .resume()        设备恢复  ← 修复后在此设置 IDLE
    │   └── device .complete()      设备完成
    ├── thaw_processes()            进程解冻
    │
    └── 返回用户空间
```

### 竞态条件的通用分析模式

此类"状态恢复太迟"的竞态有一个通用模式：

```
线程 A（主路径）：     线程 B（中断/通知路径）：
  进入临界操作
  state = BUSY
  ...操作中...
  ...操作完成...
                        检查 state
                        state 仍为 BUSY → 拒绝请求（Bug!）
  state = IDLE          （已经太迟了）
```

修复原则：**状态恢复必须在可能的检查点之前完成**。
具体到本案例，就是在中断可能触发 notifier 之前就设置好 IDLE 状态。

### 多 Agent 系统的协调挑战

在有多个 SCMI agent 的系统中，电源状态协调面临的问题：
- 各 agent 异步发送通知，无法预知时序
- Linux 的 suspend/resume 是一个长流程，期间有多个状态变化点
- SCP 可能无法区分 CPU idle 和 system suspend（两者都表现为 cluster power-off）
- 需要在 Linux 侧通过状态机正确处理各种中断到达的时机
