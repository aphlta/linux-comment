# 案例五：cpufreq schedutil 调频器冗余频率更新

| 项目 | 信息 |
|------|------|
| Commit | `8e461a1cb43d69d2fc8a97e61916dce571e6bb31` |
| 作者 | Sultan Alsawaf |
| 影响版本 | v4.18+（引入 `limits_changed` 标志后）|
| 修复引入的 Bug | `600f5badb78c` ("cpufreq: schedutil: Don't skip freq update when limits change") |
| 子系统 | cpufreq / schedutil / Scheduler |
| 严重性 | 低-中 — 性能退化，不影响功能正确性 |

## 1. 故障现象

使用 `schedutil` 调频策略时，系统产生**大量不必要的频率更新请求**。
这不是一个会导致崩溃或功能故障的 bug，而是一个**性能/功耗退化**问题：

### 直接影响
- 每次调度器回调（scheduler tick/enqueue/dequeue）都会触发一次 cpufreq 更新
- 即使目标频率与当前频率相同，仍然会向 cpufreq 驱动发送更新请求
- 额外的函数调用和驱动交互增加了调度路径的延迟

### 间接影响
- 使用硬件调频接口（如 CPPC）的系统中，每次更新都涉及寄存器写入或固件通信
- 对实时任务（RT/DL）可能增加调度延迟抖动（jitter）
- 在使用 `CPUFREQ_NEED_UPDATE_LIMITS` 的驱动上，问题更为突出
- 增加了不必要的功耗（频繁的 MMIO 或 mailbox 操作）

### 如何发现此问题
- 通过 ftrace 的 `cpu_frequency` 事件发现频率更新过于频繁
- 或在分析调度延迟时发现 schedutil 路径耗时异常

## 2. 复现手法

### 环境要求
- 任何 x86 或 ARM 系统
- 使用 `schedutil` 调频策略
- 使用声明了 `CPUFREQ_NEED_UPDATE_LIMITS` 的 cpufreq 驱动（如 `acpi-cpufreq`）

### 复现与验证步骤

```bash
# 1. 确认使用 schedutil 策略
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
# 如果不是 schedutil，设置之：
echo schedutil | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 2. 触发一次 policy limits 变更（激活 need_freq_update 标志）
# 例如临时降低最大频率再恢复
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq
echo 2000000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq
# 恢复原值
echo 3600000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq

# 3. 用 ftrace 观察后续的频率更新行为
echo 1 > /sys/kernel/debug/tracing/events/power/cpu_frequency/enable
echo 1 > /sys/kernel/debug/tracing/tracing_on

# 运行一段固定负载
stress-ng --cpu 1 --timeout 5s

# 检查 trace
cat /sys/kernel/debug/tracing/trace | grep cpu_frequency | wc -l
# 修复前：数千次更新（即使频率没变化）
# 修复后：合理数量的更新

# 4. 更精确的验证——追踪 sugov_update_next_freq 调用
echo sugov_update_next_freq > /sys/kernel/debug/tracing/set_ftrace_filter
echo function > /sys/kernel/debug/tracing/current_tracer
```

### 定量对比

```bash
# 修复前后的频率更新次数对比（10 秒内）
echo 0 > /sys/kernel/debug/tracing/trace
echo 1 > /sys/kernel/debug/tracing/events/power/cpu_frequency/enable
sleep 10
echo 0 > /sys/kernel/debug/tracing/events/power/cpu_frequency/enable

# 统计更新次数
cat /sys/kernel/debug/tracing/trace | grep -c cpu_frequency

# 预期：修复后此数值显著下降（可能减少 50% 以上）
```

## 3. 分析思路

### 第一步：理解 schedutil 的频率更新逻辑

`schedutil` 的核心决策流程：

```
调度器事件（tick/enqueue/dequeue）
    │
    ▼
sugov_should_update_freq()
    │ 检查是否需要更新频率
    │ 考虑速率限制（rate_limit）
    │ 考虑 limits_changed 标志
    │
    ▼
sugov_get_util()
    │ 获取 CPU 利用率
    │
    ▼
sugov_next_freq()
    │ 计算目标频率
    │
    ▼
sugov_update_next_freq()
    │ 检查是否需要真正发送更新
    │ 比较 next_freq 和当前频率
    │ 检查 need_freq_update 标志
    │
    ▼
cpufreq_driver_fast_switch() 或 sugov_work()
    │ 实际执行频率切换
    ▼
```

### 第二步：追踪 `need_freq_update` 标志的生命周期

问题核心在于 `need_freq_update` 标志的**设置和清除不匹配**：

```
旧代码中的标志流转：

[limits_changed 事件]
    │
    ▼
sugov_should_update_freq():
    if (sg_policy->limits_changed) {
        limits_changed = false;
        need_freq_update = true;    ← 无条件设为 true
        return true;
    }
    │
    ▼
sugov_update_next_freq():
    if (need_freq_update)
        need_freq_update = cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS);
        // ↑ 如果驱动有 NEED_UPDATE_LIMITS 标志，这永远返回 true！
        // ↑ need_freq_update 永远不会被清为 false！
    else if (next_freq == sg_policy->next_freq)
        return false;  // 频率相同就跳过

// 结果：对于 CPUFREQ_NEED_UPDATE_LIMITS 驱动，
// need_freq_update 一旦被设为 true，就永远保持 true
// 每次调度器回调都会强制执行频率更新
```

### 第三步：分析两个冗余更新路径

**路径 A：CPUFREQ_NEED_UPDATE_LIMITS 驱动的永久强制更新**

```c
// sugov_update_next_freq 中：
if (need_freq_update)
    need_freq_update = cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS);
    // 对于 acpi-cpufreq 等驱动，这永远返回 true
    // 所以 need_freq_update 永远保持 true
    // 后续的 "next_freq == sg_policy->next_freq" 检查被跳过
    // → 即使频率不变也强制更新
```

**路径 B：DL（Deadline）任务的额外冗余**

```c
// ignore_dl_rate_limit() 也检查 need_freq_update：
static bool ignore_dl_rate_limit(struct sugov_cpu *sg_cpu)
{
    if (sg_cpu->flags & SCHED_CPUFREQ_DL)
        return sg_policy->need_freq_update;
        // 如果 need_freq_update 永远为 true，
        // DL 任务会绕过速率限制，导致更频繁的更新
}
```

### 第四步：理解修复的正确性

修复重新组织了标志设置的位置和语义：

```
修复后的标志流转：

[limits_changed 事件]
    │
    ▼
sugov_should_update_freq():
    if (sg_policy->limits_changed) {
        limits_changed = false;
        need_freq_update = cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS);
        // ↑ 只在驱动需要时才设置，而非无条件设置
        return true;
    }
    │
    ▼
sugov_update_next_freq():
    if (need_freq_update)
        need_freq_update = false;    ← 使用后立即清除！
        // 强制执行一次更新，然后恢复正常的频率比较逻辑
    else if (next_freq == sg_policy->next_freq)
        return false;
```

## 4. 分析工具

### ftrace — cpu_frequency 事件（首选工具）
```bash
# 追踪频率变更事件
echo 1 > /sys/kernel/debug/tracing/events/power/cpu_frequency/enable

# 追踪 schedutil 内部决策
echo 1 > /sys/kernel/debug/tracing/events/power/pstate_sample/enable

# 查看事件
cat /sys/kernel/debug/tracing/trace_pipe
```

### ftrace — 函数跟踪
```bash
# 追踪 schedutil 关键函数的调用频率
echo 'sugov_update_next_freq sugov_should_update_freq' > \
    /sys/kernel/debug/tracing/set_ftrace_filter
echo function > /sys/kernel/debug/tracing/current_tracer

# 计数模式（不记录调用栈，只计数）
echo 0 > /sys/kernel/debug/tracing/function_profile_enabled
echo 1 > /sys/kernel/debug/tracing/function_profile_enabled
sleep 10
cat /sys/kernel/debug/tracing/trace_stat/function*
```

### perf — 性能分析
```bash
# 统计 cpufreq 相关函数的调用频率
perf stat -e 'power:cpu_frequency' -a sleep 10

# 或录制详细 trace
perf record -e 'power:cpu_frequency' -a sleep 10
perf report
```

### trace-cmd（更友好的 ftrace 前端）
```bash
# 录制 schedutil 相关事件
trace-cmd record -e power:cpu_frequency -e power:pstate_sample sleep 10
trace-cmd report | head -100

# 统计每秒的频率更新次数
trace-cmd report | grep cpu_frequency | awk '{print $1}' | cut -d. -f1 | sort | uniq -c
```

### BPF/bpftrace
```bash
# 统计 sugov_update_next_freq 的返回值分布
bpftrace -e 'kretprobe:sugov_update_next_freq {
    @ret[retval] = count();
}'
# retval=0 表示跳过更新，retval=1 表示执行更新
# 修复前：大量 retval=1（不必要的更新）
# 修复后：更多 retval=0（正确跳过）
```

## 5. 解决思路

### 最终修复（两处变更）

**变更 1**：`sugov_should_update_freq()`——只在驱动需要时才设置标志

```c
// 修复前：
if (unlikely(sg_policy->limits_changed)) {
    sg_policy->limits_changed = false;
    sg_policy->need_freq_update = true;  // 无条件设置
    return true;
}

// 修复后：
if (unlikely(sg_policy->limits_changed)) {
    sg_policy->limits_changed = false;
    sg_policy->need_freq_update =
        cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS);  // 条件设置
    return true;
}
```

**变更 2**：`sugov_update_next_freq()`——使用后立即清除标志

```c
// 修复前：
if (sg_policy->need_freq_update)
    sg_policy->need_freq_update =
        cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS);  // 可能永远为 true
else if (sg_policy->next_freq == next_freq)
    return false;

// 修复后：
if (sg_policy->need_freq_update)
    sg_policy->need_freq_update = false;  // 用完即清
else if (sg_policy->next_freq == next_freq)
    return false;
```

### 修复的逻辑完整性验证

| 场景 | 修复前行为 | 修复后行为 |
|------|-----------|-----------|
| limits 变化 + NEED_UPDATE 驱动 | 永远强制更新 | 强制更新一次，然后恢复正常 |
| limits 变化 + 普通驱动 | 强制更新一次 | 强制更新一次（不变） |
| 无 limits 变化 | 比较频率决定 | 比较频率决定（不变） |
| DL 任务 + limits 曾变化 | 永远绕过速率限制 | 只在 limits 实际变化后绕过一次 |

### 为什么不直接移除 CPUFREQ_NEED_UPDATE_LIMITS？

`CPUFREQ_NEED_UPDATE_LIMITS` 标志有其存在的意义：某些 cpufreq 驱动在硬件层面
缓存了频率限制，即使软件侧的目标频率不变，也需要在 limits 变化时重新写入硬件寄存器。
问题不是这个标志本身，而是它被错误地用来**永久**阻止频率去重。

## 6. 相关背景知识

### schedutil 调频策略原理

`schedutil` 是 Linux 内核中最现代的 cpufreq 调频策略，直接利用调度器的
CPU 利用率信息做出调频决策：

```
┌─────────────────────────────────────────────────────────┐
│                   Scheduler                              │
│   CFS util    RT util    DL util    IRQ util             │
│      │          │          │          │                   │
│      └──────────┴──────────┴──────────┘                  │
│                      │                                    │
│               sugov_update_single()                       │
│               sugov_update_shared()                       │
│                      │                                    │
│              target_freq = util × max_freq / max_util     │
│                      │                                    │
│              sugov_update_next_freq()                      │
│                      │                                    │
│              cpufreq_driver_fast_switch()                  │
│              或 irq_work → sugov_work()                    │
└─────────────────────────────────────────────────────────┘
```

### CPUFREQ_NEED_UPDATE_LIMITS 标志

声明了此标志的驱动表示：当 policy limits 变化时，即使新的目标频率和当前频率相同，
也需要重新调用驱动的 `target()` 或 `fast_switch()` 函数。

典型场景：
```
limits 从 [1GHz, 3GHz] 变为 [1GHz, 2GHz]
当前频率 = 1.5GHz
新目标频率 = 1.5GHz（基于利用率计算，恰好相同）

普通驱动：频率不变，跳过更新 ← OK
NEED_UPDATE_LIMITS 驱动：仍需更新，因为硬件需要知道新的 max limit ← 必要的
```

### 状态标志的生命周期管理原则

状态标志（flag）是内核中最常见的 bug 来源之一。正确管理需要遵循：

```
规则 1：设置和清除必须成对
  ✗ flag = true;  // 设置后从不清除 → 变成永久标志
  ✓ flag = true;  ... flag = false;  // 使用后清除

规则 2：原子性
  ✗ if (flag) { use(); flag = false; }  // 多 CPU 可能同时进入
  ✓ if (xchg(&flag, false)) { use(); }  // 原子地读取并清除

规则 3：语义清晰
  ✗ need_update 同时用于 "limits 变了" 和 "驱动需要通知" 两种语义
  ✓ 分开使用不同标志表示不同语义

本 bug 的修复遵循了规则 1——确保 need_freq_update 在执行一次强制更新后
被清为 false。
```

### 调频对功耗的量化影响

频率更新本身也有功耗代价：

```
频率更新操作的典型开销：
  MSR 写入（intel_pstate）：        ~1μs
  MMIO 寄存器写入（cpufreq-dt）：   ~5-10μs
  CPPC Mailbox（ACPI CPPC）：       ~50-100μs
  固件 IPC（如 SCMI/SCPI）：        ~100-500μs

如果每秒产生 1000 次不必要的更新（修复前的典型值），
使用 CPPC 驱动时：1000 × 100μs = 100ms 的额外 CPU 时间/秒
这相当于约 10% 的 CPU 开销——极其显著！
```

### 速率限制（Rate Limiting）机制

schedutil 使用速率限制来避免过于频繁的调频：

```c
// 默认速率限制 = 2 × 调频延迟（transition_delay_us）
// 如果上次更新到现在的时间 < rate_limit，跳过本次更新

// 但 need_freq_update=true 会绕过此限制
// 这也是为什么标志不清除的影响很大——它实质上禁用了速率限制
```

### 如何用 trace 验证修复效果

```bash
# 完整的验证流程：

# 1. 修复前基准测试
echo schedutil | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
trace-cmd record -e power:cpu_frequency -e sched:sched_switch sleep 30 -o before.dat

# 2. 应用修复补丁

# 3. 修复后基准测试
trace-cmd record -e power:cpu_frequency -e sched:sched_switch sleep 30 -o after.dat

# 4. 对比分析
echo "=== 修复前 ==="
trace-cmd report -i before.dat | grep -c cpu_frequency
echo "=== 修复后 ==="
trace-cmd report -i after.dat | grep -c cpu_frequency

# 预期：修复后的更新次数显著少于修复前
```
