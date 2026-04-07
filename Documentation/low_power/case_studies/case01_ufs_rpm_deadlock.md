# 案例一：UFS 存储控制器 Runtime PM 死锁

| 项目 | 信息 |
|------|------|
| Commit | `cb7e509c4e0197f63717fee54fb41c4990ba8d3a` |
| 作者 | Peter Wang (MediaTek) |
| 影响版本 | v6.11+ (引入 UFS RTC 支持后) |
| 修复引入的 Bug | `6bf999e0eb41` ("scsi: ufs: core: Add UFS RTC support") |
| 子系统 | SCSI / UFS Core / Runtime PM |
| 严重性 | 高 — 系统完全挂死 |

## 1. 故障现象

系统在运行一段时间后**随机挂死（hang）**。无 kernel panic 输出，无 oops，
控制台无任何主动打印。从用户态视角看，所有涉及磁盘 I/O 的操作全部卡住不返回。

### 挂死的精确表现

这是一个**软件级死锁**（workqueue 线程自等待），而非 CPU hardlockup。
这意味着：

- **中断仍然是使能的**——死锁发生在进程上下文（workqueue），不涉及关中断
- **除死锁线程外的其他 CPU 核仍在正常运行**
- 系统并非"完全"无响应，只是**所有依赖 UFS I/O 的路径被阻塞**

由于 UFS 通常承载根文件系统，挂死的传导效应非常广：
- Shell 命令卡住（`ls`、`cat` 等需要读取磁盘元数据）
- 日志写入停滞（`journald` 无法写入 `/var/log`）
- 新进程无法启动（需要从磁盘加载可执行文件）

但以下操作**仍然可用**——这是定位此类死锁的关键手段：

| 操作 | 是否可用 | 原因 |
|------|---------|------|
| **串口 SysRq**（Alt+SysRq+T） | **可用** | 通过键盘/串口中断触发，printk 直接写 UART 寄存器，全程不涉及磁盘 I/O |
| **NMI watchdog** | **可用** | 硬件 NMI 不受软件死锁影响，会报告卡住的 CPU |
| **网络 ping** | 通常可用 | 网络栈在内核中独立运行，不依赖 UFS |
| `echo t > /proc/sysrq-trigger` | **不可用** | 写 `/proc` 需要 shell 进程，而 shell 可能已因等待 I/O 卡住；即使 shell 还活着，`echo` 命令本身需要从磁盘加载 |
| SSH 远程执行 sysrq | **可能不可用** | sshd 生成新进程需要磁盘 I/O（加载 shell 二进制）|
| 查看 `dmesg` 日志文件 | **不可用** | 需要磁盘 I/O |

> **实战要点**：此类 UFS 死锁场景下，**串口控制台**是几乎唯一可靠的调试通道。
> 嵌入式平台开发时务必保留串口接入能力。如果没有串口，可以尝试通过
> `/proc/sys/kernel/sysrq` 预先配置的 NMI + kdump 来离线抓取信息。

### sysrq-t 在串口控制台上的预期输出

如果通过串口成功触发 `SysRq-t`，可以看到被卡住的 workqueue 线程的调用栈：

```
sysrq: Show State
  task                        PC stack   pid father
  ...
  kworker/0:1     D    0   123      2 0x00000000
  Call trace:
   __switch_to+0x...
   __schedule+0x...
   schedule+0x...
   schedule_timeout+0x...
   wait_for_completion+0x...          ← cancel_delayed_work_sync 在等待
   __cancel_work_timer+0x...
   ufshcd_wl_runtime_suspend+0x...    ← runtime suspend 回调
   rpm_suspend+0x...
   __pm_runtime_suspend+0x...
   ufshcd_rpm_put_sync+0x...          ← rtc_work 调用了 put_sync
   ufshcd_update_rtc+0x...
   ufshcd_rtc_work+0x...              ← 这个 work 在等待自己完成
   process_one_work+0x...
   worker_thread+0x...
```

这个调用栈清晰地展示了自死锁的全貌：`ufshcd_rtc_work` → `rpm_put_sync` →
`runtime_suspend` → `cancel_work_sync(rtc_work)` —— work 在等自己结束。

## 2. 复现手法

### 环境要求
- 使用 UFS 存储的嵌入式平台（如 MediaTek、Qualcomm SoC）
- 内核版本 >= 6.11（包含 UFS RTC 功能）
- Runtime PM 已启用（默认开启）

### 复现步骤

```bash
# 1. 确保 UFS runtime PM 已启用
cat /sys/bus/platform/devices/<ufs-device>/power/runtime_status
# 应显示 "active" 或 "suspended"

# 2. 让系统处于轻负载状态，使 UFS 控制器有机会进入 runtime suspend
# 停止大部分 I/O 操作，等待 RTC 定时器触发

# 3. 关键条件：ufshcd_rtc_work 被调度执行时，UFS 控制器的
#    pm usage_count 恰好为 0（即无其他使用者）
#    此时 ufshcd_rpm_put_sync() 会同步触发 runtime suspend

# 4. 观察系统是否挂死
# 可以通过 ftrace 监控 workqueue 事件来增加触发概率：
echo 1 > /sys/kernel/debug/tracing/events/workqueue/enable
```

### 提高复现概率的技巧
- 减少 RTC 更新周期（修改 `rtc_update_period`）使定时器更频繁触发
- 在 UFS idle 时构造恰好只有 RTC work 持有引用计数的场景
- 使用 `pm_runtime_autosuspend_delay` 设置较短的自动挂起延迟

## 3. 分析思路

### 第一步：确认挂死类型
系统挂死分为多种类型，首先需要区分：
- **硬锁死（hardlockup）**：CPU 卡在中断禁止的循环中
- **软锁死（softlockup）**：CPU 长时间不调度
- **死锁（deadlock）**：多个执行流互相等待

本案例属于典型的死锁——两个执行上下文形成循环等待。

### 第二步：理解调用链

**执行流 A — ufshcd_rtc_work（workqueue 上下文）**：

```
ufshcd_rtc_work()
  → ufshcd_update_rtc()
    → ufshcd_rpm_put_sync(hba)       // usage_count 变为 0
      → pm_runtime_put_sync()
        → rpm_suspend()              // 同步等待 suspend 回调完成
          → ufshcd_runtime_suspend()
            → cancel_delayed_work_sync(&hba->ufs_rtc_update_work)  // 等执行流A完成！
              ← 永远等不到，因为执行流A在等自己完成
```

**执行流 B — runtime suspend 回调（同一个上下文！）**：

关键洞察：`rpm_put_sync` 是**同步**的，意味着 suspend 回调在**同一个线程上下文**中执行。
所以实际上只有一个线程，它在等待自己完成，这是一个**自死锁**。

### 第三步：定位根因

根因是 `ufshcd_rpm_put_sync()` 的 "sync" 语义：
- `sync` = 在当前上下文中同步执行 suspend 回调
- suspend 回调中的 `cancel_delayed_work_sync()` 会等待正在执行的 work 完成
- 但当前上下文正是那个 work —— 形成循环

## 4. 分析工具

### lockdep（锁依赖检测器）
```bash
# 内核编译配置
CONFIG_LOCKDEP=y
CONFIG_PROVE_LOCKING=y
CONFIG_DEBUG_LOCK_ALLOC=y

# lockdep 会在检测到潜在死锁时打印警告
# 但此 bug 涉及的是 workqueue flush，lockdep 对此支持有限
```

### sysrq-t（任务状态转储）
```bash
# ★ 此死锁场景下，sysrq 只能通过串口或硬件按键触发 ★
# 因为磁盘 I/O 已被阻塞，echo 写 /proc 大概率不可用

# 方法 1（推荐）：通过串口发送 SysRq
# 在串口终端中按 Break 键，然后按 't'
# 或者如果串口连接了 minicom：Ctrl+A, F, t

# 方法 2：通过 /proc 触发（仅在 shell 未卡死时可用）
echo t > /proc/sysrq-trigger

# 方法 3：预先配置 NMI 触发 sysrq（需提前设置）
echo 1 > /proc/sys/kernel/unknown_nmi_panic  # x86
# 或使用平台特定的 NMI 按钮/调试器

# 输出通过 printk 发送到内核日志缓冲区
# 只有串口控制台或 netconsole 能在 UFS 死锁时看到输出
# dmesg 文件和 journald 都不可用（需要磁盘 I/O）
```

### netconsole（网络控制台 — 无串口时的替代方案）
```bash
# 如果没有串口，可以提前配置 netconsole 将内核日志发送到远程机器
# 在目标机器启动参数中添加：
# netconsole=@<src-ip>/eth0,@<dst-ip>/<dst-mac>

# 或动态加载：
modprobe netconsole netconsole=@192.168.1.10/eth0,6666@192.168.1.20/aa:bb:cc:dd:ee:ff

# 在远程机器上监听：
nc -u -l 6666

# netconsole 通过网络中断发送数据，不依赖磁盘 I/O
# 是 UFS 死锁场景下串口之外的最佳选择
```

### ftrace（函数跟踪）
```bash
# 跟踪 runtime PM 事件
echo 1 > /sys/kernel/debug/tracing/events/rpm/enable

# 跟踪 workqueue 事件
echo 1 > /sys/kernel/debug/tracing/events/workqueue/enable

# 设置函数跟踪过滤
echo 'ufshcd_rtc_work ufshcd_update_rtc ufshcd_runtime_suspend' > \
    /sys/kernel/debug/tracing/set_ftrace_filter
echo function > /sys/kernel/debug/tracing/current_tracer

# 读取 trace
cat /sys/kernel/debug/tracing/trace
```

### pm_debug_messages（PM 调试消息）
```bash
# 启用详细的 PM 调试输出
echo 1 > /sys/power/pm_debug_messages

# 或启动参数添加
# pm_debug_messages
```

## 5. 解决思路

### 最终修复（一行代码）

将 `ufshcd_rpm_put_sync()` 替换为 `ufshcd_rpm_put()`：

```c
// 修复前（有 bug）：
ufshcd_rpm_put_sync(hba);

// 修复后：
ufshcd_rpm_put(hba);
```

**为什么这样修复？**

| 函数 | 行为 | 是否触发死锁 |
|------|------|-------------|
| `ufshcd_rpm_put_sync()` | 同步：如果 count=0，在**当前上下文**执行 suspend | 是 |
| `ufshcd_rpm_put()` | 异步：如果 count=0，将 suspend **排队到 PM workqueue** | 否 |

异步版本将 suspend 操作推迟到 PM workqueue 执行，此时 rtc_work 已经返回，
`cancel_delayed_work_sync()` 不会阻塞。

### 设计层面的教训

更好的设计应该从根本上避免 suspend 回调 flush 自己触发的 work：

```c
// 方案 A：suspend 回调中使用 cancel_delayed_work() 而非 _sync 版本
// 风险：work 可能在 suspend 完成后仍在运行

// 方案 B（本修复采用）：work 中不使用同步的 rpm_put
// 这是最小改动且安全的方案

// 方案 C：重新设计，让 RTC work 不直接参与 PM 引用计数管理
// 改动较大，但从架构上更清晰
```

## 6. 相关背景知识

### Runtime PM 引用计数模型

Linux Runtime PM 使用引用计数（usage_count）管理设备电源状态：

```
usage_count > 0  →  设备必须保持 active
usage_count == 0 →  设备可以进入 suspended（取决于 autosuspend 设置）
```

关键 API：
- `pm_runtime_get_sync()` / `ufshcd_rpm_get()` — 增加计数，确保设备 active
- `pm_runtime_put_sync()` — 减少计数，**同步**执行可能的 suspend
- `pm_runtime_put()` — 减少计数，**异步**执行可能的 suspend
- `pm_runtime_put_autosuspend()` — 减少计数，经过 autosuspend 延迟后再 suspend

### Workqueue 与 flush 的死锁模式

这是一个已知的常见模式：

```
work_function() {
    do_something();
    call_that_eventually_flushes_this_work();  // 死锁！
}
```

Linux 内核文档 `Documentation/core-api/workqueue.rst` 中有明确警告：
> A work item cannot be flushed from within itself.

### UFS RTC（实时时钟）功能

UFS（Universal Flash Storage）规范从 2.0 版本开始支持 RTC 功能：
- 设备内部维护时间戳，用于追踪 NAND 块的编程年龄
- 主机通过 QUERY 命令周期性更新设备 RTC
- 这个功能对 UFS 设备的垃圾回收和磨损均衡策略很重要
- 内核通过 delayed_work 实现周期性 RTC 更新

### sync vs async 的 PM 操作选择原则

| 场景 | 推荐使用 | 原因 |
|------|----------|------|
| 进程上下文，需要立即 suspend | `_sync` | 确定性最强 |
| 中断上下文 | `_put()`（异步） | 不能睡眠 |
| workqueue 中 | `_put()` 或 `_put_autosuspend()` | 避免自 flush 死锁 |
| probe/remove 函数中 | `_sync` | 需要确定状态 |
