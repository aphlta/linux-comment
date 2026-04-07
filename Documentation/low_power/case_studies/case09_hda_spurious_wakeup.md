# 案例九：Intel HDA 声卡 S3 幽灵唤醒（Heisenbug）

| 项目 | 信息 |
|------|------|
| Commit | `a6630529aecb5a3e84370c376ed658e892e6261e` |
| 作者 | Takashi Iwai (SUSE) |
| 日期 | 2020-07-27 |
| 影响版本 | v5.7+（含 `c4c8dd6ef807` 后） |
| 修复引入的 Bug | `c4c8dd6ef807` ("ALSA: hda: Skip controller resume if not needed") |
| 子系统 | ALSA / HDA / Runtime PM / System Sleep |
| 严重性 | 中-高 — 系统无法进入 S3 睡眠 |
| Bugzilla | [https://bugzilla.kernel.org/show_bug.cgi?id=208649](https://bugzilla.kernel.org/show_bug.cgi?id=208649) |

## 1. 故障现象

在旧型号 Intel 平台（Haswell/Broadwell PCH 等）的笔记本上：

```bash
echo mem > /sys/power/state
# 屏幕短暂关闭后，系统立即唤醒
# 合上笔记本盖子同样无法保持睡眠
```

具体表现：
- 系统成功执行了 suspend 流程的大部分步骤
- **在进入 S3 的最后阶段**，系统立即被唤醒
- `dmesg` 中没有明确的唤醒原因
- 唤醒不是因为键盘、鼠标或定时器——是幽灵唤醒（spurious wakeup）
- 重复尝试 suspend 每次都会立即唤醒
- **回退到旧内核（v5.6）后问题消失**

这是一个典型的 **Heisenbug**（海森堡 bug）：
- 用等价的代码替换后行为不同
- 看似相同的操作因为细微的时序差异导致完全不同的结果
- 根因极难定位——"by some really mysterious reason"（原 commit 作者语）

## 2. 复现手法

### 环境要求
- Intel 平台，使用 Haswell/Broadwell 系列 PCH 的 HD Audio 控制器
- 内核版本 v5.7+（含有 `c4c8dd6ef807` 补丁）
- S3 suspend 已启用

### 复现步骤

```bash
# 1. 确认使用的音频控制器是受影响的 Intel PCH
lspci | grep -i audio
# 例如：Intel Corporation 8 Series/C220 Series HD Audio Controller

# 2. 确认睡眠模式
cat /sys/power/mem_sleep
# 确保 [deep] 可用（S3）

# 3. 尝试 suspend
echo deep > /sys/power/mem_sleep
echo mem > /sys/power/state
# 系统应该立即唤醒（bug 复现）

# 4. 验证唤醒原因
cat /sys/power/pm_wakeup_irq
# 可能显示 HDA 控制器的 IRQ

dmesg | grep -i "wakeup\|suspend\|resume" | tail -20
```

### 缩小范围

```bash
# 禁用 HDA runtime PM 后测试：
echo on > /sys/bus/pci/devices/0000:00:1b.0/power/control
echo mem > /sys/power/state
# 如果禁用后正常 → 确认是 HDA runtime PM 引起

# 或完全卸载声卡驱动：
modprobe -r snd_hda_intel
echo mem > /sys/power/state
# 如果卸载后正常 → 确认是 HDA 驱动问题
```

## 3. 分析思路

### 第一步：通过 bisect 定位引入 bug 的 commit

```bash
git bisect start
git bisect bad v5.7    # 有 bug
git bisect good v5.6   # 无 bug
# ... 多次测试 ...
# → 定位到 c4c8dd6ef807 ("ALSA: hda: Skip controller resume if not needed")
```

### 第二步：分析引入 bug 的 commit 做了什么

Commit `c4c8dd6ef807` 将 HDA 声卡的 system suspend 实现从**直接调用内部函数**
改为使用 **PM 框架的标准 API**：

```c
// 旧代码（v5.6，工作正常）：
static int azx_suspend(struct device *dev)
{
    ...
    __azx_runtime_suspend(chip);   // 直接调用内部 suspend 函数
    ...
}

static int azx_resume(struct device *dev)
{
    ...
    __azx_runtime_resume(chip, false);  // 直接调用内部 resume 函数
    ...
}

// 新代码（v5.7，引入 bug）：
static int azx_suspend(struct device *dev)
{
    ...
    pm_runtime_force_suspend(dev);   // 使用 PM 框架标准 API
    ...
}

static int azx_resume(struct device *dev)
{
    ...
    pm_runtime_force_resume(dev);    // 使用 PM 框架标准 API
    ...
}
```

从逻辑上看，`pm_runtime_force_suspend()` 内部最终也会调用
`__azx_runtime_suspend()`，两者应该是等价的。**但实际行为不同。**

### 第三步：为什么"等价"的代码会有不同行为

这是此 bug 最"神秘"的地方。`pm_runtime_force_suspend()` 和直接调用
`__azx_runtime_suspend()` 的差异在于 **PM 框架的额外操作**：

```c
// pm_runtime_force_suspend() 的内部实现：
int pm_runtime_force_suspend(struct device *dev)
{
    // 1. 调用 runtime_suspend 回调
    //    → __azx_runtime_suspend()  ← 和直接调用相同
    callback = rpm_get_suspend_cb(dev);
    ret = callback(dev);

    // 2. ★ 额外操作：修改 PM runtime 状态 ★
    pm_runtime_set_suspended(dev);

    // 3. ★ 额外操作：修改 PCI 设备的电源状态 ★
    //    可能触发 PCI PME（Power Management Event）
    //    → 这可能是幽灵唤醒的来源！

    return 0;
}
```

最可能的根因推测（commit 作者也未完全确认）：
- `pm_runtime_force_suspend()` 修改了 PCI 设备的 PM 状态标记
- 在某些旧 Intel PCH 上，这个状态变化可能触发硬件级的 PME（Power Management Event）
- PME 被配置为唤醒源 → 系统立即被唤醒

### 第四步：为什么只有旧 Intel PCH 受影响

```
受影响的平台：Haswell/Broadwell 系列 PCH
不受影响的平台：Skylake+ PCH

旧 PCH 的 HDA 控制器在 PM 状态转换时可能有硬件 quirk：
- 软件修改 PM 寄存器 → 硬件产生 PME 信号
- 这个 PME 在正常 runtime PM 流程中被过滤
- 但在 system suspend 的最后阶段，PME 被当作唤醒源
```

## 4. 分析工具

### pm_wakeup_irq（唤醒源追踪）
```bash
# suspend 后立即唤醒时检查唤醒中断
cat /sys/power/pm_wakeup_irq

# 查看所有唤醒源的状态
cat /sys/kernel/debug/wakeup_sources
# 关注 HDA 相关条目的 active_count
```

### pm_debug_messages
```bash
echo 1 > /sys/power/pm_debug_messages
echo mem > /sys/power/state
# 唤醒后检查 dmesg，会显示详细的 suspend/resume 时序
dmesg | grep -E "PM:|suspend|resume|wakeup"
```

### pm-graph / sleepgraph
```bash
# 录制完整的 suspend/resume 过程
sleepgraph -m mem -rtcwake 30

# HTML 报告会清晰显示：
# - 在哪个阶段系统被唤醒
# - 哪个设备的 resume 最先执行（暗示是唤醒源）
```

### git bisect
```bash
# 此 bug 的发现就是通过 bisect
git bisect start
git bisect bad HEAD        # 当前版本有问题
git bisect good v5.6       # 这个版本没问题

# 每次 bisect 迭代：
make -j$(nproc) && make modules_install && make install
reboot
echo mem > /sys/power/state
# 如果立即唤醒 → git bisect bad
# 如果正常睡眠 → git bisect good
```

### PCI PM 调试
```bash
# 查看 HDA 控制器的 PCI PM 状态
lspci -vv -s 00:1b.0 | grep -A 5 "Power Management"

# 监控 PME 事件
echo 1 > /sys/kernel/debug/tracing/events/power/pm_qos_update/enable
```

## 5. 解决思路

### 修复策略：对旧 Intel 平台使用 workaround

由于根因可能是**硬件行为差异**，且无法修改硬件，采用 workaround 策略——
对受影响的旧 Intel PCH 恢复直接调用内部 suspend/resume 函数：

```c
// 新增一个 capability flag 标识受影响的平台
#define AZX_DCAPS_SUSPEND_SPURIOUS_WAKEUP  (1 << ...)

// 旧 Intel PCH 的定义中加入此 flag
#define AZX_DCAPS_INTEL_PCH \
    (AZX_DCAPS_INTEL_PCH_BASE | AZX_DCAPS_PM_RUNTIME | \
     AZX_DCAPS_SUSPEND_SPURIOUS_WAKEUP)  // ★ 新增 ★

// suspend 路径：根据 flag 选择不同策略
static int azx_suspend(struct device *dev)
{
    ...
    if (chip->driver_caps & AZX_DCAPS_SUSPEND_SPURIOUS_WAKEUP)
        __azx_runtime_suspend(chip);      // 旧平台：直接调用
    else
        pm_runtime_force_suspend(dev);    // 新平台：使用 PM 框架
    ...
}

// resume 路径：同样根据 flag
static int azx_resume(struct device *dev)
{
    ...
    if (chip->driver_caps & AZX_DCAPS_SUSPEND_SPURIOUS_WAKEUP)
        __azx_runtime_resume(chip, false);  // 旧平台
    else
        pm_runtime_force_resume(dev);       // 新平台
    ...
}
```

### 为什么不直接全部回退

```
方案 A（全部回退）：
  所有平台都用直接调用 → 简单但放弃了 PM 框架的好处
  PM 框架好处：统一的状态管理、用户空间接口、调试支持

方案 B（本修复采用，条件回退）：
  只对有问题的旧平台回退
  新平台继续使用标准 PM 框架 API
  通过 driver_caps flag 区分 → 最佳平衡
```

### 此修复的自我评价

commit 作者 Takashi Iwai 在 commit message 中坦率地说：

> "As an **ugly workaround** for now..."
> （暂时的丑陋 workaround...）

这反映了这类 Heisenbug 的现实：有时候无法完全理解根因（可能是硬件 quirk），
只能通过 workaround 规避。这在内核开发中是被接受的做法——
前提是 workaround 有清晰的标注和范围限制。

## 6. 相关背景知识

### Heisenbug 的特征与应对

Heisenbug（以量子力学的海森堡不确定性原理命名）指的是在尝试观察或修改时会改变
行为的 bug。本案例是典型的 Heisenbug：

```
特征：
1. 用"等价"的代码替换后行为改变
2. 添加调试代码可能使 bug 消失（因为改变了时序）
3. 根因可能在硬件层面，软件无法完全解释
4. 只在特定硬件上出现

应对策略：
1. 尊重现实 — 如果 workaround 有效且影响可控，接受它
2. 记录清楚 — flag 命名要体现"这是 workaround"
3. 限制范围 — 只对受影响的硬件应用
4. 留下线索 — Bugzilla 链接、硬件型号等信息
```

### Intel HD Audio 与 PM 的关系

```
┌────────────────────────────────────────────┐
│        Intel HD Audio Controller            │
│                                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Codec 0  │  │ Codec 1  │  │ Codec 2  │ │
│  │(Speaker) │  │ (HDMI)   │  │(Headset) │ │
│  └──────────┘  └──────────┘  └──────────┘ │
│                                            │
│  Runtime PM：                              │
│  - 无音频播放时自动 suspend → 省电         │
│  - 检测到音频流时自动 resume               │
│                                            │
│  System Sleep：                            │
│  - 需要保存/恢复所有 codec 状态            │
│  - 需要正确管理 PCI PM 状态                │
│  - ★ 旧 PCH 在 PM 状态转换时有 quirk ★    │
└────────────────────────────────────────────┘
```

### pm_runtime_force_suspend() vs 直接调用的差异

```c
// pm_runtime_force_suspend() 的完整流程：
int pm_runtime_force_suspend(struct device *dev)
{
    // 1. 如果设备已经 suspended，直接返回
    if (pm_runtime_status_suspended(dev))
        return 0;

    // 2. 调用 runtime_suspend 回调
    callback(dev);

    // 3. 设置 PM runtime 状态为 suspended
    pm_runtime_set_suspended(dev);

    // 4. 对 PCI 设备：可能修改 PCI PM 寄存器
    //    → 这里可能触发 PME
    //    → 在旧 Intel PCH 上导致幽灵唤醒
}

// 直接调用的流程：
__azx_runtime_suspend(chip);
// 只执行步骤 2
// 不修改 PM runtime 状态
// 不触碰 PCI PM 寄存器
// → 没有幽灵唤醒
```

### PCI PME（Power Management Event）

```
PCI 电源管理定义了设备可以通过 PME 信号唤醒系统：

  设备 D3 状态 → 外部事件 → 设备发送 PME# → 系统唤醒

在 system suspend 过程中：
1. 所有设备被挂起到 D3
2. 配置了唤醒能力的设备可以发送 PME
3. PCH 收到 PME 后触发系统唤醒

如果 pm_runtime_force_suspend() 导致 HDA 控制器
发送了一个不期望的 PME → 系统立即被唤醒

这在旧 PCH 上可能是硬件 bug 或未文档化的行为
```

### 内核中的硬件 Quirk 管理模式

```c
// 内核中处理硬件 quirk 的标准模式：

// 1. 定义 capability flag
#define DRIVER_CAPS_QUIRK_FOO  (1 << N)

// 2. 在设备描述表中标记受影响的设备
static const struct pci_device_id my_ids[] = {
    { PCI_DEVICE(...), .driver_data = DRIVER_CAPS_QUIRK_FOO },
    ...
};

// 3. 在代码中条件执行
if (chip->caps & DRIVER_CAPS_QUIRK_FOO) {
    /* workaround 路径 */
} else {
    /* 标准路径 */
}

// 这个模式的优点：
// - 影响范围精确可控
// - 新硬件默认走标准路径
// - Quirk 可以通过内核参数覆盖（调试用）
```

### suspend 幽灵唤醒的调试检查清单

```bash
# 当系统无法进入 suspend（立即唤醒）时的排查步骤：

# 1. 检查唤醒源
cat /sys/power/pm_wakeup_irq
cat /sys/kernel/debug/wakeup_sources

# 2. 禁用所有非必要的唤醒源
for dev in /sys/bus/*/devices/*/power/wakeup; do
    echo disabled > $dev 2>/dev/null
done
echo mem > /sys/power/state
# 如果成功 → 逐个重新启用，找出是哪个设备

# 3. 检查 PCI PME 配置
lspci -vv | grep -A2 "PME"

# 4. 尝试禁用特定设备的 PM
echo on > /sys/bus/pci/devices/<device>/power/control
echo mem > /sys/power/state

# 5. 使用 pm_test 分阶段测试
for phase in freezer devices platform processors core; do
    echo $phase > /sys/power/pm_test
    echo mem > /sys/power/state
    echo "Phase $phase: $(dmesg | tail -1)"
done
# 找到第一个导致立即唤醒的阶段
```
