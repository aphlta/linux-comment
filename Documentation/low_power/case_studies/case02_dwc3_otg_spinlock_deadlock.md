# 案例二：USB DWC3 OTG 模式 Suspend 自旋锁死锁

| 项目 | 信息 |
|------|------|
| Commit | `7838de15bb700c2898a7d741db9b1f3cbc86c136` |
| 作者 | Meng Li (Wind River) |
| 影响版本 | v6.1+ (含 DWC3 锁重构后) |
| 修复引入的 Bug | `5265397f9442` ("usb: dwc3: Remove DWC3 locking during gadget suspend/resume") |
| 暴露 Bug 的 Commit | `c7ebd8149ee5` ("usb: dwc3: gadget: Fix NULL pointer dereference in dwc3_gadget_suspend") |
| 子系统 | USB / DWC3 / System Sleep |
| 严重性 | 高 — 系统 suspend 必现死锁 |

## 1. 故障现象

在配置了 `CONFIG_USB_DWC3_DUAL_ROLE`（USB OTG 双角色模式）的系统上，执行系统挂起时
**必现挂死**：

```bash
echo mem > /sys/power/state
# 系统立即无响应，不会进入 suspend，也不会返回
```

具体表现：
- 系统在 suspend 流程的设备挂起阶段停住
- 控制台无任何输出（中断已被禁止）
- 只有 DWC3 控制器处于 OTG device 角色时才会触发
- Host 角色或纯 device 模式（非 OTG）不受影响

## 2. 复现手法

### 环境要求
- SoC 平台使用 DesignWare USB3 控制器（常见于 NXP i.MX、Qualcomm、Intel 等）
- 内核配置 `CONFIG_USB_DWC3_DUAL_ROLE=y`
- DWC3 控制器当前处于 OTG device 角色

### 复现步骤

```bash
# 1. 确认 DWC3 配置为双角色模式
cat /sys/bus/platform/devices/<dwc3-device>/mode
# 应显示 "otg"

# 2. 确保当前 OTG 角色是 device（例如未接入 USB Host 线缆）
cat /sys/class/usb_role/<dwc3-device>-role-switch/role
# 应显示 "device"

# 3. 触发系统 suspend
echo mem > /sys/power/state
# → 系统挂死
```

### 条件分析

这个 bug 的触发需要同时满足：
1. `CONFIG_USB_DWC3_DUAL_ROLE=y`（编译时选择 OTG 支持）
2. DWC3 正在 OTG 模式运行
3. 当前 OTG 角色为 device（`DWC3_OTG_ROLE_DEVICE`）
4. 执行系统 suspend（`echo mem > /sys/power/state`）

满足以上条件即 **100% 复现**。

## 3. 分析思路

### 第一步：识别死锁类型

系统挂死在 suspend 路径，首先怀疑是锁相关问题。通过启用 `lockdep` 可以看到
**spinlock 重入**（同一个 spinlock 在同一 CPU 上被获取两次）的告警：

```
BUG: spinlock recursion on CPU#0 ...
 lock: 0x... (dwc->lock)
```

### 第二步：重建调用链

DWC3 的 suspend 路径有三种模式入口（通过 `switch(dwc->current_dr_role)` 分发）：

```
dwc3_suspend_common(dwc, msg)
├── case DWC3_GCTL_PRTCAP_DEVICE:     // 纯 device 模式
│   └── dwc3_gadget_suspend(dwc)      // 无外层锁，OK
├── case DWC3_GCTL_PRTCAP_HOST:       // 纯 host 模式
│   └── (无 gadget 操作)              // OK
└── case DWC3_GCTL_PRTCAP_OTG:        // OTG 模式 ← 问题路径！
    └── if (role == DEVICE):
        ├── spin_lock_irqsave(&dwc->lock)    ← 第一次获取锁
        ├── dwc3_gadget_suspend(dwc)
        │   └── dwc3_gadget_soft_disconnect()
        │       └── spin_lock_irqsave(&dwc->lock)  ← 第二次获取 → 死锁！
        └── spin_unlock_irqrestore(&dwc->lock)
```

### 第三步：追溯历史——跨补丁 Bug

这个 bug 是**两个独立补丁交互**产生的：

**Commit A**（`5265397f9442`，2022-09）：
> "usb: dwc3: Remove DWC3 locking during gadget suspend/resume"
>
> 移除了 `dwc3_gadget_suspend/resume` 函数外面的锁，因为 `dwc3_gadget_run_stop()`
> 可能耗时较长，不适合在 spinlock 内执行。

这个补丁正确地移除了纯 device 模式（`DWC3_GCTL_PRTCAP_DEVICE`）路径中的锁，
**但遗漏了 OTG 模式（`DWC3_GCTL_PRTCAP_OTG`）路径中的锁**。

此时 bug 已经存在，但不会触发，因为：

**Commit B**（`c7ebd8149ee5`，早期修复）：
> 之前的代码在 OTG device 路径中有 `if (!dwc->gadget_driver) return;` 检查。
> 在某些场景下 `gadget_driver` 为 NULL，直接跳过了后续有锁的代码。
>
> Commit B 移除了这个 NULL 检查（修复了另一个 NULL 解引用 bug），
> 导致代码继续执行到 `dwc3_gadget_suspend()` → 暴露了锁重入问题。

这是经典的**Bug 叠加效应**：一个潜伏的 bug 被另一个修复暴露。

## 4. 分析工具

### lockdep（最有效的工具）
```bash
# 内核编译配置
CONFIG_LOCKDEP=y
CONFIG_PROVE_LOCKING=y
CONFIG_DEBUG_LOCK_ALLOC=y
CONFIG_DEBUG_SPINLOCK=y

# lockdep 会在 spinlock 重入时立即打印告警：
# BUG: spinlock recursion on CPU#0
# lock: dwc->lock
# 并输出完整的两次获取锁的调用栈
```

### CONFIG_DEBUG_SPINLOCK
```bash
CONFIG_DEBUG_SPINLOCK=y
# 在 spinlock 重入时触发 BUG()，可以在死锁前捕获问题
```

### ftrace + function_graph
```bash
# 跟踪 suspend 路径的完整调用图
echo 'dwc3_suspend_common' > /sys/kernel/debug/tracing/set_graph_function
echo function_graph > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/tracing_on

echo mem > /sys/power/state
# 如果启用了 DEBUG_SPINLOCK，系统会在死锁前 BUG()
# 此时可以看到完整的调用图
```

### pm_test（分阶段测试 suspend）
```bash
# 只测试 freeze 阶段（不实际挂起硬件）
echo freezer > /sys/power/pm_test
echo mem > /sys/power/state

# 测试到 devices 阶段
echo devices > /sys/power/pm_test
echo mem > /sys/power/state
# → 这一步就会触发死锁
```

### git bisect（定位引入 bug 的 commit）
```bash
git bisect start
git bisect bad <挂死版本>
git bisect good <正常版本>
# 通过二分法定位引入问题的具体 commit
# 对于此 bug，会定位到 c7ebd8149ee5（暴露 bug 的 commit）
```

## 5. 解决思路

### 最终修复

移除 OTG 模式路径中多余的 `spin_lock/unlock`，因为被调用的
`dwc3_gadget_suspend()`/`dwc3_gadget_resume()` 内部已经自行管理锁：

```c
// === dwc3_suspend_common() 修复 ===
// 修复前（有 bug）：
case DWC3_GCTL_PRTCAP_OTG:
    if (dwc->current_otg_role == DWC3_OTG_ROLE_DEVICE) {
        spin_lock_irqsave(&dwc->lock, flags);     // 多余的锁
        dwc3_gadget_suspend(dwc);
        spin_unlock_irqrestore(&dwc->lock, flags); // 多余的解锁
        synchronize_irq(dwc->irq_gadget);
    }

// 修复后：
case DWC3_GCTL_PRTCAP_OTG:
    if (dwc->current_otg_role == DWC3_OTG_ROLE_DEVICE) {
        dwc3_gadget_suspend(dwc);   // 函数内部已有锁保护
        synchronize_irq(dwc->irq_gadget);
    }

// === dwc3_resume_common() 同样修复 ===
// 修复前：
} else if (dwc->current_otg_role == DWC3_OTG_ROLE_DEVICE) {
    spin_lock_irqsave(&dwc->lock, flags);
    dwc3_gadget_resume(dwc);
    spin_unlock_irqrestore(&dwc->lock, flags);
}

// 修复后：
} else if (dwc->current_otg_role == DWC3_OTG_ROLE_DEVICE) {
    dwc3_gadget_resume(dwc);
}
```

### 修复的验证

修复后需要覆盖所有三种模式的 suspend/resume 测试：

```bash
# 测试 OTG device 模式（之前挂死的路径）
echo device > /sys/class/usb_role/.../role
echo mem > /sys/power/state  # 应正常挂起和唤醒

# 测试 OTG host 模式
echo host > /sys/class/usb_role/.../role
echo mem > /sys/power/state  # 应正常

# 测试纯 device 模式（回归验证）
# 需要修改 DT 或 ACPI 配置
```

## 6. 相关背景知识

### 自旋锁（Spinlock）基本规则

Linux 内核的 spinlock 是**不可重入的**：

```c
spin_lock(&lock);
// ... 临界区 ...
spin_lock(&lock);  // 死锁！同一 CPU 永远获取不到
```

这和 mutex 不同（mutex 在同线程重入时也会死锁，但有 debug 检测）。
spinlock 在非 debug 配置下重入会静默死锁，没有任何提示。

### DWC3 的多模式架构

DesignWare USB3 控制器支持三种工作模式：

```
┌─────────────────────────────────────────────┐
│             DWC3 Controller                  │
├─────────────┬──────────────┬────────────────┤
│   Device    │    Host      │     OTG        │
│  (Gadget)   │   (xHCI)     │  (双角色切换)    │
├─────────────┼──────────────┼────────────────┤
│ PRTCAP=     │ PRTCAP=      │ PRTCAP=        │
│ DEVICE      │ HOST         │ OTG            │
└─────────────┴──────────────┴────────────────┘
```

OTG 模式下，控制器可以在 Host 和 Device 角色之间切换。
Suspend/resume 代码需要根据**当前角色**调用不同的挂起函数：
- OTG + Host 角色 → 走 xHCI suspend 路径
- OTG + Device 角色 → 走 gadget suspend 路径

### 锁重构中的常见陷阱

当重构锁的持有策略时（如将锁从调用者移到被调用者），必须检查**所有调用点**：

```
重构前：                           重构后：
caller_A() {                      caller_A() {
    lock();                           func();     // func 内部加锁
    func();                       }
    unlock();
}                                 caller_B() {
                                      lock();     // ← 遗漏！应删除
caller_B() {                          func();     // func 又加了一次锁
    lock();                           unlock();
    func();                       }
    unlock();
}
```

Commit `5265397f9442` 正是犯了这个错误——它在将锁移入
`dwc3_gadget_suspend/resume` 后，只清理了纯 device 模式的调用点，
忽略了 OTG 模式分支中的同一调用点。

### 使用 lockdep 预防此类问题

```bash
# 建议在开发和测试阶段始终启用
CONFIG_LOCKDEP=y
CONFIG_PROVE_LOCKING=y

# lockdep 会跟踪所有锁的获取顺序，检测：
# 1. 自死锁（同一个锁被同一 CPU 获取两次）← 本案例
# 2. AB-BA 死锁（两个锁以不同顺序获取）
# 3. 锁类别不匹配（如在中断上下文获取非 irqsafe 锁）
```

### System Sleep vs Runtime PM 的 Suspend 路径差异

| 特性 | System Sleep (S3) | Runtime PM |
|------|------------------|------------|
| 触发方式 | `echo mem > /sys/power/state` | 自动（idle 超时） |
| 作用范围 | 所有设备 | 单个设备 |
| 中断状态 | 逐步禁止 | 保持启用 |
| 回调函数 | `.suspend()` / `.resume()` | `.runtime_suspend()` / `.runtime_resume()` |
| 锁的上下文 | 可能持有设备锁 | PM core 持有 dev->power.lock |

本 bug 出现在 System Sleep 路径中（`dwc3_suspend_common`），
但根因是锁管理不当，在两种路径中都可能出现类似问题。
