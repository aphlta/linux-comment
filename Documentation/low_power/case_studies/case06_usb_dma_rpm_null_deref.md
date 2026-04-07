# 案例六：USB DMA 控制器 Runtime Suspend 空指针崩溃

| 项目 | 信息 |
|------|------|
| Commit | `36fa4a530b7798aa85789953b08d94c03fb09fa5` |
| 作者 | Geert Uytterhoeven (Renesas) |
| 日期 | 2015-10-25 |
| 影响版本 | v4.3-rc3+（含 USB-DMAC 驱动后） |
| 子系统 | DMA Engine / Runtime PM / ARM SoC |
| 严重性 | 高 — kernel oops，系统崩溃 |

## 1. 故障现象

ARM 嵌入式平台（Renesas R-Car 系列 SoC）在开机启动阶段**随机崩溃**，产生
kernel oops：

```
Unable to handle kernel NULL pointer dereference at virtual address 00000014
Internal error: Oops: 206 [#1] PREEMPT SMP ARM
Hardware name: Generic R8A7791 (Flattened Device Tree)
Workqueue: pm pm_runtime_work

PC is at usb_dmac_chan_halt+0xc/0xc0
LR is at usb_dmac_runtime_suspend+0x28/0x38

Call trace:
  usb_dmac_chan_halt
  usb_dmac_runtime_suspend
  pm_genpd_runtime_suspend
  rpm_callback
  rpm_suspend
  pm_runtime_work          ← PM workqueue 触发
  process_one_work
  worker_thread
```

关键特征：
- 只在 `CONFIG_PREEMPT=y` 的内核上出现（抢占式调度使竞态窗口更大）
- 崩溃发生在 PM workqueue 上下文中，而非用户进程
- 偏移 `0x14` 的地址访问说明是通过 NULL 指针加成员偏移来解引用
- 不是每次启动都崩溃，有一定的随机性

## 2. 复现手法

### 环境要求
- Renesas R-Car SoC 平台（如 R8A7791 Koelsch 开发板）
- 内核配置 `CONFIG_PREEMPT=y`
- USB-DMAC 驱动已启用
- Runtime PM 和 genpd（Generic Power Domain）已启用

### 复现步骤

```bash
# 1. 使用抢占式内核配置
make koelsch_defconfig
# 确保以下配置项：
# CONFIG_PREEMPT=y
# CONFIG_PM=y
# CONFIG_PM_GENERIC_DOMAINS=y

# 2. 正常启动系统
# 在 probe 完成后，runtime PM 可能在 DMA 通道初始化之前
# 就把设备挂起，导致崩溃

# 3. 如果不能稳定复现，可以缩短 autosuspend 延迟：
echo 0 > /sys/devices/platform/<usb-dmac>/power/autosuspend_delay_ms
```

### 竞态窗口分析

```
时间线（probe 过程中）：

usb_dmac_probe() 开始
  │
  ├── pm_runtime_enable()
  ├── pm_runtime_get_sync()      ← 设备变为 active
  ├── usb_dmac_init()            ← 初始化 DMAC 硬件
  ├── pm_runtime_put()           ← usage_count 变为 0 ← ★ 问题点
  │                                                       │
  │   ┌── PM workqueue 抢占 ──────────────────────────────┘
  │   │   rpm_suspend()
  │   │   → usb_dmac_runtime_suspend()
  │   │     → usb_dmac_chan_halt(&dmac->channels[i])
  │   │       → 访问 channels[i].iomem  ← NULL! 通道还没初始化!
  │   │   ★ OOPS ★
  │   └─────────────────────────────────────────────────────
  │
  ├── usb_dmac_chan_probe()      ← 本应在这里初始化通道（已经来不及）
  ├── usb_dmac_chan_probe()
  └── ...
```

在 `CONFIG_PREEMPT=y` 下，PM workqueue 有机会在 `pm_runtime_put()` 后
立即抢占当前 probe 线程并执行 runtime suspend，此时 DMA 通道尚未初始化。

## 3. 分析思路

### 第一步：从 oops 信息定位崩溃点

```
PC is at usb_dmac_chan_halt+0xc/0xc0
```

- 函数 `usb_dmac_chan_halt` 偏移 `0xc` 处崩溃
- 访问地址 `0x00000014` = NULL + 0x14 = 结构体成员偏移
- 说明传入的 channel 指针中某个成员（偏移 0x14 处）为 NULL

### 第二步：审查 runtime suspend 回调

```c
static int usb_dmac_runtime_suspend(struct device *dev)
{
    struct usb_dmac *dmac = dev_get_drvdata(dev);
    int i;

    for (i = 0; i < dmac->n_channels; ++i)
        usb_dmac_chan_halt(&dmac->channels[i]);
        // ↑ 如果 channels[i].iomem 为 NULL（未被 chan_probe 初始化），
        //   chan_halt 内部的 MMIO 访问会触发 NULL 解引用

    return 0;
}
```

### 第三步：审查 probe 函数的初始化顺序

```c
static int usb_dmac_probe(struct platform_device *pdev)
{
    // ... 分配 dmac 结构体 ...

    pm_runtime_enable(&pdev->dev);
    pm_runtime_get_sync(&pdev->dev);   // 设备 active

    ret = usb_dmac_init(dmac);
    pm_runtime_put(&pdev->dev);        // ← Bug: 过早释放引用！
                                        //   此时 channels 还没初始化

    // ... 注册 DMA engine ...

    for (i = 0; i < dmac->n_channels; ++i)
        usb_dmac_chan_probe(dmac, i);   // ← 通道初始化在这里
                                        //   但设备可能已被 suspend

    // ...
}
```

**根因**：`pm_runtime_put()` 被放在了 DMA 通道初始化（`usb_dmac_chan_probe`）
之前。一旦 `put` 导致 usage_count 变为 0，PM 框架可以随时调用
`usb_dmac_runtime_suspend()`，而此时通道结构体尚未初始化。

### 第四步：理解为什么只在 PREEMPT=y 下出现

```
非抢占内核（CONFIG_PREEMPT=n）：
  pm_runtime_put() 仅标记 "可以 suspend"
  但当前上下文不会被抢占
  probe 继续执行 chan_probe()
  通道初始化完成后，下次调度时才会执行 runtime suspend
  → 大概率不崩溃（但不保证）

抢占内核（CONFIG_PREEMPT=y）：
  pm_runtime_put() 标记 "可以 suspend"
  PM workqueue 的 worker 可能立即抢占 probe 线程
  worker 执行 runtime_suspend → 访问未初始化的通道 → 崩溃
  → 更容易触发
```

## 4. 分析工具

### oops 日志分析
```bash
# 从 oops 中获取关键信息：
# 1. PC（崩溃地址）→ 哪个函数的哪一行
# 2. 寄存器值 → 哪个指针为 NULL
# 3. Workqueue 名称 → 确认是 PM runtime 触发
# 4. Call trace → 完整调用链

# 使用 addr2line 将地址转换为源码行号：
addr2line -e vmlinux -f c023c880
```

### CONFIG_DEBUG_PM_RUNTIME
```bash
# 内核配置
CONFIG_PM_DEBUG=y
CONFIG_PM_ADVANCED_DEBUG=y

# 启用 runtime PM 调试消息
echo 1 > /sys/power/pm_debug_messages

# 或启动参数
# pm_debug_messages
```

### ftrace — runtime PM 事件
```bash
# 跟踪 runtime PM 状态变化
echo 1 > /sys/kernel/debug/tracing/events/rpm/enable

# 关注 rpm_suspend 和 rpm_resume 事件的时序
# 特别是 probe 过程中的 suspend 调用
cat /sys/kernel/debug/tracing/trace_pipe | grep usb_dmac
```

### printk 注入
```c
// 在 probe 和 runtime_suspend 中添加时序打印
static int usb_dmac_probe(...)
{
    ...
    pr_info("usb_dmac: before pm_runtime_put\n");
    pm_runtime_put(&pdev->dev);
    pr_info("usb_dmac: after pm_runtime_put, before chan_probe\n");
    ...
}

static int usb_dmac_runtime_suspend(struct device *dev)
{
    pr_info("usb_dmac: runtime_suspend called!\n");
    ...
}
```

### CONFIG_KASAN（内核地址消毒器）
```bash
CONFIG_KASAN=y
# 可以在 NULL 解引用发生前检测到非法地址访问
# 提供更详细的分配/释放调用栈
```

## 5. 解决思路

### 修复方法一：移动 pm_runtime_put() 的位置

将 `pm_runtime_put()` 移到 probe 函数末尾，确保所有硬件资源初始化完成后再允许 suspend：

```c
static int usb_dmac_probe(struct platform_device *pdev)
{
    ...
    pm_runtime_enable(&pdev->dev);
    pm_runtime_get_sync(&pdev->dev);

    ret = usb_dmac_init(dmac);
    // ★ 移除此处的 pm_runtime_put() ★

    if (ret) { ... goto error; }

    // DMA 通道初始化
    for (i = 0; i < dmac->n_channels; ++i)
        usb_dmac_chan_probe(dmac, i);

    // 注册 DMA engine
    ...

    pm_runtime_put(&pdev->dev);  // ★ 移到最后 ★
    return 0;

error:
    pm_runtime_put(&pdev->dev);
    return ret;
}
```

### 修复方法二：runtime_suspend 中增加防御性检查

```c
static int usb_dmac_runtime_suspend(struct device *dev)
{
    struct usb_dmac *dmac = dev_get_drvdata(dev);
    int i;

    for (i = 0; i < dmac->n_channels; ++i) {
        if (!dmac->channels[i].iomem)  // ★ 新增 NULL 检查 ★
            break;
        usb_dmac_chan_halt(&dmac->channels[i]);
    }

    return 0;
}
```

### 实际采用的修复

上游补丁**同时应用了两种修复**：
1. 移动 `pm_runtime_put()` 到 probe 末尾（治本）
2. 在 runtime_suspend 中增加 NULL 检查（防御性编程，保护 error 路径）

## 6. 相关背景知识

### probe 函数中 Runtime PM 的正确使用模式

```c
static int my_driver_probe(struct platform_device *pdev)
{
    // 1. 启用 runtime PM
    pm_runtime_enable(&pdev->dev);

    // 2. 确保设备处于 active 状态
    pm_runtime_get_sync(&pdev->dev);

    // 3. 初始化所有硬件资源
    //    ★ 这期间设备必须保持 active ★
    init_hardware();
    init_dma_channels();
    register_interrupts();

    // 4. 所有初始化完成后，才释放引用
    pm_runtime_put(&pdev->dev);
    //    ↑ 从此刻起，PM 框架可随时调用 runtime_suspend

    return 0;
}
```

**反模式（本 bug 的情况）**：
```c
static int my_driver_probe(...)
{
    pm_runtime_enable();
    pm_runtime_get_sync();

    init_hardware();
    pm_runtime_put();     // ← 过早释放！

    init_dma_channels();  // ← 此时 runtime_suspend 可能已在执行
    // → NULL 指针崩溃
}
```

### CONFIG_PREEMPT 对 Runtime PM 时序的影响

```
┌────────────────────────────────────────────────────────────────┐
│         PREEMPT=n                    PREEMPT=y                │
├────────────────────────────────────────────────────────────────┤
│  probe: pm_runtime_put()     probe: pm_runtime_put()          │
│  probe: init_channels()      ← PM worker 抢占！               │
│  probe: register()             PM: runtime_suspend()          │
│  ...                            PM: access channels → BOOM!   │
│  PM: runtime_suspend()         ← 恢复 probe                   │
│  PM: access channels → OK      probe: init_channels() (太迟)  │
└────────────────────────────────────────────────────────────────┘
```

### ARM 嵌入式平台的 Generic Power Domain（genpd）

在 ARM SoC 上，runtime PM 通常与 genpd 配合使用：

```
usb_dmac_runtime_suspend()
    ↓
pm_genpd_runtime_suspend()     ← genpd 框架拦截
    ↓
关闭 USB DMA 控制器的电源域     ← 硬件级别断电
```

这意味着一旦 runtime suspend 执行，不仅仅是软件状态改变，**硬件电源可能被直接切断**。
因此 runtime_suspend 回调必须在一个完全一致的状态下被调用。

### probe 阶段的 Runtime PM 竞态 — 常见缺陷模式

这是一个在 2013-2018 年间被大量修复的**系统性问题**。
许多驱动犯了同样的错误——在 probe 中过早调用 `pm_runtime_put()`：

```
同类修复的其他案例：
- SPI 控制器驱动（spi-imx, spi-cadence）
- I2C 控制器驱动
- 串口驱动（8250_omap）
- 网络驱动
```

这催生了一些最佳实践：
1. `pm_runtime_put()` 应该是 probe 成功路径的最后一步
2. Runtime suspend 回调应有防御性检查
3. 使用 `pm_runtime_put_autosuspend()` 留出缓冲时间

### 调试 NULL 指针解引用的通用方法

```bash
# 1. 从 oops 中获取故障地址
# "virtual address 00000014" → NULL + 0x14

# 2. 确定哪个结构体成员在偏移 0x14
# 使用 pahole 工具：
pahole -C usb_dmac_chan vmlinux | grep "0x14"

# 3. 或使用 GDB：
gdb vmlinux
(gdb) p &((struct usb_dmac_chan *)0)->iomem
# $1 = (void __iomem **) 0x14

# 4. 确认：iomem 成员为 NULL，说明通道未初始化
```
