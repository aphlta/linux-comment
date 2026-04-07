# 案例七：genpd 电源域与时钟框架 AB-BA 死锁

| 项目 | 信息 |
|------|------|
| Commit | `2071ac985d37efe496782c34318dbead93beb02f` |
| 作者 | Jiada Wang (Mentor Graphics) |
| 日期 | 2019-03-12 |
| 影响版本 | v4.x ~ v5.1（含 genpd attach_dev 回调后） |
| 子系统 | PM Domains (genpd) / Clock Framework |
| 严重性 | 高 — 系统启动阶段可能挂死 |
| 发现平台 | Renesas R-Car ARM SoC |

## 1. 故障现象

ARM 嵌入式平台（Renesas R-Car）在**启动阶段随机挂死**，表现为系统在 probe
设备时停止响应。没有 oops，没有 panic，只是静默挂住。

启用 `CONFIG_LOCKDEP=y` 后，lockdep 会报告一个经典的 **AB-BA 死锁**告警：

```
======================================================
WARNING: possible circular locking dependency detected
------------------------------------------------------

Thread 1: clk_prepare_lock → genpd->mlock
Thread 2: genpd->mlock → clk_prepare_lock

Possible unsafe locking scenario:
      CPU0                    CPU1
      ----                    ----
 lock(clk_prepare_lock);
                              lock(genpd->mlock);
                              lock(clk_prepare_lock);   ← 等 CPU0
 lock(genpd->mlock);                                    ← 等 CPU1
                              *** DEADLOCK ***
```

关键特征：
- lockdep 警告在设备 probe 阶段出现
- 涉及两个不同子系统的全局锁
- 可能不会每次都真正死锁——取决于两个线程的执行时序
- 在单核系统上不会死锁，多核系统上才有风险

## 2. 复现手法

### 环境要求
- 多核 ARM SoC 平台（如 Renesas R-Car H3/M3/E3）
- genpd 电源域已配置，且 genpd provider 有 `.attach_dev` 回调
- 时钟驱动的 `.recalc_rate` 回调中涉及 I2C/SPI 通信
- `CONFIG_LOCKDEP=y`

### 复现场景

需要两个线程同时操作涉及同一 genpd 的设备：

```bash
# 场景 1：系统启动时自然触发
# 多个设备同时 probe，一个在注册时钟，另一个在加入电源域
# 启动阶段的并行 probe 天然提供了竞争条件

# 场景 2：手动触发（模拟）
# 线程 A：加载一个使用外部时钟芯片（如 CS2000）的驱动
modprobe cs2000

# 线程 B：同时将另一个设备加入同一 genpd
# （这通常在 probe 中自动发生）
```

### lockdep 检测

```bash
# 即使实际死锁未发生，lockdep 也能检测到潜在风险：
CONFIG_LOCKDEP=y
CONFIG_PROVE_LOCKING=y

# 启动后检查：
dmesg | grep -i "circular\|deadlock"
```

## 3. 分析思路

### 第一步：理解两条锁获取路径

**路径 A — 时钟注册导致 genpd 锁（先 clk_lock → 后 genpd_lock）**：

```
cs2000_probe()                               // 外部时钟芯片 probe
  → clk_register()
    → __clk_core_init()
      → clk_prepare_lock()                   // ① 获取 prepare_lock
        → cs2000_recalc_rate()               // 调用 .recalc_rate 回调
          → i2c_smbus_read_byte_data()       // 通过 I2C 读取芯片寄存器
            → rcar_i2c_master_xfer()
              → dma_request_chan()            // 请求 DMA 通道
                → rcar_dmac_of_xlate()
                  → rcar_dmac_alloc_chan_resources()
                    → pm_runtime_get_sync()
                      → rpm_resume()
                        → genpd_runtime_resume()  // ② 获取 genpd->mlock
```

锁顺序：`prepare_lock` → `genpd->mlock`

**路径 B — 设备加入电源域导致 clk_lock（先 genpd_lock → 后 clk_lock）**：

```
genpd_add_device()                           // 将设备添加到电源域
  → genpd_lock(genpd)                        // ① 获取 genpd->mlock
    → cpg_mssr_attach_dev()                  // 调用 .attach_dev 回调
      → of_clk_get_from_provider()           // 从设备树获取时钟
        → __of_clk_get_from_provider()
          → __clk_create_clk()
            → clk_prepare_lock()             // ② 获取 prepare_lock
```

锁顺序：`genpd->mlock` → `prepare_lock`

### 第二步：确认 AB-BA 模式

```
           Thread A              Thread B
           --------              --------
    lock(prepare_lock)     lock(genpd->mlock)
           ...                    ...
    lock(genpd->mlock)     lock(prepare_lock)
         ↑ 等 B 释放            ↑ 等 A 释放
              ╲                 ╱
               ╲               ╱
                ╲             ╱
                 → DEADLOCK ←
```

这是经典的 **AB-BA 锁序反转**死锁。两个线程以相反的顺序获取两把锁。

### 第三步：分析哪条路径可以改变

| 路径 | 修改可行性 |
|------|-----------|
| A: `prepare_lock` → `genpd->mlock` | 困难。clk 框架的 prepare_lock 是全局锁，深嵌在 clk 核心代码中 |
| B: `genpd->mlock` → `prepare_lock` | 可行。`.attach_dev` 回调实际上不需要 genpd->mlock 保护 |

关键洞察：`.attach_dev` 和 `.detach_dev` 回调的内容（通常是获取时钟引用）
**不需要**在 genpd 的临界区内执行。把它们移出锁保护范围可以打破死锁链。

## 4. 分析工具

### lockdep（最关键的工具）
```bash
CONFIG_LOCKDEP=y
CONFIG_PROVE_LOCKING=y
CONFIG_DEBUG_LOCK_ALLOC=y

# lockdep 在检测到潜在 AB-BA 死锁时输出：
# 1. 两条锁获取路径的完整调用栈
# 2. 锁的持有和等待关系图
# 3. 哪些锁类别形成了环路

# lockdep 的优势：不需要真正死锁就能检测到问题！
# 只要两条路径在不同时间各执行一次，lockdep 就会记录锁序并报警
```

### /proc/lockdep 和 /proc/lock_stat
```bash
# 查看锁依赖图
cat /proc/lockdep

# 查看锁竞争统计
cat /proc/lock_stat

# 检查是否有锁序冲突
cat /proc/lockdep_chains
```

### ftrace — 锁事件
```bash
# 跟踪锁的获取和释放
echo 1 > /sys/kernel/debug/tracing/events/lock/enable

# 或只跟踪特定函数
echo 'genpd_lock genpd_unlock clk_prepare_lock' > \
    /sys/kernel/debug/tracing/set_ftrace_filter
echo function > /sys/kernel/debug/tracing/current_tracer
```

### sysrq-d（显示锁状态）
```bash
# 如果系统真的死锁了：
# 通过串口发送 SysRq+d
# 输出所有持有锁的进程信息
```

## 5. 解决思路

### 修复策略：将 attach_dev/detach_dev 移出 genpd 锁保护范围

**修复前（genpd_add_device）**：
```c
static int genpd_add_device(struct generic_pm_domain *genpd,
                            struct device *dev, ...)
{
    gpd_data = genpd_alloc_dev_data(...);

    genpd_lock(genpd);              // ① 获取锁

    ret = genpd->attach_dev ?       // ② attach_dev 在锁内执行
          genpd->attach_dev(genpd, dev) : 0;
    if (ret) goto out;

    dev_pm_domain_set(dev, &genpd->domain);
    genpd->device_count++;
    list_add_tail(&gpd_data->base.list_node, &genpd->dev_list);

out:
    genpd_unlock(genpd);            // ③ 释放锁
    return ret;
}
```

**修复后**：
```c
static int genpd_add_device(struct generic_pm_domain *genpd,
                            struct device *dev, ...)
{
    gpd_data = genpd_alloc_dev_data(...);

    // ★ attach_dev 移到锁外面 ★
    ret = genpd->attach_dev ?
          genpd->attach_dev(genpd, dev) : 0;
    if (ret) goto out;

    genpd_lock(genpd);              // 获取锁

    dev_pm_domain_set(dev, &genpd->domain);
    genpd->device_count++;
    list_add_tail(&gpd_data->base.list_node, &genpd->dev_list);

    genpd_unlock(genpd);            // 释放锁
out:
    if (ret)
        genpd_free_dev_data(dev, gpd_data);
    return ret;
}
```

**同理修复 genpd_remove_device**：
```c
// 修复前：detach_dev 在锁内
genpd_lock(genpd);
    if (genpd->detach_dev)
        genpd->detach_dev(genpd, dev);  // 在锁内
    list_del_init(&pdd->list_node);
genpd_unlock(genpd);

// 修复后：detach_dev 移到锁外
genpd_lock(genpd);
    list_del_init(&pdd->list_node);
genpd_unlock(genpd);

if (genpd->detach_dev)
    genpd->detach_dev(genpd, dev);      // 在锁外
```

### 修复正确性的论证

为什么 `.attach_dev` 和 `.detach_dev` 可以移到锁外？

1. **attach_dev** 只是设置设备的时钟/电源引用，不修改 genpd 的设备列表
2. **detach_dev** 只是清理设备的时钟/电源引用，设备已经从列表中移除
3. 多个并发的 attach_dev 调用不会互相干扰（操作不同设备）
4. genpd 内部状态（device_count、dev_list）仍在锁保护内

## 6. 相关背景知识

### AB-BA 死锁的一般原理

```
经典 AB-BA 死锁条件（全部满足才会死锁）：
1. 互斥：锁不能共享
2. 持有等待：持有 A 锁的同时等待 B 锁
3. 不可抢占：不能强制释放他人持有的锁
4. 环路等待：A→B 和 B→A 形成环路

打破任一条件即可消除死锁风险。
本修复打破的是条件 4——让两条路径不再需要同时持有两把锁。
```

### Generic Power Domain (genpd) 架构

```
┌────────────────────────────────────────────┐
│            SoC Power Domain                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Device A │  │ Device B │  │ Device C │ │
│  │(USB DMA) │  │(I2C ctrl)│  │(SPI ctrl)│ │
│  └──────────┘  └──────────┘  └──────────┘ │
│                                            │
│  genpd->mlock 保护:                        │
│  - device_count                            │
│  - dev_list                                │
│  - power state                             │
│                                            │
│  .attach_dev() — 设备加入域时调用           │
│  .detach_dev() — 设备离开域时调用           │
│  .power_on()   — 给域上电                  │
│  .power_off()  — 给域断电                  │
└────────────────────────────────────────────┘
```

### Linux 时钟框架的锁层次

```
clk_prepare_lock (全局 mutex)
  │
  ├── 保护所有时钟的 prepare/unprepare 操作
  ├── 保护时钟树的拓扑变化（注册/注销）
  ├── 保护 .recalc_rate 等回调的调用
  │
  └── ★ 这是一个非常"贪婪"的全局锁 ★
      任何涉及 clk_prepare/clk_register 的路径都会获取它
      → 容易与其他子系统的锁形成 AB-BA
```

### Renesas R-Car 平台的特殊性

为什么此 bug 在 Renesas 平台上暴露：

1. **CPG/MSSR 时钟驱动**实现了 genpd 的 `.attach_dev` 回调
2. 这个回调中调用 `of_clk_get_from_provider()` → 获取 `prepare_lock`
3. 同时，**CS2000 外部时钟芯片**的 `.recalc_rate` 回调需要通过 I2C 读取
4. I2C 传输需要 DMA → DMA 在 genpd 保护的电源域内 → 需要 `genpd->mlock`

这种跨多个子系统的长调用链使得 AB-BA 死锁更容易出现。

### lockdep 检测 AB-BA 死锁的原理

```
lockdep 维护一个全局的锁类别依赖图：

1. 每当一个锁被获取，lockdep 记录：
   - 当前线程已持有哪些锁
   - 新获取的锁类别

2. 这形成一条边：held_lock → new_lock

3. 如果反向边已存在（new_lock → held_lock），
   说明存在其他路径以相反顺序获取这两把锁
   → 报告潜在 AB-BA 死锁

关键优势：
- 不需要实际死锁发生
- 只要两条路径在系统运行期间各执行过一次
- lockdep 就能检测到潜在的死锁风险

这也是为什么建议在开发阶段始终开启 lockdep。
```

### 此类跨子系统死锁的预防原则

1. **避免在回调中获取全局锁**：回调函数可能在任意锁上下文中被调用
2. **最小化锁持有范围**：只在真正需要互斥的操作上持有锁
3. **文档化锁顺序**：在子系统头文件中声明锁的获取顺序约定
4. **始终启用 lockdep 测试**：CI 系统应包含 lockdep 启用的配置
