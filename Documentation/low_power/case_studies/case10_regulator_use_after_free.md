# 案例十：Regulator 框架 Use-After-Free 漏洞

| 项目 | 信息 |
|------|------|
| Commit | `4affd79a125ac91e6a53be843ea3960a8fc00cbb` |
| 作者 | Wen Yang (Alibaba Linux) |
| 日期 | 2019-11-24 |
| 影响版本 | 长期存在，影响多个 LTS 内核 |
| 子系统 | Regulator Core |
| 严重性 | 高 — 内存安全漏洞，可能导致崩溃或安全问题 |

## 1. 故障现象

Regulator（电压调节器）框架在获取和释放 regulator 引用时存在
**use-after-free（释放后使用）**漏洞。

### 可能的外在表现
- **随机内存损坏**：被释放的 `rdev` 结构体内存被其他分配覆盖后，
  后续的解引用读到垃圾数据
- **kernel oops/panic**：如果被释放的内存被回收并取消映射，访问会触发页错误
- **KASAN 告警**：在启用 KASAN 的内核上会被检测到并报告
- **静默数据损坏**：最危险的情况——没有可见的崩溃，但内部状态被悄悄破坏

### 触发条件
- 任何调用 `regulator_get()` 失败的路径（错误处理中的 UAF）
- 任何调用 `regulator_put()` 的路径（正常释放中的 UAF）
- 涉及电源管理的 suspend/resume 路径中频繁的 regulator get/put 操作

## 2. 复现手法

### 环境要求
- 任何使用 regulator 框架的 Linux 系统
- 推荐启用 KASAN 或 KFENCE 来检测内存错误
- 驱动中有 regulator_get/regulator_put 调用

### 复现步骤

```bash
# 方法 1：使用 KASAN 检测
# 内核配置：
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y  # 或 CONFIG_KASAN_SW_TAGS=y

# 正常使用系统，触发 regulator 的 get/put 操作
# KASAN 会在 UAF 发生时报告
# dmesg 中会出现类似：
# BUG: KASAN: use-after-free in _regulator_put+0x...
# Read of size 4 at addr ffff...
# Freed by task ...:
#  put_device
#  _regulator_get (or _regulator_put)

# 方法 2：使用 KFENCE（轻量级，适合生产环境）
CONFIG_KFENCE=y
# KFENCE 以采样方式检测 UAF，overhead 极低

# 方法 3：手动构造触发场景
# 编写一个简单的内核模块反复执行 regulator_get/put：
```

```c
/* 测试模块 — 触发 regulator UAF */
#include <linux/regulator/consumer.h>

static int __init test_init(void)
{
    struct regulator *reg;

    /* 获取一个不存在的 regulator → 触发错误路径 */
    reg = regulator_get(NULL, "nonexistent_regulator");
    if (IS_ERR(reg))
        pr_info("get failed as expected: %ld\n", PTR_ERR(reg));

    /* 或获取后释放 → 触发 _regulator_put 中的 UAF */
    reg = regulator_get(dev, "vdd");
    if (!IS_ERR(reg))
        regulator_put(reg);

    return 0;
}
```

### 通过 fault injection 提高复现率

```bash
# 使用 failslab 让 create_regulator() 的内存分配失败
# 强制进入 _regulator_get() 的错误路径

echo 1 > /sys/kernel/debug/failslab/probability
echo 1 > /sys/kernel/debug/failslab/times
echo N > /sys/kernel/debug/failslab/task-filter
# 然后触发 regulator_get() 调用
```

## 3. 分析思路

### 第一步：理解 use-after-free 的基本模式

```c
struct foo *p = kmalloc(sizeof(*p), GFP_KERNEL);
// ... 使用 p ...
kfree(p);          // 释放内存
p->member = 0;     // ★ Use-After-Free! p 已被释放 ★
```

### 第二步：分析 `_regulator_get()` 中的 UAF

```c
struct regulator *_regulator_get(struct device *dev, const char *id, ...)
{
    struct regulator_dev *rdev;
    struct regulator *regulator;

    rdev = regulator_dev_lookup(dev, id);
    // rdev 指向 regulator 设备

    regulator = create_regulator(rdev, dev, id);
    if (regulator == NULL) {
        regulator = ERR_PTR(-ENOMEM);

        put_device(&rdev->dev);    // ★ 释放 rdev 的设备引用
                                    // ★ 如果这是最后一个引用，rdev 被释放！

        module_put(rdev->owner);   // ★ UAF! rdev->owner 可能已被释放！
                                    // ★ rdev 指向的内存可能已不属于我们

        return regulator;
    }
    ...
}
```

`put_device(&rdev->dev)` 可能触发设备的 `release` 回调，释放整个 `rdev` 结构体。
之后的 `module_put(rdev->owner)` 就是在访问已释放的内存。

### 第三步：分析 `_regulator_put()` 中的 UAF

```c
static void _regulator_put(struct regulator *regulator)
{
    struct regulator_dev *rdev = regulator->rdev;

    rdev->open_count--;
    rdev->exclusive = 0;

    put_device(&rdev->dev);    // ★ 释放 rdev 的设备引用
                                // ★ rdev 可能被释放！

    regulator_unlock(rdev);    // ★ UAF! 访问已释放的 rdev 的锁！

    kfree_const(regulator->supply_name);
    kfree(regulator);

    module_put(rdev->owner);   // ★ UAF! rdev->owner 可能已被释放！
}
```

这里有**两处 UAF**：
1. `regulator_unlock(rdev)` — 在 `put_device` 后访问 `rdev` 的锁
2. `module_put(rdev->owner)` — 在 `put_device` 后访问 `rdev->owner`

### 第四步：确认 `put_device` 可能释放 `rdev`

```c
// 设备引用计数归零时的回调：
static void regulator_dev_release(struct device *dev)
{
    struct regulator_dev *rdev = dev_get_drvdata(dev);
    kfree(rdev->constraints);
    kfree(rdev);  // ← 整个 rdev 结构体被释放
}
```

当 `put_device()` 使引用计数降到 0 时，`regulator_dev_release()` 会
释放 `rdev`。之后任何对 `rdev` 成员的访问都是 UAF。

## 4. 分析工具

### KASAN（内核地址消毒器）— 最佳工具
```bash
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_INLINE=y

# KASAN 会在 UAF 发生时立即报告：
# ==================================================================
# BUG: KASAN: use-after-free in _regulator_put+0x1a8/0x200
# Read of size 8 at addr ffff8880123456 by task modprobe/1234
#
# Freed by:
#   kfree+0x...
#   regulator_dev_release+0x...
#   put_device+0x...
#   _regulator_put+0x...       ← 在这里释放
#
# Last potentially related work creation:
#   ...
#
# The buggy address belongs to the object at ffff8880123400
#  which belongs to the cache kmalloc-512 of size 512
# ==================================================================

# KASAN 提供：
# 1. 精确的 UAF 发生位置
# 2. 内存被释放的完整调用栈
# 3. 内存被分配的完整调用栈
# 4. 对象的 slab 信息
```

### KFENCE（轻量级内存检测）
```bash
CONFIG_KFENCE=y
CONFIG_KFENCE_SAMPLE_INTERVAL=100  # 每 100ms 采样一次

# KFENCE 的 overhead 极低（<1%），适合生产环境
# 通过采样的方式检测 UAF，不保证每次都能发现
# 但长时间运行后大概率会捕获
```

### SLUB debug
```bash
# 内核启动参数：
slub_debug=FZPU

# F = Sanity check (FREE)
# Z = Red zoning (缓冲区溢出检测)
# P = Poisoning (释放后填充毒药值)
# U = User tracking (记录分配/释放调用栈)

# 释放后的内存被填充 0x6b
# 如果代码读到 0x6b6b6b6b 的值，说明在读已释放的内存
```

### 静态分析工具
```bash
# Coccinelle 语义补丁可以检测此类模式
# smatch 也能部分检测 UAF 模式

# 运行 smatch：
make CHECK=smatch C=1 drivers/regulator/core.o

# 使用 Coccinelle 搜索 "put_device 后使用"的模式
```

## 5. 解决思路

### 修复方法：调整 `put_device()` 的调用顺序

**核心原则**：`put_device()` 必须是对设备引用的**最后一个操作**。
在调用 `put_device()` 之后，不能再访问该设备的任何成员。

**`_regulator_get()` 修复**：

```c
// 修复前（有 UAF）：
regulator = create_regulator(rdev, dev, id);
if (regulator == NULL) {
    regulator = ERR_PTR(-ENOMEM);
    put_device(&rdev->dev);     // 1. 先释放设备
    module_put(rdev->owner);    // 2. 再访问 rdev->owner ← UAF!
    return regulator;
}

// 修复后：
regulator = create_regulator(rdev, dev, id);
if (regulator == NULL) {
    regulator = ERR_PTR(-ENOMEM);
    module_put(rdev->owner);    // 1. 先访问 rdev->owner
    put_device(&rdev->dev);     // 2. 最后再释放设备
    return regulator;
}
```

**`_regulator_put()` 修复**：

```c
// 修复前（有 UAF）：
rdev->open_count--;
rdev->exclusive = 0;
put_device(&rdev->dev);        // 1. 先释放设备
regulator_unlock(rdev);        // 2. 访问 rdev->lock ← UAF!
kfree_const(regulator->supply_name);
kfree(regulator);
module_put(rdev->owner);       // 3. 访问 rdev->owner ← UAF!

// 修复后：
rdev->open_count--;
rdev->exclusive = 0;
regulator_unlock(rdev);        // 1. 先解锁（仍持有设备引用）
kfree_const(regulator->supply_name);
kfree(regulator);
module_put(rdev->owner);       // 2. 释放模块引用
put_device(&rdev->dev);        // 3. 最后释放设备 ← 安全！
```

## 6. 相关背景知识

### Use-After-Free 的危害等级

```
UAF 的严重程度取决于释放后内存的状态：

场景 1：内存未被重新分配
  → 读到旧数据，可能不崩溃但逻辑错误
  → 写入会破坏 slab 元数据，延迟崩溃

场景 2：内存被同大小的对象重新分配
  → 读到完全无关的数据
  → 写入会破坏其他对象 → 难以追踪的数据损坏

场景 3：内存被回收给页分配器
  → 访问可能触发 page fault → kernel oops
  → 这是最容易发现的情况

场景 4（安全漏洞）：攻击者控制重新分配的内容
  → 可以伪造任意数据 → 可能实现权限提升
  → 这就是为什么 UAF 同时是安全漏洞
```

### Linux 设备模型的引用计数

```c
// 每个 struct device 内嵌 struct kobject，
// kobject 使用 kref 管理引用计数：

get_device(dev);      // 增加引用计数
put_device(dev);      // 减少引用计数
                       // 当计数归零时，调用 dev->release()
                       // release() 通常会 kfree 整个包含结构体

// ★ 关键规则 ★
// put_device() 之后，dev 指针可能已无效
// 不能再访问 dev 或包含 dev 的外层结构体的任何成员
```

### Regulator 框架在低功耗中的角色

```
┌──────────────────────────────────────────────┐
│                  消费者驱动                    │
│  (CPU, GPU, 传感器, 通信模块等)               │
│                                              │
│  regulator_get("vdd_core")                   │
│  regulator_enable(reg)                       │
│  regulator_set_voltage(reg, 900000, 1100000) │
│  regulator_disable(reg)                      │
│  regulator_put(reg)                          │
└──────────────────────┬───────────────────────┘
                       │
         Regulator 框架（drivers/regulator/core.c）
                       │
┌──────────────────────▼───────────────────────┐
│                  Regulator 驱动               │
│  (PMIC: 如 TPS65217, S2MPS11, DA9211 等)    │
│                                              │
│  通过 I2C/SPI 控制电压调节器硬件              │
│  支持动态电压频率调节(DVFS)                   │
│  支持 suspend 模式下的电压配置                │
└──────────────────────────────────────────────┘

在低功耗流程中，regulator_get/put 被频繁调用：
- 设备 probe/remove → get/put
- Runtime PM suspend/resume → enable/disable
- System sleep → 配置 suspend 电压
- DVFS → 动态调整电压

任何 get/put 路径中的 UAF 都可能在 PM 流程中触发
```

### put_device 之后使用 — 内核中的系统性问题

这不是个别驱动的问题，而是一个**常见的编码模式错误**。
类似的 bug 在内核中被大量修复：

```
常见的错误模式：
1. put_device() 后访问设备成员        ← 本案例
2. kfree() 后使用指针
3. list_del() 后访问节点
4. kobject_put() 后使用包含对象

预防手段：
1. 代码审查中重点关注 put/free/del 后的访问
2. 使用 KASAN/KFENCE 进行运行时检测
3. 使用静态分析工具（smatch/Coccinelle）扫描
4. 编码规范：释放操作总是函数/块的最后一条语句
```

### KASAN vs KFENCE vs SLUB debug 对比

| 特性 | KASAN | KFENCE | SLUB debug |
|------|-------|--------|------------|
| 检测率 | 100% | 采样式 | 部分 |
| 性能开销 | 2-3x | <1% | 10-30% |
| 内存开销 | 3x | 极低 | 中等 |
| 适用环境 | 开发/测试 | 生产环境 | 测试环境 |
| UAF 检测 | 精确 | 概率性 | 通过 poisoning |
| 缓冲区溢出 | 精确 | 概率性 | Red zone |
| 报告质量 | 完整调用栈 | 完整调用栈 | 基本信息 |
