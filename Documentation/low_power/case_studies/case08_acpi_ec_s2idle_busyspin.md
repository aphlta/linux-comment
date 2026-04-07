# 案例八：ACPI EC s2idle 虚假唤醒导致忙等死循环

| 项目 | 信息 |
|------|------|
| Commit | `7b301750f7f8f6503e11f1af4a03832525f58c66` |
| 作者 | Rafael J. Wysocki (Intel) |
| 日期 | 2020-05-09 |
| 影响版本 | v5.4+ ~ v5.7（两个 Fixes 标签：`d5406284ff80` 和 `fdde0ff8590b`） |
| 子系统 | ACPI / EC / PM Sleep (s2idle) |
| 严重性 | 高 — 系统无法进入睡眠，CPU 100% 忙等，功耗爆表 |
| 复现平台 | Elitegroup EF20EA 笔记本 及其他 Intel 平台 |

## 1. 故障现象

用户在 x86 笔记本上执行 suspend-to-idle（s2idle）后，系统**看似进入了睡眠**
（屏幕关闭），但实际上：

- **CPU 100% 占用**在忙等循环中，不处于低功耗状态
- **风扇全速运转**（正常睡眠时风扇应停止）
- **电池急速消耗**（与正常 s2idle 功耗差距 10-100 倍）
- 按键盘唤醒时，笔记本**机身发热严重**
- 部分机器在此状态下完全**无法被唤醒**，只能强制断电

具体触发场景：
```bash
echo s2idle > /sys/power/mem_sleep
echo mem > /sys/power/state
# 屏幕关闭，但 CPU 仍在全速运行
# 或：按键唤醒时，系统卡死无响应（EF20EA 笔记本）
```

## 2. 复现手法

### 环境要求
- Intel 平台笔记本（支持 s2idle/Modern Standby）
- 系统配置使用 s2idle（而非传统 S3 深睡眠）
- ACPI EC（Embedded Controller）有活跃的 GPE 事件

### 复现步骤

```bash
# 1. 确认睡眠模式为 s2idle
cat /sys/power/mem_sleep
# 应显示 [s2idle] deep 或 [s2idle]

# 2. 如果不是 s2idle，设置之
echo s2idle > /sys/power/mem_sleep

# 3. 进入睡眠
echo mem > /sys/power/state

# 4. 观察：
#    - 正常: 风扇停转，机身不热，功耗降至 <2W
#    - 异常: 风扇持续转动，机身温热，功耗 >15W

# 5. 使用外部功耗计或 battery 监控验证：
# 进入睡眠前记录电量
cat /sys/class/power_supply/BAT0/energy_now
# 等待 10 分钟后唤醒
cat /sys/class/power_supply/BAT0/energy_now
# 计算平均功耗
```

### 增加复现概率

```bash
# EC GPE 事件越频繁，越容易触发
# 某些笔记本上插入/拔出 AC 适配器会产生 EC GPE 风暴

# 或使用 pm-graph 工具验证 s2idle 质量：
sleepgraph -m freeze -rtcwake 15
# 这会自动分析 s2idle 过程中的唤醒事件
```

## 3. 分析思路

### 第一步：理解 s2idle 的核心循环

s2idle（suspend-to-idle）不像 S3 那样完全关闭硬件，而是在一个
**软件循环**中反复进入和退出浅睡眠：

```c
// kernel/power/suspend.c 中的 s2idle_loop()
static void s2idle_loop(void)
{
    do {
        /* 进入浅睡眠 */
        s2idle_enter();

        /* 检查是否应该唤醒 */
        if (s2idle_ops && s2idle_ops->wake)
            if (s2idle_ops->wake())  // → acpi_s2idle_wake()
                break;  // 真正的唤醒，退出循环

        /* 不是真正的唤醒（虚假唤醒），重新睡眠 */

    } while (!need_resched() && ...);
}
```

正常流程：大部分 SCI（System Control Interrupt）是虚假唤醒（如 EC 温度轮询），
`acpi_s2idle_wake()` 返回 `false` 后系统重新进入睡眠。

### 第二步：定位忙等循环的原因

问题出在 `acpi_s2idle_wake()` 的返回逻辑。旧代码的判断流程：

```c
// 旧代码（有 bug）
static bool acpi_s2idle_wake(void)
{
    // 1. 检查其他 wakeup handler
    if (acpi_check_wakeup_handlers())
        return true;  // 真正的唤醒

    // 2. 检查是否有非 EC 的 GPE 被激活
    if (acpi_ec_other_gpes_active())
        return true;  // 有非 EC GPE → 真正唤醒

    // 3. 分发 EC GPE
    if (!acpi_ec_dispatch_gpe())
        return false;  // ← 这里没有取消待处理的唤醒！

    // 4. 取消唤醒并重新 arm SCI
    ...
}
```

**Bug 在步骤 3**：当 EC GPE 未被设置时，函数直接返回 `false`，
但**没有取消已经标记的 pending wakeup**。

### 第三步：理解忙等是如何发生的

```
s2idle_loop 第 1 次迭代：
  s2idle_enter()              ← 进入浅睡眠
  [SCI 中断到达，唤醒系统]
  acpi_s2idle_wake()
    → 检查 GPE：没有非 EC GPE，EC GPE 也未 set
    → return false            ← 判定为虚假唤醒
    → 但！没有取消 pending wakeup，没有重新 arm SCI

s2idle_loop 第 2 次迭代：
  s2idle_enter()              ← 因为上次的 wakeup 还 pending...
                              ← ...enter 立即返回！不会真正睡眠！
  acpi_s2idle_wake()
    → SCI 仍然 triggered（上次遗留的）
    → 同样判定为虚假唤醒
    → return false            ← 又不取消 wakeup

s2idle_loop 第 3 次迭代：
  ... 同上 ...

→ 无限循环！CPU 永远不会进入低功耗状态！
```

**根因**：`acpi_s2idle_wake()` 有一条返回 `false` 的路径
遗漏了 "cancel wakeup + re-arm SCI" 的操作，导致后续每次 `s2idle_enter()`
都因 pending wakeup 而立即返回。

### 第四步：理解为什么这是一个 EC 特有问题

EC（Embedded Controller）是笔记本上负责温度监控、电池管理、键盘扫描等功能的
独立微控制器。EC 定期通过 SCI 中断通知主 CPU：

```
EC 常见的 GPE 事件：
- 温度采样完成（每秒几次）
- 电池电量更新
- Lid（笔记本盖子）状态变化
- AC 适配器插拔
```

在 s2idle 模式下，EC 的 GPE 事件需要被正确区分为"虚假唤醒"。
如果处理逻辑有误，这些频繁的 EC 事件就会破坏整个 s2idle 循环。

## 4. 分析工具

### pm-graph / sleepgraph（最佳工具）
```bash
# 安装 pm-graph
pip install pm-graph
# 或 apt install pm-graph

# 录制 s2idle 过程的完整时序图
sleepgraph -m freeze -rtcwake 30 -o s2idle_test

# 生成 HTML 报告，包含：
# - 每个设备的 suspend/resume 时间
# - s2idle 循环的进入/退出次数
# - GPE 事件的分布
# 如果 s2idle 循环次数异常高，说明存在忙等问题
```

### ACPI 调试
```bash
# 启用 ACPI EC 调试
echo 1 > /sys/module/acpi/parameters/aml_debug_output

# 启用 PM 调试消息
echo 1 > /sys/power/pm_debug_messages

# 内核启动参数添加 EC 调试：
# ec_debug_print ec_event_clearing=query acpi.debug_level=0x2
```

### ftrace — suspend/resume 和 ACPI 事件
```bash
# 跟踪 s2idle 循环
echo 1 > /sys/kernel/debug/tracing/events/power/suspend_resume/enable

# 跟踪 ACPI GPE 事件
echo 1 > /sys/kernel/debug/tracing/events/acpi/enable

# 特别关注 s2idle_enter 的调用频率
# 正常：每次 s2idle 期间只有少数几次
# 异常：每秒数百次 → 忙等
```

### /sys/firmware/acpi 接口
```bash
# 查看 GPE 计数器
cat /sys/firmware/acpi/interrupts/gpe_all

# 查看每个 GPE 的触发次数
cat /sys/firmware/acpi/interrupts/gpe*

# 对比进入 s2idle 前后的 GPE 计数增量
```

### turbostat（功耗验证）
```bash
# 实时监控 CPU C-state 残留时间和功耗
turbostat --quiet sleep 10

# 如果 s2idle 正常，应看到大量 C6/C7/C10 残留
# 如果忙等，会看到高 C0 残留和高功耗
```

## 5. 解决思路

### 修复策略：重构 GPE 检查逻辑

将所有 GPE 检查逻辑合并到 `acpi_ec_dispatch_gpe()` 中，
确保无论哪条路径返回，调用者都能正确处理唤醒状态：

**核心变更——`acpi_ec_dispatch_gpe()` 重构**：
```c
// 修复后：统一的 GPE 处理函数
bool acpi_ec_dispatch_gpe(void)
{
    if (!first_ec)
        return acpi_any_gpe_status_set(U32_MAX);

    // 先检查非 EC GPE——如果有，返回 true（真正唤醒）
    if (acpi_any_gpe_status_set(first_ec->gpe))
        return true;

    if (ec_no_wakeup)
        return false;

    // 分发 EC GPE，但不报告唤醒
    // 让调用者在所有情况下都执行 cancel+re-arm
    ret = acpi_dispatch_gpe(NULL, first_ec->gpe);
    if (ret == ACPI_INTERRUPT_HANDLED)
        pm_pr_dbg("EC GPE dispatched\n");

    return false;  // EC 事件不是真正唤醒
}
```

**核心变更——`acpi_s2idle_wake()` 简化**：
```c
// 修复后
static bool acpi_s2idle_wake(void)
{
    if (acpi_check_wakeup_handlers())
        return true;

    // 统一的 GPE 检查 + 分发
    if (acpi_ec_dispatch_gpe())
        return true;

    // ★ 无论 acpi_ec_dispatch_gpe 返回什么，
    // ★ 都会执行到这里的 cancel wakeup + re-arm 逻辑
    // ★ 不再有遗漏取消的路径

    pm_wakeup_clear(false);     // 取消 pending wakeup
    acpi_set_wakeup_gpes();     // 重新 arm SCI
    return false;
}
```

### 修复的关键洞察

旧代码有**三条 return 路径**，但只有其中两条执行了 "cancel + re-arm"：

```
旧代码：
path 1: wakeup_handlers active → return true  (OK, 退出 loop)
path 2: non-EC GPE active → return true        (OK, 退出 loop)
path 3: EC GPE not set → return false           (BUG! 未 cancel+re-arm)
path 4: EC GPE dispatched → cancel+re-arm → return false  (OK)
```

修复后只有两条路径，且 `return false` 的路径一定会执行 cancel+re-arm。

## 6. 相关背景知识

### S2idle vs S3 的架构差异

```
              S3 (Suspend-to-RAM)              s2idle (Suspend-to-Idle)
              ─────────────────               ──────────────────────
硬件状态      CPU 断电，内存自刷新             CPU 在最深 C-state，内存在线
唤醒延迟      ~2-5 秒                         ~100ms
功耗          极低 (~50mW)                     低 (~200mW-2W)
唤醒源        专用唤醒引脚/中断                任何中断
实现方式      BIOS/固件控制                    内核软件循环
虚假唤醒处理  BIOS 处理                        ★ 内核必须自行处理 ★

s2idle 的关键挑战：
- 系统处于 "浅睡眠" 状态，各种中断都可能唤醒 CPU
- 大部分唤醒是 "虚假的"（如 EC 温度轮询），需要过滤
- 过滤逻辑有 bug → 忙等或无法唤醒
```

### ACPI EC（Embedded Controller）

```
┌─────────────────────────────────────────────┐
│              笔记本主板                       │
│                                             │
│  ┌─────────┐      SCI 中断      ┌─────────┐ │
│  │  Main   │ ←──────────────── │    EC    │ │
│  │  CPU    │                   │ (8051)   │ │
│  │ (Intel) │  ──I/O port──→   │          │ │
│  │         │  ←─── data ────  │ 温度传感器 │ │
│  └─────────┘                   │ 电池管理  │ │
│                                │ 键盘扫描  │ │
│                                │ 风扇控制  │ │
│                                └─────────┘ │
└─────────────────────────────────────────────┘

EC 通过 GPE（General Purpose Event）中断通知 CPU：
- GPE 是 ACPI 定义的中断机制
- 每个 GPE 有一个独立的 status bit
- 多个 GPE 共享 SCI 中断线
- s2idle 时需要区分哪些 GPE 是唤醒事件
```

### s2idle_loop 的完整状态机

```
                    ┌──────────────┐
                    │  s2idle_loop │
                    │    开始      │
                    └──────┬───────┘
                           │
               ┌───────────▼──────────┐
               │   s2idle_enter()     │
               │   (进入 CPU idle)    │
               │   等待任何中断...    │
               └───────────┬──────────┘
                           │ 中断唤醒
               ┌───────────▼──────────┐
               │ acpi_s2idle_wake()   │
               │ 判断是否真正唤醒     │
               └───┬──────────┬───────┘
                   │          │
            true ──┘          └── false
                   │                │
          ┌────────▼─────┐   ┌──────▼───────────┐
          │ 退出 loop    │   │ cancel wakeup    │
          │ 恢复系统     │   │ re-arm SCI       │
          └──────────────┘   │ → 回到 enter()   │
                             └──────────────────┘
                                    ↑
                                    │
                         Bug: 遗漏了这个步骤
                         导致 enter() 立即返回
                         → 忙等循环
```

### Intel 平台 s2idle 的演进历史

```
2017 (v4.14): 引入 s2idle 基础支持
2018 (v4.18): Intel 推动 Modern Standby，s2idle 成为默认模式
2019 (v5.0~5.4): 大量 s2idle bug 修复期
  - 虚假唤醒过滤逻辑不完善
  - EC 事件处理竞态
  - GPIO 唤醒源配置错误
2020 (v5.5~5.8): 本 bug 和其他 EC 相关修复
2021+: s2idle 逐渐稳定

这个时期的 s2idle 问题非常多，因为：
1. 传统 S3 由 BIOS 完全管理，内核不需要处理唤醒过滤
2. s2idle 把这个责任转移到了内核，大量边界情况需要处理
3. 每个笔记本厂商的 EC 固件行为都不完全一致
```

### 使用 pm-graph 诊断 s2idle 问题

```bash
# pm-graph 是 Intel 开发的 PM 调试神器
# 它能自动检测 s2idle 的各种异常

# 基本用法：
sleepgraph -m freeze -rtcwake 15

# 输出 HTML 报告包含：
# 1. 完整的 suspend/resume 时间线
# 2. s2idle 循环次数（正常 <10 次/分钟）
# 3. 每次唤醒的原因（哪个 GPE/中断）
# 4. 设备 suspend/resume 耗时排名
# 5. 异常标注（如忙等、超时等）

# 如果报告显示 s2idle 循环次数 > 100/分钟
# 几乎可以确定存在虚假唤醒忙等问题
```
