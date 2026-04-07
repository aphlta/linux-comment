# 案例四：MWAIT C-State Hint 编码溢出导致幽灵 C16 状态

| 项目 | 信息 |
|------|------|
| Commit | `6b8e288f49570ee2ba15a2a07c2ebf7ad2210422` |
| 作者 | He Rongguang (Alibaba Linux) |
| 影响版本 | 所有使用 ACPI cpuidle 的 x86 内核 |
| 子系统 | cpuidle / ACPI / intel_idle |
| 严重性 | 中 — 逻辑错误，可能导致 cpuidle 行为异常 |

## 1. 故障现象

在虚拟化环境（QEMU/KVM）中，当 ACPI 固件呈现特定的 C-state 配置时，
内核会计算出一个**不存在的 C16 状态**。具体表现：

- `cpuidle` 子系统认为某个空闲状态对应 C16
- x86 MWAIT 最多支持到 C15（4-bit 编码），C16 是无效的
- 对应 C-state 的 substate 检查会在错误的 CPUID 寄存器位域中读取
  （因为 cstate_type=16 超出了 `edx` 寄存器中 substate 信息的范围）
- 可能导致该空闲状态被错误判定为不可用，或进入错误的处理器空闲深度

**在物理机上不易触发**，因为真实 ACPI 固件通常不会将 MWAIT hint 0xF0 放入
C-state 表。但在虚拟机中，QEMU 生成的 ACPI 表可能包含这样的边界值。

## 2. 复现手法

### 环境要求
- x86_64 系统（物理机或虚拟机）
- 支持 MWAIT 指令的 CPU
- 可以控制 ACPI C-state 表的内容（虚拟机最容易实现）

### 在 QEMU 中复现

```bash
# 1. 创建自定义 ACPI DSDT 表，其中 C-state 使用 MWAIT hint 0xF0
#    （即 hint[7:4] = 0xF，对应规范中的 C0）

# 2. 启动 QEMU 并传入自定义 ACPI 表
qemu-system-x86_64 \
    -machine q35,accel=kvm \
    -acpitable file=custom_dsdt.aml \
    ...

# 3. 在 guest 中检查 cpuidle 状态
cat /sys/devices/system/cpu/cpu0/cpuidle/state*/name
cat /sys/devices/system/cpu/cpu0/cpuidle/state*/desc

# 4. 启用 ACPI C-state 调试
echo 'file cstate.c +p' > /sys/kernel/debug/dynamic_debug/control
# 观察日志中是否出现异常的 cstate_type 值
```

### 通过代码注入验证

```c
// 在 acpi_processor_ffh_cstate_probe_cpu() 中添加调试打印
printk("MWAIT hint=0x%lx, cstate_type=%u\n",
       cx->address, cstate_type);

// 当 cx->address 的 bit[7:4] 为 0xF 时：
// 修复前输出：cstate_type=16 (错误!)
// 修复后输出：cstate_type=0  (正确，C0)
```

### 使用 cpuid 工具辅助分析

```bash
# 查看 MWAIT 支持的子状态
cpuid -1 -l 5
# 输出示例：
# MONITOR/MWAIT (5):
#    smallest monitor-line size (bytes) = 0x40 (64)
#    largest monitor-line size (bytes)  = 0x40 (64)
#    C0 sub C-states supported using MWAIT = 0x0
#    C1 sub C-states supported using MWAIT = 0x2
#    C2 sub C-states supported using MWAIT = 0x1
#    C3 sub C-states supported using MWAIT = 0x2
#    ...
# 注意：只有 C0-C7/C10 等是有效的，C16 不存在
```

## 3. 分析思路

### 第一步：理解 MWAIT Hint 编码

x86 MWAIT 指令通过 EAX 寄存器传入 hint 值来请求特定的 C-state：

```
EAX 寄存器布局（MWAIT Hint）：
┌────────────────────────────────────────┐
│ 31        8 │ 7    4 │ 3          0    │
│  Reserved   │C-state │  Sub C-state   │
│             │  编码   │    编码         │
└────────────────────────────────────────┘

C-state 编码规则（Intel SDM & AMD Manual）：
  EAX[7:4] = 0x0  →  C1
  EAX[7:4] = 0x1  →  C2
  EAX[7:4] = 0x2  →  C3
  ...
  EAX[7:4] = 0xE  →  C15
  EAX[7:4] = 0xF  →  C0  ← 特殊值！不是 C16！

通用公式：C-state = (EAX[7:4] + 1) mod 16
          当 EAX[7:4] = 0xF 时，(0xF + 1) mod 16 = 0 = C0
```

### 第二步：定位错误代码

原始代码（`arch/x86/kernel/acpi/cstate.c`）：

```c
cstate_type = ((cx->address >> MWAIT_SUBSTATE_SIZE) &
               MWAIT_CSTATE_MASK) + 1;
```

其中 `MWAIT_SUBSTATE_SIZE = 4`，`MWAIT_CSTATE_MASK = 0xF`。

当 `cx->address` 的 bit[7:4] = 0xF 时：
- `(0xF & 0xF) + 1 = 16` ← 溢出！应该是 0（C0）

### 第三步：理解后果

`cstate_type = 16` 后续用于：

```c
edx_part = edx >> (cstate_type * MWAIT_SUBSTATE_SIZE);
num_cstate_subtype = edx_part & MWAIT_SUBSTATE_MASK;
```

其中 `edx` 来自 CPUID leaf 5（MWAIT）。`edx` 是 32-bit 寄存器：
- `edx >> (16 * 4)` = `edx >> 64` = **未定义行为**（在 x86 上通常等于 `edx >> 0`）

这意味着检查的 substate 数据可能是垃圾值，导致：
- 一个本应可用的 C-state 被认为不可用，或
- 一个无效的 C-state 被错误地认为可用

### 第四步：确认修复的正确性

需要验证 `& MWAIT_CSTATE_MASK` 对所有有效输入都正确：

```
EAX[7:4]  旧代码(+1)  新代码((+1)&0xF)  预期C-state
 0x0        1              1               C1 ✓
 0x1        2              2               C2 ✓
 ...
 0xE       15             15               C15 ✓
 0xF       16              0               C0 ✓ ← 修复的关键
```

## 4. 分析工具

### CPUID 信息查看
```bash
# 查看 MWAIT leaf (leaf 5) 的完整信息
cpuid -l 5 -1

# 或通过内核接口
cat /dev/cpu/0/cpuid  # 需要 cpuid 驱动
```

### ACPI 表转储
```bash
# 安装 acpica-tools
apt install acpica-tools

# 转储 ACPI 表
acpidump > acpi.dat
acpixtract -a acpi.dat

# 反编译 DSDT/SSDT 查看 C-state 定义
iasl -d dsdt.dat
grep -A 10 "FFH" dsdt.dsl  # 查找 FFH（Functional Fixed Hardware）类型的 C-state
```

### cpuidle sysfs 接口
```bash
# 查看所有 CPU 的空闲状态配置
for state in /sys/devices/system/cpu/cpu0/cpuidle/state*/; do
    echo "=== $(cat ${state}name) ==="
    echo "  desc: $(cat ${state}desc)"
    echo "  latency: $(cat ${state}latency) us"
    echo "  usage: $(cat ${state}usage)"
    echo "  time: $(cat ${state}time) us"
done
```

### 动态调试
```bash
# 启用 ACPI cstate 相关的调试输出
echo 'file cstate.c +p' > /sys/kernel/debug/dynamic_debug/control
echo 'file intel_idle.c +p' > /sys/kernel/debug/dynamic_debug/control

# 查看 dmesg 中的 cpuidle 初始化信息
dmesg | grep -i "cpuidle\|cstate\|mwait"
```

### 内核启动参数
```bash
# 强制使用 ACPI cpuidle 驱动（而非 intel_idle）
intel_idle.max_cstate=0

# 或完全禁用 cpuidle 来对比行为
cpuidle.off=1
```

## 5. 解决思路

### 最终修复

在 `+1` 计算后添加 `& MWAIT_CSTATE_MASK` 进行模运算，处理回绕：

**ACPI cstate 路径**（`arch/x86/kernel/acpi/cstate.c`）：
```c
// 修复前：
cstate_type = ((cx->address >> MWAIT_SUBSTATE_SIZE) &
               MWAIT_CSTATE_MASK) + 1;

// 修复后：
cstate_type = (((cx->address >> MWAIT_SUBSTATE_SIZE) &
               MWAIT_CSTATE_MASK) + 1) & MWAIT_CSTATE_MASK;
```

**intel_idle 路径**（`drivers/idle/intel_idle.c`）：
```c
// 修复前：
unsigned int mwait_cstate = MWAIT_HINT2CSTATE(mwait_hint) + 1;

// 修复后：
unsigned int mwait_cstate = (MWAIT_HINT2CSTATE(mwait_hint) + 1) &
                            MWAIT_CSTATE_MASK;
```

### 为什么不是 `if (val == 0xF) return 0;`？

使用位掩码比条件分支更好：
1. **零额外开销**——AND 指令比分支预测友好
2. **数学上等价**——`(x + 1) & 0xF` 就是 mod 16 加法，正是硬件规范定义的编码
3. **一致性**——两个路径使用相同的修复模式

### 对现有系统的影响

| 场景 | 修复前 | 修复后 |
|------|--------|--------|
| 正常 ACPI 表（hint[7:4] = 0~E） | 正确 | 正确（无变化） |
| QEMU 生成的异常表（hint[7:4] = F） | 错误（C16） | 正确（C0） |
| 未来可能的固件 | 错误 | 正确 |

修复对正常系统**完全无影响**（因为 `(n + 1) & 0xF` 在 n < 0xF 时等于 `n + 1`）。

## 6. 相关背景知识

### x86 C-State 层级

```
C0  ── 活跃态（CPU 正在执行指令）
│
C1  ── 最浅睡眠（停止指令执行，时钟仍运行）
│       唤醒延迟：~1μs
C1E ── 增强型 C1（降低核心电压）
│       唤醒延迟：~10μs
C3  ── 深睡眠（L1/L2 cache 可被 flush）
│       唤醒延迟：~50-200μs
C6  ── 深度节电（核心电压可降至 0）
│       唤醒延迟：~100-500μs
C7  ── 最深睡眠（L3 cache 也可被 flush）
│       唤醒延迟：~200-1000μs
C8/C9/C10 ── 更深层次（Package-level states）
```

### MWAIT 指令工作原理

```
1. MONITOR 指令：设置一个地址监控范围
   MONITOR(address, extensions, hints)

2. MWAIT 指令：进入指定的 C-state 等待
   MWAIT(hints, extensions)
   - hints[7:4] = 目标 C-state 编码
   - hints[3:0] = sub C-state 选择

3. 当监控的地址被写入时，CPU 从 MWAIT 唤醒
```

### CPUID Leaf 5：MWAIT 能力查询

```
CPUID.05H:
  EAX - 最小/最大 monitor-line 大小
  ECX - MWAIT 扩展（中断是否可作为唤醒事件等）
  EDX - C-state substate 信息：
    ┌────────────────────────────────────────────────────────────┐
    │ bit 31:28 │ bit 27:24 │ ... │ bit 7:4   │ bit 3:0        │
    │ C7 subs   │ C6 subs   │     │ C1 subs   │ C0 subs        │
    └────────────────────────────────────────────────────────────┘
    每 4-bit 表示该 C-state 支持的子状态数量
```

当 `cstate_type = 16` 时，`edx >> (16 * 4) = edx >> 64`——这在 x86 上是
**未定义行为**（实际上 x86 的移位操作只取低 5 bit / 6 bit），结果不可预测。

### ACPI C-State 与 MWAIT 的关系

ACPI 定义了两种 C-state 进入方式：
1. **I/O Port**：通过读取特定 I/O 端口进入（传统方式）
2. **FFH（Functional Fixed Hardware）**：通过 MWAIT 进入（现代方式）

当使用 FFH 方式时，ACPI 表中的 `address` 字段就是 MWAIT hint 值。
Linux 通过 `acpi_processor_ffh_cstate_probe_cpu()` 来验证 ACPI 表中声明的
C-state 是否真的被 CPU 硬件支持。

### 虚拟化环境对 ACPI 表的影响

QEMU 等虚拟化平台会动态生成 ACPI 表。由于虚拟 CPU 的能力与物理 CPU 不同，
QEMU 可能生成非标准的 C-state 配置：

```
物理机：ACPI 表由 BIOS/UEFI 提供，通常严格遵循 CPU 规格
虚拟机：ACPI 表由 QEMU 生成，可能包含边界值或非常规组合
```

这就是为什么很多 MWAIT/C-state 相关的 bug 首先在虚拟机中被发现。

### 位运算中的边界值处理原则

在处理硬件编码时，常见的边界值陷阱：

```c
// 陷阱 1：忘记回绕
uint8_t next = current + 1;       // 当 current=255 时溢出为 0（可能期望也可能不期望）

// 陷阱 2：有符号/无符号混淆
int cstate = (hint >> 4) + 1;     // 如果 hint 是 signed，>> 可能是算术移位

// 最佳实践：显式掩码
uint8_t next = (current + 1) & MASK;  // 明确意图，不依赖隐式行为
```

对硬件规范中定义的编码，始终使用显式掩码操作而非依赖溢出行为。
