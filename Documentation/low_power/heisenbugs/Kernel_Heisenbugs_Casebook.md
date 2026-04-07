# Linux 内核“海森堡故障”案例集：现象、根因与调试方法论

本文整理一批在本仓库历史中出现的、典型具有“海森堡特征”的 Linux 内核故障修复提交，并总结它们背后的共性原因与分析路径。

海森堡故障（Heisenbug）的典型特征是：
- 复现高度依赖时序、负载、CPU 拓扑、IRQ 嵌套、缓存状态等细节
- 加 `printk()`、插入延时、打开调试选项后反而“好了/变了”
- 可能只在特定架构（尤其是弱内存序的 arm64/ppc）或特定硬件上出现
- 常见外在表现：偶发死锁/卡死、偶发数据损坏、偶发丢包、偶发 spurious IRQ、偶发丢唤醒

---

## 1. 案例目录（来自本仓库 git 历史）

下面列出若干具有代表性的“时序/可见性/屏障/竞态”修复提交（commit id + 标题 + 关键点）。

### 1.1 上下文同步（Context Synchronization）/ 指令可见性（ISB）

**A. GIC 分发中断：ack 到 handler 之间缺失 ISB 导致读到 stale system register**
- `39a06b67c2c1256b` — irqchip/gic: Ensure we have an ISB between ack and ->handle_irq
  - 关键点：对通过 system register 暴露中断状态的设备（PMU、arch timer、profiling）需要 CSE（上下文同步事件），否则 handler 可能读到旧状态。
- `adf14453d2c037ab` — irqchip/gic-v3: Ensure pseudo-NMIs have an ISB between ack and handling
  - 关键点：pseudo-NMI（常用于 PMU）路径同样需要 ISB；否则会出现采样丢失、spurious、甚至 NMI 风暴。

**B. CoreSight/ETM：sysreg 编程后读取状态寄存器需 ISB**
- `1ab3bb9df5e35183` — coresight: etm4x: Add necessary synchronization for sysreg access
  - 关键点：规范要求写 TRCPRGCTLR 后必须有 CSE（显式 ISB）才能可靠读取 TRCSTATR。
- `aea631a30c0e8908` — coresight-etm4x: add isb() before reading the TRCSTATR
  - 关键点：进一步补齐 ISB（包括 timeout 轮询场景），防止状态读取不稳定。

**C. 自修改代码 / 指令 patching：其他 CPU 需要 ISB 才能稳定看到新指令流**
- `04b8637be92f2844` — arm64: alternatives: ensure secondary CPUs execute ISB after patching
  - 关键点：指令流被 patch 后，必须让每个执行该代码的 CPU 进行 ISB 或等效的上下文同步事件。
- `8e88fc33d42c3fe8` — arm64: jump_label: Ensure patched jump_labels are visible to all CPUs
  - 关键点：并发修改/执行 NOP/branch 允许，但仍要求同步，避免某些 CPU 处于“旧/新代码混合”的 limbo 状态。

**D. TLB/页表行走缓存：缺 ISB 可能导致页表相关操作偶发异常**
- `d6984c21d8154ca0` — arm64: tlb: Ensure we execute an ISB following walk cache invalidation
  - 关键点：TLBI 后缺少架构要求的 ISB，可能导致后续执行看到旧的翻译/行走缓存状态。

**E. PowerPC 类似问题：缺失 isync 导致安全属性/执行上下文更新不可靠**
- `e993b8a59cc284ca` — powerpc/64s/kuap: Add missing isync to KUAP restore paths
  - 关键点：写 AMR（访问权限相关）前后需要上下文同步类操作，否则可能出现“权限更新未按预期生效”的时序窗口。

### 1.2 内存顺序（Memory Ordering）/ 丢唤醒（Missing Wakeup）

**A. 文件系统：缺 wakeup 或 wakeup 前缺必要的 release 语义，导致偶发挂死**
- `2ad02e607c83a4df` — bcachefs: Add missing wakeup to bch2_inode_hash_remove()
  - 关键点：等待队列使用方式变化/锁粒度放松后，需要重新检查条件并补齐 wakeup；否则等待者偶发睡死。
- `8822e8c5d1a2bf25` — NFS: Fix wakeup of __nfs_lookup_revalidate() in unblock_revalidate()
  - 关键点：wakeup 前需要合适的内存屏障（使用 store_release_wake_up），否则对方线程被唤醒但看不到条件更新。

**B. 通用调度/唤醒接口：帮助减少易错的 wake_up_bit/var 模式**
- `ac9a6b86382773ab` — sched: Add test_and_clear_wake_up_bit() and atomic_dec_and_wake_up()
  - 关键点：把“清状态 + 唤醒”的常见组合封装成原语，避免遗漏/滥用屏障（也减少 fragile 接口使用）。

### 1.3 总线/外设侧的排序与屏障（MMIO 跨总线）

**A. 同一外设寄存器与数据通路分属不同总线：缺屏障导致偶发异常**
- `3aa576f1d77dd9af` — spi: atmel-qspi: Memory barriers after memory-mapped I/O
  - 关键点：控制/状态寄存器走 APB，但数据 MMIO 走 AHB；厂商文档要求在关键点插屏障，否则可能出现偶发读写异常。

### 1.4 网络栈/软中断：状态机与并发窗口导致偶发死锁/挂死

**A. netpoll/netconsole 与 NAPI 并发：极难复现的 NAPI 挂死**
- `b4a23cb22ce32920` / `c0e32ec90a9ab3d6` — netpoll: prevent hanging NAPI when netcons gets enabled
  - 关键点：仅在多测试串行执行时出现；表面像 double-disable，实则是 NAPI 状态与 poll_list 不一致的竞态窗口。

### 1.5 SMP/上电/热插拔：启动时序/CPU hotplug 相关的偶发挂死

**A. Rockchip SMP bringup：二级 CPU 执行 trampoline 时序竞态导致偶发卡死**
- `47769dab9073a73e` — ARM: rockchip: fix kernel hang during smp initialization
  - 关键点：主核向 SRAM 写 trampoline 时二级核已上电，偶发提前执行导致 hang；修复为调整初始化时序。

### 1.6 “反海森堡”工具性提交：人为增大竞态概率以便抓虫

**A. RCU：随机延时扩大碰撞截面（anti-heisenbug）**
- `661a85dc0d2ec040` — rcu: Add random PROVE_RCU_DELAY to grace-period initialization
  - 关键点：通过随机延时提高竞态发生概率，让原本极低概率的 bug 更容易在测试中暴露。

---

## 2. 这些海森堡故障的共性根因

把上面的案例抽象一下，常见根因集中在以下几类：

### 2.1 “可见性”与“顺序”的错觉
- 弱内存序架构上，CPU/编译器可以重排普通读写
- device/outer shareable/inner shareable 域不同，外设侧也可能存在重排/缓冲
- 解决手段：`READ_ONCE/WRITE_ONCE`、`smp_store_release/smp_load_acquire`、`smp_mb/rmb/wmb`、必要时 `dmb/dsb`

### 2.2 system register / 自修改代码需要“上下文同步事件”
- 对 sysreg 的写入或某些间接更新，需要 CSE 才能保证后续指令读取/执行看到新状态
- 指令 patching 后，其他 CPU 需要 ISB 或等效事件才能执行到新指令流
- 解决手段：`isb()`（或架构等价指令，如 powerpc `isync`），配合 cache maintenance 与 stop_machine/CPU rendezvous

### 2.3 条件变量 + wakeup 的经典丢唤醒窗口
- 条件检查、入队等待、条件更新、wakeup 的顺序稍有问题就会“偶发睡死”
- 修复常见套路：循环检查条件、使用 wait_event 系列原语、在更新条件时用 release 语义并配合 wakeup

### 2.4 状态机并发与不可见的“中间态”
- 像 NAPI 这类状态机通常需要保证多个字段一致性；竞态窗口可能让字段组合进入“非法但短暂存在”的状态
- 解决手段：更严格的锁/原子性、把状态转换做成单点、增加断言/tracepoint 观测中间态

---

## 3. 一套可复用的分析方法（SOP）

### 3.1 先做“定性”：这是逻辑 bug 还是时序/并发 bug？
- 加 `printk()`/打开调试选项后复现率显著变化：强烈指向时序/并发/可见性问题
- 只在某架构/某 SoC 出现：优先怀疑屏障/一致性域/系统寄存器同步要求

### 3.2 现场证据：确定卡在“谁”身上
- `dmesg`：soft lockup、RCU stall、hung task、irq nobody cared、spurious 等关键字
- `/proc/interrupts`：中断计数是否异常飙升（IRQ 风暴）
- 堆栈：是否反复出现在 irq handler、软中断、锁等待、RCU grace period

### 3.3 尽量用“无侵入式观测”
侵入式方法（断点/单步/大量打印）会改变时序，从而掩盖海森堡故障。
- 软件侧：ftrace/tracepoint（如 `irq_handler_entry/exit`、sched、workqueue、rcu）
- 并发检查：KCSAN、lockdep
- 内存问题：KASAN/KFENCE（对 UAF/越界更有效）
- 硬件侧：CoreSight ETM（指令流追踪）、perf event（注意本身也会改变时序）、JTAG halt 只用于“卡死现场快照”

### 3.4 快速提出“可证伪的假设”
例如：
- “缺少 release 语义导致被唤醒线程看不到条件更新”
- “TLBI 后缺少 ISB 导致页表相关状态不一致”
- “IAR ack 与 handler 之间缺少 ISB 导致 sysreg 状态 stale”

然后用最小改动进行验证（添加/移动屏障、改为原语、加 tracepoint），并用压力/长稳测试闭环。

---

## 4. 常用调试工具与适用场景

- **ftrace/tracepoints**：观察高频事件、IRQ 进入退出、调度、锁等待；对海森堡故障最友好
- **KCSAN**：数据竞争检测（对“缺锁/缺屏障”的竞态非常有效）
- **lockdep**：锁依赖死锁链路定位
- **KASAN/KFENCE**：UAF/越界导致的“偶发炸裂”
- **CoreSight ETM**：需要最强证据链时使用；可看到真实指令流与路径
- **JTAG+GDB**：用于卡死现场快照（看 PC/堆栈/寄存器），不擅长复现时序竞态

