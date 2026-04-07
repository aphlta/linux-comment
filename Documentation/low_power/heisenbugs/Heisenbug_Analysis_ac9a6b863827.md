# 深度解析：内核调度器 Wakeup 丢失与内存序问题

## 1. 提交基础信息
* **Commit IDs**: 
  - `ac9a6b863827` ("sched: Add test_and_clear_wake_up_bit() and atomic_dec_and_wake_up()")
  - 相关联的 NFS 修复提交：`8822e8c5d1a2` ("NFS: Fix wakeup of __nfs_lookup_revalidate() in unblock_revalidate()")
* **涉及子系统**: kernel/sched (调度器等待队列机制 / Wait-Bit)
* **核心关键词**: Memory Ordering, SMP, `smp_mb()`, `wake_up_var`, Missing Wakeup.

## 2. 背景知识支持 (Background)
* **等待/唤醒机制 (Wait-Queue)**：Linux 内核中最常见的同步原语。线程 A 调用 `wait_event()` 挂起，线程 B 在某个条件满足后调用 `wake_up()` 唤醒线程 A。
* **无锁等待 (Wait on Bit/Var)**：为了极高的性能，内核经常不使用互斥锁，而是直接用一个标志位或变量表示状态（如 `wait_on_bit`，`wait_var_event`）。
* **SMP 内存模型中的“读写重排”陷阱**：
  - **线程 A (Wait)**：先将自己加入等待队列（修改队列状态，这是一个 Store），然后检查变量条件是否满足（Load）。如果不满足，则休眠。
  - **线程 B (Wake)**：先修改变量条件（Store），然后去检查等待队列里有没有人（Load），有的话就唤醒。
  - **灾难**：如果 CPU 或编译器打乱了 Load 和 Store 的顺序（在 ARM/PowerPC 等弱一致性架构上非常常见），可能出现：线程 A 刚读了条件（不满足），准备加队列；线程 B 刚查了队列（没人），准备写条件。**结果线程 A 永久睡死（Missing Wakeup）**。

## 3. 故障现象 (Symptoms)
典型的死锁或永久挂起 (Hung Task)。
例如在 NFS（网络文件系统）的 `__nfs_lookup_revalidate()` 场景中，进程访问文件时被阻塞在某个标志位上，而负责清除该标志位的线程已经执行完了清除操作并退出了，但被阻塞的进程却再也没有醒过来。系统日志中会出现 `task xxx blocked for more than 120 seconds`。

## 4. 根因分析 (Root Cause)
在非原子的变量唤醒场景中，常见的错误代码模式如下：
```c
// 线程 B 的唤醒操作（Bug 版）
*var = new_value;         // Store 1
wake_up_var(var);         // 内部包含 Load 去检查队列
```
在弱一致性架构下，CPU 可能会先把 `wake_up_var()` 里的队列读取操作（Load）提前执行，然后再执行 `*var = new_value`（Store）。
这就导致了致命的时间窗口：它去查等待队列时，线程 A 还没来得及把自己挂上去；查完之后，它才更新 `*var`。线程 A 随后挂上队列去读 `*var`，由于时序交错，错过了更新。

## 5. 调试与观测手段 (Debugging)
内存序导致的丢失唤醒是极难调试的。
* **观测**：通过 `cat /proc/<pid>/stack` 或者 `sysrq-t` 查看挂起进程的堆栈，发现它停在 `wait_var_event` 或者 `wait_on_bit`。
* **验证猜想**：如果在更新变量和唤醒之间强行加一句 `smp_mb()` (全量内存屏障)，重新编译内核后压力测试，如果 Hung Task 不再出现，则 100% 确诊为内存序导致的 Wakeup 丢失。

## 6. 修复方案解析 (The Fix)
NeilBrown 和 Peter Zijlstra（调度器核心维护者）在这个提交中并不是只修了某一处，而是**从框架层面引入了安全的标准 API**，以防后续的驱动开发者继续踩坑。

他们引入了宏 `store_release_wake_up`：
```c
#define store_release_wake_up(var, val)                 \
do {                                                    \
       smp_store_release(var, val);                     \
       smp_mb();                                        \
       wake_up_var(var);                                \
} while (0)
```
**修复原理**：
1. `smp_store_release` 保证了在这个变量更新之前的所有内存写操作，对其他 CPU 都是可见的。
2. **核心防御：`smp_mb()`**。这是一个重量级的全量内存屏障。它强行阻断了 CPU 乱序执行的可能，确保**“修改变量 (Store)” 绝对先于 “读取等待队列状态 (Load)” 发生**。
只要唤醒端严格遵守 `Store -> smp_mb() -> Load`，配合等待端的 `Store(加队列) -> smp_mb() -> Load(查变量)`，就构成了经典的 Dekker 算法防线，彻底杜绝了并发盲区，解决了 Missing Wakeup 问题。