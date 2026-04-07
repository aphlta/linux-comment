# 深度解析：Netpoll 与 NAPI 状态机并发死锁 (Hang)

## 1. 提交基础信息
* **Commit ID**: `b4a23cb22ce3` ("netpoll: prevent hanging NAPI when netcons gets enabled")
* **作者**: Jakub Kicinski (网络子系统核心维护者)
* **涉及子系统**: net/core (网络收发核心 NAPI 与 Netpoll 机制)
* **核心关键词**: NAPI, Netpoll, State Machine, RCU, Race Condition.

## 2. 背景知识支持 (Background)
* **NAPI (New API)**：Linux 内核网络协议栈处理高频网络包的核心机制。为了避免中断风暴，网卡在收到第一个包时触发中断，内核随即关闭中断，并把该网卡的 NAPI 实例挂到 CPU 的轮询列表（Poll List）里，标记为 `SCHED`（已调度）。随后内核在一个软中断上下文中循环拉取数据包（`napi_poll`），直到没有包了再重新打开硬件中断并调用 `napi_complete_done` 清除 `SCHED` 标志并将其从轮询列表中摘除。
* **Netpoll (Netconsole)**：一种在极端情况下（如内核 Crash/Oops 导致中断失效）仍能通过网络发送内核日志的机制。它为了能强行把包发出去，会**绕过正常的软中断调度，直接去抢占 NAPI 的轮询权**。
* **NPSVC (NetPoll SerViCing) 标志的历史渊源**：早在 2008 年（Commit `7b363e440021`），内核开发者发现如果 Netpoll 强行调用网卡 `napi->poll`，并在结束时执行 `napi_complete`，会错误地将 NAPI 实例从**其他正常处理它的 CPU** 的链表上强行摘除，导致链表破坏崩溃。为了修复这个漏洞，内核引入了 `NAPI_STATE_NPSVC` 标志：当 Netpoll 抢占时会设置该标志。如果正常的 `napi_complete` 看到这个标志，就知道有大佬（Netpoll）在办事，**自己就会直接退出，绝对不去碰链表，也不清除 `SCHED` 标志**（把清理工作留给最初挂载它的软中断）。这个“保护链表”的防御性设计，正是本次 2025 年僵尸 Bug 的伏笔。

## 3. 故障现象 (Symptoms)
这是一个极其难以复现的条件竞争（Race Condition），只有在自动化测试套件高强度并发运行 `xdp`、`netconsole`、`netpoll` 测试用例时才会偶尔触发。
* **现象**：测试脚本卡死，关闭虚拟网卡（`virtnet_close`）时进程 Hang 住了。
* **现场状态**：用调试手段检查发现，某个 NAPI 实例处于一种**“精神分裂”**的僵尸状态：
  - `disabled: false` (没有被禁用)
  - `state` 包含 `SCHED` (认为自己正在被调度执行)
  - `poll_list: empty` (但实际上 CPU 的执行队列里根本没有它)
因为状态机错乱，内核关闭网卡时试图等待 NAPI 优雅退出，结果陷入了死等。

## 4. 根因分析 (Root Cause)
Jakub 抽丝剥茧还原了一个极其刁钻的时序窗口。这个窗口发生在**动态开启 Netpoll 的瞬间**。

```text
  [CPU 1: 正常网络收发]                        [CPU 2: 突然开启 Netpoll/Netconsole]
  napi_poll()
    // 1. 检查是否有 netpoll 在运行
    have = netpoll_poll_lock() 
      rcu_access_pointer(dev->npinfo) 
        return NULL // 此时 netpoll 还没完全建好，返回 NULL，不用锁
    
    // 2. 正常开始拉包
    __napi_poll()
      ->poll(->weight)
                                             // 3. CPU 2 恰好在这个瞬间完成了 netpoll_setup
                                             // 并立刻触发了 poll_napi() 强行收发包
                                             poll_napi()
                                               // 4. 设置 NPSVC 标志，表示 Netpoll 接管了
                                               set_bit(NAPI_STATE_NPSVC, ->state)

      // 5. CPU 1 拉包结束，准备收尾
      napi_complete_done()
        // 6. 检查状态，发现竟然有 NPSVC 标志！
        if (NAPIF_STATE_NPSVC)
           return false; // 误以为是被 Netpoll 抢占了，直接退出！
        // 灾难：CPU 1 没有清除 SCHED 标志，也没有把自己加回任何队列。
```
**死锁形成**：
CPU 1 的正常 NAPI 线程看到 `NPSVC` 标志，触发了内核在 2008 年（Commit `7b363e440021`）为了防止链表损坏而写下的防御逻辑：**"如果有 Netpoll 介入，不要去碰 poll_list 链表，也不要清 SCHED 标志，直接退出"**。
于是 CPU 1 以为 CPU 2 会负责善后，拍拍屁股走人了。
但实际上，CPU 2 的 Netpoll 按照设计只是临时发个包，它根本不负责清理 `SCHED` 标志。
最终，这个 NAPI 实例带着 `SCHED` 标志成了“三不管”的孤魂野鬼，永远不会再被调度。

## 5. 调试与观测手段 (Debugging)
这是一个典型的靠“推演”和“防御性编程验证”破案的例子。
* 作者通过 `Crash` 或 `GDB` 解析出 NAPI 结构体的内部状态字（`state: 0x37`），解码后发现 `SCHED` 被置位但不在任何链表上。
* 结合测试用例包含了 `netcons`，推导出了上述的 Race Window。
* **终极验证法**：在代码里加了一个极度针对性的 `WARN_ONCE`，专门去抓“我进来时没有 netpoll，但我执行完时突然有了 netpoll”这个极小概率事件。一旦这个 Warning 触发，紧接着必定发生网卡卡死，从而实锤了理论推导。

## 6. 修复方案解析 (The Fix)
修复非常巧妙，只需一行代码。在 `netpoll_setup()`（即创建并暴露 `dev->npinfo`）的末尾，加上：
```c
        rtnl_unlock();
+
+       /* Make sure all NAPI polls which started before dev->npinfo
+        * was visible have exited before we start calling NAPI poll.
+        * NAPI skips locking if dev->npinfo is NULL.
+        */
+       synchronize_rcu();
+
        return 0;
```
**修复原理**：
利用 RCU 的**宽限期 (Grace Period)** 机制，在“旧世界”与“新世界”之间建立一道时空隔离墙。

1. **RCU 读临界区**：由于正常的 `napi_poll` 运行在 SoftIRQ（软中断）上下文中，这在内核中天然被视为一个 RCU 读临界区。
2. **强制同步 (synchronize_rcu)**：当 `netpoll_setup` 将 `dev->npinfo` 挂载上去（对其他 CPU 可见）后，立刻调用 `synchronize_rcu()` 阻塞等待。
3. **消除重叠窗口**：
   - 如果 CPU 1 在 `npinfo` 挂载前已经进入了 `napi_poll`（处于“旧世界”），它会以无锁状态运行。
   - 此时，CPU 2 执行到 `synchronize_rcu()` 会被强制按住（休眠），**直到 CPU 1 彻底退出软中断为止**。
   - 这保证了 CPU 2 绝不会在 CPU 1 还在干活时就跑去设置 `NPSVC` 标志。
   - 当 `synchronize_rcu()` 返回时，所有按“旧规则”办事的 CPU 都已退场。此后进入的所有 CPU 都会看到新的 `npinfo` 并走正确的加锁逻辑。

这就从根本上杜绝了“CPU 1 以无锁状态进入，却在执行中途遭到 CPU 2 强行设置 `NPSVC` 标志并背刺”的重叠窗口。该修复的精妙之处在于：**它没有在极端高频的收发包路径（napi_poll）中增加任何锁开销，而是将同步代价转移到了极低频的配置路径（开启 Netpoll 时）上。**