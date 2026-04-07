# 2023：Interconnect 带宽路径持 `icc_lock` 与内存回收形成锁链死锁

## 1. 提交基础信息

- **Commit ID**：`af42269c3523492d71ebbe11fefae2653e9cdc78`
- **标题**：`interconnect: Fix locking for runpm vs reclaim`
- **作者**：Rob Clark（Google）
- **涉及子系统**：`drivers/interconnect/`、Qualcomm Adreno GPU、**runtime PM**、`mm` reclaim
- **关键词**：`icc_lock`、`icc_bw_lock`、`dma_fence`、`mmu_notifier`、`fs_reclaim`

## 2. 背景信息

- **interconnect（ICC）框架**在 **设置带宽**（`icc_set_bw`）时需持锁做聚合；在 **创建/注册节点**时可能 **`kmalloc`**，进而触发 **内存回收**。
- **GPU runtime resume** 路径会调 **`icc_set_bw`**；而 **页面回收/mmu_notifier** 路径可能 **反向**拿 **fence/map** 相关锁。
- 当 **`icc_lock`** 同时保护 **“会进入 reclaim 的节点创建”** 与 **“runtime resume 带宽更新”**，就可能形成 **多级锁链环**（lockdep 报告的 **5 层反转**）。

**为何与低功耗强相关**：问题由 **runtime PM resume** 触发；表现为 **GPU 压力 + 内存紧张** 时随机卡死。

## 3. 故障现象

- **lockdep** 报告 **possible circular locking dependency**；实机可能 **GPU 提交卡死**、**整机间歇失去响应**。
- Chromebook（如 sc7280 / Lazor）类设备上被重点修复。

## 4. 复现手法

1. 高通类平台 + **重 GPU + 低内存**（限制 cgroup memory 或并行分配）。
2. 运行 **图形负载** 同时触发 **大量 mmap/fault**。
3. 在 **lockdep** 内核上优先以 **警告复现**；无 lockdep 时依赖 **长时间压测**。

## 5. 调试方法

- **完整阅读 lockdep 反向链**：从 `icc_set_bw` → `icc_lock` → … → `fs_reclaim`。
- **区分两类临界区**：
  - **拓扑/节点创建**（可能睡眠、分配内存）；
  - **带宽聚合更新**（应在 **非 reclaim** 锁域完成）。

## 6. 解决办法

- 引入第二把锁 **`icc_bw_lock`**：**带宽更新**只持 `icc_bw_lock`；**节点增删/同步**用 `icc_lock`，必要处 **短程双持**保证一致性。
- 使 **`icc_set_bw()`** 不进入 **需 reclaim 的锁域**，从而与 **runpm** 安全共存。

**修复原理**：**“会触发 reclaim 的锁”** 与 **“设备电源/性能关键路径上的锁”** 必须分离；这是 Linux 内核 **mm 与 PM 交互**的通用纪律。

## 7. 经验总结

- **在持锁路径调用可能睡眠或 kmalloc 的 API** 前，先问：**这把锁会不会在 reclaim 中被拿到？**
- lockdep 的价值不仅是 **报 bug**，更是 **强制画出锁序图**。
