# Linux 内核 Posted-Write / 跨总线顺序问题案例集（基于 git 历史检索）

本文以 `spi: atmel-qspi: Memory barriers after memory-mapped I/O`（QSPI：AHB 数据 + APB 控制）为主线，将 Linux 内核中与 **posted write**、**读回 flush**、**non-posted MMIO**、**写完成/可见性**相关的典型提交从 git 历史里“捞出”，并按“现象 → 根因 → 快速定位/调试手段 → 修复套路”整理成可复用的排查手册。

相关背景文档（强烈建议先读一遍，很多“读回 flush”的语义这里讲得很清楚）：
- [io_ordering.rst](file:///home/alex/linux-stable/Documentation/driver-api/io_ordering.rst)（MMIO 写入到达顺序、为什么 readback 能 flush）
- [device-io.rst](file:///home/alex/linux-stable/Documentation/driver-api/device-io.rst)（bus-independent I/O、readX(_relaxed) 的语义差异）
- [mmiowb.h](file:///home/alex/linux-stable/include/asm-generic/mmiowb.h)（锁交接场景的 MMIO 写序问题）

---

## 1. 快速检索方法（复现你我刚才的“方式A”）

### 1.1 按 commit message 关键词捞候选
```bash
git log --date=short --pretty=format:'%h %ad %s' -i \
  --grep='posted write' \
  --grep='posted-write' \
  --grep='flush posted' \
  --grep='unblock posted' \
  --grep='Read to clear posted' \
  --grep='Push out posted writes' \
  --grep='non-posted' \
  --grep='write completion' \
  -n 200
```

### 1.2 对候选做“证据链”提取（commit message + diff）
```bash
git show <commit>
```
通常 commit message 会直接写出：“写是 posted，不保证立即生效，因此导致 XXX；通过 readback/屏障 flush。”

---

## 2. 常见根因模型（把复杂问题抽象成 3 类）

### 2.1 posted write 未落地（flush 缺失）
**模型**：`writel()` 之后写入停留在桥/互联写缓冲，软件继续往下走；如果后续逻辑依赖“写已生效”，就会踩时序窗口。

**典型症状**
- 清中断后立刻又被同一中断打断（spurious IRQ / IRQ storm）
- 使能/disable 后立刻进入 suspend / reset / clock gating，导致外设处于半初始化态
- doorbell/command 触发后设备没反应（timeout）

**典型修复**
- `writel*()` 后立刻 `readl*()` 回读（flush posted writes）
- 或在数据通路与控制通路间加 `wmb()/rmb()`（像 QSPI 这种跨通路问题）

### 2.2 non-posted MMIO 需求（映射属性不对）
**模型**：某些硬件要求 MMIO 必须是 non-posted（例如 arm64 的 nGnRnE），否则读/写语义不满足设备要求。

**典型修复**
- 引入 `ioremap_np()`、DT 属性 `nonposted-mmio`，让系统级资源选择 non-posted 映射

### 2.3 “flush 也要讲时机”（过早 readback 反而触发错误/回归）
**模型**：为了 flush posted write，加入 readback；但有的设备在某个窗口内 read 会返回错误值或触发总线错误，导致回归。

**典型修复**
- 推迟 flush（先 delay 再 readback）
- 或移除“读回刚写寄存器”的模式，改用“任意 non-posted read 会 flush”的更温和策略

---

## 3. 典型提交案例（按子系统归类）

下面每条案例都按同一模板描述：
- **现象**：你在产品/日志里看到什么
- **根因**：posted write / 顺序 / 映射属性
- **快速分析/调试**：最小证据链怎么拿
- **修复套路**：readback flush / barrier / non-posted mapping / 限流等

### 3.1 IRQ / 中断控制：清中断写未落地 → 同一 IRQ 再次触发

**A. Renesas RZ/G2L：EOI 写是 posted，导致“刚处理完又被拉起”**
- **Commit**：`9eec61df55c5` — irqchip/renesas-rzg2l: Flush posted write in irq_eoi()
- **现象**：EOI 清 cause 位后，CPU 仍可能立刻再次进入同一中断。
- **根因**：`writel_relaxed()` 清位是 posted，不能保证“立刻清掉”。
- **快速分析/调试**：
  - 现场通常表现为 IRQ 计数飙升、handler 极短驻留、甚至 soft lockup。
  - 最小证据链是“清位后立即 readback；若问题消失则定性为 posted write”。
- **修复套路**：`writel_relaxed()` 后 `readl_relaxed()` 回读同寄存器强制 flush（commit diff 直接说明）。

### 3.2 SoC 互联/复位：enable/disable/reset 的写未落地 → 外设访问 abort / 随机重启

**A. TI SYSC：enable/disable 后缺 flush，导致偶发 interconnect error / reboot**
- **Commit**：`5ce8aee81be6` — bus: ti-sysc: Flush posted write on enable and disable
- **现象**：偶发访问外设报 L3/L4 interconnect error，甚至疑似随机重启（commit message 给了完整堆栈示例）。
- **根因**：模块 enable/disable 写未 flush；后续访问/关时钟发生在错误窗口。
- **快速分析/调试**：
  - 看到 OCP/L3 “Data Access” 类 abort，优先怀疑“时钟/复位/互联 posted write”。
  - A/B：加 readback flush 后问题显著改善即定性。
- **修复套路**：enable/disable 写后 `sysc_read()` flush。

**B. TI SYSC：flush 的“时机”也会引入回归**
- **Commit**：`34539b442b3b` — bus: ti-sysc: Flush posted write on enable before reset
  - **现象**：AM335x 重置 MUSB 模块时出现 external abort（boot regression）。
  - **修复**：enable 后 reset 前 flush posted write。
- **Commit**：`f71f6ff8c1f6` — bus: ti-sysc: Flush posted write only after srst_udelay
  - **现象**：上一条修复在 omap4 duovero 上回归：设备在 delay 之前寄存器不可访问，过早 readback 触发 interconnect error。
  - **修复**：把 flush 放到 `srst_udelay` 之后（先等设备可访问，再 readback）。

### 3.3 pinctrl / wakeirq：使能写没到设备就 suspend → 偶发唤不醒

**A. pinctrl-single：大量 suspend/resume 后 wakeirq 偶发失效**
- **Commit**：`0ac3c0a4025f` — pinctrl: single: Fix missing flush of posted write for a wakeirq
- **现象**：重复 suspend/resume 后，某 pin 的 wakeirq 偶发不工作。
- **根因**：使能中断的写没穿过 interconnect 就进入 suspend。
- **快速分析/调试**：
  - 只在大量循环后出现、加延时概率变化，是强烈的 posted write 指纹。
  - 抓现场：suspend 前后寄存器值是否已生效（注意读可能改变时序，适合做 A/B 定性）。
- **修复套路**：写完 readback flush。

### 3.4 PCIe / posted writes：写合并与 flush 的代价（实时系统会被“批量 flush”卡住）

**A. e1000e：link up/down 更新 MTA 表导致实时系统超时抖动**
- **Commit**：`13e22972471d` — e1000e: Fix real-time violations on link up
- **现象**：实时系统在网卡 link down/up 期间出现几十微秒级别的周期抖动（例如控制周期超时、osnoise 报告延迟尖峰、cyclictest 最大延迟突刺）。这个抖动不一定发生在网卡本身的收发路径，而更常出现在“控制路径”（link 事件处理、重配寄存器）时。
- **根因模型**（posted write 的“吞吐 vs 时延”矛盾）：
  - 更新 MTA（Multicast Table Array）会对同一 BAR 上的寄存器阵列进行大量连续写入。PCIe 写通常是 posted 的，写入会在 root complex/桥/设备侧队列里堆积。
  - 所谓“flush posted writes”在 PCIe 上常通过一次 **PIO read（非 posted read）** 达成；而 PCIe 规则决定：该 read 的完成需要等待前面所有 posted writes 被提交/可见。因此“最后那一次 flush”会把前面的写堆积的等待时间一次性结算，造成 CPU 被阻塞几十微秒甚至更久。
  - 当 interconnect 被这种“批量写 + 一次性 flush”占用时，其他设备的 DMA/doorbell 也会被拖慢，形成系统级干扰（尤其在 PREEMPT_RT/实时系统里更敏感）。
- **如何快速定位（不靠猜，靠证据链）**：
  1. **先确认“尖峰与 link 事件强相关”**：让同事/你自己收集尖峰发生时的 dmesg（link up/down 时间戳）、网络驱动日志（ethtool 或 netlink 状态变化）。若尖峰几乎总与 link 事件同秒出现，这是第一强信号。
  2. **把视角从“丢包/吞吐”切换到“CPU 被阻塞在哪”**：
     - 用 `perf record`/`perf top` 或 ftrace function_graph 观察尖峰时间窗口内，CPU 在哪个函数里停留异常久。
     - 如果栈顶经常落在 e1000e 的 “set_rx_mode / update_mc_addr_list / 写 MTA 阵列”附近，基本锁定方向。
  3. **寻找“批量 MMIO 写 + flush”的结构性模式**：
     - 大量 `writel`/`E1000_WRITE_REG_ARRAY` 连续出现；
     - 某个点插入 `readl`/`POSTING_READ`/`flush`，并且尖峰的主要时间消耗集中在这个 flush（因为它等待前面所有写完成）。
  4. **最小 A/B 证伪实验（工程上最快）**：
     - 把“一次性 flush”改成“分段 flush”（每 N 次写 flush 一次），观察尖峰从“一个大尖峰”变成“多个更小的尖峰”并显著降低峰值。
     - 如果峰值延迟按预期降低，而总配置时长略增，基本可以定性为“posted write 堆积 + 末尾 flush 结算”的问题。
- **代码落点（当前树可直接对照）**：
  - e1000e 更新 MTA 的核心循环在 [mac.c:e1000e_update_mc_addr_list_generic](file:///home/alex/linux-stable/drivers/net/ethernet/intel/e1000e/mac.c#L304-L350)：
    - `E1000_WRITE_REG_ARRAY(hw, E1000_MTA, i, ...)`：连续写 MTA 表项
    - `e1e_flush()`：显式 flush posted writes
    - `CONFIG_PREEMPT_RT` 下的策略：每 8 次写 flush 一次（典型的“限流 flush”）
  - 上层触发路径通常从 [netdev.c:e1000e_set_rx_mode](file:///home/alex/linux-stable/drivers/net/ethernet/intel/e1000e/netdev.c#L3385-L3443) 进入，间接调用 `update_mc_addr_list`。
- **修复套路**：**限流 flush**（每 N 次写做一次 flush），在吞吐与 worst-case latency 之间折中。该策略的本质是把“一个大阻塞点”拆成多个小阻塞点，让峰值延迟可控。

**B. PCI/MSI：MSI-X 表项更新必须“对硬件可见”**
- **Commit**：`b9255a7cb517` — PCI/MSI: Enforce MSI[X] entry updates to be visible
- **现象**（属于“低频但代价很大”的窗口）：
  - 在 MSI/MSI-X setup、或 irq affinity 变更等低频路径中，软件会更新 MSI(-X) message（地址/数据）。
  - 逻辑上很多代码默认“函数返回时硬件已经看到更新”，否则可能出现极难解释的异常：中断投递到旧目标 CPU、短暂丢中断、或者极小概率的乱序行为（实践里往往表现为“偶发且难复现”，所以 commit message 也强调它更偏理论但不该依赖运气）。
- **根因模型**：
  - MSI-X entry 位于设备的 MSI-X table（MMIO/BAR 空间）。对 table 的写是 posted 的；如果不做 flush，函数返回并不保证写已经对设备可见。
  - 某些平台里“后续 unmask 会隐式 flush”，但这属于偶然的同步点，不应作为接口语义。
- **如何分析/定位（偏方法论）**：
  1. **先判断是否落在 MSI/MSI-X 路径**：通过 `/proc/interrupts`、`lspci -vv`（MSI/MSI-X enable）、驱动日志确认中断模式。
  2. **把问题约束在“变更发生的那一刻”**：例如复现只在 irq affinity 切换、热插拔、恢复/挂起后第一次中断等场景出现，优先怀疑“配置写的可见性”。
  3. **做 A/B**：在写 MSI/MSI-X message 后加一次 readback flush（或使用已存在的通用实现），如果异常消失，可把根因收敛到 posted write 可见性。
- **代码落点（当前树可直接对照）**：
  - MSI config space 写后读回 flags 作为“确保写可见”的同步点：[msi.c:pci_write_msg_msi](file:///home/alex/linux-stable/drivers/pci/msi/msi.c#L194-L207)
  - MSI-X table 写后读回 ENTRY_DATA 作为 flush：[msi.c:pci_write_msg_msix](file:///home/alex/linux-stable/drivers/pci/msi/msi.c#L209-L237)
- **修复套路**：在函数返回前显式 flush（即使可能冗余）。这类路径低频，宁可付出一点点额外读的成本，也要把接口语义做实，避免把“极低概率的不一致”留给用户现场。

### 3.5 “non-posted MMIO”体系化支持（从 SoC 级把坑填平）

**A. 引入 ioremap_np() 与 IORESOURCE_MEM_NONPOSTED**
- **Commit**：`7c566bb5e4d5` — asm-generic/io.h: Add a non-posted variant of ioremap()
- **价值**：把“某些设备必须 non-posted”从驱动细节提升为资源属性，避免每个驱动自己特判。

**B. DT 属性：nonposted-mmio**
- **Commit**：`89897f739d7b` — of/address: Add infrastructure to declare MMIO as non-posted
- **价值**：从设备树标注总线/子设备需要 non-posted 映射，系统自动选择 `of_iomap()` / `devm_ioremap_resource()` 的 NP 变体。

### 3.6 “不要盲目读回”：读回也会引发新问题

**A. NVMe：移除 CC 寄存器读回避免短暂返回 0 破坏配置**
- **Commit**：`9064610348b1` — nvme: remove CC register read-back during enabling
- **现象**：某些控制器在短窗口内读 CC 会返回 0，读回逻辑反而把合法配置覆盖掉，导致后续 enable 失败。
- **修复套路**：不再“读回刚写的寄存器”，依赖任意 non-posted read 的 flush 语义（更温和、更少副作用）。

### 3.7 “不是所有 flush 都值得”：过度 flush 可能纯属性能/时序负担

**A. xHCI：移除不必要的 IRQ_PENDING 读与 posted write 等待**
- **Commit**：`27e0dd4d7ccc` — USB: xhci: Remove unnecessary reads of IRQ_PENDING register.
- **现象/动机**：驱动在中断路径中多余地读寄存器并等待 posted write 完成；作者判断 host 最终会看到该写，硬件也会在决定是否再次中断前自行读取寄存器，从而隐式 flush。
- **修复套路**：删除冗余 read/wait，减小中断路径开销。

---

## 4. 从 QSPI 案例到通用排查套路

QSPI 案例的关键边界在当前代码树中非常清晰（已包含修复）：[atmel-quadspi.c](file:///home/alex/linux-stable/drivers/spi/atmel-quadspi.c#L650-L682)
- “Dummy read flush（方向 A）”：`(void)atmel_qspi_read(aq, QSPI_IFR);`
- “数据通路 AHB → 控制通路 APB 的反向同步（方向 B）”：`wmb()/rmb()`
- “控制命令”：`QSPI_CR_LASTXFER`

这类问题的通用快法（不依赖仪器也能快速定性）：
1. **A/B：延时或重复写**（如果显著改善，强烈指向 posted write/顺序）
2. **A/B：加 `wmb()`/readback flush**（若立刻稳定，基本定性）
3. **把观测放到超时/错误路径**（避免在热路径 readl() 改变时序）

---

## 5. 进一步扩展（下一轮可做）

本文目前以“posted write / flush”关键词为主抓取代表提交。下一步可以进一步：
- 把 “doorbell”/“ring”/“kick”/“write combining” 等关键词加入检索，覆盖 GPU/网卡/加速卡的 ringbell 类问题。
- 把 “APB/AHB/AXI/interconnect” 关键词加入检索，筛出更纯粹的跨通路案例。
