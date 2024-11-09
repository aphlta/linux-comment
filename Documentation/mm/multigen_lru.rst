.. SPDX-License-Identifier: GPL-2.0

=============
Multi-Gen LRU
=============
The multi-gen LRU is an alternative LRU implementation that optimizes
page reclaim and improves performance under memory pressure. Page
reclaim decides the kernel's caching policy and ability to overcommit
memory. It directly impacts the kswapd CPU usage and RAM efficiency.

# 多代LRU（Least Recently Used）是一种替代的LRU实现方案，旨在优化页面回收过程并提升内存压力下的性能。
# 页面回收决定了内核的缓存策略及其内存过量分配的能力，直接影响kswapd（内核内存管理的一部分）的CPU使用率和RAM的效率。

Design overview
===============
Objectives
----------
The design objectives are:

* Good representation of access recency
* Try to profit from spatial locality
* Fast paths to make obvious choices
* Simple self-correcting heuristics

The representation of access recency is at the core of all LRU
implementations. In the multi-gen LRU, each generation represents a
group of pages with similar access recency. Generations establish a
(time-based) common frame of reference and therefore help make better
choices, e.g., between different memcgs on a computer or different
computers in a data center (for job scheduling).

Exploiting spatial locality improves efficiency when gathering the
accessed bit. A rmap walk targets a single page and does not try to
profit from discovering a young PTE. A page table walk can sweep all
the young PTEs in an address space, but the address space can be too
sparse to make a profit. The key is to optimize both methods and use
them in combination.

Fast paths reduce code complexity and runtime overhead. Unmapped pages
do not require TLB flushes; clean pages do not require writeback.
These facts are only helpful when other conditions, e.g., access
recency, are similar. With generations as a common frame of reference,
additional factors stand out. But obvious choices might not be good
choices; thus self-correction is necessary.

The benefits of simple self-correcting heuristics are self-evident.
Again, with generations as a common frame of reference, this becomes
attainable. Specifically, pages in the same generation can be
categorized based on additional factors, and a feedback loop can
statistically compare the refault percentages across those categories
and infer which of them are better choices.
设计目标：

良好的访问近期性表示
尝试利用空间局部性
快速做出明显选择的路径
简单的自我纠正启发式规则

访问近期性的表示是所有LRU（最近最少使用）实现的核心。在多代LRU中，每一代代表一组具有相似访问近期性的页面。代际之间建立了时间上的共同参考框架，从而有助于做出更好的选择，例如，在计算机上的不同内存控制组（memcg）之间或数据中心中的不同计算机之间进行作业调度。

利用空间局部性在收集访问位时提高了效率。rmap遍历针对单个页面，并不试图从发现年轻的页面表项（PTE）中获益。页面表遍历可以扫过地址空间中所有年轻的PTE，但地址空间可能过于稀疏而无法获得收益。关键在于优化这两种方法并结合使用它们。

快速路径减少了代码复杂性和运行时开销。未映射的页面不需要TLB（Translation Lookaside Buffer）刷新；干净的页面不需要回写。这些事实只有在其他条件（例如访问近期性）相似时才有帮助。有了代际作为共同的参考框架，其他因素就显得更加突出。但明显的最佳选择未必是好的选择，因此自我纠正变得必要。

简单自我纠正启发式规则的好处是显而易见的。同样，有了代际作为共同的参考框架，这一点变得可行。具体来说，同一代的页面可以根据其他因素进行分类，反馈循环可以统计比较这些类别的重故障率，并推断出哪些类别是更好的选择。

Assumptions
-----------
The protection of hot pages and the selection of cold pages are based
on page access channels and patterns. There are two access channels:

* Accesses through page tables
* Accesses through file descriptors

The protection of the former channel is by design stronger because:

1. The uncertainty in determining the access patterns of the former
   channel is higher due to the approximation of the accessed bit.
2. The cost of evicting the former channel is higher due to the TLB
   flushes required and the likelihood of encountering the dirty bit.
3. The penalty of underprotecting the former channel is higher because
   applications usually do not prepare themselves for major page
   faults like they do for blocked I/O. E.g., GUI applications
   commonly use dedicated I/O threads to avoid blocking rendering
   threads.

There are also two access patterns:

* Accesses exhibiting temporal locality
* Accesses not exhibiting temporal locality

For the reasons listed above, the former channel is assumed to follow
the former pattern unless ``VM_SEQ_READ`` or ``VM_RAND_READ`` is
present, and the latter channel is assumed to follow the latter
pattern unless outlying refaults have been observed.
# 热页面的保护与冷页面的选择基于页面访问渠道和模式
# 存在两种访问渠道：
#
# * 通过页表进行访问
# * 通过文件描述符进行访问
#
# 前者渠道的设计保护更强，原因如下：
#
# 1. 由于访问位的近似性，确定前者渠道访问模式的不确定性更高。
# 2. 前者渠道的驱逐成本更高，因为需要进行TLB刷新，并且可能会遇到脏位。
# 3. 对前者渠道保护不足的代价更高，因为应用程序通常不会像处理阻塞I/O那样准备应对主要页面故障。例如，GUI应用程序通常使用专用的I/O线程以避免阻塞渲染线程。
#
# 还存在两种访问模式：
#
# * 展现时间局部性的访问
# * 不展现时间局部性的访问
#
# 基于以上原因，假设前者渠道遵循前者模式，除非存在``VM_SEQ_READ``或``VM_RAND_READ``；并且假设后者渠道遵循后者模式，除非已观察到异常的重新故障。

Workflow overview
=================
Evictable pages are divided into multiple generations for each
``lruvec``. The youngest generation number is stored in
``lrugen->max_seq`` for both anon and file types as they are aged on
an equal footing. The oldest generation numbers are stored in
``lrugen->min_seq[]`` separately for anon and file types as clean file
pages can be evicted regardless of swap constraints. These three
variables are monotonically increasing.

Generation numbers are truncated into ``order_base_2(MAX_NR_GENS+1)``
bits in order to fit into the gen counter in ``folio->flags``. Each
truncated generation number is an index to ``lrugen->folios[]``. The
sliding window technique is used to track at least ``MIN_NR_GENS`` and
at most ``MAX_NR_GENS`` generations. The gen counter stores a value
within ``[1, MAX_NR_GENS]`` while a page is on one of
``lrugen->folios[]``; otherwise it stores zero.

Each generation is divided into multiple tiers. A page accessed ``N``
times through file descriptors is in tier ``order_base_2(N)``. Unlike
generations, tiers do not have dedicated ``lrugen->folios[]``. In
contrast to moving across generations, which requires the LRU lock,
moving across tiers only involves atomic operations on
``folio->flags`` and therefore has a negligible cost. A feedback loop
modeled after the PID controller monitors refaults over all the tiers
from anon and file types and decides which tiers from which types to
evict or protect. The desired effect is to balance refault percentages
between anon and file types proportional to the swappiness level.

There are two conceptually independent procedures: the aging and the
eviction. They form a closed-loop system, i.e., the page reclaim.
# 可驱逐页面被划分为多个世代，每个 lruvec 作为一个单元
# 对于匿名和文件类型，最年轻世代的编号存储在 lrugen->max_seq 中，它们在老化时平等对待
# 最老世代的编号分别存储在 lrugen->min_seq[] 中，匿名和文件类型分开存储，因为干净的文件页面可以不顾交换限制被驱逐
# 这三个变量是单调递增的

# 为了适应 folio->flags 中的 gen 计数器，世代编号被截断为 order_base_2(MAX_NR_GENS+1) 位
# 每个截断的世代编号是 lrugen->folios[] 的索引
# 滑动窗口技术用于跟踪至少 MIN_NR_GENS 和最多 MAX_NR_GENS 个世代
# 当页面位于 lrugen->folios[] 中之一时，gen 计数器存储一个在 [1, MAX_NR_GENS] 范围内的值；否则，它存储零

# 每个世代又分为多个层级
# 通过文件描述符访问 N 次的页面位于 tier order_base_2(N)
# 与世代不同，层级没有专门的 lrugen->folios[]
# 与跨世代移动需要 LRU 锁不同，跨层级移动仅涉及 folio->flags 的原子操作，因此成本极低
# 类似于 PID 控制器的反馈回路监控所有层级的匿名和文件类型的重故障，并决定从哪些类型的哪些层级驱逐或保护页面
# 期望的效果是根据交换性水平在匿名和文件类型之间平衡重故障百分比

# 存在两个概念上独立的程序：老化和驱逐
# 它们形成了一个闭环系统，即页面回收
Aging
-----
The aging produces young generations. Given an ``lruvec``, it
increments ``max_seq`` when ``max_seq-min_seq+1`` approaches
``MIN_NR_GENS``. The aging promotes hot pages to the youngest
generation when it finds them accessed through page tables; the
demotion of cold pages happens consequently when it increments
``max_seq``. The aging uses page table walks and rmap walks to find
young PTEs. For the former, it iterates ``lruvec_memcg()->mm_list``
and calls ``walk_page_range()`` with each ``mm_struct`` on this list
to scan PTEs, and after each iteration, it increments ``max_seq``. For
the latter, when the eviction walks the rmap and finds a young PTE,
the aging scans the adjacent PTEs. For both, on finding a young PTE,
the aging clears the accessed bit and updates the gen counter of the
page mapped by this PTE to ``(max_seq%MAX_NR_GENS)+1``.
老化机制生成年轻代。给定一个lruvec对象，当max_seq-min_seq+1接近MIN_NR_GENS时，它会增加max_seq。老化机制在通过页表访问到热页面时，将其提升到最年轻的一代；而在增加max_seq时，会降级冷页面。老化机制通过页表遍历和rmap遍历来查找年轻的页表项（PTE）。对于前者，它遍历lruvec_memcg()->mm_list，并使用该列表上的每个mm_struct调用walk_page_range()来扫描PTEs，并在每次迭代后增加max_seq。对于后者，当驱逐过程遍历rmap并找到年轻的PTE时，老化机制会扫描相邻的PTEs。在这两种情况下，找到年轻的PTE时，老化机制会清除其访问位，并将该PTE映射的页面的代计数器更新为(max_seq%MAX_NR_GENS)+1。

Eviction
--------
The eviction consumes old generations. Given an ``lruvec``, it
increments ``min_seq`` when ``lrugen->folios[]`` indexed by
``min_seq%MAX_NR_GENS`` becomes empty. To select a type and a tier to
evict from, it first compares ``min_seq[]`` to select the older type.
If both types are equally old, it selects the one whose first tier has
a lower refault percentage. The first tier contains single-use
unmapped clean pages, which are the best bet. The eviction sorts a
page according to its gen counter if the aging has found this page
accessed through page tables and updated its gen counter. It also
moves a page to the next generation, i.e., ``min_seq+1``, if this page
was accessed multiple times through file descriptors and the feedback
loop has detected outlying refaults from the tier this page is in. To
this end, the feedback loop uses the first tier as the baseline, for
the reason stated earlier.
驱逐算法消耗旧世代的页面。给定一个lruvec对象，当lrugen->folios[]数组中由min_seq%MAX_NR_GENS计算出的索引位置变为空时，它会递增min_seq。在选择要驱逐的类型和层级时，它首先通过比较min_seq[]来选择较老的类型。如果两种类型的年龄相同，则选择第一个层级中重故障率较低的类型。第一个层级包含单次使用、未映射、干净的页面，这些页面是最优选择。驱逐算法根据gen计数器的值对页面进行排序，如果老化过程发现该页面通过页表被访问并更新了其gen计数器。此外，如果一个页面通过文件描述符被多次访问，并且反馈循环检测到该页面所在层级的重故障率异常，该页面会被移动到下一代，即min_seq+1。为此，反馈循环使用第一个层级作为基准，原因如前所述。

Working set protection
----------------------
Each generation is timestamped at birth. If ``lru_gen_min_ttl`` is
set, an ``lruvec`` is protected from the eviction when its oldest
generation was born within ``lru_gen_min_ttl`` milliseconds. In other
words, it prevents the working set of ``lru_gen_min_ttl`` milliseconds
from getting evicted. The OOM killer is triggered if this working set
cannot be kept in memory.

This time-based approach has the following advantages:

1. It is easier to configure because it is agnostic to applications
   and memory sizes.
2. It is more reliable because it is directly wired to the OOM killer.
每一代表都带有出生时的时间戳。如果设置了lru_gen_min_ttl，

设置了lru_gen_min_ttl后，当某一代最老的生成时间在lru_gen_min_ttl毫秒内时，包含这一代的lruvec将免于被驱逐。换句话说，这防止了在lru_gen_min_ttl毫秒内的工作集被驱逐。如果这一工作集无法保留在内存中，将会触发OOM（Out of Memory）杀手。
基于时间的方法具有以下优点：

更易于配置，因为它与应用程序和内存大小无关。
更可靠，因为它直接与OOM杀手相关联。


``mm_struct`` list
------------------

# 维护一个 mm_struct 列表，用于跟踪每个 memcg 的内存管理上下文
# 当一个任务被迁移时，它的 mm_struct 会跟随到新的 memcg
An ``mm_struct`` list is maintained for each memcg, and an
``mm_struct`` follows its owner task to the new memcg when this task
is migrated.

# 页表遍历器迭代 lruvec_memcg()->mm_list 并调用 walk_page_range()
# 以扫描每个 mm_struct 上的 PTE
# 当多个页表遍历器迭代相同的列表时，它们各自获取一个唯一的 mm_struct，
# 因此可以并行运行
A page table walker iterates ``lruvec_memcg()->mm_list`` and calls
``walk_page_range()`` with each ``mm_struct`` on this list to scan
PTEs. When multiple page table walkers iterate the same list, each of
them gets a unique ``mm_struct``, and therefore they can run in
parallel.

# 页表遍历器会忽略任何错位的页面，例如，如果一个 mm_struct 被迁移，
# 当前 memcg 进行回收时会忽略前一个 memcg 中遗留的页面
# 同样地，页表遍历器会忽略非当前回收节点的页面
Page table walkers ignore any misplaced pages, e.g., if an
``mm_struct`` was migrated, pages left in the previous memcg will be
ignored when the current memcg is under reclaim. Similarly, page table
walkers will ignore pages from nodes other than the one under reclaim.

# 这个基础设施还会跟踪上下文切换之间的 mm_struct 使用情况，
# 以便页表遍历器可以跳过自上次迭代以来一直休眠的进程
This infrastructure also tracks the usage of ``mm_struct`` between
context switches so that page table walkers can skip processes that
have been sleeping since the last iteration.

Rmap/PT walk feedback
---------------------
Searching the rmap for PTEs mapping each page on an LRU list (to test
and clear the accessed bit) can be expensive because pages from
different VMAs (PA space) are not cache friendly to the rmap (VA
space). For workloads mostly using mapped pages, searching the rmap
can incur the highest CPU cost in the reclaim path.

``lru_gen_look_around()`` exploits spatial locality to reduce the
trips into the rmap. It scans the adjacent PTEs of a young PTE and
promotes hot pages. If the scan was done cacheline efficiently, it
adds the PMD entry pointing to the PTE table to the Bloom filter. This
forms a feedback loop between the eviction and the aging.
在查找RMAP（Reverse Mapping）中映射每个页面的PTE（Page Table Entry）以测试并清除访问位时，可能会付出高昂的性能代价。由于来自不同VMAs（物理地址空间）的页面在RMAP（虚拟地址空间）中不是缓存友好的，对于主要使用映射页面的工作负载，扫描RMAP可能会在回收路径中产生最高的CPU成本。

`lru_gen_look_around()`函数通过利用空间局部性来减少进入RMAP的次数，从而优化性能。它扫描一个年轻PTE的邻近PTE，并提升热点页面。如果扫描以缓存行效率的方式完成，它会将指向PTE表的PMD（Page Middle Directory）条目添加到Bloom过滤器中。这在驱逐和老化之间形成了一个反馈循环。

Bloom filters
-------------
Bloom filters are a space and memory efficient data structure for set
membership test, i.e., test if an element is not in the set or may be
in the set.

In the eviction path, specifically, in ``lru_gen_look_around()``, if a
PMD has a sufficient number of hot pages, its address is placed in the
filter. In the aging path, set membership means that the PTE range
will be scanned for young pages.

Note that Bloom filters are probabilistic on set membership. If a test
is false positive, the cost is an additional scan of a range of PTEs,
which may yield hot pages anyway. Parameters of the filter itself can
control the false positive rate in the limit.
# 布隆过滤器是一种用于集合成员测试的空间和内存高效的数据结构，
# 即测试一个元素是否不在集合中或可能在集合中。
#
# 在驱逐路径中，特别是在``lru_gen_look_around()``函数中，
# 如果PMD（页面映射寄存器）有足够的热页面，它的地址将被放入过滤器中。
# 在老化路径中，集合成员意味着PTE（页面表项）范围将被扫描以寻找年轻页面。
#
# 需要注意的是，布隆过滤器对集合成员的测试是概率性的。
# 如果测试结果是误报（false positive），成本是额外扫描一段PTE范围，
# 这可能无论如何都会发现热页面。通过调整过滤器本身的参数，
# 可以在一定程度上控制误报率。

PID controller
--------------
A feedback loop modeled after the Proportional-Integral-Derivative
(PID) controller monitors refaults over anon and file types and
decides which type to evict when both types are available from the
same generation.

The PID controller uses generations rather than the wall clock as the
time domain because a CPU can scan pages at different rates under
varying memory pressure. It calculates a moving average for each new
generation to avoid being permanently locked in a suboptimal state.

根据比例积分微分建模的反馈回路
(PID) 控制器监控匿名和文件类型的故障，
决定当两种类型都可用时要驱逐哪种类型
平辈。

PID控制器使用代而不是挂钟作为
时域，因为 CPU 可以在不同的速率下扫描页面
不同的内存压力。它计算每个新的移动平均值
以避免永久锁定在次优状态。
Memcg LRU
---------
An memcg LRU is a per-node LRU of memcgs. It is also an LRU of LRUs,
since each node and memcg combination has an LRU of folios (see
``mem_cgroup_lruvec()``). Its goal is to improve the scalability of
global reclaim, which is critical to system-wide memory overcommit in
data centers. Note that memcg LRU only applies to global reclaim.

The basic structure of an memcg LRU can be understood by an analogy to
the active/inactive LRU (of folios):

1. It has the young and the old (generations), i.e., the counterparts
   to the active and the inactive;
2. The increment of ``max_seq`` triggers promotion, i.e., the
   counterpart to activation;
3. Other events trigger similar operations, e.g., offlining an memcg
   triggers demotion, i.e., the counterpart to deactivation.

In terms of global reclaim, it has two distinct features:

1. Sharding, which allows each thread to start at a random memcg (in
   the old generation) and improves parallelism;
2. Eventual fairness, which allows direct reclaim to bail out at will
   and reduces latency without affecting fairness over some time.

In terms of traversing memcgs during global reclaim, it improves the
best-case complexity from O(n) to O(1) and does not affect the
worst-case complexity O(n). Therefore, on average, it has a sublinear
complexity.
# memcg LRU简介
#
# memcg LRU 是一种在每个节点上维护的 memcg（内存控制组）LRU（最近最少使用）列表。它也是一种 LRU 的 LRU，
# 因为每个节点和 memcg 的组合都有一个 folio（内存页）的 LRU 列表（参见 `mem_cgroup_lruvec()` 函数）。
# 其目标是提高全局回收的可扩展性，这对于数据中心中的系统级内存过度分配至关重要。需要注意的是，
# memcg LRU 仅适用于全局回收。

# memcg LRU 的基本结构可以通过与活跃/非活跃 LRU（folio 的 LRU）的类比来理解：
#
# 1. 它有年轻代和年老代，即活跃和非活跃的对应物；
# 2. `max_seq` 的增加会触发晋升，即激活的对应操作；
# 3. 其他事件也会触发类似的操作，例如下线一个 memcg 会触发降级，即非活跃化的对应操作。

# 在全局回收方面，它具有两个显著特点：
#
# 1. 分片，这允许每个线程从一个随机的 memcg（在年老代中）开始，提高了并行性；
# 2. 最终公平性，这允许直接回收可以随时退出，减少了延迟而不影响一段时间内的公平性。

# 在全局回收期间遍历 memcgs 时，它将最佳情况复杂度从 O(n) 改善到 O(1)，并且不影响最坏情况复杂度 O(n)。
# 因此，平均而言，它具有亚线性复杂度。

Summary
-------
The multi-gen LRU (of folios) can be disassembled into the following
parts:

* Generations
* Rmap walks
* Page table walks via ``mm_struct`` list
* Bloom filters for rmap/PT walk feedback
* PID controller for refault feedback

The aging and the eviction form a producer-consumer model;
specifically, the latter drives the former by the sliding window over
generations. Within the aging, rmap walks drive page table walks by
inserting hot densely populated page tables to the Bloom filters.
Within the eviction, the PID controller uses refaults as the feedback
to select types to evict and tiers to protect.
多代LRU（基于folios）可以分解为以下几个部分：

代：用于管理folio的生命周期和访问频率，通过代的滑动窗口机制实现老化和驱逐。
Rmap遍历：用于查找和访问folio的物理内存映射，以实现内存的高效利用。
通过mm_struct列表进行页表遍历：用于在不同内存区域间导航，以管理整个系统的内存分配和回收。
Rmap/PT遍历的布隆过滤器：用于快速判断folio是否在某个特定的内存区域，以加速内存访问和管理。
用于refault反馈的PID控制器：通过监控refaults（再次故障）来调整和优化驱逐策略，保护关键层级的内存不受频繁驱逐的影响。
老化和驱逐形成了一个生产者-消费者模型；具体来说，驱逐过程通过代的滑动窗口机制推动老化过程。在老化过程中，Rmap遍历通过将热点和密集人口的页表插入布隆过滤器来驱动页表遍历。在驱逐过程中，PID控制器使用refaults作为反馈来选择要驱逐的类型和要保护的层级。