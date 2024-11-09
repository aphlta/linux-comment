/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifndef __ASSEMBLY__
#ifndef __GENERATING_BOUNDS_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/numa.h>
#include <linux/init.h>
#include <linux/seqlock.h>
#include <linux/nodemask.h>
#include <linux/pageblock-flags.h>
#include <linux/page-flags-layout.h>
#include <linux/atomic.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/local_lock.h>
#include <asm/page.h>

/* Free memory management - zoned buddy allocator.  */
#ifndef CONFIG_ARCH_FORCE_MAX_ORDER
#define MAX_ORDER 10
#else
#define MAX_ORDER CONFIG_ARCH_FORCE_MAX_ORDER
#endif
#define MAX_ORDER_NR_PAGES (1 << MAX_ORDER)

#define IS_MAX_ORDER_ALIGNED(pfn) IS_ALIGNED(pfn, MAX_ORDER_NR_PAGES)

/*
 * PAGE_ALLOC_COSTLY_ORDER is the order at which allocations are deemed
 * costly to service.  That is between allocation orders which should
 * coalesce naturally under reasonable reclaim pressure and those which
 * will not.
 */
#define PAGE_ALLOC_COSTLY_ORDER 3

enum migratetype {
	MIGRATE_UNMOVABLE,
	MIGRATE_MOVABLE,
	MIGRATE_RECLAIMABLE,
	MIGRATE_PCPTYPES,	/* the number of types on the pcp lists */
	MIGRATE_HIGHATOMIC = MIGRATE_PCPTYPES,
#ifdef CONFIG_CMA
	/*
	 * MIGRATE_CMA migration type is designed to mimic the way
	 * ZONE_MOVABLE works.  Only movable pages can be allocated
	 * from MIGRATE_CMA pageblocks and page allocator never
	 * implicitly change migration type of MIGRATE_CMA pageblock.
	 *
	 * The way to use it is to change migratetype of a range of
	 * pageblocks to MIGRATE_CMA which can be done by
	 * __free_pageblock_cma() function.
	 */
	MIGRATE_CMA,
#endif
#ifdef CONFIG_MEMORY_ISOLATION
	MIGRATE_ISOLATE,	/* can't allocate from here */
#endif
	MIGRATE_TYPES
};

/* In mm/page_alloc.c; keep in sync also with show_migration_types() there */
extern const char * const migratetype_names[MIGRATE_TYPES];

#ifdef CONFIG_CMA
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#  define is_migrate_cma_page(_page) (get_pageblock_migratetype(_page) == MIGRATE_CMA)
#else
#  define is_migrate_cma(migratetype) false
#  define is_migrate_cma_page(_page) false
#endif

static inline bool is_migrate_movable(int mt)
{
	return is_migrate_cma(mt) || mt == MIGRATE_MOVABLE;
}

/*
 * Check whether a migratetype can be merged with another migratetype.
 *
 * It is only mergeable when it can fall back to other migratetypes for
 * allocation. See fallbacks[MIGRATE_TYPES][3] in page_alloc.c.
 */
static inline bool migratetype_is_mergeable(int mt)
{
	return mt < MIGRATE_PCPTYPES;
}

#define for_each_migratetype_order(order, type) \
	for (order = 0; order <= MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)

extern int page_group_by_mobility_disabled;

#define MIGRATETYPE_MASK ((1UL << PB_migratetype_bits) - 1)

#define get_pageblock_migratetype(page)					\
	get_pfnblock_flags_mask(page, page_to_pfn(page), MIGRATETYPE_MASK)

#define folio_migratetype(folio)				\
	get_pfnblock_flags_mask(&folio->page, folio_pfn(folio),		\
			MIGRATETYPE_MASK)

struct free_area {
	struct list_head	free_list[MIGRATE_TYPES];
	unsigned long		nr_free;
};

struct pglist_data;

#ifdef CONFIG_NUMA
enum numa_stat_item {
	NUMA_HIT,		/* allocated in intended node */
	NUMA_MISS,		/* allocated in non intended node */
	NUMA_FOREIGN,		/* was intended here, hit elsewhere */
	NUMA_INTERLEAVE_HIT,	/* interleaver preferred this zone */
	NUMA_LOCAL,		/* allocation from local node */
	NUMA_OTHER,		/* allocation from other node */
	NR_VM_NUMA_EVENT_ITEMS
};
#else
#define NR_VM_NUMA_EVENT_ITEMS 0
#endif

enum zone_stat_item {
	/* First 128 byte cacheline (assuming 64 bit words) */
	// The global and per zone counter sums are in arrays of longs. Reorder the ZVCs
	// so that the most frequently used ZVCs are put into the same cacheline. That
	// way calculations of the global, node and per zone vm state touches only a
	// single cacheline. This is mostly important for 64 bit systems were one 128
	// byte cacheline takes only 8 longs.

	NR_FREE_PAGES,
	NR_ZONE_LRU_BASE, /* Used only for compaction and reclaim retry */
	NR_ZONE_INACTIVE_ANON = NR_ZONE_LRU_BASE,
	NR_ZONE_ACTIVE_ANON,
	NR_ZONE_INACTIVE_FILE,
	NR_ZONE_ACTIVE_FILE,
	NR_ZONE_UNEVICTABLE,
	NR_ZONE_WRITE_PENDING,	/* Count of dirty, writeback and unstable pages */
	NR_MLOCK,		/* mlock()ed pages found and moved off LRU */
	/* Second 128 byte cacheline */
	NR_BOUNCE,
#if IS_ENABLED(CONFIG_ZSMALLOC)
	NR_ZSPAGES,		/* allocated in zsmalloc */
#endif
	NR_FREE_CMA_PAGES,
#ifdef CONFIG_UNACCEPTED_MEMORY
	NR_UNACCEPTED,
#endif
	NR_VM_ZONE_STAT_ITEMS };

enum node_stat_item {
	NR_LRU_BASE,
	NR_INACTIVE_ANON = NR_LRU_BASE, /* must match order of LRU_[IN]ACTIVE */
	NR_ACTIVE_ANON,		/*  "     "     "   "       "         */
	NR_INACTIVE_FILE,	/*  "     "     "   "       "         */
	NR_ACTIVE_FILE,		/*  "     "     "   "       "         */
	NR_UNEVICTABLE,		/*  "     "     "   "       "         */
	NR_SLAB_RECLAIMABLE_B,
	NR_SLAB_UNRECLAIMABLE_B,
	NR_ISOLATED_ANON,	/* Temporary isolated pages from anon lru */
	NR_ISOLATED_FILE,	/* Temporary isolated pages from file lru */
	WORKINGSET_NODES,
	WORKINGSET_REFAULT_BASE,
	WORKINGSET_REFAULT_ANON = WORKINGSET_REFAULT_BASE,
	WORKINGSET_REFAULT_FILE,
	WORKINGSET_ACTIVATE_BASE,
	WORKINGSET_ACTIVATE_ANON = WORKINGSET_ACTIVATE_BASE,
	WORKINGSET_ACTIVATE_FILE,
	WORKINGSET_RESTORE_BASE,
	WORKINGSET_RESTORE_ANON = WORKINGSET_RESTORE_BASE,
	WORKINGSET_RESTORE_FILE,
	WORKINGSET_NODERECLAIM,
	NR_ANON_MAPPED,	/* Mapped anonymous pages */
	NR_FILE_MAPPED,	/* pagecache pages mapped into pagetables.
			   only modified from process context */
	NR_FILE_PAGES,
	NR_FILE_DIRTY,
	NR_WRITEBACK,
	NR_WRITEBACK_TEMP,	/* Writeback using temporary buffers */
	NR_SHMEM,		/* shmem pages (included tmpfs/GEM pages) */
	NR_SHMEM_THPS,
	NR_SHMEM_PMDMAPPED,
	NR_FILE_THPS,
	NR_FILE_PMDMAPPED,
	NR_ANON_THPS,
	NR_VMSCAN_WRITE,
	NR_VMSCAN_IMMEDIATE,	/* Prioritise for reclaim when writeback ends */
	NR_DIRTIED,		/* page dirtyings since bootup */
	NR_WRITTEN,		/* page writings since bootup */
	NR_THROTTLED_WRITTEN,	/* NR_WRITTEN while reclaim throttled */
	NR_KERNEL_MISC_RECLAIMABLE,	/* reclaimable non-slab kernel pages */
	NR_FOLL_PIN_ACQUIRED,	/* via: pin_user_page(), gup flag: FOLL_PIN */
	NR_FOLL_PIN_RELEASED,	/* pages returned via unpin_user_page() */
	NR_KERNEL_STACK_KB,	/* measured in KiB */
#if IS_ENABLED(CONFIG_SHADOW_CALL_STACK)
	NR_KERNEL_SCS_KB,	/* measured in KiB */
#endif
	NR_PAGETABLE,		/* used for pagetables */
	NR_SECONDARY_PAGETABLE, /* secondary pagetables, e.g. KVM pagetables */
#ifdef CONFIG_SWAP
	NR_SWAPCACHE,
#endif
#ifdef CONFIG_NUMA_BALANCING
	PGPROMOTE_SUCCESS,	/* promote successfully */
	PGPROMOTE_CANDIDATE,	/* candidate pages to promote */
#endif
	NR_VM_NODE_STAT_ITEMS
};

/*
 * Returns true if the item should be printed in THPs (/proc/vmstat
 * currently prints number of anon, file and shmem THPs. But the item
 * is charged in pages).
 */
static __always_inline bool vmstat_item_print_in_thp(enum node_stat_item item)
{
	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE))
		return false;

	return item == NR_ANON_THPS ||
	       item == NR_FILE_THPS ||
	       item == NR_SHMEM_THPS ||
	       item == NR_SHMEM_PMDMAPPED ||
	       item == NR_FILE_PMDMAPPED;
}

/*
 * Returns true if the value is measured in bytes (most vmstat values are
 * measured in pages). This defines the API part, the internal representation
 * might be different.
 */
static __always_inline bool vmstat_item_in_bytes(int idx)
{
	/*
	 * Global and per-node slab counters track slab pages.
	 * It's expected that changes are multiples of PAGE_SIZE.
	 * Internally values are stored in pages.
	 *
	 * Per-memcg and per-lruvec counters track memory, consumed
	 * by individual slab objects. These counters are actually
	 * byte-precise.
	 */
	return (idx == NR_SLAB_RECLAIMABLE_B ||
		idx == NR_SLAB_UNRECLAIMABLE_B);
}

/*
 * We do arithmetic on the LRU lists in various places in the code,
 * so it is important to keep the active lists LRU_ACTIVE higher in
 * the array than the corresponding inactive lists, and to keep
 * the *_FILE lists LRU_FILE higher than the corresponding _ANON lists.
 *
 * This has to be kept in sync with the statistics in zone_stat_item
 * above and the descriptions in vmstat_text in mm/vmstat.c
 */
#define LRU_BASE 0
#define LRU_ACTIVE 1
#define LRU_FILE 2

enum lru_list {
	LRU_INACTIVE_ANON = LRU_BASE,
	LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
	LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
	LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
	LRU_UNEVICTABLE,
	NR_LRU_LISTS
};

enum vmscan_throttle_state {
	VMSCAN_THROTTLE_WRITEBACK,
	VMSCAN_THROTTLE_ISOLATED,
	VMSCAN_THROTTLE_NOPROGRESS,
	VMSCAN_THROTTLE_CONGESTED,
	NR_VMSCAN_THROTTLE,
};

#define for_each_lru(lru) for (lru = 0; lru < NR_LRU_LISTS; lru++)

#define for_each_evictable_lru(lru) for (lru = 0; lru <= LRU_ACTIVE_FILE; lru++)

static inline bool is_file_lru(enum lru_list lru)
{
	return (lru == LRU_INACTIVE_FILE || lru == LRU_ACTIVE_FILE);
}

static inline bool is_active_lru(enum lru_list lru)
{
	return (lru == LRU_ACTIVE_ANON || lru == LRU_ACTIVE_FILE);
}

#define WORKINGSET_ANON 0
#define WORKINGSET_FILE 1
#define ANON_AND_FILE 2

enum lruvec_flags {
	/*
	 * An lruvec has many dirty pages backed by a congested BDI:
	 * 1. LRUVEC_CGROUP_CONGESTED is set by cgroup-level reclaim.
	 *    It can be cleared by cgroup reclaim or kswapd.
	 * 2. LRUVEC_NODE_CONGESTED is set by kswapd node-level reclaim.
	 *    It can only be cleared by kswapd.
	 *
	 * Essentially, kswapd can unthrottle an lruvec throttled by cgroup
	 * reclaim, but not vice versa. This only applies to the root cgroup.
	 * The goal is to prevent cgroup reclaim on the root cgroup (e.g.
	 * memory.reclaim) to unthrottle an unbalanced node (that was throttled
	 * by kswapd).
	 */
	LRUVEC_CGROUP_CONGESTED,
	LRUVEC_NODE_CONGESTED,
};

#endif /* !__GENERATING_BOUNDS_H */

// mm: multi-gen LRU: groundwork

// Evictable pages are divided into multiple generations for each lruvec.
// The youngest generation number is stored in lrugen->max_seq for both
// anon and file types as they are aged on an equal footing. The oldest
// generation numbers are stored in lrugen->min_seq[] separately for anon
// and file types as clean file pages can be evicted regardless of swap
// constraints. These three variables are monotonically increasing.

// Generation numbers are truncated into order_base_2(MAX_NR_GENS+1) bits
// in order to fit into the gen counter in folio->flags. Each truncated
// generation number is an index to lrugen->lists[]. The sliding window
// technique is used to track at least MIN_NR_GENS and at most
// MAX_NR_GENS generations. The gen counter stores a value within [1,
// MAX_NR_GENS] while a page is on one of lrugen->lists[]. Otherwise it
// stores 0.

// There are two conceptually independent procedures: "the aging", which
// produces young generations, and "the eviction", which consumes old
// generations. They form a closed-loop system, i.e., "the page reclaim".
// Both procedures can be invoked from userspace for the purposes of working
// set estimation and proactive reclaim. These techniques are commonly used
// to optimize job scheduling (bin packing) in data centers [1][2].

// To avoid confusion, the terms "hot" and "cold" will be applied to the
// multi-gen LRU, as a new convention; the terms "active" and "inactive" will
// be applied to the active/inactive LRU, as usual.

// The protection of hot pages and the selection of cold pages are based
// on page access channels and patterns. There are two access channels:
// one through page tables and the other through file descriptors. The
// protection of the former channel is by design stronger because:
// 1. The uncertainty in determining the access patterns of the former
// channel is higher due to the approximation of the accessed bit.
// 2. The cost of evicting the former channel is higher due to the TLB
// flushes required and the likelihood of encountering the dirty bit.
// 3. The penalty of underprotecting the former channel is higher because
// applications usually do not prepare themselves for major page
// faults like they do for blocked I/O. E.g., GUI applications
// commonly use dedicated I/O threads to avoid blocking rendering
// threads.

// There are also two access patterns: one with temporal locality and the
// other without. For the reasons listed above, the former channel is
// assumed to follow the former pattern unless VM_SEQ_READ or VM_RAND_READ is
// present; the latter channel is assumed to follow the latter pattern unless
// outlying refaults have been observed [3][4].

// The next patch will address the "outlying refaults". Three macros, i.e.,
// LRU_REFS_WIDTH, LRU_REFS_PGOFF and LRU_REFS_MASK, used later are added in
// this patch to make the entire patchset less diffy.

// A page is added to the youngest generation on faulting. The aging needs
// to check the accessed bit at least twice before handing this page over to
// the eviction. The first check takes care of the accessed bit set on the
// initial fault; the second check makes sure this page has not been used
// since then. This protocol, AKA second chance, requires a minimum of two
// generations, hence MIN_NR_GENS.

// [1] https://dl.acm.org/doi/10.1145/3297858.3304053
// [2] https://dl.acm.org/doi/10.1145/3503222.3507731
// [3] https://lwn.net/Articles/495543/
// [4] https://lwn.net/Articles/815342/

// Link: https://lkml.kernel.org/r/20220918080010.2920238-6-yuzhao@google.com
// Signed-off-by: Yu Zhao <yuzhao@google.com>
// Acked-by: Brian Geffon <bgeffon@google.com>
// Acked-by: Jan Alexander Steffens (heftig) <heftig@archlinux.org>
// Acked-by: Oleksandr Natalenko <oleksandr@natalenko.name>
// Acked-by: Steven Barrett <steven@liquorix.net>
// Acked-by: Suleiman Souhlal <suleiman@google.com>
// Tested-by: Daniel Byrne <djbyrne@mtu.edu>
// Tested-by: Donald Carr <d@chaos-reins.com>
// Tested-by: Holger Hoffstätte <holger@applied-asynchrony.com>
// Tested-by: Konstantin Kharlamov <Hi-Angel@yandex.ru>
// Tested-by: Shuang Zhai <szhai2@cs.rochester.edu>
// Tested-by: Sofia Trinh <sofia.trinh@edi.works>
// Tested-by: Vaibhav Jain <vaibhav@linux.ibm.com>
// Cc: Andi Kleen <ak@linux.intel.com>
// Cc: Aneesh Kumar K.V <aneesh.kumar@linux.ibm.com>
// Cc: Barry Song <baohua@kernel.org>
// Cc: Catalin Marinas <catalin.marinas@arm.com>
// Cc: Dave Hansen <dave.hansen@linux.intel.com>
// Cc: Hillf Danton <hdanton@sina.com>
// Cc: Jens Axboe <axboe@kernel.dk>
// Cc: Johannes Weiner <hannes@cmpxchg.org>
// Cc: Jonathan Corbet <corbet@lwn.net>
// Cc: Linus Torvalds <torvalds@linux-foundation.org>
// Cc: Matthew Wilcox <willy@infradead.org>
// Cc: Mel Gorman <mgorman@suse.de>
// Cc: Miaohe Lin <linmiaohe@huawei.com>
// Cc: Michael Larabel <Michael@MichaelLarabel.com>
// Cc: Michal Hocko <mhocko@kernel.org>
// Cc: Mike Rapoport <rppt@kernel.org>
// Cc: Mike Rapoport <rppt@linux.ibm.com>
// Cc: Peter Zijlstra <peterz@infradead.org>
// Cc: Qi Zheng <zhengqi.arch@bytedance.com>
// Cc: Tejun Heo <tj@kernel.org>
// Cc: Vlastimil Babka <vbabka@suse.cz>
// Cc: Will Deacon <will@kernel.org>
// Signed-off-by: Andrew Morton <akpm@linux-foundation.org>

/*
 * Evictable pages are divided into multiple generations. The youngest and the
 * oldest generation numbers, max_seq and min_seq, are monotonically increasing.
 * They form a sliding window of a variable size [MIN_NR_GENS, MAX_NR_GENS]. An
 * offset within MAX_NR_GENS, i.e., gen, indexes the LRU list of the
 * corresponding generation. The gen counter in folio->flags stores gen+1 while
 * a page is on one of lrugen->folios[]. Otherwise it stores 0.
 *
 * A page is added to the youngest generation on faulting. The aging needs to
 * check the accessed bit at least twice before handing this page over to the
 * eviction. The first check takes care of the accessed bit set on the initial
 * fault; the second check makes sure this page hasn't been used since then.
 * This process, AKA second chance, requires a minimum of two generations,
 * hence MIN_NR_GENS. And to maintain ABI compatibility with the active/inactive
 * LRU, e.g., /proc/vmstat, these two generations are considered active; the
 * rest of generations, if they exist, are considered inactive. See
 * lru_gen_is_active().
 *
 * PG_active is always cleared while a page is on one of lrugen->folios[] so
 * that the aging needs not to worry about it. And it's set again when a page
 * considered active is isolated for non-reclaiming purposes, e.g., migration.
 * See lru_gen_add_folio() and lru_gen_del_folio().
 *
 * MAX_NR_GENS is set to 4 so that the multi-gen LRU can support twice the
 * number of categories of the active/inactive LRU when keeping track of
 * accesses through page tables. This requires order_base_2(MAX_NR_GENS+1) bits
 * in folio->flags.
 */
/*
 * 对于每个节点，内存控制组（memcgs）被划分为两代：老年代和年轻代。
 * 对于每一代，memcgs被随机分片成多个bin以提高可扩展性。
 * 对于每个bin，hlist_nulls被虚拟地分为三个段：头部、尾部和默认段。
 *
 * 在老年代的随机bin的尾部添加一个在线的memcg。
 * 在老年代的随机bin的头部开始驱逐。
 * 每个节点的memcg代计数器，通过对其取模（MOD MEMCG_NR_GENS）来索引老年代，
 * 当它的所有bin变为空时，计数器递增。
 *
 * 存在四种操作：
 * 1. MEMCG_LRU_HEAD，将一个memcg移动到其当前代（老年代或年轻代）的随机bin的头部，并更新其"seg"为"head"；
 * 2. MEMCG_LRU_TAIL，将一个memcg移动到其当前代（老年代或年轻代）的随机bin的尾部，并更新其"seg"为"tail"；
 * 3. MEMCG_LRU_OLD，将一个memcg移动到老年代的随机bin的头部，将其"gen"更新为"old"，并重置其"seg"为"default"；
 * 4. MEMCG_LRU_YOUNG，将一个memcg移动到年轻代的随机bin的尾部，将其"gen"更新为"young"，并重置其"seg"为"default"。
 *
 * 触发上述操作的事件包括：
 * 1. 超过软限制，触发MEMCG_LRU_HEAD；
 * 2. 第一次尝试回收低于low的memcg，触发MEMCG_LRU_TAIL；
 * 3. 第一次尝试回收低于可回收大小阈值的memcg，触发MEMCG_LRU_TAIL；
 * 4. 第二次尝试回收低于可回收大小阈值的memcg，触发MEMCG_LRU_YOUNG；
 * 5. 尝试回收低于min的memcg，触发MEMCG_LRU_YOUNG；
 * 6. 完成回收路径上的老化过程，触发MEMCG_LRU_YOUNG；
 * 7. 离线一个memcg，触发MEMCG_LRU_OLD。
 *
 * 注意，memcg LRU仅适用于全局回收，通过轮询递增它们的最大序列号（max_seq）计数器来确保所有符合条件的memcg的最终公平性。
 * 对于memcg回收，仍然依赖于mem_cgroup_iter()。
 */
#define MIN_NR_GENS		2U
#define MAX_NR_GENS		4U

/*
 * Each generation is divided into multiple tiers. A page accessed N times
 * through file descriptors is in tier order_base_2(N). A page in the first tier
 * (N=0,1) is marked by PG_referenced unless it was faulted in through page
 * tables or read ahead. A page in any other tier (N>1) is marked by
 * PG_referenced and PG_workingset. This implies a minimum of two tiers is
 * supported without using additional bits in folio->flags.
 *
 * In contrast to moving across generations which requires the LRU lock, moving
 * across tiers only involves atomic operations on folio->flags and therefore
 * has a negligible cost in the buffered access path. In the eviction path,
 * comparisons of refaulted/(evicted+protected) from the first tier and the
 * rest infer whether pages accessed multiple times through file descriptors
 * are statistically hot and thus worth protecting.
 *
 * MAX_NR_TIERS is set to 4 so that the multi-gen LRU can support twice the
 * number of categories of the active/inactive LRU when keeping track of
 * accesses through file descriptors. This uses MAX_NR_TIERS-2 spare bits in
 * folio->flags.
 */
/*
 * 每一代分为多个层级。通过文件描述符访问N次的页面位于第order_base_2(N)层级。
 * 位于第一层（N=0,1）的页面，如果未通过页表故障或预读，则会被标记为PG_referenced。
 * 位于其他任何层级（N>1）的页面会被标记为PG_referenced和PG_workingset。
 * 这意味着即使在不使用额外位的情况下，也至少支持两个层级。
 *
 * 与跨代移动需要LRU锁不同，跨层级移动仅涉及对folio->flags的原子操作，
 * 因此在缓冲访问路径中成本可忽略不计。在驱逐路径中，通过比较第一层和其他层的
 * refaulted/(evicted+protected)可以推断通过文件描述符多次访问的页面是否统计上是热的，
 * 从而决定是否值得保护。
 *
 * MAX_NR_TIERS设置为4，这样多代LRU可以支持比活动/非活动LRU多一倍的类别数，
 * 同时跟踪通过文件描述符的访问。这使用了folio->flags中的MAX_NR_TIERS-2个备用位。
 */
//  1. 多代 LRU 的概念
// 1.1 术语
// Promotion（提升）：将“热”页面（频繁访问的页面）提升到最年轻的代。
// Demotion（降级）：将“冷”页面（不再访问的页面）降级，准备驱逐。
// 2. 页面老化
// 老化过程：在给定的 lruvec（LRU 向量）中，当 max_seq - min_seq + 1 接近 MIN_NR_GENS 时，max_seq 会被递增。这表示老化过程正在产生年轻代。
// 页面的提升和降级：
// 提升：在通过页表访问到“热”页面时，直接将其提升到最年轻的代。
// 降级：在递增 max_seq 时，自动进行降级处理。
// 3. 页面驱逐
// 驱逐过程：在给定的 lruvec 中，当由 min_seq 索引的 lrugen->lists[] 变为空时，min_seq 会递增。这表示最旧的代可以被驱逐。
// 反馈循环：通过类似 PID 控制器的反馈机制监控匿名页面和文件页面的重缺页（refaults），以决定驱逐哪种类型的页面。
// 4. 页面保护机制
// 访问计数：每个代被分为多个层次，页面被访问 N 次时，其所在的层次为 order_base_2(N)。这意味着页面的访问频率会影响其被保护的层次。
// 保护策略：
// 访问频繁的页面会被认为是“热”的，并在驱逐路径中获得保护。
// 如果反馈循环决定保护该页面，则将其移动到下一个代（即 min_seq + 1）。
// 5. 优势
// 该实现带来了一些显著的优势：

// 减少激活成本：通过推断多次通过文件描述符访问的页面是否值得保护，从而消除激活成本。
// 避免过度保护：合理考虑通过页表访问的页面，避免对多次通过文件描述符访问的页面过度保护。
// 更好的保护策略：更多的层次提供了更好的保护，尤其是在高负载的缓冲 I/O 工作负载下。
// 6. 性能基准
// 单工作负载测试：使用 fio 和 memcached 进行基准测试，显示了在不同情况下的性能提升和下降。具体数据显示，在 buffered I/O 工作负载下，IOPS 和带宽显著提升，而在匿名工作负载下略有下降。
// CPU 和内存配置：基准测试是在特定的硬件配置上进行的，确保了结果的可靠性。
// 7. 代码更改示例
// 提到了一些代码的具体更改，包括对 brd.c 驱动的修改，以支持新的内存管理策略。
// 其他配置文件的示例显示了系统在不同情况下的配置。
// 总结
// 这段补丁和注释为多代 LRU 的实现提供了详细的背景和技术细节，尤其是在页面老化、驱逐和保护机制方面。通过引入新的术语和反馈机制，Linux 内核在内存管理上实现了更灵活和高效的策略，旨在提高系统性能并减少内存压力。
// https://lkml.kernel.org/r/20220918080010.2920238-7-yuzhao@google.com
#define MAX_NR_TIERS		4U

#ifndef __GENERATING_BOUNDS_H

struct lruvec;
// mm: multi-gen LRU: exploit locality in rmap

// Searching the rmap for PTEs mapping each page on an LRU list (to test and
// clear the accessed bit) can be expensive because pages from different VMAs
// (PA space) are not cache friendly to the rmap (VA space). For workloads
// mostly using mapped pages, searching the rmap can incur the highest CPU
// cost in the reclaim path.

// This patch exploits spatial locality to reduce the trips into the rmap.
// When shrink_page_list() walks the rmap and finds a young PTE, a new
// function lru_gen_look_around() scans at most BITS_PER_LONG-1 adjacent
// PTEs. On finding another young PTE, it clears the accessed bit and
// updates the gen counter of the page mapped by this PTE to
// (max_seq%MAX_NR_GENS)+1.

// 在搜索rmap以查找映射每个页面的PTE（以测试并清除访问位）时，可能会付出高昂的代价，
// 因为来自不同VMA（物理地址空间）的页面在rmap（虚拟地址空间）中对缓存不友好。
// 对于主要使用映射页面的工作负载，在回收路径中搜索rmap可能会产生最高的CPU成本。

// 此补丁利用空间局部性来减少进入rmap的次数。当shrink_page_list()遍历rmap并找到一个年轻的PTE时，
// 一个新函数lru_gen_look_around()最多扫描相邻的BITS_PER_LONG-1个PTE。在找到另一个年轻的PTE时，
// 它清除该PTE的访问位，并将映射到该PTE的页面的gen计数器更新为(max_seq%MAX_NR_GENS)+1。

// Server benchmark results:
// Single workload:
// fio (buffered I/O): no change

// Single workload:
// memcached (anon): +[3, 5]%
// Ops/sec KB/sec
// patch1-6: 1106168.46 43025.04
// patch1-7: 1147696.57 44640.29

// Configurations:
// no change

// Client benchmark results:
// kswapd profiles:
// patch1-6
// 39.03% lzo1x_1_do_compress (real work)
// 18.47% page_vma_mapped_walk (overhead)
// 6.74% _raw_spin_unlock_irq
// 3.97% do_raw_spin_lock
// 2.49% ptep_clear_flush
// 2.48% anon_vma_interval_tree_iter_first
// 1.92% folio_referenced_one
// 1.88% __zram_bvec_write
// 1.48% memmove
// 1.31% vma_interval_tree_iter_next

// patch1-7
// 48.16% lzo1x_1_do_compress (real work)
// 8.20% page_vma_mapped_walk (overhead)
// 7.06% _raw_spin_unlock_irq
// 2.92% ptep_clear_flush
// 2.53% __zram_bvec_write
// 2.11% do_raw_spin_lock
// 2.02% memmove
// 1.93% lru_gen_look_around
// 1.56% free_unref_page_list
// 1.40% memset

// Configurations:
// no change

// // Link: https://lkml.kernel.org/r/20220918080010.2920238-8-yuzhao@google.com
struct page_vma_mapped_walk;

#define LRU_GEN_MASK		((BIT(LRU_GEN_WIDTH) - 1) << LRU_GEN_PGOFF)
#define LRU_REFS_MASK		((BIT(LRU_REFS_WIDTH) - 1) << LRU_REFS_PGOFF)

#ifdef CONFIG_LRU_GEN

enum {
	LRU_GEN_ANON,
	LRU_GEN_FILE,
};

enum {
	LRU_GEN_CORE,
	LRU_GEN_MM_WALK,
	LRU_GEN_NONLEAF_YOUNG,
	NR_LRU_GEN_CAPS
};

#define MIN_LRU_BATCH		BITS_PER_LONG
#define MAX_LRU_BATCH		(MIN_LRU_BATCH * 64)

/* whether to keep historical stats from evicted generations */
#ifdef CONFIG_LRU_GEN_STATS
#define NR_HIST_GENS		MAX_NR_GENS
#else
#define NR_HIST_GENS		1U
#endif

/*
 * The youngest generation number is stored in max_seq for both anon and file
 * types as they are aged on an equal footing. The oldest generation numbers are
 * stored in min_seq[] separately for anon and file types as clean file pages
 * can be evicted regardless of swap constraints.
 *
 * Normally anon and file min_seq are in sync. But if swapping is constrained,
 * e.g., out of swap space, file min_seq is allowed to advance and leave anon
 * min_seq behind.
 *
 * The number of pages in each generation is eventually consistent and therefore
 * can be transiently negative when reset_batch_size() is pending.
 */
/*
 * 最年轻的一代编号在 max_seq 中存储，适用于匿名和文件类型，因为它们是平等老化的。
 * 最老的一代编号分别在 min_seq[] 中为匿名和文件类型单独存储，因为干净的文件页可以
 * 不受交换限制的影响而被驱逐。
 *
 * 通常情况下，匿名和文件的 min_seq 是同步的。但如果交换受到限制，例如，没有交换空间，
 * 文件的 min_seq 允许提前推进，而留下匿名的 min_seq。
 *
 * 每一代中的页数最终是一致的，因此在重置 batch_size() 待处理时可能是临时负数。
 */
// mm: multi-gen LRU: rename lru_gen_struct to lru_gen_folio

// Patch series "mm: multi-gen LRU: memcg LRU", v3.

// Overview
// ​========

// An memcg LRU is a per-node LRU of memcgs. It is also an LRU of LRUs,
// since each node and memcg combination has an LRU of folios (see
// mem_cgroup_lruvec()).

// Its goal is to improve the scalability of global reclaim, which is
// critical to system-wide memory overcommit in data centers. Note that
// memcg reclaim is currently out of scope.

// Its memory bloat is a pointer to each lruvec and negligible to each
// pglist_data. In terms of traversing memcgs during global reclaim, it
// improves the best-case complexity from O(n) to O(1) and does not affect
// the worst-case complexity O(n). Therefore, on average, it has a sublinear
// complexity in contrast to the current linear complexity.

// The basic structure of an memcg LRU can be understood by an analogy to
// the active/inactive LRU (of folios):
// 1. It has the young and the old (generations), i.e., the counterparts
// to the active and the inactive;
// 2. The increment of max_seq triggers promotion, i.e., the counterpart
// to activation;
// 3. Other events trigger similar operations, e.g., offlining an memcg
// triggers demotion, i.e., the counterpart to deactivation.

// In terms of global reclaim, it has two distinct features:
// 1. Sharding, which allows each thread to start at a random memcg (in
// the old generation) and improves parallelism;
// 2. Eventual fairness, which allows direct reclaim to bail out at will
// and reduces latency without affecting fairness over some time.

// The commit message in patch 6 details the workflow:
// https://lore.kernel.org/r/20221222041905.2431096-7-yuzhao@google.com/

// The following is a simple test to quickly verify its effectiveness.

// Test design:
// 1. Create multiple memcgs.
// 2. Each memcg contains a job (fio).
// 3. All jobs access the same amount of memory randomly.
// 4. The system does not experience global memory pressure.
// 5. Periodically write to the root memory.reclaim.

// Desired outcome:
// 1. All memcgs have similar pgsteal counts, i.e., stddev(pgsteal)
// over mean(pgsteal) is close to 0%.
// 2. The total pgsteal is close to the total requested through
// memory.reclaim, i.e., sum(pgsteal) over sum(requested) is close
// to 100%.

// Actual outcome [1]:
// MGLRU off MGLRU on
// stddev(pgsteal) / mean(pgsteal) 75% 20%
// sum(pgsteal) / sum(requested) 425% 95%

// ####################################################################
// MEMCGS=128

// for ((memcg = 0; memcg < $MEMCGS; memcg++)); do
// mkdir /sys/fs/cgroup/memcg$memcg
// done

// start() {
// echo $BASHPID > /sys/fs/cgroup/memcg$memcg/cgroup.procs

// fio -name=memcg$memcg --numjobs=1 --ioengine=mmap \
// --filename=/dev/zero --size=1920M --rw=randrw \
// --rate=64m,64m --random_distribution=random \
// --fadvise_hint=0 --time_based --runtime=10h \
// --group_reporting --minimal
// }

// for ((memcg = 0; memcg < $MEMCGS; memcg++)); do
// start &
// done

// sleep 600

// for ((i = 0; i < 600; i++)); do
// echo 256m >/sys/fs/cgroup/memory.reclaim
// sleep 6
// done

// for ((memcg = 0; memcg < $MEMCGS; memcg++)); do
// grep "pgsteal " /sys/fs/cgroup/memcg$memcg/memory.stat
// done
// ####################################################################

// [1]: This was obtained from running the above script (touches less
// than 256GB memory) on an EPYC 7B13 with 512GB DRAM for over an
// hour.


// This patch (of 8):

// The new name lru_gen_folio will be more distinct from the coming
// lru_gen_memcg.

// Link: https://lkml.kernel.org/r/20221222041905.2431096-1-yuzhao@google.com
// Link: https://lkml.kernel.org/r/20221222041905.2431096-2-yuzhao@google.com
// Signed-off-by: Yu Zhao <yuzhao@google.com>

struct lru_gen_folio {
	/* the aging increments the youngest generation number */
	unsigned long max_seq;
	/* the eviction increments the oldest generation numbers */
	unsigned long min_seq[ANON_AND_FILE];
	/* the birth time of each generation in jiffies */
	unsigned long timestamps[MAX_NR_GENS];
	/* the multi-gen LRU lists, lazily sorted on eviction */
	// 多代LRU（Least Recently Used）链表， eviction（驱逐）时懒惰地进行排序,
	// alex's qustion :  : 为什么要和zone有关系? 不应该和node关联吗?
	struct list_head folios[MAX_NR_GENS][ANON_AND_FILE][MAX_NR_ZONES];
	/* the multi-gen LRU sizes, eventually consistent */
	/* 多代LRU（最近最少使用）缓存的大小，追求最终一致性 */
	long nr_pages[MAX_NR_GENS][ANON_AND_FILE][MAX_NR_ZONES];
	/* the exponential moving average of refaulted */
	// 计算参考故障的指数移动平均值 (EMA)。
	unsigned long avg_refaulted[ANON_AND_FILE][MAX_NR_TIERS];
	/* the exponential moving average of evicted+protected */
	unsigned long avg_total[ANON_AND_FILE][MAX_NR_TIERS];
	/* the first tier doesn't need protection, hence the minus one */
	unsigned long protected[NR_HIST_GENS][ANON_AND_FILE][MAX_NR_TIERS - 1];
	/* can be modified without holding the LRU lock */
	// alex's qustion : 为什么可以不用锁
	atomic_long_t evicted[NR_HIST_GENS][ANON_AND_FILE][MAX_NR_TIERS];
	atomic_long_t refaulted[NR_HIST_GENS][ANON_AND_FILE][MAX_NR_TIERS];
	/* whether the multi-gen LRU is enabled */
	bool enabled;
#ifdef CONFIG_MEMCG
	/* the memcg generation this lru_gen_folio belongs to */
	u8 gen;
	/* the list segment this lru_gen_folio belongs to */
	u8 seg;
	/* per-node lru_gen_folio list for global reclaim */
	struct hlist_nulls_node list;
#endif
};

enum {
	MM_LEAF_TOTAL,		/* total leaf entries */
	MM_LEAF_OLD,		/* old leaf entries */
	MM_LEAF_YOUNG,		/* young leaf entries */
	MM_NONLEAF_TOTAL,	/* total non-leaf entries */
	MM_NONLEAF_FOUND,	/* non-leaf entries found in Bloom filters */
	MM_NONLEAF_ADDED,	/* non-leaf entries added to Bloom filters */
	NR_MM_STATS
};

/* double-buffering Bloom filters */
#define NR_BLOOM_FILTERS	2

struct lru_gen_mm_state {
	/* set to max_seq after each iteration */
	unsigned long seq;
	/* where the current iteration continues after */
	struct list_head *head;
	/* where the last iteration ended before */
	struct list_head *tail;
	/* Bloom filters flip after each iteration */
	unsigned long *filters[NR_BLOOM_FILTERS];
	/* the mm stats for debugging */
	unsigned long stats[NR_HIST_GENS][NR_MM_STATS];
};

struct lru_gen_mm_walk {
	/* the lruvec under reclaim */
	struct lruvec *lruvec;
	/* unstable max_seq from lru_gen_folio */
	unsigned long max_seq;
	/* the next address within an mm to scan */
	unsigned long next_addr;
	/* to batch promoted pages */
	int nr_pages[MAX_NR_GENS][ANON_AND_FILE][MAX_NR_ZONES];
	/* to batch the mm stats */
	int mm_stats[NR_MM_STATS];
	/* total batched items */
	int batched;
	bool can_swap;
	bool force_scan;
};

void lru_gen_init_lruvec(struct lruvec *lruvec);
void lru_gen_look_around(struct page_vma_mapped_walk *pvmw);

#ifdef CONFIG_MEMCG

/*
 * For each node, memcgs are divided into two generations: the old and the
 * young. For each generation, memcgs are randomly sharded into multiple bins
 * to improve scalability. For each bin, the hlist_nulls is virtually divided
 * into three segments: the head, the tail and the default.
 *
 * An onlining memcg is added to the tail of a random bin in the old generation.
 * The eviction starts at the head of a random bin in the old generation. The
 * per-node memcg generation counter, whose reminder (mod MEMCG_NR_GENS) indexes
 * the old generation, is incremented when all its bins become empty.
 *
 * There are four operations:
 * 1. MEMCG_LRU_HEAD, which moves an memcg to the head of a random bin in its
 *    current generation (old or young) and updates its "seg" to "head";
 * 2. MEMCG_LRU_TAIL, which moves an memcg to the tail of a random bin in its
 *    current generation (old or young) and updates its "seg" to "tail";
 * 3. MEMCG_LRU_OLD, which moves an memcg to the head of a random bin in the old
 *    generation, updates its "gen" to "old" and resets its "seg" to "default";
 * 4. MEMCG_LRU_YOUNG, which moves an memcg to the tail of a random bin in the
 *    young generation, updates its "gen" to "young" and resets its "seg" to
 *    "default".
 *
 * The events that trigger the above operations are:
 * 1. Exceeding the soft limit, which triggers MEMCG_LRU_HEAD;
 * 2. The first attempt to reclaim an memcg below low, which triggers
 *    MEMCG_LRU_TAIL;
 * 3. The first attempt to reclaim an memcg below reclaimable size threshold,
 *    which triggers MEMCG_LRU_TAIL;
 * 4. The second attempt to reclaim an memcg below reclaimable size threshold,
 *    which triggers MEMCG_LRU_YOUNG;
 * 5. Attempting to reclaim an memcg below min, which triggers MEMCG_LRU_YOUNG;
 * 6. Finishing the aging on the eviction path, which triggers MEMCG_LRU_YOUNG;
 * 7. Offlining an memcg, which triggers MEMCG_LRU_OLD.
 *
 * Note that memcg LRU only applies to global reclaim, and the round-robin
 * incrementing of their max_seq counters ensures the eventual fairness to all
 * eligible memcgs. For memcg reclaim, it still relies on mem_cgroup_iter().
 */
/*
 * 对于每个节点，memcgs（内存控制组）被分为两代：老代和年轻代。对于每一代，memcgs被随机分片到多个bin中以提高可扩展性。
 * 对于每个bin，hlist_nulls（空列表）被虚拟分为三段：头、尾和默认。
 *
 * 一个上线的memcg被添加到老代的一个随机bin的尾部。驱逐操作从老代的一个随机bin的头部开始。每节点的memcg代计数器，
 * 其余数（模MEMCG_NR_GENS）索引老代，在其所有bin变为空时递增。
 *
 * 存在四种操作：
 * 1. MEMCG_LRU_HEAD，将一个memcg移动到其当前代（老或年轻）的一个随机bin的头部，并将其“seg”更新为“头”；
 * 2. MEMCG_LRU_TAIL，将一个memcg移动到其当前代（老或年轻）的一个随机bin的尾部，并将其“seg”更新为“尾”；
 * 3. MEMCG_LRU_OLD，将一个memcg移动到老代的一个随机bin的头部，将其“gen”更新为“老”，并重置其“seg”为“默认”；
 * 4. MEMCG_LRU_YOUNG，将一个memcg移动到年轻代的一个随机bin的尾部，将其“gen”更新为“年轻”，并重置其“seg”为“默认”。
 *
 * 触发上述操作的事件包括：
 * 1. 超过软限制，触发MEMCG_LRU_HEAD；
 * 2. 第一次尝试回收一个memcg至低于低阈值，触发MEMCG_LRU_TAIL；
 * 3. 第一次尝试回收一个memcg至低于可回收大小阈值，触发MEMCG_LRU_TAIL；
 * 4. 第二次尝试回收一个memcg至低于可回收大小阈值，触发MEMCG_LRU_YOUNG；
 * 5. 尝试回收一个memcg至低于最小阈值，触发MEMCG_LRU_YOUNG；
 * 6. 在驱逐路径上完成老化，触发MEMCG_LRU_YOUNG；
 * 7. 下线一个memcg，触发MEMCG_LRU_OLD。
 *
 * 注意，memcg LRU仅适用于全局回收，其最大序列计数器的轮换递增确保了对所有符合条件的memcgs的最终公平性。对于memcg回收，
 * 仍然依赖于mem_cgroup_iter()。
 */

#define MEMCG_NR_GENS	2
#define MEMCG_NR_BINS	8

struct lru_gen_memcg {
	/* the per-node memcg generation counter */
	unsigned long seq;
	/* each memcg has one lru_gen_folio per node */
	unsigned long nr_memcgs[MEMCG_NR_GENS];
	/* per-node lru_gen_folio list for global reclaim */
	struct hlist_nulls_head	fifo[MEMCG_NR_GENS][MEMCG_NR_BINS];
	/* protects the above */
	spinlock_t lock;
};

void lru_gen_init_pgdat(struct pglist_data *pgdat);

void lru_gen_init_memcg(struct mem_cgroup *memcg);
void lru_gen_exit_memcg(struct mem_cgroup *memcg);
void lru_gen_online_memcg(struct mem_cgroup *memcg);
void lru_gen_offline_memcg(struct mem_cgroup *memcg);
void lru_gen_release_memcg(struct mem_cgroup *memcg);
void lru_gen_soft_reclaim(struct mem_cgroup *memcg, int nid);

#else /* !CONFIG_MEMCG */

#define MEMCG_NR_GENS	1

struct lru_gen_memcg {
};

static inline void lru_gen_init_pgdat(struct pglist_data *pgdat)
{
}

#endif /* CONFIG_MEMCG */

#else /* !CONFIG_LRU_GEN */

static inline void lru_gen_init_pgdat(struct pglist_data *pgdat)
{
}

static inline void lru_gen_init_lruvec(struct lruvec *lruvec)
{
}

static inline void lru_gen_look_around(struct page_vma_mapped_walk *pvmw)
{
}

#ifdef CONFIG_MEMCG

static inline void lru_gen_init_memcg(struct mem_cgroup *memcg)
{
}

static inline void lru_gen_exit_memcg(struct mem_cgroup *memcg)
{
}

static inline void lru_gen_online_memcg(struct mem_cgroup *memcg)
{
}

static inline void lru_gen_offline_memcg(struct mem_cgroup *memcg)
{
}

static inline void lru_gen_release_memcg(struct mem_cgroup *memcg)
{
}

static inline void lru_gen_soft_reclaim(struct mem_cgroup *memcg, int nid)
{
}

#endif /* CONFIG_MEMCG */

#endif /* CONFIG_LRU_GEN */

struct lruvec {
	struct list_head		lists[NR_LRU_LISTS];
	/* per lruvec lru_lock for memcg */
	spinlock_t			lru_lock;
	/*
	 * These track the cost of reclaiming one LRU - file or anon -
	 * over the other. As the observed cost of reclaiming one LRU
	 * increases, the reclaim scan balance tips toward the other.
	 */
	unsigned long			anon_cost;
	unsigned long			file_cost;
	/* Non-resident age, driven by LRU movement */
	atomic_long_t			nonresident_age;
	/* Refaults at the time of last reclaim cycle */
	unsigned long			refaults[ANON_AND_FILE];
	/* Various lruvec state flags (enum lruvec_flags) */
	unsigned long			flags;
#ifdef CONFIG_LRU_GEN
	/* evictable pages divided into generations */
	struct lru_gen_folio		lrugen;
	/* to concurrently iterate lru_gen_mm_list */
	struct lru_gen_mm_state		mm_state;
#endif
#ifdef CONFIG_MEMCG
	struct pglist_data *pgdat;
#endif
};

/* Isolate unmapped pages */
#define ISOLATE_UNMAPPED	((__force isolate_mode_t)0x2)
/* Isolate for asynchronous migration */
#define ISOLATE_ASYNC_MIGRATE	((__force isolate_mode_t)0x4)
/* Isolate unevictable pages */
#define ISOLATE_UNEVICTABLE	((__force isolate_mode_t)0x8)

/* LRU Isolation modes. */
typedef unsigned __bitwise isolate_mode_t;

enum zone_watermarks {
	WMARK_MIN,
	WMARK_LOW,
	WMARK_HIGH,
	WMARK_PROMO,
	NR_WMARK
};

/*
 * One per migratetype for each PAGE_ALLOC_COSTLY_ORDER. One additional list
 * for THP which will usually be GFP_MOVABLE. Even if it is another type,
 * it should not contribute to serious fragmentation causing THP allocation
 * failures.
 */
// 根据配置宏CONFIG_TRANSPARENT_HUGEPAGE的值来决定是否支持透明大页面(THP)特性
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
#define NR_PCP_THP 1 // 定义支持THP特性时，THP列表的数量为1
#else
#define NR_PCP_THP 0 // 定义不支持THP特性时，THP列表的数量为0
#endif

// 定义低阶PCP列表的数量，基于迁移PCP类型和页面分配代价顺序常量
#define NR_LOWORDER_PCP_LISTS (MIGRATE_PCPTYPES * (PAGE_ALLOC_COSTLY_ORDER + 1))

// 总PCP列表数量等于低阶PCP列表数量加上THP列表数量
#define NR_PCP_LISTS (NR_LOWORDER_PCP_LISTS + NR_PCP_THP)

#define min_wmark_pages(z) (z->_watermark[WMARK_MIN] + z->watermark_boost)
#define low_wmark_pages(z) (z->_watermark[WMARK_LOW] + z->watermark_boost)
#define high_wmark_pages(z) (z->_watermark[WMARK_HIGH] + z->watermark_boost)
// mm: reclaim small amounts of memory when an external fragmentation event occurs

// An external fragmentation event was previously described as

// When the page allocator fragments memory, it records the event using
// the mm_page_alloc_extfrag event. If the fallback_order is smaller
// than a pageblock order (order-9 on 64-bit x86) then it's considered
// an event that will cause external fragmentation issues in the future.

// The kernel reduces the probability of such events by increasing the
// watermark sizes by calling set_recommended_min_free_kbytes early in the
// lifetime of the system. This works reasonably well in general but if
// there are enough sparsely populated pageblocks then the problem can still
// occur as enough memory is free overall and kswapd stays asleep.

// This patch introduces a watermark_boost_factor sysctl that allows a zone
// watermark to be temporarily boosted when an external fragmentation causing
// events occurs. The boosting will stall allocations that would decrease
// free memory below the boosted low watermark and kswapd is woken if the
// calling context allows to reclaim an amount of memory relative to the size
// of the high watermark and the watermark_boost_factor until the boost is
// cleared. When kswapd finishes, it wakes kcompactd at the pageblock order
// to clean some of the pageblocks that may have been affected by the
// fragmentation event. kswapd avoids any writeback, slab shrinkage and swap
// from reclaim context during this operation to avoid excessive system
// disruption in the name of fragmentation avoidance. Care is taken so that
// kswapd will do normal reclaim work if the system is really low on memory.

// This was evaluated using the same workloads as "mm, page_alloc: Spread
// allocations across zones before introducing fragmentation".
// 如何通过内核机制来回收少量内存，避免碎片化问题进一步恶化。下面是这个补丁的一些关键点：

// 背景：
// 外部碎片化事件：当页面分配器（page allocator）导致内存碎片化时，会记录这个事件。如果分配的页面大小（fallback_order）小于pageblock的大小（在64位x86系统上是order-9），那么这被认为是一个可能在未来引起外部碎片化问题的事件。

// 现有机制：内核通过增加内存水位线（watermark sizes）来减少这些事件的概率，这是通过在系统生命周期早期调用set_recommended_min_free_kbytes函数来实现的。然而，如果系统中的pageblocks分布稀疏，仍然可能发生外部碎片化问题，因为即使总体上有足够的内存，kswapd（负责后台回收内存的守护进程）也可能保持休眠状态。

// 补丁内容：
// 引入watermark_boost_factor：这是一个新的sysctl参数，当发生外部碎片化事件时，允许临时提高区域水位线。提高的水位线将阻止那些会导致空闲内存低于提高后低水位线的分配操作，同时会唤醒kswapd进程（如果调用上下文允许）来回收一定量的内存。回收的内存量取决于高水位线和watermark_boost_factor的大小，直到提升的水位线被清除。

// kswapd与kcompactd的协调：当kswapd完成内存回收后，它会在pageblock级别唤醒kcompactd进程来清理可能受到碎片化事件影响的pageblocks。为了避免系统过度受影响，kswapd在这种操作中会避免进行写回操作、缓存回收和交换操作，但如果系统确实内存非常紧张，kswapd仍会执行正常的内存回收工作。

// 评估：
// 该补丁使用了与“mm, page_alloc: Spread allocations across zones before introducing fragmentation”相同的工作负载进行评估，表明它经过了一定的性能测试。

// 总结：
// 这个补丁的目的是在外部碎片化事件发生时，通过动态调整水位线和协调kswapd与kcompactd进程，减少碎片化问题的影响，同时尽量避免对系统性能的过度干扰。
#define wmark_pages(z, i) (z->_watermark[i] + z->watermark_boost)

/* Fields and list protected by pagesets local_lock in page_alloc.c */
/**
 * 结构体 per_cpu_pages 定义了每个CPU的页面管理数据结构。
 * 它包含了用于同步和管理页面分配和释放的机制，以及用于跟踪页面状态的变量。
 */
struct per_cpu_pages {
	/* lock 用于保护 lists 字段，确保在多CPU环境下安全访问列表 */
	spinlock_t lock;

	/* count 表示当前在列表中的页面数量 */
	int count;

	/* high 表示高水位线，当页面数量超过此值时需要进行释放操作 */
	int high;

	/* batch 指定了在 buddy 算法中添加或移除页面时的块大小 */
	int batch;

	/* free_factor 在释放页面时用于调整 batch 的比例因子 */
	short free_factor;

	/* 条件编译变量 expire，用于NUMA系统中远程页面集的管理 */
#ifdef CONFIG_NUMA
	short expire;
#endif

	/* lists 是一组链表，每个迁移类型有一个链表，用于存储页面 */
	struct list_head lists[NR_PCP_LISTS];
} ____cacheline_aligned_in_smp;

struct per_cpu_zonestat {
#ifdef CONFIG_SMP
	s8 vm_stat_diff[NR_VM_ZONE_STAT_ITEMS];
	s8 stat_threshold;
#endif
#ifdef CONFIG_NUMA
	/*
	 * Low priority inaccurate counters that are only folded
	 * on demand. Use a large type to avoid the overhead of
	 * folding during refresh_cpu_vm_stats.
	 */
	unsigned long vm_numa_event[NR_VM_NUMA_EVENT_ITEMS];
#endif
};

struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[NR_VM_NODE_STAT_ITEMS];
};

#endif /* !__GENERATING_BOUNDS.H */

enum zone_type {
	/*
	 * ZONE_DMA and ZONE_DMA32 are used when there are peripherals not able
	 * to DMA to all of the addressable memory (ZONE_NORMAL).
	 * On architectures where this area covers the whole 32 bit address
	 * space ZONE_DMA32 is used. ZONE_DMA is left for the ones with smaller
	 * DMA addressing constraints. This distinction is important as a 32bit
	 * DMA mask is assumed when ZONE_DMA32 is defined. Some 64-bit
	 * platforms may need both zones as they support peripherals with
	 * different DMA addressing limitations.
	 */
#ifdef CONFIG_ZONE_DMA
	ZONE_DMA,
#endif
#ifdef CONFIG_ZONE_DMA32
	ZONE_DMA32,
#endif
	/*
	 * Normal addressable memory is in ZONE_NORMAL. DMA operations can be
	 * performed on pages in ZONE_NORMAL if the DMA devices support
	 * transfers to all addressable memory.
	 */
	ZONE_NORMAL,
#ifdef CONFIG_HIGHMEM
	/*
	 * A memory area that is only addressable by the kernel through
	 * mapping portions into its own address space. This is for example
	 * used by i386 to allow the kernel to address the memory beyond
	 * 900MB. The kernel will set up special mappings (page
	 * table entries on i386) for each page that the kernel needs to
	 * access.
	 */
	ZONE_HIGHMEM,
#endif
	/*
	 * ZONE_MOVABLE is similar to ZONE_NORMAL, except that it contains
	 * movable pages with few exceptional cases described below. Main use
	 * cases for ZONE_MOVABLE are to make memory offlining/unplug more
	 * likely to succeed, and to locally limit unmovable allocations - e.g.,
	 * to increase the number of THP/huge pages. Notable special cases are:
	 *
	 * 1. Pinned pages: (long-term) pinning of movable pages might
	 *    essentially turn such pages unmovable. Therefore, we do not allow
	 *    pinning long-term pages in ZONE_MOVABLE. When pages are pinned and
	 *    faulted, they come from the right zone right away. However, it is
	 *    still possible that address space already has pages in
	 *    ZONE_MOVABLE at the time when pages are pinned (i.e. user has
	 *    touches that memory before pinning). In such case we migrate them
	 *    to a different zone. When migration fails - pinning fails.
	 * 2. memblock allocations: kernelcore/movablecore setups might create
	 *    situations where ZONE_MOVABLE contains unmovable allocations
	 *    after boot. Memory offlining and allocations fail early.
	 * 3. Memory holes: kernelcore/movablecore setups might create very rare
	 *    situations where ZONE_MOVABLE contains memory holes after boot,
	 *    for example, if we have sections that are only partially
	 *    populated. Memory offlining and allocations fail early.
	 * 4. PG_hwpoison pages: while poisoned pages can be skipped during
	 *    memory offlining, such pages cannot be allocated.
	 * 5. Unmovable PG_offline pages: in paravirtualized environments,
	 *    hotplugged memory blocks might only partially be managed by the
	 *    buddy (e.g., via XEN-balloon, Hyper-V balloon, virtio-mem). The
	 *    parts not manged by the buddy are unmovable PG_offline pages. In
	 *    some cases (virtio-mem), such pages can be skipped during
	 *    memory offlining, however, cannot be moved/allocated. These
	 *    techniques might use alloc_contig_range() to hide previously
	 *    exposed pages from the buddy again (e.g., to implement some sort
	 *    of memory unplug in virtio-mem).
	 * 6. ZERO_PAGE(0), kernelcore/movablecore setups might create
	 *    situations where ZERO_PAGE(0) which is allocated differently
	 *    on different platforms may end up in a movable zone. ZERO_PAGE(0)
	 *    cannot be migrated.
	 * 7. Memory-hotplug: when using memmap_on_memory and onlining the
	 *    memory to the MOVABLE zone, the vmemmap pages are also placed in
	 *    such zone. Such pages cannot be really moved around as they are
	 *    self-stored in the range, but they are treated as movable when
	 *    the range they describe is about to be offlined.
	 *
	 * In general, no unmovable allocations that degrade memory offlining
	 * should end up in ZONE_MOVABLE. Allocators (like alloc_contig_range())
	 * have to expect that migrating pages in ZONE_MOVABLE can fail (even
	 * if has_unmovable_pages() states that there are no unmovable pages,
	 * there can be false negatives).
	 */
	ZONE_MOVABLE,
#ifdef CONFIG_ZONE_DEVICE
	ZONE_DEVICE,
#endif
	__MAX_NR_ZONES

};

#ifndef __GENERATING_BOUNDS_H

#define ASYNC_AND_SYNC 2

// 定义内存区域的结构体
struct zone {
	// 只读字段

	// 区域水印，使用 *_wmark_pages(zone) 宏访问
	unsigned long _watermark[NR_WMARK];
	// 水印提升值
	unsigned long watermark_boost;

	// 预留的高原子内存页数
	unsigned long nr_reserved_highatomic;

	// 为了防止在低端区域出现OOM，预留的一部分低端内存
	long lowmem_reserve[MAX_NR_ZONES];

#ifdef CONFIG_NUMA
	// NUMA节点编号
	int node;
#endif
	// 与该区域相关的页面列表数据
	struct pglist_data	*zone_pgdat;
	// 每个CPU的页面集
	struct per_cpu_pages	__percpu *per_cpu_pageset;
	// 每个CPU的区域统计信息
	struct per_cpu_zonestat	__percpu *per_cpu_zonestats;

	// 高水位线和批量值，为了快速访问而复制到各个页面集中
	int pageset_high;
	int pageset_batch;

#ifndef CONFIG_SPARSEMEM
	// 页面块标志，见 pageblock-flags.h，在SPARSEMEM中，该映射存储在struct mem_section中
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */

	// 区域起始物理页号
	unsigned long		zone_start_pfn;

	/*
	 * spanned_pages is the total pages spanned by the zone, including
	 * holes, which is calculated as:
	 * 	spanned_pages = zone_end_pfn - zone_start_pfn;
	 *
	 * present_pages is physical pages existing within the zone, which
	 * is calculated as:
	 *	present_pages = spanned_pages - absent_pages(pages in holes);
	 *
	 * present_early_pages is present pages existing within the zone
	 * located on memory available since early boot, excluding hotplugged
	 * memory.
	 *
	 * managed_pages is present pages managed by the buddy system, which
	 * is calculated as (reserved_pages includes pages allocated by the
	 * bootmem allocator):
	 *	managed_pages = present_pages - reserved_pages;
	 *
	 * cma pages is present pages that are assigned for CMA use
	 * (MIGRATE_CMA).
	 *
	 * So present_pages may be used by memory hotplug or memory power
	 * management logic to figure out unmanaged pages by checking
	 * (present_pages - managed_pages). And managed_pages should be used
	 * by page allocator and vm scanner to calculate all kinds of watermarks
	 * and thresholds.
	 *
	 * Locking rules:
	 *
	 * zone_start_pfn and spanned_pages are protected by span_seqlock.
	 * It is a seqlock because it has to be read outside of zone->lock,
	 * and it is done in the main allocator path.  But, it is written
	 * quite infrequently.
	 *
	 * The span_seq lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 *
	 * Write access to present_pages at runtime should be protected by
	 * mem_hotplug_begin/done(). Any reader who can't tolerant drift of
	 * present_pages should use get_online_mems() to get a stable value.
	 */
	// 原子计数器，用于跟踪管理的页面数量
	atomic_long_t		managed_pages;

	// 跨越的页面数量，表示区域中分配的所有物理页面的总数
	unsigned long		spanned_pages;

	// 当前实际存在的页面数量，表示当前实际可用的物理页面总数
	unsigned long		present_pages;

#if defined(CONFIG_MEMORY_HOTPLUG)
	// 早期实际存在的页面数量，用于支持热插拔功能
	unsigned long		present_early_pages;
#endif

#ifdef CONFIG_CMA
	// CMA（连续内存区域）页面数量，用于需要连续内存的设备
	unsigned long		cma_pages;
#endif

	// 区域名称，用于标识不同的内存区域
	const char		*name;

#ifdef CONFIG_MEMORY_ISOLATION
	// 隔离的页面块数量，用于解决由于竞争条件导致的页面计数不正确问题
	unsigned long		nr_isolate_pageblock;
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
	// span_seqlock 用于在热插拔操作期间同步spanned_pages和present_pages的更新
	seqlock_t		span_seqlock;
#endif

	// 初始化标志，表示该区域是否已经完成初始化
	int initialized;

	// 用于页面分配器的写密集型字段，以减少缓存未命中
	CACHELINE_PADDING(_pad1_);

	// 不同大小的空闲区域
	struct free_area	free_area[MAX_ORDER + 1];

	#ifdef CONFIG_UNACCEPTED_MEMORY
	// 未被接受的页面列表，所有在此列表上的页面都是MAX_ORDER大小
	struct list_head	unaccepted_pages;
	#endif

	// 区域标志，用于标识各种状态
	unsigned long		flags;

	// 主要用于保护free_area结构体
	spinlock_t		lock;

	// 由紧凑和vmstats使用，减少缓存未命中
	CACHELINE_PADDING(_pad2_);

	// 当空闲页面低于此标记时，读取空闲页面数量时会采取额外步骤
	unsigned long percpu_drift_mark;

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	// 紧凑型免费扫描器应开始的物理页号
	unsigned long		compact_cached_free_pfn;
	// 紧凑型迁移扫描器应开始的物理页号
	unsigned long		compact_cached_migrate_pfn[ASYNC_AND_SYNC];
	// 紧凑型初始化迁移扫描起始页号
	unsigned long		compact_init_migrate_pfn;
	// 紧凑型初始化免费扫描起始页号
	unsigned long		compact_init_free_pfn;
#endif
#ifdef CONFIG_COMPACTION
	/*
	 * 当内存整理失败时，会跳过接下来的1<<compact_defer_shift次内存整理尝试，
	 * 直到下一次再尝试。通过compact_considered来追踪自上次失败以来尝试过的次数。
	 * compact_order_failed记录的是失败的最小内存整理顺序。
	 */
	unsigned int		compact_considered;
	unsigned int		compact_defer_shift;
	int			compact_order_failed;
#endif

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* 当需要清除PG_migrate_skip位时，设置为true */
	bool			compact_blockskip_flush;
#endif

	/* 如果内存区域是连续的，设置为true */
	bool			contiguous;

	/* 用于缓存行对齐的填充 */
	CACHELINE_PADDING(_pad3_);

	/* 区域统计信息 */
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];
	atomic_long_t		vm_numa_event[NR_VM_NUMA_EVENT_ITEMS];
} ____cacheline_internodealigned_in_smp;

enum pgdat_flags {
	PGDAT_DIRTY,			/* reclaim scanning has recently found
					 * many dirty file pages at the tail
					 * of the LRU.
					 */
	PGDAT_WRITEBACK,		/* reclaim scanning has recently found
					 * many pages under writeback
					 */
	PGDAT_RECLAIM_LOCKED,		/* prevents concurrent reclaim */
};

enum zone_flags {
	ZONE_BOOSTED_WATERMARK,		/* zone recently boosted watermarks.
					 * Cleared when kswapd is woken.
					 */
	ZONE_RECLAIM_ACTIVE,		/* kswapd may be scanning the zone. */
};

static inline unsigned long zone_managed_pages(struct zone *zone)
{
	return (unsigned long)atomic_long_read(&zone->managed_pages);
}

static inline unsigned long zone_cma_pages(struct zone *zone)
{
#ifdef CONFIG_CMA
	return zone->cma_pages;
#else
	return 0;
#endif
}

static inline unsigned long zone_end_pfn(const struct zone *zone)
{
	return zone->zone_start_pfn + zone->spanned_pages;
}

static inline bool zone_spans_pfn(const struct zone *zone, unsigned long pfn)
{
	return zone->zone_start_pfn <= pfn && pfn < zone_end_pfn(zone);
}

static inline bool zone_is_initialized(struct zone *zone)
{
	return zone->initialized;
}

static inline bool zone_is_empty(struct zone *zone)
{
	return zone->spanned_pages == 0;
}

#ifndef BUILD_VDSO32_64
/*
 * The zone field is never updated after free_area_init_core()
 * sets it, so none of the operations on it need to be atomic.
 */

/* Page flags: | [SECTION] | [NODE] | ZONE | [LAST_CPUPID] | ... | FLAGS | */
#define SECTIONS_PGOFF		((sizeof(unsigned long)*8) - SECTIONS_WIDTH)
#define NODES_PGOFF		(SECTIONS_PGOFF - NODES_WIDTH)
#define ZONES_PGOFF		(NODES_PGOFF - ZONES_WIDTH)
#define LAST_CPUPID_PGOFF	(ZONES_PGOFF - LAST_CPUPID_WIDTH)
#define KASAN_TAG_PGOFF		(LAST_CPUPID_PGOFF - KASAN_TAG_WIDTH)
#define LRU_GEN_PGOFF		(KASAN_TAG_PGOFF - LRU_GEN_WIDTH)
#define LRU_REFS_PGOFF		(LRU_GEN_PGOFF - LRU_REFS_WIDTH)

/*
 * Define the bit shifts to access each section.  For non-existent
 * sections we define the shift as 0; that plus a 0 mask ensures
 * the compiler will optimise away reference to them.
 */
#define SECTIONS_PGSHIFT	(SECTIONS_PGOFF * (SECTIONS_WIDTH != 0))
#define NODES_PGSHIFT		(NODES_PGOFF * (NODES_WIDTH != 0))
#define ZONES_PGSHIFT		(ZONES_PGOFF * (ZONES_WIDTH != 0))
#define LAST_CPUPID_PGSHIFT	(LAST_CPUPID_PGOFF * (LAST_CPUPID_WIDTH != 0))
#define KASAN_TAG_PGSHIFT	(KASAN_TAG_PGOFF * (KASAN_TAG_WIDTH != 0))

/* NODE:ZONE or SECTION:ZONE is used to ID a zone for the buddy allocator */
#ifdef NODE_NOT_IN_PAGE_FLAGS
#define ZONEID_SHIFT		(SECTIONS_SHIFT + ZONES_SHIFT)
#define ZONEID_PGOFF		((SECTIONS_PGOFF < ZONES_PGOFF) ? \
						SECTIONS_PGOFF : ZONES_PGOFF)
#else
#define ZONEID_SHIFT		(NODES_SHIFT + ZONES_SHIFT)
#define ZONEID_PGOFF		((NODES_PGOFF < ZONES_PGOFF) ? \
						NODES_PGOFF : ZONES_PGOFF)
#endif

#define ZONEID_PGSHIFT		(ZONEID_PGOFF * (ZONEID_SHIFT != 0))

#define ZONES_MASK		((1UL << ZONES_WIDTH) - 1)
#define NODES_MASK		((1UL << NODES_WIDTH) - 1)
#define SECTIONS_MASK		((1UL << SECTIONS_WIDTH) - 1)
#define LAST_CPUPID_MASK	((1UL << LAST_CPUPID_SHIFT) - 1)
#define KASAN_TAG_MASK		((1UL << KASAN_TAG_WIDTH) - 1)
#define ZONEID_MASK		((1UL << ZONEID_SHIFT) - 1)

static inline enum zone_type page_zonenum(const struct page *page)
{
	ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT);
	return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
}

static inline enum zone_type folio_zonenum(const struct folio *folio)
{
	return page_zonenum(&folio->page);
}

#ifdef CONFIG_ZONE_DEVICE
static inline bool is_zone_device_page(const struct page *page)
{
	return page_zonenum(page) == ZONE_DEVICE;
}

/*
 * Consecutive zone device pages should not be merged into the same sgl
 * or bvec segment with other types of pages or if they belong to different
 * pgmaps. Otherwise getting the pgmap of a given segment is not possible
 * without scanning the entire segment. This helper returns true either if
 * both pages are not zone device pages or both pages are zone device pages
 * with the same pgmap.
 */
static inline bool zone_device_pages_have_same_pgmap(const struct page *a,
						     const struct page *b)
{
	if (is_zone_device_page(a) != is_zone_device_page(b))
		return false;
	if (!is_zone_device_page(a))
		return true;
	return a->pgmap == b->pgmap;
}

extern void memmap_init_zone_device(struct zone *, unsigned long,
				    unsigned long, struct dev_pagemap *);
#else
static inline bool is_zone_device_page(const struct page *page)
{
	return false;
}
static inline bool zone_device_pages_have_same_pgmap(const struct page *a,
						     const struct page *b)
{
	return true;
}
#endif

static inline bool folio_is_zone_device(const struct folio *folio)
{
	return is_zone_device_page(&folio->page);
}

static inline bool is_zone_movable_page(const struct page *page)
{
	return page_zonenum(page) == ZONE_MOVABLE;
}

static inline bool folio_is_zone_movable(const struct folio *folio)
{
	return folio_zonenum(folio) == ZONE_MOVABLE;
}
#endif

/*
 * Return true if [start_pfn, start_pfn + nr_pages) range has a non-empty
 * intersection with the given zone
 */
static inline bool zone_intersects(struct zone *zone,
		unsigned long start_pfn, unsigned long nr_pages)
{
	if (zone_is_empty(zone))
		return false;
	if (start_pfn >= zone_end_pfn(zone) ||
	    start_pfn + nr_pages <= zone->zone_start_pfn)
		return false;

	return true;
}

/*
 * The "priority" of VM scanning is how much of the queues we will scan in one
 * go. A value of 12 for DEF_PRIORITY implies that we will scan 1/4096th of the
 * queues ("queue_length >> 12") during an aging round.
 */
#define DEF_PRIORITY 12

/* Maximum number of zones on a zonelist */
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)

enum {
	ZONELIST_FALLBACK,	/* zonelist with fallback */
#ifdef CONFIG_NUMA
	/*
	 * The NUMA zonelists are doubled because we need zonelists that
	 * restrict the allocations to a single node for __GFP_THISNODE.
	 */
	ZONELIST_NOFALLBACK,	/* zonelist without fallback (__GFP_THISNODE) */
#endif
	MAX_ZONELISTS
};

/*
 * This struct contains information about a zone in a zonelist. It is stored
 * here to avoid dereferences into large structures and lookups of tables
 */
struct zoneref {
	struct zone *zone;	/* Pointer to actual zone */
	int zone_idx;		/* zone_idx(zoneref->zone) */
};

/*
 * One allocation request operates on a zonelist. A zonelist
 * is a list of zones, the first one is the 'goal' of the
 * allocation, the other zones are fallback zones, in decreasing
 * priority.
 *
 * To speed the reading of the zonelist, the zonerefs contain the zone index
 * of the entry being read. Helper functions to access information given
 * a struct zoneref are
 *
 * zonelist_zone()	- Return the struct zone * for an entry in _zonerefs
 * zonelist_zone_idx()	- Return the index of the zone for an entry
 * zonelist_node_idx()	- Return the index of the node for an entry
 */
struct zonelist {
	struct zoneref _zonerefs[MAX_ZONES_PER_ZONELIST + 1];
};

/*
 * The array of struct pages for flatmem.
 * It must be declared for SPARSEMEM as well because there are configurations
 * that rely on that.
 */
extern struct page *mem_map;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
struct deferred_split {
	spinlock_t split_queue_lock;
	struct list_head split_queue;
	unsigned long split_queue_len;
};
#endif

#ifdef CONFIG_MEMORY_FAILURE
/*
 * Per NUMA node memory failure handling statistics.
 */
struct memory_failure_stats {
	/*
	 * Number of raw pages poisoned.
	 * Cases not accounted: memory outside kernel control, offline page,
	 * arch-specific memory_failure (SGX), hwpoison_filter() filtered
	 * error events, and unpoison actions from hwpoison_unpoison.
	 */
	unsigned long total;
	/*
	 * Recovery results of poisoned raw pages handled by memory_failure,
	 * in sync with mf_result.
	 * total = ignored + failed + delayed + recovered.
	 * total * PAGE_SIZE * #nodes = /proc/meminfo/HardwareCorrupted.
	 */
	unsigned long ignored;
	unsigned long failed;
	unsigned long delayed;
	unsigned long recovered;
};
#endif

/*
 * On NUMA machines, each NUMA node would have a pg_data_t to describe
 * it's memory layout. On UMA machines there is a single pglist_data which
 * describes the whole memory.
 *
 * Memory statistics and page replacement data structures are maintained on a
 * per-zone basis.
 */
typedef struct pglist_data {
	/*
	 * node_zones 包含仅属于此节点的区域。并非所有区域都已填充，但它包含了完整的列表。
	 * 它被此节点的 node_zonelists 以及其他节点的 node_zonelists 引用。
	 */
	struct zone node_zones[MAX_NR_ZONES];

	/*
	 * node_zonelists 包含对所有节点中所有区域的引用。
	 * 通常，第一个区域将是对此节点的 node_zones 的引用。
	 */
	struct zonelist node_zonelists[MAX_ZONELISTS];

	int nr_zones; /* 此节点中已填充的区域数量 */

#ifdef CONFIG_FLATMEM	/* 意味着 !SPARSEMEM */
	struct page *node_mem_map;
#ifdef CONFIG_PAGE_EXTENSION
	struct page_ext *node_page_ext;
#endif
#endif

#if defined(CONFIG_MEMORY_HOTPLUG) || defined(CONFIG_DEFERRED_STRUCT_PAGE_INIT)
	/*
	 * 必须在任何时候持有 node_size_lock，以确保 node_start_pfn、
	 * node_present_pages、node_spanned_pages 或 nr_zones 保持不变。
	 * 还同步了在延迟页面初始化期间的 pgdat->first_deferred_pfn。
	 *
	 * pgdat_resize_lock() 和 pgdat_resize_unlock() 提供了在不检查
	 * CONFIG_MEMORY_HOTPLUG 或 CONFIG_DEFERRED_STRUCT_PAGE_INIT 的情况下操作 node_size_lock 的方法。
	 *
	 * 在 zone->lock 和 zone->span_seqlock 之上嵌套。
	 */
	spinlock_t node_size_lock;
#endif

	unsigned long node_start_pfn;
	unsigned long node_present_pages; /* total number of physical pages */
	unsigned long node_spanned_pages; /* total size of physical page
					     range, including holes */
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;

	/* 用于因不同原因限制回收的工作队列。 */
	wait_queue_head_t reclaim_wait[NR_VMSCAN_THROTTLE];

	atomic_t nr_writeback_throttled;/* 写回限制的任务数 */
	unsigned long nr_reclaim_start;	/* 开始限制时已写入的页面数 */

#ifdef CONFIG_MEMORY_HOTPLUG
	struct mutex kswapd_lock;
#endif
	struct task_struct *kswapd;	/* 受 kswapd_lock 保护 */
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;

	int kswapd_failures;		/* 'reclaimed == 0' 运行次数 */

#ifdef CONFIG_COMPACTION
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
	bool proactive_compact_trigger;
#endif
	/*
	 * 这是用户空间分配不可用的页面预留量。
	 */
	unsigned long		totalreserve_pages;

#ifdef CONFIG_NUMA
	/*
	 * 如果未映射的页面更多，则激活节点回收。
	 */
	unsigned long		min_unmapped_pages;
	unsigned long		min_slab_pages;
#endif /* CONFIG_NUMA */

	/* Write-intensive fields used by page reclaim */
	CACHELINE_PADDING(_pad1_);

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
	/*
	 * 如果在大型机器上延迟内存初始化，则这是需要初始化的第一个 PFN。
	 */
	unsigned long first_deferred_pfn;
#endif /* CONFIG_DEFERRED_STRUCT_PAGE_INIT */

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	struct deferred_split deferred_split_queue;
#endif

#ifdef CONFIG_NUMA_BALANCING
	/* 当前促进速率限制周期的开始时间（毫秒） */
	unsigned int nbp_rl_start;
	/* 当前速率限制周期开始时的促进候选页面数 */
	unsigned long nbp_rl_nr_cand;
	/* 促进阈值（毫秒） */
	unsigned int nbp_threshold;
	/* 当前促进阈值调整周期的开始时间（毫秒） */
	unsigned int nbp_th_start;
	/*
	 * 当前促进阈值调整周期开始时的促进候选页面数
	 */
	unsigned long nbp_th_nr_cand;
#endif

	/* 常见的页面回收扫描器字段 */

	/*
	 * 注意：如果启用了 MEMCG，则此字段未使用。
	 *
	 * 使用 mem_cgroup_lruvec() 查找 lruvecs。
	 */
	struct lruvec		__lruvec;

	unsigned long		flags;

#ifdef CONFIG_LRU_GEN
	/* kswap mm 走查数据 */
	struct lru_gen_mm_walk mm_walk;
	/* lru_gen_folio 列表 */
	struct lru_gen_memcg memcg_lru;
#endif

	// https://lore.kernel.org/all/20220826230642.566725-1-shakeelb@google.com/T/#u
	CACHELINE_PADDING(_pad2_);

	/* 每个节点的 vmstats */
	struct per_cpu_nodestat __percpu *per_cpu_nodestats;
	atomic_long_t		vm_stat[NR_VM_NODE_STAT_ITEMS];
#ifdef CONFIG_NUMA
	struct memory_tier __rcu *memtier;
#endif
#ifdef CONFIG_MEMORY_FAILURE
	struct memory_failure_stats mf_stats;
#endif
} pg_data_t;
#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)

#define node_start_pfn(nid)	(NODE_DATA(nid)->node_start_pfn)
#define node_end_pfn(nid) pgdat_end_pfn(NODE_DATA(nid))

static inline unsigned long pgdat_end_pfn(pg_data_t *pgdat)
{
	return pgdat->node_start_pfn + pgdat->node_spanned_pages;
}

#include <linux/memory_hotplug.h>

void build_all_zonelists(pg_data_t *pgdat);
void wakeup_kswapd(struct zone *zone, gfp_t gfp_mask, int order,
		   enum zone_type highest_zoneidx);
bool __zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
			 int highest_zoneidx, unsigned int alloc_flags,
			 long free_pages);
bool zone_watermark_ok(struct zone *z, unsigned int order,
		unsigned long mark, int highest_zoneidx,
		unsigned int alloc_flags);
bool zone_watermark_ok_safe(struct zone *z, unsigned int order,
		unsigned long mark, int highest_zoneidx);
/*
 * Memory initialization context, use to differentiate memory added by
 * the platform statically or via memory hotplug interface.
 */
enum meminit_context {
	MEMINIT_EARLY,
	MEMINIT_HOTPLUG,
};

extern void init_currently_empty_zone(struct zone *zone, unsigned long start_pfn,
				     unsigned long size);

extern void lruvec_init(struct lruvec *lruvec);

static inline struct pglist_data *lruvec_pgdat(struct lruvec *lruvec)
{
#ifdef CONFIG_MEMCG
	return lruvec->pgdat;
#else
	return container_of(lruvec, struct pglist_data, __lruvec);
#endif
}

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
int local_memory_node(int node_id);
#else
static inline int local_memory_node(int node_id) { return node_id; };
#endif

/*
 * zone_idx() returns 0 for the ZONE_DMA zone, 1 for the ZONE_NORMAL zone, etc.
 */
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

#ifdef CONFIG_ZONE_DEVICE
static inline bool zone_is_zone_device(struct zone *zone)
{
	return zone_idx(zone) == ZONE_DEVICE;
}
#else
static inline bool zone_is_zone_device(struct zone *zone)
{
	return false;
}
#endif

/*
 * Returns true if a zone has pages managed by the buddy allocator.
 * All the reclaim decisions have to use this function rather than
 * populated_zone(). If the whole zone is reserved then we can easily
 * end up with populated_zone() && !managed_zone().
 */
static inline bool managed_zone(struct zone *zone)
{
	return zone_managed_pages(zone);
}

/* Returns true if a zone has memory */
static inline bool populated_zone(struct zone *zone)
{
	return zone->present_pages;
}

#ifdef CONFIG_NUMA
static inline int zone_to_nid(struct zone *zone)
{
	return zone->node;
}

static inline void zone_set_nid(struct zone *zone, int nid)
{
	zone->node = nid;
}
#else
static inline int zone_to_nid(struct zone *zone)
{
	return 0;
}

static inline void zone_set_nid(struct zone *zone, int nid) {}
#endif

extern int movable_zone;

static inline int is_highmem_idx(enum zone_type idx)
{
#ifdef CONFIG_HIGHMEM
	return (idx == ZONE_HIGHMEM ||
		(idx == ZONE_MOVABLE && movable_zone == ZONE_HIGHMEM));
#else
	return 0;
#endif
}

/**
 * is_highmem - helper function to quickly check if a struct zone is a
 *              highmem zone or not.  This is an attempt to keep references
 *              to ZONE_{DMA/NORMAL/HIGHMEM/etc} in general code to a minimum.
 * @zone: pointer to struct zone variable
 * Return: 1 for a highmem zone, 0 otherwise
 */
static inline int is_highmem(struct zone *zone)
{
	return is_highmem_idx(zone_idx(zone));
}

#ifdef CONFIG_ZONE_DMA
bool has_managed_dma(void);
#else
static inline bool has_managed_dma(void)
{
	return false;
}
#endif


#ifndef CONFIG_NUMA

extern struct pglist_data contig_page_data;
static inline struct pglist_data *NODE_DATA(int nid)
{
	return &contig_page_data;
}

#else /* CONFIG_NUMA */

#include <asm/mmzone.h>

#endif /* !CONFIG_NUMA */

extern struct pglist_data *first_online_pgdat(void);
extern struct pglist_data *next_online_pgdat(struct pglist_data *pgdat);
extern struct zone *next_zone(struct zone *zone);

/**
 * for_each_online_pgdat - helper macro to iterate over all online nodes
 * @pgdat: pointer to a pg_data_t variable
 */
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
/**
 * for_each_zone - helper macro to iterate over all memory zones
 * @zone: pointer to struct zone variable
 *
 * The user only needs to declare the zone variable, for_each_zone
 * fills it in.
 */
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))

#define for_each_populated_zone(zone)		        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))			\
		if (!populated_zone(zone))		\
			; /* do nothing */		\
		else

static inline struct zone *zonelist_zone(struct zoneref *zoneref)
{
	return zoneref->zone;
}

static inline int zonelist_zone_idx(struct zoneref *zoneref)
{
	return zoneref->zone_idx;
}

static inline int zonelist_node_idx(struct zoneref *zoneref)
{
	return zone_to_nid(zoneref->zone);
}

struct zoneref *__next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes);

/**
 * next_zones_zonelist - Returns the next zone at or below highest_zoneidx within the allowed nodemask using a cursor within a zonelist as a starting point
 * @z: The cursor used as a starting point for the search
 * @highest_zoneidx: The zone index of the highest zone to return
 * @nodes: An optional nodemask to filter the zonelist with
 *
 * This function returns the next zone at or below a given zone index that is
 * within the allowed nodemask using a cursor as the starting point for the
 * search. The zoneref returned is a cursor that represents the current zone
 * being examined. It should be advanced by one before calling
 * next_zones_zonelist again.
 *
 * Return: the next zone at or below highest_zoneidx within the allowed
 * nodemask using a cursor within a zonelist as a starting point
 */
static __always_inline struct zoneref *next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	if (likely(!nodes && zonelist_zone_idx(z) <= highest_zoneidx))
		return z;
	return __next_zones_zonelist(z, highest_zoneidx, nodes);
}

/**
 * first_zones_zonelist - Returns the first zone at or below highest_zoneidx within the allowed nodemask in a zonelist
 * @zonelist: The zonelist to search for a suitable zone
 * @highest_zoneidx: The zone index of the highest zone to return
 * @nodes: An optional nodemask to filter the zonelist with
 *
 * This function returns the first zone at or below a given zone index that is
 * within the allowed nodemask. The zoneref returned is a cursor that can be
 * used to iterate the zonelist with next_zones_zonelist by advancing it by
 * one before calling.
 *
 * When no eligible zone is found, zoneref->zone is NULL (zoneref itself is
 * never NULL). This may happen either genuinely, or due to concurrent nodemask
 * update due to cpuset modification.
 *
 * Return: Zoneref pointer for the first suitable zone found
 */
static inline struct zoneref *first_zones_zonelist(struct zonelist *zonelist,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	return next_zones_zonelist(zonelist->_zonerefs,
							highest_zoneidx, nodes);
}

/**
 * for_each_zone_zonelist_nodemask - helper macro to iterate over valid zones in a zonelist at or below a given zone index and within a nodemask
 * @zone: The current zone in the iterator
 * @z: The current pointer within zonelist->_zonerefs being iterated
 * @zlist: The zonelist being iterated
 * @highidx: The zone index of the highest zone to return
 * @nodemask: Nodemask allowed by the allocator
 *
 * This iterator iterates though all zones at or below a given zone index and
 * within a given nodemask
 */
#define for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (z = first_zones_zonelist(zlist, highidx, nodemask), zone = zonelist_zone(z);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))

#define for_next_zone_zonelist_nodemask(zone, z, highidx, nodemask) \
	for (zone = z->zone;	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))


/**
 * for_each_zone_zonelist - helper macro to iterate over valid zones in a zonelist at or below a given zone index
 * @zone: The current zone in the iterator
 * @z: The current pointer within zonelist->zones being iterated
 * @zlist: The zonelist being iterated
 * @highidx: The zone index of the highest zone to return
 *
 * This iterator iterates though all zones at or below a given zone index.
 */
#define for_each_zone_zonelist(zone, z, zlist, highidx) \
	for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, NULL)

/* Whether the 'nodes' are all movable nodes */
static inline bool movable_only_nodes(nodemask_t *nodes)
{
	struct zonelist *zonelist;
	struct zoneref *z;
	int nid;

	if (nodes_empty(*nodes))
		return false;

	/*
	 * We can chose arbitrary node from the nodemask to get a
	 * zonelist as they are interlinked. We just need to find
	 * at least one zone that can satisfy kernel allocations.
	 */
	nid = first_node(*nodes);
	zonelist = &NODE_DATA(nid)->node_zonelists[ZONELIST_FALLBACK];
	z = first_zones_zonelist(zonelist, ZONE_NORMAL,	nodes);
	return (!z->zone) ? true : false;
}


#ifdef CONFIG_SPARSEMEM
#include <asm/sparsemem.h>
#endif

#ifdef CONFIG_FLATMEM
#define pfn_to_nid(pfn)		(0)
#endif

#ifdef CONFIG_SPARSEMEM

/*
 * PA_SECTION_SHIFT		physical address to/from section number
 * PFN_SECTION_SHIFT		pfn to/from section number
 */
#define PA_SECTION_SHIFT	(SECTION_SIZE_BITS)
#define PFN_SECTION_SHIFT	(SECTION_SIZE_BITS - PAGE_SHIFT)

#define NR_MEM_SECTIONS		(1UL << SECTIONS_SHIFT)

#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGE_SECTION_MASK	(~(PAGES_PER_SECTION-1))

#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)

#if (MAX_ORDER + PAGE_SHIFT) > SECTION_SIZE_BITS
#error Allocator MAX_ORDER exceeds SECTION_SIZE
#endif

static inline unsigned long pfn_to_section_nr(unsigned long pfn)
{
	return pfn >> PFN_SECTION_SHIFT;
}
static inline unsigned long section_nr_to_pfn(unsigned long sec)
{
	return sec << PFN_SECTION_SHIFT;
}

#define SECTION_ALIGN_UP(pfn)	(((pfn) + PAGES_PER_SECTION - 1) & PAGE_SECTION_MASK)
#define SECTION_ALIGN_DOWN(pfn)	((pfn) & PAGE_SECTION_MASK)

#define SUBSECTION_SHIFT 21
#define SUBSECTION_SIZE (1UL << SUBSECTION_SHIFT)

#define PFN_SUBSECTION_SHIFT (SUBSECTION_SHIFT - PAGE_SHIFT)
#define PAGES_PER_SUBSECTION (1UL << PFN_SUBSECTION_SHIFT)
#define PAGE_SUBSECTION_MASK (~(PAGES_PER_SUBSECTION-1))

#if SUBSECTION_SHIFT > SECTION_SIZE_BITS
#error Subsection size exceeds section size
#else
#define SUBSECTIONS_PER_SECTION (1UL << (SECTION_SIZE_BITS - SUBSECTION_SHIFT))
#endif

#define SUBSECTION_ALIGN_UP(pfn) ALIGN((pfn), PAGES_PER_SUBSECTION)
#define SUBSECTION_ALIGN_DOWN(pfn) ((pfn) & PAGE_SUBSECTION_MASK)

struct mem_section_usage {
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	DECLARE_BITMAP(subsection_map, SUBSECTIONS_PER_SECTION);
#endif
	/* See declaration of similar field in struct zone */
	unsigned long pageblock_flags[0];
};

void subsection_map_init(unsigned long pfn, unsigned long nr_pages);

struct page;
struct page_ext;
struct mem_section {
	/*
	 * This is, logically, a pointer to an array of struct
	 * pages.  However, it is stored with some other magic.
	 * (see sparse.c::sparse_init_one_section())
	 *
	 * Additionally during early boot we encode node id of
	 * the location of the section here to guide allocation.
	 * (see sparse.c::memory_present())
	 *
	 * Making it a UL at least makes someone do a cast
	 * before using it wrong.
	 */
	unsigned long section_mem_map;

	struct mem_section_usage *usage;
#ifdef CONFIG_PAGE_EXTENSION
	/*
	 * If SPARSEMEM, pgdat doesn't have page_ext pointer. We use
	 * section. (see page_ext.h about this.)
	 */
	struct page_ext *page_ext;
	unsigned long pad;
#endif
	/*
	 * WARNING: mem_section must be a power-of-2 in size for the
	 * calculation and use of SECTION_ROOT_MASK to make sense.
	 */
};

#ifdef CONFIG_SPARSEMEM_EXTREME
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#else
#define SECTIONS_PER_ROOT	1
#endif

#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define NR_SECTION_ROOTS	DIV_ROUND_UP(NR_MEM_SECTIONS, SECTIONS_PER_ROOT)
#define SECTION_ROOT_MASK	(SECTIONS_PER_ROOT - 1)

#ifdef CONFIG_SPARSEMEM_EXTREME
extern struct mem_section **mem_section;
#else
extern struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT];
#endif

static inline unsigned long *section_to_usemap(struct mem_section *ms)
{
	return ms->usage->pageblock_flags;
}

static inline struct mem_section *__nr_to_section(unsigned long nr)
{
	unsigned long root = SECTION_NR_TO_ROOT(nr);

	if (unlikely(root >= NR_SECTION_ROOTS))
		return NULL;

#ifdef CONFIG_SPARSEMEM_EXTREME
	if (!mem_section || !mem_section[root])
		return NULL;
#endif
	return &mem_section[root][nr & SECTION_ROOT_MASK];
}
extern size_t mem_section_usage_size(void);

/*
 * We use the lower bits of the mem_map pointer to store
 * a little bit of information.  The pointer is calculated
 * as mem_map - section_nr_to_pfn(pnum).  The result is
 * aligned to the minimum alignment of the two values:
 *   1. All mem_map arrays are page-aligned.
 *   2. section_nr_to_pfn() always clears PFN_SECTION_SHIFT
 *      lowest bits.  PFN_SECTION_SHIFT is arch-specific
 *      (equal SECTION_SIZE_BITS - PAGE_SHIFT), and the
 *      worst combination is powerpc with 256k pages,
 *      which results in PFN_SECTION_SHIFT equal 6.
 * To sum it up, at least 6 bits are available on all architectures.
 * However, we can exceed 6 bits on some other architectures except
 * powerpc (e.g. 15 bits are available on x86_64, 13 bits are available
 * with the worst case of 64K pages on arm64) if we make sure the
 * exceeded bit is not applicable to powerpc.
 */
enum {
	SECTION_MARKED_PRESENT_BIT,
	SECTION_HAS_MEM_MAP_BIT,
	SECTION_IS_ONLINE_BIT,
	SECTION_IS_EARLY_BIT,
#ifdef CONFIG_ZONE_DEVICE
	SECTION_TAINT_ZONE_DEVICE_BIT,
#endif
	SECTION_MAP_LAST_BIT,
};

#define SECTION_MARKED_PRESENT		BIT(SECTION_MARKED_PRESENT_BIT)
#define SECTION_HAS_MEM_MAP		BIT(SECTION_HAS_MEM_MAP_BIT)
#define SECTION_IS_ONLINE		BIT(SECTION_IS_ONLINE_BIT)
#define SECTION_IS_EARLY		BIT(SECTION_IS_EARLY_BIT)
#ifdef CONFIG_ZONE_DEVICE
#define SECTION_TAINT_ZONE_DEVICE	BIT(SECTION_TAINT_ZONE_DEVICE_BIT)
#endif
#define SECTION_MAP_MASK		(~(BIT(SECTION_MAP_LAST_BIT) - 1))
#define SECTION_NID_SHIFT		SECTION_MAP_LAST_BIT

static inline struct page *__section_mem_map_addr(struct mem_section *section)
{
	unsigned long map = section->section_mem_map;
	map &= SECTION_MAP_MASK;
	return (struct page *)map;
}

static inline int present_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_MARKED_PRESENT));
}

static inline int present_section_nr(unsigned long nr)
{
	return present_section(__nr_to_section(nr));
}

static inline int valid_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_HAS_MEM_MAP));
}

static inline int early_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_IS_EARLY));
}

static inline int valid_section_nr(unsigned long nr)
{
	return valid_section(__nr_to_section(nr));
}

static inline int online_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_IS_ONLINE));
}

#ifdef CONFIG_ZONE_DEVICE
static inline int online_device_section(struct mem_section *section)
{
	unsigned long flags = SECTION_IS_ONLINE | SECTION_TAINT_ZONE_DEVICE;

	return section && ((section->section_mem_map & flags) == flags);
}
#else
static inline int online_device_section(struct mem_section *section)
{
	return 0;
}
#endif

static inline int online_section_nr(unsigned long nr)
{
	return online_section(__nr_to_section(nr));
}

#ifdef CONFIG_MEMORY_HOTPLUG
void online_mem_sections(unsigned long start_pfn, unsigned long end_pfn);
void offline_mem_sections(unsigned long start_pfn, unsigned long end_pfn);
#endif

static inline struct mem_section *__pfn_to_section(unsigned long pfn)
{
	return __nr_to_section(pfn_to_section_nr(pfn));
}

extern unsigned long __highest_present_section_nr;

static inline int subsection_map_index(unsigned long pfn)
{
	return (pfn & ~(PAGE_SECTION_MASK)) / PAGES_PER_SUBSECTION;
}

#ifdef CONFIG_SPARSEMEM_VMEMMAP
static inline int pfn_section_valid(struct mem_section *ms, unsigned long pfn)
{
	int idx = subsection_map_index(pfn);

	return test_bit(idx, ms->usage->subsection_map);
}
#else
static inline int pfn_section_valid(struct mem_section *ms, unsigned long pfn)
{
	return 1;
}
#endif

#ifndef CONFIG_HAVE_ARCH_PFN_VALID
/**
 * pfn_valid - check if there is a valid memory map entry for a PFN
 * @pfn: the page frame number to check
 *
 * Check if there is a valid memory map entry aka struct page for the @pfn.
 * Note, that availability of the memory map entry does not imply that
 * there is actual usable memory at that @pfn. The struct page may
 * represent a hole or an unusable page frame.
 *
 * Return: 1 for PFNs that have memory map entries and 0 otherwise
 */
static inline int pfn_valid(unsigned long pfn)
{
	struct mem_section *ms;

	/*
	 * Ensure the upper PAGE_SHIFT bits are clear in the
	 * pfn. Else it might lead to false positives when
	 * some of the upper bits are set, but the lower bits
	 * match a valid pfn.
	 */
	if (PHYS_PFN(PFN_PHYS(pfn)) != pfn)
		return 0;

	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	ms = __pfn_to_section(pfn);
	if (!valid_section(ms))
		return 0;
	/*
	 * Traditionally early sections always returned pfn_valid() for
	 * the entire section-sized span.
	 */
	return early_section(ms) || pfn_section_valid(ms, pfn);
}
#endif

static inline int pfn_in_present_section(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return present_section(__pfn_to_section(pfn));
}

static inline unsigned long next_present_section_nr(unsigned long section_nr)
{
	while (++section_nr <= __highest_present_section_nr) {
		if (present_section_nr(section_nr))
			return section_nr;
	}

	return -1;
}

/*
 * These are _only_ used during initialisation, therefore they
 * can use __initdata ...  They could have names to indicate
 * this restriction.
 */
#ifdef CONFIG_NUMA
#define pfn_to_nid(pfn)							\
({									\
	unsigned long __pfn_to_nid_pfn = (pfn);				\
	page_to_nid(pfn_to_page(__pfn_to_nid_pfn));			\
})
#else
#define pfn_to_nid(pfn)		(0)
#endif

void sparse_init(void);
#else
#define sparse_init()	do {} while (0)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define pfn_in_present_section pfn_valid
#define subsection_map_init(_pfn, _nr_pages) do {} while (0)
#endif /* CONFIG_SPARSEMEM */

#endif /* !__GENERATING_BOUNDS.H */
#endif /* !__ASSEMBLY__ */
#endif /* _LINUX_MMZONE_H */
