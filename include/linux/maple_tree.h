/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_MAPLE_TREE_H
#define _LINUX_MAPLE_TREE_H
/*
 * Maple Tree - An RCU-safe adaptive tree for storing ranges
 * Copyright (c) 2018-2022 Oracle
 * Authors:     Liam R. Howlett <Liam.Howlett@Oracle.com>
 *              Matthew Wilcox <willy@infradead.org>
 */

#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
/* #define CONFIG_MAPLE_RCU_DISABLED */

/*
 * Allocated nodes are mutable until they have been inserted into the tree,
 * at which time they cannot change their type until they have been removed
 * from the tree and an RCU grace period has passed.
 *
 * Removed nodes have their ->parent set to point to themselves.  RCU readers
 * check ->parent before relying on the value that they loaded from the
 * slots array.  This lets us reuse the slots array for the RCU head.
 *
 * Nodes in the tree point to their parent unless bit 0 is set.
 */

/*
 * 节点的分配与状态转换说明：
 *
 * 节点分配后，它是可变的，直到被插入到树中。
 * 插入树中后，节点不能改变其类型，直到它被从树中移除
 * 并且经过一个RCU（Read-Copy-Update）宽限期。
 *
 * 移除的节点会将其->parent指针指向自身。RCU读取器
 * 在依赖slots数组中加载的值之前会检查->parent。
 * 这允许我们为RCU头部重新使用slots数组。
 *
 * 树中的节点通常指向它们的父节点，除非最低位（bit 0）被设置。
 */
#if defined(CONFIG_64BIT) || defined(BUILD_VDSO32_64)
/* 64bit sizes */
// 定义MAPLE_NODE_SLOTS的宏，用于分配节点槽位，包括指向父节点的指针
#define MAPLE_NODE_SLOTS	31	/* 256 bytes including ->parent */

// 定义MAPLE_RANGE64_SLOTS的宏，特定于64位范围的数据结构槽位分配
#define MAPLE_RANGE64_SLOTS	16	/* 256 bytes */

// 定义MAPLE_ARANGE64_SLOTS的宏，针对64位数组范围的数据结构槽位分配
#define MAPLE_ARANGE64_SLOTS	10	/* 240 bytes */

// 定义MAPLE_ARANGE64_META_MAX的宏，用于标识元数据的槽位范围上限
#define MAPLE_ARANGE64_META_MAX	15	/* Out of range for metadata */

// 定义MAPLE_ALLOC_SLOTS的宏，计算可分配的槽位总数，减去一个用于其他用途
#define MAPLE_ALLOC_SLOTS	(MAPLE_NODE_SLOTS - 1)
#else
/* 32bit sizes */
#define MAPLE_NODE_SLOTS	63	/* 256 bytes including ->parent */
#define MAPLE_RANGE64_SLOTS	32	/* 256 bytes */
#define MAPLE_ARANGE64_SLOTS	21	/* 240 bytes */
#define MAPLE_ARANGE64_META_MAX	31	/* Out of range for metadata */
#define MAPLE_ALLOC_SLOTS	(MAPLE_NODE_SLOTS - 2)
#endif /* defined(CONFIG_64BIT) || defined(BUILD_VDSO32_64) */

#define MAPLE_NODE_MASK		255UL

/*
 * The node->parent of the root node has bit 0 set and the rest of the pointer
 * is a pointer to the tree itself.  No more bits are available in this pointer
 * (on m68k, the data structure may only be 2-byte aligned).
 *
 * Internal non-root nodes can only have maple_range_* nodes as parents.  The
 * parent pointer is 256B aligned like all other tree nodes.  When storing a 32
 * or 64 bit values, the offset can fit into 4 bits.  The 16 bit values need an
 * extra bit to store the offset.  This extra bit comes from a reuse of the last
 * bit in the node type.  This is possible by using bit 1 to indicate if bit 2
 * is part of the type or the slot.
 *
 * Once the type is decided, the decision of an allocation range type or a range
 * type is done by examining the immutable tree flag for the MAPLE_ALLOC_RANGE
 * flag.
 *
 *  Node types:
 *   0x??1 = Root
 *   0x?00 = 16 bit nodes
 *   0x010 = 32 bit nodes
 *   0x110 = 64 bit nodes
 *
 *  Slot size and location in the parent pointer:
 *   type  : slot location
 *   0x??1 : Root
 *   0x?00 : 16 bit values, type in 0-1, slot in 2-6
 *   0x010 : 32 bit values, type in 0-2, slot in 3-6
 *   0x110 : 64 bit values, type in 0-2, slot in 3-6
 */
/*
 * 根节点的node->parent的第0位被设置，其余部分是指向树本身的指针。
 * 在m68k上，此数据结构可能仅支持2字节对齐。
 *
 * 内部非根节点只能有maple_range_*类型的节点作为父节点。父指针与其他所有树节点一样，是256字节对齐的。
 * 存储32位或64位值时，偏移量可以放入4位中。16位值需要额外一位来存储偏移量。
 * 这一额外位来自节点类型中的最后一位。通过使用第1位来指示第2位是属于类型还是槽位，实现了这一点。
 *
 * 一旦确定了类型，通过检查MAPLE_ALLOC_RANGE标志来决定分配范围类型还是范围类型。
 *
 * 节点类型定义：
 *   0x??1 = 根节点
 *   0x?00 = 16位节点
 *   0x010 = 32位节点
 *   0x110 = 64位节点
 *
 * 槽大小及在父指针中的位置：
 *   类型  : 槽位置
 *   0x??1 : 根节点
 *   0x?00 : 16位值，类型在0-1位，槽在2-6位
 *   0x010 : 32位值，类型在0-2位，槽在3-6位
 *   0x110 : 64位值，类型在0-2位，槽在3-6位
 */

/*
 * This metadata is used to optimize the gap updating code and in reverse
 * searching for gaps or any other code that needs to find the end of the data.
 */
/*
 * 这个元数据用于优化间隙更新代码，并用于反向搜索间隙或任何其他需要找到数据末尾的代码。
 */
struct maple_metadata {
	unsigned char end;
	unsigned char gap;
};

/*
 * Leaf nodes do not store pointers to nodes, they store user data.  Users may
 * store almost any bit pattern.  As noted above, the optimisation of storing an
 * entry at 0 in the root pointer cannot be done for data which have the bottom
 * two bits set to '10'.  We also reserve values with the bottom two bits set to
 * '10' which are below 4096 (ie 2, 6, 10 .. 4094) for internal use.  Some APIs
 * return errnos as a negative errno shifted right by two bits and the bottom
 * two bits set to '10', and while choosing to store these values in the array
 * is not an error, it may lead to confusion if you're testing for an error with
 * mas_is_err().
 *
 * Non-leaf nodes store the type of the node pointed to (enum maple_type in bits
 * 3-6), bit 2 is reserved.  That leaves bits 0-1 unused for now.
 *
 * In regular B-Tree terms, pivots are called keys.  The term pivot is used to
 * indicate that the tree is specifying ranges,  Pivots may appear in the
 * subtree with an entry attached to the value whereas keys are unique to a
 * specific position of a B-tree.  Pivot values are inclusive of the slot with
 * the same index.
 */
/*
 * 关于叶子节点和非叶子节点存储方式的说明
 *
 * 叶子节点不存储指向其他节点的指针，它们存储用户数据。用户可以存储几乎所有位模式的数据。
 * 如上所述，由于用户数据的最低两位可能设置为'10'，因此不能在根指针处存储用户数据。
 * 同时，我们还保留了最低两位为'10'且小于4096的值（即2、6、10...4094）用于内部使用。
 * 一些API返回的错误号会作为负的errno右移两位，并将最低两位设置为'10'。
 * 虽然选择将这些值存储在数组中不是错误，但如果使用mas_is_err()测试错误时可能会导致混淆。
 *
 * 非叶子节点存储所指向节点的类型（在位3-6中的maple_type枚举），位2被保留。这留下了位0-1目前未使用。
 *
 * 从常规B树的角度来说，掉转（pivots）被称为键（keys）。然而，在这里使用术语掉转是为了表明树指定的是范围。
 * 掉转可能出现在子树中，并且可以与值相关联，而键在B树的特定位置是唯一的。掉转值包括具有相同索引的槽中的值。
 */

struct maple_range_64 {
	struct maple_pnode *parent;
	unsigned long pivot[MAPLE_RANGE64_SLOTS - 1];
	union {
		void __rcu *slot[MAPLE_RANGE64_SLOTS];
		struct {
			void __rcu *pad[MAPLE_RANGE64_SLOTS - 1];
			struct maple_metadata meta;
		};
	};
};

/*
 * At tree creation time, the user can specify that they're willing to trade off
 * storing fewer entries in a tree in return for storing more information in
 * each node.
 *
 * The maple tree supports recording the largest range of NULL entries available
 * in this node, also called gaps.  This optimises the tree for allocating a
 * range.
 */
/*
 * 在树创建时，用户可以指定是否愿意在每个节点存储更多信息来换取在树中存储较少的条目。
 *
 * Maple树支持记录此节点中最大的空条目范围，也称为间隙。这优化了树以便于分配一个范围。
 */
struct maple_arange_64 {
	struct maple_pnode *parent;
	unsigned long pivot[MAPLE_ARANGE64_SLOTS - 1];
	void __rcu *slot[MAPLE_ARANGE64_SLOTS];
	unsigned long gap[MAPLE_ARANGE64_SLOTS];
	struct maple_metadata meta;
};

struct maple_alloc {
	unsigned long total;
	unsigned char node_count;
	unsigned int request_count;
	struct maple_alloc *slot[MAPLE_ALLOC_SLOTS];
};

struct maple_topiary {
	struct maple_pnode *parent;
	struct maple_enode *next; /* Overlaps the pivot */
};

enum maple_type {
	maple_dense,
	maple_leaf_64,
	maple_range_64,
	maple_arange_64,
};


/**
 * DOC: Maple tree flags
 *
 * * MT_FLAGS_ALLOC_RANGE	- Track gaps in this tree
 * * MT_FLAGS_USE_RCU		- Operate in RCU mode
 * * MT_FLAGS_HEIGHT_OFFSET	- The position of the tree height in the flags
 * * MT_FLAGS_HEIGHT_MASK	- The mask for the maple tree height value
 * * MT_FLAGS_LOCK_MASK		- How the mt_lock is used
 * * MT_FLAGS_LOCK_IRQ		- Acquired irq-safe
 * * MT_FLAGS_LOCK_BH		- Acquired bh-safe
 * * MT_FLAGS_LOCK_EXTERN	- mt_lock is not used
 *
 * MAPLE_HEIGHT_MAX	The largest height that can be stored
 */
/**
 * DOC: Maple tree flags
 *
 * * MT_FLAGS_ALLOC_RANGE	- 跟踪此树中的空隙
 * * MT_FLAGS_USE_RCU		- 以RCU模式运行
 * * MT_FLAGS_HEIGHT_OFFSET	- 树高度在标志中的位置
 * * MT_FLAGS_HEIGHT_MASK	- Maple树高度值的掩码
 * * MT_FLAGS_LOCK_MASK		- mt_lock 的使用方式
 * * MT_FLAGS_LOCK_IRQ		- 以irq安全的方式获取
 * * MT_FLAGS_LOCK_BH		- 以bh安全的方式获取
 * * MT_FLAGS_LOCK_EXTERN	- 不使用mt_lock
 *
 * MAPLE_HEIGHT_MAX		- 可存储的最大高度
 */
#define MT_FLAGS_ALLOC_RANGE	0x01
#define MT_FLAGS_USE_RCU	0x02
#define MT_FLAGS_HEIGHT_OFFSET	0x02
#define MT_FLAGS_HEIGHT_MASK	0x7C
#define MT_FLAGS_LOCK_MASK	0x300
#define MT_FLAGS_LOCK_IRQ	0x100
#define MT_FLAGS_LOCK_BH	0x200
#define MT_FLAGS_LOCK_EXTERN	0x300

#define MAPLE_HEIGHT_MAX	31


#define MAPLE_NODE_TYPE_MASK	0x0F
#define MAPLE_NODE_TYPE_SHIFT	0x03

#define MAPLE_RESERVED_RANGE	4096

#ifdef CONFIG_LOCKDEP
typedef struct lockdep_map *lockdep_map_p;
#define mt_lock_is_held(mt)	lock_is_held(mt->ma_external_lock)
#define mt_set_external_lock(mt, lock)					\
	(mt)->ma_external_lock = &(lock)->dep_map
#else
typedef struct { /* nothing */ } lockdep_map_p;
#define mt_lock_is_held(mt)	1
#define mt_set_external_lock(mt, lock)	do { } while (0)
#endif

/*
 * If the tree contains a single entry at index 0, it is usually stored in
 * tree->ma_root.  To optimise for the page cache, an entry which ends in '00',
 * '01' or '11' is stored in the root, but an entry which ends in '10' will be
 * stored in a node.  Bits 3-6 are used to store enum maple_type.
 *
 * The flags are used both to store some immutable information about this tree
 * (set at tree creation time) and dynamic information set under the spinlock.
 *
 * Another use of flags are to indicate global states of the tree.  This is the
 * case with the MAPLE_USE_RCU flag, which indicates the tree is currently in
 * RCU mode.  This mode was added to allow the tree to reuse nodes instead of
 * re-allocating and RCU freeing nodes when there is a single user.
 */
/*
 * 此注释解释了 maple 树的结构和特性。具体来说：
 *
 * 如果树在索引 0 处包含一个条目，则通常将其存储在 tree->ma_root 中。
 * 为了优化页面缓存，如果条目以 '00', '01' 或 '11' 结尾，则存储在根中；
 * 但若以 '10' 结尾的条目将存储在节点中。位 3-6 用于存储枚举值 maple_type。
 *
 * 标志（flags）用于存储有关此树的一些不变信息（在树创建时设置）
 * 以及在自旋锁下设置的动态信息。
 *
 * 标志的另一个用途是指示树的全局状态。例如，MAPLE_USE_RCU 标志
 * 表示树当前处于 RCU 模式。这种模式的引入是为了允许树重用节点
 * 而不是在只有一个用户时重新分配和 RCU 释放节点。
 */

// __rcu 是一个类型修饰符，通常用于 Linux 内核中的 RCU（Read-Copy-Update）机制中。
// RCU 机制允许在不阻塞读取操作的情况下更新数据结构，从而提高系统的并发性能。

// 具体来说：

// RCU 机制：

// RCU 机制主要用于处理读写竞争问题。
// 在读取数据时不需要锁定，而在更新数据时会延迟一些操作，直到所有读取操作完成。
// __rcu 标记：

// __rcu 标记用于标识某个指针或变量是由 RCU 机制管理的。
// 这个标记告诉编译器和内核，该指针或变量的更新需要通过 RCU 的更新机制来完成。
// 用途：

// 在多线程环境下，__rcu 标记的变量可以安全地被多个读者同时访问，而更新操作会在适当的时机进行。
// 因此，void __rcu *ma_root; 表示 ma_root 指针是一个由 RCU 机制管理的指针，
// 它指向 void __rcu 类型的数据。这种类型的指针通常用于实现高效的并发读取和更新操作。

struct maple_tree {
	union {
		spinlock_t	ma_lock;
		lockdep_map_p	ma_external_lock;
	};
	void __rcu      *ma_root;
	unsigned int	ma_flags;
};

/**
 * MTREE_INIT() - Initialize a maple tree
 * @name: The maple tree name
 * @__flags: The maple tree flags
 *
 */
/**
 * 定义一个宏，用于初始化内存树（mtree）结构。
 *
 * @param name 内存树结构的名称。
 * @param __flags 内存树的标志位，用于控制其行为。
 *
 * 该宏初始化了一个内存树结构，设置了锁、标志位和根节点。
 */
#define MTREE_INIT(name, __flags) {					\
	.ma_lock = __SPIN_LOCK_UNLOCKED((name).ma_lock),		\
	.ma_flags = __flags,						\
	.ma_root = NULL,						\
}

/**
 * MTREE_INIT_EXT() - Initialize a maple tree with an external lock.
 * @name: The tree name
 * @__flags: The maple tree flags
 * @__lock: The external lock
 */
/**
 * MTREE_INIT_EXT() - 初始化一个带有外部锁的maple树。
 * @name: 树的名称
 * @__flags: maple树的标志
 * @__lock: 外部锁
 */
#ifdef CONFIG_LOCKDEP
#define MTREE_INIT_EXT(name, __flags, __lock) {				\
	.ma_external_lock = &(__lock).dep_map,				\
	.ma_flags = (__flags),						\
	.ma_root = NULL,						\
}
#else
#define MTREE_INIT_EXT(name, __flags, __lock)	MTREE_INIT(name, __flags)
#endif

#define DEFINE_MTREE(name)						\
	struct maple_tree name = MTREE_INIT(name, 0)

#define mtree_lock(mt)		spin_lock((&(mt)->ma_lock))
#define mtree_unlock(mt)	spin_unlock((&(mt)->ma_lock))

/*
 * The Maple Tree squeezes various bits in at various points which aren't
 * necessarily obvious.  Usually, this is done by observing that pointers are
 * N-byte aligned and thus the bottom log_2(N) bits are available for use.  We
 * don't use the high bits of pointers to store additional information because
 * we don't know what bits are unused on any given architecture.
 *
 * Nodes are 256 bytes in size and are also aligned to 256 bytes, giving us 8
 * low bits for our own purposes.  Nodes are currently of 4 types:
 * 1. Single pointer (Range is 0-0)
 * 2. Non-leaf Allocation Range nodes
 * 3. Non-leaf Range nodes
 * 4. Leaf Range nodes All nodes consist of a number of node slots,
 *    pivots, and a parent pointer.
 */
/*
 * Maple Tree（枫树）存储机制说明
 *
 * 在Maple Tree中，各种信息片段会在不同点被挤压进来，这些点并不总是显而易见的。
 * 通常，这是通过观察指针是N字节对齐的，因此底部的log_2(N)位可用于存储额外信息。
 * 我们不使用指针的高位来存储附加信息，因为我们不知道在任何给定架构上哪些位是未使用的。
 *
 * 节点大小为256字节，并且也对齐到256字节，这为我们提供了8个低位用于自定义用途。
 * 节点当前分为4种类型：
 * 1. 单指针节点（范围为0-0）
 * 2. 非叶节点分配范围节点
 * 3. 非叶节点范围节点
 * 4. 叶节点范围节点
 * 所有节点都由多个节点槽、轴心值和一个父指针组成。
 */

/**
                  [200, 400, 600, 800] (root node)
                 /    |     |     |    \
          [50]       [300] [500] [700] [900]
         /   |        |   |    |   |   |   \
    [10]   [150]        [350] [450] [550] [750] [850] [950]

*/

    //            [300, 700] (root node)
    //           /     |     \
    //     [100, 200]  [500]   [800, 900]
    //    /    \        |      /     |     \
    // [50]  [150]  [400, 600] [750] [850] [950]

/*
                  [200, 400, 600, 800] (root node)
                 /    |     |     |    \
           (..200) (200..400) (400..600) (600..800) (800..)
              |       |         |         |          |
             [50]   [300]     [500]     [700]      [900]
            /  |    /   |     /   |     /   |      /   \
    	[10] [150] [250] [350] [450] [550] [750] [850] [950]
*/

struct maple_node {
	union {
		struct {
			struct maple_pnode *parent;
			void __rcu *slot[MAPLE_NODE_SLOTS];
		};
		struct {
			void *pad;
			struct rcu_head rcu;
			struct maple_enode *piv_parent;
			unsigned char parent_slot;
			enum maple_type type;
			unsigned char slot_len;
			unsigned int ma_flags;
		};
		struct maple_range_64 mr64;
		struct maple_arange_64 ma64;
		struct maple_alloc alloc;
	};
};

/*
 * More complicated stores can cause two nodes to become one or three and
 * potentially alter the height of the tree.  Either half of the tree may need
 * to be rebalanced against the other.  The ma_topiary struct is used to track
 * which nodes have been 'cut' from the tree so that the change can be done
 * safely at a later date.  This is done to support RCU.
 */
/*
 * 更复杂的存储操作可能会导致两个节点合并为一个或三个节点，
 * 并可能改变树的高度。树的任一半可能需要针对另一半进行重新平衡。
 * ma_topiary 结构用于跟踪哪些节点已被从树中“剪切”出来，
 * 以便在将来的某个时间点安全地进行更改。这样做是为了支持 RCU（Read-Copy-Update）机制。
 */
struct ma_topiary {
	struct maple_enode *head;
	struct maple_enode *tail;
	struct maple_tree *mtree;
};

void *mtree_load(struct maple_tree *mt, unsigned long index);

int mtree_insert(struct maple_tree *mt, unsigned long index,
		void *entry, gfp_t gfp);
int mtree_insert_range(struct maple_tree *mt, unsigned long first,
		unsigned long last, void *entry, gfp_t gfp);
int mtree_alloc_range(struct maple_tree *mt, unsigned long *startp,
		void *entry, unsigned long size, unsigned long min,
		unsigned long max, gfp_t gfp);
int mtree_alloc_rrange(struct maple_tree *mt, unsigned long *startp,
		void *entry, unsigned long size, unsigned long min,
		unsigned long max, gfp_t gfp);

int mtree_store_range(struct maple_tree *mt, unsigned long first,
		      unsigned long last, void *entry, gfp_t gfp);
int mtree_store(struct maple_tree *mt, unsigned long index,
		void *entry, gfp_t gfp);
void *mtree_erase(struct maple_tree *mt, unsigned long index);

void mtree_destroy(struct maple_tree *mt);
void __mt_destroy(struct maple_tree *mt);

/**
 * mtree_empty() - Determine if a tree has any present entries.
 * @mt: Maple Tree.
 *
 * Context: Any context.
 * Return: %true if the tree contains only NULL pointers.
 */
static inline bool mtree_empty(const struct maple_tree *mt)
{
	return mt->ma_root == NULL;
}

/* Advanced API */

/*
 * The maple state is defined in the struct ma_state and is used to keep track
 * of information during operations, and even between operations when using the
 * advanced API.
 *
 * If state->node has bit 0 set then it references a tree location which is not
 * a node (eg the root).  If bit 1 is set, the rest of the bits are a negative
 * errno.  Bit 2 (the 'unallocated slots' bit) is clear.  Bits 3-6 indicate the
 * node type.
 *
 * state->alloc either has a request number of nodes or an allocated node.  If
 * stat->alloc has a requested number of nodes, the first bit will be set (0x1)
 * and the remaining bits are the value.  If state->alloc is a node, then the
 * node will be of type maple_alloc.  maple_alloc has MAPLE_NODE_SLOTS - 1 for
 * storing more allocated nodes, a total number of nodes allocated, and the
 * node_count in this node.  node_count is the number of allocated nodes in this
 * node.  The scaling beyond MAPLE_NODE_SLOTS - 1 is handled by storing further
 * nodes into state->alloc->slot[0]'s node.  Nodes are taken from state->alloc
 * by removing a node from the state->alloc node until state->alloc->node_count
 * is 1, when state->alloc is returned and the state->alloc->slot[0] is promoted
 * to state->alloc.  Nodes are pushed onto state->alloc by putting the current
 * state->alloc into the pushed node's slot[0].
 *
 * The state also contains the implied min/max of the state->node, the depth of
 * this search, and the offset. The implied min/max are either from the parent
 * node or are 0-oo for the root node.  The depth is incremented or decremented
 * every time a node is walked down or up.  The offset is the slot/pivot of
 * interest in the node - either for reading or writing.
 *
 * When returning a value the maple state index and last respectively contain
 * the start and end of the range for the entry.  Ranges are inclusive in the
 * Maple Tree.
 */
/*
 * Maple状态定义在结构体 ma_state 中，用于在操作期间跟踪信息，
 * 甚至在使用高级 API 时在操作之间跟踪信息。
 *
 * 如果 state->node 的第 0 位被设置，则它引用的树位置不是节点（例如根）。
 * 如果第 1 位被设置，则其余位是一个负的 errno。第 2 位（未分配的插槽位）是清的。
 * 第 3 到 6 位指示节点类型。
 *
 * state->alloc 要么有一个节点请求编号，要么有一个已分配的节点。
 * 如果 state->alloc 有一个请求的节点编号，则第一位（0x1）将会被设置，剩余的位是数值。
 * 如果 state->alloc 是一个节点，则该节点的类型是 maple_alloc。
 * maple_alloc 有 MAPLE_NODE_SLOTS - 1 个用于存储更多已分配节点的插槽，
 * 一个表示总共分配的节点数，以及这个节点中的 node_count。
 * node_count 是在这个节点中已分配的节点数量。
 * 超过 MAPLE_NODE_SLOTS - 1 的扩展通过将更多的节点存入 state->alloc->slot[0] 的节点来处理。
 * 从 state->alloc 中获取节点，直到 state->alloc->node_count 为 1，
 * 此时 state->alloc 被回收，state->alloc->slot[0] 被提升为 state->alloc。
 * 节点被推入 state->alloc，通过将当前的 state->alloc 放入推送节点的 slot[0] 中。
 *
 * 状态还包含了 state->node 的隐含最小值/最大值、此搜索的深度和偏移量。
 * 隐含的最小值/最大值要么来自父节点，要么是根节点的 0-oo。
 * 每次节点上下遍历时，深度都会递增或递减。
 * 偏移量是节点中感兴趣的插槽/轴心位置，无论是用于读取还是写入。
 *
 * 在返回值时，maple 状态索引和 last 分别包含条目范围的开始和结束。
 * 枫树中的范围是包含在内的。
 */
struct ma_state {
	struct maple_tree *tree;	/* The tree we're operating in */
	unsigned long index;		/* The index we're operating on - range start */
	unsigned long last;		/* The last index we're operating on - range end */
	struct maple_enode *node;	/* The node containing this entry */
	unsigned long min;		/* The minimum index of this node - implied pivot min */
	unsigned long max;		/* The maximum index of this node - implied pivot max */
	struct maple_alloc *alloc;	/* Allocated nodes for this operation */
	unsigned char depth;		/* depth of tree descent during write */
	unsigned char offset;
	unsigned char mas_flags;
};

struct ma_wr_state {
	struct ma_state *mas;
	struct maple_node *node;	/* Decoded mas->node */
	unsigned long r_min;		/* range min */
	unsigned long r_max;		/* range max */
	enum maple_type type;		/* mas->node type */
	unsigned char offset_end;	/* The offset where the write ends */
	unsigned char node_end;		/* mas->node end */
	unsigned long *pivots;		/* mas->node->pivots pointer */
	unsigned long end_piv;		/* The pivot at the offset end */
	void __rcu **slots;		/* mas->node->slots pointer */
	void *entry;			/* The entry to write */
	void *content;			/* The existing entry that is being overwritten */
};

#define mas_lock(mas)           spin_lock(&((mas)->tree->ma_lock))
#define mas_unlock(mas)         spin_unlock(&((mas)->tree->ma_lock))


/*
 * Special values for ma_state.node.
 * MAS_START means we have not searched the tree.
 * MAS_ROOT means we have searched the tree and the entry we found lives in
 * the root of the tree (ie it has index 0, length 1 and is the only entry in
 * the tree).
 * MAS_NONE means we have searched the tree and there is no node in the
 * tree for this entry.  For example, we searched for index 1 in an empty
 * tree.  Or we have a tree which points to a full leaf node and we
 * searched for an entry which is larger than can be contained in that
 * leaf node.
 * MA_ERROR represents an errno.  After dropping the lock and attempting
 * to resolve the error, the walk would have to be restarted from the
 * top of the tree as the tree may have been modified.
 */
/*
 * 特殊值，用于标识ma_state.node的状态。
 *
 * MAS_START：表示我们尚未搜索树。
 *
 * MAS_ROOT：表示我们已经搜索了树，并且找到的条目位于树的根节点中（即索引为0，长度为1，并且是树中唯一的条目）。
 *
 * MAS_NONE：表示我们已经搜索了树，但在树中没有找到与此条目匹配的节点。例如，在空树中搜索索引1，
 * 或者我们有一个指向满叶子节点的树，但搜索的条目超出了该叶子节点所能容纳的范围。
 *
 * MA_ERROR：表示一个errno值。在释放锁并尝试解决错误后，必须从树的顶部重新开始遍历，因为树可能已经被修改。
 */
#define MAS_START	((struct maple_enode *)1UL)
#define MAS_ROOT	((struct maple_enode *)5UL)
#define MAS_NONE	((struct maple_enode *)9UL)
#define MAS_PAUSE	((struct maple_enode *)17UL)
#define MA_ERROR(err) \
		((struct maple_enode *)(((unsigned long)err << 2) | 2UL))

/**
 * 定义一个内存分配状态结构体
 *
 * @param name 结构体名称，用于引用该状态结构体
 * @param mt 分配树，用于管理可用内存块
 * @param first 第一个节点索引，标识分配的起始位置
 * @param end 最后一个节点索引，标识分配的结束位置
 *
 * 该宏定义用于初始化一个内存分配状态结构体，用于记录和管理内存分配的相关信息
 * 结构体包含以下重要成员：
 * - tree: 指向管理可用内存块的分配树
 * - index: 当前节点索引，用于跟踪分配位置
 * - last: 最后一个节点索引，定义分配区域的结束位置
 * - node: 当前节点状态，初始设置为MAS_START，表示分配过程开始
 * - min: 最小分配大小，初始设置为0
 * - max: 最大分配大小，初始设置为ULONG_MAX，表示几乎无限制
 * - alloc: 分配器指针，初始为NULL，表示没有分配器关联
 * - mas_flags: 状态标志，初始为0，用于记录额外状态信息
 */
#define MA_STATE(name, mt, first, end)					\
	struct ma_state name = {					\
		.tree = mt,						\
		.index = first,						\
		.last = end,						\
		.node = MAS_START,					\
		.min = 0,						\
		.max = ULONG_MAX,					\
		.alloc = NULL,						\
		.mas_flags = 0,						\
	}
#define MA_WR_STATE(name, ma_state, wr_entry)				\
	struct ma_wr_state name = {					\
		.mas = ma_state,					\
		.content = NULL,					\
		.entry = wr_entry,					\
	}

#define MA_TOPIARY(name, tree)						\
	struct ma_topiary name = {					\
		.head = NULL,						\
		.tail = NULL,						\
		.mtree = tree,						\
	}

void *mas_walk(struct ma_state *mas);
void *mas_store(struct ma_state *mas, void *entry);
void *mas_erase(struct ma_state *mas);
int mas_store_gfp(struct ma_state *mas, void *entry, gfp_t gfp);
void mas_store_prealloc(struct ma_state *mas, void *entry);
void *mas_find(struct ma_state *mas, unsigned long max);
void *mas_find_range(struct ma_state *mas, unsigned long max);
void *mas_find_rev(struct ma_state *mas, unsigned long min);
void *mas_find_range_rev(struct ma_state *mas, unsigned long max);
int mas_preallocate(struct ma_state *mas, gfp_t gfp);
bool mas_is_err(struct ma_state *mas);

bool mas_nomem(struct ma_state *mas, gfp_t gfp);
void mas_pause(struct ma_state *mas);
void maple_tree_init(void);
void mas_destroy(struct ma_state *mas);
int mas_expected_entries(struct ma_state *mas, unsigned long nr_entries);

void *mas_prev(struct ma_state *mas, unsigned long min);
void *mas_prev_range(struct ma_state *mas, unsigned long max);
void *mas_next(struct ma_state *mas, unsigned long max);
void *mas_next_range(struct ma_state *mas, unsigned long max);

int mas_empty_area(struct ma_state *mas, unsigned long min, unsigned long max,
		   unsigned long size);
/*
 * This finds an empty area from the highest address to the lowest.
 * AKA "Topdown" version,
 */
int mas_empty_area_rev(struct ma_state *mas, unsigned long min,
		       unsigned long max, unsigned long size);

static inline void mas_init(struct ma_state *mas, struct maple_tree *tree,
			    unsigned long addr)
{
	memset(mas, 0, sizeof(struct ma_state));
	mas->tree = tree;
	mas->index = mas->last = addr;
	mas->max = ULONG_MAX;
	mas->node = MAS_START;
}

/* Checks if a mas has not found anything */
static inline bool mas_is_none(const struct ma_state *mas)
{
	return mas->node == MAS_NONE;
}

/* Checks if a mas has been paused */
static inline bool mas_is_paused(const struct ma_state *mas)
{
	return mas->node == MAS_PAUSE;
}

/**
 * mas_reset() - Reset a Maple Tree operation state.
 * @mas: Maple Tree operation state.
 *
 * Resets the error or walk state of the @mas so future walks of the
 * array will start from the root.  Use this if you have dropped the
 * lock and want to reuse the ma_state.
 *
 * Context: Any context.
 */
static inline void mas_reset(struct ma_state *mas)
{
	mas->node = MAS_START;
}

/**
 * mas_for_each() - Iterate over a range of the maple tree.
 * @__mas: Maple Tree operation state (maple_state)
 * @__entry: Entry retrieved from the tree
 * @__max: maximum index to retrieve from the tree
 *
 * When returned, mas->index and mas->last will hold the entire range for the
 * entry.
 *
 * Note: may return the zero entry.
 */
#define mas_for_each(__mas, __entry, __max) \
	while (((__entry) = mas_find((__mas), (__max))) != NULL)

/**
 * mas_set_range() - Set up Maple Tree operation state for a different index.
 * @mas: Maple Tree operation state.
 * @start: New start of range in the Maple Tree.
 * @last: New end of range in the Maple Tree.
 *
 * Move the operation state to refer to a different range.  This will
 * have the effect of starting a walk from the top; see mas_next()
 * to move to an adjacent index.
 */
static inline
void mas_set_range(struct ma_state *mas, unsigned long start, unsigned long last)
{
	       mas->index = start;
	       mas->last = last;
	       mas->node = MAS_START;
}

/**
 * mas_set() - Set up Maple Tree operation state for a different index.
 * @mas: Maple Tree operation state.
 * @index: New index into the Maple Tree.
 *
 * Move the operation state to refer to a different index.  This will
 * have the effect of starting a walk from the top; see mas_next()
 * to move to an adjacent index.
 */
static inline void mas_set(struct ma_state *mas, unsigned long index)
{

	mas_set_range(mas, index, index);
}

static inline bool mt_external_lock(const struct maple_tree *mt)
{
	return (mt->ma_flags & MT_FLAGS_LOCK_MASK) == MT_FLAGS_LOCK_EXTERN;
}

/**
 * mt_init_flags() - Initialise an empty maple tree with flags.
 * @mt: Maple Tree
 * @flags: maple tree flags.
 *
 * If you need to initialise a Maple Tree with special flags (eg, an
 * allocation tree), use this function.
 *
 * Context: Any context.
 */
static inline void mt_init_flags(struct maple_tree *mt, unsigned int flags)
{
	mt->ma_flags = flags;
	if (!mt_external_lock(mt))
		spin_lock_init(&mt->ma_lock);
	rcu_assign_pointer(mt->ma_root, NULL);
}

/**
 * mt_init() - Initialise an empty maple tree.
 * @mt: Maple Tree
 *
 * An empty Maple Tree.
 *
 * Context: Any context.
 */
static inline void mt_init(struct maple_tree *mt)
{
	mt_init_flags(mt, 0);
}

static inline bool mt_in_rcu(struct maple_tree *mt)
{
#ifdef CONFIG_MAPLE_RCU_DISABLED
	return false;
#endif
	return mt->ma_flags & MT_FLAGS_USE_RCU;
}

/**
 * mt_clear_in_rcu() - Switch the tree to non-RCU mode.
 * @mt: The Maple Tree
 */
static inline void mt_clear_in_rcu(struct maple_tree *mt)
{
	if (!mt_in_rcu(mt))
		return;

	if (mt_external_lock(mt)) {
		WARN_ON(!mt_lock_is_held(mt));
		mt->ma_flags &= ~MT_FLAGS_USE_RCU;
	} else {
		mtree_lock(mt);
		mt->ma_flags &= ~MT_FLAGS_USE_RCU;
		mtree_unlock(mt);
	}
}

/**
 * mt_set_in_rcu() - Switch the tree to RCU safe mode.
 * @mt: The Maple Tree
 */
static inline void mt_set_in_rcu(struct maple_tree *mt)
{
	if (mt_in_rcu(mt))
		return;

	if (mt_external_lock(mt)) {
		WARN_ON(!mt_lock_is_held(mt));
		mt->ma_flags |= MT_FLAGS_USE_RCU;
	} else {
		mtree_lock(mt);
		mt->ma_flags |= MT_FLAGS_USE_RCU;
		mtree_unlock(mt);
	}
}

static inline unsigned int mt_height(const struct maple_tree *mt)
{
	return (mt->ma_flags & MT_FLAGS_HEIGHT_MASK) >> MT_FLAGS_HEIGHT_OFFSET;
}

void *mt_find(struct maple_tree *mt, unsigned long *index, unsigned long max);
void *mt_find_after(struct maple_tree *mt, unsigned long *index,
		    unsigned long max);
void *mt_prev(struct maple_tree *mt, unsigned long index,  unsigned long min);
void *mt_next(struct maple_tree *mt, unsigned long index, unsigned long max);

/**
 * mt_for_each - Iterate over each entry starting at index until max.
 * @__tree: The Maple Tree
 * @__entry: The current entry
 * @__index: The index to update to track the location in the tree
 * @__max: The maximum limit for @index
 *
 * Note: Will not return the zero entry.
 */
#define mt_for_each(__tree, __entry, __index, __max) \
	for (__entry = mt_find(__tree, &(__index), __max); \
		__entry; __entry = mt_find_after(__tree, &(__index), __max))


#ifdef CONFIG_DEBUG_MAPLE_TREE
enum mt_dump_format {
	mt_dump_dec,
	mt_dump_hex,
};

extern atomic_t maple_tree_tests_run;
extern atomic_t maple_tree_tests_passed;

void mt_dump(const struct maple_tree *mt, enum mt_dump_format format);
void mas_dump(const struct ma_state *mas);
void mas_wr_dump(const struct ma_wr_state *wr_mas);
void mt_validate(struct maple_tree *mt);
void mt_cache_shrink(void);
#define MT_BUG_ON(__tree, __x) do {					\
	atomic_inc(&maple_tree_tests_run);				\
	if (__x) {							\
		pr_info("BUG at %s:%d (%u)\n",				\
		__func__, __LINE__, __x);				\
		mt_dump(__tree, mt_dump_hex);				\
		pr_info("Pass: %u Run:%u\n",				\
			atomic_read(&maple_tree_tests_passed),		\
			atomic_read(&maple_tree_tests_run));		\
		dump_stack();						\
	} else {							\
		atomic_inc(&maple_tree_tests_passed);			\
	}								\
} while (0)

#define MAS_BUG_ON(__mas, __x) do {					\
	atomic_inc(&maple_tree_tests_run);				\
	if (__x) {							\
		pr_info("BUG at %s:%d (%u)\n",				\
		__func__, __LINE__, __x);				\
		mas_dump(__mas);					\
		mt_dump((__mas)->tree, mt_dump_hex);			\
		pr_info("Pass: %u Run:%u\n",				\
			atomic_read(&maple_tree_tests_passed),		\
			atomic_read(&maple_tree_tests_run));		\
		dump_stack();						\
	} else {							\
		atomic_inc(&maple_tree_tests_passed);			\
	}								\
} while (0)

#define MAS_WR_BUG_ON(__wrmas, __x) do {				\
	atomic_inc(&maple_tree_tests_run);				\
	if (__x) {							\
		pr_info("BUG at %s:%d (%u)\n",				\
		__func__, __LINE__, __x);				\
		mas_wr_dump(__wrmas);					\
		mas_dump((__wrmas)->mas);				\
		mt_dump((__wrmas)->mas->tree, mt_dump_hex);		\
		pr_info("Pass: %u Run:%u\n",				\
			atomic_read(&maple_tree_tests_passed),		\
			atomic_read(&maple_tree_tests_run));		\
		dump_stack();						\
	} else {							\
		atomic_inc(&maple_tree_tests_passed);			\
	}								\
} while (0)

#define MT_WARN_ON(__tree, __x)  ({					\
	int ret = !!(__x);						\
	atomic_inc(&maple_tree_tests_run);				\
	if (ret) {							\
		pr_info("WARN at %s:%d (%u)\n",				\
		__func__, __LINE__, __x);				\
		mt_dump(__tree, mt_dump_hex);				\
		pr_info("Pass: %u Run:%u\n",				\
			atomic_read(&maple_tree_tests_passed),		\
			atomic_read(&maple_tree_tests_run));		\
		dump_stack();						\
	} else {							\
		atomic_inc(&maple_tree_tests_passed);			\
	}								\
	unlikely(ret);							\
})

#define MAS_WARN_ON(__mas, __x) ({					\
	int ret = !!(__x);						\
	atomic_inc(&maple_tree_tests_run);				\
	if (ret) {							\
		pr_info("WARN at %s:%d (%u)\n",				\
		__func__, __LINE__, __x);				\
		mas_dump(__mas);					\
		mt_dump((__mas)->tree, mt_dump_hex);			\
		pr_info("Pass: %u Run:%u\n",				\
			atomic_read(&maple_tree_tests_passed),		\
			atomic_read(&maple_tree_tests_run));		\
		dump_stack();						\
	} else {							\
		atomic_inc(&maple_tree_tests_passed);			\
	}								\
	unlikely(ret);							\
})

#define MAS_WR_WARN_ON(__wrmas, __x) ({					\
	int ret = !!(__x);						\
	atomic_inc(&maple_tree_tests_run);				\
	if (ret) {							\
		pr_info("WARN at %s:%d (%u)\n",				\
		__func__, __LINE__, __x);				\
		mas_wr_dump(__wrmas);					\
		mas_dump((__wrmas)->mas);				\
		mt_dump((__wrmas)->mas->tree, mt_dump_hex);		\
		pr_info("Pass: %u Run:%u\n",				\
			atomic_read(&maple_tree_tests_passed),		\
			atomic_read(&maple_tree_tests_run));		\
		dump_stack();						\
	} else {							\
		atomic_inc(&maple_tree_tests_passed);			\
	}								\
	unlikely(ret);							\
})
#else
#define MT_BUG_ON(__tree, __x)		BUG_ON(__x)
#define MAS_BUG_ON(__mas, __x)		BUG_ON(__x)
#define MAS_WR_BUG_ON(__mas, __x)	BUG_ON(__x)
#define MT_WARN_ON(__tree, __x)		WARN_ON(__x)
#define MAS_WARN_ON(__mas, __x)		WARN_ON(__x)
#define MAS_WR_WARN_ON(__mas, __x)	WARN_ON(__x)
#endif /* CONFIG_DEBUG_MAPLE_TREE */

#endif /*_LINUX_MAPLE_TREE_H */
