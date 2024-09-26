// SPDX-License-Identifier: GPL-2.0
#include <linux/mm_types.h>
#include <linux/maple_tree.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/cpumask.h>
#include <linux/mman.h>
#include <linux/pgtable.h>

#include <linux/atomic.h>
#include <linux/user_namespace.h>
#include <linux/iommu.h>
#include <asm/mmu.h>

#ifndef INIT_MM_CONTEXT
#define INIT_MM_CONTEXT(name)
#endif

/*
 * For dynamically allocated mm_structs, there is a dynamically sized cpumask
 * at the end of the structure, the size of which depends on the maximum CPU
 * number the system can see. That way we allocate only as much memory for
 * mm_cpumask() as needed for the hundreds, or thousands of processes that
 * a system typically runs.
 *
 * Since there is only one init_mm in the entire system, keep it simple
 * and size this cpu_bitmask to NR_CPUS.
 */
struct mm_struct init_mm = {
	.mm_mt		= MTREE_INIT_EXT(mm_mt, MM_MT_FLAGS, init_mm.mmap_lock),
	.pgd		= swapper_pg_dir,
	.mm_users	= ATOMIC_INIT(2),
	.mm_count	= ATOMIC_INIT(1),
	.write_protect_seq = SEQCNT_ZERO(init_mm.write_protect_seq),
	MMAP_LOCK_INITIALIZER(init_mm)
	.page_table_lock =  __SPIN_LOCK_UNLOCKED(init_mm.page_table_lock),
	.arg_lock	=  __SPIN_LOCK_UNLOCKED(init_mm.arg_lock),
	.mmlist		= LIST_HEAD_INIT(init_mm.mmlist),
#ifdef CONFIG_PER_VMA_LOCK
	.mm_lock_seq	= 0,
#endif
	.user_ns	= &init_user_ns,
	.cpu_bitmap	= CPU_BITS_NONE,
#ifdef CONFIG_IOMMU_SVA
	.pasid		= IOMMU_PASID_INVALID,
#endif
	INIT_MM_CONTEXT(init_mm)
};

/**
 * 初始化内存管理模块的基础地址信息。
 *
 * 该函数的作用是将启动代码段的起始地址、结束地址、数据段的结束地址
 * 以及程序堆的结束地址（brk）赋值给内存管理模块（init_mm）的相应字段。
 * 这些地址信息对于内存管理模块来说至关重要，它们被用于内存的分配与管理，
 * 以及对程序的内存使用情况进行监控和优化。
 *
 * @param start_code 程序代码段的起始地址。
 * @param end_code 程序代码段的结束地址。
 * @param end_data 程序数据段的结束地址。
 * @param brk 程序堆的结束地址。
 */
void setup_initial_init_mm(void *start_code, void *end_code,
			   void *end_data, void *brk)
{
    // 将传入的代码段起始地址、结束地址、数据段结束地址和堆结束地址
    // 赋值给init_mm结构体的相应字段。
	init_mm.start_code = (unsigned long)start_code;
	init_mm.end_code = (unsigned long)end_code;
	init_mm.end_data = (unsigned long)end_data;
	init_mm.brk = (unsigned long)brk;
}
