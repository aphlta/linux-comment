// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 1993  Linus Torvalds
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  SMP-safe vmalloc/vfree/ioremap, Tigran Aivazian <tigran@veritas.com>, May 2000
 *  Major rework to support vmap/vunmap, Christoph Hellwig, SGI, August 2002
 *  Numa awareness, Christoph Lameter, SGI, June 2005
 *  Improving global KVA allocator, Uladzislau Rezki, Sony, May 2019
 */

#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/set_memory.h>
#include <linux/debugobjects.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/rbtree.h>
#include <linux/xarray.h>
#include <linux/io.h>
#include <linux/rcupdate.h>
#include <linux/pfn.h>
#include <linux/kmemleak.h>
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/memcontrol.h>
#include <linux/llist.h>
#include <linux/uio.h>
#include <linux/bitops.h>
#include <linux/rbtree_augmented.h>
#include <linux/overflow.h>
#include <linux/pgtable.h>
#include <linux/hugetlb.h>
#include <linux/sched/mm.h>
#include <asm/tlbflush.h>
#include <asm/shmparam.h>

#define CREATE_TRACE_POINTS
#include <trace/events/vmalloc.h>

#include "internal.h"
#include "pgalloc-track.h"

#ifdef CONFIG_HAVE_ARCH_HUGE_VMAP
static unsigned int __ro_after_init ioremap_max_page_shift = BITS_PER_LONG - 1;

static int __init set_nohugeiomap(char *str)
{
	ioremap_max_page_shift = PAGE_SHIFT;
	return 0;
}
early_param("nohugeiomap", set_nohugeiomap);
#else /* CONFIG_HAVE_ARCH_HUGE_VMAP */
static const unsigned int ioremap_max_page_shift = PAGE_SHIFT;
#endif	/* CONFIG_HAVE_ARCH_HUGE_VMAP */

#ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC
static bool __ro_after_init vmap_allow_huge = true;

static int __init set_nohugevmalloc(char *str)
{
	vmap_allow_huge = false;
	return 0;
}
early_param("nohugevmalloc", set_nohugevmalloc);
#else /* CONFIG_HAVE_ARCH_HUGE_VMALLOC */
static const bool vmap_allow_huge = false;
#endif	/* CONFIG_HAVE_ARCH_HUGE_VMALLOC */

bool is_vmalloc_addr(const void *x)
{
	unsigned long addr = (unsigned long)kasan_reset_tag(x);

	return addr >= VMALLOC_START && addr < VMALLOC_END;
}
EXPORT_SYMBOL(is_vmalloc_addr);

struct vfree_deferred {
	struct llist_head list;
	struct work_struct wq;
};
static DEFINE_PER_CPU(struct vfree_deferred, vfree_deferred);

/*** Page table manipulation functions ***/
static int vmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
	pte_t *pte;
	u64 pfn;
	unsigned long size = PAGE_SIZE;

	pfn = phys_addr >> PAGE_SHIFT;
	pte = pte_alloc_kernel_track(pmd, addr, mask);
	if (!pte)
		return -ENOMEM;
	do {
		BUG_ON(!pte_none(ptep_get(pte)));

#ifdef CONFIG_HUGETLB_PAGE
		size = arch_vmap_pte_range_map_size(addr, end, pfn, max_page_shift);
		if (size != PAGE_SIZE) {
			pte_t entry = pfn_pte(pfn, prot);

			entry = arch_make_huge_pte(entry, ilog2(size), 0);
			set_huge_pte_at(&init_mm, addr, pte, entry);
			pfn += PFN_DOWN(size);
			continue;
		}
#endif
		set_pte_at(&init_mm, addr, pte, pfn_pte(pfn, prot));
		pfn++;
	} while (pte += PFN_DOWN(size), addr += size, addr != end);
	*mask |= PGTBL_PTE_MODIFIED;
	return 0;
}

static int vmap_try_huge_pmd(pmd_t *pmd, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift)
{
	if (max_page_shift < PMD_SHIFT)
		return 0;

	if (!arch_vmap_pmd_supported(prot))
		return 0;

	if ((end - addr) != PMD_SIZE)
		return 0;

	if (!IS_ALIGNED(addr, PMD_SIZE))
		return 0;

	if (!IS_ALIGNED(phys_addr, PMD_SIZE))
		return 0;

	if (pmd_present(*pmd) && !pmd_free_pte_page(pmd, addr))
		return 0;

	return pmd_set_huge(pmd, phys_addr, prot);
}

static int vmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_alloc_track(&init_mm, pud, addr, mask);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);

		if (vmap_try_huge_pmd(pmd, addr, next, phys_addr, prot,
					max_page_shift)) {
			*mask |= PGTBL_PMD_MODIFIED;
			continue;
		}

		if (vmap_pte_range(pmd, addr, next, phys_addr, prot, max_page_shift, mask))
			return -ENOMEM;
	} while (pmd++, phys_addr += (next - addr), addr = next, addr != end);
	return 0;
}

static int vmap_try_huge_pud(pud_t *pud, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift)
{
	if (max_page_shift < PUD_SHIFT)
		return 0;

	if (!arch_vmap_pud_supported(prot))
		return 0;

	if ((end - addr) != PUD_SIZE)
		return 0;

	if (!IS_ALIGNED(addr, PUD_SIZE))
		return 0;

	if (!IS_ALIGNED(phys_addr, PUD_SIZE))
		return 0;

	if (pud_present(*pud) && !pud_free_pmd_page(pud, addr))
		return 0;

	return pud_set_huge(pud, phys_addr, prot);
}

static int vmap_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_alloc_track(&init_mm, p4d, addr, mask);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);

		if (vmap_try_huge_pud(pud, addr, next, phys_addr, prot,
					max_page_shift)) {
			*mask |= PGTBL_PUD_MODIFIED;
			continue;
		}

		if (vmap_pmd_range(pud, addr, next, phys_addr, prot,
					max_page_shift, mask))
			return -ENOMEM;
	} while (pud++, phys_addr += (next - addr), addr = next, addr != end);
	return 0;
}

static int vmap_try_huge_p4d(p4d_t *p4d, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift)
{
	if (max_page_shift < P4D_SHIFT)
		return 0;

	if (!arch_vmap_p4d_supported(prot))
		return 0;

	if ((end - addr) != P4D_SIZE)
		return 0;

	if (!IS_ALIGNED(addr, P4D_SIZE))
		return 0;

	if (!IS_ALIGNED(phys_addr, P4D_SIZE))
		return 0;

	if (p4d_present(*p4d) && !p4d_free_pud_page(p4d, addr))
		return 0;

	return p4d_set_huge(p4d, phys_addr, prot);
}

static int vmap_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_alloc_track(&init_mm, pgd, addr, mask);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);

		if (vmap_try_huge_p4d(p4d, addr, next, phys_addr, prot,
					max_page_shift)) {
			*mask |= PGTBL_P4D_MODIFIED;
			continue;
		}

		if (vmap_pud_range(p4d, addr, next, phys_addr, prot,
					max_page_shift, mask))
			return -ENOMEM;
	} while (p4d++, phys_addr += (next - addr), addr = next, addr != end);
	return 0;
}

/**
 * 在虚拟内存映射区域中添加新的映射，而不触发flush操作。
 *
 * @param addr 映射的起始虚拟地址。
 * @param end 映射的结束虚拟地址。
 * @param phys_addr 映射的起始物理地址。
 * @param prot 页面保护类型。
 * @param max_page_shift 最大的页面转换缓冲区(PTE)聚合程度。
 *
 * @return 操作结果，0表示成功，非0表示失败。
 */
static int vmap_range_noflush(unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift)
{
	// 获取页全局目录表指针
	pgd_t *pgd;
	// 记录起始地址
	unsigned long start;
	// 下一个地址
	unsigned long next;
	// 错误码
	int err;
	// 页表修改掩码
	pgtbl_mod_mask mask = 0;

	// 可能会睡眠，表明函数内部可能会进行需要睡眠的操作
	might_sleep();
	// 确保起始地址小于结束地址
	BUG_ON(addr >= end);

	// 初始化起始地址
	start = addr;
	// 获取起始地址对应的页全局目录表项
	pgd = pgd_offset_k(addr);
	// 遍历地址范围，进行映射
	do {
		// 计算下一个地址
		next = pgd_addr_end(addr, end);
		// 在当前pgd表中添加映射
		err = vmap_p4d_range(pgd, addr, next, phys_addr, prot,
					max_page_shift, &mask);
		// 操作失败则退出循环
		if (err)
			break;
	} while (pgd++, phys_addr += (next - addr), addr = next, addr != end);

	// 如果页表修改掩码指示需要同步，则进行同步操作
	if (mask & ARCH_PAGE_TABLE_SYNC_MASK)
		arch_sync_kernel_mappings(start, end);

	// 返回操作结果
	return err;
}

int ioremap_page_range(unsigned long addr, unsigned long end,
		phys_addr_t phys_addr, pgprot_t prot)
{
	int err;

	err = vmap_range_noflush(addr, end, phys_addr, pgprot_nx(prot),
				 ioremap_max_page_shift);
	flush_cache_vmap(addr, end);
	if (!err)
		err = kmsan_ioremap_page_range(addr, end, phys_addr, prot,
					       ioremap_max_page_shift);
	return err;
}

static void vunmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
			     pgtbl_mod_mask *mask)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, addr);
	do {
		pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
		WARN_ON(!pte_none(ptent) && !pte_present(ptent));
	} while (pte++, addr += PAGE_SIZE, addr != end);
	*mask |= PGTBL_PTE_MODIFIED;
}

static void vunmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
			     pgtbl_mod_mask *mask)
{
	pmd_t *pmd;
	unsigned long next;
	int cleared;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);

		cleared = pmd_clear_huge(pmd);
		if (cleared || pmd_bad(*pmd))
			*mask |= PGTBL_PMD_MODIFIED;

		if (cleared)
			continue;
		if (pmd_none_or_clear_bad(pmd))
			continue;
		vunmap_pte_range(pmd, addr, next, mask);

		cond_resched();
	} while (pmd++, addr = next, addr != end);
}

static void vunmap_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
			     pgtbl_mod_mask *mask)
{
	pud_t *pud;
	unsigned long next;
	int cleared;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);

		cleared = pud_clear_huge(pud);
		if (cleared || pud_bad(*pud))
			*mask |= PGTBL_PUD_MODIFIED;

		if (cleared)
			continue;
		if (pud_none_or_clear_bad(pud))
			continue;
		vunmap_pmd_range(pud, addr, next, mask);
	} while (pud++, addr = next, addr != end);
}

static void vunmap_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
			     pgtbl_mod_mask *mask)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);

		p4d_clear_huge(p4d);
		if (p4d_bad(*p4d))
			*mask |= PGTBL_P4D_MODIFIED;

		if (p4d_none_or_clear_bad(p4d))
			continue;
		vunmap_pud_range(p4d, addr, next, mask);
	} while (p4d++, addr = next, addr != end);
}

/*
 * vunmap_range_noflush is similar to vunmap_range, but does not
 * flush caches or TLBs.
 *
 * The caller is responsible for calling flush_cache_vmap() before calling
 * this function, and flush_tlb_kernel_range after it has returned
 * successfully (and before the addresses are expected to cause a page fault
 * or be re-mapped for something else, if TLB flushes are being delayed or
 * coalesced).
 *
 * This is an internal function only. Do not use outside mm/.
 */
void __vunmap_range_noflush(unsigned long start, unsigned long end)
{
	unsigned long next;
	pgd_t *pgd;
	unsigned long addr = start;
	pgtbl_mod_mask mask = 0;

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_bad(*pgd))
			mask |= PGTBL_PGD_MODIFIED;
		if (pgd_none_or_clear_bad(pgd))
			continue;
		vunmap_p4d_range(pgd, addr, next, &mask);
	} while (pgd++, addr = next, addr != end);

	if (mask & ARCH_PAGE_TABLE_SYNC_MASK)
		arch_sync_kernel_mappings(start, end);
}

void vunmap_range_noflush(unsigned long start, unsigned long end)
{
	kmsan_vunmap_range_noflush(start, end);
	__vunmap_range_noflush(start, end);
}

/**
 * vunmap_range - unmap kernel virtual addresses
 * @addr: start of the VM area to unmap
 * @end: end of the VM area to unmap (non-inclusive)
 *
 * Clears any present PTEs in the virtual address range, flushes TLBs and
 * caches. Any subsequent access to the address before it has been re-mapped
 * is a kernel bug.
 */
void vunmap_range(unsigned long addr, unsigned long end)
{
	flush_cache_vunmap(addr, end);
	vunmap_range_noflush(addr, end);
	flush_tlb_kernel_range(addr, end);
}

static int vmap_pages_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, pgprot_t prot, struct page **pages, int *nr,
		pgtbl_mod_mask *mask)
{
	pte_t *pte;

	/*
	 * nr is a running index into the array which helps higher level
	 * callers keep track of where we're up to.
	 */

	pte = pte_alloc_kernel_track(pmd, addr, mask);
	if (!pte)
		return -ENOMEM;
	do {
		struct page *page = pages[*nr];

		if (WARN_ON(!pte_none(ptep_get(pte))))
			return -EBUSY;
		if (WARN_ON(!page))
			return -ENOMEM;
		if (WARN_ON(!pfn_valid(page_to_pfn(page))))
			return -EINVAL;

		set_pte_at(&init_mm, addr, pte, mk_pte(page, prot));
		(*nr)++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	*mask |= PGTBL_PTE_MODIFIED;
	return 0;
}

static int vmap_pages_pmd_range(pud_t *pud, unsigned long addr,
		unsigned long end, pgprot_t prot, struct page **pages, int *nr,
		pgtbl_mod_mask *mask)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_alloc_track(&init_mm, pud, addr, mask);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		if (vmap_pages_pte_range(pmd, addr, next, prot, pages, nr, mask))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static int vmap_pages_pud_range(p4d_t *p4d, unsigned long addr,
		unsigned long end, pgprot_t prot, struct page **pages, int *nr,
		pgtbl_mod_mask *mask)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_alloc_track(&init_mm, p4d, addr, mask);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (vmap_pages_pmd_range(pud, addr, next, prot, pages, nr, mask))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}

static int vmap_pages_p4d_range(pgd_t *pgd, unsigned long addr,
		unsigned long end, pgprot_t prot, struct page **pages, int *nr,
		pgtbl_mod_mask *mask)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_alloc_track(&init_mm, pgd, addr, mask);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);
		if (vmap_pages_pud_range(p4d, addr, next, prot, pages, nr, mask))
			return -ENOMEM;
	} while (p4d++, addr = next, addr != end);
	return 0;
}

static int vmap_small_pages_range_noflush(unsigned long addr, unsigned long end,
		pgprot_t prot, struct page **pages)
{
	unsigned long start = addr;
	pgd_t *pgd;
	unsigned long next;
	int err = 0;
	int nr = 0;
	pgtbl_mod_mask mask = 0;

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_bad(*pgd))
			mask |= PGTBL_PGD_MODIFIED;
		err = vmap_pages_p4d_range(pgd, addr, next, prot, pages, &nr, &mask);
		if (err)
			return err;
	} while (pgd++, addr = next, addr != end);

	if (mask & ARCH_PAGE_TABLE_SYNC_MASK)
		arch_sync_kernel_mappings(start, end);

	return 0;
}

/*
 * vmap_pages_range_noflush is similar to vmap_pages_range, but does not
 * flush caches.
 *
 * The caller is responsible for calling flush_cache_vmap() after this
 * function returns successfully and before the addresses are accessed.
 *
 * This is an internal function only. Do not use outside mm/.
 */
/**
 * __vmap_pages_range_noflush - 在指定地址范围内映射虚拟页面，不执行刷新操作
 * @addr: 映射起始地址
 * @end: 映射结束地址（不包含该地址本身）
 * @prot: 页表项保护类型
 * @pages: 指向实际物理页面的数组指针
 * @page_shift: 页面大小的移位值，决定了页面的大小
 *
 * 该函数根据指定的地址范围、保护类型、物理页面数组和页面移位值，
 * 在虚拟内存中映射相应的页面。与标准的映射函数不同，此函数不执行
 * 映射后的数据刷新操作，适用于不需要立即可见的数据区域。
 *
 * 返回值：
 *   - 成功映射时返回0
 *   - 映射失败时返回错误码
 */
int __vmap_pages_range_noflush(unsigned long addr, unsigned long end,
		pgprot_t prot, struct page **pages, unsigned int page_shift)
{
	/* 计算需要映射的页面数量 */
	unsigned int i, nr = (end - addr) >> PAGE_SHIFT;

	/* 确保请求的页面移位值不小于默认页面大小的移位值 */
	WARN_ON(page_shift < PAGE_SHIFT);

	/* 如果系统不支持大页面映射，或者请求的页面大小与默认页面大小相同，则调用小页面映射函数 */
	if (!IS_ENABLED(CONFIG_HAVE_ARCH_HUGE_VMALLOC) ||
			page_shift == PAGE_SHIFT)
		return vmap_small_pages_range_noflush(addr, end, prot, pages);

	/* 按照指定的页面大小逐个映射页面 */
	for (i = 0; i < nr; i += 1U << (page_shift - PAGE_SHIFT)) {
		int err;

		/* 映射当前页面，并应用保护类型和页面大小 */
		err = vmap_range_noflush(addr, addr + (1UL << page_shift),
					page_to_phys(pages[i]), prot,
					page_shift);
		/* 如果映射失败，返回错误码 */
		if (err)
			return err;

		/* 更新下一页的起始地址 */
		addr += 1UL << page_shift;
	}

	/* 所有页面映射成功 */
	return 0;
}

/**
 * vmap_pages_range_noflush: 虚拟映射一组页面，并设置保护类型。
 *
 * @addr: 起始虚拟地址
 * @end: 结束虚拟地址（不包含此地址）
 * @prot: 页面保护类型
 * @pages: 页面数组的指针
 * @page_shift: 页面大小的对数
 *
 * 本函数首先调用kmsan_vmap_pages_range_noflush尝试进行虚拟映射，
 * 如果返回错误，则直接返回错误码。如果成功，则调用__vmap_pages_range_noflush
 * 进行实际的虚拟映射操作。
 *
 * 返回值:
 *   成功时返回0，失败时返回负错误码。
 */
int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
		pgprot_t prot, struct page **pages, unsigned int page_shift)
{
	// 尝试进行虚拟映射
	int ret = kmsan_vmap_pages_range_noflush(addr, end, prot, pages,
						 page_shift);

	// 如果有错误返回，则直接返回错误码
	if (ret)
		return ret;

	// 调用实际的虚拟映射操作
	return __vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
}

/**
 * vmap_pages_range - map pages to a kernel virtual address
 * @addr: start of the VM area to map
 * @end: end of the VM area to map (non-inclusive)
 * @prot: page protection flags to use
 * @pages: pages to map (always PAGE_SIZE pages)
 * @page_shift: maximum shift that the pages may be mapped with, @pages must
 * be aligned and contiguous up to at least this shift.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
/**
 * vmap_pages_range - 连续地将一组页面映射到虚拟地址空间
 * @addr: 映射的起始虚拟地址
 * @end: 映射的结束虚拟地址（不包括此地址）
 * @prot: 页面保护类型
 * @pages: 将要映射的页面数组指针
 * @page_shift: 页面大小的2的幂次方
 *
 * 本函数将一系列页面连续地映射到虚拟地址空间中，首先使用
 * vmap_pages_range_noflush进行页面映射，然后调用flush_cache_vmap
 * 刷新映射区域的缓存，确保修改能够立即反映到硬件。
 *
 * 返回: 映射操作的错误代码，0表示成功。
 */
static int vmap_pages_range(unsigned long addr, unsigned long end,
		pgprot_t prot, struct page **pages, unsigned int page_shift)
{
	int err;

	// 执行页面映射操作，但不刷新缓存
	err = vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
	// 映射完成后，刷新缓存以确保修改生效
	flush_cache_vmap(addr, end);
	return err;
}

int is_vmalloc_or_module_addr(const void *x)
{
	/*
	 * ARM, x86-64 and sparc64 put modules in a special place,
	 * and fall back on vmalloc() if that fails. Others
	 * just put it in the vmalloc space.
	 */
#if defined(CONFIG_MODULES) && defined(MODULES_VADDR)
	unsigned long addr = (unsigned long)kasan_reset_tag(x);
	if (addr >= MODULES_VADDR && addr < MODULES_END)
		return 1;
#endif
	return is_vmalloc_addr(x);
}
EXPORT_SYMBOL_GPL(is_vmalloc_or_module_addr);

/*
 * Walk a vmap address to the struct page it maps. Huge vmap mappings will
 * return the tail page that corresponds to the base page address, which
 * matches small vmap mappings.
 */
struct page *vmalloc_to_page(const void *vmalloc_addr)
{
	unsigned long addr = (unsigned long) vmalloc_addr;
	struct page *page = NULL;
	pgd_t *pgd = pgd_offset_k(addr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;

	/*
	 * XXX we might need to change this if we add VIRTUAL_BUG_ON for
	 * architectures that do not vmalloc module space
	 */
	VIRTUAL_BUG_ON(!is_vmalloc_or_module_addr(vmalloc_addr));

	if (pgd_none(*pgd))
		return NULL;
	if (WARN_ON_ONCE(pgd_leaf(*pgd)))
		return NULL; /* XXX: no allowance for huge pgd */
	if (WARN_ON_ONCE(pgd_bad(*pgd)))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;
	if (p4d_leaf(*p4d))
		return p4d_page(*p4d) + ((addr & ~P4D_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(p4d_bad(*p4d)))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;
	if (pud_leaf(*pud))
		return pud_page(*pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(pud_bad(*pud)))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;
	if (pmd_leaf(*pmd))
		return pmd_page(*pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(pmd_bad(*pmd)))
		return NULL;

	ptep = pte_offset_kernel(pmd, addr);
	pte = ptep_get(ptep);
	if (pte_present(pte))
		page = pte_page(pte);

	return page;
}
EXPORT_SYMBOL(vmalloc_to_page);

/*
 * Map a vmalloc()-space virtual address to the physical page frame number.
 */
unsigned long vmalloc_to_pfn(const void *vmalloc_addr)
{
	return page_to_pfn(vmalloc_to_page(vmalloc_addr));
}
EXPORT_SYMBOL(vmalloc_to_pfn);


/*** Global kva allocator ***/

#define DEBUG_AUGMENT_PROPAGATE_CHECK 0
#define DEBUG_AUGMENT_LOWEST_MATCH_CHECK 0


static DEFINE_SPINLOCK(vmap_area_lock);
static DEFINE_SPINLOCK(free_vmap_area_lock);
/* Export for kexec only */
LIST_HEAD(vmap_area_list);
static struct rb_root vmap_area_root = RB_ROOT;
static bool vmap_initialized __read_mostly;

static struct rb_root purge_vmap_area_root = RB_ROOT;
static LIST_HEAD(purge_vmap_area_list);
static DEFINE_SPINLOCK(purge_vmap_area_lock);

/*
 * This kmem_cache is used for vmap_area objects. Instead of
 * allocating from slab we reuse an object from this cache to
 * make things faster. Especially in "no edge" splitting of
 * free block.
 */
static struct kmem_cache *vmap_area_cachep;

/*
 * This linked list is used in pair with free_vmap_area_root.
 * It gives O(1) access to prev/next to perform fast coalescing.
 */
static LIST_HEAD(free_vmap_area_list);

/*
 * This augment red-black tree represents the free vmap space.
 * All vmap_area objects in this tree are sorted by va->va_start
 * address. It is used for allocation and merging when a vmap
 * object is released.
 *
 * Each vmap_area node contains a maximum available free block
 * of its sub-tree, right or left. Therefore it is possible to
 * find a lowest match of free area.
 */
static struct rb_root free_vmap_area_root = RB_ROOT;

/*
 * Preload a CPU with one object for "no edge" split case. The
 * aim is to get rid of allocations from the atomic context, thus
 * to use more permissive allocation masks.
 */
static DEFINE_PER_CPU(struct vmap_area *, ne_fit_preload_node);

static __always_inline unsigned long
va_size(struct vmap_area *va)
{
	return (va->va_end - va->va_start);
}

static __always_inline unsigned long
get_subtree_max_size(struct rb_node *node)
{
	struct vmap_area *va;

	va = rb_entry_safe(node, struct vmap_area, rb_node);
	return va ? va->subtree_max_size : 0;
}

RB_DECLARE_CALLBACKS_MAX(static, free_vmap_area_rb_augment_cb,
	struct vmap_area, rb_node, unsigned long, subtree_max_size, va_size)

static void reclaim_and_purge_vmap_areas(void);
static BLOCKING_NOTIFIER_HEAD(vmap_notify_list);
static void drain_vmap_area_work(struct work_struct *work);
static DECLARE_WORK(drain_vmap_work, drain_vmap_area_work);

static atomic_long_t nr_vmalloc_pages;

unsigned long vmalloc_nr_pages(void)
{
	return atomic_long_read(&nr_vmalloc_pages);
}

/* Look up the first VA which satisfies addr < va_end, NULL if none. */
static struct vmap_area *find_vmap_area_exceed_addr(unsigned long addr)
{
	struct vmap_area *va = NULL;
	struct rb_node *n = vmap_area_root.rb_node;

	addr = (unsigned long)kasan_reset_tag((void *)addr);

	while (n) {
		struct vmap_area *tmp;

		tmp = rb_entry(n, struct vmap_area, rb_node);
		if (tmp->va_end > addr) {
			va = tmp;
			if (tmp->va_start <= addr)
				break;

			n = n->rb_left;
		} else
			n = n->rb_right;
	}

	return va;
}

static struct vmap_area *__find_vmap_area(unsigned long addr, struct rb_root *root)
{
	struct rb_node *n = root->rb_node;

	addr = (unsigned long)kasan_reset_tag((void *)addr);

	while (n) {
		struct vmap_area *va;

		va = rb_entry(n, struct vmap_area, rb_node);
		if (addr < va->va_start)
			n = n->rb_left;
		else if (addr >= va->va_end)
			n = n->rb_right;
		else
			return va;
	}

	return NULL;
}

/*
 * This function returns back addresses of parent node
 * and its left or right link for further processing.
 *
 * Otherwise NULL is returned. In that case all further
 * steps regarding inserting of conflicting overlap range
 * have to be declined and actually considered as a bug.
 */
static __always_inline struct rb_node **
find_va_links(struct vmap_area *va,
	struct rb_root *root, struct rb_node *from,
	struct rb_node **parent)
{
	struct vmap_area *tmp_va;
	struct rb_node **link;

	if (root) {
		link = &root->rb_node;
		if (unlikely(!*link)) {
			*parent = NULL;
			return link;
		}
	} else {
		link = &from;
	}

	/*
	 * Go to the bottom of the tree. When we hit the last point
	 * we end up with parent rb_node and correct direction, i name
	 * it link, where the new va->rb_node will be attached to.
	 */

	// 遍历红黑树以找到适合插入新节点的位置
	do {
		tmp_va = rb_entry(*link, struct vmap_area, rb_node);

		/*
		 * During the traversal we also do some sanity check.
		 * Trigger the BUG() if there are sides(left/right)
		 * or full overlaps.
		 */

		// 检查当前节点与待插入节点的地址范围是否重叠
		if (va->va_end <= tmp_va->va_start)
			link = &(*link)->rb_left;
		else if (va->va_start >= tmp_va->va_end)
			link = &(*link)->rb_right;
		else {
			WARN(1, "vmalloc bug: 0x%lx-0x%lx overlaps with 0x%lx-0x%lx\n",
				va->va_start, va->va_end, tmp_va->va_start, tmp_va->va_end);

			return NULL;
		}
	} while (*link);

	// 更新父节点指针，并返回最终的插入位置
	*parent = &tmp_va->rb_node;
	return link;
}

static __always_inline struct list_head *
get_va_next_sibling(struct rb_node *parent, struct rb_node **link)
{
	struct list_head *list;

	if (unlikely(!parent))
		/*
		 * The red-black tree where we try to find VA neighbors
		 * before merging or inserting is empty, i.e. it means
		 * there is no free vmap space. Normally it does not
		 * happen but we handle this case anyway.
		 */
		return NULL;

	list = &rb_entry(parent, struct vmap_area, rb_node)->list;
	return (&parent->rb_right == link ? list->next : list);
}

static __always_inline void
__link_va(struct vmap_area *va, struct rb_root *root,
	struct rb_node *parent, struct rb_node **link,
	struct list_head *head, bool augment)
{
	/*
	 * VA is still not in the list, but we can
	 * identify its future previous list_head node.
	 */
	if (likely(parent)) {
		head = &rb_entry(parent, struct vmap_area, rb_node)->list;
		if (&parent->rb_right != link)
			head = head->prev;
	}

	/* Insert to the rb-tree */
	rb_link_node(&va->rb_node, parent, link);
	if (augment) {
		/*
		 * Some explanation here. Just perform simple insertion
		 * to the tree. We do not set va->subtree_max_size to
		 * its current size before calling rb_insert_augmented().
		 * It is because we populate the tree from the bottom
		 * to parent levels when the node _is_ in the tree.
		 *
		 * Therefore we set subtree_max_size to zero after insertion,
		 * to let __augment_tree_propagate_from() puts everything to
		 * the correct order later on.
		 */
		rb_insert_augmented(&va->rb_node,
			root, &free_vmap_area_rb_augment_cb);
		va->subtree_max_size = 0;
	} else {
		rb_insert_color(&va->rb_node, root);
	}

	/* Address-sort this list */
	list_add(&va->list, head);
}

static __always_inline void
link_va(struct vmap_area *va, struct rb_root *root,
	struct rb_node *parent, struct rb_node **link,
	struct list_head *head)
{
	__link_va(va, root, parent, link, head, false);
}

static __always_inline void
link_va_augment(struct vmap_area *va, struct rb_root *root,
	struct rb_node *parent, struct rb_node **link,
	struct list_head *head)
{
	__link_va(va, root, parent, link, head, true);
}

static __always_inline void
__unlink_va(struct vmap_area *va, struct rb_root *root, bool augment)
{
	if (WARN_ON(RB_EMPTY_NODE(&va->rb_node)))
		return;

	if (augment)
		rb_erase_augmented(&va->rb_node,
			root, &free_vmap_area_rb_augment_cb);
	else
		rb_erase(&va->rb_node, root);

	list_del_init(&va->list);
	RB_CLEAR_NODE(&va->rb_node);
}

static __always_inline void
unlink_va(struct vmap_area *va, struct rb_root *root)
{
	__unlink_va(va, root, false);
}

static __always_inline void
unlink_va_augment(struct vmap_area *va, struct rb_root *root)
{
	__unlink_va(va, root, true);
}

#if DEBUG_AUGMENT_PROPAGATE_CHECK
/*
 * Gets called when remove the node and rotate.
 */
static __always_inline unsigned long
compute_subtree_max_size(struct vmap_area *va)
{
	return max3(va_size(va),
		get_subtree_max_size(va->rb_node.rb_left),
		get_subtree_max_size(va->rb_node.rb_right));
}

static void
augment_tree_propagate_check(void)
{
	struct vmap_area *va;
	unsigned long computed_size;

	list_for_each_entry(va, &free_vmap_area_list, list) {
		computed_size = compute_subtree_max_size(va);
		if (computed_size != va->subtree_max_size)
			pr_emerg("tree is corrupted: %lu, %lu\n",
				va_size(va), va->subtree_max_size);
	}
}
#endif

/*
 * This function populates subtree_max_size from bottom to upper
 * levels starting from VA point. The propagation must be done
 * when VA size is modified by changing its va_start/va_end. Or
 * in case of newly inserting of VA to the tree.
 *
 * It means that __augment_tree_propagate_from() must be called:
 * - After VA has been inserted to the tree(free path);
 * - After VA has been shrunk(allocation path);
 * - After VA has been increased(merging path).
 *
 * Please note that, it does not mean that upper parent nodes
 * and their subtree_max_size are recalculated all the time up
 * to the root node.
 *
 *       4--8
 *        /\
 *       /  \
 *      /    \
 *    2--2  8--8
 *
 * For example if we modify the node 4, shrinking it to 2, then
 * no any modification is required. If we shrink the node 2 to 1
 * its subtree_max_size is updated only, and set to 1. If we shrink
 * the node 8 to 6, then its subtree_max_size is set to 6 and parent
 * node becomes 4--6.
 */
static __always_inline void
augment_tree_propagate_from(struct vmap_area *va)
{
	/*
	 * Populate the tree from bottom towards the root until
	 * the calculated maximum available size of checked node
	 * is equal to its current one.
	 */
	free_vmap_area_rb_augment_cb_propagate(&va->rb_node, NULL);

#if DEBUG_AUGMENT_PROPAGATE_CHECK
	augment_tree_propagate_check();
#endif
}

/**
 * 向虚拟内存映射区域树中插入一个新的区域
 *
 * 本函数尝试将一个新的虚拟内存映射区域（vmap_area）插入到红黑树（rb_root）中
 * 它首先通过调用find_va_links函数找到合适的插入位置，然后通过link_va函数进行插入
 *
 * @param va 待插入的虚拟内存映射区域结构体指针
 * @param root 指向红黑树根节点的指针
 * @param head 列表头的指针，用于插入vmap_area
 */
static void
insert_vmap_area(struct vmap_area *va,
	struct rb_root *root, struct list_head *head)
{
	// 用于遍历红黑树的指针
	struct rb_node **link;
	// 用于存储父节点的指针
	struct rb_node *parent;

	// 寻找插入位置的链接点和父节点
	link = find_va_links(va, root, NULL, &parent);
	if (link)
		// 插入新的虚拟内存映射区域
		link_va(va, root, parent, link, head);
}

static void
insert_vmap_area_augment(struct vmap_area *va,
	struct rb_node *from, struct rb_root *root,
	struct list_head *head)
{
	struct rb_node **link;
	struct rb_node *parent;

	if (from)
		link = find_va_links(va, NULL, from, &parent);
	else
		link = find_va_links(va, root, NULL, &parent);

	if (link) {
		link_va_augment(va, root, parent, link, head);
		augment_tree_propagate_from(va);
	}
}

/*
 * Merge de-allocated chunk of VA memory with previous
 * and next free blocks. If coalesce is not done a new
 * free area is inserted. If VA has been merged, it is
 * freed.
 *
 * Please note, it can return NULL in case of overlap
 * ranges, followed by WARN() report. Despite it is a
 * buggy behaviour, a system can be alive and keep
 * ongoing.
 */
static __always_inline struct vmap_area *
__merge_or_add_vmap_area(struct vmap_area *va,
	struct rb_root *root, struct list_head *head, bool augment)
{
	struct vmap_area *sibling;
	struct list_head *next;
	struct rb_node **link;
	struct rb_node *parent;
	bool merged = false;

	/*
	 * Find a place in the tree where VA potentially will be
	 * inserted, unless it is merged with its sibling/siblings.
	 */
	link = find_va_links(va, root, NULL, &parent);
	if (!link)
		return NULL;

	/*
	 * Get next node of VA to check if merging can be done.
	 */
	next = get_va_next_sibling(parent, link);
	if (unlikely(next == NULL))
		goto insert;

	/*
	 * start            end
	 * |                |
	 * |<------VA------>|<-----Next----->|
	 *                  |                |
	 *                  start            end
	 */
	if (next != head) {
		sibling = list_entry(next, struct vmap_area, list);
		if (sibling->va_start == va->va_end) {
			sibling->va_start = va->va_start;

			/* Free vmap_area object. */
			kmem_cache_free(vmap_area_cachep, va);

			/* Point to the new merged area. */
			va = sibling;
			merged = true;
		}
	}

	/*
	 * start            end
	 * |                |
	 * |<-----Prev----->|<------VA------>|
	 *                  |                |
	 *                  start            end
	 */
	if (next->prev != head) {
		sibling = list_entry(next->prev, struct vmap_area, list);
		if (sibling->va_end == va->va_start) {
			/*
			 * If both neighbors are coalesced, it is important
			 * to unlink the "next" node first, followed by merging
			 * with "previous" one. Otherwise the tree might not be
			 * fully populated if a sibling's augmented value is
			 * "normalized" because of rotation operations.
			 */
			if (merged)
				__unlink_va(va, root, augment);

			sibling->va_end = va->va_end;

			/* Free vmap_area object. */
			kmem_cache_free(vmap_area_cachep, va);

			/* Point to the new merged area. */
			va = sibling;
			merged = true;
		}
	}

insert:
	if (!merged)
		__link_va(va, root, parent, link, head, augment);

	return va;
}

static __always_inline struct vmap_area *
merge_or_add_vmap_area(struct vmap_area *va,
	struct rb_root *root, struct list_head *head)
{
	return __merge_or_add_vmap_area(va, root, head, false);
}

static __always_inline struct vmap_area *
merge_or_add_vmap_area_augment(struct vmap_area *va,
	struct rb_root *root, struct list_head *head)
{
	va = __merge_or_add_vmap_area(va, root, head, true);
	if (va)
		augment_tree_propagate_from(va);

	return va;
}

static __always_inline bool
is_within_this_va(struct vmap_area *va, unsigned long size,
	unsigned long align, unsigned long vstart)
{
	unsigned long nva_start_addr;

	if (va->va_start > vstart)
		nva_start_addr = ALIGN(va->va_start, align);
	else
		nva_start_addr = ALIGN(vstart, align);

	/* Can be overflowed due to big size or alignment. */
	if (nva_start_addr + size < nva_start_addr ||
			nva_start_addr < vstart)
		return false;

	return (nva_start_addr + size <= va->va_end);
}

/*
 * Find the first free block(lowest start address) in the tree,
 * that will accomplish the request corresponding to passing
 * parameters. Please note, with an alignment bigger than PAGE_SIZE,
 * a search length is adjusted to account for worst case alignment
 * overhead.
 */
/**
 * 在红黑树中查找最合适的 vmap_area 区域
 * 该函数通过红黑树搜索合适的内存区域，用于虚拟内存映射
 *
 * @param root 红黑树的根节点指针
 * @param size 请求的内存区域大小
 * @param align 内存区域的对齐要求
 * @param vstart 虚拟内存区域的起始地址
 * @param adjust_search_size 是否为对齐调整搜索大小
 *
 * @return 匹配的 vmap_area 结构指针，如果没有找到则返回 NULL
 */
static __always_inline struct vmap_area *
find_vmap_lowest_match(struct rb_root *root, unsigned long size,
	unsigned long align, unsigned long vstart, bool adjust_search_size)
{
	struct vmap_area *va; // 虚拟内存区域结构体指针
	struct rb_node *node; // 红黑树节点指针
	unsigned long length; // 调整后的搜索长度

	// 从根节点开始
	node = root->rb_node;

	// 根据对齐开销调整搜索大小
	length = adjust_search_size ? size + align - 1 : size;

	// 遍历红黑树节点
	while (node) {
		// 获取当前节点关联的虚拟内存区域
		va = rb_entry(node, struct vmap_area, rb_node);

		// 根据搜索条件决定向左子树还是右子树搜索
		if (get_subtree_max_size(node->rb_left) >= length &&
				vstart < va->va_start) {
			// 如果左子树可能有足够大的区域且 vstart 小于当前区域的起始地址，则向左搜索
			node = node->rb_left;
		} else {
			// 检查当前节点区域是否满足条件
			if (is_within_this_va(va, size, align, vstart))
				return va;

			// 如果右子树可能有足够大的区域，则向右搜索
			/*
			 * Does not make sense to go deeper towards the right
			 * sub-tree if it does not have a free block that is
			 * equal or bigger to the requested search length.
			 */
			if (get_subtree_max_size(node->rb_right) >= length) {
				node = node->rb_right;
				continue;
			}

			// 回溯寻找满足条件的右子树
			/*
			 * OK. We roll back and find the first right sub-tree,
			 * that will satisfy the search criteria. It can happen
			 * due to "vstart" restriction or an alignment overhead
			 * that is bigger then PAGE_SIZE.
			 */
			while ((node = rb_parent(node))) {
				va = rb_entry(node, struct vmap_area, rb_node);
				if (is_within_this_va(va, size, align, vstart))
					return va;

				if (get_subtree_max_size(node->rb_right) >= length &&
						vstart <= va->va_start) {
					// 更新 vstart 并搜索右子树
					/*
					 * Shift the vstart forward. Please note, we update it with
					 * parent's start address adding "1" because we do not want
					 * to enter same sub-tree after it has already been checked
					 * and no suitable free block found there.
					 */
					vstart = va->va_start + 1;
					node = node->rb_right;
					break;
				}
			}
		}
	}

	// 没有找到匹配的区域
	return NULL;
}

#if DEBUG_AUGMENT_LOWEST_MATCH_CHECK
#include <linux/random.h>

static struct vmap_area *
find_vmap_lowest_linear_match(struct list_head *head, unsigned long size,
	unsigned long align, unsigned long vstart)
{
	struct vmap_area *va;

	list_for_each_entry(va, head, list) {
		if (!is_within_this_va(va, size, align, vstart))
			continue;

		return va;
	}

	return NULL;
}

static void
find_vmap_lowest_match_check(struct rb_root *root, struct list_head *head,
			     unsigned long size, unsigned long align)
{
	struct vmap_area *va_1, *va_2;
	unsigned long vstart;
	unsigned int rnd;

	get_random_bytes(&rnd, sizeof(rnd));
	vstart = VMALLOC_START + rnd;

	va_1 = find_vmap_lowest_match(root, size, align, vstart, false);
	va_2 = find_vmap_lowest_linear_match(head, size, align, vstart);

	if (va_1 != va_2)
		pr_emerg("not lowest: t: 0x%p, l: 0x%p, v: 0x%lx\n",
			va_1, va_2, vstart);
}
#endif

enum fit_type {
	NOTHING_FIT = 0,
	FL_FIT_TYPE = 1,	/* full fit */
	LE_FIT_TYPE = 2,	/* left edge fit */
	RE_FIT_TYPE = 3,	/* right edge fit */
	NE_FIT_TYPE = 4		/* no edge fit */
};

static __always_inline enum fit_type
classify_va_fit_type(struct vmap_area *va,
	unsigned long nva_start_addr, unsigned long size)
{
	enum fit_type type;

	/* Check if it is within VA. */
	if (nva_start_addr < va->va_start ||
			nva_start_addr + size > va->va_end)
		return NOTHING_FIT;

	/* Now classify. */
	if (va->va_start == nva_start_addr) {
		if (va->va_end == nva_start_addr + size)
			type = FL_FIT_TYPE;
		else
			type = LE_FIT_TYPE;
	} else if (va->va_end == nva_start_addr + size) {
		type = RE_FIT_TYPE;
	} else {
		type = NE_FIT_TYPE;
	}

	return type;
}

/**
 * 调整虚拟地址区间以适应不同类型的内存分配请求
 *
 * 本函数根据新的内存分配请求，调整已存在的虚拟地址区间（VA）。目标是确保新的分配请求
 * 能够在虚拟地址空间中得到满足，同时尽可能高效地利用现有资源。函数通过分类不同的
 * 分配场景（完全匹配、左侧匹配、右侧匹配、无边缘匹配），执行相应的VA调整策略。
 *
 * @param root       RB树的根节点，用于维护虚拟地址区间的管理结构
 * @param head       链表头指针，用于管理空闲的虚拟地址区间
 * @param va         指向当前虚拟地址区间的结构体，需要根据新的分配请求进行调整
 * @param nva_start_addr    新的虚拟地址区间开始地址
 * @param size       新的分配请求的大小
 *
 * @return 返回0表示调整成功，非0表示调整失败
 */
static __always_inline int
adjust_va_to_fit_type(struct rb_root *root, struct list_head *head,
		      struct vmap_area *va, unsigned long nva_start_addr,
		      unsigned long size)
{
	/* 用于存储拆分后可能产生的新的虚拟地址区间 */
	struct vmap_area *lva = NULL;
	/* 确定当前分配请求的类型 */
	enum fit_type type = classify_va_fit_type(va, nva_start_addr, size);

	// 68ad4a3 的作用
	// 红黑树的使用： 以前的实现中，空闲的内存块管理是通过遍历列表实现的，复杂度为 O(n)。现在，通过引入增强型红黑树，空闲块按照地址顺序存储，并且每个节点都包含其子树中的最大可用块信息，这样可以更高效地找到合适的空闲块，复杂度降为 O(log n)。

	// 新增结构体字段： vmap_area 结构体中增加了 subtree_max_size 字段，用于存储子树中的最大空闲块大小。这使得在内存分配和释放时，可以快速找到合适的空闲区域，并减少碎片化。

	// 内存分配流程优化： 新的内存分配过程通过红黑树从根节点开始搜索，找到第一个适合的空闲块，然后根据实际需求进行分割。这与旧方法相比，更加高效。

	// 内存释放和合并： 在释放内存时，系统会尝试将释放的块与相邻的空闲块合并。如果无法合并，则将新的空闲块插入到红黑树中，同时更新相关节点的信息。

	// 锁机制的改进： 通过将全局锁拆分为两个独立的锁，一个用于分配，另一个用于释放，减少了锁竞争，进一步提升了并发性能。
	/* 完全匹配：无需拆分VA，直接移除并释放 */
	if (type == FL_FIT_TYPE) {
		/*
		 * No need to split VA, it fully fits.
		 *
		 * |               |
		 * V      NVA      V
		 * |---------------|
		 */
		unlink_va_augment(va, root);
		kmem_cache_free(vmap_area_cachep, va);
	} else if (type == LE_FIT_TYPE) {
		/*
		 * Split left edge of fit VA.
		 *
		 * |       |
		 * V  NVA  V   R
		 * |-------|-------|
		 */
		va->va_start += size;
	} else if (type == RE_FIT_TYPE) {
		/*
		 * Split right edge of fit VA.
		 *
		 *         |       |
		 *     L   V  NVA  V
		 * |-------|-------|
		 */
		va->va_end = nva_start_addr;
	} else if (type == NE_FIT_TYPE) {
		/*
		 * Split no edge of fit VA.
		 *
		 *     |       |
		 *   L V  NVA  V R
		 * |---|-------|---|
		 */
		lva = __this_cpu_xchg(ne_fit_preload_node, NULL);
		if (unlikely(!lva)) {
			/*
			 * For percpu allocator we do not do any pre-allocation
			 * and leave it as it is. The reason is it most likely
			 * never ends up with NE_FIT_TYPE splitting. In case of
			 * percpu allocations offsets and sizes are aligned to
			 * fixed align request, i.e. RE_FIT_TYPE and FL_FIT_TYPE
			 * are its main fitting cases.
			 *
			 * There are a few exceptions though, as an example it is
			 * a first allocation (early boot up) when we have "one"
			 * big free space that has to be split.
			 *
			 * Also we can hit this path in case of regular "vmap"
			 * allocations, if "this" current CPU was not preloaded.
			 * See the comment in alloc_vmap_area() why. If so, then
			 * GFP_NOWAIT is used instead to get an extra object for
			 * split purpose. That is rare and most time does not
			 * occur.
			 *
			 * What happens if an allocation gets failed. Basically,
			 * an "overflow" path is triggered to purge lazily freed
			 * areas to free some memory, then, the "retry" path is
			 * triggered to repeat one more time. See more details
			 * in alloc_vmap_area() function.
			 */
			lva = kmem_cache_alloc(vmap_area_cachep, GFP_NOWAIT);
			if (!lva)
				return -1;
		}

		/*
		 * Build the remainder.
		 */
		lva->va_start = va->va_start;
		lva->va_end = nva_start_addr;

		/*
		 * Shrink this VA to remaining size.
		 */
		va->va_start = nva_start_addr + size;
	} else {
		/* 如果不是已知的匹配类型，返回错误 */
		return -1;
	}

	/* 对不是完全匹配的情况，更新树结构和链表 */
	if (type != FL_FIT_TYPE) {
		augment_tree_propagate_from(va);

		if (lva)	/* type == NE_FIT_TYPE */
			insert_vmap_area_augment(lva, &va->rb_node, root, head);
	}

	return 0;
}

/*
 * Returns a start address of the newly allocated area, if success.
 * Otherwise a vend is returned that indicates failure.
 */
/**
 * 内联函数，用于在指定的红黑树根节点中分配一个连续的虚拟内存区域。
 *
 * @param root 红黑树的根节点指针，用于查找空闲的虚拟内存区域。
 * @param head 列表头指针，用于更新分配后的自由内存区域链表。
 * @param size 请求分配的虚拟内存区域大小（以字节为单位）。
 * @param align 对分配的虚拟内存区域起始地址的对齐要求（以字节为单位）。
 * @param vstart 分配的虚拟内存区域的起始地址。
 * @param vend 分配的虚拟内存区域的结束地址。
 *
 * @return 如果成功分配，返回分配的虚拟内存区域的起始地址；
 *         如果不能满足分配请求，返回 vend。
 */
static __always_inline unsigned long
__alloc_vmap_area(struct rb_root *root, struct list_head *head,
	unsigned long size, unsigned long align,
	unsigned long vstart, unsigned long vend)
{
	// 标志位，用于决定是否调整搜索大小
	bool adjust_search_size = true;
	unsigned long nva_start_addr;
	struct vmap_area *va;
	int ret;

	// 当对齐要求小于等于一页大小，或者请求的大小正好等于[vstart:vend]区间时，不进行调整
		/*
	 * Do not adjust when:
	 *   a) align <= PAGE_SIZE, because it does not make any sense.
	 *      All blocks(their start addresses) are at least PAGE_SIZE
	 *      aligned anyway;
	 *   b) a short range where a requested size corresponds to exactly
	 *      specified [vstart:vend] interval and an alignment > PAGE_SIZE.
	 *      With adjusted search length an allocation would not succeed.
	 */
	if (align <= PAGE_SIZE || (align > PAGE_SIZE && (vend - vstart) == size))
		adjust_search_size = false;

	// 查找最适合分配的虚拟内存区域
	va = find_vmap_lowest_match(root, size, align, vstart, adjust_search_size);
	if (unlikely(!va))
		return vend;

	// 根据对齐要求和已分配区域的起始地址，计算新的虚拟地址起始点
	if (va->va_start > vstart)
		nva_start_addr = ALIGN(va->va_start, align);
	else
		nva_start_addr = ALIGN(vstart, align);

	// 检查“vend”限制，确保分配的区域不超出这个限制
	if (nva_start_addr + size > vend)
		return vend;

	// 调整自由va链表，使其适应分配请求
	ret = adjust_va_to_fit_type(root, head, va, nva_start_addr, size);
	if (WARN_ON_ONCE(ret))
		return vend;

	// 调试代码：检查分配结果是否符合预期
#if DEBUG_AUGMENT_LOWEST_MATCH_CHECK
	find_vmap_lowest_match_check(root, head, size, align);
#endif

	// 返回分配的虚拟内存区域的起始地址
	return nva_start_addr;
}

/*
 * Free a region of KVA allocated by alloc_vmap_area
 */
static void free_vmap_area(struct vmap_area *va)
{
	/*
	 * Remove from the busy tree/list.
	 */
	spin_lock(&vmap_area_lock);
	unlink_va(va, &vmap_area_root);
	spin_unlock(&vmap_area_lock);

	/*
	 * Insert/Merge it back to the free tree/list.
	 */
	spin_lock(&free_vmap_area_lock);
	merge_or_add_vmap_area_augment(va, &free_vmap_area_root, &free_vmap_area_list);
	spin_unlock(&free_vmap_area_lock);
}

static inline void
preload_this_cpu_lock(spinlock_t *lock, gfp_t gfp_mask, int node)
{
	struct vmap_area *va = NULL;

	/*
	 * Preload this CPU with one extra vmap_area object. It is used
	 * when fit type of free area is NE_FIT_TYPE. It guarantees that
	 * a CPU that does an allocation is preloaded.
	 *
	 * We do it in non-atomic context, thus it allows us to use more
	 * permissive allocation masks to be more stable under low memory
	 * condition and high memory pressure.
	 */
	if (!this_cpu_read(ne_fit_preload_node))
		va = kmem_cache_alloc_node(vmap_area_cachep, gfp_mask, node);

	spin_lock(lock);

	if (va && __this_cpu_cmpxchg(ne_fit_preload_node, NULL, va))
		kmem_cache_free(vmap_area_cachep, va);
}

/*
 * Allocate a region of KVA of the specified size and alignment, within the
 * vstart and vend.
 */
/**
 * 分配一个虚拟内存区域。
 *
 * 该函数用于分配一个连续的虚拟内存区域，主要用于内核内部使用。
 * 它会检查参数的有效性，尝试分配内存，并在成功分配后注册该虚拟内存区域。
 *
 * @param size 要分配的虚拟内存区域的大小。
 * @param align 虚拟内存区域的对齐要求。
 * @param vstart 虚拟内存区域的建议起始地址。
 * @param vend 虚拟内存区域的建议结束地址。
 * @param node 分配内存的节点编号，用于NUMA系统。
 * @param gfp_mask 分配内存时使用的标志。
 * @param va_flags 虚拟内存区域的标志。
 *
 * @return 分配成功的虚拟内存区域结构指针，或在错误时返回ERR_PTR。
 */
static struct vmap_area *alloc_vmap_area(unsigned long size,
				unsigned long align,
				unsigned long vstart, unsigned long vend,
				int node, gfp_t gfp_mask,
				unsigned long va_flags)
{
	struct vmap_area *va;
	unsigned long freed;
	unsigned long addr;
	int purged = 0;
	int ret;

	// 检查输入参数的有效性
	if (unlikely(!size || offset_in_page(size) || !is_power_of_2(align)))
		return ERR_PTR(-EINVAL);

	// 检查vmap是否已初始化
	if (unlikely(!vmap_initialized))
		return ERR_PTR(-EBUSY);

	// 可能会睡眠
	might_sleep();
	// 确保gfp_mask仅包含有效的内存回收标志
	gfp_mask = gfp_mask & GFP_RECLAIM_MASK;

	// 从缓存中分配一个vmap_area结构
	va = kmem_cache_alloc_node(vmap_area_cachep, gfp_mask, node);
	if (unlikely(!va))
		return ERR_PTR(-ENOMEM);

	// 扫描va结构以避免泄露
	kmemleak_scan_area(&va->rb_node, SIZE_MAX, gfp_mask);

retry:
	// 尝试锁定并分配虚拟内存区域
	preload_this_cpu_lock(&free_vmap_area_lock, gfp_mask, node);
	addr = __alloc_vmap_area(&free_vmap_area_root, &free_vmap_area_list,
		size, align, vstart, vend);
	spin_unlock(&free_vmap_area_lock);

	// 记录分配的虚拟内存区域信息
	trace_alloc_vmap_area(addr, size, align, vstart, vend, addr == vend);

	// 如果分配失败，则返回错误
	// 问题背景：
	// 在现有的内核实现中，vmalloc 分配新虚拟内存区域的操作是通过遍历繁忙列表（busy list）来寻找空闲区域，这种方式的复杂度为 O(N)。由于随着系统运行时间的增长，繁忙列表中的区域会越来越碎片化，导致分配时间变长。在一些嵌入式设备上，这种分配时间可能会达到毫秒级别，这是不可接受的。

	// 解决方案：
	// 该补丁引入了一种改进的分配机制，将 KVA（Kernel Virtual Address）内存布局组织为从 1 到 ULONG_MAX 范围内的空闲区域。其核心思想是使用增强型红黑树（augment red-black tree）来管理空闲区域，并通过链表维护这些空闲区域按地址递增顺序排列。

	// 具体优化点包括：
	// 红黑树的使用：

	// 红黑树按虚拟地址 va_start 进行排序，并在节点中维护该子树内最大可用的空闲块大小。这样可以快速找到适合分配请求的最小空闲块。
	// 由于红黑树的特性，搜索和插入操作的复杂度为 O(log(N))，相比原来的 O(N) 提升了效率。
	// 内存分配：

	// 在分配新块时，通过红黑树进行搜索，直到找到一个合适的空闲块。如果该块比请求的大小大，则会进行分割（split）。
	// 该分配方法是顺序分配，倾向于最大化内存局部性，从而提高性能。
	// 内存释放：

	// 在释放 vmap 区域时，首先检查是否可以与前后的空闲块合并（merge），如果可以合并，则会创建一个更大的连续空闲块。
	// 合并操作通过链表提供的常量时间访问前后块的功能进行，从而快速检查合并条件。
	// 缓存优化：

	// 为了优化分割和合并操作中的内存分配，补丁中引入了一个 free_vmap 对象缓存，以避免频繁从 slab 中分配新结构体。
	// 测试和性能分析：
	// 补丁在多个平台（包括 x86_64、i686、ARM64 和 x86_64_NUMA）上进行了大量测试，使用的测试工具是内核提供的 test_vmalloc.sh。测试结果表明，该补丁大大减少了分配时间，在某些情况下从几分钟减少到几秒钟。

	// 例如，测试显示：

	// i5-3320M CPU：

	// 运行默认内核配置时，所有测试消耗的 CPU 周期为 646,919,905,370。
	// 使用该补丁后，消耗的 CPU 周期减少到 193,290,498,550。
	// HiKey960（ARM64）：

	// 默认内核配置下测试未能完成，而使用补丁后的测试时间为 4 分 25 秒。
	// 总结：
	// 这个补丁显著提高了 vmalloc 分配的效率，特别是在处理碎片化内存时。通过使用增强型红黑树来管理空闲块，并结合链表进行快速访问和合并操作，该补丁减少了分配和释放的时间，提升了内存管理的整体性能。
	// 68ad4a3
	if (unlikely(addr == vend))
		goto overflow;

	// 设置虚拟内存区域的起始和结束地址
	va->va_start = addr;
	va->va_end = addr + size;
	va->vm = NULL;
	va->flags = va_flags;

	// 注册虚拟内存区域
	spin_lock(&vmap_area_lock);
	// 这段补丁描述中提出了对 vmap_area_lock 的重构，目的是进一步优化 KVA（Kernel Virtual Address）的性能。

	// 背景
	// 在 5.2 版内核中引入了一种新的内存分配方法，这为减少全局自旋锁的使用提供了可能性。全局自旋锁通常会引发高锁争用，尤其是在多核处理器并行执行任务时，这会严重影响系统性能。为了解决这个问题，作者提出了将全局锁拆分为两个独立的锁，一个用于内存分配，一个用于内存释放。

	// 主要改动
	// 锁的分离：

	// 原有的全局 vmap_area_lock 被拆分为两个独立的锁，分别用于处理“空闲数据结构”和“繁忙数据结构”。
	// 这意味着内存分配和释放操作可以在不同的 CPU 上并行进行，从而减少了锁的争用。
	// 并行操作：

	// 尽管在不同 CPU 上并行执行分配和释放操作时仍然存在一定的依赖性，但通过拆分锁，这种依赖性被大大降低。
	// 两个锁允许在不同 CPU 上并行操作 "free" 和 "busy" 树，进一步提高了系统的并发能力。
	// 测试结果
	// 为了评估这个补丁，作者使用了 vmalloc test driver 进行测试，测试过程中会导致高锁争用，从而更好地衡量新方案的效果。

	// 测试设备为 HiKey 960（ARM64 架构，8 核 CPU，big.LITTLE 设计）。

	// 未打补丁的结果：

	// CPU0 至 CPU7 的测试循环分别耗费了 457,126,382 到 384,036,264 个 CPU 周期。
	// 打补丁后的结果：

	// CPU0 至 CPU7 的测试循环分别耗费了 391,521,310 到 297,092,392 个 CPU 周期。
	// 相比之下，打补丁后的结果在不同 CPU 上的 CPU 周期减少了 14% 到 23%。

	// 总结
	// 这个补丁通过将 vmap_area_lock 分离为两个独立的锁，从而减少了锁争用，显著提升了多核 CPU 环境下的 KVA 操作性能。测试结果显示，在 HiKey 960（ARM64）设备上，打补丁后性能提升约 14% 到 23%。这对高并发场景中的系统性能改进具有积极作用。
	insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
	spin_unlock(&vmap_area_lock);

	// 确保虚拟内存区域满足对齐和地址范围要求
	BUG_ON(!IS_ALIGNED(va->va_start, align));
	BUG_ON(va->va_start < vstart);
	BUG_ON(va->va_end > vend);

	// // 对分配的区域进行KASAN检查
	// 背景
	// CONFIG_KASAN_VMALLOC=y 是内核地址空间布局随机化（KASAN）的一个配置选项，它启用了对 vmalloc 分配的内存进行内存检测和错误报告的功能。启用这个选项后，内核在访问使用 vm_map_ram() 分配的内存时可能会发生崩溃，这是因为 vm_map_ram() 映射的内存没有相应的 KASAN 阴影内存（shadow memory）。

	// KASAN 的阴影内存用于跟踪实际内存访问是否有效。如果没有为特定内存区域设置阴影内存，KASAN 会报告非法访问，从而导致崩溃。

	// 修复方案
	// 为了修复这个问题，补丁的解决方案是将 kasan_populate_vmalloc() 调用移动到 alloc_vmap_area() 函数中，而不是在 vmalloc 代码的各个地方添加额外的 kasan_populate_vmalloc() 调用。

	// 主要改动
	// 移除冗余调用：通过将 kasan_populate_vmalloc() 集中到 alloc_vmap_area() 函数中，避免了在 vmalloc 代码中散布多个 KASAN 相关调用，简化了代码逻辑。

	// 修复 vm_map_ram() 崩溃问题：这种做法确保了 vm_map_ram() 分配的内存能够正确地与 KASAN 阴影内存对应，避免了因为阴影内存缺失导致的崩溃问题。
	ret = kasan_populate_vmalloc(addr, size);
	if (ret) {
		free_vmap_area(va);
		return ERR_PTR(ret);
	}

	// 返回成功分配的虚拟内存区域
	return va;

overflow:
	if (!purged) {
		reclaim_and_purge_vmap_areas();
		purged = 1;
		goto retry;
	}

	freed = 0;
	blocking_notifier_call_chain(&vmap_notify_list, 0, &freed);

	if (freed > 0) {
		purged = 0;
		goto retry;
	}

	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit())
		pr_warn("vmap allocation for size %lu failed: use vmalloc=<size> to increase size\n",
			size);

	kmem_cache_free(vmap_area_cachep, va);
	return ERR_PTR(-EBUSY);
}

int register_vmap_purge_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&vmap_notify_list, nb);
}
EXPORT_SYMBOL_GPL(register_vmap_purge_notifier);

int unregister_vmap_purge_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&vmap_notify_list, nb);
}
EXPORT_SYMBOL_GPL(unregister_vmap_purge_notifier);

/*
 * lazy_max_pages is the maximum amount of virtual address space we gather up
 * before attempting to purge with a TLB flush.
 *
 * There is a tradeoff here: a larger number will cover more kernel page tables
 * and take slightly longer to purge, but it will linearly reduce the number of
 * global TLB flushes that must be performed. It would seem natural to scale
 * this number up linearly with the number of CPUs (because vmapping activity
 * could also scale linearly with the number of CPUs), however it is likely
 * that in practice, workloads might be constrained in other ways that mean
 * vmap activity will not scale linearly with CPUs. Also, I want to be
 * conservative and not introduce a big latency on huge systems, so go with
 * a less aggressive log scale. It will still be an improvement over the old
 * code, and it will be simple to change the scale factor if we find that it
 * becomes a problem on bigger systems.
 */
static unsigned long lazy_max_pages(void)
{
	unsigned int log;

	log = fls(num_online_cpus());

	return log * (32UL * 1024 * 1024 / PAGE_SIZE);
}

static atomic_long_t vmap_lazy_nr = ATOMIC_LONG_INIT(0);

/*
 * Serialize vmap purging.  There is no actual critical section protected
 * by this lock, but we want to avoid concurrent calls for performance
 * reasons and to make the pcpu_get_vm_areas more deterministic.
 */
static DEFINE_MUTEX(vmap_purge_lock);

/* for per-CPU blocks */
static void purge_fragmented_blocks_allcpus(void);

/*
 * Purges all lazily-freed vmap areas.
 */
static bool __purge_vmap_area_lazy(unsigned long start, unsigned long end)
{
	unsigned long resched_threshold;
	unsigned int num_purged_areas = 0;
	struct list_head local_purge_list;
	struct vmap_area *va, *n_va;

	lockdep_assert_held(&vmap_purge_lock);

	spin_lock(&purge_vmap_area_lock);
	purge_vmap_area_root = RB_ROOT;
	list_replace_init(&purge_vmap_area_list, &local_purge_list);
	spin_unlock(&purge_vmap_area_lock);

	if (unlikely(list_empty(&local_purge_list)))
		goto out;

	start = min(start,
		list_first_entry(&local_purge_list,
			struct vmap_area, list)->va_start);

	end = max(end,
		list_last_entry(&local_purge_list,
			struct vmap_area, list)->va_end);

	flush_tlb_kernel_range(start, end);
	resched_threshold = lazy_max_pages() << 1;

	spin_lock(&free_vmap_area_lock);
	list_for_each_entry_safe(va, n_va, &local_purge_list, list) {
		unsigned long nr = (va->va_end - va->va_start) >> PAGE_SHIFT;
		unsigned long orig_start = va->va_start;
		unsigned long orig_end = va->va_end;

		/*
		 * Finally insert or merge lazily-freed area. It is
		 * detached and there is no need to "unlink" it from
		 * anything.
		 */
		va = merge_or_add_vmap_area_augment(va, &free_vmap_area_root,
				&free_vmap_area_list);

		if (!va)
			continue;

		if (is_vmalloc_or_module_addr((void *)orig_start))
			kasan_release_vmalloc(orig_start, orig_end,
					      va->va_start, va->va_end);

		atomic_long_sub(nr, &vmap_lazy_nr);
		num_purged_areas++;

		if (atomic_long_read(&vmap_lazy_nr) < resched_threshold)
			cond_resched_lock(&free_vmap_area_lock);
	}
	spin_unlock(&free_vmap_area_lock);

out:
	trace_purge_vmap_area_lazy(start, end, num_purged_areas);
	return num_purged_areas > 0;
}

/*
 * Reclaim vmap areas by purging fragmented blocks and purge_vmap_area_list.
 */
static void reclaim_and_purge_vmap_areas(void)

{
	mutex_lock(&vmap_purge_lock);
	purge_fragmented_blocks_allcpus();
	__purge_vmap_area_lazy(ULONG_MAX, 0);
	mutex_unlock(&vmap_purge_lock);
}

static void drain_vmap_area_work(struct work_struct *work)
{
	unsigned long nr_lazy;

	do {
		mutex_lock(&vmap_purge_lock);
		__purge_vmap_area_lazy(ULONG_MAX, 0);
		mutex_unlock(&vmap_purge_lock);

		/* Recheck if further work is required. */
		nr_lazy = atomic_long_read(&vmap_lazy_nr);
	} while (nr_lazy > lazy_max_pages());
}

/*
 * Free a vmap area, caller ensuring that the area has been unmapped,
 * unlinked and flush_cache_vunmap had been called for the correct
 * range previously.
 */
static void free_vmap_area_noflush(struct vmap_area *va)
{
	unsigned long nr_lazy_max = lazy_max_pages();
	unsigned long va_start = va->va_start;
	unsigned long nr_lazy;

	if (WARN_ON_ONCE(!list_empty(&va->list)))
		return;

	nr_lazy = atomic_long_add_return((va->va_end - va->va_start) >>
				PAGE_SHIFT, &vmap_lazy_nr);

	/*
	 * Merge or place it to the purge tree/list.
	 */
	spin_lock(&purge_vmap_area_lock);
	merge_or_add_vmap_area(va,
		&purge_vmap_area_root, &purge_vmap_area_list);
	spin_unlock(&purge_vmap_area_lock);

	trace_free_vmap_area_noflush(va_start, nr_lazy, nr_lazy_max);

	/* After this point, we may free va at any time */
	if (unlikely(nr_lazy > nr_lazy_max))
		schedule_work(&drain_vmap_work);
}

/*
 * Free and unmap a vmap area
 */
static void free_unmap_vmap_area(struct vmap_area *va)
{
	flush_cache_vunmap(va->va_start, va->va_end);
	vunmap_range_noflush(va->va_start, va->va_end);
	if (debug_pagealloc_enabled_static())
		flush_tlb_kernel_range(va->va_start, va->va_end);

	free_vmap_area_noflush(va);
}

struct vmap_area *find_vmap_area(unsigned long addr)
{
	struct vmap_area *va;

	spin_lock(&vmap_area_lock);
	va = __find_vmap_area(addr, &vmap_area_root);
	spin_unlock(&vmap_area_lock);

	return va;
}

static struct vmap_area *find_unlink_vmap_area(unsigned long addr)
{
	struct vmap_area *va;

	spin_lock(&vmap_area_lock);
	va = __find_vmap_area(addr, &vmap_area_root);
	if (va)
		unlink_va(va, &vmap_area_root);
	spin_unlock(&vmap_area_lock);

	return va;
}

/*** Per cpu kva allocator ***/

/*
 * vmap space is limited especially on 32 bit architectures. Ensure there is
 * room for at least 16 percpu vmap blocks per CPU.
 */
/*
 * If we had a constant VMALLOC_START and VMALLOC_END, we'd like to be able
 * to #define VMALLOC_SPACE		(VMALLOC_END-VMALLOC_START). Guess
 * instead (we just need a rough idea)
 */
#if BITS_PER_LONG == 32
#define VMALLOC_SPACE		(128UL*1024*1024)
#else
#define VMALLOC_SPACE		(128UL*1024*1024*1024)
#endif

#define VMALLOC_PAGES		(VMALLOC_SPACE / PAGE_SIZE)
#define VMAP_MAX_ALLOC		BITS_PER_LONG	/* 256K with 4K pages */
#define VMAP_BBMAP_BITS_MAX	1024	/* 4MB with 4K pages */
#define VMAP_BBMAP_BITS_MIN	(VMAP_MAX_ALLOC*2)
#define VMAP_MIN(x, y)		((x) < (y) ? (x) : (y)) /* can't use min() */
#define VMAP_MAX(x, y)		((x) > (y) ? (x) : (y)) /* can't use max() */
#define VMAP_BBMAP_BITS		\
		VMAP_MIN(VMAP_BBMAP_BITS_MAX,	\
		VMAP_MAX(VMAP_BBMAP_BITS_MIN,	\
			VMALLOC_PAGES / roundup_pow_of_two(NR_CPUS) / 16))

#define VMAP_BLOCK_SIZE		(VMAP_BBMAP_BITS * PAGE_SIZE)

/*
 * Purge threshold to prevent overeager purging of fragmented blocks for
 * regular operations: Purge if vb->free is less than 1/4 of the capacity.
 */
#define VMAP_PURGE_THRESHOLD	(VMAP_BBMAP_BITS / 4)

#define VMAP_RAM		0x1 /* indicates vm_map_ram area*/
#define VMAP_BLOCK		0x2 /* mark out the vmap_block sub-type*/
#define VMAP_FLAGS_MASK		0x3

struct vmap_block_queue {
	spinlock_t lock;
	struct list_head free;

	/*
	 * An xarray requires an extra memory dynamically to
	 * be allocated. If it is an issue, we can use rb-tree
	 * instead.
	 */
	struct xarray vmap_blocks;
};

struct vmap_block {
	spinlock_t lock;
	struct vmap_area *va;
	unsigned long free, dirty;
	DECLARE_BITMAP(used_map, VMAP_BBMAP_BITS);
	unsigned long dirty_min, dirty_max; /*< dirty range */
	struct list_head free_list;
	struct rcu_head rcu_head;
	struct list_head purge;
};

/* Queue of free and dirty vmap blocks, for allocation and flushing purposes */
static DEFINE_PER_CPU(struct vmap_block_queue, vmap_block_queue);

/*
 * In order to fast access to any "vmap_block" associated with a
 * specific address, we use a hash.
 *
 * A per-cpu vmap_block_queue is used in both ways, to serialize
 * an access to free block chains among CPUs(alloc path) and it
 * also acts as a vmap_block hash(alloc/free paths). It means we
 * overload it, since we already have the per-cpu array which is
 * used as a hash table. When used as a hash a 'cpu' passed to
 * per_cpu() is not actually a CPU but rather a hash index.
 *
 * A hash function is addr_to_vb_xa() which hashes any address
 * to a specific index(in a hash) it belongs to. This then uses a
 * per_cpu() macro to access an array with generated index.
 *
 * An example:
 *
 *  CPU_1  CPU_2  CPU_0
 *    |      |      |
 *    V      V      V
 * 0     10     20     30     40     50     60
 * |------|------|------|------|------|------|...<vmap address space>
 *   CPU0   CPU1   CPU2   CPU0   CPU1   CPU2
 *
 * - CPU_1 invokes vm_unmap_ram(6), 6 belongs to CPU0 zone, thus
 *   it access: CPU0/INDEX0 -> vmap_blocks -> xa_lock;
 *
 * - CPU_2 invokes vm_unmap_ram(11), 11 belongs to CPU1 zone, thus
 *   it access: CPU1/INDEX1 -> vmap_blocks -> xa_lock;
 *
 * - CPU_0 invokes vm_unmap_ram(20), 20 belongs to CPU2 zone, thus
 *   it access: CPU2/INDEX2 -> vmap_blocks -> xa_lock.
 *
 * This technique almost always avoids lock contention on insert/remove,
 * however xarray spinlocks protect against any contention that remains.
 */
static struct xarray *
addr_to_vb_xa(unsigned long addr)
{
	int index = (addr / VMAP_BLOCK_SIZE) % num_possible_cpus();

	return &per_cpu(vmap_block_queue, index).vmap_blocks;
}

/*
 * We should probably have a fallback mechanism to allocate virtual memory
 * out of partially filled vmap blocks. However vmap block sizing should be
 * fairly reasonable according to the vmalloc size, so it shouldn't be a
 * big problem.
 */

static unsigned long addr_to_vb_idx(unsigned long addr)
{
	addr -= VMALLOC_START & ~(VMAP_BLOCK_SIZE-1);
	addr /= VMAP_BLOCK_SIZE;
	return addr;
}

static void *vmap_block_vaddr(unsigned long va_start, unsigned long pages_off)
{
	unsigned long addr;

	addr = va_start + (pages_off << PAGE_SHIFT);
	BUG_ON(addr_to_vb_idx(addr) != addr_to_vb_idx(va_start));
	return (void *)addr;
}

/**
 * new_vmap_block - allocates new vmap_block and occupies 2^order pages in this
 *                  block. Of course pages number can't exceed VMAP_BBMAP_BITS
 * @order:    how many 2^order pages should be occupied in newly allocated block
 * @gfp_mask: flags for the page level allocator
 *
 * Return: virtual address in a newly allocated block or ERR_PTR(-errno)
 */
static void *new_vmap_block(unsigned int order, gfp_t gfp_mask)
{
	struct vmap_block_queue *vbq;
	struct vmap_block *vb;
	struct vmap_area *va;
	struct xarray *xa;
	unsigned long vb_idx;
	int node, err;
	void *vaddr;

	node = numa_node_id();

	vb = kmalloc_node(sizeof(struct vmap_block),
			gfp_mask & GFP_RECLAIM_MASK, node);
	if (unlikely(!vb))
		return ERR_PTR(-ENOMEM);

	va = alloc_vmap_area(VMAP_BLOCK_SIZE, VMAP_BLOCK_SIZE,
					VMALLOC_START, VMALLOC_END,
					node, gfp_mask,
					VMAP_RAM|VMAP_BLOCK);
	if (IS_ERR(va)) {
		kfree(vb);
		return ERR_CAST(va);
	}

	vaddr = vmap_block_vaddr(va->va_start, 0);
	spin_lock_init(&vb->lock);
	vb->va = va;
	/* At least something should be left free */
	BUG_ON(VMAP_BBMAP_BITS <= (1UL << order));
	bitmap_zero(vb->used_map, VMAP_BBMAP_BITS);
	vb->free = VMAP_BBMAP_BITS - (1UL << order);
	vb->dirty = 0;
	vb->dirty_min = VMAP_BBMAP_BITS;
	vb->dirty_max = 0;
	bitmap_set(vb->used_map, 0, (1UL << order));
	INIT_LIST_HEAD(&vb->free_list);

	xa = addr_to_vb_xa(va->va_start);
	vb_idx = addr_to_vb_idx(va->va_start);
	err = xa_insert(xa, vb_idx, vb, gfp_mask);
	if (err) {
		kfree(vb);
		free_vmap_area(va);
		return ERR_PTR(err);
	}

	vbq = raw_cpu_ptr(&vmap_block_queue);
	spin_lock(&vbq->lock);
	list_add_tail_rcu(&vb->free_list, &vbq->free);
	spin_unlock(&vbq->lock);

	return vaddr;
}

static void free_vmap_block(struct vmap_block *vb)
{
	struct vmap_block *tmp;
	struct xarray *xa;

	xa = addr_to_vb_xa(vb->va->va_start);
	tmp = xa_erase(xa, addr_to_vb_idx(vb->va->va_start));
	BUG_ON(tmp != vb);

	spin_lock(&vmap_area_lock);
	unlink_va(vb->va, &vmap_area_root);
	spin_unlock(&vmap_area_lock);

	free_vmap_area_noflush(vb->va);
	kfree_rcu(vb, rcu_head);
}

static bool purge_fragmented_block(struct vmap_block *vb,
		struct vmap_block_queue *vbq, struct list_head *purge_list,
		bool force_purge)
{
	if (vb->free + vb->dirty != VMAP_BBMAP_BITS ||
	    vb->dirty == VMAP_BBMAP_BITS)
		return false;

	/* Don't overeagerly purge usable blocks unless requested */
	if (!(force_purge || vb->free < VMAP_PURGE_THRESHOLD))
		return false;

	/* prevent further allocs after releasing lock */
	WRITE_ONCE(vb->free, 0);
	/* prevent purging it again */
	WRITE_ONCE(vb->dirty, VMAP_BBMAP_BITS);
	vb->dirty_min = 0;
	vb->dirty_max = VMAP_BBMAP_BITS;
	spin_lock(&vbq->lock);
	list_del_rcu(&vb->free_list);
	spin_unlock(&vbq->lock);
	list_add_tail(&vb->purge, purge_list);
	return true;
}

static void free_purged_blocks(struct list_head *purge_list)
{
	struct vmap_block *vb, *n_vb;

	list_for_each_entry_safe(vb, n_vb, purge_list, purge) {
		list_del(&vb->purge);
		free_vmap_block(vb);
	}
}

static void purge_fragmented_blocks(int cpu)
{
	LIST_HEAD(purge);
	struct vmap_block *vb;
	struct vmap_block_queue *vbq = &per_cpu(vmap_block_queue, cpu);

	rcu_read_lock();
	list_for_each_entry_rcu(vb, &vbq->free, free_list) {
		unsigned long free = READ_ONCE(vb->free);
		unsigned long dirty = READ_ONCE(vb->dirty);

		if (free + dirty != VMAP_BBMAP_BITS ||
		    dirty == VMAP_BBMAP_BITS)
			continue;

		spin_lock(&vb->lock);
		purge_fragmented_block(vb, vbq, &purge, true);
		spin_unlock(&vb->lock);
	}
	rcu_read_unlock();
	free_purged_blocks(&purge);
}

static void purge_fragmented_blocks_allcpus(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		purge_fragmented_blocks(cpu);
}

static void *vb_alloc(unsigned long size, gfp_t gfp_mask)
{
	struct vmap_block_queue *vbq;
	struct vmap_block *vb;
	void *vaddr = NULL;
	unsigned int order;

	BUG_ON(offset_in_page(size));
	BUG_ON(size > PAGE_SIZE*VMAP_MAX_ALLOC);
	if (WARN_ON(size == 0)) {
		/*
		 * Allocating 0 bytes isn't what caller wants since
		 * get_order(0) returns funny result. Just warn and terminate
		 * early.
		 */
		return NULL;
	}
	order = get_order(size);

	rcu_read_lock();
	vbq = raw_cpu_ptr(&vmap_block_queue);
	list_for_each_entry_rcu(vb, &vbq->free, free_list) {
		unsigned long pages_off;

		if (READ_ONCE(vb->free) < (1UL << order))
			continue;

		spin_lock(&vb->lock);
		if (vb->free < (1UL << order)) {
			spin_unlock(&vb->lock);
			continue;
		}

		pages_off = VMAP_BBMAP_BITS - vb->free;
		vaddr = vmap_block_vaddr(vb->va->va_start, pages_off);
		WRITE_ONCE(vb->free, vb->free - (1UL << order));
		bitmap_set(vb->used_map, pages_off, (1UL << order));
		if (vb->free == 0) {
			spin_lock(&vbq->lock);
			list_del_rcu(&vb->free_list);
			spin_unlock(&vbq->lock);
		}

		spin_unlock(&vb->lock);
		break;
	}

	rcu_read_unlock();

	/* Allocate new block if nothing was found */
	if (!vaddr)
		vaddr = new_vmap_block(order, gfp_mask);

	return vaddr;
}

static void vb_free(unsigned long addr, unsigned long size)
{
	unsigned long offset;
	unsigned int order;
	struct vmap_block *vb;
	struct xarray *xa;

	BUG_ON(offset_in_page(size));
	BUG_ON(size > PAGE_SIZE*VMAP_MAX_ALLOC);

	flush_cache_vunmap(addr, addr + size);

	order = get_order(size);
	offset = (addr & (VMAP_BLOCK_SIZE - 1)) >> PAGE_SHIFT;

	xa = addr_to_vb_xa(addr);
	vb = xa_load(xa, addr_to_vb_idx(addr));

	spin_lock(&vb->lock);
	bitmap_clear(vb->used_map, offset, (1UL << order));
	spin_unlock(&vb->lock);

	vunmap_range_noflush(addr, addr + size);

	if (debug_pagealloc_enabled_static())
		flush_tlb_kernel_range(addr, addr + size);

	spin_lock(&vb->lock);

	/* Expand the not yet TLB flushed dirty range */
	vb->dirty_min = min(vb->dirty_min, offset);
	vb->dirty_max = max(vb->dirty_max, offset + (1UL << order));

	WRITE_ONCE(vb->dirty, vb->dirty + (1UL << order));
	if (vb->dirty == VMAP_BBMAP_BITS) {
		BUG_ON(vb->free);
		spin_unlock(&vb->lock);
		free_vmap_block(vb);
	} else
		spin_unlock(&vb->lock);
}

static void _vm_unmap_aliases(unsigned long start, unsigned long end, int flush)
{
	LIST_HEAD(purge_list);
	int cpu;

	if (unlikely(!vmap_initialized))
		return;

	mutex_lock(&vmap_purge_lock);

	for_each_possible_cpu(cpu) {
		struct vmap_block_queue *vbq = &per_cpu(vmap_block_queue, cpu);
		struct vmap_block *vb;
		unsigned long idx;

		rcu_read_lock();
		xa_for_each(&vbq->vmap_blocks, idx, vb) {
			spin_lock(&vb->lock);

			/*
			 * Try to purge a fragmented block first. If it's
			 * not purgeable, check whether there is dirty
			 * space to be flushed.
			 */
			if (!purge_fragmented_block(vb, vbq, &purge_list, false) &&
			    vb->dirty_max && vb->dirty != VMAP_BBMAP_BITS) {
				unsigned long va_start = vb->va->va_start;
				unsigned long s, e;

				s = va_start + (vb->dirty_min << PAGE_SHIFT);
				e = va_start + (vb->dirty_max << PAGE_SHIFT);

				start = min(s, start);
				end   = max(e, end);

				/* Prevent that this is flushed again */
				vb->dirty_min = VMAP_BBMAP_BITS;
				vb->dirty_max = 0;

				flush = 1;
			}
			spin_unlock(&vb->lock);
		}
		rcu_read_unlock();
	}
	free_purged_blocks(&purge_list);

	if (!__purge_vmap_area_lazy(start, end) && flush)
		flush_tlb_kernel_range(start, end);
	mutex_unlock(&vmap_purge_lock);
}

/**
 * vm_unmap_aliases - unmap outstanding lazy aliases in the vmap layer
 *
 * The vmap/vmalloc layer lazily flushes kernel virtual mappings primarily
 * to amortize TLB flushing overheads. What this means is that any page you
 * have now, may, in a former life, have been mapped into kernel virtual
 * address by the vmap layer and so there might be some CPUs with TLB entries
 * still referencing that page (additional to the regular 1:1 kernel mapping).
 *
 * vm_unmap_aliases flushes all such lazy mappings. After it returns, we can
 * be sure that none of the pages we have control over will have any aliases
 * from the vmap layer.
 */
void vm_unmap_aliases(void)
{
	unsigned long start = ULONG_MAX, end = 0;
	int flush = 0;

	_vm_unmap_aliases(start, end, flush);
}
EXPORT_SYMBOL_GPL(vm_unmap_aliases);

/**
 * vm_unmap_ram - unmap linear kernel address space set up by vm_map_ram
 * @mem: the pointer returned by vm_map_ram
 * @count: the count passed to that vm_map_ram call (cannot unmap partial)
 */
void vm_unmap_ram(const void *mem, unsigned int count)
{
	unsigned long size = (unsigned long)count << PAGE_SHIFT;
	unsigned long addr = (unsigned long)kasan_reset_tag(mem);
	struct vmap_area *va;

	might_sleep();
	BUG_ON(!addr);
	BUG_ON(addr < VMALLOC_START);
	BUG_ON(addr > VMALLOC_END);
	BUG_ON(!PAGE_ALIGNED(addr));

	kasan_poison_vmalloc(mem, size);

	if (likely(count <= VMAP_MAX_ALLOC)) {
		debug_check_no_locks_freed(mem, size);
		vb_free(addr, size);
		return;
	}

	va = find_unlink_vmap_area(addr);
	if (WARN_ON_ONCE(!va))
		return;

	debug_check_no_locks_freed((void *)va->va_start,
				    (va->va_end - va->va_start));
	free_unmap_vmap_area(va);
}
EXPORT_SYMBOL(vm_unmap_ram);

/**
 * vm_map_ram - map pages linearly into kernel virtual address (vmalloc space)
 * @pages: an array of pointers to the pages to be mapped
 * @count: number of pages
 * @node: prefer to allocate data structures on this node
 *
 * If you use this function for less than VMAP_MAX_ALLOC pages, it could be
 * faster than vmap so it's good.  But if you mix long-life and short-life
 * objects with vm_map_ram(), it could consume lots of address space through
 * fragmentation (especially on a 32bit machine).  You could see failures in
 * the end.  Please use this function for short-lived objects.
 *
 * Returns: a pointer to the address that has been mapped, or %NULL on failure
 */
void *vm_map_ram(struct page **pages, unsigned int count, int node)
{
	unsigned long size = (unsigned long)count << PAGE_SHIFT;
	unsigned long addr;
	void *mem;

	if (likely(count <= VMAP_MAX_ALLOC)) {
		mem = vb_alloc(size, GFP_KERNEL);
		if (IS_ERR(mem))
			return NULL;
		addr = (unsigned long)mem;
	} else {
		struct vmap_area *va;
		va = alloc_vmap_area(size, PAGE_SIZE,
				VMALLOC_START, VMALLOC_END,
				node, GFP_KERNEL, VMAP_RAM);
		if (IS_ERR(va))
			return NULL;

		addr = va->va_start;
		mem = (void *)addr;
	}

	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
				pages, PAGE_SHIFT) < 0) {
		vm_unmap_ram(mem, count);
		return NULL;
	}

	/*
	 * Mark the pages as accessible, now that they are mapped.
	 * With hardware tag-based KASAN, marking is skipped for
	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
	 */
	mem = kasan_unpoison_vmalloc(mem, size, KASAN_VMALLOC_PROT_NORMAL);

	return mem;
}
EXPORT_SYMBOL(vm_map_ram);

static struct vm_struct *vmlist __initdata;

static inline unsigned int vm_area_page_order(struct vm_struct *vm)
{
#ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC
	return vm->page_order;
#else
	return 0;
#endif
}

static inline void set_vm_area_page_order(struct vm_struct *vm, unsigned int order)
{
#ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC
	vm->page_order = order;
#else
	BUG_ON(order != 0);
#endif
}

/**
 * vm_area_add_early - add vmap area early during boot
 * @vm: vm_struct to add
 *
 * This function is used to add fixed kernel vm area to vmlist before
 * vmalloc_init() is called.  @vm->addr, @vm->size, and @vm->flags
 * should contain proper values and the other fields should be zero.
 *
 * DO NOT USE THIS FUNCTION UNLESS YOU KNOW WHAT YOU'RE DOING.
 */
void __init vm_area_add_early(struct vm_struct *vm)
{
	struct vm_struct *tmp, **p;

	BUG_ON(vmap_initialized);
	for (p = &vmlist; (tmp = *p) != NULL; p = &tmp->next) {
		if (tmp->addr >= vm->addr) {
			BUG_ON(tmp->addr < vm->addr + vm->size);
			break;
		} else
			BUG_ON(tmp->addr + tmp->size > vm->addr);
	}
	vm->next = *p;
	*p = vm;
}

/**
 * vm_area_register_early - register vmap area early during boot
 * @vm: vm_struct to register
 * @align: requested alignment
 *
 * This function is used to register kernel vm area before
 * vmalloc_init() is called.  @vm->size and @vm->flags should contain
 * proper values on entry and other fields should be zero.  On return,
 * vm->addr contains the allocated address.
 *
 * DO NOT USE THIS FUNCTION UNLESS YOU KNOW WHAT YOU'RE DOING.
 */
void __init vm_area_register_early(struct vm_struct *vm, size_t align)
{
	unsigned long addr = ALIGN(VMALLOC_START, align);
	struct vm_struct *cur, **p;

	BUG_ON(vmap_initialized);

	for (p = &vmlist; (cur = *p) != NULL; p = &cur->next) {
		if ((unsigned long)cur->addr - addr >= vm->size)
			break;
		addr = ALIGN((unsigned long)cur->addr + cur->size, align);
	}

	BUG_ON(addr > VMALLOC_END - vm->size);
	vm->addr = (void *)addr;
	vm->next = *p;
	*p = vm;
	kasan_populate_early_vm_area_shadow(vm->addr, vm->size);
}

static void vmap_init_free_space(void)
{
	unsigned long vmap_start = 1;
	const unsigned long vmap_end = ULONG_MAX;
	struct vmap_area *busy, *free;

	/*
	 *     B     F     B     B     B     F
	 * -|-----|.....|-----|-----|-----|.....|-
	 *  |           The KVA space           |
	 *  |<--------------------------------->|
	 */
	list_for_each_entry(busy, &vmap_area_list, list) {
		if (busy->va_start - vmap_start > 0) {
			free = kmem_cache_zalloc(vmap_area_cachep, GFP_NOWAIT);
			if (!WARN_ON_ONCE(!free)) {
				free->va_start = vmap_start;
				free->va_end = busy->va_start;

				insert_vmap_area_augment(free, NULL,
					&free_vmap_area_root,
						&free_vmap_area_list);
			}
		}

		vmap_start = busy->va_end;
	}

	if (vmap_end - vmap_start > 0) {
		free = kmem_cache_zalloc(vmap_area_cachep, GFP_NOWAIT);
		if (!WARN_ON_ONCE(!free)) {
			free->va_start = vmap_start;
			free->va_end = vmap_end;

			insert_vmap_area_augment(free, NULL,
				&free_vmap_area_root,
					&free_vmap_area_list);
		}
	}
}

/**
 * 初始化vmalloc的虚拟内存区域
 *
 * 该函数在分配vmalloc虚拟内存区域时被调用，用于设置虚拟内存区域的相关参数。
 *
 * @param vm 指向vm_struct结构的指针，用于描述虚拟内存区域
 * @param va 指向vmap_area结构的指针，包含虚拟地址范围
 * @param flags 虚拟内存区域的标志，控制区域的特性和访问权限
 * @param caller 调用者信息，用于跟踪和调试
 */
static inline void setup_vmalloc_vm_locked(struct vm_struct *vm,
	struct vmap_area *va, unsigned long flags, const void *caller)
{
	// 设置虚拟内存区域的标志
	vm->flags = flags;
	// 设置虚拟内存区域的起始地址
	vm->addr = (void *)va->va_start;
	// 计算并设置虚拟内存区域的大小
	vm->size = va->va_end - va->va_start;
	// 记录调用者信息
	vm->caller = caller;
	// 将vm_struct指针关联到vmap_area结构中
	va->vm = vm;
}

static void setup_vmalloc_vm(struct vm_struct *vm, struct vmap_area *va,
			      unsigned long flags, const void *caller)
{
	spin_lock(&vmap_area_lock);
	setup_vmalloc_vm_locked(vm, va, flags, caller);
	spin_unlock(&vmap_area_lock);
}

static void clear_vm_uninitialized_flag(struct vm_struct *vm)
{
	/*
	 * Before removing VM_UNINITIALIZED,
	 * we should make sure that vm has proper values.
	 * Pair with smp_rmb() in show_numa_info().
	 */
	smp_wmb();
	vm->flags &= ~VM_UNINITIALIZED;
}

/**
 * __get_vm_area_node - 分配和初始化一个新的 vm_struct 实例
 * @size: 请求的虚拟内存区域的大小
 * @align: 对齐要求
 * @shift: 对数移位值，用于计算对齐
 * @flags: 内存区域的标志，如VM_IOREMAP、VM_ALLOC等
 * @start: 内存区域的起始地址
 * @end: 内存区域的结束地址
 * @node: NUMA节点
 * @gfp_mask: 内存分配标志
 * @caller: 调用者地址，用于调试
 *
 * 该函数用于分配一个新的 vm_struct 实例，并根据给定的参数初始化它。
 * 它确保分配的虚拟内存区域满足对齐要求，并根据标志设置访问权限。
 * 如果分配失败或参数不合法，函数返回NULL。
 */
static struct vm_struct *__get_vm_area_node(unsigned long size,
		unsigned long align, unsigned long shift, unsigned long flags,
		unsigned long start, unsigned long end, int node,
		gfp_t gfp_mask, const void *caller)
{
	struct vmap_area *va;
	struct vm_struct *area;
	unsigned long requested_size = size;

	/* 确保不在中断上下文中 */
	// 在内核开发中，__vmalloc 函数用于分配虚拟内存。如果在原子上下文中使用 __vmalloc 并传递 GFP_ATOMIC 标志（表示内存分配不能引起阻塞），那么调用链会导致 __get_vm_area_node 函数使用 GFP_KERNEL 标志来为 vm_struct 分配内存。

	// GFP_KERNEL 是一种分配标志，表示可以进行阻塞式内存分配。而在原子上下文中（即不能被中断或调度的代码执行路径），这种阻塞行为是被禁止的。因此，__get_vm_area_node 使用 GFP_KERNEL 标志时，会触发 "sleeping from invalid context" 警告，即尝试在不允许阻塞的上下文中进行可能阻塞的操作。

	// 解决方案：
	// 这个补丁的解决方法是将 __vmalloc 函数传递的内存分配标志（如 GFP_ATOMIC）继续传递到 __get_vm_area_node 函数中，使得 __get_vm_area_node 在原子上下文中也使用 GFP_ATOMIC 进行分配，从而避免触发阻塞行为，解决了 "sleeping from invalid context" 的警告。
	BUG_ON(in_interrupt());

	/* 根据移位值对请求的大小进行对齐 */
	// 背景：
	// KASAN 是一个用于检测内存越界访问（OOB, Out-Of-Bounds）和内存使用后释放错误的内核工具。它通过影子内存（shadow memory）跟踪每个字节的内存使用情况，并标记哪些内存是可以访问的。

	// vmalloc 函数用于分配虚拟内存，可能在某些情况下需要分配大页（hugepage）以优化性能。

	// 问题描述：
	// 在提交 121e6f3258fe 中，__vmalloc_node_range 函数的实现发生了变化。这个变化导致 __get_vm_area_node 函数不再使用 vmalloc 分配的真实大小，而是使用一个向上取整的大小。

	// 这个向上取整的大小在调用 kasan_unpoison_vmalloc() 函数时会出现问题。具体来说，KASAN 期望只标记实际分配的内存为可访问的，但由于尺寸被向上取整，导致 KASAN 标记了比实际分配内存更多的内存为可访问的。这会导致无法检测到 vmalloc 的越界访问错误，并导致 KASAN 的单元测试失败。

	// 解决方案：
	// 真实大小传递：为了修复这个问题，补丁将真实的 vmalloc 分配大小和期望的内存对齐方式传递给 __get_vm_area_node 函数。这使得 KASAN 可以准确地解除影子内存中的毒化状态（unpoison），仅允许访问实际分配的内存。

	// 其他调用点调整：补丁还调整了其他调用 __get_vm_area_node 的地方，确保传入 PAGE_SHIFT 作为对齐值，以保持一致性。
	size = ALIGN(size, 1ul << shift);
	if (unlikely(!size))
		return NULL;

	/* 对IO重映射进行特殊处理 */
	if (flags & VM_IOREMAP)
		align = 1ul << clamp_t(int, get_count_order_long(size),
				       PAGE_SHIFT, IOREMAP_MAX_ORDER);

	/* 分配vm_struct实例 */
	area = kzalloc_node(sizeof(*area), gfp_mask & GFP_RECLAIM_MASK, node);
	if (unlikely(!area))
		return NULL;

	/* 默认在分配区域后添加一个保护页 */
	if (!(flags & VM_NO_GUARD))
		size += PAGE_SIZE;

	/* 分配vmap_area结构并初始化 */
	va = alloc_vmap_area(size, align, start, end, node, gfp_mask, 0);
	if (IS_ERR(va)) {
		kfree(area);
		return NULL;
	}

	/* 设置vm_struct实例的内部结构 */
	setup_vmalloc_vm(area, va, flags, caller);

	/* 对非VM_ALLOC映射的页面标记为可访问 */
	/*
	 * Mark pages for non-VM_ALLOC mappings as accessible. Do it now as a
	 * best-effort approach, as they can be mapped outside of vmalloc code.
	 * For VM_ALLOC mappings, the pages are marked as accessible after
	 * getting mapped in __vmalloc_node_range().
	 * With hardware tag-based KASAN, marking is skipped for
	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
	 */
	if (!(flags & VM_ALLOC))
		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size,
						    KASAN_VMALLOC_PROT_NORMAL);

	return area;
}

struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
				       unsigned long start, unsigned long end,
				       const void *caller)
{
	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags, start, end,
				  NUMA_NO_NODE, GFP_KERNEL, caller);
}

/**
 * get_vm_area - reserve a contiguous kernel virtual area
 * @size:	 size of the area
 * @flags:	 %VM_IOREMAP for I/O mappings or VM_ALLOC
 *
 * Search an area of @size in the kernel virtual mapping area,
 * and reserved it for out purposes.  Returns the area descriptor
 * on success or %NULL on failure.
 *
 * Return: the area descriptor on success or %NULL on failure.
 */
struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
				  VMALLOC_START, VMALLOC_END,
				  NUMA_NO_NODE, GFP_KERNEL,
				  __builtin_return_address(0));
}

struct vm_struct *get_vm_area_caller(unsigned long size, unsigned long flags,
				const void *caller)
{
	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
				  VMALLOC_START, VMALLOC_END,
				  NUMA_NO_NODE, GFP_KERNEL, caller);
}

/**
 * find_vm_area - find a continuous kernel virtual area
 * @addr:	  base address
 *
 * Search for the kernel VM area starting at @addr, and return it.
 * It is up to the caller to do all required locking to keep the returned
 * pointer valid.
 *
 * Return: the area descriptor on success or %NULL on failure.
 */
struct vm_struct *find_vm_area(const void *addr)
{
	struct vmap_area *va;

	va = find_vmap_area((unsigned long)addr);
	if (!va)
		return NULL;

	return va->vm;
}

/**
 * remove_vm_area - find and remove a continuous kernel virtual area
 * @addr:	    base address
 *
 * Search for the kernel VM area starting at @addr, and remove it.
 * This function returns the found VM area, but using it is NOT safe
 * on SMP machines, except for its size or flags.
 *
 * Return: the area descriptor on success or %NULL on failure.
 */
struct vm_struct *remove_vm_area(const void *addr)
{
	struct vmap_area *va;
	struct vm_struct *vm;

	might_sleep();

	if (WARN(!PAGE_ALIGNED(addr), "Trying to vfree() bad address (%p)\n",
			addr))
		return NULL;

	va = find_unlink_vmap_area((unsigned long)addr);
	if (!va || !va->vm)
		return NULL;
	vm = va->vm;

	debug_check_no_locks_freed(vm->addr, get_vm_area_size(vm));
	debug_check_no_obj_freed(vm->addr, get_vm_area_size(vm));
	kasan_free_module_shadow(vm);
	kasan_poison_vmalloc(vm->addr, get_vm_area_size(vm));

	free_unmap_vmap_area(va);
	return vm;
}

static inline void set_area_direct_map(const struct vm_struct *area,
				       int (*set_direct_map)(struct page *page))
{
	int i;

	/* HUGE_VMALLOC passes small pages to set_direct_map */
	for (i = 0; i < area->nr_pages; i++)
		if (page_address(area->pages[i]))
			set_direct_map(area->pages[i]);
}

/*
 * Flush the vm mapping and reset the direct map.
 */
static void vm_reset_perms(struct vm_struct *area)
{
	unsigned long start = ULONG_MAX, end = 0;
	unsigned int page_order = vm_area_page_order(area);
	int flush_dmap = 0;
	int i;

	/*
	 * Find the start and end range of the direct mappings to make sure that
	 * the vm_unmap_aliases() flush includes the direct map.
	 */
	for (i = 0; i < area->nr_pages; i += 1U << page_order) {
		unsigned long addr = (unsigned long)page_address(area->pages[i]);

		if (addr) {
			unsigned long page_size;

			page_size = PAGE_SIZE << page_order;
			start = min(addr, start);
			end = max(addr + page_size, end);
			flush_dmap = 1;
		}
	}

	/*
	 * Set direct map to something invalid so that it won't be cached if
	 * there are any accesses after the TLB flush, then flush the TLB and
	 * reset the direct map permissions to the default.
	 */
	set_area_direct_map(area, set_direct_map_invalid_noflush);
	_vm_unmap_aliases(start, end, flush_dmap);
	set_area_direct_map(area, set_direct_map_default_noflush);
}

static void delayed_vfree_work(struct work_struct *w)
{
	struct vfree_deferred *p = container_of(w, struct vfree_deferred, wq);
	struct llist_node *t, *llnode;

	llist_for_each_safe(llnode, t, llist_del_all(&p->list))
		vfree(llnode);
}

/**
 * vfree_atomic - release memory allocated by vmalloc()
 * @addr:	  memory base address
 *
 * This one is just like vfree() but can be called in any atomic context
 * except NMIs.
 */
void vfree_atomic(const void *addr)
{
	struct vfree_deferred *p = raw_cpu_ptr(&vfree_deferred);

	BUG_ON(in_nmi());
	kmemleak_free(addr);

	/*
	 * Use raw_cpu_ptr() because this can be called from preemptible
	 * context. Preemption is absolutely fine here, because the llist_add()
	 * implementation is lockless, so it works even if we are adding to
	 * another cpu's list. schedule_work() should be fine with this too.
	 */
	if (addr && llist_add((struct llist_node *)addr, &p->list))
		schedule_work(&p->wq);
}

/**
 * vfree - Release memory allocated by vmalloc()
 * @addr:  Memory base address
 *
 * Free the virtually continuous memory area starting at @addr, as obtained
 * from one of the vmalloc() family of APIs.  This will usually also free the
 * physical memory underlying the virtual allocation, but that memory is
 * reference counted, so it will not be freed until the last user goes away.
 *
 * If @addr is NULL, no operation is performed.
 *
 * Context:
 * May sleep if called *not* from interrupt context.
 * Must not be called in NMI context (strictly speaking, it could be
 * if we have CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG, but making the calling
 * conventions for vfree() arch-dependent would be a really bad idea).
 */
void vfree(const void *addr)
{
	struct vm_struct *vm;
	int i;

	if (unlikely(in_interrupt())) {
		vfree_atomic(addr);
		return;
	}

	BUG_ON(in_nmi());
	kmemleak_free(addr);
	might_sleep();

	if (!addr)
		return;

	vm = remove_vm_area(addr);
	if (unlikely(!vm)) {
		WARN(1, KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
				addr);
		return;
	}

	if (unlikely(vm->flags & VM_FLUSH_RESET_PERMS))
		vm_reset_perms(vm);
	for (i = 0; i < vm->nr_pages; i++) {
		struct page *page = vm->pages[i];

		BUG_ON(!page);
		mod_memcg_page_state(page, MEMCG_VMALLOC, -1);
		/*
		 * High-order allocs for huge vmallocs are split, so
		 * can be freed as an array of order-0 allocations
		 */
		__free_page(page);
		cond_resched();
	}
	atomic_long_sub(vm->nr_pages, &nr_vmalloc_pages);
	kvfree(vm->pages);
	kfree(vm);
}
EXPORT_SYMBOL(vfree);

/**
 * vunmap - release virtual mapping obtained by vmap()
 * @addr:   memory base address
 *
 * Free the virtually contiguous memory area starting at @addr,
 * which was created from the page array passed to vmap().
 *
 * Must not be called in interrupt context.
 */
void vunmap(const void *addr)
{
	struct vm_struct *vm;

	BUG_ON(in_interrupt());
	might_sleep();

	if (!addr)
		return;
	vm = remove_vm_area(addr);
	if (unlikely(!vm)) {
		WARN(1, KERN_ERR "Trying to vunmap() nonexistent vm area (%p)\n",
				addr);
		return;
	}
	kfree(vm);
}
EXPORT_SYMBOL(vunmap);

/**
 * vmap - map an array of pages into virtually contiguous space
 * @pages: array of page pointers
 * @count: number of pages to map
 * @flags: vm_area->flags
 * @prot: page protection for the mapping
 *
 * Maps @count pages from @pages into contiguous kernel virtual space.
 * If @flags contains %VM_MAP_PUT_PAGES the ownership of the pages array itself
 * (which must be kmalloc or vmalloc memory) and one reference per pages in it
 * are transferred from the caller to vmap(), and will be freed / dropped when
 * vfree() is called on the return value.
 *
 * Return: the address of the area or %NULL on failure
 */
void *vmap(struct page **pages, unsigned int count,
	   unsigned long flags, pgprot_t prot)
{
	struct vm_struct *area;
	unsigned long addr;
	unsigned long size;		/* In bytes */

	might_sleep();

	if (WARN_ON_ONCE(flags & VM_FLUSH_RESET_PERMS))
		return NULL;

	/*
	 * Your top guard is someone else's bottom guard. Not having a top
	 * guard compromises someone else's mappings too.
	 */
	if (WARN_ON_ONCE(flags & VM_NO_GUARD))
		flags &= ~VM_NO_GUARD;

	if (count > totalram_pages())
		return NULL;

	size = (unsigned long)count << PAGE_SHIFT;
	area = get_vm_area_caller(size, flags, __builtin_return_address(0));
	if (!area)
		return NULL;

	addr = (unsigned long)area->addr;
	if (vmap_pages_range(addr, addr + size, pgprot_nx(prot),
				pages, PAGE_SHIFT) < 0) {
		vunmap(area->addr);
		return NULL;
	}

	if (flags & VM_MAP_PUT_PAGES) {
		area->pages = pages;
		area->nr_pages = count;
	}
	return area->addr;
}
EXPORT_SYMBOL(vmap);

#ifdef CONFIG_VMAP_PFN
struct vmap_pfn_data {
	unsigned long	*pfns;
	pgprot_t	prot;
	unsigned int	idx;
};

static int vmap_pfn_apply(pte_t *pte, unsigned long addr, void *private)
{
	struct vmap_pfn_data *data = private;
	unsigned long pfn = data->pfns[data->idx];
	pte_t ptent;

	if (WARN_ON_ONCE(pfn_valid(pfn)))
		return -EINVAL;

	ptent = pte_mkspecial(pfn_pte(pfn, data->prot));
	set_pte_at(&init_mm, addr, pte, ptent);

	data->idx++;
	return 0;
}

/**
 * vmap_pfn - map an array of PFNs into virtually contiguous space
 * @pfns: array of PFNs
 * @count: number of pages to map
 * @prot: page protection for the mapping
 *
 * Maps @count PFNs from @pfns into contiguous kernel virtual space and returns
 * the start address of the mapping.
 */
void *vmap_pfn(unsigned long *pfns, unsigned int count, pgprot_t prot)
{
	struct vmap_pfn_data data = { .pfns = pfns, .prot = pgprot_nx(prot) };
	struct vm_struct *area;

	area = get_vm_area_caller(count * PAGE_SIZE, VM_IOREMAP,
			__builtin_return_address(0));
	if (!area)
		return NULL;
	if (apply_to_page_range(&init_mm, (unsigned long)area->addr,
			count * PAGE_SIZE, vmap_pfn_apply, &data)) {
		free_vm_area(area);
		return NULL;
	}
	return area->addr;
}
EXPORT_SYMBOL_GPL(vmap_pfn);
#endif /* CONFIG_VMAP_PFN */

static inline unsigned int
vm_area_alloc_pages(gfp_t gfp, int nid,
		unsigned int order, unsigned int nr_pages, struct page **pages)
{
	unsigned int nr_allocated = 0;
	gfp_t alloc_gfp = gfp;
	bool nofail = false;
	struct page *page;
	int i;

	/*
	 * 对于order-0页面，我们使用批量分配器进行分配，如果由于失败，
	 * 页面数组部分或完全未被填充，则回退到更宽容的单页面分配器。
	 */
	if (!order) {
		/* 批量分配器官方不支持nofail要求 */
		gfp_t bulk_gfp = gfp & ~__GFP_NOFAIL;

		while (nr_allocated < nr_pages) {
			unsigned int nr, nr_pages_request;

			/*
			 * 每次请求的最大允许页面数为100页，以防止在批量分配器中
			 * 出现长时间抢占关闭的情况。因此请求范围为[1:100]。
			 */
			nr_pages_request = min(100U, nr_pages - nr_allocated);

			/* 内存分配应考虑内存策略，当nid为NUMA_NO_NODE时不能错误地使用最近节点，
			 * 否则可能会只在一个节点上分配内存，而内存策略可能希望交错分配。
			 */
			if (IS_ENABLED(CONFIG_NUMA) && nid == NUMA_NO_NODE)
				nr = alloc_pages_bulk_array_mempolicy(bulk_gfp,
							nr_pages_request,
							pages + nr_allocated);

			else
				nr = alloc_pages_bulk_array_node(bulk_gfp, nid,
							nr_pages_request,
							pages + nr_allocated);

			nr_allocated += nr;
			cond_resched();

			/*
			 * 如果没有获得足够的页面或部分获得页面，则回退到单页面分配器。
			 */
			if (nr != nr_pages_request)
				break;
		}
	} else if (gfp & __GFP_NOFAIL) {
		/*
		 * 高阶nofail分配非常昂贵且潜在危险（如过早OOM，破坏性回收和整理等）。
		 */
		alloc_gfp &= ~__GFP_NOFAIL;
		nofail = true;
	}

	/* 处理高阶页面或当“批量”分配失败时的回退路径。 */
	while (nr_allocated < nr_pages) {
		if (fatal_signal_pending(current))
			break;

		if (nid == NUMA_NO_NODE)
			page = alloc_pages(alloc_gfp, order);
		else
			page = alloc_pages_node(nid, alloc_gfp, order);
		if (unlikely(!page)) {
			if (!nofail)
				break;

			/* 回退到零阶分配 */
			alloc_gfp |= __GFP_NOFAIL;
			order = 0;
			continue;
		}

		/*
		 * 高阶分配必须能够被调用者视为独立的小页面（如同小页面vmalloc一样）。
		 * 一些驱动程序在其自己的引用计数上使用vmalloc_to_page()页面，
		 * 有些使用page->mapping, page->lru等。
		 */
		if (order)
			split_page(page, order);

		/*
		 * 尽管我们分配和映射的是页面顺序大小的页面，但跟踪是以PAGE_SIZE页面为单位，
		 * 以保持vm_struct API与物理/映射大小无关。
		 */
		for (i = 0; i < (1U << order); i++)
			pages[nr_allocated + i] = page + i;

		cond_resched();
		nr_allocated += 1U << order;
	}

	return nr_allocated;
}

/*
 * 为虚拟内存区域分配物理页面
 *
 * 此函数为给定的虚拟内存区域 (area) 分配足够的物理页面。
 * 它根据指定的页面转换保护 (prot) 和页面移位量 (page_shift) 来执行分配操作。
 *
 * 参数:
 *   area   - 虚拟内存区域结构指针
 *   gfp_mask   - 分配器标志
 *   prot    - 页面转换保护
 *   page_shift - 页面移位量
 *   node    - 用于分配的节点
 *
 * 返回:
 *   分配的虚拟内存区域的起始地址，如果分配失败则返回 NULL。
 */
static void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
				 pgprot_t prot, unsigned int page_shift,
				 int node)
{
	// 定义本地gfp标志，用于实际的内存分配
	const gfp_t nested_gfp = (gfp_mask & GFP_RECLAIM_MASK) | __GFP_ZERO;
	// 标记是否禁止分配失败
	bool nofail = gfp_mask & __GFP_NOFAIL;
	// 虚拟内存区域的起始地址
	unsigned long addr = (unsigned long)area->addr;
	// 虚拟内存区域的大小
	unsigned long size = get_vm_area_size(area);
	// 用于存储页面数组的大小
	unsigned long array_size;
	// 计算该区域包含的小页面数量
	unsigned int nr_small_pages = size >> PAGE_SHIFT;
	// 用于分配的页面顺序
	unsigned int page_order;
	// 临时变量，用于存储分配结果
	unsigned int flags;
	int ret;

	// 计算页面数组的大小
	array_size = (unsigned long)nr_small_pages * sizeof(struct page *);

	// 如果gfp_mask中没有指定GFP_DMA或GFP_DMA32，则添加__GFP_HIGHMEM标志
	if (!(gfp_mask & (GFP_DMA | GFP_DMA32)))
		gfp_mask |= __GFP_HIGHMEM;

	// 递归分配页面数组
	if (array_size > PAGE_SIZE) {
		area->pages = __vmalloc_node(array_size, 1, nested_gfp, node,
					area->caller);
	} else {
		area->pages = kmalloc_node(array_size, nested_gfp, node);
	}

	// 如果页面数组分配失败，发出警告并释放虚拟内存区域，返回NULL
	if (!area->pages) {
		warn_alloc(gfp_mask, NULL,
			"vmalloc error: size %lu, failed to allocated page array size %lu",
			nr_small_pages * PAGE_SIZE, array_size);
		free_vm_area(area);
		return NULL;
	}

	// 设置虚拟内存区域的页面顺序
	set_vm_area_page_order(area, page_shift - PAGE_SHIFT);
	page_order = vm_area_page_order(area);

	// 分配物理页面
	area->nr_pages = vm_area_alloc_pages(gfp_mask | __GFP_NOWARN,
		node, page_order, nr_small_pages, area->pages);

	// 更新vmalloc页面计数器
	atomic_long_add(area->nr_pages, &nr_vmalloc_pages);
	// 如果设置了__GFP_ACCOUNT标志，则更新memory cgroup页面状态
	if (gfp_mask & __GFP_ACCOUNT) {
		int i;

		for (i = 0; i < area->nr_pages; i++)
			mod_memcg_page_state(area->pages[i], MEMCG_VMALLOC, 1);
	}

	// 如果分配的页面数量不足，发出警告并跳转到失败处理
	if (area->nr_pages != nr_small_pages) {
		if (!fatal_signal_pending(current) && page_order == 0)
			warn_alloc(gfp_mask, NULL,
				"vmalloc error: size %lu, failed to allocate pages",
				area->nr_pages * PAGE_SIZE);
		goto fail;
	}

	// 根据gfp_mask设置内存分配标志
	if ((gfp_mask & (__GFP_FS | __GFP_IO)) == __GFP_IO)
		flags = memalloc_nofs_save();
	else if ((gfp_mask & (__GFP_FS | __GFP_IO)) == 0)
		flags = memalloc_noio_save();

	// 尝试映射页面，如果设置了__GFP_NOFAIL标志且映射失败，则调度器等待
	do {
		ret = vmap_pages_range(addr, addr + size, prot, area->pages,
			page_shift);
		if (nofail && (ret < 0))
			schedule_timeout_uninterruptible(1);
	} while (nofail && (ret < 0));

	// 恢复内存分配标志
	if ((gfp_mask & (__GFP_FS | __GFP_IO)) == __GFP_IO)
		memalloc_nofs_restore(flags);
	else if ((gfp_mask & (__GFP_FS | __GFP_IO)) == 0)
		memalloc_noio_restore(flags);

	// 如果页面映射失败，发出警告并跳转到失败处理
	if (ret < 0) {
		warn_alloc(gfp_mask, NULL,
			"vmalloc error: size %lu, failed to map pages",
			area->nr_pages * PAGE_SIZE);
		goto fail;
	}

	// 分配成功，返回虚拟内存区域的起始地址
	return area->addr;

fail:
	// 分配失败，释放已分配的虚拟内存区域地址并返回NULL
	vfree(area->addr);
	return NULL;
}

/**
 * __vmalloc_node_range - allocate virtually contiguous memory
 * @size:		  allocation size
 * @align:		  desired alignment
 * @start:		  vm area range start
 * @end:		  vm area range end
 * @gfp_mask:		  flags for the page level allocator
 * @prot:		  protection mask for the allocated pages
 * @vm_flags:		  additional vm area flags (e.g. %VM_NO_GUARD)
 * @node:		  node to use for allocation or NUMA_NO_NODE
 * @caller:		  caller's return address
 *
 * Allocate enough pages to cover @size from the page level
 * allocator with @gfp_mask flags. Please note that the full set of gfp
 * flags are not supported. GFP_KERNEL, GFP_NOFS and GFP_NOIO are all
 * supported.
 * Zone modifiers are not supported. From the reclaim modifiers
 * __GFP_DIRECT_RECLAIM is required (aka GFP_NOWAIT is not supported)
 * and only __GFP_NOFAIL is supported (i.e. __GFP_NORETRY and
 * __GFP_RETRY_MAYFAIL are not supported).
 *
 * __GFP_NOWARN can be used to suppress failures messages.
 *
 * Map them into contiguous kernel virtual space, using a pagetable
 * protection of @prot.
 *
 * Return: the address of the area or %NULL on failure
 */
void *__vmalloc_node_range(unsigned long size, unsigned long align,
			unsigned long start, unsigned long end, gfp_t gfp_mask,
			pgprot_t prot, unsigned long vm_flags, int node,
			const void *caller)
{
	struct vm_struct *area;
	void *ret;
	kasan_vmalloc_flags_t kasan_flags = KASAN_VMALLOC_NONE;
	unsigned long real_size = size;
	unsigned long real_align = align;
	unsigned int shift = PAGE_SHIFT;

	if (WARN_ON_ONCE(!size))
		return NULL;

	// 检查请求的vmalloc区域大小是否超过物理内存总页数
	// 如果超过，发出错误警告并返回NULL
	if ((size >> PAGE_SHIFT) > totalram_pages()) {
		warn_alloc(gfp_mask, NULL,
			"vmalloc error: size %lu, exceeds total pages",
			real_size);
		return NULL;
	}

	// 当全局变量vmap_allow_huge被设置，并且vm_flags标志中包含VM_ALLOW_HUGE_VMAP时，尝试使用大页面进行内存映射
	if (vmap_allow_huge && (vm_flags & VM_ALLOW_HUGE_VMAP)) {
		unsigned long size_per_node;

		/*
		* 尝试使用大页面。只在PAGE_KERNEL类型的分配中尝试，
		* 对于其他如模块的分配，由于apply_to_page_range不支持它们，
		* 因此这些分配不期望在他们的分配中使用大页面。
		*/

		// 初始化每个节点的大小
		size_per_node = size;
		// 如果未指定节点，则将总大小按在线节点数均分
		if (node == NUMA_NO_NODE)
			size_per_node /= num_online_nodes();
		// 根据保护类型和每个节点的大小，决定是使用PMD级别还是更低级别的页表
		if (arch_vmap_pmd_supported(prot) && size_per_node >= PMD_SIZE)
			shift = PMD_SHIFT;
		else
			shift = arch_vmap_pte_supported_shift(size_per_node);

		// 根据实际对齐要求和页表偏移量，确定最终的对齐值
		align = max(real_align, 1UL << shift);
		// 根据实际大小和页表偏移量，对大小进行对齐
		size = ALIGN(real_size, 1UL << shift);
	}

// 尝试分配VM区域。如果分配失败且分配标志中设置了__GFP_NOFAIL标志，则会重新尝试分配。
again:
    // 调用__get_vm_area_node来分配VM区域。参数包括区域大小、对齐方式、页表项偏移、VM标志、起始地址、结束地址、节点、分配标志和调用者信息。
	area = __get_vm_area_node(real_size, align, shift, VM_ALLOC |
				  VM_UNINITIALIZED | vm_flags, start, end, node,
				  gfp_mask, caller);
	if (!area) {
		// 检查是否设置了__GFP_NOFAIL标志，如果设置了，则不认为分配失败，而是重新尝试分配。
		bool nofail = gfp_mask & __GFP_NOFAIL;
		// 如果分配失败，打印警告信息。如果设置了__GFP_NOFAIL标志，则会重新尝试分配。
		warn_alloc(gfp_mask, NULL,
			"vmalloc error: size %lu, vm_struct allocation failed%s",
			real_size, (nofail) ? ". Retrying." : "");
		if (nofail) {
			// 如果设置了__GFP_NOFAIL标志，等待一段时间后重新尝试分配。
			schedule_timeout_uninterruptible(1);
			goto again;
		}
		// 如果没有设置__GFP_NOFAIL标志，分配失败，跳转到fail。
		goto fail;
	}

	// 准备__vmalloc_area_node和kasan_unpoison_vmalloc的参数。
	if (pgprot_val(prot) == pgprot_val(PAGE_KERNEL)) {
		// 如果页表项的保护位为PAGE_KERNEL，且KASAN硬件标签功能已启用，则修改保护位以允许标签，并跳过页分配的中毒和置零。
		if (kasan_hw_tags_enabled()) {
			// 修改保护位以允许标签。这必须在映射之前完成。
			/*
			 * Modify protection bits to allow tagging.
			 * This must be done before mapping.
			 */
			prot = arch_vmap_pgprot_tagged(prot);
			// 跳过页分配的中毒和置零。这些操作将由kasan_unpoison_vmalloc完成。

			/*
			 * Skip page_alloc poisoning and zeroing for physical
			 * pages backing VM_ALLOC mapping. Memory is instead
			 * poisoned and zeroed by kasan_unpoison_vmalloc().
			 */
			gfp_mask |= __GFP_SKIP_KASAN | __GFP_SKIP_ZERO;
		}
		// 记录该映射为PAGE_KERNEL。
		kasan_flags |= KASAN_VMALLOC_PROT_NORMAL;
	}

	// 分配物理页面并将它们映射到vmalloc空间中。
	ret = __vmalloc_area_node(area, gfp_mask, prot, shift, node);
	if (!ret)
		goto fail;

	// 现在页面已经被映射，标记它们为可访问。
	// 设置KASAN_VMALLOC_INIT的条件应该与post_alloc_hook()中的条件相补充，
	// 关于__GFP_SKIP_ZERO的检查，以确保在相同的条件下内存被初始化。
	// 基于标签的KASAN模式只对正常的非可执行分配分配标签，详见__kasan_unpoison_vmalloc()。
	/*
	 * Mark the pages as accessible, now that they are mapped.
	 * The condition for setting KASAN_VMALLOC_INIT should complement the
	 * one in post_alloc_hook() with regards to the __GFP_SKIP_ZERO check
	 * to make sure that memory is initialized under the same conditions.
	 * Tag-based KASAN modes only assign tags to normal non-executable
	 * allocations, see __kasan_unpoison_vmalloc().
	 */
	kasan_flags |= KASAN_VMALLOC_VM_ALLOC;
	if (!want_init_on_free() && want_init_on_alloc(gfp_mask) &&
	    (gfp_mask & __GFP_SKIP_ZERO))
		kasan_flags |= KASAN_VMALLOC_INIT;
	// 如果需要，KASAN_VMALLOC_PROT_NORMAL已经设置。
	area->addr = kasan_unpoison_vmalloc(area->addr, real_size, kasan_flags);

	// 在这个函数中，新分配的vm_struct具有VM_UNINITIALIZED标志。
	// 这意味着vm_struct尚未完全初始化。
	// 现在，它已经完全初始化，所以在这里移除这个标志。

	/*
	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
	 * flag. It means that vm_struct is not fully initialized.
	 * Now, it is fully initialized, so remove this flag here.
	 */
	clear_vm_uninitialized_flag(area);

	// 对size进行页对齐。
	size = PAGE_ALIGN(size);
	// 如果vm_flags中没有设置VM_DEFER_KMEMLEAK标志，则报告内存泄漏。
	if (!(vm_flags & VM_DEFER_KMEMLEAK))
		kmemleak_vmalloc(area, size, gfp_mask);

	// 返回分配的地址。
	return area->addr;

fail:
	// 如果shift大于PAGE_SHIFT，则重置shift，对齐和大小，并重新尝试分配。
	if (shift > PAGE_SHIFT) {
		shift = PAGE_SHIFT;
		align = real_align;
		size = real_size;
		goto again;
	}

	// 分配失败，返回NULL。
	return NULL;
}

/**
 * __vmalloc_node - allocate virtually contiguous memory
 * @size:	    allocation size
 * @align:	    desired alignment
 * @gfp_mask:	    flags for the page level allocator
 * @node:	    node to use for allocation or NUMA_NO_NODE
 * @caller:	    caller's return address
 *
 * Allocate enough pages to cover @size from the page level allocator with
 * @gfp_mask flags.  Map them into contiguous kernel virtual space.
 *
 * Reclaim modifiers in @gfp_mask - __GFP_NORETRY, __GFP_RETRY_MAYFAIL
 * and __GFP_NOFAIL are not supported
 *
 * Any use of gfp flags outside of GFP_KERNEL should be consulted
 * with mm people.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
/**
 * __vmalloc_node - 从指定节点分配vmalloc内存
 *
 * 该函数用于从系统内存的vmalloc区域中分配一段内存。这段内存的大小由'size'参数指定，
 * 并且会尝试满足由'align'参数指定的内存对齐要求。'gfp_mask'参数决定了内存分配时的
 * 扰动等级（例如，可以是GFP_KERNEL，表示可以在中断上下文中安全地分配内存）。
 * 'node'参数指定了应该从哪个NUMA节点进行内存分配。'caller'参数通常用于调试目的，
 * 可以记录下调用__vmalloc_node函数的代码位置。
 *
 * 参数:
 * @size: 要分配的内存大小（以字节为单位）
 * @align: 请求的内存对齐大小
 * @gfp_mask: 内存分配的扰动等级掩码
 * @node: 指定的NUMA节点
 * @caller: 调用__vmalloc_node的函数地址
 *
 * 返回:
 * 分配的内存指针。如果分配失败，可能返回NULL指针。
 */
void *__vmalloc_node(unsigned long size, unsigned long align,
			    gfp_t gfp_mask, int node, const void *caller)
{
	// 调用__vmalloc_node_range函数，指定vmalloc内存区域的起始和结束地址
	// VMALLOC_START和VMALLOC_END定义了vmalloc内存区域的范围
	return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
				gfp_mask, PAGE_KERNEL, 0, node, caller);
}
/*
 * This is only for performance analysis of vmalloc and stress purpose.
 * It is required by vmalloc test module, therefore do not use it other
 * than that.
 */
#ifdef CONFIG_TEST_VMALLOC_MODULE
EXPORT_SYMBOL_GPL(__vmalloc_node);
#endif

void *__vmalloc(unsigned long size, gfp_t gfp_mask)
{
	return __vmalloc_node(size, 1, gfp_mask, NUMA_NO_NODE,
				__builtin_return_address(0));
}
EXPORT_SYMBOL(__vmalloc);

/**
 * vmalloc - allocate virtually contiguous memory
 * @size:    allocation size
 *
 * Allocate enough pages to cover @size from the page level
 * allocator and map them into contiguous kernel virtual space.
 *
 * For tight control over page level allocator and protection flags
 * use __vmalloc() instead.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
/**
 * vmalloc - 虚拟内存分配
 *
 * 此函数用于分配一块连续的虚拟内存区域。
 * 主要用于内核级别的内存分配，支持硬件无关的页表和大块连续内存。
 *
 * @size: 要分配的内存块大小（以字节为单位）。
 *
 * 返回: 分配成功时返回指向分配内存块的指针，
 *       分配失败时返回 NULL。
 *
 * 在 ARM64 架构下，虚拟地址到物理地址的转换机制依赖于特定的内核地址映射规则。以下是对 ARM64 架构中虚实地址转换的概述：
 *
 * ### 1. **直接映射区域（Direct-Mapped Region）**
 *
 * 内核空间中的一部分区域是直接映射的，通常称为 `linear mapping` 或 `direct mapping` 区域。
 * 在这个区域内，虚拟地址与物理地址之 * 间有一个固定的偏移量，称为 `PAGE_OFFSET`。
 *
 * - **虚拟地址范围：** 从 `PAGE_OFFSET` 开始的地址范围（例如 `0xffff800000000000` 到 `0xffffffffffffffff`）。
 * - **物理地址范围：** 对应的物理地址范围（例如 `0x00000000` 到 `0xffffffffff`）。
 * - **转换方式：** 直接减去或加上偏移量即可完成虚拟地址与物理地址的转换。
 * 这部分地址可以通过简单的加减法在虚拟地址和物理地址之间转 * 换，因此访问开销较低。
 *
 * ### 2. **高内核地址（High Memory Region）** ARM64是不是不存在这部分地址?
 *
 * 高内核地址区域指的是虚拟地址映射到物理内存高位地址的部分，这些地址不能直接通过简单的加减法进行转换，通常需要通过页表进行映射。
 *
 * - **虚拟地址范围：** 通常是指用户空间与内核空间之间的过渡区域或更高的内存区域。
 * - **转换方式：** 需要通过页表查找才能获得物理地址，不能直接进行虚实地址转换。
 *
 * ### 3. **设备地址（Device Mappings）**
 *
 * 在 ARM64 架构中，设备的内存映射区域通常通过 `ioremap` 函数进行映射。
 * 这些地址与物理地址的关系并不是线性的，无法直接通过加减偏移 * 量进行转换。
 *
 * - **虚拟地址范围：** 设备映射的虚拟地址。
 * - **转换方式：** 需要通过映射函数来进行访问，不能直接转换。
 *
 * ### 4. **模块区域（Module Region）**
 *
 * 内核模块和某些内核动态加载的区域在内存中的位置也是动态映射的，通常不能通过简单的加减法进行虚实地址的转换。
 *
 * - **虚拟地址范围：** 内核模块加载的区域。
 * - **转换方式：** 需要通过页表查找。
 *
 * ### 总结
 *
 * - **可以直接转换的区域：** 线性映射区域（`linear mapping`）。
 * - **不可以直接转换的区域：** 高内核地址、设备映射地址、模块加载区域等。
 *
 * 你可以根据这个概念，结合实际开发中的需求，来确定是否需要虚实地址直接转换，或者是否需要借助页表查找。
 */
void *vmalloc(unsigned long size)
{
	return __vmalloc_node(size, 1, GFP_KERNEL, NUMA_NO_NODE,
				__builtin_return_address(0));
}

EXPORT_SYMBOL(vmalloc);

/**
 * vmalloc_huge - allocate virtually contiguous memory, allow huge pages
 * @size:      allocation size
 * @gfp_mask:  flags for the page level allocator
 *
 * Allocate enough pages to cover @size from the page level
 * allocator and map them into contiguous kernel virtual space.
 * If @size is greater than or equal to PMD_SIZE, allow using
 * huge pages for the memory
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *vmalloc_huge(unsigned long size, gfp_t gfp_mask)
{
	return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
				    gfp_mask, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
				    NUMA_NO_NODE, __builtin_return_address(0));
}
EXPORT_SYMBOL_GPL(vmalloc_huge);

/**
 * vzalloc - allocate virtually contiguous memory with zero fill
 * @size:    allocation size
 *
 * Allocate enough pages to cover @size from the page level
 * allocator and map them into contiguous kernel virtual space.
 * The memory allocated is set to zero.
 *
 * For tight control over page level allocator and protection flags
 * use __vmalloc() instead.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *vzalloc(unsigned long size)
{
	return __vmalloc_node(size, 1, GFP_KERNEL | __GFP_ZERO, NUMA_NO_NODE,
				__builtin_return_address(0));
}
EXPORT_SYMBOL(vzalloc);

/**
 * vmalloc_user - allocate zeroed virtually contiguous memory for userspace
 * @size: allocation size
 *
 * The resulting memory area is zeroed so it can be mapped to userspace
 * without leaking data.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *vmalloc_user(unsigned long size)
{
	return __vmalloc_node_range(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
				    GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL,
				    VM_USERMAP, NUMA_NO_NODE,
				    __builtin_return_address(0));
}
EXPORT_SYMBOL(vmalloc_user);

/**
 * vmalloc_node - allocate memory on a specific node
 * @size:	  allocation size
 * @node:	  numa node
 *
 * Allocate enough pages to cover @size from the page level
 * allocator and map them into contiguous kernel virtual space.
 *
 * For tight control over page level allocator and protection flags
 * use __vmalloc() instead.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *vmalloc_node(unsigned long size, int node)
{
	return __vmalloc_node(size, 1, GFP_KERNEL, node,
			__builtin_return_address(0));
}
EXPORT_SYMBOL(vmalloc_node);

/**
 * vzalloc_node - allocate memory on a specific node with zero fill
 * @size:	allocation size
 * @node:	numa node
 *
 * Allocate enough pages to cover @size from the page level
 * allocator and map them into contiguous kernel virtual space.
 * The memory allocated is set to zero.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *vzalloc_node(unsigned long size, int node)
{
	return __vmalloc_node(size, 1, GFP_KERNEL | __GFP_ZERO, node,
				__builtin_return_address(0));
}
EXPORT_SYMBOL(vzalloc_node);

#if defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA32)
#define GFP_VMALLOC32 (GFP_DMA32 | GFP_KERNEL)
#elif defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA)
#define GFP_VMALLOC32 (GFP_DMA | GFP_KERNEL)
#else
/*
 * 64b systems should always have either DMA or DMA32 zones. For others
 * GFP_DMA32 should do the right thing and use the normal zone.
 */
#define GFP_VMALLOC32 (GFP_DMA32 | GFP_KERNEL)
#endif

/**
 * vmalloc_32 - allocate virtually contiguous memory (32bit addressable)
 * @size:	allocation size
 *
 * Allocate enough 32bit PA addressable pages to cover @size from the
 * page level allocator and map them into contiguous kernel virtual space.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *vmalloc_32(unsigned long size)
{
	return __vmalloc_node(size, 1, GFP_VMALLOC32, NUMA_NO_NODE,
			__builtin_return_address(0));
}
EXPORT_SYMBOL(vmalloc_32);

/**
 * vmalloc_32_user - allocate zeroed virtually contiguous 32bit memory
 * @size:	     allocation size
 *
 * The resulting memory area is 32bit addressable and zeroed so it can be
 * mapped to userspace without leaking data.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *vmalloc_32_user(unsigned long size)
{
	return __vmalloc_node_range(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
				    GFP_VMALLOC32 | __GFP_ZERO, PAGE_KERNEL,
				    VM_USERMAP, NUMA_NO_NODE,
				    __builtin_return_address(0));
}
EXPORT_SYMBOL(vmalloc_32_user);

/*
 * Atomically zero bytes in the iterator.
 *
 * Returns the number of zeroed bytes.
 */
static size_t zero_iter(struct iov_iter *iter, size_t count)
{
	size_t remains = count;

	while (remains > 0) {
		size_t num, copied;

		num = min_t(size_t, remains, PAGE_SIZE);
		copied = copy_page_to_iter_nofault(ZERO_PAGE(0), 0, num, iter);
		remains -= copied;

		if (copied < num)
			break;
	}

	return count - remains;
}

/*
 * small helper routine, copy contents to iter from addr.
 * If the page is not present, fill zero.
 *
 * Returns the number of copied bytes.
 */
static size_t aligned_vread_iter(struct iov_iter *iter,
				 const char *addr, size_t count)
{
	size_t remains = count;
	struct page *page;

	while (remains > 0) {
		unsigned long offset, length;
		size_t copied = 0;

		offset = offset_in_page(addr);
		length = PAGE_SIZE - offset;
		if (length > remains)
			length = remains;
		page = vmalloc_to_page(addr);
		/*
		 * To do safe access to this _mapped_ area, we need lock. But
		 * adding lock here means that we need to add overhead of
		 * vmalloc()/vfree() calls for this _debug_ interface, rarely
		 * used. Instead of that, we'll use an local mapping via
		 * copy_page_to_iter_nofault() and accept a small overhead in
		 * this access function.
		 */
		if (page)
			copied = copy_page_to_iter_nofault(page, offset,
							   length, iter);
		else
			copied = zero_iter(iter, length);

		addr += copied;
		remains -= copied;

		if (copied != length)
			break;
	}

	return count - remains;
}

/*
 * Read from a vm_map_ram region of memory.
 *
 * Returns the number of copied bytes.
 */
static size_t vmap_ram_vread_iter(struct iov_iter *iter, const char *addr,
				  size_t count, unsigned long flags)
{
	char *start;
	struct vmap_block *vb;
	struct xarray *xa;
	unsigned long offset;
	unsigned int rs, re;
	size_t remains, n;

	/*
	 * If it's area created by vm_map_ram() interface directly, but
	 * not further subdividing and delegating management to vmap_block,
	 * handle it here.
	 */
	if (!(flags & VMAP_BLOCK))
		return aligned_vread_iter(iter, addr, count);

	remains = count;

	/*
	 * Area is split into regions and tracked with vmap_block, read out
	 * each region and zero fill the hole between regions.
	 */
	xa = addr_to_vb_xa((unsigned long) addr);
	vb = xa_load(xa, addr_to_vb_idx((unsigned long)addr));
	if (!vb)
		goto finished_zero;

	spin_lock(&vb->lock);
	if (bitmap_empty(vb->used_map, VMAP_BBMAP_BITS)) {
		spin_unlock(&vb->lock);
		goto finished_zero;
	}

	for_each_set_bitrange(rs, re, vb->used_map, VMAP_BBMAP_BITS) {
		size_t copied;

		if (remains == 0)
			goto finished;

		start = vmap_block_vaddr(vb->va->va_start, rs);

		if (addr < start) {
			size_t to_zero = min_t(size_t, start - addr, remains);
			size_t zeroed = zero_iter(iter, to_zero);

			addr += zeroed;
			remains -= zeroed;

			if (remains == 0 || zeroed != to_zero)
				goto finished;
		}

		/*it could start reading from the middle of used region*/
		offset = offset_in_page(addr);
		n = ((re - rs + 1) << PAGE_SHIFT) - offset;
		if (n > remains)
			n = remains;

		copied = aligned_vread_iter(iter, start + offset, n);

		addr += copied;
		remains -= copied;

		if (copied != n)
			goto finished;
	}

	spin_unlock(&vb->lock);

finished_zero:
	/* zero-fill the left dirty or free regions */
	return count - remains + zero_iter(iter, remains);
finished:
	/* We couldn't copy/zero everything */
	spin_unlock(&vb->lock);
	return count - remains;
}

/**
 * vread_iter() - read vmalloc area in a safe way to an iterator.
 * @iter:         the iterator to which data should be written.
 * @addr:         vm address.
 * @count:        number of bytes to be read.
 *
 * This function checks that addr is a valid vmalloc'ed area, and
 * copy data from that area to a given buffer. If the given memory range
 * of [addr...addr+count) includes some valid address, data is copied to
 * proper area of @buf. If there are memory holes, they'll be zero-filled.
 * IOREMAP area is treated as memory hole and no copy is done.
 *
 * If [addr...addr+count) doesn't includes any intersects with alive
 * vm_struct area, returns 0. @buf should be kernel's buffer.
 *
 * Note: In usual ops, vread() is never necessary because the caller
 * should know vmalloc() area is valid and can use memcpy().
 * This is for routines which have to access vmalloc area without
 * any information, as /proc/kcore.
 *
 * Return: number of bytes for which addr and buf should be increased
 * (same number as @count) or %0 if [addr...addr+count) doesn't
 * include any intersection with valid vmalloc area
 */
long vread_iter(struct iov_iter *iter, const char *addr, size_t count)
{
	struct vmap_area *va;
	struct vm_struct *vm;
	char *vaddr;
	size_t n, size, flags, remains;

	addr = kasan_reset_tag(addr);

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	remains = count;

	spin_lock(&vmap_area_lock);
	va = find_vmap_area_exceed_addr((unsigned long)addr);
	if (!va)
		goto finished_zero;

	/* no intersects with alive vmap_area */
	if ((unsigned long)addr + remains <= va->va_start)
		goto finished_zero;

	list_for_each_entry_from(va, &vmap_area_list, list) {
		size_t copied;

		if (remains == 0)
			goto finished;

		vm = va->vm;
		flags = va->flags & VMAP_FLAGS_MASK;
		/*
		 * VMAP_BLOCK indicates a sub-type of vm_map_ram area, need
		 * be set together with VMAP_RAM.
		 */
		WARN_ON(flags == VMAP_BLOCK);

		if (!vm && !flags)
			continue;

		if (vm && (vm->flags & VM_UNINITIALIZED))
			continue;

		/* Pair with smp_wmb() in clear_vm_uninitialized_flag() */
		smp_rmb();

		vaddr = (char *) va->va_start;
		size = vm ? get_vm_area_size(vm) : va_size(va);

		if (addr >= vaddr + size)
			continue;

		if (addr < vaddr) {
			size_t to_zero = min_t(size_t, vaddr - addr, remains);
			size_t zeroed = zero_iter(iter, to_zero);

			addr += zeroed;
			remains -= zeroed;

			if (remains == 0 || zeroed != to_zero)
				goto finished;
		}

		n = vaddr + size - addr;
		if (n > remains)
			n = remains;

		if (flags & VMAP_RAM)
			copied = vmap_ram_vread_iter(iter, addr, n, flags);
		else if (!(vm->flags & VM_IOREMAP))
			copied = aligned_vread_iter(iter, addr, n);
		else /* IOREMAP area is treated as memory hole */
			copied = zero_iter(iter, n);

		addr += copied;
		remains -= copied;

		if (copied != n)
			goto finished;
	}

finished_zero:
	spin_unlock(&vmap_area_lock);
	/* zero-fill memory holes */
	return count - remains + zero_iter(iter, remains);
finished:
	/* Nothing remains, or We couldn't copy/zero everything. */
	spin_unlock(&vmap_area_lock);

	return count - remains;
}

/**
 * remap_vmalloc_range_partial - map vmalloc pages to userspace
 * @vma:		vma to cover
 * @uaddr:		target user address to start at
 * @kaddr:		virtual address of vmalloc kernel memory
 * @pgoff:		offset from @kaddr to start at
 * @size:		size of map area
 *
 * Returns:	0 for success, -Exxx on failure
 *
 * This function checks that @kaddr is a valid vmalloc'ed area,
 * and that it is big enough to cover the range starting at
 * @uaddr in @vma. Will return failure if that criteria isn't
 * met.
 *
 * Similar to remap_pfn_range() (see mm/memory.c)
 */
int remap_vmalloc_range_partial(struct vm_area_struct *vma, unsigned long uaddr,
				void *kaddr, unsigned long pgoff,
				unsigned long size)
{
	struct vm_struct *area;
	unsigned long off;
	unsigned long end_index;

	if (check_shl_overflow(pgoff, PAGE_SHIFT, &off))
		return -EINVAL;

	size = PAGE_ALIGN(size);

	if (!PAGE_ALIGNED(uaddr) || !PAGE_ALIGNED(kaddr))
		return -EINVAL;

	area = find_vm_area(kaddr);
	if (!area)
		return -EINVAL;

	if (!(area->flags & (VM_USERMAP | VM_DMA_COHERENT)))
		return -EINVAL;

	if (check_add_overflow(size, off, &end_index) ||
	    end_index > get_vm_area_size(area))
		return -EINVAL;
	kaddr += off;

	do {
		struct page *page = vmalloc_to_page(kaddr);
		int ret;

		ret = vm_insert_page(vma, uaddr, page);
		if (ret)
			return ret;

		uaddr += PAGE_SIZE;
		kaddr += PAGE_SIZE;
		size -= PAGE_SIZE;
	} while (size > 0);

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

	return 0;
}

/**
 * remap_vmalloc_range - map vmalloc pages to userspace
 * @vma:		vma to cover (map full range of vma)
 * @addr:		vmalloc memory
 * @pgoff:		number of pages into addr before first page to map
 *
 * Returns:	0 for success, -Exxx on failure
 *
 * This function checks that addr is a valid vmalloc'ed area, and
 * that it is big enough to cover the vma. Will return failure if
 * that criteria isn't met.
 *
 * Similar to remap_pfn_range() (see mm/memory.c)
 */
int remap_vmalloc_range(struct vm_area_struct *vma, void *addr,
						unsigned long pgoff)
{
	return remap_vmalloc_range_partial(vma, vma->vm_start,
					   addr, pgoff,
					   vma->vm_end - vma->vm_start);
}
EXPORT_SYMBOL(remap_vmalloc_range);

void free_vm_area(struct vm_struct *area)
{
	struct vm_struct *ret;
	ret = remove_vm_area(area->addr);
	BUG_ON(ret != area);
	kfree(area);
}
EXPORT_SYMBOL_GPL(free_vm_area);

#ifdef CONFIG_SMP
static struct vmap_area *node_to_va(struct rb_node *n)
{
	return rb_entry_safe(n, struct vmap_area, rb_node);
}

/**
 * pvm_find_va_enclose_addr - find the vmap_area @addr belongs to
 * @addr: target address
 *
 * Returns: vmap_area if it is found. If there is no such area
 *   the first highest(reverse order) vmap_area is returned
 *   i.e. va->va_start < addr && va->va_end < addr or NULL
 *   if there are no any areas before @addr.
 */
static struct vmap_area *
pvm_find_va_enclose_addr(unsigned long addr)
{
	struct vmap_area *va, *tmp;
	struct rb_node *n;

	n = free_vmap_area_root.rb_node;
	va = NULL;

	while (n) {
		tmp = rb_entry(n, struct vmap_area, rb_node);
		if (tmp->va_start <= addr) {
			va = tmp;
			if (tmp->va_end >= addr)
				break;

			n = n->rb_right;
		} else {
			n = n->rb_left;
		}
	}

	return va;
}

/**
 * pvm_determine_end_from_reverse - find the highest aligned address
 * of free block below VMALLOC_END
 * @va:
 *   in - the VA we start the search(reverse order);
 *   out - the VA with the highest aligned end address.
 * @align: alignment for required highest address
 *
 * Returns: determined end address within vmap_area
 */
static unsigned long
pvm_determine_end_from_reverse(struct vmap_area **va, unsigned long align)
{
	unsigned long vmalloc_end = VMALLOC_END & ~(align - 1);
	unsigned long addr;

	if (likely(*va)) {
		list_for_each_entry_from_reverse((*va),
				&free_vmap_area_list, list) {
			addr = min((*va)->va_end & ~(align - 1), vmalloc_end);
			if ((*va)->va_start < addr)
				return addr;
		}
	}

	return 0;
}

/**
 * pcpu_get_vm_areas - allocate vmalloc areas for percpu allocator
 * @offsets: array containing offset of each area
 * @sizes: array containing size of each area
 * @nr_vms: the number of areas to allocate
 * @align: alignment, all entries in @offsets and @sizes must be aligned to this
 *
 * Returns: kmalloc'd vm_struct pointer array pointing to allocated
 *	    vm_structs on success, %NULL on failure
 *
 * Percpu allocator wants to use congruent vm areas so that it can
 * maintain the offsets among percpu areas.  This function allocates
 * congruent vmalloc areas for it with GFP_KERNEL.  These areas tend to
 * be scattered pretty far, distance between two areas easily going up
 * to gigabytes.  To avoid interacting with regular vmallocs, these
 * areas are allocated from top.
 *
 * Despite its complicated look, this allocator is rather simple. It
 * does everything top-down and scans free blocks from the end looking
 * for matching base. While scanning, if any of the areas do not fit the
 * base address is pulled down to fit the area. Scanning is repeated till
 * all the areas fit and then all necessary data structures are inserted
 * and the result is returned.
 */
struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
				     const size_t *sizes, int nr_vms,
				     size_t align)
{
	const unsigned long vmalloc_start = ALIGN(VMALLOC_START, align);
	const unsigned long vmalloc_end = VMALLOC_END & ~(align - 1);
	struct vmap_area **vas, *va;
	struct vm_struct **vms;
	int area, area2, last_area, term_area;
	unsigned long base, start, size, end, last_end, orig_start, orig_end;
	bool purged = false;

	/* verify parameters and allocate data structures */
	BUG_ON(offset_in_page(align) || !is_power_of_2(align));
	for (last_area = 0, area = 0; area < nr_vms; area++) {
		start = offsets[area];
		end = start + sizes[area];

		/* is everything aligned properly? */
		BUG_ON(!IS_ALIGNED(offsets[area], align));
		BUG_ON(!IS_ALIGNED(sizes[area], align));

		/* detect the area with the highest address */
		if (start > offsets[last_area])
			last_area = area;

		for (area2 = area + 1; area2 < nr_vms; area2++) {
			unsigned long start2 = offsets[area2];
			unsigned long end2 = start2 + sizes[area2];

			BUG_ON(start2 < end && start < end2);
		}
	}
	last_end = offsets[last_area] + sizes[last_area];

	if (vmalloc_end - vmalloc_start < last_end) {
		WARN_ON(true);
		return NULL;
	}

	vms = kcalloc(nr_vms, sizeof(vms[0]), GFP_KERNEL);
	vas = kcalloc(nr_vms, sizeof(vas[0]), GFP_KERNEL);
	if (!vas || !vms)
		goto err_free2;

	for (area = 0; area < nr_vms; area++) {
		vas[area] = kmem_cache_zalloc(vmap_area_cachep, GFP_KERNEL);
		vms[area] = kzalloc(sizeof(struct vm_struct), GFP_KERNEL);
		if (!vas[area] || !vms[area])
			goto err_free;
	}
retry:
	spin_lock(&free_vmap_area_lock);

	/* start scanning - we scan from the top, begin with the last area */
	area = term_area = last_area;
	start = offsets[area];
	end = start + sizes[area];

	va = pvm_find_va_enclose_addr(vmalloc_end);
	base = pvm_determine_end_from_reverse(&va, align) - end;

	while (true) {
		/*
		 * base might have underflowed, add last_end before
		 * comparing.
		 */
		if (base + last_end < vmalloc_start + last_end)
			goto overflow;

		/*
		 * Fitting base has not been found.
		 */
		if (va == NULL)
			goto overflow;

		/*
		 * If required width exceeds current VA block, move
		 * base downwards and then recheck.
		 */
		if (base + end > va->va_end) {
			base = pvm_determine_end_from_reverse(&va, align) - end;
			term_area = area;
			continue;
		}

		/*
		 * If this VA does not fit, move base downwards and recheck.
		 */
		if (base + start < va->va_start) {
			va = node_to_va(rb_prev(&va->rb_node));
			base = pvm_determine_end_from_reverse(&va, align) - end;
			term_area = area;
			continue;
		}

		/*
		 * This area fits, move on to the previous one.  If
		 * the previous one is the terminal one, we're done.
		 */
		area = (area + nr_vms - 1) % nr_vms;
		if (area == term_area)
			break;

		start = offsets[area];
		end = start + sizes[area];
		va = pvm_find_va_enclose_addr(base + end);
	}

	/* we've found a fitting base, insert all va's */
	for (area = 0; area < nr_vms; area++) {
		int ret;

		start = base + offsets[area];
		size = sizes[area];

		va = pvm_find_va_enclose_addr(start);
		if (WARN_ON_ONCE(va == NULL))
			/* It is a BUG(), but trigger recovery instead. */
			goto recovery;

		ret = adjust_va_to_fit_type(&free_vmap_area_root,
					    &free_vmap_area_list,
					    va, start, size);
		if (WARN_ON_ONCE(unlikely(ret)))
			/* It is a BUG(), but trigger recovery instead. */
			goto recovery;

		/* Allocated area. */
		va = vas[area];
		va->va_start = start;
		va->va_end = start + size;
	}

	spin_unlock(&free_vmap_area_lock);

	/* populate the kasan shadow space */
	for (area = 0; area < nr_vms; area++) {
		if (kasan_populate_vmalloc(vas[area]->va_start, sizes[area]))
			goto err_free_shadow;
	}

	/* insert all vm's */
	spin_lock(&vmap_area_lock);
	for (area = 0; area < nr_vms; area++) {
		insert_vmap_area(vas[area], &vmap_area_root, &vmap_area_list);

		setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
				 pcpu_get_vm_areas);
	}
	spin_unlock(&vmap_area_lock);

	/*
	 * Mark allocated areas as accessible. Do it now as a best-effort
	 * approach, as they can be mapped outside of vmalloc code.
	 * With hardware tag-based KASAN, marking is skipped for
	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
	 */
	for (area = 0; area < nr_vms; area++)
		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);

	kfree(vas);
	return vms;

recovery:
	/*
	 * Remove previously allocated areas. There is no
	 * need in removing these areas from the busy tree,
	 * because they are inserted only on the final step
	 * and when pcpu_get_vm_areas() is success.
	 */
	while (area--) {
		orig_start = vas[area]->va_start;
		orig_end = vas[area]->va_end;
		va = merge_or_add_vmap_area_augment(vas[area], &free_vmap_area_root,
				&free_vmap_area_list);
		if (va)
			kasan_release_vmalloc(orig_start, orig_end,
				va->va_start, va->va_end);
		vas[area] = NULL;
	}

overflow:
	spin_unlock(&free_vmap_area_lock);
	if (!purged) {
		reclaim_and_purge_vmap_areas();
		purged = true;

		/* Before "retry", check if we recover. */
		for (area = 0; area < nr_vms; area++) {
			if (vas[area])
				continue;

			vas[area] = kmem_cache_zalloc(
				vmap_area_cachep, GFP_KERNEL);
			if (!vas[area])
				goto err_free;
		}

		goto retry;
	}

err_free:
	for (area = 0; area < nr_vms; area++) {
		if (vas[area])
			kmem_cache_free(vmap_area_cachep, vas[area]);

		kfree(vms[area]);
	}
err_free2:
	kfree(vas);
	kfree(vms);
	return NULL;

err_free_shadow:
	spin_lock(&free_vmap_area_lock);
	/*
	 * We release all the vmalloc shadows, even the ones for regions that
	 * hadn't been successfully added. This relies on kasan_release_vmalloc
	 * being able to tolerate this case.
	 */
	for (area = 0; area < nr_vms; area++) {
		orig_start = vas[area]->va_start;
		orig_end = vas[area]->va_end;
		va = merge_or_add_vmap_area_augment(vas[area], &free_vmap_area_root,
				&free_vmap_area_list);
		if (va)
			kasan_release_vmalloc(orig_start, orig_end,
				va->va_start, va->va_end);
		vas[area] = NULL;
		kfree(vms[area]);
	}
	spin_unlock(&free_vmap_area_lock);
	kfree(vas);
	kfree(vms);
	return NULL;
}

/**
 * pcpu_free_vm_areas - free vmalloc areas for percpu allocator
 * @vms: vm_struct pointer array returned by pcpu_get_vm_areas()
 * @nr_vms: the number of allocated areas
 *
 * Free vm_structs and the array allocated by pcpu_get_vm_areas().
 */
void pcpu_free_vm_areas(struct vm_struct **vms, int nr_vms)
{
	int i;

	for (i = 0; i < nr_vms; i++)
		free_vm_area(vms[i]);
	kfree(vms);
}
#endif	/* CONFIG_SMP */

#ifdef CONFIG_PRINTK
bool vmalloc_dump_obj(void *object)
{
	struct vm_struct *vm;
	void *objp = (void *)PAGE_ALIGN((unsigned long)object);

	vm = find_vm_area(objp);
	if (!vm)
		return false;
	pr_cont(" %u-page vmalloc region starting at %#lx allocated at %pS\n",
		vm->nr_pages, (unsigned long)vm->addr, vm->caller);
	return true;
}
#endif

#ifdef CONFIG_PROC_FS
static void *s_start(struct seq_file *m, loff_t *pos)
	__acquires(&vmap_purge_lock)
	__acquires(&vmap_area_lock)
{
	mutex_lock(&vmap_purge_lock);
	spin_lock(&vmap_area_lock);

	return seq_list_start(&vmap_area_list, *pos);
}

static void *s_next(struct seq_file *m, void *p, loff_t *pos)
{
	return seq_list_next(p, &vmap_area_list, pos);
}

static void s_stop(struct seq_file *m, void *p)
	__releases(&vmap_area_lock)
	__releases(&vmap_purge_lock)
{
	spin_unlock(&vmap_area_lock);
	mutex_unlock(&vmap_purge_lock);
}

static void show_numa_info(struct seq_file *m, struct vm_struct *v)
{
	if (IS_ENABLED(CONFIG_NUMA)) {
		unsigned int nr, *counters = m->private;
		unsigned int step = 1U << vm_area_page_order(v);

		if (!counters)
			return;

		if (v->flags & VM_UNINITIALIZED)
			return;
		/* Pair with smp_wmb() in clear_vm_uninitialized_flag() */
		smp_rmb();

		memset(counters, 0, nr_node_ids * sizeof(unsigned int));

		for (nr = 0; nr < v->nr_pages; nr += step)
			counters[page_to_nid(v->pages[nr])] += step;
		for_each_node_state(nr, N_HIGH_MEMORY)
			if (counters[nr])
				seq_printf(m, " N%u=%u", nr, counters[nr]);
	}
}

static void show_purge_info(struct seq_file *m)
{
	struct vmap_area *va;

	spin_lock(&purge_vmap_area_lock);
	list_for_each_entry(va, &purge_vmap_area_list, list) {
		seq_printf(m, "0x%pK-0x%pK %7ld unpurged vm_area\n",
			(void *)va->va_start, (void *)va->va_end,
			va->va_end - va->va_start);
	}
	spin_unlock(&purge_vmap_area_lock);
}

static int s_show(struct seq_file *m, void *p)
{
	struct vmap_area *va;
	struct vm_struct *v;

	va = list_entry(p, struct vmap_area, list);

	if (!va->vm) {
		if (va->flags & VMAP_RAM)
			seq_printf(m, "0x%pK-0x%pK %7ld vm_map_ram\n",
				(void *)va->va_start, (void *)va->va_end,
				va->va_end - va->va_start);

		goto final;
	}

	v = va->vm;

	seq_printf(m, "0x%pK-0x%pK %7ld",
		v->addr, v->addr + v->size, v->size);

	if (v->caller)
		seq_printf(m, " %pS", v->caller);

	if (v->nr_pages)
		seq_printf(m, " pages=%d", v->nr_pages);

	if (v->phys_addr)
		seq_printf(m, " phys=%pa", &v->phys_addr);

	if (v->flags & VM_IOREMAP)
		seq_puts(m, " ioremap");

	if (v->flags & VM_ALLOC)
		seq_puts(m, " vmalloc");

	if (v->flags & VM_MAP)
		seq_puts(m, " vmap");

	if (v->flags & VM_USERMAP)
		seq_puts(m, " user");

	if (v->flags & VM_DMA_COHERENT)
		seq_puts(m, " dma-coherent");

	if (is_vmalloc_addr(v->pages))
		seq_puts(m, " vpages");

	show_numa_info(m, v);
	seq_putc(m, '\n');

	/*
	 * As a final step, dump "unpurged" areas.
	 */
final:
	if (list_is_last(&va->list, &vmap_area_list))
		show_purge_info(m);

	return 0;
}

static const struct seq_operations vmalloc_op = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = s_show,
};

static int __init proc_vmalloc_init(void)
{
	if (IS_ENABLED(CONFIG_NUMA))
		proc_create_seq_private("vmallocinfo", 0400, NULL,
				&vmalloc_op,
				nr_node_ids * sizeof(unsigned int), NULL);
	else
		proc_create_seq("vmallocinfo", 0400, NULL, &vmalloc_op);
	return 0;
}
module_init(proc_vmalloc_init);

#endif

void __init vmalloc_init(void)
{
	struct vmap_area *va;
	struct vm_struct *tmp;
	int i;

	/*
	 * Create the cache for vmap_area objects.
	 */
	vmap_area_cachep = KMEM_CACHE(vmap_area, SLAB_PANIC);

	for_each_possible_cpu(i) {
		struct vmap_block_queue *vbq;
		struct vfree_deferred *p;

		vbq = &per_cpu(vmap_block_queue, i);
		spin_lock_init(&vbq->lock);
		INIT_LIST_HEAD(&vbq->free);
		p = &per_cpu(vfree_deferred, i);
		init_llist_head(&p->list);
		INIT_WORK(&p->wq, delayed_vfree_work);
		xa_init(&vbq->vmap_blocks);
	}

	/* Import existing vmlist entries. */
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		va = kmem_cache_zalloc(vmap_area_cachep, GFP_NOWAIT);
		if (WARN_ON_ONCE(!va))
			continue;

		va->va_start = (unsigned long)tmp->addr;
		va->va_end = va->va_start + tmp->size;
		va->vm = tmp;
		insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
	}

	/*
	 * Now we can initialize a free vmap space.
	 */
	vmap_init_free_space();
	vmap_initialized = true;
}
