// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fixmap manipulation code
 */

#include <linux/bug.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/libfdt.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/sizes.h>

#include <asm/fixmap.h>
#include <asm/kernel-pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

#define NR_BM_PTE_TABLES \
	SPAN_NR_ENTRIES(FIXADDR_TOT_START, FIXADDR_TOP, PMD_SHIFT)
#define NR_BM_PMD_TABLES \
	SPAN_NR_ENTRIES(FIXADDR_TOT_START, FIXADDR_TOP, PUD_SHIFT)

static_assert(NR_BM_PMD_TABLES == 1);

#define __BM_TABLE_IDX(addr, shift) \
	(((addr) >> (shift)) - (FIXADDR_TOT_START >> (shift)))

#define BM_PTE_TABLE_IDX(addr)	__BM_TABLE_IDX(addr, PMD_SHIFT)

static pte_t bm_pte[NR_BM_PTE_TABLES][PTRS_PER_PTE] __page_aligned_bss;
static pmd_t bm_pmd[PTRS_PER_PMD] __page_aligned_bss __maybe_unused;
static pud_t bm_pud[PTRS_PER_PUD] __page_aligned_bss __maybe_unused;

static inline pte_t *fixmap_pte(unsigned long addr)
{
	return &bm_pte[BM_PTE_TABLE_IDX(addr)][pte_index(addr)];
}

/**
 * early_fixmap_init_pte - 在早期启动阶段初始化PTE（页表项）的函数
 *
 * 本函数旨在处理在系统早期启动阶段页表的相关初始化。具体来说，
 * 当给定的页目录项（pmd）为空（即没有关联的页表）时，该函数会根据
 * 物理地址生成一个新的页表项，并将其关联到指定的页目录项上。
 *
 * @pmdp: 指向页目录项（pmd）的指针，该目录项需要被初始化。
 * @addr: 物理地址，用于计算对应的页表项基地址。
 */
static void __init early_fixmap_init_pte(pmd_t *pmdp, unsigned long addr)
{
	// 读取页目录项的当前值，确保原子性
	pmd_t pmd = READ_ONCE(*pmdp);
	pte_t *ptep;

	// 如果页目录项没有关联的页表
	if (pmd_none(pmd)) {
		// 获取对应物理地址的预定义页表项
		ptep = bm_pte[BM_PTE_TABLE_IDX(addr)];
		// 创建一个新的页目录项，将其关联到获取的页表项物理地址
		__pmd_populate(pmdp, __pa_symbol(ptep), PMD_TYPE_TABLE);
	}
}

/**
 * early_fixmap_init_pmd - 初始化PMD级别的页表项
 * @pudp: 指向页目录项的指针
 * @addr: 要初始化的地址起始位置
 * @end: 初始化的结束地址
 *
 * 该函数负责在早期引导过程中初始化PMD（页中间目录）级别的页表项。
 * 它首先检查给定页目录项（PUD）是否为空，如果为空，则用物理地址填充。
 * 然后，函数迭代地址范围内的PMD项，并调用early_fixmap_init_pte来初始化
 * 每个PMD项内的页表项。
 */
static void __init early_fixmap_init_pmd(pud_t *pudp, unsigned long addr,
					 unsigned long end)
{
	// 计算下一个地址边界
	unsigned long next;
	// 读取一次页目录项的值，优化并发访问
	pud_t pud = READ_ONCE(*pudp);
	// 指向页中间目录项的指针
	pmd_t *pmdp;

	// 如果页目录项为空，则填充它
	if (pud_none(pud))
		__pud_populate(pudp, __pa_symbol(bm_pmd), PUD_TYPE_TABLE);

	// 计算页中间目录项的起始地址
	pmdp = pmd_offset_kimg(pudp, addr);
	// 遍历地址范围，初始化每个PMD项
	do {
		// 计算下一个地址边界
		next = pmd_addr_end(addr, end);
		// 初始化当前PMD项内的页表项
		early_fixmap_init_pte(pmdp, addr);
	} while (pmdp++, addr = next, addr != end);
}

/**
 * early_fixmap_init_pud函数用于在早期初始化阶段设置页表。
 * 这个函数主要目的是为'fixmap'（固定映射）设置页表项，
 * 它是在系统启动早期，内存管理尚未完全启动时使用的。
 *
 * @param p4dp 指向四级页表（p4d）的指针。
 * @param addr 需要设置映射的地址。
 * @param end 地址的结束值，标识映射的范围。
 *
 * 注：此函数依赖于配置项CONFIG_PGTABLE_LEVELS和CONFIG_ARM64_16K_PAGES。
 */
static void __init early_fixmap_init_pud(p4d_t *p4dp, unsigned long addr,
					 unsigned long end)
{
	/* 读取一次*p4dp，保证原子性 */
	p4d_t p4d = READ_ONCE(*p4dp);
	pud_t *pudp;

	/*
	 * 当页表级别大于3且当前p4d项不是无效项，并且p4d项的物理地址不等于bm_pud的物理地址时，
	 * 检查是否启用了16k页配置。这个条件判断是为了确保在特定的页表配置下正确处理页表项。
	 */
	if (CONFIG_PGTABLE_LEVELS > 3 && !p4d_none(p4d) &&
	    p4d_page_paddr(p4d) != __pa_symbol(bm_pud)) {
		/*
		 * 如果上述条件满足，但没有启用16k页配置，则触发BUG。
		 * 这个条件不应该在没有16k页配置的情况下被满足，
		 * 因此这里用BUG_ON宏来断言这种情况不应该发生。
		 */
		/*
		 * We only end up here if the kernel mapping and the fixmap
		 * share the top level pgd entry, which should only happen on
		 * 16k/4 levels configurations.
		 */
		BUG_ON(!IS_ENABLED(CONFIG_ARM64_16K_PAGES));
	}

	/*
	 * 如果p4d项是无效项，则填充*p4dp，将其设置为指向bm_pud页目录的物理地址，
	 * 表示这是一个有效的页目录项。
	 */
	if (p4d_none(p4d))
		__p4d_populate(p4dp, __pa_symbol(bm_pud), P4D_TYPE_TABLE);

	/*
	 * 计算出当前地址在三级页表（pud）中的偏移地址，并调用early_fixmap_init_pmd函数
	 * 继续初始化下一级页表。
	 */
	pudp = pud_offset_kimg(p4dp, addr);
	early_fixmap_init_pmd(pudp, addr, end);
}

/*
 * The p*d_populate functions call virt_to_phys implicitly so they can't be used
 * directly on kernel symbols (bm_p*d). This function is called too early to use
 * lm_alias so __p*d_populate functions must be used to populate with the
 * physical address from __pa_symbol.
 */
/*
 * 注意：以下函数（p*d_populate）内部会隐式调用virt_to_phys转换，
 * 因此不能直接应用于内核符号（如bm_p*d）。
 * 由于当前函数调用发生得过早，无法使用lm_alias机制，
 * 必须使用__p*d_populate系列函数，以从__pa_symbol获取物理地址并填充。
 */
/**
 * early_fixmap_init - 早期固件初始化
 *
 * 描述:
 * 该函数用于在系统启动早期阶段初始化固件映射。它主要负责将一段特定的
 * 物理地址空间映射到内核虚拟地址空间中，以便内核可以直接访问这些物理
 * 地址上的固件信息。这对于在系统启动时进行硬件初始化和配置非常关键。
 *
 * 参数:
 * 无
 *
 * 返回值:
 * 无
 */
void __init early_fixmap_init(void)
{
	// 定义固件映射起始地址
	unsigned long addr = FIXADDR_TOT_START;
	// 定义固件映射结束地址
	unsigned long end = FIXADDR_TOP;

	// 获取起始地址的页全局目录项
	pgd_t *pgdp = pgd_offset_k(addr);
	// 获取起始地址的页上级目录项
	p4d_t *p4dp = p4d_offset(pgdp, addr);

	// 调用辅助函数进行页目录初始化，完成固件的虚拟地址映射
	early_fixmap_init_pud(p4dp, addr, end);
}

/*
 * Unusually, this is also called in IRQ context (ghes_iounmap_irq) so if we
 * ever need to use IPIs for TLB broadcasting, then we're in trouble here.
 */
void __set_fixmap(enum fixed_addresses idx,
			       phys_addr_t phys, pgprot_t flags)
{
	unsigned long addr = __fix_to_virt(idx);
	pte_t *ptep;

	BUG_ON(idx <= FIX_HOLE || idx >= __end_of_fixed_addresses);

	ptep = fixmap_pte(addr);

	if (pgprot_val(flags)) {
		set_pte(ptep, pfn_pte(phys >> PAGE_SHIFT, flags));
	} else {
		pte_clear(&init_mm, addr, ptep);
		flush_tlb_kernel_range(addr, addr+PAGE_SIZE);
	}
}

void *__init fixmap_remap_fdt(phys_addr_t dt_phys, int *size, pgprot_t prot)
{
	const u64 dt_virt_base = __fix_to_virt(FIX_FDT);
	phys_addr_t dt_phys_base;
	int offset;
	void *dt_virt;

	/*
	 * Check whether the physical FDT address is set and meets the minimum
	 * alignment requirement. Since we are relying on MIN_FDT_ALIGN to be
	 * at least 8 bytes so that we can always access the magic and size
	 * fields of the FDT header after mapping the first chunk, double check
	 * here if that is indeed the case.
	 */
	BUILD_BUG_ON(MIN_FDT_ALIGN < 8);
	if (!dt_phys || dt_phys % MIN_FDT_ALIGN)
		return NULL;

	dt_phys_base = round_down(dt_phys, PAGE_SIZE);
	offset = dt_phys % PAGE_SIZE;
	dt_virt = (void *)dt_virt_base + offset;

	/* map the first chunk so we can read the size from the header */
	create_mapping_noalloc(dt_phys_base, dt_virt_base, PAGE_SIZE, prot);

	if (fdt_magic(dt_virt) != FDT_MAGIC)
		return NULL;

	*size = fdt_totalsize(dt_virt);
	if (*size > MAX_FDT_SIZE)
		return NULL;

	if (offset + *size > PAGE_SIZE) {
		create_mapping_noalloc(dt_phys_base, dt_virt_base,
				       offset + *size, prot);
	}

	return dt_virt;
}

/*
 * Copy the fixmap region into a new pgdir.
 */
void __init fixmap_copy(pgd_t *pgdir)
{
	if (!READ_ONCE(pgd_val(*pgd_offset_pgd(pgdir, FIXADDR_TOT_START)))) {
		/*
		 * The fixmap falls in a separate pgd to the kernel, and doesn't
		 * live in the carveout for the swapper_pg_dir. We can simply
		 * re-use the existing dir for the fixmap.
		 */
		set_pgd(pgd_offset_pgd(pgdir, FIXADDR_TOT_START),
			READ_ONCE(*pgd_offset_k(FIXADDR_TOT_START)));
	} else if (CONFIG_PGTABLE_LEVELS > 3) {
		pgd_t *bm_pgdp;
		p4d_t *bm_p4dp;
		pud_t *bm_pudp;
		/*
		 * The fixmap shares its top level pgd entry with the kernel
		 * mapping. This can really only occur when we are running
		 * with 16k/4 levels, so we can simply reuse the pud level
		 * entry instead.
		 */
		BUG_ON(!IS_ENABLED(CONFIG_ARM64_16K_PAGES));
		bm_pgdp = pgd_offset_pgd(pgdir, FIXADDR_TOT_START);
		bm_p4dp = p4d_offset(bm_pgdp, FIXADDR_TOT_START);
		bm_pudp = pud_set_fixmap_offset(bm_p4dp, FIXADDR_TOT_START);
		pud_populate(&init_mm, bm_pudp, lm_alias(bm_pmd));
		pud_clear_fixmap();
	} else {
		BUG();
	}
}
