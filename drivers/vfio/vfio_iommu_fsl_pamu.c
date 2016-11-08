/*
 * VFIO: IOMMU DMA mapping support for FSL PAMU IOMMU
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) 2013 Freescale Semiconductor, Inc.
 *
 *     Author: Bharat Bhushan <bharat.bhushan@freescale.com>
 *
 * This file is derived from driver/vfio/vfio_iommu_type1.c
 *
 * The Freescale PAMU is an aperture-based IOMMU with the following
 * characteristics.  Each device has an entry in a table in memory
 * describing the iova->phys mapping. The mapping has:
 *  -an overall aperture that is power of 2 sized, and has a start iova that
 *   is naturally aligned
 *  -has 1 or more windows within the aperture
 *     -number of windows must be power of 2, max is 256
 *     -size of each window is determined by aperture size / # of windows
 *     -iova of each window is determined by aperture start iova / # of windows
 *     -the mapped region in each window can be different than
 *      the window size...mapping must power of 2
 *     -physical address of the mapping must be naturally aligned
 *      with the mapping size
 */

#include <linux/compat.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pci.h>		/* pci_bus_type */
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/workqueue.h>
#include <linux/hugetlb.h>
#include <linux/msi.h>
#include <asm/fsl_pamu_stash.h>
#include <asm/fsl_msi.h>
#include <linux/math64.h>

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "Bharat Bhushan <bharat.bhushan@freescale.com>"
#define DRIVER_DESC     "FSL PAMU IOMMU driver for VFIO"

struct vfio_iommu {
	struct iommu_domain	*domain;
	struct mutex		lock;
	dma_addr_t		aperture_start;
	dma_addr_t		aperture_end;
	dma_addr_t		page_size;	/* Maximum mapped Page size */
	int			nsubwindows;	/* Number of subwindows */
	struct list_head	dma_list;
	struct list_head	msi_dma_list;
	struct list_head	group_list;
};

struct vfio_dma {
	struct list_head	next;
	dma_addr_t		iova;		/* Device address */
	unsigned long		vaddr;		/* Process virtual addr */
	long			npage;		/* Number of pages */
	int			prot;		/* IOMMU_READ/WRITE */
};

struct vfio_msi_dma {
	struct list_head	next;
	dma_addr_t		iova;		/* Device address */
	int			bank_id;
	int			prot;		/* IOMMU_READ/WRITE */
};

struct vfio_group {
	struct iommu_group	*iommu_group;
	struct list_head	next;
};

/*
 * This code handles mapping and unmapping of user data buffers
 * into DMA'ble space using the IOMMU
 */

#define NPAGE_TO_SIZE(npage)	((size_t)(npage) << PAGE_SHIFT)

struct vwork {
	struct mm_struct	*mm;
	long			npage;
	struct work_struct	work;
};

/* delayed decrement/increment for locked_vm */
static void vfio_lock_acct_bg(struct work_struct *work)
{
	struct vwork *vwork = container_of(work, struct vwork, work);
	struct mm_struct *mm;

	mm = vwork->mm;
	down_write(&mm->mmap_sem);
	mm->locked_vm += vwork->npage;
	up_write(&mm->mmap_sem);
	mmput(mm);
	kfree(vwork);
}

static void vfio_lock_acct(long npage)
{
	struct vwork *vwork;
	struct mm_struct *mm;

	if (!current->mm)
		return; /* process exited */

	if (down_write_trylock(&current->mm->mmap_sem)) {
		current->mm->locked_vm += npage;
		up_write(&current->mm->mmap_sem);
		return;
	}

	/*
	 * Couldn't get mmap_sem lock, so must setup to update
	 * mm->locked_vm later. If locked_vm were atomic, we
	 * wouldn't need this silliness
	 */
	vwork = kmalloc(sizeof(struct vwork), GFP_KERNEL);
	if (!vwork)
		return;
	mm = get_task_mm(current);
	if (!mm) {
		kfree(vwork);
		return;
	}
	INIT_WORK(&vwork->work, vfio_lock_acct_bg);
	vwork->mm = mm;
	vwork->npage = npage;
	schedule_work(&vwork->work);
}

/*
 * Some mappings aren't backed by a struct page, for example an mmap'd
 * MMIO range for our own or another device.  These use a different
 * pfn conversion and shouldn't be tracked as locked pages.
 */
static bool is_invalid_reserved_pfn(unsigned long pfn)
{
	if (pfn_valid(pfn)) {
		bool reserved;
		struct page *tail = pfn_to_page(pfn);
		struct page *head = compound_head(tail);
		reserved = !!(PageReserved(head));
		if (head != tail) {
			/*
			 * "head" is not a dangling pointer
			 * (compound_head takes care of that)
			 * but the hugepage may have been split
			 * from under us (and we may not hold a
			 * reference count on the head page so it can
			 * be reused before we run PageReferenced), so
			 * we've to check PageTail before returning
			 * what we just read.
			 */
			smp_rmb();
			if (PageTail(tail))
				return reserved;
		}
		return PageReserved(tail);
	}

	return true;
}

static int put_pfn(unsigned long pfn, int prot)
{
	if (!is_invalid_reserved_pfn(pfn)) {
		struct page *page = pfn_to_page(pfn);
		if (prot & IOMMU_WRITE)
			SetPageDirty(page);
		put_page(page);
		return 1;
	}
	return 0;
}

static int vaddr_get_pfn(unsigned long vaddr, int prot, unsigned long *pfn,
			 unsigned int nr_pages)
{
	struct page **pages;
	int ret = -EFAULT;
	int i;

	pages = kzalloc(sizeof(*pages) * nr_pages, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	ret = get_user_pages_fast(vaddr, nr_pages, !!(prot & IOMMU_WRITE), pages);
	if (ret != nr_pages)
		goto error;

	/* All Pages should be contigious */
	for (i = 1; i < nr_pages; i++) {
		if (page_to_pfn(pages[i]) != page_to_pfn(pages[i - 1]) + 1)
			goto error;
	}

	*pfn = page_to_pfn(pages[0]);
	kfree(pages);
	return 0;
error:
	for (i = 0; i < nr_pages; i++)
		put_page(pages[i]);
	kfree(pages);
	return -EFAULT;
}

static int iova_to_win(struct vfio_iommu *iommu, dma_addr_t iova)
{
	return (int) div64_u64(iova - iommu->aperture_start, iommu->page_size);
}

/* Unmap DMA region */
static long __vfio_dma_do_unmap(struct vfio_iommu *iommu, dma_addr_t iova_start,
				long npage, int prot)
{
	int win, win_start, win_end, i;
	long unlocked = 0;
	unsigned long size;
	unsigned int nr_pages;
	dma_addr_t iova = iova_start;

	size = npage << PAGE_SHIFT;
	nr_pages = iommu->page_size / PAGE_SIZE;
	/* Release the pinned pages */
	while (size) {
		unsigned long pfn;

		pfn = iommu_iova_to_phys(iommu->domain, iova) >> PAGE_SHIFT;
		if (pfn) {
			for (i = 0; i < nr_pages; i++, pfn++)
				unlocked += put_pfn(pfn, prot);
		}

		iova += iommu->page_size;
		size -= iommu->page_size;
	}

	/* Disable the subwindows */
	iova = iova_start;
	win_start = iova_to_win(iommu, iova);
	win_end = iova_to_win(iommu, iova + (npage << PAGE_SHIFT) - 1);
	for (win = win_start; win <= win_end ; win++)
		iommu_domain_window_disable(iommu->domain, win);

	return unlocked;
}

static void vfio_dma_unmap(struct vfio_iommu *iommu, dma_addr_t iova,
			   long npage, int prot)
{
	long unlocked;

	unlocked = __vfio_dma_do_unmap(iommu, iova, npage, prot);
	vfio_lock_acct(-unlocked);
}

static int vfio_disable_iommu_domain(struct vfio_iommu *iommu)
{
	int enable = 0;
	return iommu_domain_set_attr(iommu->domain,
				     DOMAIN_ATTR_FSL_PAMU_ENABLE, &enable);
}

static int vfio_enable_iommu_domain(struct vfio_iommu *iommu)
{
	int enable = 1;
	return iommu_domain_set_attr(iommu->domain,
				     DOMAIN_ATTR_FSL_PAMU_ENABLE, &enable);
}

static inline bool ranges_overlap(dma_addr_t start1, size_t size1,
				  dma_addr_t start2, size_t size2)
{
	if (start1 < start2)
		return (start2 - start1 < size1);
	else if (start2 < start1)
		return (start1 - start2 < size2);
	return (size1 > 0 && size2 > 0);
}

static struct vfio_dma *vfio_find_dma(struct vfio_iommu *iommu,
				      dma_addr_t start, size_t size)
{
	struct vfio_dma *dma;

	list_for_each_entry(dma, &iommu->dma_list, next) {
		if (ranges_overlap(dma->iova, NPAGE_TO_SIZE(dma->npage),
				   start, size))
			return dma;
	}
	return NULL;
}

static long vfio_remove_dma_overlap(struct vfio_iommu *iommu, dma_addr_t start,
				    size_t size, struct vfio_dma *dma)
{
	struct vfio_dma *split;
	long npage_lo, npage_hi;

	/* Existing dma region is completely covered, unmap all */
	if (start <= dma->iova &&
	    start + size >= dma->iova + NPAGE_TO_SIZE(dma->npage)) {
		vfio_dma_unmap(iommu, dma->iova, dma->npage, dma->prot);
		list_del(&dma->next);
		npage_lo = dma->npage;
		kfree(dma);
		return npage_lo;
	}

	/* Overlap low address of existing range */
	if (start <= dma->iova) {
		size_t overlap;

		overlap = start + size - dma->iova;
		npage_lo = overlap >> PAGE_SHIFT;

		vfio_dma_unmap(iommu, dma->iova, npage_lo, dma->prot);
		dma->iova += overlap;
		dma->vaddr += overlap;
		dma->npage -= npage_lo;
		return npage_lo;
	}

	/* Overlap high address of existing range */
	if (start + size >= dma->iova + NPAGE_TO_SIZE(dma->npage)) {
		size_t overlap;

		overlap = dma->iova + NPAGE_TO_SIZE(dma->npage) - start;
		npage_hi = overlap >> PAGE_SHIFT;

		vfio_dma_unmap(iommu, start, npage_hi, dma->prot);
		dma->npage -= npage_hi;
		return npage_hi;
	}

	/* Split existing */
	npage_lo = (start - dma->iova) >> PAGE_SHIFT;
	npage_hi = dma->npage - (size >> PAGE_SHIFT) - npage_lo;

	split = kzalloc(sizeof(*split), GFP_KERNEL);
	if (!split)
		return -ENOMEM;

	vfio_dma_unmap(iommu, start, size >> PAGE_SHIFT, dma->prot);

	dma->npage = npage_lo;

	split->npage = npage_hi;
	split->iova = start + size;
	split->vaddr = dma->vaddr + NPAGE_TO_SIZE(npage_lo) + size;
	split->prot = dma->prot;
	list_add(&split->next, &iommu->dma_list);
	return size >> PAGE_SHIFT;
}

/* Map DMA region */
static int __vfio_dma_map(struct vfio_iommu *iommu, dma_addr_t iova,
			  unsigned long vaddr, long npage, int prot)
{
	dma_addr_t start = iova;
	long locked = 0;
	int ret, i;
	unsigned long size;
	unsigned int win, nr_subwindows;
	dma_addr_t iova_map, iova_end;

	/*
	 * XXX We break mappings into pages and use get_user_pages_fast to
	 * pin the pages in memory.  It's been suggested that mlock might
	 * provide a more efficient mechanism, but nothing prevents the
	 * user from munlocking the pages, which could then allow the user
	 * access to random host memory.  We also have no guarantee from the
	 * IOMMU API that the iommu driver can unmap sub-pages of previous
	 * mappings.  This means we might lose an entire range if a single
	 * page within it is unmapped.  Single page mappings are inefficient,
	 * but provide the most flexibility for now.
	 */
	/* total size to be mapped */
	size = npage << PAGE_SHIFT;
	nr_subwindows = div64_u64(size, iommu->page_size);
	iova_map = iova;
	iova_end = iova + size;

	for (i = 0; i < nr_subwindows; i++) {
		unsigned long pfn;
		unsigned long nr_pages;
		dma_addr_t mapsize;

		win = iova_to_win(iommu, iova_map);
		if (iova_map != iommu->aperture_start + iommu->page_size * win) {
			pr_err("%s iova (%llx) not alligned to window size %llx\n",
				__func__, iova, iommu->page_size);
			__vfio_dma_do_unmap(iommu, start, npage, prot);
			return -EINVAL;
		}

		mapsize = min(iova_end - iova_map, iommu->page_size);
		if (mapsize < iommu->page_size) {
			pr_err("%s iova (%llx) not alligned to window size %llx\n",
				__func__, iova, iommu->page_size);
			__vfio_dma_do_unmap(iommu, start, npage, prot);
			return -EINVAL;
		}

		nr_pages = mapsize >> PAGE_SHIFT;
		ret = vaddr_get_pfn(vaddr, prot, &pfn, nr_pages);
		if (ret) {
			pr_err("%s unable to map vaddr = %lx\n",
				__func__, vaddr);
			__vfio_dma_do_unmap(iommu, start, npage, prot);
			return ret;
		}

		if (!is_invalid_reserved_pfn(pfn))
			locked++;


		ret = iommu_domain_window_enable(iommu->domain, win,
						 (phys_addr_t)pfn << PAGE_SHIFT,
						 mapsize, prot);
		if (ret) {
			pr_err("%s unable to iommu_map()\n", __func__);
			/* Back out mappings on error */
			put_pfn(pfn, prot);
			__vfio_dma_do_unmap(iommu, start, npage, prot);
			return ret;
		}

		iova_map += mapsize;
		vaddr += mapsize;
	}
	vfio_enable_iommu_domain(iommu);

	vfio_lock_acct(locked);
	return 0;
}

static int vfio_dma_do_map(struct vfio_iommu *iommu,
			   struct vfio_iommu_type1_dma_map *map)
{
	struct vfio_dma *dma, *pdma = NULL;
	dma_addr_t iova = map->iova;
	unsigned long locked, lock_limit, vaddr = map->vaddr;
	size_t size = map->size;
	int ret = 0, prot = 0;
	long npage;

	/* READ/WRITE from device perspective */
	if (map->flags & VFIO_DMA_MAP_FLAG_WRITE)
		prot |= IOMMU_WRITE;
	if (map->flags & VFIO_DMA_MAP_FLAG_READ)
		prot |= IOMMU_READ;

	if (!prot)
		return -EINVAL; /* No READ/WRITE? */

	/* Don't allow IOVA wrap */
	if (iova + size && iova + size < iova)
		return -EINVAL;

	/* Don't allow virtual address wrap */
	if (vaddr + size && vaddr + size < vaddr)
		return -EINVAL;

	npage = size >> PAGE_SHIFT;
	if (!npage)
		return -EINVAL;

	mutex_lock(&iommu->lock);

	if (vfio_find_dma(iommu, iova, size)) {
		ret = -EBUSY;
		goto out_lock;
	}

	/* account for locked pages */
	locked = current->mm->locked_vm + npage;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if (locked > lock_limit && !capable(CAP_IPC_LOCK)) {
		pr_warn("%s: RLIMIT_MEMLOCK (%ld) exceeded\n",
			__func__, rlimit(RLIMIT_MEMLOCK));
		ret = -ENOMEM;
		goto out_lock;
	}

	ret = __vfio_dma_map(iommu, iova, vaddr, npage, prot);
	if (ret)
		goto out_lock;

	/* Check if we about a region below - nothing below 0 */
	if (iova) {
		dma = vfio_find_dma(iommu, iova - 1, 1);
		if (dma && dma->prot == prot &&
		    dma->vaddr + NPAGE_TO_SIZE(dma->npage) == vaddr) {

			dma->npage += npage;
			iova = dma->iova;
			vaddr = dma->vaddr;
			npage = dma->npage;
			size = NPAGE_TO_SIZE(npage);

			pdma = dma;
		}
	}

	/* Check if we abut a region above - nothing above ~0 + 1 */
	if (iova + size) {
		dma = vfio_find_dma(iommu, iova + size, 1);
		if (dma && dma->prot == prot &&
		    dma->vaddr == vaddr + size) {

			dma->npage += npage;
			dma->iova = iova;
			dma->vaddr = vaddr;

			/*
			 * If merged above and below, remove previously
			 * merged entry.  New entry covers it.
			 */
			if (pdma) {
				list_del(&pdma->next);
				kfree(pdma);
			}
			pdma = dma;
		}
	}

	/* Isolated, new region */
	if (!pdma) {
		dma = kzalloc(sizeof(*dma), GFP_KERNEL);
		if (!dma) {
			ret = -ENOMEM;
			vfio_dma_unmap(iommu, iova, npage, prot);
			goto out_lock;
		}

		dma->npage = npage;
		dma->iova = iova;
		dma->vaddr = vaddr;
		dma->prot = prot;
		list_add(&dma->next, &iommu->dma_list);
	}

out_lock:
	mutex_unlock(&iommu->lock);
	return ret;
}

static int vfio_dma_do_unmap(struct vfio_iommu *iommu,
			     struct vfio_iommu_type1_dma_unmap *unmap)
{
	long ret = 0, npage = unmap->size >> PAGE_SHIFT;
	struct vfio_dma *dma, *tmp;

	mutex_lock(&iommu->lock);

	list_for_each_entry_safe(dma, tmp, &iommu->dma_list, next) {
		if (ranges_overlap(dma->iova, NPAGE_TO_SIZE(dma->npage),
				   unmap->iova, unmap->size)) {
			ret = vfio_remove_dma_overlap(iommu, unmap->iova,
						      unmap->size, dma);
			if (ret > 0)
				npage -= ret;
			if (ret < 0 || npage == 0)
				break;
		}
	}

	/* disable iommu if no mapping */
	if (list_empty(&iommu->dma_list))
		vfio_disable_iommu_domain(iommu);

	mutex_unlock(&iommu->lock);
	return ret > 0 ? 0 : (int)ret;
}

static int vfio_handle_get_attr(struct vfio_iommu *iommu,
			 struct vfio_pamu_attr *pamu_attr)
{
	switch (pamu_attr->attribute) {
	case VFIO_ATTR_GEOMETRY: {
		struct iommu_domain_geometry geom;
		if (iommu_domain_get_attr(iommu->domain,
				      DOMAIN_ATTR_GEOMETRY, &geom)) {
			pr_err("%s Error getting domain geometry\n",
			       __func__);
			return -EFAULT;
		}

		pamu_attr->attr_info.attr.aperture_start = geom.aperture_start;
		pamu_attr->attr_info.attr.aperture_end = geom.aperture_end;
		break;
	}
	case VFIO_ATTR_WINDOWS: {
		u32 count;
		if (iommu_domain_get_attr(iommu->domain,
				      DOMAIN_ATTR_WINDOWS, &count)) {
			pr_err("%s Error getting domain windows\n",
			       __func__);
			return -EFAULT;
		}

		pamu_attr->attr_info.windows = count;
		break;
	}
	case VFIO_ATTR_PAMU_STASH: {
		struct pamu_stash_attribute stash;
		if (iommu_domain_get_attr(iommu->domain,
				      DOMAIN_ATTR_FSL_PAMU_STASH, &stash)) {
			pr_err("%s Error getting domain windows\n",
			       __func__);
			return -EFAULT;
		}

		pamu_attr->attr_info.stash.cpu = stash.cpu;
		pamu_attr->attr_info.stash.cache = stash.cache;
		break;
	}

	default:
		pr_err("%s Error: Invalid attribute (%d)\n",
			 __func__, pamu_attr->attribute);
		return -EINVAL;
	}

	return 0;
}

static int vfio_handle_set_attr(struct vfio_iommu *iommu,
			 struct vfio_pamu_attr *pamu_attr)
{
	switch (pamu_attr->attribute) {
	case VFIO_ATTR_GEOMETRY: {
		struct iommu_domain_geometry geom;

		geom.aperture_start = pamu_attr->attr_info.attr.aperture_start;
		geom.aperture_end = pamu_attr->attr_info.attr.aperture_end;
		iommu->aperture_start = geom.aperture_start;
		iommu->aperture_end = geom.aperture_end;
		geom.force_aperture = 1;
		if (iommu_domain_set_attr(iommu->domain,
					  DOMAIN_ATTR_GEOMETRY, &geom)) {
			pr_err("%s Error setting domain geometry\n", __func__);
			return -EFAULT;
		}

		break;
	}
	case VFIO_ATTR_WINDOWS: {
		u32 count = pamu_attr->attr_info.windows;
		u64 size;
		if (count > 256) {
			pr_err("Number of subwindows requested (%d) is 256\n",
				count);
			return -EINVAL;
		}
		iommu->nsubwindows = pamu_attr->attr_info.windows;
		size = iommu->aperture_end - iommu->aperture_start + 1;
		iommu->page_size = div64_u64(size , count);
		if (iommu_domain_set_attr(iommu->domain,
				      DOMAIN_ATTR_WINDOWS, &count)) {
			pr_err("%s Error getting domain windows\n",
			       __func__);
			return -EFAULT;
		}

		break;
	}
	case VFIO_ATTR_PAMU_STASH: {
		struct pamu_stash_attribute stash;

		stash.cpu = pamu_attr->attr_info.stash.cpu;
		stash.cache = pamu_attr->attr_info.stash.cache;
		if (iommu_domain_set_attr(iommu->domain,
				      DOMAIN_ATTR_FSL_PAMU_STASH, &stash)) {
			pr_err("%s Error getting domain windows\n",
			       __func__);
			return -EFAULT;
		}
		break;
	}

	default:
		pr_err("%s Error: Invalid attribute (%d)\n",
			 __func__, pamu_attr->attribute);
		return -EINVAL;
	}

	return 0;
}

static int vfio_msi_map(struct vfio_iommu *iommu,
			struct vfio_pamu_msi_bank_map *msi_map, int prot)
{
	struct msi_region region;
	int window;
	int ret;

	ret = fsl_msi_get_region(msi_map->msi_bank_index, &region);
	if (ret) {
		pr_err("%s MSI region (%d) not found\n", __func__,
		       msi_map->msi_bank_index);
		return ret;
	}

	window = iova_to_win(iommu, msi_map->iova);
	ret = iommu_domain_window_enable(iommu->domain, window, region.addr,
					 region.size, prot);
	if (ret) {
		pr_err("%s Error: unable to map msi region\n", __func__);
		return ret;
	}

	return 0;
}

static int vfio_do_msi_map(struct vfio_iommu *iommu,
			struct vfio_pamu_msi_bank_map *msi_map)
{
	struct vfio_msi_dma *msi_dma;
	int ret, prot = 0;

	/* READ/WRITE from device perspective */
	if (msi_map->flags & VFIO_DMA_MAP_FLAG_WRITE)
		prot |= IOMMU_WRITE;
	if (msi_map->flags & VFIO_DMA_MAP_FLAG_READ)
		prot |= IOMMU_READ;

	if (!prot)
		return -EINVAL; /* No READ/WRITE? */

	ret = vfio_msi_map(iommu, msi_map, prot);
	if (ret)
		return ret;

	msi_dma = kzalloc(sizeof(*msi_dma), GFP_KERNEL);
	if (!msi_dma)
		return -ENOMEM;

	msi_dma->iova = msi_map->iova;
	msi_dma->bank_id = msi_map->msi_bank_index;
	list_add(&msi_dma->next, &iommu->msi_dma_list);
	return 0;
}

static void vfio_msi_unmap(struct vfio_iommu *iommu, dma_addr_t iova)
{
	int window;
	window = iova_to_win(iommu, iova);
	iommu_domain_window_disable(iommu->domain, window);
}

static int vfio_do_msi_unmap(struct vfio_iommu *iommu,
			     struct vfio_pamu_msi_bank_unmap *msi_unmap)
{
	struct vfio_msi_dma *mdma, *mdma_tmp;

	list_for_each_entry_safe(mdma, mdma_tmp, &iommu->msi_dma_list, next) {
		if (mdma->iova == msi_unmap->iova) {
			vfio_msi_unmap(iommu, mdma->iova);
			list_del(&mdma->next);
			kfree(mdma);
			return 0;
		}
	}

	return -EINVAL;
}
static void *vfio_iommu_fsl_pamu_open(unsigned long arg)
{
	struct vfio_iommu *iommu;

	if (arg != VFIO_FSL_PAMU_IOMMU)
		return ERR_PTR(-EINVAL);

	iommu = kzalloc(sizeof(*iommu), GFP_KERNEL);
	if (!iommu)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&iommu->group_list);
	INIT_LIST_HEAD(&iommu->dma_list);
	INIT_LIST_HEAD(&iommu->msi_dma_list);
	mutex_init(&iommu->lock);

	/*
	 * Wish we didn't have to know about bus_type here.
	 */
	iommu->domain = iommu_domain_alloc(&pci_bus_type);
	if (!iommu->domain) {
		kfree(iommu);
		return ERR_PTR(-EIO);
	}

	return iommu;
}

static void vfio_iommu_fsl_pamu_release(void *iommu_data)
{
	struct vfio_iommu *iommu = iommu_data;
	struct vfio_group *group, *group_tmp;
	struct vfio_dma *dma, *dma_tmp;
	struct vfio_msi_dma *mdma, *mdma_tmp;

	list_for_each_entry_safe(group, group_tmp, &iommu->group_list, next) {
		iommu_detach_group(iommu->domain, group->iommu_group);
		list_del(&group->next);
		kfree(group);
	}

	list_for_each_entry_safe(dma, dma_tmp, &iommu->dma_list, next) {
		vfio_dma_unmap(iommu, dma->iova, dma->npage, dma->prot);
		list_del(&dma->next);
		kfree(dma);
	}

	list_for_each_entry_safe(mdma, mdma_tmp, &iommu->msi_dma_list, next) {
		vfio_msi_unmap(iommu, mdma->iova);
		list_del(&mdma->next);
		kfree(mdma);
	}

	iommu_domain_free(iommu->domain);
	iommu->domain = NULL;
	kfree(iommu);
}

static long vfio_iommu_fsl_pamu_ioctl(void *iommu_data,
				   unsigned int cmd, unsigned long arg)
{
	struct vfio_iommu *iommu = iommu_data;
	unsigned long minsz;

	if (cmd == VFIO_CHECK_EXTENSION) {
		switch (arg) {
		case VFIO_FSL_PAMU_IOMMU:
			return 1;
		default:
			return 0;
		}
	} else if (cmd == VFIO_IOMMU_MAP_DMA) {
		struct vfio_iommu_type1_dma_map map;
		uint32_t mask = VFIO_DMA_MAP_FLAG_READ |
				VFIO_DMA_MAP_FLAG_WRITE;

		minsz = offsetofend(struct vfio_iommu_type1_dma_map, size);

		if (copy_from_user(&map, (void __user *)arg, minsz))
			return -EFAULT;

		if (map.argsz < minsz || map.flags & ~mask)
			return -EINVAL;

		return vfio_dma_do_map(iommu, &map);

	} else if (cmd == VFIO_IOMMU_UNMAP_DMA) {
		struct vfio_iommu_type1_dma_unmap unmap;

		minsz = offsetofend(struct vfio_iommu_type1_dma_unmap, size);

		if (copy_from_user(&unmap, (void __user *)arg, minsz))
			return -EFAULT;

		if (unmap.argsz < minsz || unmap.flags)
			return -EINVAL;

		return vfio_dma_do_unmap(iommu, &unmap);
	} else if (cmd == VFIO_IOMMU_PAMU_GET_ATTR) {
		struct vfio_pamu_attr pamu_attr;

		minsz = offsetofend(struct vfio_pamu_attr, attr_info);
		if (copy_from_user(&pamu_attr, (void __user *)arg, minsz))
			return -EFAULT;

		if (pamu_attr.argsz < minsz)
			return -EINVAL;

		vfio_handle_get_attr(iommu, &pamu_attr);

		copy_to_user((void __user *)arg, &pamu_attr, minsz);
		return 0;
	} else if (cmd == VFIO_IOMMU_PAMU_SET_ATTR) {
		struct vfio_pamu_attr pamu_attr;

		minsz = offsetofend(struct vfio_pamu_attr, attr_info);
		if (copy_from_user(&pamu_attr, (void __user *)arg, minsz))
			return -EFAULT;

		if (pamu_attr.argsz < minsz)
			return -EINVAL;

		vfio_handle_set_attr(iommu, &pamu_attr);
		return 0;
	} else if (cmd == VFIO_IOMMU_PAMU_GET_MSI_BANK_COUNT) {
		return fsl_msi_get_region_count();
	} else if (cmd == VFIO_IOMMU_PAMU_MAP_MSI_BANK) {
		struct vfio_pamu_msi_bank_map msi_map;

		minsz = offsetofend(struct vfio_pamu_msi_bank_map, iova);
		if (copy_from_user(&msi_map, (void __user *)arg, minsz))
			return -EFAULT;

		if (msi_map.argsz < minsz)
			return -EINVAL;
		vfio_do_msi_map(iommu, &msi_map);
		return 0;
	} else if (cmd == VFIO_IOMMU_PAMU_UNMAP_MSI_BANK) {
		struct vfio_pamu_msi_bank_unmap msi_unmap;

		minsz = offsetofend(struct vfio_pamu_msi_bank_unmap, iova);
		if (copy_from_user(&msi_unmap, (void __user *)arg, minsz))
			return -EFAULT;

		if (msi_unmap.argsz < minsz)
			return -EINVAL;

		vfio_do_msi_unmap(iommu, &msi_unmap);
		return 0;

	}

	return -ENOTTY;
}

static int vfio_iommu_fsl_pamu_attach_group(void *iommu_data,
					 struct iommu_group *iommu_group)
{
	struct vfio_iommu *iommu = iommu_data;
	struct vfio_group *group, *tmp;
	int ret;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return -ENOMEM;

	mutex_lock(&iommu->lock);

	list_for_each_entry(tmp, &iommu->group_list, next) {
		if (tmp->iommu_group == iommu_group) {
			mutex_unlock(&iommu->lock);
			kfree(group);
			return -EINVAL;
		}
	}

	ret = iommu_attach_group(iommu->domain, iommu_group);
	if (ret) {
		mutex_unlock(&iommu->lock);
		kfree(group);
		return ret;
	}

	group->iommu_group = iommu_group;
	list_add(&group->next, &iommu->group_list);

	mutex_unlock(&iommu->lock);

	return 0;
}

static void vfio_iommu_fsl_pamu_detach_group(void *iommu_data,
					  struct iommu_group *iommu_group)
{
	struct vfio_iommu *iommu = iommu_data;
	struct vfio_group *group;

	mutex_lock(&iommu->lock);

	list_for_each_entry(group, &iommu->group_list, next) {
		if (group->iommu_group == iommu_group) {
			iommu_detach_group(iommu->domain, iommu_group);
			list_del(&group->next);
			kfree(group);
			break;
		}
	}

	mutex_unlock(&iommu->lock);
}

static const struct vfio_iommu_driver_ops vfio_iommu_driver_ops_fsl_pamu = {
	.name		= "vfio-iommu-fsl_pamu",
	.owner		= THIS_MODULE,
	.open		= vfio_iommu_fsl_pamu_open,
	.release	= vfio_iommu_fsl_pamu_release,
	.ioctl		= vfio_iommu_fsl_pamu_ioctl,
	.attach_group	= vfio_iommu_fsl_pamu_attach_group,
	.detach_group	= vfio_iommu_fsl_pamu_detach_group,
};

static int __init vfio_iommu_fsl_pamu_init(void)
{
	if (!iommu_present(&pci_bus_type))
		return -ENODEV;

	return vfio_register_iommu_driver(&vfio_iommu_driver_ops_fsl_pamu);
}

static void __exit vfio_iommu_fsl_pamu_cleanup(void)
{
	vfio_unregister_iommu_driver(&vfio_iommu_driver_ops_fsl_pamu);
}

module_init(vfio_iommu_fsl_pamu_init);
module_exit(vfio_iommu_fsl_pamu_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
