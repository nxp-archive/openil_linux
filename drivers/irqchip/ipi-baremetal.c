/*
 * IPI for inter-core communiction for NXP Layerscape baremetal
 *
 * Copyright 2018 NXP
 *
 * Author: Liu Gang <gang.liu@nxp.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of the above-listed copyright holders nor the
 *	 names of any contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <asm/siginfo.h>
#include <linux/uaccess.h>
#include <linux/mman.h>

int pid;
int mycoreid;

#undef IPI_BAREMETAL_SIGNAL

#define DEVICE_NAME	"ipi_bm"

/*
 * choose 50 as baremetal signal number.
 * real-time signals are in the range of 33 to 64.
 */
#define SIG_BM 50

#ifndef IPI_BAREMETAL_SIGNAL
void __iomem *share_base;
#ifdef CONFIG_LS1021A_BAREMETAL
#define CONFIG_MAX_CPUS 2
#else
#define CONFIG_MAX_CPUS 4
#endif
#define CONFIG_SYS_DDR_SDRAM_BASE       0x80000000UL
#define CONFIG_SYS_DDR_SDRAM_SLAVE_SIZE        (256 * 1024 * 1024)
#define CONFIG_SYS_DDR_SDRAM_MASTER_SIZE       (512 * 1024 * 1024)

#define CONFIG_SYS_DDR_SDRAM_SHARE_BASE \
	(CONFIG_SYS_DDR_SDRAM_BASE + CONFIG_SYS_DDR_SDRAM_MASTER_SIZE \
	+ CONFIG_SYS_DDR_SDRAM_SLAVE_SIZE * (CONFIG_MAX_CPUS - 1))

#define CONFIG_SYS_DDR_SDRAM_SHARE_RESERVE_SIZE (16 * 1024 * 1024)
#define CONFIG_SYS_DDR_SDRAM_SHARE_SIZE \
	((256 * 1024 * 1024) - CONFIG_SYS_DDR_SDRAM_SHARE_RESERVE_SIZE)
#define CONFIG_SYS_DDR_SDRAM_SHARE_RESERVE_BASE \
	(CONFIG_SYS_DDR_SDRAM_SHARE_BASE + CONFIG_SYS_DDR_SDRAM_SHARE_SIZE)

/* number of descriptor for each ring */
#define ICC_RING_ENTRY 128
/* size of each block */
#define ICC_BLOCK_UNIT_SIZE (4 * 1024)
/* 2M space for core's ring and desc struct */
#define ICC_RING_DESC_SPACE (2 * 1024 * 1024)

/* share memory size for each core icc */
#define ICC_CORE_MEM_SPACE (CONFIG_SYS_DDR_SDRAM_SHARE_SIZE / CONFIG_MAX_CPUS)
/* share memory base for core x */
#define ICC_CORE_MEM_BASE_PHY(x) \
	(CONFIG_SYS_DDR_SDRAM_SHARE_BASE + (x) * ICC_CORE_MEM_SPACE)
/* share memory base for core x */
#define ICC_CORE_MEM_BASE(x) \
	((unsigned long)share_base + (x) * ICC_CORE_MEM_SPACE)
/* the ring struct addr of core x ring y */
#define ICC_CORE_RING_BASE(x, y) \
	(ICC_CORE_MEM_BASE(x) + (y) * sizeof(struct icc_ring))
/* the desc struct addr of core x */
#define ICC_CORE_DESC_BASE_PHY(x) \
	(ICC_CORE_MEM_BASE_PHY(x) + CONFIG_MAX_CPUS * sizeof(struct icc_ring))
/*
 * The core x block memory base addr for icc data transfer.
 * The beginning 2M space of core x icc memory is for
 * core x ring and desc struct.
 */
#define ICC_CORE_BLOCK_BASE_PHY(x) \
	(ICC_CORE_MEM_BASE_PHY(x) + ICC_RING_DESC_SPACE)
#define ICC_CORE_BLOCK_BASE(x) (ICC_CORE_MEM_BASE(x) + ICC_RING_DESC_SPACE)
#define ICC_CORE_BLOCK_END_PHY(x) \
	(ICC_CORE_MEM_BASE_PHY(x) + ICC_CORE_MEM_SPACE)
#define ICC_CORE_BLOCK_END(x) (ICC_CORE_MEM_BASE(x) + ICC_CORE_MEM_SPACE)
#define ICC_CORE_BLOCK_COUNT \
	((ICC_CORE_MEM_SPACE - ICC_RING_DESC_SPACE)/ICC_BLOCK_UNIT_SIZE)

#define ICC_PHY2VIRT(x) \
	(((void *)x - ICC_CORE_MEM_BASE_PHY(mycoreid)) \
	 + ICC_CORE_MEM_BASE(mycoreid))
#define ICC_VIRT2PHY(x) \
	(((void *)x - ICC_CORE_MEM_BASE(mycoreid)) \
	 + ICC_CORE_MEM_BASE_PHY(mycoreid))

struct icc_desc {
	unsigned long block_addr;	/* block address */
	unsigned int byte_count;	/* available bytes */
};

struct icc_ring {
	unsigned int src_coreid;	/* which core created the ring */
	unsigned int dest_coreid;	/* which core the ring sends SGI to */
	unsigned int interrupt;		/* which interrupt (SGI) be used */
	unsigned int desc_num;		/* number of descriptor */
	struct icc_desc *desc;		/* pointer of the first descriptor */
	unsigned int desc_head;		/* modified by producer */
	unsigned int desc_tail;		/* modified by consumer */
	unsigned long busy_counts;	/* statistic: ring full */
	unsigned long interrupt_counts; /* statistic: total sent number */
};
#endif

int ipi_baremetal_open(struct inode *inode, struct file *filp)
{
	pr_info("ipi_bm device open!\n");
	return 0;
}

ssize_t ipi_baremetal_read(struct file *file,
	char __user *buff, size_t count, loff_t *offp)
{
	pr_info("ipi_bm device read!\n");
	return 0;
}

ssize_t ipi_baremetal_write(struct file *file,
	const char __user *buff, size_t count, loff_t *offp)
{
	char mybuf[10];
	int ret;

	/* read the value from user space */
	if (count > 10)
		return -EINVAL;
	copy_from_user(mybuf, buff, count);
	ret = kstrtoint(mybuf, 0, &pid);
	if (ret)
		return -EINVAL;
	pr_info("ipi_bm device write. pid = %d\n", pid);

	return 0;
}

static int ipi_baremetal_release(struct inode *inode, struct file *file)
{
	pr_info("ipi_bm device close!\n");
	return 0;
}

static int icc_ring_empty(struct icc_ring *ring)
{
	if (ring->desc_tail == ring->desc_head)
		return 1;
	return 0;
}

/* how many rx blocks are valid waiting to be handled */
static int icc_ring_valid(struct icc_ring *ring)
{
	int valid;

	if (icc_ring_empty(ring))
		return 0;

	if (ring->desc_head > ring->desc_tail)
		valid = ring->desc_head - ring->desc_tail;
	else
		valid = ring->desc_num - ring->desc_tail + ring->desc_head;
	return valid;
}

int ipi_baremetal_handle(u32 irqnr, u32 irqsrc)
{
#ifdef IPI_BAREMETAL_SIGNAL
	struct siginfo info;
	struct task_struct *t;
	int si_data;
	int ret;

	if (!pid)
		return 0;

	si_data = (irqnr << 16) | irqsrc;
	/* send the signal */
	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = SIG_BM;
	info.si_code = SI_QUEUE;
	info.si_int = si_data;

	rcu_read_lock();
	/* find the task_struct associated with this pid */
	t = find_task_by_vpid(pid);
	if (t == NULL) {
		pr_info("no such pid\n");
		rcu_read_unlock();
		return -ENODEV;
	}
	rcu_read_unlock();

	/* send the signal */
	ret = send_sig_info(SIG_BM, &info, t);
	if (ret < 0) {
		pr_info("error sending signal\n");
		return ret;
	}
#else
	struct icc_ring *ring;
	struct icc_desc *desc;
	struct icc_desc *desc_phy;
	unsigned long block_addr;
	unsigned int byte_count;
	int i, valid;
	int hw_irq, src_coreid;

	hw_irq = irqnr;
	src_coreid = irqsrc;

	if (src_coreid == mycoreid) {
		pr_err("Do not support self-icc now!\n");
		return -1;
	}

	/* get the ring for this core from source core */
	ring = (struct icc_ring *)ICC_CORE_RING_BASE(src_coreid, mycoreid);
	valid = icc_ring_valid(ring);
	for (i = 0; i < valid; i++) {
		desc_phy = ring->desc + ring->desc_tail;
		desc = ICC_PHY2VIRT(desc_phy);
		block_addr = desc->block_addr;
		byte_count = desc->byte_count;

		if ((*(char *)ICC_PHY2VIRT(block_addr)) != 0x5a)
			pr_info("Get the ICC from core %d; block: 0x%lx, bytes: %d, value: 0x%x\n",
				src_coreid, block_addr, byte_count,
				(*(char *)ICC_PHY2VIRT(block_addr)));

		/* add desc_tail */
		ring->desc_tail = (ring->desc_tail + 1) % ring->desc_num;
	}
#endif
	return 0;
}

static const struct vm_operations_struct shd_mmap_mem_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys
#endif
};

static int shd_mmap_mem(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;

#ifdef CONFIG_LS1021A_BAREMETAL
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#else
	vma->vm_page_prot = pgprot_cached(vma->vm_page_prot);
#endif
	vma->vm_ops = &shd_mmap_mem_ops;

	/* Remap-pfn-range will mark the range VM_IO */
	if (remap_pfn_range(vma,
			    vma->vm_start,
			    vma->vm_pgoff,
			    size,
			    vma->vm_page_prot)) {
		return -EAGAIN;
	}
	return 0;
}

const struct file_operations ipi_bm_ops = {
	.owner = THIS_MODULE,
	.open = ipi_baremetal_open,
	.release = ipi_baremetal_release,
	.read = ipi_baremetal_read,
	.write = ipi_baremetal_write,
	.mmap = shd_mmap_mem,
};

static struct miscdevice ipi_bm_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &ipi_bm_ops,
};

static int __init ipi_baremetal_init(void)
{
	int ret;

	pr_info("NXP inter-core communiction IRQ driver\n");
#ifndef IPI_BAREMETAL_SIGNAL
#ifdef CONFIG_LS1021A_BAREMETAL
	share_base = ioremap((phys_addr_t)CONFIG_SYS_DDR_SDRAM_SHARE_BASE,
				CONFIG_SYS_DDR_SDRAM_SHARE_SIZE);
#else
	share_base = ioremap_cache((phys_addr_t)CONFIG_SYS_DDR_SDRAM_SHARE_BASE,
				CONFIG_SYS_DDR_SDRAM_SHARE_SIZE);
#endif
	if (!share_base) {
		pr_err("failed to remap share base (%lu/%u) for ICC\n",
			CONFIG_SYS_DDR_SDRAM_SHARE_BASE,
			CONFIG_SYS_DDR_SDRAM_SHARE_SIZE);
		return -ENOMEM;
	}
	mycoreid = 0;
#endif
	ret = misc_register(&ipi_bm_misc);
	if (ret < 0) {
		pr_info("Register ipi_bm error! ret: %d\n", ret);
		return ret;
	}
	pr_info("ipi_bm device created!\n");
	return 0;
}

static void __exit ipi_baremetal_exit(void)
{
	pid = 0;
#ifndef IPI_BAREMETAL_SIGNAL
	iounmap(share_base);
#endif
	misc_deregister(&ipi_bm_misc);
	pr_info("ipi_bm device deleted!\n");
}

module_init(ipi_baremetal_init);
module_exit(ipi_baremetal_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NXP");
MODULE_DESCRIPTION("NXP inter-core communiction IPI driver");
