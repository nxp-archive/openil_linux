/*
 * Copyright 2011-2013 Freescale Semiconductor, Inc.
 *
 * Author: Kai Jiang <Kai.Jiang@freescale.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the  GNU General Public License along
 * with this program; if not, write  to the Free Software Foundation, Inc.,
 * 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/module.h>
#include <linux/uio_driver.h>
#include <linux/list.h>
#include <linux/io.h>
#include <linux/mm.h>

static const char dma_uio_version[] = "DMA UIO driver v1.0";

#define DMA_SR	0x4	/* DMA Status Regsiter */

struct dma_uio_info {
	atomic_t ref; /* exclusive, only one open() at a time */
	struct uio_info uio;
	char name[20];
};

struct dma_chan {
	struct device *dev;
	struct resource  *res;
	struct dma_uio_info *info;
	struct list_head list;
	void __iomem *regs_win;
	int irq;
	u32 dma_id;
	u32 ch_id;
};

struct fsldma_device {
	struct platform_device *dev;
	struct list_head ch_list;
	u32 dma_id;
};

static int dma_uio_open(struct uio_info *info, struct inode *inode)
{
	struct dma_uio_info *i = container_of(info, struct dma_uio_info, uio);

	if (!atomic_dec_and_test(&i->ref)) {
		pr_err("%s: failing non-exclusive open()\n", i->name);
		atomic_inc(&i->ref);
		return -EBUSY;
	}

	return 0;
}

static int dma_uio_release(struct uio_info *info, struct inode *inode)
{
	struct dma_uio_info *i = container_of(info, struct dma_uio_info, uio);

	atomic_inc(&i->ref);

	return 0;
}

static irqreturn_t dma_uio_irq_handler(int irq, struct uio_info *dev_info)
{
	struct dma_chan *dma_ch = dev_info->priv;

	out_be32((u32 *)((u8 *)dma_ch->regs_win + DMA_SR), ~0);

	return IRQ_HANDLED;
}

static int dma_uio_mmap(struct uio_info *info, struct vm_area_struct *vma)
{
	int mi;
	struct uio_mem *mem;

	if (vma->vm_pgoff < MAX_UIO_MAPS) {
		if (info->mem[vma->vm_pgoff].size == 0)
			return -EINVAL;
		mi = (int)vma->vm_pgoff;
	} else {
		return -EINVAL;
	}

	mem = info->mem + mi;

	if (vma->vm_end - vma->vm_start > mem->size)
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range(vma,
			       vma->vm_start,
			       mem->addr >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start,
			       vma->vm_page_prot);
}

static int dma_chan_uio_setup(struct dma_chan *dma_ch)
{
	int ret;
	struct dma_uio_info *info;

	info = devm_kzalloc(dma_ch->dev, sizeof(struct dma_uio_info),
			    GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	dma_ch->info = info;

	atomic_set(&info->ref, 1);
	snprintf(info->name, sizeof(info->name) - 1, "dma-uio%d-%d",
		 dma_ch->dma_id, dma_ch->ch_id);
	info->uio.name = info->name;
	info->uio.version = dma_uio_version;
	info->uio.mem[0].name = "dma regs";
	info->uio.mem[0].addr = dma_ch->res->start;
	info->uio.mem[0].size = (dma_ch->res->end - dma_ch->res->start + 1 >
			PAGE_SIZE) ?
			dma_ch->res->end - dma_ch->res->start + 1 : PAGE_SIZE;
	info->uio.mem[0].internal_addr = dma_ch->regs_win;
	info->uio.mem[0].memtype = UIO_MEM_PHYS;

	info->uio.irq = dma_ch->irq;
	info->uio.irq_flags = IRQF_SHARED;
	info->uio.handler = dma_uio_irq_handler;
	info->uio.open = dma_uio_open;
	info->uio.release = dma_uio_release;
	info->uio.mmap = dma_uio_mmap;
	info->uio.priv = dma_ch;
	ret = uio_register_device(dma_ch->dev, &info->uio);
	if (ret) {
		dev_err(dma_ch->dev, "dma_uio: UIO registration failed\n");
		return ret;
	}

	return 0;
}

static int fsl_dma_chan_probe(struct fsldma_device *fdev,
			      struct device_node *node,
			      u32 chanid)
{
	struct resource regs;
	struct dma_chan *dma_ch;
	struct device_node *dma_node;
	int err;
	struct platform_device *dev = fdev->dev;

	dma_node = node;
	dev_dbg(&dev->dev, "Of-device full name %s\n", dma_node->full_name);

	dma_ch = devm_kzalloc(&dev->dev, sizeof(struct dma_chan), GFP_KERNEL);
	if (!dma_ch)
		return -ENOMEM;

	dma_ch->dma_id = fdev->dma_id;
	dma_ch->ch_id = chanid;
	dma_ch->dev = &dev->dev;

	err = of_address_to_resource(dma_node, 0, &regs);
	if (err < 0) {
		dev_err(&dev->dev, "Can't get property 'reg'\n");
		return -EFAULT;
	}

	dma_ch->res = devm_request_mem_region(&dev->dev, regs.start,
					regs.end + 1 - regs.start, "dma");
	if (!dma_ch->res) {
		dev_err(&dev->dev, "devm_request_mem_region failed\n");
		return -ENOMEM;
	}

	dev_dbg(&dev->dev, "reg start 0x%016llx, size 0x%016llx.\n",
		dma_ch->res->start, dma_ch->res->end + 1 -
		dma_ch->res->start);

	dma_ch->regs_win = devm_ioremap(&dev->dev, dma_ch->res->start,
				dma_ch->res->end - dma_ch->res->start + 1);
	if (!dma_ch->regs_win) {
		dev_err(&dev->dev, "devm_ioremap failed\n");
		return -EIO;
	}

	dma_ch->irq = irq_of_parse_and_map(dma_node, 0);
	dev_dbg(dma_ch->dev, "dma channel irq: %d\n", dma_ch->irq);

	err = dma_chan_uio_setup(dma_ch);
	if (err < 0) {
		dev_err(dma_ch->dev, "dma_chan_uio_setup failed\n");
		return err;
	}

	list_add_tail(&dma_ch->list, &fdev->ch_list);

	dev_info(&dev->dev, "dma channel %s initialized\n", dma_ch->info->name);

	return 0;
}

static void fsl_dma_chan_remove(struct dma_chan *dma_ch)
{
	uio_unregister_device(&dma_ch->info->uio);
}

static int fsl_dma_uio_probe(struct platform_device *dev)
{
	struct device_node *child;
	struct fsldma_device *fdev;
	static u32 dmaid;
	u32 chanid = 0;

	fdev = devm_kzalloc(&dev->dev, sizeof(struct fsldma_device),
			    GFP_KERNEL);
	if (!fdev)
		return -ENOMEM;

	fdev->dma_id = dmaid++;
	fdev->dev = dev;
	INIT_LIST_HEAD(&fdev->ch_list);
	dev_set_drvdata(&dev->dev, fdev);

	for_each_child_of_node(dev->dev.of_node, child)
		if (of_device_is_compatible(child, "fsl,eloplus-dma-channel"))
			fsl_dma_chan_probe(fdev, child, chanid++);
	return 0;
}

static int fsl_dma_uio_remove(struct platform_device *dev)
{
	struct fsldma_device *fdev;
	struct dma_chan *dma_ch, *ch_tmp;

	fdev = dev_get_drvdata(&dev->dev);
	list_for_each_entry_safe(dma_ch, ch_tmp, &fdev->ch_list, list) {
		list_del(&dma_ch->list);
		fsl_dma_chan_remove(dma_ch);
	}

	return 0;
}

static const struct of_device_id fsl_of_dma_match[] = {
	{ .compatible = "fsl,elo3-dma", },
	{ .compatible = "fsl,eloplus-dma", },
	{}
};

static struct platform_driver fsl_dma_uio_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "fsl-of-dma",
		.of_match_table = fsl_of_dma_match,
	},
	.probe = fsl_dma_uio_probe,
	.remove = fsl_dma_uio_remove,
};

static __init int fsl_dma_uio_init(void)
{
	int err;

	err = platform_driver_register(&fsl_dma_uio_driver);
	if (err < 0)
		pr_warn(
			": %s:%hu:%s(): platform_driver_register() = %d\n",
			__FILE__, __LINE__, __func__, err);

	return err;
}

static void __exit fsl_dma_uio_exit(void)
{
	platform_driver_unregister(&fsl_dma_uio_driver);

	pr_warn("fsl dma uio driver removed\n");
}

module_init(fsl_dma_uio_init);
module_exit(fsl_dma_uio_exit);
MODULE_LICENSE("GPL");
