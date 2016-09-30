/*
 * Copyright 2015 Freescale Semiconductor, Inc.
 *
 * Author: Minghuan Lian <Minghuan.Lian@freescale.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the License, or (at your
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

#include <linux/kernel.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/uio_driver.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mm.h>

static const char rman_uio_version[] = "RMan UIO driver v1.0";

#define IB_INDEX_OFFSET 12
#define MMIER 0x0420 /* Message manage Interrupt Enable Register*/
#define MMEDR 0x0424 /* Message manager error detect register */
#define MMEDR_CLEAR 0x800000FF

struct rman_uio_info {
	atomic_t ref; /* exclusive, only one open() at a time */
	struct uio_info uio;
	char name[30];
};

struct rman_dev {
	u32 revision;
	int irq;
	void __iomem *global_regs;
	struct device *dev;
	struct rman_uio_info info;
	struct resource  *res;
	struct list_head ib_list;
};

struct rman_inbound_block {
	struct list_head node;
	u32 index;
	struct device *dev;
	struct rman_uio_info info;
	struct resource  *res;
};

static int rman_uio_open(struct uio_info *info, struct inode *inode)
{
	struct rman_uio_info *i = container_of(info, struct rman_uio_info, uio);

	if (!atomic_dec_and_test(&i->ref)) {
		pr_err("%s: failing non-exclusive open()\n", i->name);
		atomic_inc(&i->ref);
		return -EBUSY;
	}
	return 0;
}

static int rman_uio_mmap(struct uio_info *info, struct vm_area_struct *vma)
{
	int mi;
	struct uio_mem *mem;
	unsigned long size;

	if (vma->vm_pgoff < MAX_UIO_MAPS) {
		if (info->mem[vma->vm_pgoff].size == 0)
			return -EINVAL;
		mi = (int)vma->vm_pgoff;
	} else
		return -EINVAL;

	mem = &info->mem[mi];

	size = min_t(unsigned long, vma->vm_end - vma->vm_start, mem->size);
	size = max_t(unsigned long, size, PAGE_SIZE);

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range(vma,
			       vma->vm_start,
			       mem->addr >> PAGE_SHIFT,
			       size,
			       vma->vm_page_prot);
}

static int rman_uio_release(struct uio_info *info, struct inode *inode)
{
	struct rman_uio_info *i = container_of(info, struct rman_uio_info, uio);

	atomic_inc(&i->ref);
	return 0;
}

static irqreturn_t rman_uio_irq_handler(int irq, struct uio_info *dev_info)
{
	struct rman_dev *rmdev = dev_info->priv;
	u32 status;

	status = ioread32be(rmdev->global_regs + MMEDR);

	if (status) {
		/* disable interrupt */
		iowrite32be(0, rmdev->global_regs + MMIER);
		return IRQ_HANDLED;
	} else
		return IRQ_NONE;
}

static int rman_uio_init(struct rman_dev *rmdev)
{
	int ret;
	struct rman_uio_info *info;

	info = &rmdev->info;
	atomic_set(&info->ref, 1);
	info->uio.name = info->name;
	info->uio.version = rman_uio_version;
	info->uio.mem[0].name = "rman regs";
	info->uio.mem[0].addr = rmdev->res->start;
	info->uio.mem[0].size = rmdev->res->end - rmdev->res->start + 1;
	info->uio.mem[0].internal_addr = rmdev->global_regs;
	info->uio.mem[0].memtype = UIO_MEM_PHYS;
	info->uio.irq = rmdev->irq;
	info->uio.irq_flags = IRQF_SHARED;
	info->uio.handler = rman_uio_irq_handler;
	info->uio.open = rman_uio_open;
	info->uio.release = rman_uio_release;
	info->uio.mmap = rman_uio_mmap;
	info->uio.priv = rmdev;
	ret = uio_register_device(rmdev->dev, &info->uio);
	if (ret) {
		pr_err("rman_uio: UIO registration failed\n");
		return ret;
	}
	return 0;
}

static int rman_ib_uio_init(struct rman_inbound_block *ib)
{
	int ret;
	struct rman_uio_info *info;

	info = &ib->info;
	atomic_set(&info->ref, 1);
	info->uio.name = info->name;
	info->uio.version = rman_uio_version;
	info->uio.mem[0].name = "rman inbound block regs";
	info->uio.mem[0].addr = ib->res->start;
	info->uio.mem[0].size = ib->res->end - ib->res->start + 1;
	info->uio.mem[0].memtype = UIO_MEM_PHYS;
	info->uio.open = rman_uio_open;
	info->uio.release = rman_uio_release;
	info->uio.mmap = rman_uio_mmap;
	info->uio.priv = ib;
	ret = uio_register_device(ib->dev, &info->uio);
	if (ret) {
		pr_err("rman_ib_uio: UIO registration failed\n");
		return ret;
	}
	return 0;
}

static int fsl_rman_ib_probe(struct device_node *ib_node,
			     struct rman_dev *rmdev)
{
	struct rman_inbound_block *ib;
	struct resource regs;
	int err;

	if (!ib_node || !rmdev)
		return -EINVAL;

	ib = kzalloc(sizeof(*ib), GFP_KERNEL);
	if (!ib)
		return -ENOMEM;

	ib->dev = rmdev->dev;

	err = of_address_to_resource(ib_node, 0, &regs);
	if (unlikely(err < 0)) {
		dev_err(ib->dev, "Can't get property 'reg'\n");
		err = -EFAULT;
		goto _err;
	}

	ib->index = (regs.start >> IB_INDEX_OFFSET) & 0xf;
	snprintf(ib->info.name, sizeof(ib->info.name),
		 "rman-inbound-block%d", ib->index);

	ib->res = devm_request_mem_region(rmdev->dev, regs.start,
					  regs.end + 1 - regs.start,
					  ib->info.name);
	if (unlikely(!ib->res)) {
		dev_err(ib->dev, "devm_request_mem_region failed\n");
		err = -ENOMEM;
		goto _err;
	}
	dev_dbg(ib->dev,
		 "inbound block%d reg start 0x%016llx, size 0x%016llx.\n",
		 ib->index, ib->res->start,
		 ib->res->end + 1 - ib->res->start);

	err = rman_ib_uio_init(ib);
	if (err)
		goto _err;

	list_add(&ib->node, &rmdev->ib_list);
	dev_info(ib->dev, "RMan inbound block%d initialized.\n", ib->index);
	return 0;
_err:
	kfree(ib);
	return err;
}

static int fsl_rman_ib_remove(struct rman_inbound_block *ib)
{
	if (!ib)
		return 0;

	uio_unregister_device(&ib->info.uio);
	kfree(ib);
	return 0;
}

static int fsl_rman_probe(struct platform_device *dev)
{
	struct resource regs;
	struct rman_dev *rman_dev;
	struct device_node *rman_node, *child;
	struct rman_inbound_block *ib, *tmp;
	int err, global_reg_found = 0;

	rman_node = dev->dev.of_node;
	if (!rman_node) {
		dev_err(&dev->dev, "Device OF-Node is NULL");
		return -EFAULT;
	}
	dev_info(&dev->dev, "Of-device %s initialized\n",
		 rman_node->full_name);

	rman_dev = kzalloc(sizeof(struct rman_dev), GFP_KERNEL);
	if (!rman_dev)
		return -ENOMEM;

	rman_dev->dev = &dev->dev;
	INIT_LIST_HEAD(&rman_dev->ib_list);
	platform_set_drvdata(dev, rman_dev);

	for_each_child_of_node(rman_node, child) {
		if (of_device_is_compatible(child, "fsl,rman-inbound-block"))
			fsl_rman_ib_probe(child, rman_dev);

		if (of_device_is_compatible(child, "fsl,rman-global-cfg")) {
			if (of_address_to_resource(child, 0, &regs))
				global_reg_found = 0;
			else
				global_reg_found = 1;
		}
	}

	if (!global_reg_found) {
		dev_err(&dev->dev, "Can't init global registers\n");
		err = -ENODEV;
		goto _err;
	}

	snprintf(rman_dev->info.name, sizeof(rman_dev->info.name),
		 "rman-uio");
	rman_dev->res = devm_request_mem_region(&dev->dev, regs.start,
						regs.end - regs.start + 1,
						rman_dev->info.name);
	dev_dbg(&dev->dev, "global regs start 0x%016llx, size 0x%016llx.\n",
		 rman_dev->res->start,
		 rman_dev->res->end + 1 - rman_dev->res->start);
	if (unlikely(rman_dev->res == NULL)) {
		dev_err(&dev->dev, "devm_request_mem_region failed\n");
		err = -ENOMEM;
		goto _err;
	}

	rman_dev->global_regs = devm_ioremap(&dev->dev, rman_dev->res->start,
				rman_dev->res->end - rman_dev->res->start + 1);
	if (unlikely(rman_dev->global_regs == 0)) {
		dev_err(&dev->dev, "devm_ioremap failed\n");
		err = -EIO;
		goto _err;
	}

	rman_dev->irq = irq_of_parse_and_map(rman_node, 0);
	dev_dbg(rman_dev->dev, "errirq: %d\n", rman_dev->irq);

	err = rman_uio_init(rman_dev);
	if (err)
		goto _err;
	return 0;

_err:
	platform_set_drvdata(dev, NULL);
	list_for_each_entry_safe(ib, tmp, &rman_dev->ib_list, node) {
		list_del(&ib->node);
		fsl_rman_ib_remove(ib);
	}
	kfree(rman_dev);
	return err;
}

static int fsl_rman_remove(struct platform_device *dev)
{
	struct rman_dev *rman_dev = platform_get_drvdata(dev);
	struct rman_inbound_block *ib, *tmp;

	if (!rman_dev)
		return -EINVAL;

	list_for_each_entry_safe(ib, tmp, &rman_dev->ib_list, node) {
		list_del(&ib->node);
		fsl_rman_ib_remove(ib);
	}

	uio_unregister_device(&rman_dev->info.uio);
	platform_set_drvdata(dev, NULL);
	kfree(rman_dev);
	return 0;
}

static const struct of_device_id fsl_of_rman_match[] = {
	{
		.compatible = "fsl,rman",
	},
	{}
};

static struct platform_driver fsl_rman_driver = {
	.driver = {
		.name = "fsl-of-rman",
		.owner = THIS_MODULE,
		.of_match_table = fsl_of_rman_match,
	},
	.probe = fsl_rman_probe,
	.remove = fsl_rman_remove,
};

static int __init fsl_rman_init(void)
{
	int err;

	err = platform_driver_register(&fsl_rman_driver);
	if (unlikely(err < 0))
		pr_warn(": %s:%hu:%s(): platform_driver_register() = %d\n",
			__FILE__, __LINE__, __func__, err);

	return err;
}

static void __exit fsl_rman_exit(void)
{
	platform_driver_unregister(&fsl_rman_driver);
}

module_init(fsl_rman_init);
module_exit(fsl_rman_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@nxp.com>");
MODULE_DESCRIPTION("Freescale RMan UIO driver");
