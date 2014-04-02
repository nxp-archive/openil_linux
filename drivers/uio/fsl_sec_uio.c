/*
 * Copyright 2012-2013 Freescale Semiconductor, Inc.
 *
 * Author: Po Liu <po.liu@freescale.com>
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
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/io.h>
#include <linux/uio_driver.h>
#include <linux/slab.h>
#include <linux/list.h>

static const char sec_uio_version[] = "fsl SEC UIO driver v1.0";

#define NAME_LENGTH 30
#define JR_INDEX_OFFSET 12

static const char uio_device_name[NAME_LENGTH] = "fsl-sec";
static LIST_HEAD(sec_list);

struct sec_uio_info {
	atomic_t ref; /* exclusive, only one open() at a time */
	struct uio_info uio;
	char name[NAME_LENGTH];
};

struct sec_dev {
	u32 revision;
	u32 index;
	u32 irq;
	void __iomem *global_regs;
	struct device *dev;
	struct resource res;
	struct sec_uio_info info;
	struct list_head node;
	struct list_head jr_list;
};

struct sec_job_ring {
	struct list_head list_node;
	u32 index;
	u32 irq;
	struct device *dev;
	struct sec_uio_info info;
	struct resource *res;
};

static int sec_uio_open(struct uio_info *info, struct inode *inode)
{
	struct sec_uio_info *uio_info = container_of(info,
					struct sec_uio_info, uio);

	if (!atomic_dec_and_test(&uio_info->ref)) {
		pr_err("%s: failing non-exclusive open()\n", uio_info->name);
		atomic_inc(&uio_info->ref);
		return -EBUSY;
	}

	return 0;
}

static int sec_uio_release(struct uio_info *info, struct inode *inode)
{
	struct sec_uio_info *uio_info = container_of(info,
					struct sec_uio_info, uio);
	atomic_inc(&uio_info->ref);

	return 0;
}

static irqreturn_t sec_uio_irq_handler(int irq, struct uio_info *dev_info)
{
	return IRQ_NONE;
}

static int sec_uio_irqcontrol(struct uio_info *dev_info, int irqon)
{
	return 0;
}

static irqreturn_t sec_jr_irq_handler(int irq, struct uio_info *dev_info)
{
	return IRQ_NONE;
}

static int sec_jr_irqcontrol(struct uio_info *dev_info, int irqon)
{
	return 0;
}

static int __init sec_uio_init(struct sec_dev *uio_dev)
{
	int ret;
	struct sec_uio_info *info;

	info = &uio_dev->info;
	atomic_set(&info->ref, 1);
	info->uio.version = sec_uio_version;
	info->uio.name = uio_dev->info.name;
	info->uio.mem[0].name = "sec config space";
	info->uio.mem[0].addr = uio_dev->res.start;
	info->uio.mem[0].size = uio_dev->res.end - uio_dev->res.start + 1;
	info->uio.mem[0].internal_addr = uio_dev->global_regs;
	info->uio.mem[0].memtype = UIO_MEM_PHYS;
	info->uio.irq = uio_dev->irq;
	info->uio.irq_flags = IRQF_SHARED;
	info->uio.handler = sec_uio_irq_handler;
	info->uio.irqcontrol = sec_uio_irqcontrol;
	info->uio.open = sec_uio_open;
	info->uio.release = sec_uio_release;
	info->uio.priv = uio_dev;

	ret = uio_register_device(uio_dev->dev, &info->uio);
	if (ret) {
		pr_err("sec_uio: UIO registration failed\n");
		return ret;
	}

	return 0;
}

static int __init sec_jr_uio_init(struct sec_job_ring *jr)
{
	int ret;
	struct sec_uio_info *info;

	info = &jr->info;
	atomic_set(&info->ref, 1);
	info->uio.version = sec_uio_version;
	info->uio.name = jr->info.name;
	info->uio.mem[0].name = "sec job ring";
	info->uio.mem[0].addr = jr->res->start;
	info->uio.mem[0].size = jr->res->end - jr->res->start + 1;
	info->uio.mem[0].memtype = UIO_MEM_PHYS;
	info->uio.irq = jr->irq;
	info->uio.irq_flags = IRQF_SHARED;
	info->uio.handler = sec_jr_irq_handler;
	info->uio.irqcontrol = sec_jr_irqcontrol;
	info->uio.open = sec_uio_open;
	info->uio.release = sec_uio_release;
	info->uio.priv = jr;

	ret = uio_register_device(jr->dev, &info->uio);
	if (ret) {
		pr_err("sec_jr_uio: UIO registration failed\n");
		return ret;
	}

	return 0;
}

static int fsl_sec_jr_probe(struct device_node *jr_node,
			     struct sec_dev *scdev)
{
	struct sec_job_ring *jr;
	struct resource regs;
	int ret;

	if (!jr_node || !scdev)
		return -EINVAL;

	jr = kzalloc(sizeof(*jr), GFP_KERNEL);
	if (!jr) {
		dev_err(scdev->dev, "Can't alloc memory for job ring\n");
		return -ENOMEM;
	}

	jr->dev = scdev->dev;

	ret = of_address_to_resource(jr_node, 0, &regs);
	if (unlikely(ret < 0)) {
		dev_err(jr->dev, "Can't get property 'reg'\n");
		ret = -EFAULT;
		goto abort_jr;
	}

	jr->index = (regs.start >> JR_INDEX_OFFSET) & 0xf;
	snprintf(jr->info.name, sizeof(jr->info.name)-1,
		 "sec_job_ring%d-%d", scdev->index, jr->index);

	jr->res = devm_request_mem_region(scdev->dev, regs.start,
					  regs.end + 1 - regs.start,
					  jr->info.name);
	if (unlikely(!jr->res)) {
		dev_err(jr->dev, "devm_request_mem_region failed\n");
		ret = -ENOMEM;
		goto abort_jr;
	}

	dev_dbg(jr->dev,
		 "sec_job_ring%d-%d reg start 0x%016llx, size 0x%016llx.\n",
		 scdev->index, jr->index, jr->res->start,
		 jr->res->end + 1 - jr->res->start);

	jr->irq = irq_of_parse_and_map(jr_node, 0);
	dev_dbg(jr->dev, "errirq: %d\n", jr->irq);

	ret = sec_jr_uio_init(jr);
	if (ret)
		goto abort_jr;

	list_add(&jr->list_node, &scdev->jr_list);
	dev_info(jr->dev, "sec_job_ring%d-%d initialized.\n",
			scdev->index, jr->index);

	return 0;
abort_jr:
	kfree(jr);
	return ret;
}

static int fsl_sec_jr_remove(struct sec_job_ring *jr)
{
	if (!jr)
		return 0;
	uio_unregister_device(&jr->info.uio);
	kfree(jr);

	return 0;
}

static const struct of_device_id jr_ids[] = {
	{ .compatible = "fsl,sec-v4.0-job-ring", },
	{ .compatible = "fsl,sec-v4.4-job-ring", },
	{ .compatible = "fsl,sec-v5.0-job-ring", },
	{ .compatible = "fsl,sec-v6.0-job-ring", },
	{},
};

static int fsl_sec_probe(struct platform_device *dev)
{
	struct resource regs;
	struct sec_dev *sec_dev;
	struct device_node *sec_node, *child;
	struct sec_job_ring *jr, *tmp;
	int ret, count = 0;
	struct list_head *p;

	sec_node = dev->dev.of_node;
	if (!sec_node) {
		dev_err(&dev->dev, "Device OF-Node is NULL");
		return -EFAULT;
	}

	sec_dev = kzalloc(sizeof(struct sec_dev), GFP_KERNEL);
	if (!sec_dev)
		return -ENOMEM;

	/* Creat name and index */
	list_for_each(p, &sec_list) {
		count++;
	}
	sec_dev->index = count;

	snprintf(sec_dev->info.name, sizeof(sec_dev->info.name) - 1,
			"%s%d", uio_device_name, sec_dev->index);

	sec_dev->dev = &dev->dev;
	platform_set_drvdata(dev, sec_dev);

	dev_info(sec_dev->dev, "UIO device full name %s initialized\n",
			sec_dev->info.name);

	/* Create each jr under this sec node */
	INIT_LIST_HEAD(&sec_dev->jr_list);
	for_each_child_of_node(sec_node, child) {
		if (of_match_node(jr_ids, child))
			fsl_sec_jr_probe(child, sec_dev);
	}

	/* Get the resource from dtb node */
	ret = of_address_to_resource(sec_node, 0, &regs);
	if (unlikely(ret < 0)) {
		ret = -EFAULT;
		goto abort;
	}

	sec_dev->res = regs;

	sec_dev->global_regs = of_iomap(sec_node, 0);

	sec_dev->irq = irq_of_parse_and_map(sec_node, 0);
	dev_dbg(sec_dev->dev, "errirq: %d\n", sec_dev->irq);

	/* Register UIO */
	ret = sec_uio_init(sec_dev);
	if (ret)
		goto abort_iounmap;

	list_add_tail(&sec_dev->node, &sec_list);

	return 0;

abort_iounmap:
	iounmap(sec_dev->global_regs);
abort:
	list_for_each_entry_safe(jr, tmp, &sec_dev->jr_list, list_node) {
		list_del(&jr->list_node);
		fsl_sec_jr_remove(jr);
	}
	kfree(sec_dev);
	return ret;
}

static int fsl_sec_remove(struct platform_device *dev)
{
	struct sec_dev *sec_dev = platform_get_drvdata(dev);
	struct sec_job_ring *jr, *tmp;

	if (!sec_dev)
		return 0;

	list_for_each_entry_safe(jr, tmp, &sec_dev->jr_list, list_node) {
		list_del(&jr->list_node);
		fsl_sec_jr_remove(jr);
	}

	list_del(&sec_dev->node);
	uio_unregister_device(&sec_dev->info.uio);
	platform_set_drvdata(dev, NULL);
	iounmap(sec_dev->global_regs);
	kfree(sec_dev);

	return 0;
}

static const struct of_device_id sec_ids[] = {
	{ .compatible = "fsl,sec-v4.0", },
	{ .compatible = "fsl,sec-v4.4", },
	{ .compatible = "fsl,sec-v5.0", },
	{ .compatible = "fsl,sec-v6.0", },
	{},
};

static struct platform_driver fsl_sec_driver = {
	.driver = {
		.name = "fsl-sec-uio",
		.owner = THIS_MODULE,
		.of_match_table = sec_ids,
	},
	.probe = fsl_sec_probe,
	.remove = fsl_sec_remove,
};

static __init int fsl_sec_init(void)
{
	int ret;

	ret = platform_driver_register(&fsl_sec_driver);
	if (unlikely(ret < 0))
		pr_warn(": %s:%hu:%s(): platform_driver_register() = %d\n",
			__FILE__, __LINE__, __func__, ret);

	return ret;
}

static void __exit fsl_sec_exit(void)
{
	platform_driver_unregister(&fsl_sec_driver);
}

module_init(fsl_sec_init);
module_exit(fsl_sec_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Liu Po <po.liu@freescale.com>");
MODULE_DESCRIPTION("FSL SEC UIO Driver");
