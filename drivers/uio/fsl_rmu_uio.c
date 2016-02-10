/*
 * Copyright 2012-2016 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.
 *
 */

#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/module.h>
#include <linux/uio_driver.h>
#include <linux/list.h>
#include <linux/io.h>

/* rmu unit ID, based on the unit register off-set */
#define RMU_UNIT_MSG0 0
#define RMU_UNIT_MSG1 1
#define RMU_UNIT_DBELL 4

static const char rmu_uio_version[] = "RMU UIO driver v1.0";

struct rmu_uio_info {
	atomic_t ref; /* exclusive, only one open() at a time */
	struct uio_info uio;
	char name[20];
};

struct rmu_unit {
	struct device *dev;
	struct resource  *res;
	struct rmu_uio_info *info;
	struct list_head list;
	void __iomem *regs_win;
	int irq;
	u32 unit_id;
};

struct rmu_device {
	struct platform_device *pdev;
	struct list_head unit_list;
};

static int rmu_uio_open(struct uio_info *info, struct inode *inode)
{
	struct rmu_uio_info *i = container_of(info, struct rmu_uio_info, uio);
	struct rmu_unit *unit = info->priv;

	if (!atomic_dec_and_test(&i->ref)) {
		dev_err(unit->dev,
			"%s: failing non-exclusive open()\n", i->name);
		atomic_inc(&i->ref);
		return -EBUSY;
	}

	return 0;
}

static int rmu_uio_release(struct uio_info *info, struct inode *inode)
{
	struct rmu_uio_info *i = container_of(info, struct rmu_uio_info, uio);

	atomic_inc(&i->ref);

	return 0;
}

static int __init rmu_unit_uio_setup(struct rmu_unit *unit)
{
	int ret;
	struct rmu_uio_info *info;

	info = devm_kzalloc(unit->dev, sizeof(struct rmu_uio_info),
			    GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	unit->info = info;

	atomic_set(&info->ref, 1);
	if (unit->unit_id == RMU_UNIT_DBELL)
		snprintf(info->name, sizeof(info->name), "rmu-uio-doorbell");
	else
		snprintf(info->name, sizeof(info->name), "rmu-uio-msg%d",
			 unit->unit_id);

	info->uio.name = info->name;
	info->uio.version = rmu_uio_version;
	info->uio.mem[0].name = "rmu regs";
	info->uio.mem[0].addr = unit->res->start;
	info->uio.mem[0].size = resource_size(unit->res);
	info->uio.mem[0].internal_addr = unit->regs_win;
	info->uio.mem[0].memtype = UIO_MEM_PHYS;
	info->uio.open = rmu_uio_open;
	info->uio.release = rmu_uio_release;
	info->uio.priv = unit;

	ret = uio_register_device(unit->dev, &info->uio);
	if (ret) {
		dev_err(unit->dev, "rmu_uio: UIO registration failed\n");
		return ret;
	}

	return 0;
}

static int fsl_rmu_unit_probe(struct rmu_device *rmu_dev,
			      struct device_node *node)
{
	struct resource regs;
	struct rmu_unit *unit;
	struct device_node *unit_node;
	int err;
	struct platform_device *pdev = rmu_dev->pdev;

	unit_node = node;
	dev_dbg(&pdev->dev, "of-device full name %s\n", unit_node->full_name);

	unit = devm_kzalloc(&pdev->dev, sizeof(struct rmu_unit), GFP_KERNEL);
	if (!unit)
		return -ENOMEM;

	unit->dev = &pdev->dev;

	err = of_address_to_resource(unit_node, 0, &regs);
	if (err < 0) {
		dev_err(&pdev->dev, "Can't get property 'reg'\n");
		return -EFAULT;
	}

	unit->unit_id = (regs.start >> 8) & 0xf;
	unit->res = devm_request_mem_region(&pdev->dev, regs.start,
					resource_size(&regs), "rmu");
	if (!unit->res) {
		dev_err(&pdev->dev, "devm_request_mem_region failed\n");
		return -ENOMEM;
	}

	dev_dbg(&pdev->dev, "reg start 0x%016llx, size 0x%016llx.\n",
		unit->res->start, resource_size(unit->res));

	unit->regs_win = devm_ioremap(&pdev->dev, unit->res->start,
				resource_size(unit->res));
	if (!unit->regs_win) {
		dev_err(&pdev->dev, "devm_ioremap failed\n");
		return -EIO;
	}

	err = rmu_unit_uio_setup(unit);
	if (err < 0) {
		dev_err(unit->dev, "rmu_unit_uio_setup failed\n");
		return err;
	}

	list_add_tail(&unit->list, &rmu_dev->unit_list);

	dev_info(&pdev->dev, "rmu unit %s initialized\n", unit->info->name);

	return 0;
}

static void fsl_rmu_unit_remove(struct rmu_unit *unit)
{
	uio_unregister_device(&unit->info->uio);
}

static int fsl_rmu_uio_probe(struct platform_device *pdev)
{
	struct device_node *child;
	struct rmu_device *rmu_dev;

	rmu_dev = devm_kzalloc(&pdev->dev, sizeof(struct rmu_device),
			       GFP_KERNEL);
	if (!rmu_dev)
		return -ENOMEM;

	rmu_dev->pdev = pdev;
	INIT_LIST_HEAD(&rmu_dev->unit_list);
	dev_set_drvdata(&pdev->dev, rmu_dev);

	for_each_child_of_node(pdev->dev.of_node, child)
		if ((of_device_is_compatible(child, "fsl,srio-msg-unit")) ||
		    (of_device_is_compatible(child, "fsl,srio-dbell-unit")))
			fsl_rmu_unit_probe(rmu_dev, child);

	return 0;
}

static int fsl_rmu_uio_remove(struct platform_device *pdev)
{
	struct rmu_device *rmu_dev;
	struct rmu_unit *unit, *unit_tmp;

	rmu_dev = dev_get_drvdata(&pdev->dev);
	list_for_each_entry_safe(unit, unit_tmp,
				 &rmu_dev->unit_list,
				 list) {
		list_del(&unit->list);
		fsl_rmu_unit_remove(unit);
	}

	return 0;
}

static const struct of_device_id fsl_of_rmu_match[] = {
	{
		.compatible = "fsl,srio-rmu",
	},
	{}
};

static struct platform_driver fsl_rmu_uio_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "fsl-of-rmu",
		.of_match_table = fsl_of_rmu_match,
	},
	.probe = fsl_rmu_uio_probe,
	.remove = fsl_rmu_uio_remove,
};

static __init int fsl_rmu_uio_init(void)
{
	int err;

	err = platform_driver_register(&fsl_rmu_uio_driver);
	if (err < 0)
		pr_err("fsl-rmu-uio: failed to register platform driver\n");

	return err;
}

static void __exit fsl_rmu_uio_exit(void)
{
	platform_driver_unregister(&fsl_rmu_uio_driver);
}

module_init(fsl_rmu_uio_init);
module_exit(fsl_rmu_uio_exit);
MODULE_AUTHOR("Liu Gang <Gang.Liu@freescale.com>");
MODULE_DESCRIPTION("UIO driver for Freescale RMU");
MODULE_LICENSE("GPL v2");
