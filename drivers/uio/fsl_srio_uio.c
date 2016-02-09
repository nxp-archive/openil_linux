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

#include <linux/kernel.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/uio_driver.h>
#include <linux/list.h>

#define EPWISR	 0x10010 /* Error/Port-Write Interrupt Status */
#define IECSR	 0x10130 /* Port Implementation Err Cmd & Status */
#define ESCSR	 0x00158 /* Port Error and Status Cmd & Status */
#define EDCSR	 0x00640 /* Port Error Detect Cmd & Status */
#define LTLEDCSR 0x00608 /* Logical/Transport Layer Err Detect Cmd & Status */
#define LTLEECSR 0x0060c /* Logical/Transport Layer Err Enable Cmd & Status */
#define SRIO_ESCSR_CLEAR 0x07120204
#define SRIO_IECSR_CLEAR 0x80000000

struct srio_uio_info {
	atomic_t ref;
	struct uio_info uio;
	char name[20];
};

struct srio_port_info {
	struct device *dev;
	struct srio_uio_info *info;
	struct resource *res;
	struct list_head list;
	u32 port_id;
};

struct srio_regs_info {
	struct device *dev;
	struct srio_uio_info *info;
	struct resource *res;
	void __iomem *regs_win;
};

struct srio_dev {
	struct device *dev;
	struct srio_regs_info regs;
	struct list_head port_list;
	int irq;
	u32 port_num;
};

enum srio_uio_init_type {
	SRIO_REGS,
	SRIO_PORT
};

static const char srio_uio_version[] = "SRIO UIO driver v1.0";

static int srio_uio_open(struct uio_info *info, struct inode *inode)
{
	struct srio_uio_info *i = container_of(info, struct srio_uio_info, uio);

	if (atomic_dec_return(&i->ref) < 0) {
		pr_err("%s: failing open()\n", i->name);
		atomic_inc(&i->ref);
		return -EBUSY;
	}

	return 0;
}

static int srio_uio_release(struct uio_info *info, struct inode *inode)
{
	struct srio_uio_info *i = container_of(info, struct srio_uio_info, uio);

	atomic_inc(&i->ref);

	return 0;
}

static irqreturn_t srio_uio_irq_handler(int irq, struct uio_info *dev_info)
{
	struct srio_dev *sriodev = dev_info->priv;
	int i;
	unsigned int port_bits, ltledcsr;

	ltledcsr = in_be32(sriodev->regs.regs_win + LTLEDCSR);
	port_bits = in_be32(sriodev->regs.regs_win + EPWISR);

	if (!port_bits && !ltledcsr)
		return IRQ_NONE;

	if (ltledcsr)
		/* Disable logical/transport layer error interrupt */
		out_be32(sriodev->regs.regs_win + LTLEECSR, 0);

	for (i = 0; i < sriodev->port_num; i++) {
			/* Clear retry error threshold exceeded */
			out_be32(sriodev->regs.regs_win + IECSR + 0x80 * i,
				 SRIO_IECSR_CLEAR);
			/* Clear ESCSR */
			out_be32(sriodev->regs.regs_win + ESCSR + 0x20 * i,
				 SRIO_ESCSR_CLEAR);
			/* Clear EDCSR */
			out_be32(sriodev->regs.regs_win + EDCSR + 0x40 * i,
				 0);
	}

	return IRQ_HANDLED;
}

static int __init srio_uio_setup(struct srio_dev *sriodev, u8 type, u32 port_id)
{
	int err;
	struct srio_uio_info *info;
	struct srio_port_info *srio_port, *port_tmp;

	info = devm_kzalloc(sriodev->dev, sizeof(struct srio_uio_info),
			    GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	if (type == SRIO_REGS) {
		atomic_set(&info->ref, sriodev->port_num);
		sriodev->regs.info = info;
		snprintf(info->name, sizeof(info->name) - 1, "srio-uio-regs");
		info->uio.name = info->name;
		info->uio.version = srio_uio_version;
		info->uio.mem[0].name = "srio regs";
		info->uio.mem[0].addr = sriodev->regs.res->start;
		info->uio.mem[0].size =	sriodev->regs.res->end -
					sriodev->regs.res->start + 1;
		info->uio.mem[0].memtype = UIO_MEM_PHYS;
		info->uio.irq = sriodev->irq;

	} else if (type == SRIO_PORT) {
		err = -ENODEV;
		atomic_set(&info->ref, 1);
		list_for_each_entry_safe(srio_port, port_tmp,
					 &sriodev->port_list, list) {
			if (srio_port->port_id == port_id) {
				srio_port->info = info;
				snprintf(info->name, sizeof(info->name) - 1,
					 "srio-uio-port%d", port_id);
				info->uio.name = info->name;
				info->uio.version = srio_uio_version;
				info->uio.mem[0].name = "srio window";
				info->uio.mem[0].addr = srio_port->res->start;
				info->uio.mem[0].size =	srio_port->res->end -
						srio_port->res->start +	1;
				info->uio.mem[0].memtype = UIO_MEM_PHYS;
				err = 0;
				break;
			}
		}

		if (err < 0)
			return err;
	} else {
		return -ENODEV;
	}

	info->uio.irq_flags = IRQF_SHARED;
	info->uio.handler = srio_uio_irq_handler;
	info->uio.open = srio_uio_open;
	info->uio.release = srio_uio_release;
	info->uio.priv = sriodev;

	err = uio_register_device(sriodev->dev, &info->uio);
	if (err) {
		dev_err(sriodev->dev, "srio_uio: UIO registration failed\n");
		return err;
	}

	return 0;
}

static int srio_uio_init(struct srio_dev *sriodev)
{
	struct srio_port_info *srio_port, *port_tmp;
	int err;

	srio_uio_setup(sriodev, SRIO_REGS, 0);
	list_for_each_entry_safe(srio_port, port_tmp,
				 &sriodev->port_list, list) {
		err = srio_uio_setup(sriodev, SRIO_PORT, srio_port->port_id);
		if (err < 0)
			return err;
	}

	return 0;
}

static int srio_uio_cleanup(struct srio_dev *sriodev)
{
	struct srio_port_info *srio_port, *port_tmp;

	list_for_each_entry_safe(srio_port, port_tmp,
				 &sriodev->port_list, list) {
		uio_unregister_device(&srio_port->info->uio);
		list_del(&srio_port->list);
	}

	uio_unregister_device(&sriodev->regs.info->uio);

	return 0;
}

static int fsl_srio_port_probe(struct srio_dev *srio_dev,
			       struct device_node *node)
{
	struct device_node *srio_node;
	struct srio_port_info *srio_port;
	const u32 *dt_range, *cell, *cell_index;
	u64 law_start, law_size;
	int paw, aw, sw;

	srio_node = node;

	cell_index = of_get_property(srio_node, "cell-index", NULL);
	if (!cell_index) {
		dev_err(srio_dev->dev, "Can't get %s property 'cell-index'\n",
			srio_node->full_name);
		return -ENODEV;
	}

	dt_range = of_get_property(srio_node, "ranges", NULL);
	if (!dt_range) {
		dev_err(srio_dev->dev, "Can't get %s property 'ranges'\n",
			srio_node->full_name);
		return -ENODEV;
	}

	/* Get node address wide */
	cell = of_get_property(srio_node, "#address-cells", NULL);
	if (!cell) {
		dev_err(srio_dev->dev,
			"Can't get %s property '#address-cells'\n",
			srio_node->full_name);
		return -ENODEV;
	}
	aw = *cell;

	/* Get node size wide */
	cell = of_get_property(srio_node, "#size-cells", NULL);
	if (!cell) {
		dev_err(srio_dev->dev, "Can't get %s property '#size-cells'\n",
			srio_node->full_name);
		return -ENODEV;
	}
	sw = *cell;

	/* Get parent address wide wide */
	paw = of_n_addr_cells(srio_node);
	law_start = of_read_number(dt_range + aw, paw);
	law_size = of_read_number(dt_range + aw + paw, sw);

	srio_port = devm_kzalloc(srio_dev->dev, sizeof(struct srio_port_info),
				 GFP_KERNEL);
	srio_port->res = devm_request_mem_region(srio_dev->dev, law_start,
						 law_size, "srio win");

	if (!srio_port->res) {
		dev_err(srio_dev->dev, "devm_request_mem_region failed\n");
		return -ENOMEM;
	}

	dev_dbg(srio_dev->dev, "window start 0x%016llx, size 0x%016llx.\n",
		srio_port->res->start, srio_port->res->end + 1 -
		srio_port->res->start);

	srio_port->port_id = *cell_index;
	srio_port->dev = srio_dev->dev;
	srio_dev->port_num++;
	list_add_tail(&srio_port->list, &srio_dev->port_list);

	return 0;
}

static void fsl_srio_port_remove(struct srio_dev *srio_dev)
{
	struct srio_port_info *srio_port, *port_tmp;

	list_for_each_entry_safe(srio_port, port_tmp,
				 &srio_dev->port_list, list)
		list_del(&srio_port->list);
}

static int fsl_srio_uio_probe(struct platform_device *dev)
{
	struct resource regs;
	struct srio_dev *srio_dev;
	struct device_node *srio_node;
	struct device_node *child;
	int err;

	srio_node = dev->dev.of_node;
	dev_dbg(&dev->dev, "Of-device full name %s\n", srio_node->full_name);

	srio_dev = devm_kzalloc(&dev->dev, sizeof(struct srio_dev), GFP_KERNEL);
	if (!srio_dev)
		return -ENOMEM;

	srio_dev->dev = &dev->dev;
	dev_set_drvdata(&dev->dev, srio_dev);

	err = of_address_to_resource(srio_node, 0, &regs);
	if (err < 0) {
		dev_err(&dev->dev, "Can't get property 'reg'\n");
		return -EFAULT;
	}

	srio_dev->regs.res = devm_request_mem_region(&dev->dev, regs.start,
					regs.end + 1 - regs.start, "srio regs");
	if (!srio_dev->regs.res) {
		dev_err(&dev->dev, "devm_request_mem_region failed\n");
		return -ENOMEM;
	}

	dev_dbg(&dev->dev, "reg start 0x%016llx, size 0x%016llx.\n",
		srio_dev->regs.res->start,
		srio_dev->regs.res->end + 1 - srio_dev->regs.res->start);

	srio_dev->regs.regs_win = devm_ioremap(&dev->dev,
						srio_dev->regs.res->start,
						srio_dev->regs.res->end -
						srio_dev->regs.res->start + 1);
	if (!srio_dev->regs.regs_win) {
		dev_err(&dev->dev, "devm_ioremap failed\n");
		return -EIO;
	}

	srio_dev->irq = irq_of_parse_and_map(srio_node, 0);
	dev_dbg(srio_dev->dev, "err irq: %d\n", srio_dev->irq);

	INIT_LIST_HEAD(&srio_dev->port_list);

	for_each_child_of_node(dev->dev.of_node, child) {
		err = fsl_srio_port_probe(srio_dev, child);
		if (err < 0) {
			fsl_srio_port_remove(srio_dev);
			return err;
		}
	}

	err = srio_uio_init(srio_dev);
	if (err < 0) {
		dev_err(srio_dev->dev, "srio_uio_init failed\n");
		srio_uio_cleanup(srio_dev);
		return err;
	}

	dev_info(srio_dev->dev, "Rapidio UIO driver initialized\n");

	return 0;
}

static int fsl_srio_uio_remove(struct platform_device *dev)
{
	struct srio_dev *srio_dev = platform_get_drvdata(dev);

	srio_uio_cleanup(srio_dev);

	return 0;
}

static const struct of_device_id fsl_srio_uio_match[] = {
	{
		.compatible = "fsl,srio",
	},
	{}
};

static struct platform_driver fsl_of_srio_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "fsl-of-srio",
		.of_match_table = fsl_srio_uio_match,
	},
	.probe = fsl_srio_uio_probe,
	.remove = fsl_srio_uio_remove,
};

static __init int fsl_srio_uio_init(void)
{
	int err;

	err = platform_driver_register(&fsl_of_srio_driver);
	if (err < 0)
		pr_warn(
			": %s:%hu:%s(): platform_driver_register() = %d\n",
			__FILE__, __LINE__, __func__, err);

	return err;
}

static void __exit fsl_srio_uio_exit(void)
{
	platform_driver_unregister(&fsl_of_srio_driver);

	pr_warn("fsl srio uio driver removed\n");
}

module_init(fsl_srio_uio_init);
module_exit(fsl_srio_uio_exit);
MODULE_LICENSE("GPL");
