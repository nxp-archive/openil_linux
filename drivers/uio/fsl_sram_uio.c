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
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/io.h>
#include <linux/uio_driver.h>
#include <linux/slab.h>
#include <linux/list.h>

static const char l2sram_uio_version[] = "fsl SRAM UIO driver v1.0";

#define NAME_LENGTH 30

#define L2CR_L2FI               0x40000000      /* L2 flash invalidate */
#define L2CR_L2IO               0x00200000      /* L2 instruction only */
#define L2CR_SRAM_ZERO          0x00000000      /* L2SRAM zero size */
#define L2CR_SRAM_FULL          0x00010000      /* L2SRAM full size */
#define L2CR_SRAM_HALF          0x00020000      /* L2SRAM half size */
#define L2CR_SRAM_TWO_HALFS     0x00030000      /* L2SRAM two half sizes */
#define L2CR_SRAM_QUART         0x00040000      /* L2SRAM one quarter size */
#define L2CR_SRAM_TWO_QUARTS    0x00050000      /* L2SRAM two quarter size */
#define L2CR_SRAM_EIGHTH        0x00060000      /* L2SRAM one eighth size */
#define L2CR_SRAM_TWO_EIGHTH    0x00070000      /* L2SRAM two eighth size */

#define L2SRAM_OPTIMAL_SZ_SHIFT 0x00000003      /* Optimum size for L2SRAM */

#define L2SRAM_BAR_MSK_LO18     0xFFFFC000      /* Lower 18 bits */
#define L2SRAM_BARE_MSK_HI4     0x0000000F      /* Upper 4 bits */

/* 0x000 - L2 control */
#define L2_CACHE_L2CTL		0x0
/* 0x100 - SRAM base address 0 */
#define L2_CACHE_L2SRBAR0	0x100
/* 0x104 - SRAM base address 0 */
#define L2_CACHE_L2SRBAEA0	0x104

enum cache_sram_lock_ways {
	LOCK_WAYS_ZERO,
	LOCK_WAYS_EIGHTH,
	LOCK_WAYS_TWO_EIGHTH,
	LOCK_WAYS_HALF = 4,
	LOCK_WAYS_FULL = 8,
};

struct sram_parameters {
	unsigned int sram_size;
	uint64_t sram_offset;
};

static const char uio_device_name[] = "fsl-sram";

static char *cache_sram;

struct l2sram_uio_info {
	atomic_t ref;
	struct uio_info uio;
	char name[NAME_LENGTH];
};

struct l2sram_dev {
	u32 revision;
	int irq;
	void __iomem *global_regs;
	struct device *dev;
	struct resource res;
	struct sram_parameters sram_para;
	struct l2sram_uio_info info;
};

static int l2sram_uio_open(struct uio_info *info, struct inode *inode)
{
	struct l2sram_uio_info *i = container_of(info,
			struct l2sram_uio_info, uio);

	if (!atomic_dec_and_test(&i->ref)) {
		pr_err("%s: failing non-exclusive open()\n", i->name);
		atomic_inc(&i->ref);
		return -EBUSY;
	}
	return 0;
}

static int l2sram_uio_release(struct uio_info *info, struct inode *inode)
{
	struct l2sram_uio_info *i = container_of(info,
			struct l2sram_uio_info, uio);
	atomic_inc(&i->ref);
	return 0;
}

static int __init l2sram_uio_init(struct l2sram_dev *uio_dev)
{
	int ret;
	struct l2sram_uio_info *info;

	info = &uio_dev->info;
	atomic_set(&info->ref, 1);
	info->uio.version = l2sram_uio_version;
	info->uio.mem[0].name = uio_dev->info.name;
	info->uio.name = uio_dev->info.name;
	info->uio.mem[0].addr = uio_dev->res.start;
	info->uio.mem[0].size = uio_dev->res.end - uio_dev->res.start + 1;
	/* Internal_addr may use other way for user space */
	info->uio.mem[0].internal_addr = uio_dev->global_regs;
	info->uio.mem[0].memtype = UIO_MEM_PHYS;
	info->uio.open = l2sram_uio_open;
	info->uio.release = l2sram_uio_release;
	info->uio.priv = &uio_dev->info;

	ret = uio_register_device(uio_dev->dev, &info->uio);
	if (ret) {
		pr_err("l2sram_uio: UIO registration failed\n");
		return ret;
	}
	return 0;
}

static int get_cache_sram_params(struct sram_parameters *sram_params)
{
	unsigned long long addr;
	unsigned int size;
	char *str;

	if (!cache_sram)
		return -EINVAL;

	str = strchr(cache_sram, ',');
	if (!str)
		return -EINVAL;

	*str = 0;
	str++;

	if (kstrtouint(str, 0, &size) < 0 ||
			kstrtoull(cache_sram, 0, &addr) < 0)
		return -EINVAL;

	sram_params->sram_offset = addr;
	sram_params->sram_size = size;
	return 0;
}

static int __init get_cache_sram_cmdline(char *str)
{
	if (!str)
		return 0;

	cache_sram = str;
	return 1;
}

__setup("cache-sram=", get_cache_sram_cmdline);

static int fsl_l2sram_probe(struct platform_device *dev)
{
	struct resource regs;
	struct l2sram_dev *l2sram_dev;
	struct device_node *l2sram_node;
	const unsigned int *prop;
	unsigned int l2cache_size;
	unsigned int rem;
	unsigned char ways;
	int ret;

	l2sram_node = dev->dev.of_node;
	if (!l2sram_node) {
		dev_err(&dev->dev, "Device OF-Node is NULL");
		return -EFAULT;
	}

	prop = of_get_property(dev->dev.of_node, "cache-size", NULL);
	if (!prop) {
		dev_err(&dev->dev, "Missing L2 cache-size\n");
		return -EINVAL;
	}

	l2cache_size = *prop;

	dev_info(&dev->dev, "Of-device full name %s initialized\n",
		 l2sram_node->full_name);

	l2sram_dev = kzalloc(sizeof(struct l2sram_dev), GFP_KERNEL);
	if (!l2sram_dev) {
		dev_err(&dev->dev, "Can't allocate memory for 'l2sram_dev'\n");
		return -ENOMEM;
	}

	l2sram_dev->dev = &dev->dev;
	platform_set_drvdata(dev, l2sram_dev);

	/* L2CACHE as the global_regs */
	ret = of_address_to_resource(l2sram_node, 0, &regs);
	if (unlikely(ret < 0)) {
				dev_err(&dev->dev,
					"Can't get property 'reg'\n");
				ret = -EFAULT;
				goto abort;
			}

	l2sram_dev->global_regs = devm_ioremap(&dev->dev, regs.start,
				regs.end - regs.start + 1);
	if (unlikely(!l2sram_dev->global_regs)) {
		dev_err(&dev->dev, "devm_ioremap failed\n");
		ret = -EIO;
		goto abort1;
	}

	if (get_cache_sram_params(&l2sram_dev->sram_para)) {
		dev_err(&dev->dev,
			"Entire L2 as cache, provide valid sram address and size\n");
		return -EINVAL;
	}

	rem = l2cache_size % l2sram_dev->sram_para.sram_size;
	ways = LOCK_WAYS_FULL * l2sram_dev->sram_para.sram_size / l2cache_size;
	if (rem || (ways & (ways - 1))) {
		dev_err(&dev->dev, "Illegal cache-sram-size in command line\n");
		ret = -EINVAL;
		goto abort1;
	}

	/* Write bits[0-17] to L2_CACHE_L2SRBAR0 */
	out_be32(l2sram_dev->global_regs + L2_CACHE_L2SRBAR0,
		l2sram_dev->sram_para.sram_offset & L2SRAM_BAR_MSK_LO18);

	/* Write bits[18-21] to L2_CACHE_L2SRBAEA0 */
#ifdef CONFIG_PHYS_64BIT
	out_be32(l2sram_dev->global_regs + L2_CACHE_L2SRBAEA0 , (l2sram_dev->
			sram_para.sram_offset >> 32) & L2SRAM_BARE_MSK_HI4);
#endif
	clrsetbits_be32(l2sram_dev->global_regs
			+ L2_CACHE_L2CTL, L2CR_L2E, L2CR_L2FI);

	switch (ways) {
	case LOCK_WAYS_EIGHTH:
		setbits32(l2sram_dev->global_regs + L2_CACHE_L2CTL,
			L2CR_L2E | L2CR_L2FI | L2CR_SRAM_EIGHTH);
		break;

	case LOCK_WAYS_TWO_EIGHTH:
		setbits32(l2sram_dev->global_regs + L2_CACHE_L2CTL,
			L2CR_L2E | L2CR_L2FI | L2CR_SRAM_QUART);
		break;

	case LOCK_WAYS_HALF:
	setbits32(l2sram_dev->global_regs + L2_CACHE_L2CTL,
			L2CR_L2E | L2CR_L2FI | L2CR_SRAM_HALF);
		break;

	case LOCK_WAYS_FULL:
	default:
	setbits32(l2sram_dev->global_regs + L2_CACHE_L2CTL,
			L2CR_L2E | L2CR_L2FI | L2CR_SRAM_FULL);
		break;
	}

	snprintf(l2sram_dev->info.name, sizeof(l2sram_dev->info.name) - 1,
			uio_device_name);

	regs.start = l2sram_dev->sram_para.sram_offset;
	regs.end = l2sram_dev->sram_para.sram_offset
			+ l2sram_dev->sram_para.sram_size - 1;
	l2sram_dev->res = regs;

	/* Now we can register UIO */
	ret = l2sram_uio_init(l2sram_dev);
	if (ret)
			goto abort1;
	return 0;

abort1:
	iounmap(l2sram_dev->global_regs);
abort:
	platform_set_drvdata(dev, NULL);
	kfree(l2sram_dev);
	return ret;
}

static int fsl_l2sram_remove(struct platform_device *dev)
{
	struct l2sram_dev *l2sram_dev = platform_get_drvdata(dev);

	if (!l2sram_dev)
		return 0;

	uio_unregister_device(&l2sram_dev->info.uio);
	platform_set_drvdata(dev, NULL);
	kfree(l2sram_dev);
	iounmap(l2sram_dev->global_regs);
	return 0;
}

static const struct of_device_id fsl_of_l2sram_match[] = {
	{
		.compatible = "fsl,p1010-l2-cache-controller",
	},
	{
		.compatible = "fsl,c293-l2-cache-controller",
	},
	{},
};
MODULE_DEVICE_TABLE(of, fsl_of_l2sram_match);

static struct platform_driver fsl_l2sram_driver = {
	.driver = {
		.name = "fsl-sram-uio",
		.owner = THIS_MODULE,
		.of_match_table = fsl_of_l2sram_match,
	},
	.probe = fsl_l2sram_probe,
	.remove = fsl_l2sram_remove,
};

module_platform_driver(fsl_l2sram_driver);
