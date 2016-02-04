/*
 * Freescale QorIQ Platforms GUTS Driver
 *
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/io.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/fsl/guts.h>

struct guts {
	struct ccsr_guts __iomem *regs;
	bool little_endian;
};

static struct guts *guts;

u32 guts_get_svr(void)
{
	u32 svr = 0;

	if (!(guts->regs)) {
#ifdef CONFIG_PPC
		svr =  mfspr(SPRN_SVR);
#endif
		return svr;
	}

	if (guts->little_endian)
		svr = ioread32(&guts->regs->svr);
	else
		svr = ioread32be(&guts->regs->svr);

	return svr;
}
EXPORT_SYMBOL_GPL(guts_get_svr);

static int guts_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;

	guts = kzalloc(sizeof(*guts), GFP_KERNEL);
	if (!guts)
		return -ENOMEM;

	if (of_property_read_bool(np, "little-endian"))
		guts->little_endian = true;
	else
		guts->little_endian = false;

	guts->regs = of_iomap(np, 0);
	if (!(guts->regs))
		return -ENOMEM;

	of_node_put(np);
	return 0;
}

static int guts_remove(struct platform_device *pdev)
{
	iounmap(guts->regs);
	kfree(guts);
	return 0;
}

/*
 * Table for matching compatible strings, for device tree
 * guts node, for Freescale QorIQ SOCs.
 */
static const struct of_device_id guts_of_match[] = {
	/* For T4 & B4 SOCs */
	{ .compatible = "fsl,qoriq-device-config-1.0", },
	/* For P Series SOCs */
	{ .compatible = "fsl,qoriq-device-config-2.0", },
	{ .compatible = "fsl,p1010-guts", },
	{ .compatible = "fsl,p1020-guts", },
	{ .compatible = "fsl,p1021-guts", },
	{ .compatible = "fsl,p1022-guts", },
	{ .compatible = "fsl,p1023-guts", },
	{ .compatible = "fsl,p2020-guts", },
	/* For BSC Series SOCs */
	{ .compatible = "fsl,bsc9131-guts", },
	{ .compatible = "fsl,bsc9132-guts", },
	/* For Layerscape Series SOCs */
	{ .compatible = "fsl,ls1021a-dcfg", },
	{}
};
MODULE_DEVICE_TABLE(of, guts_of_match);

static struct platform_driver guts_driver = {
	.driver = {
		.name = "fsl-guts",
		.of_match_table = guts_of_match,
	},
	.probe = guts_probe,
	.remove = guts_remove,
};

static int __init guts_drv_init(void)
{
	return platform_driver_register(&guts_driver);
}
subsys_initcall(guts_drv_init);

static void __exit guts_drv_exit(void)
{
	platform_driver_unregister(&guts_driver);
}
module_exit(guts_drv_exit);

MODULE_AUTHOR("Freescale Semiconductor, Inc.");
MODULE_DESCRIPTION("Freescale QorIQ Platforms GUTS Driver");
MODULE_LICENSE("GPL");
