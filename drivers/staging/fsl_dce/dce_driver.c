/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * This software is provided by Freescale Semiconductor "as is" and any
 * express or implied warranties, including, but not limited to, the implied
 * warranties of merchantability and fitness for a particular purpose are
 * disclaimed. In no event shall Freescale Semiconductor be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential damages
 * (including, but not limited to, procurement of substitute goods or services;
 * loss of use, data, or profits; or business interruption) however caused and
 * on any theory of liability, whether in contract, strict liability, or tort
 * (including negligence or otherwise) arising in any way out of the use of
 * this software, even if advised of the possibility of such damage.
 */

#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/export.h>
#include <linux/module.h>
#include "fsl_dce.h"
#include "flib/dce_regs.h"
#include "flib/dce_defs.h"

#define DRV_VERSION "0.1"

u16 dce_ip_rev = DCE_REV10;
EXPORT_SYMBOL(dce_ip_rev);

/* Pointer used to represent the DCE CCSR map and its instance */
static struct dce_regs *global_dce_regs;

/*
 * Driver-private storage for a single DCE block instance
 */
struct dce_drv_private {
	struct device *dev;
	struct platform_device *pdev;

	/* Physical-presence section */
	struct dce_regs __iomem *topregs;
	int err_irq;		/* Error interrupt number */
};

/* Simple DCE error interrupt handler */
static irqreturn_t dce_isr(int irq, void *st_dev)
{
	struct device *dev = st_dev;
	struct dce_drv_private *ctrlpriv = dev_get_drvdata(dev);
	static u32 last_isrstate;
	u32 isrstate = ioread32be(&ctrlpriv->topregs->isr) ^ last_isrstate;

	/* What new ISR state has been raise */
	if (!isrstate)
		return IRQ_NONE;
	if (ISEQ_32FTK(isrstate, DCE_ISR_SBE, AT_LEAST_ONE))
		dev_err(dev, "Single Bit Error detected\n");
	if (ISEQ_32FTK(isrstate, DCE_ISR_DBE, AT_LEAST_ONE))
		dev_err(dev, "Double Bit Error detected\n");
	if (ISEQ_32FTK(isrstate, DCE_ISR_UWE, AT_LEAST_ONE)) {
		u32 uwe_high, uwe_low;

		/* print extra info registers */
		uwe_high = ioread32be(&ctrlpriv->topregs->uwe_info_h);
		uwe_low = ioread32be(&ctrlpriv->topregs->uwe_info_l);
		dev_err(dev,
		 "Unreported Write Error detected: infoh = 0x%x infol = 0x%x\n",
			uwe_high, uwe_low);
	}

	/* Clear the ier interrupt bit */
	last_isrstate |= isrstate;
	iowrite32be(~last_isrstate, &ctrlpriv->topregs->ier);

	return IRQ_HANDLED;
}

static int fsl_dce_remove(struct platform_device *pdev)
{
	struct device *ctrldev;
	struct dce_drv_private *ctrlpriv;
	struct dce_regs __iomem *topregs;
	int ret = 0;

	ctrldev = &pdev->dev;
	ctrlpriv = dev_get_drvdata(ctrldev);
	topregs = ctrlpriv->topregs;

	/* Disable dce */
	iowrite32be(DCE_CFG_EN_DISABLE, &topregs->cfg);

	/* Release interrupt */
	free_irq(ctrlpriv->err_irq, ctrldev);

	/* Unmap controller region */
	iounmap(topregs);
	kfree(ctrlpriv);
	global_dce_regs = NULL;

	dev_info(&pdev->dev, "device full name %s removed\n",
		pdev->dev.of_node->full_name);
	return ret;
}

static int fsl_dce_probe(struct platform_device *pdev)
{
	int err;
	struct device *dev;
	struct device_node *nprop = NULL;
	struct dce_regs __iomem *topregs;
	struct dce_drv_private *ctrlpriv;
	const char *s;
	int ret;

	/*
	 * TODO: This standby handling won't work properly after failover, it's
	 * just to allow bring up for now.
	 */
	s = of_get_property(nprop, "fsl,hv-claimable", &ret);
	if (s && !strcmp(s, "standby"))
		return 0;

	ctrlpriv = kzalloc(sizeof(struct dce_drv_private), GFP_KERNEL);
	if (!ctrlpriv)
		return -ENOMEM;

	dev = &pdev->dev;
	dev_set_drvdata(dev, ctrlpriv);
	ctrlpriv->pdev = pdev;
	nprop = pdev->dev.of_node;

	/* Get configuration properties from device tree */

	/* First, get register page */
	topregs = of_iomap(nprop, 0);
	if (topregs == NULL) {
		dev_err(dev, "of_iomap() failed\n");
		err = -ENOMEM;
		goto out_free_ctrlpriv;
	}
	ctrlpriv->topregs = topregs;
	global_dce_regs = topregs;

	/* Get the IRQ of the error interrupt */
	ctrlpriv->err_irq = of_irq_to_resource(nprop, 0, NULL);
	if (!ctrlpriv->err_irq) {
		dev_warn(dev, "Can't get %s property '%s'\n", nprop->full_name,
			 "interrupts");
	} else {
		/* Register the dce ISR handler */
		err = request_irq(ctrlpriv->err_irq, dce_isr, IRQF_SHARED,
					"dce-err", dev);
		if (err) {
			dev_err(dev, "request_irq() failed\n");
			goto out_free_ctrlpriv;
		}
	}

	/*
	 * Set System Memory Cache Attribute Control Register. Set all
	 * transactions to coherent.
	 */
	iowrite32be(
		(FL_FGENTK(DCE_SMCACR_CHWC, COHERENT) |
		FL_FGENTK(DCE_SMCACR_SCWC, COHERENT) |
		FL_FGENTK(DCE_SMCACR_FDWC, COHERENT) |
		FL_FGENTK(DCE_SMCACR_DHWC, COHERENT) |
		FL_FGENTK(DCE_SMCACR_CHRC, COHERENT) |
		FL_FGENTK(DCE_SMCACR_SCRC, COHERENT) |
		FL_FGENTK(DCE_SMCACR_FDRC, COHERENT) |
		FL_FGENTK(DCE_SMCACR_DHRC, COHERENT)),
		&topregs->smcacr);

	/* Enable interrupts */
	/*iowrite32be(DCE_IER_ALL, &topregs->ier);*/
	iowrite32be(FL_FGENTK(DCE_IER_ALL, ENABLE), &topregs->ier);

	/* Enable dce */
	iowrite32be(FL_FGENTK(DCE_CFG_EN, ENABLE), &topregs->cfg);

	dev_info(&pdev->dev, "Device %s initialized ver: 0x%08x\n\n",
		pdev->dev.of_node->full_name, ioread32be(&topregs->ip_rev_1));

	return 0;

out_free_ctrlpriv:
	kfree(ctrlpriv);
	dev_set_drvdata(dev, NULL);
	global_dce_regs = NULL;
	return err;
}

static struct of_device_id fsl_dce_match[] = {
	{
		.compatible = "fsl,dce",
	},
	{}
};
MODULE_DEVICE_TABLE(of, fsl_dce_match);

static struct platform_driver fsl_dce_driver = {
	.driver = {
		.name = "fsl-dce",
		.owner = THIS_MODULE,
		.of_match_table = fsl_dce_match,
	},
	.probe		= fsl_dce_probe,
	.remove		= fsl_dce_remove,
};

static int __init fsl_dce_init(void)
{
	int ret;

	ret = platform_driver_register(&fsl_dce_driver);
	if (ret)
		pr_err("fsl-dce: Failed to register platform driver\n");

	return ret;
}

static void __exit fsl_dce_exit(void)
{
	platform_driver_unregister(&fsl_dce_driver);
}

module_init(fsl_dce_init);
module_exit(fsl_dce_exit);

MODULE_AUTHOR("Jeffrey Ladouceur");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("FSL DCE driver");
MODULE_VERSION(DRV_VERSION);

/*
 * These APIs are the only functional hooks into the control driver, besides the
 * sysfs attributes.
 */

int fsl_dce_have_control(void)
{
	return global_dce_regs ? 1 : 0;
}
EXPORT_SYMBOL(fsl_dce_have_control);

int fsl_dce_get_stat(enum fsl_dce_stat_attr attr, u64 *val, int reset)
{
	if (!fsl_dce_have_control())
		return -ENODEV;

	switch (attr) {
	case DCE_COMP_INPUT_BYTES:
		*val = ioread32be(&global_dce_regs->cibc_h);
		*val <<= 32;
		*val |= ioread32be(&global_dce_regs->cibc_l);
		if (reset) {
			iowrite32be(0, &global_dce_regs->cibc_l);
			iowrite32be(0, &global_dce_regs->cibc_h);
		}
		break;
	case DCE_COMP_OUTPUT_BYTES:
		*val = ioread32be(&global_dce_regs->cobc_h);
		*val <<= 32;
		*val |= ioread32be(&global_dce_regs->cobc_l);
		if (reset) {
			iowrite32be(0, &global_dce_regs->cobc_l);
			iowrite32be(0, &global_dce_regs->cobc_h);
		}
		break;
	case DCE_DECOMP_INPUT_BYTES:
		*val = ioread32be(&global_dce_regs->dibc_h);
		*val <<= 32;
		*val |= ioread32be(&global_dce_regs->dibc_l);
		if (reset) {
			iowrite32be(0, &global_dce_regs->dibc_l);
			iowrite32be(0, &global_dce_regs->dibc_h);
		}
		break;
	case DCE_DECOMP_OUTPUT_BYTES:
		*val = ioread32be(&global_dce_regs->dobc_h);
		*val <<= 32;
		*val |= ioread32be(&global_dce_regs->dobc_l);
		if (reset) {
			iowrite32be(0, &global_dce_regs->dobc_l);
			iowrite32be(0, &global_dce_regs->dobc_h);
		}
		break;
	default:
		pr_err("fsl_dce: Unknown attr %u\n", attr);
		return -EINVAL;
	};
	return 0;
}
EXPORT_SYMBOL(fsl_dce_get_stat);

int fsl_dce_clear_stat(enum fsl_dce_stat_attr attr)
{
	if (!fsl_dce_have_control())
		return -ENODEV;

	switch (attr) {
	case DCE_COMP_INPUT_BYTES:
		iowrite32be(0, &global_dce_regs->cibc_l);
		iowrite32be(0, &global_dce_regs->cibc_h);
		break;
	case DCE_COMP_OUTPUT_BYTES:
		iowrite32be(0, &global_dce_regs->cobc_l);
		iowrite32be(0, &global_dce_regs->cobc_h);
		break;
	case DCE_DECOMP_INPUT_BYTES:
		iowrite32be(0, &global_dce_regs->dibc_l);
		iowrite32be(0, &global_dce_regs->dibc_h);
		break;
	case DCE_DECOMP_OUTPUT_BYTES:
		iowrite32be(0, &global_dce_regs->dobc_l);
		iowrite32be(0, &global_dce_regs->dobc_h);
		break;
	default:
		pr_err("fsl_dce: Unknown attr %u\n", attr);
		return -EINVAL;
	};
	return 0;
}
EXPORT_SYMBOL(fsl_dce_clear_stat);


