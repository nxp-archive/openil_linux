/*
 * PCIe host controller driver for Freescale Layerscape SoCs
 *
 * Copyright (C) 2014 Freescale Semiconductor.
 *
 * Author: Minghuan Lian <Minghuan.Lian@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/resource.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>
#include <linux/list.h>
#include <linux/syscore_ops.h>

#include "pcie-designware.h"

/* PEX1/2 Misc Ports Status Register */
#define SCFG_PEXMSCPORTSR(pex_idx)	(0x94 + (pex_idx) * 4)
#define SCFG_PEXPMWRCR(pex_idx)		(0x5c + (pex_idx) * 0x64)
#define LTSSM_STATE_SHIFT	20
#define LTSSM_STATE_MASK	0x3f
#define LTSSM_PCIE_L0		0x11 /* L0 state */
#define LTSSM_PCIE_L2_IDLE	0x15 /* L2 idle state */

/* PEX Internal Configuration Registers */
#define PCIE_STRFMR1		0x71c /* Symbol Timer & Filter Mask Register1 */
#define PCIE_DBI_RO_WR_EN	0x8bc /* DBI Read-Only Write Enable Register */

/* PEX LUT registers */
#define PCIE_LUT_DBG		0x7FC /* PEX LUT Debug Register */
#define PCIE_LUT_UDR(n)		(0x800 + (n) * 8)
#define PCIE_LUT_LDR(n)		(0x804 + (n) * 8)
#define PCIE_LUT_MASK_ALL	0xffff
#define PCIE_LUT_DR_NUM		32
#define PCIE_LUT_ENABLE		(1 << 31)

#define PCIE_PM_SCR		0x44
#define PCIE_PM_SCR_PMEEN	0x10
#define PCIE_PM_SCR_PMEPS_D0	0xfffc
#define PCIE_PM_SCR_PMEPS_D3	0x3
#define PCIE_PM_SCR_PME_STATE	0x8000

#define PCIE_PEX_DCR		0x78
#define PCIE_PEX_DCR_AUXPOWEREN	0x0400

#define PCIE_PEX_SSR		0x8a
#define PCIE_PEX_SSR_PDS	0x40

#define PCIE_PEX_RCR		0x8c
#define PCIE_PEX_RCR_PMEIE	0x0008

#define PCIE_PEX_RSR		0x90
#define PCIE_PEX_PMES		0x00010000

#define QIXIS_RST_FORCE_3		0x45
#define QIXIS_RST_FORCE_3_PCIESLOT	0xe0

#define CPLD_RST_PCIE_SLOT	0x14
#define CPLD_RST_PCIESLOT	0x3

#define PCIE_IATU_NUM		6

struct ls_pcie;

struct ls_pcie_pm_data {
	void __iomem *fpga;
	void __iomem *cpld;
};

struct ls_pcie_pm_ops {
	u32 (*get_link_state)(struct ls_pcie *pcie);
	int (*send_turn_off_message)(struct ls_pcie *pcie);
	void (*clear_turn_off_message)(struct ls_pcie *pcie);
	void (*reset_slot)(struct ls_pcie *pcie,
			   struct ls_pcie_pm_data *pm_data);
};

struct ls_pcie_drvdata {
	u32 lut_offset;
	u32 ltssm_shift;
	struct pcie_host_ops *ops;
	struct ls_pcie_pm_ops *pm;
};

struct ls_pcie {
	struct list_head list_node;
	void __iomem *dbi;
	void __iomem *lut;
	struct regmap *scfg;
	struct pcie_port pp;
	const struct ls_pcie_drvdata *drvdata;
	struct ls_pcie_pm_data pm_data;
	int index;
	const u32 *avail_streamids;
	int streamid_index;
	int pme_irq;
	bool in_slot;
};

#define to_ls_pcie(x)	container_of(x, struct ls_pcie, pp)

static void ls_pcie_host_init(struct pcie_port *pp);

u32 set_pcie_streamid_translation(struct pci_dev *pdev, u32 devid)
{
	u32 index, streamid;
	struct pcie_port *pp = pdev->bus->sysdata;
	struct ls_pcie *pcie = to_ls_pcie(pp);

	if (!pcie->avail_streamids || !pcie->streamid_index)
		return ~(u32)0;

	index = --pcie->streamid_index;
	/* mask is set as all zeroes, want to match all bits */
	iowrite32((devid << 16), pcie->lut + PCIE_LUT_UDR(index));
	streamid = be32_to_cpup(&pcie->avail_streamids[index]);
	iowrite32(streamid | PCIE_LUT_ENABLE, pcie->lut + PCIE_LUT_LDR(index));

	return streamid;
}

LIST_HEAD(hose_list);

static bool ls_pcie_is_bridge(struct ls_pcie *pcie)
{
	u32 header_type;

	header_type = ioread8(pcie->dbi + PCI_HEADER_TYPE);
	header_type &= 0x7f;

	return header_type == PCI_HEADER_TYPE_BRIDGE;
}

/* Clear multi-function bit */
static void ls_pcie_clear_multifunction(struct ls_pcie *pcie)
{
	iowrite8(PCI_HEADER_TYPE_BRIDGE, pcie->dbi + PCI_HEADER_TYPE);
}

/* Fix class value */
static void ls_pcie_fix_class(struct ls_pcie *pcie)
{
	iowrite16(PCI_CLASS_BRIDGE_PCI, pcie->dbi + PCI_CLASS_DEVICE);
}

/* Drop MSG TLP except for Vendor MSG */
static void ls_pcie_drop_msg_tlp(struct ls_pcie *pcie)
{
	u32 val;

	val = ioread32(pcie->dbi + PCIE_STRFMR1);
	val &= 0xDFFFFFFF;
	iowrite32(val, pcie->dbi + PCIE_STRFMR1);
}

static void ls_pcie_disable_outbound_atus(struct ls_pcie *pcie)
{
	int i;

	for (i = 0; i < PCIE_IATU_NUM; i++)
		dw_pcie_disable_outbound_atu(&pcie->pp, i);
}

static int ls1021_pcie_link_up(struct pcie_port *pp)
{
	u32 state;
	struct ls_pcie *pcie = to_ls_pcie(pp);

	if (!pcie->scfg)
		return 0;

	regmap_read(pcie->scfg, SCFG_PEXMSCPORTSR(pcie->index), &state);
	state = (state >> LTSSM_STATE_SHIFT) & LTSSM_STATE_MASK;

	if (state < LTSSM_PCIE_L0)
		return 0;

	return 1;
}

static u32 ls1021_pcie_get_link_state(struct ls_pcie *pcie)
{
	u32 state;

	if (!pcie->scfg)
		return 0;

	regmap_read(pcie->scfg, SCFG_PEXMSCPORTSR(pcie->index), &state);
	state = (state >> LTSSM_STATE_SHIFT) & LTSSM_STATE_MASK;

	return state;
}

static int ls1021_pcie_send_turn_off_message(struct ls_pcie *pcie)
{
	u32 val;

	if (!pcie->scfg)
		return -EINVAL;

	/* Send Turn_off message */
	regmap_read(pcie->scfg, SCFG_PEXPMWRCR(pcie->index), &val);
	val |= 0x80000000;
	regmap_write(pcie->scfg, SCFG_PEXPMWRCR(pcie->index), val);

	return 0;
}

static void ls1021_pcie_clear_turn_off_message(struct ls_pcie *pcie)
{
	u32 val;

	if (!pcie->scfg)
		return;

	/* Clear Turn_off message */
	regmap_read(pcie->scfg, SCFG_PEXPMWRCR(pcie->index), &val);
	val &= 0x00000000;
	regmap_write(pcie->scfg, SCFG_PEXPMWRCR(pcie->index), val);
}

static void ls1021_pcie_reset_slot(struct ls_pcie *pcie,
				   struct ls_pcie_pm_data *pm_data)
{
	u8 val;

	/* Try to reset PCIe slot to relink EP */
	if (pm_data->fpga) {
		/* PULL DOWN PCIe RST# */
		val = ioread8(pm_data->fpga + QIXIS_RST_FORCE_3);
		val |= QIXIS_RST_FORCE_3_PCIESLOT;
		iowrite8(val, pm_data->fpga + QIXIS_RST_FORCE_3);

		/* PULL ON PCIe RST# */
		val = ioread8(pm_data->fpga + QIXIS_RST_FORCE_3);
		val &= 0x0;
		iowrite8(val, pm_data->fpga + QIXIS_RST_FORCE_3);
	}

	if (pm_data->cpld) {
		/* PULL DOWN PCIe RST# */
		val = ioread8(pm_data->cpld + CPLD_RST_PCIE_SLOT);
		val &= 0x0;
		iowrite8(val, pm_data->cpld + CPLD_RST_PCIE_SLOT);

		/* PULL ON PCIe RST# */
		val = ioread8(pm_data->cpld + CPLD_RST_PCIE_SLOT);
		val |= CPLD_RST_PCIESLOT;
		iowrite8(val, pm_data->cpld + CPLD_RST_PCIE_SLOT);
	}
}

static void ls1021_pcie_host_init(struct pcie_port *pp)
{
	struct ls_pcie *pcie = to_ls_pcie(pp);
	u32 index[2];

	pcie->scfg = syscon_regmap_lookup_by_phandle(pp->dev->of_node,
						     "fsl,pcie-scfg");
	if (IS_ERR(pcie->scfg)) {
		dev_err(pp->dev, "No syscfg phandle specified\n");
		pcie->scfg = NULL;
		return;
	}

	if (of_property_read_u32_array(pp->dev->of_node,
				       "fsl,pcie-scfg", index, 2)) {
		pcie->scfg = NULL;
		return;
	}
	pcie->index = index[1];

	ls_pcie_host_init(pp);

	dw_pcie_setup_rc(pp);
}

static int ls_pcie_link_up(struct pcie_port *pp)
{
	struct ls_pcie *pcie = to_ls_pcie(pp);
	u32 state;

	state = (ioread32(pcie->lut + PCIE_LUT_DBG) >>
		 pcie->drvdata->ltssm_shift) &
		 LTSSM_STATE_MASK;

	if (state < LTSSM_PCIE_L0)
		return 0;

	return 1;
}

static u32 ls_pcie_get_link_state(struct ls_pcie *pcie)
{
	return (ioread32(pcie->lut + PCIE_LUT_DBG) >>
		 pcie->drvdata->ltssm_shift) &
		 LTSSM_STATE_MASK;
}

static void ls_pcie_host_init(struct pcie_port *pp)
{
	struct ls_pcie *pcie = to_ls_pcie(pp);

	iowrite32(1, pcie->dbi + PCIE_DBI_RO_WR_EN);
	ls_pcie_fix_class(pcie);
	ls_pcie_clear_multifunction(pcie);
	ls_pcie_drop_msg_tlp(pcie);
	iowrite32(0, pcie->dbi + PCIE_DBI_RO_WR_EN);

	ls_pcie_disable_outbound_atus(pcie);
}

static int ls_pcie_msi_host_init(struct pcie_port *pp,
				 struct msi_controller *chip)
{
	struct device_node *msi_node;
	struct device_node *np = pp->dev->of_node;

	/*
	 * The MSI domain is set by the generic of_msi_configure().  This
	 * .msi_host_init() function keeps us from doing the default MSI
	 * domain setup in dw_pcie_host_init() and also enforces the
	 * requirement that "msi-parent" exists.
	 */
	msi_node = of_parse_phandle(np, "msi-parent", 0);
	if (!msi_node) {
		dev_err(pp->dev, "failed to find msi-parent\n");
		return -EINVAL;
	}

	return 0;
}

static struct pcie_host_ops ls1021_pcie_host_ops = {
	.link_up = ls1021_pcie_link_up,
	.host_init = ls1021_pcie_host_init,
	.msi_host_init = ls_pcie_msi_host_init,
};

static struct ls_pcie_pm_ops ls1021_pcie_host_pm_ops = {
	.get_link_state = &ls1021_pcie_get_link_state,
	.send_turn_off_message = &ls1021_pcie_send_turn_off_message,
	.clear_turn_off_message = &ls1021_pcie_clear_turn_off_message,
	.reset_slot = &ls1021_pcie_reset_slot,
};

static struct pcie_host_ops ls_pcie_host_ops = {
	.link_up = ls_pcie_link_up,
	.host_init = ls_pcie_host_init,
	.msi_host_init = ls_pcie_msi_host_init,
};

static struct ls_pcie_pm_ops ls_pcie_host_pm_ops = {
	.get_link_state = &ls_pcie_get_link_state,
};

static struct ls_pcie_drvdata ls1021_drvdata = {
	.ops = &ls1021_pcie_host_ops,
	.pm = &ls1021_pcie_host_pm_ops,
};

static struct ls_pcie_drvdata ls1043_drvdata = {
	.lut_offset = 0x10000,
	.ltssm_shift = 24,
	.ops = &ls_pcie_host_ops,
	.pm = &ls_pcie_host_pm_ops,
};

static struct ls_pcie_drvdata ls2080_drvdata = {
	.lut_offset = 0x80000,
	.ltssm_shift = 0,
	.ops = &ls_pcie_host_ops,
	.pm = &ls_pcie_host_pm_ops,
};

static const struct of_device_id ls_pcie_of_match[] = {
	{ .compatible = "fsl,ls1021a-pcie", .data = &ls1021_drvdata },
	{ .compatible = "fsl,ls1043a-pcie", .data = &ls1043_drvdata },
	{ .compatible = "fsl,ls2080a-pcie", .data = &ls2080_drvdata },
	{ .compatible = "fsl,ls2085a-pcie", .data = &ls2080_drvdata },
	{ },
};
MODULE_DEVICE_TABLE(of, ls_pcie_of_match);

static void ls_pcie_host_hack_pm_init(struct ls_pcie *pcie)
{
	struct device_node *np;
	struct ls_pcie_pm_data *pm_data = &pcie->pm_data;

	np = of_find_compatible_node(NULL, NULL, "fsl,ls1021aqds-fpga");
	if (np)
		pm_data->fpga = of_iomap(np, 0);

	of_node_put(np);

	np = of_find_compatible_node(NULL, NULL, "fsl,ls1021atwr-cpld");
	if (np)
		pm_data->cpld = of_iomap(np, 0);

	of_node_put(np);
}

static irqreturn_t ls_pcie_pme_irq_handler(int irq, void *data)
{
	struct pcie_port *pp = data;
	struct ls_pcie *pcie = to_ls_pcie(pp);
	u32 val;

	if (pcie->drvdata->pm->clear_turn_off_message)
		pcie->drvdata->pm->clear_turn_off_message(pcie);

	/* Clear Host root PME_STATE bit */
	val = ioread32(pcie->dbi + PCIE_PEX_RSR);
	val |= PCIE_PEX_PMES;
	iowrite32(val, pcie->dbi + PCIE_PEX_RSR);

	return IRQ_HANDLED;
}

static int ls_pcie_host_pme_init(struct ls_pcie *pcie,
				 struct platform_device *pdev)
{
	struct pcie_port *pp;
	int ret;
	u16 val;

	pp = &pcie->pp;

	if (dw_pcie_link_up(&pcie->pp))
		pcie->in_slot = true;
	else
		pcie->in_slot = false;

	pcie->pme_irq = platform_get_irq_byname(pdev, "pme");
	if (pcie->pme_irq < 0) {
		dev_err(&pdev->dev,
			"failed to get PME IRQ: %d\n", pcie->pme_irq);
		return pcie->pme_irq;
	}

	ret = devm_request_irq(pp->dev, pcie->pme_irq, ls_pcie_pme_irq_handler,
			       IRQF_SHARED, "ls-pcie-pme", pp);
	if (ret) {
		dev_err(pp->dev, "Failed to request pme irq\n");
		return ret;
	}

	ls_pcie_host_hack_pm_init(pcie);

	/* AUX Power PM Enable */
	val = ioread16(pcie->dbi + PCIE_PEX_DCR);
	val |= PCIE_PEX_DCR_AUXPOWEREN;
	iowrite16(val, pcie->dbi + PCIE_PEX_DCR);

	/* Enable PME message */
	val = ioread16(pcie->dbi + PCIE_PM_SCR);
	val |= PCIE_PM_SCR_PMEEN;
	iowrite16(val, pcie->dbi + PCIE_PM_SCR);

	/* Clear Host PME_STATE bit */
	val = ioread16(pcie->dbi + PCIE_PM_SCR);
	val |= PCIE_PM_SCR_PME_STATE;
	iowrite16(val, pcie->dbi + PCIE_PM_SCR);

	/* Enable Host %d interrupt */
	val = ioread16(pcie->dbi + PCIE_PEX_RCR);
	val |= PCIE_PEX_RCR_PMEIE;
	iowrite16(val, pcie->dbi + PCIE_PEX_RCR);

	return 0;
}

static int __init ls_add_pcie_port(struct pcie_port *pp,
				   struct platform_device *pdev)
{
	int ret;
	struct ls_pcie *pcie = to_ls_pcie(pp);

	pp->dev = &pdev->dev;
	pp->dbi_base = pcie->dbi;
	pp->ops = pcie->drvdata->ops;

	ret = dw_pcie_host_init(pp);
	if (ret) {
		dev_err(pp->dev, "failed to initialize host\n");
		return ret;
	}

	ret = ls_pcie_host_pme_init(pcie, pdev);
	if (ret)
		dev_warn(pp->dev, "failed to initialize PME\n");

	return 0;
}

static int ls_pcie_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	struct ls_pcie *pcie;
	struct resource *dbi_base;
	int ret;

	match = of_match_device(ls_pcie_of_match, &pdev->dev);
	if (!match)
		return -ENODEV;

	pcie = devm_kzalloc(&pdev->dev, sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;

	dbi_base = platform_get_resource_byname(pdev, IORESOURCE_MEM, "regs");
	pcie->dbi = devm_ioremap_resource(&pdev->dev, dbi_base);
	if (IS_ERR(pcie->dbi)) {
		dev_err(&pdev->dev, "missing *regs* space\n");
		return PTR_ERR(pcie->dbi);
	}

	pcie->drvdata = match->data;
	pcie->lut = pcie->dbi + pcie->drvdata->lut_offset;
	/* Disable LDR zero */
	iowrite32(0, pcie->lut + PCIE_LUT_LDR(0));

	if (!ls_pcie_is_bridge(pcie))
		return -ENODEV;

	if (of_device_is_compatible(pdev->dev.of_node, "fsl,ls2085a-pcie") ||
	of_device_is_compatible(pdev->dev.of_node, "fsl,ls2080a-pcie")) {
		int len;
		const u32 *prop;
		struct device_node *np;

		np = pdev->dev.of_node;
		prop = (u32 *)of_get_property(np, "available-stream-ids", &len);
		if (prop) {
			pcie->avail_streamids = prop;
			pcie->streamid_index = len/sizeof(u32);
		} else
			dev_err(&pdev->dev, "PCIe endpoint partitioning not possible\n");
	}

	ret = ls_add_pcie_port(&pcie->pp, pdev);
	if (ret < 0)
		return ret;

	list_add_tail(&pcie->list_node, &hose_list);

	platform_set_drvdata(pdev, pcie);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int ls_pcie_pm_do_suspend(struct ls_pcie *pcie)
{
	u32 state;
	int i = 0;
	int ret;
	u16 val;

	if (!pcie->in_slot)
		return 0;

	if (!pcie->drvdata->pm->send_turn_off_message)
		return 0;

	ret = pcie->drvdata->pm->send_turn_off_message(pcie);
	if (ret)
		return -EINVAL;

	while (i < 100) {
		state = pcie->drvdata->pm->get_link_state(pcie);
		if (state == LTSSM_PCIE_L2_IDLE)
			break;
		i++;
		mdelay(1);
	}

	/* Put RC in D3 */
	val = ioread16(pcie->dbi + PCIE_PM_SCR);
	val |= PCIE_PM_SCR_PMEPS_D3;
	iowrite16(val, pcie->dbi + PCIE_PM_SCR);

	mdelay(10);

	return 0;
}

static int ls_pcie_pm_do_resume(struct ls_pcie *pcie)
{
	u32 state;
	int i = 0;
	u16 val;
	struct pcie_port *pp = &pcie->pp;

	if (!pcie->in_slot)
		return 0;

	dw_pcie_setup_rc(pp);
	ls_pcie_host_init(pp);

	/* Put RC in D0 */
	val = ioread16(pcie->dbi + PCIE_PM_SCR);
	val &= PCIE_PM_SCR_PMEPS_D0;
	iowrite16(val, pcie->dbi + PCIE_PM_SCR);

	mdelay(10);

	state = pcie->drvdata->pm->get_link_state(pcie);
	if (state == LTSSM_PCIE_L0)
		return 0;

	if (!pcie->drvdata->pm->reset_slot)
		return -EINVAL;

	pcie->drvdata->pm->reset_slot(pcie, &pcie->pm_data);

	while (i < 100) {
		state = pcie->drvdata->pm->get_link_state(pcie);
		if (state == LTSSM_PCIE_L0)
			return 0;
		i++;
		mdelay(1);
	}

	return -EINVAL;
}

static int ls_pcie_pm_suspend(void)
{
	struct ls_pcie *hose, *tmp;

	list_for_each_entry_safe(hose, tmp, &hose_list, list_node)
		ls_pcie_pm_do_suspend(hose);

	return 0;
}

static void ls_pcie_pm_resume(void)
{
	struct ls_pcie *hose, *tmp;

	list_for_each_entry_safe(hose, tmp, &hose_list, list_node)
		ls_pcie_pm_do_resume(hose);
}

static struct syscore_ops ls_pcie_syscore_pm_ops = {
	.suspend = ls_pcie_pm_suspend,
	.resume = ls_pcie_pm_resume,
};
#endif /* CONFIG_PM_SLEEP */

static struct platform_driver ls_pcie_driver = {
	.probe = ls_pcie_probe,
	.driver = {
		.name = "layerscape-pcie",
		.of_match_table = ls_pcie_of_match,
	},
};

static int __init fsl_pci_init(void)
{
#ifdef CONFIG_PM_SLEEP
	register_syscore_ops(&ls_pcie_syscore_pm_ops);
#endif
	return platform_driver_register(&ls_pcie_driver);
}
module_init(fsl_pci_init);

MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@freescale.com>");
MODULE_DESCRIPTION("Freescale Layerscape PCIe host controller driver");
MODULE_LICENSE("GPL v2");
