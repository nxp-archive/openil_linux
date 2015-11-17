/*
 * PCIe host controller driver for Freescale Layerscape SoCs
 *
 * Copyright (C) 2014 - 2015 Freescale Semiconductor.
 *
  * Author: Minghuan Lian <Minghuan.Lian@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/resource.h>

#include "pcie-designware-base.h"
#include "pci-layerscape.h"

struct ls_pcie {
	struct dw_pcie_port	pp;
	void __iomem		*regs;
	void __iomem		*lut;
	struct regmap		*scfg;
	int			index;
	const u32 *avail_streamids;
	int streamid_index;
};


#define to_ls_pcie(x)	container_of(x, struct ls_pcie, pp)

u32 set_pcie_streamid_translation(struct pci_dev *pdev, u32 devid)
{
	u32 index, streamid;
	struct dw_pcie_port *pp = pdev->bus->sysdata;
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

static bool ls_pcie_is_bridge(struct ls_pcie *pcie)
{
	u32 header_type;

	header_type = ioread32(pcie->regs + (PCI_HEADER_TYPE & ~0x3));
	header_type = (header_type >> (8 * (PCI_HEADER_TYPE & 0x3))) & 0x7f;

	return header_type == PCI_HEADER_TYPE_BRIDGE;
}

static int ls1_pcie_link_up(struct dw_pcie_port *pp)
{
	struct ls_pcie *pcie = to_ls_pcie(pp);
	u32 state;

	if (!pcie->scfg)
		return 0;

	regmap_read(pcie->scfg, SCFG_PEXMSCPORTSR(pcie->index), &state);
	state = (state >> LTSSM_STATE_SHIFT) & LTSSM_STATE_MASK;

	if (state < LTSSM_PCIE_L0)
		return 0;

	return 1;
}

static int ls1_pcie_host_init(struct dw_pcie_port *pp)
{
	struct ls_pcie *pcie = to_ls_pcie(pp);
	u32 val, index[2];
	int ret;

	pcie->scfg = syscon_regmap_lookup_by_phandle(pp->dev->of_node,
						     "fsl,pcie-scfg");
	if (IS_ERR(pcie->scfg)) {
		dev_err(pp->dev, "No syscfg phandle specified\n");
		return PTR_ERR(pcie->scfg);
	}

	ret = of_property_read_u32_array(pp->dev->of_node,
					 "fsl,pcie-scfg", index, 2);
	if (ret)
		return ret;

	pcie->index = index[1];

	/*
	 * LS1021A Workaround for internal TKT228622
	 * to fix the INTx hang issue
	 */
	val = dw_pcie_dbi_read(pp, PCIE_SYMBOL_TIMER_1);
	val &= 0xffff;
	dw_pcie_dbi_write(pp, val, PCIE_SYMBOL_TIMER_1);

	/* Fix class value */
	val = dw_pcie_dbi_read(pp, PCI_CLASS_REVISION);
	val = (val & 0x0000ffff) | (PCI_CLASS_BRIDGE_PCI << 16);
	dw_pcie_dbi_write(pp, val, PCI_CLASS_REVISION);

	if (!ls1_pcie_link_up(pp))
		dev_err(pp->dev, "phy link never came up\n");

	return 0;
}

static struct dw_host_ops ls1_dw_host_ops = {
	.link_up = ls1_pcie_link_up,
	.host_init = ls1_pcie_host_init,
};

static int ls2_pcie_link_up(struct dw_pcie_port *pp)
{
	struct ls_pcie *pcie = to_ls_pcie(pp);
	u32 state;

	if (!pcie->lut)
		return 0;

	state = ioread32(pcie->lut + PCIE_LUT_DBG) & LTSSM_STATE_MASK;
	if (state < LTSSM_PCIE_L0)
		return 0;

	return 1;
}

static int ls2_pcie_host_init(struct dw_pcie_port *pp)
{
	struct ls_pcie *pcie = to_ls_pcie(pp);
	u32 val;

	pcie->lut = pp->dbi + PCIE_LUT_BASE;
	/* Disable LDR zero */
	iowrite32(0, pcie->lut + PCIE_LUT_LDR(0));

	dw_pcie_dbi_write(pp, 1, PCIE_DBI_RO_WR_EN);
	/* Fix class value */
	val = dw_pcie_dbi_read(pp, PCI_CLASS_REVISION);
	val = (val & 0x0000ffff) | (PCI_CLASS_BRIDGE_PCI << 16);
	dw_pcie_dbi_write(pp, val, PCI_CLASS_REVISION);
	/* clean multi-func bit */
	val = dw_pcie_dbi_read(pp, PCI_HEADER_TYPE & ~0x3);
	val &= ~(1 << 23);
	dw_pcie_dbi_write(pp, val, PCI_HEADER_TYPE & ~0x3);
	dw_pcie_dbi_write(pp, 0, PCIE_DBI_RO_WR_EN);

	if (!ls2_pcie_link_up(pp))
		dev_err(pp->dev, "phy link never came up\n");

	return 0;
}

static struct dw_host_ops ls2_dw_host_ops = {
	.link_up = ls2_pcie_link_up,
	.host_init = ls2_pcie_host_init,
};

static const struct of_device_id ls_pcie_of_match[] = {
	{ .compatible = "fsl,ls1021a-pcie", .data = &ls1_dw_host_ops },
	{ .compatible = "fsl,ls2085a-pcie", .data = &ls2_dw_host_ops },
	{ .compatible = "fsl,ls2080a-pcie", .data = &ls2_dw_host_ops },
	{ },
};
MODULE_DEVICE_TABLE(of, ls_pcie_of_match);

static int __init ls_pcie_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	struct ls_pcie *pcie;
	struct resource *res;
	int ret;

	match = of_match_device(ls_pcie_of_match, &pdev->dev);
	if (!match)
		return -ENODEV;

	pcie = devm_kzalloc(&pdev->dev, sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "regs");
	pcie->regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(pcie->regs)) {
		dev_err(&pdev->dev, "missing *regs* space\n");
		return PTR_ERR(pcie->regs);
	}

	pcie->lut = pcie->regs + PCIE_LUT_BASE;
	/* Disable LDR zero */
	iowrite32(0, pcie->lut + PCIE_LUT_LDR(0));
	pcie->pp.dev = &pdev->dev;
	pcie->pp.dbi = pcie->regs;
	pcie->pp.dw_ops = (struct dw_host_ops *)match->data;
	pcie->pp.atu_num = PCIE_ATU_NUM;

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

	if (!ls_pcie_is_bridge(pcie))
		return -ENODEV;

	ret = dw_pcie_port_init(&pcie->pp);
	if (ret < 0)
		return ret;

	platform_set_drvdata(pdev, pcie);

	return 0;
}

static struct platform_driver ls_pcie_driver = {
	.driver = {
		.name = "layerscape-pcie",
		.of_match_table = ls_pcie_of_match,
	},
};

module_platform_driver_probe(ls_pcie_driver, ls_pcie_probe);

MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@freescale.com>");
MODULE_DESCRIPTION("Freescale Layerscape PCIe host controller driver");
MODULE_LICENSE("GPL v2");
