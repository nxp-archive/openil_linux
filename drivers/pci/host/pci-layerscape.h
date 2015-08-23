/*
 * Copyright (C) 2015 Freescale Semiconductor.
 *
 * Author: Varun Sethi <Varun.Sethi@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _PCI_LAYERSCAPE_H
#define _PCI_LAYERSCAPE_H

/* PEX1/2 Misc Ports Status Register */
#define SCFG_PEXMSCPORTSR(pex_idx)	(0x94 + (pex_idx) * 4)
#define LTSSM_STATE_SHIFT	20
#define LTSSM_STATE_MASK	0x3f
#define LTSSM_PCIE_L0		0x11 /* L0 state */

/* PEX LUT registers */
#define PCIE_LUT_BASE		0x80000
#define PCIE_LUT_PEXLSR		0x020 /* PEX LUT Status Register */
#define PCIE_LUT_PEXLCR		0x024 /* PEX LUT Control Register */
#define PCIE_LUT_DBG		0x7FC /* PEX LUT Debug register */
#define PCIE_LUT_UDR(n)		(0x800 + (n) * 8)
#define PCIE_LUT_LDR(n)		(0x804 + (n) * 8)
#define PCIE_LUT_MASK_ALL	0xffff
#define PCIE_LUT_DR_NUM		32
#define PCIE_LUT_ENABLE		(1 << 31)

/* function for setting up stream id to device id translation */
u32 set_pcie_streamid_translation(struct pci_dev *pdev, u32 devid);

#define PCIE_ATU_NUM		6

#endif /* _PCI_LAYERSCAPE_H */
