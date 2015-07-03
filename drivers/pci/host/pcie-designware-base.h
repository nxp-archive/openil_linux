/*
 * Synopsys Designware PCIe host controller base driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _PCIE_DESIGNWARE_BASE_H
#define _PCIE_DESIGNWARE_BASE_H

/* Synopsis specific PCIE configuration registers */
#define PCIE_SYMBOL_TIMER_1		0x71c
#define PCIE_DBI_RO_WR_EN		0x8bc

#define PCIE_ATU_VIEWPORT		0x900
#define PCIE_ATU_REGION_INBOUND		(0x1 << 31)
#define PCIE_ATU_REGION_OUTBOUND	(0x0 << 31)
#define PCIE_ATU_REGION_INDEX0		(0x0 << 0)
#define PCIE_ATU_CR1			0x904
#define PCIE_ATU_TYPE_MEM		(0x0 << 0)
#define PCIE_ATU_TYPE_IO		(0x2 << 0)
#define PCIE_ATU_TYPE_CFG0		(0x4 << 0)
#define PCIE_ATU_TYPE_CFG1		(0x5 << 0)
#define PCIE_ATU_CR2			0x908
#define PCIE_ATU_ENABLE			(0x1 << 31)
#define PCIE_ATU_BAR_MODE_ENABLE	(0x1 << 30)
#define PCIE_ATU_LOWER_BASE		0x90C
#define PCIE_ATU_UPPER_BASE		0x910
#define PCIE_ATU_LIMIT			0x914
#define PCIE_ATU_LOWER_TARGET		0x918
#define PCIE_ATU_BUS(x)			(((x) & 0xff) << 24)
#define PCIE_ATU_DEV(x)			(((x) & 0x1f) << 19)
#define PCIE_ATU_FUNC(x)		(((x) & 0x7) << 16)
#define PCIE_ATU_UPPER_TARGET		0x91C

struct dw_pcie_port;

struct dw_host_ops {
	int (*link_up)(struct dw_pcie_port *pp);
	int (*host_init)(struct dw_pcie_port *pp);
};

struct dw_pcie_port {
	struct device		*dev;
	void __iomem		*dbi;
	void __iomem		*cfg;
	u64			cfg_addr;
	u32			cfg_size;
	u64			io_cpu_addr;
	u64			io_pci_addr;
	u32			io_size;
	u32			atu_num;
	struct dw_host_ops	*dw_ops;
	struct pci_ops		*pci_ops;
	struct msi_controller	*msi_chip;
};

void dw_pcie_dbi_write(struct dw_pcie_port *pp, u32 value, u32 offset);
u32 dw_pcie_dbi_read(struct dw_pcie_port *pp, u32 offset);
int dw_pcie_host_link_up(struct dw_pcie_port *pp);
void dw_pcie_atu_outbound_set(struct dw_pcie_port *pp, int idx, int type,
			      u64 cpu_addr, u64 pci_addr, u32 size);
int dw_pcie_port_init(struct dw_pcie_port *pp);

#endif /* _PCIE_DESIGNWARE_BASE_H */
