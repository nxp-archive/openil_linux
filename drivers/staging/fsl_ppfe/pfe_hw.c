/*
 *
 *  Copyright (C) 2007 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "pfe_mod.h"
#include "pfe_hw.h"

/* Functions to handle most of pfe hw register initialization */

int pfe_hw_init(struct pfe *pfe, int resume)
{
	CLASS_CFG class_cfg = {
		.pe_sys_clk_ratio = PE_SYS_CLK_RATIO,
		.route_table_baseaddr = pfe->ddr_phys_baseaddr + ROUTE_TABLE_BASEADDR,
		.route_table_hash_bits = ROUTE_TABLE_HASH_BITS,
	};

	TMU_CFG tmu_cfg = {
		.pe_sys_clk_ratio = PE_SYS_CLK_RATIO,
		.llm_base_addr = pfe->ddr_phys_baseaddr + TMU_LLM_BASEADDR,
		.llm_queue_len = TMU_LLM_QUEUE_LEN,
	};

#if !defined(CONFIG_UTIL_DISABLED)
	UTIL_CFG util_cfg = {
		.pe_sys_clk_ratio = PE_SYS_CLK_RATIO,
	};
#endif

	BMU_CFG bmu1_cfg = {
		.baseaddr = CBUS_VIRT_TO_PFE(LMEM_BASE_ADDR + BMU1_LMEM_BASEADDR),
		.count = BMU1_BUF_COUNT,
		.size = BMU1_BUF_SIZE,
	};

	BMU_CFG bmu2_cfg = {
		.baseaddr = DDR_PHYS_TO_PFE(pfe->ddr_phys_baseaddr + BMU2_DDR_BASEADDR),
		.count = BMU2_BUF_COUNT,
		.size = BMU2_BUF_SIZE,
	};

	GPI_CFG egpi1_cfg = {
		.lmem_rtry_cnt = EGPI1_LMEM_RTRY_CNT,
		.tmlf_txthres = EGPI1_TMLF_TXTHRES,
		.aseq_len = EGPI1_ASEQ_LEN,
	};

	GPI_CFG egpi2_cfg = {
		.lmem_rtry_cnt = EGPI2_LMEM_RTRY_CNT,
		.tmlf_txthres = EGPI2_TMLF_TXTHRES,
		.aseq_len = EGPI2_ASEQ_LEN,
	};

#if defined(CONFIG_PLATFORM_C2000)
	GPI_CFG egpi3_cfg = {
		.lmem_rtry_cnt = EGPI3_LMEM_RTRY_CNT,
		.tmlf_txthres = EGPI3_TMLF_TXTHRES,
		.aseq_len = EGPI3_ASEQ_LEN,
	};
#endif

	GPI_CFG hgpi_cfg = {
		.lmem_rtry_cnt = HGPI_LMEM_RTRY_CNT,
		.tmlf_txthres = HGPI_TMLF_TXTHRES,
		.aseq_len = HGPI_ASEQ_LEN,
	};

	printk(KERN_INFO "%s\n", __func__);

#if defined(CONFIG_PLATFORM_LS1012A) && !defined(LS1012A_PFE_RESET_WA)
	/* LS1012A needs this to make PE work correctly */
        writel(0x3,     CLASS_PE_SYS_CLK_RATIO);
        writel(0x3,     TMU_PE_SYS_CLK_RATIO);
        writel(0x3,     UTIL_PE_SYS_CLK_RATIO);
        udelay(10);
#endif

	printk(KERN_INFO "CLASS version: %x\n", readl(CLASS_VERSION));
	printk(KERN_INFO "TMU version: %x\n", readl(TMU_VERSION));

	printk(KERN_INFO "BMU1 version: %x\n", readl(BMU1_BASE_ADDR + BMU_VERSION));
	printk(KERN_INFO "BMU2 version: %x\n", readl(BMU2_BASE_ADDR + BMU_VERSION));
#if defined(CONFIG_PLATFORM_C2000)
	printk(KERN_INFO "EMAC1 network cfg: %x\n", readl(EMAC1_BASE_ADDR + EMAC_NETWORK_CONFIG));
	printk(KERN_INFO "EMAC2 network cfg: %x\n", readl(EMAC2_BASE_ADDR + EMAC_NETWORK_CONFIG));
#if !defined(CONFIG_PLATFORM_PCI)
	printk(KERN_INFO "EMAC3 network cfg: %x\n", readl(EMAC3_BASE_ADDR + EMAC_NETWORK_CONFIG));
#endif
#else
	//TODO print MTIP config
#endif

	printk(KERN_INFO "EGPI1 version: %x\n", readl(EGPI1_BASE_ADDR + GPI_VERSION));
	printk(KERN_INFO "EGPI2 version: %x\n", readl(EGPI2_BASE_ADDR + GPI_VERSION));
#if !defined(CONFIG_PLATFORM_PCI) && !defined(CONFIG_PLATFORM_LS1012A)
	printk(KERN_INFO "EGPI3 version: %x\n", readl(EGPI3_BASE_ADDR + GPI_VERSION));
#endif
	printk(KERN_INFO "HGPI version: %x\n", readl(HGPI_BASE_ADDR + GPI_VERSION));

#if !defined(CONFIG_PLATFORM_PCI)
	printk(KERN_INFO "GPT version: %x\n", readl(CBUS_GPT_VERSION));
#endif

	printk(KERN_INFO "HIF version: %x\n", readl(HIF_VERSION));
	printk(KERN_INFO "HIF NOPCY version: %x\n", readl(HIF_NOCPY_VERSION));

#if !defined(CONFIG_UTIL_DISABLED)
	printk(KERN_INFO "UTIL version: %x\n", readl(UTIL_VERSION));
#endif
	while(!(readl(TMU_CTRL) & ECC_MEM_INIT_DONE)) ;

	hif_rx_disable();
	hif_tx_disable();

	bmu_init(BMU1_BASE_ADDR, &bmu1_cfg);

	printk(KERN_INFO "bmu_init(1) done\n");

	bmu_init(BMU2_BASE_ADDR, &bmu2_cfg);

	printk(KERN_INFO "bmu_init(2) done\n");

	class_cfg.resume = resume ? 1 : 0;

	class_init(&class_cfg);

	printk(KERN_INFO "class_init() done\n");

	tmu_init(&tmu_cfg);

	printk(KERN_INFO "tmu_init() done\n");
#if !defined(CONFIG_UTIL_DISABLED)
	util_init(&util_cfg);

	printk(KERN_INFO "util_init() done\n");
#endif
	gpi_init(EGPI1_BASE_ADDR, &egpi1_cfg);

	printk(KERN_INFO "gpi_init(1) done\n");

	gpi_init(EGPI2_BASE_ADDR, &egpi2_cfg);

	printk(KERN_INFO "gpi_init(2) done\n");
#if !defined(CONFIG_PLATFORM_PCI) && !defined(CONFIG_PLATFORM_LS1012A)
	gpi_init(EGPI3_BASE_ADDR, &egpi3_cfg);

	printk(KERN_INFO "gpi_init(3) done\n");
#endif
	gpi_init(HGPI_BASE_ADDR, &hgpi_cfg);

	printk(KERN_INFO "gpi_init(hif) done\n");

	bmu_enable(BMU1_BASE_ADDR);

	printk(KERN_INFO "bmu_enable(1) done\n");

	bmu_enable(BMU2_BASE_ADDR);

	printk(KERN_INFO "bmu_enable(2) done\n");

	return 0;
}

void pfe_hw_exit(struct pfe *pfe)
{
	printk(KERN_INFO "%s\n", __func__);

	bmu_disable(BMU1_BASE_ADDR);
	bmu_reset(BMU1_BASE_ADDR);

	bmu_disable(BMU2_BASE_ADDR);
	bmu_reset(BMU2_BASE_ADDR);
}
