/*
 * Support deep sleep feature for T104x
 *
 * Copyright 2015 Freescale Semiconductor Inc.
 *
 * Author: Chenhui Zhao <chenhui.zhao@freescale.com>
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/slab.h>
#include <sysdev/fsl_soc.h>
#include <asm/machdep.h>
#include <asm/fsl_pm.h>

#include "sleep_fsm.h"

#define CCSR_LAW_OFFSET		0xC00

#define CPC_CPCHDBCR0		0x0f00
#define CPC_CPCHDBCR0_SPEC_DIS	0x08000000

#define CCSR_SCFG_DPSLPCR	0x000
#define CCSR_SCFG_DPSLPCR_WDRR_EN	0x1
#define CCSR_SCFG_SPARECR2	0x504
#define CCSR_SCFG_SPARECR3	0x508

#define CCSR_GPIO1_GPDIR	0x000
#define CCSR_GPIO1_GPODR	0x004
#define CCSR_GPIO1_GPDAT	0x008
#define CCSR_GPIO1_GPDIR_29	0x4

#define QIXIS_PWR_CTL2		0x21
#define QIXIS_PWR_CTL2_PCTL	0x2

#define QORIQ_CPLD_MISCCSR		0x17
#define QORIQ_CPLD_MISCCSR_SLEEPEN	0x40

#define GPIO1_OFFSET		0x130000

#define CCSR_LCC_BSTRH	0x20
#define CCSR_LCC_BSTRL	0x24
#define CCSR_LCC_BSTAR	0x28

#define CCSR_DCFG_BRR	0xE4

#define CCSR_RCPM_PCTBENR	0x1A0

/* the target id for the memory complex 1 (MC1) */
#define MC1_TRGT_ID		0x10

/* 128 bytes buffer for restoring data broke by DDR training initialization */
#define DDR_BUF_SIZE	128
static u8 ddr_buff[DDR_BUF_SIZE] __aligned(64);

static void fsl_dp_iounmap(void);

static struct fsl_iomap fsl_dp_priv;

struct fsl_ccsr_law {
	u32	lawbarh;	/* LAWn base address high */
	u32	lawbarl;	/* LAWn base address low */
	u32	lawar;		/* LAWn attributes */
	u32	reserved;
};

static struct fsl_regs_buffer {
	u32 bstrh;
	u32 bstrl;
	u32 bstar;
	u32 brr;
	u32 pctbenr;
	u32 law_count;
	void *law_regs;
} fsl_dp_buffer;

static const struct of_device_id fsl_dp_cpld_ids[] __initconst = {
	{ .compatible = "fsl,t1024-cpld", },
	{ .compatible = "fsl,t1040rdb-cpld", },
	{ .compatible = "fsl,t1042rdb-cpld", },
	{ .compatible = "fsl,t1042rdb_pi-cpld", },
	{ .compatible = "fsl,t1040d4rdb-cpld", },
	{}
};

static const struct of_device_id fsl_dp_fpga_ids[] __initconst = {
	{ .compatible = "fsl,fpga-qixis", },
	{ .compatible = "fsl,tetra-fpga", },
	{}
};

static void fsl_regs_save(struct fsl_iomap *base,
			  struct fsl_regs_buffer *buffer)
{
	int i;
	struct fsl_ccsr_law *src = base->ccsr_lcc_base + CCSR_LAW_OFFSET;
	struct fsl_ccsr_law *dst = buffer->law_regs;

	buffer->bstrh = in_be32(base->ccsr_lcc_base + CCSR_LCC_BSTRH);
	buffer->bstrl = in_be32(base->ccsr_lcc_base + CCSR_LCC_BSTRL);
	buffer->bstar = in_be32(base->ccsr_lcc_base + CCSR_LCC_BSTAR);
	buffer->brr = in_be32(base->ccsr_dcfg_base + CCSR_DCFG_BRR);
	buffer->pctbenr = in_be32(base->ccsr_rcpm_base + CCSR_RCPM_PCTBENR);

	for (i = 0; i < buffer->law_count; i++) {
		dst->lawbarh = in_be32(&src->lawbarh);
		dst->lawbarl = in_be32(&src->lawbarl);
		dst->lawar = in_be32(&src->lawar);
		dst++;
		src++;
	}
}

static void fsl_regs_restore(struct fsl_iomap *base,
			     struct fsl_regs_buffer *buffer)
{
	int i;
	u32 attr;
	struct fsl_ccsr_law *src = buffer->law_regs;
	struct fsl_ccsr_law *dst = base->ccsr_lcc_base + CCSR_LAW_OFFSET;

	out_be32(base->ccsr_lcc_base + CCSR_LCC_BSTRH, buffer->bstrh);
	out_be32(base->ccsr_lcc_base + CCSR_LCC_BSTRL, buffer->bstrl);
	out_be32(base->ccsr_lcc_base + CCSR_LCC_BSTAR, buffer->bstar);
	out_be32(base->ccsr_dcfg_base + CCSR_DCFG_BRR, buffer->brr);
	out_be32(base->ccsr_rcpm_base + CCSR_RCPM_PCTBENR, buffer->pctbenr);

	for (i = 0; i < buffer->law_count; i++) {
		/*
		 * If the LAW with the target id of MC1 has been set,
		 * skip. Because changing it here causes memory
		 * access error.
		 */
		attr = in_be32(&dst->lawar);
		if (((attr >> 20) & 0xff) == MC1_TRGT_ID)
			continue;
		out_be32(&dst->lawar, 0);
		out_be32(&dst->lawbarl, src->lawbarl);
		out_be32(&dst->lawbarh, src->lawbarh);
		out_be32(&dst->lawar, src->lawar);
		src++;
		dst++;
	}
}

static void fsl_dp_set_resume_pointer(void)
{
	u32 resume_addr;

	/* the bootloader will finally jump to this address to return kernel */
#ifdef CONFIG_PPC32
	resume_addr = (u32)(__pa(fsl_booke_deep_sleep_resume));
#else
	resume_addr = (u32)(__pa(*(u64 *)fsl_booke_deep_sleep_resume)
			    & 0xffffffff);
#endif

	/* use the register SPARECR2 to save the resume address */
	out_be32(fsl_dp_priv.ccsr_scfg_base + CCSR_SCFG_SPARECR2,
		 resume_addr);
}

static void fsl_dp_pins_setup(void)
{
	/* set GPIO1_29 as an output pin (not open-drain), and output 0 */
	clrbits32(fsl_dp_priv.ccsr_gpio1_base + CCSR_GPIO1_GPDAT,
		  CCSR_GPIO1_GPDIR_29);
	clrbits32(fsl_dp_priv.ccsr_gpio1_base + CCSR_GPIO1_GPODR,
		  CCSR_GPIO1_GPDIR_29);
	setbits32(fsl_dp_priv.ccsr_gpio1_base + CCSR_GPIO1_GPDIR,
		  CCSR_GPIO1_GPDIR_29);

	/* wait for the stabilization of GPIO1_29 */
	udelay(10);

	/* enable the functionality of pins relevant to deep sleep */
	if (fsl_dp_priv.cpld_base) {
		setbits8(fsl_dp_priv.cpld_base + QORIQ_CPLD_MISCCSR,
			 QORIQ_CPLD_MISCCSR_SLEEPEN);
	} else if (fsl_dp_priv.fpga_base) {
		setbits8(fsl_dp_priv.fpga_base + QIXIS_PWR_CTL2,
			 QIXIS_PWR_CTL2_PCTL);
	}
}

static void fsl_dp_ddr_save(void *scfg_base)
{
	u32 ddr_buff_addr;

	/*
	 * DDR training initialization will break 128 bytes at the beginning
	 * of DDR, therefore, save them so that the bootloader will restore
	 * them. Assume that DDR is mapped to the address space started with
	 * CONFIG_PAGE_OFFSET.
	 */
	memcpy(ddr_buff, (void *)CONFIG_PAGE_OFFSET, DDR_BUF_SIZE);

	/* assume ddr_buff is in the physical address space of 4GB */
	ddr_buff_addr = (u32)(__pa(ddr_buff) & 0xffffffff);

	/*
	 * the bootloader will restore the first 128 bytes of DDR from
	 * the location indicated by the register SPARECR3
	 */
	out_be32(scfg_base + CCSR_SCFG_SPARECR3, ddr_buff_addr);
}

int fsl_enter_deepsleep(void)
{
	fsl_dp_ddr_save(fsl_dp_priv.ccsr_scfg_base);

	fsl_dp_set_resume_pointer();

	fsl_regs_save(&fsl_dp_priv, &fsl_dp_buffer);

	/*  enable Warm Device Reset request. */
	setbits32(fsl_dp_priv.ccsr_scfg_base + CCSR_SCFG_DPSLPCR,
		  CCSR_SCFG_DPSLPCR_WDRR_EN);

	/*
	 * Disable CPC speculation to avoid deep sleep hang, especially
	 * in secure boot mode. This bit will be cleared automatically
	 * when resuming from deep sleep.
	 */
	setbits32(fsl_dp_priv.ccsr_cpc_base + CPC_CPCHDBCR0,
		  CPC_CPCHDBCR0_SPEC_DIS);

	fsl_epu_setup_default(fsl_dp_priv.dcsr_epu_base);
	fsl_npc_setup_default(fsl_dp_priv.dcsr_npc_base);
	fsl_dcsr_rcpm_setup(fsl_dp_priv.dcsr_rcpm_base);

	fsl_dp_pins_setup();

	fsl_dp_enter_low(&fsl_dp_priv);

	fsl_regs_restore(&fsl_dp_priv, &fsl_dp_buffer);

	/* disable Warm Device Reset request */
	clrbits32(fsl_dp_priv.ccsr_scfg_base + CCSR_SCFG_DPSLPCR,
		  CCSR_SCFG_DPSLPCR_WDRR_EN);

	fsl_epu_clean_default(fsl_dp_priv.dcsr_epu_base);

	return 0;
}

static void __init *fsl_of_iomap(char *comp)
{
	struct device_node *np;
	void *addr;

	np = of_find_compatible_node(NULL, NULL, comp);
	if (np) {
		addr = of_iomap(np, 0);
		of_node_put(np);
		return addr;
	}

	return NULL;
}

static int __init fsl_dp_iomap(void)
{
	struct device_node *np;
	u32 val;

	np = of_find_matching_node(NULL, fsl_dp_cpld_ids);
	if (np) {
		fsl_dp_priv.cpld_base = of_iomap(np, 0);
		of_node_put(np);
	} else {
		np = of_find_matching_node(NULL, fsl_dp_fpga_ids);
		if (np) {
			fsl_dp_priv.fpga_base = of_iomap(np, 0);
			of_node_put(np);
		} else {
			goto err;
		}
	}

	fsl_dp_priv.ccsr_dcfg_base =
			fsl_of_iomap("fsl,qoriq-device-config-2.0");
	if (!fsl_dp_priv.ccsr_dcfg_base)
		goto err;

	fsl_dp_priv.ccsr_scfg_base = fsl_of_iomap("fsl,t1040-scfg");
	if (!fsl_dp_priv.ccsr_scfg_base) {
		fsl_dp_priv.ccsr_scfg_base = fsl_of_iomap("fsl,t1024-scfg");
		if (!fsl_dp_priv.ccsr_scfg_base)
			goto err;
	}

	fsl_dp_priv.ccsr_rcpm_base = fsl_of_iomap("fsl,qoriq-rcpm-2.1");
	if (!fsl_dp_priv.ccsr_rcpm_base)
		goto err;

	fsl_dp_priv.ccsr_ddr_base = fsl_of_iomap("fsl,qoriq-memory-controller");
	if (!fsl_dp_priv.ccsr_ddr_base)
		goto err;

	/* find the node of GPIO1 */
	np = NULL;
	while (1) {
		np = of_find_compatible_node(np, NULL, "fsl,qoriq-gpio");
		if (!np)
			goto err;
		of_property_read_u32(np, "reg", &val);
		if (val == GPIO1_OFFSET)
			break;
	}

	fsl_dp_priv.ccsr_gpio1_base = of_iomap(np, 0);
	of_node_put(np);
	if (!fsl_dp_priv.ccsr_gpio1_base)
		goto err;

	fsl_dp_priv.ccsr_cpc_base =
			fsl_of_iomap("fsl,t1040-l3-cache-controller");
	if (!fsl_dp_priv.ccsr_cpc_base) {
		fsl_dp_priv.ccsr_cpc_base =
			fsl_of_iomap("fsl,t1024-l3-cache-controller");
		if (!fsl_dp_priv.ccsr_cpc_base)
			goto err;
	}

	fsl_dp_priv.dcsr_epu_base = fsl_of_iomap("fsl,dcsr-epu");
	if (!fsl_dp_priv.dcsr_epu_base)
		goto err;

	fsl_dp_priv.dcsr_npc_base = fsl_of_iomap("fsl,dcsr-cnpc");
	if (!fsl_dp_priv.dcsr_npc_base)
		goto err;

	fsl_dp_priv.dcsr_rcpm_base = fsl_of_iomap("fsl,dcsr-rcpm");
	if (!fsl_dp_priv.dcsr_rcpm_base)
		goto err;

	fsl_dp_priv.ccsr_lcc_base = fsl_of_iomap("fsl,corenet-law");
	if (!fsl_dp_priv.ccsr_lcc_base)
		goto err;

	np = of_find_compatible_node(NULL, NULL, "fsl,corenet-law");
	if (of_property_read_u32(np, "fsl,num-laws",
				 &fsl_dp_buffer.law_count))
		goto err;

	fsl_dp_buffer.law_regs = kcalloc(fsl_dp_buffer.law_count,
				sizeof(struct fsl_ccsr_law), GFP_KERNEL);
	if (!fsl_dp_buffer.law_regs)
		goto err;

	return 0;
err:
	fsl_dp_iounmap();
	return -1;
}

static void __init fsl_dp_iounmap(void)
{
	void **p = (void *)&fsl_dp_priv;
	int i;

	for (i = 0; i < sizeof(struct fsl_iomap) / sizeof(void *); i++) {
		iounmap(*p);
		*p = NULL;
		p++;
	}
}

int __init fsl_deepsleep_init(void)
{
	return fsl_dp_iomap();
}
