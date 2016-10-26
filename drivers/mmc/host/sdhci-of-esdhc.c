/*
 * Freescale eSDHC controller driver.
 *
 * Copyright (c) 2007, 2010, 2012 Freescale Semiconductor, Inc.
 * Copyright (c) 2009 MontaVista Software, Inc.
 *
 * Authors: Xiaobo Xie <X.Xie@freescale.com>
 *	    Anton Vorontsov <avorontsov@ru.mvista.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include <linux/err.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/fsl/svr.h>
#include <linux/fsl/guts.h>
#include <linux/mmc/host.h>
#include "sdhci-pltfm.h"
#include "sdhci-esdhc.h"

#define VENDOR_V_22	0x12
#define VENDOR_V_23	0x13

/* eSDHC Adapter Card Type */
#define ESDHC_ADAPTER_TYPE_EMMC45	0x1	/* eMMC Card Rev4.5 */
#define ESDHC_ADAPTER_TYPE_SDMMC_LEGACY	0x2	/* SD/MMC Legacy Card */
#define ESDHC_ADAPTER_TYPE_EMMC44	0x3	/* eMMC Card Rev4.4 */
#define ESDHC_ADAPTER_TYPE_RSV		0x4	/* Reserved */
#define ESDHC_ADAPTER_TYPE_MMC		0x5	/* MMC Card */
#define ESDHC_ADAPTER_TYPE_SD		0x6	/* SD Card Rev2.0 3.0 */
#define ESDHC_NO_ADAPTER		0x7	/* No Card is Present*/

static void esdhc_clock_control(struct sdhci_host *host, bool enable);

struct sdhci_esdhc {
	u8 vendor_ver;
	u8 spec_ver;
	u32 soc_ver;
	u8 soc_rev;
	u8 adapter_type;
	unsigned int peripheral_clock;
};

/**
 * esdhc_read*_fixup - Fixup the value read from incompatible eSDHC register
 *		       to make it compatible with SD spec.
 *
 * @host: pointer to sdhci_host
 * @spec_reg: SD spec register address
 * @value: 32bit eSDHC register value on spec_reg address
 *
 * In SD spec, there are 8/16/32/64 bits registers, while all of eSDHC
 * registers are 32 bits. There are differences in register size, register
 * address, register function, bit position and function between eSDHC spec
 * and SD spec.
 *
 * Return a fixed up register value
 */
static u32 esdhc_readl_fixup(struct sdhci_host *host,
				     int spec_reg, u32 value)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_esdhc *esdhc = pltfm_host->priv;
	u32 clsl;
	u32 dlsl;
	u32 ret;

	/*
	 * The bit of ADMA flag in eSDHC is not compatible with standard
	 * SDHC register, so set fake flag SDHCI_CAN_DO_ADMA2 when ADMA is
	 * supported by eSDHC.
	 * And for many FSL eSDHC controller, the reset value of field
	 * SDHCI_CAN_DO_ADMA1 is 1, but some of them can't support ADMA,
	 * only these vendor version is greater than 2.2/0x12 support ADMA.
	 */
	if ((spec_reg == SDHCI_CAPABILITIES) && (value & SDHCI_CAN_DO_ADMA1)) {
		if (esdhc->vendor_ver > VENDOR_V_22) {
			ret = value | SDHCI_CAN_DO_ADMA2;
			return ret;
		}
	}

	if (spec_reg == SDHCI_CAPABILITIES_1) {
		switch (esdhc->adapter_type) {
		case ESDHC_ADAPTER_TYPE_EMMC45:
			if (value & ESDHC_SPEED_MODE_SDR104)
				host->mmc->caps2 |= MMC_CAP2_HS200;
			break;
		case ESDHC_ADAPTER_TYPE_SDMMC_LEGACY:
			if (value & ESDHC_SPEED_MODE_MASK) {
				/* If it exists UHS-I support, enable SDR50 */
				host->mmc->caps |= (MMC_CAP_UHS_SDR50 |
						    MMC_CAP_UHS_SDR25 |
						    MMC_CAP_UHS_SDR12);
			}
			break;
		case ESDHC_ADAPTER_TYPE_EMMC44:
			if (value & ESDHC_SPEED_MODE_DDR50) {
				ret = value & ESDHC_SPEED_MODE_DDR50_SEL;
				/* enable 1/8V DDR capable */
				host->mmc->caps |= MMC_CAP_1_8V_DDR;
				return ret;
			}
			break;
		}
		ret = value & (~ESDHC_SPEED_MODE_MASK);
		return ret;
	}

	if (spec_reg == SDHCI_PRESENT_STATE) {
		clsl = value & ESDHC_CLSL_MASK;
		dlsl = value & ESDHC_DLSL_MASK;
		ret = value &
		      (~((ESDHC_CLSL_MASK << 1) | (ESDHC_DLSL_MASK >> 4)));
		ret |= ((clsl << 1) | (dlsl >> 4));
		return ret;
	}
	ret = value;
	return ret;
}

static u16 esdhc_readw_fixup(struct sdhci_host *host,
				     int spec_reg, u32 value)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_esdhc *esdhc = pltfm_host->priv;
	u16 ret;
	int shift = (spec_reg & 0x2) * 8;

	if (spec_reg == SDHCI_HOST_VERSION)
		ret = value & 0xffff;
	else
		ret = (value >> shift) & 0xffff;

	/* Workaround for T4240-4160-4080-R1.0-R2.0 eSDHC which has incorrect
	 * vendor version and spec version information.
	 */
	if ((spec_reg == SDHCI_HOST_VERSION) &&
	    ((esdhc->soc_ver == SVR_T4240) ||
	     (esdhc->soc_ver == SVR_T4160) ||
	     (esdhc->soc_ver == SVR_T4080)) &&
	    (esdhc->soc_rev <= 0x20))
		ret = (VENDOR_V_23 << SDHCI_VENDOR_VER_SHIFT) | SDHCI_SPEC_200;
	return ret;
}

static u8 esdhc_readb_fixup(struct sdhci_host *host,
				     int spec_reg, u32 value)
{
	u8 ret;
	u8 dma_bits;
	int shift = (spec_reg & 0x3) * 8;

	ret = (value >> shift) & 0xff;

	/*
	 * "DMA select" locates at offset 0x28 in SD specification, but on
	 * P5020 or P3041, it locates at 0x29.
	 */
	if (spec_reg == SDHCI_HOST_CONTROL) {
		/* DMA select is 22,23 bits in Protocol Control Register */
		dma_bits = (value >> 5) & SDHCI_CTRL_DMA_MASK;
		/* fixup the result */
		ret &= ~SDHCI_CTRL_DMA_MASK;
		ret |= dma_bits;
	}
	return ret;
}

/**
 * esdhc_write*_fixup - Fixup the SD spec register value so that it could be
 *			written into eSDHC register.
 *
 * @host: pointer to sdhci_host
 * @spec_reg: SD spec register address
 * @value: 8/16/32bit SD spec register value that would be written
 * @old_value: 32bit eSDHC register value on spec_reg address
 *
 * In SD spec, there are 8/16/32/64 bits registers, while all of eSDHC
 * registers are 32 bits. There are differences in register size, register
 * address, register function, bit position and function between eSDHC spec
 * and SD spec.
 *
 * Return a fixed up register value
 */
static u32 esdhc_writel_fixup(struct sdhci_host *host,
				     int spec_reg, u32 value, u32 old_value)
{
	u32 ret;

	/*
	 * Enabling IRQSTATEN[BGESEN] is just to set IRQSTAT[BGE]
	 * when SYSCTL[RSTD] is set for some special operations.
	 * No any impact on other operation.
	 */
	if (spec_reg == SDHCI_INT_ENABLE)
		ret = value | SDHCI_INT_BLK_GAP;
	else
		ret = value;

	return ret;
}

static u32 esdhc_writew_fixup(struct sdhci_host *host,
				     int spec_reg, u16 value, u32 old_value)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	int shift = (spec_reg & 0x2) * 8;
	u32 ret;

	switch (spec_reg) {
	case SDHCI_TRANSFER_MODE:
		/*
		 * Postpone this write, we must do it together with a
		 * command write that is down below. Return old value.
		 */
		pltfm_host->xfer_mode_shadow = value;
		return old_value;
	case SDHCI_COMMAND:
		ret = (value << 16) | pltfm_host->xfer_mode_shadow;
		return ret;
	}

	ret = old_value & (~(0xffff << shift));
	ret |= (value << shift);

	if (spec_reg == SDHCI_BLOCK_SIZE) {
		/*
		 * Two last DMA bits are reserved, and first one is used for
		 * non-standard blksz of 4096 bytes that we don't support
		 * yet. So clear the DMA boundary bits.
		 */
		ret &= (~SDHCI_MAKE_BLKSZ(0x7, 0));
	}
	return ret;
}

static u32 esdhc_writeb_fixup(struct sdhci_host *host,
				     int spec_reg, u8 value, u32 old_value)
{
	u32 ret;
	u32 dma_bits;
	u8 tmp;
	int shift = (spec_reg & 0x3) * 8;

	/*
	 * eSDHC doesn't have a standard power control register, so we do
	 * nothing here to avoid incorrect operation.
	 */
	if (spec_reg == SDHCI_POWER_CONTROL)
		return old_value;
	/*
	 * "DMA select" location is offset 0x28 in SD specification, but on
	 * P5020 or P3041, it's located at 0x29.
	 */
	if (spec_reg == SDHCI_HOST_CONTROL) {
		/*
		 * If host control register is not standard, exit
		 * this function
		 */
		if (host->quirks2 & SDHCI_QUIRK2_BROKEN_HOST_CONTROL)
			return old_value;

		/* DMA select is 22,23 bits in Protocol Control Register */
		dma_bits = (value & SDHCI_CTRL_DMA_MASK) << 5;
		ret = (old_value & (~(SDHCI_CTRL_DMA_MASK << 5))) | dma_bits;
		tmp = (value & (~SDHCI_CTRL_DMA_MASK)) |
		      (old_value & SDHCI_CTRL_DMA_MASK);
		ret = (ret & (~0xff)) | tmp;

		/* Prevent SDHCI core from writing reserved bits (e.g. HISPD) */
		ret &= ~ESDHC_HOST_CONTROL_RES;
		ret &= ~SDHCI_CTRL_HISPD;
		ret |= (old_value & SDHCI_CTRL_HISPD);
		return ret;
	}

	ret = (old_value & (~(0xff << shift))) | (value << shift);
	return ret;
}

static u32 esdhc_be_readl(struct sdhci_host *host, int reg)
{
	u32 ret;
	u32 value;

	/*
	 * The eSDHC CAPABILITIES_1 register has a large address offset
	 * from the standard CAPABILITIES_1 register. So, we have to
	 * fix this here rather than in fixup function.
	 */
	if (reg == SDHCI_CAPABILITIES_1)
		value = ioread32be(host->ioaddr + ESDHC_CAPABILITIES_1);
	else
		value = ioread32be(host->ioaddr + reg);
	ret = esdhc_readl_fixup(host, reg, value);

	return ret;
}

static u32 esdhc_le_readl(struct sdhci_host *host, int reg)
{
	u32 ret;
	u32 value;

	/*
	 * The eSDHC CAPABILITIES_1 register has a large address offset
	 * from the standard CAPABILITIES_1 register. So, we have to
	 * fix this here rather than in fixup function.
	 */
	if (reg == SDHCI_CAPABILITIES_1)
		value = ioread32(host->ioaddr + ESDHC_CAPABILITIES_1);
	else
		value = ioread32(host->ioaddr + reg);
	ret = esdhc_readl_fixup(host, reg, value);

	return ret;
}

static u16 esdhc_be_readw(struct sdhci_host *host, int reg)
{
	u16 ret;
	u32 value;
	int base = reg & ~0x3;

	value = ioread32be(host->ioaddr + base);
	ret = esdhc_readw_fixup(host, reg, value);
	return ret;
}

static u16 esdhc_le_readw(struct sdhci_host *host, int reg)
{
	u16 ret;
	u32 value;
	int base = reg & ~0x3;

	value = ioread32(host->ioaddr + base);
	ret = esdhc_readw_fixup(host, reg, value);
	return ret;
}

static u8 esdhc_be_readb(struct sdhci_host *host, int reg)
{
	u8 ret;
	u32 value;
	int base = reg & ~0x3;

	value = ioread32be(host->ioaddr + base);
	ret = esdhc_readb_fixup(host, reg, value);
	return ret;
}

static u8 esdhc_le_readb(struct sdhci_host *host, int reg)
{
	u8 ret;
	u32 value;
	int base = reg & ~0x3;

	value = ioread32(host->ioaddr + base);
	ret = esdhc_readb_fixup(host, reg, value);
	return ret;
}

static void esdhc_be_writel(struct sdhci_host *host, u32 val, int reg)
{
	u32 value;

	value = esdhc_writel_fixup(host, reg, val, 0);
	iowrite32be(value, host->ioaddr + reg);
}

static void esdhc_le_writel(struct sdhci_host *host, u32 val, int reg)
{
	u32 value;

	value = esdhc_writel_fixup(host, reg, val, 0);
	iowrite32(value, host->ioaddr + reg);
}

static void esdhc_be_writew(struct sdhci_host *host, u16 val, int reg)
{
	int base = reg & ~0x3;
	u32 value;
	u32 ret;

	value = ioread32be(host->ioaddr + base);
	ret = esdhc_writew_fixup(host, reg, val, value);
	if (reg != SDHCI_TRANSFER_MODE)
		iowrite32be(ret, host->ioaddr + base);
}

static void esdhc_le_writew(struct sdhci_host *host, u16 val, int reg)
{
	int base = reg & ~0x3;
	u32 value;
	u32 ret;

	value = ioread32(host->ioaddr + base);
	ret = esdhc_writew_fixup(host, reg, val, value);
	if (reg != SDHCI_TRANSFER_MODE)
		iowrite32(ret, host->ioaddr + base);
}

static void esdhc_be_writeb(struct sdhci_host *host, u8 val, int reg)
{
	int base = reg & ~0x3;
	u32 value;
	u32 ret;

	value = ioread32be(host->ioaddr + base);
	ret = esdhc_writeb_fixup(host, reg, val, value);
	iowrite32be(ret, host->ioaddr + base);
}

static void esdhc_le_writeb(struct sdhci_host *host, u8 val, int reg)
{
	int base = reg & ~0x3;
	u32 value;
	u32 ret;

	value = ioread32(host->ioaddr + base);
	ret = esdhc_writeb_fixup(host, reg, val, value);
	iowrite32(ret, host->ioaddr + base);
}

/*
 * For Abort or Suspend after Stop at Block Gap, ignore the ADMA
 * error(IRQSTAT[ADMAE]) if both Transfer Complete(IRQSTAT[TC])
 * and Block Gap Event(IRQSTAT[BGE]) are also set.
 * For Continue, apply soft reset for data(SYSCTL[RSTD]);
 * and re-issue the entire read transaction from beginning.
 */
static void esdhc_of_adma_workaround(struct sdhci_host *host, u32 intmask)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_esdhc *esdhc = pltfm_host->priv;
	bool applicable;
	dma_addr_t dmastart;
	dma_addr_t dmanow;

	applicable = (intmask & SDHCI_INT_DATA_END) &&
		     (intmask & SDHCI_INT_BLK_GAP) &&
		     (esdhc->vendor_ver == VENDOR_V_23);
	if (applicable) {

		sdhci_reset(host, SDHCI_RESET_DATA);
		host->data->error = 0;
		dmastart = sg_dma_address(host->data->sg);
		dmanow = dmastart + host->data->bytes_xfered;
		/*
		 * Force update to the next DMA block boundary.
		 */
		dmanow = (dmanow & ~(SDHCI_DEFAULT_BOUNDARY_SIZE - 1)) +
			SDHCI_DEFAULT_BOUNDARY_SIZE;
		host->data->bytes_xfered = dmanow - dmastart;
		sdhci_writel(host, dmanow, SDHCI_DMA_ADDRESS);

		return;
	}

	/*
	 * Check for A-004388: eSDHC DMA might not stop if error
	 * occurs on system transaction
	 * Impact list:
	 * T4240-4160-4080-R1.0 B4860-4420-R1.0-R2.0 P1010-1014-R1.0
	 * P3041-R1.0-R2.0-R1.1 P2041-2040-R1.0-R1.1-R2.0
	 * P5020-5010-R2.0-R1.0 P5040-5021-R2.0-R2.1
	 */
	if (!(((esdhc->soc_ver == SVR_T4240) && (esdhc->soc_rev == 0x10)) ||
		((esdhc->soc_ver == SVR_T4160) && (esdhc->soc_rev == 0x10)) ||
		((esdhc->soc_ver == SVR_T4080) && (esdhc->soc_rev == 0x10)) ||
		((esdhc->soc_ver == SVR_B4860) && (esdhc->soc_rev == 0x10)) ||
		((esdhc->soc_ver == SVR_B4860) && (esdhc->soc_rev == 0x20)) ||
		((esdhc->soc_ver == SVR_B4420) && (esdhc->soc_rev == 0x10)) ||
		((esdhc->soc_ver == SVR_B4420) && (esdhc->soc_rev == 0x20)) ||
		((esdhc->soc_ver == SVR_P1010) && (esdhc->soc_rev == 0x10)) ||
		((esdhc->soc_ver == SVR_P1014) && (esdhc->soc_rev == 0x10)) ||
		((esdhc->soc_ver == SVR_P3041) && (esdhc->soc_rev <= 0x20)) ||
		((esdhc->soc_ver == SVR_P2041) && (esdhc->soc_rev <= 0x20)) ||
		((esdhc->soc_ver == SVR_P2040) && (esdhc->soc_rev <= 0x20)) ||
		((esdhc->soc_ver == SVR_P5020) && (esdhc->soc_rev <= 0x20)) ||
		((esdhc->soc_ver == SVR_P5010) && (esdhc->soc_rev <= 0x20)) ||
		((esdhc->soc_ver == SVR_P5040) && (esdhc->soc_rev <= 0x21)) ||
		((esdhc->soc_ver == SVR_P5021) && (esdhc->soc_rev <= 0x21))))
		return;

	sdhci_reset(host, SDHCI_RESET_DATA);

	if (host->flags & SDHCI_USE_ADMA) {
		u32 mod, i, offset;
		u8 *desc;
		dma_addr_t addr;
		struct scatterlist *sg;
		__le32 *dataddr;
		__le32 *cmdlen;

		/*
		 * If block count was enabled, in case read transfer there
		 * is no data was corrupted
		 */
		mod = sdhci_readl(host, SDHCI_TRANSFER_MODE);
		if ((mod & SDHCI_TRNS_BLK_CNT_EN) &&
				(host->data->flags & MMC_DATA_READ))
			host->data->error = 0;

		BUG_ON(!host->data);
		desc = host->adma_table;
		for_each_sg(host->data->sg, sg, host->sg_count, i) {
			addr = sg_dma_address(sg);
			offset = (4 - (addr & 0x3)) & 0x3;
			if (offset)
				desc += 8;
			desc += 8;
		}

		/*
		 * Add an extra zero descriptor next to the
		 * terminating descriptor.
		 */
		desc += 8;
		WARN_ON((desc - (u8 *)(host->adma_table)) > (128 * 2 + 1) * 4);

		dataddr = (__le32 __force *)(desc + 4);
		cmdlen = (__le32 __force *)desc;

		cmdlen[0] = cpu_to_le32(0);
		dataddr[0] = cpu_to_le32(0);
	}

	if ((host->flags & SDHCI_USE_SDMA) &&
			(host->data->flags & MMC_DATA_READ))
		host->data->error = 0;

	return;
}

static int esdhc_of_enable_dma(struct sdhci_host *host)
{
	u32 value;

	value = sdhci_readl(host, ESDHC_DMA_SYSCTL);
	value |= ESDHC_DMA_SNOOP;
	sdhci_writel(host, value, ESDHC_DMA_SYSCTL);
	return 0;
}

static unsigned int esdhc_of_get_max_clock(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);

	return pltfm_host->clock;
}

static unsigned int esdhc_of_get_min_clock(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);

	return pltfm_host->clock / 256 / 16;
}

static void esdhc_of_set_clock(struct sdhci_host *host, unsigned int clock)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_esdhc *esdhc = pltfm_host->priv;
	int pre_div = 1;
	int div = 1;
	u32 temp;
	u32 timeout;

	host->mmc->actual_clock = 0;

	if (clock == 0) {
		esdhc_clock_control(host, false);
		return;
	}

	/* Workaround to start pre_div at 2 for VNN < VENDOR_V_23 */
	if (esdhc->vendor_ver < VENDOR_V_23)
		pre_div = 2;

	/* Workaround to reduce the clock frequency for p1010 esdhc */
	if (of_find_compatible_node(NULL, NULL, "fsl,p1010-esdhc")) {
		if (clock > 20000000)
			clock -= 5000000;
		if (clock > 40000000)
			clock -= 5000000;
	}

	temp = sdhci_readl(host, ESDHC_SYSTEM_CONTROL);
	temp &= ~(ESDHC_CLOCK_IPGEN | ESDHC_CLOCK_HCKEN | ESDHC_CLOCK_PEREN
		| ESDHC_CLOCK_CRDEN | ESDHC_CLOCK_MASK);
	sdhci_writel(host, temp, ESDHC_SYSTEM_CONTROL);

	while (host->max_clk / pre_div / 16 > clock && pre_div < 256)
		pre_div *= 2;

	while (host->max_clk / pre_div / div > clock && div < 16)
		div++;

	dev_dbg(mmc_dev(host->mmc), "desired SD clock: %d, actual: %d\n",
		clock, host->max_clk / pre_div / div);
	host->mmc->actual_clock = host->max_clk / pre_div / div;
	pre_div >>= 1;
	div--;

	temp = sdhci_readl(host, ESDHC_SYSTEM_CONTROL);
	temp |= (ESDHC_CLOCK_IPGEN | ESDHC_CLOCK_HCKEN | ESDHC_CLOCK_PEREN
		| (div << ESDHC_DIVIDER_SHIFT)
		| (pre_div << ESDHC_PREDIV_SHIFT));
	sdhci_writel(host, temp, ESDHC_SYSTEM_CONTROL);

	/* Wait max 20 ms */
	timeout = 20;
	while (!(sdhci_readl(host, ESDHC_PRESENT_STATE) & ESDHC_CLOCK_STABLE)) {
		if (timeout == 0) {
			pr_err("%s: Internal clock never stabilised.\n",
				mmc_hostname(host->mmc));
			return;
		}
		timeout--;
		mdelay(1);
	}

	temp |= ESDHC_CLOCK_CRDEN;
	sdhci_writel(host, temp, ESDHC_SYSTEM_CONTROL);
}

static void esdhc_pltfm_set_bus_width(struct sdhci_host *host, int width)
{
	u32 ctrl;

	ctrl = sdhci_readl(host, ESDHC_PROCTL);
	ctrl &= (~ESDHC_CTRL_BUSWIDTH_MASK);
	switch (width) {
	case MMC_BUS_WIDTH_8:
		ctrl |= ESDHC_CTRL_8BITBUS;
		break;

	case MMC_BUS_WIDTH_4:
		ctrl |= ESDHC_CTRL_4BITBUS;
		break;

	default:
		break;
	}

	sdhci_writel(host, ctrl, ESDHC_PROCTL);
}

/*
 * A-003980: SDHC: Glitch is generated on the card clock with software reset
 * or clock divider change
 * Workaround:
 * A simple workaround is to disable the SD card clock before the software
 * reset, and enable it when the module resumes normal operation. The Host
 * and the SD card are in a master-slave relationship. The Host provides
 * clock and control transfer across the interface. Therefore, any existing
 * operation is discarded when the Host controller is reset.
 */
static int esdhc_of_reset_workaround(struct sdhci_host *host, u8 mask)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_esdhc *esdhc = pltfm_host->priv;
	bool disable_clk_before_reset = false;
	u32 temp;

	/*
	 * Check for A-003980
	 * Impact list:
	 * T4240-4160-4080-R1.0-R2.0 B4860-4420-R1.0-R2.0
	 * P5040-5021-R1.0-R2.0-R2.1 P5020-5010-R1.0-R2.0
	 * P3041-R1.0-R1.1-R2.0 P2041-2040-R1.0-R1.1-R2.0
	 * P1010-1014-R1.0
	 */
	if (((esdhc->soc_ver == SVR_T4240) && (esdhc->soc_rev == 0x10)) ||
	    ((esdhc->soc_ver == SVR_T4240) && (esdhc->soc_rev == 0x20)) ||
	    ((esdhc->soc_ver == SVR_T4160) && (esdhc->soc_rev == 0x10)) ||
	    ((esdhc->soc_ver == SVR_T4160) && (esdhc->soc_rev == 0x20)) ||
	    ((esdhc->soc_ver == SVR_T4080) && (esdhc->soc_rev == 0x10)) ||
	    ((esdhc->soc_ver == SVR_T4080) && (esdhc->soc_rev == 0x20)) ||
	    ((esdhc->soc_ver == SVR_B4860) && (esdhc->soc_rev == 0x10)) ||
	    ((esdhc->soc_ver == SVR_B4860) && (esdhc->soc_rev == 0x20)) ||
	    ((esdhc->soc_ver == SVR_B4420) && (esdhc->soc_rev == 0x10)) ||
	    ((esdhc->soc_ver == SVR_B4420) && (esdhc->soc_rev == 0x20)) ||
	    ((esdhc->soc_ver == SVR_P5040) && (esdhc->soc_rev <= 0x21)) ||
	    ((esdhc->soc_ver == SVR_P5021) && (esdhc->soc_rev <= 0x21)) ||
	    ((esdhc->soc_ver == SVR_P5020) && (esdhc->soc_rev <= 0x20)) ||
	    ((esdhc->soc_ver == SVR_P5010) && (esdhc->soc_rev <= 0x20)) ||
	    ((esdhc->soc_ver == SVR_P3041) && (esdhc->soc_rev <= 0x20)) ||
	    ((esdhc->soc_ver == SVR_P2041) && (esdhc->soc_rev <= 0x20)) ||
	    ((esdhc->soc_ver == SVR_P2040) && (esdhc->soc_rev <= 0x20)) ||
	    ((esdhc->soc_ver == SVR_P1014) && (esdhc->soc_rev == 0x10)) ||
	    ((esdhc->soc_ver == SVR_P1010) && (esdhc->soc_rev == 0x10)))
		disable_clk_before_reset = true;

	if (disable_clk_before_reset && (mask & SDHCI_RESET_ALL)) {
		temp = sdhci_readl(host, ESDHC_SYSTEM_CONTROL);
		temp &= ~ESDHC_CLOCK_CRDEN;
		sdhci_writel(host, temp, ESDHC_SYSTEM_CONTROL);
		sdhci_reset(host, mask);
		temp = sdhci_readl(host, ESDHC_SYSTEM_CONTROL);
		temp |= ESDHC_CLOCK_CRDEN;
		sdhci_writel(host, temp, ESDHC_SYSTEM_CONTROL);
		return 1;
	}
	return 0;
}

static void esdhc_reset(struct sdhci_host *host, u8 mask)
{
	if (!esdhc_of_reset_workaround(host, mask))
		sdhci_reset(host, mask);

	sdhci_writel(host, host->ier, SDHCI_INT_ENABLE);
	sdhci_writel(host, host->ier, SDHCI_SIGNAL_ENABLE);
}

#ifdef CONFIG_PM
static u32 esdhc_proctl;
static int esdhc_of_suspend(struct device *dev)
{
	struct sdhci_host *host = dev_get_drvdata(dev);

	esdhc_proctl = sdhci_readl(host, SDHCI_HOST_CONTROL);

	return sdhci_suspend_host(host);
}

static int esdhc_of_resume(struct device *dev)
{
	struct sdhci_host *host = dev_get_drvdata(dev);
	int ret = sdhci_resume_host(host);

	if (ret == 0)
		sdhci_writel(host, esdhc_proctl, SDHCI_HOST_CONTROL);

	return ret;
}

static const struct dev_pm_ops esdhc_pmops = {
	.suspend	= esdhc_of_suspend,
	.resume		= esdhc_of_resume,
};
#define ESDHC_PMOPS (&esdhc_pmops)
#else
#define ESDHC_PMOPS NULL
#endif

static void esdhc_clock_control(struct sdhci_host *host, bool enable)
{
	u32 val;
	u32 timeout;

	val = sdhci_readl(host, ESDHC_SYSTEM_CONTROL);

	if (enable)
		val |= ESDHC_CLOCK_CRDEN;
	else
		val &= ~ESDHC_CLOCK_CRDEN;

	sdhci_writel(host, val, ESDHC_SYSTEM_CONTROL);

	timeout = 20;
	val = ESDHC_CLOCK_STABLE;
	while (!(sdhci_readl(host, ESDHC_PRESENT_STATE) & val)) {
		if (timeout == 0) {
			pr_err("%s: Internal clock never stabilised.\n",
				mmc_hostname(host->mmc));
			break;
		}
		timeout--;
		mdelay(1);
	}
}

static void esdhc_set_uhs_signaling(struct sdhci_host *host, unsigned int uhs)
{
	u16 ctrl_2;
	u32 val;
	u32 timeout;

	ctrl_2 = sdhci_readw(host, SDHCI_HOST_CONTROL2);
	/* Select Bus Speed Mode for host */
	ctrl_2 &= ~SDHCI_CTRL_UHS_MASK;
	if ((uhs == MMC_TIMING_MMC_HS200) ||
		(uhs == MMC_TIMING_UHS_SDR104))
		ctrl_2 |= SDHCI_CTRL_UHS_SDR104;
	else if (uhs == MMC_TIMING_UHS_SDR12)
		ctrl_2 |= SDHCI_CTRL_UHS_SDR12;
	else if (uhs == MMC_TIMING_UHS_SDR25)
		ctrl_2 |= SDHCI_CTRL_UHS_SDR25;
	else if (uhs == MMC_TIMING_UHS_SDR50)
		ctrl_2 |= SDHCI_CTRL_UHS_SDR50;
	else if ((uhs == MMC_TIMING_UHS_DDR50) ||
		 (uhs == MMC_TIMING_MMC_DDR52))
		ctrl_2 |= SDHCI_CTRL_UHS_DDR50;
	else if (uhs == MMC_TIMING_MMC_HS400)
		ctrl_2 |= SDHCI_CTRL_HS400; /* Non-standard */

	if ((uhs == MMC_TIMING_UHS_DDR50) ||
	    (uhs == MMC_TIMING_MMC_DDR52)) {
		esdhc_clock_control(host, false);
		sdhci_writew(host, ctrl_2, SDHCI_HOST_CONTROL2);
		val = sdhci_readl(host, ESDHC_CLOCK_CONTROL);
		val |= (ESDHC_LPBK_CLK_SEL | ESDHC_CMD_CLK_CTL);
		sdhci_writel(host, val, ESDHC_CLOCK_CONTROL);
		esdhc_clock_control(host, true);

		esdhc_clock_control(host, false);
		val = sdhci_readl(host, ESDHC_DMA_SYSCTL);
		val |= ESDHC_FLUSH_ASYNC_FIFO;
		sdhci_writel(host, val, ESDHC_DMA_SYSCTL);
		/* Wait max 20 ms */
		timeout = 20;
		val = ESDHC_FLUSH_ASYNC_FIFO;
		while (sdhci_readl(host, ESDHC_DMA_SYSCTL) & val) {
			if (timeout == 0) {
				pr_err("%s: FAF bit is auto cleaned failed.\n",
					mmc_hostname(host->mmc));

				break;
			}
			timeout--;
			mdelay(1);
		}
		esdhc_clock_control(host, true);
	} else
		sdhci_writew(host, ctrl_2, SDHCI_HOST_CONTROL2);
}

static const struct of_device_id scfg_device_ids[] = {
	{ .compatible = "fsl,t1040-scfg", },
	{}
};
#define SCFG_SDHCIOVSELCR	0x408
#define SDHCIOVSELCR_TGLEN	0x80000000
#define SDHCIOVSELCR_SDHC_VS	0x00000001

void esdhc_signal_voltage_switch(struct sdhci_host *host,
				 unsigned char signal_voltage)
{
	struct device_node *scfg_node;
	void __iomem *scfg_base = NULL;
	u32 scfg_sdhciovselcr;
	u32 val;

	val = sdhci_readl(host, ESDHC_PROCTL);

	switch (signal_voltage) {
	case MMC_SIGNAL_VOLTAGE_330:
		val &= (~ESDHC_VOLT_SEL);
		sdhci_writel(host, val, ESDHC_PROCTL);
		break;
	case MMC_SIGNAL_VOLTAGE_180:
		scfg_node = of_find_matching_node(NULL, scfg_device_ids);
		if (scfg_node) {
			scfg_base = of_iomap(scfg_node, 0);
			of_node_put(scfg_node);
		}
		if (scfg_base) {
			scfg_sdhciovselcr = SDHCIOVSELCR_TGLEN |
					    SDHCIOVSELCR_SDHC_VS;
			iowrite32be(scfg_sdhciovselcr,
				scfg_base + SCFG_SDHCIOVSELCR);
			iounmap(scfg_base);
		}
		val |= ESDHC_VOLT_SEL;
		sdhci_writel(host, val, ESDHC_PROCTL);
		break;
	default:
		return;
	}
}

void esdhc_set_tuning_block(struct sdhci_host *host)
{
	u32 val;

	esdhc_clock_control(host, false);
	val = sdhci_readl(host, ESDHC_DMA_SYSCTL);
	val |= ESDHC_FLUSH_ASYNC_FIFO;
	sdhci_writel(host, val, ESDHC_DMA_SYSCTL);

	val = sdhci_readl(host, ESDHC_TBCTL);
	val |= ESDHC_TB_EN;
	sdhci_writel(host, val, ESDHC_TBCTL);
	esdhc_clock_control(host, true);
}

static const struct sdhci_ops sdhci_esdhc_be_ops = {
	.read_l = esdhc_be_readl,
	.read_w = esdhc_be_readw,
	.read_b = esdhc_be_readb,
	.write_l = esdhc_be_writel,
	.write_w = esdhc_be_writew,
	.write_b = esdhc_be_writeb,
	.set_clock = esdhc_of_set_clock,
	.enable_dma = esdhc_of_enable_dma,
	.get_max_clock = esdhc_of_get_max_clock,
	.get_min_clock = esdhc_of_get_min_clock,
	.adma_workaround = esdhc_of_adma_workaround,
	.set_bus_width = esdhc_pltfm_set_bus_width,
	.reset = esdhc_reset,
	.set_uhs_signaling = esdhc_set_uhs_signaling,
	.signal_voltage_switch = esdhc_signal_voltage_switch,
	.set_tuning_block = esdhc_set_tuning_block,
};

static const struct sdhci_ops sdhci_esdhc_le_ops = {
	.read_l = esdhc_le_readl,
	.read_w = esdhc_le_readw,
	.read_b = esdhc_le_readb,
	.write_l = esdhc_le_writel,
	.write_w = esdhc_le_writew,
	.write_b = esdhc_le_writeb,
	.set_clock = esdhc_of_set_clock,
	.enable_dma = esdhc_of_enable_dma,
	.get_max_clock = esdhc_of_get_max_clock,
	.get_min_clock = esdhc_of_get_min_clock,
	.adma_workaround = esdhc_of_adma_workaround,
	.set_bus_width = esdhc_pltfm_set_bus_width,
	.reset = esdhc_reset,
	.set_uhs_signaling = esdhc_set_uhs_signaling,
	.signal_voltage_switch = esdhc_signal_voltage_switch,
	.set_tuning_block = esdhc_set_tuning_block,
};

static const struct sdhci_pltfm_data sdhci_esdhc_be_pdata = {
	.quirks = ESDHC_DEFAULT_QUIRKS | SDHCI_QUIRK_BROKEN_CARD_DETECTION
		| SDHCI_QUIRK_NO_CARD_NO_RESET
		| SDHCI_QUIRK_NO_ENDATTR_IN_NOPDESC,
	.ops = &sdhci_esdhc_be_ops,
};

static const struct sdhci_pltfm_data sdhci_esdhc_le_pdata = {
	.quirks = ESDHC_DEFAULT_QUIRKS | SDHCI_QUIRK_BROKEN_CARD_DETECTION
		| SDHCI_QUIRK_NO_CARD_NO_RESET
		| SDHCI_QUIRK_NO_ENDATTR_IN_NOPDESC,
	.ops = &sdhci_esdhc_le_ops,
};

static void esdhc_init(struct platform_device *pdev, struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host;
	struct sdhci_esdhc *esdhc;
	struct device_node *np;
	const __be32 *val;
	int size;
	u16 host_ver;
	u32 svr;

	pltfm_host = sdhci_priv(host);
	esdhc = devm_kzalloc(&pdev->dev, sizeof(struct sdhci_esdhc),
			     GFP_KERNEL);
	pltfm_host->priv = esdhc;

	svr = fsl_guts_get_svr();
	esdhc->soc_ver = SVR_SOC_VER(svr);
	esdhc->soc_rev = SVR_REV(svr);

	host_ver = sdhci_readw(host, SDHCI_HOST_VERSION);
	esdhc->vendor_ver = (host_ver & SDHCI_VENDOR_VER_MASK) >>
			     SDHCI_VENDOR_VER_SHIFT;
	esdhc->spec_ver = host_ver & SDHCI_SPEC_VER_MASK;

	np = pdev->dev.of_node;
	val = of_get_property(np, "adapter-type", &size);
	if (val && size == sizeof(*val) && *val)
		esdhc->adapter_type = be32_to_cpup(val);

	val = of_get_property(np, "peripheral-frequency", &size);
	if (val && size == sizeof(*val) && *val)
		esdhc->peripheral_clock = be32_to_cpup(val);
}

static int sdhci_esdhc_probe(struct platform_device *pdev)
{
	struct sdhci_host *host;
	struct device_node *np;
	struct sdhci_pltfm_host *pltfm_host;
	struct sdhci_esdhc *esdhc;
	int ret;
	u32 val;

	np = pdev->dev.of_node;

	if (of_get_property(np, "little-endian", NULL))
		host = sdhci_pltfm_init(pdev, &sdhci_esdhc_le_pdata, 0);
	else
		host = sdhci_pltfm_init(pdev, &sdhci_esdhc_be_pdata, 0);

	if (IS_ERR(host))
		return PTR_ERR(host);

	esdhc_init(pdev, host);

	sdhci_get_of_property(pdev);

	pltfm_host = sdhci_priv(host);
	esdhc = pltfm_host->priv;
	if (esdhc->vendor_ver == VENDOR_V_22)
		host->quirks2 |= SDHCI_QUIRK2_HOST_NO_CMD23;

	if (esdhc->vendor_ver > VENDOR_V_22)
		host->quirks &= ~SDHCI_QUIRK_NO_BUSY_IRQ;

	host->quirks2 |= SDHCI_QUIRK2_DELAY_BETWEEN_TUNING_CYCLES;

	if (of_device_is_compatible(np, "fsl,p5040-esdhc") ||
	    of_device_is_compatible(np, "fsl,p5020-esdhc") ||
	    of_device_is_compatible(np, "fsl,p4080-esdhc") ||
	    of_device_is_compatible(np, "fsl,p1020-esdhc") ||
	    of_device_is_compatible(np, "fsl,t1040-esdhc") ||
	    of_device_is_compatible(np, "fsl,ls1021a-esdhc") ||
	    of_device_is_compatible(np, "fsl,ls2080a-esdhc") ||
	    of_device_is_compatible(np, "fsl,ls2085a-esdhc") ||
	    of_device_is_compatible(np, "fsl,ls1043a-esdhc") ||
	    of_device_is_compatible(np, "fsl,ls1046a-esdhc"))
		host->quirks &= ~SDHCI_QUIRK_BROKEN_CARD_DETECTION;

	if (of_device_is_compatible(np, "fsl,ls1021a-esdhc"))
		host->quirks |= SDHCI_QUIRK_BROKEN_TIMEOUT_VAL;

	if (of_device_is_compatible(np, "fsl,p2020-esdhc")) {
		/*
		 * Freescale messed up with P2020 as it has a non-standard
		 * host control register
		 */
		host->quirks2 |= SDHCI_QUIRK2_BROKEN_HOST_CONTROL;
	}

	/* call to generic mmc_of_parse to support additional capabilities */
	ret = mmc_of_parse(host->mmc);
	if (ret)
		goto err;

	mmc_of_parse_voltage(np, &host->ocr_mask);

	/* Select peripheral clock as the eSDHC clock */
	if (esdhc->peripheral_clock) {
		pltfm_host->clock = esdhc->peripheral_clock;
		esdhc_clock_control(host, false);
		val = sdhci_readl(host, ESDHC_DMA_SYSCTL);
		val |= ESDHC_PERIPHERAL_CLK_SEL;
		sdhci_writel(host, val, ESDHC_DMA_SYSCTL);
		esdhc_clock_control(host, true);
	}

	ret = sdhci_add_host(host);
	if (ret)
		goto err;

	return 0;
 err:
	sdhci_pltfm_free(pdev);
	return ret;
}

static const struct of_device_id sdhci_esdhc_of_match[] = {
	{ .compatible = "fsl,mpc8379-esdhc" },
	{ .compatible = "fsl,mpc8536-esdhc" },
	{ .compatible = "fsl,esdhc" },
	{ }
};
MODULE_DEVICE_TABLE(of, sdhci_esdhc_of_match);

static struct platform_driver sdhci_esdhc_driver = {
	.driver = {
		.name = "sdhci-esdhc",
		.of_match_table = sdhci_esdhc_of_match,
		.pm = ESDHC_PMOPS,
	},
	.probe = sdhci_esdhc_probe,
	.remove = sdhci_pltfm_unregister,
};

module_platform_driver(sdhci_esdhc_driver);

MODULE_DESCRIPTION("SDHCI OF driver for Freescale MPC eSDHC");
MODULE_AUTHOR("Xiaobo Xie <X.Xie@freescale.com>, "
	      "Anton Vorontsov <avorontsov@ru.mvista.com>");
MODULE_LICENSE("GPL v2");
