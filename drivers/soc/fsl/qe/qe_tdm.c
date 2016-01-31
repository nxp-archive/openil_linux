/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Authors:	Zhao Qiang <qiang.zhao@nxp.com>
 *
 * Description:
 * QE TDM API Set - TDM specific routines implementations.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <soc/fsl/qe/qe_tdm.h>

/* #define DEBUG */

#ifdef DEBUG
static void dump_siram(struct ucc_tdm *utdm)
{
	int i;
	u16 *siram = utdm->siram;

	pr_info("QE-TDM: Dump the SI RX RAM\n");
	for (i = 0; i < utdm->num_of_ts; i++) {
		pr_info("%04x ",
			be16_to_cpu(siram[utdm->siram_entry_id * 32 + i]));
		if (!((i + 1) & 3))
			pr_info("\n");
	}

	pr_info("QE-TDM: Dump the SI TX RAM\n");
	for (i = 0; i < utdm->num_of_ts; i++) {
		pr_info("%04x ", be16_to_cpu(siram[utdm->siram_entry_id * 32 +
			0x200 + i]));
		if (!((i + 1) & 3))
			pr_info("\n");
	}
}
#endif

static enum tdm_mode_t set_tdm_mode(const char *tdm_mode_type)
{
	if (strcasecmp(tdm_mode_type, "internal-loopback") == 0)
		return TDM_INTERNAL_LOOPBACK;
	else
		return TDM_NORMAL;
}

static enum tdm_framer_t set_tdm_framer(const char *tdm_framer_type)
{
	if (strcasecmp(tdm_framer_type, "e1") == 0)
		return TDM_FRAMER_E1;
	else
		return TDM_FRAMER_T1;
}

static void set_si_param(struct ucc_tdm *utdm, struct ucc_tdm_info *ut_info)
{
	struct si_mode_info *si_info = &ut_info->si_info;

	if (utdm->tdm_mode == TDM_INTERNAL_LOOPBACK) {
		si_info->simr_crt = 1;
		si_info->simr_rfsd = 0;
	}
}

int of_parse_tdm(struct device_node *np,
		struct ucc_tdm *utdm, struct ucc_tdm_info *ut_info)
{
	const char *sprop;
	int ret = 0;
	u32 val;
	struct resource res;
	struct device_node *np2;
	static int siram_init_flag;

	sprop = of_get_property(np, "fsl,rx-sync-clock", NULL);
	if (sprop) {
		ut_info->uf_info.rx_sync = qe_clock_source(sprop);
		if ((ut_info->uf_info.rx_sync < QE_CLK_NONE) ||
			(ut_info->uf_info.rx_sync > QE_RSYNC_PIN)) {
			pr_err("QE-TDM: Invalid rx-sync-clock property\n");
		return -EINVAL;
		}
	} else {
		pr_err("QE-TDM: Invalid rx-sync-clock property\n");
		return -EINVAL;
	}

	sprop = of_get_property(np, "fsl,tx-sync-clock", NULL);
	if (sprop) {
		ut_info->uf_info.tx_sync = qe_clock_source(sprop);
		if ((ut_info->uf_info.tx_sync < QE_CLK_NONE) ||
			(ut_info->uf_info.tx_sync > QE_TSYNC_PIN)) {
			pr_err("QE-TDM: Invalid tx-sync-clock property\n");
		return -EINVAL;
		}
	} else {
		pr_err("QE-TDM: Invalid tx-sync-clock property\n");
		return -EINVAL;
	}

	ret = of_property_read_u32_index(np, "fsl,tx-timeslot", 0, &val);
	if (ret) {
		ret = -EINVAL;
		pr_err("QE-TDM: Invalid tx-timeslot property\n");
		return ret;
	}
	utdm->tx_ts_mask = val;

	ret = of_property_read_u32_index(np, "fsl,rx-timeslot", 0, &val);
	if (ret) {
		ret = -EINVAL;
		pr_err("QE-TDM: Invalid rx-timeslot property\n");
		return ret;
	}
	utdm->rx_ts_mask = val;

	ret = of_property_read_u32_index(np, "fsl,tdm-id", 0, &val);
	if (ret) {
		ret = -EINVAL;
		pr_err("QE-TDM: No fsl,tdm-id property for this UCC\n");
		return ret;
	}
	utdm->tdm_port = val;
	ut_info->uf_info.tdm_num = utdm->tdm_port;

	sprop = of_get_property(np, "fsl,tdm-mode", NULL);
	if (!sprop) {
		ret = -EINVAL;
		pr_err("QE-TDM: No tdm-mode property for UCC\n");
		return ret;
	}
	utdm->tdm_mode = set_tdm_mode(sprop);

	sprop = of_get_property(np, "fsl,tdm-framer-type", NULL);
	if (!sprop) {
		ret = -EINVAL;
		pr_err("QE-TDM: No tdm-framer-type property for UCC\n");
		return ret;
	}
	utdm->tdm_framer_type = set_tdm_framer(sprop);

	ret = of_property_read_u32_index(np, "fsl,siram-entry-id", 0, &val);
	if (ret) {
		ret = -EINVAL;
		pr_err("QE-TDM: No siram entry id for UCC\n");
		return ret;
	}
	utdm->siram_entry_id = val;

	set_si_param(utdm, ut_info);

	np2 = of_find_node_by_name(NULL, "si");
	if (!np2) {
		ret = -EINVAL;
		pr_err("QE-TDM: No si property\n");
		return ret;
	}
	of_address_to_resource(np2, 0, &res);
	utdm->si_regs = ioremap(res.start,
				res.end - res.start + 1);
	of_node_put(np2);

	np2 = of_find_node_by_name(NULL, "siram");
	if (!np2) {
		ret = -EINVAL;
		pr_err("QE-TDM: No siramproperty\n");
		goto err_miss_siram_property;
	}
	of_address_to_resource(np2, 0, &res);
	utdm->siram = ioremap(res.start, res.end - res.start + 1);
	of_node_put(np2);

	if (siram_init_flag == 0) {
		memset_io(utdm->siram, 0,  res.end - res.start + 1);
		siram_init_flag = 1;
	}

	return ret;

err_miss_siram_property:
	iounmap(utdm->si_regs);
	return ret;
}

void init_si(struct ucc_tdm *utdm, struct ucc_tdm_info *ut_info)
{
	struct si1 __iomem *si_regs;
	u16 __iomem *siram;
	u16 siram_entry_valid;
	u16 siram_entry_closed;
	u16 ucc_num;
	u8 csel;
	u16 sixmr;
	u16 tdm_port;
	u32 siram_entry_id;
	u32 mask;
	int i;

	si_regs = utdm->si_regs;
	siram = utdm->siram;
	ucc_num = ut_info->uf_info.ucc_num;
	tdm_port = utdm->tdm_port;
	siram_entry_id = utdm->siram_entry_id;

	if (utdm->tdm_framer_type == TDM_FRAMER_T1)
		utdm->num_of_ts = 24;
	if (utdm->tdm_framer_type == TDM_FRAMER_E1)
		utdm->num_of_ts = 32;

	/* set siram table */
	csel = (ucc_num < 4) ? ucc_num + 9 : ucc_num - 3;

	siram_entry_valid = SIR_CSEL(csel) | SIR_BYTE | SIR_CNT(0);
	siram_entry_closed = SIR_IDLE | SIR_BYTE | SIR_CNT(0);

	for (i = 0; i < utdm->num_of_ts; i++) {
		mask = 0x01 << i;

		if (utdm->tx_ts_mask & mask)
			iowrite16be(siram_entry_valid,
					&siram[siram_entry_id * 32 + i]);
		else
			iowrite16be(siram_entry_closed,
					&siram[siram_entry_id * 32 + i]);

		if (utdm->rx_ts_mask & mask)
			iowrite16be(siram_entry_valid,
				&siram[siram_entry_id * 32 + 0x200 +  i]);
		else
			iowrite16be(siram_entry_closed,
				&siram[siram_entry_id * 32 + 0x200 +  i]);
	}

	qe_setbits16(&siram[(siram_entry_id * 32) + (utdm->num_of_ts - 1)],
			SIR_LAST);
	qe_setbits16(&siram[(siram_entry_id * 32) +
		     0x200 + (utdm->num_of_ts - 1)], SIR_LAST);

	/* Set SIxMR register */
	sixmr = SIMR_SAD(siram_entry_id);

	sixmr &= ~SIMR_SDM_MASK;

	if (utdm->tdm_mode == TDM_INTERNAL_LOOPBACK)
		sixmr |= SIMR_SDM_INTERNAL_LOOPBACK;
	else
		sixmr |= SIMR_SDM_NORMAL;

	sixmr |= SIMR_RFSD(ut_info->si_info.simr_rfsd) |
			SIMR_TFSD(ut_info->si_info.simr_tfsd);

	if (ut_info->si_info.simr_crt)
		sixmr |= SIMR_CRT;
	if (ut_info->si_info.simr_sl)
		sixmr |= SIMR_SL;
	if (ut_info->si_info.simr_ce)
		sixmr |= SIMR_CE;
	if (ut_info->si_info.simr_fe)
		sixmr |= SIMR_FE;
	if (ut_info->si_info.simr_gm)
		sixmr |= SIMR_GM;

	switch (tdm_port) {
	case 0:
		iowrite16be(sixmr, &si_regs->sixmr1[0]);
		break;
	case 1:
		iowrite16be(sixmr, &si_regs->sixmr1[1]);
		break;
	case 2:
		iowrite16be(sixmr, &si_regs->sixmr1[2]);
		break;
	case 3:
		iowrite16be(sixmr, &si_regs->sixmr1[3]);
		break;
	default:
		pr_err("QE-TDM: can not find tdm sixmr reg\n");
		break;
	}

#ifdef DEBUG
	dump_siram(utdm);
#endif

}
