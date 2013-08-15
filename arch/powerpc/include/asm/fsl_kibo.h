/**
 * Freecale shared cluster L2 cache (Kibo)
 *
 * Authors: Varun Sethi <Varun.Sethi@freescale.com>
 *
 * Copyright 2013 Freescale Semiconductor, Inc
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#ifndef __ASM_POWERPC_FSL_KIBO_H__
#define __ASM_POWERPC_FSL_KIBO_H__
#ifdef __KERNEL__

/**
 * Shared cluster L2 cache(Kibo) Registers.
 * 
 * Shared cluster L2 cache or Kibo is a backside cache shared by e6500 and
 * star core DSP cores in a cluster. Kibo is present on Freescale SOCs (T4/B4)
 * following the chassis 2 specification. 
 * 
 * These registers are memory mapped and can be accessed through the CCSR space.
 *
 */

#define CLUSTER_L2_STASH_MASK 0xff

struct ccsr_cluster_l2 {
	u32 l2csr0;	/* 0x000 L2 cache control and status register 0 */
	u32 l2csr1;	/* 0x004 L2 cache control and status register 1 */
	u32 l2cfg0;	/* 0x008 L2 cache configuration register 0 */
	u8  res_0c[500];/* 0x00c - 0x1ff */
	u32 l2pir0;	/* 0x200 L2 cache partitioning ID register 0 */
	u8  res_204[4];
	u32 l2par0;	/* 0x208 L2 cache partitioning allocation register 0 */
	u32 l2pwr0;	/* 0x20c L2 cache partitioning way register 0 */
	u32 l2pir1;	/* 0x210 L2 cache partitioning ID register 1 */
	u8  res_214[4];
	u32 l2par1;	/* 0x218 L2 cache partitioning allocation register 1 */
	u32 l2pwr1;	/* 0x21c L2 cache partitioning way register 1 */
	u32 u2pir2;	/* 0x220 L2 cache partitioning ID register 2 */
	u8  res_224[4];
	u32 l2par2;	/* 0x228 L2 cache partitioning allocation register 2 */
	u32 l2pwr2;	/* 0x22c L2 cache partitioning way register 2 */
	u32 l2pir3;	/* 0x230 L2 cache partitioning ID register 3 */
	u8  res_234[4];
	u32 l2par3;	/* 0x238 L2 cache partitining allocation register 3 */
	u32 l2pwr3;	/* 0x23c L2 cache partitining way register 3 */
	u32 l2pir4;	/* 0x240 L2 cache partitioning ID register 3 */
	u8  res244[4];
	u32 l2par4;	/* 0x248 L2 cache partitioning allocation register 3 */
	u32 l2pwr4;	/* 0x24c L2 cache partitioning way register 3 */
	u32 l2pir5;	/* 0x250 L2 cache partitioning ID register 3 */
	u8  res_254[4];
	u32 l2par5;	/* 0x258 L2 cache partitioning allocation register 3 */
	u32 l2pwr5;	/* 0x25c L2 cache partitioning way register 3 */
	u32 l2pir6;	/* 0x260 L2 cache partitioning ID register 3 */
	u8  res_264[4];
	u32 l2par6;	/* 0x268 L2 cache partitioning allocation register 3 */
	u32 l2pwr6;	/* 0x26c L2 cache partitioning way register 3 */
	u32 l2pir7;	/* 0x270 L2 cache partitioning ID register 3 */
	u8  res274[4];
	u32 l2par7;	/* 0x278 L2 cache partitioning allocation register 3 */
	u32 l2pwr7;	/* 0x27c L2 cache partitioning way register 3 */
	u8  res_280[0xb80]; /* 0x280 - 0xdff */
	u32 l2errinjhi;	/* 0xe00 L2 cache error injection mask high */
	u32 l2errinjlo;	/* 0xe04 L2 cache error injection mask low */
	u32 l2errinjctl;/* 0xe08 L2 cache error injection control */
	u8  res_e0c[20];	/* 0xe0c - 0x01f */
	u32 l2captdatahi; /* 0xe20 L2 cache error capture data high */
	u32 l2captdatalo; /* 0xe24 L2 cache error capture data low */
	u32 l2captecc;	/* 0xe28 L2 cache error capture ECC syndrome */
	u8  res_e2c[20];	/* 0xe2c - 0xe3f */
	u32 l2errdet;	/* 0xe40 L2 cache error detect */
	u32 l2errdis;	/* 0xe44 L2 cache error disable */
	u32 l2errinten;	/* 0xe48 L2 cache error interrupt enable */
	u32 l2errattr;	/* 0xe4c L2 cache error attribute */
	u32 l2erreaddr;	/* 0xe50 L2 cache error extended address */
	u32 l2erraddr;	/* 0xe54 L2 cache error address */
	u32 l2errctl;	/* 0xe58 L2 cache error control */
	u8  res_e5c[0xa4];	/* 0xe5c - 0xf00 */
	u32 l2hdbcr0;	/* 0xf00 L2 cache hardware debugcontrol register 0 */
	u32 l2hdbcr1;	/* 0xf00 L2 cache hardware debugcontrol register 1 */
	u32 l2hdbcr2;	/* 0xf00 L2 cache hardware debugcontrol register 2 */
};
#endif /*__KERNEL__ */
#endif /*__ASM_POWERPC_FSL_KIBO_H__*/
