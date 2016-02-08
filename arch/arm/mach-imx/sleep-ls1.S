/*
 * Support deep sleep feature for LS1
 *
 * Copyright 2014 Freescale Semiconductor Inc.
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/cache.h>
#include <asm/cp15.h>

#define CCSR_DDR_BASE			0x01080000
#define CCSR_DDR_SDRAM_CFG_2		0x114

#define CCSR_SCFG_BASE			0x01570000
#define CCSR_SCFG_HRSTCR		0x1a8

#define DCSR_EPU_BASE			0x20000000
#define	DCSR_EPU_EPGCR			0x0
#define DCSR_EPU_EPECR0			0x300
#define DCSR_EPU_EPECR15		0x33c

#define CCSR_GIC_BASE		0x1400000
#define CCSR_GICD_CTLR		0x1000
#define CCSR_GICC_CTLR		0x2000

/* for big endian registers */
.macro ls1_set_bits, addr, value
	ldr	r4, \addr
	ldr	r5, [r4]
	ldr	r6, \value
	rev	r6, r6
	orr	r5, r5, r6
	str	r5, [r4]
.endm

/* 1000 loops per round */
.macro ls1_delay, count
	mov	r0, \count
11:	mov	r7, #1000
12:	subs	r7, r7, #1
	bne	12b
	subs	r0, r0, #1
	bne	11b
.endm

/*
 * r0: the physical entry address of SRAM code
 *
 */
	.align L1_CACHE_SHIFT
	.pushsection	.idmap.text,"ax"
ENTRY(ls1_do_deepsleep)
	/* disable MMU, M bit in SCTLR */
	mrc	p15, 0, r3, c1, c0, 0
	bic	r3, r3, #CR_M
	mcr	p15, 0, r3, c1, c0, 0
	isb

	/* jump to sram code using physical address */
 THUMB( orr r0, r0, #1 )
	bx	r0
ENDPROC(ls1_do_deepsleep)
	.popsection

/*
 * The code will be copied to SRAM.
 */
	.align L1_CACHE_SHIFT
ENTRY(ls1_start_fsm)
	/* set HRSTCR */
	ls1_set_bits	ls1_ccsr_scfg_hrstcr_addr, ls1_ccsr_scfg_hrstcr_val

	/* Place DDR controller in self refresh mode */
	ls1_set_bits	ls1_ddr_cfg2_addr, ls1_ddr_cfg2_val

	ls1_delay	#2000

	/* Set EVT4_B to lock the signal MCKE down */
	ldr	r4, ls1_dcsr_epu_epecr0
	ldr	r5, ls1_dcsr_epu_epecr0_val
	rev	r5, r5
	str	r5, [r4]

	ls1_delay	#2000

	mov	r7, #0
	ldr	r8, ls1_ccsr_gicd_ctlr
	str	r7, [r8]
	ldr	r9, ls1_ccsr_gicc_ctlr
	str	r7, [r9]
	dsb

	/* Enable all EPU Counters */
	ls1_set_bits	ls1_dcsr_epu_epgcr_addr, ls1_dcsr_epu_epgcr_val

	/* Enable SCU15 */
	ls1_set_bits	ls1_dcsr_epu_epecr15, ls1_dcsr_epu_epecr15_val

	/* Enter WFI mode, and EPU FSM will start */
	isb
	wfi
	nop
20:	b	20b

ls1_ccsr_scfg_hrstcr_addr:
	.word	CCSR_SCFG_BASE + CCSR_SCFG_HRSTCR
ls1_ccsr_scfg_hrstcr_val:
	.word	0x80000000

ls1_ddr_cfg2_addr:
	.word	CCSR_DDR_BASE + CCSR_DDR_SDRAM_CFG_2
ls1_ddr_cfg2_val:
	.word	(1 << 31)

ls1_dcsr_epu_epgcr_addr:
	.word	DCSR_EPU_BASE + DCSR_EPU_EPGCR
ls1_dcsr_epu_epgcr_val:
	.word	0x80000000

ls1_dcsr_epu_epecr0:
	.word	DCSR_EPU_BASE + DCSR_EPU_EPECR0
ls1_dcsr_epu_epecr0_val:
	.word	0

ls1_dcsr_epu_epecr15:
	.word	DCSR_EPU_BASE + DCSR_EPU_EPECR15
ls1_dcsr_epu_epecr15_val:
	.word	0x90000004

ls1_ccsr_gicd_ctlr:
	.word	CCSR_GIC_BASE + CCSR_GICD_CTLR

ls1_ccsr_gicc_ctlr:
	.word	CCSR_GIC_BASE + CCSR_GICC_CTLR

ENTRY(ls1_sram_code_size)
	.word	. - ls1_start_fsm

/* the bootloader will jump to here after wakeup from deep sleep  */
	.arm
	.align L1_CACHE_SHIFT
ENTRY(ls1_deepsleep_resume)
 THUMB(	adr	r6, BSYM(1f)	)
 THUMB(	bx	r6		)
 THUMB(	.thumb			)
 THUMB(1:			)
	b cpu_resume
