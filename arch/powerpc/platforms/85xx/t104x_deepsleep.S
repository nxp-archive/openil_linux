/*
 * Enter and resume from deep sleep state
 *
 * Copyright 2015 Freescale Semiconductor Inc.
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <asm/page.h>
#include <asm/ppc_asm.h>
#include <asm/reg.h>
#include <asm/asm-offsets.h>
#include <asm/mmu.h>

/*
 * the number of bytes occupied by one register
 * the value of 8 is compatible with both 32-bit and 64-bit registers
 */
#define STRIDE_SIZE		8

/* GPR0 - GPR31 */
#define BOOKE_GPR0_OFF		0x0000
#define BOOKE_GPR_COUNT		32
/* IVOR0 - IVOR42 */
#define BOOKE_IVOR0_OFF	   (BOOKE_GPR0_OFF + BOOKE_GPR_COUNT * STRIDE_SIZE)
#define BOOKE_IVOR_COUNT	43
/* SPRG0 - SPRG9 */
#define BOOKE_SPRG0_OFF	   (BOOKE_IVOR0_OFF + BOOKE_IVOR_COUNT * STRIDE_SIZE)
#define BOOKE_SPRG_COUNT	10
/* IVPR */
#define BOOKE_IVPR_OFF	   (BOOKE_SPRG0_OFF + BOOKE_SPRG_COUNT * STRIDE_SIZE)

#define BOOKE_LR_OFF		(BOOKE_IVPR_OFF + STRIDE_SIZE)
#define BOOKE_MSR_OFF		(BOOKE_LR_OFF + STRIDE_SIZE)
#define BOOKE_TBU_OFF		(BOOKE_MSR_OFF + STRIDE_SIZE)
#define BOOKE_TBL_OFF		(BOOKE_TBU_OFF + STRIDE_SIZE)
#define BOOKE_EPCR_OFF		(BOOKE_TBL_OFF + STRIDE_SIZE)
#define BOOKE_HID0_OFF		(BOOKE_EPCR_OFF + STRIDE_SIZE)
#define BOOKE_PIR_OFF		(BOOKE_HID0_OFF + STRIDE_SIZE)
#define BOOKE_PID0_OFF		(BOOKE_PIR_OFF + STRIDE_SIZE)
#define BOOKE_BUCSR_OFF		(BOOKE_PID0_OFF + STRIDE_SIZE)

#define BUFFER_SIZE		(BOOKE_BUCSR_OFF + STRIDE_SIZE)

#undef SAVE_GPR
#define SAVE_GPR(gpr, offset) \
	PPC_STL gpr, offset(r10)

#define RESTORE_GPR(gpr, offset) \
	PPC_LL gpr, offset(r10)

#define SAVE_SPR(spr, offset)	\
	mfspr	r0, spr;	\
	PPC_STL	r0, offset(r10)

#define RESTORE_SPR(spr, offset) \
	PPC_LL	r0, offset(r10); \
	mtspr	spr, r0

#define SAVE_ALL_GPR \
	SAVE_GPR(r1, BOOKE_GPR0_OFF + STRIDE_SIZE * 1) ;\
	SAVE_GPR(r2, BOOKE_GPR0_OFF + STRIDE_SIZE * 2) ;\
	SAVE_GPR(r13, BOOKE_GPR0_OFF + STRIDE_SIZE * 13) ;\
	SAVE_GPR(r14, BOOKE_GPR0_OFF + STRIDE_SIZE * 14) ;\
	SAVE_GPR(r15, BOOKE_GPR0_OFF + STRIDE_SIZE * 15) ;\
	SAVE_GPR(r16, BOOKE_GPR0_OFF + STRIDE_SIZE * 16) ;\
	SAVE_GPR(r17, BOOKE_GPR0_OFF + STRIDE_SIZE * 17) ;\
	SAVE_GPR(r18, BOOKE_GPR0_OFF + STRIDE_SIZE * 18) ;\
	SAVE_GPR(r19, BOOKE_GPR0_OFF + STRIDE_SIZE * 19) ;\
	SAVE_GPR(r20, BOOKE_GPR0_OFF + STRIDE_SIZE * 20) ;\
	SAVE_GPR(r21, BOOKE_GPR0_OFF + STRIDE_SIZE * 21) ;\
	SAVE_GPR(r22, BOOKE_GPR0_OFF + STRIDE_SIZE * 22) ;\
	SAVE_GPR(r23, BOOKE_GPR0_OFF + STRIDE_SIZE * 23) ;\
	SAVE_GPR(r24, BOOKE_GPR0_OFF + STRIDE_SIZE * 24) ;\
	SAVE_GPR(r25, BOOKE_GPR0_OFF + STRIDE_SIZE * 25) ;\
	SAVE_GPR(r26, BOOKE_GPR0_OFF + STRIDE_SIZE * 26) ;\
	SAVE_GPR(r27, BOOKE_GPR0_OFF + STRIDE_SIZE * 27) ;\
	SAVE_GPR(r28, BOOKE_GPR0_OFF + STRIDE_SIZE * 28) ;\
	SAVE_GPR(r29, BOOKE_GPR0_OFF + STRIDE_SIZE * 29) ;\
	SAVE_GPR(r30, BOOKE_GPR0_OFF + STRIDE_SIZE * 30) ;\
	SAVE_GPR(r31, BOOKE_GPR0_OFF + STRIDE_SIZE * 31)

#define RESTORE_ALL_GPR \
	RESTORE_GPR(r1, BOOKE_GPR0_OFF + STRIDE_SIZE * 1) ;\
	RESTORE_GPR(r2, BOOKE_GPR0_OFF + STRIDE_SIZE * 2) ;\
	RESTORE_GPR(r13, BOOKE_GPR0_OFF + STRIDE_SIZE * 13) ;\
	RESTORE_GPR(r14, BOOKE_GPR0_OFF + STRIDE_SIZE * 14) ;\
	RESTORE_GPR(r15, BOOKE_GPR0_OFF + STRIDE_SIZE * 15) ;\
	RESTORE_GPR(r16, BOOKE_GPR0_OFF + STRIDE_SIZE * 16) ;\
	RESTORE_GPR(r17, BOOKE_GPR0_OFF + STRIDE_SIZE * 17) ;\
	RESTORE_GPR(r18, BOOKE_GPR0_OFF + STRIDE_SIZE * 18) ;\
	RESTORE_GPR(r19, BOOKE_GPR0_OFF + STRIDE_SIZE * 19) ;\
	RESTORE_GPR(r20, BOOKE_GPR0_OFF + STRIDE_SIZE * 20) ;\
	RESTORE_GPR(r21, BOOKE_GPR0_OFF + STRIDE_SIZE * 21) ;\
	RESTORE_GPR(r22, BOOKE_GPR0_OFF + STRIDE_SIZE * 22) ;\
	RESTORE_GPR(r23, BOOKE_GPR0_OFF + STRIDE_SIZE * 23) ;\
	RESTORE_GPR(r24, BOOKE_GPR0_OFF + STRIDE_SIZE * 24) ;\
	RESTORE_GPR(r25, BOOKE_GPR0_OFF + STRIDE_SIZE * 25) ;\
	RESTORE_GPR(r26, BOOKE_GPR0_OFF + STRIDE_SIZE * 26) ;\
	RESTORE_GPR(r27, BOOKE_GPR0_OFF + STRIDE_SIZE * 27) ;\
	RESTORE_GPR(r28, BOOKE_GPR0_OFF + STRIDE_SIZE * 28) ;\
	RESTORE_GPR(r29, BOOKE_GPR0_OFF + STRIDE_SIZE * 29) ;\
	RESTORE_GPR(r30, BOOKE_GPR0_OFF + STRIDE_SIZE * 30) ;\
	RESTORE_GPR(r31, BOOKE_GPR0_OFF + STRIDE_SIZE * 31)

#define SAVE_ALL_SPRG \
	SAVE_SPR(SPRN_SPRG0, BOOKE_SPRG0_OFF + STRIDE_SIZE * 0) ;\
	SAVE_SPR(SPRN_SPRG1, BOOKE_SPRG0_OFF + STRIDE_SIZE * 1) ;\
	SAVE_SPR(SPRN_SPRG2, BOOKE_SPRG0_OFF + STRIDE_SIZE * 2) ;\
	SAVE_SPR(SPRN_SPRG3, BOOKE_SPRG0_OFF + STRIDE_SIZE * 3) ;\
	SAVE_SPR(SPRN_SPRG4, BOOKE_SPRG0_OFF + STRIDE_SIZE * 4) ;\
	SAVE_SPR(SPRN_SPRG5, BOOKE_SPRG0_OFF + STRIDE_SIZE * 5) ;\
	SAVE_SPR(SPRN_SPRG6, BOOKE_SPRG0_OFF + STRIDE_SIZE * 6) ;\
	SAVE_SPR(SPRN_SPRG7, BOOKE_SPRG0_OFF + STRIDE_SIZE * 7) ;\
	SAVE_SPR(SPRN_SPRG8, BOOKE_SPRG0_OFF + STRIDE_SIZE * 8) ;\
	SAVE_SPR(SPRN_SPRG9, BOOKE_SPRG0_OFF + STRIDE_SIZE * 9)

#define RESTORE_ALL_SPRG \
	RESTORE_SPR(SPRN_SPRG0, BOOKE_SPRG0_OFF + STRIDE_SIZE * 0) ;\
	RESTORE_SPR(SPRN_SPRG1, BOOKE_SPRG0_OFF + STRIDE_SIZE * 1) ;\
	RESTORE_SPR(SPRN_SPRG2, BOOKE_SPRG0_OFF + STRIDE_SIZE * 2) ;\
	RESTORE_SPR(SPRN_SPRG3, BOOKE_SPRG0_OFF + STRIDE_SIZE * 3) ;\
	RESTORE_SPR(SPRN_SPRG4, BOOKE_SPRG0_OFF + STRIDE_SIZE * 4) ;\
	RESTORE_SPR(SPRN_SPRG5, BOOKE_SPRG0_OFF + STRIDE_SIZE * 5) ;\
	RESTORE_SPR(SPRN_SPRG6, BOOKE_SPRG0_OFF + STRIDE_SIZE * 6) ;\
	RESTORE_SPR(SPRN_SPRG7, BOOKE_SPRG0_OFF + STRIDE_SIZE * 7) ;\
	RESTORE_SPR(SPRN_SPRG8, BOOKE_SPRG0_OFF + STRIDE_SIZE * 8) ;\
	RESTORE_SPR(SPRN_SPRG9, BOOKE_SPRG0_OFF + STRIDE_SIZE * 9)

#define SAVE_ALL_IVOR \
	SAVE_SPR(SPRN_IVOR0, BOOKE_IVOR0_OFF + STRIDE_SIZE * 0) ;\
	SAVE_SPR(SPRN_IVOR1, BOOKE_IVOR0_OFF + STRIDE_SIZE * 1) ;\
	SAVE_SPR(SPRN_IVOR2, BOOKE_IVOR0_OFF + STRIDE_SIZE * 2) ;\
	SAVE_SPR(SPRN_IVOR3, BOOKE_IVOR0_OFF + STRIDE_SIZE * 3) ;\
	SAVE_SPR(SPRN_IVOR4, BOOKE_IVOR0_OFF + STRIDE_SIZE * 4) ;\
	SAVE_SPR(SPRN_IVOR5, BOOKE_IVOR0_OFF + STRIDE_SIZE * 5) ;\
	SAVE_SPR(SPRN_IVOR6, BOOKE_IVOR0_OFF + STRIDE_SIZE * 6) ;\
	SAVE_SPR(SPRN_IVOR7, BOOKE_IVOR0_OFF + STRIDE_SIZE * 7) ;\
	SAVE_SPR(SPRN_IVOR8, BOOKE_IVOR0_OFF + STRIDE_SIZE * 8) ;\
	SAVE_SPR(SPRN_IVOR9, BOOKE_IVOR0_OFF + STRIDE_SIZE * 9) ;\
	SAVE_SPR(SPRN_IVOR10, BOOKE_IVOR0_OFF + STRIDE_SIZE * 10) ;\
	SAVE_SPR(SPRN_IVOR11, BOOKE_IVOR0_OFF + STRIDE_SIZE * 11) ;\
	SAVE_SPR(SPRN_IVOR12, BOOKE_IVOR0_OFF + STRIDE_SIZE * 12) ;\
	SAVE_SPR(SPRN_IVOR13, BOOKE_IVOR0_OFF + STRIDE_SIZE * 13) ;\
	SAVE_SPR(SPRN_IVOR14, BOOKE_IVOR0_OFF + STRIDE_SIZE * 14) ;\
	SAVE_SPR(SPRN_IVOR15, BOOKE_IVOR0_OFF + STRIDE_SIZE * 15) ;\
	SAVE_SPR(SPRN_IVOR35, BOOKE_IVOR0_OFF + STRIDE_SIZE * 35) ;\
	SAVE_SPR(SPRN_IVOR36, BOOKE_IVOR0_OFF + STRIDE_SIZE * 36) ;\
	SAVE_SPR(SPRN_IVOR37, BOOKE_IVOR0_OFF + STRIDE_SIZE * 37) ;\
	SAVE_SPR(SPRN_IVOR38, BOOKE_IVOR0_OFF + STRIDE_SIZE * 38) ;\
	SAVE_SPR(SPRN_IVOR39, BOOKE_IVOR0_OFF + STRIDE_SIZE * 39) ;\
	SAVE_SPR(SPRN_IVOR40, BOOKE_IVOR0_OFF + STRIDE_SIZE * 40) ;\
	SAVE_SPR(SPRN_IVOR41, BOOKE_IVOR0_OFF + STRIDE_SIZE * 41)

#define RESTORE_ALL_IVOR \
	RESTORE_SPR(SPRN_IVOR0, BOOKE_IVOR0_OFF + STRIDE_SIZE * 0) ;\
	RESTORE_SPR(SPRN_IVOR1, BOOKE_IVOR0_OFF + STRIDE_SIZE * 1) ;\
	RESTORE_SPR(SPRN_IVOR2, BOOKE_IVOR0_OFF + STRIDE_SIZE * 2) ;\
	RESTORE_SPR(SPRN_IVOR3, BOOKE_IVOR0_OFF + STRIDE_SIZE * 3) ;\
	RESTORE_SPR(SPRN_IVOR4, BOOKE_IVOR0_OFF + STRIDE_SIZE * 4) ;\
	RESTORE_SPR(SPRN_IVOR5, BOOKE_IVOR0_OFF + STRIDE_SIZE * 5) ;\
	RESTORE_SPR(SPRN_IVOR6, BOOKE_IVOR0_OFF + STRIDE_SIZE * 6) ;\
	RESTORE_SPR(SPRN_IVOR7, BOOKE_IVOR0_OFF + STRIDE_SIZE * 7) ;\
	RESTORE_SPR(SPRN_IVOR8, BOOKE_IVOR0_OFF + STRIDE_SIZE * 8) ;\
	RESTORE_SPR(SPRN_IVOR9, BOOKE_IVOR0_OFF + STRIDE_SIZE * 9) ;\
	RESTORE_SPR(SPRN_IVOR10, BOOKE_IVOR0_OFF + STRIDE_SIZE * 10) ;\
	RESTORE_SPR(SPRN_IVOR11, BOOKE_IVOR0_OFF + STRIDE_SIZE * 11) ;\
	RESTORE_SPR(SPRN_IVOR12, BOOKE_IVOR0_OFF + STRIDE_SIZE * 12) ;\
	RESTORE_SPR(SPRN_IVOR13, BOOKE_IVOR0_OFF + STRIDE_SIZE * 13) ;\
	RESTORE_SPR(SPRN_IVOR14, BOOKE_IVOR0_OFF + STRIDE_SIZE * 14) ;\
	RESTORE_SPR(SPRN_IVOR15, BOOKE_IVOR0_OFF + STRIDE_SIZE * 15) ;\
	RESTORE_SPR(SPRN_IVOR35, BOOKE_IVOR0_OFF + STRIDE_SIZE * 35) ;\
	RESTORE_SPR(SPRN_IVOR36, BOOKE_IVOR0_OFF + STRIDE_SIZE * 36) ;\
	RESTORE_SPR(SPRN_IVOR37, BOOKE_IVOR0_OFF + STRIDE_SIZE * 37) ;\
	RESTORE_SPR(SPRN_IVOR38, BOOKE_IVOR0_OFF + STRIDE_SIZE * 38) ;\
	RESTORE_SPR(SPRN_IVOR39, BOOKE_IVOR0_OFF + STRIDE_SIZE * 39) ;\
	RESTORE_SPR(SPRN_IVOR40, BOOKE_IVOR0_OFF + STRIDE_SIZE * 40) ;\
	RESTORE_SPR(SPRN_IVOR41, BOOKE_IVOR0_OFF + STRIDE_SIZE * 41)

/* reset time base to prevent from overflow */
#define DELAY(count)		\
	li	r3, count;	\
	li	r4, 0;		\
	mtspr	SPRN_TBWL, r4;	\
101:	mfspr	r4, SPRN_TBRL;	\
	cmpw	r4, r3;		\
	blt	101b

#define FSL_DIS_ALL_IRQ		\
	mfmsr	r8;			\
	rlwinm	r8, r8, 0, ~MSR_CE;	\
	rlwinm	r8, r8, 0, ~MSR_ME;	\
	rlwinm	r8, r8, 0, ~MSR_EE;	\
	rlwinm	r8, r8, 0, ~MSR_DE;	\
	mtmsr	r8;			\
	isync

	.section .data
	.align	6
regs_buffer:
	.space BUFFER_SIZE

	.section .text
/*
 * Save CPU registers
 * r3 : the base address of the buffer which stores the values of registers
 */
e5500_cpu_state_save:
	/* store the base address to r10 */
	mr	r10, r3

	SAVE_ALL_GPR
	SAVE_ALL_SPRG
	SAVE_ALL_IVOR

	SAVE_SPR(SPRN_IVPR, BOOKE_IVPR_OFF)
	SAVE_SPR(SPRN_PID0, BOOKE_PID0_OFF)
	SAVE_SPR(SPRN_EPCR, BOOKE_EPCR_OFF)
	SAVE_SPR(SPRN_HID0, BOOKE_HID0_OFF)
	SAVE_SPR(SPRN_PIR, BOOKE_PIR_OFF)
	SAVE_SPR(SPRN_BUCSR, BOOKE_BUCSR_OFF)
1:
	mfspr	r5, SPRN_TBRU
	mfspr	r4, SPRN_TBRL
	SAVE_GPR(r5, BOOKE_TBU_OFF)
	SAVE_GPR(r4, BOOKE_TBL_OFF)
	mfspr	r3, SPRN_TBRU
	cmpw	r3, r5
	bne	1b

	blr

/*
 * Restore CPU registers
 * r3 : the base address of the buffer which stores the values of registers
 */
e5500_cpu_state_restore:
	/* store the base address to r10 */
	mr	r10, r3

	RESTORE_ALL_GPR
	RESTORE_ALL_SPRG
	RESTORE_ALL_IVOR

	RESTORE_SPR(SPRN_IVPR, BOOKE_IVPR_OFF)
	RESTORE_SPR(SPRN_PID0, BOOKE_PID0_OFF)
	RESTORE_SPR(SPRN_EPCR, BOOKE_EPCR_OFF)
	RESTORE_SPR(SPRN_HID0, BOOKE_HID0_OFF)
	RESTORE_SPR(SPRN_PIR, BOOKE_PIR_OFF)
	RESTORE_SPR(SPRN_BUCSR, BOOKE_BUCSR_OFF)

	li	r0, 0
	mtspr	SPRN_TBWL, r0
	RESTORE_SPR(SPRN_TBWU, BOOKE_TBU_OFF)
	RESTORE_SPR(SPRN_TBWL, BOOKE_TBL_OFF)

	blr

#define CPC_CPCCSR0		0x0
#define CPC_CPCCSR0_CPCFL	0x800

/*
 * Flush the CPC cache.
 * r3 : the base address of CPC
 */
flush_cpc_cache:
	lwz	r6, CPC_CPCCSR0(r3)
	ori	r6, r6, CPC_CPCCSR0_CPCFL
	stw	r6, CPC_CPCCSR0(r3)
	sync

	/* Wait until completing the flush */
1:	lwz	r6, CPC_CPCCSR0(r3)
	andi.	r6, r6, CPC_CPCCSR0_CPCFL
	bne	1b

	blr

/*
 * the last stage to enter deep sleep
 */
	.align 6
_GLOBAL(fsl_dp_enter_low)
deepsleep_start:
	LOAD_REG_ADDR(r9, buf_tmp)
	/* save the return address and MSR */
	mflr	r8
	PPC_STL r8, 0(r9)
	mfmsr	r8
	PPC_STL r8, 8(r9)
	mfspr	r8, SPRN_TCR
	PPC_STL r8, 16(r9)
	mfcr	r8
	PPC_STL	r8, 24(r9)

	li	r8, 0
	mtspr	SPRN_TCR, r8

	/* save the parameters */
	PPC_STL	r3, 32(r9)

	LOAD_REG_ADDR(r3, regs_buffer)
	bl	e5500_cpu_state_save

	/* restore the parameters */
	LOAD_REG_ADDR(r9, buf_tmp)
	PPC_LL	r31, 32(r9)

	/* flush caches inside CPU */
	LOAD_REG_ADDR(r3, cur_cpu_spec)
	PPC_LL	r3, 0(r3)
	PPC_LL	r3, CPU_DOWN_FLUSH(r3)
	PPC_LCMPI  0, r3, 0
	beq	10f
#ifdef CONFIG_PPC64
	PPC_LL	r3, 0(r3)
#endif
	mtctr	r3
	bctrl
10:
	/* Flush the CPC cache */
	PPC_LL	r3, CCSR_CPC_BASE(r31)
	bl	flush_cpc_cache

	/* prefecth TLB */
#define CCSR_GPIO1_GPDAT	0x0008
#define CCSR_GPIO1_GPDAT_29	0x4
	PPC_LL	r11, CCSR_GPIO1_BASE(r31)
	addi	r11, r11, CCSR_GPIO1_GPDAT
	lwz	r10, 0(r11)

#define CCSR_RCPM_PCPH15SETR	0x0b4
#define CCSR_RCPM_PCPH15SETR_CORE0	0x1
	PPC_LL	r12, CCSR_RCPM_BASE(r31)
	addi	r12, r12, CCSR_RCPM_PCPH15SETR
	lwz	r10, 0(r12)

#define CCSR_DDR_SDRAM_CFG_2	0x114
#define CCSR_DDR_SDRAM_CFG_2_FRC_SR	0x80000000
	PPC_LL	r13, CCSR_DDR_BASE(r31)
	addi	r13, r13, CCSR_DDR_SDRAM_CFG_2
	lwz	r10, 0(r13)

#define	DCSR_EPU_EPGCR		0x000
#define DCSR_EPU_EPGCR_GCE	0x80000000
	PPC_LL	r14, DCSR_EPU_BASE(r31)
	addi	r14, r14, DCSR_EPU_EPGCR
	lwz	r10, 0(r14)

#define	DCSR_EPU_EPECR15	0x33C
#define DCSR_EPU_EPECR15_IC0	0x80000000
	PPC_LL	r15, DCSR_EPU_BASE(r31)
	addi	r15, r15, DCSR_EPU_EPECR15
	lwz	r10, 0(r15)

#define CCSR_SCFG_QMIFRSTCR		0x40c
#define CCSR_SCFG_QMIFRSTCR_QMIFRST	0x80000000
	PPC_LL	r16, CCSR_SCFG_BASE(r31)
	addi	r16, r16, CCSR_SCFG_QMIFRSTCR
	lwz	r10, 0(r16)

	LOAD_REG_ADDR(r8, deepsleep_start)
	LOAD_REG_ADDR(r9, deepsleep_end)

	/* prefecth code to cache so that executing code after disable DDR */
1:	icbtls	2, 0, r8
	addi	r8, r8, 64
	cmpw	r8, r9
	blt	1b
	sync

	FSL_DIS_ALL_IRQ

	/*
	 * Place DDR controller in self refresh mode.
	 * From here on, can't access DDR any more.
	 */
	lwz	r10, 0(r13)
	oris	r10, r10, CCSR_DDR_SDRAM_CFG_2_FRC_SR@h
	stw	r10, 0(r13)
	lwz	r10, 0(r13)
	sync

	DELAY(500)

	/*
	 * Set GPIO1_29 to lock the signal MCKE down during deep sleep.
	 * The bootloader will clear it when wakeup.
	 */
	lwz	r10, 0(r11)
	ori	r10, r10, CCSR_GPIO1_GPDAT_29
	stw	r10, 0(r11)
	lwz	r10, 0(r11)

	DELAY(100)

	/* Reset QMan system bus interface */
	lwz	r10, 0(r16)
	oris	r10, r10, CCSR_SCFG_QMIFRSTCR_QMIFRST@h
	stw	r10, 0(r16)
	lwz	r10, 0(r16)

	/* Enable all EPU Counters */
	li	r10, 0
	oris	r10, r10, DCSR_EPU_EPGCR_GCE@h
	stw	r10, 0(r14)
	lwz	r10, 0(r14)

	/* Enable SCU15 to trigger on RCPM Concentrator 0 */
	lwz	r10, 0(r15)
	oris	r10, r10, DCSR_EPU_EPECR15_IC0@h
	stw	r10, 0(r15)
	lwz	r10, 0(r15)

	/* put Core0 in PH15 mode, trigger EPU FSM */
	lwz	r10, 0(r12)
	ori	r10, r10, CCSR_RCPM_PCPH15SETR_CORE0
	stw	r10, 0(r12)
2:
	b 2b

	/*
	 * Leave some space to prevent prefeching instruction
	 * beyond deepsleep_end. The space also can be used as heap.
	 */
buf_tmp:
	.space 128
	.align 6
deepsleep_end:

	.align 12
#ifdef CONFIG_PPC32
_GLOBAL(fsl_booke_deep_sleep_resume)
	/* disable interrupts */
	FSL_DIS_ALL_IRQ

#define ENTRY_DEEPSLEEP_SETUP
#define ENTRY_MAPPING_BOOT_SETUP
#include <../../kernel/fsl_booke_entry_mapping.S>
#undef ENTRY_DEEPSLEEP_SETUP
#undef ENTRY_MAPPING_BOOT_SETUP

	li	r3, 0
	mfspr   r4, SPRN_PIR
	bl	call_setup_cpu

	/* Load each CAM entry */
	LOAD_REG_ADDR(r3, tlbcam_index)
	lwz	r3, 0(r3)
	mtctr	r3
	li	r9, 0
3:	mr	r3, r9
	bl	loadcam_entry
	addi	r9, r9, 1
	bdnz	3b

	/* restore cpu registers */
	LOAD_REG_ADDR(r3, regs_buffer)
	bl	e5500_cpu_state_restore

	/* restore return address */
	LOAD_REG_ADDR(r3, buf_tmp)
	lwz	r4, 16(r3)
	mtspr	SPRN_TCR, r4
	lwz	r4, 0(r3)
	mtlr	r4
	lwz	r4, 8(r3)
	mtmsr	r4
	lwz	r4, 24(r3)
	mtcr	r4

	blr

#else /* CONFIG_PPC32 */

_GLOBAL(fsl_booke_deep_sleep_resume)
	/* disable interrupts */
	FSL_DIS_ALL_IRQ

	/* switch to 64-bit mode */
	bl	.enable_64b_mode

	/* set TOC pointer */
	bl	.relative_toc

	/* setup initial TLBs, switch to kernel space ... */
	bl	.start_initialization_book3e

	/* address space changed, set TOC pointer again */
	bl	.relative_toc

	/* call a cpu state restore handler */
	LOAD_REG_ADDR(r23, cur_cpu_spec)
	ld	r23,0(r23)
	ld	r23,CPU_SPEC_RESTORE(r23)
	cmpdi	0,r23,0
	beq	1f
	ld	r23,0(r23)
	mtctr	r23
	bctrl
1:
	LOAD_REG_ADDR(r3, regs_buffer)
	bl	e5500_cpu_state_restore

	/* Load each CAM entry */
	LOAD_REG_ADDR(r3, tlbcam_index)
	lwz	r3, 0(r3)
	mtctr	r3
	li	r0, 0
3:	mr	r3, r0
	bl	loadcam_entry
	addi	r0, r0, 1
	bdnz	3b

	/* restore return address */
	LOAD_REG_ADDR(r3, buf_tmp)
	ld	r4, 16(r3)
	mtspr	SPRN_TCR, r4
	ld	r4, 0(r3)
	mtlr	r4
	ld	r4, 8(r3)
	mtmsr	r4
	ld	r4, 24(r3)
	mtcr	r4

	blr

#endif /* CONFIG_PPC32 */
