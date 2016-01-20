/*
 * Freescale deep sleep FSM (finite-state machine) configuration
 *
 * Copyright 2015 Freescale Semiconductor Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#ifndef _FSL_SLEEP_FSM_H
#define _FSL_SLEEP_FSM_H

/* End flag */
#define FSM_END_FLAG		0xFFFFFFFFUL

/* EPGCR (Event Processor Global Control Register) */
#define EPGCR		0x000

/* EPEVTCR0-9 (Event Processor EVT Pin Control Registers) */
#define EPEVTCR0	0x050
#define EPEVTCR9	0x074
#define EPEVTCR_STRIDE	4

/* EPXTRIGCR (Event Processor Crosstrigger Control Register) */
#define EPXTRIGCR	0x090

/* EPIMCR0-31 (Event Processor Input Mux Control Registers) */
#define EPIMCR0		0x100
#define EPIMCR31	0x17C
#define EPIMCR_STRIDE	4

/* EPSMCR0-15 (Event Processor SCU Mux Control Registers) */
#define EPSMCR0		0x200
#define EPSMCR15	0x278
#define EPSMCR_STRIDE	8

/* EPECR0-15 (Event Processor Event Control Registers) */
#define EPECR0		0x300
#define EPECR15		0x33C
#define EPECR_STRIDE	4

/* EPACR0-15 (Event Processor Action Control Registers) */
#define EPACR0		0x400
#define EPACR15		0x43C
#define EPACR_STRIDE	4

/* EPCCRi0-15 (Event Processor Counter Control Registers) */
#define EPCCR0		0x800
#define EPCCR15		0x83C
#define EPCCR31		0x87C
#define EPCCR_STRIDE	4

/* EPCMPR0-15 (Event Processor Counter Compare Registers) */
#define EPCMPR0		0x900
#define EPCMPR15	0x93C
#define EPCMPR31	0x97C
#define EPCMPR_STRIDE	4

/* EPCTR0-31 (Event Processor Counter Register) */
#define EPCTR0		0xA00
#define EPCTR31		0xA7C
#define EPCTR_STRIDE	4

/* NPC triggered Memory-Mapped Access Registers */
#define NCR		0x000
#define MCCR1		0x0CC
#define MCSR1		0x0D0
#define MMAR1LO		0x0D4
#define MMAR1HI		0x0D8
#define MMDR1		0x0DC
#define MCSR2		0x0E0
#define MMAR2LO		0x0E4
#define MMAR2HI		0x0E8
#define MMDR2		0x0EC
#define MCSR3		0x0F0
#define MMAR3LO		0x0F4
#define MMAR3HI		0x0F8
#define MMDR3		0x0FC

/* RCPM Core State Action Control Register 0 */
#define CSTTACR0	0xB00

/* RCPM Core Group 1 Configuration Register 0 */
#define CG1CR0		0x31C

void fsl_epu_setup_default(void __iomem *epu_base);
void fsl_npc_setup_default(void __iomem *npc_base);
void fsl_dcsr_rcpm_setup(void __iomem *rcpm_base);
void fsl_epu_clean_default(void __iomem *epu_base);

#endif /* _FSL_SLEEP_FSM_H */
