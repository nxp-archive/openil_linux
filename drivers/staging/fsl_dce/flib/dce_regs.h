/*
 * Copyright 2013 Freescale Semiconductor, Inc.
 */

#ifndef FL_DCE_REGS_H
#define FL_DCE_REGS_H

/* Memory Mapped Registers */

/** @Description struct for defining dce CCSR registes */
struct dce_regs {
	/* DCE Global Common Configuration */
	u32 cfg;		/* DCE configuration */
	u8 reserved1[0x014-0x004];
	u32 oll;		/* Output Length Limit */
	u8 reserved2[0x024-0x018];
	u32 hcl;		/* Hop Count Limit */
	u8 reserved3[0x03c-0x028];
	u32 idle;		/* DCE Idle status */
	u8 reserved4[0x100-0x040];

	/* System Memory Configuration */
	u32 liodnbr;	/* LIODN Base */
	u32 srcidr;	/* Source ID Register */
	u32 smcacr;	/* System Memory Cache Attribute Control */
	u32 smpcr;		/* System Memory Priority Control */
	u32 icir;		/* Internal Context Invalidate */
	u8 reserved5[0x200-0x114];

	/* Statistics */
	u32 cibc_h;	/* Compressor Input Bytes count High */
	u32 cibc_l;	/* Compressor Input Bytes count Low */
	u32 cobc_h;	/* Compressor Output Bytes count High */
	u32 cobc_l;	/* Compressor Output Bytes count Low */
	u32 dibc_h;	/* Decompressor Input Bytes count High */
	u32 dibc_l;	/* Decompressor Input Bytes count Low */
	u32 dobc_h;	/* Decompressor Output Bytes count High */
	u32 dobc_l;	/* Decompressor Output Bytes count Low */
	u8 reserved6[0x3f8-0x220];

	/* Block ID */
	u32 ip_rev_1;	/* DCE IP Block Revision 1 */
	u32 ip_rev_2;	/* DCE IP Block Revision 2 */

	/* Interrupt */
	u32 isr;		/* Interrupt Status */
	u32 ier;		/* Interrupt Enable */
	u32 isdr;		/* Interrupt Status Disable */
	u32 iir;		/* Interrupt Inhibit */
	u32 ifr;		/* Interrupt Force */
	u8 reserved7[0x440-0x414];

	/* Error status */
	u32 ecc1bes;	/* ECC 1-Bit Error Status */
	u32 ecc2bes;	/* ECC 2-Bit Error Status */
	u32 eccaddr;	/* ECC Address */
	u32 ecc1th;	/* ECC 1-Bit Threshold */
	u32 dhecc1ec;	/*
				 * Decompression History memory ECC 1-Bit Error
				 * Count
				 */
	u32 cxecc1ec;	/*
				 * Internal Context memory ECC 1-Bit Error
				 * Count
				 */
	u32 cbecc1ec;	/* Internal Data memory ECC 1-Bit Error Count */
	u8 reserved8[0x480-0x45C];
	/* revision 1.1 */
	u32 uwe_info_h;	/* Unreported Write Error Information High */
	u32 uwe_info_l;	/* Unreported Write Error Information Low */
	/* pad out to 4k */
	u8 padding[0x1000-0x488];
};

/* masks and shifts */

/* DCE Configuration definitions */

/* Read Safe Behavior */
#define DCE_CFG_RSD_SHIFT	20
#define DCE_CFG_RSD_MASK	(0x1UL << DCE_CFG_RSD_SHIFT)
/* RSD Tokens */
#define DCE_CFG_RSD_ENABLE	0x0UL
#define DCE_CFG_RSD_DISABLE	0x1UL

/* Dynamic Power Management Disable */
#define DCE_CFG_DPMD_SHIFT	17
#define DCE_CFG_DPMD_MASK	(0x1UL << DCE_CFG_DPMD_SHIFT)
/* DPMD Tokens */
#define DCE_CFG_DPMD_ENABLE	0x0UL
#define DCE_CFG_DPMD_DISABLE	0x1UL

/* Enable Level */
#define DCE_CFG_EN_SHIFT	0
#define DCE_CFG_EN_MASK		(0x3UL << DCE_CFG_EN_SHIFT)

/* Enable level Tokens */
#define DCE_CFG_EN_DISABLE	0x0UL
#define DCE_CFG_EN_PAUSE	0x1UL
#define DCE_CFG_EN_RESERVED	0x2UL
#define DCE_CFG_EN_ENABLE	0x3UL

/* Output Length Limit */
#define DCE_OLL_SHIFT		0
#define DCE_OLL_MASK		(0xffffUL << DCE_OLL_SHIFT)

/* Hop Count Limit */
#define DCE_HCL_SHIFT		0
#define DCE_HCL_MASK		(0x3ffUL << DCE_HCL_SHIFT)

/* Idle status */
#define DCE_IDLE_STOPPED_SHIFT	8
#define DCE_IDLE_STOPPED_MASK	(0x1UL << DCE_IDLE_STOPPED_SHIFT)

/* Stopped Tokens */
#define DCE_IDLE_STOPPED_YES	0x1UL
#define DCE_IDLE_STOPPED_NO	0x0UL
/* Idle */
#define DCE_IDLE_IDLE_SHIFT	0
#define DCE_IDLE_IDLE_MASK	(0x1UL << DCE_IDLE_IDLE_SHIFT)

/* Idle Tokens */
#define DCE_IDLE_IDLE_YES	0x1UL
#define DCE_IDLE_IDLE_NO	0x0UL

/* DCE System memory configuration */

/* LIODN Base */
#define DCE_LIODNBR_QI_SHARED_LIODN_BASE_SHIFT	16
#define DCE_LIODNBR_QI_SHARED_LIODN_BASE_MASK \
		(0xfffUL << DCE_LIODNBR_QI_SHARED_LIODN_BASE_SHIFT)

#define DCE_LIODNBR_QI_JOB_LIODN_BASE_SHIFT	0
#define DCE_LIODNBR_QI_JOB_LIODN_BASE_MASK \
		(0xfffUL << DCE_LIODNBR_QI_JOB_LIODN_BASE_SHIFT)

/* Source ID */
#define DCE_SCRID_SHIFT			0
#define DCE_SRCID_MASK			(0xffUL << DCE_SCRID_SHIFT)

/* System Memory Cache Attribute Control */
#define DCE_SMCACR_CHWC_SHIFT		28
#define DCE_SMCACR_CHWC_MASK		(0x3UL << DCE_SMCACR_CHWC_SHIFT)

/* CHWC Tokens */
#define DCE_SMCACR_CHWC_NON_COHERENT	0x0UL
#define DCE_SMCACR_CHWC_COHERENT	0x1UL
#define DCE_SMCACR_CHWC_COHERENT_STASH	0x2UL

#define DCE_SMCACR_SCWC_SHIFT		24
#define DCE_SMCACR_SCWC_MASK		(0x3UL << DCE_SMCACR_SCWC_SHIFT)

/* SCWC Tokens */
#define DCE_SMCACR_SCWC_NON_COHERENT	0x0UL
#define DCE_SMCACR_SCWC_COHERENT	0x1UL
#define DCE_SMCACR_SCWC_COHERENT_STASH	0x2UL

#define DCE_SMCACR_FDWC_SHIFT		20
#define DCE_SMCACR_FDWC_MASK		(0x3UL << DCE_SMCACR_FDWC_SHIFT)
/* SMCACR Tokens */
#define DCE_SMCACR_FDWC_NON_COHERENT	0x0UL
#define DCE_SMCACR_FDWC_COHERENT	0x1UL
#define DCE_SMCACR_FDWC_COHERENT_STASH	0x2UL

#define DCE_SMCACR_DHWC_SHIFT		16
#define DCE_SMCACR_DHWC_MASK		(0x3UL << DCE_SMCACR_DHWC_SHIFT)
/* DHWC Tokens */
#define DCE_SMCACR_DHWC_NON_COHERENT	0x0UL
#define DCE_SMCACR_DHWC_COHERENT	0x1UL
#define DCE_SMCACR_DHWC_COHERENT_STASH	0x2UL

#define DCE_SMCACR_CHRC_SHIFT		12
#define DCE_SMCACR_CHRC_MASK		(0x3UL << DCE_SMCACR_CHRC_SHIFT)
/* CHRC Tokens */
#define DCE_SMCACR_CHRC_NON_COHERENT	0x0UL
#define DCE_SMCACR_CHRC_COHERENT	0x1UL
#define DCE_SMCACR_CHRC_COHERENT_STASH	0x2UL

#define DCE_SMCACR_SCRC_SHIFT		8
#define DCE_SMCACR_SCRC_MASK		(0x3UL << DCE_SMCACR_SCRC_SHIFT)
/* SCRC Tokens */
#define DCE_SMCACR_SCRC_NON_COHERENT	0x0UL
#define DCE_SMCACR_SCRC_COHERENT	0x1UL
#define DCE_SMCACR_SCRC_COHERENT_STASH	0x2UL

#define DCE_SMCACR_FDRC_SHIFT		4
#define DCE_SMCACR_FDRC_MASK		(0x3UL << DCE_SMCACR_FDRC_SHIFT)
/* FDRC Tokens */
#define DCE_SMCACR_FDRC_NON_COHERENT	0x0
#define DCE_SMCACR_FDRC_COHERENT	0x1
#define DCE_SMCACR_FDRC_COHERENT_STASH	0x2

#define DCE_SMCACR_DHRC_SHIFT		0
#define DCE_SMCACR_DHRC_MASK		(0x3UL << DCE_SMCACR_DHRC_SHIFT)
/* DHRC Tokens */
#define DCE_SMCACR_DHRC_NON_COHERENT	0x0UL
#define DCE_SMCACR_DHRC_COHERENT	0x1UL
#define DCE_SMCACR_DHRC_COHERENT_STASH	0x2UL

/* System Memory Priority Control */
/* Write Priority */
#define DCE_SMPCR_WP_SHIFT		4
#define DCE_SMPCR_WP_MASK		(0x1UL << DCE_SMPCR_WP_SHIFT)
/* WP Tokens */
#define DCE_SMPCR_WP_NORMAL		0x0UL
#define DCE_SMPCR_WP_ELEVATED		0x1UL
/* Read Priority */
#define DCE_SMPCR_RP_SHIFT		0
#define DCE_SMPCR_RP_MASK		(0x1UL << DCE_SMPCR_RP_SHIFT)
/* RP Tokens */
#define DCE_SMPCR_RP_NORMAL		0x0UL
#define DCE_SMPCR_RP_ELEVATED		0x1UL

/* Internal Context Invalid */
/* Invalidate Internal Context */
#define DCE_ICIR_ICI_SHIFT		0
#define DCE_ICIR_ICI_MASK		(0x1UL << DCE_ICIR_ICI_SHIFT)
/* ICIR Tokens */
#define DCE_ICIR_ICI_NO_EFFECT		0x0
#define DCE_ICIR_ICI_INVALIDATE		0x1

/* Statistics */
/* Compressor Input Byte count High */
#define DCE_CIBC_H_SHIFT		0
#define DCE_CIBC_H_MASK			(0xffffffffUL << DCE_CIBC_H_SHIFT)
/* Compressor Input Byte count Low */
#define DCE_CIBC_L_SHIFT		0
#define DCE_CIBC_L_MASK			(0xffffffffUL << DCE_CIBC_L_SHIFT)
/* Compressor Output Byte count High */
#define DCE_COBC_H_SHIFT		0
#define DCE_COBC_H_MASK			(0xffffffffUL << DCE_COBC_H_SHIFT)
/* Compressor Output Byte count Low */
#define DCE_COBC_L_SHIFT		0
#define DCE_COBC_L_MASK			(0xffffffffUL << DCE_COBC_L_SHIFT)

/* Decompressor Input Byte count High */
#define DCE_DIBC_H_SHIFT		0
#define DCE_DIBC_H_MASK			(0xffffffffUL << DCE_DIBC_H_SHIFT)
/* Decompressor Input Byte count Low */
#define DCE_DIBC_L_SHIFT		0
#define DCE_DIBC_L_MASK			(0xffffffffUL << DCE_DIBC_L_SHIFT)
/* Decompressor Output Byte count High */
#define DCE_DOBC_H_SHIFT		0
#define DCE_DOBC_H_MASK			(0xffffffffUL << DCE_DOBC_H_SHIFT)
/* Decompressor Output Byte count Low */
#define DCE_DOBC_L_SHIFT		0
#define DCE_DOBC_L_MASK			(0xffffffffUL << DCE_DOBC_L_SHIFT)

/* Block ID */
/* Revision 1 */
#define DCE_IP_REV_1_IP_ID_SHIFT	16
#define DCE_IP_REV_1_IP_ID_MASK		(0xffffUL << DCE_IP_REV_1_IP_ID_SHIFT)
/* IP_ID Tokens */
#define DCE_IP_REV_1_IP_ID_DCE		0xaf0UL
/* Major */
#define DCE_IP_REV_1_IP_MJ_SHIFT	8
#define DCE_IP_REV_1_IP_MJ_MASK		(0xffUL << DCE_IP_REV_1_IP_MJ_SHIFT)
/* Minor */
#define DCE_IP_REV_1_IP_MN_SHIFT	0
#define DCE_IP_REV_1_IP_MN_MASK		(0xffUL << DCE_IP_REV_1_IP_MN_SHIFT)
/* Revision 2 */
/* Integration Option */
#define DCE_IP_REV_2_IP_INT_SHIFT	16
#define DCE_IP_REV_2_IP_INT_MASK	(0xffUL << DCE_IP_REV_2_IP_INT_SHIFT)
/* Errata Revision Level */
#define DCE_IP_REV_2_IP_ERR_SHIFT	8
#define DCE_IP_REV_2_IP_ERR_MASK	(0xffUL << DCE_IP_REV_2_IP_ERR_SHIFT)
/* Configuration Option */
#define DCE_IP_REV_2_IP_CFG_SHIFT	0
#define DCE_IP_REV_2_IP_CFG_MASK	(0xffUL << DCE_IP_REV_2_IP_CFG_SHIFT)

/* Interrupt */

/* Interrupt Status */
/* Unreported Write Error */
#define DCE_ISR_UWE_SHIFT		7
#define DCE_ISR_UWE_MASK		(0x1UL << DCE_ISR_UWE_SHIFT)
/* ISR UWE Tokens */
#define DCE_ISR_UWE_NONE		0x0UL
#define DCE_ISR_UWE_AT_LEAST_ONE	0x1UL

/* Single Bit Error */
#define DCE_ISR_SBE_SHIFT		1
#define DCE_ISR_SBE_MASK		(0x1UL << DCE_ISR_SBE_SHIFT)

/* ISR SBE Tokens */
#define DCE_ISR_SBE_NONE		0x0UL
#define DCE_ISR_SBE_AT_LEAST_ONE	0x1UL

/* Double Bit Error */
#define DCE_ISR_DBE_SHIFT		0
#define DCE_ISR_DBE_MASK		(0x1UL << DCE_ISR_DBE_SHIFT)
/* ISR DBE Tokens */
#define DCE_ISR_DBE_NONE		0x0UL
#define DCE_ISR_DBE_AT_LEAST_ONE	0x1UL

/* Interrupt Enable */
/* Unreported Write Error */
#define DCE_IER_UWE_SHIFT		7
#define DCE_IER_UWE_MASK		(0x1UL << DCE_IER_UWE_SHIFT)

/* IER UWE Tokens */
#define DCE_IER_UWE_DISABLE		0x0UL
#define DCE_IER_UWE_ENABLE		0x1UL

/* Single Bit Error */
#define DCE_IER_SBE_SHIFT		1
#define DCE_IER_SBE_MASK		(0x1UL << DCE_IER_SBE_SHIFT)
/* IER SBE Tokens */
#define DCE_IER_SBE_DISABLE		0x0
#define DCE_IER_SBE_ENABLE		0x1

/* Double Bit Error */
#define DCE_IER_DBE_SHIFT		0
#define DCE_IER_DBE_MASK		(0x1UL << DCE_IER_DBE_SHIFT)
/* IER DBE Tokens */
#define DCE_IER_DBE_DISABLE		0x0
#define DCE_IER_DBE_ENABLE		0x1

/* All interrupts */
#define DCE_IER_ALL_MASK \
	(DCE_IER_UWE_MASK | DCE_IER_SBE_MASK | DCE_IER_DBE_MASK)
#define DCE_IER_ALL_SHIFT		0
/* IER ALL Tokens */
#define DCE_IER_ALL_DISABLE		0x0UL
#define DCE_IER_ALL_ENABLE		0x83UL

/* Interrupt Status Disable */
/* Unreported Write Error */
#define DCE_ISDR_UWE_SHIFT		7
#define DCE_ISDR_UWE_MASK		(0x1UL << DCE_ISDR_UWE_SHIFT)

/* IER UWE Tokens */
#define DCE_ISDR_UWE_DISABLE		0x0UL
#define DCE_ISDR_UWE_ENABLE		0x1UL

/* Single Bit Error */
#define DCE_ISDR_SBE_SHIFT		1
#define DCE_ISDR_SBE_MASK		(0x1UL << DCE_ISDR_SBE_SHIFT)
/* IER SBE Tokens */
#define DCE_ISDR_SBE_DISABLE		0x0UL
#define DCE_ISDR_SBE_ENABLE		0x1UL

/* Double Bit Error */
#define DCE_ISDR_DBE_SHIFT		0
#define DCE_ISDR_DBE_MASK		(0x1UL << DCE_ISDR_DBE_SHIFT)
/* IER DBE Tokens */
#define DCE_ISDR_DBE_DISABLE		0x0UL
#define DCE_ISDR_DBE_ENABLE		0x1UL

/* Interrupt Inhibit */
/* Inhibit */
#define DCE_IIR_I_SHIFT			0
#define DCE_IIR_I_MASK			(0x1UL << DCE_IIR_I_SHIFT)

/* IIR I Tokens */
#define DCE_IIR_I_CLEAR			0x0UL
#define DCE_IIR_I_SET			0x1UL

/* Interrupt Force */
/* Unreported Write Error */
#define DCE_IFR_UWE_SHIFT		7
#define DCE_IFR_UWE_MASK		(0x1UL << DCE_IFR_UWE_SHIFT)
/* IFR UWE Tokens */
#define DCE_IFR_UWE_SET			0x1UL

/* Single Bit Error */
#define DCE_IFR_SBE_SHIFT		1
#define DCE_IFR_SBE_MASK		(0x1UL << DCE_IFR_SBE_SHIFT)
/* IFR SBE Tokens */
#define DCE_IFR_SBE_SET			0x1UL

/* Double Bit Error */
#define DCE_IFR_DBE_SHIFT		0
#define DCE_IFR_DBE_MASK		(0x1UL << DCE_IFR_DBE_SHIFT)
/* IFR DBE Tokens */
#define DCE_IFR_DBE_SET			0x1

/* Error Status */

/* ECC 1-Bit Error Status */
/* Compression History Memory */
#define DCE_ECC1BES_CBM_SHIFT		2
#define DCE_ECC1BES_CBM_MASK		(0x1UL << DCE_ECC1BES_CBM_MASK)

/* CBM Tokens */
#define DCE_ECC1BES_CBM_FALSE		0x0UL
#define DCE_ECC1BES_CBM_TRUE		0x1UL
#define DCE_ECC1BES_CBM_CLEAR		0x1UL

/* Decompression History Memory */
#define DCE_ECC1BES_DHM_SHIFT		1
#define DCE_ECC1BES_DHM_MASK		(0x1UL << DCE_ECC1BES_DHM_SHIFT)
/* DHM Tokens */
#define DCE_ECC1BES_DHM_FALSE		0x0UL
#define DCE_ECC1BES_DHM_TRUE		0x1UL
#define DCE_ECC1BES_DHM_CLEAR		0x1UL

/* Internal Context Memory */
#define DCE_ECC1BES_CXM_SHIFT		0
#define DCE_ECC1BES_CXM_MASK		(0x1UL << DCE_ECC1BES_CXM_SHIFT)
/* CXM Tokens */
#define DCE_ECC1BES_CXM_FALSE		0x0UL
#define DCE_ECC1BES_CXM_TRUE		0x1UL
#define DCE_ECC1BES_CXM_CLEAR		0x1UL

/* ECC 2-Bit Error Status */
/* Compression History Memory */
#define DCE_ECC2BES_CBM_SHIFT		2
#define DCE_ECC2BES_CBM_MASK		(0x1UL << DCE_ECC2BES_CBM_SHIFT)
/* CBM Tokens */
#define DCE_ECC2BES_CBM_FALSE		0x0UL
#define DCE_ECC2BES_CBM_TRUE		0x1UL
#define DCE_ECC2BES_CBM_CLEAR		0x1UL

/* Decompression History Memory */
#define DCE_ECC2BES_DHM_SHIFT		1
#define DCE_ECC2BES_DHM_MASK		(0x1UL << DCE_ECC2BES_DHM_SHIFT)
/* DHM Tokens */
#define DCE_ECC2BES_DHM_FALSE		0x0UL
#define DCE_ECC2BES_DHM_TRUE		0x1UL
#define DCE_ECC2BES_DHM_CLEAR		0x1UL

/* Internal Context Memory */
#define DCE_ECC2BES_CXM_SHIFT		0
#define DCE_ECC2BES_CXM_MASK		(0x1UL << DCE_ECC2BES_CXM_SHIFT)
/* CXM Tokens */
#define DCE_ECC2BES_CXM_FALSE		0x0UL
#define DCE_ECC2BES_CXM_TRUE		0x1UL
#define DCE_ECC2BES_CXM_CLEAR		0x1UL

/* ECC Address */
/* Capture Error Indication */
#define DCE_ECCADDR_CAP_SHIFT		31
#define DCE_ECCADDR_CAP_MASK		(0x1UL << DCE_ECCADDR_CAP_SHIFT)
/* CAP Tokens */
#define DCE_ECCADDR_CAP_NONE		0x0UL
#define DCE_ECCADDR_CAP_CAPTURED	0x1UL
#define DCE_ECCADDR_CAP_CLEAR		0x1UL

/* Capture Error Type */
#define DCE_ECCADDR_CAT_SHIFT		30
#define DCE_ECCADDR_CAT_MASK		(0x1UL << DCE_ECCADDR_CAT_SHIFT)
/* CAT Tokens */
#define DCE_ECCADDR_CAT_SB_ECC		0x0UL
#define DCE_ECCADDR_CAT_MB_ECC		0x1UL

/* Memory Identifier */
#define DCE_ECCADDR_MEM_SHIFT		16
#define DCE_ECCADDR_MEM_MASK		(0x1fUL << DCE_ECCADDR_MEM_SHIFT)
/* MEM Tokens */
#define DCE_ECCADDR_MEM_DHM0		0x0UL
#define DCE_ECCADDR_MEM_DHM1		0x1UL
#define DCE_ECCADDR_MEM_DHM2		0x2UL
#define DCE_ECCADDR_MEM_DHM3		0x3UL
#define DCE_ECCADDR_MEM_DHM4		0x4UL
#define DCE_ECCADDR_MEM_DHM5		0x5UL
#define DCE_ECCADDR_MEM_DHM6		0x6UL
#define DCE_ECCADDR_MEM_DHM7		0x7UL
#define DCE_ECCADDR_MEM_CBM0		0x8UL
#define DCE_ECCADDR_MEM_CBM1		0x9UL
#define DCE_ECCADDR_MEM_CBM2		0xaUL
#define DCE_ECCADDR_MEM_CBM3		0xbUL
#define DCE_ECCADDR_MEM_CBM4		0xcUL
#define DCE_ECCADDR_MEM_CBM5		0xdUL
#define DCE_ECCADDR_MEM_CBM6		0xeUL
#define DCE_ECCADDR_MEM_CBM7		0xfUL
#define DCE_ECCADDR_MEM_CXMA0		0x10UL
#define DCE_ECCADDR_MEM_CXMB0		0x11UL
#define DCE_ECCADDR_MEM_CXMA1		0x12UL
#define DCE_ECCADDR_MEM_CXMB1		0x13UL
#define DCE_ECCADDR_MEM_CXMA2		0x14UL
#define DCE_ECCADDR_MEM_CXMB2		0x15UL
#define DCE_ECCADDR_MEM_CXMA3		0x16UL
#define DCE_ECCADDR_MEM_CXMB3		0x17UL
#define DCE_ECCADDR_MEM_CXMA4		0x18UL
#define DCE_ECCADDR_MEM_CXMB4		0x19UL
#define DCE_ECCADDR_MEM_CXMA5		0x1aUL
#define DCE_ECCADDR_MEM_CXMB5		0x1bUL
#define DCE_ECCADDR_MEM_CXMA6		0x1cUL
#define DCE_ECCADDR_MEM_CXMB6		0x1dUL
#define DCE_ECCADDR_MEM_CXMA7		0x1eUL
#define DCE_ECCADDR_MEM_CXMB7		0x1fUL

/* Capture the address within the memory upon which the error occurred */
#define DCE_ECCADDR_ADDR_SHIFT		0
#define DCE_ECCADDR_ADDR_MASK		(0xffffUL << DCE_ECCADDR_ADDR_SHIFT)

/* ECC 1-Bit Threshold */
/* Internal Data Memory */
#define DCE_ECC1TH_DECBM_SHIFT		10
#define DCE_ECC1TH_DECBM_MASK		(0x1UL << DCE_ECC1TH_DECBM_SHIFT)
/* DECBM Tokens */
#define DCE_ECC1TH_DECBM_DISABLE	0x1UL
#define DCE_ECC1TH_DECBM_ENABLE		0x0UL

/* Decompression History Memory */
#define DCE_ECC1TH_DEDHM_SHIFT		9
#define DCE_ECC1TH_DEDHM_MASK		(0x1UL << DCE_ECC1TH_DEDHM_SHIFT)
/* DEDHM Tokens */
#define DCE_ECC1TH_DEDHM_DISABLE	0x1UL
#define DCE_ECC1TH_DEDHM_ENABLE		0x0UL

/* Internal Context Memory */
#define DCE_ECC1TH_DECXM_SHIFT		8
#define DCE_ECC1TH_DECXM_MASK		(0x1UL << DCE_ECC1TH_DECXM_SHIFT)
/* DECXM Tokens */
#define DCE_ECC1TH_DECXM_DISABLE	0x1UL
#define DCE_ECC1TH_DECXM_ENABLE		0x0UL

/* Threshold value */
#define DCE_ECC1TH_THRESH_SHIFT		0
#define DCE_ECC1TH_THRESH_MASK		(0xffUL << DCE_ECC1TH_THRESH_SHIFT)

/* Decompression History memory ECC 1-Bit Count */
/* Count */
#define DCE_ECC1EC_COUNT_SHIFT		0
#define DCE_ECC1EC_COUNT_MASK		(0xffUL << DCE_ECC1EC_COUNT_SHIFT)

/* Internal Context ECC 1-Bit Error Count */
/* Count */
#define DCE_CXECC1EC_COUNT_SHIFT	0
#define DCE_CXECC1EC_COUNT_MASK		(0xffUL << DCE_CXECC1EC_COUNT_SHIFT)

/* Internal Data ECC 1-Bit Error Count */
/* Count */
#define DCE_CBECC1EC_COUNT_SHIFT	0
#define DCE_CBECC1EC_COUNT_MASK		(0xffUL << DCE_CBECC1EC_COUNT_SHIFT)

/* Unreported Write Error Information High */
/* LIODN */
#define DCE_UWE_INFO_H_LIODN_SHIFT	16
#define DCE_UWE_INFO_H_LIODN_MASK	(0xfffUL << DCE_UWE_INFO_H_LIODN_SHIFT)
/* SCRP */
#define DCE_UWE_INFO_H_SCRP_SHIFT	0
#define DCE_UWE_INFO_H_SCRP_MASK (0xffUL << DCE_UWE_INFO_H_SCRP_SHIFT)

/* Unreported Write Error Information Low */
#define DCE_UWE_INFO_L_SCRP_SHIFT	6
#define DCE_UWE_INFO_L_SCRP_MASK (0x3ffffffUL << DCE_UWE_INFO_L_SCRP_SHIFT)

/* helper to get combine and shift SCRPH and L */
#define DCE_GEN_SCRP(scrp_h, scrp_l) \
	(((u64)scrp_h << 32 | scrp_l) << DCE_UWE_INFO_L_SCRP_SHIFT)

#endif /* FL_DCE_REGS_H */
