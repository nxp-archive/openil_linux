/* Copyright 2008-2011 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PME2_PRIVATE_H
#define PME2_PRIVATE_H

#include "pme2_sys.h"
#include <linux/fsl_pme.h>

#undef PME2_DEBUG

#ifdef PME2_DEBUG
#define PMEPRINFO(fmt, args...) pr_info("PME2: %s: " fmt, __func__, ## args)
#else
#define PMEPRINFO(fmt, args...)
#endif

#define PMEPRERR(fmt, args...) pr_err("PME2: %s: " fmt, __func__, ## args)
#define PMEPRCRIT(fmt, args...) pr_crit("PME2: %s: " fmt, __func__, ## args)

#ifdef CONFIG_FSL_PME2_CTRL
/* Hooks */
int pme2_create_sysfs_dev_files(struct platform_device *ofdev);
void pme2_remove_sysfs_dev_files(struct platform_device *ofdev);
void accumulator_update_interval(u32 interval);
#endif

#ifdef CONFIG_PM

struct pme_save_regs_pmfa {
	uint32_t isr;
	uint32_t ier;
	uint32_t isdr;
	uint32_t iir;
	uint32_t ifr;
	uint32_t rll;
	uint32_t cdcr;
	uint32_t reserved1[2];
	uint32_t trunci;
	uint32_t rbc;
	uint32_t esr;
	uint32_t ecr0;
	uint32_t ecr1;
	uint32_t reserved2[6];
	uint32_t efqc;
	uint32_t sram_addr;
	uint32_t sram_rdat;
	uint32_t sram_wdat;
	uint32_t faconf;
	uint32_t pmstat;
	uint32_t famcr;
	uint32_t pmtr;
	uint32_t reserved3;
	uint32_t pehd;
	uint32_t reserved4[2];
	uint32_t bsc0;
	uint32_t bsc1;
	uint32_t bsc2;
	uint32_t bsc3;
	uint32_t bsc4;
	uint32_t bsc5;
	uint32_t bsc6;
	uint32_t bsc7;
	uint32_t reserved5[16];
	uint32_t qmbfd0;
	uint32_t qmbfd1;
	uint32_t qmbfd2;
	uint32_t qmbfd3;
	uint32_t qmbctxtah;
	uint32_t qmbctxtal;
	uint32_t qmbctxtb;
	uint32_t qmbctl;
	uint32_t ecc1bes;
	uint32_t ecc2bes;
	uint32_t reserved6[2];
	uint32_t eccaddr;
	uint32_t reserved7[27];
	uint32_t tbt0ecc1th;
	uint32_t tbt0ecc1ec;
	uint32_t tbt1ecc1th;
	uint32_t tbt1ecc1ec;
	uint32_t vlt0ecc1th;
	uint32_t vlt0ecc1ec;
	uint32_t vlt1ecc1th;
	uint32_t vlt1ecc1ec;
	uint32_t cmecc1th;
	uint32_t cmecc1ec;
	uint32_t reserved8[2];
	uint32_t dxcmecc1th;
	uint32_t dxcmecc1ec;
	uint32_t reserved9[2];
	uint32_t dxemecc1th;
	uint32_t dxemecc1ec;
	uint32_t reserved10[14];
};

struct pme_save_regs_kes {
	uint32_t stnib;
	uint32_t stnis;
	uint32_t stnth1;
	uint32_t stnth2;
	uint32_t stnthv;
	uint32_t stnths;
	uint32_t stnch;
	uint32_t swdb;
	uint32_t kvlts;
	uint32_t kec;
	uint32_t reserved1[22];
};

struct pme_save_regs_dxe {
	uint32_t stnpm;
	uint32_t stns1m;
	uint32_t drcic;
	uint32_t drcmc;
	uint32_t stnpmr;
	uint32_t reserved1[3];
	uint32_t pdsrbah;
	uint32_t pdsrbal;
	uint32_t dmcr;
	uint32_t dec0;
	uint32_t dec1;
	uint32_t reserved2[3];
	uint32_t dlc;
	uint32_t reserved3[15];
};

struct pme_save_regs_sre {
	uint32_t stndrs;
	uint32_t stnesr;
	uint32_t stns1r;
	uint32_t stnob;
	uint32_t scbarh;
	uint32_t scbarl;
	uint32_t smcr;
	uint32_t reserved1;
	uint32_t srec;
	uint32_t reserved2;
	uint32_t esrp;
	uint32_t reserved3[3];
	uint32_t srrv0;
	uint32_t srrv1;
	uint32_t srrv2;
	uint32_t srrv3;
	uint32_t srrv4;
	uint32_t srrv5;
	uint32_t srrv6;
	uint32_t srrv7;
	uint32_t srrfi;
	uint32_t reserved4;
	uint32_t srri;
	uint32_t srrr;
	uint32_t srrwc;
	uint32_t sfrcc;
	uint32_t sec1;
	uint32_t sec2;
	uint32_t sec3;
	uint32_t reserved5;
};

struct pme_save_regs_mia {
	uint32_t mia_byc;
	uint32_t mia_blc;
	uint32_t mia_ce;
	uint32_t reserved1;
	uint32_t mia_cr;
	uint32_t reserved2[284];
};

struct pme_save_regs_gen {
	uint32_t liodnbr;
	uint32_t reserved1[126];
	uint32_t srcidr;
	uint32_t reserved2[2];
	uint32_t liodnr;
	uint32_t reserved3[122];
	uint32_t pm_ip_rev_1;
	uint32_t pm_ip_rev_2;
};

struct pme_save_reg_all {
	struct pme_save_regs_pmfa pmfa;
	struct pme_save_regs_kes kes;
	struct pme_save_regs_dxe dxe;
	struct pme_save_regs_sre sre;
	struct pme_save_regs_mia mia;
	struct pme_save_regs_gen gen;
};

struct pme_pwrmgmt_ctx {
	struct qman_fq tx_fq;
	struct qman_fq rx_fq;
	struct qm_fd result_fd;
	struct completion done;
};

struct pmtcc_raw_db {
	/* vmalloc's memory. Save PME's sram data */
	uint8_t *alldb;
};

struct ccsr_backup_info {
	uint32_t save_faconf_en;
	uint32_t save_cdcr;
	struct pme_save_reg_all regdb;
};

struct portal_backup_info {
	/* vmalloc's memory. Save PME's sram data */
	struct pmtcc_raw_db db;
	struct pme_pwrmgmt_ctx *ctx;
	struct platform_device *pdev;
	int backup_failed;
};

#endif /* CONFIG_PM */

struct pme2_private_data {
	uint32_t pme_rev1;
	uint32_t __iomem *regs;
#ifdef CONFIG_PM
	struct ccsr_backup_info save_ccsr;
	struct portal_backup_info save_db;
#endif
};

#ifdef CONFIG_PM
/* Hooks from pme_ctrl to pme_suspend */
int init_pme_suspend(struct pme2_private_data *priv_data);
void exit_pme_suspend(struct pme2_private_data *priv_data);
int pme_suspend(struct pme2_private_data *priv_data);
int pme_resume(struct pme2_private_data *priv_data);

/* Hooks from pme_suspend into pme_ctrl */
void restore_all_ccsr(struct ccsr_backup_info *save_ccsr,
			uint32_t __iomem *regs);
void save_all_ccsr(struct ccsr_backup_info *save_ccsr,
			uint32_t __iomem *regs);
#endif

static inline void set_fd_addr(struct qm_fd *fd, dma_addr_t addr)
{
	qm_fd_addr_set64(fd, addr);
}
static inline dma_addr_t get_fd_addr(const struct qm_fd *fd)
{
	return (dma_addr_t)qm_fd_addr_get64(fd);
}
static inline void set_sg_addr(struct qm_sg_entry *sg, dma_addr_t addr)
{
	qm_sg_entry_set64(sg, addr);
}
static inline dma_addr_t get_sg_addr(const struct qm_sg_entry *sg)
{
	return qm_sg_addr(sg);
}

/******************/
/* Datapath types */
/******************/

enum pme_mode {
	pme_mode_direct = 0x00,
	pme_mode_flow = 0x80
};

struct pme_context_a {
	enum pme_mode mode:8;
	u8 __reserved;
	/* Flow Context pointer (48-bit), ignored if mode==direct */
	u16 flow_hi;
	u32 flow_lo;
} __packed;
static inline u64 pme_context_a_get64(const struct pme_context_a *p)
{
	return ((u64)p->flow_hi << 32) | (u64)p->flow_lo;
}
/* Macro, so we compile better if 'v' isn't always 64-bit */
#define pme_context_a_set64(p, v) \
	do { \
		struct pme_context_a *__p931 = (p); \
		__p931->flow_hi = upper_32_bits(v); \
		__p931->flow_lo = lower_32_bits(v); \
	} while (0)

struct pme_context_b {
	u32 rbpid:8;
	u32 rfqid:24;
} __packed;


/* This is the 32-bit frame "cmd/status" field, sent to PME */
union pme_cmd {
	struct pme_cmd_nop {
		enum pme_cmd_type cmd:3;
	} nop;
	struct pme_cmd_flow_read {
		enum pme_cmd_type cmd:3;
	} fcr;
	struct pme_cmd_flow_write {
		enum pme_cmd_type cmd:3;
		u8 __reserved:5;
		u8 flags;	/* See PME_CMD_FCW_*** */
	} __packed fcw;
	struct pme_cmd_pmtcc {
		enum pme_cmd_type cmd:3;
	} pmtcc;
	struct pme_cmd_scan {
		union {
			struct {
				enum pme_cmd_type cmd:3;
				u8 flags:5; /* See PME_CMD_SCAN_*** */
			} __packed;
		};
		u8 set;
		u16 subset;
	} __packed scan;
};

/*
 * The exported macro forms a "scan_args" u32 from 3 inputs, these private
 * inlines do the inverse, if you need to crack one apart.
 */
static inline u8 scan_args_get_flags(u32 args)
{
	return args >> 24;
}
static inline u8 scan_args_get_set(u32 args)
{
	return (args >> 16) & 0xff;
}
static inline u16 scan_args_get_subset(u32 args)
{
	return args & 0xffff;
}

/* Hook from pme2_high to pme2_low */
struct qman_fq *slabfq_alloc(void);
void slabfq_free(struct qman_fq *fq);

/* Hook from pme2_high to pme2_ctrl */
int pme2_have_control(void);
int pme2_exclusive_set(struct qman_fq *fq);
int pme2_exclusive_unset(void);

#define DECLARE_GLOBAL(name, t, mt, def, desc) \
	static t name = def; \
	module_param(name, mt, 0644); \
	MODULE_PARM_DESC(name, desc ", default: " __stringify(def));

/* Constants used by the SRE ioctl. */
#define PME_PMFA_SRE_POLL_MS		100
#define PME_PMFA_SRE_INDEX_MAX		(1 << 27)
#define PME_PMFA_SRE_INC_MAX		(1 << 12)
#define PME_PMFA_SRE_REP_MAX		(1 << 28)
#define PME_PMFA_SRE_INTERVAL_MAX	(1 << 12)

/* Encapsulations for mapping */
#define flow_map(flow) \
({ \
	struct pme_flow *__f913 = (flow); \
	pme_map(__f913); \
})

#define residue_map(residue) \
({ \
	struct pme_hw_residue *__f913 = (residue); \
	pme_map(__f913); \
})

/* 4k minus residue */
#define PME_MAX_SCAN_SIZE_BUG_2_1_4	(4095 - 127)

#define PME_PM_IP_REV_1_IP_MJ_MASK 0x0000ff00UL
#define PME_PM_IP_REV_1_IP_MJ_SHIFT 8UL
#define PME_PM_IP_REV_1_IP_MN_MASK 0x000000ffUL
#define PME_PM_IP_REV_1_IP_MN_SHIFT 0UL
#define PME_PM_IP_REV_2_IP_ERR_MASK 0x0000ff00UL
#define PME_PM_IP_REV_2_IP_ERR_SHIFT 8UL

static inline int get_major_rev(u32 pme_rev1)
{
	return (pme_rev1 & PME_PM_IP_REV_1_IP_MJ_MASK) >>
		PME_PM_IP_REV_1_IP_MJ_SHIFT;
}

static inline int get_minor_rev(u32 pme_rev1)
{
	return (pme_rev1 & PME_PM_IP_REV_1_IP_MN_MASK) >>
		PME_PM_IP_REV_1_IP_MN_SHIFT;
}

static inline int get_errata_rev(u32 pme_rev2)
{
	return (pme_rev2 & PME_PM_IP_REV_2_IP_ERR_MASK) >>
		PME_PM_IP_REV_2_IP_ERR_SHIFT;
}

static inline int is_version_2_1_4(u32 pme_rev1, u32 pme_rev2)
{
	return  (get_major_rev(pme_rev1) == 2) &&
		(get_minor_rev(pme_rev1) == 1) &&
		(get_errata_rev(pme_rev2) == 4);
}

static inline int is_version(u32 pme_rev1, int major, int minor)
{
	return  (get_major_rev(pme_rev1) == major) &&
		(get_minor_rev(pme_rev1) == minor);
}

#endif
