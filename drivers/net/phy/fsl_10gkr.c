/* Freescale XFI 10GBASE-KR driver.
 *   Author: Shaohui Xie <Shaohui.Xie@freescale.com>
 *
 * Copyright 2014 Freescale Semiconductor, Inc.
 *
 * Licensed under the GPL-2 or later.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/phy.h>
#include <linux/of.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

#define FSL_XFI_PCS_PHY_ID		0x7C000012
#define FSL_XFI_PCS_PHY_ID2		0x0083e400

/* Freescale XFI PCS MMD */
#define FSL_XFI_PMD			0x1
#define FSL_XFI_PCS			0x3
#define FSL_XFI_AN			0x7
#define FSL_XFI_VS1			0x1e

/* Freescale XFI PMD registers */
#define FSL_XFI_PMD_CTRL		0x0
#define FSL_XFI_KR_PMD_CTRL		0x0096
#define FSL_XFI_KR_PMD_STATUS		0x0097
#define FSL_XFI_KR_LP_CU		0x0098
#define FSL_XFI_KR_LP_STATUS		0x0099
#define FSL_XFI_KR_LD_CU		0x009a
#define FSL_XFI_KR_LD_STATUS		0x009b

/* PMD define */
#define PMD_RESET			0x1
#define PMD_STATUS_SUP_STAT		0x4
#define PMD_STATUS_FRAME_LOCK		0x2
#define TRAIN_EN			0x3
#define TRAIN_DISABLE			0x1
#define RX_STAT				0x1

/* Freescale XFI PCS registers */
#define FSL_XFI_PCS_CTRL		0x0
#define FSL_XFI_PCS_STATUS		0x1

/* Freescale XFI Auto-Negotiation Registers */
#define FSL_XFI_AN_CTRL			0x0000
#define FSL_XFI_LNK_STATUS		0x0001
#define FSL_XFI_AN_AD_1			0x0011
#define FSL_XFI_BP_STATUS		0x0030

#define XFI_AN_AD1			0x85
#define XF_AN_RESTART			0x1200
#define XFI_AN_LNK_STAT_UP		0x4

/* Freescale XFI Vendor-Specific 1 Registers */
#define FSL_XFI_PCS_INTR_EVENT		0x0002
#define FSL_XFI_PCS_INTR_MASK		0x0003
#define FSL_XFI_AN_INTR_EVENT		0x0004
#define FSL_XFI_AN_INTR_MASK		0x0005
#define FSL_XFI_LT_INTR_EVENT		0x0006
#define FSL_XFI_LT_INTR_MASK		0x0007

/* C(-1) */
#define BIN_M1				0
/* C(1) */
#define BIN_LONG			1
#define BIN_M1_SEL			6
#define BIN_Long_SEL			7
#define CDR_SEL_MASK			0x00070000
#define BIN_SNAPSHOT_NUM		5
#define BIN_M1_THRESHOLD		3
#define BIN_LONG_THRESHOLD		2

#define PRE_COE_MASK			0x03c00000
#define POST_COE_MASK			0x001f0000
#define ZERO_COE_MASK			0x00003f00
#define PRE_COE_SHIFT			22
#define POST_COE_SHIFT			16
#define ZERO_COE_SHIFT			8

#define PRE_COE_MAX			0x0
#define PRE_COE_MIN			0x8
#define POST_COE_MAX			0x0
#define POST_COE_MIN			0x10
#define ZERO_COE_MAX			0x30
#define ZERO_COE_MIN			0x0

#define TECR0_INIT			0x24200000
#define RATIO_PREQ			0x3
#define RATIO_PST1Q			0xd
#define RATIO_EQ			0x20

#define GCR1_CTL_SNP_START_MASK		0x00002000
#define GCR1_SNP_START_MASK		0x00000040
#define RECR1_SNP_DONE_MASK		0x00000004
#define RECR1_CTL_SNP_DONE_MASK		0x00000002
#define TCSR1_SNP_DATA_MASK		0x0000ffc0
#define TCSR1_SNP_DATA_SHIFT		6
#define TCSR1_EQ_SNPBIN_SIGN_MASK	0x100

#define RECR1_GAINK2_MASK		0x0f000000
#define RECR1_GAINK2_SHIFT		24
#define RECR1_GAINK3_MASK		0x000f0000
#define RECR1_GAINK3_SHIFT		16
#define RECR1_OFFSET_MASK		0x00003f80
#define RECR1_OFFSET_SHIFT		7
#define RECR1_BLW_MASK			0x00000f80
#define RECR1_BLW_SHIFT			7
#define EYE_CTRL_SHIFT			12
#define BASE_WAND_SHIFT			10

#define XGKR_TIMEOUT			1050
#define AN_ABILITY_MASK			0x9
#define AN_10GKR_MASK			0x8
#define LT_10GKR_MASK			0x4
#define TRAIN_FAIL			0x8

#define INCREMENT			1
#define DECREMENT			2
#define TIMEOUT_LONG			3
#define TIMEOUT_M1			3

#define RX_READY_MASK			0x8000
#define PRESET_MASK			0x2000
#define INIT_MASK			0x1000
#define COP1_MASK			0x30
#define COP1_SHIFT			4
#define COZ_MASK			0xc
#define COZ_SHIFT			2
#define COM1_MASK			0x3
#define COM1_SHIFT			0
#define REQUEST_MASK			0x3f
#define LD_ALL_MASK			(PRESET_MASK | INIT_MASK | \
					COP1_MASK | COZ_MASK | COM1_MASK)

#define FSL_SERDES_INSTANCE1_BASE	0xffe0ea000
#define FSL_SERDES_INSTANCE2_BASE	0xffe0eb000
#define FSL_LANE_A_BASE			0x800
#define FSL_LANE_B_BASE			0x840
#define FSL_LANE_C_BASE			0x880
#define FSL_LANE_D_BASE			0x8C0
#define FSL_LANE_E_BASE			0x900
#define FSL_LANE_F_BASE			0x940
#define FSL_LANE_G_BASE			0x980
#define FSL_LANE_H_BASE			0x9C0
#define GCR0_RESET_MASK			0x600000

#define NEW_ALGORITHM_TRAIN_TX
#ifdef	NEW_ALGORITHM_TRAIN_TX
#define	FORCE_INC_COP1_NUMBER		0
#define	FORCE_INC_COM1_NUMBER		1
#endif

enum fsl_xgkr_driver {
	FSL_XGKR_REV1,
	FSL_XGKR_REV2,
	FSL_XGKR_INV
};

static struct phy_driver fsl_xgkr_driver[FSL_XGKR_INV];

enum coe_filed {
	COE_COP1,
	COE_COZ,
	COE_COM
};

enum coe_update {
	COE_NOTUPDATED,
	COE_UPDATED,
	COE_MIN,
	COE_MAX,
	COE_INV
};

enum serdes_inst {
	SERDES_1,
	SERDES_2,
	SERDES_MAX
};

enum lane_inst {
	LANE_A,
	LANE_B,
	LANE_C,
	LANE_D,
	LANE_E,
	LANE_F,
	LANE_G,
	LANE_H,
	LANE_MAX
};

struct serdes_map {
	const char *serdes_name;
	unsigned long serdes_base;
};

struct lane_map {
	const char *lane_name;
	unsigned long lane_base;
};

const struct serdes_map s_map[SERDES_MAX] = {
	{"serdes-1", FSL_SERDES_INSTANCE1_BASE},
	{"serdes-2", FSL_SERDES_INSTANCE2_BASE}
};

const struct lane_map l_map[LANE_MAX] = {
	{"lane-a", FSL_LANE_A_BASE},
	{"lane-b", FSL_LANE_B_BASE},
	{"lane-c", FSL_LANE_C_BASE},
	{"lane-d", FSL_LANE_D_BASE},
	{"lane-e", FSL_LANE_E_BASE},
	{"lane-f", FSL_LANE_F_BASE},
	{"lane-g", FSL_LANE_G_BASE},
	{"lane-h", FSL_LANE_H_BASE}
};

struct per_lane_ctrl_status {
	__be32 gcr0;	/* 0x.000 - General Control Register 0 */
	__be32 gcr1;	/* 0x.004 - General Control Register 1 */
	__be32 gcr2;	/* 0x.008 - General Control Register 2 */
	__be32 resv1;	/* 0x.00C - Reserved */
	__be32 recr0;	/* 0x.010 - Receive Equalization Control Register 0 */
	__be32 recr1;	/* 0x.014 - Receive Equalization Control Register 1 */
	__be32 tecr0;	/* 0x.018 - Transmit Equalization Control Register 0 */
	__be32 resv2;	/* 0x.01C - Reserved */
	__be32 tlcr0;	/* 0x.020 - TTL Control Register 0 */
	__be32 tlcr1;	/* 0x.024 - TTL Control Register 1 */
	__be32 tlcr2;	/* 0x.028 - TTL Control Register 2 */
	__be32 tlcr3;	/* 0x.02C - TTL Control Register 3 */
	__be32 tcsr0;	/* 0x.030 - Test Control/Status Register 0 */
	__be32 tcsr1;	/* 0x.034 - Test Control/Status Register 1 */
	__be32 tcsr2;	/* 0x.038 - Test Control/Status Register 2 */
	__be32 tcsr3;	/* 0x.03C - Test Control/Status Register 3 */
};

struct training_state_machine {
	bool bin_m1_late_early;
	bool bin_long_late_early;
	bool bin_m1_stop;
	bool bin_long_stop;
	bool tx_complete;
	bool an_ok;
	bool link_up;
	bool running;
	bool sent_init;
	int m1_min_max_cnt;
	int long_min_max_cnt;
#ifdef	NEW_ALGORITHM_TRAIN_TX
	int pre_inc;
	int post_inc;
#endif
};

struct fsl_xgkr_inst {
	void *reg_base;
	struct mii_bus *bus;
	struct phy_device *phydev;
	struct training_state_machine t_s_m;
	u32 ld_update;
	u32 ld_status;
	u32 ratio_preq;
	u32 ratio_pst1q;
	u32 adpt_eq;
};

struct fsl_xgkr_wk {
	struct work_struct xgkr_wk;
	struct list_head xgkr_list;
	struct fsl_xgkr_inst *xgkr_inst;
};

LIST_HEAD(fsl_xgkr_list);

static struct timer_list xgkr_timer;
static int fire_timer;
static struct workqueue_struct *xgkr_wq;

static void init_state_machine(struct training_state_machine *s_m)
{
	s_m->bin_m1_late_early = true;
	s_m->bin_long_late_early = false;
	s_m->bin_m1_stop = false;
	s_m->bin_long_stop = false;
	s_m->tx_complete = false;
	s_m->an_ok = false;
	s_m->link_up = false;
	s_m->running = false;
	s_m->sent_init = false;
	s_m->m1_min_max_cnt = 0;
	s_m->long_min_max_cnt = 0;
#ifdef	NEW_ALGORITHM_TRAIN_TX
	s_m->pre_inc = FORCE_INC_COM1_NUMBER;
	s_m->post_inc = FORCE_INC_COP1_NUMBER;
#endif
}

void tune_tecr0(struct fsl_xgkr_inst *inst)
{
	struct per_lane_ctrl_status *reg_base;
	u32 val;

	reg_base = (struct per_lane_ctrl_status *)inst->reg_base;

	val = TECR0_INIT |
		inst->adpt_eq << ZERO_COE_SHIFT |
		inst->ratio_preq << PRE_COE_SHIFT |
		inst->ratio_pst1q << POST_COE_SHIFT;

	/* reset the lane */
	iowrite32be(ioread32be(&reg_base->gcr0) & ~GCR0_RESET_MASK,
		    &reg_base->gcr0);
	udelay(1);
	iowrite32be(val, &reg_base->tecr0);
	udelay(1);
	/* unreset the lane */
	iowrite32be(ioread32be(&reg_base->gcr0) | GCR0_RESET_MASK,
		    &reg_base->gcr0);
	udelay(1);
}

static void start_lt(struct phy_device *phydev)
{
	phy_write_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_PMD_CTRL, TRAIN_EN);
}

static void stop_lt(struct phy_device *phydev)
{
	phy_write_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_PMD_CTRL, TRAIN_DISABLE);
}

static void reset_gcr0(struct fsl_xgkr_inst *inst)
{
	struct per_lane_ctrl_status *reg_base;

	reg_base = (struct per_lane_ctrl_status *)inst->reg_base;

	iowrite32be(ioread32be(&reg_base->gcr0) & ~GCR0_RESET_MASK,
		    &reg_base->gcr0);
	udelay(1);
	iowrite32be(ioread32be(&reg_base->gcr0) | GCR0_RESET_MASK,
		    &reg_base->gcr0);
	udelay(1);
}

static void reset_lt(struct phy_device *phydev)
{
	phy_write_mmd(phydev, FSL_XFI_PMD, FSL_XFI_PMD_CTRL, PMD_RESET);
	phy_write_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_PMD_CTRL, TRAIN_DISABLE);
	phy_write_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_LD_CU, 0);
	phy_write_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_LD_STATUS, 0);
	phy_write_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_PMD_STATUS, 0);
	phy_write_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_LP_CU, 0);
	phy_write_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_LP_STATUS, 0);
}

static void start_an(struct phy_device *phydev)
{
	reset_lt(phydev);
	phy_write_mmd(phydev, FSL_XFI_AN, FSL_XFI_AN_AD_1, XFI_AN_AD1);
	phy_write_mmd(phydev, FSL_XFI_AN, FSL_XFI_AN_CTRL, XF_AN_RESTART);
}

static void ld_coe_status(struct fsl_xgkr_inst *inst)
{
	phy_write_mmd(inst->phydev, FSL_XFI_PMD,
		      FSL_XFI_KR_LD_STATUS, inst->ld_status);
}

static void ld_coe_update(struct fsl_xgkr_inst *inst)
{
	phy_write_mmd(inst->phydev, FSL_XFI_PMD,
		      FSL_XFI_KR_LD_CU, inst->ld_update);
}

static void init_inst(struct fsl_xgkr_inst *inst, int reset)
{
	if (reset) {
		inst->ratio_preq = RATIO_PREQ;
		inst->ratio_pst1q = RATIO_PST1Q;
		inst->adpt_eq = RATIO_EQ;
		tune_tecr0(inst);
	}

	inst->ld_status &= RX_READY_MASK;
	ld_coe_status(inst);

	/* init state machine */
	init_state_machine(&inst->t_s_m);

	inst->ld_update = 0;
	ld_coe_update(inst);

	inst->ld_status &= ~RX_READY_MASK;
	ld_coe_status(inst);
}

#ifdef	NEW_ALGORITHM_TRAIN_TX
static int get_median_gaink2(u32 *reg)
{
	int gaink2_snap_shot[BIN_SNAPSHOT_NUM];
	u32 rx_eq_snp;
	struct per_lane_ctrl_status *reg_base;
	int timeout;
	int i, j, tmp, pos;

	reg_base = (struct per_lane_ctrl_status *)reg;

	for (i = 0; i < BIN_SNAPSHOT_NUM; i++) {
		/* wait RECR1_CTL_SNP_DONE_MASK has cleared */
		timeout = 100;
		while (ioread32be(&reg_base->recr1) &
		       RECR1_CTL_SNP_DONE_MASK) {
			udelay(1);
			timeout--;
			if (timeout == 0)
				break;
		}

		/* start snap shot */
		iowrite32be((ioread32be(&reg_base->gcr1) |
			    GCR1_CTL_SNP_START_MASK),
			    &reg_base->gcr1);

		/* wait for SNP done */
		timeout = 100;
		while (!(ioread32be(&reg_base->recr1) &
		       RECR1_CTL_SNP_DONE_MASK)) {
			udelay(1);
			timeout--;
			if (timeout == 0)
				break;
		}

		/* read and save the snap shot */
		rx_eq_snp = ioread32be(&reg_base->recr1);
		gaink2_snap_shot[i] = (rx_eq_snp & RECR1_GAINK2_MASK) >>
					RECR1_GAINK2_SHIFT;

		/* terminate the snap shot by setting GCR1[REQ_CTL_SNP] */
		iowrite32be((ioread32be(&reg_base->gcr1) &
			    ~GCR1_CTL_SNP_START_MASK),
			    &reg_base->gcr1);
	}

	/* get median of the 5 snap shot */
	for (i = 0; i < BIN_SNAPSHOT_NUM - 1; i++) {
		tmp = gaink2_snap_shot[i];
		pos = i;
		for (j = i + 1; j < BIN_SNAPSHOT_NUM; j++) {
			if (gaink2_snap_shot[j] < tmp) {
				tmp = gaink2_snap_shot[j];
				pos = j;
			}
		}

		gaink2_snap_shot[pos] = gaink2_snap_shot[i];
		gaink2_snap_shot[i] = tmp;
	}

	return gaink2_snap_shot[2];
}
#endif

static bool is_bin_early(int bin_sel, void __iomem *reg)
{
	bool early = false;
	int bin_snap_shot[BIN_SNAPSHOT_NUM];
	int i, negative_count = 0;
	struct per_lane_ctrl_status *reg_base;
	int timeout;

	reg_base = (struct per_lane_ctrl_status *)reg;

	for (i = 0; i < BIN_SNAPSHOT_NUM; i++) {
		/* wait RECR1_SNP_DONE_MASK has cleared */
		timeout = 100;
		while ((ioread32be(&reg_base->recr1) & RECR1_SNP_DONE_MASK)) {
				udelay(1);
				timeout--;
				if (timeout == 0)
					break;
		}

		/* set TCSR1[CDR_SEL] to BinM1/BinLong */
		if (bin_sel == BIN_M1) {
			iowrite32be((ioread32be(&reg_base->tcsr1) &
				     ~CDR_SEL_MASK) | BIN_M1_SEL,
				     &reg_base->tcsr1);
		} else {
			iowrite32be((ioread32be(&reg_base->tcsr1) &
				     ~CDR_SEL_MASK) | BIN_Long_SEL,
				     &reg_base->tcsr1);
		}

		/* start snap shot */
		iowrite32be(ioread32be(&reg_base->gcr1) | GCR1_SNP_START_MASK,
			    &reg_base->gcr1);

		/* wait for SNP done */
		timeout = 100;
		while (!(ioread32be(&reg_base->recr1) & RECR1_SNP_DONE_MASK)) {
				udelay(1);
				timeout--;
				if (timeout == 0)
					break;
		}

		/* read and save the snap shot */
		bin_snap_shot[i] = (ioread32be(&reg_base->tcsr1) &
				   TCSR1_SNP_DATA_MASK) >> TCSR1_SNP_DATA_SHIFT;
		if (bin_snap_shot[i] & TCSR1_EQ_SNPBIN_SIGN_MASK)
			negative_count++;

		/* terminate the snap shot by setting GCR1[REQ_CTL_SNP] */
		iowrite32be(ioread32be(&reg_base->gcr1) & ~GCR1_SNP_START_MASK,
			    &reg_base->gcr1);
	}

	if (((bin_sel == BIN_M1) && negative_count > BIN_M1_THRESHOLD) ||
	    ((bin_sel == BIN_LONG && negative_count > BIN_LONG_THRESHOLD))) {
		early = true;
	}

	return early;
}

static void train_tx(struct fsl_xgkr_inst *inst)
{
	struct phy_device *phydev = inst->phydev;
	struct training_state_machine *s_m = &inst->t_s_m;
	bool bin_m1_early, bin_long_early;
	u32 lp_status, old_ld_update;
	u32 status_cop1, status_coz, status_com1;
	u32 req_cop1, req_coz, req_com1, req_preset, req_init;
	u32 temp;
#ifdef	NEW_ALGORITHM_TRAIN_TX
	u32 median_gaink2;
#endif

recheck:
	if (s_m->bin_long_stop && s_m->bin_m1_stop) {
		s_m->tx_complete = true;
		inst->ld_status |= RX_READY_MASK;
		ld_coe_status(inst);
		/* tell LP we are ready */
		phy_write_mmd(phydev, FSL_XFI_PMD,
			      FSL_XFI_KR_PMD_STATUS, RX_STAT);
		return;
	}

	/* We start by checking the current LP status. If we got any responses,
	 * we can clear up the appropriate update request so that the
	 * subsequent code may easily issue new update requests if needed.
	 */
	lp_status = phy_read_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_LP_STATUS) &
				 REQUEST_MASK;
	status_cop1 = (lp_status & COP1_MASK) >> COP1_SHIFT;
	status_coz = (lp_status & COZ_MASK) >> COZ_SHIFT;
	status_com1 = (lp_status & COM1_MASK) >> COM1_SHIFT;

	old_ld_update = inst->ld_update;
	req_cop1 = (old_ld_update & COP1_MASK) >> COP1_SHIFT;
	req_coz = (old_ld_update & COZ_MASK) >> COZ_SHIFT;
	req_com1 = (old_ld_update & COM1_MASK) >> COM1_SHIFT;
	req_preset = old_ld_update & PRESET_MASK;
	req_init = old_ld_update & INIT_MASK;

	/* IEEE802.3-2008, 72.6.10.2.3.1
	 * We may clear PRESET when all coefficients show UPDATED or MAX.
	 */
	if (req_preset) {
		if ((status_cop1 == COE_UPDATED || status_cop1 == COE_MAX) &&
		    (status_coz == COE_UPDATED || status_coz == COE_MAX) &&
		    (status_com1 == COE_UPDATED || status_com1 == COE_MAX)) {
			inst->ld_update &= ~PRESET_MASK;
		}
	}

	/* IEEE802.3-2008, 72.6.10.2.3.2
	 * We may clear INITIALIZE when no coefficients show NOT UPDATED.
	 */
	if (req_init) {
		if (status_cop1 != COE_NOTUPDATED &&
		    status_coz != COE_NOTUPDATED &&
		    status_com1 != COE_NOTUPDATED) {
			inst->ld_update &= ~INIT_MASK;
		}
	}

	/* IEEE802.3-2008, 72.6.10.2.3.2
	 * we send initialize to the other side to ensure default settings
	 * for the LP. Naturally, we should do this only once.
	 */
	if (!s_m->sent_init) {
		if (!lp_status && !(old_ld_update & (LD_ALL_MASK))) {
			inst->ld_update |= INIT_MASK;
			s_m->sent_init = true;
		}
	}

	/* IEEE802.3-2008, 72.6.10.2.3.3
	 * We set coefficient requests to HOLD when we get the information
	 * about any updates On clearing our prior response, we also update
	 * our internal status.
	 */
	if (status_cop1 != COE_NOTUPDATED) {
		if (req_cop1) {
			inst->ld_update &= ~COP1_MASK;
#ifdef	NEW_ALGORITHM_TRAIN_TX
			if (s_m->post_inc) {
				if (req_cop1 == INCREMENT &&
				    status_cop1 == COE_MAX) {
					s_m->post_inc = 0;
					s_m->bin_long_stop = true;
					s_m->bin_m1_stop = true;
				} else {
					s_m->post_inc -= 1;
				}

				ld_coe_update(inst);
				goto recheck;
			}
#endif
			if ((req_cop1 == DECREMENT && status_cop1 == COE_MIN) ||
			    (req_cop1 == INCREMENT && status_cop1 == COE_MAX)) {
				s_m->long_min_max_cnt++;
				if (s_m->long_min_max_cnt >= TIMEOUT_LONG) {
					s_m->bin_long_stop = true;
					ld_coe_update(inst);
					goto recheck;
				}
			}
		}
	}

	if (status_coz != COE_NOTUPDATED) {
		if (req_coz)
			inst->ld_update &= ~COZ_MASK;
	}

	if (status_com1 != COE_NOTUPDATED) {
		if (req_com1) {
			inst->ld_update &= ~COM1_MASK;
#ifdef	NEW_ALGORITHM_TRAIN_TX
			if (s_m->pre_inc) {
				if (req_com1 == INCREMENT &&
				    status_com1 == COE_MAX)
					s_m->pre_inc = 0;
				else
					s_m->pre_inc -= 1;

				ld_coe_update(inst);
				goto recheck;
			}
#endif
			/* Stop If we have reached the limit for a parameter. */
			if ((req_com1 == DECREMENT && status_com1 == COE_MIN) ||
			    (req_com1 == INCREMENT && status_com1 == COE_MAX)) {
				s_m->m1_min_max_cnt++;
				if (s_m->m1_min_max_cnt >= TIMEOUT_M1) {
					s_m->bin_m1_stop = true;
					ld_coe_update(inst);
					goto recheck;
				}
			}
		}
	}

	if (old_ld_update != inst->ld_update) {
		ld_coe_update(inst);
		/* Redo these status checks and updates until we have no more
		 * changes, to speed up the overall process.
		 */
		goto recheck;
	}

	/* Do nothing if we have pending request. */
	if ((req_coz || req_com1 || req_cop1))
		return;
	else if (lp_status)
		/* No pending request but LP status was not reverted to
		 * not updated.
		 */
		return;

#ifdef	NEW_ALGORITHM_TRAIN_TX
	if (!(inst->ld_update & (PRESET_MASK | INIT_MASK))) {
		if (s_m->pre_inc) {
			inst->ld_update = INCREMENT << COM1_SHIFT;
			ld_coe_update(inst);
			return;
		}

		if (status_cop1 != COE_MAX) {
			median_gaink2 = get_median_gaink2(inst->reg_base);
			if (median_gaink2 == 0xf) {
				s_m->post_inc = 1;
			} else {
				/* Gaink2 median lower than "F" */
				s_m->bin_m1_stop = true;
				s_m->bin_long_stop = true;
				goto recheck;
			}
		} else {
			/* C1 MAX */
			s_m->bin_m1_stop = true;
			s_m->bin_long_stop = true;
			goto recheck;
		}

		if (s_m->post_inc) {
			inst->ld_update = INCREMENT << COP1_SHIFT;
			ld_coe_update(inst);
			return;
		}
	}
#endif

	/* snapshot and select bin */
	bin_m1_early = is_bin_early(BIN_M1, inst->reg_base);
	bin_long_early = is_bin_early(BIN_LONG, inst->reg_base);

	if (!s_m->bin_m1_stop && !s_m->bin_m1_late_early && bin_m1_early) {
		s_m->bin_m1_stop = true;
		goto recheck;
	}

	if (!s_m->bin_long_stop &&
	    s_m->bin_long_late_early && !bin_long_early) {
		s_m->bin_long_stop = true;
		goto recheck;
	}

	/* IEEE802.3-2008, 72.6.10.2.3.3
	 * We only request coefficient updates when no PRESET/INITIALIZE is
	 * pending! We also only request coefficient updates when the
	 * corresponding status is NOT UPDATED and nothing is pending.
	 */
	if (!(inst->ld_update & (PRESET_MASK | INIT_MASK))) {
		if (!s_m->bin_long_stop) {
			/* BinM1 correction means changing COM1 */
			if (!status_com1 && !(inst->ld_update & COM1_MASK)) {
				/* Avoid BinM1Late by requesting an
				 * immediate decrement.
				 */
				if (!bin_m1_early) {
					/* request decrement c(-1) */
					temp = DECREMENT << COM1_SHIFT;
					inst->ld_update |= temp;
					ld_coe_update(inst);
					s_m->bin_m1_late_early = bin_m1_early;
					return;
				}
			}

			/* BinLong correction means changing COP1 */
			if (!status_cop1 && !(inst->ld_update & COP1_MASK)) {
				/* Locate BinLong transition point (if any)
				 * while avoiding BinM1Late.
				 */
				if (bin_long_early) {
					/* request increment c(1) */
					temp = INCREMENT << COP1_SHIFT;
					inst->ld_update |= temp;
				} else {
					/* request decrement c(1) */
					temp = DECREMENT << COP1_SHIFT;
					inst->ld_update |= temp;
				}

				ld_coe_update(inst);
				s_m->bin_long_late_early = bin_long_early;
			}
			/* We try to finish BinLong before we do BinM1 */
			return;
		}

		if (!s_m->bin_m1_stop) {
			/* BinM1 correction means changing COM1 */
			if (!status_com1 && !(inst->ld_update & COM1_MASK)) {
				/* Locate BinM1 transition point (if any) */
				if (bin_m1_early) {
					/* request increment c(-1) */
					temp = INCREMENT << COM1_SHIFT;
					inst->ld_update |= temp;
				} else {
					/* request decrement c(-1) */
					temp = DECREMENT << COM1_SHIFT;
					inst->ld_update |= temp;
				}

				ld_coe_update(inst);
				s_m->bin_m1_late_early = bin_m1_early;
			}
		}
	}
}

static int check_an_link(struct phy_device *phydev)
{
	int val;
	int timeout = 100;

	while (timeout--) {
		val = phy_read_mmd(phydev, FSL_XFI_AN, FSL_XFI_LNK_STATUS);
		if (val & XFI_AN_LNK_STAT_UP)
			return 1;
		usleep_range(100, 500);
	}

	return 0;
}

static int is_link_training_fail(struct phy_device *phydev)
{
	int val;

	val = phy_read_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_PMD_STATUS);
	if (!(val & TRAIN_FAIL) && (val & RX_STAT)) {
		/* check LNK_STAT for sure */
		if (check_an_link(phydev))
			return 0;
		return 1;
	}
	return 1;
}

static int check_rx(struct phy_device *phydev)
{
	return phy_read_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_LP_STATUS) &
			    RX_READY_MASK;
}

/* Coefficient values have hardware restrictions */
static int is_ld_valid(u32 *ld_coe)
{
	u32 ratio_pst1q = *ld_coe;
	u32 adpt_eq = *(ld_coe + 1);
	u32 ratio_preq = *(ld_coe + 2);

	if ((ratio_pst1q + adpt_eq + ratio_preq) > 48)
		return 0;

	if (((ratio_pst1q + adpt_eq + ratio_preq) * 4) >=
	    ((adpt_eq - ratio_pst1q - ratio_preq) * 17))
		return 0;

	if (ratio_preq > ratio_pst1q)
		return 0;

	if (ratio_preq > 8)
		return 0;

	if (adpt_eq < 26)
		return 0;

	if (ratio_pst1q > 16)
		return 0;

	return 1;
}

#define VAL_INVALID 0xff

static const u32 preq_table[] = {0x0, 0x1, 0x3, 0x5,
				 0x7, 0x9, 0xb, 0xc, VAL_INVALID};
static const u32 pst1q_table[] = {0x0, 0x1, 0x3, 0x5,
				  0x7, 0x9, 0xb, 0xd, 0xf, 0x10, VAL_INVALID};

static int is_value_allowed(const u32 *val_table, u32 val)
{
	int i;

	for (i = 0;; i++) {
		if (*(val_table + i) == VAL_INVALID)
			return 0;
		if (*(val_table + i) == val)
			return 1;
	}
}

static int inc_dec(struct fsl_xgkr_inst *inst, int field, int request)
{
	u32 ld_limit[3], ld_coe[3], step[3];

	ld_coe[0] = inst->ratio_pst1q;
	ld_coe[1] = inst->adpt_eq;
	ld_coe[2] = inst->ratio_preq;

	/* Information specific to the Freescale SerDes for 10GBase-KR:
	 * Incrementing C(+1) means *decrementing* RATIO_PST1Q
	 * Incrementing C(0) means incrementing ADPT_EQ
	 * Incrementing C(-1) means *decrementing* RATIO_PREQ
	 */
	step[0] = -1;
	step[1] = 1;
	step[2] = -1;

	switch (request) {
	case INCREMENT:
		ld_limit[0] = POST_COE_MAX;
		ld_limit[1] = ZERO_COE_MAX;
		ld_limit[2] = PRE_COE_MAX;
		if (ld_coe[field] != ld_limit[field])
			ld_coe[field] += step[field];
		else
			/* MAX */
			return 2;
		break;
	case DECREMENT:
		ld_limit[0] = POST_COE_MIN;
		ld_limit[1] = ZERO_COE_MIN;
		ld_limit[2] = PRE_COE_MIN;
		if (ld_coe[field] != ld_limit[field])
			ld_coe[field] -= step[field];
		else
			/* MIN */
			return 1;
		break;
	default:
		break;
	}

	if (is_ld_valid(ld_coe)) {
		/* accept new ld */
		inst->ratio_pst1q = ld_coe[0];
		inst->adpt_eq = ld_coe[1];
		inst->ratio_preq = ld_coe[2];
		/* only some values for preq and pst1q can be used.
		 * for preq: 0x0, 0x1, 0x3, 0x5, 0x7, 0x9, 0xb, 0xc.
		 * for pst1q: 0x0, 0x1, 0x3, 0x5, 0x7, 0x9, 0xb, 0xd, 0xf, 0x10.
		 */
		if (!is_value_allowed((const u32 *)&preq_table, ld_coe[2])) {
			dev_dbg(&inst->phydev->dev,
				"preq skipped value: %d.\n", ld_coe[2]);
			return 0;
		}

		if (!is_value_allowed((const u32 *)&pst1q_table, ld_coe[0])) {
			dev_dbg(&inst->phydev->dev,
				"pst1q skipped value: %d.\n", ld_coe[0]);
			return 0;
		}

		tune_tecr0(inst);
	} else {
		if (request == DECREMENT)
			/* MIN */
			return 1;
		if (request == INCREMENT)
			/* MAX */
			return 2;
	}

	return 0;
}

static void min_max_updated(struct fsl_xgkr_inst *inst, int field, int new_ld)
{
	u32 ld_coe[] = {COE_UPDATED, COE_MIN, COE_MAX};
	u32 mask, val;

	switch (field) {
	case COE_COP1:
		mask = COP1_MASK;
		val = ld_coe[new_ld] << COP1_SHIFT;
		break;
	case COE_COZ:
		mask = COZ_MASK;
		val = ld_coe[new_ld] << COZ_SHIFT;
		break;
	case COE_COM:
		mask = COM1_MASK;
		val = ld_coe[new_ld] << COM1_SHIFT;
		break;
	default:
		return;
		break;
	}

	inst->ld_status &= ~mask;
	inst->ld_status |= val;
}

static void check_request(struct fsl_xgkr_inst *inst, int request)
{
	int cop1_req, coz_req, com_req;
	int old_status, new_ld_sta;

	cop1_req = (request & COP1_MASK) >> COP1_SHIFT;
	coz_req = (request & COZ_MASK) >> COZ_SHIFT;
	com_req = (request & COM1_MASK) >> COM1_SHIFT;

	/* IEEE802.3-2008, 72.6.10.2.5
	 * Ensure we only act on INCREMENT/DECREMENT when we are in NOT UPDATED!
	 */
	old_status = inst->ld_status;

	if (cop1_req && !(inst->ld_status & COP1_MASK)) {
		new_ld_sta = inc_dec(inst, COE_COP1, cop1_req);
		min_max_updated(inst, COE_COP1, new_ld_sta);
	}

	if (coz_req && !(inst->ld_status & COZ_MASK)) {
		new_ld_sta = inc_dec(inst, COE_COZ, coz_req);
		min_max_updated(inst, COE_COZ, new_ld_sta);
	}

	if (com_req && !(inst->ld_status & COM1_MASK)) {
		new_ld_sta = inc_dec(inst, COE_COM, com_req);
		min_max_updated(inst, COE_COM, new_ld_sta);
	}

	if (old_status != inst->ld_status)
		ld_coe_status(inst);

}

static void preset(struct fsl_xgkr_inst *inst)
{
	/* These are all MAX values from the IEEE802.3 perspective! */
	inst->ratio_pst1q = POST_COE_MAX;
	inst->adpt_eq = ZERO_COE_MAX;
	inst->ratio_preq = PRE_COE_MAX;

	tune_tecr0(inst);
	inst->ld_status &= ~(COP1_MASK | COZ_MASK | COM1_MASK);
	inst->ld_status |= COE_MAX << COP1_SHIFT |
			   COE_MAX << COZ_SHIFT |
			   COE_MAX << COM1_SHIFT;
	ld_coe_status(inst);
}

static void initialize(struct fsl_xgkr_inst *inst)
{
	inst->ratio_preq = RATIO_PREQ;
	inst->ratio_pst1q = RATIO_PST1Q;
	inst->adpt_eq = RATIO_EQ;

	tune_tecr0(inst);
	inst->ld_status &= ~(COP1_MASK | COZ_MASK | COM1_MASK);
	inst->ld_status |= COE_UPDATED << COP1_SHIFT |
			   COE_UPDATED << COZ_SHIFT |
			   COE_UPDATED << COM1_SHIFT;
	ld_coe_status(inst);
}

static void train_rx(struct fsl_xgkr_inst *inst)
{
	struct phy_device *phydev = inst->phydev;
	int request, old_ld_status;

	/* get request from LP */
	request = phy_read_mmd(phydev, FSL_XFI_PMD, FSL_XFI_KR_LP_CU) &
			      (LD_ALL_MASK);
	old_ld_status = inst->ld_status;

	/* IEEE802.3-2008, 72.6.10.2.5
	 * Ensure we always go to NOT UDPATED for status reporting in
	 * response to HOLD requests.
	 * IEEE802.3-2008, 72.6.10.2.3.1/2
	 * ... but only if PRESET/INITIALIZE are not active to ensure
	 * we keep status until they are released!
	 */
	if (!(request & (PRESET_MASK | INIT_MASK))) {
		if (!(request & COP1_MASK))
			inst->ld_status &= ~COP1_MASK;

		if (!(request & COZ_MASK))
			inst->ld_status &= ~COZ_MASK;

		if (!(request & COM1_MASK))
			inst->ld_status &= ~COM1_MASK;

		if (old_ld_status != inst->ld_status)
			ld_coe_status(inst);

	}

	/* As soon as the LP shows ready, no need to do any more updates. */
	if (check_rx(phydev)) {
		/* LP receiver is ready */
		if (inst->ld_status & (COP1_MASK | COZ_MASK | COM1_MASK)) {
			inst->ld_status &= ~(COP1_MASK | COZ_MASK | COM1_MASK);
			ld_coe_status(inst);
		}
	} else {
		/* IEEE802.3-2008, 72.6.10.2.3.1/2
		 * only act on PRESET/INITIALIZE if all status is NOT UPDATED.
		 */
		if (request & (PRESET_MASK | INIT_MASK)) {
			if (!(inst->ld_status &
			      (COP1_MASK | COZ_MASK | COM1_MASK))) {
				if (request & PRESET_MASK)
					preset(inst);

				if (request & INIT_MASK)
					initialize(inst);
			}
		}

		/* LP Coefficient are not in HOLD */
		if (request & REQUEST_MASK)
			check_request(inst, request & REQUEST_MASK);
	}
}

static void xgkr_wq_state_machine(struct work_struct *work)
{
	struct fsl_xgkr_wk *wk = container_of(work,
				struct fsl_xgkr_wk, xgkr_wk);
	struct fsl_xgkr_inst *inst = wk->xgkr_inst;
	struct training_state_machine *s_m = &inst->t_s_m;
	struct phy_device *phydev = inst->phydev;
	int val = 0, i;
	int an_state, lt_state;
	unsigned long dead_line;
	int rx_ok, tx_ok;

	if (s_m->link_up) {
		/* check abnormal link down events when link is up, for ex.
		 * the cable is pulled out or link partner is down.
		 */
		an_state = phy_read_mmd(phydev, FSL_XFI_AN, FSL_XFI_LNK_STATUS);
		if (!(an_state & XFI_AN_LNK_STAT_UP)) {
			dev_info(&phydev->dev,
				 "Detect hotplug, restart training!\n");
			init_inst(inst, 1);
			start_an(phydev);
		}
		s_m->running = false;
		return;
	}

	if (!s_m->an_ok) {
		an_state = phy_read_mmd(phydev, FSL_XFI_AN, FSL_XFI_BP_STATUS);
		if (!(an_state & AN_10GKR_MASK)) {
			s_m->running = false;
			return;
		} else
			s_m->an_ok = true;
	}

	dev_info(&phydev->dev, "is training.\n");

	start_lt(phydev);
	for (i = 0; i < 2;) {
		/* i < 1 also works, but start one more try immediately when
		 * failed can adjust our training frequency to match other
		 * devices. This can help the link being established more
		 * quickly.
		 */
		dead_line = jiffies + msecs_to_jiffies(500);
		while (time_before(jiffies, dead_line)) {
			val = phy_read_mmd(phydev, FSL_XFI_PMD,
					FSL_XFI_KR_PMD_STATUS);
			if (val & TRAIN_FAIL) {
				/* LT failed already, reset lane to avoid
				 * it run into hanging, then start LT again.
				 */
				reset_gcr0(inst);
				start_lt(phydev);
			} else if (val & PMD_STATUS_SUP_STAT &&
					val & PMD_STATUS_FRAME_LOCK)
				break;
			usleep_range(100, 500);
		}

		if (!(val & PMD_STATUS_FRAME_LOCK &&
		      val & PMD_STATUS_SUP_STAT)) {
			i++;
			continue;
		}

		/* init process */
		rx_ok = tx_ok = false;
		/* the LT should be finished in 500ms, failed or OK. */
		dead_line = jiffies + msecs_to_jiffies(500);

		while (time_before(jiffies, dead_line)) {
			/* check if the LT is already failed */
			lt_state = phy_read_mmd(phydev, FSL_XFI_PMD,
						FSL_XFI_KR_PMD_STATUS);
			if (lt_state & TRAIN_FAIL) {
				reset_gcr0(inst);
				break;
			}

			rx_ok = check_rx(phydev);
			tx_ok = s_m->tx_complete;

			if (rx_ok && tx_ok)
				break;

			if (!rx_ok)
				train_rx(inst);

			if (!tx_ok)
				train_tx(inst);
			usleep_range(100, 500);
		}

		i++;
		/* check LT result */
		if (is_link_training_fail(phydev)) {
			/* reset state machine */
			init_inst(inst, 0);
			continue;
		} else {
			stop_lt(phydev);
			s_m->running = false;
			s_m->link_up = true;
			dev_info(&phydev->dev, "LT training is SUCCEEDED!\n");
			break;
		}
	}

	if (!s_m->link_up) {
		/* reset state machine */
		init_inst(inst, 0);
	}
}

static void xgkr_timer_handle(unsigned long arg)
{
	struct list_head *pos;
	struct fsl_xgkr_wk *wk;
	struct fsl_xgkr_inst *xgkr_inst;
	struct phy_device *phydev;
	struct training_state_machine *s_m;

	list_for_each(pos, &fsl_xgkr_list) {
		wk = list_entry(pos, struct fsl_xgkr_wk, xgkr_list);
		xgkr_inst = wk->xgkr_inst;
		phydev = xgkr_inst->phydev;
		s_m = &xgkr_inst->t_s_m;

		if (!s_m->running && (!s_m->an_ok || s_m->link_up)) {
			s_m->running = true;
			queue_work(xgkr_wq, (struct work_struct *)wk);
		}
	}

	if (!list_empty(&fsl_xgkr_list))
		mod_timer(&xgkr_timer,
			  jiffies + msecs_to_jiffies(XGKR_TIMEOUT));
}

static int fsl_xgkr_bind_serdes(const char *lane_name,
				struct phy_device *phydev)
{
	unsigned long serdes_base;
	unsigned long lane_base;
	int i;

	for (i = 0; i < SERDES_MAX; i++) {
		if (strstr(lane_name, s_map[i].serdes_name)) {
			serdes_base = s_map[i].serdes_base;
			break;
		}
	}

	if (i == SERDES_MAX)
		goto serdes_err;

	for (i = 0; i < LANE_MAX; i++) {
		if (strstr(lane_name, l_map[i].lane_name)) {
			lane_base = l_map[i].lane_base;
			break;
		}
	}

	if (i == LANE_MAX)
		goto lane_err;

	phydev->priv = ioremap(serdes_base + lane_base,
			       sizeof(struct per_lane_ctrl_status));
	if (!phydev->priv)
		return -ENOMEM;

	return 0;

serdes_err:
		dev_err(&phydev->dev, "Unknown SerDes name");
		return -EINVAL;
lane_err:
		dev_err(&phydev->dev, "Unknown Lane name");
		return -EINVAL;
}

static int fsl_xgkr_probe(struct phy_device *phydev)
{
	struct fsl_xgkr_inst *xgkr_inst;
	struct fsl_xgkr_wk *xgkr_wk;
	struct device_node *child;
	const char *lane_name;
	int len;

	child = phydev->dev.of_node;

	/* if there is lane-instance property, 10G-KR need to run */
	lane_name = of_get_property(child, "lane-instance", &len);
	if (!lane_name || (fsl_xgkr_bind_serdes(lane_name, phydev)))
		return 0;

	xgkr_inst = kzalloc(sizeof(struct fsl_xgkr_inst), GFP_KERNEL);
	if (!xgkr_inst)
		goto mem_err1;

	xgkr_inst->reg_base = phydev->priv;

	xgkr_inst->bus = phydev->bus;

	xgkr_inst->phydev = phydev;

	init_inst(xgkr_inst, 1);

	xgkr_wk = kzalloc(sizeof(struct fsl_xgkr_wk), GFP_KERNEL);
	if (!xgkr_wk)
		goto mem_err2;

	xgkr_wk->xgkr_inst = xgkr_inst;
	phydev->priv = xgkr_wk;

	list_add(&xgkr_wk->xgkr_list, &fsl_xgkr_list);

	if (!fire_timer) {
		setup_timer(&xgkr_timer, xgkr_timer_handle,
			   (unsigned long)&fsl_xgkr_list);
		mod_timer(&xgkr_timer,
			   jiffies + msecs_to_jiffies(XGKR_TIMEOUT));
		fire_timer = 1;
		xgkr_wq = create_workqueue("fsl_xgkr");
	}
	INIT_WORK((struct work_struct *)xgkr_wk, xgkr_wq_state_machine);

	/* start auto-negotiation to detect link partner */
	start_an(phydev);

	return 0;
mem_err2:
	kfree(xgkr_inst);
mem_err1:
	dev_err(&phydev->dev, "failed to allocate memory!\n");
	return -ENOMEM;
}

static int fsl_xgkr_config_init(struct phy_device *phydev)
{
	return 0;
}

static int fsl_xgkr_config_aneg(struct phy_device *phydev)
{
	return 0;
}

static void fsl_xgkr_remove(struct phy_device *phydev)
{
	struct fsl_xgkr_wk *wk = (struct fsl_xgkr_wk *)phydev->priv;
	struct fsl_xgkr_inst *xgkr_inst = wk->xgkr_inst;
	struct list_head *this, *next;
	struct fsl_xgkr_wk *tmp;

	list_for_each_safe(this, next, &fsl_xgkr_list) {
		tmp = list_entry(this, struct fsl_xgkr_wk, xgkr_list);
		if (tmp == wk) {
			cancel_work_sync((struct work_struct *)wk);
			list_del(this);
		}
	}

	if (list_empty(&fsl_xgkr_list))
		del_timer(&xgkr_timer);

	if (xgkr_inst->reg_base)
		iounmap(xgkr_inst->reg_base);

	kfree(xgkr_inst);
	kfree(wk);
}

static int fsl_xgkr_read_status(struct phy_device *phydev)
{
	int val = phy_read_mmd(phydev, FSL_XFI_AN, FSL_XFI_LNK_STATUS);

	phydev->speed = SPEED_10000;
	phydev->duplex = 1;

	if (val & XFI_AN_LNK_STAT_UP)
		phydev->link = 1;
	else
		phydev->link = 0;

	return 0;
}

static int fsl_xgkr_match_phy_device(struct phy_device *phydev)
{
	return phydev->c45_ids.device_ids[3] == FSL_XFI_PCS_PHY_ID;
}

static int fsl_xgkr_match_phy_device2(struct phy_device *phydev)
{
	return phydev->c45_ids.device_ids[3] == FSL_XFI_PCS_PHY_ID2;
}

static struct phy_driver fsl_xgkr_driver[] = {
	{
	.phy_id		= FSL_XFI_PCS_PHY_ID,
	.name		= "Freescale 10G KR Rev1",
	.phy_id_mask	= 0xffffffff,
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.probe          = fsl_xgkr_probe,
	.config_init	= &fsl_xgkr_config_init,
	.config_aneg	= &fsl_xgkr_config_aneg,
	.read_status	= &fsl_xgkr_read_status,
	.match_phy_device = fsl_xgkr_match_phy_device,
	.remove		= fsl_xgkr_remove,
	.driver		= { .owner = THIS_MODULE,},
	},
	{
	.phy_id		= FSL_XFI_PCS_PHY_ID2,
	.name		= "Freescale 10G KR Rev2",
	.phy_id_mask	= 0xffffffff,
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.probe          = fsl_xgkr_probe,
	.config_init	= &fsl_xgkr_config_init,
	.config_aneg	= &fsl_xgkr_config_aneg,
	.read_status	= &fsl_xgkr_read_status,
	.match_phy_device = fsl_xgkr_match_phy_device2,
	.remove		= fsl_xgkr_remove,
	.driver		= { .owner = THIS_MODULE,},
	},
};

static int __init fsl_xgkr_init(void)
{
	return phy_drivers_register(fsl_xgkr_driver,
		ARRAY_SIZE(fsl_xgkr_driver));
}

static void __exit fsl_xgkr_exit(void)
{
	phy_drivers_unregister(fsl_xgkr_driver,
		ARRAY_SIZE(fsl_xgkr_driver));
}

module_init(fsl_xgkr_init);
module_exit(fsl_xgkr_exit);

static struct mdio_device_id __maybe_unused freescale_tbl[] = {
	{ FSL_XFI_PCS_PHY_ID, 0xffffffff },
	{ FSL_XFI_PCS_PHY_ID2, 0xffffffff },
	{ }
};

MODULE_DEVICE_TABLE(mdio, freescale_tbl);
