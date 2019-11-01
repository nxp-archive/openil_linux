// SPDX-License-Identifier: GPL-2.0+
/*
 * QorIQ FMAN Independent Mode Ethernet driver for NXP Layerscape
 *
 * Copyright 2018-2019 NXP
 *
 */
#include <linux/device.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/string.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_platform.h>
#include <linux/of_net.h>
#include <linux/of_irq.h>
#include <linux/ethtool.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/crc32.h>
#include <rtnet_port.h>
#include <rtdm/driver.h>
#include <linux/mii.h>
#include <linux/mdio.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "fman_im.h"
#include "memac.h"

#define RCTRL_INIT      (RCTRL_GRS | RCTRL_UPROM)
#define TCTRL_INIT      TCTRL_GTS
#define MACCFG1_INIT    MACCFG1_SOFT_RST
#define MACCFG2_INIT    (MACCFG2_PRE_LEN(0x7) | MACCFG2_LEN_CHECK | \
		MACCFG2_PAD_CRC | MACCFG2_FULL_DUPLEX | \
		MACCFG2_IF_MODE_NIBBLE)

/* MAXFRM - maximum frame length register */
#define MAXFRM_MASK      0x0000ffff
#define CONFIG_SYS_TBIPA_VALUE  8
#define JUMBO_FRAME_SIZE	9600

static phys_addr_t sys_ccsrbar, sys_fm1_offset;
static phys_addr_t sys_fm1_addr;

static u32 fm_assign_risc(int port_id)
{
	u32 risc_sel, val;

	risc_sel = (port_id & 0x1) ? FMFPPRC_RISC2 : FMFPPRC_RISC1;
	val = (port_id << FMFPPRC_PORTID_SHIFT) & FMFPPRC_PORTID_MASK;
	val |= ((risc_sel << FMFPPRC_ORA_SHIFT) | risc_sel);

	return val;
}

static void bmi_rx_port_init(struct fm_im_private *priv,
	struct fm_bmi_rx_port *rx_port)
{
	int port_id, val;

	/* Set BMI to independent mode, Rx port disable */
	fm_im_write(&rx_port->fmbm_rcfg, FMBM_RCFG_IM);
	/* Clear FOF in IM case */
	fm_im_write(&rx_port->fmbm_rim, 0);
	/* Rx frame next engine -RISC */
	fm_im_write(&rx_port->fmbm_rfne, NIA_ENG_RISC | NIA_RISC_AC_IM_RX);
	/* Rx command attribute - no order, MR[3] = 1 */
	fm_im_clrbits(&rx_port->fmbm_rfca, FMBM_RFCA_ORDER | FMBM_RFCA_MR_MASK);
	fm_im_setbits(&rx_port->fmbm_rfca, FMBM_RFCA_MR(4));
	/* Enable Rx statistic counters */
	fm_im_write(&rx_port->fmbm_rstc, FMBM_RSTC_EN);
	/* Disable Rx performance counters */
	fm_im_write(&rx_port->fmbm_rpc, 0);

	/* Common BMI parameter for this port */
	/*
	 * Set port parameters - FMBM_PP_x
	 * max tasks 10G Rx/Tx=12, 1G Rx/Tx 4, others is 1
	 * max dma 10G Rx/Tx=3, others is 1
	 * set port FIFO size - FMBM_PFS_x
	 * 4KB for all Rx and Tx ports
	 */
	/* Rx 1G port */
	port_id = RX_PORT_1G_BASE + priv->num - 1;
	/* Max tasks=4, max dma=1, no extra */
	fm_im_write(&priv->reg->fm_bmi_common.fmbm_pp[port_id], FMBM_PP_MXT(4));
	/* FIFO size - 3KB, no extra */
	fm_im_write(&priv->reg->fm_bmi_common.fmbm_pfs[port_id],
		    FMBM_PFS_IFSZ(0xf));

	val = fm_im_read(&priv->reg->fm_bmi_common.fmbm_pp[port_id]);
	val = fm_im_read(&priv->reg->fm_bmi_common.fmbm_pfs[port_id]);
	/* IM mode, each even port ID to RISC#1, each odd port ID to RISC#2 */

	/* Rx 1G port */
	val = fm_assign_risc(port_id + 1);
	fm_im_write(&priv->reg->fm_fpm.fpmprc, val);
}

static void bmi_tx_port_init(struct fm_im_private *priv,
	struct fm_bmi_tx_port *tx_port)
{
	int port_id, val;

	/* Set BMI to independent mode, Tx port disable */
	fm_im_write(&tx_port->fmbm_tcfg, FMBM_TCFG_IM);

	/* Tx frame next engine -RISC */
	fm_im_write(&tx_port->fmbm_tfne, NIA_ENG_RISC | NIA_RISC_AC_IM_TX);
	fm_im_write(&tx_port->fmbm_tfene, NIA_ENG_RISC | NIA_RISC_AC_IM_TX);

	/* Tx command attribute - no order, MR[3] = 1 */
	fm_im_clrbits(&tx_port->fmbm_tfca, FMBM_TFCA_ORDER | FMBM_TFCA_MR_MASK);
	fm_im_setbits(&tx_port->fmbm_tfca, FMBM_TFCA_MR(4));

	/* Enable Tx statistic counters */
	fm_im_write(&tx_port->fmbm_tstc, FMBM_TSTC_EN);

	/* Disable Tx performance counters */
	fm_im_write(&tx_port->fmbm_tpc, 0);

	/* Common BMI parameter for this port */
	/*
	 * set port parameters - FMBM_PP_x
	 * max tasks 10G Rx/Tx=12, 1G Rx/Tx 4, others is 1
	 * max dma 10G Rx/Tx=3, others is 1
	 * set port FIFO size - FMBM_PFS_x
	 * 4KB for all Rx and Tx ports
	 */
	/* Tx 1G port FIFO size - 4KB, no extra */
	port_id = TX_PORT_1G_BASE + priv->num - 1;

	/* Max tasks=4, max dma=1, no extra */
	fm_im_write(&priv->reg->fm_bmi_common.fmbm_pp[port_id], FMBM_PP_MXT(4));

	/* FIFO size - 4KB, no extra */
	fm_im_write(&priv->reg->fm_bmi_common.fmbm_pfs[port_id],
		    FMBM_PFS_IFSZ(0xf));

	val = fm_im_read(&priv->reg->fm_bmi_common.fmbm_pp[port_id]);
	val = fm_im_read(&priv->reg->fm_bmi_common.fmbm_pfs[port_id]);

	/* IM mode, each even port ID to RISC#1, each odd port ID to RISC#2 */
	/* Tx 1G port */
	val = fm_assign_risc(port_id + 1);
	fm_im_write(&priv->reg->fm_fpm.fpmprc, val);
}

struct fm_muram muram[CONFIG_SYS_NUM_FMAN];
static void fm_init_muram(int fm_idx, void *muram_base)
{
	muram[fm_idx].base = muram_base;
	muram[fm_idx].size = CONFIG_SYS_FM_MURAM_SIZE;
	muram[fm_idx].alloc = muram_base + FM_MURAM_RES_SIZE;
	muram[fm_idx].top = muram_base + CONFIG_SYS_FM_MURAM_SIZE;
}

void *fm_muram_base(int fm_idx)
{
	return muram[fm_idx].base;
}

void *fm_muram_alloc(int fm_idx, size_t size, u64 align)
{
	void *ret;
	u64 align_mask;
	size_t off;
	void *save;
	u32 *p;

	align_mask = align - 1;
	save = muram[fm_idx].alloc;

	off = (u64)save & align_mask;
	if (off != 0)
		muram[fm_idx].alloc += (align - off);
	off = size & align_mask;
	if (off != 0)
		size += (align - off);
	if ((muram[fm_idx].alloc + size) >= muram[fm_idx].top) {
		muram[fm_idx].alloc = save;
		pr_info("%s: Run out of ram.\n", __func__);
	}

	ret = muram[fm_idx].alloc;
	muram[fm_idx].alloc += size;
	/* memset((void *)ret, 0, size); */
	for (p = (u32 *)ret; p < (u32 *)ret + size; p++)
		*(u32 *)p = 0;

	return ret;
}

static u16 muram_readw(u16 *addr)
{
	u64 base = (u64)addr & ~0x3UL;
	u32 val32 = fm_im_read((void *)base);
	int byte_pos;
	u16 ret;

	byte_pos = (u64)addr & 0x3UL;
	if (byte_pos)
		ret = (u16)(val32 & 0x0000ffff);
	else
		ret = (u16)((val32 & 0xffff0000) >> 16);

	return ret;
}

static void muram_writew(u16 *addr, u16 val)
{
	u64 base = (u64)addr & ~0x3;
	u32 org32 = fm_im_read((void *)base);
	u32 val32;
	int byte_pos;

	byte_pos = (u64)addr & 0x3UL;
	if (byte_pos)
		val32 = (org32 & 0xffff0000) | val;
	else
		val32 = (org32 & 0x0000ffff) | ((u32)val << 16);

	fm_im_write((void *)base, val32);
}

/* De-active all the ports */
static void fman_de_active(struct ccsr_fman_t *reg)
{
	int i, port_id;
	struct fm_bmi_rx_port *port_rg;

	/* Rx 1G port */
	for (i = 0; i < MAX_NUM_RX_PORT_1G; i++) {
		port_id = RX_PORT_1G_BASE + i - 1;
		port_rg = (struct fm_bmi_rx_port *)&(reg->port[port_id].fm_bmi);
		fm_im_clrbits(&port_rg->fmbm_rcfg, FMBM_RCFG_EN);
	}

	/* Tx 1G port */
	for (i = 0; i < MAX_NUM_TX_PORT_1G; i++) {
		port_id = TX_PORT_1G_BASE + i - 1;
		port_rg = (struct fm_bmi_rx_port *)&(reg->port[port_id].fm_bmi);
		fm_im_clrbits(&port_rg->fmbm_rcfg, FMBM_RCFG_EN);
	}
}

/* Active return 1 */
static int fman_is_active(struct ccsr_fman_t *reg, int mac_idx)
{
	int port_id, val;
	struct fm_bmi_rx_port *port_reg;

	/* Rx 1G port */
	port_id = RX_PORT_1G_BASE + mac_idx - 1;
	port_reg = (struct fm_bmi_rx_port *)&(reg->port[port_id].fm_bmi);
	val = fm_im_read(&port_reg->fmbm_rcfg);
	if (val & FMBM_RCFG_EN) {
		pr_info("%s: port_id = %d, val = 0x%0x\n",
			__func__, port_id+1, val);
		return 1;
	}

	/* Tx 1G p rt */
	port_id = TX_PORT_1G_BASE + mac_idx - 1;
	port_reg = (struct fm_bmi_rx_port *)&(reg->port[port_id].fm_bmi);
	val = fm_im_read(&port_reg->fmbm_rcfg);
	if (val & FMBM_RCFG_EN) {
		pr_info("%s: port_id = %d, val = 0x%0x\n",
			__func__, port_id+1, val);
		return 1;
	}

	return 0;
}

static int fm_eth_rx_port_parameter_init(struct fm_im_private *priv,
	struct rtnet_device *dev)
{
	struct fm_port_global_pram *pram;
	u32 pram_page_offset;
	void *rx_bd_ring_base;
	struct fm_port_bd *rxbd;
	struct fm_port_qd *rxqd;
	struct fm_bmi_rx_port *bmi_rx_port = priv->rx_port;
	dma_addr_t buf;
	int i, j;
	int mac_idx = priv->num;
	u16 val;

	priv = rtnetdev_priv(dev);

	/* Alloc global parameter ram at MURAM */
	if (priv->tx_pram) {
		priv->rx_pram = priv->tx_pram;
		pram = priv->tx_pram;
	} else   {
		if (fman_is_active(priv->reg, mac_idx)) {
			pr_info("%s: Could not allocate muram when other BMI ports are active.\n",
				__func__);
			return 0;
		}
		pram = (struct fm_port_global_pram *)
			fm_muram_alloc(priv->fm_index,
					FM_PRAM_SIZE, FM_PRAM_ALIGN);
		priv->rx_pram = pram;
	}

	/* Parameter page offset to MURAM */
	pram_page_offset = (u64)pram - (u64)fm_muram_base(priv->fm_index);

	/* Init the Rx queue descriptor pionter */
	fm_im_write(&pram->rxqd_ptr, pram_page_offset + 0x20);

	/* Set the max receive buffer length, power of 2 */
	muram_writew(&pram->mrblr, MAX_RXBUF_LOG2);

	/* Alloc Rx buffer descriptors from main memory */
	rx_bd_ring_base = kzalloc(sizeof(struct fm_port_bd) * RX_BD_RING_SIZE,
					GFP_KERNEL);
	if (!rx_bd_ring_base)
		return 0;
	memset(rx_bd_ring_base, 0, sizeof(struct fm_port_bd) * RX_BD_RING_SIZE);

	/* Alloc Rx buffer from main memory */
	priv->rx_skbuff = rtdm_malloc(
				sizeof(*priv->rx_skbuff) * RX_BD_RING_SIZE);
	if (!priv->rx_skbuff) {
		pr_info("Could not allocate rx_skbuff\n");
		return 0;
	}

	for (j = 0; j < RX_BD_RING_SIZE; j++)
		priv->rx_skbuff[j] = NULL;

	/* Save them to priv */
	priv->rx_bd_ring = rx_bd_ring_base;
	priv->cur_rxbd = rx_bd_ring_base;
	priv->skb_currx = 0;

	/* Init Rx BDs ring */
	rxbd = (struct fm_port_bd *)rx_bd_ring_base;
	for (i = 0; i < RX_BD_RING_SIZE; i++) {
		struct rtskb *skb;

		skb = rtnetdev_alloc_rtskb(dev,
				priv->rx_buffer_size + RXBUF_ALIGNMENT);
		if (!skb) {
			pr_info("Can't allocate RX buffers\n");
			return 0;
		}
		rtskb_reserve(skb, RXBUF_ALIGNMENT -
			(((unsigned long) skb->data) & (RXBUF_ALIGNMENT - 1)));
		priv->rx_skbuff[i] = skb;

		buf = dma_map_single(priv->dev, skb->data,
				priv->rx_buffer_size, DMA_FROM_DEVICE);

		muram_writew(&rxbd->status, RxBD_EMPTY);
		muram_writew(&rxbd->len, 0);
		muram_writew(&rxbd->buf_ptr_hi, (buf >> 32) & 0xffff);
		fm_im_write(&rxbd->buf_ptr_lo, (u32)(buf & 0xffffffff));
		rxbd++;
	}

	/* Set the Rx queue descriptor */
	rxqd = &pram->rxqd;
	muram_writew(&rxqd->gen, RX_QD_RXF_INTMASK |
			RX_QD_BSY_INTMASK | priv->fpm_event_num);
	val = muram_readw(&rxqd->gen);
	buf = virt_to_phys(rx_bd_ring_base);
	muram_writew(&rxqd->bd_ring_base_hi, (buf >> 32) & 0xffff);
	fm_im_write(&rxqd->bd_ring_base_lo, (u32)(buf & 0xffffffff));
	muram_writew(&rxqd->bd_ring_size,
		sizeof(struct fm_port_bd) * RX_BD_RING_SIZE);
	muram_writew(&rxqd->offset_in, 0);
	muram_writew(&rxqd->offset_out, 0);

	/* Set IM parameter ram pointer to Rx Frame Queue ID */
	fm_im_write(&bmi_rx_port->fmbm_rfqid, pram_page_offset);

	return 1;
}

static int fm_eth_tx_port_parameter_init(struct fm_im_private *priv,
	struct rtnet_device *dev)
{
	struct fm_port_global_pram *pram;
	u32 pram_page_offset;
	void *tx_bd_ring_base;
	struct fm_port_bd *txbd;
	struct fm_port_qd *txqd;
	struct fm_bmi_tx_port *bmi_tx_port = priv->tx_port;
	dma_addr_t buf;
	int i;
	int mac_idx = priv->num;

	/* Alloc global parameter ram at MURAM */
	if (priv->rx_pram) {
		priv->tx_pram = priv->rx_pram;
		pram = priv->rx_pram;
	} else {
		if (fman_is_active(priv->reg, mac_idx)) {
			pr_info("%s: Could not allocate muram when other BMI ports are active.\n",
					__func__);
			return 0;
		}
		pram = (struct fm_port_global_pram *)
				fm_muram_alloc(priv->fm_index,
				FM_PRAM_SIZE, FM_PRAM_ALIGN);
		priv->tx_pram = pram;
	}

	/* Parameter page offset to MURAM */
	pram_page_offset = (u64)pram - (u64)fm_muram_base(priv->fm_index);

	/* Enable global mode- snooping data buffers and BDs */
	fm_im_write(&pram->mode, PRAM_MODE_GLOBAL);

	/* Init the Tx queue descriptor pionter */
	fm_im_write(&pram->txqd_ptr, pram_page_offset + 0x40);

	/* Alloc Tx buffer descriptors from main memory */
	tx_bd_ring_base = kzalloc(sizeof(struct fm_port_bd) * TX_BD_RING_SIZE,
				GFP_KERNEL);
	if (!tx_bd_ring_base)
		return 0;
	memset(tx_bd_ring_base, 0, sizeof(struct fm_port_bd) * TX_BD_RING_SIZE);
	/* Save it to priv */
	priv->tx_bd_ring = tx_bd_ring_base;
	priv->cur_txbd = tx_bd_ring_base;

	/* Init Tx BDs ring */
	txbd = (struct fm_port_bd *)tx_bd_ring_base;
	for (i = 0; i < TX_BD_RING_SIZE; i++) {
		muram_writew(&txbd->status, TxBD_LAST);
		muram_writew(&txbd->len, 0);
		muram_writew(&txbd->buf_ptr_hi, 0);
		fm_im_write(&txbd->buf_ptr_lo, 0);
		txbd++;
	}

	/* Alloc SKB free queue from main memory */
	priv->tx_skbuff = rtdm_malloc(
				sizeof(*priv->tx_skbuff) * TX_BD_RING_SIZE);
	if (!priv->tx_skbuff) {
		pr_info("Could not allocate tx_skbuff\n");
		return 0;
	}

	for (i = 0; i < TX_BD_RING_SIZE; i++)
		priv->tx_skbuff[i] = NULL;

	/* Set the Tx queue decriptor */
	txqd = &pram->txqd;
	buf = virt_to_phys(tx_bd_ring_base);
	muram_writew(&txqd->bd_ring_base_hi, (buf >> 32) & 0xff);
	fm_im_write(&txqd->bd_ring_base_lo, (u32)(buf & 0xffffffff));
	muram_writew(&txqd->bd_ring_size,
			sizeof(struct fm_port_bd) * TX_BD_RING_SIZE);
	muram_writew(&txqd->offset_in, 0);
	muram_writew(&txqd->offset_out, 0);

	/* Set IM parameter ram pointer to Tx Confirmation Frame Queue ID */
	fm_im_write(&bmi_tx_port->fmbm_tcfqid, pram_page_offset);

	return 1;
}

static int port_parameter_init(struct fm_im_private *priv,
	struct rtnet_device *dev)
{

	if (!fm_eth_rx_port_parameter_init(priv, dev))
		return 0;

	if (!fm_eth_tx_port_parameter_init(priv, dev))
		return 0;

	return 1;
}

static void memac_init_mac(struct fsl_enet_mac *mac)
{
	struct memac *regs = mac->base;

	/* Mask all interrupt */
	fm_im_write(&regs->imask, IMASK_MASK_ALL);

	/* Clear all events */
	fm_im_write(&regs->ievent, IEVENT_CLEAR_ALL);

	/* Set the max receive length */
	fm_im_write(&regs->maxfrm, mac->max_rx_len & MAXFRM_MASK);

	/* Multicast frame reception for the hash entry disable */
	fm_im_write(&regs->hashtable_ctrl, 0);
}

static void memac_enable_mac(struct fsl_enet_mac *mac)
{
	struct memac *regs = mac->base;

	fm_im_setbits(&regs->command_config,
			MEMAC_CMD_CFG_RXTX_EN | MEMAC_CMD_CFG_NO_LEN_CHK);
}

static void memac_disable_mac(struct fsl_enet_mac *mac)
{
	struct memac *regs = mac->base;

	fm_im_clrbits(&regs->command_config, MEMAC_CMD_CFG_RXTX_EN);
}

static void memac_set_mac_addr(struct fsl_enet_mac *mac, u8 *mac_addr)
{
	struct memac *regs = mac->base;
	u32 mac_addr0, mac_addr1;
	u32 val0, val1;

	mac_addr0 = (mac_addr[3] << 24) | (mac_addr[2] << 16) |
		    (mac_addr[1] << 8)  | (mac_addr[0]);
	fm_im_write(&regs->mac_addr_0, mac_addr0);

	mac_addr1 = ((mac_addr[5] << 8) | mac_addr[4]) & 0x0000ffff;
	fm_im_write(&regs->mac_addr_1, mac_addr1);
	val0 = fm_im_read(&regs->mac_addr_0);
	val1 = fm_im_read(&regs->mac_addr_1);
}

static void memac_set_interface_mode(struct fsl_enet_mac *mac,
	phy_interface_t type, int speed)
{
	struct memac *regs = mac->base;
	u32 if_mode, if_status;

	/* Clear all bits relative with interface mode */
	if_mode = fm_im_read(&regs->if_mode);
	if_status = fm_im_read(&regs->if_status);

	/* Set interface mode */
	switch (type) {
	case PHY_INTERFACE_MODE_GMII:
		if_mode &= ~IF_MODE_MASK;
		if_mode |= IF_MODE_GMII;
		break;
	case PHY_INTERFACE_MODE_RGMII:
		if_mode |= (IF_MODE_GMII | IF_MODE_RG);
		break;
	case PHY_INTERFACE_MODE_RGMII_TXID:
		if_mode |= (IF_MODE_GMII | IF_MODE_RG);
		break;
	case PHY_INTERFACE_MODE_RMII:
		if_mode |= (IF_MODE_GMII | IF_MODE_RM);
		break;
	case PHY_INTERFACE_MODE_SGMII:
		if_mode &= ~IF_MODE_MASK;
		if_mode |= (IF_MODE_GMII);
		break;
	case PHY_INTERFACE_MODE_XGMII:
		if_mode &= ~IF_MODE_MASK;
		if_mode |= IF_MODE_XGMII;
		break;
	default:
		break;
	}

	/* Enable automatic speed selection for Non-XGMII */
	if (type != PHY_INTERFACE_MODE_XGMII)
		if_mode |= IF_MODE_EN_AUTO;

	if ((type == PHY_INTERFACE_MODE_RGMII) ||
			(type == PHY_INTERFACE_MODE_RGMII_TXID)) {
		if_mode &= ~IF_MODE_EN_AUTO;
		if_mode &= ~IF_MODE_SETSP_MASK;
		switch (speed) {
		case SPEED_1000:
			if_mode |= IF_MODE_SETSP_1000M;
			break;
		case SPEED_100:
			if_mode |= IF_MODE_SETSP_100M;
			break;
		case SPEED_10:
			if_mode |= IF_MODE_SETSP_10M;
		default:
			break;
		}
	}

	fm_im_write(&regs->if_mode, if_mode);
}

void init_memac(struct fsl_enet_mac *mac, void *base,
	void *phyregs, int max_rx_len)
{
	mac->base = base;
	mac->phyregs = phyregs;
	mac->max_rx_len = max_rx_len;
	mac->init_mac = memac_init_mac;
	mac->enable_mac = memac_enable_mac;
	mac->disable_mac = memac_disable_mac;
	mac->set_mac_addr = memac_set_mac_addr;
	mac->set_if_mode = memac_set_interface_mode;
}

static int fm_eth_init_mac(struct fm_im_private *priv, struct ccsr_fman_t *reg)
{
	struct fsl_enet_mac *mac;
	void *base, *phyregs = NULL;
	int num;

	num = priv->num;

	if (priv->type == FM_ETH_10G_E)
		num += 8;
	base = &reg->memac[num].fm_memac;
	phyregs = &reg->memac[num].fm_memac_mdio;

	/* Alloc mac controller */
	mac = kzalloc(sizeof(struct fsl_enet_mac), GFP_KERNEL);
	if (!mac)
		return 0;
	memset(mac, 0, sizeof(struct fsl_enet_mac));

	/* Save the mac to fm_eth struct */
	priv->mac = mac;

	init_memac(mac, base, phyregs, MAX_RXBUF_LEN);

	return 1;
}

static void adjust_link(struct net_device *dev)
{
	struct fman_enet_netdev_priv *npriv = netdev_priv(dev);
	struct rtnet_device *ndev = npriv->rtdev;
	struct fm_im_private *priv = rtnetdev_priv(ndev);
	struct memac __iomem *regs = priv->mac->base;
	struct phy_device *phydev = priv->phydev;
	uint32_t tmp;
	int new_state = 0;
	u32 if_mode, if_status;

	if (phydev->link) {
		tmp = fm_im_read(&regs->if_mode);

		if (phydev->duplex != priv->oldduplex) {
			new_state = 1;
			if (phydev->duplex)
				tmp &= ~IF_MODE_HD;
			else
				tmp |= IF_MODE_HD;

			priv->oldduplex = phydev->duplex;
		}

		if (phydev->speed != priv->oldspeed &&
			priv->interface == PHY_INTERFACE_MODE_RGMII ||
			priv->interface == PHY_INTERFACE_MODE_RGMII_TXID) {

			new_state = 1;
			/* Configure RGMII in manual mode */
			tmp &= ~IF_MODE_EN_AUTO;
			tmp &= ~IF_MODE_SETSP_MASK;

			if (phydev->duplex)
				tmp |= IF_MODE_RGMII_FD;
			else
				tmp &= ~IF_MODE_RGMII_FD;

			switch (phydev->speed) {
			case 1000:
				tmp |= IF_MODE_SETSP_1000M;
				break;
			case 100:
				tmp |= IF_MODE_SETSP_100M;
				break;
			case 10:
				tmp |= IF_MODE_SETSP_10M;
				break;
			default:
				break;
			}
			priv->oldspeed = phydev->speed;
		}

		fm_im_write(&regs->if_mode, tmp);

		if (!priv->oldlink) {
			new_state = 1;
			priv->oldlink = 1;
		}
	} else if (priv->oldlink) {
		new_state = 1;
		priv->oldlink = 0;
		priv->oldspeed = 0;
		priv->oldduplex = -1;
	}

	if (new_state && netif_msg_link(priv))
		phy_print_status(phydev);

	if_mode = fm_im_read(&regs->if_mode);
	if_status = fm_im_read(&regs->if_status);
}

static int init_phy(struct rtnet_device *dev)
{
	struct fm_im_private *priv = rtnetdev_priv(dev);
	u32 supported;

	priv->oldlink = 0;
	priv->oldspeed = 0;
	priv->oldduplex = -1;

	priv->phydev = of_phy_connect(priv->ndev, priv->phy_node,
				&adjust_link, 0, priv->interface);

	if (!priv->phydev) {
		pr_info("could not attach to PHY\n");
		return -ENODEV;
	}

	if (priv->type == FM_ETH_1G_E) {
		supported = (SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full |
				SUPPORTED_100baseT_Half |
				SUPPORTED_100baseT_Full |
				SUPPORTED_1000baseT_Full);
	} else {
		supported = SUPPORTED_10000baseT_Full;
	}

	/* Remove any features not supported by the controller */
	priv->phydev->supported &= supported;
	priv->phydev->advertising = priv->phydev->supported;

	return 0;
}

static void fm_init_qmi(struct ccsr_fman_t *reg, int mac_idx)
{
	struct fm_qmi_common_t *qmi = &(reg->fm_qmi_common);

	/* Disable enqueue and dequeue of QMI */
	fm_im_clrbits(&qmi->fmqm_gc, FMQM_GC_ENQ_EN | FMQM_GC_DEQ_EN);

	if (!fman_is_active(reg, mac_idx)) {
		/* Disable all error interrupts */
		fm_im_write(&qmi->fmqm_eien, FMQM_EIEN_DISABLE_ALL);
		/* Clear all error events */
		fm_im_write(&qmi->fmqm_eie, FMQM_EIE_CLEAR_ALL);

		/* Disable all interrupts */
		fm_im_write(&qmi->fmqm_ien, FMQM_IEN_DISABLE_ALL);
		/* Clear all interrupts */
		fm_im_write(&qmi->fmqm_ie, FMQM_IE_CLEAR_ALL);
	}
}

static void fm_init_fpm(struct ccsr_fman_t *reg, int mac_idx)
{
	int i;
	struct fm_fpm_t *fpm = &(reg->fm_fpm);

	if (!fman_is_active(reg, mac_idx)) {
		/* Disable the dispatch limit in IM case */
		fm_im_write(&fpm->fpmflc, FMFP_FLC_DISP_LIM_NONE);
		/* Clear events */
		fm_im_write(&fpm->fmfpee, FMFPEE_CLEAR_EVENT);

		/* Clear risc events */
		for (i = 0; i < 4; i++)
			fm_im_write(&fpm->fpmcev[i], 0xffffffff);

		/* Clear error */
		fm_im_write(&fpm->fpmrcr, FMFP_RCR_MDEC | FMFP_RCR_IDEC);
	}
}

static int fm_init_bmi(int fm_idx, int mac_idx, struct ccsr_fman_t *reg)
{
	int blk;
	u32 val, offset;
	void *base;
	struct fm_bmi_common_t *bmi = &(reg->fm_bmi_common);

	/* Assume U-Boot or other FMAN software has changed it.*/
	if ((!fman_is_active(reg, mac_idx))) {
		/* Disable all BMI interrupt */
		fm_im_write(&bmi->fmbm_ier, FMBM_IER_DISABLE_ALL);

		/* Clear all events */
		fm_im_write(&bmi->fmbm_ievr, FMBM_IEVR_CLEAR_ALL);

		/* Alloc free buffer pool in MURAM */
		base = fm_muram_alloc(fm_idx, FM_FREE_POOL_SIZE,
					FM_FREE_POOL_ALIGN);
		if (!base) {
			pr_info("%s: no muram for free buffer pool\n",
				__func__);
			return -ENOMEM;
		}
		offset = base - fm_muram_base(fm_idx);

		/* Need 128KB total free buffer pool size */
		val = offset / 256;
		blk = FM_FREE_POOL_SIZE / 256;

		/* In IM, we must not begin from offset 0 in MURAM */
		val |= ((blk - 1) << FMBM_CFG1_FBPS_SHIFT);
		fm_im_write(&bmi->fmbm_cfg1, val);
		fm_im_write(&bmi->fmbm_cfg2, FMBM_CFG2_TNTSKS_MASK);

		/* Initialize internal buffers data base (linked list) */
		fm_im_write(&bmi->fmbm_init, FMBM_INIT_START);
	}

	return 0;
}

static int fm_init_common(int fm_idx, int mac_idx, struct ccsr_fman_t *reg)
{
	/* Workaround: to de-active all the ports first */
	fman_de_active(reg);
	fm_init_muram(fm_idx, &reg->muram);
	fm_init_qmi(reg, mac_idx);
	fm_init_fpm(reg, mac_idx);

	if (!fman_is_active(reg, mac_idx)) {
		/* Clear DMA status */
		fm_im_setbits(&reg->fm_dma.fmdmsr, FMDMSR_CLEAR_ALL);

		/* Set DMA mode */
		fm_im_setbits(&reg->fm_dma.fmdmmr, FMDMMR_SBER);
	}

	return fm_init_bmi(fm_idx, mac_idx, reg);
}

int check_shared_interrupt(struct fm_im_private *priv, u32 pending)
{
	if ((pending & FMNPI_EN_REV0) && priv->fpm_event_num == 0)
		return 1;
	if ((pending & FMNPI_EN_REV1) && priv->fpm_event_num == 1)
		return 1;
	if ((pending & FMNPI_EN_REV2) && priv->fpm_event_num == 2)
		return 1;
	if ((pending & FMNPI_EN_REV3) && priv->fpm_event_num == 3)
		return 1;

	return 0;
}

const struct of_device_id fman_match[] = {
	{ .compatible = "fsl,im-ethernet", },
	{},
};
MODULE_DEVICE_TABLE(of, fman_match);

irqreturn_t fm_im_receive(int irq, void *private)
{
	struct fm_im_private *priv = (struct fm_im_private *)private;
	struct fman_enet_netdev_priv *npriv;
	struct rtnet_device *dev;
	struct rtskb *skb;
	struct fm_port_global_pram *pram;
	struct fm_port_bd *rxbd, *rxbd_base;
	u16 status, offset_out;
	u32 ievent, pending;
	int pkt_len;
	struct fm_fpm_t *fpm;
	dma_addr_t buf;
	u32 buf_lo, buf_hi;
	nanosecs_abs_t time_stamp = rtdm_clock_read();

	npriv = netdev_priv(priv->ndev);
	dev = npriv->rtdev;

	pram = priv->rx_pram;
	rxbd = priv->cur_rxbd;
	status = muram_readw(&rxbd->status);
	fpm = &priv->reg->fm_fpm;

	pending = fm_im_read(&fpm->fmnpi);

	if (!check_shared_interrupt(priv, pending))
		return IRQ_NONE;

	/* Clear event register */
	ievent = fm_im_read(&fpm->fpmfcevent[priv->fpm_event_num]);
	fm_im_write(&fpm->fpmcev[priv->fpm_event_num], ievent);

	while (!(status & RxBD_EMPTY)) {
		struct rtskb *newskb = NULL;

		newskb = rtnetdev_alloc_rtskb(dev,
				priv->rx_buffer_size + RXBUF_ALIGNMENT);
		if (!newskb) {
			pr_info("Can't allocate RX buffers\n");
			return 0;
		}

		rtskb_reserve(newskb, RXBUF_ALIGNMENT -
				(((unsigned long) newskb->data) &
				(RXBUF_ALIGNMENT - 1)));

		skb = priv->rx_skbuff[priv->skb_currx];
		buf_hi = muram_readw(&rxbd->buf_ptr_hi);
		buf_lo = fm_im_read(&rxbd->buf_ptr_lo);
		buf = ((u64)buf_hi << 32) | buf_lo;
		dma_unmap_single(priv->dev, buf, priv->rx_buffer_size,
					DMA_FROM_DEVICE);

		/* We drop the frame if we failed to allocate a new buffer */
		if (unlikely(!newskb ||
			!(muram_readw(&rxbd->status) & RxBD_LAST) ||
			muram_readw(&rxbd->status) & RxBD_ERROR)) {
			if (unlikely(!newskb))
				newskb = skb;
			else if (skb)
				kfree_rtskb(skb);
		} else {
			if (likely(skb)) {
				pkt_len = muram_readw(&rxbd->len) - ETH_FCS_LEN;
				rtskb_put(skb, pkt_len);
				skb->protocol = rt_eth_type_trans(skb, dev);
				skb->rtdev = dev;
				skb->time_stamp = time_stamp;
				rtnetif_rx(skb);
				rt_mark_stack_mgr(dev);
			} else {
				pr_info("Missing skb!\n");
			}
		}

		priv->rx_skbuff[priv->skb_currx] = newskb;
		buf = dma_map_single(priv->dev, newskb->data,
				priv->rx_buffer_size, DMA_FROM_DEVICE);
		muram_writew(&rxbd->buf_ptr_hi, (buf >> 32) & 0xffff);
		fm_im_write(&rxbd->buf_ptr_lo, (u32)(buf & 0xffffffff));

		/* Clear the RxBDs */
		muram_writew(&rxbd->status, RxBD_EMPTY);
		muram_writew(&rxbd->len, 0);
		mb();/*memory sync*/

		/* Advance RxBD */
		rxbd++;
		rxbd_base = (struct fm_port_bd *)priv->rx_bd_ring;
		if (rxbd >= (rxbd_base + RX_BD_RING_SIZE))
			rxbd = rxbd_base;
		/* Read next status */
		status = muram_readw(&rxbd->status);

		/* Update to point at the next skb */
		priv->skb_currx = (priv->skb_currx + 1) & (RX_BD_RING_SIZE - 1);

		/* Update RxQD */
		offset_out = muram_readw(&pram->rxqd.offset_out);
		offset_out += sizeof(struct fm_port_bd);
		if (offset_out >= muram_readw(&pram->rxqd.bd_ring_size))
			offset_out = 0;
		muram_writew(&pram->rxqd.offset_out, offset_out);
		mb();/*memory sync*/

	}
	priv->cur_rxbd = (void *)rxbd;

	return IRQ_HANDLED;
}

static int fm_im_startup(struct rtnet_device *dev)
{
	struct fm_im_private *priv;
	struct memac *regs;

	priv = rtnetdev_priv(dev);

	/* Rx/TxBDs, Rx/TxQDs, Rx buff and parameter ram init */
	if (!port_parameter_init(priv, dev))
		return 0;

	regs = priv->mac->base;
	priv->mac->init_mac(priv->mac);

	return 1;
}

static int fm_im_enet_open(struct rtnet_device *dev)
{
	struct fm_im_private *priv;
	struct fsl_enet_mac *mac;
	int i, err;
	u32 val;

	priv = rtnetdev_priv(dev);
	pr_info("fm_im open!\n");
	err = request_irq(priv->irq, fm_im_receive,
				IRQF_SHARED, "fman_im", priv);
	if (err < 0)
		pr_info("Request irq ERROR!\n");

	mac = priv->mac;
	mac->set_mac_addr(mac, dev->dev_addr);

	if (init_phy(dev))
		return 0;

	/* Init bmi rx port, IM mode and disable */
	bmi_rx_port_init(priv, priv->rx_port);
	/* Enable bmi Rx port */
	fm_im_write(&priv->rx_port->fmbm_rfqid,
		((u64)priv->rx_pram - (u64)fm_muram_base(priv->fm_index)));
	fm_im_setbits(&priv->rx_port->fmbm_rcfg, FMBM_RCFG_EN);

	/* Enable MAC rx/tx port */
	mac->enable_mac(mac);

	/* Init bmi tx port, IM mode and disable */
	bmi_tx_port_init(priv, priv->tx_port);
	/* Enable bmi Tx port */
	fm_im_write(&priv->tx_port->fmbm_tcfqid,
		((u64)priv->tx_pram - (u64)fm_muram_base(priv->fm_index)));
	fm_im_setbits(&priv->tx_port->fmbm_tcfg, FMBM_TCFG_EN);
	/* Re-enable transmission of frame */
	priv->tx_pram->mode &= ~PRAM_MODE_GRACEFUL_STOP;
	/* Enable interrupt */
	for (i = 0; i < 4; i++) {
		fm_im_setbits(&(&priv->reg->fm_fpm)->fpmfcmask[i],
				FMFPCEE_IM_MASK_RXF);
		val = fm_im_read(&(&priv->reg->fm_fpm)->fpmfcmask[i]);
	}

	mb();/*memory sync*/

	phy_start(priv->phydev);

	/* Set the MAC-PHY mode */
	mac->set_if_mode(mac, priv->interface, priv->phydev->speed);

	rt_stack_connect(dev, &STACK_manager);
	rtnetif_start_queue(dev);
	pr_info("fm_im rtstack connect\n");

	for (i = 0; i < 4; i++)
		val = fm_im_read(&(&priv->reg->fm_fpm)->fpmfcevent[i]);

	return 0;
}

static int fm_im_close(struct rtnet_device *dev)
{

	struct fm_im_private *priv = rtnetdev_priv(dev);
	int i;

	rtnetif_stop_queue(dev);
	/* Allow the Fman (Tx) port to process in-flight frames before we
	 * try switching it off.
	 */
	/* Re-enable transmission of frame */
	priv->tx_pram->mode |= PRAM_MODE_GRACEFUL_STOP;
	usleep_range(5000, 10000);

	phy_stop(priv->phydev);

	for (i = 0; i < 4; i++)
		fm_im_setbits(&(&priv->reg->fm_fpm)->fpmfcmask[i], 0x0);

	/* Clear DMA status */
	fm_im_setbits(&priv->reg->fm_dma.fmdmsr, FMDMSR_CLEAR_ALL);

	/* Disable bmi Tx port */
	fm_im_clrbits(&priv->tx_port->fmbm_tcfg, FMBM_TCFG_EN);

	/* Disable MAC rx/tx port */
	priv->mac->disable_mac(priv->mac);

	/* Disable bmi Rx port */
	fm_im_clrbits(&priv->rx_port->fmbm_rcfg, FMBM_RCFG_EN);

	/* Release irq line */
	free_irq(priv->irq, priv);

	/* Free skb resource */
	/* Not implemented yet */

	/* Disconnect from the PHY */
	phy_disconnect(priv->phydev);
	priv->phydev = NULL;

	return 0;
}

static int fm_im_start_xmit(struct rtskb *skb, struct rtnet_device *dev)
{
	struct fm_im_private *priv;
	struct fm_port_global_pram *pram;
	struct fm_port_bd *txbd, *txbd_base;
	struct netdev_queue *txq;
	u16 offset_in;
	dma_addr_t buf;
	int i, rq = 0;

	priv = rtnetdev_priv(dev);
	pram = priv->tx_pram;
	txbd = priv->cur_txbd;
	txq = netdev_get_tx_queue(priv->ndev, rq);

	/* Find one empty TxBD */
	for (i = 0; muram_readw(&txbd->status) & TxBD_READY; i++) {
		udelay(100);
		if (i > 0x1000) {
			pr_info("%s: Tx buffer not ready\n", dev->name);
			netif_tx_stop_queue(txq);

			return NETDEV_TX_BUSY;
		}
	}

	i = (u32)((void *)txbd -
		((void *)priv->tx_bd_ring))/sizeof(struct fm_port_bd);
	if (i >=  TX_BD_RING_SIZE) {
		pr_info("index of Tx BD ring [%d] is out of the range [%d]\n",
			i, TX_BD_RING_SIZE);

		return NETDEV_TX_BUSY;
	}

	if (priv->tx_skbuff[i]) {
		buf = ((uint64_t)txbd->buf_ptr_hi << 32) + txbd->buf_ptr_lo;
		dma_unmap_single(priv->dev, buf,
			rtskb_headlen(priv->tx_skbuff[i]), DMA_TO_DEVICE);
		kfree_rtskb(priv->tx_skbuff[i]);
	}
	priv->tx_skbuff[i] = skb;

	/* Setup TxBD */
	buf = dma_map_single(priv->dev, skb->data,
				rtskb_headlen(skb), DMA_TO_DEVICE);
	muram_writew(&txbd->buf_ptr_hi, (buf >> 32) & 0xff);
	fm_im_write(&txbd->buf_ptr_lo, (u32)(buf & 0xffffffff));
	muram_writew(&txbd->len, rtskb_headlen(skb));
	mb();/*memory sync*/
	muram_writew(&txbd->status, TxBD_READY | TxBD_LAST);
	mb();/*memory sync*/

	/* Update TxQD, let RISC to send the packet */
	offset_in = muram_readw(&pram->txqd.offset_in);
	offset_in += sizeof(struct fm_port_bd);
	if (offset_in >= muram_readw(&pram->txqd.bd_ring_size))
		offset_in = 0;
	muram_writew(&pram->txqd.offset_in, offset_in);
	mb();/*memory sync*/

	/* Wait for buffer to be transmitted */
	for (i = 0; muram_readw(&txbd->status) & TxBD_READY; i++) {
		udelay(100);
		if (i > 0x10000) {
			pr_info("%s: Tx error\n", dev->name);
			return 0;
		}
	}

	/* Advance the TxBD */
	txbd++;
	txbd_base = (struct fm_port_bd *)priv->tx_bd_ring;
	if (txbd >= (txbd_base + TX_BD_RING_SIZE))
		txbd = txbd_base;
	/* Update current txbd */
	priv->cur_txbd = (void *)txbd;

	if (skb->xmit_stamp)
		*skb->xmit_stamp = cpu_to_be64(rtdm_clock_read() +
					*skb->xmit_stamp);

	return NETDEV_TX_OK;
}

static int fm_im_remove(struct platform_device *of_dev)
{
	struct rtnet_device *ndev = dev_get_drvdata(&of_dev->dev);
	struct fm_im_private *priv = rtnetdev_priv(ndev);

	int i;
	struct fm_port_bd *txbd, *rxbd;
	dma_addr_t buf;

	if (priv->phy_node)
		of_node_put(priv->phy_node);
	if (priv->tbi_node)
		of_node_put(priv->tbi_node);

	dev_set_drvdata(&of_dev->dev, NULL);

	/* free Rx resources */
	for (i = 0, rxbd = priv->rx_bd_ring; i < RX_BD_RING_SIZE; i++) {
		buf = ((uint64_t)rxbd->buf_ptr_hi << 32) + rxbd->buf_ptr_lo;
		dma_unmap_single(priv->dev, buf,
			rtskb_headlen(priv->rx_skbuff[i]), DMA_FROM_DEVICE);
		kfree_rtskb(priv->rx_skbuff[i]);
		rxbd++;
	}
	rtdm_free(priv->rx_bd_ring);
	rtdm_free(priv->rx_skbuff);

	/* free Tx resources */
	for (i = 0, txbd = priv->tx_bd_ring; i < TX_BD_RING_SIZE; i++, txbd++) {
		if (!priv->tx_skbuff[i])
			continue;
		buf = ((uint64_t)txbd->buf_ptr_hi << 32) + txbd->buf_ptr_lo;
		dma_unmap_single(priv->dev, buf,
			rtskb_headlen(priv->tx_skbuff[i]), DMA_TO_DEVICE);
		kfree_rtskb(priv->tx_skbuff[i]);
	}
	rtdm_free(priv->tx_bd_ring);
	rtdm_free(priv->tx_skbuff);

	rt_unregister_rtnetdev(ndev);
	rtdev_free(ndev);

	return 0;
}

static int fm_im_probe(struct platform_device *of_dev)
{
	struct ccsr_fman_t __iomem *reg;
	static struct ccsr_fman_t *fm1_reg;
	static int fm1_flag;
	struct fman_enet_netdev_priv *npriv;
	struct rtnet_device *net_dev = NULL;
	struct fm_im_private *priv = NULL;
	struct device *dev = &of_dev->dev;
	const char *dev_name, *ctype;
	const int *fm_id, *mac_id, *fpm_event_id;
	int fm_idx, mac_idx;
	u16 rx_port_id, tx_port_id;
	const struct of_device_id *match;
	const void *mac_addr;
	struct device_node *mac_node;
	int err = 0;

	match = of_match_device(fman_match, dev);
	if (!match) {
		pr_info("%s(): No matching device found.\n", __func__);
		return -EINVAL;
	}

	if (dev->init_name)
		dev_name = dev->init_name;
	else
		dev_name = (&dev->kobj)->name;

	mac_node = of_parse_phandle(dev->of_node, "fsl,fman-mac", 0);
	if (!mac_node) {
		pr_info("%s(): of_parse_phandle get fsl,fman-mac failed!\n",
			__func__);
		return -EINVAL;
	}

	fm_id = of_get_property(mac_node->parent, "cell-index", NULL);
	if (!fm_id) {
		pr_info("of_get_property get cell-index failed!\n");
		return -EINVAL;
	}
	mac_id = of_get_property(mac_node, "cell-index", NULL);
	if (!mac_id) {
		pr_info("of_get_property get cell-index failed!\n");
		return -EINVAL;
	}

	fm_idx = fm_im_read((unsigned __iomem *)fm_id);
	mac_idx = fm_im_read((unsigned __iomem *)mac_id);
	pr_info("DEV: FM%d@DTSEC%d, DTS Node: %s\n",
		fm_idx+1, mac_idx+1, dev_name);

	fpm_event_id = of_get_property(dev->of_node, "fpmevt-sel", NULL);
	if (!fpm_event_id) {
		pr_info("of_get_property get fpmevt-sel failed!\n");
		return -EINVAL;
	}

	rx_port_id = RX_PORT_1G_BASE + mac_idx;
	tx_port_id = TX_PORT_1G_BASE + mac_idx;

	sys_ccsrbar = CONFIG_SYS_CCSRBAR_BASE;
	sys_fm1_offset = CONFIG_SYS_FM1_OFFSET;
	sys_fm1_addr = (sys_ccsrbar + sys_fm1_offset);

	if (fm_idx == 0) {
		if (!fm1_reg) {
			reg = ioremap(sys_fm1_addr, sizeof(struct ccsr_fman_t));
			fm_init_common(fm_idx, mac_idx, reg);
			fm1_reg = reg;
		} else {
			reg = fm1_reg;
			fm1_flag = 1;
		}
	} else {
		pr_info("FM NUM ERROR!\n");
		return -EINVAL;
	}

	net_dev = rt_alloc_etherdev(sizeof(struct fm_im_private),
					2 * 128 + 256);
	if (!net_dev) {
		dev_err(dev, "alloc_etherdev() failed\n");
		err = -ENOMEM;
		goto alloc_etherdev_fail;
	}
	rtdev_alloc_name(net_dev, "rteth%d");
	rt_rtdev_connect(net_dev, &RTDEV_manager);
	net_dev->vers = RTDEV_VERS_2_0;

	priv = rtnetdev_priv(net_dev);
	memset(priv, 0, sizeof(*priv));
	priv->ofdev = of_dev;
	priv->dev = dev;
	/* RTnet: allocate dummy linux netdev structure for phy handling */
	priv->ndev = alloc_etherdev(sizeof(struct fman_enet_netdev_priv));
	if (!priv->ndev)
		goto alloc_etherdev_fail;

	SET_NETDEV_DEV(priv->ndev, dev);
	npriv = netdev_priv(priv->ndev);
	npriv->rtdev = net_dev;
	dev_set_drvdata(dev, priv);

	priv->reg = reg;
	priv->fm_index = fm_idx;
	priv->num = mac_idx;
	priv->type = FM_ETH_1G_E;
	priv->rx_buffer_size = DEFAULT_RX_BUFFER_SIZE;


	/* Enable most messages by default */
	priv->msg_enable = (NETIF_MSG_IFUP << 1) - 1;

	priv->rx_port = (void *)&reg->port[rx_port_id - 1].fm_bmi;
	priv->tx_port = (void *)&reg->port[tx_port_id - 1].fm_bmi;

	ctype = of_get_property(mac_node, "phy-connection-type", NULL);
	if (ctype && !strcmp(ctype, "rgmii-id"))
		priv->interface = PHY_INTERFACE_MODE_RGMII_ID;
	else if (ctype && !strcmp(ctype, "rgmii-txid"))
		priv->interface = PHY_INTERFACE_MODE_RGMII_TXID;
	else if (ctype && !strcmp(ctype, "rgmii"))
		priv->interface = PHY_INTERFACE_MODE_RGMII;
	else if (ctype && !strcmp(ctype, "sgmii"))
		priv->interface = PHY_INTERFACE_MODE_SGMII;
	else
		priv->interface = PHY_INTERFACE_MODE_MII;

	priv->phy_node = of_parse_phandle(mac_node, "phy-handle", 0);

	/* Find the TBI PHY.  If it's not there, we don't support SGMII */
	priv->tbi_node = of_parse_phandle(mac_node, "tbi-handle", 0);
	priv->irq = irq_of_parse_and_map(mac_node->parent, 0);

	priv->fpm_event_num = fm_im_read((unsigned __iomem *)fpm_event_id);

	if (priv->fpm_event_num < 0 || priv->fpm_event_num > 3) {
		pr_info("of_get_property get wrong fpm event register num!\n");
		err = -EINVAL;
		goto ioremap_fail;
	}

	mac_addr = of_get_mac_address(mac_node);
	/* Set the ethernet max receive length */
	priv->max_rx_len = MAX_RXBUF_LEN;

	/* Init global mac structure */
	if (!fm_eth_init_mac(priv, reg)) {
		err = -EINVAL;
		goto ioremap_fail;
	}

	/* To align the same name in U-Boot */
	strncpy(net_dev->name, "rteth%d", sizeof(net_dev->name) - 1);

	if (!fm_im_startup(net_dev)) {
		err = -EINVAL;
		goto ioremap_fail;
	}
	net_dev->base_addr = (unsigned long)reg;
	net_dev->mtu = 1500;

	net_dev->open = fm_im_enet_open;
	net_dev->stop = fm_im_close;
	net_dev->hard_start_xmit = fm_im_start_xmit;
	net_dev->vers = RTDEV_VERS_2_0;
	net_dev->features |= NETIF_F_LLTX;

	spin_lock_init(&priv->lock);

	err = rt_register_rtnetdev(net_dev);
	if (err) {
		pr_info("%s: register net device failed.\n", net_dev->name);
		goto ioremap_fail;
	}
	pr_info("fm_im register net device ok\n");
	rtnetif_carrier_on(net_dev);

	return 0;

ioremap_fail:
	iounmap(priv->reg);
alloc_etherdev_fail:
	rtdev_free(net_dev);
	return err;
}

static struct platform_driver fm_im_driver = {
	.driver = {
		.name           = KBUILD_MODNAME,
		.of_match_table = fman_match,
		.owner          = THIS_MODULE,
	},
	.probe	= fm_im_probe,
	.remove	= fm_im_remove,
};

static int __init __cold fm_im_load(void)
{
	int _errno;

	pr_info(":QorIQ FMAN Independent Mode Ethernet Driver\n");
	_errno = platform_driver_register(&fm_im_driver);
	if (unlikely(_errno < 0)) {
		pr_err(KBUILD_MODNAME
			": %s:%hu:%s(): platform_driver_register() = %d\n",
			KBUILD_BASENAME".c", __LINE__, __func__, _errno);
	}

	return _errno;
}

static void __exit __cold fm_im_unload(void)
{
	pr_info(": -> %s:%s()\n", KBUILD_BASENAME".c", __func__);
	platform_driver_unregister(&fm_im_driver);
}

module_init(fm_im_load);
module_exit(fm_im_unload);
MODULE_DESCRIPTION("QorIQ FMAN Independent Mode Ethernet driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("NXP");
