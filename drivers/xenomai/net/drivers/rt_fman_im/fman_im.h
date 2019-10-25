/* SPDX-License-Identifier: GPL-2.0+
 *
 * QorIQ FMAN Independent Mode Ethernet driver for NXP Layerscape
 *
 * Copyright 2018-2019 NXP
 *
 */

#ifndef __FMAN_IM_H__
#define __FMAN_IM_H__

#include <linux/io.h>
#include <linux/etherdevice.h>
#include "fman.h"

#define CONFIG_SYS_NUM_FMAN	1

#define CONFIG_SYS_CCSRBAR_BASE		0x01000000
#define CONFIG_SYS_FM1_OFFSET		0xA00000
#define CONFIG_SYS_NUM_FM1_MEMAC	6
#define CONFIG_SYS_NUM_FM1_10GEC	1
#define CONFIG_SYS_FM_MURAM_SIZE	0x60000

/* Port ID */
#define OH_PORT_ID_BASE		0x02
#define MAX_NUM_OH_PORT		4
#define RX_PORT_1G_BASE		0x08
#define MAX_NUM_RX_PORT_1G      CONFIG_SYS_NUM_FM1_MEMAC
#define MAX_NUM_RX_PORT_10G     CONFIG_SYS_NUM_FM1_10GEC
#define RX_PORT_10G_BASE        0x10
#define TX_PORT_1G_BASE         0x28
#define MAX_NUM_TX_PORT_1G      CONFIG_SYS_NUM_FM1_MEMAC
#define MAX_NUM_TX_PORT_10G     CONFIG_SYS_NUM_FM1_10GEC
#define TX_PORT_10G_BASE        0x30
#ifndef rtnetdev_priv
#define rtnetdev_priv(ndev) ((ndev)->priv)
#endif

enum fm_eth_type {
	FM_ETH_1G_E,
	FM_ETH_10G_E,
};

struct fm_muram {
	void *base;
	void *top;
	size_t size;
	void *alloc;
};

#define FM_MURAM_RES_SIZE	0x01000

/* Rx/Tx buffer descriptor */
struct fm_port_bd {
	u16 status;
	u16 len;
	u32 res0;
	u16 res1;
	u16 buf_ptr_hi;
	u32 buf_ptr_lo;
};

/* Common BD flags */
#define BD_LAST			0x0800

/* Rx BD status flags */
#define RxBD_EMPTY		0x8000
#define RxBD_LAST		BD_LAST
#define RxBD_FIRST		0x0400
#define RxBD_PHYS_ERR		0x0008
#define RxBD_SIZE_ERR		0x0004
#define RxBD_ERROR		(RxBD_PHYS_ERR | RxBD_SIZE_ERR)

/* Tx BD status flags */
#define TxBD_READY		0x8000
#define TxBD_LAST		BD_LAST

/* Rx/Tx queue descriptor */
struct fm_port_qd {
	u16 gen;
	u16 bd_ring_base_hi;
	u32 bd_ring_base_lo;
	u16 bd_ring_size;
	u16 offset_in;
	u16 offset_out;
	u16 res0;
	u32 res1[0x4];
};

/* IM global parameter RAM */
struct fm_port_global_pram {
	u32 mode;	/* independent mode register */
	u32 rxqd_ptr;	/* Rx queue descriptor pointer */
	u32 txqd_ptr;	/* Tx queue descriptor pointer */
	u16 mrblr;	/* max Rx buffer length */
	u16 rxqd_bsy_cnt;	/* RxQD busy counter, should be cleared */
	u32 res0[0x4];
	struct fm_port_qd rxqd;	/* Rx queue descriptor */
	struct fm_port_qd txqd;	/* Tx queue descriptor */
	u32 res1[0x28];
};

#define FM_PRAM_SIZE		sizeof(struct fm_port_global_pram)
#define FM_PRAM_ALIGN		256
#define PRAM_MODE_GLOBAL	0x20000000
#define PRAM_MODE_GRACEFUL_STOP	0x00800000

#define FM_FREE_POOL_SIZE	0x20000 /* 128K bytes */
#define FM_FREE_POOL_ALIGN	256

struct fsl_enet_mac {
	void *base; /* MAC controller registers base address */
	void *phyregs;
	int max_rx_len;
	void (*init_mac)(struct fsl_enet_mac *mac);
	void (*enable_mac)(struct fsl_enet_mac *mac);
	void (*disable_mac)(struct fsl_enet_mac *mac);
	void (*set_mac_addr)(struct fsl_enet_mac *mac, u8 *mac_addr);
	void (*set_if_mode)(struct fsl_enet_mac *mac, phy_interface_t type,
			int speed);
};

/* Fman ethernet private struct */
struct fm_im_private {
	struct device *dev;
	struct net_device *ndev;
	struct platform_device *ofdev;
	int fm_index;			/* Fman index */
	int irq;
	u32 num;			/* 0..n-1 for give type */
	/* FPM Fman Controller Event Register 0..3 for im device */
	int fpm_event_num;
	struct fm_bmi_tx_port *tx_port;
	struct fm_bmi_rx_port *rx_port;
	enum fm_eth_type type;		/* 1G or 10G ethernet */
	struct ccsr_fman_t __iomem *reg;
	struct rtskb **rx_skbuff;
	struct rtskb **tx_skbuff;
	struct napi_struct napi;
	int rx_buffer_size;
	u16 skb_currx;

	/* PHY stuff */
	phy_interface_t interface;
	struct device_node *phy_node;
	struct device_node *tbi_node;
	struct phy_device *phydev;
	struct mii_dev *bus;
	int oldspeed;
	int oldduplex;
	int oldlink;

	struct fsl_enet_mac *mac;	/* MAC controller */
	int phyaddr;
	int max_rx_len;
	struct fm_port_global_pram *rx_pram; /* Rx parameter table */
	struct fm_port_global_pram *tx_pram; /* Tx parameter table */
	void *rx_bd_ring;		/* Rx BD ring base */
	void *cur_rxbd;			/* current Rx BD */
	void *rx_buf;			/* Rx buffer base */
	void *tx_bd_ring;		/* Tx BD ring base */
	void *cur_txbd;			/* current Tx BD */

	uint32_t msg_enable;
	spinlock_t lock;

};

/* For phy handling */
struct fman_enet_netdev_priv {
	struct rtnet_device *rtdev;
};

#define RX_QD_RXF_INTMASK	0x0010
#define RX_QD_BSY_INTMASK	0x0008
#define RX_BD_RING_SIZE		8
#define TX_BD_RING_SIZE		8
#define MAX_RXBUF_LOG2		11
#define MAX_RXBUF_LEN		(1 << MAX_RXBUF_LOG2)
#define RXBUF_ALIGNMENT		64
#define DEFAULT_RX_BUFFER_SIZE	1536


#define PORT_IS_ENABLED(port)	fm_info[fm_port_to_index(port)].enabled

#define FMAN_IM_TX_QUEUES	1
#define FMAN_IM_RX_QUEUES	128

#define IMASK_TXCEN		0x00800000
#define IMASK_TXEEN		0x00400000
#define IMASK_RXCEN		0x40000000
#define IMASK_TX_DEFAULT	(IMASK_TXCEN | IMASK_TXEEN)
#define IMASK_RX_DEFAULT	IMASK_RXCEN

static inline u32 fm_im_read(unsigned __iomem *addr)
{
	return ioread32be(addr);
}

static inline void fm_im_write(unsigned __iomem *addr, u32 val)
{
	iowrite32be(val, addr);
}

static inline void fm_im_clrbits(unsigned __iomem *addr, u32 clear)
{
	u32 val;

	val = ioread32be(addr);
	val = val & (~clear);
	iowrite32be(val, addr);
}

static inline void fm_im_setbits(unsigned __iomem *addr, u32 set)
{
	u32 val;

	val = ioread32be(addr);
	val = val | set;
	iowrite32be(val, addr);
}

#endif /* __FM_H__ */
