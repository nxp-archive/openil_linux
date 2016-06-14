/*
 *
 *  Copyright (C) 2007 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _PFE_ETH_H_
#define _PFE_ETH_H_
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/phy.h>
#include <linux/clk.h>
#include <linux/interrupt.h>
#include <linux/time.h>

#define PFE_ETH_NAPI_STATS
#define PFE_ETH_TX_STATS

#define PFE_ETH_FRAGS_MAX (65536/HIF_RX_PKT_MIN_SIZE)
#define LRO_LEN_COUNT_MAX	32
#define LRO_NB_COUNT_MAX	32

#if defined(CONFIG_PLATFORM_PCI) || defined(CONFIG_PLATFORM_EMULATION) || defined(CONFIG_PLATFORM_LS1012A)

#define CONFIG_COMCERTO_GEMAC           1

#define CONFIG_COMCERTO_USE_MII         1
#define CONFIG_COMCERTO_USE_RMII                2
#define CONFIG_COMCERTO_USE_GMII                4
#define CONFIG_COMCERTO_USE_RGMII       8
#define CONFIG_COMCERTO_USE_SGMII       16

#define GEMAC_SW_CONF                   (1 << 8) | (1 << 11)    // GEMAC configured by SW
#define GEMAC_PHY_CONF          0                       // GEMAC configured by phy lines (not for MII/GMII)
#define GEMAC_SW_FULL_DUPLEX    (1 << 9)
#define GEMAC_SW_SPEED_10M      (0 << 12)
#define GEMAC_SW_SPEED_100M     (1 << 12)
#define GEMAC_SW_SPEED_1G               (2 << 12)

#define GEMAC_NO_PHY                    (1 << 0)                // set if no phy connected to MAC (ex ethernet switch). In this case use MAC fixed configuration
#define GEMAC_PHY_RGMII_ADD_DELAY       (1 << 1)

/* gemac to interface name assignment */
#define GEMAC0_ITF_NAME "eth5"
#define GEMAC1_ITF_NAME "eth6"
#define GEMAC2_ITF_NAME "eth7"

#define GEMAC0_MAC { 0x00, 0xED, 0xCD, 0xEF, 0xAA, 0xCC }
#define GEMAC1_MAC { 0x00, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E }

struct comcerto_eth_platform_data {
	/* device specific information */
	u32 device_flags;
	char name[16];


	/* board specific information */
	u32 mii_config;
	u32 gemac_mode;
	u32 phy_flags;
	u32 gem_id;
	u32 bus_id;
	u32 phy_id;
	u32 mdio_muxval;
	u8 mac_addr[ETH_ALEN];
};

struct comcerto_mdio_platform_data {
	int enabled;
	int irq[32];
	u32 phy_mask;
	int mdc_div;
};

struct comcerto_pfe_platform_data
{
	struct comcerto_eth_platform_data comcerto_eth_pdata[3];
	struct comcerto_mdio_platform_data comcerto_mdio_pdata[3];
};
#if !defined(CONFIG_PLATFORM_LS1012A)
static struct comcerto_pfe_platform_data comcerto_pfe_pdata = {
	.comcerto_eth_pdata[0] = {
		.name = GEMAC0_ITF_NAME,
		.device_flags = CONFIG_COMCERTO_GEMAC,
		.mii_config = CONFIG_COMCERTO_USE_MII,
		.gemac_mode = GEMAC_SW_CONF | GEMAC_SW_FULL_DUPLEX | GEMAC_SW_SPEED_100M,
#if defined(CONFIG_PLATFORM_EMULATION) || defined(CONFIG_PLATFORM_PCI) 
		.phy_flags = GEMAC_NO_PHY,
#else
		.phy_flags = GEMAC_PHY_RGMII_ADD_DELAY,
#endif
		.bus_id = 0,
		.phy_id = 0,
		.gem_id = 0,
		.mac_addr = (u8[])GEMAC0_MAC,
	},

	.comcerto_eth_pdata[1] = {
		.name = GEMAC1_ITF_NAME,
		.device_flags = CONFIG_COMCERTO_GEMAC,
		.mii_config = CONFIG_COMCERTO_USE_RGMII,
		.gemac_mode = GEMAC_SW_CONF | GEMAC_SW_FULL_DUPLEX | GEMAC_SW_SPEED_1G,
		.phy_flags = GEMAC_NO_PHY,
		.gem_id = 1,
		.mac_addr = (u8[])GEMAC1_MAC,
	},

	.comcerto_eth_pdata[2] = {
		.name = GEMAC2_ITF_NAME,
	},

	.comcerto_mdio_pdata[0] = {
		.enabled = 1,
		.phy_mask = 0xFFFFFFFE,
		.mdc_div = 96,
		.irq = {
			[0] = PHY_POLL,
		},
	},
};
#endif
#endif

#if defined(CONFIG_PLATFORM_LS1012A)
#define NUM_GEMAC_SUPPORT		2
#define DRV_NAME			"ls1012a-geth"
#else
#define NUM_GEMAC_SUPPORT		3
#define DRV_NAME			"c2000-geth"
#endif
#define COMCERTO_INFOSTR_LEN		32
#define COMCERTO_TX_RECOVERY_TIMEOUT_MS	500
#define COMCERTO_TX_FAST_RECOVERY_TIMEOUT_MS	3
#define TX_POLL_TIMEOUT_MS		1000

#define EMAC_TXQ_CNT	16
#define EMAC_TXQ_DEPTH	(HIF_TX_DESC_NT)

#define JUMBO_FRAME_SIZE	10258
/**
 * Client Tx queue threshold, for txQ flush condition.
 * It must be smaller than the queue size (in case we ever change it in the future).
 */
#define HIF_CL_TX_FLUSH_MARK	32

/**
 * Max number of TX resources (HIF descriptors or skbs) that will be released
 * in a single go during batch recycling.
 * Should be lower than the flush mark so the SW can provide the HW with a
 * continuous stream of packets instead of bursts.
 */
#define TX_FREE_MAX_COUNT 16
#define EMAC_RXQ_CNT	3
#define EMAC_RXQ_DEPTH	HIF_RX_DESC_NT /* make sure clients can receive a full burst of packets */
#define EMAC_RMON_TXBYTES_POS	0x00
#define EMAC_RMON_RXBYTES_POS	0x14

#define EMAC_QUEUENUM_MASK      (emac_txq_cnt - 1)
#define EMAC_MDIO_TIMEOUT	1000
#define MAX_UC_SPEC_ADDR_REG 31


/* The set of statistics registers implemented in the Cadence MAC.
 * The statistics registers implemented are a subset of all the statistics
 * available, but contains all the compulsory ones.
 * For full descriptions on the registers, refer to the Cadence MAC programmers
 * guide or the IEEE 802.3 specifications.
 */
struct gemac_stats{
	u32 octets_tx_bot;      /* Lower 32-bits for number of octets tx'd */
	u32 octets_tx_top;      /* Upper 16-bits for number of octets tx'd */
	u32 frames_tx;          /* Number of frames transmitted OK */
	u32 broadcast_tx;       /* Number of broadcast frames transmitted */
	u32 multicast_tx;       /* Number of multicast frames transmitted */
	u32 pause_tx;           /* Number of pause frames transmitted. */
	u32 frame64_tx;         /* Number of 64byte frames transmitted */
	u32 frame65_127_tx;     /* Number of 65-127 byte frames transmitted */
	u32 frame128_255_tx;    /* Number of 128-255 byte frames transmitted */
	u32 frame256_511_tx;    /* Number of 256-511 byte frames transmitted */
	u32 frame512_1023_tx;   /* Number of 512-1023 byte frames transmitted */
	u32 frame1024_1518_tx;  /* Number of 1024-1518 byte frames transmitted*/
	u32 frame1519_tx;       /* Number of frames greater than 1518 bytes tx*/
	u32 tx_urun;            /* Transmit underrun errors due to DMA */
	u32 single_col;         /* Number of single collision frames */
	u32 multi_col;          /* Number of multi collision frames */
	u32 excess_col;         /* Number of excessive collision frames. */
	u32 late_col;           /* Collisions occuring after slot time */
	u32 def_tx;             /* Frames deferred due to crs */
	u32 crs_errors;         /* Errors caused by crs not being asserted. */
	u32 octets_rx_bot;      /* Lower 32-bits for number of octets rx'd */
	u32 octets_rx_top;      /* Upper 16-bits for number of octets rx'd */
	u32 frames_rx;          /* Number of frames received OK */
	u32 broadcast_rx;       /* Number of broadcast frames received */
	u32 multicast_rx;       /* Number of multicast frames received */
	u32 pause_rx;           /* Number of pause frames received. */
	u32 frame64_rx;         /* Number of 64byte frames received */
	u32 frame65_127_rx;     /* Number of 65-127 byte frames received */
	u32 frame128_255_rx;    /* Number of 128-255 byte frames received */
	u32 frame256_511_rx;    /* Number of 256-511 byte frames received */
	u32 frame512_1023_rx;   /* Number of 512-1023 byte frames received */
	u32 frame1024_1518_rx;  /* Number of 1024-1518 byte frames received*/
	u32 frame1519_rx;       /* Number of frames greater than 1518 bytes rx*/
	u32 usize_frames;       /* Frames received less than min of 64 bytes */
	u32 excess_length;      /* Number of excessive length frames rx */
	u32 jabbers;            /* Excessive length + crc or align errors. */
	u32 fcs_errors;         /* Number of frames received with crc errors */
	u32 length_check_errors;/* Number of frames with incorrect length */
	u32 rx_symbol_errors;   /* Number of times rx_er asserted during rx */
	u32 align_errors;       /* Frames received without integer no. bytes */
	u32 rx_res_errors;      /* Number of times buffers ran out during rx */
	u32 rx_orun;            /* Receive overrun errors due to DMA */
	u32 ip_cksum;           /* IP header checksum errors */
	u32 tcp_cksum;           /* TCP checksum errors */
	u32 udp_cksum;           /* UDP checksum errors */
};

#define EMAC_REG_SPACE sizeof(struct gemac_reg)
#define EMAC_RMON_LEN (sizeof(struct gemac_stats)/sizeof(u32))


struct pfe_eth_fast_timer {
	int queuenum;
	struct hrtimer timer;
	void * base;
};

typedef struct  pfe_eth_priv_s
{
	struct pfe 		*pfe;
	struct hif_client_s	client;
	struct napi_struct	lro_napi;
	struct napi_struct   	low_napi;
	struct napi_struct   	high_napi;
	int			low_tmuQ;
	int			high_tmuQ;
	struct net_device_stats stats;
	struct net_device 	*dev;
	int 			id;
	int 			promisc;
	unsigned int		msg_enable;
	unsigned int 		usr_features;

	spinlock_t 		lock;
	unsigned int 		event_status;
	int 			irq;
	void*   		EMAC_baseaddr;
	void*			PHY_baseaddr; /* This points to the EMAC base from where we access PHY */
	void*   		GPI_baseaddr;
	int			mdio_muxval;
	/* PHY stuff */
	struct phy_device 	*phydev;
	int 			oldspeed;
	int 			oldduplex;
	int 			oldlink;
	/* mdio info */
	int 			mdc_div;
	struct mii_bus 		*mii_bus;
	struct clk		*gemtx_clk;
	int				wol;

	int 			default_priority;
	struct timer_list	tx_timer;
	struct pfe_eth_fast_timer fast_tx_timeout[EMAC_TXQ_CNT];

	struct comcerto_eth_platform_data *einfo;
	struct sk_buff *skb_inflight[EMAC_RXQ_CNT + 6];

#ifdef PFE_ETH_LRO_STATS
	unsigned int lro_len_counters[LRO_LEN_COUNT_MAX];
	unsigned int lro_nb_counters[LRO_NB_COUNT_MAX]; //TODO change to exact max number when RX scatter done
#endif


#ifdef PFE_ETH_TX_STATS
	unsigned int stop_queue_total[EMAC_TXQ_CNT];
	unsigned int stop_queue_hif[EMAC_TXQ_CNT];
	unsigned int stop_queue_hif_client[EMAC_TXQ_CNT];
	unsigned int stop_queue_credit[EMAC_TXQ_CNT];
	unsigned int clean_fail[EMAC_TXQ_CNT];
	unsigned int was_stopped[EMAC_TXQ_CNT];
#endif

#ifdef PFE_ETH_NAPI_STATS
	unsigned int napi_counters[NAPI_MAX_COUNT];
#endif
	unsigned int frags_inflight[EMAC_RXQ_CNT + 6];

}pfe_eth_priv_t;

struct pfe_eth {
	struct pfe_eth_priv_s *eth_priv[3];
};

int pfe_eth_init(struct pfe *pfe);
void pfe_eth_exit(struct pfe *pfe);
int pfe_eth_suspend(struct net_device *dev);
int pfe_eth_resume(struct net_device *dev);
int pfe_eth_mdio_reset(struct mii_bus *bus);

/** pfe_compute_csum
 *
 */
static int inline pfe_compute_csum(struct sk_buff *skb)
{
	struct skb_shared_info *sh;
	unsigned int nr_frags;
	skb_frag_t *f;
	u32 csum = 0;
	int i;
	int len;

	/* Make sure that no intermediate buffers/fragments are odd byte aligned */
	if (skb_is_nonlinear(skb)) {
		int linearize = 0;

		sh = skb_shinfo(skb);
		nr_frags = sh->nr_frags;
		len = skb_headlen(skb) -  skb_transport_offset(skb);

		if (len & 0x1) {
			linearize = 1;
			//printk("#1 Odd length %d\n", len);
		}
		else {
			for (i = 0; i < nr_frags - 1; i++) {
				f = &sh->frags[i];
				len = skb_frag_size(f);

				if (len & 0x1) {
					linearize = 1;
					//printk("#2 %d Odd length %d\n", i, len);
					break;
				}
			}
		}

		if (linearize)
			if (skb_linearize(skb))
				return -1;
	}

	/* Compute checksum */
	if (!skb_is_nonlinear(skb)) {
		*(u16*)(skb_transport_header(skb) + skb->csum_offset) = csum_fold(csum_partial(skb_transport_header(skb), skb->len - skb_transport_offset(skb), 0));
	}
	else {
		sh = skb_shinfo(skb);
		nr_frags = sh->nr_frags;

		if (nr_frags) {
			csum = csum_partial(skb_transport_header(skb), skb_headlen(skb) -  skb_transport_offset(skb), 0);

			for (i = 0; i < nr_frags - 1; i++) {
				f = &sh->frags[i];
				csum = csum_partial(skb_frag_address(f),  skb_frag_size(f), csum);
			}

			f = &sh->frags[i];
			*(u16*)(skb_transport_header(skb) + skb->csum_offset) = csum_fold(csum_partial(skb_frag_address(f), skb_frag_size(f), csum));
		}
	}

	return 0;
}



#endif /* _PFE_ETH_H_ */
