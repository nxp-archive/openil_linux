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

/** @pfe_eth.c.
 *  Ethernet driver for to handle exception path for PFE.
 *  - uses HIF functions to send/receive packets.
 *  - uses ctrl function to start/stop interfaces.
 *  - uses direct register accesses to control phy operation.
 */
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/phy.h>
#include <linux/timer.h>
#include <linux/hrtimer.h>
#include <linux/platform_device.h>

#include <net/ip.h>
#include <net/sock.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/delay.h>
#include <linux/regmap.h>
#include <linux/i2c.h>

#if defined(CONFIG_NF_CONNTRACK_MARK)
#include <net/netfilter/nf_conntrack.h>
#endif

#include "pfe_mod.h"
#include "pfe_eth.h"

const char comcerto_eth_driver_version[]="1.0";
static void *cbus_emac_base[3];
static void *cbus_gpi_base[3];

/* Forward Declaration */
static void pfe_eth_exit_one(struct pfe_eth_priv_s *priv);
static void pfe_eth_flush_tx(struct pfe_eth_priv_s *priv, int force);
static void pfe_eth_flush_txQ(struct pfe_eth_priv_s *priv, int txQ_num, int from_tx, int n_desc);

#if defined(CONFIG_PLATFORM_C2000)
static void pfe_eth_set_device_wakeup(struct pfe *pfe);



unsigned int gemac_regs[] = {
	0x0000,	/* Network control */
	0x0004,	/* Network configuration */
	0x0008, /* Network status */
	0x0010, /* DMA configuration */
	0x0014, /* Transmit status */
	0x0020, /* Receive status */
	0x0024, /* Interrupt status */
	0x0030, /* Interrupt mask */
	0x0038, /* Received pause quantum */
	0x003c, /* Transmit pause quantum */
	0x0080, /* Hash register bottom [31:0] */
	0x0084, /* Hash register bottom [63:32] */
	0x0088, /* Specific address 1 bottom [31:0] */
	0x008c, /* Specific address 1 top [47:32] */
	0x0090, /* Specific address 2 bottom [31:0] */
	0x0094, /* Specific address 2 top [47:32] */
	0x0098, /* Specific address 3 bottom [31:0] */
	0x009c, /* Specific address 3 top [47:32] */
	0x00a0, /* Specific address 4 bottom [31:0] */
	0x00a4, /* Specific address 4 top [47:32] */
	0x00a8, /* Type ID Match 1 */
	0x00ac, /* Type ID Match 2 */
	0x00b0, /* Type ID Match 3 */
	0x00b4, /* Type ID Match 4 */
	0x00b8, /* Wake Up ON LAN  */
	0x00bc, /* IPG stretch register */
	0x00c0, /* Stacked VLAN Register */
	0x00fc, /* Module ID */
	0x07a0  /* EMAC Control register */
};
#else
unsigned int gemac_regs[] = {
	0x0004, /*Interrupt event */
	0x0008, /*Interrupt mask */
	0x0024, /*Ethernet control */
	0x0064, /*MIB Control/Status */
	0x0084, /*Receive control/status */
	0x00C4, /*Transmit control */
	0x00E4, /*Physical address low */
	0x00E8, /*Physical address high */
	0x0144, /*Transmit FIFO Watermark and Store and Forward Control*/
	0x0190, /* Receive FIFO Section Full Threshold */
	0x01A0, /* Transmit FIFO Section Empty Threshold */
	0x01B0, /* Frame Truncation Length */
};
#endif
/********************************************************************/
/*                   SYSFS INTERFACE				    */
/********************************************************************/



#ifdef PFE_ETH_NAPI_STATS
/*
 * pfe_eth_show_napi_stats
 */
static ssize_t pfe_eth_show_napi_stats(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct pfe_eth_priv_s *priv = netdev_priv(to_net_dev(dev));
	ssize_t len = 0;

	len += sprintf(buf + len, "sched:  %u\n", priv->napi_counters[NAPI_SCHED_COUNT]);
	len += sprintf(buf + len, "poll:   %u\n", priv->napi_counters[NAPI_POLL_COUNT]);
	len += sprintf(buf + len, "packet: %u\n", priv->napi_counters[NAPI_PACKET_COUNT]);
	len += sprintf(buf + len, "budget: %u\n", priv->napi_counters[NAPI_FULL_BUDGET_COUNT]);
	len += sprintf(buf + len, "desc:   %u\n", priv->napi_counters[NAPI_DESC_COUNT]);

	return len;
}

/*
 * pfe_eth_set_napi_stats
 */
static ssize_t pfe_eth_set_napi_stats(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct pfe_eth_priv_s *priv = netdev_priv(to_net_dev(dev));

	memset(priv->napi_counters, 0, sizeof(priv->napi_counters));

	return count;
}
#endif
#ifdef PFE_ETH_TX_STATS
/** pfe_eth_show_tx_stats
 *
 */
static ssize_t pfe_eth_show_tx_stats(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct pfe_eth_priv_s *priv = netdev_priv(to_net_dev(dev));
	ssize_t len = 0;
	int i;

	len += sprintf(buf + len, "TX queues stats:\n");

	for (i = 0; i < emac_txq_cnt; i++) {
		struct netdev_queue *tx_queue = netdev_get_tx_queue(priv->dev, i); 

		len += sprintf(buf + len, "\n");
		__netif_tx_lock_bh(tx_queue);

		hif_tx_lock(&pfe->hif);
		len += sprintf(buf + len, "Queue %2d :  credits               = %10d\n", i, hif_lib_tx_credit_avail(pfe, priv->id, i));
		len += sprintf(buf + len, "            tx packets            = %10d\n",  pfe->tmu_credit.tx_packets[priv->id][i]);
		hif_tx_unlock(&pfe->hif);

		/* Don't output additionnal stats if queue never used */
		if (!pfe->tmu_credit.tx_packets[priv->id][i])
			goto skip;

		len += sprintf(buf + len, "            clean_fail            = %10d\n", priv->clean_fail[i]);
		len += sprintf(buf + len, "            stop_queue            = %10d\n", priv->stop_queue_total[i]);
		len += sprintf(buf + len, "            stop_queue_hif        = %10d\n", priv->stop_queue_hif[i]);
		len += sprintf(buf + len, "            stop_queue_hif_client = %10d\n", priv->stop_queue_hif_client[i]);
		len += sprintf(buf + len, "            stop_queue_credit     = %10d\n", priv->stop_queue_credit[i]);
skip:
		__netif_tx_unlock_bh(tx_queue);
	}
	return len;
}

/** pfe_eth_set_tx_stats
 *
 */
static ssize_t pfe_eth_set_tx_stats(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct pfe_eth_priv_s *priv = netdev_priv(to_net_dev(dev));
	int i;

	for (i = 0; i < emac_txq_cnt; i++) {
		struct netdev_queue *tx_queue = netdev_get_tx_queue(priv->dev, i); 

		__netif_tx_lock_bh(tx_queue);
		priv->clean_fail[i] = 0;
		priv->stop_queue_total[i] = 0;
		priv->stop_queue_hif[i] = 0;
		priv->stop_queue_hif_client[i]= 0;
		priv->stop_queue_credit[i] = 0;
		__netif_tx_unlock_bh(tx_queue);
	}

	return count;
}
#endif
/** pfe_eth_show_txavail
 *
 */
static ssize_t pfe_eth_show_txavail(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct pfe_eth_priv_s *priv = netdev_priv(to_net_dev(dev));
	ssize_t len = 0;
	int i;

	for (i = 0; i < emac_txq_cnt; i++) {
		struct netdev_queue *tx_queue = netdev_get_tx_queue(priv->dev, i); 

		__netif_tx_lock_bh(tx_queue);

		len += sprintf(buf + len, "%d", hif_lib_tx_avail(&priv->client, i));

		__netif_tx_unlock_bh(tx_queue);

		if (i == (emac_txq_cnt - 1))
			len += sprintf(buf + len, "\n");
		else
			len += sprintf(buf + len, " ");
	}

	return len;
}


/** pfe_eth_show_default_priority
 *
 */ 
static ssize_t pfe_eth_show_default_priority(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct pfe_eth_priv_s *priv = netdev_priv(to_net_dev(dev));
	unsigned long flags;
	int rc;

	spin_lock_irqsave(&priv->lock, flags);
	rc = sprintf(buf, "%d\n", priv->default_priority);
	spin_unlock_irqrestore(&priv->lock, flags);

	return rc;
}

/** pfe_eth_set_default_priority
 *
 */

static ssize_t pfe_eth_set_default_priority(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct pfe_eth_priv_s *priv = netdev_priv(to_net_dev(dev));
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	priv->default_priority = simple_strtoul(buf, NULL, 0);
	spin_unlock_irqrestore(&priv->lock, flags);

	return count;
}

static DEVICE_ATTR(txavail, 0444, pfe_eth_show_txavail, NULL);
static DEVICE_ATTR(default_priority, 0644, pfe_eth_show_default_priority, pfe_eth_set_default_priority);

#ifdef PFE_ETH_NAPI_STATS
static DEVICE_ATTR(napi_stats, 0644, pfe_eth_show_napi_stats, pfe_eth_set_napi_stats);
#endif

#ifdef PFE_ETH_TX_STATS
static DEVICE_ATTR(tx_stats, 0644, pfe_eth_show_tx_stats, pfe_eth_set_tx_stats);
#endif


/** pfe_eth_sysfs_init
 *
 */
static int pfe_eth_sysfs_init(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	int err;

	/* Initialize the default values */
	/* By default, packets without conntrack will use this default high priority queue */
	priv->default_priority = 15;

	/* Create our sysfs files */
	err = device_create_file(&dev->dev, &dev_attr_default_priority);
	if (err) {
		netdev_err(dev, "failed to create default_priority sysfs files\n");
		goto err_priority;
	}

	err = device_create_file(&dev->dev, &dev_attr_txavail);
	if (err) {
		netdev_err(dev, "failed to create default_priority sysfs files\n");
		goto err_txavail;
	}

#ifdef PFE_ETH_NAPI_STATS
	err = device_create_file(&dev->dev, &dev_attr_napi_stats);
	if (err) {
		netdev_err(dev, "failed to create napi stats sysfs files\n");
		goto err_napi;
	}
#endif

#ifdef PFE_ETH_TX_STATS
	err = device_create_file(&dev->dev, &dev_attr_tx_stats);
	if (err) {
		netdev_err(dev, "failed to create tx stats sysfs files\n");
		goto err_tx;
	}
#endif

	return 0;

#ifdef PFE_ETH_TX_STATS
err_tx:
#endif
#ifdef PFE_ETH_NAPI_STATS
	device_remove_file(&dev->dev, &dev_attr_napi_stats);

err_napi:
#endif
	device_remove_file(&dev->dev, &dev_attr_txavail);

err_txavail:
	device_remove_file(&dev->dev, &dev_attr_default_priority);

err_priority:
	return -1;
}

/** pfe_eth_sysfs_exit
 *
 */
void pfe_eth_sysfs_exit(struct net_device *dev)
{
#ifdef PFE_ETH_TX_STATS
	device_remove_file(&dev->dev, &dev_attr_tx_stats);
#endif

#ifdef PFE_ETH_NAPI_STATS
	device_remove_file(&dev->dev, &dev_attr_napi_stats);
#endif
	device_remove_file(&dev->dev, &dev_attr_txavail);
	device_remove_file(&dev->dev, &dev_attr_default_priority);
}

/*************************************************************************/
/*		ETHTOOL INTERCAE					 */
/*************************************************************************/

#if defined(CONFIG_PLATFORM_C2000)
static char stat_gstrings[][ETH_GSTRING_LEN] = {
	"tx- octets",
	"tx- packets",
	"tx- broadcast",
	"tx- multicast",
	"tx- pause",
	"tx- 64 bytes packets",
	"tx- 64 - 127 bytes packets",
	"tx- 128 - 255 bytes packets",
	"tx- 256 - 511 bytes packets",
	"tx- 512 - 1023 bytes packets",
	"tx- 1024 - 1518 bytes packets",
	"tx- > 1518 bytes packets",
	"tx- underruns  - errors",
	"tx- single collision",
	"tx- multi collision",
	"tx- exces. collision  - errors",
	"tx- late collision  - errors",
	"tx- deferred",
	"tx- carrier sense - errors",
	"rx- octets",
	"rx- packets",
	"rx- broadcast",
	"rx- multicast",
	"rx- pause",
	"rx- 64 bytes packets",
	"rx- 64 - 127 bytes packets",
	"rx- 128 - 255 bytes packets",
	"rx- 256 - 511 bytes packets",
	"rx- 512 - 1023 bytes packets",
	"rx- 1024 - 1518 bytes packets",
	"rx- > 1518 bytes packets",
	"rx- undersize -errors",
	"rx- oversize  - errors ",
	"rx- jabbers - errors",
	"rx- fcs - errors",
	"rx- length - errors",
	"rx- symbol - errors",
	"rx- align - errors",
	"rx- ressource - errors",
	"rx- overrun - errors",
	"rx- IP cksum - errors",
	"rx- TCP cksum - errors",
	"rx- UDP cksum - errors"
};


/**
 * pfe_eth_gstrings - Fill in a buffer with the strings which correspond to
 *                    the stats.
 *
 */
static void pfe_eth_gstrings(struct net_device *dev, u32 stringset, u8 * buf)
{
	switch (stringset) {
		case ETH_SS_STATS:
			memcpy(buf, stat_gstrings, (EMAC_RMON_LEN - 2) * ETH_GSTRING_LEN);
			break;

		default:
			WARN_ON(1);
			break;
	}
}

/** 
 * pfe_eth_fill_stats - Fill in an array of 64-bit statistics from 
 *			various sources. This array will be appended 
 *			to the end of the ethtool_stats* structure, and 
 *			returned to user space
 */
static void pfe_eth_fill_stats(struct net_device *dev, struct ethtool_stats *dummy, u64 * buf)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	int i;
	for (i=0;i<EMAC_RMON_LEN;i++, buf++) {
		*buf = readl(priv->EMAC_baseaddr + EMAC_RMON_BASE_OFST + (i << 2));	
		if ( ( i == EMAC_RMON_TXBYTES_POS ) || ( i == EMAC_RMON_RXBYTES_POS ) ){
			i++;
			*buf |= (u64)readl(priv->EMAC_baseaddr + EMAC_RMON_BASE_OFST + (i << 2)) << 32;
		}
	}

}

/**
 * pfe_eth_stats_count - Returns the number of stats (and their corresponding strings) 
 *
 */
static int pfe_eth_stats_count(struct net_device *dev, int sset)
{
	switch (sset) {
		case ETH_SS_STATS:
			return EMAC_RMON_LEN - 2;
		default:
			return -EOPNOTSUPP;
	}
}

#if defined(CONFIG_PLATFORM_C2000)
/**
 * pfe_eth_set_wol - Set the magic packet option, in WoL register.
 *
 */
static int pfe_eth_set_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	if (wol->wolopts & ~(WAKE_MAGIC | WAKE_ARP | WAKE_MCAST | WAKE_UCAST))
		return -EOPNOTSUPP;

	priv->wol = 0;

	if (wol->wolopts & WAKE_MAGIC)
		 priv->wol |= EMAC_WOL_MAGIC;
	if (wol->wolopts & WAKE_ARP)
		 priv->wol |= EMAC_WOL_ARP;
	if (wol->wolopts & WAKE_MCAST)
		 priv->wol |= EMAC_WOL_MULTI;
	if (wol->wolopts & WAKE_UCAST)
		 priv->wol |= EMAC_WOL_SPEC_ADDR;

	pfe_eth_set_device_wakeup(priv->pfe);

	return 0;
}

/**
 *
 * pfe_eth_get_wol - Get the WoL options.
 *
 */
static void pfe_eth_get_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	wol->supported = (WAKE_MAGIC | WAKE_ARP | WAKE_MCAST | WAKE_UCAST);
	wol->wolopts = 0;

	if(priv->wol & EMAC_WOL_MAGIC)
		wol->wolopts |= WAKE_MAGIC;
	if(priv->wol & EMAC_WOL_ARP)
		wol->wolopts |= WAKE_ARP;
	if(priv->wol & EMAC_WOL_MULTI)
		wol->wolopts |= WAKE_UCAST;
	if(priv->wol & EMAC_WOL_SPEC_ADDR)
		wol->wolopts |= WAKE_UCAST;

	memset(&wol->sopass, 0, sizeof(wol->sopass));
}
#endif
/**
 * pfe_eth_gemac_reglen - Return the length of the register structure.
 *
 */
static int pfe_eth_gemac_reglen(struct net_device *dev)
{
	return (sizeof (gemac_regs)/ sizeof(u32)) + (( MAX_UC_SPEC_ADDR_REG - 3 ) * 2);
}

/**
 * pfe_eth_gemac_get_regs - Return the gemac register structure.
 *
 */
static void  pfe_eth_gemac_get_regs(struct net_device *dev, struct ethtool_regs *regs, void *regbuf)
{
	int i,j;
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	u32 *buf = (u32 *) regbuf;

	for (i = 0; i < sizeof (gemac_regs) / sizeof (u32); i++)
		buf[i] = readl( priv->EMAC_baseaddr + gemac_regs[i] );

	for (j = 0; j < (( MAX_UC_SPEC_ADDR_REG - 3 ) * 2); j++,i++)
		buf[i] = readl( priv->EMAC_baseaddr + EMAC_SPEC5_ADD_BOT + (j<<2) );

}


#else //if defined(CONFIG_PLATFORM_C2000)
/*MTIP GEMAC */
static const struct fec_stat {
	char name[ETH_GSTRING_LEN];
	u16 offset;
} fec_stats[] = {
	/* RMON TX */
	{ "tx_dropped", RMON_T_DROP },
	{ "tx_packets", RMON_T_PACKETS },
	{ "tx_broadcast", RMON_T_BC_PKT },
	{ "tx_multicast", RMON_T_MC_PKT },
	{ "tx_crc_errors", RMON_T_CRC_ALIGN },
	{ "tx_undersize", RMON_T_UNDERSIZE },
	{ "tx_oversize", RMON_T_OVERSIZE },
	{ "tx_fragment", RMON_T_FRAG },
	{ "tx_jabber", RMON_T_JAB },
	{ "tx_collision", RMON_T_COL },
	{ "tx_64byte", RMON_T_P64 },
	{ "tx_65to127byte", RMON_T_P65TO127 },
	{ "tx_128to255byte", RMON_T_P128TO255 },
	{ "tx_256to511byte", RMON_T_P256TO511 },
	{ "tx_512to1023byte", RMON_T_P512TO1023 },
	{ "tx_1024to2047byte", RMON_T_P1024TO2047 },
	{ "tx_GTE2048byte", RMON_T_P_GTE2048 },
	{ "tx_octets", RMON_T_OCTETS },

	/* IEEE TX */
	{ "IEEE_tx_drop", IEEE_T_DROP },
	{ "IEEE_tx_frame_ok", IEEE_T_FRAME_OK },
	{ "IEEE_tx_1col", IEEE_T_1COL },
	{ "IEEE_tx_mcol", IEEE_T_MCOL },
	{ "IEEE_tx_def", IEEE_T_DEF },
	{ "IEEE_tx_lcol", IEEE_T_LCOL },
	{ "IEEE_tx_excol", IEEE_T_EXCOL },
	{ "IEEE_tx_macerr", IEEE_T_MACERR },
	{ "IEEE_tx_cserr", IEEE_T_CSERR },
	{ "IEEE_tx_sqe", IEEE_T_SQE },
	{ "IEEE_tx_fdxfc", IEEE_T_FDXFC },
	{ "IEEE_tx_octets_ok", IEEE_T_OCTETS_OK },

	/* RMON RX */
	{ "rx_packets", RMON_R_PACKETS },
	{ "rx_broadcast", RMON_R_BC_PKT },
	{ "rx_multicast", RMON_R_MC_PKT },
	{ "rx_crc_errors", RMON_R_CRC_ALIGN },
	{ "rx_undersize", RMON_R_UNDERSIZE },
	{ "rx_oversize", RMON_R_OVERSIZE },
	{ "rx_fragment", RMON_R_FRAG },
	{ "rx_jabber", RMON_R_JAB },
	{ "rx_64byte", RMON_R_P64 },
	{ "rx_65to127byte", RMON_R_P65TO127 },
	{ "rx_128to255byte", RMON_R_P128TO255 },
	{ "rx_256to511byte", RMON_R_P256TO511 },
	{ "rx_512to1023byte", RMON_R_P512TO1023 },
	{ "rx_1024to2047byte", RMON_R_P1024TO2047 },
	{ "rx_GTE2048byte", RMON_R_P_GTE2048 },
	{ "rx_octets", RMON_R_OCTETS },

	/* IEEE RX */
	{ "IEEE_rx_drop", IEEE_R_DROP },
	{ "IEEE_rx_frame_ok", IEEE_R_FRAME_OK },
	{ "IEEE_rx_crc", IEEE_R_CRC },
	{ "IEEE_rx_align", IEEE_R_ALIGN },
	{ "IEEE_rx_macerr", IEEE_R_MACERR },
	{ "IEEE_rx_fdxfc", IEEE_R_FDXFC },
	{ "IEEE_rx_octets_ok", IEEE_R_OCTETS_OK },
};

static void pfe_eth_fill_stats(struct net_device *dev, struct ethtool_stats *stats, u64 *data)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < ARRAY_SIZE(fec_stats); i++)
		data[i] = readl(priv->EMAC_baseaddr + fec_stats[i].offset);
}

static void pfe_eth_gstrings(struct net_device *netdev,
	u32 stringset, u8 *data)
{
	int i;
	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < ARRAY_SIZE(fec_stats); i++)
			memcpy(data + i * ETH_GSTRING_LEN,
				fec_stats[i].name, ETH_GSTRING_LEN);
		break;
	}
}

static int pfe_eth_stats_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(fec_stats);
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * pfe_eth_gemac_reglen - Return the length of the register structure.
 *
 */
static int pfe_eth_gemac_reglen(struct net_device *dev)
{
	printk("%s() \n", __func__);
	return (sizeof (gemac_regs)/ sizeof(u32)) ;
}

/**
 * pfe_eth_gemac_get_regs - Return the gemac register structure.
 *
 */
static void  pfe_eth_gemac_get_regs(struct net_device *dev, struct ethtool_regs *regs, void *regbuf)
{
	int i;
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	u32 *buf = (u32 *) regbuf;

	printk("%s() \n", __func__);
	for (i = 0; i < sizeof (gemac_regs) / sizeof (u32); i++)
		buf[i] = readl( priv->EMAC_baseaddr + gemac_regs[i] );

}


#endif

/**
 * pfe_eth_get_drvinfo -  Fills in the drvinfo structure with some basic info 
 *
 */
static void pfe_eth_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *drvinfo)
{
	strncpy(drvinfo->driver, DRV_NAME, COMCERTO_INFOSTR_LEN);
	strncpy(drvinfo->version, comcerto_eth_driver_version, COMCERTO_INFOSTR_LEN);
	strncpy(drvinfo->fw_version, "N/A", COMCERTO_INFOSTR_LEN);
	strncpy(drvinfo->bus_info, "N/A", COMCERTO_INFOSTR_LEN);
	drvinfo->testinfo_len = 0;
	drvinfo->regdump_len = 0;
	drvinfo->eedump_len = 0;
}

/**
 * pfe_eth_set_settings - Used to send commands to PHY. 
 *
 */

static int pfe_eth_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	struct phy_device *phydev = priv->phydev;

	if (NULL == phydev)
		return -ENODEV;

	return phy_ethtool_sset(phydev, cmd);
}


/**
 * pfe_eth_getsettings - Return the current settings in the ethtool_cmd structure.
 *
 */
static int pfe_eth_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	struct phy_device *phydev = priv->phydev;

	if (NULL == phydev)
		return -ENODEV;

	return phy_ethtool_gset(phydev, cmd);
}


/**
 * pfe_eth_get_msglevel - Gets the debug message mask.
 *
 */
static uint32_t pfe_eth_get_msglevel(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	return priv->msg_enable;
}

/**
 * pfe_eth_set_msglevel - Sets the debug message mask.
 *
 */
static void pfe_eth_set_msglevel(struct net_device *dev, uint32_t data)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	priv->msg_enable = data;
}

#define HIF_RX_COAL_MAX_CLKS		(~(1<<31))
#define HIF_RX_COAL_CLKS_PER_USEC	(pfe->ctrl.sys_clk/1000)
#define HIF_RX_COAL_MAX_USECS		(HIF_RX_COAL_MAX_CLKS/HIF_RX_COAL_CLKS_PER_USEC)

/**
 * pfe_eth_set_coalesce - Sets rx interrupt coalescing timer.
 *
 */
static int pfe_eth_set_coalesce(struct net_device *dev,
                              struct ethtool_coalesce *ec)
{
	if (ec->rx_coalesce_usecs > HIF_RX_COAL_MAX_USECS)
		  return -EINVAL;

	if (!ec->rx_coalesce_usecs) {
		writel(0, HIF_INT_COAL);
		return 0;
	}

	writel((ec->rx_coalesce_usecs * HIF_RX_COAL_CLKS_PER_USEC) | HIF_INT_COAL_ENABLE, HIF_INT_COAL);

	return 0;
}

/**
 * pfe_eth_get_coalesce - Gets rx interrupt coalescing timer value.
 *
 */
static int pfe_eth_get_coalesce(struct net_device *dev,
                              struct ethtool_coalesce *ec)
{
	int reg_val = readl(HIF_INT_COAL);

	if (reg_val & HIF_INT_COAL_ENABLE)
		ec->rx_coalesce_usecs = (reg_val & HIF_RX_COAL_MAX_CLKS) / HIF_RX_COAL_CLKS_PER_USEC;
	else
		ec->rx_coalesce_usecs = 0;

        return 0;
}

#if defined(CONFIG_PLATFORM_C2000)
/**
 * pfe_eth_pause_rx_enabled - Tests if pause rx is enabled on GEM
 *
 */
static int pfe_eth_pause_rx_enabled(struct pfe_eth_priv_s *priv)
{
	return (readl(priv->EMAC_baseaddr + EMAC_NETWORK_CONFIG) & EMAC_ENABLE_PAUSE_RX) != 0;
}

/**
 * pfe_eth_set_pauseparam - Sets pause parameters
 *
 */
static int pfe_eth_set_pauseparam(struct net_device *dev, struct ethtool_pauseparam *epause)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	if (epause->rx_pause)
	{
		gemac_enable_pause_rx(priv->EMAC_baseaddr);
		if (priv->phydev)
			priv->phydev->advertising |= ADVERTISED_Pause | ADVERTISED_Asym_Pause;
	}
	else
	{
		gemac_disable_pause_rx(priv->EMAC_baseaddr);
		if (priv->phydev)
			priv->phydev->advertising &= ~(ADVERTISED_Pause | ADVERTISED_Asym_Pause);
	}

	return 0;
}

/**
 * pfe_eth_get_pauseparam - Gets pause parameters
 *
 */
static void pfe_eth_get_pauseparam(struct net_device *dev, struct ethtool_pauseparam *epause)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	epause->autoneg = 0;
	epause->tx_pause = 0;
	epause->rx_pause = pfe_eth_pause_rx_enabled(priv);
}

/** pfe_eth_get_hash
 */
static int pfe_eth_get_hash(u8 * addr)
{
	u8 temp1,temp2,temp3,temp4,temp5,temp6,temp7,temp8;
	temp1 = addr[0] & 0x3F ;
	temp2 = ((addr[0] & 0xC0)  >> 6)| ((addr[1] & 0x0F) << 2);
	temp3 = ((addr[1] & 0xF0) >> 4) | ((addr[2] & 0x03) << 4);
	temp4 = (addr[2] & 0xFC) >> 2;
	temp5 = addr[3] & 0x3F;
	temp6 = ((addr[3] & 0xC0) >> 6) | ((addr[4] & 0x0F) << 2);
	temp7 = ((addr[4] & 0xF0) >>4 ) | ((addr[5] & 0x03) << 4);
	temp8 = ((addr[5] &0xFC) >> 2);
	return (temp1 ^ temp2 ^ temp3 ^ temp4 ^ temp5 ^ temp6 ^ temp7 ^ temp8);
}

#else
	/*TODO Add pause frame support for LS1012A */

/** pfe_eth_get_hash
 */
#define HASH_BITS	6		/* #bits in hash */
#define CRC32_POLY	0xEDB88320

static int pfe_eth_get_hash(u8 * addr)
{
	unsigned int i, bit, data, crc, hash;

	/* calculate crc32 value of mac address */
	crc = 0xffffffff;

	for (i = 0; i < 6; i++) {
		data = addr[i];
		for (bit = 0; bit < 8; bit++, data >>= 1) {
			crc = (crc >> 1) ^
				(((crc ^ data) & 1) ? CRC32_POLY : 0);
		}
	}

	/* only upper 6 bits (HASH_BITS) are used
	 * which point to specific bit in he hash registers
	 */
	hash = (crc >> (32 - HASH_BITS)) & 0x3f;

	return hash;
}

#endif

struct ethtool_ops pfe_ethtool_ops = {
	.get_settings = pfe_eth_get_settings,
	.set_settings = pfe_eth_set_settings,
	.get_drvinfo = pfe_eth_get_drvinfo,
	.get_regs_len = pfe_eth_gemac_reglen,
	.get_regs = pfe_eth_gemac_get_regs,
	.get_link = ethtool_op_get_link,
#if defined(CONFIG_PLATFORM_C2000)
	.get_wol  = pfe_eth_get_wol,
	.set_wol  = pfe_eth_set_wol,
	.set_pauseparam = pfe_eth_set_pauseparam,
	.get_pauseparam = pfe_eth_get_pauseparam,
#endif
	.get_strings = pfe_eth_gstrings,
	.get_sset_count = pfe_eth_stats_count,
	.get_ethtool_stats = pfe_eth_fill_stats,
	.get_msglevel = pfe_eth_get_msglevel,
	.set_msglevel = pfe_eth_set_msglevel,
	.set_coalesce = pfe_eth_set_coalesce,
	.get_coalesce = pfe_eth_get_coalesce,
};



#if defined(CONFIG_PLATFORM_C2000)
/** pfe_eth_mdio_reset
 */
int pfe_eth_mdio_reset(struct mii_bus *bus)
{
	struct pfe_eth_priv_s *priv = (struct pfe_eth_priv_s *)bus->priv;

	netif_info(priv, hw, priv->dev, "%s\n", __func__);

#if !defined(CONFIG_PLATFORM_EMULATION)
	mutex_lock(&bus->mdio_lock);

	/* Setup the MII Mgmt clock speed */
	if (priv->mii_bus)
		gemac_set_mdc_div(priv->EMAC_baseaddr, priv->mdc_div);

	/* Reset the management interface */
	__raw_writel(__raw_readl(priv->EMAC_baseaddr + EMAC_NETWORK_CONTROL) | EMAC_MDIO_EN, 
			priv->EMAC_baseaddr + EMAC_NETWORK_CONTROL);

	/* Wait until the bus is free */
	while(!(__raw_readl(priv->EMAC_baseaddr + EMAC_NETWORK_STATUS) & EMAC_PHY_IDLE));

	mutex_unlock(&bus->mdio_lock);
#endif

	return 0;
}


/** pfe_eth_gemac_phy_timeout
 *
 */
static int pfe_eth_gemac_phy_timeout(struct pfe_eth_priv_s *priv, int timeout)
{
	while(!(__raw_readl(priv->EMAC_baseaddr + EMAC_NETWORK_STATUS) & EMAC_PHY_IDLE)) {

		if (timeout-- <= 0) {
			return -1;
		}

		udelay(10);
	}

	return 0;
}


/** pfe_eth_mdio_write
 */
static int pfe_eth_mdio_write(struct mii_bus *bus, int mii_id, int regnum, u16 value)
{
	struct pfe_eth_priv_s *priv = (struct pfe_eth_priv_s *)bus->priv;
	u32 write_data;

#if !defined(CONFIG_PLATFORM_EMULATION)

	netif_info(priv, hw, priv->dev, "%s: phy %d\n", __func__, mii_id);

//	netif_info(priv, hw, priv->dev, "%s %d %d %x\n", bus->id, mii_id, regnum, value);

	write_data = 0x50020000;
	write_data |= ((mii_id << 23) | (regnum << 18) | value);
	__raw_writel(write_data, priv->EMAC_baseaddr + EMAC_PHY_MANAGEMENT);

	if (pfe_eth_gemac_phy_timeout(priv, EMAC_MDIO_TIMEOUT)){
		netdev_err(priv->dev, "%s: phy MDIO write timeout\n", __func__);
		return -1;
	}

#endif

	return 0;
}


/** pfe_eth_mdio_read
 */
static int pfe_eth_mdio_read(struct mii_bus *bus, int mii_id, int regnum)
{
	struct pfe_eth_priv_s *priv = (struct pfe_eth_priv_s *)bus->priv;
	u16 value = 0;
	u32 write_data;

#if !defined(CONFIG_PLATFORM_EMULATION)
	netif_info(priv, hw, priv->dev, "%s: phy %d\n", __func__, mii_id);

	write_data = 0x60020000;
	write_data |= ((mii_id << 23) | (regnum << 18));

	__raw_writel(write_data, priv->EMAC_baseaddr + EMAC_PHY_MANAGEMENT);

	if (pfe_eth_gemac_phy_timeout( priv, EMAC_MDIO_TIMEOUT))	{
		netdev_err(priv->dev, "%s: phy MDIO read timeout\n", __func__);
		return -1;	
	}

	value = __raw_readl(priv->EMAC_baseaddr + EMAC_PHY_MANAGEMENT) & 0xFFFF;
#endif

//	netif_info(priv, hw, priv->dev, "%s %d %d %x\n", bus->id, mii_id, regnum, value);

	return value;
}

#else
/** pfe_eth_mdio_reset
 */
int pfe_eth_mdio_reset(struct mii_bus *bus)
{
	struct pfe_eth_priv_s *priv = (struct pfe_eth_priv_s *)bus->priv;
	u32 phy_speed, pclk = 250000000; /*TODO this needs to be checked read from the correct source*/

	netif_info(priv, hw, priv->dev, "%s\n", __func__);

	mutex_lock(&bus->mdio_lock);

	/*
	 * Set MII speed to 2.5 MHz (= clk_get_rate() / 2 * phy_speed)
	 *
	 * The formula for FEC MDC is 'ref_freq / (MII_SPEED x 2)' while
	 * for ENET-MAC is 'ref_freq / ((MII_SPEED + 1) x 2)'.
	 */
	phy_speed = (DIV_ROUND_UP(pclk, 4000000) << EMAC_MII_SPEED_SHIFT);
	phy_speed |= EMAC_HOLDTIME(0x5);
	__raw_writel(phy_speed, priv->PHY_baseaddr + EMAC_MII_CTRL_REG);

	mutex_unlock(&bus->mdio_lock);

	return 0;
}

/** pfe_eth_gemac_phy_timeout
 *
 */
static int pfe_eth_gemac_phy_timeout(struct pfe_eth_priv_s *priv, int timeout)
{
	while(!(__raw_readl(priv->PHY_baseaddr + EMAC_IEVENT_REG) & EMAC_IEVENT_MII)) {

		if (timeout-- <= 0) {
			return -1;
		}

		udelay(10);
	}
	__raw_writel(EMAC_IEVENT_MII, priv->PHY_baseaddr + EMAC_IEVENT_REG);

	return 0;
}

static int pfe_eth_mdio_mux(u8 muxval)
{
	struct i2c_adapter *a;
	struct i2c_msg msg;
	unsigned char buf[2];
	int ret;

	a = i2c_get_adapter(0);
        if (!a)
                return -ENODEV;

        /* set bit 1 (the second bit) of chip at 0x09, register 0x13 */
        buf[0] = 0x54; //reg number
        buf[1] = (muxval << 6)| 0x3; //data
        msg.addr = 0x66;
        msg.buf = buf;
        msg.len = 2;
        msg.flags = 0;
        ret = i2c_transfer(a, &msg, 1);
	i2c_put_adapter(a);
        if (ret != 1)
                return -ENODEV;
	return 0;


}

static int pfe_eth_mdio_write(struct mii_bus *bus, int mii_id, int regnum, u16 value)
{
	struct pfe_eth_priv_s *priv = (struct pfe_eth_priv_s *)bus->priv;

	/*FIXME Dirty hack to configure mux */
	if(priv->mdio_muxval) {
		if(mii_id == 0x1)
			pfe_eth_mdio_mux(0x1);
		else
			pfe_eth_mdio_mux(0x2);
	}

	/* start a write op */
	__raw_writel(EMAC_MII_DATA_ST | EMAC_MII_DATA_OP_WR |
			EMAC_MII_DATA_PA(mii_id) | EMAC_MII_DATA_RA(regnum) |
			EMAC_MII_DATA_TA | EMAC_MII_DATA(value),
			priv->PHY_baseaddr + EMAC_MII_DATA_REG);

	if (pfe_eth_gemac_phy_timeout(priv, EMAC_MDIO_TIMEOUT)){
		netdev_err(priv->dev, "%s: phy MDIO write timeout\n", __func__);
		return -1;
	}
	netif_info(priv, hw, priv->dev, "%s: phy %x reg %x val %x\n", __func__, mii_id, regnum, value);

	return 0;


}
static int pfe_eth_mdio_read(struct mii_bus *bus, int mii_id, int regnum)
{
	struct pfe_eth_priv_s *priv = (struct pfe_eth_priv_s *)bus->priv;
	u16 value = 0;

	/*FIXME Dirty hack to configure mux */
	if(priv->mdio_muxval){
		if(mii_id == 0x1)
			pfe_eth_mdio_mux(0x1);
		else
			pfe_eth_mdio_mux(0x2);
	}

	/* start a read op */
	__raw_writel(EMAC_MII_DATA_ST | EMAC_MII_DATA_OP_RD |
			EMAC_MII_DATA_PA(mii_id) | EMAC_MII_DATA_RA(regnum) |
			EMAC_MII_DATA_TA, priv->PHY_baseaddr + EMAC_MII_DATA_REG);

	if (pfe_eth_gemac_phy_timeout( priv, EMAC_MDIO_TIMEOUT))	{
		netdev_err(priv->dev, "%s: phy MDIO read timeout\n", __func__);
		return -1;
	}

	value = EMAC_MII_DATA(__raw_readl(priv->PHY_baseaddr + EMAC_MII_DATA_REG));
	netif_info(priv, hw, priv->dev, "%s: phy %x reg %x val %x\n", __func__, mii_id, regnum, value);
	return value;
}
#endif
static int pfe_eth_mdio_init(struct pfe_eth_priv_s *priv, struct comcerto_mdio_platform_data *minfo)
{
	struct mii_bus *bus;
	int rc;

	netif_info(priv, drv, priv->dev, "%s\n", __func__);
	printk( "%s\n", __func__);

#if !defined(CONFIG_PLATFORM_EMULATION) 
	bus = mdiobus_alloc();
	if (!bus) {
		netdev_err(priv->dev, "mdiobus_alloc() failed\n");
		rc = -ENOMEM;
		goto err0;
	}

	bus->name = "Comcerto MDIO Bus";
	bus->read = &pfe_eth_mdio_read;
	bus->write = &pfe_eth_mdio_write;
	bus->reset = &pfe_eth_mdio_reset;
	snprintf(bus->id, MII_BUS_ID_SIZE, "comcerto-%x", priv->id);
	bus->priv = priv;

	bus->phy_mask = minfo->phy_mask;
	priv->mdc_div = minfo->mdc_div;

	if (!priv->mdc_div)
		priv->mdc_div = 64;

	bus->irq = minfo->irq;

	bus->parent = priv->pfe->dev;

	netif_info(priv, drv, priv->dev, "%s: mdc_div: %d, phy_mask: %x \n", __func__, priv->mdc_div, bus->phy_mask);
	rc = mdiobus_register(bus);
	if (rc) {
		netdev_err(priv->dev, "mdiobus_register(%s) failed\n", bus->name);
		goto err1;
	}

	priv->mii_bus = bus;
	pfe_eth_mdio_reset(bus);

	return 0;

err1:
	mdiobus_free(bus);
err0:
	return rc;
#else
	return 0;
#endif

}

/** pfe_eth_mdio_exit
 */
static void pfe_eth_mdio_exit(struct mii_bus *bus)
{
	if (!bus)
		return;

	netif_info((struct pfe_eth_priv_s *)bus->priv, drv, ((struct pfe_eth_priv_s *)(bus->priv))->dev, "%s\n", __func__);

	mdiobus_unregister(bus);
	mdiobus_free(bus);
}

#if defined(CONFIG_PLATFORM_C2000)
/** pfe_get_interface
 */
static phy_interface_t pfe_get_interface(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	u32 mii_mode = priv->einfo->mii_config;

	netif_info(priv, drv, dev, "%s\n", __func__);

	if (priv->einfo->gemac_mode & (GEMAC_SW_CONF)) {
		switch (mii_mode) {
			case CONFIG_COMCERTO_USE_GMII:
				return PHY_INTERFACE_MODE_GMII;
				break;
			case CONFIG_COMCERTO_USE_RGMII:
				return PHY_INTERFACE_MODE_RGMII;
				break;
			case CONFIG_COMCERTO_USE_RMII:
				return PHY_INTERFACE_MODE_RMII;
				break;
			case CONFIG_COMCERTO_USE_SGMII:
				return PHY_INTERFACE_MODE_SGMII;
				break;

			default :
			case CONFIG_COMCERTO_USE_MII:
				return PHY_INTERFACE_MODE_MII;
				break;

		}
	} else {
		// Bootstrap config read from controller
		BUG();
		return 0;
	}
}
#endif

/** pfe_get_phydev_speed
 */
static int pfe_get_phydev_speed(struct phy_device *phydev)
{
	switch (phydev->speed) {
		case 10:
			return SPEED_10M;
		case 100:
			return SPEED_100M;
		case 1000:
		default:
			return SPEED_1000M;
	}

}

/** pfe_set_rgmii_speed
 */
#define RGMIIPCR	0x434
/* RGMIIPCR bit definitions*/
#define SCFG_RGMIIPCR_EN_AUTO           (0x00000008)
#define SCFG_RGMIIPCR_SETSP_1000M       (0x00000004)
#define SCFG_RGMIIPCR_SETSP_100M        (0x00000000)
#define SCFG_RGMIIPCR_SETSP_10M         (0x00000002)
#define SCFG_RGMIIPCR_SETFD             (0x00000001)

static void pfe_set_rgmii_speed(struct phy_device *phydev)
{
	u32 rgmii_pcr;

	regmap_read(pfe->scfg, RGMIIPCR, &rgmii_pcr);
	rgmii_pcr  &= ~(SCFG_RGMIIPCR_SETSP_1000M|SCFG_RGMIIPCR_SETSP_10M);

	switch (phydev->speed) {
		case 10:
			rgmii_pcr |= SCFG_RGMIIPCR_SETSP_10M;
			break;
		case 1000:
			rgmii_pcr |= SCFG_RGMIIPCR_SETSP_1000M;
			break;
		case 100:
		default:
			/* Default is 100M */
			break;
	}
	regmap_write(pfe->scfg, RGMIIPCR, rgmii_pcr);


}
/** pfe_get_phydev_duplex
 */
static int pfe_get_phydev_duplex(struct phy_device *phydev)
{
	//return ( phydev->duplex == DUPLEX_HALF ) ? DUP_HALF:DUP_FULL ;
	return DUPLEX_FULL;
}

/** pfe_eth_adjust_link
 */
static void pfe_eth_adjust_link(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	unsigned long flags;
	struct phy_device *phydev = priv->phydev;
	int new_state = 0;

	netif_info(priv, drv, dev, "%s\n", __func__);

	spin_lock_irqsave(&priv->lock, flags);
	if (phydev->link) {
		/* Now we make sure that we can be in full duplex mode.
		 * If not, we operate in half-duplex mode. */
		if (phydev->duplex != priv->oldduplex) {
			new_state = 1;
			gemac_set_duplex(priv->EMAC_baseaddr, pfe_get_phydev_duplex(phydev));
			priv->oldduplex = phydev->duplex;
		}

		if (phydev->speed != priv->oldspeed) {
			new_state = 1;
			gemac_set_speed(priv->EMAC_baseaddr, pfe_get_phydev_speed(phydev));
			if(priv->einfo->mii_config == PHY_INTERFACE_MODE_RGMII)
				pfe_set_rgmii_speed(phydev);
			priv->oldspeed = phydev->speed;
		}

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

	spin_unlock_irqrestore(&priv->lock, flags);
}


/** pfe_phy_exit
 */
static void pfe_phy_exit(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	netif_info(priv, drv, dev, "%s\n", __func__);

	phy_disconnect(priv->phydev);
	priv->phydev = NULL;
}

/** pfe_eth_stop
 */
static void pfe_eth_stop( struct net_device *dev , int wake)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	netif_info(priv, drv, dev, "%s\n", __func__);

	if (wake)
		gemac_tx_disable(priv->EMAC_baseaddr);
	else {
		gemac_disable(priv->EMAC_baseaddr);
		gpi_disable(priv->GPI_baseaddr);

		if (priv->phydev)
			phy_stop(priv->phydev);
	}
}

/** pfe_eth_start
 */
static int pfe_eth_start( struct pfe_eth_priv_s *priv )
{
	netif_info(priv, drv, priv->dev, "%s\n", __func__);

	if (priv->phydev)
		phy_start(priv->phydev);

	gpi_enable(priv->GPI_baseaddr);
	gemac_enable(priv->EMAC_baseaddr);

	return 0;
}

/*Configure on chip serdes through mdio
 * Is there any better way to do this? */
static void ls1012a_configure_serdes(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = pfe->eth.eth_priv[0];  // FIXME This will not work for EMAC2 as SGMII
        /*int value,sgmii_2500=0; */
	struct mii_bus *bus = priv->mii_bus;

	netif_info(priv, drv, dev, "%s\n", __func__);
        /* PCS configuration done with corresponding GEMAC */

	pfe_eth_mdio_read(bus, 0, 0);
	pfe_eth_mdio_read(bus, 0, 1);
#if 1
       /*These settings taken from validtion team */
        pfe_eth_mdio_write(bus, 0, 0x0, 0x8000);
        pfe_eth_mdio_write(bus, 0, 0x14, 0xb); 
        pfe_eth_mdio_write(bus, 0, 0x4, 0x1a1);
        pfe_eth_mdio_write(bus, 0, 0x12, 0x400);
        pfe_eth_mdio_write(bus, 0, 0x13, 0x0);
        pfe_eth_mdio_write(bus, 0, 0x0, 0x1140);
        return;
#else
       /*Reset serdes */
        pfe_eth_mdio_write(bus, 0, 0x0, 0x8000);

        /* SGMII IF mode + AN enable only for 1G SGMII, not for 2.5G */
        value = PHY_SGMII_IF_MODE_SGMII;
        if (!sgmii_2500)
                value |= PHY_SGMII_IF_MODE_AN;

        pfe_eth_mdio_write(bus, 0, 0x14, value);

        /* Dev ability according to SGMII specification */
        value = PHY_SGMII_DEV_ABILITY_SGMII;
        pfe_eth_mdio_write(bus, 0, 0x4, value);

        //These values taken from validation team
        pfe_eth_mdio_write(bus, 0, 0x13, 0x0);
        pfe_eth_mdio_write(bus, 0, 0x12, 0x400);

        /* Restart AN */
        value = PHY_SGMII_CR_DEF_VAL;
        if (!sgmii_2500)
                value |= PHY_SGMII_CR_RESET_AN;
        pfe_eth_mdio_write(bus, 0, 0, value);

#endif
}

/** pfe_phy_init
 *
 */
static int pfe_phy_init(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	struct phy_device *phydev;
	char phy_id[MII_BUS_ID_SIZE + 3];
	char bus_id[MII_BUS_ID_SIZE];
	phy_interface_t interface;

	priv->oldlink = 0;
	priv->oldspeed = 0;
	priv->oldduplex = -1;

	snprintf(bus_id, MII_BUS_ID_SIZE, "comcerto-%d", 0);
	snprintf(phy_id, MII_BUS_ID_SIZE + 3, PHY_ID_FMT, bus_id, priv->einfo->phy_id);

	netif_info(priv, drv, dev, "%s: %s\n", __func__, phy_id);
#if defined(CONFIG_PLATFORM_C2000)
	interface = pfe_get_interface(dev);
#else
	interface = priv->einfo->mii_config;
	if(interface == PHY_INTERFACE_MODE_SGMII) {
		/*Configure SGMII PCS */
		if(pfe->scfg) {
			/*Config MDIO from serdes */
			regmap_write(pfe->scfg, 0x484, 0x00000000);
		}
		ls1012a_configure_serdes(dev);
	}

	if(pfe->scfg) {
		/*Config MDIO from PAD */
		regmap_write(pfe->scfg, 0x484, 0x80000000);
	}
#endif


	priv->oldlink = 0;
	priv->oldspeed = 0;
	priv->oldduplex = -1;

	printk("%s interface %x \n", __func__, interface);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
	phydev = phy_connect(dev, phy_id, &pfe_eth_adjust_link, interface);
#else
	phydev = phy_connect(dev, phy_id, &pfe_eth_adjust_link, 0, interface);
#endif

	if (IS_ERR(phydev)) {
		netdev_err(dev, "phy_connect() failed\n");
		return PTR_ERR(phydev);
	}

	priv->phydev = phydev;
	phydev->irq = PHY_POLL;

#if defined(CONFIG_PLATFORM_C2000)
	/* Pause frame support */
	phydev->supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
	if (pfe_eth_pause_rx_enabled(priv))
		phydev->advertising |= ADVERTISED_Pause | ADVERTISED_Asym_Pause;
	else
		phydev->advertising &= ~(ADVERTISED_Pause | ADVERTISED_Asym_Pause);
#else
	/*TODO Add pause frame support for LS1012A */
#endif

	return 0;
}

/** pfe_gemac_init
 */
static int pfe_gemac_init(struct pfe_eth_priv_s *priv)
{
	GEMAC_CFG cfg;

	netif_info(priv, ifup, priv->dev, "%s\n", __func__);

	/* software config */
	/* MII interface mode selection */ 
	switch (priv->einfo->mii_config) {
		case CONFIG_COMCERTO_USE_GMII:
			cfg.mode = GMII;
			break;

		case CONFIG_COMCERTO_USE_MII:
			cfg.mode = MII;
			break;

		case CONFIG_COMCERTO_USE_RGMII:
			cfg.mode = RGMII;
			break;

		case CONFIG_COMCERTO_USE_RMII:
			cfg.mode = RMII;
			break;

		case CONFIG_COMCERTO_USE_SGMII:
			cfg.mode = SGMII;
			break;

		default:
			cfg.mode = RGMII;
	}

	/* Speed selection */
	switch (priv->einfo->gemac_mode & GEMAC_SW_SPEED_1G ) {
		case GEMAC_SW_SPEED_1G:
			cfg.speed = SPEED_1000M;
			break;

		case GEMAC_SW_SPEED_100M:
			cfg.speed = SPEED_100M;
			break;

		case GEMAC_SW_SPEED_10M:
			cfg.speed = SPEED_10M;
			break;

		default:
			cfg.speed = SPEED_1000M;
	}

	/* Duplex selection */
	cfg.duplex =  ( priv->einfo->gemac_mode & GEMAC_SW_FULL_DUPLEX ) ? DUPLEX_FULL : DUPLEX_HALF;

	gemac_set_config( priv->EMAC_baseaddr, &cfg);
	gemac_allow_broadcast( priv->EMAC_baseaddr );
	gemac_disable_unicast( priv->EMAC_baseaddr );
	gemac_disable_multicast( priv->EMAC_baseaddr );
	gemac_disable_fcs_rx( priv->EMAC_baseaddr );
	gemac_enable_1536_rx( priv->EMAC_baseaddr );
	gemac_enable_rx_jmb( priv->EMAC_baseaddr );
	gemac_enable_stacked_vlan( priv->EMAC_baseaddr );
	gemac_enable_pause_rx( priv->EMAC_baseaddr );
	gemac_set_bus_width(priv->EMAC_baseaddr, 64);
	/*TODO just for testing remove it later */
	gemac_enable_copy_all(priv->EMAC_baseaddr);

	/*GEM will perform checksum verifications*/
	if (priv->dev->features & NETIF_F_RXCSUM)
		gemac_enable_rx_checksum_offload(priv->EMAC_baseaddr);
	else
		gemac_disable_rx_checksum_offload(priv->EMAC_baseaddr);	

	return 0;
}

/** pfe_eth_event_handler
 */
static int pfe_eth_event_handler(void *data, int event, int qno)
{
	struct pfe_eth_priv_s *priv = data;

	switch (event) {
	case EVENT_RX_PKT_IND:

		if (qno == 0) {
			if (napi_schedule_prep(&priv->high_napi)) {
				netif_info(priv, intr, priv->dev, "%s: schedule high prio poll\n", __func__);

#ifdef PFE_ETH_NAPI_STATS
				priv->napi_counters[NAPI_SCHED_COUNT]++;
#endif

				__napi_schedule(&priv->high_napi);
			}
		}
		else if (qno == 1) {
			if (napi_schedule_prep(&priv->low_napi)) {
				netif_info(priv, intr, priv->dev, "%s: schedule low prio poll\n", __func__);

#ifdef PFE_ETH_NAPI_STATS
				priv->napi_counters[NAPI_SCHED_COUNT]++;
#endif
				__napi_schedule(&priv->low_napi);
			}
		}
		else if (qno == 2) {
			if (napi_schedule_prep(&priv->lro_napi)) {
				netif_info(priv, intr, priv->dev, "%s: schedule lro prio poll\n", __func__);

#ifdef PFE_ETH_NAPI_STATS
				priv->napi_counters[NAPI_SCHED_COUNT]++;
#endif
				__napi_schedule(&priv->lro_napi);
			}
		}

		break;

	case EVENT_TXDONE_IND:
	case EVENT_HIGH_RX_WM:
	default:
		break;
	}

	return 0;
}

/** pfe_eth_open
 */
static int pfe_eth_open(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	struct hif_client_s *client;
	int rc;

	netif_info(priv, ifup, dev, "%s\n", __func__);

	/* Register client driver with HIF */
	client = &priv->client;
	memset(client, 0, sizeof(*client));
	client->id = PFE_CL_GEM0 + priv->id;
	client->tx_qn = emac_txq_cnt;
	client->rx_qn = EMAC_RXQ_CNT;
	client->priv    = priv;
	client->pfe     = priv->pfe;
	client->event_handler   = pfe_eth_event_handler;

	/* FIXME : For now hif lib sets all tx and rx queues to same size */
	client->tx_qsize = EMAC_TXQ_DEPTH;
	client->rx_qsize = EMAC_RXQ_DEPTH;

	if ((rc = hif_lib_client_register(client))) {
		netdev_err(dev, "%s: hif_lib_client_register(%d) failed\n", __func__, client->id);
		goto err0;
	}

	netif_info(priv, drv, dev, "%s: registered client: %p\n", __func__,  client);

#if defined(CONFIG_PLATFORM_C2000)
	/* Enable gemac tx clock */
	clk_enable(priv->gemtx_clk);
#endif

	pfe_gemac_init(priv);

	if (!is_valid_ether_addr(dev->dev_addr)) {
		netdev_err(dev, "%s: invalid MAC address\n", __func__);
		rc = -EADDRNOTAVAIL;
		goto err1;
	}

	gemac_set_laddrN( priv->EMAC_baseaddr, ( MAC_ADDR *)dev->dev_addr, 1 );

	napi_enable(&priv->high_napi);
	napi_enable(&priv->low_napi);
	napi_enable(&priv->lro_napi);

	rc = pfe_eth_start(priv);

	netif_tx_wake_all_queues(dev);

	//pfe_ctrl_set_eth_state(priv->id, 1, dev->dev_addr);

	priv->tx_timer.expires = jiffies + ( COMCERTO_TX_RECOVERY_TIMEOUT_MS * HZ )/1000;
	add_timer(&priv->tx_timer);

	return rc;

err1:
	hif_lib_client_unregister(&priv->client);
#if defined(CONFIG_PLATFORM_C2000)
	clk_disable(priv->gemtx_clk);
#endif

err0:
	return rc;
}
/*
 *  pfe_eth_shutdown
 */
int pfe_eth_shutdown( struct net_device *dev, int wake)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	int i, qstatus;
	unsigned long next_poll = jiffies + 1, end = jiffies + (TX_POLL_TIMEOUT_MS * HZ) / 1000;
	int tx_pkts, prv_tx_pkts;

	netif_info(priv, ifdown, dev, "%s\n", __func__);

	del_timer_sync(&priv->tx_timer);

	for(i = 0; i < emac_txq_cnt; i++)
		hrtimer_cancel(&priv->fast_tx_timeout[i].timer);

	netif_tx_stop_all_queues(dev);

	do {
		tx_pkts = 0;
		pfe_eth_flush_tx(priv, 1);

		for (i = 0; i < emac_txq_cnt; i++) 
			tx_pkts += hif_lib_tx_pending(&priv->client, i);

		if (tx_pkts) {
			/*Don't wait forever, break if we cross max timeout */
			if (time_after(jiffies, end)) {
				printk(KERN_ERR "(%s)Tx is not complete after %dmsec\n", dev->name, TX_POLL_TIMEOUT_MS);
				break;
			}

			printk("%s : (%s) Waiting for tx packets to free. Pending tx pkts = %d.\n", __func__, dev->name, tx_pkts);
			if (need_resched())
				schedule();
		}

	} while(tx_pkts);

	end = jiffies + (TX_POLL_TIMEOUT_MS * HZ) / 1000;
	/*Disable transmit in PFE before disabling GEMAC */
	//pfe_ctrl_set_eth_state(priv->id, 0, NULL);

	prv_tx_pkts = tmu_pkts_processed(priv->id);
	/*Wait till TMU transmits all pending packets
	* poll tmu_qstatus and pkts processed by TMU for every 10ms
	* Consider TMU is busy, If we see TMU qeueu pending or any packets processed by TMU
	*/
	while(1) {

		if (time_after(jiffies, next_poll)) {

			tx_pkts = tmu_pkts_processed(priv->id);
			qstatus = tmu_qstatus(priv->id) & 0x7ffff;

			if(!qstatus && (tx_pkts == prv_tx_pkts)) {
				break;
			}
			/*Don't wait forever, break if we cross max timeout(TX_POLL_TIMEOUT_MS) */
			if (time_after(jiffies, end)) {
				printk(KERN_ERR "TMU%d is busy after %dmsec\n", priv->id, TX_POLL_TIMEOUT_MS);
				break;
			}
			prv_tx_pkts = tx_pkts;
			next_poll++;
		}
		if (need_resched())
			schedule();


	}
	/* Wait for some more time to complete transmitting packet if any */
	next_poll = jiffies + 1;
	while(1) {
		if (time_after(jiffies, next_poll))
			break;
		if (need_resched())
			schedule();
	}

	pfe_eth_stop(dev, wake);

	napi_disable(&priv->lro_napi);
	napi_disable(&priv->low_napi);
	napi_disable(&priv->high_napi);

#if defined(CONFIG_PLATFORM_C2000)
	/* Disable gemac tx clock */
	clk_disable(priv->gemtx_clk);
#endif

	hif_lib_client_unregister(&priv->client);

	return 0;
}

/* pfe_eth_close
 *
 */
static int pfe_eth_close( struct net_device *dev )
{
	pfe_eth_shutdown(dev, 0);

	return 0;
}

/* pfe_eth_suspend
 *
 * return value : 1 if netdevice is configured to wakeup system
 *                0 otherwise
 */
int pfe_eth_suspend(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	int retval = 0;

	if (priv->wol) {
		gemac_set_wol(priv->EMAC_baseaddr, priv->wol);
		retval = 1;
	}
	pfe_eth_shutdown(dev, priv->wol);

	return retval;
}

/** pfe_eth_resume
 *
 */
int pfe_eth_resume(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	if (priv->wol)
		gemac_set_wol(priv->EMAC_baseaddr, 0);

	return pfe_eth_open(dev);
}

#if defined(CONFIG_PLATFORM_C2000)
/** pfe_eth_set_device_wakeup
 *
 *  Called when a netdevice changes its wol status.
 *  Scans state of all interfaces and updae PFE device
 *  wakeable state
 */
static void pfe_eth_set_device_wakeup(struct pfe *pfe)
{
	int i;
	int wake = 0;

	for(i = 0; i < NUM_GEMAC_SUPPORT; i++)
			wake |= pfe->eth.eth_priv[i]->wol;

	device_set_wakeup_enable(pfe->dev, wake);
	//TODO Find correct IRQ mapping.
	//TODO interface with PMU
	//int irq_set_irq_wake(unsigned int irq, unsigned int on)
}
#endif
/** pfe_eth_get_queuenum
 *
 */
static int pfe_eth_get_queuenum( struct pfe_eth_priv_s *priv, struct sk_buff *skb )
{
	int queuenum = 0;
	unsigned long flags;

	/* Get the Fast Path queue number */
	/* Use conntrack mark (if conntrack exists), then packet mark (if any), then fallback to default */
#if defined(CONFIG_IP_NF_CONNTRACK_MARK) || defined(CONFIG_NF_CONNTRACK_MARK)
	if (skb->nfct) {
		enum ip_conntrack_info cinfo;
		struct nf_conn *ct;
		ct = nf_ct_get(skb, &cinfo);

		if (ct) {
			u_int32_t connmark;
			connmark = ct->mark;

			if ((connmark & 0x80000000) && priv->id != 0)
				connmark >>= 16;

			queuenum = connmark & EMAC_QUEUENUM_MASK;
		}
	}
	else  /* continued after #endif ... */
#endif
		if (skb->mark)
			queuenum = skb->mark & EMAC_QUEUENUM_MASK;
		else {
			spin_lock_irqsave(&priv->lock, flags);	
			queuenum = priv->default_priority & EMAC_QUEUENUM_MASK;
			spin_unlock_irqrestore(&priv->lock, flags);	
		}

	return queuenum;
}



/** pfe_eth_might_stop_tx
 *
 */
static int pfe_eth_might_stop_tx(struct pfe_eth_priv_s *priv, int queuenum, struct netdev_queue *tx_queue, unsigned int n_desc, unsigned int n_segs)
{
	int tried = 0;
	ktime_t kt;

try_again:
	if (unlikely((__hif_tx_avail(&pfe->hif) < n_desc)
	|| (hif_lib_tx_avail(&priv->client, queuenum) < n_desc)
	|| (hif_lib_tx_credit_avail(pfe, priv->id, queuenum) < n_segs))) {

		if (!tried) {
			hif_tx_unlock(&pfe->hif);
			pfe_eth_flush_txQ(priv, queuenum, 1, n_desc);
			hif_lib_update_credit(&priv->client, queuenum);
			tried = 1;
			hif_tx_lock(&pfe->hif);
			goto try_again;
		}
#ifdef PFE_ETH_TX_STATS
		if (__hif_tx_avail(&pfe->hif) < n_desc)
			priv->stop_queue_hif[queuenum]++;
		else if (hif_lib_tx_avail(&priv->client, queuenum) < n_desc) {
			priv->stop_queue_hif_client[queuenum]++;
		}
		else if (hif_lib_tx_credit_avail(pfe, priv->id, queuenum) < n_segs) {
			priv->stop_queue_credit[queuenum]++;
		}
		priv->stop_queue_total[queuenum]++;
#endif
		netif_tx_stop_queue(tx_queue);

		kt = ktime_set(0, COMCERTO_TX_FAST_RECOVERY_TIMEOUT_MS * NSEC_PER_MSEC);
		hrtimer_start(&priv->fast_tx_timeout[queuenum].timer, kt, HRTIMER_MODE_REL);
		return -1;
	}
	else {
		return 0;
	}
}

#define SA_MAX_OP 2
/** pfe_hif_send_packet
 *
 * At this level if TX fails we drop the packet
 */
static void pfe_hif_send_packet( struct sk_buff *skb, struct  pfe_eth_priv_s *priv, int queuenum)
{
	struct skb_shared_info *sh = skb_shinfo(skb);
	unsigned int nr_frags;
	u32 ctrl = 0;

	netif_info(priv, tx_queued, priv->dev, "%s\n", __func__);

	if (skb_is_gso(skb)) {
		priv->stats.tx_dropped++;
		return;
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (skb->len > 1522) {
			skb->ip_summed = 0;
			ctrl = 0;

			if (pfe_compute_csum(skb)){
				kfree_skb(skb);
				return;
			}
		}
		else
			ctrl = HIF_CTRL_TX_CHECKSUM;
	}

	nr_frags = sh->nr_frags;

	if (nr_frags) {
		skb_frag_t *f;
		int i;

		__hif_lib_xmit_pkt(&priv->client, queuenum, skb->data, skb_headlen(skb), ctrl, HIF_FIRST_BUFFER, skb);

		for (i = 0; i < nr_frags - 1; i++) {
			f = &sh->frags[i];
			__hif_lib_xmit_pkt(&priv->client, queuenum, skb_frag_address(f), skb_frag_size(f), 0x0, 0x0, skb);
		}

		f = &sh->frags[i];

		__hif_lib_xmit_pkt(&priv->client, queuenum, skb_frag_address(f), skb_frag_size(f), 0x0, HIF_LAST_BUFFER|HIF_DATA_VALID, skb);

		netif_info(priv, tx_queued, priv->dev, "%s: pkt sent successfully skb:%p nr_frags:%d len:%d\n", __func__, skb, nr_frags, skb->len);
	}
	else {
		__hif_lib_xmit_pkt(&priv->client, queuenum, skb->data, skb->len, ctrl, HIF_FIRST_BUFFER | HIF_LAST_BUFFER | HIF_DATA_VALID, skb);
		netif_info(priv, tx_queued, priv->dev, "%s: pkt sent successfully skb:%p len:%d\n", __func__, skb, skb->len);
	}
	hif_tx_dma_start();
	priv->stats.tx_packets++;
	priv->stats.tx_bytes += skb->len;
	hif_lib_tx_credit_use(pfe, priv->id, queuenum, 1);
}

/** pfe_eth_flush_txQ
 */
static void pfe_eth_flush_txQ(struct pfe_eth_priv_s *priv, int txQ_num, int from_tx, int n_desc)
{
	struct sk_buff *skb;
	struct netdev_queue *tx_queue = netdev_get_tx_queue(priv->dev, txQ_num);
	int count = max(TX_FREE_MAX_COUNT, n_desc);
	unsigned int flags;

	netif_info(priv, tx_done, priv->dev, "%s\n", __func__);

	if (!from_tx)
		__netif_tx_lock_bh(tx_queue);

	/* Clean HIF and client queue */
	while (count && (skb = hif_lib_tx_get_next_complete(&priv->client, txQ_num, &flags, count))) {

		/* FIXME : Invalid data can be skipped in hif_lib itself */
		if (flags & HIF_DATA_VALID) {
			dev_kfree_skb_any(skb);

		}
		// When called from the timer, flush all descriptors
		if (from_tx)
			count--;
	}

	if (!from_tx)
		__netif_tx_unlock_bh(tx_queue);
}

/** pfe_eth_flush_tx
 */
static void pfe_eth_flush_tx(struct pfe_eth_priv_s *priv, int force)
{
	int ii;

	netif_info(priv, tx_done, priv->dev, "%s\n", __func__);

	for (ii = 0; ii < emac_txq_cnt; ii++) {
		if (force || (time_after(jiffies, priv->client.tx_q[ii].jiffies_last_packet + (COMCERTO_TX_RECOVERY_TIMEOUT_MS * HZ)/1000))) {
			pfe_eth_flush_txQ(priv, ii, 0, 0); //We will release everything we can based on from_tx param, so the count param can be set to any value
			hif_lib_update_credit(&priv->client, ii);
		}
	}
}

void pfe_tx_get_req_desc(struct sk_buff *skb, unsigned int *n_desc, unsigned int *n_segs)
{
	struct skb_shared_info *sh = skb_shinfo(skb);

	// Scattered data
	if (sh->nr_frags) {
		*n_desc = sh->nr_frags + 1;
		*n_segs = 1;
	}
	// Regular case
	else {
		*n_desc = 1;
		*n_segs = 1;
	}
	return;
}

/** pfe_eth_send_packet
 */
static int pfe_eth_send_packet(struct sk_buff *skb, struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	int txQ_num = skb_get_queue_mapping(skb);
	int n_desc, n_segs, count;
	struct netdev_queue *tx_queue = netdev_get_tx_queue(priv->dev, txQ_num);

	netif_info(priv, tx_queued, dev, "%s\n", __func__);

	if ((!skb_is_gso(skb)) && (skb_headroom(skb) < (PFE_PKT_HEADER_SZ + sizeof(unsigned long)))) {

		netif_warn(priv, tx_err, priv->dev, "%s: copying skb\n", __func__);

		if (pskb_expand_head(skb, (PFE_PKT_HEADER_SZ + sizeof(unsigned long)), 0, GFP_ATOMIC)) {
			/* No need to re-transmit, no way to recover*/
			kfree_skb(skb);
			priv->stats.tx_dropped++;
			return NETDEV_TX_OK;
		}
	}

	pfe_tx_get_req_desc(skb, &n_desc, &n_segs);

	hif_tx_lock(&pfe->hif);
	if(unlikely(pfe_eth_might_stop_tx(priv, txQ_num, tx_queue, n_desc, n_segs))) {
#ifdef PFE_ETH_TX_STATS
		if(priv->was_stopped[txQ_num]) {
			priv->clean_fail[txQ_num]++;
			priv->was_stopped[txQ_num] = 0;
		}
#endif
		hif_tx_unlock(&pfe->hif);
		return NETDEV_TX_BUSY;
	}

	pfe_hif_send_packet(skb, priv, txQ_num);

	hif_tx_unlock(&pfe->hif);

	dev->trans_start = jiffies;

	// Recycle buffers if a socket's send buffer becomes half full or if the HIF client queue starts filling up
	if (((count = (hif_lib_tx_pending(&priv->client, txQ_num) - HIF_CL_TX_FLUSH_MARK)) > 0)
		|| (skb->sk && ((sk_wmem_alloc_get(skb->sk) << 1) > skb->sk->sk_sndbuf)))
		pfe_eth_flush_txQ(priv, txQ_num, 1, count);

#ifdef PFE_ETH_TX_STATS
	priv->was_stopped[txQ_num] = 0;
#endif

	return NETDEV_TX_OK;
}

/** pfe_eth_select_queue
 *
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
static u16 pfe_eth_select_queue( struct net_device *dev, struct sk_buff *skb,
		void *accel_priv, select_queue_fallback_t fallback)
#else
static u16 pfe_eth_select_queue( struct net_device *dev, struct sk_buff *skb )
#endif
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	return pfe_eth_get_queuenum(priv, skb);
}


/** pfe_eth_get_stats
 */
static struct net_device_stats *pfe_eth_get_stats(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	netif_info(priv, drv, dev, "%s\n", __func__);

	return &priv->stats;
}


/** pfe_eth_change_mtu
 */
static int pfe_eth_change_mtu(struct net_device *dev, int new_mtu)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	int oldsize = dev->mtu ;
	int frame_size = new_mtu + ETH_HLEN +4;

	netif_info(priv, drv, dev, "%s\n", __func__);

	if ((frame_size < 64) || (frame_size > JUMBO_FRAME_SIZE)) {
		netif_err(priv, drv, dev, "Invalid MTU setting\n");
		return -EINVAL;
	}

	if ((new_mtu > 1500) && (dev->features & NETIF_F_TSO))
	{
		priv->usr_features = dev->features;
		if (dev->features & NETIF_F_TSO)
		{
			netdev_err(dev, "MTU cannot be set to more than 1500 while TSO is enabled. disabling TSO.\n");
			dev->features &= ~(NETIF_F_TSO);
		}
	}
	else if ((dev->mtu > 1500) && (new_mtu <= 1500))
	{
		if (priv->usr_features & NETIF_F_TSO)
		{
			priv->usr_features &= ~(NETIF_F_TSO);
			dev->features |= NETIF_F_TSO;
			netdev_err(dev, "MTU is <= 1500, Enabling TSO feature.\n");
		}
	}

	/* Only stop and start the controller if it isn't already
	 * stopped, and we changed something */
	if ((oldsize != new_mtu) && (dev->flags & IFF_UP)){
		netdev_err(dev, "Can not change MTU - fast_path must be disabled and ifconfig down must be issued first\n");

		return -EINVAL;
	}

	dev->mtu = new_mtu;

	return 0;
}

/** pfe_eth_set_mac_address
 */
static int pfe_eth_set_mac_address(struct net_device *dev, void *addr)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	struct sockaddr *sa = addr;

	netif_info(priv, drv, dev, "%s\n", __func__);

	if (!is_valid_ether_addr(sa->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(dev->dev_addr, sa->sa_data, ETH_ALEN);

	gemac_set_laddrN(priv->EMAC_baseaddr, (MAC_ADDR *)dev->dev_addr, 1);

	return 0;

}

/** pfe_eth_enet_addr_byte_mac
 */
int pfe_eth_enet_addr_byte_mac(u8 * enet_byte_addr, MAC_ADDR *enet_addr)
{
	if ((enet_byte_addr == NULL) || (enet_addr == NULL))
	{
		return -1;
	}
	else
	{
		enet_addr->bottom = enet_byte_addr[0] |
			(enet_byte_addr[1] << 8) |
			(enet_byte_addr[2] << 16) |
			(enet_byte_addr[3] << 24);
		enet_addr->top = enet_byte_addr[4] |
			(enet_byte_addr[5] << 8);
		return 0;
	}
}



/** pfe_eth_set_multi
 */
static void pfe_eth_set_multi(struct net_device *dev)
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	MAC_ADDR    hash_addr;          /* hash register structure */
	MAC_ADDR    spec_addr;		/* specific mac address register structure */
	int         result;          /* index into hash register to set.. */
	int 	    uc_count = 0;
	struct netdev_hw_addr *ha;

	if (dev->flags & IFF_PROMISC) {
		netif_info(priv, drv, dev, "entering promiscuous mode\n");

		priv->promisc = 1;
		gemac_enable_copy_all(priv->EMAC_baseaddr);
	} else {
		priv->promisc = 0;
		gemac_disable_copy_all(priv->EMAC_baseaddr);
	}

	/* Enable broadcast frame reception if required. */
	if (dev->flags & IFF_BROADCAST) {
		gemac_allow_broadcast(priv->EMAC_baseaddr);
	} else {
		netif_info(priv, drv, dev, "disabling broadcast frame reception\n");

		gemac_no_broadcast(priv->EMAC_baseaddr);
	}

	if (dev->flags & IFF_ALLMULTI) {
		/* Set the hash to rx all multicast frames */
		hash_addr.bottom = 0xFFFFFFFF;
		hash_addr.top = 0xFFFFFFFF;
		gemac_set_hash(priv->EMAC_baseaddr, &hash_addr);
		gemac_enable_multicast(priv->EMAC_baseaddr);
		netdev_for_each_uc_addr(ha, dev) {
			if(uc_count >= MAX_UC_SPEC_ADDR_REG) break;
			pfe_eth_enet_addr_byte_mac(ha->addr, &spec_addr);
			gemac_set_laddrN(priv->EMAC_baseaddr, &spec_addr, uc_count + 2);
			uc_count++;
		}
	} else if ((netdev_mc_count(dev) > 0)  || (netdev_uc_count(dev))) {
		u8 *addr;

		hash_addr.bottom = 0;
		hash_addr.top = 0;

		netdev_for_each_mc_addr(ha, dev) {
			addr = ha->addr;

			netif_info(priv, drv, dev, "adding multicast address %X:%X:%X:%X:%X:%X to gem filter\n",
						addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

			result = pfe_eth_get_hash(addr);

			if (result >= EMAC_HASH_REG_BITS) {
				break;
			} else {
				if (result < 32) {
					hash_addr.bottom |= (1 << result);
				} else {
					hash_addr.top |= (1 << (result - 32));
				}
			}

		}

		uc_count = -1;
		netdev_for_each_uc_addr(ha, dev) {
			addr = ha->addr;

			if(++uc_count < MAX_UC_SPEC_ADDR_REG)  
			{
				netdev_info(dev, "adding unicast address %02x:%02x:%02x:%02x:%02x:%02x to gem filter\n",
						addr[0], addr[1], addr[2],
						addr[3], addr[4], addr[5]);

				pfe_eth_enet_addr_byte_mac(addr, &spec_addr);
				gemac_set_laddrN(priv->EMAC_baseaddr, &spec_addr, uc_count + 2);
			}
			else
			{
				netif_info(priv, drv, dev, "adding unicast address %02x:%02x:%02x:%02x:%02x:%02x to gem hash\n",
							addr[0], addr[1], addr[2],
							addr[3], addr[4], addr[5]);

				result = pfe_eth_get_hash(addr);
				if (result >= EMAC_HASH_REG_BITS) {
					break;
				} else {
					if (result < 32)
						hash_addr.bottom |= (1 << result);
					else
						hash_addr.top |= (1 << (result - 32));
				}


			}
		}

		gemac_set_hash(priv->EMAC_baseaddr, &hash_addr);
		if(netdev_mc_count(dev))
			gemac_enable_multicast(priv->EMAC_baseaddr);
		else
			gemac_disable_multicast(priv->EMAC_baseaddr);		
	}

	if(netdev_uc_count(dev) >= MAX_UC_SPEC_ADDR_REG)
		gemac_enable_unicast(priv->EMAC_baseaddr);
	else
	{
		/* Check if there are any specific address HW registers that need 
		 *  to be flushed 
		 *  */
		for(uc_count = netdev_uc_count(dev); uc_count < MAX_UC_SPEC_ADDR_REG; uc_count++) 
			gemac_clear_laddrN(priv->EMAC_baseaddr, uc_count + 2);

		gemac_disable_unicast(priv->EMAC_baseaddr);
	}

	if (dev->flags & IFF_LOOPBACK) {
		gemac_set_loop(priv->EMAC_baseaddr, LB_LOCAL);
	}

	return;
}

/** pfe_eth_set_features
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
static int pfe_eth_set_features(struct net_device *dev, netdev_features_t features)
#else
static int pfe_eth_set_features(struct net_device *dev, u32 features)
#endif
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);
	int rc = 0;

	if (features & NETIF_F_RXCSUM)
		gemac_enable_rx_checksum_offload(priv->EMAC_baseaddr);
	else
		gemac_disable_rx_checksum_offload(priv->EMAC_baseaddr);
	return rc;
}

/** pfe_eth_fix_features
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
static netdev_features_t pfe_eth_fix_features(struct net_device *dev, netdev_features_t features)
#else
static unsigned int pfe_eth_fix_features(struct net_device *dev,u32 features)
#endif
{
	struct pfe_eth_priv_s *priv = netdev_priv(dev);

	if (dev->mtu > 1500)
	{
		if (features & (NETIF_F_TSO))
		{
			priv->usr_features |= NETIF_F_TSO;
			features &= ~(NETIF_F_TSO);
			netdev_err(dev, "TSO cannot be enabled when the MTU is larger than 1500. Please set the MTU to 1500 or lower first.\n");
		}
	}

	return features;
}

/** pfe_eth_tx_timeout
 */
void pfe_eth_tx_timeout(unsigned long data )
{
	struct pfe_eth_priv_s *priv = (struct pfe_eth_priv_s *)data;

	netif_info(priv, timer, priv->dev, "%s\n", __func__);

	pfe_eth_flush_tx(priv, 0);

	priv->tx_timer.expires = jiffies + ( COMCERTO_TX_RECOVERY_TIMEOUT_MS * HZ )/1000;
	add_timer(&priv->tx_timer);
}

/** pfe_eth_fast_tx_timeout
 */
static enum hrtimer_restart pfe_eth_fast_tx_timeout(struct hrtimer *timer)
{
	struct pfe_eth_fast_timer *fast_tx_timeout = container_of(timer, struct pfe_eth_fast_timer, timer);
	struct pfe_eth_priv_s *priv =  container_of(fast_tx_timeout->base, struct pfe_eth_priv_s, fast_tx_timeout);
	struct netdev_queue *tx_queue = netdev_get_tx_queue(priv->dev, fast_tx_timeout->queuenum);

	if(netif_tx_queue_stopped(tx_queue)) {
#ifdef PFE_ETH_TX_STATS
		priv->was_stopped[fast_tx_timeout->queuenum] = 1;
#endif
		netif_tx_wake_queue(tx_queue);
	}

	return HRTIMER_NORESTART;
}

/** pfe_eth_fast_tx_timeout_init
 */
static void pfe_eth_fast_tx_timeout_init(struct pfe_eth_priv_s *priv)
{
	int i;
	for (i = 0; i < emac_txq_cnt; i++) {
		priv->fast_tx_timeout[i].queuenum = i;
		hrtimer_init(&priv->fast_tx_timeout[i].timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		priv->fast_tx_timeout[i].timer.function = pfe_eth_fast_tx_timeout;
		priv->fast_tx_timeout[i].base = priv->fast_tx_timeout;
	}
}

static struct sk_buff *pfe_eth_rx_skb(struct net_device *dev, struct pfe_eth_priv_s *priv, unsigned int qno)
{
	void *buf_addr;
	unsigned int rx_ctrl;
	unsigned int desc_ctrl = 0;
	struct hif_ipsec_hdr *ipsec_hdr = NULL;
	struct sk_buff *skb;
	struct sk_buff *skb_frag, *skb_frag_last = NULL;
	int length = 0, offset;

	skb = priv->skb_inflight[qno];

	if (skb && (skb_frag_last = skb_shinfo(skb)->frag_list)) {
		while (skb_frag_last->next)
			skb_frag_last = skb_frag_last->next;
	}

	while (!(desc_ctrl & CL_DESC_LAST)) {

		buf_addr = hif_lib_receive_pkt(&priv->client, qno, &length, &offset, &rx_ctrl, &desc_ctrl, (void **)&ipsec_hdr);
		if (!buf_addr)
			goto incomplete;

#ifdef PFE_ETH_NAPI_STATS
		priv->napi_counters[NAPI_DESC_COUNT]++;
#endif

		/* First frag */
		if (desc_ctrl & CL_DESC_FIRST) {
#if defined(CONFIG_PLATFORM_EMULATION) || defined(CONFIG_PLATFORM_PCI)
			skb = dev_alloc_skb(PFE_BUF_SIZE);
			if (unlikely(!skb)) {
				goto pkt_drop;
			}

			skb_copy_to_linear_data(skb, buf_addr, length + offset);
			kfree(buf_addr);
#else
#if defined(CONFIG_COMCERTO_ZONE_DMA_NCNB)
			skb = alloc_skb(length + offset + 32, GFP_ATOMIC);
#else
			skb = alloc_skb_header(PFE_BUF_SIZE, buf_addr, GFP_ATOMIC);
#endif
			if (unlikely(!skb)) {
				goto pkt_drop;
			}
#endif
			skb_reserve(skb, offset);
#if defined(CONFIG_COMCERTO_ZONE_DMA_NCNB)
			__memcpy(skb->data, buf_addr + offset, length);
			if (ipsec_hdr) {
				sah_local = *(unsigned int *)&ipsec_hdr->sa_handle[0];
			}
			kfree(buf_addr);
#endif
			skb_put(skb, length);
			skb->dev = dev;

			if ((dev->features & NETIF_F_RXCSUM) && (rx_ctrl & HIF_CTRL_RX_CHECKSUMMED))
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			else
				skb_checksum_none_assert(skb);

		} else {

			/* Next frags */
			if (unlikely(!skb)) {
				printk(KERN_ERR "%s: NULL skb_inflight\n", __func__);
				goto pkt_drop;
			}

#if defined(CONFIG_COMCERTO_ZONE_DMA_NCNB)
			skb_frag = alloc_skb(length + offset + 32, GFP_ATOMIC);
#else
			skb_frag = alloc_skb_header(PFE_BUF_SIZE, buf_addr, GFP_ATOMIC);
#endif
			if (unlikely(!skb_frag)) {
				kfree(buf_addr);
				goto pkt_drop;
			}

			skb_reserve(skb_frag, offset);
#if defined(CONFIG_COMCERTO_ZONE_DMA_NCNB)
			__memcpy(skb_frag->data, buf_addr + offset, length);
			kfree(buf_addr);
#endif
			skb_put(skb_frag, length);

			skb_frag->dev = dev;

			if (skb_shinfo(skb)->frag_list)
				skb_frag_last->next = skb_frag;
			else
				skb_shinfo(skb)->frag_list = skb_frag;

			skb->truesize += skb_frag->truesize;
			skb->data_len += length;
			skb->len += length;
			skb_frag_last = skb_frag;
		}
	}

	priv->skb_inflight[qno] = NULL;
	return skb;

incomplete:
	priv->skb_inflight[qno] = skb;
	return NULL;

pkt_drop:
	priv->skb_inflight[qno] = NULL;

	if (skb) {
		kfree_skb(skb);
	} else {
		kfree(buf_addr);
	}

	priv->stats.rx_errors++;

	return NULL;
}


/** pfe_eth_poll
 */
static int pfe_eth_poll(struct pfe_eth_priv_s *priv, struct napi_struct *napi, unsigned int qno, int budget)
{
	struct net_device *dev = priv->dev;
	struct sk_buff *skb;
	int work_done = 0;
	unsigned int len;

	netif_info(priv, intr, priv->dev, "%s\n", __func__);

#ifdef PFE_ETH_NAPI_STATS
	priv->napi_counters[NAPI_POLL_COUNT]++;
#endif

	do {
		skb = pfe_eth_rx_skb(dev, priv, qno);

		if (!skb)
			break;

		len = skb->len;

		/* Packet will be processed */
		skb->protocol = eth_type_trans(skb, dev);

		netif_receive_skb(skb);

		priv->stats.rx_packets++;
		priv->stats.rx_bytes += len;

		dev->last_rx = jiffies;

		work_done++;

#ifdef PFE_ETH_NAPI_STATS
		priv->napi_counters[NAPI_PACKET_COUNT]++;
#endif

	} while (work_done < budget);

	/* If no Rx receive nor cleanup work was done, exit polling mode.
	 * No more netif_running(dev) check is required here , as this is checked in
	 * net/core/dev.c ( 2.6.33.5 kernel specific).
	 */
	if (work_done < budget) {
		napi_complete(napi);

		hif_lib_event_handler_start(&priv->client, EVENT_RX_PKT_IND, qno);
	}
#ifdef PFE_ETH_NAPI_STATS
	else
		priv->napi_counters[NAPI_FULL_BUDGET_COUNT]++;
#endif

	return work_done;
}

/** pfe_eth_lro_poll
 */
static int pfe_eth_lro_poll(struct napi_struct *napi, int budget)
{
	struct pfe_eth_priv_s *priv = container_of(napi, struct pfe_eth_priv_s, lro_napi);

	netif_info(priv, intr, priv->dev, "%s\n", __func__);

	return pfe_eth_poll(priv, napi, 2, budget);
}


/** pfe_eth_low_poll
 */
static int pfe_eth_low_poll(struct napi_struct *napi, int budget)
{
	struct pfe_eth_priv_s *priv = container_of(napi, struct pfe_eth_priv_s, low_napi);

	netif_info(priv, intr, priv->dev, "%s\n", __func__);

	return pfe_eth_poll(priv, napi, 1, budget);
}

/** pfe_eth_high_poll
 */
static int pfe_eth_high_poll(struct napi_struct *napi, int budget )
{
	struct pfe_eth_priv_s *priv = container_of(napi, struct pfe_eth_priv_s, high_napi);

	netif_info(priv, intr, priv->dev, "%s\n", __func__);

	return pfe_eth_poll(priv, napi, 0, budget);
}

static const struct net_device_ops pfe_netdev_ops = {
	.ndo_open = pfe_eth_open,
	.ndo_stop = pfe_eth_close,
	.ndo_start_xmit = pfe_eth_send_packet,
	.ndo_select_queue = pfe_eth_select_queue,
	.ndo_get_stats = pfe_eth_get_stats,
	.ndo_change_mtu = pfe_eth_change_mtu,
	.ndo_set_mac_address = pfe_eth_set_mac_address,
	.ndo_set_rx_mode = pfe_eth_set_multi,
	.ndo_set_features = pfe_eth_set_features,
	.ndo_fix_features = pfe_eth_fix_features,
	.ndo_validate_addr = eth_validate_addr,
};


/** pfe_eth_init_one 
 */

static int pfe_eth_init_one( struct pfe *pfe, int id )
{
	struct net_device *dev = NULL;
	struct pfe_eth_priv_s *priv = NULL;
	struct comcerto_eth_platform_data *einfo;
	struct comcerto_mdio_platform_data *minfo;
	struct comcerto_pfe_platform_data *pfe_info;
	int err;

	/* Extract pltform data */
#if defined(CONFIG_PLATFORM_EMULATION) || defined(CONFIG_PLATFORM_PCI)
	pfe_info = (struct comcerto_pfe_platform_data *) &comcerto_pfe_pdata;
#else
	pfe_info = (struct comcerto_pfe_platform_data *) pfe->dev->platform_data;
#endif
	if (!pfe_info) {
		printk(KERN_ERR "%s: pfe missing additional platform data\n", __func__);
		err = -ENODEV;
		goto err0;
	}

	einfo = (struct comcerto_eth_platform_data *) pfe_info->comcerto_eth_pdata;

	/* einfo never be NULL, but no harm in having this check */ 
	if (!einfo) {
		printk(KERN_ERR "%s: pfe missing additional gemacs platform data\n", __func__);
		err = -ENODEV;
		goto err0;
	}

	minfo = (struct comcerto_mdio_platform_data *) pfe_info->comcerto_mdio_pdata;

	/* einfo never be NULL, but no harm in having this check */ 
	if (!minfo) {
		printk(KERN_ERR "%s: pfe missing additional mdios platform data\n", __func__);
		err = -ENODEV;
		goto err0;
	}

	/*
	 * FIXME: Need to check some flag in "einfo" to know whether
	 *        GEMAC is enabled Or not.
	 */

	/* Create an ethernet device instance */
	dev = alloc_etherdev_mq(sizeof (*priv), emac_txq_cnt);

	if (!dev) {
		printk(KERN_ERR "%s: gemac %d device allocation failed\n", __func__, einfo[id].gem_id);
		err = -ENOMEM;
		goto err0;
	}

	priv = netdev_priv(dev);
	priv->dev = dev;
	priv->id = einfo[id].gem_id;
	priv->pfe = pfe;

#if defined(CONFIG_PLATFORM_C2000)
	/* get gemac tx clock */
	priv->gemtx_clk = clk_get(NULL, "gemtx");

	if (IS_ERR(priv->gemtx_clk)) {
		printk(KERN_ERR "%s: Unable to get the clock for gemac %d\n", __func__, priv->id);
		err = -ENODEV;
		goto err1; 
	}
#endif

	pfe->eth.eth_priv[id] = priv;

	/* Set the info in the priv to the current info */
	priv->einfo = &einfo[id];
	priv->EMAC_baseaddr = cbus_emac_base[id];
	priv->PHY_baseaddr = cbus_emac_base[0];
	priv->mdio_muxval = einfo[id].mdio_muxval;
	priv->GPI_baseaddr = cbus_gpi_base[id];

	/* FIXME : For now TMU queue numbers hardcoded, later should be taken from pfe.h */	
#define HIF_GEMAC_TMUQ_BASE	6
	priv->low_tmuQ	=  HIF_GEMAC_TMUQ_BASE + (id * 2);	
	priv->high_tmuQ	=  priv->low_tmuQ + 1;	

	spin_lock_init(&priv->lock);
	priv->tx_timer.data = (unsigned long)priv;
	priv->tx_timer.function = pfe_eth_tx_timeout;
	priv->tx_timer.expires = jiffies + ( COMCERTO_TX_RECOVERY_TIMEOUT_MS * HZ )/1000;
	init_timer(&priv->tx_timer);

	pfe_eth_fast_tx_timeout_init(priv);

	/* Copy the station address into the dev structure, */
	memcpy(dev->dev_addr, einfo[id].mac_addr, ETH_ALEN);

	/* Initialize mdio */
	if (minfo[id].enabled) {
		if ((err = pfe_eth_mdio_init(priv, &minfo[id]))) {
			netdev_err(dev, "%s: pfe_eth_mdio_init() failed\n", __func__);
			goto err2;
		}
	}

	dev->mtu = 1500;

	/* supported features */
	dev->hw_features = NETIF_F_SG;
	/* Enable after checksum offload is validated 
	dev->hw_features = NETIF_F_RXCSUM | NETIF_F_IP_CSUM |  NETIF_F_IPV6_CSUM |
				NETIF_F_SG; */

	/* enabled by default */
	dev->features = dev->hw_features;

	priv->usr_features = dev->features;

	dev->netdev_ops = &pfe_netdev_ops;

	dev->ethtool_ops = &pfe_ethtool_ops;

	/* Enable basic messages by default */
	priv->msg_enable = NETIF_MSG_IFUP | NETIF_MSG_IFDOWN | NETIF_MSG_LINK | NETIF_MSG_PROBE;

	netif_napi_add(dev, &priv->low_napi, pfe_eth_low_poll, HIF_RX_POLL_WEIGHT - 16);
	netif_napi_add(dev, &priv->high_napi, pfe_eth_high_poll, HIF_RX_POLL_WEIGHT - 16);
	netif_napi_add(dev, &priv->lro_napi, pfe_eth_lro_poll, HIF_RX_POLL_WEIGHT - 16);

	err = register_netdev(dev);

	if (err) {
		netdev_err(dev, "register_netdev() failed\n");
		goto err3;
	}

	if (!(priv->einfo->phy_flags & GEMAC_NO_PHY)) {
		err = pfe_phy_init(dev);
		if (err) {
			netdev_err(dev, "%s: pfe_phy_init() failed\n", __func__);
			goto err4;
		}
	}


	/* Create all the sysfs files */
	if(pfe_eth_sysfs_init(dev))
		goto err4;

	netif_info(priv, probe, dev, "%s: created interface, baseaddr: %p\n", __func__, priv->EMAC_baseaddr);

	return 0;
err4:
	unregister_netdev(dev);
err3:
	pfe_eth_mdio_exit(priv->mii_bus);
err2:
#if defined(CONFIG_PLATFORM_C2000)
	clk_put(priv->gemtx_clk);
err1:
#endif
	free_netdev(priv->dev);

err0:
	return err;
}

/** pfe_eth_init
 */
int pfe_eth_init(struct pfe *pfe)
{
	int ii = 0;
	int err;

	printk(KERN_INFO "%s\n", __func__);

	cbus_emac_base[0] = EMAC1_BASE_ADDR;
	cbus_emac_base[1] = EMAC2_BASE_ADDR;

	cbus_gpi_base[0] = EGPI1_BASE_ADDR;
	cbus_gpi_base[1] = EGPI2_BASE_ADDR;

#if !defined(CONFIG_PLATFORM_LS1012A)
	cbus_emac_base[2] = EMAC3_BASE_ADDR;
	cbus_gpi_base[2] = EGPI3_BASE_ADDR;
#endif

	for (ii = 0; ii < NUM_GEMAC_SUPPORT; ii++) {
		if ((err = pfe_eth_init_one(pfe, ii)))
			goto err0;
	}

	return 0;

err0:
	while(ii--){
		pfe_eth_exit_one( pfe->eth.eth_priv[ii] );
	} 

	/* Register three network devices in the kernel */
	return err;
}

/** pfe_eth_exit_one
 */
static void pfe_eth_exit_one(struct pfe_eth_priv_s *priv)
{
	netif_info(priv, probe, priv->dev, "%s\n", __func__);

	pfe_eth_sysfs_exit(priv->dev);

#if defined(CONFIG_PLATFORM_C2000)
	clk_put(priv->gemtx_clk);
#endif

	unregister_netdev(priv->dev);

	pfe_eth_mdio_exit(priv->mii_bus);

	if (!(priv->einfo->phy_flags & GEMAC_NO_PHY))
		pfe_phy_exit(priv->dev);

	free_netdev(priv->dev);
}

/** pfe_eth_exit
 */
void pfe_eth_exit(struct pfe *pfe)
{
	int ii;

	printk(KERN_INFO "%s\n", __func__);

	for(ii = 0; ii < NUM_GEMAC_SUPPORT; ii++ ) {
		/*
		 * FIXME: Need to check some flag in "einfo" to know whether
		 *        GEMAC is enabled Or not.
		 */

		pfe_eth_exit_one(pfe->eth.eth_priv[ii]);
	}
}

