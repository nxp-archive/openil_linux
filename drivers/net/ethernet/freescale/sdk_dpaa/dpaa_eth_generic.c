/* Copyright 2013-2015 Freescale Semiconductor Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/of_net.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/percpu.h>

#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "dpaa_eth_base.h"
#include "dpaa_eth_generic.h"

#define DPA_DEFAULT_TX_HEADROOM		64
#define DPA_GENERIC_SKB_COPY_MAX_SIZE	256
#define DPA_GENERIC_NAPI_WEIGHT		64
#define DPA_GENERIC_DESCRIPTION "FSL DPAA Generic Ethernet driver"
#define DPA_GENERIC_BUFFER_QUOTA       	4

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION(DPA_GENERIC_DESCRIPTION);

static uint8_t generic_debug = -1;
module_param(generic_debug, byte, S_IRUGO);
MODULE_PARM_DESC(generic_debug, "Module/Driver verbosity level");

/* This has to work in tandem with the DPA_CS_THRESHOLD_xxx values. */
static uint16_t tx_timeout = 1000;
module_param(tx_timeout, ushort, S_IRUGO);
MODULE_PARM_DESC(tx_timeout, "The Tx timeout in ms");

struct rtnl_link_stats64 *__cold
dpa_generic_get_stats64(struct net_device *netdev,
			struct rtnl_link_stats64 *stats);
static int dpa_generic_set_mac_address(struct net_device *net_dev,
				       void *addr);
static int __cold dpa_generic_start(struct net_device *netdev);
static int __cold dpa_generic_stop(struct net_device *netdev);
static int dpa_generic_eth_probe(struct platform_device *_of_dev);
static int dpa_generic_remove(struct platform_device *of_dev);
static void dpa_generic_ern(struct qman_portal *portal,
			    struct qman_fq *fq,
			    const struct qm_mr_entry *msg);
static int __hot dpa_generic_tx(struct sk_buff *skb,
				struct net_device *netdev);
static void dpa_generic_drain_bp(struct dpa_bp *bp, u8 nbuf);
static void dpa_generic_drain_sg_bp(struct dpa_bp *sg_bp, u8 nbuf);

static const struct net_device_ops dpa_generic_ops = {
	.ndo_open = dpa_generic_start,
	.ndo_start_xmit = dpa_generic_tx,
	.ndo_stop = dpa_generic_stop,
	.ndo_set_mac_address = dpa_generic_set_mac_address,
	.ndo_tx_timeout = dpa_timeout,
	.ndo_get_stats64 = dpa_generic_get_stats64,
	.ndo_init = dpa_ndo_init,
	.ndo_set_features = dpa_set_features,
	.ndo_fix_features = dpa_fix_features,
	.ndo_change_mtu = dpa_change_mtu,
};

static void dpa_generic_draining_timer(unsigned long arg)
{
	struct dpa_generic_priv_s *priv = (struct dpa_generic_priv_s *)arg;

	dpa_generic_drain_bp(priv->draining_tx_bp, DPA_GENERIC_BUFFER_QUOTA);
	dpa_generic_drain_sg_bp(priv->draining_tx_sg_bp,
			DPA_GENERIC_BUFFER_QUOTA);

	if (priv->net_dev->flags & IFF_UP)
		mod_timer(&(priv->timer), jiffies + 1);
}

struct rtnl_link_stats64 *__cold
dpa_generic_get_stats64(struct net_device *netdev,
			struct rtnl_link_stats64 *stats)
{
	struct dpa_generic_priv_s *priv = netdev_priv(netdev);
	u64 *cpustats;
	u64 *netstats = (u64 *)stats;
	int i, j;
	struct dpa_percpu_priv_s *percpu_priv;
	int numstats = sizeof(struct rtnl_link_stats64) / sizeof(u64);

	for_each_online_cpu(i) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, i);

		cpustats = (u64 *)&percpu_priv->stats;

		for (j = 0; j < numstats; j++)
			netstats[j] += cpustats[j];
	}

	return stats;
}

static int dpa_generic_set_mac_address(struct net_device *net_dev,
				       void *addr)
{
	const struct dpa_generic_priv_s *priv = netdev_priv(net_dev);
	int _errno;

	_errno = eth_mac_addr(net_dev, addr);
	if (_errno < 0) {
		if (netif_msg_drv(priv))
			netdev_err(net_dev, "eth_mac_addr() = %d\n", _errno);
		return _errno;
	}

	return 0;
}

static const struct of_device_id dpa_generic_match[] = {
	{
		.compatible	= "fsl,dpa-ethernet-generic"
	},
	{}
};

MODULE_DEVICE_TABLE(of, dpa_generic_match);

static struct platform_driver dpa_generic_driver = {
	.driver = {
		.name		= KBUILD_MODNAME,
		.of_match_table	= dpa_generic_match,
		.owner		= THIS_MODULE,
	},
	.probe		= dpa_generic_eth_probe,
	.remove		= dpa_generic_remove
};

static int get_port_ref(struct device_node *dev_node,
		  struct fm_port **port)
{
	struct platform_device *port_of_dev = NULL;
	struct device *op_dev = NULL;
	struct device_node *port_node = NULL;

	port_node = of_parse_phandle(dev_node, "fsl,fman-oh-port", 0);
	if (port_node == NULL)
		return -EINVAL;

	port_of_dev = of_find_device_by_node(port_node);
	of_node_put(port_node);

	if (port_of_dev == NULL)
		return -EINVAL;

	/* get the reference to oh port from FMD */
	op_dev = &port_of_dev->dev;
	*port = fm_port_bind(op_dev);

	if (*port == NULL)
		return -EINVAL;

	return 0;
}

static void dpaa_generic_napi_enable(struct dpa_generic_priv_s *priv)
{
	struct dpa_percpu_priv_s *percpu_priv;
	int i, j;

	for_each_possible_cpu(i) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, i);

		for (j = 0; j < qman_portal_max; j++)
			napi_enable(&percpu_priv->np[j].napi);
	}
}

static void dpaa_generic_napi_disable(struct dpa_generic_priv_s *priv)
{
	struct dpa_percpu_priv_s *percpu_priv;
	int i, j;

	for_each_possible_cpu(i) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, i);

		for (j = 0; j < qman_portal_max; j++)
			napi_disable(&percpu_priv->np[j].napi);
	}
}

static struct device_node *get_rx_op_port_node(struct platform_device *_of_dev)
{
	struct device *dev = &_of_dev->dev;
	struct device_node *port_node = NULL;
	struct device_node *onic_node = NULL;
	int num_ports = 0;

	onic_node = dev->of_node;

	num_ports = of_count_phandle_with_args(onic_node, "fsl,oh-ports", NULL);
	if (num_ports != 2) {
		dev_err(dev, "There should be two O/H port handles in the device tree\n");
		return ERR_PTR(-EINVAL);
	}

	port_node = of_parse_phandle(onic_node, "fsl,oh-ports", 0);
	if (port_node == NULL) {
		dev_err(dev, "Cannot find O/H port node in the device tree\n");
		return ERR_PTR(-EFAULT);
	}

	return port_node;
}

static int __cold dpa_generic_start(struct net_device *netdev)
{
	struct dpa_generic_priv_s *priv = netdev_priv(netdev);

	/* seed default buffer pool */
	dpa_bp_priv_seed(priv->rx_bp);

	dpaa_generic_napi_enable(priv);
	netif_tx_start_all_queues(netdev);

	mod_timer(&priv->timer, jiffies + 100);

	return 0;
}

static int __cold dpa_generic_stop(struct net_device *netdev)
{
	struct dpa_generic_priv_s *priv = netdev_priv(netdev);

	netif_tx_stop_all_queues(netdev);
	dpaa_generic_napi_disable(priv);

	return 0;
}

static enum qman_cb_dqrr_result __hot
dpa_generic_rx_err_dqrr(struct qman_portal *portal,
			struct qman_fq *fq,
			const struct qm_dqrr_entry *dq)
{
	struct net_device		*netdev;
	struct dpa_generic_priv_s	*priv;
	struct dpa_percpu_priv_s	*percpu_priv;
	const struct qm_fd		*fd;
	int *countptr;

	netdev = ((struct dpa_fq *)fq)->net_dev;
	priv = netdev_priv(netdev);
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);
	countptr = raw_cpu_ptr(priv->rx_bp->percpu_count);
	fd = &dq->fd;

	/* TODO: extract bpid from the fd; when multiple bps are supported
	 * there won't be a default bp
	 */

	if (dpaa_eth_napi_schedule(percpu_priv, portal))
		return qman_cb_dqrr_stop;

	if (unlikely(dpaa_eth_refill_bpools(priv->rx_bp, countptr))) {
		/* Unable to refill the buffer pool due to insufficient
		 * system memory. Just release the frame back into the pool,
		 * otherwise we'll soon end up with an empty buffer pool.
		 */
		dpa_fd_release(netdev, fd);
		goto qman_consume;
	}

	/* limit common, possibly innocuous Rx FIFO Overflow errors'
	 * interference with zero-loss convergence benchmark results.
	 */
	if (likely(fd->status & FM_FD_STAT_ERR_PHYSICAL))
		pr_warn_once("fsl-dpa: non-zero error counters in fman statistics (sysfs)\n");
	else
		if (netif_msg_hw(priv) && net_ratelimit())
			netdev_err(netdev, "Err FD status 2 = 0x%08x\n",
					fd->status & FM_FD_STAT_RX_ERRORS);


	percpu_priv->stats.rx_errors++;

	if (fd->status & FM_PORT_FRM_ERR_DMA)
		percpu_priv->rx_errors.dme++;
	if (fd->status & FM_PORT_FRM_ERR_PHYSICAL)
		percpu_priv->rx_errors.fpe++;
	if (fd->status & FM_PORT_FRM_ERR_SIZE)
		percpu_priv->rx_errors.fse++;
	if (fd->status & FM_PORT_FRM_ERR_PRS_HDR_ERR)
		percpu_priv->rx_errors.phe++;

	/* TODO dpa_csum_validation */

	dpa_fd_release(netdev, fd);

qman_consume:
	return qman_cb_dqrr_consume;
}


static enum qman_cb_dqrr_result __hot
dpa_generic_rx_dqrr(struct qman_portal *portal,
		    struct qman_fq *fq,
		    const struct qm_dqrr_entry *dq)
{
	struct net_device *netdev;
	struct dpa_generic_priv_s *priv;
	struct dpa_bp *bp;
	struct dpa_percpu_priv_s *percpu_priv;
	struct sk_buff **skbh;
	struct sk_buff *skb;
	const struct qm_fd *fd = &dq->fd;
	unsigned int skb_len;
	u32 fd_status = fd->status;
	u64 pad;
	dma_addr_t addr = qm_fd_addr(fd);
	unsigned int data_start;
	unsigned long skb_addr;
	int *countptr;

	netdev = ((struct dpa_fq *)fq)->net_dev;
	priv = netdev_priv(netdev);
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);
	countptr = raw_cpu_ptr(priv->rx_bp->percpu_count);

	/* This is needed for TCP traffic as draining only on TX is not
	 * enough
	 */
	dpa_generic_drain_bp(priv->draining_tx_bp, 1);
	dpa_generic_drain_sg_bp(priv->draining_tx_sg_bp, 1);

	if (unlikely(dpaa_eth_napi_schedule(percpu_priv, portal)))
		return qman_cb_dqrr_stop;

	if (unlikely(dpaa_eth_refill_bpools(priv->rx_bp, countptr))) {
		/* Unable to refill the buffer pool due to insufficient
		 * system memory. Just release the frame back into the pool,
		 * otherwise we'll soon end up with an empty buffer pool.
		 */
		dpa_fd_release(netdev, fd);
		goto qman_consume;
	}

	DPA_READ_SKB_PTR(skb, skbh, phys_to_virt(addr), -1);

	if (unlikely(fd_status & FM_FD_STAT_RX_ERRORS) != 0) {
		if (netif_msg_hw(priv) && net_ratelimit())
			netdev_warn(netdev, "FD status = 0x%08x\n",
					fd->status & FM_FD_STAT_RX_ERRORS);

		percpu_priv->stats.rx_errors++;
		dpa_fd_release(netdev, fd);
		goto qman_consume;
	}
	if (unlikely(fd->format != qm_fd_contig)) {
		percpu_priv->stats.rx_dropped++;
		if (netif_msg_rx_status(priv) && net_ratelimit())
			netdev_warn(netdev, "Dropping a SG frame\n");
		dpa_fd_release(netdev, fd);
		goto qman_consume;
	}

	bp = dpa_bpid2pool(fd->bpid);

	/* find out the pad */
	skb_addr = virt_to_phys(skb->head);
	pad = addr - skb_addr;

	dma_unmap_single(bp->dev, addr, bp->size, DMA_BIDIRECTIONAL);

	countptr = raw_cpu_ptr(bp->percpu_count);
	(*countptr)--;

	/* The skb is currently pointed at head + headroom. The packet
	 * starts at skb->head + pad + fd offset.
	 */
	data_start = (unsigned int)(pad + dpa_fd_offset(fd) -
				    skb_headroom(skb));
	skb_put(skb, dpa_fd_length(fd) + data_start);
	skb_pull(skb, data_start);
	skb->protocol = eth_type_trans(skb, netdev);
	if (unlikely(dpa_check_rx_mtu(skb, netdev->mtu))) {
		percpu_priv->stats.rx_dropped++;
		dev_kfree_skb(skb);
		goto qman_consume;
	}

	skb_len = skb->len;

	if (fd->status & FM_FD_STAT_L4CV)
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	else
		skb->ip_summed = CHECKSUM_NONE;

	if (unlikely(netif_receive_skb(skb) == NET_RX_DROP))
		goto qman_consume;

	percpu_priv->stats.rx_packets++;
	percpu_priv->stats.rx_bytes += skb_len;

qman_consume:
	return qman_cb_dqrr_consume;
}

static void dpa_generic_drain_sg_bp(struct dpa_bp *sgbp, u8 nbuf)
{
	int ret;
	struct bm_buffer bmb[8];

	do {
		ret = bman_acquire(sgbp->pool, bmb, nbuf, 0);
	} while (ret >= 0);
}

inline void dpa_release_sg(struct sk_buff *skb, dma_addr_t addr,
		struct dpa_bp *bp)
{
	struct qm_sg_entry *sgt = phys_to_virt(addr + DPA_DEFAULT_TX_HEADROOM);
	int nr_frags = skb_shinfo(skb)->nr_frags;
	dma_addr_t sg_addr;
	int j;

	dma_unmap_single(bp->dev, addr, DPA_DEFAULT_TX_HEADROOM +
			sizeof(struct qm_sg_entry) * (1 + nr_frags),
			DMA_BIDIRECTIONAL);

	for (j = 0; j <= nr_frags; j++) {
		DPA_BUG_ON(sgt[j].extension);
		sg_addr = qm_sg_addr(&sgt[j]);
		dma_unmap_page(bp->dev, sg_addr,
				sgt[j].length, DMA_BIDIRECTIONAL);
	}

	dev_kfree_skb_any(skb);
}

inline void dpa_release_contig(struct sk_buff *skb, dma_addr_t addr,
		struct dpa_bp *bp)
{
	dma_unmap_single(bp->dev, addr, bp->size, DMA_BIDIRECTIONAL);
	dev_kfree_skb_any(skb);
}

static void dpa_generic_drain_bp(struct dpa_bp *bp, u8 nbuf)
{
	int ret, i;
	struct bm_buffer bmb[8];
	dma_addr_t addr;
	int *countptr = raw_cpu_ptr(bp->percpu_count);
	int count = *countptr;
	struct sk_buff **skbh;

	do {
		/* bman_acquire will fail if nbuf > 8 */
		ret = bman_acquire(bp->pool, bmb, nbuf, 0);
		if (ret > 0) {
			for (i = 0; i < nbuf; i++) {
				addr = bm_buf_addr(&bmb[i]);
				skbh = (struct sk_buff **)phys_to_virt(addr);
				dma_unmap_single(bp->dev, addr, bp->size,
						DMA_TO_DEVICE);

				if (skb_is_nonlinear(*skbh))
					dpa_release_sg(*skbh, addr, bp);
				else
					dpa_release_contig(*skbh, addr, bp);
			}
			count -= i;
		}
	} while (ret > 0);

	*countptr = count;
}

/**
 * Turn on HW checksum computation for this outgoing frame.
 * If the current protocol is not something we support in this regard
 * (or if the stack has already computed the SW checksum), we do nothing.
 *
 * Returns 0 if all goes well (or HW csum doesn't apply), and a negative value
 * otherwise.
 *
 * Note that this function may modify the fd->cmd field and the skb data buffer
 * (the Parse Results area).
 */
static int dpa_generic_tx_csum(struct dpa_generic_priv_s *priv,
			       struct sk_buff *skb,
			       struct qm_fd *fd,
			       char *parse_results)
{
	fm_prs_result_t *parse_result;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h = NULL;
	int l4_proto;
	int ethertype = ntohs(skb->protocol);
	int retval = 0;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	/* Note: L3 csum seems to be already computed in sw, but we can't choose
	 * L4 alone from the FM configuration anyway.
	 */

	/* Fill in some fields of the Parse Results array, so the FMan
	 * can find them as if they came from the FMan Parser.
	 */
	parse_result = (fm_prs_result_t *)parse_results;

	/* If we're dealing with VLAN, get the real Ethernet type */
	if (ethertype == ETH_P_8021Q) {
		/* We can't always assume the MAC header is set correctly
		 * by the stack, so reset to beginning of skb->data
		 */
		skb_reset_mac_header(skb);
		ethertype = ntohs(vlan_eth_hdr(skb)->h_vlan_encapsulated_proto);
	}

	/* Fill in the relevant L3 parse result fields
	 * and read the L4 protocol type
	 */
	switch (ethertype) {
	case ETH_P_IP:
		parse_result->l3r = FM_L3_PARSE_RESULT_IPV4;
		iph = ip_hdr(skb);
		BUG_ON(iph == NULL);
		l4_proto = iph->protocol;
		break;
	case ETH_P_IPV6:
		parse_result->l3r = FM_L3_PARSE_RESULT_IPV6;
		ipv6h = ipv6_hdr(skb);
		BUG_ON(ipv6h == NULL);
		l4_proto = ipv6h->nexthdr;
		break;
	default:
		/* We shouldn't even be here */
		if (netif_msg_tx_err(priv) && net_ratelimit())
			netdev_alert(priv->net_dev,
				     "Can't compute HW csum for L3 proto 0x%x\n",
				     ntohs(skb->protocol));
		retval = -EIO;
		goto return_error;
	}

	/* Fill in the relevant L4 parse result fields */
	switch (l4_proto) {
	case IPPROTO_UDP:
		parse_result->l4r = FM_L4_PARSE_RESULT_UDP;
		break;
	case IPPROTO_TCP:
		parse_result->l4r = FM_L4_PARSE_RESULT_TCP;
		break;
	default:
		/* This can as well be a BUG() */
		if (netif_msg_tx_err(priv) && net_ratelimit())
			netdev_alert(priv->net_dev,
				     "Can't compute HW csum for L4 proto 0x%x\n",
				     l4_proto);
		retval = -EIO;
		goto return_error;
	}

	/* At index 0 is IPOffset_1 as defined in the Parse Results */
	parse_result->ip_off[0] = (uint8_t)skb_network_offset(skb);
	parse_result->l4_off = (uint8_t)skb_transport_offset(skb);

	/* Enable L3 (and L4, if TCP or UDP) HW checksum. */
	fd->cmd |= FM_FD_CMD_RPD | FM_FD_CMD_DTC;

	/* On P1023 and similar platforms fd->cmd interpretation could
	 * be disabled by setting CONTEXT_A bit ICMD; currently this bit
	 * is not set so we do not need to check; in the future, if/when
	 * using context_a we need to check this bit
	 */

return_error:
	return retval;
}

static inline int generic_skb_to_sg_fd(struct dpa_generic_priv_s *priv,
		struct sk_buff *skb, struct qm_fd *fd)
{
	struct dpa_bp *dpa_bp = priv->draining_tx_bp;
	struct dpa_bp *dpa_sg_bp = priv->draining_tx_sg_bp;
	dma_addr_t addr;
	struct sk_buff **skbh;
	struct net_device *net_dev = priv->net_dev;
	int err;

	struct qm_sg_entry *sgt;
	void *sgt_buf;
	void *buffer_start;
	skb_frag_t *frag;
	int i, j;
	const enum dma_data_direction dma_dir = DMA_BIDIRECTIONAL;
	const int nr_frags = skb_shinfo(skb)->nr_frags;

	memset(fd, 0, sizeof(*fd));
	fd->format = qm_fd_sg;

	/* get a page frag to store the SGTable */
	sgt_buf = netdev_alloc_frag(priv->tx_headroom +
			sizeof(struct qm_sg_entry) * (1 + nr_frags));
	if (unlikely(!sgt_buf)) {
		dev_err(dpa_bp->dev, "netdev_alloc_frag() failed\n");
		return -ENOMEM;
	}

	memset(sgt_buf, 0, priv->tx_headroom +
			sizeof(struct qm_sg_entry) * (1 + nr_frags));

	/* do this before dma_map_single(DMA_TO_DEVICE), because we may need to
	 * write into the skb.
	 */
	err = dpa_generic_tx_csum(priv, skb, fd,
			sgt_buf + DPA_TX_PRIV_DATA_SIZE);
	if (unlikely(err < 0)) {
		if (netif_msg_tx_err(priv) && net_ratelimit())
			netdev_err(net_dev, "HW csum error: %d\n", err);
		goto csum_failed;
	}

	sgt = (struct qm_sg_entry *)(sgt_buf + priv->tx_headroom);
	sgt[0].bpid = dpa_sg_bp->bpid;
	sgt[0].offset = 0;
	sgt[0].length = skb_headlen(skb);
	sgt[0].extension = 0;
	sgt[0].final = 0;

	addr = dma_map_single(dpa_sg_bp->dev, skb->data, sgt[0].length,
			dma_dir);
	if (unlikely(dma_mapping_error(dpa_sg_bp->dev, addr))) {
		dev_err(dpa_sg_bp->dev, "DMA mapping failed");
		err = -EINVAL;
		goto sg0_map_failed;
	}

	sgt[0].addr_hi = (uint8_t)upper_32_bits(addr);
	sgt[0].addr_lo = cpu_to_be32(lower_32_bits(addr));

	/* populate the rest of SGT entries */
	for (i = 1; i <= nr_frags; i++) {
		frag = &skb_shinfo(skb)->frags[i - 1];
		sgt[i].bpid = dpa_sg_bp->bpid;
		sgt[i].offset = 0;
		sgt[i].length = frag->size;
		sgt[i].extension = 0;
		sgt[i].final = 0;

		DPA_BUG_ON(!skb_frag_page(frag));
		addr = skb_frag_dma_map(dpa_bp->dev, frag, 0, sgt[i].length,
				dma_dir);
		if (unlikely(dma_mapping_error(dpa_sg_bp->dev, addr))) {
			dev_err(dpa_sg_bp->dev, "DMA mapping failed");
			err = -EINVAL;
			goto sg_map_failed;
		}

		/* keep the offset in the address */
		sgt[i].addr_hi = (uint8_t)upper_32_bits(addr);
		sgt[i].addr_lo = cpu_to_be32(lower_32_bits(addr));
	}
	sgt[i - 1].final = 1;

	fd->length20 = skb->len;
	fd->offset = priv->tx_headroom;

	/* DMA map the SGT page */
	buffer_start = (void *)sgt - dpa_fd_offset(fd);
	/* Can't write at "negative" offset in buffer_start, because this skb
	 * may not have been allocated by us.
	 */
	DPA_WRITE_SKB_PTR(skb, skbh, buffer_start, 0);

	addr = dma_map_single(dpa_bp->dev, buffer_start,
			priv->tx_headroom + sizeof(struct qm_sg_entry) * (1 + nr_frags),
			dma_dir);
	if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
		dev_err(dpa_bp->dev, "DMA mapping failed");
		err = -EINVAL;
		goto sgt_map_failed;
	}

	fd->bpid = dpa_bp->bpid;
	fd->addr_hi = (uint8_t)upper_32_bits(addr);
	fd->addr_lo = lower_32_bits(addr);

	return 0;

sgt_map_failed:
sg_map_failed:
	for (j = 0; j < i; j++)
		dma_unmap_page(dpa_sg_bp->dev, qm_sg_addr(&sgt[j]),
				be32_to_cpu(sgt[j].length), dma_dir);
sg0_map_failed:
csum_failed:
	put_page(virt_to_head_page(sgt_buf));

	return err;
}

static int __hot dpa_generic_tx(struct sk_buff *skb, struct net_device *netdev)
{
	struct dpa_generic_priv_s *priv = netdev_priv(netdev);
	struct dpa_percpu_priv_s *percpu_priv =
		raw_cpu_ptr(priv->percpu_priv);
	struct rtnl_link_stats64 *percpu_stats = &percpu_priv->stats;
	struct dpa_bp *bp = priv->draining_tx_bp;
	struct dpa_bp *sg_bp = priv->draining_tx_sg_bp;
	struct sk_buff **skbh = NULL;
	dma_addr_t addr;
	struct qm_fd fd;
	int queue_mapping;
	struct qman_fq *egress_fq;
	const bool nonlinear = skb_is_nonlinear(skb);
	int i = 0, err = 0;
	int *countptr;

	if (nonlinear && skb_shinfo(skb)->nr_frags < DPA_SGT_MAX_ENTRIES) {
		err = generic_skb_to_sg_fd(priv, skb, &fd);
		if (unlikely(err < 0))
			goto sg_failed;
		percpu_priv->tx_frag_skbuffs++;
		addr = qm_fd_addr(&fd);
	} else {
		if (unlikely(skb_headroom(skb) < priv->tx_headroom)) {
			struct sk_buff *skb_new;

			skb_new = skb_realloc_headroom(skb, priv->tx_headroom);
			if (unlikely(!skb_new)) {
				percpu_stats->tx_errors++;
				kfree_skb(skb);
				goto done;
			}

			kfree_skb(skb);
			skb = skb_new;
		}

		clear_fd(&fd);

		/* store skb backpointer to release the skb later */
		skbh = (struct sk_buff **)(skb->data - priv->tx_headroom);
		*skbh = skb;

		/* do this before dma_map_single(), because we may need to write
		 * into the skb.
		 */
		err = dpa_generic_tx_csum(priv, skb, &fd,
				((char *)skbh) + DPA_TX_PRIV_DATA_SIZE);
		if (unlikely(err < 0)) {
			if (netif_msg_tx_err(priv) && net_ratelimit())
				netdev_err(netdev, "HW csum error: %d\n", err);
			return err;
		}

		addr = dma_map_single(bp->dev, skbh,
				skb->len + priv->tx_headroom, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(bp->dev, addr))) {
			if (netif_msg_tx_err(priv)  && net_ratelimit())
				netdev_err(netdev, "dma_map_single() failed\n");
			goto dma_mapping_failed;
		}

		fd.format = qm_fd_contig;
		fd.length20 = skb->len;
		fd.offset = priv->tx_headroom;
		fd.addr_hi = (uint8_t)upper_32_bits(addr);
		fd.addr_lo = lower_32_bits(addr);
		/* fd.cmd |= FM_FD_CMD_FCO; */
		fd.bpid = bp->bpid;
	}

	dpa_generic_drain_bp(bp, 1);
	dpa_generic_drain_sg_bp(sg_bp, 1);

	queue_mapping = dpa_get_queue_mapping(skb);
	egress_fq = priv->egress_fqs[queue_mapping];

	for (i = 0; i < 100000; i++) {
		err = qman_enqueue(egress_fq, &fd, 0);
		if (err != -EBUSY)
			break;
	}

	if (unlikely(err < 0)) {
		percpu_stats->tx_fifo_errors++;
		goto xmit_failed;
	}

	countptr = raw_cpu_ptr(bp->percpu_count);
	(*countptr)++;

	percpu_stats->tx_packets++;
	percpu_stats->tx_bytes += fd.length20;
	netdev->trans_start = jiffies;

	goto done;

xmit_failed:
	dma_unmap_single(bp->dev, addr, fd.offset + fd.length20, DMA_TO_DEVICE);
sg_failed:
dma_mapping_failed:
	percpu_stats->tx_errors++;
	dev_kfree_skb(skb);
done:
	return NETDEV_TX_OK;
}

static int dpa_generic_napi_add(struct net_device *net_dev)
{
	struct dpa_generic_priv_s *priv = netdev_priv(net_dev);
	struct dpa_percpu_priv_s *percpu_priv;
	int i, cpu;

	for_each_possible_cpu(cpu) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, cpu);

		percpu_priv->np = devm_kzalloc(net_dev->dev.parent,
			qman_portal_max * sizeof(struct dpa_napi_portal),
			GFP_KERNEL);

		if (unlikely(percpu_priv->np == NULL)) {
			dev_err(net_dev->dev.parent, "devm_kzalloc() failed\n");
			return -ENOMEM;
		}

		for (i = 0; i < qman_portal_max; i++)
			netif_napi_add(net_dev, &percpu_priv->np[i].napi,
					dpaa_eth_poll, DPA_GENERIC_NAPI_WEIGHT);
	}

	return 0;
}

static void dpa_generic_napi_del(struct net_device *net_dev)
{
	struct dpa_generic_priv_s *priv = netdev_priv(net_dev);
	struct dpa_percpu_priv_s *percpu_priv;
	int i, cpu;

	for_each_possible_cpu(cpu) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, cpu);

		if (percpu_priv->np) {
			for (i = 0; i < qman_portal_max; i++)
				netif_napi_del(&percpu_priv->np[i].napi);

			devm_kfree(net_dev->dev.parent, percpu_priv->np);
		}
	}
}


static int dpa_generic_netdev_init(struct device_node *dpa_node,
				   struct net_device *netdev)
{
	struct dpa_generic_priv_s *priv = netdev_priv(netdev);
	struct device *dev = netdev->dev.parent;
	const uint8_t *mac_addr;
	int err;

	netdev->netdev_ops = &dpa_generic_ops;

	mac_addr = of_get_mac_address(dpa_node);
	if (mac_addr == NULL) {
		if (netif_msg_probe(priv))
			dev_err(dev, "No virtual MAC address found!\n");
		return -EINVAL;
	}

	netdev->hw_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_SG;
	netdev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	netdev->features |= netdev->hw_features;
	netdev->vlan_features = netdev->features;

	memcpy(netdev->perm_addr, mac_addr, netdev->addr_len);
	memcpy(netdev->dev_addr, mac_addr, netdev->addr_len);

	netdev->ethtool_ops = &dpa_generic_ethtool_ops;

	netdev->needed_headroom = priv->tx_headroom;
	netdev->watchdog_timeo = msecs_to_jiffies(tx_timeout);

	err = register_netdev(netdev);
	if (err < 0) {
		dev_err(dev, "register_netdev() = %d\n", err);
		return err;
	}

	return 0;
}

static struct dpa_fq_cbs_t generic_fq_cbs = {
	.rx_defq = { .cb = { .dqrr = dpa_generic_rx_dqrr } },
	.rx_errq = { .cb = { .dqrr = dpa_generic_rx_err_dqrr } },
	.egress_ern = { .cb = { .ern = dpa_generic_ern } }
};

static struct fqid_cell *__fq_alloc(struct device *dev,
				   int num_ranges,
				   const void *fqids_off)
{
	struct fqid_cell *fqids;
	int i;

	fqids = kzalloc(sizeof(*fqids) * num_ranges, GFP_KERNEL);
	if (fqids == NULL)
		return NULL;

	/* convert to CPU endianess */
	for (i = 0; i < num_ranges; i++) {
		fqids[i].start = be32_to_cpup(fqids_off +
				i * sizeof(*fqids));
		fqids[i].count = be32_to_cpup(fqids_off +
				i * sizeof(*fqids) + sizeof(__be32));
	}

	return fqids;
}

static struct list_head *dpa_generic_fq_probe(struct platform_device *_of_dev,
					      struct fm_port *tx_port)
{
	struct device *dev = &_of_dev->dev;
	struct device_node *oh_node = NULL;
	struct device_node *onic_node = NULL;
	struct fqid_cell *fqids;
	const void *fqids_off;
	struct dpa_fq *fq, *tmp;
	struct list_head *list;
	int num_ranges;
	int i, lenp;

	onic_node = dev->of_node;

	list = devm_kzalloc(dev, sizeof(*list), GFP_KERNEL);
	if (!list) {
		dev_err(dev, "Cannot allocate space for frame queues list\n");
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(list);

	/* RX queues (RX error, RX default) are specified in Rx O/H port node */
	oh_node = get_rx_op_port_node(_of_dev);
	fqids_off = of_get_property(oh_node, "fsl,qman-frame-queues-oh", &lenp);
	if (fqids_off == NULL) {
		dev_err(dev, "Need Rx FQ definition in dts for generic devices\n");
		return ERR_PTR(-EINVAL);
	}
	of_node_put(oh_node);

	num_ranges = lenp / sizeof(*fqids);
	if (num_ranges != 2) {
		dev_err(dev, "Need 2 Rx FQ definitions in dts for generic devices\n");
		return ERR_PTR(-EINVAL);
	}

	fqids = __fq_alloc(dev, num_ranges, fqids_off);
	if (!dpa_fq_alloc(dev, fqids[0].start, fqids[0].count, list,
			  FQ_TYPE_RX_ERROR) ||
			!dpa_fq_alloc(dev, fqids[1].start, fqids[1].count,
				      list, FQ_TYPE_RX_DEFAULT)) {
		kfree(fqids);
		dev_err(dev, "Cannot allocate space for default frame queues\n");
		return ERR_PTR(-ENOMEM);
	}
	kfree(fqids);

	/* TX queues */
	fqids_off = of_get_property(onic_node, "fsl,qman-frame-queues-tx",
			&lenp);
	if (fqids_off == NULL) {
		dev_err(dev, "Need Tx FQ definition in dts for generic devices\n");
		return ERR_PTR(-EINVAL);
	}

	num_ranges = lenp / sizeof(*fqids);
	fqids = __fq_alloc(dev, num_ranges, fqids_off);
	for (i = 0; i < num_ranges; i++) {
		if (!dpa_fq_alloc(dev, fqids[i].start, fqids[i].count, list,
				  FQ_TYPE_TX)) {
			dev_err(dev, "_dpa_fq_alloc() failed\n");
			kfree(fqids);
			return ERR_PTR(-ENOMEM);
		}
	}
	kfree(fqids);

	/* optional RX PCD queues */
	lenp = 0;
	fqids_off = of_get_property(onic_node,
			"fsl,qman-frame-queues-rx", &lenp);
	if (fqids_off) {
		num_ranges = lenp / sizeof(*fqids);
		fqids = __fq_alloc(dev, num_ranges, fqids_off);
		for (i = 0; i < num_ranges; i++) {
			if (!dpa_fq_alloc(dev, fqids[i].start, fqids[i].count, list,
				  	  FQ_TYPE_RX_PCD)) {
				dev_err(dev, "_dpa_fq_alloc() failed\n");
				kfree(fqids);
				return ERR_PTR(-ENOMEM);
			}
		}
		kfree(fqids);
	}

	list_for_each_entry_safe(fq, tmp, list, list) {
		if (fq->fq_type == FQ_TYPE_TX)
			fq->channel = fm_get_tx_port_channel(tx_port);
	}

	return list;
}

static void dpa_generic_ern(struct qman_portal *portal,
			    struct qman_fq *fq,
			    const struct qm_mr_entry *msg)
{
	struct net_device *netdev;
	const struct dpa_generic_priv_s *priv;
	struct dpa_percpu_priv_s *percpu_priv;
	struct qm_fd fd = msg->ern.fd;

	netdev = ((struct dpa_fq *)fq)->net_dev;
	priv = netdev_priv(netdev);
	/* Non-migratable context, safe to use raw_cpu_ptr */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);
	percpu_priv->stats.tx_dropped++;
	percpu_priv->stats.tx_fifo_errors++;
	count_ern(percpu_priv, msg);

	/* release this buffer into the draining buffer pool */
	dpa_fd_release(netdev, &fd);
}

static int dpa_generic_rx_bp_probe(struct platform_device *_of_dev,
				   struct fm_port *rx_port,
				   int *rx_bp_count,
				   struct dpa_bp **rx_bp,
				   struct dpa_buffer_layout_s **rx_buf_layout)
{
	struct device *dev = &_of_dev->dev;
	struct fm_port_params params;
	struct dpa_bp *bp = NULL;
	int bp_count = 0;
	int bpid;
	const __be32 *bpool_cfg = NULL;
	struct device_node *dev_node = NULL;
	struct device_node *oh_node = NULL;
	struct dpa_buffer_layout_s *buf_layout = NULL;
	int lenp = 0;
	int na = 0, ns = 0;
	int err = 0, i = 0;

	oh_node = get_rx_op_port_node(_of_dev);

	bp_count = of_count_phandle_with_args(oh_node,
			"fsl,bman-buffer-pools", NULL);
	if (bp_count <= 0) {
		dev_err(dev, "Missing buffer pool handles from onic node from device tree\n");
		return -EINVAL;
	}

	bp = devm_kzalloc(dev, bp_count * sizeof(*bp), GFP_KERNEL);
	if (unlikely(bp == NULL)) {
		dev_err(dev, "devm_kzalloc() failed\n");
		err = -ENOMEM;
		goto _return_of_node_put;
	}

	dev_node = of_find_node_by_path("/");
	if (unlikely(dev_node == NULL)) {
		dev_err(dev, "of_find_node_by_path(/) failed\n");
		err = -EINVAL;
		goto _return_of_node_put;
	}

	na = of_n_addr_cells(dev_node);
	ns = of_n_size_cells(dev_node);

	of_node_put(dev_node);

	for (i = 0; i < bp_count; i++) {
		dev_node = of_parse_phandle(oh_node,
				"fsl,bman-buffer-pools", i);
		if (dev_node == NULL) {
			dev_err(dev, "Cannot find buffer pool node in the device tree\n");
			err = -EINVAL;
			goto _return_of_node_put;
		}

		err = of_property_read_u32(dev_node, "fsl,bpid", &bpid);
		if (err) {
			dev_err(dev, "Cannot find buffer pool ID in the buffer pool node in the device tree\n");
			goto _return_of_node_put;
		}

		bp[i].bpid = (uint8_t)bpid;

		bpool_cfg = of_get_property(dev_node, "fsl,bpool-ethernet-cfg",
				&lenp);
		if (bpool_cfg && (lenp == (2 * ns + na) * sizeof(*bpool_cfg))) {
			bp[i].config_count = (int)of_read_number(bpool_cfg, ns);
			bp[i].size = of_read_number(bpool_cfg + ns, ns);
			bp[i].paddr = 0;
			bp[i].seed_pool = false;
		} else {
			dev_err(dev, "Missing/invalid fsl,bpool-ethernet-cfg device tree entry for node %s\n",
					dev_node->full_name);
			err = -EINVAL;
			goto _return_of_node_put;
		}

		bp[i].percpu_count = devm_alloc_percpu(dev,
						       *bp[i].percpu_count);
	}

	of_node_put(oh_node);

	buf_layout = devm_kzalloc(dev, sizeof(*buf_layout), GFP_KERNEL);
	if (!buf_layout) {
		dev_err(dev, "devm_kzalloc() failed\n");
		err = -ENOMEM;
		goto _return_of_node_put;
	}

	buf_layout->priv_data_size = DPA_TX_PRIV_DATA_SIZE;
	buf_layout->parse_results = false;
	buf_layout->hash_results = false;
	buf_layout->time_stamp = false;
	fm_port_get_buff_layout_ext_params(rx_port, &params);
	buf_layout->manip_extra_space = params.manip_extra_space;
	/* a value of zero for data alignment means "don't care", so align to
	 * a non-zero value to prevent FMD from using its own default
	 */
	buf_layout->data_align = params.data_align ? : DPA_FD_DATA_ALIGNMENT;

	*rx_buf_layout = buf_layout;
	*rx_bp = bp;
	*rx_bp_count = bp_count;

	return 0;

_return_of_node_put:
	if (dev_node)
		of_node_put(dev_node);

	return err;
}

static int dpa_generic_tx_bp_probe(struct platform_device *_of_dev,
				   struct fm_port *tx_port,
				   struct dpa_bp **draining_tx_bp,
				   struct dpa_bp **draining_tx_sg_bp,
				   struct dpa_buffer_layout_s **tx_buf_layout)
{
	struct device *dev = &_of_dev->dev;
	struct fm_port_params params;
	struct dpa_bp *bp = NULL;
	struct dpa_bp *bp_sg = NULL;
	struct dpa_buffer_layout_s *buf_layout = NULL;

	buf_layout = devm_kzalloc(dev, sizeof(*buf_layout), GFP_KERNEL);
	if (!buf_layout) {
		dev_err(dev, "devm_kzalloc() failed\n");
		return -ENOMEM;
	}

	buf_layout->priv_data_size = DPA_TX_PRIV_DATA_SIZE;
	buf_layout->parse_results = true;
	buf_layout->hash_results = true;
	buf_layout->time_stamp = false;

	fm_port_get_buff_layout_ext_params(tx_port, &params);
	buf_layout->manip_extra_space = params.manip_extra_space;
	buf_layout->data_align = params.data_align ? : DPA_FD_DATA_ALIGNMENT;

	bp = devm_kzalloc(dev, sizeof(*bp), GFP_KERNEL);
	if (unlikely(bp == NULL)) {
		dev_err(dev, "devm_kzalloc() failed\n");
		return -ENOMEM;
	}

	bp->size = dpa_bp_size(buf_layout);
	bp->percpu_count = devm_alloc_percpu(dev, *bp->percpu_count);
	bp->target_count = CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT;

	*draining_tx_bp = bp;

	bp_sg = devm_kzalloc(dev, sizeof(*bp_sg), GFP_KERNEL);
	if (unlikely(bp_sg == NULL)) {
		dev_err(dev, "devm_kzalloc() failed\n");
		return -ENOMEM;
	}

	bp_sg->size = dpa_bp_size(buf_layout);
	bp_sg->percpu_count = alloc_percpu(*bp_sg->percpu_count);
	bp_sg->target_count = CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT;

	*draining_tx_sg_bp = bp_sg;

	*tx_buf_layout = buf_layout;

	return 0;
}

static int dpa_generic_buff_dealloc_probe(struct platform_device *_of_dev,
					  int *disable_buff_dealloc)
{
	struct device *dev = &_of_dev->dev;
	const phandle *disable_handle = NULL;
	int lenp = 0;
	int err = 0;

	disable_handle = of_get_property(dev->of_node,
			"fsl,disable_buff_dealloc", &lenp);
	if (disable_handle != NULL)
		*disable_buff_dealloc = 1;

	return err;
}

static int dpa_generic_port_probe(struct platform_device *_of_dev,
				  struct fm_port **rx_port,
				  struct fm_port **tx_port)
{
	struct device *dev = &_of_dev->dev;
	struct device_node *dev_node = NULL;
	struct device_node *onic_node = NULL;
	int num_ports = 0;
	int err = 0;

	onic_node = dev->of_node;

	num_ports = of_count_phandle_with_args(onic_node, "fsl,oh-ports", NULL);
	if (num_ports != 2) {
		dev_err(dev, "There should be two OH ports in device tree (one for RX, one for TX\n");
		return -EINVAL;
	}

	dev_node = of_parse_phandle(onic_node, "fsl,oh-ports", RX);
	if (dev_node == NULL) {
		dev_err(dev, "Cannot find Rx OH port node in device tree\n");
		return err;
	}

	err = get_port_ref(dev_node, rx_port);
	if (err) {
		dev_err(dev, "Cannot read Rx OH port node in device tree\n");
		return err;
	}

	dev_node = of_parse_phandle(onic_node, "fsl,oh-ports", TX);
	if (dev_node == NULL) {
		dev_err(dev, "Cannot find Tx OH port node in device tree\n");
		return -EFAULT;
	}

	err = get_port_ref(dev_node, tx_port);
	if (err) {
		dev_err(dev, "Cannot read Tx OH port node in device tree\n");
		return err;
	}

	return 0;
}

static inline void dpa_generic_setup_ingress(
		const struct dpa_generic_priv_s *priv,
		struct dpa_fq *fq,
		const struct qman_fq *template)
{
	fq->fq_base = *template;
	fq->net_dev = priv->net_dev;

	fq->flags = QMAN_FQ_FLAG_NO_ENQUEUE;
	fq->channel = priv->channel;
}

static inline void dpa_generic_setup_egress(
		const struct dpa_generic_priv_s *priv,
		struct dpa_fq *fq,
		struct fm_port *port,
		const struct qman_fq *template)
{
	fq->fq_base = *template;
	fq->net_dev = priv->net_dev;

	fq->flags = QMAN_FQ_FLAG_TO_DCPORTAL;
	fq->channel = fm_get_tx_port_channel(port);
}

static void dpa_generic_fq_setup(struct dpa_generic_priv_s *priv,
				 const struct dpa_fq_cbs_t *fq_cbs,
				 struct fm_port *tx_port)
{
	struct dpa_fq *fq;
	int egress_cnt = 0;

	/* Initialize each FQ in the list */
	list_for_each_entry(fq, &priv->dpa_fq_list, list) {
		switch (fq->fq_type) {
		case FQ_TYPE_RX_DEFAULT:
			dpa_generic_setup_ingress(priv, fq, &fq_cbs->rx_defq);
			break;
		case FQ_TYPE_RX_ERROR:
			dpa_generic_setup_ingress(priv, fq, &fq_cbs->rx_errq);
			break;
		case FQ_TYPE_RX_PCD:
			dpa_generic_setup_ingress(priv, fq, &fq_cbs->rx_defq);
			break;
		case FQ_TYPE_TX:
			dpa_generic_setup_egress(priv, fq,
					tx_port, &fq_cbs->egress_ern);
			/* If we have more Tx queues than the number of cores,
			 * just ignore the extra ones.
			 */
			if (egress_cnt < DPAA_ETH_TX_QUEUES)
				priv->egress_fqs[egress_cnt++] = &fq->fq_base;
			break;
		default:
			dev_warn(priv->net_dev->dev.parent,
				 "Unknown FQ type detected!\n");
			break;
		}
	}

	/* The number of Tx queues may be smaller than the number of cores, if
	 * the Tx queue range is specified in the device tree instead of being
	 * dynamically allocated.
	 * Make sure all CPUs receive a corresponding Tx queue.
	 */
	while (egress_cnt < DPAA_ETH_TX_QUEUES) {
		list_for_each_entry(fq, &priv->dpa_fq_list, list) {
			if (fq->fq_type != FQ_TYPE_TX)
				continue;
			priv->egress_fqs[egress_cnt++] = &fq->fq_base;
			if (egress_cnt == DPAA_ETH_TX_QUEUES)
				break;
		}
	}
}

static int dpa_generic_fq_init(struct dpa_fq *dpa_fq, int disable_buff_dealloc)
{
	int			 _errno;
	struct device		*dev;
	struct qman_fq		*fq;
	struct qm_mcc_initfq	 initfq;

	dev = dpa_fq->net_dev->dev.parent;

	if (dpa_fq->fqid == 0)
		dpa_fq->flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;

	_errno = qman_create_fq(dpa_fq->fqid, dpa_fq->flags, &dpa_fq->fq_base);
	if (_errno) {
		dev_err(dev, "qman_create_fq() failed\n");
		return _errno;
	}
	fq = &dpa_fq->fq_base;

	initfq.we_mask = QM_INITFQ_WE_FQCTRL;
	/* FIXME: why would we want to keep an empty FQ in cache? */
	initfq.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;

	/* FQ placement */
	initfq.we_mask |= QM_INITFQ_WE_DESTWQ;

	initfq.fqd.dest.channel	= dpa_fq->channel;
	initfq.fqd.dest.wq = dpa_fq->wq;

	if (dpa_fq->fq_type == FQ_TYPE_TX && !disable_buff_dealloc) {
		initfq.we_mask |= QM_INITFQ_WE_CONTEXTA;
		/* ContextA: A2V=1 (contextA A2 field is valid)
		 * ContextA A2: EBD=1 (deallocate buffers inside FMan)
		 */
		initfq.fqd.context_a.hi = 0x10000000;
		initfq.fqd.context_a.lo = 0x80000000;
	}

	/* Initialization common to all ingress queues */
	if (dpa_fq->flags & QMAN_FQ_FLAG_NO_ENQUEUE) {
		initfq.we_mask |= QM_INITFQ_WE_CONTEXTA;
		initfq.fqd.fq_ctrl |=
			QM_FQCTRL_CTXASTASHING | QM_FQCTRL_AVOIDBLOCK;
		initfq.fqd.context_a.stashing.exclusive =
			QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_CTX |
			QM_STASHING_EXCL_ANNOTATION;
		initfq.fqd.context_a.stashing.data_cl = 2;
		initfq.fqd.context_a.stashing.annotation_cl = 1;
		initfq.fqd.context_a.stashing.context_cl =
			DIV_ROUND_UP(sizeof(struct qman_fq), 64);
	}

	_errno = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &initfq);
	if (_errno < 0) {
		dev_err(dev, "qman_init_fq(%u) = %d\n",
				qman_fq_fqid(fq), _errno);
		qman_destroy_fq(fq, 0);
		return _errno;
	}

	dpa_fq->fqid = qman_fq_fqid(fq);

	return 0;
}

static int dpa_generic_fq_create(struct net_device *netdev,
				 struct list_head *dpa_fq_list,
				 struct fm_port *tx_port)
{
	struct dpa_generic_priv_s *priv = netdev_priv(netdev);
	struct dpa_fq *fqs = NULL, *tmp = NULL;
	struct task_struct *kth;
	int err = 0;
	int channel;

	INIT_LIST_HEAD(&priv->dpa_fq_list);

	list_replace_init(dpa_fq_list, &priv->dpa_fq_list);

	channel = dpa_get_channel();
	if (channel < 0)
		return channel;
	priv->channel = (uint16_t)channel;

	/* Start a thread that will walk the cpus with affine portals
	 * and add this pool channel to each's dequeue mask.
	 */
	kth = kthread_run(dpaa_eth_add_channel,
			  (void *)(unsigned long)priv->channel,
			  "dpaa_%p:%d", netdev, priv->channel);
	if (!kth)
		return -ENOMEM;

	dpa_generic_fq_setup(priv, &generic_fq_cbs, tx_port);

	/* Add the FQs to the interface, and make them active */
	list_for_each_entry_safe(fqs, tmp, &priv->dpa_fq_list, list) {
		err = dpa_generic_fq_init(fqs, priv->disable_buff_dealloc);
		if (err)
			return err;
	}

	return 0;
}

static int dpa_generic_bp_create(struct net_device *net_dev,
				 int rx_bp_count,
				 struct dpa_bp *rx_bp,
				 struct dpa_buffer_layout_s *rx_buf_layout,
				 struct dpa_bp *draining_tx_bp,
				 struct dpa_bp *draining_tx_sg_bp,
				 struct dpa_buffer_layout_s *tx_buf_layout)
{
	struct dpa_generic_priv_s *priv = netdev_priv(net_dev);
	int err = 0;

	/* TODO: multiple Rx bps */
	priv->rx_bp_count = rx_bp_count;
	priv->rx_bp = rx_bp;
	priv->rx_buf_layout = rx_buf_layout;
	priv->draining_tx_bp = draining_tx_bp;
	priv->draining_tx_sg_bp = draining_tx_sg_bp;
	priv->tx_buf_layout = tx_buf_layout;

	err = dpa_bp_alloc(priv->rx_bp);
	if (err < 0) {
		priv->rx_bp = NULL;
		return err;
	}

	err = dpa_bp_alloc(priv->draining_tx_bp);
	if (err < 0) {
		priv->draining_tx_bp = NULL;
		return err;
	}

	err = dpa_bp_alloc(priv->draining_tx_sg_bp);
	if (err < 0) {
		priv->draining_tx_sg_bp = NULL;
		return err;
	}

	return 0;
}

static void dpa_generic_relase_bp(struct dpa_bp *bp)
{
	if (!bp)
		return;

	if (!atomic_dec_and_test(&bp->refs))
		return;

	if (bp->free_buf_cb)
		dpa_bp_drain(bp);

	bman_free_pool(bp->pool);

	if (bp->dev)
		platform_device_unregister(to_platform_device(bp->dev));
}

static void dpa_generic_bp_free(struct dpa_generic_priv_s *priv)
{
	int i = 0;

	/* release the rx bpools */
	for (i = 0; i < priv->rx_bp_count; i++)
		dpa_generic_relase_bp(&priv->rx_bp[i]);

	/* release the tx draining bpools */
	dpa_generic_relase_bp(priv->draining_tx_bp);
	dpa_generic_relase_bp(priv->draining_tx_sg_bp);
}

static int dpa_generic_remove(struct platform_device *of_dev)
{
	int err;
	struct device *dev;
	struct net_device *net_dev;
	struct dpa_generic_priv_s *priv;

	dev = &of_dev->dev;
	net_dev = dev_get_drvdata(dev);
	priv = netdev_priv(net_dev);

	dpaa_eth_generic_sysfs_remove(dev);

	dev_set_drvdata(dev, NULL);
	unregister_netdev(net_dev);

	err = dpa_fq_free(dev, &priv->dpa_fq_list);

	dpa_generic_napi_del(net_dev);

	dpa_generic_bp_free(priv);

	free_netdev(net_dev);

	return err;
}

static int dpa_generic_eth_probe(struct platform_device *_of_dev)
{
	struct device *dev = &_of_dev->dev;
	struct device_node *dpa_node = dev->of_node;
	struct net_device *netdev = NULL;
	struct dpa_generic_priv_s *priv;
	struct fm_port *rx_port = NULL;
	struct fm_port *tx_port = NULL;
	struct dpa_percpu_priv_s *percpu_priv;
	int rx_bp_count = 0;
	int disable_buff_dealloc = 0;
	struct dpa_bp *rx_bp = NULL, *draining_tx_bp = NULL;
	struct dpa_bp *draining_tx_sg_bp = NULL;
	struct dpa_buffer_layout_s *rx_buf_layout = NULL, *tx_buf_layout = NULL;
	struct list_head *dpa_fq_list;
	static u8 generic_idx;
	int err = 0;
	int i = 0;

	if (!of_device_is_available(dpa_node))
		return -ENODEV;

	err = dpa_generic_port_probe(_of_dev, &rx_port, &tx_port);
	if (err < 0)
		return err;

	err = dpa_generic_rx_bp_probe(_of_dev, rx_port, &rx_bp_count,
			&rx_bp, &rx_buf_layout);
	if (err < 0)
		return err;

	err = dpa_generic_tx_bp_probe(_of_dev, tx_port, &draining_tx_bp,
			&draining_tx_sg_bp, &tx_buf_layout);
	if (err < 0)
		return err;

	dpa_fq_list = dpa_generic_fq_probe(_of_dev, tx_port);
	if (IS_ERR(dpa_fq_list))
		return PTR_ERR(dpa_fq_list);

	err = dpa_generic_buff_dealloc_probe(_of_dev, &disable_buff_dealloc);
	if (err < 0)
		return err;

	/* just one queue for now */
	netdev = alloc_etherdev_mq(sizeof(*priv), 1);
	if (!netdev) {
		dev_err(dev, "alloc_etherdev_mq() failed\n");
		return -ENOMEM;
	}

	SET_NETDEV_DEV(netdev, dev);
	dev_set_drvdata(dev, netdev);
	priv = netdev_priv(netdev);
	priv->net_dev = netdev;
	sprintf(priv->if_type, "generic%d", generic_idx++);
	priv->msg_enable = netif_msg_init(generic_debug, -1);
	priv->tx_headroom = DPA_DEFAULT_TX_HEADROOM;

	init_timer(&priv->timer);
	priv->timer.data = (unsigned long)priv;
	priv->timer.function = dpa_generic_draining_timer;

	err = dpa_generic_bp_create(netdev, rx_bp_count, rx_bp, rx_buf_layout,
			draining_tx_bp, draining_tx_sg_bp, tx_buf_layout);
	if (err < 0)
		goto bp_create_failed;

	priv->disable_buff_dealloc = disable_buff_dealloc;

	err = dpa_generic_fq_create(netdev, dpa_fq_list, rx_port);
	if (err < 0)
		goto fq_create_failed;

	priv->tx_headroom = dpa_get_headroom(tx_buf_layout);
	priv->rx_headroom = dpa_get_headroom(rx_buf_layout);
	priv->rx_port = rx_port;
	priv->tx_port = tx_port;
	priv->mac_dev = NULL;


	priv->percpu_priv = devm_alloc_percpu(dev, *priv->percpu_priv);
	if (priv->percpu_priv == NULL) {
		dev_err(dev, "devm_alloc_percpu() failed\n");
		err = -ENOMEM;
		goto alloc_percpu_failed;
	}
	for_each_online_cpu(i) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, i);
		memset(percpu_priv, 0, sizeof(*percpu_priv));
	}

	/* Initialize NAPI */
	err = dpa_generic_napi_add(netdev);
	if (err < 0)
		goto napi_add_failed;

	err = dpa_generic_netdev_init(dpa_node, netdev);
	if (err < 0)
		goto netdev_init_failed;

	dpaa_eth_generic_sysfs_init(&netdev->dev);

	pr_info("fsl_dpa_generic: Probed %s interface as %s\n",
			priv->if_type, netdev->name);

	return 0;

netdev_init_failed:
napi_add_failed:
	dpa_generic_napi_del(netdev);
alloc_percpu_failed:
	if (netdev)
		dpa_fq_free(dev, &priv->dpa_fq_list);
fq_create_failed:
bp_create_failed:
	if (netdev)
		dpa_generic_bp_free(priv);
	dev_set_drvdata(dev, NULL);
	if (netdev)
		free_netdev(netdev);

	return err;
}

static int __init __cold dpa_generic_load(void)
{
	int	 _errno;

	pr_info(KBUILD_MODNAME ": " DPA_GENERIC_DESCRIPTION "\n");

	/* initialise dpaa_eth mirror values */
	dpa_rx_extra_headroom = fm_get_rx_extra_headroom();
	dpa_max_frm = fm_get_max_frm();

	_errno = platform_driver_register(&dpa_generic_driver);
	if (unlikely(_errno < 0)) {
		pr_err(KBUILD_MODNAME
			": %s:%hu:%s(): platform_driver_register() = %d\n",
			KBUILD_BASENAME".c", __LINE__, __func__, _errno);
	}

	pr_debug(KBUILD_MODNAME ": %s:%s() ->\n",
		KBUILD_BASENAME".c", __func__);

	return _errno;
}

/* waiting for all referenced ports to be initialized
 * by other kernel modules (proxy ethernet, offline_port)
 */
late_initcall(dpa_generic_load);

static void __exit __cold dpa_generic_unload(void)
{
	pr_debug(KBUILD_MODNAME ": -> %s:%s()\n",
		KBUILD_BASENAME".c", __func__);

	platform_driver_unregister(&dpa_generic_driver);

	pr_debug(KBUILD_MODNAME ": %s:%s() ->\n",
		KBUILD_BASENAME".c", __func__);
}
module_exit(dpa_generic_unload);
