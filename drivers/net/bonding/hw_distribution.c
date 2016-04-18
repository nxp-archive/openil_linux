/* Copyright 2014 Freescale Semiconductor Inc.
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
#include <linux/kthread.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <net/hw_distribution.h>
#include "mac.h"
#define to_dev(obj)     container_of(obj, struct device, kobj)
#define to_bond(cd)     ((struct bonding *)(netdev_priv(to_net_dev(cd))))
#define master_to_bond(net_dev)     ((struct bonding *)(netdev_priv(net_dev)))
/**
 * This includes L4 checksum errors, but also other errors that
 * the Hard Parser can detect, such as invalid combinations of
 * TCP control flags, or bad UDP lengths.
 */
#define FM_L4_PARSE_ERROR      0x10
/* Check if the hardware parser has run */
#define FM_L4_HXS_RUN          0xE0
/**
 * Check if the FMan Hardware Parser has run for L4 protocols.
 * @parse_result_ptr must be of type (fm_prs_result_t *).
 */
#define fm_l4_hxs_has_run(parse_result_ptr) \
	((parse_result_ptr)->l4r & FM_L4_HXS_RUN)
/**
 * If the FMan Hardware Parser has run for L4 protocols, check
 * error status.
 * @parse_result_ptr must be of type fm_prs_result_t *).
 */
#define fm_l4_hxs_error(parse_result_ptr) \
	       ((parse_result_ptr)->l4r & FM_L4_PARSE_ERROR)

#define DPA_WRITE_SKB_PTR(skb, skbh, addr, off) \
	{ \
		skbh = (struct sk_buff **)addr; \
		*(skbh + (off)) = skb; \
	}

#define DPA_READ_SKB_PTR(skb, skbh, addr, off) \
	{ \
		skbh = (struct sk_buff **)addr; \
		skb = *(skbh + (off)); \
	}

static const struct of_device_id oh_port_match_table[] = {
	{
		.compatible	= "fsl,dpa-oh"
	},
	{}
};

struct oh_port_priv *poh; /* Offline port information pointer */
int available_num_of_oh_ports;
/**
 * Sysfs interfaces:
 * Show the statistics information by offline port xmit.
 */
ssize_t bonding_show_offline_port_xmit_statistics(struct device *d,
						  struct device_attribute *attr,
						  char *buf)
{
	int res = 0, mode;
	struct bonding *bond = to_bond(d);

	mode = bond->params.mode;
	if (mode != BOND_MODE_8023AD && mode != BOND_MODE_XOR) {
		pr_err("%s: This command only support 802.3ad and xor mode.\n",
		       bond->dev->name);
		return -EPERM;
	}

	if (!bond->params.ohp) {
		pr_err("error, have not bind an offline port\n");

		return -EPERM;
	}

	if (!bond->params.ohp->oh_en) {
		pr_err("error, binded offline port is not enabled.\n");

		return -EPERM;
	}

	res += sprintf(buf + res, "offline port TX packets: %llu\n",
			bond->params.oh_stats.tx_packets);
	res += sprintf(buf + res, "offline port TX bytes: %llu\n",
			bond->params.oh_stats.tx_bytes);
	res += sprintf(buf + res, "offline port TX errors: %llu\n",
			bond->params.oh_stats.tx_errors);
	res += sprintf(buf + res, "offline port TX dropped: %llu\n",
			bond->params.oh_stats.tx_dropped);

	if (res)
		buf[res - 1] = '\n'; /* eat the leftover space */
	return res;
}

/**
 * Sysfs interfaces:
 * Show all available offline ports can be binded to a bond.
 */
ssize_t bonding_show_offline_ports(struct device *d,
				   struct device_attribute *attr,
				   char *buf)
{
	int i, res = 0, mode;
	struct bonding *bond = to_bond(d);

	mode = bond->params.mode;
	if (mode != BOND_MODE_8023AD && mode != BOND_MODE_XOR) {
		pr_err("%s: This command only support 802.3ad and xor mode.\n",
		       bond->dev->name);
		return -EPERM;
	}

	for (i = 0; i < available_num_of_oh_ports; i++) {
		if (poh[i].oh_dev)
			res += sprintf(buf + res, "%s\n", poh[i].friendname);
	}
	if (res)
		buf[res - 1] = '\n'; /* eat the leftover space */
	return res;
}

/**
 * Sysfs interfaces:
 * Show the offline_port has already attached to the current bond,
 * which can help bond to do hardware based slave selection.
 */
ssize_t
bonding_show_oh_needed_for_hw_distribution(struct device *d,
					   struct device_attribute *attr,
					   char *buf)
{
	int res = 0, mode;
	struct bonding *bond = to_bond(d);

	mode = bond->params.mode;
	if (mode != BOND_MODE_8023AD && mode != BOND_MODE_XOR) {
		pr_err("%s: This command only support 802.3ad and xor mode.\n",
		       bond->dev->name);
		return -EPERM;
	}

	if (!bond->params.ohp) {
		pr_err("error, have not bind an offline port\n");

		return -EPERM;
	}

	res += sprintf(buf + res, "%s\n", bond->params.ohp->friendname);
	if (res)
		buf[res - 1] = '\n'; /* eat the leftover space */

	return res;
}

/**
 * System interface:
 * Add one Offline port into the current bond for utilizing PCD to
 * do TX traffic distribution based on hard ware.
 * This codes firt verify the input Offline port name validation,
 * then store the Offline port to the current bond->params.
 */
ssize_t
bonding_store_oh_needed_for_hw_distribution(struct device *d,
					    struct device_attribute *attr,
					    const char *buffer,
					    size_t count)
{
	char command[OHFRIENDNAMSIZ + 1] = { 0, };
	int ret = count, i, errno, mode;
	struct bonding *bond = to_bond(d);
	struct oh_port_priv *tmp = poh;
	bool find = false;

	mode = bond->params.mode;
	if (mode != BOND_MODE_8023AD && mode != BOND_MODE_XOR) {
		pr_err("%s: This command only support 802.3ad and xor mode.\n",
		       bond->dev->name);
		return -EPERM;
	}
	if (bond->slave_cnt > 0) {
		pr_err("%s: Detach slaves before change oh binding.\n",
		       bond->dev->name);
		return -EPERM;
	}

	if (!rtnl_trylock())
		return restart_syscall();

	/* OHFRIENDNAMSIZ = 10, there is 10 chars in a command. */
	errno = sscanf(buffer, "%10s", command);
	if ((strlen(command) <= 1) || (errno != 1))
		goto err_no_cmd;

	if ((bond->params.ohp) && (bond->params.ohp->friendname[0]) &&
	    !strncasecmp(command, bond->params.ohp->friendname,
			OHFRIENDNAMSIZ)) {
				pr_err("%s: has already used %s.\n",
				       bond->dev->name, command);
		ret = -EPERM;
		goto out;
	} else
		for (i = 0; i < available_num_of_oh_ports; i++) {
			if (tmp->oh_dev) {
				if (strncasecmp(command, tmp->friendname,
						OHFRIENDNAMSIZ) == 0) {
					find = true;
					bond->params.ohp = tmp;
					break;
				}
				tmp++;
			}
		}

	if (!find)
		goto err_no_cmd;

	pr_info("bind OH port oh_needed_for_hw_distribution: %s to %s\n",
		bond->params.ohp->friendname, bond->dev->name);

	goto out;

err_no_cmd:
	pr_err("%s:bad command or no such OH port,\n"
			"please try other OH ports.\n"
			"Eg: echo OH0 > oh_needed_for_hw_distribution.\n",
			bond->dev->name);
	ret = -EPERM;

out:
	rtnl_unlock();
	return ret;
}

/**
 * Sysfs interfaces:
 * Show whether current offline port binding to the bond is active or not.
 */
ssize_t bonding_show_oh_enable(struct device *d,
			       struct device_attribute *attr,
			       char *buf)
{
	int res = 0, ret, mode;
	struct bonding *bond = to_bond(d);
	uint16_t channel;
	unsigned long fman_dcpid, oh_offset, cell_index;

	mode = bond->params.mode;
	if (mode != BOND_MODE_8023AD && mode != BOND_MODE_XOR) {
		pr_err("%s: This command only support 802.3ad and xor mode.\n",
		       bond->dev->name);
		return -EPERM;
	}

	if (!bond->params.ohp) {
		pr_err("error, have not bind a offline port\n");

		return -EPERM;
	}

	res += sprintf(buf + res, "%d\n", bond->params.ohp->oh_en);
	if (res)
		buf[res - 1] = '\n'; /* eat the leftover space */

	ret = export_oh_port_info_to_ceetm(bond, &channel, &fman_dcpid,
					   &oh_offset, &cell_index);

	if (!ret && bond->params.ohp->oh_en)
		hw_lag_dbg("offline port channel:%d\n", channel);

	return res;
}

/**
 * Sysfs interfaces:
 * Set current offline port which is binding to the bond active or not,
 * this interface can disable or enable the offline port which is binding
 * to a bond at run-time.
 */
ssize_t bonding_store_oh_enable(struct device *d,
				struct device_attribute *attr,
				const char *buffer,
				size_t count)
{
	int new_value, ret, mode;
	struct bonding *bond = to_bond(d);

	mode = bond->params.mode;
	if (mode != BOND_MODE_8023AD && mode != BOND_MODE_XOR) {
		pr_err("%s: This command only support 802.3ad and xor mode.\n",
		       bond->dev->name);
		return -EPERM;
	}

	ret = kstrtoint(buffer, 10, &new_value);
	pr_info("new_value:%d, ret: %d\n", new_value, ret);
	if (ret) {
		pr_err("%s: Bad command, use echo [1|0] > oh_en.\n",
		       bond->dev->name);
		return -EINVAL;
	}

	if (!bond->params.ohp) {
		pr_err("error, have not bind a offline port\n");
		return -EPERM;
	}

	if ((new_value == 0) || (new_value == 1)) {
		bond->params.ohp->oh_en = new_value;
		return count;
	}
	pr_err("%s: Bad value, only is 1 or 0.\n",
	       bond->dev->name);
	return -EINVAL;
}

/**
 * Judge a slave net device is a dpa-eth NIC,
 * return true if it is a dpa-eth NIC,
 * otherwise return false.
 */
static bool is_dpa_eth_port(struct net_device *netdev)
{
	int ret;
	struct device *dev = (struct device *)&netdev->dev;

	if (strlen(dev_driver_string(dev->parent)) >= 7) {
		ret = strncmp(dev_driver_string(dev->parent), "fsl_dpa", 7);
		return ret ? false : true;
	}

	return false;
}

bool are_all_slaves_linkup(struct bonding *bond)
{
	struct slave *s;
	struct list_head *iter;

	bond_for_each_slave(bond, s, iter) {
		hw_lag_dbg("This slave:%s link status is up:%s\n",
			   s->dev->name, IS_UP(s->dev) ? "true" : "false");

		if (!(IS_UP(s->dev)))
			return false;
	}

	return true;
}

unsigned int to_which_oh_i_attached(struct oh_port_priv *current_poh)
{
	struct oh_port_priv *org = poh;
	int i = 0;

	while (current_poh - org) {
		i++;
		org++;
	}

	return i;
}

/* Borrowed from dpa_fd_release, removed netdev params. */
static void __attribute__((nonnull))
dpa_oh_fd_release(const struct qm_fd *fd)
{
	struct qm_sg_entry *sgt;
	struct dpa_bp *dpa_bp;
	struct bm_buffer bmb;

	bmb.hi = fd->addr_hi;
	bmb.lo = fd->addr_lo;

	dpa_bp = dpa_bpid2pool(fd->bpid);
	DPA_BUG_ON(!dpa_bp);

	if (fd->format == qm_fd_sg) {
		sgt = (phys_to_virt(bm_buf_addr(&bmb)) + dpa_fd_offset(fd));
		dpa_release_sgt(sgt);
	}

	while (bman_release(dpa_bp->pool, &bmb, 1, 0))
		cpu_relax();
}

static void dpa_oh_drain_bp(struct dpa_bp *bp)
{
	int i, num;
	struct bm_buffer bmb[8];
	dma_addr_t addr;
	int *countptr = this_cpu_ptr(bp->percpu_count);
	int count = *countptr;
	struct sk_buff **skbh;

	while (count >= 8) {
		num = bman_acquire(bp->pool, bmb, 8, 0);
		/* There may still be up to 7 buffers in the pool;
		 * just leave them there until more arrive
		 */
		if (num < 0)
			break;
		for (i = 0; i < num; i++) {
			addr = bm_buf_addr(&bmb[i]);
			/* bp->free_buf_cb(phys_to_virt(addr)); */
			skbh = (struct sk_buff **)phys_to_virt(addr);
			dma_unmap_single(bp->dev, addr, bp->size,
					 DMA_TO_DEVICE);
			dev_kfree_skb(*skbh);
		}
		count -= num;
	}
	*countptr = count;
}

static int dpa_oh_tx_bp_probe(struct device *dev,
			      struct fm_port *tx_port,
			      struct dpa_bp **draining_tx_bp,
			      struct dpa_buffer_layout_s **tx_buf_layout)
{
	struct fm_port_params params;
	struct dpa_bp *bp = NULL;
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
	if (unlikely(!bp)) {
		dev_err(dev, "devm_kzalloc() failed\n");
		return -ENOMEM;
	}

	bp->size = dpa_bp_size(buf_layout);
	bp->percpu_count = alloc_percpu(*bp->percpu_count);
	bp->target_count = CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT;

	*draining_tx_bp = bp;
	*tx_buf_layout = buf_layout;

	return 0;
}

static int dpa_oh_bp_create(struct oh_port_priv *ohp)
{
	int err = 0;
	struct dpa_bp *draining_tx_bp;
	struct dpa_buffer_layout_s *tx_buf_layout;

	err = dpa_oh_tx_bp_probe(ohp->dpa_oh_dev, ohp->oh_config->oh_port,
				 &draining_tx_bp, &tx_buf_layout);
	if (err) {
		pr_err("errors on dpa_oh_tx_bp_probe()\n");
		return err;
	}

	ohp->tx_bp = draining_tx_bp;
	ohp->tx_buf_layout = tx_buf_layout;

	err = dpa_bp_alloc(ohp->tx_bp);
	if (err < 0) {
		/* _dpa_bp_free(ohp->tx_bp); */
		pr_err("error on dpa_bp_alloc()\n");
		ohp->tx_bp = NULL;
		return err;
	}
	hw_lag_dbg("created bp, bpid(ohp->tx_bp):%d\n", ohp->tx_bp->bpid);

	return 0;
}

/**
 * Copied from DPA-Eth driver (since they have different params type):
 * Cleanup function for outgoing frame descriptors that were built on Tx path,
 * either contiguous frames or scatter/gather ones.
 * Skb freeing is not handled here.
 *
 * This function may be called on error paths in the Tx function, so guard
 * against cases when not all fd relevant fields were filled in.
 *
 * Return the skb backpointer, since for S/G frames the buffer containing it
 * gets freed here.
 */
struct sk_buff *oh_cleanup_tx_fd(const struct qm_fd *fd)
{
	int i, nr_frags;
	const struct qm_sg_entry *sgt;
	struct sk_buff **skbh;
	struct sk_buff *skb = NULL;
	dma_addr_t addr = qm_fd_addr(fd);
	struct dpa_bp *dpa_bp = dpa_bpid2pool(fd->bpid);
	const enum dma_data_direction dma_dir = DMA_TO_DEVICE;

	DPA_BUG_ON(fd->cmd & FM_FD_CMD_FCO);
	dma_unmap_single(dpa_bp->dev, addr, dpa_bp->size, dma_dir);

	/* retrieve skb back pointer */
	DPA_READ_SKB_PTR(skb, skbh, phys_to_virt((unsigned long)addr), 0);
	nr_frags = skb_shinfo(skb)->nr_frags;

	if (fd->format == qm_fd_sg) {
		/* The sgt buffer has been allocated with netdev_alloc_frag(),
		 * it's from lowmem.
		 */
		sgt = phys_to_virt(addr + dpa_fd_offset(fd));

		/* sgt[0] is from lowmem, was dma_map_single()-ed */
		dma_unmap_single(dpa_bp->dev, sgt[0].addr,
				 sgt[0].length, dma_dir);

		/* remaining pages were mapped with dma_map_page() */
		for (i = 1; i < nr_frags; i++) {
			DPA_BUG_ON(sgt[i].extension);

			dma_unmap_page(dpa_bp->dev, sgt[i].addr,
				       sgt[i].length, dma_dir);
		}

		/* Free the page frag that we allocated on Tx */
		put_page(virt_to_head_page(sgt));
	}

	return skb;
}

static void dump_parser_result(const struct qm_fd *fd)
{
#ifdef CONFIG_HW_LAG_DEBUG
	dma_addr_t addr = qm_fd_addr(fd);
	void *vaddr;
	const fm_prs_result_t *parse_results;

	vaddr = phys_to_virt((unsigned long)addr);
	DPA_BUG_ON(!IS_ALIGNED((unsigned long)vaddr, SMP_CACHE_BYTES));

	parse_results = (const fm_prs_result_t *)(vaddr +
				DPA_TX_PRIV_DATA_SIZE);

	hw_lag_dbg("parse_results->l2r:0x%08x\n", parse_results->l2r);

	hw_lag_dbg("FM_L3_PARSE_RESULT_IPV4:0x%0x\n"
			"FM_L3_PARSE_RESULT_IPV6:0x%0x\n"
			"parse_results->l3r:0x%08x\n",
			parse_results->l3r & FM_L3_PARSE_RESULT_IPV4,
			parse_results->l3r & FM_L3_PARSE_RESULT_IPV6,
			parse_results->l3r);

	hw_lag_dbg("fm_l4_hxs_has_run(parse_results):0x%0x\n"
			"fm_l4_hxs_error(parse_results):0x%0x\n",
			fm_l4_hxs_has_run(parse_results),
			fm_l4_hxs_error(parse_results));

	hw_lag_dbg("fd->status & FM_FD_STAT_L4CV:0x%x\n"
			"parse_results->l4r:0x%08x\n"
			"fm_l4_frame_is_tcp(parse_results):0x%0x\n",
			fd->status & FM_FD_STAT_L4CV,
			parse_results->l4r,
			fm_l4_frame_is_tcp(parse_results));
#endif
}

static void show_dbg_info(const struct qm_fd *fd, const char *func_name,
			  struct sk_buff *skb)
{
#ifdef CONFIG_HW_LAG_DEBUG
	u32 fd_status;
	unsigned long pad;
	dma_addr_t addr;
	struct ethhdr *eth;
	struct iphdr  *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	unsigned int data_start;
	unsigned long skb_addr;

	fd_status = fd->status;
	addr = qm_fd_addr(fd);

	/* find out the pad */
	skb_addr = virt_to_phys(skb->head);
	pad = (unsigned long)addr - skb_addr;

	/* The skb is currently pointed at head + headroom. The packet
	 * starts at skb->head + pad + fd offset.
	 */
	data_start = pad + dpa_fd_offset(fd) - skb_headroom(skb);

	skb_pull(skb, data_start);

	pr_info("[%s]:fd->status:0x%08x\n", func_name, fd_status);
	pr_info("[%s]:fd tx status:0x%08x. fd rx status:0x%08x\n",
		func_name, fd_status & FM_FD_STAT_TX_ERRORS,
		fd_status & FM_FD_STAT_RX_ERRORS);

	if (likely(fd_status & FM_FD_STAT_ERR_PHYSICAL))
		pr_err("FM_FD_STAT_ERR_PHYSICAL\n");
	if (fd_status & FM_PORT_FRM_ERR_DMA)
		pr_err("FM_PORT_FRM_ERR_DMA\n");
	if (fd_status & FM_PORT_FRM_ERR_PHYSICAL)
		pr_err("FM_PORT_FRM_ERR_PHYSICAL\n");
	if (fd_status & FM_PORT_FRM_ERR_SIZE)
		pr_err("FM_PORT_FRM_ERR_SIZE\n");
	if (fd_status & FM_PORT_FRM_ERR_PRS_HDR_ERR)
		pr_err("[%s]:FM_PORT_FRM_ERR_PRS_HDR_ERR\n", func_name);

	pr_info("[%s]:fd->format - qm_fd_contig:%d\n", func_name,
		fd->format - qm_fd_contig);
	pr_info("[%s]:fd->bpid:%d\n", func_name, fd->bpid);

	/* get L2 info */
	skb->protocol = htons(ETH_P_802_3);
	skb_reset_mac_header(skb);
	skb_pull_inline(skb, ETH_HLEN);

	eth = eth_hdr(skb);

	pr_info("\n[%s]:dmac:%02x:%02x:%02x:%02x:%02x:%02x\n"
			"smac:%02x:%02x:%02x:%02x:%02x:%02x\n"
			"h_proto:0x%04x\n", func_name,
			eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
			eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
			eth->h_source[0], eth->h_source[1], eth->h_source[2],
			eth->h_source[3], eth->h_source[4], eth->h_source[5],
			eth->h_proto);

	if (fd_status & FM_FD_STAT_L4CV) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		pr_info("[%s]:skb->ip_summed = CHECKSUM_UNNECESSARY\n",
			func_name);
	} else {
		skb->ip_summed = CHECKSUM_NONE;
		pr_info("[%s]:skb->ip_summed = CHECKSUM_NONE\n", func_name);
	}

	/* get L3 and part of L4 info */
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_reset_mac_len(skb);

	if (eth->h_proto == ETH_P_IP) {
		iph = ip_hdr(skb);
		pr_info("[%s]:L3_pro:0x%0x, dip:0x%0x, sip:0x%0x\n", func_name,
			iph->protocol, iph->daddr, iph->saddr);

		skb_pull_inline(skb, ip_hdrlen(skb));
		skb_reset_transport_header(skb);

		if (iph->protocol == IPPROTO_TCP) {
			tcph = tcp_hdr(skb);
			pr_info("[%s]:tcp csum:0x%0x\n",
				func_name, tcph->check);
		} else if (iph->protocol == IPPROTO_UDP) {
			udph = udp_hdr(skb);
			pr_info("[%s]:udp csum:0x%0x\n",
				func_name, udph->check);
		}

	} else if (eth->h_proto == ETH_P_ARP) {
		pr_info("[%s]:ARP.\n", func_name);
	} else if (eth->h_proto == ETH_P_IPV6) {
		pr_info("[%s]:IPv6.\n", func_name);
	} else if (eth->h_proto == ETH_P_SLOW) {
		pr_info("[%s]:802.3ad pkt.\n", func_name);
	} else {
		pr_info("[%s]:other pkt.\n", func_name);
	}

	return;
#endif
}

/**
 * When enqueue an frame from kernel module to offline port,
 * once errors happeds, this callback will be entered.
 */
static enum qman_cb_dqrr_result
oh_ingress_tx_error_dqrr(struct qman_portal *portal, struct qman_fq *fq,
			 const struct qm_dqrr_entry *dq)
{
	struct sk_buff *skb;
	const struct qm_fd *fd = &dq->fd;

	skb = oh_cleanup_tx_fd(fd);
	dump_parser_result(fd);
	show_dbg_info(fd, __func__, skb);
	dev_kfree_skb_any(skb);

	return qman_cb_dqrr_consume;
}

/**
 * This subroutine is copied from oNIC, it should not be call
 * in normal case, only for debugging outgoing traffics to oh
 * tx port while no PCD applied for oh port. such as debugging
 * oh port tx L4 csum.
 */
static enum qman_cb_dqrr_result __hot
oh_ingress_tx_default_dqrr(struct qman_portal *portal, struct qman_fq *fq,
			   const struct qm_dqrr_entry *dq)
{
	struct net_device *netdev;
	struct dpa_priv_s *priv;
	struct dpa_bp *bp;
	struct dpa_percpu_priv_s *percpu_priv;
	struct sk_buff **skbh;
	struct sk_buff *skb;
	struct iphdr  *iph;
	const struct qm_fd *fd = &dq->fd;
	u32 fd_status = fd->status;
	u32 pad;
	dma_addr_t addr = qm_fd_addr(fd);
	unsigned int data_start;
	unsigned long skb_addr;
	int *countptr;
	struct ethhdr *eth;

	hw_lag_dbg("fd->status:0x%08x\n", fd_status);

	hw_lag_dbg("fd tx status:0x%08x. fd rx status:0x%08x\n",
		   fd_status & FM_FD_STAT_TX_ERRORS,
		   fd_status & FM_FD_STAT_RX_ERRORS);

	if (likely(fd_status & FM_FD_STAT_ERR_PHYSICAL))
		pr_err("FM_FD_STAT_ERR_PHYSICAL\n");

	if (fd_status & FM_PORT_FRM_ERR_DMA)
		pr_err("FM_PORT_FRM_ERR_DMA\n");
	if (fd_status & FM_PORT_FRM_ERR_PHYSICAL)
		pr_err("FM_PORT_FRM_ERR_PHYSICAL\n");
	if (fd_status & FM_PORT_FRM_ERR_SIZE)
		pr_err("FM_PORT_FRM_ERR_SIZE\n");
	if (fd_status & FM_PORT_FRM_ERR_PRS_HDR_ERR)
		pr_err("oh_tx_defq FM_PORT_FRM_ERR_PRS_HDR_ERR\n");

	netdev = ((struct dpa_fq *)fq)->net_dev;
	if (!netdev) {
		pr_err("error netdev == NULL.\n");
		skbh = (struct sk_buff **)phys_to_virt((unsigned long)addr);
		dev_kfree_skb(*skbh);
		return qman_cb_dqrr_consume;
	}
	priv = netdev_priv(netdev);
	dump_parser_result(fd);

	percpu_priv = this_cpu_ptr(priv->percpu_priv);
	countptr = this_cpu_ptr(priv->dpa_bp->percpu_count);

	skbh = (struct sk_buff **)phys_to_virt(addr);
	/* according to the last common code (bp refill) the skb pointer is set
	 * to another address shifted by sizeof(struct sk_buff) to the left
	 */
	skb = *(skbh - 1);

	if (unlikely(fd_status & FM_FD_STAT_RX_ERRORS) != 0) {
		hw_lag_dbg("FD status = 0x%08x\n",
			   fd_status & FM_FD_STAT_RX_ERRORS);

		percpu_priv->stats.rx_errors++;
		oh_cleanup_tx_fd(fd);
		goto qman_consume;
	}
	if (unlikely(fd->format != qm_fd_contig)) {
		percpu_priv->stats.rx_dropped++;
		hw_lag_dbg("Dropping a SG frame\n");
		oh_cleanup_tx_fd(fd);
		goto qman_consume;
	}

	hw_lag_dbg("fd->bpid:%d\n", fd->bpid);
	bp = dpa_bpid2pool(fd->bpid);
	dma_unmap_single(bp->dev, addr, bp->size, DMA_TO_DEVICE);

	/* find out the pad */
	skb_addr = virt_to_phys(skb->head);
	pad = (u32)(addr - skb_addr);

	countptr = this_cpu_ptr(bp->percpu_count);
	(*countptr)--;

	/* The skb is currently pointed at head + headroom. The packet
	 * starts at skb->head + pad + fd offset.
	 */
	data_start = pad + dpa_fd_offset(fd) - skb_headroom(skb);
	skb_pull(skb, data_start);

	/* get L2 info */
	skb->protocol = eth_type_trans(skb, netdev);
	eth = eth_hdr(skb);

	hw_lag_dbg("dmac:%02x:%02x:%02x:%02x:%02x:%02x\n"
		   "smac:%02x:%02x:%02x:%02x:%02x:%02x\n"
		   "h_proto:0x%04x\n",
		   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
		   eth->h_source[0], eth->h_source[1], eth->h_source[2],
		   eth->h_source[3], eth->h_source[4], eth->h_source[5],
		   eth->h_proto);

	if (unlikely(dpa_check_rx_mtu(skb, netdev->mtu))) {
		percpu_priv->stats.rx_dropped++;
		goto qman_consume;
	}

	if (fd_status & FM_FD_STAT_L4CV) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		hw_lag_dbg("skb->ip_summed = CHECKSUM_UNNECESSARY\n");
	} else {
		skb->ip_summed = CHECKSUM_NONE;
		hw_lag_dbg("skb->ip_summed = CHECKSUM_NONE\n");
	}

	/* get L3 and part of L4 info */
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_reset_mac_len(skb);

	if (eth->h_proto == ETH_P_IP) {
		iph = ip_hdr(skb);
		hw_lag_dbg("L3_pro:0x%0x, dip:0x%0x, sip:0x%0x\n",
			   iph->protocol, iph->daddr, iph->saddr);
	} else if (eth->h_proto == ETH_P_ARP) {
		hw_lag_dbg("ARP.\n");
	} else if (eth->h_proto == ETH_P_IPV6) {
		hw_lag_dbg("IPv6.\n");
	} else if (eth->h_proto == ETH_P_SLOW) {
		hw_lag_dbg("802.3ad pkt.\n");
	} else {
		hw_lag_dbg("other pkt.\n");
	}

qman_consume:
	dev_kfree_skb_any(skb);

	return qman_cb_dqrr_consume;
}

/**
 * When frame leave from PCD fqs then goes final terminated physical
 * ports(MAC ports),once errors happend, this callback will be entered.
 * dump debugging information when HW_LAG_DEBUG enabled .
 */
static enum qman_cb_dqrr_result
oh_pcd_err_dqrr(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{
	struct sk_buff *skb;
	const struct qm_fd *fd = &dq->fd;

	skb = oh_cleanup_tx_fd(fd);
	dump_parser_result(fd);
	show_dbg_info(fd, __func__, skb);
	dev_kfree_skb_any(skb);

	return qman_cb_dqrr_consume;
}

/**
 * When frame leave from offline port tx fqs then goes into offline tx
 * ports(MAC ports), it will be into confirm fq, this callback will be
 * entered.
 * dump debugging information when HW_LAG_DEBUG enabled.
 * don't free skb, since offline port is not the final consumer.
 */
static enum qman_cb_dqrr_result __hot
oh_tx_conf_dqrr(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{
	struct sk_buff *skb;
	const struct qm_fd *fd = &dq->fd;

	skb = oh_cleanup_tx_fd(fd);
	dump_parser_result(fd);
	show_dbg_info(fd, __func__, skb);

	return qman_cb_dqrr_consume;
}

static void lag_public_egress_ern(struct qman_portal *portal,
				  struct qman_fq *fq,
				  const struct qm_mr_entry *msg)
{
	/* will add ERN statistics in the future version. */
	const struct qm_fd *fd = &msg->ern.fd;
	struct sk_buff *skb;

	if (msg->ern.fd.cmd & FM_FD_CMD_FCO) {
		dpa_oh_fd_release(fd);
		return;
	}

	skb = oh_cleanup_tx_fd(fd);
	dump_parser_result(fd);
	show_dbg_info(fd, __func__, skb);
	dev_kfree_skb_any(skb);
}

/**
 * This subroutine will be called when frame out of oh pcd fqs and
 * consumed by (MAC ports).
 * Display debugging information if HW_LAG_DEBUG on.
 */
static enum qman_cb_dqrr_result __hot
oh_pcd_conf_dqrr(struct qman_portal *portal, struct qman_fq *fq,
		 const struct qm_dqrr_entry *dq)
{
	struct sk_buff *skb;
	const struct qm_fd *fd = &dq->fd;

	skb = oh_cleanup_tx_fd(fd);
	show_dbg_info(fd, __func__, skb);
	dev_kfree_skb_any(skb);

	return qman_cb_dqrr_consume;
}

static const struct qman_fq oh_tx_defq = {
	.cb = { .dqrr = oh_ingress_tx_default_dqrr}
};

/* for OH ports Rx Error queues = Tx Error queues */
static const struct qman_fq oh_tx_errq = {
	.cb = { .dqrr = oh_ingress_tx_error_dqrr}
};

static const struct qman_fq oh_pcd_confq = {
	.cb = { .dqrr = oh_pcd_conf_dqrr}
};

static const struct qman_fq oh_pcd_errq = {
	.cb = { .dqrr = oh_pcd_err_dqrr}
};

static const struct qman_fq oh_tx_confq = {
	.cb = { .dqrr = oh_tx_conf_dqrr}
};

static const struct qman_fq oh_pcd_egress_ernq = {
	.cb = { .ern = lag_public_egress_ern}
};

static const struct qman_fq oh_egress_ernq = {
	.cb = { .ern = lag_public_egress_ern}
};

static int op_add_channel(void *__arg)
{
	int cpu;
	struct qman_portal *portal;
	const cpumask_t *cpus = qman_affine_cpus();
	u32 pool = QM_SDQCR_CHANNELS_POOL_CONV((u16)(unsigned long)__arg);

	for_each_cpu(cpu, cpus) {
		portal = (struct qman_portal *)qman_get_affine_portal(cpu);
		qman_p_static_dequeue_add(portal, pool);
	}

	return 0;
}

static int op_alloc_pool_channel(uint16_t *priv_channel)
{
	int errno;
	u32 channel;
	struct task_struct *kth;

	/* Get a channel */
	errno = qman_alloc_pool(&channel);
	if (errno) {
		pr_err("error on getting pool channel.\n");
		return errno;
	}

	/* Start a thread that will walk the cpus with affine portals
	 * and add this pool channel to each's dequeue mask.
	 */

	kth = kthread_run(op_add_channel, (void *)(unsigned long)channel,
			  "op_add_channel");
	if (!kth) {
		pr_warn("run kthread failed ...\n");
		return -ENOMEM;
	}

	*priv_channel = (uint16_t)channel;

	return 0;
}

static int init_oh_errq_defq(struct device *dev,
			     uint32_t fqid_err, uint32_t fqid_def,
			     struct dpa_fq **oh_errq, struct dpa_fq **oh_defq,
			     uint16_t channel)
{
	int errno;
	struct dpa_fq *errq, *defq;
	/* These two vaules come from DPA-Eth driver */
	uint8_t wq_errq = 2, wq_defq = 1;
	struct qm_mcc_initfq initfq;

	/* Allocate memories for Tx ErrQ and Tx DefQ of oh port */
	errq = devm_kzalloc(dev, sizeof(struct dpa_fq), GFP_KERNEL);
	if (!errq) {
		pr_err("devm_kzalloc() for OH errq failed\n");
		return -ENOMEM;
	}
	defq = devm_kzalloc(dev, sizeof(struct dpa_fq), GFP_KERNEL);
	if (!defq) {
		pr_err("devm_kzalloc() for OH defq failed.\n");
		return -ENOMEM;
	}

	/* Set Tx ErrQ callbacks of oh port */
	errq->fq_base = oh_tx_errq;

	/* Set the flags of the oh port Tx ErrQ/Tx DefQ and create the FQs */
	errq->fq_base.flags = QMAN_FQ_FLAG_NO_ENQUEUE;
	errno = qman_create_fq(fqid_err, errq->fq_base.flags, &errq->fq_base);
	if (errno) {
		pr_err("error on create OH errq.\n");
		return errno;
	}

	defq->fq_base = oh_tx_defq;
	defq->fq_base.flags = QMAN_FQ_FLAG_NO_ENQUEUE;
	errno = qman_create_fq(fqid_def, defq->fq_base.flags, &defq->fq_base);
	if (errno) {
		pr_err("error on create OH defq.\n");
		return errno;
	}

	/* Set the FQs init options then init the FQs */
	initfq.we_mask = QM_INITFQ_WE_DESTWQ;
	initfq.fqd.dest.channel = (uint16_t)channel;
	initfq.fqd.dest.wq = wq_errq;
	initfq.we_mask |= QM_INITFQ_WE_FQCTRL;
	initfq.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	initfq.we_mask |= QM_INITFQ_WE_CONTEXTA;
	initfq.fqd.fq_ctrl |= QM_FQCTRL_CTXASTASHING | QM_FQCTRL_AVOIDBLOCK;
	initfq.fqd.context_a.stashing.exclusive = QM_STASHING_EXCL_DATA |
		QM_STASHING_EXCL_CTX | QM_STASHING_EXCL_ANNOTATION;
	initfq.fqd.context_a.stashing.data_cl = 2;
	initfq.fqd.context_a.stashing.annotation_cl = 1;
	initfq.fqd.context_a.stashing.context_cl =
		DIV_ROUND_UP(sizeof(struct qman_fq), 64);

	/* init oh ports errors fq */
	errno = qman_init_fq(&errq->fq_base, QMAN_INITFQ_FLAG_SCHED, &initfq);
	if (errno < 0) {
		pr_err("error on qman_init_fq %u = %d\n", fqid_err, errno);
		qman_destroy_fq(&errq->fq_base, 0);
		devm_kfree(dev, errq);
		return errno;
	}

	/* init oh ports default fq */
	initfq.fqd.dest.wq = wq_defq;
	errno = qman_init_fq(&defq->fq_base, QMAN_INITFQ_FLAG_SCHED, &initfq);
	if (errno < 0) {
		pr_err("error on qman_init_fq %u = %d\n", fqid_def, errno);
		qman_destroy_fq(&defq->fq_base, 0);
		devm_kfree(dev, defq);
		return errno;
	}

	*oh_errq = errq;
	*oh_defq = defq;

	hw_lag_dbg("oh port defq and oh port errq initialize OK\n");

	return BOND_OH_SUCCESS;
}

/**
 * Initialize pcd err fqs and pcd confirmation fqs.
 * HW LAG uses this method rather than reuse DPA-Eth private rx err/
 * rx def/tx err/tx confirm FQs and callbacks, since HW LAG uses
 * different data structure from DPA-Eth private driver.
 */
static int init_oh_pcderrq_pcdconfq(struct device *dev,	uint32_t *fqid_pcderr,
				    uint32_t *fqid_pcdconf,
				    struct dpa_fq **oh_pcderrq,
				    struct dpa_fq **oh_pcdconfq,
				    uint16_t priv_channel)
{
	int errno;
	struct dpa_fq *pcderrq, *pcdconfq;
	/* These two vaules come from DPA-Eth driver */
	uint8_t wq_errq = 2, wq_confq = 1;
	struct qm_mcc_initfq initfq;

	/* Allocate memories for PCD ErrQ and PCD confirm Q of oh port */
	pcderrq = devm_kzalloc(dev, sizeof(struct dpa_fq), GFP_KERNEL);
	if (!pcderrq) {
		pr_err("devm_kzalloc() for OH pcderrq failed\n");
		return -ENOMEM;
	}

	pcdconfq = devm_kzalloc(dev, sizeof(struct dpa_fq), GFP_KERNEL);
	if (!pcdconfq) {
		pr_err("devm_kzalloc() for OH pcdconfq failed.\n");
		return -ENOMEM;
	}

	/* Set PCD ErrQ callbacks of oh port */
	pcderrq->fq_base = oh_pcd_errq;

	/* Set the flags of the oh port PCD ErrQ, create the FQs */
	pcderrq->fq_base.flags = QMAN_FQ_FLAG_NO_ENQUEUE |
		QMAN_FQ_FLAG_DYNAMIC_FQID;
	errno = qman_create_fq(0, pcderrq->fq_base.flags, &pcderrq->fq_base);
	if (errno) {
		pr_err("error on create OH pcderrq.\n");
		return errno;
	}
	*fqid_pcderr = pcderrq->fq_base.fqid;
	hw_lag_dbg("*fqid_pcderr:%d\n", *fqid_pcderr);

	/* Set PCD confirm Q callbacks of oh port */
	pcdconfq->fq_base = oh_pcd_confq;
	/* Set the flags of the oh port PCD confQ, create the FQs */
	pcdconfq->fq_base.flags = QMAN_FQ_FLAG_NO_ENQUEUE |
		QMAN_FQ_FLAG_DYNAMIC_FQID;
	errno = qman_create_fq(0, pcdconfq->fq_base.flags, &pcdconfq->fq_base);
	if (errno) {
		pr_err("error on create OH pcdconfq.\n");
		return errno;
	}
	*fqid_pcdconf = pcdconfq->fq_base.fqid;
	hw_lag_dbg("*fqid_pcdconf:%d\n", *fqid_pcdconf);

	/* Set the FQs init options then init the FQs */
	initfq.we_mask = QM_INITFQ_WE_DESTWQ;
	initfq.fqd.dest.channel = priv_channel;
	initfq.fqd.dest.wq = wq_errq;
	initfq.we_mask |= QM_INITFQ_WE_FQCTRL;
	initfq.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	initfq.we_mask |= QM_INITFQ_WE_CONTEXTA;
	initfq.fqd.fq_ctrl |= QM_FQCTRL_CTXASTASHING | QM_FQCTRL_AVOIDBLOCK;
	initfq.fqd.context_a.stashing.exclusive = QM_STASHING_EXCL_DATA |
		QM_STASHING_EXCL_CTX | QM_STASHING_EXCL_ANNOTATION;
	initfq.fqd.context_a.stashing.data_cl = 2;
	initfq.fqd.context_a.stashing.annotation_cl = 1;
	initfq.fqd.context_a.stashing.context_cl =
		DIV_ROUND_UP(sizeof(struct qman_fq), 64);

	/* init pcd errors fq */
	errno = qman_init_fq(&pcderrq->fq_base,
			     QMAN_INITFQ_FLAG_SCHED, &initfq);
	if (errno < 0) {
		pr_err("error on qman_init_fq pcderrq:%u = %d\n",
		       *fqid_pcderr, errno);
		qman_destroy_fq(&pcderrq->fq_base, 0);
		devm_kfree(dev, pcderrq);

		return errno;
	}

	/* init pcd confirm fq */
	initfq.fqd.dest.wq = wq_confq;
	errno = qman_init_fq(&pcdconfq->fq_base,
			     QMAN_INITFQ_FLAG_SCHED, &initfq);
	if (errno < 0) {
		pr_err("error on qman_init_fq pcdconfq:%u = %d\n",
		       *fqid_pcdconf, errno);
		qman_destroy_fq(&pcdconfq->fq_base, 0);
		devm_kfree(dev, pcdconfq);

		return errno;
	}

	*oh_pcderrq = pcderrq;
	*oh_pcdconfq = pcdconfq;

	hw_lag_dbg("oh pcd confq and pcd errq initialize OK\n");

	return BOND_OH_SUCCESS;
}

/**
 * Initialize confirmation fq for offline port tx fqs.
 * This confirmation call back is enabled in case of buffer is released
 * by BM after frame entered into tx port of offline port.
 */
static int init_oh_txconfq(struct device *dev, uint32_t *fqid_ohtxconf,
			   struct dpa_fq **oh_txconfq, uint16_t priv_channel)
{
	int errno;
	struct dpa_fq *txconfq;
	/* This value comes from DPA-Eth driver */
	uint8_t wq_confq = 1;
	struct qm_mcc_initfq initfq;

	/* Allocate memories for PCD ErrQ and PCD confirm Q of oh port */
	txconfq = devm_kzalloc(dev, sizeof(struct dpa_fq), GFP_KERNEL);
	if (!txconfq) {
		pr_err("devm_kzalloc() for OH tx confq failed.\n");
		return -ENOMEM;
	}

	/* Set tx confirm Q callbacks of oh port */
	txconfq->fq_base = oh_tx_confq;
	/* Set the flags of the oh port PCD confQ, create the FQs */
	txconfq->fq_base.flags = QMAN_FQ_FLAG_NO_ENQUEUE |
		QMAN_FQ_FLAG_DYNAMIC_FQID;
	errno = qman_create_fq(0, txconfq->fq_base.flags, &txconfq->fq_base);
	if (errno) {
		pr_err("error on create OH tx confq.\n");
		return errno;
	}
	*fqid_ohtxconf = txconfq->fq_base.fqid;
	hw_lag_dbg("dynamic *fqid_ohtxconf:%d\n", *fqid_ohtxconf);

	/* Set the FQs init options then init the FQs */
	initfq.we_mask = QM_INITFQ_WE_DESTWQ;
	initfq.fqd.dest.channel = priv_channel;
	initfq.fqd.dest.wq = wq_confq;
	initfq.we_mask |= QM_INITFQ_WE_FQCTRL;
	initfq.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	initfq.we_mask |= QM_INITFQ_WE_CONTEXTA;
	initfq.fqd.fq_ctrl |= QM_FQCTRL_CTXASTASHING | QM_FQCTRL_AVOIDBLOCK;
	initfq.fqd.context_a.stashing.exclusive = QM_STASHING_EXCL_DATA |
		QM_STASHING_EXCL_CTX | QM_STASHING_EXCL_ANNOTATION;
	initfq.fqd.context_a.stashing.data_cl = 2;
	initfq.fqd.context_a.stashing.annotation_cl = 1;
	initfq.fqd.context_a.stashing.context_cl =
		DIV_ROUND_UP(sizeof(struct qman_fq), 64);

	/* init oh tx confirm fq */
	initfq.fqd.dest.wq = wq_confq;
	errno = qman_init_fq(&txconfq->fq_base,
			     QMAN_INITFQ_FLAG_SCHED, &initfq);
	if (errno < 0) {
		pr_err("error on qman_init_fq oh tx confq:%u = %d\n",
		       *fqid_ohtxconf, errno);
		qman_destroy_fq(&txconfq->fq_base, 0);
		devm_kfree(dev, txconfq);

		return errno;
	}

	*oh_txconfq = txconfq;

	hw_lag_dbg("oh tx confq initialize OK\n");

	return BOND_OH_SUCCESS;
}

/**
 * Initialize dynamic particular tx fqs of offline port for LAG xmit,
 * does not reuse tx fqs initialized by offline port driver. This method
 * can avoid to modify offline port driver even if the confirmation fq
 * need to be enabled.
 */
static int init_oh_tx_lag_fqs(struct device *dev,
			      struct dpa_fq **oh_tx_lag_fqs,
			      uint32_t fqid_ohtxconf, uint16_t oh_tx_channel)
{
	int errno = BOND_OH_SUCCESS, i, tx_fqs_count;
	uint16_t wq_id;
	struct dpa_fq *lag_fqs;
	struct qm_mcc_initfq fq_opts;
	uint32_t create_flags, init_flags;

	tx_fqs_count = num_possible_cpus();
	/* Allocate particular tx queues of offline port for LAG xmit. */
	lag_fqs = devm_kzalloc(dev, sizeof(struct dpa_fq) * tx_fqs_count,
			       GFP_KERNEL);
	if (!lag_fqs) {
		pr_err("Can't allocate tx fqs for LAG xmit.\n");
		errno = -ENOMEM;
		goto return_kfree;
	}

	/* Set flags for particular tx fqs, especially for dynamic fqid. */
	create_flags = QMAN_FQ_FLAG_TO_DCPORTAL | QMAN_FQ_FLAG_DYNAMIC_FQID;

	/* Create particular tx fqs of offline port for LAG xmit */
	for (i = 0; i < tx_fqs_count; i++) {
		/* set egress_ern callback for offline port tx fq */
		lag_fqs[i].fq_base = oh_egress_ernq;
		errno = qman_create_fq(0, create_flags, &lag_fqs[i].fq_base);
		if (errno) {
			pr_err("Error on creating tx fqs for LAG xmit.\n");
			goto return_kfree;
		}
	}

	/* Set init flags for tx fqs of oh port */
	init_flags = QMAN_INITFQ_FLAG_SCHED;

	/* Set fq init options. Specify destination wq id and channel */
	memset(&fq_opts, 0, sizeof(fq_opts));
	fq_opts.we_mask = QM_INITFQ_WE_DESTWQ;
	/* wq info from DPA-Eth driver */
	wq_id = 3;
	fq_opts.fqd.dest.wq = wq_id;
	fq_opts.fqd.dest.channel = oh_tx_channel;

	fq_opts.we_mask |= QM_INITFQ_WE_FQCTRL;
	fq_opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	fq_opts.fqd.fq_ctrl |= QM_FQCTRL_CTXASTASHING | QM_FQCTRL_AVOIDBLOCK;
	fq_opts.fqd.context_a.stashing.exclusive = QM_STASHING_EXCL_DATA |
	QM_STASHING_EXCL_CTX | QM_STASHING_EXCL_ANNOTATION;
	fq_opts.fqd.context_a.stashing.data_cl = 2;
	fq_opts.fqd.context_a.stashing.annotation_cl = 1;
	fq_opts.fqd.context_a.stashing.context_cl =
		DIV_ROUND_UP(sizeof(struct qman_fq), 64);

#ifdef CONFIG_HW_LAG_DEBUG
	fq_opts.we_mask |= QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_CONTEXTB;
	/**
	 * CTXA[OVFQ] = 1
	 * we set particular tx own confirmation fq and their own callback
	 * in case of interrupt DPA-Eth private conf callback/err callback
	 * /def callback.
	 */

	fq_opts.fqd.context_a.hi = 0x80000000;
	fq_opts.fqd.context_a.lo = 0x0;
	fq_opts.fqd.context_b = fqid_ohtxconf;
#endif
	/* Initialize particular tx frame queue of offline port for LAG xmit */
	for (i = 0; i < tx_fqs_count; i++) {
		errno = qman_init_fq(&lag_fqs[i].fq_base, init_flags, &fq_opts);
		if (errno)
			goto init_error;
	}

	for (i = 0; i < tx_fqs_count; i++) {
		hw_lag_dbg("ok, created lag_fqs: fqid:%d\n",
			   lag_fqs[i].fq_base.fqid);
	}

	*oh_tx_lag_fqs = lag_fqs;

	return BOND_OH_SUCCESS;
init_error:
	while (i-- < 0) {
		hw_lag_dbg("errors on initializing tx fqs, No.:%d tx fq.\n", i);
		qman_destroy_fq(&lag_fqs[i].fq_base, 0);
	}

return_kfree:
	if (lag_fqs)
		devm_kfree(dev, lag_fqs);

	return errno;
}

/**
 * This subroutine has been copied from offline_port driver
 * to get all information of all offline ports by parse DTS
 * return BOND_OH_SUCCESS when get information successfully.
 */
int get_oh_info(void)
{
	struct platform_device *oh_of_dev, *of_dev;
	struct device *dpa_oh_dev, *oh_dev;
	const unsigned int *p_port_id;
	const unsigned int *p_channel_id;
	struct fm_port *oh_port;
	unsigned long port_handle_cnt;
	struct fm_port_params params;
	struct device_node *oh_node, *dpa_oh_node = NULL;
	int fqcount, lenp, err = BOND_OH_SUCCESS, i = 0;

	const phandle *p_oh_port_handle;

	available_num_of_oh_ports = 0;

	/* probe offline ports and alloc memory, these codes need refining
	 * to save memory and need to get rid of the global variable.
	 */
	poh = kzalloc(sizeof(*poh) * FM_MAX_NUM_OF_OH_PORTS,
		      GFP_KERNEL);
	if (!poh)
		return -ENOMEM;

	for_each_matching_node(dpa_oh_node, oh_port_match_table) {
		if (dpa_oh_node) {
			p_oh_port_handle = of_get_property(dpa_oh_node,
							   "fsl,fman-oh-port",
							   &lenp);
			if (!p_oh_port_handle) {
				pr_err("No OH port handle in node %s\n",
				       dpa_oh_node->full_name);
				return -EINVAL;
			}
			hw_lag_dbg("dpa_oh_node->name:%s\n",
				   dpa_oh_node->full_name);
			BUG_ON(lenp % sizeof(*p_oh_port_handle));
			if (lenp != sizeof(*p_oh_port_handle)) {
				port_handle_cnt =
					lenp / sizeof(*p_oh_port_handle);

				pr_err("Found %lu oh port in node %s\n"
				       "only 1 phandle is allowed.\n",
				       port_handle_cnt,
				       dpa_oh_node->full_name);
				return -EINVAL;
			}

			oh_node = of_find_node_by_phandle(*p_oh_port_handle);
			if (!oh_node) {
				pr_err("no oh node referenced from %s\n",
				       dpa_oh_node->full_name);
				return -EINVAL;
			}
			hw_lag_dbg("Found oh_node->full_name  %s.\n",
				   oh_node->full_name);
			p_port_id = of_get_property(oh_node, "cell-index",
						    &lenp);

			if (!p_port_id) {
				pr_err("No port id found in node %s\n",
				       dpa_oh_node->full_name);
				return -EINVAL;
			}

			hw_lag_dbg("Found port id %u, in node %s\n",
				   *p_port_id, dpa_oh_node->full_name);
			BUG_ON(lenp % sizeof(*p_port_id));

			/* Read channel id for the queues */
			p_channel_id =
				of_get_property(oh_node,
						"fsl,qman-channel-id", &lenp);
			if (!p_channel_id) {
				pr_err("No channel id found in node %s\n",
				       dpa_oh_node->full_name);
				return -EINVAL;
			}

			BUG_ON(lenp % sizeof(*p_channel_id));

			oh_of_dev = of_find_device_by_node(oh_node);
			BUG_ON(!oh_of_dev);
			oh_dev = &oh_of_dev->dev;
			of_dev = of_find_device_by_node(dpa_oh_node);
			BUG_ON(!of_dev);
			dpa_oh_dev = &of_dev->dev;
			poh[i].of_dev = of_dev;
			poh[i].oh_of_dev = oh_of_dev;
			poh[i].dpa_oh_dev = dpa_oh_dev;
			poh[i].oh_dev = oh_dev;
			poh[i].dpa_oh_node = dpa_oh_node;
			poh[i].oh_node = oh_node;
			poh[i].cell_index = *p_port_id;
			poh[i].oh_config = dev_get_drvdata(dpa_oh_dev);
			poh[i].p_oh_port_handle = p_oh_port_handle;
			poh[i].oh_channel_id = (uint16_t)*p_channel_id;
			oh_port = poh[i].oh_config->oh_port;
			fm_port_get_buff_layout_ext_params(oh_port, &params);
			poh[i].bpid = params.pool_param[0].id;
			poh[i].bp_size = params.pool_param[0].size;
			/* give a friend name like "fman0-oh@1"
			 * rather than "/fsl,dpaa/dpa-fman0-oh@1".
			 * fill friendname array with dpa_oh_node->full_name,
			 * please don't use oh0 since documentatin says oh0
			 * has bad performance.
			 */
			memcpy(poh[i].friendname,
			       dpa_oh_node->full_name + 14, 10);

			fqcount = roundup_pow_of_two(FM_MAX_NUM_OF_MACS);
			if (qman_alloc_fqid_range(&poh[i].pcd_fqids_base,
						  fqcount, fqcount, 0) !=
						  fqcount) {
				pr_err("error on alloc continuous pcd fqid\n");
				return -EINVAL;
			}

			if (!poh[i].p_oh_rcv_channel) {
				uint16_t ch;

				err = op_alloc_pool_channel(&ch);
				if (err) {
					pr_err("Get pool channel error.\n");
					return err;
				}
				poh[i].p_oh_rcv_channel = ch;
			}

			err = init_oh_errq_defq(poh[i].dpa_oh_dev,
						poh[i].oh_config->error_fqid,
						poh[i].oh_config->default_fqid,
						&poh[i].oh_errq,
						&poh[i].oh_defq,
						poh[i].p_oh_rcv_channel);
			if (err != BOND_OH_SUCCESS) {
				pr_err("error when probe errq or defq.\n");
				return err;
			}

			err = init_oh_pcderrq_pcdconfq(poh[i].dpa_oh_dev,
						       &poh[i].fqid_pcderr,
						       &poh[i].fqid_pcdconf,
						       &poh[i].oh_pcderrq,
						       &poh[i].oh_pcdconfq,
						       poh[i].p_oh_rcv_channel);
			if (err != BOND_OH_SUCCESS) {
				pr_err("error on probe pcderrq or pcdconfq\n");
				return err;
			}

			err = init_oh_txconfq(poh[i].dpa_oh_dev,
					      &poh[i].fqid_ohtxconf,
					      &poh[i].oh_txconfq,
					      poh[i].oh_channel_id);
			if (err != BOND_OH_SUCCESS) {
				pr_err("error on init offline port tx confq\n");
				return err;
			}

			err = init_oh_tx_lag_fqs(poh[i].dpa_oh_dev,
						 &poh[i].oh_tx_lag_fqs,
						 poh[i].fqid_ohtxconf,
						 poh[i].oh_channel_id);
			if (err != BOND_OH_SUCCESS) {
				pr_err("error on init offline port tx confq\n");
				return err;
			}

			err = dpa_oh_bp_create(&poh[i]);
			if (err != BOND_OH_SUCCESS) {
				pr_err("error on init offline tx bp.\n");
				return err;
			}

			poh[i].allocated_pcd_mem = false;
			poh[i].applied_pcd = false;
			available_num_of_oh_ports = ++i;
		}
	}

	return err;
}

/**
 * Get the FM_MAC_RES_ID from a dpa-eth NIC, return 0 if it is not a dpa-eth，
 * otherwise return FM_MAC_RES_ID
 * this function does not process macless, LAG does not need a macless IF.
 */
static unsigned long long get_fm_mac_res_id(struct net_device *netdev)
{
	struct dpa_priv_s *priv = netdev_priv(netdev);

	if (!is_dpa_eth_port(netdev))
		return 0;

	return (unsigned long long)priv->mac_dev->res->start;
}

/**
 * Get the DCP_ID from a dpa-eth NIC, return 0 if it is not a dpa-eth，
 * return 1 if it's fm0, return 2 if it's fm1, since there are only 2
 * FMAN in current DPA SOC.
 * this function does not process macless, LAG does not need a macless IF.
 */
int get_dcp_id_from_dpa_eth_port(struct net_device *netdev)
{
	unsigned long long mac_res_start = get_fm_mac_res_id(netdev);

	if ((mac_res_start >= FM1_GB0) && (mac_res_start <= FM1_10G))
		return 1;
	else if ((mac_res_start >= FM2_GB0) && (mac_res_start <= FM2_10G))
		return 2;
	else
		return 0;
}

/**
 * Get all information of the offline port which is being used
 * by a bundle, such as fman_dcpid, offline port offset, cell index,
 * offline port channel. This API is required by CEETM Qos.
 */
int export_oh_port_info_to_ceetm(struct bonding *bond, uint16_t *channel,
				 unsigned long *fman_dcpid,
				 unsigned long *oh_offset,
				 unsigned long *cell_index)
{
	struct oh_port_priv *p = bond->params.ohp;
	char tmp[] = "cell-index";

	if (!p) {
		pr_err("The bundle has not binded an offline port.\n");
		return BOND_OH_ERROR;
	}

	if (!p->oh_en) {
		pr_err("The offline is disabled, to enable it, use sysfs.\n");
		return BOND_OH_ERROR;
	}

	if (!p->oh_node) {
		pr_err("The offline node error.\n");
		return BOND_OH_ERROR;
	}

	if (of_property_read_u32(p->oh_node, "reg", (u32 *)oh_offset)) {
		pr_err("Errors on getting offline port offset.\n");
		return BOND_OH_ERROR;
	}

	if (of_property_read_u32(p->oh_node->parent, tmp, (u32 *)fman_dcpid)) {
		pr_err("Errors on getting fman_dcpid.\n");
		return BOND_OH_ERROR;
	}

	*channel = (uint16_t)p->oh_channel_id;
	*cell_index = p->cell_index;

	hw_lag_dbg("This oh port mapped to bond has channel:0x%0x\n", *channel);
	hw_lag_dbg("fman_dcpid:0x%0lx, oh_offset:0x%0lx, cell-index:%0lx\n",
		   *fman_dcpid, *oh_offset, *cell_index);

	return BOND_OH_SUCCESS;
}
EXPORT_SYMBOL(export_oh_port_info_to_ceetm);

/**
 * Public APIs which can use for Link Aggregation and CEETM Qos
 * show bond info and slave device info when they are available
 */
int show_dpa_slave_info(struct bonding *bond, struct slave *slave)
{
	struct dpa_priv_s *priv = netdev_priv(slave->dev);

	if (bond)
		pr_info("bond->dev->name:%s, slave_cnt:%d\n",
			bond->dev->name, bond->slave_cnt);
	if (slave)
		pr_info("new_slave:%s\n", slave->dev->name);

	if (is_dpa_eth_port(slave->dev)) {
		pr_info("priv->mac_dev->res->start:%llx\n",
			(unsigned long long)priv->mac_dev->res->start);
		pr_info("get_dcp_id_from_dpa_eth_port(netdev):0x%0x\n",
			get_dcp_id_from_dpa_eth_port(slave->dev));
	} else
		pr_info("the slave device %s is not a DPAA-Eth NIC\n",
			slave->dev->name);

	return 0;
}

int init_status(struct net_device *netdev)
{
	struct bonding *bond = master_to_bond(netdev);

	memset(&bond->params.oh_stats, 0, sizeof(struct rtnl_link_stats64));

	return BOND_OH_SUCCESS;
}

void add_statistics(struct bonding *bond, struct rtnl_link_stats64 *stats)
{
	stats->tx_packets += bond->params.oh_stats.tx_packets;
	stats->tx_bytes += bond->params.oh_stats.tx_bytes;
	stats->tx_errors += bond->params.oh_stats.tx_errors;
	stats->tx_dropped += bond->params.oh_stats.tx_dropped;
}

static void dump_ip_summed_type(struct sk_buff *skb)
{
#ifdef CONFIG_HW_LAG_DEBUG
	if (skb->ip_summed == CHECKSUM_NONE)
		hw_lag_dbg("skb->ip_summed == CHECKSUM_NONE.\n");
	if (skb->ip_summed == CHECKSUM_UNNECESSARY)
		hw_lag_dbg("skb->ip_summed == CHECKSUM_UNNECESSARY.\n");
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		hw_lag_dbg("skb->ip_summed == CHECKSUM_COMPLETE.\n");
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		hw_lag_dbg("skb->ip_summed == CHECKSUM_PARTIAL.\n");
#endif
}

/**
 * Copied from oNIC (removed priv)
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
int oh_tx_csum_enable(struct sk_buff *skb, struct qm_fd *fd,
		      char *parse_results)
{
	fm_prs_result_t *parse_result;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h = NULL;
	struct tcphdr *tcph;
	struct udphdr *udph;
	int l4_proto;
	int ethertype = ntohs(skb->protocol);
	int retval = 0, i;
	unsigned char *p;

	dump_ip_summed_type(skb);
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		/* Process termination path, fill in some fields of the
		 * Parse Results array, so the FMan can find them as if
		 * they came from the FMan Parser.
		 */
		int j = 0;

		parse_result = (fm_prs_result_t *)parse_results;
		/* If we're dealing with VLAN, get the real Ethernet type */
		if (ethertype == ETH_P_8021Q) {
			/* We can't always assume the MAC header is set
			 * correctly by the stack, so reset to beginning of
			 * skb->data
			 */
			__be16 etype;

			skb_reset_mac_header(skb);
			etype = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
			ethertype = ntohs(etype);
			/* below l2r need look up FMAN RM to verify */
			parse_result->l2r = FM_PR_L2_VLAN | FM_PR_L2_VLAN_STACK;
		} else {
			parse_result->l2r = FM_PR_L2_ETHERNET;
		}

		/* Fill in the relevant L3 parse result fields
		 * and read the L4 protocol type
		 */
		switch (ethertype) {
		case ETH_P_IP:
			parse_result->l3r = FM_L3_PARSE_RESULT_IPV4;
			iph = ip_hdr(skb);
			BUG_ON(!iph);
			l4_proto = ntohs(iph->protocol);
			break;
		case ETH_P_IPV6:
			parse_result->l3r = FM_L3_PARSE_RESULT_IPV6;
			ipv6h = ipv6_hdr(skb);
			BUG_ON(!ipv6h);
			l4_proto = ntohs(ipv6h->nexthdr);
			break;
		default:
			/* We shouldn't even be here */
			hw_lag_dbg("Can't compute HW csum for L3 proto 0x%x\n",
				   ntohs(skb->protocol));
			retval = -EIO;
			goto return_error;
		}

		hw_lag_dbg("skb->protocol(L3):0x%04x, ethertype:%x\n",
			   ntohs(skb->protocol), ethertype);

		/* Fill in the relevant L4 parse result fields */
		switch (l4_proto) {
			int offset;

		case IPPROTO_UDP:
			parse_result->l4r = FM_L4_PARSE_RESULT_UDP;
			udph = (struct udphdr *)(skb->data +
						 skb_transport_offset(skb));
			hw_lag_dbg("udp org csum:0x%0x\n", udph->check);
			offset = skb_checksum_start_offset(skb);
			skb_set_transport_header(skb, offset);
			skb_checksum_help(skb);
			hw_lag_dbg("udp software csum:0x%0x\n", udph->check);
			break;
		case IPPROTO_TCP:
			parse_result->l4r = FM_L4_PARSE_RESULT_TCP;
			tcph = (struct tcphdr *)(skb->data +
						 skb_transport_offset(skb));
			p = skb->data;
			hw_lag_dbg("\ndmac:%02x:%02x:%02x:%02x:%02x:%02x\n"
				   "smac:%02x:%02x:%02x:%02x:%02x:%02x\n"
				   "h_proto:0x%04x\n", p[0], p[1], p[2], p[3],
				   p[4], p[5], p[6], p[7], p[8], p[9], p[10],
				   p[11], *((short *)(p + 12)));

			/* dump skb data info for manual calculate L4CSUM,
			 * jump over net header first
			 */
			p += skb_network_offset(skb);
			j = skb->len - skb_network_offset(skb) - 4;
			for (i = 0; i < j; i += 4)
				hw_lag_dbg("%08x\n",
					   *((unsigned int *)(p + i)));

			j = skb->len - skb_network_offset(skb);
			for (; i < j; i++)
				hw_lag_dbg("%02x\n", *(p + i));

			hw_lag_dbg("tcp org csum:0x%0x.\n", tcph->check);
			offset = skb_checksum_start_offset(skb);
			skb_set_transport_header(skb, offset);
			skb_checksum_help(skb);
			hw_lag_dbg("tcp software csum:0x%0x,\n", tcph->check);

			break;
		default:
			/* This can as well be a BUG() */
			pr_err("Can't compute HW csum for L4 proto 0x%x\n",
			       l4_proto);
			retval = -EIO;
			goto return_error;
		}

		hw_lag_dbg("l4_proto:0x%04x, result->l2r:0x%04x\n",
			   l4_proto, parse_result->l2r);
		hw_lag_dbg("result->l3r:0x%04x, result->l4r:0x%02x.\n",
			   parse_result->l3r, parse_result->l4r);

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
	} else if ((skb->ip_summed == CHECKSUM_NONE) ||
			(skb->ip_summed == CHECKSUM_UNNECESSARY)) {
		/* Process forwarding path, fill in some fields of the
		 * Parse Results array, so the FMan can find them as if
		 * they came from the FMan Parser.
		 */
		parse_result = (fm_prs_result_t *)parse_results;
		/* If we're dealing with VLAN, get the real Ethernet type */
		if (ethertype == ETH_P_8021Q) {
			/* We can't always assume the MAC header is set
			 * correctly by the stack, so reset to beginning
			 * of skb->data
			 */
			__be16 etype;

			skb_reset_mac_header(skb);
			etype = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
			ethertype = ntohs(etype);
			/* below l2r need look up FMAN RM to verify */
			parse_result->l2r = FM_PR_L2_VLAN | FM_PR_L2_VLAN_STACK;
		} else {
			parse_result->l2r = FM_PR_L2_ETHERNET;
		}

		/* Fill in the relevant L3 parse result fields
		 * and read the L4 protocol type
		 */
		switch (ethertype) {
		case ETH_P_IP:
			parse_result->l3r = FM_L3_PARSE_RESULT_IPV4;
			iph = ip_hdr(skb);
			BUG_ON(!iph);
			l4_proto = ntohs(iph->protocol);
			break;
		case ETH_P_IPV6:
			parse_result->l3r = FM_L3_PARSE_RESULT_IPV6;
			ipv6h = ipv6_hdr(skb);
			BUG_ON(!ipv6h);
			l4_proto = ntohs(ipv6h->nexthdr);
			break;
		default:
			/* Other L3 use default value. */
			hw_lag_dbg("L3 proto 0x%x\n", ntohs(skb->protocol));
			return 0;
		}

		hw_lag_dbg("skb->protocol(L3):0x%04x, ethertype:%x\n",
			   ntohs(skb->protocol), ethertype);

		/* Fill in the relevant L4 parse result fields */
		switch (l4_proto) {
		case IPPROTO_UDP:
			parse_result->l4r = FM_L4_PARSE_RESULT_UDP;
			udph = (struct udphdr *)(skb->data +
						 skb_transport_offset(skb));
			hw_lag_dbg("udp org csum:0x%0x\n", udph->check);
			break;
		case IPPROTO_TCP:
			parse_result->l4r = FM_L4_PARSE_RESULT_TCP;
			tcph = (struct tcphdr *)(skb->data +
						 skb_transport_offset(skb));
			p = skb->data;
			hw_lag_dbg("\ndmac:%02x:%02x:%02x:%02x:%02x:%02x\n"
				   "smac:%02x:%02x:%02x:%02x:%02x:%02x\n"
				   "h_proto:0x%04x\n", p[0], p[1], p[2], p[3],
				   p[4], p[5], p[6], p[7], p[8], p[9], p[10],
				   p[11], *((short *)(p + 12)));

			hw_lag_dbg("tcp org csum:0x%0x.\n", tcph->check);
			break;
		default:
			/* at forwarding path, we only help TCP/UDP
			 * to fill parser result.
			 */
			hw_lag_dbg("L4 proto 0x%x\n", l4_proto);
			return 0;
		}

		hw_lag_dbg("l4_proto:0x%04x, result->l2r:0x%04x\n",
			   l4_proto, parse_result->l2r);
		hw_lag_dbg("result->l3r:0x%04x, result->l4r:0x%02x.\n",
			   parse_result->l3r, parse_result->l4r);

		/* At index 0 is IPOffset_1 as defined in the Parse Results */
		parse_result->ip_off[0] = (uint8_t)skb_network_offset(skb);
		parse_result->l4_off = (uint8_t)skb_transport_offset(skb);

		/* Enable L3 (and L4, if TCP or UDP) HW checksum. */
		fd->cmd |= FM_FD_CMD_RPD | FM_FD_CMD_DCL4C;
	}

	return 0;
}

static int __hot dpa_oh_xmit(struct qm_fd *fd, struct qman_fq *tx_fq)
{
	int err, i;

	for (i = 0; i < 100000; i++) {
		err = qman_enqueue(tx_fq, fd, 0);
		if (err != -EBUSY)
			break;
	}

	if (unlikely(err < 0)) {
		/* TODO differentiate b/w -EBUSY (EQCR full) and other codes? */
		pr_err("qman_enqueue() error.\n");
		return err;
	}

	return 0;
}

int __hot dpa_oh_tx(struct sk_buff *skb, struct bonding *bond,
		    struct net_device *net_dev, struct dpa_fq *tx_fq)
{
	struct dpa_priv_s	*priv;
	struct dpa_bp *bp = bond->params.ohp->tx_bp;

	struct sk_buff **skbh = NULL;
	dma_addr_t addr;
	struct qm_fd fd;
	int err = 0;
	int *countptr;
	struct rtnl_link_stats64 *percpu_stats;

	tx_fq->net_dev = bond->params.ohp->slave[0]->dev;
	priv = netdev_priv(bond->params.ohp->slave[0]->dev);
	percpu_stats = &bond->params.oh_stats;
	countptr = this_cpu_ptr(bond->params.ohp->tx_bp->percpu_count);

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

	/* TODO check if skb->len + priv->tx_headroom < bp->size */

	/* Enable L3/L4 hardware checksum computation.
	 *
	 * We must do this before dma_map_single(), because we may
	 * need to write into the skb.
	 */
	err = oh_tx_csum_enable(skb, &fd,
				((char *)skbh) + DPA_TX_PRIV_DATA_SIZE);

	if (unlikely(err < 0)) {
		pr_err("HW csum error: %d\n", err);

		return err;
	}

	addr = dma_map_single(bp->dev, skbh,
			      skb->len + priv->tx_headroom, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(bp->dev, addr))) {
			pr_err("dma_map_single() failed\n");
		goto dma_mapping_failed;
	}

	fd.format = qm_fd_contig;
	fd.length20 = skb->len;
	fd.offset = priv->tx_headroom;
	fd.addr_hi = (u8)upper_32_bits(addr);
	fd.addr_lo = lower_32_bits(addr);
	/* fd.cmd |= FM_FD_CMD_FCO; */
	fd.bpid = bp->bpid;

	/* (Partially) drain the Draining Buffer Pool pool; each core
	 * acquires at most the number of buffers it put there; since
	 * BMan allows for up to 8 buffers to be acquired at one time,
	 * work in batches of 8 for efficiency reasons
	 */
	dpa_oh_drain_bp(bp);

	if (unlikely(dpa_oh_xmit(&fd, &tx_fq->fq_base) < 0)) {
		/* oh tx error, add statistics */
		bond->params.oh_stats.tx_packets++;
		bond->params.oh_stats.tx_errors++;
		hw_lag_dbg("3ad enqueue_pkt error...txerr_pkt:%llu\n",
			   bond->params.oh_stats.tx_packets);
		goto xmit_failed;
	} else {
		/* oh tx OK, add statistics */
		bond->params.oh_stats.tx_packets++;
		bond->params.oh_stats.tx_bytes += skb->len;
		hw_lag_dbg("3ad enqueue_pkt OK...tx_pkt:%llu\n",
			   bond->params.oh_stats.tx_packets);
		return NETDEV_TX_OK;
	}

	countptr = this_cpu_ptr(bp->percpu_count);
	(*countptr)++;

	goto done;

xmit_failed:
	dma_unmap_single(bp->dev, addr, fd.offset + fd.length20, DMA_TO_DEVICE);
dma_mapping_failed:
	percpu_stats->tx_errors++;
	dev_kfree_skb(skb);
done:
	return NETDEV_TX_OK;
}

/**
 * Enqueue one skb pkt to offline port which attached to a bond.
 * bond: current bond's pointer
 * skb:  pkt which will be enqueued to the offline port
 * ceetm_fq: pkt will use this fq for xmit. if this ceetm_fq is
 * pointing to NULL, will use default tx_fq for xmit.
 * return BOND_OH_SUCCESS if enqueued, otherwise return errors.
 */
int enqueue_pkt_to_oh(struct bonding *bond, struct sk_buff *skb,
		      struct dpa_fq *ceetm_fq)
{
	struct oh_port_priv *p_oh = bond->params.ohp;
	struct net_device *slave_netdev = NULL;
	struct dpa_fq *tx_fq = p_oh->oh_tx_lag_fqs;

	slave_netdev = p_oh->slave[0]->dev;

	p_oh->oh_errq->net_dev = slave_netdev;
	p_oh->oh_defq->net_dev = slave_netdev;

	if (!is_dpa_eth_port(slave_netdev)) {
		pr_err("is not dpaa NIC or NULL pointer.\n");
		return -EINVAL;
	}

	if (ceetm_fq)
		return dpa_oh_tx(skb, bond, slave_netdev, ceetm_fq);
	else
		return dpa_oh_tx(skb, bond, slave_netdev, tx_fq);
}
EXPORT_SYMBOL(enqueue_pkt_to_oh);

static int get_dpa_slave_info(struct slave *slave, uint16_t *tx_channel)
{
	struct dpa_priv_s *priv = netdev_priv(slave->dev);

	if (!is_dpa_eth_port(slave->dev) || !(priv->mac_dev))
		return BOND_OH_ERROR;

	*tx_channel = (uint16_t)fm_get_tx_port_channel(
				priv->mac_dev->port_dev[TX]);

	return BOND_OH_SUCCESS;
}

int get_dpa_slave_info_ex(struct slave *slave, uint16_t *tx_channel,
			  struct qman_fq **egress_fq, u32 *first_fqid)
{
	struct dpa_priv_s *priv = netdev_priv(slave->dev);

	if (!is_dpa_eth_port(slave->dev) || !(priv->mac_dev))
		return BOND_OH_ERROR;

	*tx_channel	= (uint16_t)fm_get_tx_port_channel(
				    priv->mac_dev->port_dev[TX]);
	*egress_fq	= priv->egress_fqs[0];
	*first_fqid	= priv->egress_fqs[0]->fqid;

	return BOND_OH_SUCCESS;
}

/* Creates Frame Queues, these 2 good subroutines are completely copied from
 * Bogdan Purcareata's good patch "Offline port queues initialization", HW_LAG
 * need to initialize FQs for an offline port PCD usage with tx_channel/wq of
 * slave devices which have already attached to a bond, HW_LAG OH port dequeue,
 * then enqueue PCD FQs to DPA-Eth via these PCD FQs.
 */
static int create_oh_pcd_fq(struct qman_fq *fq, u32 fqid_pcdconf,
			    uint32_t fq_id, uint16_t tx_channel, uint16_t wq_id)
{
	struct qm_mcc_initfq fq_opts;
	uint32_t create_flags, init_flags;
	uint32_t ret = 0;

	if (!fq)
		return BOND_OH_ERROR;

	/* Set flags for FQ create */
	create_flags = QMAN_FQ_FLAG_TO_DCPORTAL;

	/* set egress_ern callback for pcd fqs */
	*fq = oh_pcd_egress_ernq;

	/* Create frame queue */
	ret = qman_create_fq(fq_id, create_flags, fq);
	if (ret != 0)
		return BOND_OH_ERROR;

	/* Set flags for FQ init */
	init_flags = QMAN_INITFQ_FLAG_SCHED;

	/* Set FQ init options. Specify destination WQ ID and channel */
	memset(&fq_opts, 0, sizeof(fq_opts));
	fq_opts.we_mask = QM_INITFQ_WE_DESTWQ;
	fq_opts.fqd.dest.wq = wq_id;
	fq_opts.fqd.dest.channel = tx_channel;

	fq_opts.we_mask |= QM_INITFQ_WE_FQCTRL;
	fq_opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	fq_opts.fqd.fq_ctrl |= QM_FQCTRL_CTXASTASHING | QM_FQCTRL_AVOIDBLOCK;
	fq_opts.fqd.context_a.stashing.exclusive = QM_STASHING_EXCL_DATA |
		QM_STASHING_EXCL_CTX | QM_STASHING_EXCL_ANNOTATION;
	fq_opts.fqd.context_a.stashing.data_cl = 2;
	fq_opts.fqd.context_a.stashing.annotation_cl = 1;
	fq_opts.fqd.context_a.stashing.context_cl =
		DIV_ROUND_UP(sizeof(struct qman_fq), 64);

	fq_opts.we_mask |= QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_CONTEXTB;
	/**
	 * CTXA[OVFQ] = 1
	 * we set PCD own confirmation Q and their own callback in case of
	 * interrupt DPA-Eth private conf callback/err callback/def callback.
	 */
	fq_opts.fqd.context_a.hi = 0x80000000;
	fq_opts.fqd.context_a.lo = 0x0;
	fq_opts.fqd.context_b = fqid_pcdconf;

	/* Initialize frame queue */
	ret = qman_init_fq(fq, init_flags, &fq_opts);
	if (ret != 0) {
		qman_destroy_fq(fq, 0);
		return BOND_OH_ERROR;
	}
	hw_lag_dbg("FQ create_flags:0X%0x, init_flags:0X%0x\n",
		   create_flags, init_flags);

	return BOND_OH_SUCCESS;
}

static int hw_lag_allocate_pcd_queues(struct device *dev,
				      struct dpa_fq **p_pcd_fq,
				      u32 fqid_pcdconf, u32 fqid,
				      uint16_t tx_channel, uint16_t wq)
{
	/* Allocate pcd queues */
	int errno = BOND_OH_SUCCESS;
	struct dpa_fq *pcd_fq;

	hw_lag_dbg("Allocating PCD queues...p_pcd_fq:%p, fqid:%d\n",
		   *p_pcd_fq, fqid);
	pcd_fq = devm_kzalloc(dev, sizeof(struct dpa_fq), GFP_KERNEL);
	if (!pcd_fq) {
		pr_err("can't allocate slave PCD FQ!\n");
		errno = -ENOMEM;
		goto return_kfree;
	}

	hw_lag_dbg("Allocated pcd_fq:%p, fqid:%d\n", pcd_fq, fqid);
	/* Create pcd queues */
	errno = create_oh_pcd_fq(&pcd_fq->fq_base, fqid_pcdconf,
				 fqid, tx_channel, wq);
	if (errno != BOND_OH_SUCCESS) {
		pr_err("can't create lag PCD FQ:%u\n", fqid);
		errno = -EINVAL;
		goto return_kfree;
	}

	*p_pcd_fq = pcd_fq;
	hw_lag_dbg("created pcd_fq:%p, fqid:%d, *p_pcd_fq:%p\n",
		   pcd_fq, fqid, *p_pcd_fq);
	return BOND_OH_SUCCESS;

return_kfree:
	if (pcd_fq)
		devm_kfree(dev, pcd_fq);
	return errno;
}

/* Destroys Frame Queues */
static void hw_lag_fq_destroy(struct qman_fq *fq)
{
	int errno = BOND_OH_SUCCESS;

	errno = qman_retire_fq(fq, NULL);
	if (unlikely(errno < 0))
		pr_err("qman_retire_fq(%u)=%d\n", qman_fq_fqid(fq), errno);

	errno = qman_oos_fq(fq);
	if (unlikely(errno < 0))
		pr_err("qman_oos_fq(%u)=%d\n", qman_fq_fqid(fq), errno);

	qman_destroy_fq(fq, 0);
}

/* release fq memory */
static int hw_lag_release_fq(struct device *dev, struct dpa_fq *fq)
{
	if (!fq)
		return BOND_OH_ERROR;

	hw_lag_fq_destroy(&fq->fq_base);
	if (!dev)
		return BOND_OH_ERROR;

	devm_kfree(dev, fq);

	return BOND_OH_SUCCESS;
}

/**
 * Get DPA slave device information: wq/channel_id, allocate FQID/FQ memory,
 * then set FQ flags, record the slave pointer in case of remove these
 * information when detaching slave in the future.
 */
int fill_oh_pcd_fqs_with_slave_info(struct bonding *bond, struct slave *slave)
{
	uint16_t tx_channel, mode;
	struct dpa_fq *pcd_fq = NULL;
	struct oh_port_priv *cur;
	u32 fqid;
	uint16_t wq_id = 3; /* the default value in DPA-Eth private driver */

	mode = bond->params.mode;
	if (mode != BOND_MODE_8023AD && mode != BOND_MODE_XOR) {
		pr_err("%s: This command only support 802.3ad and xor mode.\n",
		       bond->dev->name);
		return BOND_OH_ERROR;
	}

	if (is_dpa_eth_port(slave->dev) == false) {
		pr_err("error, only support dpa eth nic.\n");
		return BOND_OH_ERROR;
	}

	if (bond->slave_cnt > SLAVES_PER_BOND) {
		pr_err("error, only support 2 dpa nic per bond.\n");
		return BOND_OH_ERROR;
	}

	if (get_dpa_slave_info(slave, &tx_channel) == BOND_OH_ERROR) {
		pr_err("error on getting dpa info when fill OH FQs.\n");
		return BOND_OH_ERROR;
	}

	cur = bond->params.ohp;
	if (!cur) {
		pr_err("have not bind an OH port,\n");
		pr_err("will use software tx traffic distribution.\n");
		return BOND_OH_ERROR;
	}

	hw_lag_dbg("cur->pcd_fqs[0]:%p, cur->pcd_fqs[1]:%p\n",
		   cur->pcd_fqs[0], cur->pcd_fqs[1]);
	if (!cur->pcd_fqs[0])
		fqid = cur->pcd_fqids_base;
	else
		fqid = cur->pcd_fqids_base + 1;

	hw_lag_dbg("pcd_fq:%p, fqid:%d Before alloc.\n", pcd_fq, fqid);

	if (hw_lag_allocate_pcd_queues(cur->dpa_oh_dev, &pcd_fq,
				       cur->fqid_pcdconf, fqid, tx_channel,
				       wq_id) == BOND_OH_ERROR) {
		pr_err("error on create pcd fqs\n");
		return BOND_OH_ERROR;
	}

	hw_lag_dbg("pcd_fq:%p, fqid:%d, tx_channel:%d, wq_id:%d After alloc.\n",
		   pcd_fq, fqid, tx_channel, wq_id);
	hw_lag_dbg("fqid:0x%0x, tx_channel:0x%0x, wq_id:0x%0x After alloc.\n",
		   fqid, tx_channel, wq_id);

	if (!cur->pcd_fqs[0]) {
		cur->pcd_fqs[0] = pcd_fq;
		cur->slave[0] = slave;
	} else if (!cur->pcd_fqs[1]) {
		cur->pcd_fqs[1] = pcd_fq;
		cur->slave[1] = slave;
	}

	return BOND_OH_SUCCESS;
}

/* forget offline port pcd information according to slave pointer,
 * then destroy fq and release the fq memory.
 */
int del_oh_pcd_fqs_with_slave_info(struct bonding *bond, struct slave *slave)
{
	struct oh_port_priv *cur;
	struct dpa_fq *pcd_fq;

	if (is_dpa_eth_port(slave->dev) == false) {
		pr_err("error, only support dpa eth nic.\n");
		return BOND_OH_ERROR;
	}
	cur = bond->params.ohp;
	if (!cur) {
		pr_err("have not bind an OH port,\n");
		pr_err("will use software tx traffic distribution.\n");
		return BOND_OH_ERROR;
	}
	if (slave == cur->slave[0]) {
		pcd_fq = cur->pcd_fqs[0];
		cur->pcd_fqs[0] = NULL;
		cur->slave[0] = NULL;
	} else if (slave == cur->slave[1]) {
		pcd_fq = cur->pcd_fqs[1];
		cur->pcd_fqs[1] = NULL;
		cur->slave[1] = NULL;
	} else {
		pcd_fq = NULL;
	}

	return hw_lag_release_fq(cur->dpa_oh_dev, pcd_fq);
}
