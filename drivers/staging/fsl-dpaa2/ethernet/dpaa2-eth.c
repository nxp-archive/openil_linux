/* Copyright 2014-2015 Freescale Semiconductor Inc.
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
#include <linux/platform_device.h>
#include <linux/etherdevice.h>
#include <linux/of_net.h>
#include <linux/interrupt.h>
#include <linux/debugfs.h>
#include <linux/kthread.h>

#include "../../fsl-mc/include/mc.h"
#include "../../fsl-mc/include/mc-sys.h" /* FSL_MC_IO_ATOMIC_CONTEXT_PORTAL */
#include "dpaa2-eth.h"

/* CREATE_TRACE_POINTS only needs to be defined once. Other dpa files
 * using trace events only need to #include <trace/events/sched.h>
 */
#define CREATE_TRACE_POINTS
#include "dpaa2-eth-trace.h"

#define LDPAA_ETH_DESCRIPTION "Freescale DPAA Ethernet Driver"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Freescale Semiconductor, Inc");
MODULE_DESCRIPTION(LDPAA_ETH_DESCRIPTION);

static uint8_t debug = -1;
module_param(debug, byte, S_IRUGO);
MODULE_PARM_DESC(debug, "Module/Driver verbosity level");

/* Iterate through the cpumask in a round-robin fashion. */
#define cpumask_rr(cpu, maskptr) \
do { \
	(cpu) = cpumask_next((cpu), (maskptr)); \
	if ((cpu) >= nr_cpu_ids) \
		(cpu) = cpumask_first((maskptr)); \
} while (0)

static int ldpaa_dpbp_refill(struct ldpaa_eth_priv *priv, uint16_t bpid);
static int ldpaa_dpbp_seed(struct ldpaa_eth_priv *priv, uint16_t bpid);
static void __cold __ldpaa_dpbp_free(struct ldpaa_eth_priv *priv);

/* TODO Assert it is smaller than LDPAA_ETH_SWA_SIZE */
struct ldpaa_eth_swa {
	struct sk_buff *skb;
	struct scatterlist *scl;
	int num_sg;
	int num_dma_bufs;
};

static void ldpaa_eth_rx_csum(struct ldpaa_eth_priv *priv,
			      uint32_t fd_status,
			      struct sk_buff *skb)
{
	skb_checksum_none_assert(skb);

	/* HW checksum validation is disabled, nothing to do here */
	if (!(priv->net_dev->features & NETIF_F_RXCSUM))
		return;

	/* Read checksum validation bits */
	if (!((fd_status & LDPAA_ETH_FAS_L3CV) &&
	      (fd_status & LDPAA_ETH_FAS_L4CV)))
		return;

	/* Inform the stack there's no need to compute L3/L4 csum anymore */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/* Free a received FD.
 * Not to be used for Tx conf FDs or on any other paths.
 */
static void ldpaa_eth_free_rx_fd(struct ldpaa_eth_priv *priv,
				 const struct dpaa_fd *fd,
				 void *vaddr)
{
	struct device *dev = priv->net_dev->dev.parent;
	dma_addr_t addr = ldpaa_fd_get_addr(fd);
	uint8_t fd_format = ldpaa_fd_get_format(fd);

	if (fd_format == dpaa_fd_sg) {
		struct dpaa_sg_entry *sgt = vaddr + ldpaa_fd_get_offset(fd);
		void *sg_vaddr;
		int i;

		for (i = 0; i < LDPAA_ETH_MAX_SG_ENTRIES; i++) {
			ldpaa_sg_le_to_cpu(&sgt[i]);

			addr = ldpaa_sg_get_addr(&sgt[i]);
			dma_unmap_single(dev, addr, LDPAA_ETH_RX_BUFFER_SIZE,
					 DMA_FROM_DEVICE);

			sg_vaddr = phys_to_virt(addr);
			put_page(virt_to_head_page(sg_vaddr));

			if (ldpaa_sg_is_final(&sgt[i]))
				break;
		}
	}

	put_page(virt_to_head_page(vaddr));
}

/* Build a linear skb based on a single-buffer frame descriptor */
static struct sk_buff *ldpaa_eth_build_linear_skb(struct ldpaa_eth_priv *priv,
						  const struct dpaa_fd *fd,
						  void *fd_vaddr)
{
	struct sk_buff *skb = NULL;
	uint16_t fd_offset = ldpaa_fd_get_offset(fd);
	uint32_t fd_length = ldpaa_fd_get_len(fd);
	int *count;

	skb = build_skb(fd_vaddr, LDPAA_ETH_RX_BUFFER_SIZE +
			SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
	if (unlikely(!skb)) {
		netdev_err(priv->net_dev, "build_skb() failed\n");
		return NULL;
	}

	skb_reserve(skb, fd_offset);
	skb_put(skb, fd_length);

	count = this_cpu_ptr(priv->buf_count);
	(*count)--;

	return skb;
}


/* Build a non linear (fragmented) skb based on a S/G table */
static struct sk_buff *ldpaa_eth_build_frag_skb(struct ldpaa_eth_priv *priv,
						struct dpaa_sg_entry *sgt)
{
	struct sk_buff *skb = NULL;
	struct device *dev = priv->net_dev->dev.parent;
	void *sg_vaddr;
	dma_addr_t sg_addr;
	uint16_t sg_offset;
	uint32_t sg_length;
	struct page *page, *head_page;
	int page_offset;
	int *count;
	int i;

	for (i = 0; i < LDPAA_ETH_MAX_SG_ENTRIES; i++) {
		struct dpaa_sg_entry *sge = &sgt[i];

		ldpaa_sg_le_to_cpu(sge);

		/* We don't support anything else yet! */
		BUG_ON(ldpaa_sg_get_format(sge) != dpaa_sg_single);

		/* Get the address, offset and length from the S/G entry */
		sg_addr = ldpaa_sg_get_addr(sge);
		dma_unmap_single(dev, sg_addr, LDPAA_ETH_RX_BUFFER_SIZE,
				 DMA_FROM_DEVICE);
		if (unlikely(dma_mapping_error(dev, sg_addr))) {
			netdev_err(priv->net_dev, "DMA unmap failed\n");
			return NULL;
		}
		sg_vaddr = phys_to_virt(sg_addr);
		sg_length = ldpaa_sg_get_len(sge);

		if (i == 0) {
			/* We build the skb around the first data buffer */
			skb = build_skb(sg_vaddr, LDPAA_ETH_RX_BUFFER_SIZE +
				SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
			if (unlikely(!skb)) {
				netdev_err(priv->net_dev, "build_skb failed\n");
				return NULL;
			}
			sg_offset = ldpaa_sg_get_offset(sge);
			skb_reserve(skb, sg_offset);
			skb_put(skb, sg_length);
		} else {
			/* Subsequent data in SGEntries are stored at
			 * offset 0 in their buffers, we don't need to
			 * compute sg_offset.
			 */
			WARN_ONCE(ldpaa_sg_get_offset(sge) != 0,
				  "Non-zero offset in SGE[%d]!\n", i);

			/* Rest of the data buffers are stored as skb frags */
			page = virt_to_page(sg_vaddr);
			head_page = virt_to_head_page(sg_vaddr);

			/* Offset in page (which may be compound) */
			page_offset = ((unsigned long)sg_vaddr &
				(PAGE_SIZE - 1)) +
				(page_address(page) - page_address(head_page));

			skb_add_rx_frag(skb, i - 1, head_page, page_offset,
					sg_length, LDPAA_ETH_RX_BUFFER_SIZE);
		}

		if (ldpaa_sg_is_final(sge))
			break;
	}

	/* Count all data buffers + sgt buffer */
	count = this_cpu_ptr(priv->buf_count);
	*count -= i + 2;

	return skb;
}

static void ldpaa_eth_rx(struct ldpaa_eth_priv *priv,
			 const struct dpaa_fd *fd,
			 struct napi_struct *napi)
{
	dma_addr_t addr = ldpaa_fd_get_addr(fd);
	uint8_t fd_format = ldpaa_fd_get_format(fd);
	void *vaddr;
	struct sk_buff *skb;
	struct rtnl_link_stats64 *percpu_stats;
	struct ldpaa_eth_stats *percpu_extras;
	struct device *dev = priv->net_dev->dev.parent;
	struct ldpaa_fas *fas;
	uint32_t status = 0;

	/* Tracing point */
	trace_ldpaa_rx_fd(priv->net_dev, fd);

	dma_unmap_single(dev, addr, LDPAA_ETH_RX_BUFFER_SIZE, DMA_FROM_DEVICE);
	vaddr = phys_to_virt(addr);

	prefetch(vaddr + priv->buf_layout.private_data_size);
	prefetch(vaddr + ldpaa_fd_get_offset(fd));

	percpu_stats = this_cpu_ptr(priv->percpu_stats);
	percpu_extras = this_cpu_ptr(priv->percpu_extras);

	if (fd_format == dpaa_fd_single) {
		skb = ldpaa_eth_build_linear_skb(priv, fd, vaddr);
	} else if (fd_format == dpaa_fd_sg) {
		struct dpaa_sg_entry *sgt =
				vaddr + ldpaa_fd_get_offset(fd);
		skb = ldpaa_eth_build_frag_skb(priv, sgt);
		put_page(virt_to_head_page(vaddr));
		percpu_extras->rx_sg_frames++;
		percpu_extras->rx_sg_bytes += ldpaa_fd_get_len(fd);
	} else {
		/* We don't support any other format */
		netdev_err(priv->net_dev, "Received invalid frame format\n");
		BUG();
	}

	if (unlikely(!skb)) {
		netdev_err(priv->net_dev, "error building skb\n");
		goto err_build_skb;
	}

	prefetch(skb->data);

	/* Check if we need to validate the L4 csum */
	if (likely(fd->simple.frc & LDPAA_FD_FRC_FASV)) {
		fas = (struct ldpaa_fas *)
				(vaddr + priv->buf_layout.private_data_size);
		status = le32_to_cpu(fas->status);
		ldpaa_eth_rx_csum(priv, status, skb);
	}

	skb->protocol = eth_type_trans(skb, priv->net_dev);

	percpu_stats->rx_packets++;
	percpu_stats->rx_bytes += skb->len;

	if (priv->net_dev->features & NETIF_F_GRO)
		napi_gro_receive(napi, skb);
	else
		netif_receive_skb(skb);

	return;

err_build_skb:
	ldpaa_eth_free_rx_fd(priv, fd, vaddr);
	percpu_stats->rx_dropped++;
}

#ifdef CONFIG_FSL_DPAA2_ETH_USE_ERR_QUEUE
static void ldpaa_eth_rx_err(struct ldpaa_eth_priv *priv,
			     const struct dpaa_fd *fd,
			     struct napi_struct *napi __always_unused)
{
	struct device *dev = priv->net_dev->dev.parent;
	dma_addr_t addr = ldpaa_fd_get_addr(fd);
	void *vaddr;
	struct rtnl_link_stats64 *percpu_stats;
	struct ldpaa_fas *fas;
	uint32_t status = 0;

	dma_unmap_single(dev, addr, LDPAA_ETH_RX_BUFFER_SIZE, DMA_FROM_DEVICE);
	vaddr = phys_to_virt(addr);

	if (fd->simple.frc & LDPAA_FD_FRC_FASV) {
		fas = (struct ldpaa_fas *)
			(vaddr + priv->buf_layout.private_data_size);
		status = le32_to_cpu(fas->status);

		/* All frames received on this queue should have at least
		 * one of the Rx error bits set */
		WARN_ON_ONCE((status & LDPAA_ETH_RX_ERR_MASK) == 0);
		netdev_dbg(priv->net_dev, "Rx frame error: 0x%08x\n",
			   status & LDPAA_ETH_RX_ERR_MASK);
	}
	ldpaa_eth_free_rx_fd(priv, fd, vaddr);

	percpu_stats = this_cpu_ptr(priv->percpu_stats);
	percpu_stats->rx_errors++;
}
#endif

/* Consume all frames pull-dequeued into the store. This is the simplest way to
 * make sure we don't accidentally issue another volatile dequeue which would
 * overwrite (leak) frames already in the store.
 *
 * Observance of NAPI budget is not our concern, leaving that to the caller.
 */
static int ldpaa_eth_store_consume(struct ldpaa_eth_channel *ch)
{
	struct ldpaa_eth_priv *priv = ch->priv;
	struct ldpaa_eth_fq *fq;
	struct ldpaa_dq *dq;
	const struct dpaa_fd *fd;
	int cleaned = 0;
	int is_last;

	do {
		dq = dpaa_io_store_next(ch->store, &is_last);
		if (unlikely(!dq)) {
			if (unlikely(!is_last)) {
				netdev_dbg(priv->net_dev,
					   "Channel %d reqturned no valid frames\n",
					   ch->ch_id);
				/* MUST retry until we get some sort of
				 * valid response token (be it "empty dequeue"
				 * or a valid frame).
				 */
				continue;
			}
			/* TODO add a ethtool counter for empty dequeues */
			break;
		}

		/* Obtain FD and process it */
		fd = ldpaa_dq_fd(dq);
		fq = (struct ldpaa_eth_fq *)ldpaa_dq_fqd_ctx(dq);
		fq->stats.frames++;
		fq->consume(priv, fd, &ch->napi);
		cleaned++;
	} while (!is_last);

	return cleaned;
}

static int ldpaa_eth_build_sg_fd(struct ldpaa_eth_priv *priv,
				 struct sk_buff *skb,
				 struct dpaa_fd *fd)
{
	struct device *dev = priv->net_dev->dev.parent;
	void *sgt_buf = NULL;
	dma_addr_t addr;
	int nr_frags = skb_shinfo(skb)->nr_frags;
	struct dpaa_sg_entry *sgt;
	int i, j, err;
	int sgt_buf_size;
	struct scatterlist *scl, *crt_scl;
	int num_sg;
	int num_dma_bufs;
	struct ldpaa_eth_swa *bps;

	/* Create and map scatterlist.
	 * We don't advertise NETIF_F_FRAGLIST, so skb_to_sgvec() will not have
	 * to go beyond nr_frags+1.
	 * TODO We don't support chained scatterlists; we could just fallback
	 * to the old implementation.
	 */
	WARN_ON(PAGE_SIZE / sizeof(struct scatterlist) < nr_frags + 1);
	scl = kcalloc(nr_frags + 1, sizeof(struct scatterlist), GFP_ATOMIC);
	if (unlikely(!scl))
		return -ENOMEM;

	sg_init_table(scl, nr_frags + 1);
	num_sg = skb_to_sgvec(skb, scl, 0, skb->len);
	num_dma_bufs = dma_map_sg(dev, scl, num_sg, DMA_TO_DEVICE);
	if (unlikely(!num_dma_bufs)) {
		netdev_err(priv->net_dev, "dma_map_sg() error\n");
		err = -ENOMEM;
		goto dma_map_sg_failed;
	}

	/* Prepare the HW SGT structure */
	sgt_buf_size = priv->tx_data_offset +
		       sizeof(struct dpaa_sg_entry) * (1 + num_dma_bufs);
	sgt_buf = kzalloc(sgt_buf_size + LDPAA_ETH_TX_BUF_ALIGN, GFP_ATOMIC);
	if (unlikely(!sgt_buf)) {
		netdev_err(priv->net_dev, "failed to allocate SGT buffer\n");
		err = -ENOMEM;
		goto sgt_buf_alloc_failed;
	}
	sgt_buf = PTR_ALIGN(sgt_buf, LDPAA_ETH_TX_BUF_ALIGN);

	/* PTA from egress side is passed as is to the confirmation side so
	 * we need to clear some fields here in order to find consistent values
	 * on TX confirmation. We are clearing FAS (Frame Annotation Status)
	 * field here.
	 */
	memset(sgt_buf + priv->buf_layout.private_data_size, 0, 8);

	sgt = (struct dpaa_sg_entry *)(sgt_buf + priv->tx_data_offset);

	/* Fill in the HW SGT structure.
	 *
	 * sgt_buf is zeroed out, so the following fields are implicit
	 * in all sgt entries:
	 *   - offset is 0
	 *   - format is 'dpaa_sg_single'
	 */
	for_each_sg(scl, crt_scl, num_dma_bufs, i) {
		ldpaa_sg_set_addr(&sgt[i], sg_dma_address(crt_scl));
		ldpaa_sg_set_len(&sgt[i], sg_dma_len(crt_scl));
	}
	ldpaa_sg_set_final(&sgt[i-1], true);

	/* Store the skb backpointer in the SGT buffer.
	 * Fit the scatterlist and the number of buffers alongside the
	 * skb backpointer in the SWA. We'll need all of them on Tx Conf.
	 */
	bps = (struct ldpaa_eth_swa *)sgt_buf;
	bps->skb = skb;
	bps->scl = scl;
	bps->num_sg = num_sg;
	bps->num_dma_bufs = num_dma_bufs;

	for (j = 0; j < i; j++)
		ldpaa_sg_cpu_to_le(&sgt[j]);

	/* Separately map the SGT buffer */
	addr = dma_map_single(dev, sgt_buf, sgt_buf_size, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, addr))) {
		netdev_err(priv->net_dev, "dma_map_single() failed\n");
		err = -ENOMEM;
		goto dma_map_single_failed;
	}
	ldpaa_fd_set_offset(fd, priv->tx_data_offset);
	ldpaa_fd_set_bpid(fd, priv->dpbp_attrs.bpid);
	ldpaa_fd_set_format(fd, dpaa_fd_sg);
	ldpaa_fd_set_addr(fd, addr);
	ldpaa_fd_set_len(fd, skb->len);

	fd->simple.ctrl = LDPAA_FD_CTRL_ASAL | LDPAA_FD_CTRL_PTA |
			 LDPAA_FD_CTRL_PTV1;

	return 0;

dma_map_single_failed:
	kfree(sgt_buf);
sgt_buf_alloc_failed:
	dma_unmap_sg(dev, scl, num_sg, DMA_TO_DEVICE);
dma_map_sg_failed:
	kfree(scl);
	return err;
}

static int ldpaa_eth_build_single_fd(struct ldpaa_eth_priv *priv,
				     struct sk_buff *skb,
				     struct dpaa_fd *fd)
{
	struct device *dev = priv->net_dev->dev.parent;
	uint8_t *buffer_start;
	struct sk_buff **skbh;
	dma_addr_t addr;

	buffer_start = PTR_ALIGN(skb->data - priv->tx_data_offset -
				 LDPAA_ETH_TX_BUF_ALIGN,
				 LDPAA_ETH_TX_BUF_ALIGN);

	/* PTA from egress side is passed as is to the confirmation side so
	 * we need to clear some fields here in order to find consistent values
	 * on TX confirmation. We are clearing FAS (Frame Annotation Status)
	 * field here.
	 */
	memset(buffer_start + priv->buf_layout.private_data_size, 0, 8);

	/* Store a backpointer to the skb at the beginning of the buffer
	 * (in the private data area) such that we can release it
	 * on Tx confirm
	 */
	skbh = (struct sk_buff **)buffer_start;
	*skbh = skb;

	addr = dma_map_single(dev,
			      buffer_start,
			      skb_tail_pointer(skb) - buffer_start,
			      DMA_TO_DEVICE);
	if (dma_mapping_error(dev, addr)) {
		dev_err(dev, "dma_map_single() failed\n");
		return -EINVAL;
	}

	ldpaa_fd_set_addr(fd, addr);
	ldpaa_fd_set_offset(fd, (uint16_t)(skb->data - buffer_start));
	ldpaa_fd_set_bpid(fd, priv->dpbp_attrs.bpid);
	ldpaa_fd_set_len(fd, skb->len);
	ldpaa_fd_set_format(fd, dpaa_fd_single);

	fd->simple.ctrl = LDPAA_FD_CTRL_ASAL | LDPAA_FD_CTRL_PTA |
			 LDPAA_FD_CTRL_PTV1;

	return 0;
}

/* DMA-unmap and free FD and possibly SGT buffer allocated on Tx. The skb
 * back-pointed to is also freed.
 * This can be called either from ldpaa_eth_tx_conf() or on the error path of
 * ldpaa_eth_tx().
 * Optionally, return the frame annotation status word (FAS), which needs
 * to be checked if we're on the confirmation path.
 */
static void ldpaa_eth_free_fd(const struct ldpaa_eth_priv *priv,
			       const struct dpaa_fd *fd,
			       uint32_t *status)
{
	struct device *dev = priv->net_dev->dev.parent;
	dma_addr_t fd_addr;
	struct sk_buff **skbh, *skb;
	unsigned char *buffer_start;
	int nr_frags, unmap_size;
	struct scatterlist *scl;
	int num_sg, num_dma_bufs;
	struct ldpaa_eth_swa *bps;
	bool fd_single;
	struct ldpaa_fas *fas;

	fd_addr = ldpaa_fd_get_addr(fd);
	skbh = phys_to_virt(fd_addr);
	fd_single = (ldpaa_fd_get_format(fd) == dpaa_fd_single);

	if (fd_single) {
		skb = *skbh;
		buffer_start = (unsigned char *)skbh;
		/* Accessing the skb buffer is safe before dma unmap, because
		 * we didn't map the actual skb shell.
		 */
		dma_unmap_single(dev, fd_addr,
				 skb_tail_pointer(skb) - buffer_start,
				 DMA_TO_DEVICE);
	} else {
		bps = (struct ldpaa_eth_swa *)skbh;
		skb = bps->skb;
		scl = bps->scl;
		num_sg = bps->num_sg;
		num_dma_bufs = bps->num_dma_bufs;

		/* Unmap the scatterlist */
		dma_unmap_sg(dev, scl, num_sg, DMA_TO_DEVICE);
		kfree(scl);

		/* Unmap the SGT buffer */
		nr_frags = skb_shinfo(skb)->nr_frags;
		unmap_size = priv->tx_data_offset +
		       sizeof(struct dpaa_sg_entry) * (1 + num_dma_bufs);
		dma_unmap_single(dev, fd_addr, unmap_size, DMA_TO_DEVICE);
	}

	/* Check the status from the Frame Annotation after we unmap the first
	 * buffer but before we free it.
	 */
	if (status && (fd->simple.frc & LDPAA_FD_FRC_FASV)) {
		fas = (struct ldpaa_fas *)
			((void *)skbh + priv->buf_layout.private_data_size);
		*status = le32_to_cpu(fas->status);
	}

	/* Free SGT buffer kmalloc'ed on tx */
	if (!fd_single)
		kfree(skbh);

	/* Move on with skb release */
	dev_kfree_skb(skb);
}

static int ldpaa_eth_tx(struct sk_buff *skb, struct net_device *net_dev)
{
	struct ldpaa_eth_priv *priv = netdev_priv(net_dev);
	struct dpaa_fd fd;
	struct rtnl_link_stats64 *percpu_stats;
	struct ldpaa_eth_stats *percpu_extras;
	int err, i;
	/* TxConf FQ selection primarily based on cpu affinity; this is
	 * non-migratable context, so it's safe to call smp_processor_id().
	 */
	int queue_mapping = smp_processor_id() % priv->dpni_attrs.max_senders;

	percpu_stats = this_cpu_ptr(priv->percpu_stats);
	percpu_extras = this_cpu_ptr(priv->percpu_extras);

	/* Setup the FD fields */
	memset(&fd, 0, sizeof(fd));

	if (unlikely(skb_headroom(skb) < LDPAA_ETH_NEEDED_HEADROOM(priv))) {
		struct sk_buff *ns;

		dev_info_once(net_dev->dev.parent,
			      "skb headroom too small, must realloc.\n");
		ns = skb_realloc_headroom(skb, LDPAA_ETH_NEEDED_HEADROOM(priv));
		if (unlikely(!ns)) {
			percpu_stats->tx_dropped++;
			goto err_alloc_headroom;
		}
		dev_kfree_skb(skb);
		skb = ns;
	}

	/* We'll be holding a back-reference to the skb until Tx Confirmation;
	 * we don't want that overwritten by a concurrent Tx with a cloned skb.
	 */
	skb = skb_unshare(skb, GFP_ATOMIC);
	if (unlikely(!skb)) {
		netdev_err(net_dev, "Out of memory for skb_unshare()");
		/* skb_unshare() has already freed the skb */
		percpu_stats->tx_dropped++;
		return NETDEV_TX_OK;
	}

	if (skb_is_nonlinear(skb)) {
		err = ldpaa_eth_build_sg_fd(priv, skb, &fd);
		percpu_extras->tx_sg_frames++;
		percpu_extras->tx_sg_bytes += skb->len;
	} else
		err = ldpaa_eth_build_single_fd(priv, skb, &fd);
	if (unlikely(err)) {
		percpu_stats->tx_dropped++;
		goto err_build_fd;
	}

	/* Tracing point */
	trace_ldpaa_tx_fd(net_dev, &fd);

	for (i = 0; i < (LDPAA_ETH_TX_QUEUES << 1); i++) {
		err = dpaa_io_service_enqueue_qd(NULL, priv->tx_qdid, 0,
						 priv->fq[queue_mapping].flowid,
						 &fd);
		if (err != -EBUSY)
			break;
	}
	percpu_extras->tx_portal_busy += i;
	if (unlikely(err < 0)) {
		netdev_dbg(net_dev, "error enqueueing Tx frame\n");
		percpu_stats->tx_errors++;
		/* Clean up everything, including freeing the skb */
		ldpaa_eth_free_fd(priv, &fd, NULL);
	} else {
		percpu_stats->tx_packets++;
		percpu_stats->tx_bytes += skb->len;
	}

	return NETDEV_TX_OK;

err_build_fd:
err_alloc_headroom:
	dev_kfree_skb(skb);

	return NETDEV_TX_OK;
}

static void ldpaa_eth_tx_conf(struct ldpaa_eth_priv *priv,
			      const struct dpaa_fd *fd,
			      struct napi_struct *napi __always_unused)
{
	struct rtnl_link_stats64 *percpu_stats;
	struct ldpaa_eth_stats *percpu_extras;
	uint32_t status = 0;

	/* Tracing point */
	trace_ldpaa_tx_conf_fd(priv->net_dev, fd);

	percpu_extras = this_cpu_ptr(priv->percpu_extras);
	percpu_extras->tx_conf_frames++;
	percpu_extras->tx_conf_bytes += ldpaa_fd_get_len(fd);

	ldpaa_eth_free_fd(priv, fd, &status);

	if (unlikely(status & LDPAA_ETH_TXCONF_ERR_MASK)) {
		netdev_err(priv->net_dev, "TxConf frame error(s): 0x%08x\n",
			   status & LDPAA_ETH_TXCONF_ERR_MASK);
		percpu_stats = this_cpu_ptr(priv->percpu_stats);
		/* Tx-conf logically pertains to the egress path. */
		percpu_stats->tx_errors++;
	}
}

static int ldpaa_eth_set_rx_csum(struct ldpaa_eth_priv *priv, bool enable)
{
	int err;

	err = dpni_set_l3_chksum_validation(priv->mc_io, 0, priv->mc_token,
					    enable);
	if (unlikely(err)) {
		netdev_err(priv->net_dev,
			   "dpni_set_l3_chksum_validation() failed\n");
		return err;
	}

	err = dpni_set_l4_chksum_validation(priv->mc_io, 0, priv->mc_token,
					    enable);
	if (unlikely(err)) {
		netdev_err(priv->net_dev,
			   "dpni_set_l4_chksum_validation failed\n");
		return err;
	}

	return 0;
}

static int ldpaa_eth_set_tx_csum(struct ldpaa_eth_priv *priv, bool enable)
{
	struct ldpaa_eth_fq *fq;
	struct dpni_tx_flow_cfg tx_flow_cfg;
	int err;
	int i;

	memset(&tx_flow_cfg, 0, sizeof(tx_flow_cfg));
	tx_flow_cfg.options = DPNI_TX_FLOW_OPT_L3_CHKSUM_GEN |
			      DPNI_TX_FLOW_OPT_L4_CHKSUM_GEN;
	tx_flow_cfg.l3_chksum_gen = enable;
	tx_flow_cfg.l4_chksum_gen = enable;

	for (i = 0; i < priv->num_fqs; i++) {
		fq = &priv->fq[i];
		if (fq->type != LDPAA_TX_CONF_FQ)
			continue;

		/* The Tx flowid is kept in the corresponding TxConf FQ. */
		err = dpni_set_tx_flow(priv->mc_io, 0, priv->mc_token,
				       &fq->flowid, &tx_flow_cfg);
		if (unlikely(err)) {
			netdev_err(priv->net_dev, "dpni_set_tx_flow failed\n");
			return err;
		}
	}

	return 0;
}

static inline int __ldpaa_eth_pull_channel(struct ldpaa_eth_channel *ch)
{
	int err;
	int dequeues = -1;
	struct ldpaa_eth_priv *priv = ch->priv;

	/* Retry while portal is busy */
	do {
		err = dpaa_io_service_pull_channel(NULL, ch->ch_id, ch->store);
		dequeues++;
	} while (err == -EBUSY);
	if (unlikely(err))
		netdev_err(priv->net_dev, "dpaa_io_service_pull err %d", err);

	ch->stats.dequeue_portal_busy += dequeues;
	return err;
}

static int ldpaa_eth_poll(struct napi_struct *napi, int budget)
{
	struct ldpaa_eth_channel *ch;
	int cleaned = 0, store_cleaned;
	struct ldpaa_eth_priv *priv;
	int err;

	ch = container_of(napi, struct ldpaa_eth_channel, napi);
	priv = ch->priv;

	__ldpaa_eth_pull_channel(ch);

	do {
		/* Refill pool if appropriate */
		ldpaa_dpbp_refill(priv, priv->dpbp_attrs.bpid);

		store_cleaned = ldpaa_eth_store_consume(ch);
		cleaned += store_cleaned;

		if (store_cleaned == 0 ||
		    cleaned > budget - LDPAA_ETH_STORE_SIZE)
			break;

		/* Try to dequeue some more */
		err = __ldpaa_eth_pull_channel(ch);
		if (unlikely(err))
			break;
	} while (1);

	if (cleaned < budget) {
		napi_complete_done(napi, cleaned);
		err = dpaa_io_service_rearm(NULL, &ch->nctx);
		if (unlikely(err))
			netdev_err(priv->net_dev,
				   "Notif rearm failed for channel %d\n",
				   ch->ch_id);
	}

	ch->stats.frames += cleaned;

	return cleaned;
}

static void ldpaa_eth_napi_enable(struct ldpaa_eth_priv *priv)
{
	struct ldpaa_eth_channel *ch;
	int i;

	for (i = 0; i < priv->num_channels; i++) {
		ch = priv->channel[i];
		napi_enable(&ch->napi);
	}
}

static void ldpaa_eth_napi_disable(struct ldpaa_eth_priv *priv)
{
	struct ldpaa_eth_channel *ch;
	int i;

	for (i = 0; i < priv->num_channels; i++) {
		ch = priv->channel[i];
		napi_disable(&ch->napi);
	}
}

static int ldpaa_link_state_update(struct ldpaa_eth_priv *priv)
{
	struct dpni_link_state state;
	int err;

	err = dpni_get_link_state(priv->mc_io, 0, priv->mc_token, &state);
	if (unlikely(err)) {
		netdev_err(priv->net_dev,
			   "dpni_get_link_state() failed\n");
		return err;
	}

	/* TODO: Speed / duplex changes are not treated yet */
	if (priv->link_state.up == state.up)
		return 0;

	priv->link_state = state;
	if (state.up) {
		netif_carrier_on(priv->net_dev);
		netif_tx_start_all_queues(priv->net_dev);
	} else {
		netif_tx_stop_all_queues(priv->net_dev);
		netif_carrier_off(priv->net_dev);
	}

	netdev_info(priv->net_dev, "Link Event: state %s",
		    state.up ? "up" : "down");

	return 0;
}

static int __cold ldpaa_eth_open(struct net_device *net_dev)
{
	struct ldpaa_eth_priv *priv = netdev_priv(net_dev);
	int err;

	err = ldpaa_dpbp_seed(priv, priv->dpbp_attrs.bpid);
	if (err) {
		/* Not much to do; the buffer pool, though not filled up,
		 * may still contain some buffers which would enable us
		 * to limp on.
		 */
		netdev_err(net_dev, "Buffer seeding failed for DPBP %d (bpid=%d)\n",
			   priv->dpbp_dev->obj_desc.id, priv->dpbp_attrs.bpid);
	}

	/* We'll only start the txqs when the link is actually ready; make sure
	 * we don't race against the link up notification, which may come
	 * immediately after dpni_enable();
	 */
	netif_tx_stop_all_queues(net_dev);
	ldpaa_eth_napi_enable(priv);
	/* Also, explicitly set carrier off, otherwise netif_carrier_ok() will
	 * return true and cause 'ip link show' to report the LOWER_UP flag,
	 * even though the link notification wasn't even received.
	 */
	netif_carrier_off(net_dev);

	err = dpni_enable(priv->mc_io, 0, priv->mc_token);
	if (err < 0) {
		dev_err(net_dev->dev.parent, "dpni_enable() failed\n");
		goto enable_err;
	}

	/* If the DPMAC object has already processed the link up interrupt,
	 * we have to learn the link state ourselves.
	 */
	err = ldpaa_link_state_update(priv);
	if (err < 0) {
		dev_err(net_dev->dev.parent, "Can't update link state\n");
		goto link_state_err;
	}

	return 0;

link_state_err:
enable_err:
	ldpaa_eth_napi_disable(priv);
	__ldpaa_dpbp_free(priv);
	return err;
}

static int __cold ldpaa_eth_stop(struct net_device *net_dev)
{
	struct ldpaa_eth_priv *priv = netdev_priv(net_dev);

	/* Stop Tx and Rx traffic */
	netif_tx_stop_all_queues(net_dev);
	netif_carrier_off(net_dev);
	dpni_disable(priv->mc_io, 0, priv->mc_token);

	/* TODO: Make sure queues are drained before if down is complete! */
	msleep(500);

	ldpaa_eth_napi_disable(priv);
	msleep(100);

	__ldpaa_dpbp_free(priv);

	return 0;
}

static int ldpaa_eth_init(struct net_device *net_dev)
{
	uint64_t supported = 0;
	uint64_t not_supported = 0;
	const struct ldpaa_eth_priv *priv = netdev_priv(net_dev);
	uint32_t options = priv->dpni_attrs.options;

	/* Capabilities listing */
	supported |= IFF_LIVE_ADDR_CHANGE | IFF_PROMISC | IFF_ALLMULTI;

	if (options & DPNI_OPT_UNICAST_FILTER)
		supported |= IFF_UNICAST_FLT;
	else
		not_supported |= IFF_UNICAST_FLT;

	if (options & DPNI_OPT_MULTICAST_FILTER)
		supported |= IFF_MULTICAST;
	else
		not_supported |= IFF_MULTICAST;

	net_dev->priv_flags |= supported;
	net_dev->priv_flags &= ~not_supported;

	/* Features */
	net_dev->features = NETIF_F_RXCSUM |
			    NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
			    NETIF_F_SG | NETIF_F_HIGHDMA |
			    NETIF_F_LLTX;
	net_dev->hw_features = net_dev->features;

	return 0;
}

static int ldpaa_eth_set_addr(struct net_device *net_dev, void *addr)
{
	struct ldpaa_eth_priv *priv = netdev_priv(net_dev);
	struct device *dev = net_dev->dev.parent;
	int err;

	err = eth_mac_addr(net_dev, addr);
	if (err < 0) {
		dev_err(dev, "eth_mac_addr() failed with error %d\n", err);
		return err;
	}

	err = dpni_set_primary_mac_addr(priv->mc_io, 0, priv->mc_token,
					net_dev->dev_addr);
	if (err) {
		dev_err(dev, "dpni_set_primary_mac_addr() failed (%d)\n", err);
		return err;
	}

	return 0;
}

/** Fill in counters maintained by the GPP driver. These may be different from
 * the hardware counters obtained by ethtool.
 */
static struct rtnl_link_stats64
*ldpaa_eth_get_stats(struct net_device *net_dev,
		     struct rtnl_link_stats64 *stats)
{
	struct ldpaa_eth_priv *priv = netdev_priv(net_dev);
	struct rtnl_link_stats64 *percpu_stats;
	u64 *cpustats;
	u64 *netstats = (u64 *)stats;
	int i, j;
	int num = sizeof(struct rtnl_link_stats64) / sizeof(u64);

	for_each_possible_cpu(i) {
		percpu_stats = per_cpu_ptr(priv->percpu_stats, i);
		cpustats = (u64 *)percpu_stats;
		for (j = 0; j < num; j++)
			netstats[j] += cpustats[j];
	}

	return stats;
}

static int ldpaa_eth_change_mtu(struct net_device *net_dev, int mtu)
{
	struct ldpaa_eth_priv *priv = netdev_priv(net_dev);
	int err;

	if (mtu < 68 || mtu > LDPAA_ETH_MAX_MTU) {
		netdev_err(net_dev, "Invalid MTU %d. Valid range is: 68..%d\n",
			   mtu, LDPAA_ETH_MAX_MTU);
		return -EINVAL;
	}

	/* Set the maximum Rx frame length to match the transmit side;
	 * account for L2 headers when computing the MFL
	 */
	err = dpni_set_max_frame_length(priv->mc_io, 0, priv->mc_token,
					(uint16_t)LDPAA_ETH_L2_MAX_FRM(mtu));
	if (err) {
		netdev_err(net_dev, "dpni_set_mfl() failed\n");
		return err;
	}

	net_dev->mtu = mtu;
	return 0;
}

/* Convenience macro to make code littered with error checking more readable */
#define LDPAA_ETH_WARN_IF_ERR(err, netdevp, format, ...) \
do { \
	if (unlikely(err)) \
		netdev_warn(netdevp, format, ##__VA_ARGS__); \
} while (0)

/* Copy mac unicast addresses from @net_dev to @priv.
 * Its sole purpose is to make ldpaa_eth_set_rx_mode() more readable.
 */
static inline void _ldpaa_eth_hw_add_uc_addr(const struct net_device *net_dev,
					     struct ldpaa_eth_priv *priv)
{
	struct netdev_hw_addr *ha;
	int err;

	netdev_for_each_uc_addr(ha, net_dev) {
		err = dpni_add_mac_addr(priv->mc_io, 0, priv->mc_token,
					ha->addr);
		LDPAA_ETH_WARN_IF_ERR(err, priv->net_dev,
				      "Could not add ucast MAC %pM to the filtering table (err %d)\n",
				      ha->addr, err);
	}
}

/* Copy mac multicast addresses from @net_dev to @priv
 * Its sole purpose is to make ldpaa_eth_set_rx_mode() more readable.
 */
static inline void _ldpaa_eth_hw_add_mc_addr(const struct net_device *net_dev,
					     struct ldpaa_eth_priv *priv)
{
	struct netdev_hw_addr *ha;
	int err;

	netdev_for_each_mc_addr(ha, net_dev) {
		err = dpni_add_mac_addr(priv->mc_io, 0, priv->mc_token,
					ha->addr);
		LDPAA_ETH_WARN_IF_ERR(err, priv->net_dev,
				      "Could not add mcast MAC %pM to the filtering table (err %d)\n",
				      ha->addr, err);
	}
}

static void ldpaa_eth_set_rx_mode(struct net_device *net_dev)
{
	struct ldpaa_eth_priv *priv = netdev_priv(net_dev);
	int uc_count = netdev_uc_count(net_dev);
	int mc_count = netdev_mc_count(net_dev);
	uint8_t max_uc = priv->dpni_attrs.max_unicast_filters;
	uint8_t max_mc = priv->dpni_attrs.max_multicast_filters;
	uint32_t options = priv->dpni_attrs.options;
	uint16_t mc_token = priv->mc_token;
	struct fsl_mc_io *mc_io = priv->mc_io;
	int err;

	/* Basic sanity checks; these probably indicate a misconfiguration */
	if (!(options & DPNI_OPT_UNICAST_FILTER) && max_uc != 0)
		netdev_info(net_dev,
			    "max_unicast_filters=%d, you must have DPNI_OPT_UNICAST_FILTER in the DPL\n",
			    max_uc);
	if (!(options & DPNI_OPT_MULTICAST_FILTER) && max_mc != 0)
		netdev_info(net_dev,
			    "max_multicast_filters=%d, you must have DPNI_OPT_MULTICAST_FILTER in the DPL\n",
			    max_mc);

	/* Force promiscuous if the uc or mc counts exceed our capabilities. */
	if (uc_count > max_uc) {
		netdev_info(net_dev,
			    "Unicast addr count reached %d, max allowed is %d; forcing promisc\n",
			    uc_count, max_uc);
		goto force_promisc;
	}
	if (mc_count > max_mc) {
		netdev_info(net_dev,
			    "Multicast addr count reached %d, max allowed is %d; forcing promisc\n",
			    mc_count, max_mc);
		goto force_mc_promisc;
	}

	/* Adjust promisc settings due to flag combinations */
	if (net_dev->flags & IFF_PROMISC) {
		goto force_promisc;
	} else if (net_dev->flags & IFF_ALLMULTI) {
		/* First, rebuild unicast filtering table. This should be done
		 * in promisc mode, in order to avoid frame loss while we
		 * progressively add entries to the table.
		 * We don't know whether we had been in promisc already, and
		 * making an MC call to find it is expensive; so set uc promisc
		 * nonetheless.
		 */
		err = dpni_set_unicast_promisc(mc_io, 0, mc_token, 1);
		LDPAA_ETH_WARN_IF_ERR(err, net_dev, "Can't set uc promisc\n");

		/* Actual uc table reconstruction. */
		err = dpni_clear_mac_filters(mc_io, 0, mc_token, 1, 0);
		LDPAA_ETH_WARN_IF_ERR(err, net_dev, "Can't clear uc filters\n");
		_ldpaa_eth_hw_add_uc_addr(net_dev, priv);

		/* Finally, clear uc promisc and set mc promisc as requested. */
		err = dpni_set_unicast_promisc(mc_io, 0, mc_token, 0);
		LDPAA_ETH_WARN_IF_ERR(err, net_dev, "Can't clear uc promisc\n");
		goto force_mc_promisc;
	}

	/* Neither unicast, nor multicast promisc will be on... eventually.
	 * For now, rebuild mac filtering tables while forcing both of them on.
	 */
	err = dpni_set_unicast_promisc(mc_io, 0, mc_token, 1);
	LDPAA_ETH_WARN_IF_ERR(err, net_dev, "Can't set uc promisc (%d)\n", err);
	err = dpni_set_multicast_promisc(mc_io, 0, mc_token, 1);
	LDPAA_ETH_WARN_IF_ERR(err, net_dev, "Can't set mc promisc (%d)\n", err);

	/* Actual mac filtering tables reconstruction */
	err = dpni_clear_mac_filters(mc_io, 0, mc_token, 1, 1);
	LDPAA_ETH_WARN_IF_ERR(err, net_dev, "Can't clear mac filters\n");
	_ldpaa_eth_hw_add_mc_addr(net_dev, priv);
	_ldpaa_eth_hw_add_uc_addr(net_dev, priv);

	/* Now we can clear both ucast and mcast promisc, without risking
	 * to drop legitimate frames anymore.
	 */
	err = dpni_set_unicast_promisc(mc_io, 0, mc_token, 0);
	LDPAA_ETH_WARN_IF_ERR(err, net_dev, "Can't clear ucast promisc\n");
	err = dpni_set_multicast_promisc(mc_io, 0, mc_token, 0);
	LDPAA_ETH_WARN_IF_ERR(err, net_dev, "Can't clear mcast promisc\n");

	return;

force_promisc:
	err = dpni_set_unicast_promisc(mc_io, 0, mc_token, 1);
	LDPAA_ETH_WARN_IF_ERR(err, net_dev, "Can't set ucast promisc\n");
force_mc_promisc:
	err = dpni_set_multicast_promisc(mc_io, 0, mc_token, 1);
	LDPAA_ETH_WARN_IF_ERR(err, net_dev, "Can't set mcast promisc\n");
}

static int ldpaa_eth_set_features(struct net_device *net_dev,
				  netdev_features_t features)
{
	struct ldpaa_eth_priv *priv = netdev_priv(net_dev);
	netdev_features_t changed = features ^ net_dev->features;
	int err;

	if (changed & NETIF_F_RXCSUM) {
		bool enable = !!(features & NETIF_F_RXCSUM);

		err = ldpaa_eth_set_rx_csum(priv, enable);
		if (unlikely(err))
			return err;
	}

	if (changed & (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM)) {
		bool enable = !!(features &
				 (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM));
		err = ldpaa_eth_set_tx_csum(priv, enable);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static const struct net_device_ops ldpaa_eth_ops = {
	.ndo_open = ldpaa_eth_open,
	.ndo_start_xmit = ldpaa_eth_tx,
	.ndo_stop = ldpaa_eth_stop,
	.ndo_init = ldpaa_eth_init,
	.ndo_set_mac_address = ldpaa_eth_set_addr,
	.ndo_get_stats64 = ldpaa_eth_get_stats,
	.ndo_change_mtu = ldpaa_eth_change_mtu,
	.ndo_set_rx_mode = ldpaa_eth_set_rx_mode,
	.ndo_set_features = ldpaa_eth_set_features,
};

static void ldpaa_eth_cdan_cb(struct dpaa_io_notification_ctx *ctx)
{
	struct ldpaa_eth_channel *ch;

	ch = container_of(ctx, struct ldpaa_eth_channel, nctx);

	/* Update NAPI statistics */
	ch->stats.cdan++;

	napi_schedule_irqoff(&ch->napi);
}

static void ldpaa_eth_setup_fqs(struct ldpaa_eth_priv *priv)
{
	int i;

	/* We have one TxConf FQ per Tx flow */
	for (i = 0; i < priv->dpni_attrs.max_senders; i++) {
		priv->fq[priv->num_fqs].netdev_priv = priv;
		priv->fq[priv->num_fqs].type = LDPAA_TX_CONF_FQ;
		priv->fq[priv->num_fqs].consume = ldpaa_eth_tx_conf;
		priv->fq[priv->num_fqs++].flowid = DPNI_NEW_FLOW_ID;
	}

	/* The number of Rx queues (Rx distribution width) may be different from
	 * the number of cores.
	 *
	 * TODO: We still only have one traffic class for now,
	 * but for multiple TCs may need an array of dist sizes.
	 */
	for (i = 0; i < ldpaa_queue_count(priv); i++) {
		priv->fq[priv->num_fqs].netdev_priv = priv;
		priv->fq[priv->num_fqs].type = LDPAA_RX_FQ;
		priv->fq[priv->num_fqs].consume = ldpaa_eth_rx;
		priv->fq[priv->num_fqs++].flowid = (uint16_t)i;
	}

#ifdef CONFIG_FSL_DPAA2_ETH_USE_ERR_QUEUE
	/* We have exactly one Rx error queue per DPNI */
	priv->fq[priv->num_fqs].netdev_priv = priv;
	priv->fq[priv->num_fqs].type = LDPAA_RX_ERR_FQ;
	priv->fq[priv->num_fqs++].consume = ldpaa_eth_rx_err;
#endif
}

static struct fsl_mc_device *ldpaa_dpcon_setup(struct ldpaa_eth_priv *priv)
{
	struct fsl_mc_device *dpcon;
	struct device *dev = priv->net_dev->dev.parent;
	int err;

	err = fsl_mc_object_allocate(to_fsl_mc_device(dev),
				     FSL_MC_POOL_DPCON, &dpcon);
	if (unlikely(err)) {
		dev_err(dev, "DPCON allocation failed\n");
		return NULL;
	}

	err = dpcon_open(priv->mc_io, 0, dpcon->obj_desc.id, &dpcon->mc_handle);
	if (unlikely(err)) {
		dev_err(dev, "dpcon_open() failed\n");
		goto err_open;
	}

	err = dpcon_enable(priv->mc_io, 0, dpcon->mc_handle);
	if (unlikely(err)) {
		dev_err(dev, "dpcon_enable() failed\n");
		goto err_enable;
	}

	return dpcon;

err_enable:
	dpcon_close(priv->mc_io, 0, dpcon->mc_handle);
err_open:
	fsl_mc_object_free(dpcon);

	return NULL;
}

static void __cold ldpaa_dpcon_free(struct ldpaa_eth_priv *priv,
				    struct fsl_mc_device *dpcon)
{
	dpcon_disable(priv->mc_io, 0, dpcon->mc_handle);
	dpcon_close(priv->mc_io, 0, dpcon->mc_handle);
	fsl_mc_object_free(dpcon);
}

static struct ldpaa_eth_channel *
ldpaa_alloc_channel(struct ldpaa_eth_priv *priv, int cpu)
{
	struct ldpaa_eth_channel *channel;
	struct dpcon_attr attr;
	struct device *dev = priv->net_dev->dev.parent;
	int err;

	channel = kzalloc(sizeof(struct ldpaa_eth_channel), GFP_ATOMIC);
	if (unlikely(!channel)) {
		dev_err(dev, "Memory allocation failed\n");
		return NULL;
	}

	channel->dpcon = ldpaa_dpcon_setup(priv);
	if (unlikely(!channel->dpcon))
		goto err_setup;

	err = dpcon_get_attributes(priv->mc_io, 0, channel->dpcon->mc_handle,
				   &attr);
	if (unlikely(err)) {
		dev_err(dev, "dpcon_get_attributes() failed\n");
		goto err_get_attr;
	}

	channel->dpcon_id = attr.id;
	channel->ch_id = attr.qbman_ch_id;
	channel->priv = priv;

	return channel;

err_get_attr:
	ldpaa_dpcon_free(priv, channel->dpcon);
err_setup:
	kfree(channel);
	return NULL;
}

static void ldpaa_free_channel(struct ldpaa_eth_priv *priv,
			       struct ldpaa_eth_channel *channel)
{
	ldpaa_dpcon_free(priv, channel->dpcon);
	kfree(channel);
}

static int __cold ldpaa_dpio_setup(struct ldpaa_eth_priv *priv)
{
	struct dpaa_io_notification_ctx *nctx;
	struct ldpaa_eth_channel *channel;
	struct dpcon_notification_cfg dpcon_notif_cfg;
	struct device *dev = priv->net_dev->dev.parent;
	int i, err;

	/* Don't allocate more channels than strictly necessary and assign
	 * them to cores starting from the first one available in
	 * cpu_online_mask.
	 * If the number of channels is lower than the number of cores,
	 * there will be no rx/tx conf processing on the last cores in the mask.
	 */
	cpumask_clear(&priv->dpio_cpumask);
	for_each_online_cpu(i) {
		/* Try to allocate a channel */
		channel = ldpaa_alloc_channel(priv, i);
		if (unlikely(!channel))
			goto err_alloc_ch;

		priv->channel[priv->num_channels] = channel;

		nctx = &channel->nctx;
		nctx->is_cdan = 1;
		nctx->cb = ldpaa_eth_cdan_cb;
		nctx->id = channel->ch_id;
		nctx->desired_cpu = i;

		/* Register the new context */
		err = dpaa_io_service_register(NULL, nctx);
		if (unlikely(err)) {
			dev_info(dev, "No affine DPIO for core %d\n", i);
			/* This core doesn't have an affine DPIO, but there's
			 * a chance another one does, so keep trying
			 */
			ldpaa_free_channel(priv, channel);
			continue;
		}

		/* Register DPCON notification with MC */
		dpcon_notif_cfg.dpio_id = nctx->dpio_id;
		dpcon_notif_cfg.priority = 0;
		dpcon_notif_cfg.user_ctx = nctx->qman64;
		err = dpcon_set_notification(priv->mc_io, 0,
					     channel->dpcon->mc_handle,
					     &dpcon_notif_cfg);
		if (unlikely(err)) {
			dev_err(dev, "dpcon_set_notification failed()\n");
			goto err_set_cdan;
		}

		/* If we managed to allocate a channel and also found an affine
		 * DPIO for this core, add it to the final mask
		 */
		cpumask_set_cpu(i, &priv->dpio_cpumask);
		priv->num_channels++;

		if (priv->num_channels == ldpaa_max_channels(priv))
			break;
	}

	/* Tx confirmation queues can only be serviced by cpus
	 * with an affine DPIO/channel
	 */
	cpumask_copy(&priv->txconf_cpumask, &priv->dpio_cpumask);

	return 0;

err_set_cdan:
	dpaa_io_service_deregister(NULL, nctx);
	ldpaa_free_channel(priv, channel);
err_alloc_ch:
	if (unlikely(cpumask_empty(&priv->dpio_cpumask))) {
		dev_err(dev, "No cpu with an affine DPIO/DPCON\n");
		return -ENODEV;
	}
	cpumask_copy(&priv->txconf_cpumask, &priv->dpio_cpumask);

	return 0;
}

static void __cold ldpaa_dpio_free(struct ldpaa_eth_priv *priv)
{
	int i;
	struct ldpaa_eth_channel *ch;

	/* deregister CDAN notifications and free channels */
	for (i = 0; i < priv->num_channels; i++) {
		ch = priv->channel[i];
		dpaa_io_service_deregister(NULL, &ch->nctx);
		ldpaa_free_channel(priv, ch);
	}
}

static struct ldpaa_eth_channel *
ldpaa_get_channel_by_cpu(struct ldpaa_eth_priv *priv, int cpu)
{
	struct device *dev = priv->net_dev->dev.parent;
	int i;

	for (i = 0; i < priv->num_channels; i++)
		if (priv->channel[i]->nctx.desired_cpu == cpu)
			return priv->channel[i];

	/* We should never get here. Issue a warning and return
	 * the first channel, because it's still better than nothing
	 */
	dev_warn(dev, "No affine channel found for cpu %d\n", cpu);

	return priv->channel[0];
}

static void ldpaa_set_fq_affinity(struct ldpaa_eth_priv *priv)
{
	struct ldpaa_eth_fq *fq;
	int rx_cpu, txconf_cpu;
	int i;

	/* For each FQ, pick one channel/CPU to deliver frames to.
	 * This may well change at runtime, either through irqbalance or
	 * through direct user intervention.
	 */
	rx_cpu = cpumask_first(&priv->dpio_cpumask);
	txconf_cpu = cpumask_first(&priv->txconf_cpumask);

	for (i = 0; i < priv->num_fqs; i++) {
		fq = &priv->fq[i];
		switch (fq->type) {
		case LDPAA_RX_FQ:
		case LDPAA_RX_ERR_FQ:
			fq->target_cpu = rx_cpu;
			cpumask_rr(rx_cpu, &priv->dpio_cpumask);
			break;
		case LDPAA_TX_CONF_FQ:
			fq->target_cpu = txconf_cpu;
			cpumask_rr(txconf_cpu, &priv->txconf_cpumask);
			break;
		default:
			netdev_err(priv->net_dev, "Unknown FQ type: %d\n",
				   fq->type);
		}
		fq->channel = ldpaa_get_channel_by_cpu(priv, fq->target_cpu);
	}
}

static void ldpaa_dpbp_drain_cnt(struct ldpaa_eth_priv *priv, int count)
{
	struct device *dev = priv->net_dev->dev.parent;
	uint64_t buf_array[7];
	void *vaddr;
	int ret, i;

	BUG_ON(count > 7);

	do {
		ret = dpaa_io_service_acquire(NULL, priv->dpbp_attrs.bpid,
					      buf_array, count);
		if (ret < 0) {
			pr_err("dpaa_io_service_acquire() failed\n");
			return;
		}
		for (i = 0; i < ret; i++) {
			/* Same logic as on regular Rx path */
			dma_unmap_single(dev, buf_array[i],
					 LDPAA_ETH_RX_BUFFER_SIZE,
					 DMA_FROM_DEVICE);
			vaddr = phys_to_virt(buf_array[i]);
			put_page(virt_to_head_page(vaddr));
		}
	} while (ret);
}

static void ldpaa_dpbp_drain(struct ldpaa_eth_priv *priv)
{
	ldpaa_dpbp_drain_cnt(priv, 7);
	ldpaa_dpbp_drain_cnt(priv, 1);
}

static int ldpaa_bp_add_7(struct ldpaa_eth_priv *priv, uint16_t bpid)
{
	struct device *dev = priv->net_dev->dev.parent;
	uint64_t buf_array[7];
	void *buf;
	dma_addr_t addr;
	int i;

	for (i = 0; i < 7; i++) {
		/* Allocate buffer visible to WRIOP + skb shared info +
		 * alignment padding
		 */
		buf = napi_alloc_frag(LDPAA_ETH_BUF_RAW_SIZE);
		if (unlikely(!buf)) {
			dev_err(dev, "buffer allocation failed\n");
			goto err_alloc;
		}
		buf = PTR_ALIGN(buf, LDPAA_ETH_RX_BUF_ALIGN);

		addr = dma_map_single(dev, buf, LDPAA_ETH_RX_BUFFER_SIZE,
				      DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, addr)) {
			dev_err(dev, "dma_map_single() failed\n");
			goto err_map;
		}
		buf_array[i] = addr;

		/* tracing point */
		trace_ldpaa_eth_buf_seed(priv->net_dev,
					 buf, LDPAA_ETH_BUF_RAW_SIZE,
					 addr, LDPAA_ETH_RX_BUFFER_SIZE,
					 bpid);
	}

release_bufs:
	/* In case the portal is busy, retry until successful.
	 * This function is guaranteed to succeed in a reasonable amount
	 * of time.
	 */
	while (dpaa_io_service_release(NULL, bpid, buf_array, i))
		cpu_relax();
	return i;

err_map:
	put_page(virt_to_head_page(buf));
err_alloc:
	if (i)
		goto release_bufs;

	return 0;
}

static int ldpaa_dpbp_seed(struct ldpaa_eth_priv *priv, uint16_t bpid)
{
	int i, j;
	int new_count;
	int *count;

	/* This is the lazy seeding of Rx buffer pools.
	 * ldpaa_bp_add_7() is also used on the Rx hotpath and calls
	 * napi_alloc_frag(). The trouble with that is that it in turn ends up
	 * calling this_cpu_ptr(), which mandates execution in atomic context.
	 * Rather than splitting up the code, do a one-off preempt disable.
	 */
	preempt_disable();
	for_each_possible_cpu(j) {
		for (i = 0; i < LDPAA_ETH_NUM_BUFS; i += 7) {
			new_count = ldpaa_bp_add_7(priv, bpid);
			count = per_cpu_ptr(priv->buf_count, j);
			*count += new_count;

			if (unlikely(new_count < 7)) {
				preempt_enable();
				goto out_of_memory;
			}
		}
	}
	preempt_enable();

	return 0;

out_of_memory:
	return -ENOMEM;
}

/* Function is called from softirq context only, so we don't need to guard
 * the access to percpu count
 */
static int ldpaa_dpbp_refill(struct ldpaa_eth_priv *priv, uint16_t bpid)
{
	int new_count;
	int err = 0;
	int *count = this_cpu_ptr(priv->buf_count);

	if (unlikely(*count < LDPAA_ETH_REFILL_THRESH)) {
		do {
			new_count = ldpaa_bp_add_7(priv, bpid);
			if (unlikely(!new_count)) {
				/* Out of memory; abort for now, we'll
				 * try later on
				 */
				break;
			}
			*count += new_count;
		} while (*count < LDPAA_ETH_NUM_BUFS);

		if (unlikely(*count < LDPAA_ETH_NUM_BUFS))
			err = -ENOMEM;
	}

	return err;
}

static int __cold ldpaa_dpbp_setup(struct ldpaa_eth_priv *priv)
{
	int err;
	struct fsl_mc_device *dpbp_dev;
	struct device *dev = priv->net_dev->dev.parent;

	err = fsl_mc_object_allocate(to_fsl_mc_device(dev), FSL_MC_POOL_DPBP,
				     &dpbp_dev);
	if (err) {
		dev_err(dev, "DPBP device allocation failed\n");
		return err;
	}

	priv->dpbp_dev = dpbp_dev;

	err = dpbp_open(priv->mc_io, 0, priv->dpbp_dev->obj_desc.id,
			&dpbp_dev->mc_handle);
	if (err) {
		dev_err(dev, "dpbp_open() failed\n");
		goto err_open;
	}

	err = dpbp_enable(priv->mc_io, 0, dpbp_dev->mc_handle);
	if (err) {
		dev_err(dev, "dpbp_enable() failed\n");
		goto err_enable;
	}

	err = dpbp_get_attributes(priv->mc_io, 0, dpbp_dev->mc_handle,
				  &priv->dpbp_attrs);
	if (err) {
		dev_err(dev, "dpbp_get_attributes() failed\n");
		goto err_get_attr;
	}

	return 0;

err_get_attr:
	dpbp_disable(priv->mc_io, 0, dpbp_dev->mc_handle);
err_enable:
	dpbp_close(priv->mc_io, 0, dpbp_dev->mc_handle);
err_open:
	fsl_mc_object_free(dpbp_dev);

	return err;
}


static void __cold __ldpaa_dpbp_free(struct ldpaa_eth_priv *priv)
{
	int cpu, *count;

	ldpaa_dpbp_drain(priv);

	for_each_possible_cpu(cpu) {
		count = per_cpu_ptr(priv->buf_count, cpu);
		*count = 0;
	}
}

static void __cold ldpaa_dpbp_free(struct ldpaa_eth_priv *priv)
{
	__ldpaa_dpbp_free(priv);
	dpbp_disable(priv->mc_io, 0, priv->dpbp_dev->mc_handle);
	dpbp_close(priv->mc_io, 0, priv->dpbp_dev->mc_handle);
	fsl_mc_object_free(priv->dpbp_dev);
}

static int __cold ldpaa_dpni_setup(struct fsl_mc_device *ls_dev)
{
	struct device *dev = &ls_dev->dev;
	struct ldpaa_eth_priv *priv;
	struct net_device *net_dev;
	int err;

	net_dev = dev_get_drvdata(dev);
	priv = netdev_priv(net_dev);

	priv->dpni_id = ls_dev->obj_desc.id;

	/* and get a handle for the DPNI this interface is associate with */
	err = dpni_open(priv->mc_io, 0, priv->dpni_id, &priv->mc_token);
	if (err) {
		dev_err(dev, "dpni_open() failed\n");
		goto err_open;
	}

	/* FIXME Alex's moral compass says this must be done */
	ls_dev->mc_io = priv->mc_io;
	ls_dev->mc_handle = priv->mc_token;
	err = dpni_get_attributes(priv->mc_io, 0, priv->mc_token,
				  &priv->dpni_attrs);
	if (err) {
		dev_err(dev, "dpni_get_attributes() failed (err=%d)\n", err);
		goto err_get_attr;
	}

	/* Configure our buffers' layout */
	priv->buf_layout.options = DPNI_BUF_LAYOUT_OPT_PARSER_RESULT |
				   DPNI_BUF_LAYOUT_OPT_FRAME_STATUS |
				   DPNI_BUF_LAYOUT_OPT_PRIVATE_DATA_SIZE |
				   DPNI_BUF_LAYOUT_OPT_DATA_ALIGN;
	priv->buf_layout.pass_parser_result = true;
	priv->buf_layout.pass_frame_status = true;
	priv->buf_layout.private_data_size = LDPAA_ETH_SWA_SIZE;
	/* HW erratum mandates data alignment in multiples of 256 */
	priv->buf_layout.data_align = LDPAA_ETH_RX_BUF_ALIGN;
	/* ...rx, ... */
	err = dpni_set_rx_buffer_layout(priv->mc_io, 0, priv->mc_token,
					&priv->buf_layout);
	if (err) {
		dev_err(dev, "dpni_set_rx_buffer_layout() failed");
		goto err_buf_layout;
	}
	/* ... tx, ... */
	/* remove Rx-only options */
	priv->buf_layout.options &= ~(DPNI_BUF_LAYOUT_OPT_DATA_ALIGN |
				      DPNI_BUF_LAYOUT_OPT_PARSER_RESULT);
	err = dpni_set_tx_buffer_layout(priv->mc_io, 0, priv->mc_token,
					&priv->buf_layout);
	if (err) {
		dev_err(dev, "dpni_set_tx_buffer_layout() failed");
		goto err_buf_layout;
	}
	/* ... tx-confirm. */
	priv->buf_layout.options &= ~DPNI_BUF_LAYOUT_OPT_PRIVATE_DATA_SIZE;
	err = dpni_set_tx_conf_buffer_layout(priv->mc_io, 0, priv->mc_token,
					     &priv->buf_layout);
	if (err) {
		dev_err(dev, "dpni_set_tx_conf_buffer_layout() failed");
		goto err_buf_layout;
	}
	/* Now that we've set our tx buffer layout, retrieve the minimum
	 * required tx data offset.
	 */
	err = dpni_get_tx_data_offset(priv->mc_io, 0, priv->mc_token,
				      &priv->tx_data_offset);
	if (err) {
		dev_err(dev, "dpni_get_tx_data_offset() failed\n");
		goto err_data_offset;
	}

	/* Warn in case TX data offset is not multiple of 64 bytes. */
	WARN_ON(priv->tx_data_offset % 64);

	/* Accommodate SWA space. */
	priv->tx_data_offset += LDPAA_ETH_SWA_SIZE;

	/* allocate classification rule space */
	priv->cls_rule = kzalloc(sizeof(struct ldpaa_cls_rule)
				 * LDPAA_CLASSIFIER_ENTRY_COUNT, GFP_KERNEL);
	if (!priv->cls_rule)
		return -ENOMEM;

	return 0;

err_data_offset:
err_buf_layout:
err_get_attr:
	dpni_close(priv->mc_io, 0, priv->mc_token);
err_open:
	return err;
}

static void ldpaa_dpni_free(struct ldpaa_eth_priv *priv)
{
	int err;

	err = dpni_reset(priv->mc_io, 0, priv->mc_token);
	if (unlikely(err))
		netdev_warn(priv->net_dev, "dpni_reset() failed (err %d)\n",
			    err);

	dpni_close(priv->mc_io, 0, priv->mc_token);
}

static int ldpaa_rx_flow_setup(struct ldpaa_eth_priv *priv,
			       struct ldpaa_eth_fq *fq)
{
	struct dpni_queue_attr rx_queue_attr;
	struct dpni_queue_cfg queue_cfg;
	int err;

	memset(&queue_cfg, 0, sizeof(queue_cfg));
	queue_cfg.options = DPNI_QUEUE_OPT_USER_CTX | DPNI_QUEUE_OPT_DEST;
	queue_cfg.dest_cfg.dest_type = DPNI_DEST_DPCON;
	queue_cfg.dest_cfg.priority = 1;
	queue_cfg.user_ctx = (uint64_t)fq;
	queue_cfg.dest_cfg.dest_id = fq->channel->dpcon_id;
	err = dpni_set_rx_flow(priv->mc_io, 0, priv->mc_token, 0, fq->flowid,
			       &queue_cfg);
	if (unlikely(err)) {
		netdev_err(priv->net_dev, "dpni_set_rx_flow() failed\n");
		return err;
	}

	/* Get the actual FQID that was assigned by MC */
	err = dpni_get_rx_flow(priv->mc_io, 0, priv->mc_token, 0, fq->flowid,
			       &rx_queue_attr);
	if (unlikely(err)) {
		netdev_err(priv->net_dev, "dpni_get_rx_flow() failed\n");
		return err;
	}
	fq->fqid = rx_queue_attr.fqid;

	return 0;
}

static int ldpaa_tx_flow_setup(struct ldpaa_eth_priv *priv,
			       struct ldpaa_eth_fq *fq)
{
	struct dpni_tx_flow_cfg tx_flow_cfg;
	struct dpni_queue_cfg queue_cfg;
	struct dpni_tx_flow_attr tx_flow_attr;
	int err;

	memset(&tx_flow_cfg, 0, sizeof(tx_flow_cfg));
	tx_flow_cfg.options = DPNI_TX_FLOW_OPT_QUEUE;
	queue_cfg.options = DPNI_QUEUE_OPT_USER_CTX | DPNI_QUEUE_OPT_DEST;
	queue_cfg.user_ctx = (uint64_t)fq;
	queue_cfg.dest_cfg.dest_type = DPNI_DEST_DPCON;
	queue_cfg.dest_cfg.dest_id = fq->channel->dpcon_id;
	queue_cfg.dest_cfg.priority = 0;
	tx_flow_cfg.conf_err_cfg.queue_cfg = queue_cfg;
	err = dpni_set_tx_flow(priv->mc_io, 0, priv->mc_token,
			       &fq->flowid, &tx_flow_cfg);
	if (unlikely(err)) {
		netdev_err(priv->net_dev, "dpni_set_tx_flow() failed\n");
		return err;
	}

	err = dpni_get_tx_flow(priv->mc_io, 0, priv->mc_token,
			       fq->flowid, &tx_flow_attr);
	if (unlikely(err)) {
		netdev_err(priv->net_dev, "dpni_get_tx_flow() failed\n");
		return err;
	}
	fq->fqid = tx_flow_attr.conf_err_attr.queue_attr.fqid;

	return 0;
}

#ifdef CONFIG_FSL_DPAA2_ETH_USE_ERR_QUEUE
static int ldpaa_rx_err_setup(struct ldpaa_eth_priv *priv,
			      struct ldpaa_eth_fq *fq)
{
	struct dpni_queue_attr queue_attr;
	struct dpni_queue_cfg queue_cfg;
	int err;

	/* Configure the Rx error queue to generate CDANs,
	 * just like the Rx queues */
	queue_cfg.options = DPNI_QUEUE_OPT_USER_CTX | DPNI_QUEUE_OPT_DEST;
	queue_cfg.dest_cfg.dest_type = DPNI_DEST_DPCON;
	queue_cfg.dest_cfg.priority = 1;
	queue_cfg.user_ctx = (uint64_t)fq;
	queue_cfg.dest_cfg.dest_id = fq->channel->dpcon_id;
	err = dpni_set_rx_err_queue(priv->mc_io, 0, priv->mc_token, &queue_cfg);
	if (unlikely(err)) {
		netdev_err(priv->net_dev, "dpni_set_rx_err_queue() failed\n");
		return err;
	}

	/* Get the FQID */
	err = dpni_get_rx_err_queue(priv->mc_io, 0, priv->mc_token, &queue_attr);
	if (unlikely(err)) {
		netdev_err(priv->net_dev, "dpni_get_rx_err_queue() failed\n");
		return err;
	}
	fq->fqid = queue_attr.fqid;

	return 0;
}
#endif

static int ldpaa_dpni_bind(struct ldpaa_eth_priv *priv)
{
	struct net_device *net_dev = priv->net_dev;
	struct device *dev = net_dev->dev.parent;
	struct dpni_pools_cfg pools_params;
	struct dpni_error_cfg err_cfg;
	int err = 0;
	int i;

	pools_params.num_dpbp = 1;
	pools_params.pools[0].dpbp_id = priv->dpbp_dev->obj_desc.id;
	pools_params.pools[0].backup_pool = 0;
	pools_params.pools[0].buffer_size = LDPAA_ETH_RX_BUFFER_SIZE;
	err = dpni_set_pools(priv->mc_io, 0, priv->mc_token, &pools_params);
	if (unlikely(err)) {
		dev_err(dev, "dpni_set_pools() failed\n");
		return err;
	}

	ldpaa_cls_check(net_dev);

	/* have the interface implicitly distribute traffic based on supported
	 * header fields
	 */
	if (ldpaa_eth_hash_enabled(priv)) {
		err = ldpaa_set_hash(net_dev, LDPAA_RXH_SUPPORTED);
		if (unlikely(err))
			return err;
	}

	/* Configure handling of error frames */
	err_cfg.errors = LDPAA_ETH_RX_ERR_MASK;
	err_cfg.set_frame_annotation = 1;
#ifdef CONFIG_FSL_DPAA2_ETH_USE_ERR_QUEUE
	err_cfg.error_action = DPNI_ERROR_ACTION_SEND_TO_ERROR_QUEUE;
#else
	err_cfg.error_action = DPNI_ERROR_ACTION_DISCARD;
#endif
	err = dpni_set_errors_behavior(priv->mc_io, 0, priv->mc_token,
				       &err_cfg);
	if (unlikely(err)) {
		netdev_err(priv->net_dev, "dpni_set_errors_behavior failed\n");
		return err;
	}

	/* Configure Rx and Tx conf queues to generate CDANs */
	for (i = 0; i < priv->num_fqs; i++) {
		switch (priv->fq[i].type) {
		case LDPAA_RX_FQ:
			err = ldpaa_rx_flow_setup(priv, &priv->fq[i]);
			break;
		case LDPAA_TX_CONF_FQ:
			err = ldpaa_tx_flow_setup(priv, &priv->fq[i]);
			break;
#ifdef CONFIG_FSL_DPAA2_ETH_USE_ERR_QUEUE
		case LDPAA_RX_ERR_FQ:
			err = ldpaa_rx_err_setup(priv, &priv->fq[i]);
			break;
#endif
		default:
			netdev_err(net_dev, "Invalid FQ type %d\n",
				   priv->fq[i].type);
			return -EINVAL;
		}
		if (unlikely(err))
			return err;
	}

	err = dpni_get_qdid(priv->mc_io, 0, priv->mc_token, &priv->tx_qdid);
	if (unlikely(err)) {
		netdev_err(net_dev, "dpni_get_qdid() failed\n");
		return err;
	}

	return 0;
}

static int ldpaa_eth_alloc_rings(struct ldpaa_eth_priv *priv)
{
	struct net_device *net_dev = priv->net_dev;
	struct device *dev = net_dev->dev.parent;
	int i;

	for (i = 0; i < priv->num_channels; i++) {
		priv->channel[i]->store =
			dpaa_io_store_create(LDPAA_ETH_STORE_SIZE, dev);
		if (unlikely(!priv->channel[i]->store)) {
			netdev_err(net_dev, "dpaa_io_store_create() failed\n");
			goto err_ring;
		}
	}

	return 0;

err_ring:
	for (i = 0; i < priv->num_channels; i++) {
		if (!priv->channel[i]->store)
			break;
		dpaa_io_store_destroy(priv->channel[i]->store);
	}

	return -ENOMEM;
}

static void ldpaa_eth_free_rings(struct ldpaa_eth_priv *priv)
{
	int i;

	for (i = 0; i < priv->num_channels; i++)
		dpaa_io_store_destroy(priv->channel[i]->store);
}

static int ldpaa_eth_netdev_init(struct net_device *net_dev)
{
	int err;
	struct device *dev = net_dev->dev.parent;
	struct ldpaa_eth_priv *priv = netdev_priv(net_dev);
	uint8_t mac_addr[ETH_ALEN];

	net_dev->netdev_ops = &ldpaa_eth_ops;

	/* If the DPL contains all-0 mac_addr, set a random hardware address */
	err = dpni_get_primary_mac_addr(priv->mc_io, 0, priv->mc_token,
					mac_addr);
	if (unlikely(err)) {
		netdev_err(net_dev, "dpni_get_primary_mac_addr() failed (%d)",
			   err);
		return err;
	}
	if (is_zero_ether_addr(mac_addr)) {
		/* Fills in net_dev->dev_addr, as required by
		 * register_netdevice()
		 */
		eth_hw_addr_random(net_dev);
		/* Make the user aware, without cluttering the boot log */
		pr_info_once(KBUILD_MODNAME " device(s) have all-zero hwaddr, replaced with random");
		err = dpni_set_primary_mac_addr(priv->mc_io, 0, priv->mc_token,
						net_dev->dev_addr);
		if (unlikely(err)) {
			netdev_err(net_dev,
				   "dpni_set_primary_mac_addr() failed (%d)\n",
				   err);
			return err;
		}
		/* Override NET_ADDR_RANDOM set by eth_hw_addr_random(); for all
		 * practical purposes, this will be our "permanent" mac address,
		 * at least until the next reboot. This move will also permit
		 * register_netdevice() to properly fill up net_dev->perm_addr.
		 */
		net_dev->addr_assign_type = NET_ADDR_PERM;
	} else {
		/* NET_ADDR_PERM is default, all we have to do is
		 * fill in the device addr.
		 */
		memcpy(net_dev->dev_addr, mac_addr, net_dev->addr_len);
	}

	/* Reserve enough space to align buffer as per hardware requirement;
	 * NOTE: priv->tx_data_offset MUST be initialized at this point.
	 */
	net_dev->needed_headroom = LDPAA_ETH_NEEDED_HEADROOM(priv);

	/* Our .ndo_init will be called herein */
	err = register_netdev(net_dev);
	if (err < 0) {
		dev_err(dev, "register_netdev() = %d\n", err);
		return err;
	}

	return 0;
}

#ifdef CONFIG_FSL_DPAA2_ETH_LINK_POLL
static int ldpaa_poll_link_state(void *arg)
{
	struct ldpaa_eth_priv *priv = (struct ldpaa_eth_priv *)arg;
	int err;

	while (!kthread_should_stop()) {
		err = ldpaa_link_state_update(priv);
		if (unlikely(err))
			return err;

		msleep(LDPAA_ETH_LINK_STATE_REFRESH);
	}

	return 0;
}
#else
static irqreturn_t dpni_irq0_handler(int irq_num, void *arg)
{
	return IRQ_WAKE_THREAD;
}

static irqreturn_t dpni_irq0_handler_thread(int irq_num, void *arg)
{
	uint8_t irq_index = DPNI_IRQ_INDEX;
	uint32_t status, clear = 0;
	struct device *dev = (struct device *)arg;
	struct fsl_mc_device *dpni_dev = to_fsl_mc_device(dev);
	struct net_device *net_dev = dev_get_drvdata(dev);
	int err;

	netdev_dbg(net_dev, "IRQ %d received\n", irq_num);
	/* Sanity check; TODO a bit of cleanup here */
	if (WARN_ON(!dpni_dev || !dpni_dev->irqs || !dpni_dev->irqs[irq_index]))
		goto out;
	if (WARN_ON(dpni_dev->irqs[irq_index]->irq_number != irq_num))
		goto out;

	err = dpni_get_irq_status(dpni_dev->mc_io, 0, dpni_dev->mc_handle,
				  irq_index, &status);
	if (unlikely(err)) {
		netdev_err(net_dev, "Can't get irq status (err %d)", err);
		clear = 0xffffffff;
		goto out;
	}

	if (status & DPNI_IRQ_EVENT_LINK_CHANGED) {
		clear |= DPNI_IRQ_EVENT_LINK_CHANGED;
		ldpaa_link_state_update(netdev_priv(net_dev));
	}

out:
	dpni_clear_irq_status(dpni_dev->mc_io, 0, dpni_dev->mc_handle,
			      irq_index, clear);
	return IRQ_HANDLED;
}

static int ldpaa_eth_setup_irqs(struct fsl_mc_device *ls_dev)
{
	int err = 0;
	struct fsl_mc_device_irq *irq;
	int irq_count = ls_dev->obj_desc.irq_count;
	uint8_t irq_index = DPNI_IRQ_INDEX;
	uint32_t mask = DPNI_IRQ_EVENT_LINK_CHANGED;

	/* The only interrupt supported now is the link state notification. */
	if (WARN_ON(irq_count != 1))
		return -EINVAL;

	irq = ls_dev->irqs[0];
	err = devm_request_threaded_irq(&ls_dev->dev, irq->irq_number,
					dpni_irq0_handler,
					dpni_irq0_handler_thread,
					IRQF_NO_SUSPEND | IRQF_ONESHOT,
					dev_name(&ls_dev->dev), &ls_dev->dev);
	if (err < 0) {
		dev_err(&ls_dev->dev, "devm_request_threaded_irq(): %d", err);
		return err;
	}

	err = dpni_set_irq_mask(ls_dev->mc_io, 0, ls_dev->mc_handle,
				irq_index, mask);
	if (err < 0) {
		dev_err(&ls_dev->dev, "dpni_set_irq_mask(): %d", err);
		return err;
	}

	err = dpni_set_irq_enable(ls_dev->mc_io, 0, ls_dev->mc_handle,
				  irq_index, 1);
	if (err < 0) {
		dev_err(&ls_dev->dev, "dpni_set_irq_enable(): %d", err);
		return err;
	}

	return 0;
}
#endif

static void ldpaa_eth_napi_add(struct ldpaa_eth_priv *priv)
{
	int i;
	struct ldpaa_eth_channel *ch;

	for (i = 0; i < priv->num_channels; i++) {
		ch = priv->channel[i];
		netif_napi_add(priv->net_dev, &ch->napi, ldpaa_eth_poll,
			       LDPAA_ETH_NAPI_WEIGHT);
	}
}

static void ldpaa_eth_napi_del(struct ldpaa_eth_priv *priv)
{
	int i;
	struct ldpaa_eth_channel *ch;

	for (i = 0; i < priv->num_channels; i++) {
		ch = priv->channel[i];
		netif_napi_del(&ch->napi);
	}
}

/* SysFS support */

static ssize_t ldpaa_eth_show_tx_shaping(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct ldpaa_eth_priv *priv = netdev_priv(to_net_dev(dev));
	/* No MC API for getting the shaping config. We're stateful. */
	struct dpni_tx_shaping_cfg *scfg = &priv->shaping_cfg;

	return sprintf(buf, "%u %hu\n", scfg->rate_limit, scfg->max_burst_size);
}

static ssize_t ldpaa_eth_write_tx_shaping(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf,
					  size_t count)
{
	int err, items;
	struct ldpaa_eth_priv *priv = netdev_priv(to_net_dev(dev));
	struct dpni_tx_shaping_cfg scfg;

	items = sscanf(buf, "%u %hu", &scfg.rate_limit, &scfg.max_burst_size);
	if (items != 2) {
		pr_err("Expected format: \"rate_limit(Mbps) max_burst_size(bytes)\"\n");
		return -EINVAL;
	}
	/* Size restriction as per MC API documentation */
	if (scfg.max_burst_size > 64000) {
		pr_err("max_burst_size must be <= 64000, thanks.\n");
		return -EINVAL;
	}

	err = dpni_set_tx_shaping(priv->mc_io, 0, priv->mc_token, &scfg);
	if (unlikely(err)) {
		dev_err(dev, "dpni_set_tx_shaping() failed\n");
		return -EPERM;
	}
	/* If successful, save the current configuration for future inquiries */
	priv->shaping_cfg = scfg;

	return count;
}

static ssize_t ldpaa_eth_show_txconf_cpumask(struct device *dev,
					     struct device_attribute *attr,
					     char *buf)
{
	struct ldpaa_eth_priv *priv = netdev_priv(to_net_dev(dev));

	return cpumap_print_to_pagebuf(1, buf, &priv->txconf_cpumask);
}

static ssize_t ldpaa_eth_write_txconf_cpumask(struct device *dev,
					      struct device_attribute *attr,
					      const char *buf,
					      size_t count)
{
	struct ldpaa_eth_priv *priv = netdev_priv(to_net_dev(dev));
	struct ldpaa_eth_fq *fq;
	bool running = netif_running(priv->net_dev);
	int i, err;

	err = cpulist_parse(buf, &priv->txconf_cpumask);
	if (unlikely(err))
		return err;

	/* Only accept CPUs that have an affine DPIO */
	if (!cpumask_subset(&priv->txconf_cpumask, &priv->dpio_cpumask)) {
		netdev_info(priv->net_dev,
			    "cpumask must be a subset of 0x%lx\n",
			    *cpumask_bits(&priv->dpio_cpumask));
		cpumask_and(&priv->txconf_cpumask, &priv->dpio_cpumask,
			    &priv->txconf_cpumask);
	}

	/* Rewiring the TxConf FQs requires interface shutdown.
	 * FIXME hold device lock
	 */
	if (running) {
		err = ldpaa_eth_stop(priv->net_dev);
		if (unlikely(err))
			return -ENODEV;
	}

	/* Set the new TxConf FQ affinities */
	ldpaa_set_fq_affinity(priv);

#ifdef CONFIG_FSL_DPAA2_ETH_LINK_POLL
	/* ldpaa_eth_open() below will *stop* the Tx queues until an explicit
	 * link up notification is received. Give the polling thread enough time
	 * to detect the link state change, or else we'll end up with the
	 * transmission side forever shut down.
	 */
	msleep(2 * LDPAA_ETH_LINK_STATE_REFRESH);
#endif

	for (i = 0; i < priv->num_fqs; i++) {
		fq = &priv->fq[i];
		if (fq->type != LDPAA_TX_CONF_FQ)
			continue;
		ldpaa_tx_flow_setup(priv, fq);
	}

	if (running) {
		err = ldpaa_eth_open(priv->net_dev);
		if (unlikely(err))
			return -ENODEV;
	}

	return count;
}

static struct device_attribute ldpaa_eth_attrs[] = {
	__ATTR(txconf_cpumask,
	       S_IRUSR | S_IWUSR,
	       ldpaa_eth_show_txconf_cpumask,
	       ldpaa_eth_write_txconf_cpumask),

	__ATTR(tx_shaping,
	       S_IRUSR | S_IWUSR,
	       ldpaa_eth_show_tx_shaping,
	       ldpaa_eth_write_tx_shaping),
};

void ldpaa_eth_sysfs_init(struct device *dev)
{
	int i, err;

	for (i = 0; i < ARRAY_SIZE(ldpaa_eth_attrs); i++) {
		err = device_create_file(dev, &ldpaa_eth_attrs[i]);
		if (unlikely(err)) {
			dev_err(dev, "ERROR creating sysfs file\n");
			goto undo;
		}
	}
	return;

undo:
	while (i > 0)
		device_remove_file(dev, &ldpaa_eth_attrs[--i]);
}

void ldpaa_eth_sysfs_remove(struct device *dev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ldpaa_eth_attrs); i++)
		device_remove_file(dev, &ldpaa_eth_attrs[i]);
}

static int __cold
ldpaa_eth_probe(struct fsl_mc_device *dpni_dev)
{
	struct device			*dev;
	struct net_device		*net_dev = NULL;
	struct ldpaa_eth_priv		*priv = NULL;
	int				err = 0;
	u8				bcast_addr[ETH_ALEN];

	dev = &dpni_dev->dev;

	/* Net device */
	net_dev = alloc_etherdev_mq(sizeof(*priv), LDPAA_ETH_TX_QUEUES);
	if (!net_dev) {
		dev_err(dev, "alloc_etherdev_mq() failed\n");
		return -ENOMEM;
	}

	SET_NETDEV_DEV(net_dev, dev);
	dev_set_drvdata(dev, net_dev);

	priv = netdev_priv(net_dev);
	priv->net_dev = net_dev;
	priv->msg_enable = netif_msg_init(debug, -1);

	/* Obtain a MC portal */
	err = fsl_mc_portal_allocate(dpni_dev, FSL_MC_IO_ATOMIC_CONTEXT_PORTAL,
				     &priv->mc_io);
	if (err) {
		dev_err(dev, "MC portal allocation failed\n");
		goto err_portal_alloc;
	}

#ifndef CONFIG_FSL_DPAA2_ETH_LINK_POLL
	err = fsl_mc_allocate_irqs(dpni_dev);
	if (err) {
		dev_err(dev, "MC irqs allocation failed\n");
		goto err_irqs_alloc;
	}
#endif

	/* DPNI initialization */
	err = ldpaa_dpni_setup(dpni_dev);
	if (err < 0)
		goto err_dpni_setup;

	/* DPIO */
	err = ldpaa_dpio_setup(priv);
	if (err)
		goto err_dpio_setup;

	/* FQs */
	ldpaa_eth_setup_fqs(priv);
	ldpaa_set_fq_affinity(priv);

	/* DPBP */
	priv->buf_count = alloc_percpu(*priv->buf_count);
	if (!priv->buf_count) {
		dev_err(dev, "alloc_percpu() failed\n");
		err = -ENOMEM;
		goto err_alloc_bp_count;
	}
	err = ldpaa_dpbp_setup(priv);
	if (err)
		goto err_dpbp_setup;

	/* DPNI binding to DPIO and DPBPs */
	err = ldpaa_dpni_bind(priv);
	if (err)
		goto err_bind;

	ldpaa_eth_napi_add(priv);

	/* Percpu statistics */
	priv->percpu_stats = alloc_percpu(*priv->percpu_stats);
	if (!priv->percpu_stats) {
		dev_err(dev, "alloc_percpu(percpu_stats) failed\n");
		err = -ENOMEM;
		goto err_alloc_percpu_stats;
	}
	priv->percpu_extras = alloc_percpu(*priv->percpu_extras);
	if (!priv->percpu_extras) {
		dev_err(dev, "alloc_percpu(percpu_extras) failed\n");
		err = -ENOMEM;
		goto err_alloc_percpu_extras;
	}

	snprintf(net_dev->name, IFNAMSIZ, "ni%d", dpni_dev->obj_desc.id);
	if (!dev_valid_name(net_dev->name)) {
		dev_warn(&net_dev->dev,
			 "netdevice name \"%s\" cannot be used, reverting to default..\n",
			 net_dev->name);
		dev_alloc_name(net_dev, "eth%d");
		dev_warn(&net_dev->dev, "using name \"%s\"\n", net_dev->name);
	}

	err = ldpaa_eth_netdev_init(net_dev);
	if (err)
		goto err_netdev_init;

	/* Explicitly add the broadcast address to the MAC filtering table;
	 * the MC won't do that for us.
	 */
	eth_broadcast_addr(bcast_addr);
	err = dpni_add_mac_addr(priv->mc_io, 0, priv->mc_token, bcast_addr);
	if (err) {
		netdev_warn(net_dev,
			    "dpni_add_mac_addr() failed with code %d\n", err);
		/* Won't return an error; at least, we'd have egress traffic */
	}

	/* Configure checksum offload based on current interface flags */
	err = ldpaa_eth_set_rx_csum(priv,
				    !!(net_dev->features & NETIF_F_RXCSUM));
	if (unlikely(err))
		goto err_csum;

	err = ldpaa_eth_set_tx_csum(priv,
				    !!(net_dev->features &
				    (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM)));
	if (unlikely(err))
		goto err_csum;

	err = ldpaa_eth_alloc_rings(priv);
	if (unlikely(err))
		goto err_alloc_rings;

	net_dev->ethtool_ops = &ldpaa_ethtool_ops;

#ifdef CONFIG_FSL_DPAA2_ETH_LINK_POLL
	priv->poll_thread = kthread_run(ldpaa_poll_link_state, priv,
					"%s_poll_link", net_dev->name);
#else
	err = ldpaa_eth_setup_irqs(dpni_dev);
	if (unlikely(err)) {
		netdev_err(net_dev, "ERROR %d setting up interrupts", err);
		goto err_setup_irqs;
	}
#endif

	ldpaa_eth_sysfs_init(&net_dev->dev);
	ldpaa_dbg_add(priv);

	dev_info(dev, "Probed interface %s\n", net_dev->name);
	return 0;

#ifndef CONFIG_FSL_DPAA2_ETH_LINK_POLL
err_setup_irqs:
#endif
	ldpaa_eth_free_rings(priv);
err_alloc_rings:
err_csum:
	unregister_netdev(net_dev);
err_netdev_init:
	free_percpu(priv->percpu_extras);
err_alloc_percpu_extras:
	free_percpu(priv->percpu_stats);
err_alloc_percpu_stats:
	ldpaa_eth_napi_del(priv);
err_bind:
	ldpaa_dpbp_free(priv);
err_dpbp_setup:
	free_percpu(priv->buf_count);
err_alloc_bp_count:
	ldpaa_dpio_free(priv);
err_dpio_setup:
	kfree(priv->cls_rule);
	dpni_close(priv->mc_io, 0, priv->mc_token);
err_dpni_setup:
#ifndef CONFIG_FSL_DPAA2_ETH_LINK_POLL
	fsl_mc_free_irqs(dpni_dev);
err_irqs_alloc:
#endif
	fsl_mc_portal_free(priv->mc_io);
err_portal_alloc:
	dev_set_drvdata(dev, NULL);
	free_netdev(net_dev);

	return err;
}

static int __cold
ldpaa_eth_remove(struct fsl_mc_device *ls_dev)
{
	struct device		*dev;
	struct net_device	*net_dev;
	struct ldpaa_eth_priv *priv;

	dev = &ls_dev->dev;
	net_dev = dev_get_drvdata(dev);
	priv = netdev_priv(net_dev);

	ldpaa_dbg_remove(priv);
	ldpaa_eth_sysfs_remove(&net_dev->dev);

	unregister_netdev(net_dev);
	dev_info(net_dev->dev.parent, "Removed interface %s\n", net_dev->name);

	ldpaa_dpio_free(priv);
	ldpaa_eth_free_rings(priv);
	ldpaa_eth_napi_del(priv);
	ldpaa_dpbp_free(priv);
	ldpaa_dpni_free(priv);

	fsl_mc_portal_free(priv->mc_io);

	free_percpu(priv->percpu_stats);
	free_percpu(priv->percpu_extras);
	free_percpu(priv->buf_count);

#ifdef CONFIG_FSL_DPAA2_ETH_LINK_POLL
	kthread_stop(priv->poll_thread);
#else
	fsl_mc_free_irqs(ls_dev);
#endif

	kfree(priv->cls_rule);

	dev_set_drvdata(dev, NULL);
	free_netdev(net_dev);

	return 0;
}

static const struct fsl_mc_device_match_id ldpaa_eth_match_id_table[] = {
	{
		.vendor = FSL_MC_VENDOR_FREESCALE,
		.obj_type = "dpni",
		.ver_major = DPNI_VER_MAJOR,
		.ver_minor = DPNI_VER_MINOR
	},
	{ .vendor = 0x0 }
};

static struct fsl_mc_driver ldpaa_eth_driver = {
	.driver = {
		.name		= KBUILD_MODNAME,
		.owner		= THIS_MODULE,
	},
	.probe		= ldpaa_eth_probe,
	.remove		= ldpaa_eth_remove,
	.match_id_table = ldpaa_eth_match_id_table
};

static int __init ldpaa_eth_driver_init(void)
{
	int err;

	ldpaa_eth_dbg_init();

	err = fsl_mc_driver_register(&ldpaa_eth_driver);
	if (err) {
		ldpaa_eth_dbg_exit();
		return err;
	}

	return 0;
}

static void __exit ldpaa_eth_driver_exit(void)
{
	fsl_mc_driver_unregister(&ldpaa_eth_driver);
	ldpaa_eth_dbg_exit();
}

module_init(ldpaa_eth_driver_init);
module_exit(ldpaa_eth_driver_exit);
