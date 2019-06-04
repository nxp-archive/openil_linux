// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
/* Copyright 2017-2019 NXP */

#include "enetc.h"
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/of_mdio.h>
#include <rtnet_port.h>
#include <rtdm/driver.h>

static int enetc_map_tx_buffs(struct enetc_bdr *tx_ring, struct rtskb *skb,
			      bool tstamp);
static void enetc_unmap_tx_buff(struct enetc_bdr *tx_ring,
				struct enetc_tx_swbd *tx_swbd);
static int enetc_clean_tx_ring(struct enetc_bdr *tx_ring);

static struct rtskb *enetc_map_rx_buff_to_skb(struct enetc_bdr *rx_ring,
						int i, u16 size);
static void enetc_add_rx_buff_to_skb(struct enetc_bdr *rx_ring, int i,
				     u16 size, struct rtskb *skb);
static void enetc_process_skb(struct enetc_bdr *rx_ring, struct rtskb *skb);
static int enetc_clean_rx_ring(struct enetc_bdr *rx_ring);

static int enetc_msix(rtdm_irq_t *irq_handle)
{
	struct enetc_int_vector	*v =
		rtdm_irq_get_arg(irq_handle, struct enetc_int_vector);
	int j;

	for (j = 0; j < v->count_tx_rings; j++)
		enetc_clean_tx_ring(&v->tx_ring[j]);

	enetc_clean_rx_ring(&v->rx_ring);

	return RTDM_IRQ_HANDLED;
}

/* max number of fragments + optional extension BD */
#define ENETC_FREE_TXBD_NEEDED (MAX_SKB_FRAGS + 1)

netdev_tx_t enetc_xmit(struct rtskb *skb, struct rtnet_device *ndev)
{
	struct enetc_ndev_priv *priv = rtnetdev_priv(ndev);
	struct enetc_bdr *tx_ring;
	int count;

	tx_ring = priv->tx_ring[0];
	if (enetc_bd_unused(tx_ring) < ENETC_FREE_TXBD_NEEDED)
		return NETDEV_TX_BUSY;

	count = enetc_map_tx_buffs(tx_ring, skb, priv->tx_tstamp);
	if (unlikely(!count)) {
		kfree_rtskb(skb);
		return NETDEV_TX_OK;
	}

	if (enetc_bd_unused(tx_ring) < ENETC_FREE_TXBD_NEEDED)
		rtnetif_stop_queue(ndev);


	return NETDEV_TX_OK;
}

static int enetc_map_tx_buffs(struct enetc_bdr *tx_ring, struct rtskb *skb,
			      bool tstamp)
{
	struct enetc_tx_swbd *tx_swbd;
	int len = rtskb_headlen(skb);
	union enetc_tx_bd *txbd;
	int i, start, count = 0;
	dma_addr_t dma;
	u8 flags = 0;

	i = tx_ring->next_to_use;
	start = tx_ring->next_to_use;

	dma = dma_map_single(tx_ring->dev, skb->data, len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(tx_ring->dev, dma)))
		goto dma_err;

	txbd = ENETC_TXBD(*tx_ring, i);
	txbd->addr = cpu_to_le64(dma);
	txbd->buf_len = cpu_to_le16(len);

	tx_swbd = &tx_ring->tx_swbd[i];
	tx_swbd->dma = dma;
	tx_swbd->len = len;
	tx_swbd->is_dma_page = 0;
	count++;

	/* first BD needs frm_len and offload flags set */
	txbd->frm_len = cpu_to_le16(skb->len);
	txbd->flags = flags;

	if (flags & ENETC_TXBD_FLAGS_EX) {
		u8 e_flags = 0;
		/* add extension BD for VLAN and/or timestamping */
		flags = 0;
		tx_swbd++;
		txbd++;
		i++;
		if (unlikely(i == tx_ring->bd_count)) {
			i = 0;
			tx_swbd = tx_ring->tx_swbd;
			txbd = ENETC_TXBD(*tx_ring, 0);
		}
		txbd->ext.e_flags = e_flags;
		count++;
	}
	/* last BD needs 'F' bit set */
	flags |= ENETC_TXBD_FLAGS_F;
	txbd->flags = flags;
	tx_ring->tx_swbd[i].skb = skb;

	enetc_bdr_idx_inc(tx_ring, &i);
	tx_ring->next_to_use = i;

	/* let H/W know BD ring has been updated */
	enetc_wr_reg(tx_ring->tpir, i); /* includes wmb() */

	return count;

dma_err:
	dev_err(tx_ring->dev, "DMA map error");

	do {
		tx_swbd = &tx_ring->tx_swbd[i];
		enetc_unmap_tx_buff(tx_ring, tx_swbd);
		if (i == 0)
			i = tx_ring->bd_count;
		i--;
	} while (count--);

	return 0;
}

static void enetc_unmap_tx_buff(struct enetc_bdr *tx_ring,
				struct enetc_tx_swbd *tx_swbd)
{
	if (tx_swbd->dma) {
		if (tx_swbd->is_dma_page)
			dma_unmap_page(tx_ring->dev, tx_swbd->dma,
				       tx_swbd->len, DMA_TO_DEVICE);
		else
			dma_unmap_single(tx_ring->dev, tx_swbd->dma,
					 tx_swbd->len, DMA_TO_DEVICE);
		tx_swbd->dma = 0;
	}

	if (tx_swbd->skb) {
		kfree_rtskb(tx_swbd->skb);
		tx_swbd->skb = NULL;
	}
}

static int enetc_bd_ready_count(struct enetc_bdr *tx_ring, int ci)
{
	int pi = enetc_rd_reg(tx_ring->tcir) & ENETC_TBCIR_IDX_MASK;

	return pi >= ci ? pi - ci : tx_ring->bd_count - ci + pi;
}

static void enetc_get_tx_tstamp(struct enetc_hw *hw, union enetc_tx_bd *txbd,
				u64 *tstamp)
{
	u32 lo, hi;

	if (txbd->flags & ENETC_TXBD_FLAGS_W) {
		lo = enetc_rd(hw, ENETC_SICTR0);
		hi = enetc_rd(hw, ENETC_SICTR1);
		if (lo <= txbd->ext.tstamp)
			hi -= 1;
		*tstamp = (u64)hi << 32 | txbd->ext.tstamp;
	}
}

static int enetc_clean_tx_ring(struct enetc_bdr *tx_ring)
{
	struct rtnet_device *ndev = tx_ring->ndev;
	int tx_frm_cnt = 0, tx_byte_cnt = 0;
	struct enetc_tx_swbd *tx_swbd;
	struct enetc_ndev_priv *priv;
	int i, bds_to_clean;
	bool do_tstamp, first;
	u64 tstamp = 0;

	priv = rtnetdev_priv(ndev);
	do_tstamp = priv->tx_tstamp;

	i = tx_ring->next_to_clean;
	tx_swbd = &tx_ring->tx_swbd[i];
	first = true;
	bds_to_clean = enetc_bd_ready_count(tx_ring, i);

	while (bds_to_clean) {
		bool is_eof = !!tx_swbd->skb;

		if (unlikely(do_tstamp)) {
			if (unlikely(first)) {
				union enetc_tx_bd *txbd;

				txbd = ENETC_TXBD(*tx_ring, i);
				enetc_get_tx_tstamp(&priv->si->hw, txbd,
						    &tstamp);
			}
		}

		enetc_unmap_tx_buff(tx_ring, tx_swbd);
		tx_byte_cnt += tx_swbd->len;

		bds_to_clean--;
		tx_swbd++;
		i++;
		if (unlikely(i == tx_ring->bd_count)) {
			i = 0;
			tx_swbd = tx_ring->tx_swbd;
		}

		/* BD iteration loop end */
		first = false;
		if (is_eof) {
			tx_frm_cnt++;
			first = true;
			/* re-arm interrupt source */
			enetc_wr_reg(tx_ring->idr, BIT(tx_ring->index) |
				     BIT(16 + tx_ring->index));
		}

		if (unlikely(!bds_to_clean))
			bds_to_clean = enetc_bd_ready_count(tx_ring, i);
	}

	tx_ring->next_to_clean = i;
	tx_ring->stats.packets += tx_frm_cnt;
	tx_ring->stats.bytes += tx_byte_cnt;

	if (unlikely(tx_frm_cnt && rtnetif_carrier_ok(ndev) &&
		     rtnetif_queue_stopped(ndev) &&
		     (enetc_bd_unused(tx_ring) >= ENETC_FREE_TXBD_NEEDED))) {
		rtnetif_wake_queue(ndev);
	}

	return tx_frm_cnt;
}

static bool enetc_new_skb(struct enetc_bdr *rx_ring,
			   struct enetc_rx_swbd *rx_swbd)
{
	struct rtskb *skb;
	dma_addr_t addr;


	skb = rtnetdev_alloc_rtskb(rx_ring->ndev,
			ENETC_RX_MAXFRM_SIZE);
	if (!skb) {
		pr_info("Can't allocate RX buffers\n");
		return false;
	}
	rx_swbd->skb = skb;

	addr = dma_map_single(rx_ring->dev, skb->data,
			ENETC_RXB_DMA_SIZE, DMA_FROM_DEVICE);
	rx_swbd->dma = addr;
	rx_swbd->page_offset = ENETC_RXB_PAD;

	return true;
}

static int enetc_refill_rx_ring(struct enetc_bdr *rx_ring, const int buff_cnt)
{
	struct enetc_rx_swbd *rx_swbd;
	union enetc_rx_bd *rxbd;
	int i, j;

	i = rx_ring->next_to_use;
	rx_swbd = &rx_ring->rx_swbd[i];
	rxbd = ENETC_RXBD(*rx_ring, i);

	for (j = 0; j < buff_cnt; j++) {
		/* try reuse page */
		if (unlikely(!rx_swbd->page)) {
			if (unlikely(!enetc_new_skb(rx_ring, rx_swbd))) {
				rx_ring->stats.rx_alloc_errs++;
				break;
			}
		}

		/* update RxBD */
		rxbd->w.addr = cpu_to_le64(rx_swbd->dma +
					   rx_swbd->page_offset);
		/* clear 'R" as well */
		rxbd->r.lstatus = 0;

		rx_swbd++;
		rxbd++;
		i++;
		if (unlikely(i == rx_ring->bd_count)) {
			i = 0;
			rx_swbd = rx_ring->rx_swbd;
			rxbd = ENETC_RXBD(*rx_ring, 0);
		}
	}

	if (likely(j)) {
		rx_ring->next_to_alloc = i; /* keep track from page reuse */
		rx_ring->next_to_use = i;
		/* update ENETC's consumer index */
		enetc_wr_reg(rx_ring->rcir, i);
	}

	return j;
}

#define ENETC_RXBD_BUNDLE 16 /* recommended # of BDs to update at once */

static int enetc_clean_rx_ring(struct enetc_bdr *rx_ring)
{
	int rx_frm_cnt = 0, rx_byte_cnt = 0;
	int cleaned_cnt, i;
	nanosecs_abs_t time_stamp = rtdm_clock_read();

	cleaned_cnt = enetc_bd_unused(rx_ring);
	/* next descriptor to process */
	i = rx_ring->next_to_clean;
	while (likely(rx_frm_cnt < 10)) {
		union enetc_rx_bd *rxbd;
		struct rtskb *skb;
		u32 bd_status;
		u16 size;

		if (cleaned_cnt >= ENETC_RXBD_BUNDLE) {
			int count = enetc_refill_rx_ring(rx_ring, cleaned_cnt);

			cleaned_cnt -= count;
		}

		rxbd = ENETC_RXBD(*rx_ring, i);
		bd_status = le32_to_cpu(rxbd->r.lstatus);
		if (!bd_status)
			break;

		enetc_wr_reg(rx_ring->idr, BIT(rx_ring->index));
		dma_rmb(); /* for readig other rxbd fields */
		size = le16_to_cpu(rxbd->r.buf_len);
		skb = enetc_map_rx_buff_to_skb(rx_ring, i, size);
		if (!skb)
			break;

		cleaned_cnt++;
		rxbd++;
		i++;
		if (unlikely(i == rx_ring->bd_count)) {
			i = 0;
			rxbd = ENETC_RXBD(*rx_ring, 0);
		}

		if (unlikely(bd_status &
			     ENETC_RXBD_LSTATUS(ENETC_RXBD_ERR_MASK))) {
			kfree_rtskb(skb);
			while (!(bd_status & ENETC_RXBD_LSTATUS_F)) {
				dma_rmb();
				bd_status = le32_to_cpu(rxbd->r.lstatus);
				rxbd++;
				i++;
				if (unlikely(i == rx_ring->bd_count)) {
					i = 0;
					rxbd = ENETC_RXBD(*rx_ring, 0);
				}
			}

			break;
		}

		/* not last BD in frame? */
		while (!(bd_status & ENETC_RXBD_LSTATUS_F)) {
			bd_status = le32_to_cpu(rxbd->r.lstatus);
			size = ENETC_RXB_DMA_SIZE;

			if (bd_status & ENETC_RXBD_LSTATUS_F) {
				dma_rmb();
				size = le16_to_cpu(rxbd->r.buf_len);
			}

			enetc_add_rx_buff_to_skb(rx_ring, i, size, skb);

			cleaned_cnt++;
			rxbd++;
			i++;
			if (unlikely(i == rx_ring->bd_count)) {
				i = 0;
				rxbd = ENETC_RXBD(*rx_ring, 0);
			}
		}

		rx_byte_cnt += skb->len;

		enetc_process_skb(rx_ring, skb);
		skb->time_stamp = time_stamp;
		skb->rtdev = rx_ring->ndev;
		rtnetif_rx(skb);
		rt_mark_stack_mgr(rx_ring->ndev);
		rx_frm_cnt++;
	}

	rx_ring->next_to_clean = i;
	// TODO: 64-bit stats
	rx_ring->stats.packets += rx_frm_cnt;
	rx_ring->stats.bytes += rx_byte_cnt;

	return rx_frm_cnt;
}

struct enetc_rx_swbd *enetc_get_rx_buff(struct enetc_bdr *rx_ring, int i,
					u16 size)
{
	struct enetc_rx_swbd *rx_swbd = &rx_ring->rx_swbd[i];

	dma_sync_single_range_for_cpu(rx_ring->dev, rx_swbd->dma,
				      rx_swbd->page_offset,
				      size, DMA_FROM_DEVICE);
	return rx_swbd;
}

static void enetc_put_rx_buff(struct enetc_bdr *rx_ring,
			      struct enetc_rx_swbd *rx_swbd)
{
	dma_sync_single_range_for_device(rx_ring->dev, rx_swbd->dma,
						 rx_swbd->page_offset,
						 ENETC_RXB_DMA_SIZE,
						 DMA_FROM_DEVICE);
}

static struct rtskb *enetc_map_rx_buff_to_skb(struct enetc_bdr *rx_ring,
						int i, u16 size)
{
	struct enetc_rx_swbd *rx_swbd = enetc_get_rx_buff(rx_ring, i, size);
	struct rtskb *skb;
	void *ba;

	ba = page_address(rx_swbd->page) + rx_swbd->page_offset;
	skb = rx_swbd->skb;
	if (unlikely(!skb)) {
		rx_ring->stats.rx_alloc_errs++;
		return NULL;
	}

	rtskb_reserve(skb, ENETC_RXB_PAD);
	__rtskb_put(skb, size);
	enetc_put_rx_buff(rx_ring, rx_swbd);


	return skb;
}

static void enetc_add_rx_buff_to_skb(struct enetc_bdr *rx_ring, int i,
				     u16 size, struct rtskb *skb)
{
	struct enetc_rx_swbd *rx_swbd = enetc_get_rx_buff(rx_ring, i, size);

	enetc_put_rx_buff(rx_ring, rx_swbd);
}

static void enetc_process_skb(struct enetc_bdr *rx_ring,
			      struct rtskb *skb)
{
	skb->protocol = rt_eth_type_trans(skb, rx_ring->ndev);
}

/* Probing and Init */
#define ENETC_MAX_RFS_SIZE 64
void enetc_get_si_caps(struct enetc_si *si)
{
	struct enetc_hw *hw = &si->hw;
	u32 val;

	/* find out how many of various resources we have to work with */
	val = enetc_rd(hw, ENETC_SICAPR0);
	/* we expect to have the same number of Rx and Tx rings, but in case
	 * that's not true use the min value
	 */
	si->num_rx_rings = (val >> 16) & 0xff;
	si->num_tx_rings = val & 0xff;
	si->num_fs_entries = enetc_rd(hw, ENETC_SIRFSCAPR) & 0x7f;
	si->num_fs_entries = min(si->num_fs_entries, ENETC_MAX_RFS_SIZE);
	val = enetc_rd(hw, ENETC_SIRSSCAPR) & 0xf;
	si->num_rss = BIT(val) * 32;

	val = enetc_rd(hw, ENETC_SIPCAPR0);
	if (!(val & ENETC_SIPCAPR0_RSS))
		si->num_rss = 0;
}

static int enetc_alloc_txbdr(struct enetc_bdr *txr)
{
	int size;

	txr->tx_swbd = vzalloc(txr->bd_count * sizeof(struct enetc_tx_swbd));
	if (!txr->tx_swbd)
		return -ENOMEM;

	size = txr->bd_count * sizeof(union enetc_tx_bd);
	txr->bd_base = dma_zalloc_coherent(txr->dev, size, &txr->bd_dma_base,
					   GFP_KERNEL);
	if (!txr->bd_base) {
		rtdm_free(txr->tx_swbd);
		return -ENOMEM;
	}

	txr->next_to_clean = 0;
	txr->next_to_use = 0;

	return 0;
}

static void enetc_free_txbdr(struct enetc_bdr *txr)
{
	int size;

	size = txr->bd_count * sizeof(union enetc_tx_bd);

	dma_free_coherent(txr->dev, size, txr->bd_base, txr->bd_dma_base);
	txr->bd_base = NULL;

	rtdm_free(txr->tx_swbd);
	txr->tx_swbd = 0;
	// TODO: free tx_ring dma mappings and skbs
}

static int enetc_alloc_tx_resources(struct enetc_ndev_priv *priv)
{
	int i, err;

	for (i = 0; i < priv->num_tx_rings; i++) {
		err = enetc_alloc_txbdr(priv->tx_ring[i]);

		if (err)
			goto fail;
	}

	return 0;

fail:
	while (i-- > 0)
		enetc_free_txbdr(priv->tx_ring[i]);

	return err;
}

static void enetc_free_tx_resources(struct enetc_ndev_priv *priv)
{
	int i;

	for (i = 0; i < priv->num_tx_rings; i++)
		enetc_free_txbdr(priv->tx_ring[i]);
}

static int enetc_alloc_rxbdr(struct enetc_bdr *rxr)
{
	int size;

	rxr->rx_swbd = vzalloc(rxr->bd_count * sizeof(struct enetc_rx_swbd));
	if (!rxr->rx_swbd)
		return -ENOMEM;

	size = rxr->bd_count * sizeof(union enetc_rx_bd);
	rxr->bd_base = dma_zalloc_coherent(rxr->dev, size, &rxr->bd_dma_base,
					   GFP_KERNEL);
	if (!rxr->bd_base) {
		rtdm_free(rxr->rx_swbd);
		return -ENOMEM;
	}

	rxr->next_to_clean = 0;
	rxr->next_to_use = 0;
	rxr->next_to_alloc = 0;

	return 0;
}

static void enetc_free_rxbdr(struct enetc_bdr *rxr)
{
	int size;

	size = rxr->bd_count * sizeof(union enetc_rx_bd);

	dma_free_coherent(rxr->dev, size, rxr->bd_base, rxr->bd_dma_base);
	rxr->bd_base = NULL;

	rtdm_free(rxr->rx_swbd);
	rxr->rx_swbd = NULL;
}

static int enetc_alloc_rx_resources(struct enetc_ndev_priv *priv)
{
	int i, err;

	for (i = 0; i < priv->num_rx_rings; i++) {
		err = enetc_alloc_rxbdr(priv->rx_ring[i]);

		if (err)
			goto fail;
	}

	return 0;

fail:
	while (i-- > 0)
		enetc_free_rxbdr(priv->rx_ring[i]);

	return err;
}

static void enetc_free_rx_resources(struct enetc_ndev_priv *priv)
{
	int i;

	for (i = 0; i < priv->num_rx_rings; i++)
		enetc_free_rxbdr(priv->rx_ring[i]);
}

static void enetc_free_tx_ring(struct enetc_bdr *tx_ring)
{
	int i;

	if (!tx_ring->tx_swbd)
		return;

	for (i = 0; i < tx_ring->bd_count; i++) {
		struct enetc_tx_swbd *tx_swbd = &tx_ring->tx_swbd[i];

		enetc_unmap_tx_buff(tx_ring, tx_swbd);
	}

	tx_ring->next_to_clean = 0;
	tx_ring->next_to_use = 0;
}

static void enetc_free_rx_ring(struct enetc_bdr *rx_ring)
{
	int i;

	if (!rx_ring->rx_swbd)
		return;

	for (i = 0; i < rx_ring->bd_count; i++) {
		struct enetc_rx_swbd *rx_swbd = &rx_ring->rx_swbd[i];

		if (!rx_swbd->page)
			continue;

		dma_unmap_single(rx_ring->dev, rx_swbd->dma,
			ENETC_RXB_DMA_SIZE, DMA_FROM_DEVICE);
		kfree_rtskb(rx_swbd->skb);
		rx_swbd->page = NULL;
	}

	// TODO: zero out rx_swbd and BD ring?
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
	rx_ring->next_to_alloc = 0;
}

static void enetc_free_rxtx_rings(struct enetc_ndev_priv *priv)
{
	int i;

	for (i = 0; i < priv->num_rx_rings; i++)
		enetc_free_rx_ring(priv->rx_ring[i]);

	for (i = 0; i < priv->num_tx_rings; i++)
		enetc_free_tx_ring(priv->tx_ring[i]);
}

static int enetc_alloc_cbdr(struct device *dev, struct enetc_cbdr *cbdr)
{
	int size = cbdr->bd_count * sizeof(struct enetc_cbd);

	cbdr->bd_base = dma_zalloc_coherent(dev, size, &cbdr->bd_dma_base,
					    GFP_KERNEL);
	if (!cbdr->bd_base)
		return -ENOMEM;

	cbdr->next_to_clean = 0;
	cbdr->next_to_use = 0;

	return 0;
}

static void enetc_free_cbdr(struct device *dev, struct enetc_cbdr *cbdr)
{
	int size = cbdr->bd_count * sizeof(struct enetc_cbd);

	dma_free_coherent(dev, size, cbdr->bd_base, cbdr->bd_dma_base);
	cbdr->bd_base = NULL;
}

static void enetc_setup_cbdr(struct enetc_hw *hw, struct enetc_cbdr *cbdr)
{
	WARN_ON(lower_32_bits(cbdr->bd_dma_base) & 0x7f);

	/* set CBDR cache attributes */
	enetc_wr(hw, ENETC_SICAR2,
		 ENETC_SICAR_RD_COHERENT | ENETC_SICAR_WR_COHERENT);

	enetc_wr(hw, ENETC_SICBDRBAR0, lower_32_bits(cbdr->bd_dma_base));
	enetc_wr(hw, ENETC_SICBDRBAR1, upper_32_bits(cbdr->bd_dma_base));
	enetc_wr(hw, ENETC_SICBDRLENR, ENETC_RTBLENR_LEN(cbdr->bd_count));

	enetc_wr(hw, ENETC_SICBDRPIR, 0);
	enetc_wr(hw, ENETC_SICBDRCIR, 0);

	/* enable ring */
	enetc_wr(hw, ENETC_SICBDRMR, BIT(31));

	cbdr->pir = hw->reg + ENETC_SICBDRPIR;
	cbdr->cir = hw->reg + ENETC_SICBDRCIR;
}

static void enetc_clear_cbdr(struct enetc_hw *hw)
{
	enetc_wr(hw, ENETC_SICBDRMR, 0);
}

static int enetc_configure_si(struct enetc_ndev_priv *priv)
{
	struct enetc_si *si = priv->si;
	struct enetc_hw *hw = &si->hw;
	int *rss_table;
	int i;

	rss_table = rtdm_malloc(sizeof(*rss_table));
	if (!rss_table)
		return -ENOMEM;

	enetc_setup_cbdr(hw, &si->cbd_ring);
	/* set SI cache attributes */
	enetc_wr(hw, ENETC_SICAR0,
		 ENETC_SICAR_RD_COHERENT | ENETC_SICAR_WR_COHERENT);
	enetc_wr(hw, ENETC_SICAR1, ENETC_SICAR_MSI);
	/* enable SI */
	enetc_wr(hw, ENETC_SIMR, ENETC_SIMR_EN);

	if (si->num_rss) {
		/* Set up RSS table defaults */
		for (i = 0; i < si->num_rss; i++)
			rss_table[i] = i % priv->num_rx_rings;

		enetc_set_rss_table(si, rss_table, si->num_rss);
	}

	rtdm_free(rss_table);

	return 0;
}

void enetc_init_si_rings_params(struct enetc_ndev_priv *priv)
{
	struct enetc_si *si = priv->si;
	int cpus = num_online_cpus();

	priv->tx_bd_count = 1024; //TODO: use defines for defaults
	priv->rx_bd_count = 1024;

	/* Enable all available TX rings in order to configure as many
	 * priorities as possible, when needed.
	 * TODO: Make # of TX rings run-time configurable
	 */
	priv->num_rx_rings = min_t(int, cpus, si->num_rx_rings);
	priv->num_tx_rings = si->num_tx_rings;
	priv->bdr_int_num = cpus;

	/* SI specific */
	si->cbd_ring.bd_count = 64; //TODO: use defines for defaults
}

int enetc_alloc_si_resources(struct enetc_ndev_priv *priv)
{
	struct enetc_si *si = priv->si;
	int err;

	err = enetc_alloc_cbdr(priv->dev, &si->cbd_ring);
	if (err)
		goto err_alloc_cbdr;

	priv->cls_rules = kcalloc(si->num_fs_entries, sizeof(*priv->cls_rules),
				  GFP_KERNEL);
	if (!priv->cls_rules) {
		err = -ENOMEM;
		goto err_alloc_cls;
	}

	err = enetc_configure_si(priv);
	if (err)
		goto err_config_si;

	return 0;

err_config_si:
	rtdm_free(priv->cls_rules);
err_alloc_cls:
	enetc_clear_cbdr(&si->hw);
	enetc_free_cbdr(priv->dev, &si->cbd_ring);
err_alloc_cbdr:

	return err;
}

void enetc_free_si_resources(struct enetc_ndev_priv *priv)
{
	struct enetc_si *si = priv->si;

	enetc_clear_cbdr(&si->hw);
	enetc_free_cbdr(priv->dev, &si->cbd_ring);

	rtdm_free(priv->cls_rules);
}

static void enetc_setup_txbdr(struct enetc_hw *hw, struct enetc_bdr *tx_ring)
{
	int idx = tx_ring->index;
	u32 tbmr;

	/* 128B alignment required */
	WARN_ON(lower_32_bits(tx_ring->bd_dma_base) & 0x7f);

	enetc_txbdr_wr(hw, idx, ENETC_TBBAR0,
		       lower_32_bits(tx_ring->bd_dma_base));

	enetc_txbdr_wr(hw, idx, ENETC_TBBAR1,
		       upper_32_bits(tx_ring->bd_dma_base));

	WARN_ON(tx_ring->bd_count & 0x3f); //FIXME: must be multiple of 64

	enetc_txbdr_wr(hw, idx, ENETC_TBLENR,
		       ENETC_RTBLENR_LEN(tx_ring->bd_count));

	/* clearing PI/CI registers for Tx not supported, adjust sw indexes */
	tx_ring->next_to_use = enetc_txbdr_rd(hw, idx, ENETC_TBPIR);
	tx_ring->next_to_clean = enetc_txbdr_rd(hw, idx, ENETC_TBCIR);

	/* enable Tx ints by setting pkt thr to 1 */
	enetc_txbdr_wr(hw, idx, ENETC_TBICIR0, ENETC_TBICIR0_ICEN | 0x1);

	tbmr = ENETC_TBMR_EN;
	if (tx_ring->ndev->features & NETIF_F_HW_VLAN_CTAG_TX)
		tbmr |= ENETC_TBMR_VIH;

	if (enetc_tsn_is_enabled()) {
		tbmr &= ~ENETC_TBMR_PRIO_MASK;
		tbmr |= ENETC_TBMR_PRIO_SET(idx % 8);
	}

	/* enable ring */
	enetc_txbdr_wr(hw, idx, ENETC_TBMR, tbmr);

	tx_ring->tpir = hw->reg + ENETC_BDR(TX, idx, ENETC_TBPIR);
	tx_ring->tcir = hw->reg + ENETC_BDR(TX, idx, ENETC_TBCIR);
	tx_ring->idr = hw->reg + ENETC_SITXIDR;
}

static void enetc_setup_rxbdr(struct enetc_hw *hw, struct enetc_bdr *rx_ring)
{
	int idx = rx_ring->index;
	u32 rbmr;

	/* 128B alignment required */
	WARN_ON(lower_32_bits(rx_ring->bd_dma_base) & 0x7f);

	enetc_rxbdr_wr(hw, idx, ENETC_RBBAR0,
		       lower_32_bits(rx_ring->bd_dma_base));

	enetc_rxbdr_wr(hw, idx, ENETC_RBBAR1,
		       upper_32_bits(rx_ring->bd_dma_base));

	WARN_ON(rx_ring->bd_count & 0x3f); //FIXME: must be multiple of 64

	enetc_rxbdr_wr(hw, idx, ENETC_RBLENR,
		       ENETC_RTBLENR_LEN(rx_ring->bd_count));

	enetc_rxbdr_wr(hw, idx, ENETC_RBBSR, ENETC_RXB_DMA_SIZE);

	enetc_rxbdr_wr(hw, idx, ENETC_RBPIR, 0);

	/* enable Rx ints by setting pkt thr to 1 (BG 0.7) */
	enetc_rxbdr_wr(hw, idx, ENETC_RBICIR0, ENETC_RBICIR0_ICEN | 0x1);

	rbmr = ENETC_RBMR_EN;
	if (rx_ring->ndev->features & NETIF_F_HW_VLAN_CTAG_RX)
		rbmr |= ENETC_RBMR_VTE;
	if (enetc_has_extended_rxbds())
		rbmr |= ENETC_RBMR_BDS;

	rx_ring->rcir = hw->reg + ENETC_BDR(RX, idx, ENETC_RBCIR);
	rx_ring->idr = hw->reg + ENETC_SIRXIDR;

	enetc_refill_rx_ring(rx_ring, enetc_bd_unused(rx_ring));

	/* enable ring */
	enetc_rxbdr_wr(hw, idx, ENETC_RBMR, rbmr);
}

static void enetc_setup_bdrs(struct enetc_ndev_priv *priv)
{
	int i;

	for (i = 0; i < priv->num_tx_rings; i++)
		enetc_setup_txbdr(&priv->si->hw, priv->tx_ring[i]);

	for (i = 0; i < priv->num_rx_rings; i++)
		enetc_setup_rxbdr(&priv->si->hw, priv->rx_ring[i]);
}

static void enetc_clear_rxbdr(struct enetc_hw *hw, struct enetc_bdr *rx_ring)
{
	int idx = rx_ring->index;

	/* disable EN bit on ring */
	enetc_rxbdr_wr(hw, idx, ENETC_RBMR, 0);
}

static void enetc_clear_txbdr(struct enetc_hw *hw, struct enetc_bdr *tx_ring)
{
	int delay = 16, timeout = 1000;
	int idx = tx_ring->index;

	/* disable EN bit on ring */
	enetc_txbdr_wr(hw, idx, ENETC_TBMR, 0);

	/* wait for busy to clear */
	while (delay < timeout &&
	       enetc_txbdr_rd(hw, idx, ENETC_TBSR) & ENETC_TBSR_BUSY) {
		msleep(delay);
		delay *= 2;
	}

	if (delay >= timeout)
		pr_info("timeout for tx ring #%d clear\n", idx);
}

static void enetc_clear_bdrs(struct enetc_ndev_priv *priv)
{
	int i;

	for (i = 0; i < priv->num_tx_rings; i++)
		enetc_clear_txbdr(&priv->si->hw, priv->tx_ring[i]);

	for (i = 0; i < priv->num_rx_rings; i++)
		enetc_clear_rxbdr(&priv->si->hw, priv->rx_ring[i]);

	udelay(1);
}

int enetc_setup_irqs(struct enetc_ndev_priv *priv)
{
	struct pci_dev *pdev = priv->si->pdev;
	int i, j, err;

	for (i = 0; i < priv->bdr_int_num; i++) {
		int irq = pci_irq_vector(pdev, ENETC_BDR_INT_BASE_IDX + i);
		struct enetc_int_vector *v = priv->int_vector[i];
		int entry = ENETC_BDR_INT_BASE_IDX + i;
		struct enetc_hw *hw = &priv->si->hw;

		sprintf(v->name, "%s-rxtx%d", priv->ndev->name, i);
		err = rtdm_irq_request(&v->irq_handle, irq,
				enetc_msix, 0, v->name, v);
		if (err) {
			dev_err(priv->dev, "rtdm_irq_request() failed!\n");
			goto irq_err;
		}

		v->tbier_base = hw->reg + ENETC_BDR(TX, 0, ENETC_TBIER);
		v->rbier = hw->reg + ENETC_BDR(RX, i, ENETC_RBIER);

		enetc_wr(hw, ENETC_SIMSIRRV(i), entry);

		for (j = 0; j < v->count_tx_rings; j++) {
			int idx = v->tx_ring[j].index;

			enetc_wr(hw, ENETC_SIMSITRV(idx), entry);
		}
	}

	return 0;

irq_err:
	while (i--)
		free_irq(pci_irq_vector(pdev, ENETC_BDR_INT_BASE_IDX + i),
			 priv->int_vector[i]);

	return err;
}

void enetc_free_irqs(struct enetc_ndev_priv *priv)
{
	struct pci_dev *pdev = priv->si->pdev;
	int i;

	for (i = 0; i < priv->bdr_int_num; i++)
		free_irq(pci_irq_vector(pdev, ENETC_BDR_INT_BASE_IDX + i),
			 priv->int_vector[i]);
}

static void enetc_enable_interrupts(struct enetc_ndev_priv *priv)
{
	int i;

	/* enable Tx & Rx event indication */
	for (i = 0; i < priv->num_rx_rings; i++) {
		enetc_rxbdr_wr(&priv->si->hw, i,
			       ENETC_RBIER, ENETC_RBIER_RXTIE);
	}

	for (i = 0; i < priv->num_tx_rings; i++) {
		enetc_txbdr_wr(&priv->si->hw, i,
			       ENETC_TBIER, ENETC_TBIER_TXTIE);
	}
}

static void enetc_disable_interrupts(struct enetc_ndev_priv *priv)
{
	struct pci_dev *pdev = priv->si->pdev;
	int i;

	for (i = 0; i < priv->bdr_int_num; i++) {
		int irq = pci_irq_vector(pdev, ENETC_BDR_INT_BASE_IDX + i);

		synchronize_irq(irq);
	}

	for (i = 0; i < priv->num_tx_rings; i++)
		enetc_txbdr_wr(&priv->si->hw, i, ENETC_TBIER, 0);

	for (i = 0; i < priv->num_rx_rings; i++)
		enetc_rxbdr_wr(&priv->si->hw, i, ENETC_RBIER, 0);
}

static void adjust_link(struct net_device *ndev)
{
	struct phy_device *phydev = ndev->phydev;

	phy_print_status(phydev);
}

int enetc_open(struct rtnet_device *ndev)
{
	struct enetc_ndev_priv *priv = rtnetdev_priv(ndev);
	int err;

	if (priv->phy_node) {
		struct phy_device *phydev;

		phydev = of_phy_connect(priv->ndev, priv->phy_node,
				&adjust_link, 0, priv->if_mode);
		if (!phydev) {
			pr_info("could not attach to PHY\n");
			return -ENODEV;
		}

		phy_attached_info(phydev);
	}

	err = enetc_alloc_tx_resources(priv);
	if (err)
		goto err_alloc_tx;

	err = enetc_alloc_rx_resources(priv);
	if (err)
		goto err_alloc_rx;

	enetc_setup_bdrs(priv);

	if (priv->ndev->phydev)
		phy_start(priv->ndev->phydev);
	else
		rtnetif_carrier_on(ndev);

	enetc_enable_interrupts(priv);

	rt_stack_connect(ndev, &STACK_manager);

	rtnetif_start_queue(ndev);

	return 0;

err_alloc_rx:
	enetc_free_tx_resources(priv);
err_alloc_tx:

	return err;
}

int enetc_close(struct rtnet_device *ndev)
{
	struct enetc_ndev_priv *priv = rtnetdev_priv(ndev);

	rtnetif_stop_queue(ndev);

	enetc_disable_interrupts(priv);

	if (priv->ndev->phydev) {
		phy_stop(priv->ndev->phydev);
		phy_disconnect(priv->ndev->phydev);
	} else {
		rtnetif_carrier_off(ndev);
	}

	enetc_clear_bdrs(priv);

	enetc_free_rxtx_rings(priv);
	enetc_free_rx_resources(priv);
	enetc_free_tx_resources(priv);

	return 0;
}

int enetc_alloc_msix(struct enetc_ndev_priv *priv)
{
	struct pci_dev *pdev = priv->si->pdev;
	int size, v_tx_rings;
	int i, n, err, nvec;
	struct enetc_netdev_priv *npriv = netdev_priv(priv->ndev);

	nvec = ENETC_BDR_INT_BASE_IDX + priv->bdr_int_num;
	/* allocate MSIX for both messaging and Rx/Tx interrupts */
	n = pci_alloc_irq_vectors(pdev, nvec, nvec, PCI_IRQ_MSIX);

	if (n < 0)
		return n;

	if (n != nvec)
		return -EPERM;

	/* # of tx rings per int vector */
	v_tx_rings = priv->num_tx_rings / priv->bdr_int_num;
	size = sizeof(struct enetc_int_vector) +
	       sizeof(struct enetc_bdr) * v_tx_rings;

	for (i = 0; i < priv->bdr_int_num; i++) {
		struct enetc_int_vector *v;
		struct enetc_bdr *bdr;
		int j;

		v = kzalloc(size, GFP_KERNEL);
		if (!v) {
			err = -ENOMEM;
			goto fail;
		}

		priv->int_vector[i] = v;

		v->count_tx_rings = v_tx_rings;

		for (j = 0; j < v_tx_rings; j++) {
			int idx;

			/* default tx ring mapping policy */
			if (priv->bdr_int_num == ENETC_MAX_BDR_INT)
				idx = 2 * j + i; /* 2 CPUs */
			else
				idx = j + i * v_tx_rings; /* default */

			__set_bit(idx, &v->tx_rings_map);
			bdr = &v->tx_ring[j];
			bdr->index = idx;
			bdr->ndev = npriv->rtdev;
			bdr->dev = priv->dev;
			bdr->bd_count = priv->tx_bd_count;
			priv->tx_ring[idx] = bdr;
		}

		bdr = &v->rx_ring;
		bdr->index = i;
		bdr->ndev = npriv->rtdev;
		bdr->dev = priv->dev;
		bdr->bd_count = priv->rx_bd_count;
		priv->rx_ring[i] = bdr;
	}

	return 0;

fail:
	while (i--)
		rtdm_free(priv->int_vector[i]);

	pci_free_irq_vectors(pdev);

	return err;
}

void enetc_free_msix(struct enetc_ndev_priv *priv)
{
	int i;

	for (i = 0; i < priv->num_rx_rings; i++)
		priv->rx_ring[i] = NULL;

	for (i = 0; i < priv->num_tx_rings; i++)
		priv->tx_ring[i] = NULL;

	for (i = 0; i < priv->bdr_int_num; i++) {
		rtdm_free(priv->int_vector[i]);
		priv->int_vector[i] = NULL;
	}

	/* disable all MSIX for this device */
	pci_free_irq_vectors(priv->si->pdev);
}

static void enetc_kfree_si(struct enetc_si *si)
{
	char *p = (char *)si - si->pad;

	rtdm_free(p);
}

static void enetc_detect_errata(struct enetc_si *si)
{
	if (si->pdev->revision == ENETC_REV1)
		si->errata = ENETC_ERR_TXCSUM | ENETC_ERR_VLAN_ISOL |
			     ENETC_ERR_UCMCSWP | ENETC_ERR_TXSG;
}

int enetc_pci_probe(struct pci_dev *pdev, const char *name, int sizeof_priv)
{
	struct enetc_si *si, *p;
	struct enetc_hw *hw;
	size_t alloc_size;
	int err, len;

	pcie_flr(pdev);
	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev, "device enable failed\n");
		return err;
	}

	/* set up for high or low dma */
	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev,
				"DMA configuration failed: 0x%x\n", err);
			goto err_dma;
		}
	}

	err = pci_request_mem_regions(pdev, name);
	if (err) {
		dev_err(&pdev->dev, "pci_request_regions failed err=%d\n", err);
		goto err_pci_mem_reg;
	}

	pci_set_master(pdev);

	alloc_size = sizeof(struct enetc_si);
	if (sizeof_priv) {
		/* align priv to 32B */
		alloc_size = ALIGN(alloc_size, ENETC_SI_ALIGN);
		alloc_size += sizeof_priv;
	}
	/* force 32B alignment for enetc_si */
	alloc_size += ENETC_SI_ALIGN - 1;

	p = kzalloc(alloc_size, GFP_KERNEL);
	if (!p) {
		err = -ENOMEM;
		goto err_alloc_si;
	}

	si = PTR_ALIGN(p, ENETC_SI_ALIGN);
	si->pad = (char *)si - (char *)p;

	pci_set_drvdata(pdev, si);
	si->pdev = pdev;
	hw = &si->hw;

	len = pci_resource_len(pdev, ENETC_BAR_REGS);
	hw->reg = ioremap(pci_resource_start(pdev, ENETC_BAR_REGS), len);
	if (!hw->reg) {
		err = -ENXIO;
		dev_err(&pdev->dev, "ioremap() failed\n");
		goto err_ioremap;
	}
	if (len > ENETC_PORT_BASE)
		hw->port = hw->reg + ENETC_PORT_BASE;
	if (len > ENETC_GLOBAL_BASE)
		hw->global = hw->reg + ENETC_GLOBAL_BASE;

	enetc_detect_errata(si);

	return 0;

err_ioremap:
	enetc_kfree_si(si);
err_alloc_si:
	pci_release_mem_regions(pdev);
err_pci_mem_reg:
err_dma:
	pci_disable_device(pdev);

	return err;
}

void enetc_pci_remove(struct pci_dev *pdev)
{
	struct enetc_si *si = pci_get_drvdata(pdev);
	struct enetc_hw *hw = &si->hw;

	iounmap(hw->reg);
	enetc_kfree_si(si);
	pci_release_mem_regions(pdev);
	pci_disable_device(pdev);
}
