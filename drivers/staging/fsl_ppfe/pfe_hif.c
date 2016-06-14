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

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/slab.h>

#include <asm/io.h>
#include <asm/irq.h>
#else
#include "platform.h"
#endif


#include "pfe_mod.h"
#if 0
#define DMA_MAP_SINGLE(dev, vaddr, size, direction)	dma_map_single(dev, vaddr, size, direction)
#define DMA_UNMAP_SINGLE(dev, vaddr, size, direction)	dma_unmap_single(dev, vaddr, size, direction)
void ct_flush(void *addr, u32 size)
{
	dma_map_single(pfe->dev, addr, size, DMA_TO_DEVICE);
}
#else
#define DMA_UNMAP_SINGLE(dev, vaddr, size, direction)
#define DMA_MAP_SINGLE(dev, vaddr, size, direction)	virt_to_phys(vaddr)
#define ct_flush(addr, sz)
#endif

#define HIF_INT_MASK	(HIF_INT | HIF_RXPKT_INT)

#define inc_cl_idx(idxname) idxname = (idxname+1) & (queue->size-1)
#define inc_hif_rxidx(idxname) idxname = (idxname+1) & (hif->RxRingSize-1)
#define inc_hif_txidx(idxname) idxname = (idxname+1) & (hif->TxRingSize-1)

unsigned char napi_first_batch = 0;

static int pfe_hif_alloc_descr(struct pfe_hif *hif)
{
#if !defined(CONFIG_PLATFORM_PCI)
	void *addr;
	dma_addr_t dma_addr;
	int err = 0;

	printk(KERN_INFO "%s\n", __func__);
	addr = dma_alloc_coherent(pfe->dev,
			HIF_RX_DESC_NT * sizeof(struct hif_desc) + HIF_TX_DESC_NT * sizeof(struct hif_desc),
			&dma_addr, GFP_KERNEL);

	if (!addr) {
		printk(KERN_ERR "%s: Could not allocate buffer descriptors!\n", __func__);
		err = -ENOMEM;
		goto err0;
	}

	hif->descr_baseaddr_p = dma_addr;
	hif->descr_baseaddr_v = addr;
#else
	hif->descr_baseaddr_p = pfe->ddr_phys_baseaddr + HIF_DESC_BASEADDR;
	hif->descr_baseaddr_v = pfe->ddr_baseaddr + HIF_DESC_BASEADDR;
#endif
	hif->RxRingSize = HIF_RX_DESC_NT;
	hif->TxRingSize = HIF_TX_DESC_NT;

	return 0;

err0:
	return err;
}

static void pfe_hif_free_descr(struct pfe_hif *hif)
{
	printk(KERN_INFO "%s\n", __func__);
#if !defined(CONFIG_PLATFORM_PCI)
	dma_free_coherent(pfe->dev,
			hif->RxRingSize * sizeof(struct hif_desc) + hif->TxRingSize * sizeof(struct hif_desc),
			hif->descr_baseaddr_v, hif->descr_baseaddr_p);
#endif
}
void pfe_hif_desc_dump(struct pfe_hif *hif)
{
	struct hif_desc	*desc;
	unsigned long desc_p;
	int ii=0;

	printk(KERN_INFO "%s\n", __func__);

	desc = hif->RxBase;
	desc_p = (u32)((u64)desc - (u64)hif->descr_baseaddr_v + hif->descr_baseaddr_p);

	printk("HIF Rx desc base %p physical %x\n", desc, (u32)desc_p);
	for (ii = 0; ii < hif->RxRingSize; ii++) {
		printk(KERN_INFO "status: %08x, ctrl: %08x, data: %08x, next: %x\n",
				desc->status, desc->ctrl, desc->data, desc->next);
		desc++;
	}

	desc = hif->TxBase;
	desc_p = ((u64)desc - (u64)hif->descr_baseaddr_v + hif->descr_baseaddr_p);

	printk("HIF Tx desc base %p physical %x\n", desc, (u32)desc_p);
	for (ii = 0; ii < hif->TxRingSize; ii++) {
		printk(KERN_INFO "status: %08x, ctrl: %08x, data: %08x, next: %x\n",
				desc->status, desc->ctrl, desc->data, desc->next);
		desc++;
	}

}

/* pfe_hif_release_buffers
 *
 */
static void pfe_hif_release_buffers(struct pfe_hif *hif)
{
	struct hif_desc	*desc;
	int i = 0;

	hif->RxBase = hif->descr_baseaddr_v;

	printk(KERN_INFO "%s\n", __func__);
	/*Free Rx buffers */
#if !defined(CONFIG_PLATFORM_PCI)
	desc = hif->RxBase;
	for (i = 0; i < hif->RxRingSize; i++) {
		if (desc->data) {
			if ((i < hif->shm->rx_buf_pool_cnt) && (hif->shm->rx_buf_pool[i] == NULL)) {
				//dma_unmap_single(hif->dev, desc->data,  hif->rx_buf_len[i], DMA_FROM_DEVICE);
				DMA_UNMAP_SINGLE(hif->dev, desc->data,  hif->rx_buf_len[i], DMA_FROM_DEVICE);
				hif->shm->rx_buf_pool[i] = hif->rx_buf_addr[i];
			}
			else {
				/*TODO This should not happen*/
				printk(KERN_ERR "%s: buffer pool already full\n", __func__);
			}
		}

		desc->data = 0;
		desc->status = 0;
		desc->ctrl =  0;
		desc++;
	}
#endif
}


/*
 * pfe_hif_init_buffers
 * This function initializes the HIF Rx/Tx ring descriptors and
 * initialize Rx queue with buffers.
 */
static int pfe_hif_init_buffers(struct pfe_hif *hif)
{
	struct hif_desc	*desc, *first_desc_p;
	u32 data;
	int i = 0;

	printk(KERN_INFO "%s\n", __func__);

	/* Check enough Rx buffers available in the shared memory */
	if (hif->shm->rx_buf_pool_cnt < hif->RxRingSize)
		return -ENOMEM;

	hif->RxBase = hif->descr_baseaddr_v;
	memset(hif->RxBase, 0, hif->RxRingSize * sizeof(struct hif_desc));

	/*Initialize Rx descriptors */
	desc = hif->RxBase;
	first_desc_p = (struct hif_desc *)hif->descr_baseaddr_p;

	for (i = 0; i < hif->RxRingSize; i++) {
		/* Initialize Rx buffers from the shared memory */

#if defined(CONFIG_PLATFORM_PCI)
		data = pfe->ddr_phys_baseaddr + HIF_RX_PKT_DDR_BASEADDR + i * DDR_BUF_SIZE;
#else
		data = (u32)DMA_MAP_SINGLE(hif->dev, hif->shm->rx_buf_pool[i], pfe_pkt_size, DMA_FROM_DEVICE);
		hif->rx_buf_addr[i] = hif->shm->rx_buf_pool[i];
		hif->rx_buf_len[i] = pfe_pkt_size;
	//	printk("#%d %p %p %d\n", i, data, hif->rx_buf_addr[i], hif->rx_buf_len[i]);
		hif->shm->rx_buf_pool[i] = NULL;
#endif
		if (likely(dma_mapping_error(hif->dev, data) == 0)) {
			desc->data = DDR_PHYS_TO_PFE(data);
		} else {
			printk(KERN_ERR "%s : low on mem\n",  __func__);

			goto err;
		}

		desc->status = 0;
		wmb();
		desc->ctrl = BD_CTRL_PKT_INT_EN | BD_CTRL_LIFM | BD_CTRL_DIR |
			BD_CTRL_DESC_EN | BD_BUF_LEN(pfe_pkt_size);
		/* Chain descriptors */
		desc->next = (u32)DDR_PHYS_TO_PFE(first_desc_p + i + 1);
		desc++;
	}

	/* Overwrite last descriptor to chain it to first one*/
	desc--;
	desc->next = (u32)DDR_PHYS_TO_PFE(first_desc_p);

	hif->RxtocleanIndex = 0;

	/*Initialize Rx buffer descriptor ring base address */
	writel(DDR_PHYS_TO_PFE(hif->descr_baseaddr_p), HIF_RX_BDP_ADDR);

	hif->TxBase = hif->RxBase + hif->RxRingSize;
	first_desc_p = (struct hif_desc *)hif->descr_baseaddr_p + hif->RxRingSize;
	memset(hif->TxBase, 0, hif->TxRingSize * sizeof(struct hif_desc));

	/*Initialize tx descriptors */
	desc = hif->TxBase;

	for (i = 0; i < hif->TxRingSize; i++) {
		/* Chain descriptors */
		desc->next = (u32)DDR_PHYS_TO_PFE(first_desc_p + i + 1);
#if defined(CONFIG_PLATFORM_PCI)
		desc->data =  pfe->ddr_phys_baseaddr + HIF_TX_PKT_DDR_BASEADDR + i * DDR_BUF_SIZE;
#endif
		desc->ctrl = 0;
		desc++;
	}

	/* Overwrite last descriptor to chain it to first one */
	desc--;
	desc->next = (u32)DDR_PHYS_TO_PFE(first_desc_p);
	hif->TxAvail = hif->TxRingSize;
	hif->Txtosend = 0;
	hif->Txtoclean = 0;
	hif->Txtoflush = 0;

	/*Initialize Tx buffer descriptor ring base address */
	writel((u32)DDR_PHYS_TO_PFE(first_desc_p), HIF_TX_BDP_ADDR);

	return 0;

err:
	pfe_hif_release_buffers(hif);
	return -ENOMEM;
}

/* pfe_hif_client_register
 *
 * This function used to register a client driver with the HIF driver.
 *
 * Return value:
 * 0 - on Successful registration
 */
static int pfe_hif_client_register(struct pfe_hif *hif, u32 client_id, struct hif_client_shm *client_shm)
{
	struct hif_client *client = &hif->client[client_id];
	u32 i, cnt;
	struct rx_queue_desc *rx_qbase;
	struct tx_queue_desc *tx_qbase;
	struct hif_rx_queue *rx_queue;
	struct hif_tx_queue *tx_queue;
	int err = 0;

	printk(KERN_INFO "%s\n", __func__);

	spin_lock_bh(&hif->tx_lock);

	if (test_bit(client_id, &hif->shm->gClient_status[0])) {
		printk(KERN_ERR "%s: client %d already registered\n", __func__, client_id);
		err = -1;
		goto unlock;
	}

	memset(client, 0, sizeof(struct hif_client));

	/*Initialize client Rx queues baseaddr, size */

	cnt = CLIENT_CTRL_RX_Q_CNT(client_shm->ctrl);
	/*Check if client is requesting for more queues than supported */
	if (cnt > HIF_CLIENT_QUEUES_MAX)
		cnt = HIF_CLIENT_QUEUES_MAX;

	client->rx_qn = cnt;
	rx_qbase = (struct rx_queue_desc *)client_shm->rx_qbase;
	for (i = 0; i < cnt; i++)
	{
		rx_queue = &client->rx_q[i];
		rx_queue->base = rx_qbase + i * client_shm->rx_qsize;
		rx_queue->size = client_shm->rx_qsize;
		rx_queue->write_idx = 0;
	}

	/*Initialize client Tx queues baseaddr, size */
	cnt = CLIENT_CTRL_TX_Q_CNT(client_shm->ctrl);

	/*Check if client is requesting for more queues than supported */
	if (cnt > HIF_CLIENT_QUEUES_MAX)
		cnt = HIF_CLIENT_QUEUES_MAX;

	client->tx_qn = cnt;
	tx_qbase = (struct tx_queue_desc *)client_shm->tx_qbase;
	for (i = 0; i < cnt; i++)
	{
		tx_queue = &client->tx_q[i];
		tx_queue->base = tx_qbase + i * client_shm->tx_qsize;
		tx_queue->size = client_shm->tx_qsize;
		tx_queue->ack_idx = 0;
	}

	set_bit(client_id, &hif->shm->gClient_status[0]);

unlock:
	spin_unlock_bh(&hif->tx_lock);

	return err;
}


/* pfe_hif_client_unregister
 *
 * This function used to unregister a client  from the HIF driver.
 *
 */
static void pfe_hif_client_unregister(struct pfe_hif *hif, u32 client_id)
{
	printk(KERN_INFO "%s\n", __func__);

	/* Mark client as no longer available (which prevents further packet receive for this client) */
	spin_lock_bh(&hif->tx_lock);

	if (!test_bit(client_id, &hif->shm->gClient_status[0])) {
		printk(KERN_ERR "%s: client %d not registered\n", __func__, client_id);

		spin_unlock_bh(&hif->tx_lock);
		return;
	}

	clear_bit(client_id, &hif->shm->gClient_status[0]);

	spin_unlock_bh(&hif->tx_lock);
}

/* client_put_rxpacket-
 * This functions puts the Rx pkt  in the given client Rx queue.
 * It actually swap the Rx pkt in the client Rx descriptor buffer
 * and returns the free buffer from it.
 *
 * If the funtion returns NULL means client Rx queue is full and
 * packet couldn't send to client queue.
 */
static void *client_put_rxpacket(struct hif_rx_queue *queue, void *pkt, u32 len, u32 flags, u32 client_ctrl, u32 *rem_len)
{
	void *free_pkt = NULL;
	struct rx_queue_desc *desc = queue->base + queue->write_idx;

	if (desc->ctrl & CL_DESC_OWN) {
#if defined(CONFIG_PLATFORM_PCI)
		memcpy(desc->data, pkt, len);
		free_pkt = PFE_HOST_TO_PCI(pkt);
		smp_wmb();
		desc->ctrl = CL_DESC_BUF_LEN(len) | flags;
		inc_cl_idx(queue->write_idx);
#else
		//TODO: move allocations after Rx loop to improve instruction cache locality
		if (page_mode) {
			int rem_page_size = PAGE_SIZE -  PRESENT_OFST_IN_PAGE(pkt);
			int cur_pkt_size = ROUND_MIN_RX_SIZE(len +  pfe_pkt_headroom);
			*rem_len = (rem_page_size - cur_pkt_size);
			//printk("%p rem_len %d cur_len %d buf_len %d\n", pkt, rem_page_size, cur_pkt_size, *rem_len);
			if (*rem_len)
			{
				free_pkt = pkt + cur_pkt_size;
				get_page(virt_to_page(free_pkt));
			} else {
				free_pkt = (void *)__get_free_page(GFP_ATOMIC | GFP_DMA_PFE);
				*rem_len = pfe_pkt_size;
			}
		} else {
			free_pkt = kmalloc(PFE_BUF_SIZE, GFP_ATOMIC | GFP_DMA_PFE);
			*rem_len = PFE_BUF_SIZE - pfe_pkt_headroom;
		}

		if (free_pkt) {
			desc->data = pkt;
			desc->client_ctrl = client_ctrl;
			smp_wmb();
			desc->ctrl = CL_DESC_BUF_LEN(len) | flags;
			inc_cl_idx(queue->write_idx);
			free_pkt += pfe_pkt_headroom;
		}
#endif
	}

	return free_pkt;
}


/* pfe_hif_rx_process-
 * This function does pfe hif rx queue processing.
 * Dequeue packet from Rx queue and send it to corresponding client queue 
 */
static int pfe_hif_rx_process(struct pfe_hif *hif, int budget)
{
	struct hif_desc	*desc;
	struct hif_hdr *pkt_hdr;
	struct __hif_hdr hif_hdr;
	void *free_buf;
	int rtc, len, rx_processed = 0;
	struct __hif_desc local_desc;
	int flags;
	unsigned int desc_p;
	unsigned int buf_size = 0;

	spin_lock_bh(&hif->lock);

	rtc = hif->RxtocleanIndex;

	while (rx_processed < budget)
	{
		/*TODO may need to implement rx process budget */
		desc = hif->RxBase + rtc;

		__memcpy12(&local_desc, desc);

		/* ACK pending Rx interrupt */
		if (local_desc.ctrl & BD_CTRL_DESC_EN) {
			writel(HIF_INT_MASK, HIF_INT_SRC);

			if(rx_processed == 0)
			{
				if(napi_first_batch == 1)
				{
					desc_p = hif->descr_baseaddr_p + ((unsigned long int)(desc) - (unsigned long int)hif->descr_baseaddr_v);
#if defined(CONFIG_PLATFORM_C2000)
					outer_inv_range(desc_p, (desc_p + 16));
#endif
					napi_first_batch = 0;
				}
			}

			__memcpy12(&local_desc, desc);

			if (local_desc.ctrl & BD_CTRL_DESC_EN)
				break;
		}

		napi_first_batch = 0;

#ifdef HIF_NAPI_STATS
		hif->napi_counters[NAPI_DESC_COUNT]++;
#endif
		len = BD_BUF_LEN(local_desc.ctrl);
#if defined(CONFIG_PLATFORM_PCI)
		pkt_hdr = &hif_hdr;
		memcpy(pkt_hdr, (void *)PFE_PCI_TO_HOST(local_desc.data), sizeof(struct hif_hdr));
#else
		//dma_unmap_single(hif->dev, DDR_PFE_TO_PHYS(local_desc.data),  hif->rx_buf_len[rtc], DMA_FROM_DEVICE);
		DMA_UNMAP_SINGLE(hif->dev, DDR_PFE_TO_PHYS(local_desc.data),  hif->rx_buf_len[rtc], DMA_FROM_DEVICE);

		pkt_hdr = (struct hif_hdr *)hif->rx_buf_addr[rtc];

		/* Track last HIF header received */
		if (!hif->started) {
			hif->started = 1;

			__memcpy8(&hif_hdr, pkt_hdr);

			hif->qno = hif_hdr.hdr.qNo;
			hif->client_id = hif_hdr.hdr.client_id;
			hif->client_ctrl = (hif_hdr.hdr.client_ctrl1 << 16) | hif_hdr.hdr.client_ctrl;
			flags = CL_DESC_FIRST;

//			printk(KERN_INFO "start of packet: id %d, q %d, len %d, flags %x %x\n", hif->client_id, hif->qno, len, local_desc.ctrl, hif->client_ctrl);
		}
		else {
//			printk(KERN_INFO "continuation: id %d, q %d, len %d, flags %x\n", hif->client_id, hif->qno, len, local_desc.ctrl);
			flags = 0;
		}

		if (local_desc.ctrl & BD_CTRL_LIFM)
			flags |= CL_DESC_LAST;
#endif
		/* Check for valid client id and still registered */
		if ((hif->client_id >= HIF_CLIENTS_MAX) || !(test_bit(hif->client_id, &hif->shm->gClient_status[0]))) {
			if (printk_ratelimit())
				printk(KERN_ERR "%s: packet with invalid client id %d qNo %d\n", __func__, hif->client_id, hif->qno);

#if defined(CONFIG_PLATFORM_PCI)
			free_buf = local_desc.data;
#else
			free_buf = pkt_hdr;
#endif
			goto pkt_drop;
		}

		/* Check to valid queue number */
		if (hif->client[hif->client_id].rx_qn <= hif->qno) {
			printk(KERN_INFO "%s: packet with invalid queue: %d\n", __func__, hif->qno);
			hif->qno = 0;
		}

#if defined(CONFIG_PLATFORM_PCI)
		free_buf = client_put_rxpacket(&hif->client[hif->client_id].rx_q[hif->qno],
				(void *)PFE_PCI_TO_HOST(desc->data), len, flags, hif->client_ctrl, &buf_zize);
#else
		free_buf = client_put_rxpacket(&hif->client[hif->client_id].rx_q[hif->qno],
				(void *)pkt_hdr, len, flags, hif->client_ctrl, &buf_size);
#endif

		hif_lib_indicate_client(hif->client_id, EVENT_RX_PKT_IND, hif->qno);

		if (unlikely(!free_buf)) {
#ifdef HIF_NAPI_STATS
			hif->napi_counters[NAPI_CLIENT_FULL_COUNT]++;
#endif
			/* If we want to keep in polling mode to retry later, we need to tell napi that we consumed
			the full budget or we will hit a livelock scenario. The core code keeps this napi instance
			at the head of the list and none of the other instances get to run */
			rx_processed = budget;

			if (flags & CL_DESC_FIRST)
				hif->started = 0;

			break;
		}

	pkt_drop:
#if defined(CONFIG_PLATFORM_PCI)
		desc->data = (u32)free_buf;
#else
		/*Fill free buffer in the descriptor */
		hif->rx_buf_addr[rtc] = free_buf;
		hif->rx_buf_len[rtc] = min(pfe_pkt_size, buf_size);
		desc->data = DDR_PHYS_TO_PFE((u32)DMA_MAP_SINGLE(hif->dev, free_buf, hif->rx_buf_len[rtc], DMA_FROM_DEVICE));
		//printk("#%p %p %d\n", desc->data, hif->rx_buf_addr[rtc], hif->rx_buf_len[rtc]);
#endif
		wmb();
		desc->ctrl = BD_CTRL_PKT_INT_EN | BD_CTRL_LIFM | BD_CTRL_DIR |
			BD_CTRL_DESC_EN | BD_BUF_LEN(hif->rx_buf_len[rtc]);

		inc_hif_rxidx(rtc);

		if (local_desc.ctrl & BD_CTRL_LIFM) {
			if (!(hif->client_ctrl & HIF_CTRL_RX_CONTINUED)) {
				rx_processed++;

#ifdef HIF_NAPI_STATS
				hif->napi_counters[NAPI_PACKET_COUNT]++;
#endif
			}
			hif->started = 0;
		}
	}

	hif->RxtocleanIndex = rtc;
	spin_unlock_bh(&hif->lock);

	/* we made some progress, re-start rx dma in case it stopped */
	hif_rx_dma_start();

	return rx_processed;
}


/* client_ack_txpacket-
 * This function ack the Tx packet in the give client Tx queue by resetting
 * ownership bit in the descriptor.
 */
static int client_ack_txpacket(struct pfe_hif *hif, unsigned int client_id, unsigned int q_no)
{
	struct hif_tx_queue *queue = &hif->client[client_id].tx_q[q_no];
	struct tx_queue_desc *desc = queue->base + queue->ack_idx;

	if (desc->ctrl & CL_DESC_OWN) {
		/*TODO Do we need to match the pkt address also? */
		desc->ctrl &= ~CL_DESC_OWN;
		inc_cl_idx(queue->ack_idx);

		return 0;
	}
	else {
		/*This should not happen */
		printk(KERN_ERR "%s: %d %d %d %d %d %p %d\n", __func__, hif->Txtosend, hif->Txtoclean, hif->TxAvail, client_id, q_no, queue, queue->ack_idx);
		BUG();
		return 1;
	}
}

void __hif_tx_done_process(struct pfe_hif *hif, int count)
{
	struct hif_desc *desc;
	struct hif_desc_sw *desc_sw;
	int ttc, tx_avl;

	ttc = hif->Txtoclean;
	tx_avl = hif->TxAvail;

	while ((tx_avl < hif->TxRingSize) && count--) {
		desc = hif->TxBase + ttc;

		if (desc->ctrl & BD_CTRL_DESC_EN)
			break;

		desc_sw = &hif->tx_sw_queue[ttc];

		if (desc_sw->data) {
#if !defined(CONFIG_PLATFORM_PCI)
			//dmap_unmap_single(hif->dev, desc_sw->data, desc_sw->len, DMA_TO_DEVICE);
			DMA_UNMAP_SINGLE(hif->dev, desc_sw->data, desc_sw->len, DMA_TO_DEVICE);
#endif
		}
		client_ack_txpacket(hif, desc_sw->client_id, desc_sw->q_no);

		inc_hif_txidx(ttc);
		tx_avl++;
	}

	hif->Txtoclean = ttc;
	hif->TxAvail = tx_avl;
}


/* __hif_xmit_pkt -
 * This function puts one packet in the HIF Tx queue
 */
void __hif_xmit_pkt(struct pfe_hif *hif, unsigned int client_id, unsigned int q_no, void *data, u32 len, unsigned int flags)
{
	struct hif_desc	*desc;
	struct hif_desc_sw *desc_sw;

#if defined(CONFIG_PLATFORM_EMULATION)
	{
		struct hif_queue *queue = &hif->client[client_id].rx_q[0];
		struct queue_desc *qdesc = queue->base + queue->write_idx;
		void *buf;

		printk("%s: packet loop backed client_id:%d qno:%d data : %p len:%d\n", __func__, client_id, q_no, data, len);
#if 1
		if (qdesc->ctrl & CL_DESC_OWN) {
			buf = (void *)qdesc->data;
			memcpy(buf, data, len);
			wmb();
			qdesc->ctrl = CL_DESC_BUF_LEN(len);
			inc_cl_idx(queue->write_idx);
			printk("%s: packet loop backed..\n", __func__);
			hif_lib_indicate_client(client_id, EVENT_RX_PKT_IND, q_no);
			client_ack_txpacket(&hif->client[client_id].tx_q[q_no]);
		}
#endif
	}

#else
	desc = hif->TxBase + hif->Txtosend;
	desc_sw = &hif->tx_sw_queue[hif->Txtosend];

	desc_sw->len = len;
	desc_sw->client_id = client_id;
	desc_sw->q_no = q_no;
	desc_sw->flags = flags;

#if !defined(CONFIG_PLATFORM_PCI)
	if (flags & HIF_DONT_DMA_MAP) {
		desc_sw->data = 0;
		desc->data = (u32)DDR_PHYS_TO_PFE(data);
	} else {
		desc_sw->data = DMA_MAP_SINGLE(hif->dev, data, len, DMA_TO_DEVICE);
		desc->data = (u32)DDR_PHYS_TO_PFE(desc_sw->data);
	}
#else
#define ALIGN32(x)	((x) & ~0x3)
	memcpy(PFE_PCI_TO_HOST(desc->data), data, ALIGN32(len+0x3));
#endif

	inc_hif_txidx(hif->Txtosend);
	hif->TxAvail--;

	/* For TSO we skip actual TX until the last descriptor */
	/* This reduce the number of required wmb() */
	if ((flags & HIF_TSO) && (!((flags & HIF_DATA_VALID) && (flags & HIF_LAST_BUFFER))))
		goto skip_tx;

	wmb();

	do {
		desc_sw = &hif->tx_sw_queue[hif->Txtoflush];
		desc = hif->TxBase + hif->Txtoflush;

		if (desc_sw->flags & HIF_LAST_BUFFER) {
			if ((desc_sw->client_id < PFE_CL_VWD0) || (desc_sw->client_id > (PFE_CL_VWD0 + MAX_VAP_SUPPORT)))
				desc->ctrl = BD_CTRL_LIFM | BD_CTRL_BRFETCH_DISABLE |
						BD_CTRL_RTFETCH_DISABLE | BD_CTRL_PARSE_DISABLE |
						BD_CTRL_DESC_EN | BD_BUF_LEN(desc_sw->len);
			else {

				desc->ctrl = BD_CTRL_LIFM | BD_CTRL_DESC_EN | BD_BUF_LEN(desc_sw->len);
			}
		}
		else
			desc->ctrl = BD_CTRL_DESC_EN | BD_BUF_LEN(desc_sw->len);

		inc_hif_txidx(hif->Txtoflush);
	}
	while (hif->Txtoflush != hif->Txtosend);

skip_tx:
	return;

#endif
}


int hif_xmit_pkt(struct pfe_hif *hif, unsigned int client_id, unsigned int q_no, void *data, unsigned int len)
{
	int rc = 0;

	spin_lock_bh(&hif->tx_lock);

	if (!hif->TxAvail)
		rc = 1;
	else {
		__hif_xmit_pkt(hif, client_id, q_no, data, len, HIF_FIRST_BUFFER | HIF_LAST_BUFFER);
		hif_tx_dma_start();
	}
	if (hif->TxAvail < (hif->TxRingSize >> 1))
		__hif_tx_done_process(hif, TX_FREE_MAX_COUNT);

	spin_unlock_bh(&hif->tx_lock);

	return rc;
}

/* hif_isr-
 * This ISR routine processes Rx/Tx done interrupts from the HIF hardware block
 */
static irqreturn_t hif_isr(int irq, void *dev_id)
{
	struct pfe_hif *hif = (struct pfe_hif *) dev_id;
	int int_status;

	/*Read hif interrupt source register */
	int_status = readl_relaxed(HIF_INT_SRC);

	if ((int_status & HIF_INT) == 0)
		return(IRQ_NONE);

	int_status &= ~(HIF_INT);

	if (int_status & HIF_RXPKT_INT) {
		int_status &= ~(HIF_RXPKT_INT);

		/* Disable interrupts */
		writel_relaxed(0, HIF_INT_ENABLE);
		
		napi_first_batch = 1;
		
		if (napi_schedule_prep(&hif->napi))
		{
#ifdef HIF_NAPI_STATS
			hif->napi_counters[NAPI_SCHED_COUNT]++;
#endif
			__napi_schedule(&hif->napi);
		}
	}

	if (int_status) {
		printk(KERN_INFO "%s : Invalid interrupt : %d\n", __func__, int_status);
		writel(int_status, HIF_INT_SRC);
	}

	return IRQ_HANDLED;
}


void hif_process_client_req(struct pfe_hif *hif, int req, int data1, int data2)
{
	unsigned int client_id = data1;

	if (client_id >= HIF_CLIENTS_MAX)
	{
		printk(KERN_ERR "%s: client id %d out of bounds\n", __func__, client_id);
		return;
	}

	switch (req) {
		case REQUEST_CL_REGISTER:
			/* Request for register a client */
			printk(KERN_INFO "%s: register client_id %d\n", __func__, client_id);
			pfe_hif_client_register(hif, client_id, (struct hif_client_shm *)&hif->shm->client[client_id]);
			break;

		case REQUEST_CL_UNREGISTER:
			printk(KERN_INFO "%s: unregister client_id %d\n", __func__, client_id);

			/* Request for unregister a client */
			pfe_hif_client_unregister(hif, client_id);

			break;

		default:
			printk(KERN_ERR "%s: unsupported request %d\n", __func__, req);
			break;
	}

	/*TODO check for TMU queue resume request */

	/*Process client Tx queues
	 * Currently we don't have checking for tx pending*/
}

/** pfe_hif_rx_poll
 *  This function is NAPI poll function to process HIF Rx queue.
 */
static int pfe_hif_rx_poll(struct napi_struct *napi, int budget)
{
	struct pfe_hif *hif = container_of(napi, struct pfe_hif, napi);
	int work_done;

#ifdef HIF_NAPI_STATS
	hif->napi_counters[NAPI_POLL_COUNT]++;
#endif

	work_done = pfe_hif_rx_process(hif, budget);

	if (work_done < budget)
	{
		napi_complete(napi);
		writel_relaxed(HIF_INT_MASK, HIF_INT_ENABLE);
	}
#ifdef HIF_NAPI_STATS
	else
		hif->napi_counters[NAPI_FULL_BUDGET_COUNT]++;
#endif

	return work_done;
}

/* pfe_hif_init
 * This function initializes the baseaddresses and irq, etc.
 */
int pfe_hif_init(struct pfe *pfe)
{
	struct pfe_hif *hif = &pfe->hif;
	int err;

	printk(KERN_INFO "%s\n", __func__);

	hif->dev = pfe->dev;
	hif->irq = pfe->hif_irq;

	if ((err = pfe_hif_alloc_descr(hif))) {
		goto err0;
	}

	if (pfe_hif_init_buffers(hif)) { 
		printk(KERN_ERR "%s: Could not initialize buffer descriptors\n", __func__);
		err = -ENOMEM;
		goto err1;
	}

	/* Initilize NAPI for Rx processing */
	init_dummy_netdev(&hif->dummy_dev);
	netif_napi_add(&hif->dummy_dev, &hif->napi, pfe_hif_rx_poll, HIF_RX_POLL_WEIGHT);
	napi_enable(&hif->napi);

	spin_lock_init(&hif->tx_lock);
	spin_lock_init(&hif->lock);

	hif_init();
	hif_rx_enable();
	hif_tx_enable();

	/* Disable tx done interrupt */
	writel(HIF_INT_MASK, HIF_INT_ENABLE);

	gpi_enable(HGPI_BASE_ADDR);

#ifdef __KERNEL__
	err = request_irq(hif->irq, hif_isr, 0, "pfe_hif", hif);
	if (err) {
		printk(KERN_ERR "%s: failed to get the hif IRQ = %d\n",  __func__, hif->irq);
		goto err1;
	}
#else
	/*TODO register interrupts */
#endif

	return 0;
err1:
	pfe_hif_free_descr(hif);
err0:
	return err;
}

/* pfe_hif_exit-
 */
void pfe_hif_exit(struct pfe *pfe)
{
	struct pfe_hif *hif = &pfe->hif;

	printk(KERN_INFO "%s\n", __func__);

	spin_lock_bh(&hif->lock);
	hif->shm->gClient_status[0] = 0;
	hif->shm->gClient_status[1] = 0; /* Make sure all clients are disabled */

	spin_unlock_bh(&hif->lock);

	/*Disable Rx/Tx */
	gpi_disable(HGPI_BASE_ADDR);
	hif_rx_disable();
	hif_tx_disable();

	napi_disable(&hif->napi);
	netif_napi_del(&hif->napi);

#ifdef __KERNEL__
	free_irq(hif->irq, hif);
#endif
	pfe_hif_release_buffers(hif);
	pfe_hif_free_descr(hif);
}
