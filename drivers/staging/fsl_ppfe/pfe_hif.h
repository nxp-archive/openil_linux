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

#ifndef _PFE_HIF_H_
#define _PFE_HIF_H_

#include <linux/netdevice.h>

#define HIF_NAPI_STATS

#define HIF_CLIENT_QUEUES_MAX	16
#define HIF_RX_POLL_WEIGHT	64

#define HIF_RX_PKT_MIN_SIZE 0x800 /* 2KB */
#define HIF_RX_PKT_MIN_SIZE_MASK ~(HIF_RX_PKT_MIN_SIZE - 1)
#define ROUND_MIN_RX_SIZE(_sz) ((_sz + (HIF_RX_PKT_MIN_SIZE - 1)) & HIF_RX_PKT_MIN_SIZE_MASK)
#define PRESENT_OFST_IN_PAGE(_buf) (((unsigned long int)_buf & (PAGE_SIZE - 1)) & HIF_RX_PKT_MIN_SIZE_MASK)

enum {
	NAPI_SCHED_COUNT = 0,
	NAPI_POLL_COUNT,
	NAPI_PACKET_COUNT,
	NAPI_DESC_COUNT,
	NAPI_FULL_BUDGET_COUNT,
	NAPI_CLIENT_FULL_COUNT,
	NAPI_MAX_COUNT
};


/* XXX  HIF_TX_DESC_NT value should be always greter than 4,
 *      Otherwise HIF_TX_POLL_MARK will become zero.
 */
#if defined(CONFIG_PLATFORM_PCI)
#define HIF_RX_DESC_NT		4
#define HIF_TX_DESC_NT		4
#else
#if defined(CONFIG_COMCERTO_64K_PAGES) 
#define HIF_RX_DESC_NT		64
#else
#define HIF_RX_DESC_NT		256
#endif
#define HIF_TX_DESC_NT		2048
#endif

#define HIF_FIRST_BUFFER		(1 << 0)
#define HIF_LAST_BUFFER		(1 << 1)
#define HIF_DONT_DMA_MAP		(1 << 2) //TODO merge it with TSO
#define HIF_DATA_VALID			(1 << 3)
#define HIF_TSO			(1 << 4)

#define MAX_VAP_SUPPORT 3
#define MAX_WIFI_VAPS MAX_VAP_SUPPORT

enum {
	PFE_CL_GEM0 = 0,
	PFE_CL_GEM1,
	PFE_CL_GEM2,
	PFE_CL_VWD0,
	PFE_CL_VWD_LAST = PFE_CL_VWD0 + MAX_VAP_SUPPORT,
	PFE_CL_PCAP0,
	HIF_CLIENTS_MAX
};

/*structure to store client queue info */
struct hif_rx_queue {
	struct rx_queue_desc *base;
	u32	size;
	u32	write_idx;
};

struct hif_tx_queue {
	struct tx_queue_desc *base;
	u32	size;
	u32	ack_idx;
};

/*Structure to store the client info */
struct hif_client {
	int	rx_qn;
	struct hif_rx_queue 	rx_q[HIF_CLIENT_QUEUES_MAX];
	int	tx_qn;
	struct hif_tx_queue	tx_q[HIF_CLIENT_QUEUES_MAX];
};

/*HIF hardware buffer descriptor */
struct hif_desc {
	volatile u32 ctrl;
	volatile u32 status;
	volatile u32 data;
	volatile u32 next;
};

struct __hif_desc {
	u32 ctrl;
	u32 status;
	u32 data;
};

struct hif_desc_sw {
	dma_addr_t data;
	u16 len;
	u8 client_id;
	u8 q_no;
	u16 flags;
};

struct hif_hdr {
	u8 client_id;
	u8 qNo;
	u16 client_ctrl;
	u16 client_ctrl1;
};

struct __hif_hdr {
	union {
		struct hif_hdr hdr;
		u32 word[2];
	};
};

struct hif_lro_hdr {
	u16 data_offset;
	u16 mss;
};

struct hif_ipsec_hdr {
	u16	sa_handle[2];
}__attribute__((packed));

#define MAX_TSO_BUF_DESCS 5
struct hif_tso_buf_desc {
	u32	addr;
	u32	ctrl;
#define TSO_CTRL_LAST_BUFFER (1 << 31)
};

struct hif_tso_hdr {
	struct	hif_hdr pkt_hdr;
	u16	ip_off;
	u16	ip_id;
	u16	ip_len;
	u16	tcp_off;
	u32	tcp_seq;
} __attribute__((packed));

struct hif_tso_hdr_nocpy {
	struct	hif_tso_hdr tso_hdr;
	struct hif_tso_buf_desc bdesc[MAX_TSO_BUF_DESCS];
} __attribute__((packed));

struct hif_pcap_hdr {
	u8	ifindex;
	u8 	unused;
	u16	seqno;
	u32	timestamp;
}__attribute__((packed));

/*  HIF_CTRL_TX... defines */
#define HIF_CTRL_TX_TSO_NOCPY		(1 << 8)
#define HIF_CTRL_TX_IPSEC_OUT		(1 << 7)
#define HIF_CTRL_TX_OWN_MAC		(1 << 6)
#define HIF_CTRL_TX_TSO_END		(1 << 5)
#define HIF_CTRL_TX_TSO6		(1 << 4)
#define HIF_CTRL_TX_TSO			(1 << 3)
#define HIF_CTRL_TX_CHECKSUM		(1 << 2)
#define HIF_CTRL_TX_CSUM_VALIDATE	(1 << 1)
#define HIF_CTRL_TX_WIFI		(1 << 0)

/*  HIF_CTRL_RX... defines */
#define HIF_CTRL_RX_OFFSET_OFST		(24)
#define HIF_CTRL_RX_PE_ID_OFST		(16)
#define HIF_CTRL_RX_IPSEC_IN		(1 << 4)
#define HIF_CTRL_RX_WIFI_EXPT		(1 << 3)
#define HIF_CTRL_RX_CHECKSUMMED		(1 << 2)
#define HIF_CTRL_RX_CONTINUED		(1 << 1)
#define HIF_CTRL_RX_WIFI_HEADROOM	(1 << 0)

#define HIF_CTRL_VAPID_OFST		(8)

struct pfe_hif {
	/* To store registered clients in hif layer */
	struct hif_client client[HIF_CLIENTS_MAX];
	struct hif_shm *shm;
	int	irq;

	void	*descr_baseaddr_v;
	unsigned long	descr_baseaddr_p;

	struct hif_desc *RxBase;
	u32	RxRingSize;
	u32	RxtocleanIndex;
	void	*rx_buf_addr[HIF_RX_DESC_NT];
	int	rx_buf_len[HIF_RX_DESC_NT];
	unsigned int qno;
	unsigned int client_id;
	unsigned int client_ctrl;
	unsigned int started;

	struct hif_desc *TxBase;
	u32	TxRingSize;
	u32	Txtosend;
	u32	Txtoclean;
	u32	TxAvail;
	u32	Txtoflush;
	struct hif_desc_sw tx_sw_queue[HIF_TX_DESC_NT];
	struct hif_tso_hdr_nocpy *tso_hdr_v;
	dma_addr_t tso_hdr_p;

	spinlock_t tx_lock;
	spinlock_t lock;
	struct net_device	dummy_dev;
	struct napi_struct	napi;
	struct device *dev;

#ifdef CONFIG_HOTPLUG_CPU
	struct notifier_block   cpu_notify;
#endif

#ifdef HIF_NAPI_STATS
	unsigned int napi_counters[NAPI_MAX_COUNT];
#endif
};

void __hif_xmit_pkt(struct pfe_hif *hif, unsigned int client_id, unsigned int q_no, void *data, u32 len, unsigned int flags);
int hif_xmit_pkt(struct pfe_hif *hif, unsigned int client_id, unsigned int q_no, void *data, unsigned int len);
void __hif_tx_done_process(struct pfe_hif *hif, int count);
void hif_process_client_req(struct pfe_hif *hif, int req, int data1, int data2);
int pfe_hif_init(struct pfe *pfe);
void pfe_hif_exit(struct pfe *pfe);

static inline void hif_tx_done_process(struct pfe_hif *hif, int count)
{
	spin_lock_bh(&hif->tx_lock);
	__hif_tx_done_process(hif, count);
	spin_unlock_bh(&hif->tx_lock);
}

static inline void hif_tx_lock(struct pfe_hif *hif)
{
	spin_lock_bh(&hif->tx_lock);
}

static inline void hif_tx_unlock(struct pfe_hif *hif)
{
	spin_unlock_bh(&hif->tx_lock);
}

static inline int __hif_tx_avail(struct pfe_hif *hif)
{
	return hif->TxAvail;
}

#if defined(CONFIG_PLATFORM_C2000)
static inline void __memcpy8(void *dst, void *src)
{
	asm volatile (	"ldm %1, {r9, r10}\n\t"
			"stm %0, {r9, r10}\n\t"
			:
			: "r" (dst), "r" (src)
			: "r9", "r10", "memory"
		);
}

static inline void __memcpy12(void *dst, void *src)
{
	asm volatile (	"ldm %1, {r8, r9, r10}\n\t"
			"stm %0, {r8, r9, r10}\n\t"
			:
			: "r" (dst), "r" (src)
			: "r8", "r9", "r10", "memory"
		);
}

static inline void __memcpy16(void *dst, void *src)
{
	asm volatile (	"ldm %1, {r7, r8, r9, r10}\n\t"
			"stm %0, {r7, r8, r9, r10}\n\t"
			:
			: "r"(dst), "r"(src)
			: "r7", "r8", "r9", "r10", "memory"
		);
}

#define HIF_MEMCPY_BURSTSIZE 32                 /*__memcpy copy 32byte in a burst*/
static inline void __memcpy(void *dst, void *src, unsigned int len)
{
	void *end = src + len;

	dst = (void *)((unsigned long)dst & ~0x3);
	src = (void *)((unsigned long)src & ~0x3);

	while (src < end) {
		asm volatile (	"ldm %1!, {r3, r4, r5, r6, r7, r8, r9, r10}\n\t"
				"stm %0!, {r3, r4, r5, r6, r7, r8, r9, r10}\n\t"
				: "+r"(dst), "+r"(src)
				:
				: "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "memory"
			);
	}
}
#else
#define __memcpy8(dst, src)		memcpy(dst, src, 8)
#define __memcpy12(dst, src)		memcpy(dst, src, 12)
#define __memcpy(dst, src, len)		memcpy(dst, src, len)
#endif
#endif /* _PFE_HIF_H_ */
