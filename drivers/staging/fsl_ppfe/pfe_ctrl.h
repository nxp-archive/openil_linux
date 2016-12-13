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

#ifndef _PFE_CTRL_H_
#define _PFE_CTRL_H_

#include <linux/dmapool.h>

#include "pfe_mod.h"
#include "pfe/pfe.h"

#define DMA_BUF_SIZE_128	0x80	/* enough for 1 conntracks */
#define DMA_BUF_SIZE_256	0x100	/* enough for 2 conntracks, 1 bridge entry or 1 multicast entry */
#define DMA_BUF_SIZE_512	0x200	/* 512bytes dma allocated buffers used by rtp relay feature */
#define DMA_BUF_MIN_ALIGNMENT	8
#define DMA_BUF_BOUNDARY	(4 * 1024) /* bursts can not cross 4k boundary */

#define CMD_TX_ENABLE	0x0501
#define CMD_TX_DISABLE	0x0502

#define CMD_RX_LRO		0x0011
#define CMD_PKTCAP_ENABLE       0x0d01
#define CMD_QM_EXPT_RATE	0x020c

#define EXPT_TYPE_PCAP		0x3

struct pfe_ctrl {
	struct mutex mutex;
	spinlock_t lock;

	void *dma_pool;
	void *dma_pool_512;
	void *dma_pool_128;

	struct device *dev;

	void *hash_array_baseaddr;		/** Virtual base address of the conntrack hash array */
	unsigned long hash_array_phys_baseaddr; /** Physical base address of the conntrack hash array */

	struct task_struct *timer_thread;
	struct list_head timer_list;
	unsigned long timer_period;

	int (*event_cb)(u16, u16, u16*);

	unsigned long sync_mailbox_baseaddr[MAX_PE]; /* Sync mailbox PFE internal address, initialized when parsing elf images */
	unsigned long msg_mailbox_baseaddr[MAX_PE]; /* Msg mailbox PFE internal address, initialized when parsing elf images */

	unsigned long class_dmem_sh;
	unsigned long class_pe_lmem_sh;
	unsigned long tmu_dmem_sh;
	unsigned long util_dmem_sh;
	unsigned long util_ddr_sh;
	struct clk *clk_axi;
	unsigned int sys_clk;			// AXI clock value, in KHz
	void *ipsec_lmem_baseaddr;
	unsigned long ipsec_lmem_phys_baseaddr;
	
	/* used for asynchronous message transfer to PFE */
	struct list_head msg_list;
	struct work_struct work;
};

int pfe_ctrl_init(struct pfe *pfe);
void pfe_ctrl_exit(struct pfe *pfe);

int pe_send_cmd(unsigned short cmd_type, unsigned short action, unsigned long param1, unsigned long param2);
int pe_sync_stop(struct pfe_ctrl *ctrl, int pe_mask);
void pe_start(struct pfe_ctrl *ctrl, int pe_mask);
int pe_request(struct pfe_ctrl *ctrl, int id,unsigned short cmd_type, unsigned long dst, unsigned long src, int len);
int pe_read(struct pfe_ctrl *ctrl, int id, u32 *dst, unsigned long src, int len, int clear_flag);
int tmu_pe_request(struct pfe_ctrl *ctrl, int id, unsigned int tmu_cmd_bitmask);

int pfe_ctrl_set_eth_state(int id, unsigned int state, unsigned char *mac_addr);
int pfe_ctrl_set_lro(char enable);
#ifdef CFG_PCAP
int pfe_ctrl_set_pcap(char enable);
int pfe_ctrl_set_pcap_ratelimit(u32 pkts_per_msec);
#endif
void pfe_ctrl_suspend(struct pfe_ctrl *ctrl);
void pfe_ctrl_resume(struct pfe_ctrl *ctrl);
int relax(unsigned long end);

/* used for asynchronous message transfer to PFE */
#define FPP_MAX_MSG_LENGTH	256 /* expressed in U8 -> 256 bytes*/
struct fpp_msg {
        struct list_head list;
        void (*callback)(unsigned long, int, u16, u16 *);
        unsigned long data;
        u16 fcode;
        u16 length;
        u16 *payload;
};

#endif /* _PFE_CTRL_H_ */
