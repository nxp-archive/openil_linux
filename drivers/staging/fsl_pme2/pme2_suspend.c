/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * This software is provided by Freescale Semiconductor "as is" and any
 * express or implied warranties, including, but not limited to, the implied
 * warranties of merchantability and fitness for a particular purpose are
 * disclaimed. In no event shall Freescale Semiconductor be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential damages
 * (including, but not limited to, procurement of substitute goods or services;
 * loss of use, data, or profits; or business interruption) however caused and
 * on any theory of liability, whether in contract, strict liability, or tort
 * (including negligence or otherwise) arising in any way out of the use of
 * this software, even if advised of the possibility of such damage.
 */

#ifdef CONFIG_PM

#include "pme2_private.h"
#include "pme2_regs.h"
#include <linux/vmalloc.h>

static dma_addr_t pme_suspend_map(struct platform_device *pdev, void *ptr)
{
	return dma_map_single(&pdev->dev, ptr, 1, DMA_BIDIRECTIONAL);
}

#ifdef PME_SUSPEND_DEBUG

static inline void __hexdump(unsigned long start, unsigned long end,
			     unsigned long p, size_t sz, const unsigned char *c)
{
	while (start < end) {
		unsigned int pos = 0;
		char buf[64];
		int nl = 0;
		pos += sprintf(buf + pos, "%08lx: ", start);
		do {
			if ((start < p) || (start >= (p + sz)))
				pos += sprintf(buf + pos, "..");
			else
				pos += sprintf(buf + pos, "%02x", *(c++));
			if (!(++start & 15)) {
				buf[pos++] = '\n';
				nl = 1;
			} else {
				nl = 0;
				if (!(start & 1))
					buf[pos++] = ' ';
				if (!(start & 3))
					buf[pos++] = ' ';
			}
		} while (start & 15);
		if (!nl)
			buf[pos++] = '\n';
		buf[pos] = '\0';
		pr_info("%s", buf);
	}
}

static inline void hexdump(const void *ptr, size_t sz)
{
	unsigned long p = (unsigned long)ptr;
	unsigned long start = p & ~(unsigned long)15;
	unsigned long end = (p + sz + 15) & ~(unsigned long)15;
	const unsigned char *c = ptr;
	__hexdump(start, end, p, sz, c);
}
#endif

/*
 * The following SRAM tables need to be saved
 *	1-byte trigger table
 *	2-byte trigger table
 *	variable length trigger table
 *	confidence table
 *	User-Defined Group Mapping tablle
 *	Equivalent Byte Mapping table
 *	Special Trigger table
 */
enum pme_pmtcc_table_id {
	PME_ONE_BYTE_TRIGGER_TBL	= 0x00,
	PME_TWO_BYTE_TRIGGER_TBL	= 0x01,
	PME_VARIABLE_TRIGGER_TBL	= 0x02,
	PME_CONFIDENCE_TBL		= 0x03,
	PME_UDG_TBL			= 0x05,
	PME_EQUIVALENT_BYTE_TBL		= 0x06,
	PME_SPECIAL_TRIGGER_TBL		= 0x08,
	PME_LAST_TABLE			= PME_SPECIAL_TRIGGER_TBL
};

static enum pme_pmtcc_table_id table_list[] = {PME_ONE_BYTE_TRIGGER_TBL,
	PME_TWO_BYTE_TRIGGER_TBL, PME_VARIABLE_TRIGGER_TBL, PME_CONFIDENCE_TBL,
	PME_UDG_TBL, PME_EQUIVALENT_BYTE_TBL, PME_SPECIAL_TRIGGER_TBL};

struct pme_pmtcc_header_t {
	uint8_t	protocol_version;
	uint8_t	msg_type;
	uint16_t	reserved;
	/* total message length, including the header */
	uint32_t	msg_length;
	uint64_t	msg_id;
	uint8_t	data[0];
} __packed;

/*
 * The next few macros define the sizes (in bytes) of the entries in
 * the different PM H/W tables.
 */
#define PME_ONE_BYTE_TRIGGER_ENTRY_SIZE		32
#define PME_TWO_BYTE_TRIGGER_ENTRY_SIZE		8
#define PME_VARIABLE_TRIGGER_ENTRY_SIZE		8
#define PME_CONFIDENCE_ENTRY_SIZE		4
#define PME_CONFIRMATION_ENTRY_SIZE		128
#define PME_USER_DEFINED_GROUP_READ_ENTRY_SIZE	4
#define PME_USER_DEFINED_GROUP_WRITE_ENTRY_SIZE	256
#define PME_EQUIVALENCE_READ_ENTRY_SIZE		4
#define PME_EQUIVALENCE_WRITE_ENTRY_SIZE	256
#define PME_SESSION_CONTEXT_ENTRY_SIZE		32
#define PME_SPECIAL_TRIGGER_ENTRY_SIZE		32

union pme_table_entry_t {
	/* The next few types define the entries for the different PM tables. */
	uint8_t one_byte_trigger_entry[PME_ONE_BYTE_TRIGGER_ENTRY_SIZE];
	uint8_t two_byte_trigger_entry[PME_TWO_BYTE_TRIGGER_ENTRY_SIZE];
	uint8_t variable_trigger_entry[PME_VARIABLE_TRIGGER_ENTRY_SIZE];
	uint8_t confidence_entry[PME_CONFIDENCE_ENTRY_SIZE];
	uint8_t udg_read_entry[PME_USER_DEFINED_GROUP_READ_ENTRY_SIZE];
	uint8_t udg_write_entry[PME_USER_DEFINED_GROUP_WRITE_ENTRY_SIZE];
	uint8_t equivalence_read_entry[PME_EQUIVALENCE_READ_ENTRY_SIZE];
	uint8_t equivalence_write_entry[PME_EQUIVALENCE_WRITE_ENTRY_SIZE];
	uint8_t special_trigger_entry[PME_SPECIAL_TRIGGER_ENTRY_SIZE];
} __packed;

/* This type defines an indexed table entry. */
struct pme_indexed_table_entry_t {
	uint32_t		index;
	union pme_table_entry_t	entry;
} __packed;

/* table read request */
struct pme_pmtcc_read_request_msg_t {
	struct pme_pmtcc_header_t	header;
	uint32_t	table_id;
	uint32_t	index;
} __packed;

/* table read reply message. */
struct pme_pmtcc_read_reply_msg_t {
	struct pme_pmtcc_header_t	header;
	uint32_t	table_id;
	struct pme_indexed_table_entry_t  indexed_entry;
} __packed;

/* table write request message */
struct pme_pmtcc_write_request_msg_t {
	struct pme_pmtcc_header_t	header;
	uint32_t	table_id;
	struct pme_indexed_table_entry_t  indexed_entry;
} __packed;

/*
 * The next few macros define the number of entries in the different PM
 * H/W tables.
 */
#define PME_CONFIDENCE_ENTRY_NUM_PER_TRIGGER_ENTRY 4

#define PME_ONE_BYTE_TRIGGER_ENTRY_NUM             1

#define PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V1          512
#define PME_VARIABLE_TRIGGER_ENTRY_NUM_V1          4096

#define PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V2_0        2048
#define PME_VARIABLE_TRIGGER_ENTRY_NUM_V2_0        16384

#define PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V2_1        1024
#define PME_VARIABLE_TRIGGER_ENTRY_NUM_V2_1        8192

#define PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V2_2        512
#define PME_VARIABLE_TRIGGER_ENTRY_NUM_V2_2        4096

#define PME_SPECIAL_CONFIDENCE_ENTRY_NUM           64
#define PME_ONE_BYTE_CONFIDENCE_ENTRY_NUM          64

#define PME_CONFIDENCE_ENTRY_NUM_V1		\
	((PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V1 +	\
	PME_VARIABLE_TRIGGER_ENTRY_NUM_V1 +	\
	PME_ONE_BYTE_CONFIDENCE_ENTRY_NUM +	\
	PME_SPECIAL_CONFIDENCE_ENTRY_NUM) *	\
	PME_CONFIDENCE_ENTRY_NUM_PER_TRIGGER_ENTRY)

#define PME_CONFIDENCE_ENTRY_NUM_V2_0		\
	((PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V2_0 +	\
	PME_VARIABLE_TRIGGER_ENTRY_NUM_V2_0 +	\
	PME_ONE_BYTE_CONFIDENCE_ENTRY_NUM +	\
	PME_SPECIAL_CONFIDENCE_ENTRY_NUM) *	\
	PME_CONFIDENCE_ENTRY_NUM_PER_TRIGGER_ENTRY)

#define PME_CONFIDENCE_ENTRY_NUM_V2_1		\
	((PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V2_1 +	\
	PME_VARIABLE_TRIGGER_ENTRY_NUM_V2_1 +	\
	PME_ONE_BYTE_CONFIDENCE_ENTRY_NUM +	\
	PME_SPECIAL_CONFIDENCE_ENTRY_NUM) *	\
	PME_CONFIDENCE_ENTRY_NUM_PER_TRIGGER_ENTRY)

#define PME_CONFIDENCE_ENTRY_NUM_V2_2			\
	((PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V2_2 +		\
	PME_VARIABLE_TRIGGER_ENTRY_NUM_V2_2 +		\
	PME_ONE_BYTE_CONFIDENCE_ENTRY_NUM +		\
	PME_SPECIAL_CONFIDENCE_ENTRY_NUM) *		\
	PME_CONFIDENCE_ENTRY_NUM_PER_TRIGGER_ENTRY)

#define PME_EQUIVALENCE_ENTRY_NUM                  1
#define PME_USER_DEFINED_GROUP_ENTRY_NUM           1
#define PME_SPECIAL_TRIGGER_ENTRY_NUM              1

/*
 * The next few macros below define the sizes of the different
 * messages.  Note the the macros related to the table read and write
 * messages assume that there is only one entry in the read/write
 * message.
 */
#define PME_TABLE_READ_REQUEST_MSG_SIZE			\
	sizeof(struct pme_pmtcc_read_request_msg_t)

#define PME_ONE_BYTE_TABLE_READ_REPLY_MSG_SIZE		\
	(sizeof(struct pme_pmtcc_read_reply_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_ONE_BYTE_TRIGGER_ENTRY_SIZE)

#define PME_TWO_BYTE_TABLE_READ_REPLY_MSG_SIZE		\
	(sizeof(struct pme_pmtcc_read_reply_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_TWO_BYTE_TRIGGER_ENTRY_SIZE)

#define PME_VARIABLE_TABLE_READ_REPLY_MSG_SIZE		\
	(sizeof(struct pme_pmtcc_read_reply_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_VARIABLE_TRIGGER_ENTRY_SIZE)

#define PME_CONFIDENCE_TABLE_READ_REPLY_MSG_SIZE	\
	(sizeof(struct pme_pmtcc_read_reply_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_CONFIDENCE_ENTRY_SIZE)

#define PME_UDG_TABLE_READ_REPLY_MSG_SIZE		\
	(sizeof(struct pme_pmtcc_read_reply_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_USER_DEFINED_GROUP_READ_ENTRY_SIZE)

#define PME_EQUIVALENCE_TABLE_READ_REPLY_MSG_SIZE	\
	(sizeof(struct pme_pmtcc_read_reply_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_EQUIVALENCE_READ_ENTRY_SIZE)

#define PME_SPECIAL_TABLE_READ_REPLY_MSG_SIZE		\
	(sizeof(struct pme_pmtcc_read_reply_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_SPECIAL_TRIGGER_ENTRY_SIZE)

#define PME_ONE_BYTE_TABLE_WRITE_REQUEST_MSG_SIZE	\
	(sizeof(struct pme_pmtcc_write_request_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_ONE_BYTE_TRIGGER_ENTRY_SIZE)

#define PME_TWO_BYTE_TABLE_WRITE_REQUEST_MSG_SIZE	\
	(sizeof(struct pme_pmtcc_write_request_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_TWO_BYTE_TRIGGER_ENTRY_SIZE)

#define PME_VARIABLE_TABLE_WRITE_REQUEST_MSG_SIZE	\
	(sizeof(struct pme_pmtcc_write_request_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_VARIABLE_TRIGGER_ENTRY_SIZE)

#define PME_CONFIDENCE_TABLE_WRITE_REQUEST_MSG_SIZE	\
	(sizeof(struct pme_pmtcc_write_request_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_CONFIDENCE_ENTRY_SIZE)

#define PME_UDG_TABLE_WRITE_REQUEST_MSG_SIZE		\
	(sizeof(struct pme_pmtcc_write_request_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_USER_DEFINED_GROUP_WRITE_ENTRY_SIZE)

#define PME_EQUIVALENCE_TABLE_WRITE_REQUEST_MSG_SIZE	\
	(sizeof(struct pme_pmtcc_write_request_msg_t) -	\
	sizeof(union pme_table_entry_t) +		\
	PME_EQUIVALENCE_WRITE_ENTRY_SIZE)

#define PME_SPECIAL_TABLE_WRITE_REQUEST_MSG_SIZE	\
	(sizeof(struct pme_pmtcc_write_request_msg_t) -	\
	sizeof(union pme_table_entry_t)		+	\
	PME_SPECIAL_TRIGGER_ENTRY_SIZE)

/*
 * Index 0..255, bools do indicated which errors are serious
 * 0x40, 0x41, 0x48, 0x49, 0x4c, 0x4e, 0x4f, 0x50, 0x51, 0x59, 0x5a, 0x5b,
 * 0x5c, 0x5d, 0x5f, 0x60, 0x80, 0xc0, 0xc1, 0xc2, 0xc4, 0xd2,
 * 0xd4, 0xd5, 0xd7, 0xd9, 0xda, 0xe0, 0xe7
 */
static u8 serious_error_vec[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static enum qman_cb_dqrr_result cb_dqrr(struct qman_portal *portal,
			struct qman_fq *fq, const struct qm_dqrr_entry *dq)
{
	u8 status = (u8)pme_fd_res_status(&dq->fd);
	u8 flags = pme_fd_res_flags(&dq->fd);
	struct  pme_pwrmgmt_ctx *ctx = (struct pme_pwrmgmt_ctx *)fq;

	if (unlikely(flags & PME_STATUS_UNRELIABLE))
		pr_err("pme error %d\n", __LINE__);
	else if (unlikely((serious_error_vec[status])))
		pr_err("pme error %d\n", __LINE__);
	else {
		memcpy(&ctx->result_fd, &dq->fd, sizeof(*&dq->fd));
		complete(&ctx->done);
	}
	return qman_cb_dqrr_consume;
}

static void cb_fqs(__always_unused struct qman_portal *portal,
			__always_unused struct qman_fq *fq,
			const struct qm_mr_entry *mr)
{
	u8 verb = mr->verb & QM_MR_VERB_TYPE_MASK;
	if (verb == QM_MR_VERB_FQRNI)
		return;
	/* nothing else is supposed to occur */
	BUG();
}

static const struct qman_fq_cb pme_fq_base_out = {
	.dqrr = cb_dqrr,
	.fqs = cb_fqs
};

static const struct qman_fq_cb pme_fq_base_in = {
	.fqs = cb_fqs,
	.ern = NULL
};

static void pme_pwrmgmt_initfq(struct qm_mcc_initfq *initfq, u32 rfqid)
{
	struct pme_context_a *pme_a =
		(struct pme_context_a *)&initfq->fqd.context_a;
	struct pme_context_b *pme_b =
		(struct pme_context_b *)&initfq->fqd.context_b;

	initfq->we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA |
				QM_INITFQ_WE_CONTEXTB;
	initfq->fqd.dest.channel = qm_channel_pme;
	initfq->fqd.dest.wq = 4;
	pme_a->mode = pme_mode_direct;
	pme_context_a_set64(pme_a, 0);
	pme_b->rfqid = rfqid;
}

static int pme_pwrmgmt_ctx_reconfigure_tx(struct pme_pwrmgmt_ctx *ctx)
{
	struct qm_mcc_initfq initfq;
	u32 flags = QMAN_INITFQ_FLAG_SCHED | QMAN_INITFQ_FLAG_LOCAL;
	int ret;

	memset(&initfq, 0, sizeof(initfq));
	initfq.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL;
	initfq.fqd.dest.wq = 4;
	initfq.fqd.fq_ctrl = 0; /* disable stashing */
	ret = qman_init_fq(&ctx->tx_fq, flags, &initfq);
	return ret;
}

static int pme_pwrmgmt_ctx_reconfigure_rx(struct pme_pwrmgmt_ctx *ctx)
{
	struct qm_mcc_initfq initfq;
	int ret;

	memset(&initfq, 0, sizeof(initfq));
	pme_pwrmgmt_initfq(&initfq, qman_fq_fqid(&ctx->tx_fq));
	ret = qman_init_fq(&ctx->rx_fq, 0, &initfq);
	return ret;
}

int pme_pwrmgmt_ctx_init(struct pme_pwrmgmt_ctx *ctx)
{
	int ret;

	ctx->tx_fq.cb = pme_fq_base_out;
	ctx->rx_fq.cb = pme_fq_base_in;

	/* Create tx (from pme point of view) frame queue */
	ret = qman_create_fq(0, QMAN_FQ_FLAG_TO_DCPORTAL |
			QMAN_FQ_FLAG_DYNAMIC_FQID | QMAN_FQ_FLAG_LOCKED,
			&ctx->rx_fq);
	if (ret)
		return ret;

	ret = qman_create_fq(0, QMAN_FQ_FLAG_NO_ENQUEUE |
			QMAN_FQ_FLAG_DYNAMIC_FQID | QMAN_FQ_FLAG_LOCKED,
			&ctx->tx_fq);
	if (ret)
		goto create_rx_failed;

	ret = pme_pwrmgmt_ctx_reconfigure_rx(ctx);
	if (ret)
		goto config_rx_failed;

	ret = pme_pwrmgmt_ctx_reconfigure_tx(ctx);
	if (ret)
		goto config_tx_failed;

	return 0;
config_tx_failed:
config_rx_failed:
	qman_destroy_fq(&ctx->rx_fq, 0);
create_rx_failed:
	qman_destroy_fq(&ctx->tx_fq, 0);
	return ret;
}

static void pme_pwrmgmt_ctx_finish(struct pme_pwrmgmt_ctx *ctx)
{
	u32 flags;
	int ret;

	ret = qman_retire_fq(&ctx->tx_fq, &flags);
	BUG_ON(ret);
	BUG_ON(flags & QMAN_FQ_STATE_BLOCKOOS);
	ret = qman_retire_fq(&ctx->rx_fq, &flags);
	BUG_ON(ret);
	BUG_ON(flags & QMAN_FQ_STATE_BLOCKOOS);
	ret = qman_oos_fq(&ctx->tx_fq);
	BUG_ON(ret);
	ret = qman_oos_fq(&ctx->rx_fq);
	BUG_ON(ret);
	qman_destroy_fq(&ctx->tx_fq, 0);
	qman_destroy_fq(&ctx->rx_fq, 0);
}

static int create_pwrmgmt_ctx(struct portal_backup_info *save_db)
{
	int ret;

	/* check to see if context already exists */
	if (save_db->ctx)
		return 0;

	save_db->ctx = kzalloc(sizeof(*save_db->ctx), GFP_KERNEL);
	if (!save_db->ctx)
		return -ENOMEM;

	init_completion(&save_db->ctx->done);
	ret = pme_pwrmgmt_ctx_init(save_db->ctx);
	if (ret) {
		pr_err("Error pme_pwrmgmt_ctx_init\n");
		goto error_free_mem;
	}
	return 0;

error_free_mem:
	kfree(save_db->ctx);
	save_db->ctx = NULL;
	return ret;
}

static int delete_pwrmgmt_ctx(struct portal_backup_info *save_db)
{
	if (!save_db->ctx)
		return 0;

	pme_pwrmgmt_ctx_finish(save_db->ctx);
	kfree(save_db->ctx);
	save_db->ctx = NULL;

	return 0;
}

/* Send a pmtcc pme frame */
static int pme_pwrmgmt_ctx_pmtcc(struct pme_pwrmgmt_ctx *ctx, u32 flags,
			struct qm_fd *fd)
{
	int ret;

	struct pme_cmd_pmtcc *pmtcc = (struct pme_cmd_pmtcc *)&fd->cmd;
	pmtcc->cmd = pme_cmd_pmtcc;

	ret = qman_enqueue(&ctx->rx_fq, fd, flags &
			(QMAN_ENQUEUE_FLAG_WAIT | QMAN_ENQUEUE_FLAG_WAIT_INT));

	return ret;
}

static int get_table_attributes(enum pme_pmtcc_table_id tbl_id,
	uint32_t pme_rev1, int *num_read_entries, int *num_write_entries,
	int *read_size, int *read_reply_size, int *write_size,
	int *read_entry_size, int *write_entry_size)
{
	*read_size = PME_TABLE_READ_REQUEST_MSG_SIZE;

	switch (tbl_id) {
	case PME_ONE_BYTE_TRIGGER_TBL:
		*num_read_entries = PME_ONE_BYTE_TRIGGER_ENTRY_NUM;
		*num_write_entries = PME_ONE_BYTE_TRIGGER_ENTRY_NUM;
		*read_reply_size = PME_ONE_BYTE_TABLE_READ_REPLY_MSG_SIZE;
		*write_size = PME_ONE_BYTE_TABLE_WRITE_REQUEST_MSG_SIZE;
		*read_entry_size = PME_ONE_BYTE_TRIGGER_ENTRY_SIZE;
		*write_entry_size = PME_ONE_BYTE_TRIGGER_ENTRY_SIZE;
		break;

	case PME_TWO_BYTE_TRIGGER_TBL:
		if (is_version(pme_rev1, 2, 0))
			*num_read_entries = PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V2_0;
		else if (is_version(pme_rev1, 2, 1))
			*num_read_entries = PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V2_1;
		else if (is_version(pme_rev1, 2, 2))
			*num_read_entries = PME_TWO_BYTE_TRIGGER_ENTRY_NUM_V2_2;
		else {
			pr_err("pme suspend: unsupported pme version %u\n",
				pme_rev1);
			return -EINVAL;
		}
		*num_write_entries = *num_read_entries;
		*read_reply_size = PME_TWO_BYTE_TABLE_READ_REPLY_MSG_SIZE;
		*write_size = PME_TWO_BYTE_TABLE_WRITE_REQUEST_MSG_SIZE;
		*read_entry_size = PME_TWO_BYTE_TRIGGER_ENTRY_SIZE;
		*write_entry_size = PME_TWO_BYTE_TRIGGER_ENTRY_SIZE;
		break;

	case PME_VARIABLE_TRIGGER_TBL:
		if (is_version(pme_rev1, 2, 0))
			*num_read_entries = PME_VARIABLE_TRIGGER_ENTRY_NUM_V2_0;
		else if (is_version(pme_rev1, 2, 1))
			*num_read_entries = PME_VARIABLE_TRIGGER_ENTRY_NUM_V2_1;
		else if (is_version(pme_rev1, 2, 2))
			*num_read_entries = PME_VARIABLE_TRIGGER_ENTRY_NUM_V2_2;
		else {
			pr_err("pme suspend: unsupported pme version %u\n",
				pme_rev1);
			return -EINVAL;
		}
		*num_write_entries = *num_read_entries;
		*read_reply_size = PME_VARIABLE_TABLE_READ_REPLY_MSG_SIZE;
		*write_size = PME_VARIABLE_TABLE_WRITE_REQUEST_MSG_SIZE;
		*read_entry_size = PME_VARIABLE_TRIGGER_ENTRY_SIZE;
		*write_entry_size = PME_VARIABLE_TRIGGER_ENTRY_SIZE;
		break;

	case PME_CONFIDENCE_TBL:
		if (is_version(pme_rev1, 2, 0))
			*num_read_entries = PME_CONFIDENCE_ENTRY_NUM_V2_0;
		else if (is_version(pme_rev1, 2, 1))
			*num_read_entries = PME_CONFIDENCE_ENTRY_NUM_V2_1;
		else if (is_version(pme_rev1, 2, 2))
			*num_read_entries = PME_CONFIDENCE_ENTRY_NUM_V2_2;
		else {
			pr_err("pme suspend: unsupported pme version %u\n",
				pme_rev1);
			return -EINVAL;
		}
		*num_write_entries = *num_read_entries;
		*read_reply_size = PME_CONFIDENCE_TABLE_READ_REPLY_MSG_SIZE;
		*write_size = PME_CONFIDENCE_TABLE_WRITE_REQUEST_MSG_SIZE;
		*read_entry_size = PME_CONFIDENCE_ENTRY_SIZE;
		*write_entry_size = PME_CONFIDENCE_ENTRY_SIZE;
		break;
	case PME_UDG_TBL:
		*num_read_entries = 256;
		*num_write_entries = PME_USER_DEFINED_GROUP_ENTRY_NUM;
		*read_reply_size = PME_UDG_TABLE_READ_REPLY_MSG_SIZE;
		*write_size = PME_UDG_TABLE_WRITE_REQUEST_MSG_SIZE;
		*read_entry_size = (PME_UDG_TABLE_READ_REPLY_MSG_SIZE -
				   PME_TABLE_READ_REQUEST_MSG_SIZE);
		*write_entry_size = PME_USER_DEFINED_GROUP_WRITE_ENTRY_SIZE;
		break;

	case PME_EQUIVALENT_BYTE_TBL:
		*num_read_entries = 256;
		*num_write_entries = PME_EQUIVALENCE_ENTRY_NUM;
		*read_reply_size = PME_EQUIVALENCE_TABLE_READ_REPLY_MSG_SIZE;
		*write_size = PME_EQUIVALENCE_TABLE_WRITE_REQUEST_MSG_SIZE;
		*read_entry_size = (PME_EQUIVALENCE_TABLE_READ_REPLY_MSG_SIZE -
			PME_TABLE_READ_REQUEST_MSG_SIZE);
		*write_entry_size = PME_EQUIVALENCE_WRITE_ENTRY_SIZE;
		break;

	case PME_SPECIAL_TRIGGER_TBL:
		*num_read_entries = PME_SPECIAL_TRIGGER_ENTRY_NUM;
		*num_write_entries = PME_SPECIAL_TRIGGER_ENTRY_NUM;
		*read_reply_size = PME_SPECIAL_TABLE_READ_REPLY_MSG_SIZE;
		*write_size = PME_SPECIAL_TABLE_WRITE_REQUEST_MSG_SIZE;
		*read_entry_size = PME_SPECIAL_TRIGGER_ENTRY_SIZE;
		*write_entry_size = PME_SPECIAL_TRIGGER_ENTRY_SIZE;
		break;
	}
	return 0;
}

#ifdef PME_SUSPEND_DEBUG
static int total_size_read_request(enum pme_pmtcc_table_id tbl_id,
	uint32_t pme_rev1)
{
	int ret, num_read_entries, read_size, read_reply_size, write_size,
		read_entry_size, write_entry_size, num_write_entries;

	ret = get_table_attributes(tbl_id, pme_rev1, &num_read_entries,
		&num_write_entries, &read_size, &read_reply_size, &write_size,
		&read_entry_size, &write_entry_size);

	if (ret)
		return ret;

	return num_read_entries * read_size;
}

static int total_size_read_response_request(enum pme_pmtcc_table_id tbl_id,
	uint32_t pme_rev1)
{
	int ret, num_read_entries, read_size, read_reply_size, write_size,
		read_entry_size, write_entry_size, num_write_entries;

	ret = get_table_attributes(tbl_id, pme_rev1, &num_read_entries,
		&num_write_entries, &read_size, &read_reply_size, &write_size,
		&read_entry_size, &write_entry_size);

	if (ret)
		return ret;

	return num_read_entries * read_reply_size;
}

static int total_size_write_request(enum pme_pmtcc_table_id tbl_id,
	uint32_t pme_rev1)
{
	int ret, num_read_entries, read_size, read_reply_size, write_size,
		read_entry_size, write_entry_size, num_write_entries;

	ret = get_table_attributes(tbl_id, pme_rev1, &num_read_entries,
		&num_write_entries, &read_size, &read_reply_size, &write_size,
		&read_entry_size, &write_entry_size);

	if (ret)
		return ret;

	return num_write_entries * write_entry_size;
}
#endif

static int sizeof_all_db_tables(uint32_t pme_rev1)
{
	enum pme_pmtcc_table_id tbl_id;
	int i, ret, size = 0;

	for (i = 0; i < ARRAY_SIZE(table_list); i++) {
		int num_read_entries, read_size, read_reply_size, write_size,
			read_entry_size, write_entry_size, num_write_entries;
		tbl_id = table_list[i];

		ret = get_table_attributes(tbl_id, pme_rev1, &num_read_entries,
			&num_write_entries, &read_size, &read_reply_size,
			&write_size, &read_entry_size, &write_entry_size);

		if (ret)
			return ret;
		size += (write_entry_size * num_write_entries);
	}
	return size;
}

#ifdef PME_SUSPEND_DEBUG
static void print_debug(uint32_t pme_rev1)
{
	int i = 0;

	pr_info("size of db is %d\n", sizeof_all_db_tables(pme_rev1));

	do {
		int num_read_entries, read_size, read_reply_size, write_size,
			num_write_entries, read_entry_size, write_entry_size;

		get_table_attributes(table_list[i], pme_rev1, &num_read_entries,
			&num_write_entries, &read_size, &read_reply_size,
			&write_size, &read_entry_size, &write_entry_size);

		pr_info("Table Id %d\n", table_list[i]);
		pr_info(" num_read_entries %d, r_sz %d, rr_sz %d, w_sz %d\n",
			num_read_entries, read_size, read_reply_size,
			write_size);
		pr_info(" num_wr_entries %d, r_entry_size %d w_entry_size %d\n",
			num_write_entries, read_entry_size, write_entry_size);
		pr_info(" total read request size %d\n",
			total_size_read_request(table_list[i], pme_rev1));
		pr_info(" total read reply request size %d\n",
			total_size_read_response_request(table_list[i],
				pme_rev1));
		pr_info(" total write request size %d\n",
			total_size_write_request(table_list[i], pme_rev1));

		if (table_list[i] == PME_LAST_TABLE)
			break;
		i++;
	} while (1);
}
#endif

static void free_databases(struct portal_backup_info *save_db)
{
	vfree(save_db->db.alldb);
	save_db->db.alldb = NULL;
}

static int alloc_databases(struct pme2_private_data *priv_data)
{
	int sizedb;

	sizedb = sizeof_all_db_tables(priv_data->pme_rev1);
	if (sizedb < 0) {
		pr_err("Error getting db size\n");
		return -EINVAL;
	}

	priv_data->save_db.db.alldb = vzalloc(sizedb);
	if (!priv_data->save_db.db.alldb)
		return -ENOMEM;

	return 0;
}

static int save_all_tables(struct portal_backup_info *save_db,
			   uint32_t pme_rev1)
{
	struct pmtcc_raw_db *db = &save_db->db;
	enum pme_pmtcc_table_id tbl_id;
	int i, ret;
	uint8_t *current_tbl = db->alldb;

	for (i = 0; i < ARRAY_SIZE(table_list); i++) {
		int num_read_entries, read_size, read_reply_size, write_size,
			read_entry_size, write_entry_size, num_write_entries;
		int idx;
		struct pme_pmtcc_read_request_msg_t *entry;
		struct qm_fd fd;
		struct qm_sg_entry *sg_table = NULL;
		uint8_t *input_data, *output_data;
		enum pme_status status;

		tbl_id = table_list[i];
		ret = get_table_attributes(tbl_id, pme_rev1, &num_read_entries,
			&num_write_entries, &read_size, &read_reply_size,
			&write_size, &read_entry_size, &write_entry_size);

		/* Allocate input and output frame data */
		output_data = kzalloc(read_reply_size, GFP_KERNEL);
		input_data = kzalloc(read_size, GFP_KERNEL);
		sg_table = kzalloc(2 * sizeof(*sg_table), GFP_KERNEL);

		entry = (struct pme_pmtcc_read_request_msg_t *)
				input_data;
		entry->header.protocol_version = pme_rev1;
		entry->header.msg_length = read_size;
		entry->table_id = tbl_id;

		/* build fd */
		memset(&fd, 0, sizeof(fd));
		qm_sg_entry_set64(&sg_table[0], pme_suspend_map(save_db->pdev,
				output_data));
		sg_table[0].length = read_reply_size;
		qm_sg_entry_set64(&sg_table[1], pme_suspend_map(save_db->pdev,
				input_data));
		sg_table[1].length = read_size;
		sg_table[1].final = 1;
		fd.format = qm_fd_compound;
		qm_fd_addr_set64(&fd, pme_suspend_map(save_db->pdev, sg_table));
#ifdef PME_SUSPEND_DEBUG
		pr_info("Doing table %d\n", tbl_id);
#endif
		for (idx = 0; idx < num_read_entries; idx++) {
			entry->index = idx;
			memset(output_data, 0, read_reply_size);
			ret = pme_pwrmgmt_ctx_pmtcc(save_db->ctx,
				QMAN_ENQUEUE_FLAG_WAIT, &fd);

			if (ret)
				pr_err("error with pme_pwrmgmt_ctx_pmtcc\n");

			wait_for_completion(&save_db->ctx->done);

			status = pme_fd_res_status(&save_db->ctx->result_fd);
			if (status) {
				ret = -EINVAL;
				pr_err("PMTCC read status failed %d\n", status);
			}
			if (pme_fd_res_flags(&save_db->ctx->result_fd) &
			    PME_STATUS_UNRELIABLE) {
				pr_err("pme %x\n", pme_fd_res_flags(
					&save_db->ctx->result_fd));
				ret = -EINVAL;
			}
			/* copy the response */
			if (tbl_id == PME_UDG_TBL ||
			    tbl_id == PME_EQUIVALENT_BYTE_TBL) {
				/* Only copy over 8 lower bits to first byte */
				uint32_t tmp32;
				uint8_t tmp8;
				memcpy(&tmp32, output_data + read_size,
				       read_entry_size);
				tmp8 = (uint8_t)tmp32;
				memcpy(current_tbl + (idx * 1), &tmp8, 1);
			} else {
				memcpy(current_tbl + (idx * write_entry_size),
				       output_data + read_size,
				       write_entry_size);
			}
		}
		current_tbl += num_write_entries * write_entry_size;

		/* Free input and output frame data */
		kfree(output_data);
		kfree(input_data);
		kfree(sg_table);
	}
	return 0;
}

/* don't need to write zero to PME sram since POR is all zero */
static int is_all_zero(uint8_t *buf, int size)
{
	int i;
	for (i = 0; i < size; i++) {
		if (buf[i] != 0)
			return 0;
	}
	return 1;
}

static int restore_all_tables(struct portal_backup_info *save_db,
			      uint32_t pme_rev1)
{
	struct pmtcc_raw_db *db = &save_db->db;
	enum pme_pmtcc_table_id tbl_id;
	int i, ret;
	uint8_t *current_tbl = db->alldb;

	for (i = 0; i < ARRAY_SIZE(table_list); i++) {
		int num_read_entries, read_size, read_reply_size, write_size,
			read_entry_size, write_entry_size, num_write_entries;
		int idx;
		struct pme_pmtcc_write_request_msg_t *entry;
		struct qm_fd fd;
		uint8_t *input_data;
		enum pme_status status;

		tbl_id = table_list[i];
		ret = get_table_attributes(tbl_id, pme_rev1, &num_read_entries,
			&num_write_entries, &read_size, &read_reply_size,
			&write_size, &read_entry_size, &write_entry_size);

		/* Allocate input frame data */
		input_data = kzalloc(write_size, GFP_KERNEL);

		entry = (struct pme_pmtcc_write_request_msg_t *)
				input_data;
		entry->header.protocol_version = pme_rev1;
		entry->header.msg_type = 0x01; /* write */
		entry->header.msg_length = write_size;
		entry->table_id = tbl_id;

		/* build fd */
		memset(&fd, 0, sizeof(fd));
		qm_fd_addr_set64(&fd, pme_suspend_map(save_db->pdev,
				input_data));
		fd.format = qm_fd_contig_big;
		fd.length29 = write_size;
#ifdef PME_SUSPEND_DEBUG
		pr_info("Doing table %d\n", tbl_id);
#endif
		for (idx = 0; idx < num_write_entries; idx++) {
			if (is_all_zero(current_tbl + (idx * write_entry_size),
					write_entry_size)) {
				continue;
			}
			entry->indexed_entry.index = idx;

			memcpy(input_data + (write_size - write_entry_size),
			       current_tbl + (idx * write_entry_size),
			       write_entry_size);

			ret = pme_pwrmgmt_ctx_pmtcc(save_db->ctx,
				QMAN_ENQUEUE_FLAG_WAIT, &fd);

			if (ret)
				pr_err("error with pmtcc\n");

			wait_for_completion(&save_db->ctx->done);

			status = pme_fd_res_status(&save_db->ctx->result_fd);
			if (status) {
				ret = -EINVAL;
				pr_err("PMTCC write status fail %d\n", status);
			}
			if (pme_fd_res_flags(&save_db->ctx->result_fd) &
			    PME_STATUS_UNRELIABLE) {
				pr_err("pme %x\n", pme_fd_res_flags(
					&save_db->ctx->result_fd));
				ret = -EINVAL;
			}
		}
		current_tbl += num_write_entries * write_entry_size;

		/* Free input and output frame data */
		kfree(input_data);
	}
	return 0;
}

int fsl_pme_save_db(struct pme2_private_data *priv_data)
{
	int ret;
	struct portal_backup_info *save_db = &priv_data->save_db;

#ifdef PME_SUSPEND_DEBUG
	print_debug(priv_data->pme_rev1);
#endif
	ret = save_all_tables(save_db, priv_data->pme_rev1);

	return ret;
}

static int is_pme_active(void)
{
	uint32_t val;
	int ret;

	ret = pme_attr_get(pme_attr_pmstat, &val);
	if (ret) {
		pr_err("Error reading activity bit\n");
		return ret;
	}
	return val;
}

/**
 * pme_suspend - power management suspend function
 *
 * @priv_data: pme2 device private data
 *
 * Saves the pme device volatile state prior to suspension.
 * CCSR space and SRAM state is saved to DDR
 */
int pme_suspend(struct pme2_private_data *priv_data)
{
	int ret;
	struct ccsr_backup_info *ccsr_info;
	struct portal_backup_info *db_info;

	ccsr_info = &priv_data->save_ccsr;
	db_info = &priv_data->save_db;

	pme_attr_get(pme_attr_faconf_en, &ccsr_info->save_faconf_en);
	pme_attr_get(pme_attr_cdcr, &ccsr_info->save_cdcr);

	/* disable pme */
	pme_attr_set(pme_attr_faconf_en, 0);
	/* disable caching, only SRE will be flushed. FC caching already off */
	pme_attr_set(pme_attr_cdcr, 0xffffffff);

	/* wait until device is not active */
	while (is_pme_active()) {
		cpu_relax();
		/* TODO: sanity check */
	}
#ifdef PME_SUSPEND_DEBUG
	pr_info("PME is quiescent\n");
#endif

	/* save CCSR space */
	save_all_ccsr(ccsr_info, priv_data->regs);

#ifdef PME_SUSPEND_DEBUG
	pr_info("First reg read is %u\n",
		ccsr_info->regdb.pmfa.faconf);
	pr_info("Last reg read is %u\n",
		ccsr_info->regdb.gen.pm_ip_rev_2);
#endif

	/* save sram, must first configure the new exclusive fq before
	 * enabling pme */
	ret = pme2_exclusive_set(&db_info->ctx->rx_fq);
	if (ret)
		pr_err("Error getting exclusive mode\n");

	/* save sram database, hook into pme_suspend. enable pme first */
	pme_attr_set(pme_attr_faconf_en, 1);
	ret = fsl_pme_save_db(priv_data);
	/* disable pme */
	pme_attr_set(pme_attr_faconf_en, 0);

	/* wait until device is not active */
	while (is_pme_active()) {
		cpu_relax();
		/* TODO: sanity check */
	}
#ifdef PME_SUSPEND_DEBUG
	pr_info("PME is quiescent\n");
#endif

#ifdef PME_SUSPEND_DEBUG
	/* set the PME reset bit */
	pme_attr_set(pme_attr_faconf_rst, 1);
	/* clear the PME reset bit */
	pme_attr_set(pme_attr_faconf_rst, 0);
#endif

	return 0;
}

/**
 * pme_resume - power management resume function
 *
 * @priv_data: pme2 device private data
 *
 * Restores the pme device to its original state prior to suspension.
 * CCSR space and SRAM state is restored
 */
int pme_resume(struct pme2_private_data *priv_data)
{
	int ret;
	struct ccsr_backup_info *ccsr_info;
	struct portal_backup_info *db_info;

	ccsr_info = &priv_data->save_ccsr;
	db_info = &priv_data->save_db;

#ifdef PME_SUSPEND_DEBUG
	pr_info("fsl_pme_restore_db\n");
	print_debug(priv_data->pme_rev1);
#endif

	/* when PME was saved, it was disabled. Therefore it will remain */
	restore_all_ccsr(ccsr_info, priv_data->regs);
	/* restore caching state */
	pme_attr_set(pme_attr_cdcr, ccsr_info->save_cdcr);

	/* set private exclusive mode before enabling pme */
	/* save sram, must first configure the new exclusive fq before
	 * enabling pme */
	ret = pme2_exclusive_set(&db_info->ctx->rx_fq);
	if (ret)
		pr_err("Error getting exclusive mode\n");

	/* save sram database, hook into pme_suspend. enable pme first */
	pme_attr_set(pme_attr_faconf_en, 1);

	ret = restore_all_tables(db_info, priv_data->pme_rev1);

	/* disable pme */
	pme_attr_set(pme_attr_faconf_en, 0);
	/* wait until device is not active */
	while (is_pme_active()) {
		cpu_relax();
		/* TODO: sanity check */
	}

	/* restore EFQC register */
	pme_attr_set(pme_attr_efqc, ccsr_info->regdb.pmfa.efqc);

	/* restore pme enable state */
	pme_attr_set(pme_attr_faconf_en, ccsr_info->save_faconf_en);

	return 0;
}


/**
 * init_pme_suspend - initialize pme resources for power management
 *
 * @priv_data: pme2 device private data
 *
 * All resources required to suspend the PME device are allocated.
 * They include memory,frame queues, platform device
 */
int init_pme_suspend(struct pme2_private_data *priv_data)
{
	int ret;
	struct ccsr_backup_info *ccsr_info;
	struct portal_backup_info *db_info;

	ccsr_info = &priv_data->save_ccsr;
	db_info = &priv_data->save_db;

	db_info->pdev = platform_device_alloc("fsl_pme_suspend", -1);
	if (!db_info->pdev)
		goto failed_alloc_device;
	if (dma_set_mask(&db_info->pdev->dev, DMA_BIT_MASK(40)))
		goto failed_dma_mask;
	if (platform_device_add(db_info->pdev))
		goto failed_device_add;

	/* allocate frame queues */
	ret = create_pwrmgmt_ctx(db_info);
	if (ret)
		goto failed_create_pwrmgmt_ctx;

	ret = alloc_databases(priv_data);
	if (ret)
		goto failed_alloc_databases;

	return 0;

failed_alloc_databases:
	delete_pwrmgmt_ctx(db_info);
failed_create_pwrmgmt_ctx:
	platform_device_del(db_info->pdev);
failed_device_add:
failed_dma_mask:
	platform_device_put(db_info->pdev);
	db_info->pdev = NULL;
failed_alloc_device:
	return -ENOMEM;
}

/**
 * exit_pme_suspend - release pme resources for power management
 *
 * @priv_data: pme2 device private data
 *
 * All resources required to suspend the PME device are released.
 * They include memory,frame queues, platform device
 */
void exit_pme_suspend(struct pme2_private_data *priv_data)
{
	struct portal_backup_info *db_info;

	db_info = &priv_data->save_db;

	free_databases(db_info);
	delete_pwrmgmt_ctx(db_info);
	platform_device_del(db_info->pdev);
	platform_device_put(db_info->pdev);
	db_info->pdev = NULL;
}

#endif /* CONFIG_PM */

