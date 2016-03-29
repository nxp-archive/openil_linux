/* Copyright 2013 Freescale Semiconductor, Inc. */

#include "../dce_sys.h"
#include "dce_flow.h"
#include "dce_helper.h"

#define LOW_PRIORITY_WQ	7
#define DEXP_MAX	22
#define DEXP_OFFSET	6
#define DMANT_MAX	16

#define MAX_FIFO_SIZE	256

/* Internal-only flow flags, mustn't conflict with exported ones */
#define DCE_FLOW_FLAG_DEAD		0x80000000
#define DCE_FLOW_FLAG_FINISHING		0x40000000
#define DCE_FLOW_FLAG_FINISHED		0x20000000
#define DCE_FLOW_FLAG_INITIALIZING	0x10000000
#define DCE_FLOW_FLAG_PRIVATE		0xf8000000 /* mask of them all */

/* Internal-only cmd flags, musn't conflict with exported ones */
#define DCE_FLOW_OP_PRIVATE		0x80000000 /* mask of them all */

static enum qman_cb_dqrr_result cb_dqrr(struct qman_portal *, struct qman_fq *,
				const struct qm_dqrr_entry *);
static void cb_ern(struct qman_portal *, struct qman_fq *,
				const struct qm_mr_entry *);
static void cb_fqs(struct qman_portal *, struct qman_fq *,
				const struct qm_mr_entry *);
static const struct qman_fq_cb dce_fq_base_rx = {
	.fqs = cb_fqs,
	.ern = cb_ern
};
static const struct qman_fq_cb dce_fq_base_tx = {
	.dqrr = cb_dqrr,
	.fqs = cb_fqs
};

/* this is hitting the rx FQ with a large blunt instrument, ie. park()
 * does a retire, query, oos, and (re)init. It's possible to force-eligible the
 * rx FQ instead, then use a DCA_PK within the cb_dqrr() callback to park it.
 * Implement this optimisation later if it's an issue (and incur the additional
 * complexity in the state-machine). */
static int park(struct qman_fq *fq, struct qm_mcc_initfq *initfq)
{
	int ret;
	u32 flags;

	ret = qman_retire_fq(fq, &flags);
	if (ret)
		return ret;
	BUG_ON(flags & QMAN_FQ_STATE_BLOCKOOS);
	/* We can't revert from now on */
	ret = qman_query_fq(fq, &initfq->fqd);
	BUG_ON(ret);
	ret = qman_oos_fq(fq);
	BUG_ON(ret);
	/* can't set QM_INITFQ_WE_OAC and QM_INITFQ_WE_TDTHRESH
	 * at the same time */
	initfq->we_mask = QM_INITFQ_WE_MASK & ~QM_INITFQ_WE_TDTHRESH;
	ret = qman_init_fq(fq, 0, initfq);
	BUG_ON(ret);
	initfq->we_mask = QM_INITFQ_WE_TDTHRESH;
	ret = qman_init_fq(fq, 0, initfq);
	BUG_ON(ret);
	return 0;
}

static int configure_tx(struct fsl_dce_flow *flow, bool use_specified_txfq_dest,
			u16 dest_qm_channel)
{
	struct qm_mcc_initfq initfq;
	u32 qinit_flags = QMAN_INITFQ_FLAG_SCHED;
	int ret;

	initfq.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL;
	initfq.fqd.dest.wq = LOW_PRIORITY_WQ;
	initfq.fqd.fq_ctrl = 0; /* disable stashing */
	if (use_specified_txfq_dest) {
		/* TODO: this path not supported at the moment */
		BUG();
		initfq.fqd.dest.channel = dest_qm_channel;
		/* Set hold-active *IFF* it's a pool channel */
		if (dest_qm_channel >= qm_channel_pool1)
			initfq.fqd.fq_ctrl |= QM_FQCTRL_HOLDACTIVE;
	} else {
		qinit_flags |= QMAN_INITFQ_FLAG_LOCAL;
	}
	ret = qman_init_fq(&flow->fq_tx, qinit_flags, &initfq);
	return ret;
}

static int configure_rx(struct fsl_dce_flow *flow, struct dce_bman_cfg *bcfg,
			dma_addr_t scr)
{
	int ret;
	struct qm_mcc_initfq initfq;
	struct dce_context_a *dce_ctx_a =
		(struct dce_context_a *)&initfq.fqd.context_a;
	struct dce_context_b *dce_ctx_b =
		(struct dce_context_b *)&initfq.fqd.context_b;

	pr_debug("dce_flow configure_rx: flow %p, bcfg %p, scr 0x%llx\n",
		flow, bcfg, scr);

	memset(&initfq, 0, sizeof(initfq));

	initfq.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA |
				QM_INITFQ_WE_CONTEXTB;
	/* compression channel uses sub-portal 0, decompression sub-portal 1 */
	initfq.fqd.dest.channel = (flow->mode == DCE_COMPRESSION) ?
		qm_channel_dce : qm_channel_dce + 1;
	initfq.fqd.dest.wq = LOW_PRIORITY_WQ;

	/*
	 * bit shift scr since it is required to be 64B aligned and the
	 * hardware assumes lower 6 bits to be zero
	 */
	BUG_ON(scr & 0x3F);
	dce_context_a_set_scrp(dce_ctx_a, scr);
	SET_BF64(dce_ctx_a->d64, DCE_CONTEXT_A_TSIZE,
		((bcfg) ? bcfg->tsize : 0));
	/* adjust DEXP according to spec */
	if (bcfg && bcfg->dbpid)  {
		if (bcfg->dexp == DEXP_MAX)
			SET_BF64(dce_ctx_a->d64, DCE_CONTEXT_A_DEXP, 0);
		else
			SET_BF64(dce_ctx_a->d64, DCE_CONTEXT_A_DEXP,
				(bcfg->dexp - DEXP_OFFSET));
		/* adjust DMANT according to spec */
		if (bcfg->dmant == DMANT_MAX)
			SET_BF64(dce_ctx_a->d64, DCE_CONTEXT_A_DMANT, 0);
		else
			SET_BF64(dce_ctx_a->d64, DCE_CONTEXT_A_DMANT,
				bcfg->dmant);
	}
	SET_BF64(dce_ctx_a->d64, DCE_CONTEXT_A_TBPID,
		((bcfg) ? bcfg->tbpid : 0));
	/* Setup context_b field */
	SET_BF32(dce_ctx_b->d32, DCE_CONTEXT_B_DBPID,
		((bcfg) ? bcfg->dbpid : 0));
	SET_BF32(dce_ctx_b->d32, DCE_CONTEXT_B_FQID,
		qman_fq_fqid(&flow->fq_tx));

	ret = qman_init_fq(&flow->fq_rx, QMAN_INITFQ_FLAG_SCHED, &initfq);
	return ret;
}

void fsl_dce_flow_setopt_fqtx_id(struct fsl_dce_flow *flow, u32 id)
{
	flow->fqtx_id = id;
}

void fsl_dce_flow_setopt_fqrx_id(struct fsl_dce_flow *flow, u32 id)
{
	flow->fqrx_id = id;
}

void fsl_dce_flow_setopt_bcfg(struct fsl_dce_flow *flow,
				struct dce_bman_cfg bcfg)
{
	flow->bcfg = bcfg;
}

int fsl_dce_flow_setopt_txfqdest(struct fsl_dce_flow *flow, u32 dest)
{
	if (dest == 0xffffffff) {
		flow->use_specified_txfq_dest = false;
	} else {
		flow->use_specified_txfq_dest = true;
		flow->txfq_dest = (u32)dest;
	}

	return 0;
}

int fsl_dce_flow_setopt_outputoffset(struct fsl_dce_flow *flow, u32 val)
{
	switch (val) {
	case DCE_PROCESS_OO_NONE_LONG:
	case DCE_PROCESS_OO_32B:
	case DCE_PROCESS_OO_64B:
	case DCE_PROCESS_OO_128B:
	case DCE_PROCESS_OO_256B:
	case DCE_PROCESS_OO_512B:
	case DCE_PROCESS_OO_1024B:
	case DCE_PROCESS_OO_NON_SHORT:
		SET_BF32(flow->proc_flags, DCE_PROCESS_OO, val);
		return 0;
	default:
		return -EINVAL;
	}
}

int fsl_dce_flow_setopt_compression_effort(struct fsl_dce_flow *flow,
					u32 val)
{
	switch (val) {
	case DCE_PROCESS_CE_NONE:
	case DCE_PROCESS_CE_STATIC_HUFF_STRMATCH:
	case DCE_PROCESS_CE_HUFF_ONLY:
	case DCE_PROCESS_CE_BEST_POSSIBLE:
		SET_BF32(flow->proc_flags, DCE_PROCESS_CE, val);
		return 0;
	default:
		return -EINVAL;
	}
}

int fsl_dce_flow_setopt_release_input(struct fsl_dce_flow *flow, bool val)
{
	if (val)
		SET_BF32_TK(flow->proc_flags, DCE_PROCESS_RB, YES);
	else
		SET_BF32_TK(flow->proc_flags, DCE_PROCESS_RB, NO);
	return 0;
}

int fsl_dce_flow_setopt_base64(struct fsl_dce_flow *flow, bool val)
{
	if (val)
		SET_BF32_TK(flow->proc_flags, DCE_PROCESS_B64, YES);
	else
		SET_BF32_TK(flow->proc_flags, DCE_PROCESS_B64, NO);
	return 0;
}

int fsl_dce_flow_init(struct fsl_dce_flow *flow,
		struct fsl_dce_flow_init_params *params)
{
	int ret = -EINVAL, ret_tmp;

	if (!params) {
		pr_debug("dce_flow: params is null\n");
		goto failed_params;
	}

	if (!params->fifo_depth) {
		pr_err("dce_flow: invalid fifo depth of zero\n");
		goto failed_params;
	}
	if (params->fifo_depth > MAX_FIFO_SIZE) {
		pr_err("dce_flow: fifo depth too large %d > %d\n",
			params->fifo_depth, MAX_FIFO_SIZE);
		goto failed_params;
	}

	flow->proc_flags = 0;
	SET_BF32_TK(flow->proc_flags, DCE_PROCESS_OO, NONE_LONG);
	SET_BF32_TK(flow->proc_flags, DCE_PROCESS_Z_FLUSH, NO_FLUSH);
	SET_BF32_TK(flow->proc_flags, DCE_PROCESS_CF, DEFLATE);
	SET_BF32_TK(flow->proc_flags, DCE_PROCESS_CE, BEST_POSSIBLE);
	SET_BF32_TK(flow->proc_flags, DCE_PROCESS_SCUS, NORMAL_MODE);


	/* set callback functions */
	flow->cbs.process_cb = params->process_cb;
	flow->cbs.nop_cb = params->nop_cb;
	flow->cbs.scr_invalidate_cb = params->scr_invalidate_cb;
	flow->cbs.base_cb = params->base_cb;
	/* set compression/decompression mode */
	flow->mode = params->mode;

	/*
	 * QMan driver invokes these callback function when a frame is dequeued
	 * on the tx frame queue
	 */
	flow->fq_tx.cb = dce_fq_base_tx;
	flow->fq_rx.cb = dce_fq_base_rx;

	/*
	 * allow a fifo depth of 1. Need to bump to 2 for kfifo since
	 * it only allows power of 2, starting with 2. Otherwise it
	 * will round down.
	 */
	flow->wanted_fifo_depth = params->fifo_depth;
	if (params->fifo_depth == 1)
		ret = kfifo_alloc(&flow->fifo, 2, GFP_KERNEL);
	else
		ret = kfifo_alloc(&flow->fifo, flow->wanted_fifo_depth,
				GFP_KERNEL);
	if (ret) {
		pr_err("dce_flow: error allocating kfifo 0x%x\n", ret);
		goto failed_params;
	}
	flow->actual_fifo_depth = kfifo_size(&flow->fifo);

	pr_debug("Requested fifo %d, actual %d\n",
		flow->wanted_fifo_depth, flow->actual_fifo_depth);

	/* Create the Rx frame queue. Use QMan multi-core locking always */
	ret = qman_create_fq(flow->fqrx_id, QMAN_FQ_FLAG_TO_DCPORTAL |
			((flow->fqrx_id) ?  0 : QMAN_FQ_FLAG_DYNAMIC_FQID) |
			QMAN_FQ_FLAG_LOCKED, &flow->fq_rx);
	if (ret) {
		pr_err("dce_flow: failed to create RX frame queue 0x%x\n", ret);
		goto failed_create_rx_fq;
	}
	ret = qman_create_fq(flow->fqtx_id, QMAN_FQ_FLAG_NO_ENQUEUE |
			((flow->fqtx_id) ?  0 : QMAN_FQ_FLAG_DYNAMIC_FQID) |
			QMAN_FQ_FLAG_LOCKED , &flow->fq_tx);
	if (ret) {
		pr_err("dce_flow: failed to create TX frame queue 0x%x\n", ret);
		goto failed_create_tx_fq;
	}

	/* Setup RX FQ */
	ret = configure_rx(flow, &flow->bcfg, params->scr);
	if (ret) {
		pr_err("dce_flow: failed to configure RX frame queue 0x%x\n",
			ret);
		goto failed_configure_rx_fq;
	}

	/* Setup TX FQ */
	ret = configure_tx(flow, flow->use_specified_txfq_dest,
			flow->txfq_dest);
	if (ret) {
		pr_err("dce_flow: failed to configure TX frame queue 0x%x\n",
			ret);
		goto failed_configure_tx_fq;
	}
	return 0;
failed_configure_tx_fq:
	ret_tmp = qman_oos_fq(&flow->fq_rx);
	BUG_ON(ret_tmp);
failed_configure_rx_fq:
	qman_destroy_fq(&flow->fq_tx, 0);
failed_create_tx_fq:
	qman_destroy_fq(&flow->fq_rx, 0);
failed_create_rx_fq:
	kfifo_free(&flow->fifo);
failed_params:
	return ret;
}

int fsl_dce_flow_fifo_len(struct fsl_dce_flow *flow)
{
	return kfifo_len(&flow->fifo);
}

int fsl_dce_flow_finish(struct fsl_dce_flow *flow, u32 flags)
{
	int ret = 0;
	struct qm_mcc_initfq initfq;

	/* This pipeline must be empty */
	if (kfifo_len(&flow->fifo))
		return -EBUSY;

	/* Park fq_rx */
	ret = park(&flow->fq_rx, &initfq);
	/**
	 * All the conditions for park() to succeed should be met. If
	 * this fails, there's a bug (s/w or h/w).
	 */
	if (ret)
		pr_err("fsl_dce: park() should never fail! (%d)\n", ret);
	/* Rx/Tx are empty so retirement should be immediate */
	ret = qman_retire_fq(&flow->fq_rx, &flags);
	BUG_ON(ret);
	BUG_ON(flags & QMAN_FQ_STATE_BLOCKOOS);
	ret = qman_retire_fq(&flow->fq_tx, &flags);
	BUG_ON(ret);
	BUG_ON(flags & QMAN_FQ_STATE_BLOCKOOS);
	/* OOS and destroy */
	ret = qman_oos_fq(&flow->fq_rx);
	BUG_ON(ret);
	ret = qman_oos_fq(&flow->fq_tx);
	BUG_ON(ret);
	qman_destroy_fq(&flow->fq_rx, 0);
	qman_destroy_fq(&flow->fq_tx, 0);
	kfifo_free(&flow->fifo);
	return 0;
}

/**
 * Used for 'work' APIs, convert DCE->QMAN wait flags. The DCE and
 * QMAN "wait" flags have been aligned so that the below conversion should
 * compile with good straight-line speed.
 */
static inline u32 ctrl2eq(u32 flags)
{
#ifdef CONFIG_FSL_DPA_CAN_WAIT
	return flags & (QMAN_ENQUEUE_FLAG_WAIT | QMAN_ENQUEUE_FLAG_WAIT_INT);
#else
	return flags;
#endif
}

/*
 * Have qman enqueue call this function just before setting the verb so
 * that we write to our fifo just before having qman process the request.
 * This way we don't have to remove (rollback) this transaction
 */
struct qman_precommit_arg {
	struct fsl_dce_flow *flow;
	struct fsl_dce_cmd_token *token;
};

static int _pre_commit_cb(void *arg)
{
	struct qman_precommit_arg *fifo_arg = (struct qman_precommit_arg *)arg;
	if (unlikely(kfifo_put(&fifo_arg->flow->fifo, *fifo_arg->token) == 0))
		return -ENOMEM;
	return 0;
}

static inline int submit_job(struct fsl_dce_flow *flow, u32 flags,
			struct qm_fd *fd, struct fsl_dce_cmd_token *token)
{
	int ret = 0;
	struct qman_precommit_arg cb_arg;

	cb_arg.flow = flow;
	cb_arg.token = token;

	if (unlikely(kfifo_len(&flow->fifo) == flow->wanted_fifo_depth))
		return -ENOMEM;

	ret = qman_enqueue_precommit(&flow->fq_rx, fd, ctrl2eq(flags),
		_pre_commit_cb, &cb_arg);

	return ret;
}

int fsl_dce_nop(struct fsl_dce_flow *flow, u32 flags, void *callback_tag)
{
	struct qm_fd fd;
	struct fsl_dce_cmd_token token;

	token.callback_tag = callback_tag;
	/* enqueue the NOP command to DCE */
	memset(&fd, 0, sizeof(fd));
	fsl_dce_cmd_set_nop(&fd.cmd);
	return submit_job(flow, flags, &fd, &token);
}

int fsl_dce_process(struct fsl_dce_flow *flow, u32 flags, struct qm_fd *fd,
		void *callback_tag)
{
	struct fsl_dce_cmd_token token;

	token.callback_tag = callback_tag;
	/* set process options flags */
	fd->cmd |= flow->proc_flags;
	/* This is the primary interface to compress/decompress frames */
	fsl_dce_cmd_set_process(&fd->cmd);
	return submit_job(flow, flags, fd, &token);
}

int fsl_dce_scr_invalidate(struct fsl_dce_flow *flow, u32 flags,
			void *callback_tag)
{
	struct qm_fd fd;
	struct fsl_dce_cmd_token token;

	memset(&fd, 0, sizeof(fd));
	token.callback_tag = callback_tag;
	/* enqueue the DCE_CMD_CTX_INVALIDATE command to DCE */
	fsl_dce_cmd_set_ctx_invalidate(&fd.cmd);
	return submit_job(flow, flags, &fd, &token);
}

static inline void cb_helper(__always_unused struct qman_portal *portal,
			struct fsl_dce_flow *flow, const struct qm_fd *fd,
			enum dce_status status)
{
	struct fsl_dce_cmd_token token;

	if (unlikely(kfifo_get(&flow->fifo, &token) == 0)) {
		pr_err("dce_flow: fifo empty\n");
		return;
	}
	flow->cbs.base_cb(flow, fd, token.callback_tag);
}

/* TODO: this scheme does not allow DCE receivers to use held-active at all. Eg.
 * there's no configuration of held-active for 'fq', and if there was, there's
 * (a) nothing in the cb_dqrr() to support "park" or "defer" logic, and (b)
 * nothing in cb_fqs() to support a delayed FQPN (DCAP_PK) notification. */
static enum qman_cb_dqrr_result cb_dqrr(struct qman_portal *portal,
			struct qman_fq *fq, const struct qm_dqrr_entry *dq)
{
	enum dce_status status = dq->fd.status & DCE_PROCESS_STATUS_MASK;
	struct fsl_dce_flow *flow = (struct fsl_dce_flow *)fq;

	/* Put flow into DEAD state if a serious error is received ? */
	cb_helper(portal, flow, &dq->fd, status);
	return qman_cb_dqrr_consume;
}

static void cb_ern(__always_unused struct qman_portal *portal,
		struct qman_fq *fq, const struct qm_mr_entry *mr)
{
	pr_err("ERN un-expected\n");
	BUG();
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

