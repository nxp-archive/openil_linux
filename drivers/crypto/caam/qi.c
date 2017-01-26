/*
 * CAAM/SEC 4.x QI transport/backend driver
 * Queue Interface backend functionality
 *
 * Copyright 2013 Freescale Semiconductor, Inc.
 */

#include <linux/cpumask.h>
#include <linux/kthread.h>
#include <linux/fsl_qman.h>

#include "regs.h"
#include "qi.h"
#include "desc.h"
#include "intern.h"
#include "desc_constr.h"
#include "sg_sw_qm.h"

#define PRE_HDR_LEN		2	/* Length in u32 words */
#define PREHDR_RSLS_SHIFT	31
#ifndef CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT
/* If DPA_ETH is not available, then use a reasonably backlog per CPU */
#define MAX_RSP_FQ_BACKLOG_PER_CPU	64
#endif
#define CAAM_QI_MEMCACHE_SIZE	256	/* Length of a single buffer in
					   the QI driver memory cache. */

/*
 * The jobs are processed by the driver against a driver context.
 * With every cryptographic context, a driver context is attached.
 * The driver context contains data for private use by driver.
 * For the applications, this is an opaque structure.
 */

struct caam_drv_ctx {
	u32 prehdr[PRE_HDR_LEN];	/* Preheader placed before shrd desc */
	u32 sh_desc[MAX_SDLEN];		/* Shared descriptor */
	dma_addr_t context_a; /* shared descriptor dma address */
	struct qman_fq *req_fq;		/* Request frame queue to caam */
	struct qman_fq *rsp_fq;		/* Response frame queue from caam */
	int cpu;			/* cpu on which to recv caam rsp */
	struct device *qidev;		/* device pointer for QI backend */
} ____cacheline_aligned;

struct caam_napi {
	struct napi_struct irqtask;	/* IRQ task for QI backend */
	struct qman_portal *p;
};

/*
 * percpu private data structure to main list of pending responses expected
 * on each cpu.
 */
struct caam_qi_pcpu_priv {
	struct caam_napi caam_napi;
	struct net_device net_dev;	/* netdev used by NAPI */
	struct qman_fq rsp_fq;		/* Response FQ from CAAM */
} ____cacheline_aligned;

static DEFINE_PER_CPU(struct caam_qi_pcpu_priv, pcpu_qipriv);

struct caam_qi_priv {
	struct qman_cgr rsp_cgr;	/* QMAN response CGR */
	struct platform_device *qi_pdev; /* Platform device for QI backend */
};

static struct caam_qi_priv qipriv ____cacheline_aligned;

/*
 * This is written by one core - the one that initialized the CGR, and
 * read by multiple cores (all the others)
 */
static bool caam_congested __read_mostly;

#ifdef CONFIG_DEBUG_FS
/*
 * This is a counter for the number of times the congestion group (where all
 * the response queueus are) was congested. Incremented each time the congestion
 * callback is called with congested == true,.
 */
static u64 times_congested;
#endif
/*
 * CPU from where the module initialised. This is required because
 * QMAN driver requires CGRs to be removed from same CPU from where
 * they were originally allocated
 */
static int mod_init_cpu;

/*
 * This is a a cache of buffers, from which the users of CAAM QI driver
 * can allocate short (currently 128B) buffers. It's speedier than
 * doing malloc on the hotpath.
 * NOTE: A more elegant solution would be to have some headroom in the frames
 *       being processed. This can be added by the dpa_eth driver. This would
 *       pose a problem for userspace application processing which cannot
 *       know of this limitation. So for now, this will work.
 * NOTE: The memcache is SMP-safe. No need to handle spinlocks in-here
 */
static struct kmem_cache *qi_cache;

bool caam_drv_ctx_busy(struct caam_drv_ctx *drv_ctx)
{
	return caam_congested;
}
EXPORT_SYMBOL(caam_drv_ctx_busy);

int caam_qi_enqueue(struct device *qidev, struct caam_drv_req *req)
{
	struct qm_fd fd;
	int ret;
	const size_t size = 2 * sizeof(struct qm_sg_entry);
	int num_retries = 0;

	fd.cmd = 0;
	fd.format = qm_fd_compound;
	fd.cong_weight = req->fd_sgt[1].length;

	cpu_to_hw_sg(&req->fd_sgt[0]);
	cpu_to_hw_sg(&req->fd_sgt[1]);
	fd.addr = dma_map_single(qidev, req->fd_sgt, size,
				 DMA_BIDIRECTIONAL);
	if (dma_mapping_error(qidev, fd.addr)) {
		dev_err(qidev, "DMA mapping error for QI enqueue request\n");
		return -EIO;
	}

	do {
		ret = qman_enqueue(req->drv_ctx->req_fq, &fd, 0);
		if (likely(!ret))
			return 0;

		if (-EBUSY != ret)
			break;
		num_retries++;
	} while (num_retries < 10000);

	dev_err(qidev, "qman_enqueue failed: %d\n", ret);

	return ret;
}
EXPORT_SYMBOL(caam_qi_enqueue);

static void caam_fq_ern_cb(struct qman_portal *qm, struct qman_fq *fq,
			   const struct qm_mr_entry *msg)
{
	const struct qm_fd *fd;
	struct caam_drv_req *drv_req;
	const size_t size = 2 * sizeof(struct qm_sg_entry);
	struct device *qidev = &(raw_cpu_ptr(&pcpu_qipriv)->net_dev.dev);

	fd = &msg->ern.fd;

	if (qm_fd_compound != fd->format) {
		dev_err(qidev, "Non compound FD from CAAM\n");
		return;
	}

	drv_req = ((struct caam_drv_req *)phys_to_virt(fd->addr));
	if (!drv_req) {
		dev_err(qidev,
			"Can't find original request for caam response\n");
		return;
	}

	dma_unmap_single(drv_req->drv_ctx->qidev, fd->addr,
			 size, DMA_BIDIRECTIONAL);

	drv_req->cbk(drv_req, -EIO);
}

static struct qman_fq *create_caam_req_fq(struct device *qidev,
					  struct qman_fq *rsp_fq,
					  dma_addr_t hwdesc,
					  int fq_sched_flag)
{
	int ret, flags;
	struct qman_fq *req_fq;
	struct qm_mcc_initfq opts;

	req_fq = kzalloc(sizeof(*req_fq), GFP_ATOMIC);
	if (!req_fq) {
		dev_err(qidev, "Mem alloc for CAAM req FQ failed\n");
		return ERR_PTR(-ENOMEM);
	}

	req_fq->cb.ern = caam_fq_ern_cb;
	req_fq->cb.fqs = NULL;

	flags = QMAN_FQ_FLAG_DYNAMIC_FQID |
		QMAN_FQ_FLAG_TO_DCPORTAL |
		QMAN_FQ_FLAG_LOCKED;

	ret = qman_create_fq(0, flags, req_fq);
	if (ret) {
		dev_err(qidev, "Failed to create session REQ FQ\n");
		goto create_req_fq_fail;
	}

	flags = fq_sched_flag;
	opts.we_mask = QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_DESTWQ |
			QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;

	opts.fqd.fq_ctrl = QM_FQCTRL_CPCSTASH;
	opts.fqd.dest.channel = qm_channel_caam;
	opts.fqd.dest.wq = 2;
	opts.fqd.context_b = qman_fq_fqid(rsp_fq);
	opts.fqd.context_a.hi = upper_32_bits(hwdesc);
	opts.fqd.context_a.lo = lower_32_bits(hwdesc);

	ret = qman_init_fq(req_fq, flags, &opts);
	if (ret) {
		dev_err(qidev, "Failed to init session req FQ\n");
		goto init_req_fq_fail;
	}
#ifdef DEBUG
	dev_info(qidev, "Allocated request FQ %u for CPU %u\n",
		 req_fq->fqid, smp_processor_id());
#endif
	return req_fq;

init_req_fq_fail:
	qman_destroy_fq(req_fq, 0);

create_req_fq_fail:
	kfree(req_fq);
	return ERR_PTR(ret);
}

static int empty_retired_fq(struct device *qidev, struct qman_fq *fq)
{
	int ret;
	enum qman_fq_state state;

	u32 flags = QMAN_VOLATILE_FLAG_WAIT_INT | QMAN_VOLATILE_FLAG_FINISH;
	u32 vdqcr = QM_VDQCR_PRECEDENCE_VDQCR | QM_VDQCR_NUMFRAMES_TILLEMPTY;

	ret = qman_volatile_dequeue(fq, flags, vdqcr);
	if (ret) {
		dev_err(qidev, "Volatile dequeue fail for FQ: %u\n", fq->fqid);
		return ret;
	}

	do {
		qman_poll_dqrr(16);
		qman_fq_state(fq, &state, &flags);
	} while (flags & QMAN_FQ_STATE_NE);

	return 0;
}

static int kill_fq(struct device *qidev, struct qman_fq *fq)
{
	enum qman_fq_state state;
	u32 flags;
	int ret;

	ret = qman_retire_fq(fq, &flags);
	if (ret < 0) {
		dev_err(qidev, "qman_retire_fq failed\n");
		return ret;
	}

	if (!ret)
		goto empty_fq;

	/* Async FQ retirement condition */
	if (1 == ret) {
		/* Retry till FQ gets in retired state */
		do {
			msleep(20);
			qman_fq_state(fq, &state, &flags);
		} while (qman_fq_state_retired != state);

		WARN_ON(flags & QMAN_FQ_STATE_BLOCKOOS);
		WARN_ON(flags & QMAN_FQ_STATE_ORL);
	}

empty_fq:
	if (flags & QMAN_FQ_STATE_NE) {
		ret = empty_retired_fq(qidev, fq);
		if (ret) {
			dev_err(qidev, "empty_retired_fq fail for FQ: %u\n",
				fq->fqid);
			return ret;
		}
	}

	ret = qman_oos_fq(fq);
	if (ret)
		dev_err(qidev, "OOS of FQID: %u failed\n", fq->fqid);

	qman_destroy_fq(fq, 0);

	return ret;
}

/*
 * TODO: This CAAM FQ empty logic can be improved. We can enqueue a NULL
 * job descriptor to the FQ. This must be the last enqueue request to the
 * FQ. When the response of this job comes back, the FQ is empty. Also
 * holding tanks are guaranteed to be not holding any jobs from this FQ.
 */
static int empty_caam_fq(struct qman_fq *fq)
{
	int ret;
	struct qm_mcr_queryfq_np np;

	/* Wait till the older CAAM FQ get empty */
	do {
		ret = qman_query_fq_np(fq, &np);
		if (ret)
			return ret;

		if (!np.frm_cnt)
			break;

		msleep(20);
	} while (1);

	/*
	 * Give extra time for pending jobs from this FQ in holding tanks
	 * to get processed
	 */
	msleep(20);
	return 0;
}

int caam_drv_ctx_update(struct caam_drv_ctx *drv_ctx, u32 *sh_desc)
{
	size_t size;
	u32 num_words;
	int ret;
	struct qman_fq *new_fq, *old_fq;
	struct device *qidev = drv_ctx->qidev;

	/* Check the size of new shared descriptor */
	num_words = desc_len(sh_desc);
	if (num_words > MAX_SDLEN) {
		dev_err(qidev, "Invalid descriptor len: %d words\n",
			num_words);
		return -EINVAL;
	}

	/* Note down older req FQ */
	old_fq = drv_ctx->req_fq;

	/* Create a new req FQ in parked state */
	new_fq = create_caam_req_fq(drv_ctx->qidev, drv_ctx->rsp_fq,
				    drv_ctx->context_a, 0);
	if (unlikely(IS_ERR_OR_NULL(new_fq))) {
		dev_err(qidev, "FQ allocation for shdesc update failed\n");
		return PTR_ERR(new_fq);
	}

	/* Hook up new FQ to context so that new requests keep queueing */
	drv_ctx->req_fq = new_fq;

	/* Empty and remove the older FQ */
	ret = empty_caam_fq(old_fq);
	if (ret) {
		dev_err(qidev, "Old SEC FQ empty failed\n");

		/* We can revert to older FQ */
		drv_ctx->req_fq = old_fq;

		if (kill_fq(qidev, new_fq)) {
			dev_warn(qidev, "New SEC FQ: %u kill failed\n",
				 new_fq->fqid);
		}

		return ret;
	}

	/*
	 * Now update the shared descriptor for driver context.
	 * Re-initialise pre-header. Set RSLS and SDLEN
	 */
	drv_ctx->prehdr[0] = cpu_to_caam32((1 << PREHDR_RSLS_SHIFT) |
					   num_words);

	/* Copy the new shared descriptor now */
	memcpy(drv_ctx->sh_desc, sh_desc, desc_bytes(sh_desc));

	size = sizeof(drv_ctx->sh_desc) + sizeof(drv_ctx->prehdr);
	dma_sync_single_for_device(qidev, drv_ctx->context_a,
				   size, DMA_BIDIRECTIONAL);

	/* Put the new FQ in scheduled state */
	ret = qman_schedule_fq(new_fq);
	if (ret) {
		dev_err(qidev, "Fail to sched new SEC FQ, ecode = %d\n", ret);

		/*
		 * We can kill new FQ and revert to old FQ.
		 * Since the desc is already modified, it is success case
		 */

		drv_ctx->req_fq = old_fq;

		if (kill_fq(qidev, new_fq)) {
			dev_warn(qidev, "New SEC FQ: %u kill failed\n",
				 new_fq->fqid);
		}
	} else {
		/* Remove older FQ */
		if (kill_fq(qidev, old_fq)) {
			dev_warn(qidev, "Old SEC FQ: %u kill failed\n",
				 old_fq->fqid);
		}
	}

	return 0;
}
EXPORT_SYMBOL(caam_drv_ctx_update);



struct caam_drv_ctx *caam_drv_ctx_init(struct device *qidev,
				       int *cpu,
				       u32 *sh_desc)
{
	size_t size;
	u32 num_words;
	dma_addr_t hwdesc;
	struct qman_fq *rsp_fq;
	struct caam_drv_ctx *drv_ctx;
	const cpumask_t *cpus = qman_affine_cpus();
	static DEFINE_PER_CPU(int, last_cpu);

	num_words = desc_len(sh_desc);
	if (num_words > MAX_SDLEN) {
		dev_err(qidev, "Invalid descriptor len: %d words\n",
			num_words);
		return ERR_PTR(-EINVAL);
	}

	drv_ctx = kzalloc(sizeof(*drv_ctx), GFP_ATOMIC);
	if (!drv_ctx) {
		dev_err(qidev, "Mem alloc for driver context failed\n");
		return ERR_PTR(-ENOMEM);
	}

	/* Initialise pre-header. Set RSLS and SDLEN */
	drv_ctx->prehdr[0] = cpu_to_caam32((1 << PREHDR_RSLS_SHIFT) |
					   num_words);

	/* Copy the shared descriptor now */
	memcpy(drv_ctx->sh_desc, sh_desc, desc_bytes(sh_desc));

	/* Map address for pre-header + descriptor */
	size = sizeof(drv_ctx->prehdr) + sizeof(drv_ctx->sh_desc);
	hwdesc = dma_map_single(qidev, drv_ctx->prehdr,
				size, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(qidev, hwdesc)) {
		dev_err(qidev, "DMA map error for preheader+shdesc\n");
		kfree(drv_ctx);
		return ERR_PTR(-ENOMEM);
	}

	drv_ctx->context_a = hwdesc;

	/*
	 * If the given CPU does not own the portal, choose another
	 * one with a portal.
	 */
	if (!cpumask_test_cpu(*cpu, cpus)) {
		last_cpu = cpumask_next(last_cpu, cpus);
		if (last_cpu >= nr_cpu_ids)
			last_cpu = cpumask_first(cpus);
		 *cpu = last_cpu;
	}

	drv_ctx->cpu = *cpu;

	/* Find response FQ hooked with this CPU*/
	rsp_fq = &per_cpu(pcpu_qipriv.rsp_fq, drv_ctx->cpu);
	drv_ctx->rsp_fq = rsp_fq;

	/*Attach request FQ*/
	drv_ctx->req_fq = create_caam_req_fq(qidev, rsp_fq,
					     hwdesc, QMAN_INITFQ_FLAG_SCHED);
	if (unlikely(IS_ERR_OR_NULL(drv_ctx->req_fq))) {
		dev_err(qidev, "create_caam_req_fq failed\n");
		dma_unmap_single(qidev, hwdesc, size, DMA_BIDIRECTIONAL);
		kfree(drv_ctx);
		return ERR_PTR(-ENOMEM);
	}

	drv_ctx->qidev = qidev;
	return drv_ctx;
}
EXPORT_SYMBOL(caam_drv_ctx_init);

void *qi_cache_alloc(gfp_t flags)
{
	return kmem_cache_alloc(qi_cache, flags);
}
EXPORT_SYMBOL(qi_cache_alloc);

void qi_cache_free(void *obj)
{
	kmem_cache_free(qi_cache, obj);
}
EXPORT_SYMBOL(qi_cache_free);

static int caam_qi_poll(struct napi_struct *napi, int budget)
{
	struct caam_napi *np = container_of(napi, struct caam_napi, irqtask);

	int cleaned = qman_p_poll_dqrr(np->p, budget);

	if (cleaned < budget) {
		napi_complete(napi);
		qman_p_irqsource_add(np->p, QM_PIRQ_DQRI);
	}

	return cleaned;
}


void caam_drv_ctx_rel(struct caam_drv_ctx *drv_ctx)
{
	size_t size;

	if (IS_ERR_OR_NULL(drv_ctx))
		return;

	size = sizeof(drv_ctx->sh_desc) + sizeof(drv_ctx->prehdr);

	/* Remove request FQ*/
	if (kill_fq(drv_ctx->qidev, drv_ctx->req_fq))
		dev_err(drv_ctx->qidev, "Crypto session Req FQ kill failed\n");

	dma_unmap_single(drv_ctx->qidev, drv_ctx->context_a,
			 size, DMA_BIDIRECTIONAL);

	kfree(drv_ctx);
}
EXPORT_SYMBOL(caam_drv_ctx_rel);

int caam_qi_shutdown(struct device *qidev)
{
	struct caam_qi_priv *priv = dev_get_drvdata(qidev);
	int i, ret;

	const cpumask_t *cpus = qman_affine_cpus();
	struct cpumask old_cpumask = *tsk_cpus_allowed(current);

	for_each_cpu(i, cpus) {
		struct napi_struct *irqtask;

		irqtask = &per_cpu_ptr(&pcpu_qipriv.caam_napi, i)->irqtask;

		napi_disable(irqtask);
		netif_napi_del(irqtask);

		if (kill_fq(qidev, &per_cpu(pcpu_qipriv.rsp_fq, i)))
			dev_err(qidev, "Rsp FQ kill failed, cpu: %d\n", i);
	}

	/*
	 * QMAN driver requires CGRs to be deleted from same CPU from where
	 * they were instantiated. Hence we get the module removal execute
	 * from the same CPU from where it was originally inserted.
	 */
	set_cpus_allowed_ptr(current, get_cpu_mask(mod_init_cpu));

	ret = qman_delete_cgr(&priv->rsp_cgr);
	if (ret)
		dev_err(qidev, "Delete response CGR failed: %d\n", ret);
	else
		qman_release_cgrid(priv->rsp_cgr.cgrid);

	if (qi_cache)
		kmem_cache_destroy(qi_cache);

	/* Now that we're done with the CGRs, restore the cpus allowed mask */
	set_cpus_allowed_ptr(current, &old_cpumask);

	platform_device_unregister(priv->qi_pdev);
	return ret;
}

static void rsp_cgr_cb(struct qman_portal *qm, struct qman_cgr *cgr,
			int congested)
{
	caam_congested = congested;

	if (congested) {
#ifdef CONFIG_DEBUG_FS
		times_congested++;
#endif
		pr_debug_ratelimited("CAAM rsp path congested\n");

	} else {
		pr_debug_ratelimited("CAAM rsp path congestion state exit\n");
	}
}

static int caam_qi_napi_schedule(struct qman_portal *p, struct caam_napi *np)
{
	/*
	 * In case of threaded ISR for RT enable kernel,
	 * in_irq() does not return appropriate value, so use
	 * in_serving_softirq to distinguish softirq or irq context.
	 */
	if (unlikely(in_irq() || !in_serving_softirq())) {
		/* Disable QMan IRQ source and invoke NAPI */
		int ret = qman_p_irqsource_remove(p, QM_PIRQ_DQRI);

		if (likely(!ret)) {
			np->p = p;
			napi_schedule(&np->irqtask);
			return 1;
		}
	}
	return 0;
}

static enum qman_cb_dqrr_result caam_rsp_fq_dqrr_cb(struct qman_portal *p,
					struct qman_fq *rsp_fq,
					const struct qm_dqrr_entry *dqrr)
{
	struct caam_napi *caam_napi = raw_cpu_ptr(&pcpu_qipriv.caam_napi);
	struct caam_drv_req *drv_req;
	const struct qm_fd *fd;
	const size_t size = 2 * sizeof(struct qm_sg_entry);
	struct device *qidev = &(raw_cpu_ptr(&pcpu_qipriv)->net_dev.dev);

	if (caam_qi_napi_schedule(p, caam_napi))
		return qman_cb_dqrr_stop;

	fd = &dqrr->fd;
	if (unlikely(fd->status))
		dev_err(qidev, "Error: %#x in CAAM response FD\n", fd->status);

	if (unlikely(qm_fd_compound != fd->format)) {
		dev_err(qidev, "Non compound FD from CAAM\n");
		return qman_cb_dqrr_consume;
	}

	drv_req = (struct caam_drv_req *)phys_to_virt(fd->addr);
	if (unlikely(!drv_req)) {
		dev_err(qidev,
			"Can't find original request for caam response\n");
		return qman_cb_dqrr_consume;
	}

	dma_unmap_single(drv_req->drv_ctx->qidev, fd->addr,
			 size, DMA_BIDIRECTIONAL);

	drv_req->cbk(drv_req, fd->status);

	return qman_cb_dqrr_consume;
}

static int alloc_rsp_fq_cpu(struct device *qidev, unsigned int cpu)
{
	struct qm_mcc_initfq opts;
	struct qman_fq *fq;
	int ret;
	u32 flags;

	fq = &per_cpu(pcpu_qipriv.rsp_fq, cpu);

	fq->cb.dqrr = caam_rsp_fq_dqrr_cb;

	flags = QMAN_FQ_FLAG_NO_ENQUEUE | QMAN_FQ_FLAG_DYNAMIC_FQID;

	ret = qman_create_fq(0, flags, fq);
	if (ret) {
		dev_err(qidev, "Rsp FQ create failed\n");
		return -ENODEV;
	}

	flags = QMAN_INITFQ_FLAG_SCHED;

	opts.we_mask = QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_DESTWQ |
		QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA |
		QM_INITFQ_WE_CGID | QMAN_INITFQ_FLAG_LOCAL;

	opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING |
			   QM_FQCTRL_CPCSTASH |
			   QM_FQCTRL_CGE;

	opts.fqd.dest.channel = qman_affine_channel(cpu);
	opts.fqd.cgid = qipriv.rsp_cgr.cgrid;
	opts.fqd.dest.wq = 3;
	opts.fqd.context_a.stashing.exclusive =
					QM_STASHING_EXCL_CTX |
					QM_STASHING_EXCL_DATA;

	opts.fqd.context_a.stashing.data_cl = 1;
	opts.fqd.context_a.stashing.context_cl = 1;

	ret = qman_init_fq(fq, flags, &opts);
	if (ret) {
		dev_err(qidev, "Rsp FQ init failed\n");
		return -ENODEV;
	}
#ifdef DEBUG
	dev_info(qidev, "Allocated response FQ %u for CPU %u",
		 fq->fqid, cpu);
#endif
	return 0;
}

static int alloc_cgrs(struct device *qidev)
{
	struct qm_mcc_initcgr opts;
	int ret;
	const u64 cpus = *(u64 *)qman_affine_cpus();
	const int num_cpus = hweight64(cpus);
	u64 val;

	/*Allocate response CGR*/
	ret = qman_alloc_cgrid(&qipriv.rsp_cgr.cgrid);
	if (ret) {
		dev_err(qidev, "CGR alloc failed for rsp FQs");
		return ret;
	}

	qipriv.rsp_cgr.cb = rsp_cgr_cb;
	memset(&opts, 0, sizeof(opts));
	opts.we_mask = QM_CGR_WE_CSCN_EN | QM_CGR_WE_CS_THRES |
			QM_CGR_WE_MODE;
	opts.cgr.cscn_en = QM_CGR_EN;
	opts.cgr.mode = QMAN_CGR_MODE_FRAME;
#ifdef CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT
	/*
	 * This effectively sets the to-CPU threshold equal to half of the
	 * number of buffers available to dpa_eth driver. It means that at most
	 * half of the buffers can be in the queues from SEC, waiting
	 * to be transmitted to the core (and then on the TX queues).
	 * NOTE: This is an arbitrary division; the factor '2' below could
	 *       also be '3' or '4'. It also depends on the number of devices
	 *       using the dpa_eth buffers (which can be >1 if f.i. PME/DCE are
	 *       also used.
	 */
	val = num_cpus * CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT / 2;
#else
	val = num_cpus * MAX_RSP_FQ_BACKLOG_PER_CPU;
#endif
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, val, 1);

	ret = qman_create_cgr(&qipriv.rsp_cgr,
				QMAN_CGR_FLAG_USE_INIT, &opts);
	if (ret) {
		dev_err(qidev, "Error %d creating CAAM rsp CGRID: %u\n",
			ret, qipriv.rsp_cgr.cgrid);
		return ret;
	}
#ifdef DEBUG
	dev_info(qidev, "CAAM to CPU threshold set to %llu\n", val);
#endif
	return 0;
}

static int alloc_rsp_fqs(struct device *qidev)
{
	const cpumask_t *cpus = qman_affine_cpus();
	int ret, i;

	/*Now create response FQs*/
	for_each_cpu(i, cpus) {
		ret = alloc_rsp_fq_cpu(qidev, i);
		if (ret) {
			dev_err(qidev, "CAAM rsp FQ alloc failed, cpu: %u", i);
			return ret;
		}
	}

	return 0;
}

int caam_qi_init(struct platform_device *caam_pdev, struct device_node *np)
{
	struct platform_device *qi_pdev;
	struct device *ctrldev = &caam_pdev->dev, *qidev;
	struct caam_drv_private *ctrlpriv;
	int err, i;
	const cpumask_t *cpus = qman_affine_cpus();
	struct cpumask old_cpumask = *tsk_cpus_allowed(current);
	static struct platform_device_info qi_pdev_info = {
		.name = "caam_qi",
		.id = PLATFORM_DEVID_NONE
	};

	/*
	 * QMAN requires that CGR must be removed from same CPU+portal from
	 * where it was originally allocated. Hence we need to note down
	 * the initialisation CPU and use the same CPU for module exit.
	 * We select the first CPU to from the list of portal owning
	 * CPUs. Then we pin module init to this CPU.
	 */
	mod_init_cpu = cpumask_first(cpus);
	set_cpus_allowed_ptr(current, get_cpu_mask(mod_init_cpu));

	qi_pdev_info.parent = ctrldev;
	qi_pdev_info.dma_mask = dma_get_mask(ctrldev);
	qi_pdev = platform_device_register_full(&qi_pdev_info);
	if (IS_ERR(qi_pdev))
		return PTR_ERR(qi_pdev);

	ctrlpriv = dev_get_drvdata(ctrldev);
	qidev = &qi_pdev->dev;

	qipriv.qi_pdev = qi_pdev;
	dev_set_drvdata(qidev, &qipriv);

	/* Response path cannot be congested */
	caam_congested = false;

#ifdef CONFIG_DEBUG_FS
	/* The response path was congested 0 times */
	times_congested = 0;
#endif

	/* kmem_cache wasn't yet allocated */
	qi_cache = NULL;

	/* Initialise the CGRs congestion detection */
	err = alloc_cgrs(qidev);
	if (err) {
		dev_err(qidev, "Can't allocate CGRs\n");
		platform_device_unregister(qi_pdev);
		return err;
	}

	/* Initialise response FQs */
	err = alloc_rsp_fqs(qidev);
	if (err) {
		dev_err(qidev, "Can't allocate SEC response FQs\n");
		platform_device_unregister(qi_pdev);
		return err;
	}

	/*
	 * Enable the NAPI contexts on each of the core which has a affine
	 * portal.
	 */
	for_each_cpu(i, cpus) {
		struct caam_qi_pcpu_priv *priv = per_cpu_ptr(&pcpu_qipriv, i);
		struct caam_napi *caam_napi = &priv->caam_napi;
		struct napi_struct *irqtask = &caam_napi->irqtask;
		struct net_device *net_dev = &priv->net_dev;

		net_dev->dev = *qidev;
		INIT_LIST_HEAD(&net_dev->napi_list);

		netif_napi_add(net_dev, irqtask, caam_qi_poll,
			       CAAM_NAPI_WEIGHT);

		napi_enable(irqtask);
	}

	/* Hook up QI device to parent controlling caam device */
	ctrlpriv->qidev = qidev;

	qi_cache = kmem_cache_create("caamqicache", 512, 0,
				     SLAB_CACHE_DMA, NULL);
	if (!qi_cache) {
		dev_err(qidev, "Can't allocate SEC cache\n");
		platform_device_unregister(qi_pdev);
		return err;
	}

	/* Done with the CGRs; restore the cpus allowed mask */
	set_cpus_allowed_ptr(current, &old_cpumask);
#ifdef CONFIG_DEBUG_FS
	ctrlpriv->qi_congested =
			debugfs_create_file("qi_congested",
					    S_IRUSR | S_IRGRP | S_IROTH,
					    ctrlpriv->ctl, &times_congested,
					    &caam_fops_u64_ro);
#endif
	dev_info(qidev, "Linux CAAM Queue I/F driver initialised\n");

	return 0;
}
