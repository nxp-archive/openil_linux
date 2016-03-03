/*
 * CAAM public-level include definitions for the QI backend
 *
 * Copyright 2013 Freescale Semiconductor, Inc.
 */

#ifndef __QI_H__
#define __QI_H__

#include "compat.h"
#include "desc.h"
#include "linux/fsl_qman.h"

/*
 * The CAAM QI hardware constructs a job descriptor which points
 * to shared descriptor (as pointed by context_a of FQ to CAAM).
 * When the job descriptor is executed by deco, the whole job
 * descriptor together with shared descriptor gets loaded in
 * deco buffer which is 64 words long (each 32-bit).
 *
 * The job descriptor constructed by QI hardware has layout:
 *
 *	HEADER		(1 word)
 *	Shdesc ptr	(1 or 2 words)
 *	SEQ_OUT_PTR	(1 word)
 *	Out ptr		(1 or 2 words)
 *	Out length	(1 word)
 *	SEQ_IN_PTR	(1 word)
 *	In ptr		(1 or 2 words)
 *	In length	(1 word)
 *
 * The shdesc ptr is used to fetch shared descriptor contents
 * into deco buffer.
 *
 * Apart from shdesc contents, the total number of words that
 * get loaded in deco buffer are '8' or '11'. The remaining words
 * in deco buffer can be used for storing shared descriptor.
 */
#define MAX_SDLEN	((CAAM_DESC_BYTES_MAX - DESC_JOB_IO_LEN)/CAAM_CMD_SZ)

/*
 * This is the request structure the driver application should fill while
 * submitting a job to driver.
 */
struct caam_drv_req;

/*
 * Application's callback function invoked by the driver when the request
 * has been successfully processed.
 *
 * drv_req:	Original request that was submitted
 * stats:	Completion status of request.
 *		0		- Success
 *		Non-zero	- Error code
 */
typedef void (*caam_qi_cbk)(struct caam_drv_req *drv_req,
			    u32 status);

/*
 * The jobs are processed by the driver against a driver context.
 * With every cryptographic context, a driver context is attached.
 * The driver context contains data for private use by driver.
 * For the applications, this is an opaque structure.
 */
struct caam_drv_ctx;

/*
 * This is the request structure the driver application should fill while
 * submitting a job to driver.
 *
 * fd_sgt[0] - QMAN S/G pointing to output buffer
 * fd_sgt[1] - QMAN S/G pointing to input buffer
 * cbk	     - Callback function to invoke when job is completed
 * app_ctx   - Arbit context attached with request by the application
 *
 * The fields mentioned below should not be used by application.
 * These are for private use by driver.
 *
 * hdr__     - Linked list header to maintain list of outstanding requests
 *	       to CAAM.
 * hwaddr    - DMA address for the S/G table.
 */
struct caam_drv_req {
	struct qm_sg_entry fd_sgt[2];
	struct caam_drv_ctx *drv_ctx;
	caam_qi_cbk cbk;
	void *app_ctx;
} ____cacheline_aligned;

/*
 * caam_drv_ctx_init - Initialise a QI drv context.
 *
 * A QI driver context must be attached with each cryptographic context.
 * This function allocates memory for QI context an returns a handle to
 * the application. This handle must be submitted along with each enqueue
 * request to the driver by the application.
 *
 * cpu	-	CPU where the application prefers to the driver to receive
 *		CAAM responses. The request completion callback would be
 *		issued from this CPU.
 * sh_desc -	Shared descriptor pointer to be attached with QI driver
 *		context.
 *
 * Returns a driver context on success or negative error code on failure.
 */
extern struct caam_drv_ctx *caam_drv_ctx_init(struct device *qidev,
					      int *cpu, u32 *sh_desc);

/*
 * caam_qi_enqueue - Submit a request to QI backend driver.
 *
 * The request structure must be properly filled as described above.
 *
 * Returns 0 on success or negative error code on failure.
 */
extern int caam_qi_enqueue(struct device *qidev, struct caam_drv_req *req);

/*
 * caam_drv_ctx_busy - Check if there are too many jobs pending with CAAM.
 *		       or too many CAAM responses are pending to be processed.
 *
 * drv_ctx - Driver context for which job is to be submitted.
 *
 * Returns caam congestion status 'true/false'
 */
extern bool caam_drv_ctx_busy(struct caam_drv_ctx *drv_ctx);

/*
 * caam_drv_ctx_update - Upate QI drv context.
 *
 * Invoked when shared descriptor is required to be change in driver context.
 *
 * drv_ctx -	Driver context to be updated
 *
 * sh_desc -	New shared descriptor pointer to be updated in QI driver
 *		context.
 *
 * Returns 0 on success or negative error code on failure.
 */
extern int caam_drv_ctx_update(struct caam_drv_ctx *drv_ctx, u32 *sh_desc);

/*
 * caam_drv_ctx_rel - Release a QI driver context.
 *
 * drv_ctx - Context to be released.
 *
 */
extern void caam_drv_ctx_rel(struct caam_drv_ctx *drv_ctx);

extern int caam_qi_init(struct platform_device *pdev, struct device_node *np);
extern int caam_qi_shutdown(struct device *dev);

/*
 * qi_cache_alloc - Allocate buffers from CAAM-QI cache
 *
 * Invoked when a user of the CAAM-QI (i.e. caamalg-qi) needs data which has
 * to be allocated on the hotpath. Instead of using malloc, one can use the
 * services of the CAAM QI memory cache (backed by kmem_cache). The buffers
 * will have a size of 256B, which is sufficient for hosting 16 SG entries.
 *
 * flags -	flags that would be used for the equivalent malloc(..) call
 * *
 * Returns a pointer to a retrieved buffer on success or NULL on failure.
 */
extern void *qi_cache_alloc(gfp_t flags);

/*
 * qi_cache_free - Frees buffers allocated from CAAM-QI cache
 *
 * Invoked when a user of the CAAM-QI (i.e. caamalg-qi) no longer needs
 * the buffer previously allocated by a qi_cache_alloc call.
 * No checking is being done, the call is a passthrough call to
 * kmem_cache_free(...)
 */
extern void qi_cache_free(void *obj);

#endif /* QI_H */
