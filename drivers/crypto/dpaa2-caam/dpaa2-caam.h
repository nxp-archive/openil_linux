/* Copyright 2015 Freescale Semiconductor Inc.
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

#ifndef __DPAA2_CAAM_H
#define __DPAA2_CAAM_H

#include "../../../drivers/staging/fsl-mc/include/fsl_dpaa2_io.h"
#include "../../../drivers/staging/fsl-mc/include/fsl_dpaa2_fd.h"
#include <linux/threads.h>
#include "fsl_dpseci.h"
#include "desc_constr.h"

/*
 * 1 (Tx + Rx) FQ pair (2 FQs) per CPU
 * Terminology: Tx = Request = Enqueue; Rx = Response = Dequeue
 */
#define DPAA2_CAAM_MAX_QUEUE_PAIRS	NR_CPUS
#define DPAA2_CAAM_MAX_QUEUES		(2 * DPAA2_CAAM_MAX_QUEUE_PAIRS)

#define DPAA2_CAAM_NAPI_WEIGHT	63

/**
 * dpaa2_caam_priv - driver private data
 * @dpseci_id: DPSECI object unique ID
 * @dpseci_attr: DPSECI attributes
 * @rx_queue_attr: array of Rx queue attributes
 * @tx_queue_attr: array of Tx queue attributes
 * @dev: device associated with the DPSECI object
 * @mc_io: pointer to MC portal's I/O object
 * @ppriv: per CPU pointers to privata data
 */
struct dpaa2_caam_priv {
	int dpsec_id;

	struct dpseci_attr dpseci_attr;
	struct dpseci_rx_queue_attr rx_queue_attr[DPSECI_PRIO_NUM];
	struct dpseci_tx_queue_attr tx_queue_attr[DPSECI_PRIO_NUM];
	int num_pairs;

	struct device *dev;
	struct fsl_mc_io *mc_io;

	struct dpaa2_caam_priv_per_cpu __percpu *ppriv;
};

/**
 * dpaa2_caam_priv_per_cpu - per CPU private data
 * @napi: napi structure
 * @net_dev: netdev used by napi
 * @req_fqid: (virtual) request (Tx / enqueue) FQID
 * @rsp_fqid: (virtual) response (Rx / dequeue) FQID
 * @prio: internal queue number - index for dpaa2_caam_priv.*_queue_attr
 * @nctx: notification context of response FQ
 * @store: where dequeued frames are stored
 * @has_frames: indication that response FQ has frames to be dequeued
 * @priv: backpointer to dpaa2_caam_priv
 */
struct dpaa2_caam_priv_per_cpu {
	struct napi_struct napi;
	struct net_device net_dev;
	int req_fqid;
	int rsp_fqid;
	int prio;
	struct dpaa2_io_notification_ctx nctx;
	struct dpaa2_io_store *store;
	bool has_frames;
	struct dpaa2_caam_priv *priv;
};

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
#define MAX_SDLEN	((CAAM_DESC_BYTES_MAX - DESC_JOB_IO_LEN) / CAAM_CMD_SZ)

/*
 * aead_edesc - s/w-extended aead descriptor
 * @assoc_nents: number of segments in associated data (SPI+Seq) scatterlist
 * @assoc_chained: if assoc is chained
 * @src_nents: number of segments in input scatterlist
 * @src_chained: if source is chained
 * @dst_nents: number of segments in output scatterlist
 * @dst_chained: if destination is chained
 * @iv_dma: dma address of iv for checking continuity and link table
 * @qm_sg_bytes: length of dma mapped qm_sg space
 * @qm_sg_dma: I/O virtual address of h/w link table
 * @qm_sg: h/w link table
 */
struct aead_edesc {
	int assoc_nents;
	bool assoc_chained;
	int src_nents;
	bool src_chained;
	int dst_nents;
	bool dst_chained;
	dma_addr_t iv_dma;
	int qm_sg_bytes;
	dma_addr_t qm_sg_dma;
	struct dpaa_sg_entry qm_sg[0];
};

/*
 * ablkcipher_edesc - s/w-extended ablkcipher descriptor
 * @src_nents: number of segments in input scatterlist
 * @src_chained: if source is chained
 * @dst_nents: number of segments in output scatterlist
 * @dst_chained: if destination is chained
 * @iv_dma: dma address of iv for checking continuity and link table
 * @qm_sg_bytes: length of dma mapped qm_sg space
 * @qm_sg_dma: I/O virtual address of h/w link table
 * @qm_sg: h/w link table
 */
struct ablkcipher_edesc {
	int src_nents;
	bool src_chained;
	int dst_nents;
	bool dst_chained;
	dma_addr_t iv_dma;
	int qm_sg_bytes;
	dma_addr_t qm_sg_dma;
	struct dpaa_sg_entry qm_sg[0];
};

/*
 * ahash_edesc - s/w-extended ahash descriptor
 * @dst_dma: I/O virtual address of req->result
 * @chained: if source is chained
 * @src_nents: number of segments in input scatterlist
 * @qm_sg_bytes: length of dma mapped qm_sg space
 * @qm_sg_dma: I/O virtual address of h/w link table
 * @qm_sg: pointer to h/w link table
 */
struct ahash_edesc {
	dma_addr_t dst_dma;
	bool chained;
	int src_nents;
	int qm_sg_bytes;
	dma_addr_t qm_sg_dma;
	struct dpaa_sg_entry qm_sg[0];
};

/**
 * caam_flc - Flow Context (FLC)
 * @flc: Flow Context options
 * @sh_desc: Shared Descriptor
 */
struct caam_flc {
	u32 flc[16];
	u32 sh_desc[MAX_SDLEN];
} ____cacheline_aligned;

/**
 * caam_request - the request structure the driver application should fill while
 *                submitting a job to driver.
 * @fd_flt: Frame list table defining input and output
 *          fd_flt[0] - FLE pointing to output buffer
 *          fd_flt[1] - FLE pointing to input buffer
 * @fd_flt_dma: DMA address for the frame list table
 * @flc: Flow Context
 * @flc_dma: DMA address of Flow Context
 * @cbk: Callback function to invoke when job is completed
 * @ctx: arbit context attached with request by the application
 * @edesc: extended descriptor; points to one of {ablkcipher,ahash,aead}_edesc
 */
struct caam_request {
	struct dpaa_fl_entry fd_flt[2];
	dma_addr_t fd_flt_dma;
	struct caam_flc *flc;
	dma_addr_t flc_dma;
	void (*cbk)(void *ctx, u32 err);
	void *ctx;
	void *edesc;
} ____cacheline_aligned;

/* max hash key is max split key size */
#define CAAM_MAX_HASH_KEY_SIZE		(SHA512_DIGEST_SIZE * 2)

#define CAAM_MAX_HASH_BLOCK_SIZE	SHA512_BLOCK_SIZE
#define CAAM_MAX_HASH_DIGEST_SIZE	SHA512_DIGEST_SIZE

/* length of descriptors text */
#define DESC_AHASH_BASE			(4 * CAAM_CMD_SZ)
#define DESC_AHASH_UPDATE_LEN		(6 * CAAM_CMD_SZ)
#define DESC_AHASH_UPDATE_FIRST_LEN	(DESC_AHASH_BASE + 4 * CAAM_CMD_SZ)
#define DESC_AHASH_FINAL_LEN		(DESC_AHASH_BASE + 5 * CAAM_CMD_SZ)
#define DESC_AHASH_FINUP_LEN		(DESC_AHASH_BASE + 5 * CAAM_CMD_SZ)
#define DESC_AHASH_DIGEST_LEN		(DESC_AHASH_BASE + 4 * CAAM_CMD_SZ)

#define DESC_HASH_MAX_USED_BYTES	(DESC_AHASH_FINAL_LEN + \
					 CAAM_MAX_HASH_KEY_SIZE)
#define DESC_HASH_MAX_USED_LEN		(DESC_HASH_MAX_USED_BYTES / CAAM_CMD_SZ)

/* caam context sizes for hashes: running digest + 8 */
#define HASH_MSG_LEN			8
#define MAX_CTX_LEN			(HASH_MSG_LEN + SHA512_DIGEST_SIZE)

/* ahash state */
struct caam_hash_state {
	struct caam_request caam_req;
	dma_addr_t buf_dma;
	dma_addr_t ctx_dma;
	u8 buf_0[CAAM_MAX_HASH_BLOCK_SIZE] ____cacheline_aligned;
	int buflen_0;
	u8 buf_1[CAAM_MAX_HASH_BLOCK_SIZE] ____cacheline_aligned;
	int buflen_1;
	u8 caam_ctx[MAX_CTX_LEN] ____cacheline_aligned;
	/*
	 * Dummy guard - never touched by CPU, only inserted to make sure
	 * caam_ctx not trashed by CPU writes.
	 * TODO: When HW coherency support is fixed, this can (and should)
	 * be safely removed.
	 */
	int  dummy_guard ____cacheline_aligned;
	int (*update)(struct ahash_request *req);
	int (*final)(struct ahash_request *req);
	int (*finup)(struct ahash_request *req);
	int current_buf;
};

/**
 * dpaa2_caam_enqueue() - enqueue a crypto request
 * @dev: device associated with the DPSECI object
 * @req: pointer to caam_request
 */
int dpaa2_caam_enqueue(struct device *dev, struct caam_request *req);

#endif	/* __DPAA2_CAAM_H */
