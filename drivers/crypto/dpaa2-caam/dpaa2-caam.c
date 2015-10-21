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

#include "compat.h"
#include "dpaa2-caam.h"
#include "fsl_dpseci_cmd.h"
#include "desc_constr.h"
#include "error.h"
#include "sg_sw_sec4.h"
#include "sg_sw_qm.h"
#include "../../../drivers/staging/fsl-mc/include/mc.h"
#include "../../../drivers/staging/fsl-mc/include/fsl_dpaa2_io.h"
#include "../../../drivers/staging/fsl-mc/include/fsl_dpaa2_fd.h"

#define CAAM_CRA_PRIORITY	3000

/* max key is sum of AES_MAX_KEY_SIZE, max split key size */
#define CAAM_MAX_KEY_SIZE		(AES_MAX_KEY_SIZE + \
					 SHA512_DIGEST_SIZE * 2)

/* Length of a single buffer in the QI driver memory cache */
#define CAAM_QI_MEMCACHE_SIZE	512

enum optype {
	ENCRYPT = 0,
	DECRYPT,
	GIVENCRYPT,
	NUM_OP
};

/*
 * This is a a cache of buffers, from which the users of CAAM QI driver
 * can allocate short buffers. It's speedier than doing kmalloc on the hotpath.
 * NOTE: A more elegant solution would be to have some headroom in the frames
 *       being processed. This can be added by the dpaa2-eth driver. This would
 *       pose a problem for userspace application processing which cannot
 *       know of this limitation. So for now, this will work.
 * NOTE: The memcache is SMP-safe. No need to handle spinlocks in-here
 */
static struct kmem_cache *qi_cache;

/**
 * caam_ctx - per-session context
 * @flc: Flow Contexts array
 * @flc_dma: DMA addresses of the Flow Contexts
 * @priv: driver private data
 * @class1_alg_type: algorithm to execute on a Class 1 CHA
 * @class2_alg_type: algorithm to execute on a Class 2 CHA
 * @alg_op: type of MDHA operation (only if MDHA split key generation is needed)
 * @key:  virtual address of the key(s): [authentication key], encryption key
 * @key_dma: I/O virtual address of the key
 * @enckeylen: encryption key length
 * @split_key_len: MDHA split key length (to be used to KEY commands)
 * @split_key_pad_len: padded MDHA split key length (real key data length)
 * @authsize: authentication tag (a.k.a. ICV / MAC) size
 */
struct caam_ctx {
	/* TODO: Group flc and flc_dma in a struct ?! */
	struct caam_flc flc[NUM_OP];
	dma_addr_t flc_dma[NUM_OP];
	struct dpaa2_caam_priv *priv;
	u32 class1_alg_type;
	u32 class2_alg_type;
	u32 alg_op;
	u8 key[CAAM_MAX_KEY_SIZE];
	dma_addr_t key_dma;
	unsigned int enckeylen;
	unsigned int split_key_len;
	unsigned int split_key_pad_len;
	unsigned int authsize;
};

/*
 * qi_cache_alloc - Allocate buffers from CAAM-QI cache
 *
 * Allocate data on the hotpath. Instead of using kmalloc, one can use the
 * services of the CAAM QI memory cache (backed by kmem_cache). The buffers
 * will have a size of CAAM_QI_MEMCACHE_SIZE, which should be sufficient for
 * hosting 16 SG entries.
 *
 * @flags - flags that would be used for the equivalent kmalloc(..) call
 *
 * Returns a pointer to a retrieved buffer on success or NULL on failure.
 */
static inline void *qi_cache_alloc(gfp_t flags)
{
	return kmem_cache_alloc(qi_cache, flags);
}

/*
 * qi_cache_free - Frees buffers allocated from CAAM-QI cache
 *
 * @obj - buffer previously allocated by qi_cache_alloc
 *
 * No checking is being done, the call is a passthrough call to
 * kmem_cache_free(...)
 */
static inline void qi_cache_free(void *obj)
{
	kmem_cache_free(qi_cache, obj);
}

static struct caam_request *to_caam_req(struct crypto_async_request *areq)
{
	switch (crypto_tfm_alg_type(areq->tfm)) {
	case CRYPTO_ALG_TYPE_ABLKCIPHER:
		return ablkcipher_request_ctx(ablkcipher_request_cast(areq));
	case CRYPTO_ALG_TYPE_GIVCIPHER:
		return skcipher_givcrypt_reqctx(skcipher_givcrypt_cast(areq));
	case CRYPTO_ALG_TYPE_AHASH:
		return ahash_request_ctx(ahash_request_cast(areq));
	case CRYPTO_ALG_TYPE_AEAD:
		return aead_request_ctx(container_of(areq, struct aead_request,
						     base));
	default:
		return ERR_PTR(-EINVAL);
	}
}

/* Set DK bit in class 1 operation if shared */
static inline void append_dec_op1(u32 *desc, u32 type)
{
	u32 *jump_cmd, *uncond_jump_cmd;

	/* DK bit is valid only for AES */
	if ((type & OP_ALG_ALGSEL_MASK) != OP_ALG_ALGSEL_AES) {
		append_operation(desc, type | OP_ALG_AS_INITFINAL |
				 OP_ALG_DECRYPT);
		return;
	}

	jump_cmd = append_jump(desc, JUMP_TEST_ALL | JUMP_COND_SHRD);
	append_operation(desc, type | OP_ALG_AS_INITFINAL |
			 OP_ALG_DECRYPT);
	uncond_jump_cmd = append_jump(desc, JUMP_TEST_ALL);
	set_jump_tgt_here(desc, jump_cmd);
	append_operation(desc, type | OP_ALG_AS_INITFINAL |
			 OP_ALG_DECRYPT | OP_ALG_AAI_DK);
	set_jump_tgt_here(desc, uncond_jump_cmd);
}

/*
 * For ablkcipher encrypt and decrypt, read from req->src and
 * write to req->dst
 */
static inline void ablkcipher_append_src_dst(u32 *desc)
{
	append_math_add(desc, VARSEQOUTLEN, SEQINLEN, REG0, CAAM_CMD_SZ);
	append_math_add(desc, VARSEQINLEN, SEQINLEN, REG0, CAAM_CMD_SZ);
	append_seq_fifo_store(desc, 0, FIFOST_TYPE_MESSAGE_DATA | KEY_VLF);
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS1 |
			     KEY_VLF | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1);
}

static int ablkcipher_setkey(struct crypto_ablkcipher *ablkcipher,
			     const u8 *key, unsigned int keylen)
{
	struct caam_ctx *ctx = crypto_ablkcipher_ctx(ablkcipher);
	struct ablkcipher_tfm *crt = &ablkcipher->base.crt_ablkcipher;
	struct crypto_tfm *tfm = crypto_ablkcipher_tfm(ablkcipher);
	const char *alg_name = crypto_tfm_alg_name(tfm);
	struct device *dev = ctx->priv->dev;
	struct caam_flc *flc;
	dma_addr_t *flc_dma;
	int ret = 0;
	u32 *key_jump_cmd;
	u32 *desc;
	u32 *nonce;
	u32 geniv;
	u32 ctx1_iv_off = 0;
	const bool ctr_mode = ((ctx->class1_alg_type & OP_ALG_AAI_MASK) ==
			       OP_ALG_AAI_CTR_MOD128);
	const bool is_rfc3686 = (ctr_mode &&
				 (strstr(alg_name, "rfc3686") != NULL));

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "key in @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, key, keylen, 1);
#endif
	/*
	 * AES-CTR needs to load IV in CONTEXT1 reg
	 * at an offset of 128bits (16bytes)
	 * CONTEXT1[255:128] = IV
	 */
	if (ctr_mode)
		ctx1_iv_off = 16;

	/*
	 * RFC3686 specific:
	 *	| CONTEXT1[255:128] = {NONCE, IV, COUNTER}
	 *	| *key = {KEY, NONCE}
	 */
	if (is_rfc3686) {
		ctx1_iv_off = 16 + CTR_RFC3686_NONCE_SIZE;
		keylen -= CTR_RFC3686_NONCE_SIZE;
	}

	memcpy(ctx->key, key, keylen);
	ctx->key_dma = dma_map_single(dev, ctx->key, keylen, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, ctx->key_dma)) {
		dev_err(dev, "unable to map key i/o memory\n");
		return -ENOMEM;
	}
	ctx->enckeylen = keylen;

	/* ablkcipher_encrypt shared descriptor */
	flc = &ctx->flc[ENCRYPT];
	flc_dma = &ctx->flc_dma[ENCRYPT];
	desc = flc->sh_desc;
	init_sh_desc(desc, HDR_SHARE_SERIAL | HDR_SAVECTX);
	/* Skip if already shared */
	key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
				   JUMP_COND_SHRD);

	/* Load class1 key only */
	append_key_as_imm(desc, (void *)ctx->key, ctx->enckeylen,
			  ctx->enckeylen, CLASS_1 |
			  KEY_DEST_CLASS_REG);

	/* Load nonce into CONTEXT1 reg */
	if (is_rfc3686) {
		nonce = (u32 *)(key + keylen);
		append_load_imm_u32(desc, *nonce, LDST_CLASS_IND_CCB |
				    LDST_SRCDST_BYTE_OUTFIFO | LDST_IMM);
		append_move(desc, MOVE_WAITCOMP |
			    MOVE_SRC_OUTFIFO |
			    MOVE_DEST_CLASS1CTX |
			    (16 << MOVE_OFFSET_SHIFT) |
			    (CTR_RFC3686_NONCE_SIZE << MOVE_LEN_SHIFT));
	}

	set_jump_tgt_here(desc, key_jump_cmd);

	/* Load iv */
	append_seq_load(desc, crt->ivsize, LDST_SRCDST_BYTE_CONTEXT |
			LDST_CLASS_1_CCB | (ctx1_iv_off << LDST_OFFSET_SHIFT));

	/* Load counter into CONTEXT1 reg */
	if (is_rfc3686)
		append_load_imm_u32(desc, be32_to_cpu(1), LDST_IMM |
				    LDST_CLASS_1_CCB |
				    LDST_SRCDST_BYTE_CONTEXT |
				    ((ctx1_iv_off + CTR_RFC3686_IV_SIZE) <<
				     LDST_OFFSET_SHIFT));

	/* Load operation */
	append_operation(desc, ctx->class1_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* Perform operation */
	ablkcipher_append_src_dst(desc);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) +
				  desc_bytes(desc), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}

#ifdef DEBUG
	print_hex_dump(KERN_ERR,
		       "ablkcipher enc shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif
	/* ablkcipher_decrypt shared descriptor */
	flc = &ctx->flc[DECRYPT];
	flc_dma = &ctx->flc_dma[DECRYPT];
	desc = flc->sh_desc;

	init_sh_desc(desc, HDR_SHARE_SERIAL | HDR_SAVECTX);
	/* Skip if already shared */
	key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
				   JUMP_COND_SHRD);

	/* Load class1 key only */
	append_key_as_imm(desc, (void *)ctx->key, ctx->enckeylen,
			  ctx->enckeylen, CLASS_1 |
			  KEY_DEST_CLASS_REG);

	/* Load nonce into CONTEXT1 reg */
	if (is_rfc3686) {
		nonce = (u32 *)(key + keylen);
		append_load_imm_u32(desc, *nonce, LDST_CLASS_IND_CCB |
				    LDST_SRCDST_BYTE_OUTFIFO | LDST_IMM);
		append_move(desc, MOVE_WAITCOMP |
			    MOVE_SRC_OUTFIFO |
			    MOVE_DEST_CLASS1CTX |
			    (16 << MOVE_OFFSET_SHIFT) |
			    (CTR_RFC3686_NONCE_SIZE << MOVE_LEN_SHIFT));
	}

	set_jump_tgt_here(desc, key_jump_cmd);

	/* load IV */
	append_seq_load(desc, crt->ivsize, LDST_SRCDST_BYTE_CONTEXT |
			LDST_CLASS_1_CCB | (ctx1_iv_off << LDST_OFFSET_SHIFT));

	/* Load counter into CONTEXT1 reg */
	if (is_rfc3686)
		append_load_imm_u32(desc, be32_to_cpu(1), LDST_IMM |
				    LDST_CLASS_1_CCB |
				    LDST_SRCDST_BYTE_CONTEXT |
				    ((ctx1_iv_off + CTR_RFC3686_IV_SIZE) <<
				     LDST_OFFSET_SHIFT));

	/* Choose operation */
	if (ctr_mode)
		append_operation(desc, ctx->class1_alg_type |
				 OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT);
	else
		append_dec_op1(desc, ctx->class1_alg_type);

	/* Perform operation */
	ablkcipher_append_src_dst(desc);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) +
				  desc_bytes(desc), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}

#ifdef DEBUG
	print_hex_dump(KERN_ERR,
		       "ablkcipher dec shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif
	/* ablkcipher_givencrypt shared descriptor */
	flc = &ctx->flc[GIVENCRYPT];
	flc_dma = &ctx->flc_dma[GIVENCRYPT];
	desc = flc->sh_desc;

	init_sh_desc(desc, HDR_SHARE_SERIAL | HDR_SAVECTX);
	/* Skip if already shared */
	key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
				   JUMP_COND_SHRD);

	/* Load class1 key only */
	append_key_as_imm(desc, (void *)ctx->key, ctx->enckeylen,
			  ctx->enckeylen, CLASS_1 |
			  KEY_DEST_CLASS_REG);

	/* Load Nonce into CONTEXT1 reg */
	if (is_rfc3686) {
		nonce = (u32 *)(key + keylen);
		append_load_imm_u32(desc, *nonce, LDST_CLASS_IND_CCB |
				    LDST_SRCDST_BYTE_OUTFIFO | LDST_IMM);
		append_move(desc, MOVE_WAITCOMP |
			    MOVE_SRC_OUTFIFO |
			    MOVE_DEST_CLASS1CTX |
			    (16 << MOVE_OFFSET_SHIFT) |
			    (CTR_RFC3686_NONCE_SIZE << MOVE_LEN_SHIFT));
	}
	set_jump_tgt_here(desc, key_jump_cmd);

	/* Generate IV */
	geniv = NFIFOENTRY_STYPE_PAD | NFIFOENTRY_DEST_DECO |
		NFIFOENTRY_DTYPE_MSG | NFIFOENTRY_LC1 |
		NFIFOENTRY_PTYPE_RND | (crt->ivsize << NFIFOENTRY_DLEN_SHIFT);
	append_load_imm_u32(desc, geniv, LDST_CLASS_IND_CCB |
			    LDST_SRCDST_WORD_INFO_FIFO | LDST_IMM);
	append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);
	append_move(desc, MOVE_WAITCOMP |
		    MOVE_SRC_INFIFO |
		    MOVE_DEST_CLASS1CTX |
		    (crt->ivsize << MOVE_LEN_SHIFT) |
		    (ctx1_iv_off << MOVE_OFFSET_SHIFT));
	append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* Copy generated IV to memory */
	append_seq_store(desc, crt->ivsize,
			 LDST_SRCDST_BYTE_CONTEXT | LDST_CLASS_1_CCB |
			 (ctx1_iv_off << LDST_OFFSET_SHIFT));

	/* Load Counter into CONTEXT1 reg */
	if (is_rfc3686)
		append_load_imm_u32(desc, (u32)1, LDST_IMM |
				    LDST_CLASS_1_CCB |
				    LDST_SRCDST_BYTE_CONTEXT |
				    ((ctx1_iv_off + CTR_RFC3686_IV_SIZE) <<
				     LDST_OFFSET_SHIFT));

	if (ctx1_iv_off)
		append_jump(desc, JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_NCP |
			    (1 << JUMP_OFFSET_SHIFT));

	/* Load operation */
	append_operation(desc, ctx->class1_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* Perform operation */
	ablkcipher_append_src_dst(desc);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) +
				  desc_bytes(desc), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}

#ifdef DEBUG
	print_hex_dump(KERN_ERR,
		       "ablkcipher givenc shdesc@" __stringify(__LINE__) ": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	return ret;
}

static struct ablkcipher_edesc *ablkcipher_edesc_alloc(struct ablkcipher_request
						       *req)
{
	struct crypto_ablkcipher *ablkcipher = crypto_ablkcipher_reqtfm(req);
	struct caam_request *req_ctx = ablkcipher_request_ctx(req);
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	struct caam_ctx *ctx = crypto_ablkcipher_ctx(ablkcipher);
	struct device *dev = ctx->priv->dev;
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
					  CRYPTO_TFM_REQ_MAY_SLEEP)) ?
		       GFP_KERNEL : GFP_ATOMIC;
	int src_nents, dst_nents = 0, qm_sg_bytes;
	struct ablkcipher_edesc *edesc;
	dma_addr_t iv_dma = 0;
	bool iv_contig = false;
	int sgc;
	int ivsize = crypto_ablkcipher_ivsize(ablkcipher);
	bool src_chained = false, dst_chained = false;
	struct dpaa_sg_entry *sg_table;
	int qm_sg_index = 0;

	src_nents = sg_count(req->src, req->nbytes, &src_chained);

	if (req->dst != req->src)
		dst_nents = sg_count(req->dst, req->nbytes, &dst_chained);

	if (likely(req->src == req->dst)) {
		sgc = dma_map_sg_chained(dev, req->src, src_nents ? : 1,
					 DMA_BIDIRECTIONAL, src_chained);
	} else {
		sgc = dma_map_sg_chained(dev, req->src, src_nents ? : 1,
					 DMA_TO_DEVICE, src_chained);
		sgc = dma_map_sg_chained(dev, req->dst, dst_nents ? : 1,
					 DMA_FROM_DEVICE, dst_chained);
	}

	iv_dma = dma_map_single(dev, req->info, ivsize, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, iv_dma)) {
		dev_err(dev, "unable to map IV\n");
		return ERR_PTR(-ENOMEM);
	}

	/*
	 * Check if iv can be contiguous with source and destination.
	 * If so, include it. If not, create scatterlist.
	 */
	if (!src_nents && iv_dma + ivsize == sg_dma_address(req->src))
		iv_contig = true;
	else
		src_nents = src_nents ? : 1;
	qm_sg_bytes = ((iv_contig ? 0 : 1) + src_nents + dst_nents) *
		      sizeof(struct dpaa_sg_entry);

	/* allocate space for base edesc and link tables */
	edesc = qi_cache_alloc(GFP_DMA | flags);
	if (!edesc) {
		dev_err(dev, "could not allocate extended descriptor\n");
		return ERR_PTR(-ENOMEM);
	}

	edesc->src_nents = src_nents;
	edesc->src_chained = src_chained;
	edesc->dst_nents = dst_nents;
	edesc->dst_chained = dst_chained;
	edesc->iv_dma = iv_dma;
	edesc->qm_sg_bytes = qm_sg_bytes;
	sg_table = &edesc->qm_sg[0];
	edesc->qm_sg_dma = dma_map_single(dev, sg_table, qm_sg_bytes,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->qm_sg_dma)) {
		dev_err(dev, "unable to map S/G table\n");
		return ERR_PTR(-ENOMEM);
	}

	memset(&req_ctx->fd_flt, 0, sizeof(req_ctx->fd_flt));
	dpaa2_fl_set_final(in_fle, true);

	if (!iv_contig) {
		dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
		dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);

		dma_to_qm_sg_one(sg_table, iv_dma, ivsize, 0);
		sg_to_qm_sg_last(req->src, src_nents, sg_table + 1, 0);
		qm_sg_index = 1 + src_nents;
	} else {
		dpaa2_fl_set_format(in_fle, dpaa_fl_single);
		dpaa2_fl_set_addr(in_fle, iv_dma);
	}

	if (req->src == req->dst) {
		if (!iv_contig) {
			dpaa2_fl_set_format(out_fle, dpaa_fl_sg);
			dpaa2_fl_set_addr(out_fle, edesc->qm_sg_dma +
					  sizeof(struct dpaa_sg_entry));
		} else {
			dpaa2_fl_set_format(out_fle, dpaa_fl_single);
			dpaa2_fl_set_addr(out_fle, sg_dma_address(req->src));
		}
	} else if (dst_nents) {
		dpaa2_fl_set_format(out_fle, dpaa_fl_sg);
		dpaa2_fl_set_addr(out_fle, edesc->qm_sg_dma + qm_sg_index *
				  sizeof(struct dpaa_sg_entry));
		sg_to_qm_sg_last(req->dst, dst_nents, sg_table + qm_sg_index,
				 0);
	} else {
		dpaa2_fl_set_format(out_fle, dpaa_fl_single);
		dpaa2_fl_set_addr(out_fle, sg_dma_address(req->dst));
	}

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ablkcipher qm_sg@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, sg_table, qm_sg_bytes, 1);
#endif

	return edesc;
}

static struct ablkcipher_edesc *ablkcipher_giv_edesc_alloc(
	struct skcipher_givcrypt_request *greq)
{
	struct ablkcipher_request *req = &greq->creq;
	struct crypto_ablkcipher *ablkcipher = crypto_ablkcipher_reqtfm(req);
	struct caam_request *req_ctx = ablkcipher_request_ctx(req);
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	struct caam_ctx *ctx = crypto_ablkcipher_ctx(ablkcipher);
	struct device *dev = ctx->priv->dev;
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
					  CRYPTO_TFM_REQ_MAY_SLEEP)) ?
		       GFP_KERNEL : GFP_ATOMIC;
	int src_nents, dst_nents = 0, qm_sg_bytes;
	struct ablkcipher_edesc *edesc;
	dma_addr_t iv_dma = 0;
	bool iv_contig = false;
	int sgc;
	int ivsize = crypto_ablkcipher_ivsize(ablkcipher);
	bool src_chained = false, dst_chained = false;
	struct dpaa_sg_entry *sg_table;
	int qm_sg_index = 0;

	src_nents = sg_count(req->src, req->nbytes, &src_chained);

	if (req->dst != req->src)
		dst_nents = sg_count(req->dst, req->nbytes, &dst_chained);

	if (likely(req->src == req->dst)) {
		sgc = dma_map_sg_chained(dev, req->src, src_nents ? : 1,
					 DMA_BIDIRECTIONAL, src_chained);
	} else {
		sgc = dma_map_sg_chained(dev, req->src, src_nents ? : 1,
					 DMA_TO_DEVICE, src_chained);
		sgc = dma_map_sg_chained(dev, req->dst, dst_nents ? : 1,
					 DMA_FROM_DEVICE, dst_chained);
	}

	iv_dma = dma_map_single(dev, greq->giv, ivsize, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, iv_dma)) {
		dev_err(dev, "unable to map IV\n");
		return ERR_PTR(-ENOMEM);
	}

	/*
	 * Check if iv can be contiguous with source and destination.
	 * If so, include it. If not, create scatterlist.
	 */
	if (!dst_nents && iv_dma + ivsize == sg_dma_address(req->dst))
		iv_contig = true;
	else
		dst_nents = dst_nents ? : 1;
	qm_sg_bytes = ((iv_contig ? 0 : 1) + src_nents + dst_nents) *
		      sizeof(struct dpaa_sg_entry);

	/* allocate space for base edesc and link tables */
	edesc = qi_cache_alloc(GFP_DMA | flags);
	if (!edesc) {
		dev_err(dev, "could not allocate extended descriptor\n");
		return ERR_PTR(-ENOMEM);
	}

	edesc->src_nents = src_nents;
	edesc->src_chained = src_chained;
	edesc->dst_nents = dst_nents;
	edesc->dst_chained = dst_chained;
	edesc->iv_dma = iv_dma;
	edesc->qm_sg_bytes = qm_sg_bytes;
	sg_table = &edesc->qm_sg[0];
	edesc->qm_sg_dma = dma_map_single(dev, sg_table, qm_sg_bytes,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->qm_sg_dma)) {
		dev_err(dev, "unable to map S/G table\n");
		return ERR_PTR(-ENOMEM);
	}

	memset(&req_ctx->fd_flt, 0, sizeof(req_ctx->fd_flt));
	dpaa2_fl_set_final(in_fle, true);

	if (src_nents) {
		dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
		dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);
		sg_to_qm_sg_last(req->src, src_nents, sg_table, 0);
		qm_sg_index = src_nents;
	} else {
		dpaa2_fl_set_format(in_fle, dpaa_fl_single);
		dpaa2_fl_set_addr(in_fle, sg_dma_address(req->src));
	}

	if (!iv_contig) {
		dpaa2_fl_set_format(out_fle, dpaa_fl_sg);
		dpaa2_fl_set_addr(out_fle, edesc->qm_sg_dma);

		dma_to_qm_sg_one(sg_table + qm_sg_index, iv_dma, ivsize, 0);
		qm_sg_index++;
		sg_to_qm_sg_last(req->dst, dst_nents, sg_table + qm_sg_index,
				 0);
	} else {
		dpaa2_fl_set_format(out_fle, dpaa_fl_single);
		dpaa2_fl_set_addr(out_fle, sg_dma_address(req->dst));
	}

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ablkcipher qm_sg@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, sg_table, qm_sg_bytes, 1);
#endif

	return edesc;
}

static void caam_unmap(struct device *dev, struct scatterlist *src,
		       struct scatterlist *dst, int src_nents,
		       bool src_chained, int dst_nents, bool dst_chained,
		       dma_addr_t iv_dma, int ivsize, dma_addr_t qm_sg_dma,
		       int qm_sg_bytes)
{
	if (dst != src) {
		dma_unmap_sg_chained(dev, src, src_nents ? : 1, DMA_TO_DEVICE,
				     src_chained);
		dma_unmap_sg_chained(dev, dst, dst_nents ? : 1, DMA_FROM_DEVICE,
				     dst_chained);
	} else {
		dma_unmap_sg_chained(dev, src, src_nents ? : 1,
				     DMA_BIDIRECTIONAL, src_chained);
	}

	if (iv_dma)
		dma_unmap_single(dev, iv_dma, ivsize, DMA_TO_DEVICE);
	if (qm_sg_bytes)
		dma_unmap_single(dev, qm_sg_dma, qm_sg_bytes, DMA_TO_DEVICE);
}

static void ablkcipher_unmap(struct device *dev,
			     struct ablkcipher_edesc *edesc,
			     struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *ablkcipher = crypto_ablkcipher_reqtfm(req);
	int ivsize = crypto_ablkcipher_ivsize(ablkcipher);

	caam_unmap(dev, req->src, req->dst,
		   edesc->src_nents, edesc->src_chained, edesc->dst_nents,
		   edesc->dst_chained, edesc->iv_dma, ivsize,
		   edesc->qm_sg_dma, edesc->qm_sg_bytes);
}

static void ablkcipher_encrypt_done(void *cbk_ctx, u32 err)
{
	struct crypto_async_request *areq = cbk_ctx;
	struct ablkcipher_request *req = ablkcipher_request_cast(areq);
	struct caam_request *req_ctx = to_caam_req(areq);
	struct crypto_ablkcipher *ablkcipher = crypto_ablkcipher_reqtfm(req);
	struct caam_ctx *ctx = crypto_ablkcipher_ctx(ablkcipher);
	struct ablkcipher_edesc *edesc = req_ctx->edesc;
#ifdef DEBUG
	int ivsize = crypto_ablkcipher_ivsize(ablkcipher);

	dev_err(ctx->priv->dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
#endif

	if (unlikely(err))
		caam_jr_strstatus(ctx->priv->dev, err);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "dstiv  @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, req->info,
		       edesc->src_nents > 1 ? 100 : ivsize, 1);
	print_hex_dump(KERN_ERR, "dst    @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, sg_virt(req->src),
		       edesc->dst_nents > 1 ? 100 : req->nbytes, 1);
#endif

	ablkcipher_unmap(ctx->priv->dev, edesc, req);
	qi_cache_free(edesc);

	ablkcipher_request_complete(req, err);
}

static void ablkcipher_decrypt_done(void *cbk_ctx, u32 err)
{
	struct crypto_async_request *areq = cbk_ctx;
	struct ablkcipher_request *req = ablkcipher_request_cast(areq);
	struct caam_request *req_ctx = to_caam_req(areq);
	struct crypto_ablkcipher *ablkcipher = crypto_ablkcipher_reqtfm(req);
	struct caam_ctx *ctx = crypto_ablkcipher_ctx(ablkcipher);
	struct ablkcipher_edesc *edesc = req_ctx->edesc;
#ifdef DEBUG
	int ivsize = crypto_ablkcipher_ivsize(ablkcipher);

	dev_err(ctx->priv->dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
#endif

	if (unlikely(err))
		caam_jr_strstatus(ctx->priv->dev, err);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "dstiv  @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, req->info,
		       ivsize, 1);
	print_hex_dump(KERN_ERR, "dst    @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, sg_virt(req->src),
		       edesc->dst_nents > 1 ? 100 : req->nbytes, 1);
#endif

	ablkcipher_unmap(ctx->priv->dev, edesc, req);
	qi_cache_free(edesc);

	ablkcipher_request_complete(req, err);
}

static int ablkcipher_encrypt(struct ablkcipher_request *req)
{
	struct ablkcipher_edesc *edesc;
	struct crypto_ablkcipher *ablkcipher = crypto_ablkcipher_reqtfm(req);
	struct caam_ctx *ctx = crypto_ablkcipher_ctx(ablkcipher);
	struct caam_request *caam_req = ablkcipher_request_ctx(req);
	int ivsize = crypto_ablkcipher_ivsize(ablkcipher);
	int ret = 0;

	/* allocate extended descriptor */
	edesc = ablkcipher_edesc_alloc(req);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	dpaa2_fl_set_len(&caam_req->fd_flt[0], req->nbytes);
	dpaa2_fl_set_len(&caam_req->fd_flt[1], req->nbytes + ivsize);
	caam_req->flc = &ctx->flc[ENCRYPT];
	caam_req->flc_dma = ctx->flc_dma[ENCRYPT];
	caam_req->cbk = ablkcipher_encrypt_done;
	caam_req->ctx = &req->base;
	caam_req->edesc = edesc;
	ret = dpaa2_caam_enqueue(ctx->priv->dev, caam_req);
	if (ret != -EINPROGRESS &&
	    !(ret == -EBUSY && req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG)) {
		ablkcipher_unmap(ctx->priv->dev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
}

static int ablkcipher_givencrypt(struct skcipher_givcrypt_request *greq)
{
	struct ablkcipher_request *req = &greq->creq;
	struct ablkcipher_edesc *edesc;
	struct crypto_ablkcipher *ablkcipher = crypto_ablkcipher_reqtfm(req);
	struct caam_ctx *ctx = crypto_ablkcipher_ctx(ablkcipher);
	struct caam_request *caam_req = ablkcipher_request_ctx(req);
	int ivsize = crypto_ablkcipher_ivsize(ablkcipher);
	int ret = 0;

	/* allocate extended descriptor */
	edesc = ablkcipher_giv_edesc_alloc(greq);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	dpaa2_fl_set_len(&caam_req->fd_flt[0], req->nbytes + ivsize);
	dpaa2_fl_set_len(&caam_req->fd_flt[1], req->nbytes);
	caam_req->flc = &ctx->flc[GIVENCRYPT];
	caam_req->flc_dma = ctx->flc_dma[GIVENCRYPT];
	caam_req->cbk = ablkcipher_encrypt_done;
	caam_req->ctx = &req->base;
	caam_req->edesc = edesc;
	ret = dpaa2_caam_enqueue(ctx->priv->dev, caam_req);
	if (ret != -EINPROGRESS &&
	    !(ret == -EBUSY && req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG)) {
		ablkcipher_unmap(ctx->priv->dev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
}

static int ablkcipher_decrypt(struct ablkcipher_request *req)
{
	struct ablkcipher_edesc *edesc;
	struct crypto_ablkcipher *ablkcipher = crypto_ablkcipher_reqtfm(req);
	struct caam_ctx *ctx = crypto_ablkcipher_ctx(ablkcipher);
	struct caam_request *caam_req = ablkcipher_request_ctx(req);
	int ivsize = crypto_ablkcipher_ivsize(ablkcipher);
	int ret = 0;

	/* allocate extended descriptor */
	edesc = ablkcipher_edesc_alloc(req);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	dpaa2_fl_set_len(&caam_req->fd_flt[0], req->nbytes);
	dpaa2_fl_set_len(&caam_req->fd_flt[1], req->nbytes + ivsize);
	caam_req->flc = &ctx->flc[DECRYPT];
	caam_req->flc_dma = ctx->flc_dma[DECRYPT];
	caam_req->cbk = ablkcipher_decrypt_done;
	caam_req->ctx = &req->base;
	caam_req->edesc = edesc;
	ret = dpaa2_caam_enqueue(ctx->priv->dev, caam_req);
	if (ret != -EINPROGRESS &&
	    !(ret == -EBUSY && req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG)) {
		ablkcipher_unmap(ctx->priv->dev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
}

/**
 * caam_crypto_alg - CAAM-specific algorithm struct wrapping crypto_alg
 * @entry: used for linking this struct in a list used for object management
 * @priv: driver private data
 * @class1_alg_type: algorithm to execute on a Class 1 CHA
 * @class2_alg_type: algorithm to execute on a Class 2 CHA
 * @alg_op: type of MDHA operation (only if MDHA split key generation is needed)
 * @crypto_alg: Crypto API's cipher algorithm
 */
struct caam_crypto_alg {
	struct list_head entry;
	struct dpaa2_caam_priv *priv;
	int class1_alg_type;
	int class2_alg_type;
	int alg_op;
	struct crypto_alg crypto_alg;
};

static int caam_cra_init(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	struct caam_crypto_alg *caam_alg =
		 container_of(alg, struct caam_crypto_alg, crypto_alg);
	struct caam_ctx *ctx = crypto_tfm_ctx(tfm);

	/* copy descriptor header template value */
	ctx->class1_alg_type = OP_TYPE_CLASS1_ALG | caam_alg->class1_alg_type;
	ctx->class2_alg_type = OP_TYPE_CLASS2_ALG | caam_alg->class2_alg_type;
	ctx->alg_op = OP_TYPE_CLASS2_ALG | caam_alg->alg_op;

	ctx->priv = caam_alg->priv;

	return 0;
}

static int caam_cra_init_ablkcipher(struct crypto_tfm *tfm)
{
	struct ablkcipher_tfm *ablkcipher_tfm =
		crypto_ablkcipher_crt(__crypto_ablkcipher_cast(tfm));

	ablkcipher_tfm->reqsize = sizeof(struct caam_request);
	return caam_cra_init(tfm);
}

static int caam_cra_init_aead(struct crypto_tfm *tfm)
{
	struct aead_tfm *aead_tfm = crypto_aead_crt(__crypto_aead_cast(tfm));

	aead_tfm->reqsize = sizeof(struct caam_request);
	return caam_cra_init(tfm);
}

static void caam_cra_exit(struct crypto_tfm *tfm)
{
	struct caam_ctx *ctx = crypto_tfm_ctx(tfm);
	int i;

	for (i = 0; i < NUM_OP; i++) {
		if (!ctx->flc_dma[i])
			continue;
		dma_unmap_single(ctx->priv->dev, ctx->flc_dma[i],
				 sizeof(ctx->flc[i].flc) +
					desc_bytes(ctx->flc[i].sh_desc),
				 DMA_TO_DEVICE);
	}

	if (ctx->key_dma)
		dma_unmap_single(ctx->priv->dev, ctx->key_dma, ctx->enckeylen +
				 ctx->split_key_pad_len, DMA_TO_DEVICE);
}

#define template_aead		template_u.aead
#define template_ablkcipher	template_u.ablkcipher
struct caam_alg_template {
	char name[CRYPTO_MAX_ALG_NAME];
	char driver_name[CRYPTO_MAX_ALG_NAME];
	unsigned int blocksize;
	u32 type;
	union {
		struct ablkcipher_alg ablkcipher;
		struct aead_alg aead;
		struct blkcipher_alg blkcipher;
		struct cipher_alg cipher;
		struct compress_alg compress;
		struct rng_alg rng;
	} template_u;
	u32 class1_alg_type;
	u32 class2_alg_type;
	u32 alg_op;
};

static struct caam_alg_template driver_algs[] = {
	/* ablkcipher descriptor */
	{
		.name = "cbc(aes)",
		.driver_name = "cbc-aes-dpaa2-caam",
		.blocksize = AES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_GIVCIPHER,
		.template_ablkcipher = {
			.setkey = ablkcipher_setkey,
			.encrypt = ablkcipher_encrypt,
			.decrypt = ablkcipher_decrypt,
			.givencrypt = ablkcipher_givencrypt,
			.geniv = "<built-in>",
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.ivsize = AES_BLOCK_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
	},
	{
		.name = "cbc(des3_ede)",
		.driver_name = "cbc-3des-dpaa2-caam",
		.blocksize = DES3_EDE_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_GIVCIPHER,
		.template_ablkcipher = {
			.setkey = ablkcipher_setkey,
			.encrypt = ablkcipher_encrypt,
			.decrypt = ablkcipher_decrypt,
			.givencrypt = ablkcipher_givencrypt,
			.geniv = "<built-in>",
			.min_keysize = DES3_EDE_KEY_SIZE,
			.max_keysize = DES3_EDE_KEY_SIZE,
			.ivsize = DES3_EDE_BLOCK_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
	},
	{
		.name = "cbc(des)",
		.driver_name = "cbc-des-dpaa2-caam",
		.blocksize = DES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_GIVCIPHER,
		.template_ablkcipher = {
			.setkey = ablkcipher_setkey,
			.encrypt = ablkcipher_encrypt,
			.decrypt = ablkcipher_decrypt,
			.givencrypt = ablkcipher_givencrypt,
			.geniv = "<built-in>",
			.min_keysize = DES_KEY_SIZE,
			.max_keysize = DES_KEY_SIZE,
			.ivsize = DES_BLOCK_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
	},
	{
		.name = "ctr(aes)",
		.driver_name = "ctr-aes-dpaa2-caam",
		.blocksize = 1,
		.type = CRYPTO_ALG_TYPE_ABLKCIPHER,
		.template_ablkcipher = {
			.setkey = ablkcipher_setkey,
			.encrypt = ablkcipher_encrypt,
			.decrypt = ablkcipher_decrypt,
			.geniv = "chainiv",
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.ivsize = AES_BLOCK_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CTR_MOD128,
	},
	{
		.name = "rfc3686(ctr(aes))",
		.driver_name = "rfc3686-ctr-aes-dpaa2-caam",
		.blocksize = 1,
		.type = CRYPTO_ALG_TYPE_GIVCIPHER,
		.template_ablkcipher = {
			.setkey = ablkcipher_setkey,
			.encrypt = ablkcipher_encrypt,
			.decrypt = ablkcipher_decrypt,
			.givencrypt = ablkcipher_givencrypt,
			.geniv = "<built-in>",
			.min_keysize = AES_MIN_KEY_SIZE +
				       CTR_RFC3686_NONCE_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE +
				       CTR_RFC3686_NONCE_SIZE,
			.ivsize = CTR_RFC3686_IV_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CTR_MOD128,
	}
};

static struct caam_crypto_alg *caam_alg_alloc(struct dpaa2_caam_priv *priv,
					      struct caam_alg_template
					      *template)
{
	struct caam_crypto_alg *t_alg;
	struct crypto_alg *alg;

	t_alg = kzalloc(sizeof(*t_alg), GFP_KERNEL);
	if (!t_alg)
		return ERR_PTR(-ENOMEM);

	alg = &t_alg->crypto_alg;

	snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s", template->name);
	snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
		 template->driver_name);
	alg->cra_module = THIS_MODULE;
	alg->cra_exit = caam_cra_exit;
	alg->cra_priority = CAAM_CRA_PRIORITY;
	alg->cra_blocksize = template->blocksize;
	alg->cra_alignmask = 0;
	alg->cra_ctxsize = sizeof(struct caam_ctx);
	alg->cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY |
			 template->type;
	switch (template->type) {
	case CRYPTO_ALG_TYPE_GIVCIPHER:
		alg->cra_init = caam_cra_init_ablkcipher;
		alg->cra_type = &crypto_givcipher_type;
		alg->cra_ablkcipher = template->template_ablkcipher;
		break;
	case CRYPTO_ALG_TYPE_ABLKCIPHER:
		alg->cra_init = caam_cra_init_ablkcipher;
		alg->cra_type = &crypto_ablkcipher_type;
		alg->cra_ablkcipher = template->template_ablkcipher;
		break;
	case CRYPTO_ALG_TYPE_AEAD:
		alg->cra_init = caam_cra_init_aead;
		alg->cra_type = &crypto_aead_type;
		alg->cra_aead = template->template_aead;
		break;
	}

	t_alg->class1_alg_type = template->class1_alg_type;
	t_alg->class2_alg_type = template->class2_alg_type;
	t_alg->alg_op = template->alg_op;
	t_alg->priv = priv;

	return t_alg;
}

static void dpaa2_caam_fqdan_cb(struct dpaa2_io_notification_ctx *nctx)
{
	struct dpaa2_caam_priv_per_cpu *ppriv;
	int err;

	ppriv = container_of(nctx, struct dpaa2_caam_priv_per_cpu, nctx);

	do {
		err = dpaa2_io_service_pull_fq(NULL, ppriv->rsp_fqid,
					       ppriv->store);
	} while (err);

	ppriv->has_frames = true;
	napi_schedule_irqoff(&ppriv->napi);
}

static int __cold dpaa2_dpseci_dpio_setup(struct dpaa2_caam_priv *priv)
{
	struct device *dev = priv->dev;
	struct dpaa2_io_notification_ctx *nctx;
	struct dpaa2_caam_priv_per_cpu *ppriv;
	int err, i;

	for_each_online_cpu(i) {
		ppriv = per_cpu_ptr(priv->ppriv, i);
		ppriv->priv = priv;
		nctx = &ppriv->nctx;
		nctx->is_cdan = 0;
		nctx->id = ppriv->rsp_fqid;
		nctx->desired_cpu = i;
		nctx->cb = dpaa2_caam_fqdan_cb;

		/* Register notification callbacks */
		err = dpaa2_io_service_register(NULL, nctx);
		if (unlikely(err)) {
			dev_err(dev, "notification register failed\n");
			nctx->cb = NULL;
			goto err;
		}

		ppriv->store = dpaa2_io_store_create(16, dev);
		if (unlikely(!ppriv->store)) {
			dev_err(dev, "dpaa2_io_store_create() failed\n");
			goto err;
		}
	}

	return 0;

err:
	for_each_online_cpu(i) {
		ppriv = per_cpu_ptr(priv->ppriv, i);
		if (!ppriv->nctx.cb)
			break;
		dpaa2_io_service_deregister(NULL, &ppriv->nctx);
	}

	for_each_online_cpu(i) {
		ppriv = per_cpu_ptr(priv->ppriv, i);
		if (!ppriv->store)
			break;
		dpaa2_io_store_destroy(ppriv->store);
	}

	return err;
}

static void __cold dpaa2_dpseci_dpio_free(struct dpaa2_caam_priv *priv)
{
	struct dpaa2_caam_priv_per_cpu *ppriv;
	int i;

	for_each_online_cpu(i) {
		ppriv = per_cpu_ptr(priv->ppriv, i);
		dpaa2_io_service_deregister(NULL, &ppriv->nctx);
		dpaa2_io_store_destroy(ppriv->store);
	}
}

static int dpaa2_dpseci_bind(struct dpaa2_caam_priv *priv)
{
	struct dpseci_rx_queue_cfg rx_queue_cfg;
	struct device *dev = priv->dev;
	struct fsl_mc_device *ls_dev = to_fsl_mc_device(dev);
	struct dpaa2_caam_priv_per_cpu *ppriv;
	int err = 0, i, j = 0;

	/*
	 * Configure Rx queues
	 * TODO: if number of Rx queues > number of (online) cores,
	 * not all Rx queues will be configured/used
	 */
	for_each_online_cpu(i) {
		ppriv = per_cpu_ptr(priv->ppriv, i);

		rx_queue_cfg.options = DPSECI_QUEUE_OPT_DEST |
				       DPSECI_QUEUE_OPT_USER_CTX;
		rx_queue_cfg.order_preservation_en = 0;
		rx_queue_cfg.dest_cfg.dest_type = DPSECI_DEST_DPIO;
		rx_queue_cfg.dest_cfg.dest_id = ppriv->nctx.dpio_id;
		/* TODO: hard-coded Rx priority (WQ) */
		rx_queue_cfg.dest_cfg.priority = 4;
		rx_queue_cfg.user_ctx = ppriv->nctx.qman64;

		err = dpseci_set_rx_queue(priv->mc_io, 0, ls_dev->mc_handle, j,
					  &rx_queue_cfg);
		if (err) {
			dev_err(dev, "dpseci_set_rx_queue() failed with err %d\n",
				err);
			return err;
		}

		j++;
		if (j == priv->dpseci_attr.num_rx_queues)
			break;
	}

	return err;
}

static void dpaa2_dpseci_free(struct dpaa2_caam_priv *priv)
{
	struct device *dev = priv->dev;
	struct fsl_mc_device *ls_dev = to_fsl_mc_device(dev);

	dpseci_close(priv->mc_io, 0, ls_dev->mc_handle);
}

static void dpaa2_caam_process_fd(struct dpaa2_caam_priv *priv,
				  const struct dpaa_fd *fd)
{
	struct caam_request *req;
	dma_addr_t rflc_dma;
	u32 err;

	if (dpaa2_fd_get_format(fd) != dpaa_fd_list) {
		dev_err(priv->dev, "Only Frame List FD format is supported!\n");
		return;
	}

	/*
	 * TODO: First check FD[ERR]
	 * see DPAA2RM section "3.4.5 Error handling" for error codes
	 */
	err = dpaa2_fd_get_frc(fd);
	if (err) {
		dev_err(priv->dev, "FD[FRC] err = %x\n", err);
		caam_jr_strstatus(priv->dev, err);
	}

	rflc_dma = dpaa2_fd_get_flc(fd);
	req = phys_to_virt(dma_to_phys(priv->dev, rflc_dma));
	dma_unmap_single(priv->dev, rflc_dma, sizeof(*req), DMA_TO_DEVICE);
	dma_unmap_single(priv->dev, req->fd_flt_dma, sizeof(req->fd_flt),
			 DMA_BIDIRECTIONAL);
	req->cbk(req->ctx, err);
}

static int dpaa2_dpseci_poll(struct napi_struct *napi, int budget)
{
	struct dpaa2_caam_priv_per_cpu *ppriv;
	struct dpaa2_caam_priv *priv;
	struct dpaa2_dq *dq;
	int err, cleaned = 0, is_last = 0;

	ppriv = container_of(napi, struct dpaa2_caam_priv_per_cpu, napi);

	if (!ppriv->has_frames) {
		napi_complete_done(napi, cleaned);
		return 0;
	}

	priv = ppriv->priv;
	while (!is_last && cleaned < budget) {
		do {
			dq = dpaa2_io_store_next(ppriv->store, &is_last);
		} while (!is_last && !dq);

		if (unlikely(!dq)) {
			dev_err(priv->dev, "FQID %d returned no valid frames!\n",
				ppriv->rsp_fqid);
			break;
		}

		/* Process FD */
		dpaa2_caam_process_fd(priv, dpaa2_dq_fd(dq));
		cleaned++;
	}

	/* Rearm if there are no more frames dequeued in store */
	if (is_last) {
		ppriv->has_frames = false;
		err = dpaa2_io_service_rearm(NULL, &ppriv->nctx);
		if (unlikely(err))
			dev_err(priv->dev, "Notification rearm failed\n");
	}

	if (cleaned < budget)
		napi_complete_done(napi, cleaned);

	return cleaned;
}

static int __cold dpaa2_dpseci_setup(struct fsl_mc_device *ls_dev)
{
	struct device *dev = &ls_dev->dev;
	struct dpaa2_caam_priv *priv;
	struct dpaa2_caam_priv_per_cpu *ppriv;
	int i, err;

	priv = dev_get_drvdata(dev);

	priv->dev = dev;
	priv->dpsec_id = ls_dev->obj_desc.id;

	/* Get a handle for the DPSECI this interface is associate with */
	err = dpseci_open(priv->mc_io, 0, priv->dpsec_id, &ls_dev->mc_handle);
	if (err)
		dev_err(dev, "dpsec_open() failed\n");
	else
		dev_info(dev, "Opened dpseci object successfully\n");

	err = dpseci_get_attributes(priv->mc_io, 0, ls_dev->mc_handle,
				    &priv->dpseci_attr);
	if (err) {
		dev_err(dev, "dpseci_get_attributes() failed\n");
		return err;
	}

	priv->num_pairs = min(priv->dpseci_attr.num_rx_queues,
			      priv->dpseci_attr.num_tx_queues);

	for (i = 0; i < priv->dpseci_attr.num_rx_queues; i++) {
		err = dpseci_get_rx_queue(priv->mc_io, 0, ls_dev->mc_handle, i,
					  &priv->rx_queue_attr[i]);
		if (err) {
			dev_err(dev, "dpseci_get_rx_queue() failed\n");
			return err;
		}
	}

	for (i = 0; i < priv->dpseci_attr.num_tx_queues; i++) {
		err = dpseci_get_tx_queue(priv->mc_io, 0, ls_dev->mc_handle, i,
					  &priv->tx_queue_attr[i]);
		if (err) {
			dev_err(dev, "dpseci_get_tx_queue() failed\n");
			return err;
		}
	}

	for (i = 0; i < priv->num_pairs; i++) {
		dev_info(dev, "prio %d: rx queue %d, tx queue %d\n", i,
			 priv->rx_queue_attr[i].fqid,
			 priv->tx_queue_attr[i].fqid);

		/* TODO: Assumption - number of queues <= number of cores */
		ppriv = per_cpu_ptr(priv->ppriv, i);
		ppriv->req_fqid = priv->tx_queue_attr[i].fqid;
		ppriv->rsp_fqid = priv->rx_queue_attr[i].fqid;
		ppriv->prio = i;

		ppriv->net_dev.dev = *dev;
		INIT_LIST_HEAD(&ppriv->net_dev.napi_list);
		netif_napi_add(&ppriv->net_dev, &ppriv->napi, dpaa2_dpseci_poll,
			       DPAA2_CAAM_NAPI_WEIGHT);
	}

	return 0;
}

static int dpaa2_dpseci_enable(struct dpaa2_caam_priv *priv)
{
	struct device *dev = priv->dev;
	struct fsl_mc_device *ls_dev = to_fsl_mc_device(dev);
	struct dpaa2_caam_priv_per_cpu *ppriv;
	int err, i;

	for (i = 0; i < priv->num_pairs; i++) {
		ppriv = per_cpu_ptr(priv->ppriv, i);
		napi_enable(&ppriv->napi);
	}

	err = dpseci_enable(priv->mc_io, 0, ls_dev->mc_handle);
	if (err) {
		dev_err(dev, "dpseci_enable() failed\n");
		return err;
	}

	dev_info(dev, "DPSECI version %d.%d\n",
		 priv->dpseci_attr.version.major,
		 priv->dpseci_attr.version.minor);

	return 0;
}

static int __cold dpaa2_dpseci_disable(struct dpaa2_caam_priv *priv)
{
	struct device *dev = priv->dev;
	struct dpaa2_caam_priv_per_cpu *ppriv;
	struct fsl_mc_device *ls_dev = to_fsl_mc_device(dev);
	int i, err = 0, enabled;

	err = dpseci_disable(priv->mc_io, 0, ls_dev->mc_handle);
	if (err) {
		dev_err(dev, "dpseci_disable() failed\n");
		return err;
	}

	err = dpseci_is_enabled(priv->mc_io, 0, ls_dev->mc_handle, &enabled);
	if (err) {
		dev_err(dev, "dpseci_is_enabled() failed\n");
		return err;
	}

	dev_dbg(dev, "disable: %s\n", enabled ? "false" : "true");

	for (i = 0; i < priv->num_pairs; i++) {
		ppriv = per_cpu_ptr(priv->ppriv, i);
		napi_disable(&ppriv->napi);
		netif_napi_del(&ppriv->napi);
	}

	return 0;
}

static struct list_head alg_list;

static int dpaa2_caam_probe(struct fsl_mc_device *dpseci_dev)
{
	struct device *dev;
	struct dpaa2_caam_priv *priv;
	int i, err = 0;

	dev = &dpseci_dev->dev;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	dev_set_drvdata(dev, priv);

	qi_cache = kmem_cache_create("dpaa2_caamqicache", CAAM_QI_MEMCACHE_SIZE,
				     0, SLAB_CACHE_DMA, NULL);
	if (!qi_cache) {
		dev_err(dev, "Can't allocate SEC cache\n");
		err = -ENOMEM;
		goto err_qicache;
	}

	/* DMA settings, will need later on for zero copy Rx/Tx */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(49));
	if (err) {
		dev_err(dev, "dma_set_mask_and_coherent() failed\n");
		goto err_dma_mask;
	}

	/* Obtain a MC portal */
	err = fsl_mc_portal_allocate(dpseci_dev, 0, &priv->mc_io);
	if (err) {
		dev_err(dev, "MC portal allocation failed\n");
		goto err_portal_alloc;
	}

	priv->ppriv = alloc_percpu(*priv->ppriv);
	if (!priv->ppriv) {
		dev_err(dev, "alloc_percpu() failed\n");
		goto err_alloc_ppriv;
	}

	/* DPSECI initialization */
	err = dpaa2_dpseci_setup(dpseci_dev);
	if (err < 0) {
		dev_err(dev, "dpaa2_dpseci_setup() failed\n");
		goto err_dpseci_setup;
	}

	/* DPIO */
	err = dpaa2_dpseci_dpio_setup(priv);
	if (err) {
		dev_err(dev, "dpaa2_dpseci_dpio_setup() failed\n");
		goto err_dpio_setup;
	}

	/* DPSECI binding to DPIO */
	err = dpaa2_dpseci_bind(priv);
	if (err) {
		dev_err(dev, "dpaa2_dpseci_bind() failed\n");
		goto err_bind;
	}

	/* DPSECI enable */
	err = dpaa2_dpseci_enable(priv);
	if (err) {
		dev_err(dev, "dpaa2_dpseci_enable() failed");
		goto err_bind;
	}

	/* register crypto algorithms the device supports */
	INIT_LIST_HEAD(&alg_list);
	for (i = 0; i < ARRAY_SIZE(driver_algs); i++) {
		/* TODO: check if h/w supports alg */
		struct caam_crypto_alg *t_alg;

		t_alg = caam_alg_alloc(priv, &driver_algs[i]);
		if (IS_ERR(t_alg)) {
			err = PTR_ERR(t_alg);
			dev_warn(dev, "%s alg allocation failed\n",
				 driver_algs[i].driver_name);
			continue;
		}

		err = crypto_register_alg(&t_alg->crypto_alg);
		if (err) {
			dev_warn(dev, "%s alg registration failed\n",
				 t_alg->crypto_alg.cra_driver_name);
			kfree(t_alg);
		} else {
			list_add_tail(&t_alg->entry, &alg_list);
		}
	}
	if (!list_empty(&alg_list))
		dev_info(dev, "algorithms registered in /proc/crypto\n");

	return err;

err_bind:
	dpaa2_dpseci_dpio_free(priv);
err_dpio_setup:
	dpaa2_dpseci_free(priv);
err_dpseci_setup:
	fsl_mc_portal_free(priv->mc_io);
err_alloc_ppriv:
	dpseci_close(priv->mc_io, 0, dpseci_dev->mc_handle);
err_portal_alloc:
err_dma_mask:
err_qicache:
	dev_set_drvdata(dev, NULL);

	return err;
}

static int __cold dpaa2_caam_remove(struct fsl_mc_device *ls_dev)
{
	struct device		*dev;
	struct dpaa2_caam_priv *priv;
	struct caam_crypto_alg *t_alg, *n;

	dev = &ls_dev->dev;
	priv = dev_get_drvdata(dev);

	if (alg_list.next)
		list_for_each_entry_safe(t_alg, n, &alg_list, entry) {
			crypto_unregister_alg(&t_alg->crypto_alg);
			list_del(&t_alg->entry);
			kfree(t_alg);
		}

	dpaa2_dpseci_disable(priv);
	dpaa2_dpseci_dpio_free(priv);
	dpaa2_dpseci_free(priv);
	fsl_mc_portal_free(priv->mc_io);
	dev_set_drvdata(dev, NULL);

	if (qi_cache)
		kmem_cache_destroy(qi_cache);

	return 0;
}

int dpaa2_caam_enqueue(struct device *dev, struct caam_request *req)
{
	size_t size;
	struct dpaa_fd fd;
	struct dpaa2_caam_priv *priv = dev_get_drvdata(dev);
	dma_addr_t rflc_dma;
	int err, i;

	if (IS_ERR(req))
		return PTR_ERR(req);

	dpaa2_fl_set_flc(&req->fd_flt[1], req->flc_dma);

	size = sizeof(req->fd_flt);
	req->fd_flt_dma = dma_map_single(dev, req->fd_flt, size,
					 DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, req->fd_flt_dma)) {
		dev_err(dev, "DMA mapping error for QI enqueue request\n");
		return -EIO;
	}

	memset(&fd, 0, sizeof(fd));
	dpaa2_fd_set_format(&fd, dpaa_fd_list);
	dpaa2_fd_set_addr(&fd, req->fd_flt_dma);
	dpaa2_fd_set_len(&fd, req->fd_flt[1].len);
	dpaa2_fd_set_flc(&fd, req->flc_dma);

	rflc_dma = dma_map_single(dev, req, sizeof(*req), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, rflc_dma)) {
		dev_err(dev, "DMA mapping error for response FLC\n");
		goto err_rflc_dma;
	}
	req->flc->flc[1] = desc_len(req->flc->sh_desc); /* SDL */
	req->flc->flc[2] = lower_32_bits(rflc_dma); /* RFLC_LO */
	req->flc->flc[3] = upper_32_bits(rflc_dma); /* RFLC_HI */
	dma_sync_single_for_device(dev, req->flc_dma,
				   sizeof(req->flc->flc) +
				   desc_bytes(req->flc->sh_desc),
				   DMA_TO_DEVICE);

	for (i = 0; i < 100000; i++) {
		/* TODO: priority hard-coded to zero */
		err = dpaa2_io_service_enqueue_fq(NULL,
						 priv->tx_queue_attr[0].fqid,
						 &fd);
		if (err != -EBUSY)
			break;
	}

	if (unlikely(err < 0)) {
		dev_err(dev, "Error enqueuing frame\n");
		goto err_enq;
	}

	return -EINPROGRESS;

err_enq:
	dma_unmap_single(dev, rflc_dma, sizeof(*req), DMA_TO_DEVICE);
err_rflc_dma:
	dma_unmap_single(dev, req->fd_flt_dma, size, DMA_BIDIRECTIONAL);
	return -EIO;
}
EXPORT_SYMBOL(dpaa2_caam_enqueue);

const struct fsl_mc_device_match_id dpaa2_caam_match_id_table[] = {
	{
		.vendor = FSL_MC_VENDOR_FREESCALE,
		.obj_type = "dpseci",
	},
	{ .vendor = 0x0 }
};

static struct fsl_mc_driver dpaa2_caam_driver = {
	.driver = {
		.name		= KBUILD_MODNAME,
		.owner		= THIS_MODULE,
	},
	.probe		= dpaa2_caam_probe,
	.remove		= dpaa2_caam_remove,
	.match_id_table = dpaa2_caam_match_id_table
};

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Freescale Semiconductor, Inc");
MODULE_DESCRIPTION("Freescale DPAA2 CAAM Driver");

module_fsl_mc_driver(dpaa2_caam_driver);
