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
#include "regs.h"
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
					 CTR_RFC3686_NONCE_SIZE + \
					 SHA512_DIGEST_SIZE * 2)

/* length of descriptors text */
#define DESC_AEAD_BASE			(4 * CAAM_CMD_SZ)
#define DESC_AEAD_ENC_LEN		(DESC_AEAD_BASE + 15 * CAAM_CMD_SZ)
#define DESC_AEAD_DEC_LEN		(DESC_AEAD_BASE + 18 * CAAM_CMD_SZ)
#define DESC_AEAD_GIVENC_LEN		(DESC_AEAD_ENC_LEN + 7 * CAAM_CMD_SZ)

/* Note: Nonce is counted in enckeylen */
#define DESC_AEAD_CTR_RFC3686_LEN	(6 * CAAM_CMD_SZ)

#define DESC_GCM_BASE			(3 * CAAM_CMD_SZ)
#define DESC_GCM_ENC_LEN		(DESC_GCM_BASE + 23 * CAAM_CMD_SZ)
#define DESC_GCM_DEC_LEN		(DESC_GCM_BASE + 19 * CAAM_CMD_SZ)

/* Length of a single buffer in the QI driver memory cache */
#define CAAM_QI_MEMCACHE_SIZE	512

/*
 * If all data, including src (with assoc and iv) or dst (with iv only) are
 * contiguous
 */
#define GIV_SRC_CONTIG		1
#define GIV_DST_CONTIG		(1 << 1)

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
 * qi_cache_zalloc - Allocate zeroized buffers from CAAM-QI cache
 *
 * Allocate data on the hotpath. Instead of using kmalloc, one can use the
 * services of the CAAM QI memory cache (backed by kmem_cache). The buffers
 * will have a size of CAAM_QI_MEMCACHE_SIZE, which should be sufficient for
 * hosting 16 SG entries.
 *
 * @flags - flags that would be used for the equivalent kzalloc(..) call
 *
 * Returns a pointer to a retrieved buffer on success or NULL on failure.
 */
static inline void *qi_cache_zalloc(gfp_t flags)
{
	return kmem_cache_zalloc(qi_cache, flags);
}

/*
 * qi_cache_free - Frees buffers allocated from CAAM-QI cache
 *
 * @obj - buffer previously allocated by qi_cache_[z]alloc
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
 * For aead functions, read payload and write payload,
 * both of which are specified in req->src and req->dst
 */
static inline void aead_append_src_dst(u32 *desc, u32 msg_type)
{
	append_seq_fifo_store(desc, 0, FIFOST_TYPE_MESSAGE_DATA | KEY_VLF);
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_BOTH |
			     KEY_VLF | msg_type | FIFOLD_TYPE_LASTBOTH);
}

/*
 * For aead encrypt and decrypt, read iv for both classes
 */
static inline void aead_append_ld_iv(u32 *desc, int ivsize, int ivoffset)
{
	append_seq_load(desc, ivsize, LDST_CLASS_1_CCB |
			LDST_SRCDST_BYTE_CONTEXT |
			(ivoffset << LDST_OFFSET_SHIFT));
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_CLASS2INFIFO |
		    (ivoffset << MOVE_OFFSET_SHIFT) | ivsize);
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

static void append_key_aead(u32 *desc, struct caam_ctx *ctx,
			    int keys_fit_inline, bool is_rfc3686)
{
	u32 *nonce;
	unsigned int enckeylen = ctx->enckeylen;

	/*
	 * RFC3686 specific:
	 *	| ctx->key = {AUTH_KEY, ENC_KEY, NONCE}
	 *	| enckeylen = encryption key size + nonce size
	 */
	if (is_rfc3686)
		enckeylen -= CTR_RFC3686_NONCE_SIZE;

	if (keys_fit_inline) {
		append_key_as_imm(desc, ctx->key, ctx->split_key_pad_len,
				  ctx->split_key_len, CLASS_2 |
				  KEY_DEST_MDHA_SPLIT | KEY_ENC);
		append_key_as_imm(desc, (void *)ctx->key +
				  ctx->split_key_pad_len, enckeylen,
				  enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	} else {
		append_key(desc, ctx->key_dma, ctx->split_key_len, CLASS_2 |
			   KEY_DEST_MDHA_SPLIT | KEY_ENC);
		append_key(desc, ctx->key_dma + ctx->split_key_pad_len,
			   enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	}

	/* Load Counter into CONTEXT1 reg */
	if (is_rfc3686) {
		nonce = (u32 *)((void *)ctx->key + ctx->split_key_pad_len +
			       enckeylen);
		append_load_imm_u32(desc, *nonce, LDST_CLASS_IND_CCB |
				    LDST_SRCDST_BYTE_OUTFIFO | LDST_IMM);
		append_move(desc,
			    MOVE_SRC_OUTFIFO |
			    MOVE_DEST_CLASS1CTX |
			    (16 << MOVE_OFFSET_SHIFT) |
			    (CTR_RFC3686_NONCE_SIZE << MOVE_LEN_SHIFT));
	}
}

static void init_sh_desc_key_aead(u32 *desc, struct caam_ctx *ctx,
				  int keys_fit_inline, bool is_rfc3686)
{
	u32 *key_jump_cmd;

	/* Note: Context registers are saved. */
	init_sh_desc(desc, HDR_SHARE_SERIAL | HDR_SAVECTX);

	/* Skip if already shared */
	key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
				   JUMP_COND_SHRD);

	append_key_aead(desc, ctx, keys_fit_inline, is_rfc3686);

	set_jump_tgt_here(desc, key_jump_cmd);
}

static int aead_set_sh_desc(struct crypto_aead *aead)
{
	struct aead_tfm *tfm = &aead->base.crt_aead;
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct crypto_tfm *ctfm = crypto_aead_tfm(aead);
	const char *alg_name = crypto_tfm_alg_name(ctfm);
	struct device *dev = ctx->priv->dev;
	struct caam_flc *flc;
	dma_addr_t *flc_dma;
	bool keys_fit_inline;
	u32 geniv, moveiv;
	u32 ctx1_iv_off = 0;
	u32 *desc;
	const bool ctr_mode = ((ctx->class1_alg_type & OP_ALG_AAI_MASK) ==
			       OP_ALG_AAI_CTR_MOD128);
	const bool is_rfc3686 = (ctr_mode &&
				 (strstr(alg_name, "rfc3686") != NULL));

	if (!ctx->enckeylen || !ctx->authsize)
		return 0;

	/*
	 * AES-CTR needs to load IV in CONTEXT1 reg
	 * at an offset of 128bits (16bytes)
	 * CONTEXT1[255:128] = IV
	 */
	if (ctr_mode)
		ctx1_iv_off = 16;

	/*
	 * RFC3686 specific:
	 *	CONTEXT1[255:128] = {NONCE, IV, COUNTER}
	 */
	if (is_rfc3686)
		ctx1_iv_off = 16 + CTR_RFC3686_NONCE_SIZE;

	/*
	 * Job Descriptor and Shared Descriptors
	 * must all fit into the 64-word Descriptor h/w Buffer
	 */
	keys_fit_inline = false;
	if (DESC_AEAD_ENC_LEN + DESC_JOB_IO_LEN +
	    ctx->split_key_pad_len + ctx->enckeylen +
	    (is_rfc3686 ? DESC_AEAD_CTR_RFC3686_LEN : 0) <=
	    CAAM_DESC_BYTES_MAX)
		keys_fit_inline = true;

	/* aead_encrypt shared descriptor */
	flc = &ctx->flc[ENCRYPT];
	flc_dma = &ctx->flc_dma[ENCRYPT];
	desc = flc->sh_desc;

	/* Note: Context registers are saved. */
	init_sh_desc_key_aead(desc, ctx, keys_fit_inline, is_rfc3686);

	/* Class 2 operation */
	append_operation(desc, ctx->class2_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* cryptlen = seqoutlen - authsize */
	append_math_sub_imm_u32(desc, REG3, SEQOUTLEN, IMM, ctx->authsize);

	/* assoclen + cryptlen = seqinlen - ivsize */
	append_math_sub_imm_u32(desc, REG2, SEQINLEN, IMM, tfm->ivsize);

	/* assoclen = (assoclen + cryptlen) - cryptlen */
	append_math_sub(desc, VARSEQINLEN, REG2, REG3, CAAM_CMD_SZ);

	/* read assoc before reading payload */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG |
			     KEY_VLF);
	aead_append_ld_iv(desc, tfm->ivsize, ctx1_iv_off);

	/* Load Counter into CONTEXT1 reg */
	if (is_rfc3686)
		append_load_imm_u32(desc, be32_to_cpu(1), LDST_IMM |
				    LDST_CLASS_1_CCB |
				    LDST_SRCDST_BYTE_CONTEXT |
				    ((ctx1_iv_off + CTR_RFC3686_IV_SIZE) <<
				     LDST_OFFSET_SHIFT));

	/* Class 1 operation */
	append_operation(desc, ctx->class1_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* Read and write cryptlen bytes */
	append_math_add(desc, VARSEQINLEN, ZERO, REG3, CAAM_CMD_SZ);
	append_math_add(desc, VARSEQOUTLEN, ZERO, REG3, CAAM_CMD_SZ);
	aead_append_src_dst(desc, FIFOLD_TYPE_MSG1OUT2);

	/* Write ICV */
	append_seq_store(desc, ctx->authsize, LDST_CLASS_2_CCB |
			 LDST_SRCDST_BYTE_CONTEXT);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) +
				  desc_bytes(desc), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "aead enc shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif

	/*
	 * Job Descriptor and Shared Descriptors
	 * must all fit into the 64-word Descriptor h/w Buffer
	 */
	keys_fit_inline = false;
	if (DESC_AEAD_DEC_LEN + DESC_JOB_IO_LEN +
	    ctx->split_key_pad_len + ctx->enckeylen +
	    (is_rfc3686 ? DESC_AEAD_CTR_RFC3686_LEN : 0) <=
	    CAAM_DESC_BYTES_MAX)
		keys_fit_inline = true;

	/* aead_decrypt shared descriptor */
	flc = &ctx->flc[DECRYPT];
	flc_dma = &ctx->flc_dma[DECRYPT];
	desc = flc->sh_desc;

	/* Note: Context registers are saved. */
	init_sh_desc_key_aead(desc, ctx, keys_fit_inline, is_rfc3686);

	/* Class 2 operation */
	append_operation(desc, ctx->class2_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT | OP_ALG_ICV_ON);

	/* assoclen + cryptlen = seqinlen - ivsize - authsize */
	append_math_sub_imm_u32(desc, REG3, SEQINLEN, IMM,
				ctx->authsize + tfm->ivsize);
	/* assoclen = (assoclen + cryptlen) - cryptlen */
	append_math_sub(desc, REG2, SEQOUTLEN, REG0, CAAM_CMD_SZ);
	append_math_sub(desc, VARSEQINLEN, REG3, REG2, CAAM_CMD_SZ);

	/* read assoc before reading payload */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG |
			     KEY_VLF);

	aead_append_ld_iv(desc, tfm->ivsize, ctx1_iv_off);

	/* Load Counter into CONTEXT1 reg */
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

	/* Read and write cryptlen bytes */
	append_math_add(desc, VARSEQINLEN, ZERO, REG2, CAAM_CMD_SZ);
	append_math_add(desc, VARSEQOUTLEN, ZERO, REG2, CAAM_CMD_SZ);
	aead_append_src_dst(desc, FIFOLD_TYPE_MSG);

	/* Load ICV */
	append_seq_fifo_load(desc, ctx->authsize, FIFOLD_CLASS_CLASS2 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_ICV);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) +
				  desc_bytes(desc), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "aead dec shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif

	/*
	 * Job Descriptor and Shared Descriptors
	 * must all fit into the 64-word Descriptor h/w Buffer
	 */
	keys_fit_inline = false;
	if (DESC_AEAD_GIVENC_LEN + DESC_JOB_IO_LEN +
	    ctx->split_key_pad_len + ctx->enckeylen +
	    (is_rfc3686 ? DESC_AEAD_CTR_RFC3686_LEN : 0) <=
	    CAAM_DESC_BYTES_MAX)
		keys_fit_inline = true;

	/* aead_givencrypt shared descriptor */
	flc = &ctx->flc[GIVENCRYPT];
	flc_dma = &ctx->flc_dma[GIVENCRYPT];
	desc = flc->sh_desc;

	/* Note: Context registers are saved. */
	init_sh_desc_key_aead(desc, ctx, keys_fit_inline, is_rfc3686);

	/* Generate IV */
	geniv = NFIFOENTRY_STYPE_PAD | NFIFOENTRY_DEST_DECO |
		NFIFOENTRY_DTYPE_MSG | NFIFOENTRY_LC1 |
		NFIFOENTRY_PTYPE_RND | (tfm->ivsize << NFIFOENTRY_DLEN_SHIFT);
	append_load_imm_u32(desc, geniv, LDST_CLASS_IND_CCB |
			    LDST_SRCDST_WORD_INFO_FIFO | LDST_IMM);
	append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);
	append_move(desc, MOVE_WAITCOMP |
		    MOVE_SRC_INFIFO | MOVE_DEST_CLASS1CTX |
		    (ctx1_iv_off << MOVE_OFFSET_SHIFT) |
		    (tfm->ivsize << MOVE_LEN_SHIFT));
	append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* Copy IV to class 1 context */
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_OUTFIFO |
		    (ctx1_iv_off << MOVE_OFFSET_SHIFT) |
		    (tfm->ivsize << MOVE_LEN_SHIFT));

	/* Return to encryption */
	append_operation(desc, ctx->class2_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* ivsize + cryptlen = seqoutlen - authsize */
	append_math_sub_imm_u32(desc, REG3, SEQOUTLEN, IMM, ctx->authsize);

	/* assoclen = seqinlen - (ivsize + cryptlen) */
	append_math_sub(desc, VARSEQINLEN, SEQINLEN, REG3, CAAM_CMD_SZ);

	/* read assoc before reading payload */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG |
			     KEY_VLF);

	/* Copy iv from outfifo to class 2 fifo */
	moveiv = NFIFOENTRY_STYPE_OFIFO | NFIFOENTRY_DEST_CLASS2 |
		 NFIFOENTRY_DTYPE_MSG | (tfm->ivsize << NFIFOENTRY_DLEN_SHIFT);
	append_load_imm_u32(desc, moveiv, LDST_CLASS_IND_CCB |
			    LDST_SRCDST_WORD_INFO_FIFO | LDST_IMM);
	append_load_imm_u32(desc, tfm->ivsize, LDST_CLASS_2_CCB |
			    LDST_SRCDST_WORD_DATASZ_REG | LDST_IMM);

	/* Load Counter into CONTEXT1 reg */
	if (is_rfc3686)
		append_load_imm_u32(desc, be32_to_cpu(1), LDST_IMM |
				    LDST_CLASS_1_CCB |
				    LDST_SRCDST_BYTE_CONTEXT |
				    ((ctx1_iv_off + CTR_RFC3686_IV_SIZE) <<
				     LDST_OFFSET_SHIFT));

	/* Class 1 operation */
	append_operation(desc, ctx->class1_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* Will write ivsize + cryptlen */
	append_math_add(desc, VARSEQOUTLEN, SEQINLEN, REG0, CAAM_CMD_SZ);

	/* Not need to reload iv */
	append_seq_fifo_load(desc, tfm->ivsize,
			     FIFOLD_CLASS_SKIP);

	/* Will read cryptlen */
	append_math_add(desc, VARSEQINLEN, SEQINLEN, REG0, CAAM_CMD_SZ);
	aead_append_src_dst(desc, FIFOLD_TYPE_MSG1OUT2);

	/* Write ICV */
	append_seq_store(desc, ctx->authsize, LDST_CLASS_2_CCB |
			 LDST_SRCDST_BYTE_CONTEXT);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) +
				  desc_bytes(desc), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "aead givenc shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	return 0;
}

static int aead_setauthsize(struct crypto_aead *authenc, unsigned int authsize)
{
	struct caam_ctx *ctx = crypto_aead_ctx(authenc);

	ctx->authsize = authsize;
	aead_set_sh_desc(authenc);

	return 0;
}

struct split_key_result {
	struct completion completion;
	int err;
	struct device *dev;
};

void split_key_done(void *cbk_ctx, u32 err)
{
	struct split_key_result *res = cbk_ctx;

#ifdef DEBUG
	dev_err(res->dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
#endif

	if (err)
		caam_jr_strstatus(res->dev, err);

	res->err = err;
	complete(&res->completion);
}

int gen_split_key(struct device *dev, u8 *key_out, int split_key_len,
		  int split_key_pad_len, const u8 *key_in, u32 keylen,
		  u32 alg_op)
{
	struct caam_request *req_ctx;
	u32 *desc;
	struct split_key_result result;
	dma_addr_t dma_addr_in, dma_addr_out, flc_dma;
	struct caam_flc *flc;
	struct dpaa_fl_entry *in_fle, *out_fle;
	int ret = -ENOMEM;

	req_ctx = kzalloc(sizeof(*req_ctx), GFP_KERNEL | GFP_DMA);
	if (!req_ctx)
		return -ENOMEM;

	in_fle = &req_ctx->fd_flt[1];
	out_fle = &req_ctx->fd_flt[0];

	flc = kzalloc(sizeof(*flc), GFP_KERNEL | GFP_DMA);
	if (!flc)
		goto err_flc;

	dma_addr_in = dma_map_single(dev, (void *)key_in, keylen,
				     DMA_TO_DEVICE);
	if (dma_mapping_error(dev, dma_addr_in)) {
		dev_err(dev, "unable to map key input memory\n");
		goto err_dma_addr_in;
	}

	dma_addr_out = dma_map_single(dev, key_out, split_key_pad_len,
				      DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, dma_addr_out)) {
		dev_err(dev, "unable to map key output memory\n");
		goto err_dma_addr_out;
	}

	desc = flc->sh_desc;

	init_sh_desc(desc, 0);
	append_key(desc, dma_addr_in, keylen, CLASS_2 | KEY_DEST_CLASS_REG);

	/* Sets MDHA up into an HMAC-INIT */
	append_operation(desc, alg_op | OP_ALG_DECRYPT | OP_ALG_AS_INIT);

	/*
	 * do a FIFO_LOAD of zero, this will trigger the internal key expansion
	 * into both pads inside MDHA
	 */
	append_fifo_load_as_imm(desc, NULL, 0, LDST_CLASS_2_CCB |
				FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/*
	 * FIFO_STORE with the explicit split-key content store
	 * (0x26 output type)
	 */
	append_fifo_store(desc, dma_addr_out, split_key_len,
			  LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);

	flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) + desc_bytes(desc),
				 DMA_TO_DEVICE);
	if (dma_mapping_error(dev, flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		goto err_flc_dma;
	}

	dpaa2_fl_set_final(in_fle, true);
	dpaa2_fl_set_format(in_fle, dpaa_fl_single);
	dpaa2_fl_set_addr(in_fle, dma_addr_in);
	dpaa2_fl_set_len(in_fle, keylen);
	dpaa2_fl_set_format(out_fle, dpaa_fl_single);
	dpaa2_fl_set_addr(out_fle, dma_addr_out);
	dpaa2_fl_set_len(out_fle, split_key_pad_len);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ctx.key@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, key_in, keylen, 1);
	print_hex_dump(KERN_ERR, "desc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif

	result.err = 0;
	init_completion(&result.completion);
	result.dev = dev;

	req_ctx->flc = flc;
	req_ctx->flc_dma = flc_dma;
	req_ctx->cbk = split_key_done;
	req_ctx->ctx = &result;

	ret = dpaa2_caam_enqueue(dev, req_ctx);
	if (ret == -EINPROGRESS) {
		/* in progress */
		wait_for_completion_interruptible(&result.completion);
		ret = result.err;
#ifdef DEBUG
		print_hex_dump(KERN_ERR, "ctx.key@"__stringify(__LINE__)": ",
			       DUMP_PREFIX_ADDRESS, 16, 4, key_out,
			       split_key_pad_len, 1);
#endif
	}

	dma_unmap_single(dev, flc_dma, sizeof(flc->flc) + desc_bytes(desc),
			 DMA_TO_DEVICE);
err_flc_dma:
	dma_unmap_single(dev, dma_addr_out, split_key_pad_len, DMA_FROM_DEVICE);
err_dma_addr_out:
	dma_unmap_single(dev, dma_addr_in, keylen, DMA_TO_DEVICE);
err_dma_addr_in:
	kfree(flc);
err_flc:
	kfree(req_ctx);
	return ret;
}

static int gen_split_aead_key(struct caam_ctx *ctx, const u8 *key_in,
			      u32 authkeylen)
{
	return gen_split_key(ctx->priv->dev, ctx->key, ctx->split_key_len,
			     ctx->split_key_pad_len, key_in, authkeylen,
			     ctx->alg_op);
}

static int aead_setkey(struct crypto_aead *aead, const u8 *key,
		       unsigned int keylen)
{
	/* Sizes for MDHA pads (*not* keys): MD5, SHA1, 224, 256, 384, 512 */
	static const u8 mdpadlen[] = { 16, 20, 32, 32, 64, 64 };
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct device *dev = ctx->priv->dev;
	struct crypto_authenc_keys keys;
	int ret = 0;

	if (crypto_authenc_extractkeys(&keys, key, keylen) != 0)
		goto badkey;

	/* Pick class 2 key length from algorithm submask */
	ctx->split_key_len = mdpadlen[(ctx->alg_op & OP_ALG_ALGSEL_SUBMASK) >>
				      OP_ALG_ALGSEL_SHIFT] * 2;
	ctx->split_key_pad_len = ALIGN(ctx->split_key_len, 16);

	if (ctx->split_key_pad_len + keys.enckeylen > CAAM_MAX_KEY_SIZE)
		goto badkey;

#ifdef DEBUG
	dev_err(dev, "keylen %d enckeylen %d authkeylen %d\n",
		keys.authkeylen + keys.enckeylen, keys.enckeylen,
		keys.authkeylen);
	dev_err(dev, "split_key_len %d split_key_pad_len %d\n",
		ctx->split_key_len, ctx->split_key_pad_len);
	print_hex_dump(KERN_ERR, "key in @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, key, keylen, 1);
#endif

	ret = gen_split_aead_key(ctx, keys.authkey, keys.authkeylen);
	if (ret)
		goto badkey;

	/* postpend encryption key to auth split key */
	memcpy(ctx->key + ctx->split_key_pad_len, keys.enckey, keys.enckeylen);

	ctx->key_dma = dma_map_single(dev, ctx->key, ctx->split_key_pad_len +
				      keys.enckeylen, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, ctx->key_dma)) {
		dev_err(dev, "unable to map key i/o memory\n");
		return -ENOMEM;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ctx.key@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, ctx->key,
		       ctx->split_key_pad_len + keys.enckeylen, 1);
#endif

	ctx->enckeylen = keys.enckeylen;

	ret = aead_set_sh_desc(aead);
	if (ret) {
		dma_unmap_single(dev, ctx->key_dma, ctx->split_key_pad_len +
				 keys.enckeylen, DMA_TO_DEVICE);
	}

	return ret;
badkey:
	crypto_aead_set_flags(aead, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

static struct aead_edesc *aead_edesc_alloc(struct aead_request *req,
					   bool encrypt)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_request *req_ctx = aead_request_ctx(req);
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct device *dev = ctx->priv->dev;
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	int assoc_nents, src_nents, dst_nents = 0;
	struct aead_edesc *edesc;
	dma_addr_t iv_dma = 0;
	int sgc;
	bool all_contig;
	bool assoc_chained = false, src_chained = false, dst_chained = false;
	int ivsize = crypto_aead_ivsize(aead);
	int qm_sg_index = 0, qm_sg_nents = 0, qm_sg_bytes;
	unsigned int authsize = ctx->authsize;
	struct dpaa_sg_entry *sg_table;
	bool is_gcm = false;

	assoc_nents = sg_count(req->assoc, req->assoclen, &assoc_chained);

	if (unlikely(req->dst != req->src)) {
		src_nents = sg_count(req->src, req->cryptlen, &src_chained);
		dst_nents = sg_count(req->dst,
				     req->cryptlen +
					(encrypt ? authsize : (-authsize)),
				     &dst_chained);
	} else {
		src_nents = sg_count(req->src,
				     req->cryptlen +
					(encrypt ? authsize : 0),
				     &src_chained);
	}

	sgc = dma_map_sg_chained(dev, req->assoc, assoc_nents ? : 1,
				 DMA_TO_DEVICE, assoc_chained);
	if (likely(req->src == req->dst)) {
		sgc = dma_map_sg_chained(dev, req->src, src_nents ? : 1,
					 DMA_BIDIRECTIONAL, src_chained);
	} else {
		sgc = dma_map_sg_chained(dev, req->src, src_nents ? : 1,
					 DMA_TO_DEVICE, src_chained);
		sgc = dma_map_sg_chained(dev, req->dst, dst_nents ? : 1,
					 DMA_FROM_DEVICE, dst_chained);
	}

	iv_dma = dma_map_single(dev, req->iv, ivsize, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, iv_dma)) {
		dev_err(dev, "unable to map IV\n");
		return ERR_PTR(-ENOMEM);
	}

	if (((ctx->class1_alg_type & OP_ALG_ALGSEL_MASK) ==
	      OP_ALG_ALGSEL_AES) &&
	    ((ctx->class1_alg_type & OP_ALG_AAI_MASK) == OP_ALG_AAI_GCM))
		is_gcm = true;

	/*
	 * Check if data are contiguous.
	 * GCM expected input sequence: IV, AAD, text
	 * All other - expected input sequence: AAD, IV, text
	 */
	if (is_gcm)
		all_contig = (!assoc_nents &&
			      iv_dma + ivsize == sg_dma_address(req->assoc) &&
			      !src_nents && sg_dma_address(req->assoc) +
			      req->assoclen == sg_dma_address(req->src));
	else
		all_contig = (!assoc_nents && sg_dma_address(req->assoc) +
			      req->assoclen == iv_dma && !src_nents &&
			      iv_dma + ivsize == sg_dma_address(req->src));
	if (!all_contig) {
		assoc_nents = assoc_nents ? : 1;
		src_nents = src_nents ? : 1;
		qm_sg_nents = assoc_nents + 1 + src_nents;
	}

	qm_sg_nents += dst_nents;
	qm_sg_bytes = qm_sg_nents * sizeof(struct dpaa_sg_entry);

	/* allocate space for base edesc and link tables */
	edesc = qi_cache_alloc(GFP_DMA | flags);
	if (!edesc) {
		dev_err(dev, "could not allocate extended descriptor\n");
		return ERR_PTR(-ENOMEM);
	}

	edesc->assoc_nents = assoc_nents;
	edesc->assoc_chained = assoc_chained;
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

	if (!all_contig) {
		dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
		dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);

		if (!is_gcm) {
			sg_to_qm_sg(req->assoc, assoc_nents, sg_table, 0);
			qm_sg_index += assoc_nents;
		}

		dma_to_qm_sg_one(sg_table + qm_sg_index, iv_dma, ivsize, 0);
		qm_sg_index += 1;

		if (is_gcm) {
			sg_to_qm_sg(req->assoc, assoc_nents, sg_table +
				    qm_sg_index, 0);
			qm_sg_index += assoc_nents;
		}

		sg_to_qm_sg_last(req->src, src_nents, sg_table + qm_sg_index,
				 0);
		qm_sg_index += src_nents;
	} else {
		dpaa2_fl_set_format(in_fle, dpaa_fl_single);
		if (is_gcm)
			dpaa2_fl_set_addr(in_fle, iv_dma);
		else
			dpaa2_fl_set_addr(in_fle, sg_dma_address(req->assoc));
	}

	if (dst_nents)
		sg_to_qm_sg_last(req->dst, dst_nents, sg_table + qm_sg_index,
				 0);

	if (req->src == req->dst) {
		if (src_nents <= 1) {
			dpaa2_fl_set_format(out_fle, dpaa_fl_single);
			dpaa2_fl_set_addr(out_fle, sg_dma_address(req->src));
		} else {
			dpaa2_fl_set_format(out_fle, dpaa_fl_sg);
			dpaa2_fl_set_addr(out_fle, edesc->qm_sg_dma +
					  ((edesc->assoc_nents ? : 1) + 1) *
					  sizeof(struct dpaa_sg_entry));
		}
	} else if (!dst_nents) {
		dpaa2_fl_set_format(out_fle, dpaa_fl_single);
		dpaa2_fl_set_addr(out_fle, sg_dma_address(req->dst));
	} else {
		dpaa2_fl_set_format(out_fle, dpaa_fl_sg);
		dpaa2_fl_set_addr(out_fle, edesc->qm_sg_dma + qm_sg_index *
				  sizeof(struct dpaa_sg_entry));
	}

	dma_sync_single_for_device(dev, edesc->qm_sg_dma, qm_sg_bytes,
				   DMA_TO_DEVICE);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "aead qm_sg@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, sg_table, qm_sg_bytes, 1);
#endif

	return edesc;
}

static struct aead_edesc *aead_giv_edesc_alloc(struct aead_givcrypt_request
					       *areq)
{
	struct aead_request *req = &areq->areq;
	struct caam_request *req_ctx = aead_request_ctx(req);
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct device *dev = ctx->priv->dev;
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	int assoc_nents, src_nents, dst_nents = 0;
	struct aead_edesc *edesc;
	dma_addr_t iv_dma = 0;
	int sgc;
	u32 contig = GIV_SRC_CONTIG | GIV_DST_CONTIG;
	int ivsize = crypto_aead_ivsize(aead);
	bool assoc_chained = false, src_chained = false, dst_chained = false;
	int qm_sg_index = 0, qm_sg_nents = 0, qm_sg_bytes;
	struct dpaa_sg_entry *sg_table;
	bool is_gcm = false;

	assoc_nents = sg_count(req->assoc, req->assoclen, &assoc_chained);
	src_nents = sg_count(req->src, req->cryptlen, &src_chained);

	if (unlikely(req->dst != req->src))
		dst_nents = sg_count(req->dst, req->cryptlen + ctx->authsize,
				     &dst_chained);

	sgc = dma_map_sg_chained(dev, req->assoc, assoc_nents ? : 1,
				 DMA_TO_DEVICE, assoc_chained);
	if (likely(req->src == req->dst)) {
		sgc = dma_map_sg_chained(dev, req->src, src_nents ? : 1,
					 DMA_BIDIRECTIONAL, src_chained);
	} else {
		sgc = dma_map_sg_chained(dev, req->src, src_nents ? : 1,
					 DMA_TO_DEVICE, src_chained);
		sgc = dma_map_sg_chained(dev, req->dst, dst_nents ? : 1,
					 DMA_FROM_DEVICE, dst_chained);
	}

	iv_dma = dma_map_single(dev, areq->giv, ivsize, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, iv_dma)) {
		dev_err(dev, "unable to map IV\n");
		return ERR_PTR(-ENOMEM);
	}

	if (((ctx->class1_alg_type & OP_ALG_ALGSEL_MASK) ==
	      OP_ALG_ALGSEL_AES) &&
	    ((ctx->class1_alg_type & OP_ALG_AAI_MASK) == OP_ALG_AAI_GCM))
		is_gcm = true;

	/*
	 * Check if data are contiguous.
	 * GCM expected input sequence: IV, AAD, text
	 * All other - expected input sequence: AAD, IV, text
	 */

	if (is_gcm) {
		if (assoc_nents || iv_dma + ivsize !=
		    sg_dma_address(req->assoc) || src_nents ||
		    sg_dma_address(req->assoc) + req->assoclen !=
		    sg_dma_address(req->src))
			contig &= ~GIV_SRC_CONTIG;
	} else {
		if (assoc_nents ||
		    sg_dma_address(req->assoc) + req->assoclen != iv_dma ||
		    src_nents || iv_dma + ivsize != sg_dma_address(req->src))
			contig &= ~GIV_SRC_CONTIG;
	}

	if (dst_nents || iv_dma + ivsize != sg_dma_address(req->dst))
		contig &= ~GIV_DST_CONTIG;

	if (!(contig & GIV_SRC_CONTIG)) {
		assoc_nents = assoc_nents ? : 1;
		src_nents = src_nents ? : 1;
		qm_sg_nents += assoc_nents + 1 + src_nents;
		if (req->src == req->dst &&
		    (src_nents || iv_dma + ivsize != sg_dma_address(req->src)))
			contig &= ~GIV_DST_CONTIG;
	}

	/*
	 * Add new sg entries for GCM output sequence.
	 * Expected output sequence: IV, encrypted text.
	 */
	if (is_gcm && req->src == req->dst && !(contig & GIV_DST_CONTIG))
		qm_sg_nents += 1 + src_nents;

	if (unlikely(req->src != req->dst)) {
		dst_nents = dst_nents ? : 1;
		qm_sg_nents += 1 + dst_nents;
	}

	qm_sg_bytes = qm_sg_nents * sizeof(struct dpaa_sg_entry);

	/* allocate space for base edesc and link tables */
	edesc = qi_cache_alloc(GFP_DMA | flags);
	if (unlikely(!edesc)) {
		dev_err(dev, "could not allocate extended descriptor\n");
		return ERR_PTR(-ENOMEM);
	}

	edesc->assoc_nents = assoc_nents;
	edesc->assoc_chained = assoc_chained;
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

	if (!(contig & GIV_SRC_CONTIG)) {
		dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
		dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);

		if (!is_gcm) {
			sg_to_qm_sg(req->assoc, assoc_nents, sg_table +
				    qm_sg_index, 0);
			qm_sg_index += assoc_nents;
		}

		dma_to_qm_sg_one(sg_table + qm_sg_index, iv_dma, ivsize, 0);
		qm_sg_index += 1;

		if (is_gcm) {
			sg_to_qm_sg(req->assoc, assoc_nents, sg_table +
				    qm_sg_index, 0);
			qm_sg_index += assoc_nents;
		}

		sg_to_qm_sg_last(req->src, src_nents, sg_table + qm_sg_index,
				 0);
		qm_sg_index += src_nents;
	} else {
		dpaa2_fl_set_format(in_fle, dpaa_fl_single);
		if (is_gcm)
			dpaa2_fl_set_addr(in_fle, iv_dma);
		else
			dpaa2_fl_set_addr(in_fle, sg_dma_address(req->assoc));
	}

	if (!(contig & GIV_DST_CONTIG)) {
		dpaa2_fl_set_format(out_fle, dpaa_fl_sg);
		if (req->src == req->dst) {
			dpaa2_fl_set_addr(out_fle, edesc->qm_sg_dma +
					  (edesc->assoc_nents + (is_gcm ? 1 +
					   edesc->src_nents : 0)) *
					   sizeof(struct dpaa_sg_entry));
			if (is_gcm) {
				dma_to_qm_sg_one(sg_table + qm_sg_index, iv_dma,
						 ivsize, 0);
				qm_sg_index += 1;
				sg_to_qm_sg_last(req->src, src_nents, sg_table +
						 qm_sg_index, 0);
			}
		} else {
			dpaa2_fl_set_addr(out_fle, edesc->qm_sg_dma +
					  qm_sg_index *
					  sizeof(struct dpaa_sg_entry));
			dma_to_qm_sg_one(sg_table + qm_sg_index, iv_dma, ivsize,
					 0);
			qm_sg_index += 1;
			sg_to_qm_sg_last(req->dst, dst_nents, sg_table +
					 qm_sg_index, 0);
		}
	} else {
		dpaa2_fl_set_format(out_fle, dpaa_fl_single);
		dpaa2_fl_set_addr(out_fle, iv_dma);
	}

	dma_sync_single_for_device(dev, edesc->qm_sg_dma, qm_sg_bytes,
				   DMA_TO_DEVICE);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "aead giv qm_sg@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, sg_table, qm_sg_bytes, 1);
#endif

	return edesc;
}

static int gcm_set_sh_desc(struct crypto_aead *aead)
{
	struct aead_tfm *tfm = &aead->base.crt_aead;
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct device *dev = ctx->priv->dev;
	struct caam_flc *flc;
	dma_addr_t *flc_dma;
	bool keys_fit_inline = false;
	u32 *key_jump_cmd, *zero_payload_jump_cmd,
	    *zero_assoc_jump_cmd1, *zero_assoc_jump_cmd2;
	u32 *desc;

	if (!ctx->enckeylen || !ctx->authsize)
		return 0;

	/*
	 * AES GCM encrypt shared descriptor
	 * Job Descriptor and Shared Descriptor
	 * must fit into the 64-word Descriptor h/w Buffer
	 */
	if (DESC_GCM_ENC_LEN + DESC_JOB_IO_LEN +
	    ctx->enckeylen <= CAAM_DESC_BYTES_MAX)
		keys_fit_inline = true;

	flc = &ctx->flc[ENCRYPT];
	flc_dma = &ctx->flc_dma[ENCRYPT];
	desc = flc->sh_desc;

	init_sh_desc(desc, HDR_SHARE_SERIAL);

	/* skip key loading if they are loaded due to sharing */
	key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
				   JUMP_COND_SHRD | JUMP_COND_SELF);
	if (keys_fit_inline)
		append_key_as_imm(desc, (void *)ctx->key, ctx->enckeylen,
				  ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	else
		append_key(desc, ctx->key_dma, ctx->enckeylen,
			   CLASS_1 | KEY_DEST_CLASS_REG);
	set_jump_tgt_here(desc, key_jump_cmd);

	/* class 1 operation */
	append_operation(desc, ctx->class1_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* cryptlen = seqoutlen - authsize */
	append_math_sub_imm_u32(desc, REG3, SEQOUTLEN, IMM, ctx->authsize);

	/* assoclen + cryptlen = seqinlen - ivsize */
	append_math_sub_imm_u32(desc, REG2, SEQINLEN, IMM, tfm->ivsize);

	/* assoclen = (assoclen + cryptlen) - cryptlen */
	append_math_sub(desc, REG1, REG2, REG3, CAAM_CMD_SZ);

	/* if cryptlen is ZERO jump to zero-payload commands */
	append_math_add(desc, VARSEQOUTLEN, ZERO, REG3, CAAM_CMD_SZ);
	zero_payload_jump_cmd = append_jump(desc, JUMP_TEST_ALL |
					    JUMP_COND_MATH_Z);
	/* read IV */
	append_seq_fifo_load(desc, tfm->ivsize, FIFOLD_CLASS_CLASS1 |
			     FIFOLD_TYPE_IV | FIFOLD_TYPE_FLUSH1);

	/* if assoclen is ZERO, skip reading the assoc data */
	append_math_add(desc, VARSEQINLEN, ZERO, REG1, CAAM_CMD_SZ);
	zero_assoc_jump_cmd1 = append_jump(desc, JUMP_TEST_ALL |
					   JUMP_COND_MATH_Z);

	/* read assoc data */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
			     FIFOLD_TYPE_AAD | FIFOLD_TYPE_FLUSH1);
	set_jump_tgt_here(desc, zero_assoc_jump_cmd1);

	append_math_add(desc, VARSEQINLEN, ZERO, REG3, CAAM_CMD_SZ);

	/* write encrypted data */
	append_seq_fifo_store(desc, 0, FIFOST_TYPE_MESSAGE_DATA | FIFOLDST_VLF);

	/* read payload data */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
			     FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1);

	/* jump the zero-payload commands */
	append_jump(desc, JUMP_TEST_ALL | 7);

	/* zero-payload commands */
	set_jump_tgt_here(desc, zero_payload_jump_cmd);

	/* if assoclen is ZERO, jump to IV reading - is the only input data */
	append_math_add(desc, VARSEQINLEN, ZERO, REG1, CAAM_CMD_SZ);
	zero_assoc_jump_cmd2 = append_jump(desc, JUMP_TEST_ALL |
					   JUMP_COND_MATH_Z);
	/* read IV */
	append_seq_fifo_load(desc, tfm->ivsize, FIFOLD_CLASS_CLASS1 |
			     FIFOLD_TYPE_IV | FIFOLD_TYPE_FLUSH1);

	/* read assoc data */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
			     FIFOLD_TYPE_AAD | FIFOLD_TYPE_LAST1);

	/* jump to ICV writing */
	append_jump(desc, JUMP_TEST_ALL | 2);

	/* read IV - is the only input data */
	set_jump_tgt_here(desc, zero_assoc_jump_cmd2);
	append_seq_fifo_load(desc, tfm->ivsize, FIFOLD_CLASS_CLASS1 |
			     FIFOLD_TYPE_IV | FIFOLD_TYPE_FLUSH1 |
			     FIFOLD_TYPE_LAST1);

	/* write ICV */
	append_seq_store(desc, ctx->authsize, LDST_CLASS_1_CCB |
			 LDST_SRCDST_BYTE_CONTEXT);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) +
				  desc_bytes(desc), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "gcm enc shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	/*
	 * Job Descriptor and Shared Descriptors
	 * must all fit into the 64-word Descriptor h/w Buffer
	 */
	keys_fit_inline = false;
	if (DESC_GCM_DEC_LEN + DESC_JOB_IO_LEN +
	    ctx->enckeylen <= CAAM_DESC_BYTES_MAX)
		keys_fit_inline = true;

	flc = &ctx->flc[DECRYPT];
	flc_dma = &ctx->flc_dma[DECRYPT];
	desc = flc->sh_desc;

	init_sh_desc(desc, HDR_SHARE_SERIAL);

	/* skip key loading if they are loaded due to sharing */
	key_jump_cmd = append_jump(desc, JUMP_JSL |
				   JUMP_TEST_ALL | JUMP_COND_SHRD |
				   JUMP_COND_SELF);
	if (keys_fit_inline)
		append_key_as_imm(desc, (void *)ctx->key, ctx->enckeylen,
				  ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	else
		append_key(desc, ctx->key_dma, ctx->enckeylen,
			   CLASS_1 | KEY_DEST_CLASS_REG);
	set_jump_tgt_here(desc, key_jump_cmd);

	/* class 1 operation */
	append_operation(desc, ctx->class1_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT | OP_ALG_ICV_ON);

	/* assoclen + cryptlen = seqinlen - ivsize - icvsize */
	append_math_sub_imm_u32(desc, REG3, SEQINLEN, IMM,
				ctx->authsize + tfm->ivsize);

	/* assoclen = (assoclen + cryptlen) - cryptlen */
	append_math_sub(desc, REG2, SEQOUTLEN, REG0, CAAM_CMD_SZ);
	append_math_sub(desc, REG1, REG3, REG2, CAAM_CMD_SZ);

	/* read IV */
	append_seq_fifo_load(desc, tfm->ivsize, FIFOLD_CLASS_CLASS1 |
			     FIFOLD_TYPE_IV | FIFOLD_TYPE_FLUSH1);

	/* jump to zero-payload command if cryptlen is zero */
	append_math_add(desc, VARSEQOUTLEN, ZERO, REG2, CAAM_CMD_SZ);
	zero_payload_jump_cmd = append_jump(desc, JUMP_TEST_ALL |
					    JUMP_COND_MATH_Z);

	append_math_add(desc, VARSEQINLEN, ZERO, REG1, CAAM_CMD_SZ);
	/* if asoclen is ZERO, skip reading assoc data */
	zero_assoc_jump_cmd1 = append_jump(desc, JUMP_TEST_ALL |
					   JUMP_COND_MATH_Z);
	/* read assoc data */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
			     FIFOLD_TYPE_AAD | FIFOLD_TYPE_FLUSH1);
	set_jump_tgt_here(desc, zero_assoc_jump_cmd1);

	append_math_add(desc, VARSEQINLEN, ZERO, REG2, CAAM_CMD_SZ);

	/* store encrypted data */
	append_seq_fifo_store(desc, 0, FIFOST_TYPE_MESSAGE_DATA | FIFOLDST_VLF);

	/* read payload data */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
			     FIFOLD_TYPE_MSG | FIFOLD_TYPE_FLUSH1);

	/* jump the zero-payload commands */
	append_jump(desc, JUMP_TEST_ALL | 4);

	/* zero-payload command */
	set_jump_tgt_here(desc, zero_payload_jump_cmd);

	/* if assoclen is ZERO, jump to ICV reading */
	append_math_add(desc, VARSEQINLEN, ZERO, REG1, CAAM_CMD_SZ);
	zero_assoc_jump_cmd2 = append_jump(desc, JUMP_TEST_ALL |
					   JUMP_COND_MATH_Z);
	/* read assoc data */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
			     FIFOLD_TYPE_AAD | FIFOLD_TYPE_FLUSH1);
	set_jump_tgt_here(desc, zero_assoc_jump_cmd2);

	/* read ICV */
	append_seq_fifo_load(desc, ctx->authsize, FIFOLD_CLASS_CLASS1 |
			     FIFOLD_TYPE_ICV | FIFOLD_TYPE_LAST1);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) +
				  desc_bytes(desc), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "gcm dec shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	return 0;
}

static int gcm_setauthsize(struct crypto_aead *authenc, unsigned int authsize)
{
	struct caam_ctx *ctx = crypto_aead_ctx(authenc);

	ctx->authsize = authsize;
	gcm_set_sh_desc(authenc);

	return 0;
}

static int gcm_setkey(struct crypto_aead *aead,
		      const u8 *key, unsigned int keylen)
{
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct device *dev = ctx->priv->dev;
	int ret = 0;

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "key in @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, key, keylen, 1);
#endif

	memcpy(ctx->key, key, keylen);
	ctx->key_dma = dma_map_single(dev, ctx->key, keylen, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, ctx->key_dma)) {
		dev_err(dev, "unable to map key i/o memory\n");
		return -ENOMEM;
	}
	ctx->enckeylen = keylen;

	ret = gcm_set_sh_desc(aead);
	if (ret)
		dma_unmap_single(dev, ctx->key_dma, ctx->enckeylen,
				 DMA_TO_DEVICE);

	return ret;
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

	dma_sync_single_for_device(dev, edesc->qm_sg_dma, qm_sg_bytes,
				   DMA_TO_DEVICE);

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

	dma_sync_single_for_device(dev, edesc->qm_sg_dma, qm_sg_bytes,
				   DMA_TO_DEVICE);

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

static void aead_unmap(struct device *dev, struct aead_edesc *edesc,
		       struct aead_request *req)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	int ivsize = crypto_aead_ivsize(aead);

	dma_unmap_sg_chained(dev, req->assoc, edesc->assoc_nents,
			     DMA_TO_DEVICE, edesc->assoc_chained);

	caam_unmap(dev, req->src, req->dst,
		   edesc->src_nents, edesc->src_chained, edesc->dst_nents,
		   edesc->dst_chained, edesc->iv_dma, ivsize,
		   edesc->qm_sg_dma, edesc->qm_sg_bytes);
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

static void aead_encrypt_done(void *cbk_ctx, u32 err)
{
	struct crypto_async_request *areq = cbk_ctx;
	struct aead_request *req = container_of(areq, struct aead_request,
						base);
	struct caam_request *req_ctx = to_caam_req(areq);
	struct aead_edesc *edesc = req_ctx->edesc;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
#ifdef DEBUG
	int ivsize = crypto_aead_ivsize(aead);

	dev_err(ctx->priv->dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
#endif

	if (unlikely(err))
		caam_jr_strstatus(ctx->priv->dev, err);

	aead_unmap(ctx->priv->dev, edesc, req);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "assoc  @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, sg_virt(req->assoc),
		       req->assoclen, 1);
	print_hex_dump(KERN_ERR, "dstiv  @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, sg_virt(req->src) - ivsize,
		       edesc->src_nents ? 100 : ivsize, 1);
	print_hex_dump(KERN_ERR, "dst    @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, sg_virt(req->src),
		       edesc->src_nents ? 100 : req->cryptlen +
		       ctx->authsize + 4, 1);
#endif

	qi_cache_free(edesc);
	aead_request_complete(req, err);
}

static void aead_decrypt_done(void *cbk_ctx, u32 err)
{
	struct crypto_async_request *areq = cbk_ctx;
	struct aead_request *req = container_of(areq, struct aead_request,
						base);
	struct caam_request *req_ctx = to_caam_req(areq);
	struct aead_edesc *edesc = req_ctx->edesc;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
#ifdef DEBUG
	int ivsize = crypto_aead_ivsize(aead);

	dev_err(ctx->priv->dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
	print_hex_dump(KERN_ERR, "dstiv  @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, req->iv,
		       ivsize, 1);
	print_hex_dump(KERN_ERR, "dst    @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, sg_virt(req->dst),
		       req->cryptlen - ctx->authsize, 1);
#endif

	if (unlikely(err))
		caam_jr_strstatus(ctx->priv->dev, err);

	aead_unmap(ctx->priv->dev, edesc, req);

	/*
	 * verify hw auth check passed else return -EBADMSG
	 */
	if ((err & JRSTA_CCBERR_ERRID_MASK) == JRSTA_CCBERR_ERRID_ICVCHK)
		err = -EBADMSG;

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "iphdrout@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4,
		       ((char *)sg_virt(req->assoc) - sizeof(struct iphdr)),
		       sizeof(struct iphdr) + req->assoclen +
		       ((req->cryptlen > 1500) ? 1500 : req->cryptlen) +
		       ctx->authsize + 36, 1);
	if (!err && edesc->qm_sg_bytes) {
		struct scatterlist *sg = sg_last(req->src, edesc->src_nents);

		print_hex_dump(KERN_ERR, "sglastout@"__stringify(__LINE__)": ",
			       DUMP_PREFIX_ADDRESS, 16, 4, sg_virt(sg),
			       sg->length + ctx->authsize + 16, 1);
	}
#endif

	qi_cache_free(edesc);
	aead_request_complete(req, err);
}

static int aead_encrypt(struct aead_request *req)
{
	struct aead_edesc *edesc;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct caam_request *caam_req = aead_request_ctx(req);
	int ivsize = crypto_aead_ivsize(aead);
	int ret = 0;

	/* allocate extended descriptor */
	edesc = aead_edesc_alloc(req, true);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	dpaa2_fl_set_len(&caam_req->fd_flt[0], req->cryptlen + ctx->authsize);
	dpaa2_fl_set_len(&caam_req->fd_flt[1], req->assoclen + ivsize +
			 req->cryptlen);
	caam_req->flc = &ctx->flc[ENCRYPT];
	caam_req->flc_dma = ctx->flc_dma[ENCRYPT];
	caam_req->cbk = aead_encrypt_done;
	caam_req->ctx = &req->base;
	caam_req->edesc = edesc;
	ret = dpaa2_caam_enqueue(ctx->priv->dev, caam_req);
	if (ret != -EINPROGRESS &&
	    !(ret == -EBUSY && req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG)) {
		aead_unmap(ctx->priv->dev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
}

static int aead_givencrypt(struct aead_givcrypt_request *areq)
{
	struct aead_request *req = &areq->areq;
	struct aead_edesc *edesc;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct caam_request *caam_req = aead_request_ctx(req);
	int ivsize = crypto_aead_ivsize(aead);
	int ret = 0;

	/* allocate extended descriptor */
	edesc = aead_giv_edesc_alloc(areq);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	dpaa2_fl_set_len(&caam_req->fd_flt[0], ivsize + req->cryptlen +
			 ctx->authsize);
	dpaa2_fl_set_len(&caam_req->fd_flt[1], req->assoclen + ivsize +
			 req->cryptlen);
	caam_req->flc = &ctx->flc[GIVENCRYPT];
	caam_req->flc_dma = ctx->flc_dma[GIVENCRYPT];
	caam_req->cbk = aead_encrypt_done;
	caam_req->ctx = &req->base;
	caam_req->edesc = edesc;
	ret = dpaa2_caam_enqueue(ctx->priv->dev, caam_req);
	if (ret != -EINPROGRESS &&
	    !(ret == -EBUSY && req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG)) {
		aead_unmap(ctx->priv->dev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
}

static int aead_decrypt(struct aead_request *req)
{
	struct aead_edesc *edesc;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct caam_request *caam_req = aead_request_ctx(req);
	int ivsize = crypto_aead_ivsize(aead);
	int ret = 0;

	/* allocate extended descriptor */
	edesc = aead_edesc_alloc(req, false);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	dpaa2_fl_set_len(&caam_req->fd_flt[0], req->cryptlen - ctx->authsize);
	dpaa2_fl_set_len(&caam_req->fd_flt[1], req->assoclen + ivsize +
			 req->cryptlen);
	caam_req->flc = &ctx->flc[DECRYPT];
	caam_req->flc_dma = ctx->flc_dma[DECRYPT];
	caam_req->cbk = aead_decrypt_done;
	caam_req->ctx = &req->base;
	caam_req->edesc = edesc;
	ret = dpaa2_caam_enqueue(ctx->priv->dev, caam_req);
	if (ret != -EINPROGRESS &&
	    !(ret == -EBUSY && req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG)) {
		aead_unmap(ctx->priv->dev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
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
	/* single-pass ipsec_esp descriptor */
	{
		.name = "authenc(hmac(md5),cbc(aes))",
		.driver_name = "authenc-hmac-md5-cbc-aes-dpaa2-caam",
		.blocksize = AES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = MD5_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha1),cbc(aes))",
		.driver_name = "authenc-hmac-sha1-cbc-aes-dpaa2-caam",
		.blocksize = AES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = SHA1_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha224),cbc(aes))",
		.driver_name = "authenc-hmac-sha224-cbc-aes-dpaa2-caam",
		.blocksize = AES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = SHA224_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA224 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha256),cbc(aes))",
		.driver_name = "authenc-hmac-sha256-cbc-aes-dpaa2-caam",
		.blocksize = AES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = SHA256_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA256 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha384),cbc(aes))",
		.driver_name = "authenc-hmac-sha384-cbc-aes-dpaa2-caam",
		.blocksize = AES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = SHA384_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA384 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha512),cbc(aes))",
		.driver_name = "authenc-hmac-sha512-cbc-aes-dpaa2-caam",
		.blocksize = AES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = SHA512_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA512 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(md5),cbc(des3_ede))",
		.driver_name = "authenc-hmac-md5-cbc-des3_ede-dpaa2-caam",
		.blocksize = DES3_EDE_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES3_EDE_BLOCK_SIZE,
			.maxauthsize = MD5_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha1),cbc(des3_ede))",
		.driver_name = "authenc-hmac-sha1-cbc-des3_ede-dpaa2-caam",
		.blocksize = DES3_EDE_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES3_EDE_BLOCK_SIZE,
			.maxauthsize = SHA1_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha224),cbc(des3_ede))",
		.driver_name = "authenc-hmac-sha224-cbc-des3_ede-dpaa2-caam",
		.blocksize = DES3_EDE_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES3_EDE_BLOCK_SIZE,
			.maxauthsize = SHA224_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA224 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha256),cbc(des3_ede))",
		.driver_name = "authenc-hmac-sha256-cbc-des3_ede-dpaa2-caam",
		.blocksize = DES3_EDE_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES3_EDE_BLOCK_SIZE,
			.maxauthsize = SHA256_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA256 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha384),cbc(des3_ede))",
		.driver_name = "authenc-hmac-sha384-cbc-des3_ede-dpaa2-caam",
		.blocksize = DES3_EDE_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES3_EDE_BLOCK_SIZE,
			.maxauthsize = SHA384_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA384 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha512),cbc(des3_ede))",
		.driver_name = "authenc-hmac-sha512-cbc-des3_ede-dpaa2-caam",
		.blocksize = DES3_EDE_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES3_EDE_BLOCK_SIZE,
			.maxauthsize = SHA512_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA512 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(md5),cbc(des))",
		.driver_name = "authenc-hmac-md5-cbc-des-dpaa2-caam",
		.blocksize = DES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES_BLOCK_SIZE,
			.maxauthsize = MD5_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha1),cbc(des))",
		.driver_name = "authenc-hmac-sha1-cbc-des-dpaa2-caam",
		.blocksize = DES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES_BLOCK_SIZE,
			.maxauthsize = SHA1_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha224),cbc(des))",
		.driver_name = "authenc-hmac-sha224-cbc-des-dpaa2-caam",
		.blocksize = DES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES_BLOCK_SIZE,
			.maxauthsize = SHA224_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA224 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha256),cbc(des))",
		.driver_name = "authenc-hmac-sha256-cbc-des-dpaa2-caam",
		.blocksize = DES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES_BLOCK_SIZE,
			.maxauthsize = SHA256_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA256 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha384),cbc(des))",
		.driver_name = "authenc-hmac-sha384-cbc-des-dpaa2-caam",
		.blocksize = DES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES_BLOCK_SIZE,
			.maxauthsize = SHA384_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA384 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha512),cbc(des))",
		.driver_name = "authenc-hmac-sha512-cbc-des-dpaa2-caam",
		.blocksize = DES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = DES_BLOCK_SIZE,
			.maxauthsize = SHA512_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA512 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(md5),rfc3686(ctr(aes)))",
		.driver_name = "authenc-hmac-md5-rfc3686-ctr-aes-dpaa2-caam",
		.blocksize = 1,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = CTR_RFC3686_IV_SIZE,
			.maxauthsize = MD5_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CTR_MOD128,
		.class2_alg_type = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha1),rfc3686(ctr(aes)))",
		.driver_name = "authenc-hmac-sha1-rfc3686-ctr-aes-dpaa2-caam",
		.blocksize = 1,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = CTR_RFC3686_IV_SIZE,
			.maxauthsize = SHA1_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CTR_MOD128,
		.class2_alg_type = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha224),rfc3686(ctr(aes)))",
		.driver_name = "authenc-hmac-sha224-rfc3686-ctr-aes-dpaa2-caam",
		.blocksize = 1,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = CTR_RFC3686_IV_SIZE,
			.maxauthsize = SHA224_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CTR_MOD128,
		.class2_alg_type = OP_ALG_ALGSEL_SHA224 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha256),rfc3686(ctr(aes)))",
		.driver_name = "authenc-hmac-sha256-rfc3686-ctr-aes-dpaa2-caam",
		.blocksize = 1,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = CTR_RFC3686_IV_SIZE,
			.maxauthsize = SHA256_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CTR_MOD128,
		.class2_alg_type = OP_ALG_ALGSEL_SHA256 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha384),rfc3686(ctr(aes)))",
		.driver_name = "authenc-hmac-sha384-rfc3686-ctr-aes-dpaa2-caam",
		.blocksize = 1,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = CTR_RFC3686_IV_SIZE,
			.maxauthsize = SHA384_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CTR_MOD128,
		.class2_alg_type = OP_ALG_ALGSEL_SHA384 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC,
	},
	{
		.name = "authenc(hmac(sha512),rfc3686(ctr(aes)))",
		.driver_name = "authenc-hmac-sha512-rfc3686-ctr-aes-dpaa2-caam",
		.blocksize = 1,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = aead_setkey,
			.setauthsize = aead_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = aead_givencrypt,
			.geniv = "<built-in>",
			.ivsize = CTR_RFC3686_IV_SIZE,
			.maxauthsize = SHA512_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CTR_MOD128,
		.class2_alg_type = OP_ALG_ALGSEL_SHA512 |
				   OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC,
	},
	/* Galois Counter Mode */
	{
		.name = "gcm(aes)",
		.driver_name = "gcm-aes-dpaa2-caam",
		.blocksize = 1,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = gcm_setkey,
			.setauthsize = gcm_setauthsize,
			.encrypt = aead_encrypt,
			.decrypt = aead_decrypt,
			.givencrypt = NULL,
			.geniv = "<built-in>",
			.ivsize = 12,
			.maxauthsize = AES_BLOCK_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_GCM,
	},
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

enum hash_optype {
	UPDATE = 0,
	UPDATE_FIRST,
	FINALIZE,
	DIGEST,
	FINALIZE_UPDATE,
	HASH_NUM_OP
};

/**
 * caam_hash_ctx - ahash per-session context
 * @flc: Flow Contexts array
 * @flc_dma: DMA addresses of the Flow Contexts
 * @priv: driver private data
 * @alg_type: algorithm to execute on a Class 2 CHA
 * @alg_op: type of MDHA operation (only if MDHA split key generation is needed)
 * @key:  virtual address of the authentication key
 * @key_dma: I/O virtual address of the key
 * @ctx_len: TODO
 * @split_key_len: MDHA split key length (to be used to KEY commands)
 * @split_key_pad_len: padded MDHA split key length (real key data length)
 */
struct caam_hash_ctx {
	struct caam_flc flc[HASH_NUM_OP];
	dma_addr_t flc_dma[HASH_NUM_OP];
	struct dpaa2_caam_priv *priv;
	u32 alg_type;
	u32 alg_op;
	u8 key[CAAM_MAX_HASH_KEY_SIZE];
	dma_addr_t key_dma;
	int ctx_len;
	unsigned int split_key_len;
	unsigned int split_key_pad_len;
};

struct caam_hash_template {
	char name[CRYPTO_MAX_ALG_NAME];
	char driver_name[CRYPTO_MAX_ALG_NAME];
	char hmac_name[CRYPTO_MAX_ALG_NAME];
	char hmac_driver_name[CRYPTO_MAX_ALG_NAME];
	unsigned int blocksize;
	struct ahash_alg template_ahash;
	u32 alg_type;
	u32 alg_op;
};

/* Map current buffer in state and put it in link table */
static inline dma_addr_t buf_map_to_qm_sg(struct device *dev,
					  struct dpaa_sg_entry *qm_sg, u8 *buf,
					  int buflen)
{
	dma_addr_t buf_dma;

	buf_dma = dma_map_single(dev, buf, buflen, DMA_TO_DEVICE);
	dma_to_qm_sg_one(qm_sg, buf_dma, buflen, 0);

	return buf_dma;
}

/* Map req->src and put it in link table */
static inline void src_map_to_qm_sg(struct device *dev, struct scatterlist *src,
				    int src_nents, struct dpaa_sg_entry *qm_sg,
				    bool chained)
{
	dma_map_sg_chained(dev, src, src_nents, DMA_TO_DEVICE, chained);
	sg_to_qm_sg_last(src, src_nents, qm_sg, 0);
}

/*
 * Only put buffer in link table if it contains data, which is possible,
 * since a buffer has previously been used, and needs to be unmapped,
 */
static inline dma_addr_t
try_buf_map_to_qm_sg(struct device *dev, struct dpaa_sg_entry *qm_sg, u8 *buf,
		     dma_addr_t buf_dma, int buflen, int last_buflen)
{
	if (buf_dma && !dma_mapping_error(dev, buf_dma))
		dma_unmap_single(dev, buf_dma, last_buflen, DMA_TO_DEVICE);
	if (buflen)
		buf_dma = buf_map_to_qm_sg(dev, qm_sg, buf, buflen);
	else
		buf_dma = 0;

	return buf_dma;
}

/* Append key if it has been set */
static inline void init_sh_desc_key_ahash(u32 *desc, struct caam_hash_ctx *ctx)
{
	u32 *key_jump_cmd;

	init_sh_desc(desc, HDR_SHARE_SERIAL);

	if (ctx->split_key_len) {
		/* Skip if already shared */
		key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
					   JUMP_COND_SHRD);

		append_key_as_imm(desc, ctx->key, ctx->split_key_pad_len,
				  ctx->split_key_len, CLASS_2 |
				  KEY_DEST_MDHA_SPLIT | KEY_ENC);

		set_jump_tgt_here(desc, key_jump_cmd);
	}

	/* Propagate errors from shared to job descriptor */
	append_cmd(desc, SET_OK_NO_PROP_ERRORS | CMD_LOAD);
}

/*
 * For ahash read data from seqin following state->caam_ctx,
 * and write resulting class2 context to seqout, which may be state->caam_ctx
 * or req->result
 */
static inline void ahash_append_load_str(u32 *desc, int digestsize)
{
	/* Calculate remaining bytes to read */
	append_math_add(desc, VARSEQINLEN, SEQINLEN, REG0, CAAM_CMD_SZ);

	/* Read remaining bytes */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_LAST2 |
			     FIFOLD_TYPE_MSG | KEY_VLF);

	/* Store class2 context bytes */
	append_seq_store(desc, digestsize, LDST_CLASS_2_CCB |
			 LDST_SRCDST_BYTE_CONTEXT);
}

/* For ahash firsts and digest, read and write to seqout */
static inline void ahash_data_to_out(u32 *desc, u32 op, u32 state,
				     int digestsize, struct caam_hash_ctx *ctx)
{
	init_sh_desc_key_ahash(desc, ctx);

	/* Class 2 operation */
	append_operation(desc, op | state | OP_ALG_ENCRYPT);

	/*
	 * Load from buf and/or src and write to req->result or state->context
	 */
	ahash_append_load_str(desc, digestsize);
}

/*
 * For ahash update, final and finup, import context, read and write to seqout
 */
static inline void ahash_ctx_data_to_out(u32 *desc, u32 op, u32 state,
					 int digestsize,
					 struct caam_hash_ctx *ctx)
{
	init_sh_desc_key_ahash(desc, ctx);

	/* Import context from software */
	append_cmd(desc, CMD_SEQ_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_2_CCB | ctx->ctx_len);

	/* Class 2 operation */
	append_operation(desc, op | state | OP_ALG_ENCRYPT);

	/*
	 * Load from buf and/or src and write to req->result or state->context
	 */
	ahash_append_load_str(desc, digestsize);
}

static int gen_split_hash_key(struct caam_hash_ctx *ctx, const u8 *key_in,
			      u32 keylen)
{
	return gen_split_key(ctx->priv->dev, ctx->key, ctx->split_key_len,
			     ctx->split_key_pad_len, key_in, keylen,
			     ctx->alg_op);
}

/* Digest hash size if it is too large */
static int hash_digest_key(struct caam_hash_ctx *ctx, const u8 *key_in,
			   u32 *keylen, u8 *key_out, u32 digestsize)
{
	struct caam_request *req_ctx;
	struct device *dev = ctx->priv->dev;
	u32 *desc;
	struct split_key_result result;
	dma_addr_t src_dma, dst_dma, flc_dma;
	struct caam_flc *flc;
	int ret = -ENOMEM;
	struct dpaa_fl_entry *in_fle, *out_fle;

	req_ctx = kzalloc(sizeof(*req_ctx), GFP_KERNEL | GFP_DMA);
	if (!req_ctx)
		return -ENOMEM;

	in_fle = &req_ctx->fd_flt[1];
	out_fle = &req_ctx->fd_flt[0];

	flc = kzalloc(sizeof(*flc), GFP_KERNEL | GFP_DMA);
	if (!flc)
		goto err_flc;

	src_dma = dma_map_single(dev, (void *)key_in, *keylen, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, src_dma)) {
		dev_err(dev, "unable to map key input memory\n");
		goto err_src_dma;
	}
	dst_dma = dma_map_single(dev, (void *)key_out, digestsize,
				 DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, dst_dma)) {
		dev_err(dev, "unable to map key output memory\n");
		goto err_dst_dma;
	}

	desc = flc->sh_desc;

	init_sh_desc(desc, 0);

	/* descriptor to perform unkeyed hash on key_in */
	append_operation(desc, ctx->alg_type | OP_ALG_ENCRYPT |
			 OP_ALG_AS_INITFINAL);
	append_seq_fifo_load(desc, *keylen, FIFOLD_CLASS_CLASS2 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_MSG);
	append_seq_store(desc, digestsize, LDST_CLASS_2_CCB |
			 LDST_SRCDST_BYTE_CONTEXT);

	flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) + desc_bytes(desc),
				 DMA_TO_DEVICE);
	if (dma_mapping_error(dev, flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		goto err_flc_dma;
	}

	dpaa2_fl_set_final(in_fle, true);
	dpaa2_fl_set_format(in_fle, dpaa_fl_single);
	dpaa2_fl_set_addr(in_fle, src_dma);
	dpaa2_fl_set_len(in_fle, *keylen);
	dpaa2_fl_set_format(out_fle, dpaa_fl_single);
	dpaa2_fl_set_addr(out_fle, dst_dma);
	dpaa2_fl_set_len(out_fle, digestsize);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "key_in@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, key_in, *keylen, 1);
	print_hex_dump(KERN_ERR, "shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif

	result.err = 0;
	init_completion(&result.completion);
	result.dev = dev;

	req_ctx->flc = flc;
	req_ctx->flc_dma = flc_dma;
	req_ctx->cbk = split_key_done;
	req_ctx->ctx = &result;

	ret = dpaa2_caam_enqueue(dev, req_ctx);
	if (ret == -EINPROGRESS) {
		/* in progress */
		wait_for_completion_interruptible(&result.completion);
		ret = result.err;
#ifdef DEBUG
		print_hex_dump(KERN_ERR,
			       "digested key@"__stringify(__LINE__)": ",
			       DUMP_PREFIX_ADDRESS, 16, 4, key_in,
			       digestsize, 1);
#endif
	}

	dma_unmap_single(dev, flc_dma, sizeof(flc->flc) + desc_bytes(desc),
			 DMA_TO_DEVICE);
err_flc_dma:
	dma_unmap_single(dev, dst_dma, digestsize, DMA_FROM_DEVICE);
err_dst_dma:
	dma_unmap_single(dev, src_dma, *keylen, DMA_TO_DEVICE);
err_src_dma:
	kfree(flc);
err_flc:
	kfree(req_ctx);

	*keylen = digestsize;

	return ret;
}

static int ahash_set_sh_desc(struct crypto_ahash *ahash)
{
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	int digestsize = crypto_ahash_digestsize(ahash);
	struct device *dev = ctx->priv->dev;
	struct caam_flc *flc;
	dma_addr_t *flc_dma;
	u32 have_key = 0;
	u32 *desc;

	if (ctx->split_key_len)
		have_key = OP_ALG_AAI_HMAC_PRECOMP;

	/* ahash_update shared descriptor */
	flc = &ctx->flc[UPDATE];
	flc_dma = &ctx->flc_dma[UPDATE];
	desc = flc->sh_desc;
	init_sh_desc(desc, HDR_SHARE_SERIAL);

	/* Import context from software */
	append_cmd(desc, CMD_SEQ_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_2_CCB | ctx->ctx_len);

	/* Class 2 operation */
	append_operation(desc, ctx->alg_type | OP_ALG_AS_UPDATE |
			 OP_ALG_ENCRYPT);

	/* Load data and write to result or context */
	ahash_append_load_str(desc, ctx->ctx_len);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) +
				  desc_bytes(desc), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}

#ifdef DEBUG
	print_hex_dump(KERN_ERR,
		       "ahash update shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif

	/* ahash_update_first shared descriptor */
	flc = &ctx->flc[UPDATE_FIRST];
	flc_dma = &ctx->flc_dma[UPDATE_FIRST];
	desc = flc->sh_desc;

	ahash_data_to_out(desc, have_key | ctx->alg_type, OP_ALG_AS_INIT,
			  ctx->ctx_len, ctx);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) + desc_bytes(desc),
				  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR,
		       "ahash update first shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif

	/* ahash_final shared descriptor */
	flc = &ctx->flc[FINALIZE];
	flc_dma = &ctx->flc_dma[FINALIZE];
	desc = flc->sh_desc;

	ahash_ctx_data_to_out(desc, have_key | ctx->alg_type,
			      OP_ALG_AS_FINALIZE, digestsize, ctx);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) + desc_bytes(desc),
				  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ahash final shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	/* ahash_finup shared descriptor */
	flc = &ctx->flc[FINALIZE_UPDATE];
	flc_dma = &ctx->flc_dma[FINALIZE_UPDATE];
	desc = flc->sh_desc;

	ahash_ctx_data_to_out(desc, have_key | ctx->alg_type,
			      OP_ALG_AS_FINALIZE, digestsize, ctx);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) + desc_bytes(desc),
				  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ahash finup shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	/* ahash_digest shared descriptor */
	flc = &ctx->flc[DIGEST];
	flc_dma = &ctx->flc_dma[DIGEST];
	desc = flc->sh_desc;

	ahash_data_to_out(desc, have_key | ctx->alg_type, OP_ALG_AS_INITFINAL,
			  digestsize, ctx);

	*flc_dma = dma_map_single(dev, flc, sizeof(flc->flc) + desc_bytes(desc),
				  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *flc_dma)) {
		dev_err(dev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR,
		       "ahash digest shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif

	return 0;
}

static int ahash_setkey(struct crypto_ahash *ahash, const u8 *key,
			unsigned int keylen)
{
	/* Sizes for MDHA pads (*not* keys): MD5, SHA1, 224, 256, 384, 512 */
	static const u8 mdpadlen[] = { 16, 20, 32, 32, 64, 64 };
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct device *dev = ctx->priv->dev;
	unsigned int blocksize = crypto_tfm_alg_blocksize(&ahash->base);
	unsigned int digestsize = crypto_ahash_digestsize(ahash);
	int ret = 0;
	u8 *hashed_key = NULL;

#ifdef DEBUG
	pr_err("keylen %d\n", keylen);
	pr_err("blocksize %d\n", blocksize);
#endif

	if (keylen > blocksize) {
		hashed_key = kmalloc(digestsize, GFP_KERNEL | GFP_DMA);
		if (!hashed_key)
			return -ENOMEM;
		ret = hash_digest_key(ctx, key, &keylen, hashed_key,
				      digestsize);
		if (ret)
			goto badkey;
		key = hashed_key;
	}

	/* Pick class 2 key length from algorithm submask */
	ctx->split_key_len = mdpadlen[(ctx->alg_op & OP_ALG_ALGSEL_SUBMASK) >>
				      OP_ALG_ALGSEL_SHIFT] * 2;
	ctx->split_key_pad_len = ALIGN(ctx->split_key_len, 16);

#ifdef DEBUG
	dev_err(dev, "split_key_len %d split_key_pad_len %d\n",
		ctx->split_key_len, ctx->split_key_pad_len);
	print_hex_dump(KERN_ERR, "key in @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, key, keylen, 1);
#endif

	ret = gen_split_hash_key(ctx, key, keylen);
	if (ret)
		goto badkey;

	ctx->key_dma = dma_map_single(dev, ctx->key, ctx->split_key_pad_len,
				      DMA_TO_DEVICE);
	if (dma_mapping_error(dev, ctx->key_dma)) {
		dev_err(dev, "unable to map key i/o memory\n");
		ret = -ENOMEM;
		goto map_err;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ctx.key@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, ctx->key,
		       ctx->split_key_pad_len, 1);
#endif

	ret = ahash_set_sh_desc(ahash);
	if (ret) {
		dma_unmap_single(dev, ctx->key_dma, ctx->split_key_pad_len,
				 DMA_TO_DEVICE);
	}

map_err:
	kfree(hashed_key);
	return ret;
badkey:
	kfree(hashed_key);
	crypto_ahash_set_flags(ahash, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

static inline void ahash_unmap(struct device *dev, struct ahash_edesc *edesc,
			       struct ahash_request *req, int dst_len)
{
	if (edesc->src_nents)
		dma_unmap_sg_chained(dev, req->src, edesc->src_nents,
				     DMA_TO_DEVICE, edesc->chained);
	if (edesc->dst_dma)
		dma_unmap_single(dev, edesc->dst_dma, dst_len, DMA_FROM_DEVICE);

	if (edesc->qm_sg_bytes)
		dma_unmap_single(dev, edesc->qm_sg_dma, edesc->qm_sg_bytes,
				 DMA_TO_DEVICE);
}

static inline void ahash_unmap_ctx(struct device *dev,
				   struct ahash_edesc *edesc,
				   struct ahash_request *req, int dst_len,
				   u32 flag)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct caam_hash_state *state = ahash_request_ctx(req);

	if (state->ctx_dma)
		dma_unmap_single(dev, state->ctx_dma, ctx->ctx_len, flag);
	ahash_unmap(dev, edesc, req, dst_len);
}

static void ahash_done(void *cbk_ctx, u32 err)
{
	struct crypto_async_request *areq = cbk_ctx;
	struct ahash_request *req = ahash_request_cast(areq);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct ahash_edesc *edesc = state->caam_req.edesc;
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	int digestsize = crypto_ahash_digestsize(ahash);

#ifdef DEBUG
	dev_err(ctx->priv->dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
#endif

	if (unlikely(err))
		caam_jr_strstatus(ctx->priv->dev, err);

	ahash_unmap(ctx->priv->dev, edesc, req, digestsize);
	qi_cache_free(edesc);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ctx@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, state->caam_ctx,
		       ctx->ctx_len, 1);
	if (req->result)
		print_hex_dump(KERN_ERR, "result@"__stringify(__LINE__)": ",
			       DUMP_PREFIX_ADDRESS, 16, 4, req->result,
			       digestsize, 1);
#endif

	req->base.complete(&req->base, err);
}

static void ahash_done_bi(void *cbk_ctx, u32 err)
{
	struct crypto_async_request *areq = cbk_ctx;
	struct ahash_request *req = ahash_request_cast(areq);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct ahash_edesc *edesc = state->caam_req.edesc;
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
#ifdef DEBUG
	int digestsize = crypto_ahash_digestsize(ahash);

	dev_err(ctx->priv->dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
#endif

	if (unlikely(err))
		caam_jr_strstatus(ctx->priv->dev, err);

	ahash_unmap_ctx(ctx->priv->dev, edesc, req, ctx->ctx_len,
			DMA_BIDIRECTIONAL);
	qi_cache_free(edesc);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ctx@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, state->caam_ctx,
		       ctx->ctx_len, 1);
	if (req->result)
		print_hex_dump(KERN_ERR, "result@"__stringify(__LINE__)": ",
			       DUMP_PREFIX_ADDRESS, 16, 4, req->result,
			       digestsize, 1);
#endif

	req->base.complete(&req->base, err);
}

static void ahash_done_ctx_src(void *cbk_ctx, u32 err)
{
	struct crypto_async_request *areq = cbk_ctx;
	struct ahash_request *req = ahash_request_cast(areq);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct ahash_edesc *edesc = state->caam_req.edesc;
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	int digestsize = crypto_ahash_digestsize(ahash);

#ifdef DEBUG
	dev_err(ctx->priv->dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
#endif

	if (unlikely(err))
		caam_jr_strstatus(ctx->priv->dev, err);

	ahash_unmap_ctx(ctx->priv->dev, edesc, req, digestsize, DMA_TO_DEVICE);
	qi_cache_free(edesc);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ctx@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, state->caam_ctx,
		       ctx->ctx_len, 1);
	if (req->result)
		print_hex_dump(KERN_ERR, "result@"__stringify(__LINE__)": ",
			       DUMP_PREFIX_ADDRESS, 16, 4, req->result,
			       digestsize, 1);
#endif

	req->base.complete(&req->base, err);
}

static void ahash_done_ctx_dst(void *cbk_ctx, u32 err)
{
	struct crypto_async_request *areq = cbk_ctx;
	struct ahash_request *req = ahash_request_cast(areq);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct ahash_edesc *edesc = state->caam_req.edesc;
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
#ifdef DEBUG
	int digestsize = crypto_ahash_digestsize(ahash);

	dev_err(ctx->priv->dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
#endif

	if (unlikely(err))
		caam_jr_strstatus(ctx->priv->dev, err);

	ahash_unmap_ctx(ctx->priv->dev, edesc, req, ctx->ctx_len,
			DMA_FROM_DEVICE);
	qi_cache_free(edesc);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ctx@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, state->caam_ctx,
		       ctx->ctx_len, 1);
	if (req->result)
		print_hex_dump(KERN_ERR, "result@"__stringify(__LINE__)": ",
			       DUMP_PREFIX_ADDRESS, 16, 4, req->result,
			       digestsize, 1);
#endif

	req->base.complete(&req->base, err);
}

static int ahash_update_ctx(struct ahash_request *req)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct caam_request *req_ctx = &state->caam_req;
	struct device *dev = ctx->priv->dev;
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	u8 *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int *buflen = state->current_buf ? &state->buflen_1 : &state->buflen_0;
	u8 *next_buf = state->current_buf ? state->buf_0 : state->buf_1;
	int *next_buflen = state->current_buf ? &state->buflen_0 :
			   &state->buflen_1, last_buflen;
	int in_len = *buflen + req->nbytes, to_hash;
	int src_nents, qm_sg_bytes, qm_sg_src_index;
	struct ahash_edesc *edesc;
	struct dpaa_sg_entry *sg_table;
	bool chained = false;
	int ret = 0;

	last_buflen = *next_buflen;
	*next_buflen = in_len & (crypto_tfm_alg_blocksize(&ahash->base) - 1);
	to_hash = in_len - *next_buflen;

	if (to_hash) {
		src_nents = __sg_count(req->src, req->nbytes - (*next_buflen),
				       &chained);
		qm_sg_src_index = 1 + (*buflen ? 1 : 0);
		qm_sg_bytes = (qm_sg_src_index + src_nents) *
				 sizeof(struct dpaa_sg_entry);

		/* allocate space for base edesc and link tables */
		edesc = qi_cache_zalloc(GFP_DMA | flags);
		if (!edesc) {
			dev_err(dev, "could not allocate extended descriptor\n");
			return -ENOMEM;
		}

		edesc->src_nents = src_nents;
		edesc->chained = chained;
		edesc->qm_sg_bytes = qm_sg_bytes;
		sg_table = &edesc->qm_sg[0];

		state->ctx_dma = dma_map_single(dev, state->caam_ctx,
						ctx->ctx_len,
						DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dev, state->ctx_dma)) {
			dev_err(dev, "unable to map ctx\n");
			return -ENOMEM;
		}
		dma_to_qm_sg_one(sg_table, state->ctx_dma, ctx->ctx_len, 0);

		state->buf_dma = try_buf_map_to_qm_sg(dev, sg_table + 1, buf,
						      state->buf_dma, *buflen,
						      last_buflen);

		if (src_nents) {
			src_map_to_qm_sg(dev, req->src, src_nents, sg_table +
					 qm_sg_src_index, chained);
			if (*next_buflen)
				scatterwalk_map_and_copy(next_buf, req->src,
							 to_hash - *buflen,
							 *next_buflen, 0);
		} else {
			dpaa2_sg_set_final(sg_table + qm_sg_src_index - 1,
					   true);
		}

		state->current_buf = !state->current_buf;

		edesc->qm_sg_dma = dma_map_single(dev, sg_table, qm_sg_bytes,
						  DMA_TO_DEVICE);
		if (dma_mapping_error(dev, edesc->qm_sg_dma)) {
			dev_err(dev, "unable to map S/G table\n");
			return -ENOMEM;
		}

		memset(&req_ctx->fd_flt, 0, sizeof(req_ctx->fd_flt));
		dpaa2_fl_set_final(in_fle, true);

		dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
		dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);
		dpaa2_fl_set_format(out_fle, dpaa_fl_single);
		dpaa2_fl_set_addr(out_fle, state->ctx_dma);

		dpaa2_fl_set_len(out_fle, ctx->ctx_len);
		dpaa2_fl_set_len(in_fle, ctx->ctx_len + to_hash);

		req_ctx->flc = &ctx->flc[UPDATE];
		req_ctx->flc_dma = ctx->flc_dma[UPDATE];
		req_ctx->cbk = ahash_done_bi;
		req_ctx->ctx = &req->base;
		req_ctx->edesc = edesc;

		ret = dpaa2_caam_enqueue(ctx->priv->dev, req_ctx);
		if (ret != -EINPROGRESS) {
			ahash_unmap_ctx(dev, edesc, req, ctx->ctx_len,
					DMA_BIDIRECTIONAL);
			qi_cache_free(edesc);
		}
	} else if (*next_buflen) {
		scatterwalk_map_and_copy(buf + *buflen, req->src, 0,
					 req->nbytes, 0);
		*buflen = *next_buflen;
		*next_buflen = last_buflen;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "buf@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, buf, *buflen, 1);
	print_hex_dump(KERN_ERR, "next buf@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, next_buf,
		       *next_buflen, 1);
#endif

	return ret;
}

static int ahash_final_ctx(struct ahash_request *req)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct caam_request *req_ctx = &state->caam_req;
	struct device *dev = ctx->priv->dev;
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	u8 *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int buflen = state->current_buf ? state->buflen_1 : state->buflen_0;
	int last_buflen = state->current_buf ? state->buflen_0 :
			  state->buflen_1;
	int qm_sg_bytes, qm_sg_src_index;
	int digestsize = crypto_ahash_digestsize(ahash);
	struct ahash_edesc *edesc;
	struct dpaa_sg_entry *sg_table;
	int ret = 0;

	qm_sg_src_index = 1 + (buflen ? 1 : 0);
	qm_sg_bytes = qm_sg_src_index * sizeof(struct dpaa_sg_entry);

	/* allocate space for base edesc and link tables */
	edesc = qi_cache_zalloc(GFP_DMA | flags);
	if (!edesc) {
		dev_err(dev, "could not allocate extended descriptor\n");
		return -ENOMEM;
	}

	edesc->qm_sg_bytes = qm_sg_bytes;
	sg_table = &edesc->qm_sg[0];

	state->ctx_dma = dma_map_single(dev, state->caam_ctx, ctx->ctx_len,
					DMA_TO_DEVICE);
	if (dma_mapping_error(dev, state->ctx_dma)) {
		dev_err(dev, "unable to map ctx\n");
		return -ENOMEM;
	}
	dma_to_qm_sg_one(sg_table, state->ctx_dma, ctx->ctx_len, 0);

	state->buf_dma = try_buf_map_to_qm_sg(dev, sg_table + 1, buf,
					      state->buf_dma, buflen,
					      last_buflen);
	dpaa2_sg_set_final(sg_table + qm_sg_src_index - 1, true);

	edesc->qm_sg_dma = dma_map_single(dev, sg_table, qm_sg_bytes,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->qm_sg_dma)) {
		dev_err(dev, "unable to map S/G table\n");
		return -ENOMEM;
	}

	edesc->dst_dma = dma_map_single(dev, req->result, digestsize,
					DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->dst_dma)) {
		dev_err(dev, "unable to map dst\n");
		return -ENOMEM;
	}

	memset(&req_ctx->fd_flt, 0, sizeof(req_ctx->fd_flt));
	dpaa2_fl_set_final(in_fle, true);
	dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
	dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);
	dpaa2_fl_set_len(in_fle, ctx->ctx_len + buflen);
	dpaa2_fl_set_format(out_fle, dpaa_fl_single);
	dpaa2_fl_set_addr(out_fle, edesc->dst_dma);
	dpaa2_fl_set_len(out_fle, digestsize);

	req_ctx->flc = &ctx->flc[FINALIZE];
	req_ctx->flc_dma = ctx->flc_dma[FINALIZE];
	req_ctx->cbk = ahash_done_ctx_src;
	req_ctx->ctx = &req->base;
	req_ctx->edesc = edesc;

	ret = dpaa2_caam_enqueue(ctx->priv->dev, req_ctx);
	if (ret != -EINPROGRESS) {
		ahash_unmap_ctx(dev, edesc, req, digestsize, DMA_FROM_DEVICE);
		qi_cache_free(edesc);
	}

	return ret;
}

static int ahash_finup_ctx(struct ahash_request *req)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct caam_request *req_ctx = &state->caam_req;
	struct device *dev = ctx->priv->dev;
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	u8 *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int buflen = state->current_buf ? state->buflen_1 : state->buflen_0;
	int last_buflen = state->current_buf ? state->buflen_0 :
			  state->buflen_1;
	int qm_sg_bytes, qm_sg_src_index;
	int src_nents;
	int digestsize = crypto_ahash_digestsize(ahash);
	struct ahash_edesc *edesc;
	struct dpaa_sg_entry *sg_table;
	bool chained = false;
	int ret = 0;

	src_nents = __sg_count(req->src, req->nbytes, &chained);
	qm_sg_src_index = 1 + (buflen ? 1 : 0);
	qm_sg_bytes = (qm_sg_src_index + src_nents) *
		      sizeof(struct dpaa_sg_entry);

	/* allocate space for base edesc and link tables */
	edesc = qi_cache_zalloc(GFP_DMA | flags);
	if (!edesc) {
		dev_err(dev, "could not allocate extended descriptor\n");
		return -ENOMEM;
	}

	edesc->src_nents = src_nents;
	edesc->chained = chained;
	edesc->qm_sg_bytes = qm_sg_bytes;
	sg_table = &edesc->qm_sg[0];

	state->ctx_dma = dma_map_single(dev, state->caam_ctx, ctx->ctx_len,
					DMA_TO_DEVICE);
	if (dma_mapping_error(dev, state->ctx_dma)) {
		dev_err(dev, "unable to map ctx\n");
		return -ENOMEM;
	}

	dma_to_qm_sg_one(sg_table, state->ctx_dma, ctx->ctx_len, 0);

	state->buf_dma = try_buf_map_to_qm_sg(dev, sg_table + 1, buf,
					      state->buf_dma, buflen,
					      last_buflen);

	src_map_to_qm_sg(dev, req->src, src_nents, sg_table + qm_sg_src_index,
			 chained);

	edesc->qm_sg_dma = dma_map_single(dev, sg_table, qm_sg_bytes,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->qm_sg_dma)) {
		dev_err(dev, "unable to map S/G table\n");
		return -ENOMEM;
	}

	edesc->dst_dma = dma_map_single(dev, req->result, digestsize,
					DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->dst_dma)) {
		dev_err(dev, "unable to map dst\n");
		return -ENOMEM;
	}

	memset(&req_ctx->fd_flt, 0, sizeof(req_ctx->fd_flt));
	dpaa2_fl_set_final(in_fle, true);
	dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
	dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);
	dpaa2_fl_set_format(out_fle, dpaa_fl_single);
	dpaa2_fl_set_addr(out_fle, edesc->dst_dma);

	dpaa2_fl_set_len(out_fle, digestsize);
	dpaa2_fl_set_len(in_fle, ctx->ctx_len + buflen + req->nbytes);

	req_ctx->flc = &ctx->flc[FINALIZE_UPDATE];
	req_ctx->flc_dma = ctx->flc_dma[FINALIZE_UPDATE];
	req_ctx->cbk = ahash_done_ctx_src;
	req_ctx->ctx = &req->base;
	req_ctx->edesc = edesc;

	ret = dpaa2_caam_enqueue(ctx->priv->dev, req_ctx);
	if (ret != -EINPROGRESS) {
		ahash_unmap_ctx(dev, edesc, req, digestsize, DMA_FROM_DEVICE);
		qi_cache_free(edesc);
	}

	return ret;
}

static int ahash_digest(struct ahash_request *req)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct caam_request *req_ctx = &state->caam_req;
	struct device *dev = ctx->priv->dev;
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	int digestsize = crypto_ahash_digestsize(ahash);
	int src_nents, qm_sg_bytes;
	struct ahash_edesc *edesc;
	struct dpaa_sg_entry *sg_table;
	bool chained = false;
	int ret = 0;

	src_nents = sg_count(req->src, req->nbytes, &chained);
	dma_map_sg_chained(dev, req->src, src_nents ? : 1, DMA_TO_DEVICE,
			   chained);
	qm_sg_bytes = src_nents * sizeof(struct dpaa_sg_entry);

	/* allocate space for base edesc and link tables */
	edesc = qi_cache_zalloc(GFP_DMA | flags);
	if (!edesc) {
		dev_err(dev, "could not allocate extended descriptor\n");
		return -ENOMEM;
	}

	edesc->qm_sg_bytes = qm_sg_bytes;
	edesc->src_nents = src_nents;
	edesc->chained = chained;
	sg_table = &edesc->qm_sg[0];

	memset(&req_ctx->fd_flt, 0, sizeof(req_ctx->fd_flt));

	if (src_nents) {
		sg_to_qm_sg_last(req->src, src_nents, sg_table, 0);
		edesc->qm_sg_dma = dma_map_single(dev, sg_table, qm_sg_bytes,
						  DMA_TO_DEVICE);
		if (dma_mapping_error(dev, edesc->qm_sg_dma)) {
			dev_err(dev, "unable to map S/G table\n");
			return -ENOMEM;
		}
		dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
		dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);
	} else {
		dpaa2_fl_set_format(in_fle, dpaa_fl_single);
		dpaa2_fl_set_addr(in_fle, sg_dma_address(req->src));
	}

	edesc->dst_dma = dma_map_single(dev, req->result, digestsize,
					DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->dst_dma)) {
		dev_err(dev, "unable to map dst\n");
		return -ENOMEM;
	}

	dpaa2_fl_set_final(in_fle, true);
	dpaa2_fl_set_format(out_fle, dpaa_fl_single);
	dpaa2_fl_set_addr(out_fle, edesc->dst_dma);

	dpaa2_fl_set_len(out_fle, digestsize);
	dpaa2_fl_set_len(in_fle, req->nbytes);

	req_ctx->flc = &ctx->flc[DIGEST];
	req_ctx->flc_dma = ctx->flc_dma[DIGEST];
	req_ctx->cbk = ahash_done;
	req_ctx->ctx = &req->base;
	req_ctx->edesc = edesc;
	ret = dpaa2_caam_enqueue(ctx->priv->dev, req_ctx);
	if (ret != -EINPROGRESS &&
	    !(ret == -EBUSY && req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG)) {
		ahash_unmap(ctx->priv->dev, edesc, req, digestsize);
		qi_cache_free(edesc);
	}

	return ret;
}

static int ahash_final_no_ctx(struct ahash_request *req)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct caam_request *req_ctx = &state->caam_req;
	struct device *dev = ctx->priv->dev;
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	u8 *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int buflen = state->current_buf ? state->buflen_1 : state->buflen_0;
	int digestsize = crypto_ahash_digestsize(ahash);
	struct ahash_edesc *edesc;
	int ret = 0;

	/* allocate space for base edesc and link tables */
	edesc = qi_cache_zalloc(GFP_DMA | flags);
	if (!edesc) {
		dev_err(dev, "could not allocate extended descriptor\n");
		return -ENOMEM;
	}

	state->buf_dma = dma_map_single(dev, buf, buflen, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, state->buf_dma)) {
		dev_err(dev, "unable to map src\n");
		return -ENOMEM;
	}

	edesc->dst_dma = dma_map_single(dev, req->result, digestsize,
					DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->dst_dma)) {
		dev_err(dev, "unable to map dst\n");
		return -ENOMEM;
	}

	memset(&req_ctx->fd_flt, 0, sizeof(req_ctx->fd_flt));
	dpaa2_fl_set_final(in_fle, true);
	dpaa2_fl_set_format(in_fle, dpaa_fl_single);
	dpaa2_fl_set_addr(in_fle, state->buf_dma);
	dpaa2_fl_set_len(in_fle, buflen);
	dpaa2_fl_set_format(out_fle, dpaa_fl_single);
	dpaa2_fl_set_addr(out_fle, edesc->dst_dma);
	dpaa2_fl_set_len(out_fle, digestsize);

	req_ctx->flc = &ctx->flc[DIGEST];
	req_ctx->flc_dma = ctx->flc_dma[DIGEST];
	req_ctx->cbk = ahash_done;
	req_ctx->ctx = &req->base;
	req_ctx->edesc = edesc;

	ret = dpaa2_caam_enqueue(ctx->priv->dev, req_ctx);
	if (ret != -EINPROGRESS) {
		ahash_unmap(dev, edesc, req, digestsize);
		qi_cache_free(edesc);
	}

	return ret;
}

static int ahash_update_no_ctx(struct ahash_request *req)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct caam_request *req_ctx = &state->caam_req;
	struct device *dev = ctx->priv->dev;
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	u8 *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int *buflen = state->current_buf ? &state->buflen_1 : &state->buflen_0;
	u8 *next_buf = state->current_buf ? state->buf_0 : state->buf_1;
	int *next_buflen = state->current_buf ? &state->buflen_0 :
			   &state->buflen_1;
	int in_len = *buflen + req->nbytes, to_hash;
	int qm_sg_bytes, src_nents;
	struct ahash_edesc *edesc;
	struct dpaa_sg_entry *sg_table;
	bool chained = false;
	int ret = 0;

	*next_buflen = in_len & (crypto_tfm_alg_blocksize(&ahash->base) - 1);
	to_hash = in_len - *next_buflen;

	if (to_hash) {
		src_nents = __sg_count(req->src, req->nbytes - (*next_buflen),
				       &chained);
		qm_sg_bytes = (1 + src_nents) * sizeof(struct dpaa_sg_entry);

		/* allocate space for base edesc and link tables */
		edesc = qi_cache_zalloc(GFP_DMA | flags);
		if (!edesc) {
			dev_err(dev, "could not allocate extended descriptor\n");
			return -ENOMEM;
		}

		edesc->src_nents = src_nents;
		edesc->chained = chained;
		edesc->qm_sg_bytes = qm_sg_bytes;
		sg_table = &edesc->qm_sg[0];

		state->buf_dma = buf_map_to_qm_sg(dev, sg_table, buf, *buflen);
		src_map_to_qm_sg(dev, req->src, src_nents, sg_table + 1,
				 chained);
		if (*next_buflen)
			scatterwalk_map_and_copy(next_buf, req->src,
						 to_hash - *buflen,
						 *next_buflen, 0);

		state->current_buf = !state->current_buf;

		edesc->qm_sg_dma = dma_map_single(dev, sg_table, qm_sg_bytes,
						  DMA_TO_DEVICE);
		if (dma_mapping_error(dev, edesc->qm_sg_dma)) {
			dev_err(dev, "unable to map S/G table\n");
			return -ENOMEM;
		}

		state->ctx_dma = dma_map_single(dev, state->caam_ctx,
						ctx->ctx_len, DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, state->ctx_dma)) {
				dev_err(dev, "unable to map ctx\n");
				return -ENOMEM;
		}

		memset(&req_ctx->fd_flt, 0, sizeof(req_ctx->fd_flt));
		dpaa2_fl_set_final(in_fle, true);
		dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
		dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);
		dpaa2_fl_set_format(out_fle, dpaa_fl_single);
		dpaa2_fl_set_addr(out_fle, state->ctx_dma);

		dpaa2_fl_set_len(out_fle, ctx->ctx_len);
		dpaa2_fl_set_len(in_fle, to_hash);

		req_ctx->flc = &ctx->flc[UPDATE_FIRST];
		req_ctx->flc_dma = ctx->flc_dma[UPDATE_FIRST];
		req_ctx->cbk = ahash_done_ctx_dst;
		req_ctx->ctx = &req->base;
		req_ctx->edesc = edesc;

		ret = dpaa2_caam_enqueue(ctx->priv->dev, req_ctx);
		if (ret == -EINPROGRESS) {
			state->update = ahash_update_ctx;
			state->finup = ahash_finup_ctx;
			state->final = ahash_final_ctx;
		} else {
			ahash_unmap_ctx(dev, edesc, req, ctx->ctx_len,
					DMA_TO_DEVICE);
			qi_cache_free(edesc);
		}
	} else if (*next_buflen) {
		scatterwalk_map_and_copy(buf + *buflen, req->src, 0,
					 req->nbytes, 0);
		*buflen = *next_buflen;
		*next_buflen = 0;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "buf@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, buf, *buflen, 1);
	print_hex_dump(KERN_ERR, "next buf@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, next_buf,
		       *next_buflen, 1);
#endif

	return ret;
}

static int ahash_finup_no_ctx(struct ahash_request *req)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct caam_request *req_ctx = &state->caam_req;
	struct device *dev = ctx->priv->dev;
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	u8 *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int buflen = state->current_buf ? state->buflen_1 : state->buflen_0;
	int last_buflen = state->current_buf ? state->buflen_0 :
			  state->buflen_1;
	int qm_sg_bytes, qm_sg_src_index, src_nents;
	int digestsize = crypto_ahash_digestsize(ahash);
	struct ahash_edesc *edesc;
	struct dpaa_sg_entry *sg_table;
	bool chained = false;
	int ret = 0;

	src_nents = __sg_count(req->src, req->nbytes, &chained);
	qm_sg_src_index = 2;
	qm_sg_bytes = (qm_sg_src_index + src_nents) *
			 sizeof(struct dpaa_sg_entry);

	/* allocate space for base edesc and link tables */
	edesc = qi_cache_zalloc(GFP_DMA | flags);
	if (!edesc) {
		dev_err(dev, "could not allocate extended descriptor\n");
		return -ENOMEM;
	}

	edesc->src_nents = src_nents;
	edesc->chained = chained;
	edesc->qm_sg_bytes = qm_sg_bytes;
	sg_table = &edesc->qm_sg[0];

	state->buf_dma = try_buf_map_to_qm_sg(dev, sg_table, buf,
					      state->buf_dma, buflen,
					      last_buflen);

	src_map_to_qm_sg(dev, req->src, src_nents, sg_table + 1, chained);

	edesc->qm_sg_dma = dma_map_single(dev, sg_table, qm_sg_bytes,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->qm_sg_dma)) {
		dev_err(dev, "unable to map S/G table\n");
		return -ENOMEM;
	}

	edesc->dst_dma = dma_map_single(dev, req->result, digestsize,
					DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->dst_dma)) {
			dev_err(dev, "unable to map dst\n");
			return -ENOMEM;
	}

	memset(&req_ctx->fd_flt, 0, sizeof(req_ctx->fd_flt));
	dpaa2_fl_set_final(in_fle, true);
	dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
	dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);
	dpaa2_fl_set_format(out_fle, dpaa_fl_single);
	dpaa2_fl_set_addr(out_fle, edesc->dst_dma);

	/* TODO: Is this really needed? */
	dma_sync_single_for_device(dev, edesc->qm_sg_dma, qm_sg_bytes,
				   DMA_TO_DEVICE);

	dpaa2_fl_set_len(out_fle, digestsize);
	dpaa2_fl_set_len(in_fle, buflen + req->nbytes);

	req_ctx->flc = &ctx->flc[DIGEST];
	req_ctx->flc_dma = ctx->flc_dma[DIGEST];
	req_ctx->cbk = ahash_done;
	req_ctx->ctx = &req->base;
	req_ctx->edesc = edesc;
	ret = dpaa2_caam_enqueue(ctx->priv->dev, req_ctx);
	if (ret != -EINPROGRESS &&
	    !(ret == -EBUSY && req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG)) {
		ahash_unmap(ctx->priv->dev, edesc, req, digestsize);
		qi_cache_free(edesc);
	}

	return ret;
}

static int ahash_update_first(struct ahash_request *req)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct caam_request *req_ctx = &state->caam_req;
	struct device *dev = ctx->priv->dev;
	struct dpaa_fl_entry *in_fle = &req_ctx->fd_flt[1];
	struct dpaa_fl_entry *out_fle = &req_ctx->fd_flt[0];
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	u8 *next_buf = state->current_buf ? state->buf_1 : state->buf_0;
	int *next_buflen = state->current_buf ?
		&state->buflen_1 : &state->buflen_0;
	int to_hash;
	int qm_sg_bytes, src_nents;
	struct ahash_edesc *edesc;
	struct dpaa_sg_entry *sg_table;
	bool chained = false;
	int ret = 0;

	*next_buflen = req->nbytes & (crypto_tfm_alg_blocksize(&ahash->base) -
				      1);
	to_hash = req->nbytes - *next_buflen;

	if (to_hash) {
		src_nents = sg_count(req->src, req->nbytes - (*next_buflen),
				     &chained);
		dma_map_sg_chained(dev, req->src, src_nents ? : 1,
				   DMA_TO_DEVICE, chained);
		qm_sg_bytes = src_nents * sizeof(struct dpaa_sg_entry);

		/* allocate space for base edesc and link tables */
		edesc = qi_cache_zalloc(GFP_DMA | flags);
		if (!edesc) {
			dev_err(dev, "could not allocate extended descriptor\n");
			return -ENOMEM;
		}

		edesc->src_nents = src_nents;
		edesc->chained = chained;
		edesc->qm_sg_bytes = qm_sg_bytes;
		sg_table = &edesc->qm_sg[0];

		memset(&req_ctx->fd_flt, 0, sizeof(req_ctx->fd_flt));
		dpaa2_fl_set_final(in_fle, true);

		if (src_nents) {
			sg_to_qm_sg_last(req->src, src_nents, sg_table, 0);
			edesc->qm_sg_dma = dma_map_single(dev, sg_table,
							  qm_sg_bytes,
							  DMA_TO_DEVICE);
			if (dma_mapping_error(dev, edesc->qm_sg_dma)) {
				dev_err(dev, "unable to map S/G table\n");
				return -ENOMEM;
			}
			dpaa2_fl_set_format(in_fle, dpaa_fl_sg);
			dpaa2_fl_set_addr(in_fle, edesc->qm_sg_dma);
		} else {
			dpaa2_fl_set_format(in_fle, dpaa_fl_single);
			dpaa2_fl_set_addr(in_fle, sg_dma_address(req->src));
		}

		if (*next_buflen)
			scatterwalk_map_and_copy(next_buf, req->src, to_hash,
						 *next_buflen, 0);

		state->ctx_dma = dma_map_single(dev, state->caam_ctx,
						ctx->ctx_len, DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, state->ctx_dma)) {
			dev_err(dev, "unable to map ctx\n");
			return -ENOMEM;
		}

		dpaa2_fl_set_format(out_fle, dpaa_fl_single);
		dpaa2_fl_set_addr(out_fle, state->ctx_dma);

		dpaa2_fl_set_len(out_fle, ctx->ctx_len);
		dpaa2_fl_set_len(in_fle, to_hash);

		req_ctx->flc = &ctx->flc[UPDATE_FIRST];
		req_ctx->flc_dma = ctx->flc_dma[UPDATE_FIRST];
		req_ctx->cbk = ahash_done_ctx_dst;
		req_ctx->ctx = &req->base;
		req_ctx->edesc = edesc;

		ret = dpaa2_caam_enqueue(ctx->priv->dev, req_ctx);
		if (ret == -EINPROGRESS) {
			state->update = ahash_update_ctx;
			state->finup = ahash_finup_ctx;
			state->final = ahash_final_ctx;
		} else {
			ahash_unmap_ctx(dev, edesc, req, ctx->ctx_len,
					DMA_TO_DEVICE);
			qi_cache_free(edesc);
		}
	} else if (*next_buflen) {
		state->update = ahash_update_no_ctx;
		state->finup = ahash_finup_no_ctx;
		state->final = ahash_final_no_ctx;
		scatterwalk_map_and_copy(next_buf, req->src, 0,
					 req->nbytes, 0);
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "next buf@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, next_buf,
		       *next_buflen, 1);
#endif

	return ret;
}

static int ahash_finup_first(struct ahash_request *req)
{
	return ahash_digest(req);
}

static int ahash_init(struct ahash_request *req)
{
	struct caam_hash_state *state = ahash_request_ctx(req);

	state->update = ahash_update_first;
	state->finup = ahash_finup_first;
	state->final = ahash_final_no_ctx;

	state->current_buf = 0;
	state->buf_dma = 0;
	state->buflen_0 = 0;
	state->buflen_1 = 0;

	return 0;
}

static int ahash_update(struct ahash_request *req)
{
	struct caam_hash_state *state = ahash_request_ctx(req);

	return state->update(req);
}

static int ahash_finup(struct ahash_request *req)
{
	struct caam_hash_state *state = ahash_request_ctx(req);

	return state->finup(req);
}

static int ahash_final(struct ahash_request *req)
{
	struct caam_hash_state *state = ahash_request_ctx(req);

	return state->final(req);
}

static int ahash_export(struct ahash_request *req, void *out)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_state *state = ahash_request_ctx(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);

	memcpy(out, ctx, sizeof(struct caam_hash_ctx));
	memcpy(out + sizeof(struct caam_hash_ctx), state,
	       sizeof(struct caam_hash_state));
	return 0;
}

static int ahash_import(struct ahash_request *req, const void *in)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct caam_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct caam_hash_state *state = ahash_request_ctx(req);

	memcpy(ctx, in, sizeof(struct caam_hash_ctx));
	memcpy(state, in + sizeof(struct caam_hash_ctx),
	       sizeof(struct caam_hash_state));
	return 0;
}

/* ahash descriptors */
static struct caam_hash_template driver_hash[] = {
	{
		.name = "sha1",
		.driver_name = "sha1-dpaa2-caam",
		.hmac_name = "hmac(sha1)",
		.hmac_driver_name = "hmac-sha1-dpaa2-caam",
		.blocksize = SHA1_BLOCK_SIZE,
		.template_ahash = {
			.init = ahash_init,
			.update = ahash_update,
			.final = ahash_final,
			.finup = ahash_finup,
			.digest = ahash_digest,
			.export = ahash_export,
			.import = ahash_import,
			.setkey = ahash_setkey,
			.halg = {
				.digestsize = SHA1_DIGEST_SIZE,
				},
			},
		.alg_type = OP_ALG_ALGSEL_SHA1,
		.alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	}, {
		.name = "sha224",
		.driver_name = "sha224-dpaa2-caam",
		.hmac_name = "hmac(sha224)",
		.hmac_driver_name = "hmac-sha224-dpaa2-caam",
		.blocksize = SHA224_BLOCK_SIZE,
		.template_ahash = {
			.init = ahash_init,
			.update = ahash_update,
			.final = ahash_final,
			.finup = ahash_finup,
			.digest = ahash_digest,
			.export = ahash_export,
			.import = ahash_import,
			.setkey = ahash_setkey,
			.halg = {
				.digestsize = SHA224_DIGEST_SIZE,
				},
			},
		.alg_type = OP_ALG_ALGSEL_SHA224,
		.alg_op = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC,
	}, {
		.name = "sha256",
		.driver_name = "sha256-dpaa2-caam",
		.hmac_name = "hmac(sha256)",
		.hmac_driver_name = "hmac-sha256-dpaa2-caam",
		.blocksize = SHA256_BLOCK_SIZE,
		.template_ahash = {
			.init = ahash_init,
			.update = ahash_update,
			.final = ahash_final,
			.finup = ahash_finup,
			.digest = ahash_digest,
			.export = ahash_export,
			.import = ahash_import,
			.setkey = ahash_setkey,
			.halg = {
				.digestsize = SHA256_DIGEST_SIZE,
				},
			},
		.alg_type = OP_ALG_ALGSEL_SHA256,
		.alg_op = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC,
	}, {
		.name = "sha384",
		.driver_name = "sha384-dpaa2-caam",
		.hmac_name = "hmac(sha384)",
		.hmac_driver_name = "hmac-sha384-dpaa2-caam",
		.blocksize = SHA384_BLOCK_SIZE,
		.template_ahash = {
			.init = ahash_init,
			.update = ahash_update,
			.final = ahash_final,
			.finup = ahash_finup,
			.digest = ahash_digest,
			.export = ahash_export,
			.import = ahash_import,
			.setkey = ahash_setkey,
			.halg = {
				.digestsize = SHA384_DIGEST_SIZE,
				},
			},
		.alg_type = OP_ALG_ALGSEL_SHA384,
		.alg_op = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC,
	}, {
		.name = "sha512",
		.driver_name = "sha512-dpaa2-caam",
		.hmac_name = "hmac(sha512)",
		.hmac_driver_name = "hmac-sha512-dpaa2-caam",
		.blocksize = SHA512_BLOCK_SIZE,
		.template_ahash = {
			.init = ahash_init,
			.update = ahash_update,
			.final = ahash_final,
			.finup = ahash_finup,
			.digest = ahash_digest,
			.export = ahash_export,
			.import = ahash_import,
			.setkey = ahash_setkey,
			.halg = {
				.digestsize = SHA512_DIGEST_SIZE,
				},
			},
		.alg_type = OP_ALG_ALGSEL_SHA512,
		.alg_op = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC,
	}, {
		.name = "md5",
		.driver_name = "md5-dpaa2-caam",
		.hmac_name = "hmac(md5)",
		.hmac_driver_name = "hmac-md5-dpaa2-caam",
		.blocksize = MD5_BLOCK_WORDS * 4,
		.template_ahash = {
			.init = ahash_init,
			.update = ahash_update,
			.final = ahash_final,
			.finup = ahash_finup,
			.digest = ahash_digest,
			.export = ahash_export,
			.import = ahash_import,
			.setkey = ahash_setkey,
			.halg = {
				.digestsize = MD5_DIGEST_SIZE,
				},
			},
		.alg_type = OP_ALG_ALGSEL_MD5,
		.alg_op = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC,
	}
};

struct caam_hash_alg {
	struct list_head entry;
	struct dpaa2_caam_priv *priv;
	int alg_type;
	int alg_op;
	struct ahash_alg ahash_alg;
};

static int caam_hash_cra_init(struct crypto_tfm *tfm)
{
	struct crypto_ahash *ahash = __crypto_ahash_cast(tfm);
	struct crypto_alg *base = tfm->__crt_alg;
	struct hash_alg_common *halg =
		 container_of(base, struct hash_alg_common, base);
	struct ahash_alg *alg =
		 container_of(halg, struct ahash_alg, halg);
	struct caam_hash_alg *caam_hash =
		 container_of(alg, struct caam_hash_alg, ahash_alg);
	struct caam_hash_ctx *ctx = crypto_tfm_ctx(tfm);
	/* Sizes for MDHA running digests: MD5, SHA1, 224, 256, 384, 512 */
	static const u8 runninglen[] = { HASH_MSG_LEN + MD5_DIGEST_SIZE,
					 HASH_MSG_LEN + SHA1_DIGEST_SIZE,
					 HASH_MSG_LEN + 32,
					 HASH_MSG_LEN + SHA256_DIGEST_SIZE,
					 HASH_MSG_LEN + 64,
					 HASH_MSG_LEN + SHA512_DIGEST_SIZE };

	/* copy descriptor header template value */
	ctx->alg_type = OP_TYPE_CLASS2_ALG | caam_hash->alg_type;
	ctx->alg_op = OP_TYPE_CLASS2_ALG | caam_hash->alg_op;

	ctx->ctx_len = runninglen[(ctx->alg_op & OP_ALG_ALGSEL_SUBMASK) >>
				  OP_ALG_ALGSEL_SHIFT];

	ctx->priv = caam_hash->priv;

	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct caam_hash_state));

	return ahash_set_sh_desc(ahash);
}

static void caam_hash_cra_exit(struct crypto_tfm *tfm)
{
	struct caam_hash_ctx *ctx = crypto_tfm_ctx(tfm);
	int i;

	for (i = 0; i < HASH_NUM_OP; i++) {
		if (!ctx->flc_dma[i])
			continue;
		dma_unmap_single(ctx->priv->dev, ctx->flc_dma[i],
				 sizeof(ctx->flc[i].flc) +
				 desc_bytes(ctx->flc[i].sh_desc),
				 DMA_TO_DEVICE);
	}
}

static struct caam_hash_alg *caam_hash_alloc(struct dpaa2_caam_priv *priv,
	struct caam_hash_template *template, bool keyed)
{
	struct caam_hash_alg *t_alg;
	struct ahash_alg *halg;
	struct crypto_alg *alg;

	t_alg = kzalloc(sizeof(*t_alg), GFP_KERNEL);
	if (!t_alg)
		return ERR_PTR(-ENOMEM);

	t_alg->ahash_alg = template->template_ahash;
	halg = &t_alg->ahash_alg;
	alg = &halg->halg.base;

	if (keyed) {
		snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->hmac_name);
		snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->hmac_driver_name);
	} else {
		snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->name);
		snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->driver_name);
	}
	alg->cra_module = THIS_MODULE;
	alg->cra_init = caam_hash_cra_init;
	alg->cra_exit = caam_hash_cra_exit;
	alg->cra_ctxsize = sizeof(struct caam_hash_ctx);
	alg->cra_priority = CAAM_CRA_PRIORITY;
	alg->cra_blocksize = template->blocksize;
	alg->cra_alignmask = 0;
	alg->cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_TYPE_AHASH;
	alg->cra_type = &crypto_ahash_type;

	t_alg->alg_type = template->alg_type;
	t_alg->alg_op = template->alg_op;
	t_alg->priv = priv;

	return t_alg;
}

static void dpaa2_caam_fqdan_cb(struct dpaa2_io_notification_ctx *nctx)
{
	struct dpaa2_caam_priv_per_cpu *ppriv;

	ppriv = container_of(nctx, struct dpaa2_caam_priv_per_cpu, nctx);
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

		ppriv->store = dpaa2_io_store_create(DPAA2_CAAM_STORE_SIZE,
						     dev);
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

static int dpaa2_caam_pull_fq(struct dpaa2_caam_priv_per_cpu *ppriv)
{
	int err;

	/* Retry while portal is busy */
	do {
		err = dpaa2_io_service_pull_fq(NULL, ppriv->rsp_fqid,
					       ppriv->store);
	} while (err == -EBUSY);

	if (unlikely(err))
		dev_err(ppriv->priv->dev, "dpaa2_io_service_pull err %d", err);

	return err;
}

static int dpaa2_caam_store_consume(struct dpaa2_caam_priv_per_cpu *ppriv)
{
	struct dpaa2_dq *dq;
	int cleaned = 0, is_last;

	do {
		dq = dpaa2_io_store_next(ppriv->store, &is_last);
		if (unlikely(!dq)) {
			if (unlikely(!is_last)) {
				dev_dbg(ppriv->priv->dev,
					"FQ %d returned no valid frames\n",
					ppriv->rsp_fqid);
				/*
				 * MUST retry until we get some sort of
				 * valid response token (be it "empty dequeue"
				 * or a valid frame).
				 */
				continue;
			}
			break;
		}

		/* Process FD */
		dpaa2_caam_process_fd(ppriv->priv, dpaa2_dq_fd(dq));
		cleaned++;
	} while (!is_last);

	return cleaned;
}

static int dpaa2_dpseci_poll(struct napi_struct *napi, int budget)
{
	struct dpaa2_caam_priv_per_cpu *ppriv;
	struct dpaa2_caam_priv *priv;
	int err, cleaned = 0, store_cleaned;

	ppriv = container_of(napi, struct dpaa2_caam_priv_per_cpu, napi);
	priv = ppriv->priv;

	if (unlikely(dpaa2_caam_pull_fq(ppriv)))
		return 0;

	do {
		store_cleaned = dpaa2_caam_store_consume(ppriv);
		cleaned += store_cleaned;

		if (store_cleaned == 0 ||
		    cleaned > budget - DPAA2_CAAM_STORE_SIZE)
			break;

		/* Try to dequeue some more */
		err = dpaa2_caam_pull_fq(ppriv);
		if (unlikely(err))
			break;
	} while (1);

	if (cleaned < budget)
		napi_complete_done(napi, cleaned);
		err = dpaa2_io_service_rearm(NULL, &ppriv->nctx);
		if (unlikely(err))
			dev_err(priv->dev, "Notification rearm failed\n");

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
static struct list_head hash_list;

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

	/* register hash algorithms the device supports */
	INIT_LIST_HEAD(&hash_list);
	for (i = 0; i < ARRAY_SIZE(driver_hash); i++) {
		struct caam_hash_alg *t_hash_alg;

		/* register hmac version */
		t_hash_alg = caam_hash_alloc(priv, &driver_hash[i], true);
		if (IS_ERR(t_hash_alg)) {
			err = PTR_ERR(t_hash_alg);
			dev_warn(dev, "%s hash alg allocation failed\n",
				 driver_hash[i].driver_name);
			continue;
		}

		err = crypto_register_ahash(&t_hash_alg->ahash_alg);
		if (err) {
			dev_warn(dev, "%s alg registration failed\n",
				 t_hash_alg->ahash_alg.halg.base.cra_driver_name);
			kfree(t_hash_alg);
		} else {
			list_add_tail(&t_hash_alg->entry, &hash_list);
		}

		/* register unkeyed version */
		t_hash_alg = caam_hash_alloc(priv, &driver_hash[i], false);
		if (IS_ERR(t_hash_alg)) {
			err = PTR_ERR(t_hash_alg);
			dev_warn(dev, "%s alg allocation failed\n",
				 driver_hash[i].driver_name);
			continue;
		}

		err = crypto_register_ahash(&t_hash_alg->ahash_alg);
		if (err) {
			dev_warn(dev, "%s alg registration failed\n",
				 t_hash_alg->ahash_alg.halg.base.cra_driver_name);
			kfree(t_hash_alg);
		} else {
			list_add_tail(&t_hash_alg->entry, &hash_list);
		}
	}
	if (!list_empty(&hash_list))
		dev_info(dev, "hash algorithms registered in /proc/crypto\n");

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
	struct caam_hash_alg *t_hash_alg, *p;

	dev = &ls_dev->dev;
	priv = dev_get_drvdata(dev);

	if (alg_list.next)
		list_for_each_entry_safe(t_alg, n, &alg_list, entry) {
			crypto_unregister_alg(&t_alg->crypto_alg);
			list_del(&t_alg->entry);
			kfree(t_alg);
		}

	if (hash_list.next)
		list_for_each_entry_safe(t_hash_alg, p, &hash_list, entry) {
			crypto_unregister_ahash(&t_hash_alg->ahash_alg);
			list_del(&t_hash_alg->entry);
			kfree(t_hash_alg);
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
