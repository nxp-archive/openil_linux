/*
 * Freescale FSL CAAM support for crypto API over QI backend
 *
 * Copyright 2008-2011, 2013 Freescale Semiconductor, Inc.
 *
 */


#include "compat.h"

#include "regs.h"
#include "intern.h"
#include "desc_constr.h"
#include "error.h"
#include "sg_sw_sec4.h"
#include "sg_sw_qm.h"
#include "key_gen.h"
#include "qi.h"
#include "jr.h"
#include "ctrl.h"

/*
 * crypto alg
 */
#define CAAM_CRA_PRIORITY		4000
/* max key is sum of AES_MAX_KEY_SIZE, max split key size */
#define CAAM_MAX_KEY_SIZE		(AES_MAX_KEY_SIZE + \
					 SHA512_DIGEST_SIZE * 2)
/* max IV is max of AES_BLOCK_SIZE, DES3_EDE_BLOCK_SIZE */
#define CAAM_MAX_IV_LENGTH		16

/* length of descriptors text */
#define DESC_AEAD_BASE			(4 * CAAM_CMD_SZ)
#define DESC_AEAD_ENC_LEN		(DESC_AEAD_BASE + 16 * CAAM_CMD_SZ)
#define DESC_AEAD_DEC_LEN		(DESC_AEAD_BASE + 21 * CAAM_CMD_SZ)
#define DESC_AEAD_GIVENC_LEN		(DESC_AEAD_ENC_LEN + 7 * CAAM_CMD_SZ)

#define DESC_TLS_BASE			(4 * CAAM_CMD_SZ)
#define DESC_TLS10_ENC_LEN		(DESC_TLS_BASE + 29 * CAAM_CMD_SZ)

#define DESC_MAX_USED_BYTES		(DESC_AEAD_GIVENC_LEN + \
					 CAAM_MAX_KEY_SIZE)
#define DESC_MAX_USED_LEN		(DESC_MAX_USED_BYTES / CAAM_CMD_SZ)

/* Set DK bit in class 1 operation if shared */
static inline void append_dec_op1(u32 *desc, u32 type)
{
	u32 *jump_cmd, *uncond_jump_cmd;

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
static inline void aead_append_ld_iv(u32 *desc, int ivsize)
{
	append_cmd(desc, CMD_SEQ_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_1_CCB | ivsize);
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_CLASS2INFIFO | ivsize);
}

/*
 * If all data, including src (with assoc and iv) or dst (with iv only) are
 * contiguous
 */
#define GIV_SRC_CONTIG		1
#define GIV_DST_CONTIG		(1 << 1)

enum optype {
	ENCRYPT,
	DECRYPT,
	GIVENCRYPT,
	NUM_OP
};
/*
 * per-session context
 */
struct caam_ctx {
	struct device *jrdev;
	u32 sh_desc_enc[DESC_MAX_USED_LEN];
	u32 sh_desc_dec[DESC_MAX_USED_LEN];
	u32 sh_desc_givenc[DESC_MAX_USED_LEN];
	u32 class1_alg_type;
	u32 class2_alg_type;
	u32 alg_op;
	u8 key[CAAM_MAX_KEY_SIZE];
	dma_addr_t key_dma;
	unsigned int enckeylen;
	unsigned int split_key_len;
	unsigned int split_key_pad_len;
	unsigned int authsize;
	struct device *qidev;
	spinlock_t lock;	/* Protects multiple init of driver context */
	struct caam_drv_ctx *drv_ctx[NUM_OP];
};

static void append_key_aead(u32 *desc, struct caam_ctx *ctx,
			    int keys_fit_inline)
{
	if (keys_fit_inline) {
		append_key_as_imm(desc, ctx->key, ctx->split_key_pad_len,
				  ctx->split_key_len, CLASS_2 |
				  KEY_DEST_MDHA_SPLIT | KEY_ENC);
		append_key_as_imm(desc, (void *)ctx->key +
				  ctx->split_key_pad_len, ctx->enckeylen,
				  ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	} else {
		append_key(desc, ctx->key_dma, ctx->split_key_len, CLASS_2 |
			   KEY_DEST_MDHA_SPLIT | KEY_ENC);
		append_key(desc, ctx->key_dma + ctx->split_key_pad_len,
			   ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	}
}

static void init_sh_desc_key_aead(u32 *desc, struct caam_ctx *ctx,
				  int keys_fit_inline)
{
	u32 *key_jump_cmd;

	init_sh_desc(desc, HDR_SHARE_SERIAL);

	/* Skip if already shared */
	key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
				   JUMP_COND_SHRD);

	append_key_aead(desc, ctx, keys_fit_inline);

	set_jump_tgt_here(desc, key_jump_cmd);
}

static int aead_set_sh_desc(struct crypto_aead *aead)
{
	struct aead_tfm *tfm = &aead->base.crt_aead;
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	bool keys_fit_inline;
	u32 *key_jump_cmd;
	u32 geniv, moveiv;
	u32 *desc;

	if (!ctx->enckeylen || !ctx->authsize)
		return 0;

	/*
	 * Job Descriptor and Shared Descriptors
	 * must all fit into the 64-word Descriptor h/w Buffer
	 */
	keys_fit_inline = false;
	if (DESC_AEAD_ENC_LEN + DESC_JOB_IO_LEN +
	    ctx->split_key_pad_len + ctx->enckeylen <=
	    CAAM_DESC_BYTES_MAX)
		keys_fit_inline = true;

	/* aead_encrypt shared descriptor */
	desc = ctx->sh_desc_enc;

	init_sh_desc_key_aead(desc, ctx, keys_fit_inline);

	/* Class 2 operation */
	append_operation(desc, ctx->class2_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* cryptlen = seqoutlen - authsize */
	append_math_sub_imm_u32(desc, REG3, SEQOUTLEN, IMM, ctx->authsize);

	/* assoclen + cryptlen = seqinlen - ivsize */
	append_math_sub_imm_u32(desc, REG2, SEQINLEN, IMM, tfm->ivsize);

	/* assoclen + cryptlen = (assoclen + cryptlen) - cryptlen */
	append_math_sub(desc, VARSEQINLEN, REG2, REG3, CAAM_CMD_SZ);

	/* read assoc before reading payload */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG |
			     KEY_VLF);
	aead_append_ld_iv(desc, tfm->ivsize);

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

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "aead enc shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	/*
	 * Job Descriptor and Shared Descriptors
	 * must all fit into the 64-word Descriptor h/w Buffer
	 */
	keys_fit_inline = false;
	if (DESC_AEAD_DEC_LEN + DESC_JOB_IO_LEN +
	    ctx->split_key_pad_len + ctx->enckeylen <=
	    CAAM_DESC_BYTES_MAX)
		keys_fit_inline = true;

	desc = ctx->sh_desc_dec;

	/* aead_decrypt shared descriptor */
	init_sh_desc(desc, HDR_SHARE_SERIAL);

	/* Skip if already shared */
	key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
				   JUMP_COND_SHRD);

	append_key_aead(desc, ctx, keys_fit_inline);

	set_jump_tgt_here(desc, key_jump_cmd);

	/* Class 2 operation */
	append_operation(desc, ctx->class2_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT | OP_ALG_ICV_ON);

	/* assoclen + cryptlen = seqinlen - ivsize */
	append_math_sub_imm_u32(desc, REG3, SEQINLEN, IMM,
				ctx->authsize + tfm->ivsize);
	/* assoclen = (assoclen + cryptlen) - cryptlen */
	append_math_sub(desc, REG2, SEQOUTLEN, REG0, CAAM_CMD_SZ);
	append_math_sub(desc, VARSEQINLEN, REG3, REG2, CAAM_CMD_SZ);

	/* read assoc before reading payload */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG |
			     KEY_VLF);

	aead_append_ld_iv(desc, tfm->ivsize);

	append_dec_op1(desc, ctx->class1_alg_type);

	/* Read and write cryptlen bytes */
	append_math_add(desc, VARSEQINLEN, ZERO, REG2, CAAM_CMD_SZ);
	append_math_add(desc, VARSEQOUTLEN, ZERO, REG2, CAAM_CMD_SZ);
	aead_append_src_dst(desc, FIFOLD_TYPE_MSG);

	/* Load ICV */
	append_seq_fifo_load(desc, ctx->authsize, FIFOLD_CLASS_CLASS2 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_ICV);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "aead dec shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	/*
	 * Job Descriptor and Shared Descriptors
	 * must all fit into the 64-word Descriptor h/w Buffer
	 */
	keys_fit_inline = false;
	if (DESC_AEAD_GIVENC_LEN + DESC_JOB_IO_LEN +
	    ctx->split_key_pad_len + ctx->enckeylen <=
	    CAAM_DESC_BYTES_MAX)
		keys_fit_inline = true;

	/* aead_givencrypt shared descriptor */
	desc = ctx->sh_desc_givenc;

	init_sh_desc_key_aead(desc, ctx, keys_fit_inline);

	/* Generate IV */
	geniv = NFIFOENTRY_STYPE_PAD | NFIFOENTRY_DEST_DECO |
		NFIFOENTRY_DTYPE_MSG | NFIFOENTRY_LC1 |
		NFIFOENTRY_PTYPE_RND | (tfm->ivsize << NFIFOENTRY_DLEN_SHIFT);
	append_load_imm_u32(desc, geniv, LDST_CLASS_IND_CCB |
			    LDST_SRCDST_WORD_INFO_FIFO | LDST_IMM);
	append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);
	append_move(desc, MOVE_SRC_INFIFO |
		    MOVE_DEST_CLASS1CTX | (tfm->ivsize << MOVE_LEN_SHIFT));
	append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* Copy IV to class 1 context */
	append_move(desc, MOVE_SRC_CLASS1CTX |
		    MOVE_DEST_OUTFIFO | (tfm->ivsize << MOVE_LEN_SHIFT));

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

	/* Copy iv from class 1 ctx to class 2 fifo*/
	moveiv = NFIFOENTRY_STYPE_OFIFO | NFIFOENTRY_DEST_CLASS2 |
		 NFIFOENTRY_DTYPE_MSG | (tfm->ivsize << NFIFOENTRY_DLEN_SHIFT);
	append_load_imm_u32(desc, moveiv, LDST_CLASS_IND_CCB |
			    LDST_SRCDST_WORD_INFO_FIFO | LDST_IMM);
	append_load_imm_u32(desc, tfm->ivsize, LDST_CLASS_2_CCB |
			    LDST_SRCDST_WORD_DATASZ_REG | LDST_IMM);

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
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_BOTH | KEY_VLF |
			     FIFOLD_TYPE_MSG1OUT2 | FIFOLD_TYPE_LASTBOTH);
	append_seq_fifo_store(desc, 0, FIFOST_TYPE_MESSAGE_DATA | KEY_VLF);

	/* Write ICV */
	append_seq_store(desc, ctx->authsize, LDST_CLASS_2_CCB |
			 LDST_SRCDST_BYTE_CONTEXT);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "aead givenc shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	return 0;
}

static int aead_setauthsize(struct crypto_aead *authenc,
				    unsigned int authsize)
{
	struct caam_ctx *ctx = crypto_aead_ctx(authenc);

	ctx->authsize = authsize;
	aead_set_sh_desc(authenc);

	return 0;
}

static int tls_set_sh_desc(struct crypto_aead *aead)
{
	struct aead_tfm *tfm = &aead->base.crt_aead;
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	bool keys_fit_inline = false;
	u32 *key_jump_cmd, *zero_payload_jump_cmd, *skip_zero_jump_cmd;
	u32 genpad, idx_ld_datasz, idx_ld_pad, jumpback, stidx;
	u32 *desc;
	unsigned int blocksize = crypto_aead_blocksize(aead);
	/* Associated data length is always = 13 for TLS */
	unsigned int assoclen = 13;
	/*
	 * Pointer Size bool determines the size of address pointers.
	 * false - Pointers fit in one 32-bit word.
	 * true - Pointers fit in two 32-bit words.
	 */
	static const bool ps = (CAAM_PTR_SZ != CAAM_CMD_SZ);

	if (!ctx->enckeylen || !ctx->authsize)
		return 0;

	/*
	 * TLS 1.0 encrypt shared descriptor
	 * Job Descriptor and Shared Descriptor
	 * must fit into the 64-word Descriptor h/w Buffer
	 */

	/*
	 * Compute the index (in bytes) for the LOAD with destination of
	 * Class 1 Data Size Register and for the LOAD that generates padding
	 */
	if (DESC_TLS10_ENC_LEN + DESC_JOB_IO_LEN +
	    ctx->split_key_pad_len + ctx->enckeylen <=
	    CAAM_DESC_BYTES_MAX) {
		keys_fit_inline = true;

		idx_ld_datasz = DESC_TLS10_ENC_LEN + ctx->split_key_pad_len +
				ctx->enckeylen - 4 * CAAM_CMD_SZ;
		idx_ld_pad = DESC_TLS10_ENC_LEN + ctx->split_key_pad_len +
			     ctx->enckeylen - 2 * CAAM_CMD_SZ;
	} else {
		idx_ld_datasz = DESC_TLS10_ENC_LEN + 2 * CAAM_PTR_SZ -
				4 * CAAM_CMD_SZ;
		idx_ld_pad = DESC_TLS10_ENC_LEN + 2 * CAAM_PTR_SZ -
			     2 * CAAM_CMD_SZ;
	}

	desc = ctx->sh_desc_enc;

	stidx = 1 << HDR_START_IDX_SHIFT;
	init_sh_desc(desc, HDR_SHARE_SERIAL | stidx);

	/* skip key loading if they are loaded due to sharing */
	key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
				   JUMP_COND_SHRD);
	append_key_aead(desc, ctx, keys_fit_inline);
	set_jump_tgt_here(desc, key_jump_cmd);

	/* class 2 operation */
	append_operation(desc, ctx->class2_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);
	/* class 1 operation */
	append_operation(desc, ctx->class1_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* payloadlen = input data length - (assoclen + ivlen) */
	append_math_sub_imm_u32(desc, REG0, SEQINLEN, IMM, assoclen +
				tfm->ivsize);

	/* math1 = payloadlen + icvlen */
	append_math_add_imm_u32(desc, REG1, REG0, IMM, ctx->authsize);

	/* padlen = block_size - math1 % block_size */
	append_math_and_imm_u32(desc, REG3, REG1, IMM, blocksize - 1);
	append_math_sub_imm_u32(desc, REG2, IMM, REG3, blocksize);

	/* cryptlen = payloadlen + icvlen + padlen */
	append_math_add(desc, VARSEQOUTLEN, REG1, REG2, 4);

	/*
	 * update immediate data with the padding length value
	 * for the LOAD in the class 1 data size register.
	 */
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH2 |
			(idx_ld_datasz << MOVE_OFFSET_SHIFT) | 7);
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF |
			(idx_ld_datasz << MOVE_OFFSET_SHIFT) | 8);

	/* overwrite PL field for the padding iNFO FIFO entry  */
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH2 |
			(idx_ld_pad << MOVE_OFFSET_SHIFT) | 7);
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF |
			(idx_ld_pad << MOVE_OFFSET_SHIFT) | 8);

	/* store encrypted payload, icv and padding */
	append_seq_fifo_store(desc, 0, FIFOST_TYPE_MESSAGE_DATA | LDST_VLF);

	/* if payload length is zero, jump to zero-payload commands */
	append_math_add(desc, VARSEQINLEN, ZERO, REG0, 4);
	zero_payload_jump_cmd = append_jump(desc, JUMP_TEST_ALL |
					    JUMP_COND_MATH_Z);

	/* read assoc for authentication */
	append_seq_fifo_load(desc, assoclen, FIFOLD_CLASS_CLASS2 |
			     FIFOLD_TYPE_MSG);
	/* load iv in context1 */
	append_cmd(desc, CMD_SEQ_LOAD | LDST_SRCDST_WORD_CLASS_CTX |
		   LDST_CLASS_1_CCB | tfm->ivsize);
	/* insnoop payload */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_BOTH | FIFOLD_TYPE_MSG |
			     FIFOLD_TYPE_LAST2 | FIFOLDST_VLF);
	/* jump the zero-payload commands */
	append_jump(desc, JUMP_TEST_ALL | 3);

	/* zero-payload commands */
	set_jump_tgt_here(desc, zero_payload_jump_cmd);
	/* assoc data is the only data for authentication */
	append_seq_fifo_load(desc, assoclen, FIFOLD_CLASS_CLASS2 |
			     FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);
	/* load iv in context1 */
	append_cmd(desc, CMD_SEQ_LOAD | LDST_SRCDST_WORD_CLASS_CTX |
		   LDST_CLASS_1_CCB | tfm->ivsize);

	/* send icv to encryption */
	append_move(desc, MOVE_SRC_CLASS2CTX | MOVE_DEST_CLASS1INFIFO |
		    ctx->authsize);

	/* update class 1 data size register with padding length */
	append_load_imm_u32(desc, 0, LDST_CLASS_1_CCB |
			    LDST_SRCDST_WORD_DATASZ_REG | LDST_IMM);

	/* generate padding and send it to encryption */
	genpad = NFIFOENTRY_DEST_CLASS1 | NFIFOENTRY_LC1 | NFIFOENTRY_FC1 |
	      NFIFOENTRY_STYPE_PAD | NFIFOENTRY_DTYPE_MSG | NFIFOENTRY_PTYPE_N;
	append_load_imm_u32(desc, genpad, LDST_CLASS_IND_CCB |
			    LDST_SRCDST_WORD_INFO_FIFO | LDST_IMM);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "tls enc shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	/*
	 * TLS 1.0 decrypt shared descriptor
	 * Keys do not fit inline, regardless of algorithms used
	 */
	desc = ctx->sh_desc_dec;

	stidx = 1 << HDR_START_IDX_SHIFT;
	init_sh_desc(desc, HDR_SHARE_SERIAL | stidx);

	/* skip key loading if they are loaded due to sharing */
	key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
				   JUMP_COND_SHRD);
	append_key(desc, ctx->key_dma, ctx->split_key_len, CLASS_2 |
		   KEY_DEST_MDHA_SPLIT | KEY_ENC);
	append_key(desc, ctx->key_dma + ctx->split_key_pad_len,
		   ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	set_jump_tgt_here(desc, key_jump_cmd);

	/* class 2 operation */
	append_operation(desc, ctx->class2_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT | OP_ALG_ICV_ON);
	/* class 1 operation */
	append_operation(desc, ctx->class1_alg_type |
			 OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT);

	/* VSIL = input data length - 2 * block_size */
	append_math_sub_imm_u32(desc, VARSEQINLEN, SEQINLEN, IMM, 2 *
				blocksize);

	/*
	 * payloadlen + icvlen + padlen = input data length - (assoclen +
	 * ivsize)
	 */
	append_math_sub_imm_u32(desc, REG3, SEQINLEN, IMM, assoclen +
				tfm->ivsize);

	/* skip data to the last but one cipher block */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_SKIP | LDST_VLF);

	/* load iv for the last cipher block */
	append_cmd(desc, CMD_SEQ_LOAD | LDST_SRCDST_WORD_CLASS_CTX |
		   LDST_CLASS_1_CCB | tfm->ivsize);

	/* read last cipher block */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_MSG |
			FIFOLD_TYPE_LAST1 | blocksize);

	/* move decrypted block into math0 and math1 */
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_MATH0 |
		    blocksize);

	/* reset AES CHA */
	append_load_imm_u32(desc, CCTRL_RESET_CHA_AESA, LDST_CLASS_IND_CCB |
			    LDST_SRCDST_WORD_CHACTRL | LDST_IMM);

	/* rewind input sequence */
	append_seq_in_ptr_intlen(desc, 0, 65535, SQIN_RTO);

	/* key1 is in decryption form */
	append_operation(desc, ctx->class1_alg_type | OP_ALG_AAI_DK |
			 OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT);

	/* read sequence number */
	append_seq_fifo_load(desc, 8, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG);
	/* load Type, Version and Len fields in math0 */
	append_cmd(desc, CMD_SEQ_LOAD | LDST_CLASS_DECO |
		   LDST_SRCDST_WORD_DECO_MATH0 | (3 << LDST_OFFSET_SHIFT) | 5);

	/* load iv in context1 */
	append_cmd(desc, CMD_SEQ_LOAD | LDST_CLASS_1_CCB |
		   LDST_SRCDST_WORD_CLASS_CTX | tfm->ivsize);

	/* compute (padlen - 1) */
	append_math_and_imm_u64(desc, REG1, REG1, IMM, 255);

	/* math2 = icvlen + (padlen - 1) + 1 */
	append_math_add_imm_u32(desc, REG2, REG1, IMM, ctx->authsize + 1);

	append_jump(desc, JUMP_TEST_ALL | JUMP_COND_CALM | 1);

	/* VSOL = payloadlen + icvlen + padlen */
	append_math_add(desc, VARSEQOUTLEN, ZERO, REG3, 4);

#ifdef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
	append_moveb(desc, MOVE_WAITCOMP |
		     MOVE_SRC_MATH0 | MOVE_DEST_MATH0 | 8);
#endif
	/* update Len field */
	append_math_sub(desc, REG0, REG0, REG2, 8);

	/* store decrypted payload, icv and padding */
	append_seq_fifo_store(desc, 0, FIFOST_TYPE_MESSAGE_DATA | LDST_VLF);

	/* VSIL = (payloadlen + icvlen + padlen) - (icvlen + padlen)*/
	append_math_sub(desc, VARSEQINLEN, REG3, REG2, 4);

	zero_payload_jump_cmd = append_jump(desc, JUMP_TEST_ALL |
					    JUMP_COND_MATH_Z);

	/* send Type, Version and Len(pre ICV) fields to authentication */
	append_move(desc, MOVE_WAITCOMP |
		    MOVE_SRC_MATH0 | MOVE_DEST_CLASS2INFIFO |
		    (3 << MOVE_OFFSET_SHIFT) | 5);

	/* outsnooping payload */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_BOTH |
			     FIFOLD_TYPE_MSG1OUT2 | FIFOLD_TYPE_LAST2 |
			     FIFOLDST_VLF);
	skip_zero_jump_cmd = append_jump(desc, JUMP_TEST_ALL | 2);

	set_jump_tgt_here(desc, zero_payload_jump_cmd);
	/* send Type, Version and Len(pre ICV) fields to authentication */
	append_move(desc, MOVE_WAITCOMP | MOVE_AUX_LS |
		    MOVE_SRC_MATH0 | MOVE_DEST_CLASS2INFIFO |
		    (3 << MOVE_OFFSET_SHIFT) | 5);

	set_jump_tgt_here(desc, skip_zero_jump_cmd);
	append_math_add(desc, VARSEQINLEN, ZERO, REG2, 4);

	/* load icvlen and padlen */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_MSG |
			     FIFOLD_TYPE_LAST1 | FIFOLDST_VLF);

	/* VSIL = (payloadlen + icvlen + padlen) - icvlen + padlen */
	append_math_sub(desc, VARSEQINLEN, REG3, REG2, 4);

	/*
	 * Start a new input sequence using the SEQ OUT PTR command options,
	 * pointer and length used when the current output sequence was defined.
	 */
	if (ps) {
		/*
		 * Move the lower 32 bits of Shared Descriptor address, the
		 * SEQ OUT PTR command, Output Pointer (2 words) and
		 * Output Length into math registers.
		 */
#ifdef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF |
			    MOVE_DEST_MATH0 | (55 * 4 << MOVE_OFFSET_SHIFT) |
			    20);
#else
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF |
			    MOVE_DEST_MATH0 | (54 * 4 << MOVE_OFFSET_SHIFT) |
			    20);
#endif
		/* Transform SEQ OUT PTR command in SEQ IN PTR command */
		append_math_and_imm_u32(desc, REG0, REG0, IMM,
					~(CMD_SEQ_IN_PTR ^ CMD_SEQ_OUT_PTR));
		/* Append a JUMP command after the copied fields */
		jumpback = CMD_JUMP | (char)-9;
		append_load_imm_u32(desc, jumpback, LDST_CLASS_DECO | LDST_IMM |
				    LDST_SRCDST_WORD_DECO_MATH2 |
				    (4 << LDST_OFFSET_SHIFT));
		append_jump(desc, JUMP_TEST_ALL | JUMP_COND_CALM | 1);
		/* Move the updated fields back to the Job Descriptor */
#ifdef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_MATH0 |
			    MOVE_DEST_DESCBUF | (55 * 4 << MOVE_OFFSET_SHIFT) |
			    24);
#else
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_MATH0 |
			    MOVE_DEST_DESCBUF | (54 * 4 << MOVE_OFFSET_SHIFT) |
			    24);
#endif
		/*
		 * Read the new SEQ IN PTR command, Input Pointer, Input Length
		 * and then jump back to the next command from the
		 * Shared Descriptor.
		 */
		append_jump(desc, JUMP_TEST_ALL | JUMP_COND_CALM | 6);
	} else {
		/*
		 * Move the SEQ OUT PTR command, Output Pointer (1 word) and
		 * Output Length into math registers.
		 */
#ifdef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF |
			    MOVE_DEST_MATH0 | (54 * 4 << MOVE_OFFSET_SHIFT) |
			    12);
#else
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF |
			    MOVE_DEST_MATH0 | (53 * 4 << MOVE_OFFSET_SHIFT) |
			    12);
#endif
		/* Transform SEQ OUT PTR command in SEQ IN PTR command */
#ifdef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
		append_math_and_imm_u64(desc, REG0, REG0, IMM,
			~((u64)(CMD_SEQ_IN_PTR ^ CMD_SEQ_OUT_PTR)));
#else
		append_math_and_imm_u64(desc, REG0, REG0, IMM,
			~(((u64)(CMD_SEQ_IN_PTR ^ CMD_SEQ_OUT_PTR)) << 32));
#endif
		/* Append a JUMP command after the copied fields */
		jumpback = CMD_JUMP | (char)-7;
		append_load_imm_u32(desc, jumpback, LDST_CLASS_DECO | LDST_IMM |
				    LDST_SRCDST_WORD_DECO_MATH1 |
				    (4 << LDST_OFFSET_SHIFT));
		append_jump(desc, JUMP_TEST_ALL | JUMP_COND_CALM | 1);
		/* Move the updated fields back to the Job Descriptor */
#ifdef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_MATH0 |
			    MOVE_DEST_DESCBUF | (54 * 4 << MOVE_OFFSET_SHIFT) |
			    16);
#else
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_MATH0 |
			    MOVE_DEST_DESCBUF | (53 * 4 << MOVE_OFFSET_SHIFT) |
			    16);
#endif
		/*
		 * Read the new SEQ IN PTR command, Input Pointer, Input Length
		 * and then jump back to the next command from the
		 * Shared Descriptor.
		 */
		 append_jump(desc, JUMP_TEST_ALL | JUMP_COND_CALM | 5);
	}

	/* skip payload */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_SKIP | FIFOLDST_VLF);
	/* check icv */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_ICV |
			     FIFOLD_TYPE_LAST2 | ctx->authsize);

#ifdef DEBUG
	print_hex_dump(KERN_ERR, "tls dec shdesc@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, desc,
		       desc_bytes(desc), 1);
#endif

	return 0;
}

static int tls_setauthsize(struct crypto_aead *tls, unsigned int authsize)
{
	struct caam_ctx *ctx = crypto_aead_ctx(tls);

	ctx->authsize = authsize;

	return 0;
}

static u32 gen_split_aead_key(struct caam_ctx *ctx, const u8 *key_in,
			      u32 authkeylen)
{
	return gen_split_key(ctx->jrdev, ctx->key, ctx->split_key_len,
			       ctx->split_key_pad_len, key_in, authkeylen,
			       ctx->alg_op);
}

static int aead_setkey(struct crypto_aead *aead,
			       const u8 *key, unsigned int keylen)
{
	/* Sizes for MDHA pads (*not* keys): MD5, SHA1, 224, 256, 384, 512 */
	static const u8 mdpadlen[] = { 16, 20, 32, 32, 64, 64 };
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct device *jrdev = ctx->jrdev;
	struct rtattr *rta = (void *)key;
	struct crypto_authenc_key_param *param;
	unsigned int authkeylen;
	unsigned int enckeylen;
	int ret = 0;

	param = RTA_DATA(rta);
	enckeylen = be32_to_cpu(param->enckeylen);

	key += RTA_ALIGN(rta->rta_len);
	keylen -= RTA_ALIGN(rta->rta_len);

	if (keylen < enckeylen)
		goto badkey;

	authkeylen = keylen - enckeylen;

	if (keylen > CAAM_MAX_KEY_SIZE)
		goto badkey;

	/* Pick class 2 key length from algorithm submask */
	ctx->split_key_len = mdpadlen[(ctx->alg_op & OP_ALG_ALGSEL_SUBMASK) >>
				      OP_ALG_ALGSEL_SHIFT] * 2;
	ctx->split_key_pad_len = ALIGN(ctx->split_key_len, 16);

#ifdef DEBUG
	printk(KERN_ERR "keylen %d enckeylen %d authkeylen %d\n",
	       keylen, enckeylen, authkeylen);
	printk(KERN_ERR "split_key_len %d split_key_pad_len %d\n",
	       ctx->split_key_len, ctx->split_key_pad_len);
	print_hex_dump(KERN_ERR, "key in @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, key, keylen, 1);
#endif

	ret = gen_split_aead_key(ctx, key, authkeylen);
	if (ret)
		goto badkey;

	/* postpend encryption key to auth split key */
	memcpy(ctx->key + ctx->split_key_pad_len, key + authkeylen, enckeylen);

	ctx->key_dma = dma_map_single(jrdev, ctx->key, ctx->split_key_pad_len +
				       enckeylen, DMA_TO_DEVICE);
	if (dma_mapping_error(jrdev, ctx->key_dma)) {
		dev_err(jrdev, "unable to map key i/o memory\n");
		return -ENOMEM;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ctx.key@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, ctx->key,
		       ctx->split_key_pad_len + enckeylen, 1);
#endif

	ctx->enckeylen = enckeylen;

	ret = aead_set_sh_desc(aead);
	if (ret) {
		dma_unmap_single(jrdev, ctx->key_dma, ctx->split_key_pad_len +
				 enckeylen, DMA_TO_DEVICE);
		goto badkey;
	}

	/* Now update the driver contexts with the new shared descriptor */
	if (ctx->drv_ctx[ENCRYPT]) {
		ret = caam_drv_ctx_update(ctx->drv_ctx[ENCRYPT],
					  ctx->sh_desc_enc);
		if (ret) {
			dev_err(jrdev, "driver enc context update failed\n");
			goto badkey;
		}
	}

	if (ctx->drv_ctx[DECRYPT]) {
		ret = caam_drv_ctx_update(ctx->drv_ctx[DECRYPT],
					  ctx->sh_desc_dec);
		if (ret) {
			dev_err(jrdev, "driver dec context update failed\n");
			goto badkey;
		}
	}

	if (ctx->drv_ctx[GIVENCRYPT]) {
		ret = caam_drv_ctx_update(ctx->drv_ctx[GIVENCRYPT],
					  ctx->sh_desc_givenc);
		if (ret) {
			dev_err(jrdev, "driver givenc context update failed\n");
			goto badkey;
		}
	}

	return ret;
badkey:
	crypto_aead_set_flags(aead, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}


static int tls_setkey(struct crypto_aead *aead, const u8 *key,
					  unsigned int keylen)
{
	/* Sizes for MDHA pads (*not* keys): MD5, SHA1, 224, 256, 384, 512 */
	static const u8 mdpadlen[] = { 16, 20, 32, 32, 64, 64 };
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct device *jrdev = ctx->jrdev;
	struct rtattr *rta = (void *)key;
	struct crypto_authenc_key_param *param;
	unsigned int authkeylen;
	unsigned int enckeylen;
	int ret = 0;

	param = RTA_DATA(rta);
	enckeylen = be32_to_cpu(param->enckeylen);

	key += RTA_ALIGN(rta->rta_len);
	keylen -= RTA_ALIGN(rta->rta_len);

	if (keylen < enckeylen)
		goto badkey;

	authkeylen = keylen - enckeylen;

	if (keylen > CAAM_MAX_KEY_SIZE)
		goto badkey;

	/* Pick class 2 key length from algorithm submask */
	ctx->split_key_len = mdpadlen[(ctx->alg_op & OP_ALG_ALGSEL_SUBMASK) >>
				      OP_ALG_ALGSEL_SHIFT] * 2;
	ctx->split_key_pad_len = ALIGN(ctx->split_key_len, 16);

#ifdef DEBUG
	dev_err(jrdev, "keylen %d enckeylen %d authkeylen %d\n", keylen,
		enckeylen, authkeylen);
	dev_err(jrdev, "split_key_len %d split_key_pad_len %d\n",
		ctx->split_key_len, ctx->split_key_pad_len);
	print_hex_dump(KERN_ERR, "key in @"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, key, keylen, 1);
#endif

	ret = gen_split_aead_key(ctx, key, authkeylen);
	if (ret)
		goto badkey;

	/* postpend encryption key to auth split key */
	memcpy(ctx->key + ctx->split_key_pad_len, key + authkeylen, enckeylen);

	ctx->key_dma = dma_map_single(jrdev, ctx->key, ctx->split_key_pad_len +
				       enckeylen, DMA_TO_DEVICE);
	if (dma_mapping_error(jrdev, ctx->key_dma)) {
		dev_err(jrdev, "unable to map key i/o memory\n");
		return -ENOMEM;
	}
#ifdef DEBUG
	print_hex_dump(KERN_ERR, "ctx.key@"__stringify(__LINE__)": ",
		       DUMP_PREFIX_ADDRESS, 16, 4, ctx->key,
		       ctx->split_key_pad_len + enckeylen, 1);
#endif

	ctx->enckeylen = enckeylen;

	ret = tls_set_sh_desc(aead);
	if (ret) {
		dma_unmap_single(jrdev, ctx->key_dma, ctx->split_key_pad_len +
				 enckeylen, DMA_TO_DEVICE);
	}

	/* Now update the driver contexts with the new shared descriptor */
	if (ctx->drv_ctx[ENCRYPT]) {
		ret = caam_drv_ctx_update(ctx->drv_ctx[ENCRYPT],
					  ctx->sh_desc_enc);
		if (ret) {
			dev_err(jrdev, "driver enc context update failed\n");
			goto badkey;
		}
	}

	if (ctx->drv_ctx[DECRYPT]) {
		ret = caam_drv_ctx_update(ctx->drv_ctx[DECRYPT],
					  ctx->sh_desc_dec);
		if (ret) {
			dev_err(jrdev, "driver dec context update failed\n");
			goto badkey;
		}
	}

	if (ctx->drv_ctx[GIVENCRYPT]) {
		ret = caam_drv_ctx_update(ctx->drv_ctx[GIVENCRYPT],
					  ctx->sh_desc_givenc);
		if (ret) {
			dev_err(jrdev, "driver givenc context update failed\n");
			goto badkey;
		}
	}

	return ret;
badkey:
	crypto_aead_set_flags(aead, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

/*
 * aead_edesc - s/w-extended aead descriptor
 * @assoc_nents: number of segments in associated data (SPI+Seq) scatterlist
 * @assoc_chained: if source is chained
 * @src_nents: number of segments in input scatterlist
 * @src_chained: if source is chained
 * @dst_nents: number of segments in output scatterlist
 * @dst_chained: if destination is chained
 * @iv_dma: dma address of iv for checking continuity and link table
 * @desc: h/w descriptor (variable length; must not exceed MAX_CAAM_DESCSIZE)
 * @qm_sg_bytes: length of dma mapped sec4_sg space
 * @qm_sg_dma: bus physical mapped address of h/w link table
 * @hw_desc: the h/w job descriptor followed by any referenced link tables
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
	struct caam_drv_req drv_req;
	struct qm_sg_entry sgt[0];
};


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
		dma_unmap_single(dev, qm_sg_dma, qm_sg_bytes, DMA_BIDIRECTIONAL);
}

static void aead_unmap(struct device *dev,
		       struct aead_edesc *edesc,
		       struct aead_request *req)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	int ivsize = crypto_aead_ivsize(aead);

	dma_unmap_sg_chained(dev, req->assoc, edesc->assoc_nents,
			     DMA_BIDIRECTIONAL, edesc->assoc_chained);

	caam_unmap(dev, req->src, req->dst,
		   edesc->src_nents, edesc->src_chained, edesc->dst_nents,
		   edesc->dst_chained, edesc->iv_dma, ivsize,
		   edesc->qm_sg_dma, edesc->qm_sg_bytes);
}

static void aead_done(struct caam_drv_req *drv_req, u32 status)
{
	struct device *qidev;
	struct aead_edesc *edesc;
	struct aead_request *aead_req = drv_req->app_ctx;
	struct crypto_aead *aead = crypto_aead_reqtfm(aead_req);
	struct caam_ctx *caam_ctx = crypto_aead_ctx(aead);
	int ecode = 0;

	qidev = caam_ctx->qidev;

	if (unlikely(status)) {
		caam_jr_strstatus(qidev, status);
		ecode = -EIO;
	}

	edesc = container_of(drv_req, struct aead_edesc, drv_req);
	aead_unmap(qidev, edesc, aead_req);

	aead_request_complete(aead_req, ecode);
	qi_cache_free(edesc);
}

/* For now, identical to aead_done */
static inline void tls_encrypt_done(struct caam_drv_req *drv_req, u32 status)
{
	struct device *qidev;
	struct aead_edesc *edesc;
	struct aead_request *aead_req = drv_req->app_ctx;
	struct crypto_aead *aead = crypto_aead_reqtfm(aead_req);
	struct caam_ctx *caam_ctx = crypto_aead_ctx(aead);
	int ecode = 0;

	qidev = caam_ctx->qidev;

	if (status) {
		caam_jr_strstatus(qidev, status);
		ecode = -EIO;
	}

	edesc = container_of(drv_req, struct aead_edesc, drv_req);
	aead_unmap(qidev, edesc, aead_req);

	aead_request_complete(aead_req, ecode);
	qi_cache_free(edesc);
}

static inline void tls_decrypt_done(struct caam_drv_req *drv_req, u32 status)
{
	struct device *qidev;
	struct aead_edesc *edesc;
	struct aead_request *aead_req = drv_req->app_ctx;
	struct crypto_aead *aead = crypto_aead_reqtfm(aead_req);
	struct caam_ctx *caam_ctx = crypto_aead_ctx(aead);
	int ecode = 0;
	int cryptlen = aead_req->cryptlen;
	u8 padsize;
	u8 padding[255]; /* padding can be 0-255 bytes */
	int i;

	qidev = caam_ctx->qidev;

	if (status) {
		caam_jr_strstatus(qidev, status);
		ecode = -EIO;
	}

	edesc = container_of(drv_req, struct aead_edesc, drv_req);
	aead_unmap(qidev, edesc, aead_req);

	/*
	 * verify hw auth check passed else return -EBADMSG
	 */
	if ((status & JRSTA_CCBERR_ERRID_MASK) == JRSTA_CCBERR_ERRID_ICVCHK) {
		ecode = -EBADMSG;
		goto out;
	}

	/* Padding checking */
	cryptlen -= 1;
	scatterwalk_map_and_copy(&padsize, aead_req->dst, cryptlen, 1, 0);
	if (padsize > cryptlen) {
		ecode = -EBADMSG;
		goto out;
	}
	cryptlen -= padsize;
	scatterwalk_map_and_copy(padding, aead_req->dst, cryptlen, padsize, 0);
	/* the padding content must be equal with padsize */
	for (i = 0; i < padsize; i++)
		if (padding[i] != padsize) {
			ecode = -EBADMSG;
			break;
		}

out:
	aead_request_complete(aead_req, ecode);
	qi_cache_free(edesc);
}

/*
 * allocate and map the aead extended descriptor
 */
static struct aead_edesc *aead_edesc_alloc(struct aead_request *req,
					   bool encrypt, bool strip_icv)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct device *qidev = ctx->qidev;
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	int assoc_nents, src_nents, dst_nents = 0;
	struct aead_edesc *edesc;
	dma_addr_t iv_dma = 0, qm_sg_dma;
	int sgc;
	bool all_contig = true;
	bool assoc_chained = false, src_chained = false, dst_chained = false;
	int ivsize = crypto_aead_ivsize(aead);
	unsigned int authsize = ctx->authsize;

	int qm_sg_index, qm_sg_ents = 0, qm_sg_bytes;
	struct qm_sg_entry *sg_table, *fd_sgt;
	struct caam_drv_req *drv_req;
	bool src_is_dst = true;

	assoc_nents = sg_count(req->assoc, req->assoclen, &assoc_chained);

	if (likely(req->dst == req->src)) {
		src_nents = sg_count(req->src,
				     req->cryptlen +
					(encrypt ? authsize : 0),
				     &src_chained);
		sgc = dma_map_sg_chained(qidev, req->src, src_nents ? : 1,
					 DMA_BIDIRECTIONAL, src_chained);
	} else {
		int extralen;

		src_is_dst = false;
		src_nents = sg_count(req->src, req->cryptlen, &src_chained);

		if (encrypt)
			extralen = authsize;
		else
			extralen = strip_icv ? (-authsize) : 0;
		dst_nents = sg_count(req->dst, req->cryptlen + extralen,
				     &dst_chained);
		sgc = dma_map_sg_chained(qidev, req->src, src_nents ? : 1,
					 DMA_TO_DEVICE, src_chained);
		sgc = dma_map_sg_chained(qidev, req->dst, dst_nents ? : 1,
					 DMA_FROM_DEVICE, dst_chained);
	}

	sgc = dma_map_sg_chained(qidev, req->assoc, assoc_nents ? : 1,
				 DMA_TO_DEVICE, assoc_chained);

	/* Check if data are contiguous */
	iv_dma = dma_map_single(qidev, req->iv, ivsize, DMA_TO_DEVICE);
	if (assoc_nents ||
	    sg_dma_address(req->assoc) + req->assoclen != iv_dma ||
	    src_nents || iv_dma + ivsize != sg_dma_address(req->src)) {
		all_contig = false;
		assoc_nents = assoc_nents ? : 1;
		src_nents = src_nents ? : 1;
		qm_sg_ents = assoc_nents + 1 + src_nents;
	}

	qm_sg_ents += dst_nents;
	qm_sg_bytes = qm_sg_ents * sizeof(struct qm_sg_entry);

	/* allocate space for base edesc and hw desc commands, link tables */
	edesc = qi_cache_alloc(GFP_DMA | flags);
	if (unlikely(!edesc)) {
		dev_err(qidev, "could not allocate extended descriptor\n");
		return ERR_PTR(-ENOMEM);
	}

	qm_sg_index = 0;
	drv_req = &edesc->drv_req;
	sg_table = &edesc->sgt[0];
	fd_sgt = &drv_req->fd_sgt[0];

	qm_sg_dma = dma_map_single(qidev, sg_table,
				qm_sg_bytes, DMA_BIDIRECTIONAL);

	edesc->assoc_nents = assoc_nents;
	edesc->assoc_chained = assoc_chained;
	edesc->src_nents = src_nents;
	edesc->src_chained = src_chained;
	edesc->dst_nents = dst_nents;
	edesc->dst_chained = dst_chained;
	edesc->iv_dma = iv_dma;
	edesc->qm_sg_dma = qm_sg_dma;
	edesc->qm_sg_bytes = qm_sg_bytes;

	fd_sgt[0].final = 0;
	fd_sgt[0].__reserved2 = 0;
	fd_sgt[0].bpid = 0;
	fd_sgt[0].__reserved3 = 0;
	fd_sgt[0].offset = 0;

	fd_sgt[1].final = 1;
	fd_sgt[1].__reserved2 = 0;
	fd_sgt[1].bpid = 0;
	fd_sgt[1].__reserved3 = 0;
	fd_sgt[1].offset = 0;

	if (!all_contig) {
		fd_sgt[1].extension = 1;
		fd_sgt[1].addr = qm_sg_dma;

		sg_to_qm_sg(req->assoc, assoc_nents, sg_table, 0);
		qm_sg_index += assoc_nents;

		dma_to_qm_sg_one(sg_table + qm_sg_index, iv_dma, ivsize, 0);
		qm_sg_index += 1;

		sg_to_qm_sg_last(req->src, src_nents,
				 sg_table + qm_sg_index, 0);
		qm_sg_index += src_nents;

	} else {
		fd_sgt[1].extension = 0;
		fd_sgt[1].addr = sg_dma_address(req->assoc);
	}

	if (dst_nents)
		sg_to_qm_sg_last(req->dst, dst_nents,
				 sg_table + qm_sg_index, 0);

	if (likely(src_is_dst)) {
		if (src_nents <= 1) {
			fd_sgt[0].addr = sg_dma_address(req->src);
			fd_sgt[0].extension = 0;
		} else {
			fd_sgt[0].extension = 1;
			fd_sgt[0].addr = fd_sgt[1].addr +
				sizeof(struct qm_sg_entry) *
					((edesc->assoc_nents ? : 1) + 1);
		}
	} else {
		if (!dst_nents) {
			fd_sgt[0].addr = sg_dma_address(req->dst);
			fd_sgt[0].extension = 0;
		} else {
			fd_sgt[0].addr = qm_sg_dma +
				(sizeof(struct qm_sg_entry) * qm_sg_index);
			fd_sgt[0].extension = 1;
		}
	}

	return edesc;
}

static struct caam_drv_ctx *get_drv_ctx(struct caam_ctx *ctx,
					enum optype type)
{
	/* This function is called on the fast path with values of 'type'
	 * known at compile time. Invalid arguments are not expected and
	 * thus no checks are made */
	struct caam_drv_ctx *drv_ctx = ctx->drv_ctx[type];
	u32 *desc;

	if (unlikely(!drv_ctx)) {
		spin_lock(&ctx->lock);

		/* Read again to check if some other core init drv_ctx */
		drv_ctx = ctx->drv_ctx[type];
		if (!drv_ctx) {
			int cpu;

			if (ENCRYPT == type)
				desc = ctx->sh_desc_enc;
			else if (DECRYPT == type)
				desc = ctx->sh_desc_dec;
			else /* (GIVENCRYPT == type) */
				desc = ctx->sh_desc_givenc;

			cpu = smp_processor_id();
			drv_ctx = caam_drv_ctx_init(ctx->qidev, &cpu, desc);

			ctx->drv_ctx[type] = drv_ctx;
		}

		spin_unlock(&ctx->lock);
	}

	return drv_ctx;
}

static int aead_encrypt(struct aead_request *req)
{
	struct aead_edesc *edesc;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	int ivsize = crypto_aead_ivsize(aead);
	struct device *qidev = ctx->qidev;
	struct caam_drv_ctx *drv_ctx;
	struct caam_drv_req *drv_req;
	int ret;

	drv_ctx = get_drv_ctx(ctx, ENCRYPT);
	if (unlikely(IS_ERR_OR_NULL(drv_ctx)))
		return PTR_ERR(drv_ctx);

	if (unlikely(caam_drv_ctx_busy(drv_ctx)))
		return -EAGAIN;

	/* allocate extended descriptor */
	edesc = aead_edesc_alloc(req, true, true);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	/* Create and submit job descriptor */
	drv_req = &edesc->drv_req;
	drv_req->app_ctx = req;
	drv_req->cbk = aead_done;
	drv_req->fd_sgt[0].length = req->cryptlen + ctx->authsize;
	drv_req->fd_sgt[1].length = req->assoclen + ivsize + req->cryptlen;

	drv_req->drv_ctx = drv_ctx;
	ret = caam_qi_enqueue(qidev, drv_req);
	if (!ret) {
		ret = -EINPROGRESS;
	} else {
		aead_unmap(qidev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
}

static int aead_decrypt(struct aead_request *req)
{
	struct aead_edesc *edesc;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	int ivsize = crypto_aead_ivsize(aead);
	struct device *qidev = ctx->qidev;
	struct caam_drv_ctx *drv_ctx;
	struct caam_drv_req *drv_req;
	int ret = 0;

	drv_ctx = get_drv_ctx(ctx, DECRYPT);
	if (unlikely(IS_ERR_OR_NULL(drv_ctx)))
		return PTR_ERR(drv_ctx);

	if (unlikely(caam_drv_ctx_busy(drv_ctx)))
		return -EAGAIN;

	/* allocate extended descriptor */
	edesc = aead_edesc_alloc(req, false, true);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	/* Create and submit job descriptor */
	drv_req = &edesc->drv_req;
	drv_req->app_ctx = req;
	drv_req->cbk = aead_done;
	drv_req->fd_sgt[0].length = req->cryptlen - ctx->authsize;
	drv_req->fd_sgt[1].length = req->assoclen + ivsize + req->cryptlen;

	drv_req->drv_ctx = drv_ctx;
	ret = caam_qi_enqueue(qidev, drv_req);
	if (!ret) {
		ret = -EINPROGRESS;
	} else {
		aead_unmap(qidev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
}

static int tls_encrypt(struct aead_request *req)
{
	struct aead_edesc *edesc;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	int ivsize = crypto_aead_ivsize(aead);
	struct device *qidev = ctx->qidev;
	struct caam_drv_ctx *drv_ctx;
	struct caam_drv_req *drv_req;
	int ret;
	unsigned int blocksize = crypto_aead_blocksize(aead);
	unsigned int padsize;

	drv_ctx = get_drv_ctx(ctx, ENCRYPT);
	if (unlikely(IS_ERR_OR_NULL(drv_ctx)))
		return PTR_ERR(drv_ctx);

	if (unlikely(caam_drv_ctx_busy(drv_ctx)))
		return -EAGAIN;

	padsize = blocksize - ((req->cryptlen + ctx->authsize) % blocksize);

	/*
	 * allocate extended tls descriptor
	 * TLS 1.0 has no explicit IV in the packet, but it is needed as input
	 * since it is used by CBC.
	 * ctx->authsize is temporary set to include also padlen
	 */
	ctx->authsize += padsize;
	edesc = aead_edesc_alloc(req, true, true);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);
	ctx->authsize -= padsize;

	/* Create and submit job descriptor */
	drv_req = &edesc->drv_req;
	drv_req->app_ctx = req;
	drv_req->cbk = tls_encrypt_done;
	drv_req->fd_sgt[0].length = req->cryptlen + padsize + ctx->authsize;
	drv_req->fd_sgt[1].length = req->assoclen + ivsize + req->cryptlen;

	drv_req->drv_ctx = drv_ctx;
	ret = caam_qi_enqueue(qidev, drv_req);
	if (!ret) {
		ret = -EINPROGRESS;
	} else {
		aead_unmap(qidev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
}

static int tls_decrypt(struct aead_request *req)
{
	struct aead_edesc *edesc;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	int ivsize = crypto_aead_ivsize(aead);
	struct device *qidev = ctx->qidev;
	struct caam_drv_ctx *drv_ctx;
	struct caam_drv_req *drv_req;
	int ret = 0;

	drv_ctx = get_drv_ctx(ctx, DECRYPT);
	if (unlikely(IS_ERR_OR_NULL(drv_ctx)))
		return PTR_ERR(drv_ctx);

	if (unlikely(caam_drv_ctx_busy(drv_ctx)))
		return -EAGAIN;

	/*
	 * allocate extended descriptor
	 * TLS 1.0 has no explicit IV in the packet, but it is needed as input
	 * since it is used by CBC.
	 * Assumption: since padding and ICV are not stripped (upper layer
	 * checks padding), req->dst has to be big enough to hold payloadlen +
	 * padlen + icvlen.
	 */
	edesc = aead_edesc_alloc(req, false, false);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	/* Create and submit job descriptor */
	drv_req = &edesc->drv_req;
	drv_req->app_ctx = req;
	drv_req->cbk = tls_decrypt_done;
	/*
	 * For decrypt, do not strip ICV, Padding, Padding length since
	 * upper layer(s) perform padding checking.
	 */
	drv_req->fd_sgt[0].length = req->cryptlen;
	drv_req->fd_sgt[1].length = req->assoclen + ivsize + req->cryptlen;

	drv_req->drv_ctx = drv_ctx;
	ret = caam_qi_enqueue(qidev, drv_req);
	if (!ret) {
		ret = -EINPROGRESS;
	} else {
		aead_unmap(qidev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
}

/*
 * allocate and map the aead extended descriptor for aead givencrypt
 */
static struct aead_edesc *aead_giv_edesc_alloc(struct aead_givcrypt_request
					       *greq)
{
	struct aead_request *req = &greq->areq;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct device *qidev = ctx->qidev;
	gfp_t flags = (req->base.flags & (CRYPTO_TFM_REQ_MAY_BACKLOG |
		       CRYPTO_TFM_REQ_MAY_SLEEP)) ? GFP_KERNEL : GFP_ATOMIC;
	int assoc_nents, src_nents, dst_nents = 0;
	struct aead_edesc *edesc;
	dma_addr_t iv_dma = 0, qm_sg_dma;
	int sgc;
	u32 contig = GIV_SRC_CONTIG | GIV_DST_CONTIG;
	int ivsize = crypto_aead_ivsize(aead);
	bool assoc_chained = false, src_chained = false, dst_chained = false;

	int qm_sg_index, qm_sg_ents = 0, qm_sg_bytes;
	struct qm_sg_entry *sg_table, *fd_sgt;
	struct caam_drv_req *drv_req;
	bool src_is_dst = true;

	assoc_nents = sg_count(req->assoc, req->assoclen, &assoc_chained);
	src_nents = sg_count(req->src, req->cryptlen, &src_chained);

	sgc = dma_map_sg_chained(qidev, req->assoc, assoc_nents ? : 1,
				 DMA_TO_DEVICE, assoc_chained);

	if (likely(req->src == req->dst)) {
		sgc = dma_map_sg_chained(qidev, req->src, src_nents ? : 1,
					 DMA_BIDIRECTIONAL, src_chained);
	} else {
		src_is_dst = false;
		dst_nents = sg_count(req->dst, req->cryptlen + ctx->authsize,
				     &dst_chained);
		sgc = dma_map_sg_chained(qidev, req->src, src_nents ? : 1,
					 DMA_TO_DEVICE, src_chained);
		sgc = dma_map_sg_chained(qidev, req->dst, dst_nents ? : 1,
					 DMA_FROM_DEVICE, dst_chained);
	}

	/* Check if data are contiguous */
	iv_dma = dma_map_single(qidev, greq->giv, ivsize, DMA_TO_DEVICE);

	if (assoc_nents ||
	    sg_dma_address(req->assoc) + req->assoclen != iv_dma ||
	    src_nents || iv_dma + ivsize != sg_dma_address(req->src))
		contig &= ~GIV_SRC_CONTIG;

	if (dst_nents || iv_dma + ivsize != sg_dma_address(req->dst))
		contig &= ~GIV_DST_CONTIG;

	if (unlikely(!src_is_dst)) {
		dst_nents = dst_nents ? : 1;
		qm_sg_ents += 1;
	}

	if (!(contig & GIV_SRC_CONTIG)) {
		assoc_nents = assoc_nents ? : 1;
		src_nents = src_nents ? : 1;
		qm_sg_ents += assoc_nents + 1 + src_nents;
		if (likely(src_is_dst))
			contig &= ~GIV_DST_CONTIG;
	}

	qm_sg_ents += dst_nents;

	qm_sg_bytes = qm_sg_ents * sizeof(struct qm_sg_entry);

	/* allocate space for base edesc and hw desc commands, link tables */
	edesc = qi_cache_alloc(GFP_DMA | flags);
	if (unlikely(!edesc)) {
		dev_err(qidev, "could not allocate extended descriptor\n");
		return ERR_PTR(-ENOMEM);
	}

	drv_req = &edesc->drv_req;
	sg_table = &edesc->sgt[0];
	fd_sgt = &drv_req->fd_sgt[0];

	qm_sg_dma = dma_map_single(qidev, sg_table,
				qm_sg_bytes, DMA_BIDIRECTIONAL);

	edesc->assoc_nents = assoc_nents;
	edesc->assoc_chained = assoc_chained;
	edesc->src_nents = src_nents;
	edesc->src_chained = src_chained;
	edesc->dst_nents = dst_nents;
	edesc->dst_chained = dst_chained;
	edesc->iv_dma = iv_dma;
	edesc->qm_sg_bytes = qm_sg_bytes;
	edesc->qm_sg_dma = qm_sg_dma;

	fd_sgt[0].final = 0;
	fd_sgt[0].extension = 0;
	fd_sgt[0].__reserved2 = 0;
	fd_sgt[0].bpid = 0;
	fd_sgt[0].__reserved3 = 0;
	fd_sgt[0].offset = 0;

	fd_sgt[1].final = 1;
	fd_sgt[1].extension = 0;
	fd_sgt[1].__reserved2 = 0;
	fd_sgt[1].bpid = 0;
	fd_sgt[1].__reserved3 = 0;
	fd_sgt[1].offset = 0;

	qm_sg_index = 0;
	if (unlikely(!(contig & GIV_SRC_CONTIG))) {
		fd_sgt[1].extension = 1;
		fd_sgt[1].addr = qm_sg_dma;

		sg_to_qm_sg(req->assoc, assoc_nents,
			    sg_table + qm_sg_index, 0);

		qm_sg_index += assoc_nents;

		dma_to_qm_sg_one(sg_table + qm_sg_index,
				 iv_dma, ivsize, 0);

		qm_sg_index += 1;

		sg_to_qm_sg_last(req->src, src_nents,
				 sg_table + qm_sg_index, 0);

		qm_sg_index += src_nents;
	} else {
		fd_sgt[1].addr = sg_dma_address(req->assoc);
	}

	if (unlikely(!src_is_dst && !(contig & GIV_DST_CONTIG))) {
		fd_sgt[0].addr = qm_sg_dma +
				(sizeof(struct qm_sg_entry) * qm_sg_index);
		fd_sgt[0].extension = 1;

		dma_to_qm_sg_one(sg_table + qm_sg_index, iv_dma, ivsize, 0);
		qm_sg_index += 1;
		sg_to_qm_sg_last(req->dst, dst_nents,
				 sg_table + qm_sg_index, 0);
	} else {
		if (src_is_dst && !(contig & GIV_DST_CONTIG)) {
			fd_sgt[0].extension = 1;
			fd_sgt[0].addr = edesc->qm_sg_dma +
					sizeof(struct qm_sg_entry) *
					edesc->assoc_nents;
		} else {
			fd_sgt[0].addr = edesc->iv_dma;
		}
	}

	return edesc;
}

static int aead_givencrypt(struct aead_givcrypt_request *areq)
{
	struct aead_request *req = &areq->areq;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct caam_ctx *ctx = crypto_aead_ctx(aead);
	struct device *qidev = ctx->qidev;
	struct caam_drv_ctx *drv_ctx;
	struct caam_drv_req *drv_req;
	int ivsize = crypto_aead_ivsize(aead);
	struct aead_edesc *edesc;
	int ret;

	drv_ctx = get_drv_ctx(ctx, GIVENCRYPT);
	if (unlikely(IS_ERR_OR_NULL(drv_ctx)))
		return PTR_ERR(drv_ctx);

	if (unlikely(caam_drv_ctx_busy(drv_ctx)))
		return -EAGAIN;

	/* allocate extended descriptor */
	edesc = aead_giv_edesc_alloc(areq);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	drv_req = &edesc->drv_req;
	drv_req->app_ctx = req;
	drv_req->cbk = aead_done;
	drv_req->fd_sgt[0].length = ivsize + req->cryptlen + ctx->authsize;
	drv_req->fd_sgt[1].length = req->assoclen + ivsize + req->cryptlen;

	drv_req->drv_ctx = drv_ctx;
	ret = caam_qi_enqueue(qidev, drv_req);
	if (!ret) {
		ret = -EINPROGRESS;
	} else {
		aead_unmap(qidev, edesc, req);
		qi_cache_free(edesc);
	}

	return ret;
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
		.driver_name = "authenc-hmac-md5-cbc-aes-caam-qi",
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
		.driver_name = "authenc-hmac-sha1-cbc-aes-caam-qi",
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
		.driver_name = "authenc-hmac-sha224-cbc-aes-caam-qi",
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
		.driver_name = "authenc-hmac-sha256-cbc-aes-caam-qi",
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
		.driver_name = "authenc-hmac-sha384-cbc-aes-caam-qi",
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
		.driver_name = "authenc-hmac-sha512-cbc-aes-caam-qi",
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
		.driver_name = "authenc-hmac-md5-cbc-des3_ede-caam-qi",
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
		.driver_name = "authenc-hmac-sha1-cbc-des3_ede-caam-qi",
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
		.driver_name = "authenc-hmac-sha224-cbc-des3_ede-caam-qi",
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
		.driver_name = "authenc-hmac-sha256-cbc-des3_ede-caam-qi",
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
		.driver_name = "authenc-hmac-sha384-cbc-des3_ede-caam-qi",
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
		.driver_name = "authenc-hmac-sha512-cbc-des3_ede-caam-qi",
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
		.driver_name = "authenc-hmac-md5-cbc-des-caam-qi",
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
		.driver_name = "authenc-hmac-sha1-cbc-des-caam-qi",
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
		.driver_name = "authenc-hmac-sha224-cbc-des-caam-qi",
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
		.driver_name = "authenc-hmac-sha256-cbc-des-caam-qi",
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
		.driver_name = "authenc-hmac-sha384-cbc-des-caam-qi",
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
		.driver_name = "authenc-hmac-sha512-cbc-des-caam-qi",
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
	/* TLS record descriptors */
	{
		.name = "tls10(hmac(sha1),cbc(aes))",
		.driver_name = "tls10-hmac-sha1-cbc-aes-caam-qi",
		.blocksize = AES_BLOCK_SIZE,
		.type = CRYPTO_ALG_TYPE_AEAD,
		.template_aead = {
			.setkey = tls_setkey,
			.setauthsize = tls_setauthsize,
			.encrypt = tls_encrypt,
			.decrypt = tls_decrypt,
			.givencrypt = NULL,
			.geniv = "<built-in>",
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = SHA1_DIGEST_SIZE,
			},
		.class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
		.class2_alg_type = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC_PRECOMP,
		.alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	}
};

struct caam_crypto_alg {
	struct list_head entry;
	struct device *ctrldev;
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
	struct caam_drv_private *priv = dev_get_drvdata(caam_alg->ctrldev);
	/* Digest sizes for MD5, SHA1, SHA-224, SHA-256, SHA-384, SHA-512 */
	static const u8 digest_size[] = {
		MD5_DIGEST_SIZE,
		SHA1_DIGEST_SIZE,
		SHA224_DIGEST_SIZE,
		SHA256_DIGEST_SIZE,
		SHA384_DIGEST_SIZE,
		SHA512_DIGEST_SIZE
	};
	u8 op_id;

	/*
	 * distribute tfms across job rings to ensure in-order
	 * crypto request processing per tfm
	 */
	ctx->jrdev = caam_jr_alloc();
	if (IS_ERR(ctx->jrdev)) {
		pr_err("Job Ring Device allocation for transform failed\n");
		return PTR_ERR(ctx->jrdev);
	}

	/* copy descriptor header template value */
	ctx->class1_alg_type = OP_TYPE_CLASS1_ALG | caam_alg->class1_alg_type;
	ctx->class2_alg_type = OP_TYPE_CLASS2_ALG | caam_alg->class2_alg_type;
	ctx->alg_op = OP_TYPE_CLASS2_ALG | caam_alg->alg_op;

	/*
	 * Need authsize, in case setauthsize callback not called
	 * by upper layer (e.g. TLS).
	 */
	if (caam_alg->alg_op) {
		op_id = (ctx->alg_op & OP_ALG_ALGSEL_SUBMASK)
				>> OP_ALG_ALGSEL_SHIFT;
		if (op_id < ARRAY_SIZE(digest_size)) {
			ctx->authsize = digest_size[op_id];
		} else {
			dev_err(ctx->jrdev,
				"incorrect op_id %d; must be less than %zu\n",
				op_id, ARRAY_SIZE(digest_size));
			caam_jr_free(ctx->jrdev);
			return -EINVAL;
		}
	} else {
		ctx->authsize = 0;
	}

	ctx->qidev = priv->qidev;

	spin_lock_init(&ctx->lock);
	ctx->drv_ctx[ENCRYPT] = NULL;
	ctx->drv_ctx[DECRYPT] = NULL;
	ctx->drv_ctx[GIVENCRYPT] = NULL;

	return 0;
}

static void caam_cra_exit(struct crypto_tfm *tfm)
{
	struct caam_ctx *ctx = crypto_tfm_ctx(tfm);

	caam_drv_ctx_rel(ctx->drv_ctx[ENCRYPT]);
	caam_drv_ctx_rel(ctx->drv_ctx[DECRYPT]);
	caam_drv_ctx_rel(ctx->drv_ctx[GIVENCRYPT]);

	caam_jr_free(ctx->jrdev);
}

static struct list_head alg_list;
static void __exit caam_qi_algapi_exit(void)
{
	struct caam_crypto_alg *t_alg, *n;

	if (!alg_list.next)
		return;

	list_for_each_entry_safe(t_alg, n, &alg_list, entry) {
		crypto_unregister_alg(&t_alg->crypto_alg);
		list_del(&t_alg->entry);
		kfree(t_alg);
	}
}

static struct caam_crypto_alg *caam_alg_alloc(struct device *ctrldev,
					      struct caam_alg_template
					      *template)
{
	struct caam_crypto_alg *t_alg;
	struct crypto_alg *alg;

	t_alg = kzalloc(sizeof(struct caam_crypto_alg), GFP_KERNEL);
	if (!t_alg) {
		dev_err(ctrldev, "failed to allocate t_alg\n");
		return ERR_PTR(-ENOMEM);
	}

	alg = &t_alg->crypto_alg;

	snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s", template->name);
	snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
		 template->driver_name);
	alg->cra_module = THIS_MODULE;
	alg->cra_init = caam_cra_init;
	alg->cra_exit = caam_cra_exit;
	alg->cra_priority = CAAM_CRA_PRIORITY;
	alg->cra_blocksize = template->blocksize;
	alg->cra_alignmask = 0;
	alg->cra_ctxsize = sizeof(struct caam_ctx);
	alg->cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY |
			 template->type;
	switch (template->type) {
	case CRYPTO_ALG_TYPE_ABLKCIPHER:
		alg->cra_type = &crypto_ablkcipher_type;
		alg->cra_ablkcipher = template->template_ablkcipher;
		break;
	case CRYPTO_ALG_TYPE_AEAD:
		alg->cra_type = &crypto_aead_type;
		alg->cra_aead = template->template_aead;
		break;
	}

	t_alg->class1_alg_type = template->class1_alg_type;
	t_alg->class2_alg_type = template->class2_alg_type;
	t_alg->alg_op = template->alg_op;
	t_alg->ctrldev = ctrldev;

	return t_alg;
}

static int __init caam_qi_algapi_init(void)
{
	struct device_node *dev_node;
	struct platform_device *pdev;
	struct device *ctrldev;
	struct caam_drv_private *priv;
	int i = 0, err = 0;

	dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec-v4.0");
	if (!dev_node) {
		dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec4.0");
		if (!dev_node)
			return -ENODEV;
	}

	pdev = of_find_device_by_node(dev_node);
	of_node_put(dev_node);
	if (!pdev)
		return -ENODEV;

	ctrldev = &pdev->dev;
	priv = dev_get_drvdata(ctrldev);
	/*
	* If priv is NULL, it's probably because the caam driver wasn't
	* properly initialized (e.g. RNG4 init failed). Thus, bail out here.
	*/
	if (!priv || !priv->qi_present)
		return -ENODEV;

	INIT_LIST_HEAD(&alg_list);

	/* register crypto algorithms the device supports */
	for (i = 0; i < ARRAY_SIZE(driver_algs); i++) {
		/* TODO: check if h/w supports alg */
		struct caam_crypto_alg *t_alg;

		t_alg = caam_alg_alloc(ctrldev, &driver_algs[i]);
		if (IS_ERR(t_alg)) {
			err = PTR_ERR(t_alg);
			dev_warn(priv->qidev, "%s alg allocation failed\n",
				 driver_algs[i].driver_name);
			continue;
		}

		err = crypto_register_alg(&t_alg->crypto_alg);
		if (err) {
			dev_warn(priv->qidev, "%s alg registration failed\n",
				 t_alg->crypto_alg.cra_driver_name);
			kfree(t_alg);
		} else {
			list_add_tail(&t_alg->entry, &alg_list);
		}
	}

	if (!list_empty(&alg_list))
		dev_info(priv->qidev, "algorithms registered in /proc/crypto\n");

	return err;
}

module_init(caam_qi_algapi_init);
module_exit(caam_qi_algapi_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Support for crypto API using CAAM-QI backend");
MODULE_AUTHOR("Freescale Semiconductor - NMG/STC");
