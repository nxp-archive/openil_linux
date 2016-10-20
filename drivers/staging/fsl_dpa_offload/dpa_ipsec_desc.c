/* Copyright 2008-2012 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include <linux/version.h>
#include <linux/platform_device.h>

#include "compat.h"
#include "desc.h"
#include "error.h"
#include "jr.h"
#include "ctrl.h"

#include "dpa_ipsec_desc.h"

static struct device *get_jrdev(struct dpa_ipsec *dpa_ipsec);

/* If SEC ERA is unknown default to this value */
#define SEC_DEF_ERA	2 /* like in P4080 */

/*
 * to retrieve a 256 byte aligned buffer address from an address
 * we need to copy only the first 7 bytes
 */
#define ALIGNED_PTR_ADDRESS_SZ	(CAAM_PTR_SZ - 1)

#define JOB_DESC_HDR_LEN	CAAM_CMD_SZ
#define SEQ_OUT_PTR_SGF_MASK	0x01000000;
/* relative offset where the input pointer should be updated in the descriptor*/
#define IN_PTR_REL_OFF		4 /* words from current location */
/* dummy pointer value */
#define DUMMY_PTR_VAL		0x00000000
#define PTR_LEN			2	/* Descriptor is created only for 8 byte
					 * pointer. PTR_LEN is in words. */

/* retrieve and store SEC information */
int get_sec_info(struct dpa_ipsec *dpa_ipsec)
{
	struct device_node *sec_node;
	const u32 *sec_era;
	int prop_size;

	sec_node = of_find_node_with_property(NULL, "fsl,sec-era");
	if (sec_node) {
		sec_era = of_get_property(sec_node, "fsl,sec-era", &prop_size);
		if (sec_era && prop_size == sizeof(*sec_era) && *sec_era > 0)
			dpa_ipsec->sec_era = be32_to_cpu(*sec_era);
		of_node_put(sec_node);
	}

	if (dpa_ipsec->sec_era == 0) {
		dpa_ipsec->sec_era = SEC_DEF_ERA;
		log_warn("Unable to acquire the SEC era from the device tree. Defaulting to SEC era %d.\n",
			dpa_ipsec->sec_era);
	}

	dpa_ipsec->jrdev = get_jrdev(dpa_ipsec);
	if (!dpa_ipsec->jrdev)
		return -ENODEV;

	return 0;
}


static struct device *get_jrdev(struct dpa_ipsec *dpa_ipsec)
{
	struct device *sec_jr_dev;

	if (!IS_ERR_OR_NULL(dpa_ipsec->jrdev))
		return dpa_ipsec->jrdev;

	sec_jr_dev = caam_jr_alloc();
	if (IS_ERR(sec_jr_dev)) {
		log_err("No available SEC job-ring\n");
		return NULL;
	}

	return sec_jr_dev;
}

static inline u32 get_ipsec_op_type(enum dpa_ipsec_direction sa_dir)
{
	return sa_dir == DPA_IPSEC_INBOUND ?  OP_TYPE_DECAP_PROTOCOL :
					      OP_TYPE_ENCAP_PROTOCOL;
}

static inline int get_cipher_params(enum dpa_ipsec_cipher_alg cipher_alg,
				    uint32_t *iv_length, uint32_t *icv_length,
				    uint32_t *max_pad_length)
{
	switch (cipher_alg) {
	case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_MD5_128:
	case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_SHA_160:
		*iv_length = 8;
		*max_pad_length = 8;
		*icv_length = 12;
		break;
	case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_MD5_128:
		*iv_length = 8;
		*max_pad_length = 8;
		*icv_length = 16;
		break;
	case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_160:
	case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_256_128:
		*iv_length = 8;
		*max_pad_length = 8;
		*icv_length = 20;
		break;
	case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_384_192:
		*iv_length = 8;
		*max_pad_length = 8;
		*icv_length = 24;
		break;
	case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_512_256:
		*iv_length = 8;
		*max_pad_length = 8;
		*icv_length = 32;
		break;
	case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_MD5_128:
	case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_SHA_160:
	case DPA_IPSEC_CIPHER_ALG_AES_CBC_AES_XCBC_MAC_96:
		*iv_length = 16;
		*max_pad_length = 16;
		*icv_length = 12;
		break;
	case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_MD5_128:
	case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_256_128:
		*iv_length = 16;
		*max_pad_length = 16;
		*icv_length = 16;
		break;
	case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_160:
		*iv_length = 16;
		*max_pad_length = 16;
		*icv_length = 20;
		break;
	case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_384_192:
		*iv_length = 16;
		*max_pad_length = 16;
		*icv_length = 24;
		break;
	case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_512_256:
		*iv_length = 16;
		*max_pad_length = 16;
		*icv_length = 32;
		break;
	case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_MD5_128:
	case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_SHA_160:
	case DPA_IPSEC_CIPHER_ALG_AES_CTR_AES_XCBC_MAC_96:
		*iv_length = 16;
		*max_pad_length = 16;
		*icv_length = 12;
		break;
	case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_MD5_128:
	case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_256_128:
		*iv_length = 8;
		*max_pad_length = 4;
		*icv_length = 16;
		break;
	case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_160:
		*iv_length = 8;
		*max_pad_length = 4;
		*icv_length = 20;
		break;
	case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_384_192:
		*iv_length = 8;
		*max_pad_length = 4;
		*icv_length = 24;
		break;
	case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_512_256:
		*iv_length = 8;
		*max_pad_length = 4;
		*icv_length = 32;
		break;
	default:
		*iv_length = 0;
		*icv_length = 0;
		*max_pad_length = 0;
		log_err("Unsupported cipher suite %d\n", cipher_alg);
		return -EINVAL;
	}

	return 0;
}

static inline void build_stats_descriptor_part(struct dpa_ipsec_sa *sa,
					       size_t pdb_len)
{
	u32 *desc, *padding_jump;
	u32 block_size, stats_offset, offset;

	BUG_ON(!sa);

	desc = (u32 *) sa->sec_desc->desc;

	stats_offset = sizeof(sa->sec_desc->hdr_word) + pdb_len -
		       DPA_IPSEC_STATS_LEN * sizeof(u32);
	sa->stats_offset = stats_offset;
	memset((u8 *)desc + stats_offset, 0, DPA_IPSEC_STATS_LEN * sizeof(u32));

	/* Copy from descriptor to MATH REG 0 the current statistics */
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | MOVE_WAITCOMP |
		    (stats_offset << MOVE_OFFSET_SHIFT) | sizeof(u64));

	/* Load 1 in MATH REG 1 */
	append_math_add(desc, REG1, ZERO, ONE, MATH_LEN_8BYTE);

	/*
	 * Perform 32-bit left shift of DEST and concatenate with left 32 bits
	 * of SRC1 i.e MATH REG 1 = 0x00000001_00000000
	 */
	append_math_shld(desc, REG1, REG0, REG1, MATH_LEN_8BYTE);

	if (sa->sa_dir == DPA_IPSEC_INBOUND) {
		/* MATH REG 2 = Sequence in length */
		append_math_add_imm_u32(desc, REG2, SEQINLEN, IMM, 0);
		goto after_padding;
	} else {
		/* MATH REG 2 = Sequence in length + 2 */
		append_math_add_imm_u32(desc, REG2, SEQINLEN, IMM, 2);
	}

	switch (sa->cipher_data.cipher_type) {
	case OP_PCL_IPSEC_3DES:
		block_size = 8; /* block size in bytes */
		break;
	case OP_PCL_IPSEC_AES_CBC:
	case OP_PCL_IPSEC_AES_CTR:
	case OP_PCL_IPSEC_AES_XTS:
	case OP_PCL_IPSEC_AES_CCM8:
	case OP_PCL_IPSEC_AES_CCM12:
	case OP_PCL_IPSEC_AES_CCM16:
	case OP_PCL_IPSEC_AES_GCM8:
	case OP_PCL_IPSEC_AES_GCM12:
	case OP_PCL_IPSEC_AES_GCM16:
		block_size = 16; /* block size in bytes */
		break;
	default:
		pr_crit("Invalid cipher algorithm for SA %d\n", sa->id);
		return;
	}

	/* Adding padding to byte counter */
	append_math_and_imm_u32(desc, REG3, REG2, IMM, block_size - 1);

	/* Previous operation result is 0 i.e padding added to bytes count */
	padding_jump = append_jump(desc, CLASS_BOTH | JUMP_TEST_ALL |
				   JUMP_COND_MATH_Z);

	/* MATH REG 2 = MATH REG 2 + 1 */
	append_math_add(desc, REG2, REG2, ONE, MATH_LEN_8BYTE);

	/* jump back to adding padding i.e jump back 4 words */
	offset = (-4) & 0x000000FF;
	append_jump(desc, (offset << JUMP_OFFSET_SHIFT));

	set_jump_tgt_here(desc, padding_jump);
	/* Done adding padding to byte counter */

after_padding:
	/* MATH REG 1  = MATH REG 1 + MATH REG 2 */
	append_math_add(desc, REG1, REG1, REG2, MATH_LEN_8BYTE);

	/* MATH REG0 = MATH REG 0 + MATH REG1 */
	append_math_add(desc, REG0, REG0, REG1, MATH_LEN_8BYTE);

	/* Store in the descriptor but not in external memory */
	append_move(desc, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF | MOVE_WAITCOMP |
		    (stats_offset << MOVE_OFFSET_SHIFT) | sizeof(u64));
}

static inline void save_stats_in_external_mem(struct dpa_ipsec_sa *sa)
{
	u32 *desc;
	u32 stats_offset;

	desc = (u32 *) sa->sec_desc->desc;

	/* statistics offset = predetermined offset */
	stats_offset = sa->stats_offset;

	/* Store command: in the case of the Descriptor Buffer the length
	 * is specified in 4-byte words, but in all other cases the length
	 * is specified in bytes. Offset in 4 byte words */
	append_store(desc, 0, DPA_IPSEC_STATS_LEN, LDST_CLASS_DECO |
		     ((stats_offset / 4) << LDST_OFFSET_SHIFT) |
		     LDST_SRCDST_WORD_DESCBUF_SHARED);

	/* Jump with CALM to be sure previous operation was finished */
	append_jump(desc, JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT));
}

/* insert cmds for SEQ_IN/OUT_PTR copy with specified offset (shr_desc_len) */
static void insert_ptr_copy_cmds(uint32_t *desc, uint32_t index,
				 uint32_t shr_desc_len, bool update_desc_len)
{
	uint32_t move_cmd, off, len;
	uint32_t *tmp;

	/*
	 * insert the commands at the specified index
	 * if index == 0 insert at next position in desc
	 */
	if (!index)
		index = desc_len(desc);

	tmp = desc + index;
	/*
	 * move out ptr (from job desc) to math reg 1 & 2, except the last byte;
	 * assuming all buffers are 256 bits aligned, setting the last address
	 * byte to 0x00  will give the buffer address;
	 */
	off = CAAM_PTR_SZ;
	off = (shr_desc_len * CAAM_CMD_SZ + off) << MOVE_OFFSET_SHIFT;
	len = CAAM_CMD_SZ + JOB_DESC_HDR_LEN + ALIGNED_PTR_ADDRESS_SZ;
	move_cmd = CMD_MOVE | MOVE_SRC_DESCBUF | MOVE_DEST_MATH1 | off | len;
	if (update_desc_len)
		append_cmd(desc, move_cmd);
	else
		tmp = write_cmd(tmp, move_cmd);

	/*
	 * move in ptr (from job desc) to math reg 0, except the last byte;
	 * assuming all buffers are 256 bits aligned, setting the last address
	 * byte to 0x00  will give the buffer address;
	 */
	off = JOB_DESC_HDR_LEN + 3 * CAAM_CMD_SZ + 2 * CAAM_PTR_SZ;
	off = (shr_desc_len * CAAM_CMD_SZ + off) << MOVE_OFFSET_SHIFT;
	len = ALIGNED_PTR_ADDRESS_SZ;
	move_cmd = CMD_MOVE | MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | off | len;
	if (update_desc_len)
		append_cmd(desc, move_cmd);
	else
		tmp = write_cmd(tmp, move_cmd);
}

/* build the command set for copying the frame meta data */
static void build_meta_data_desc_cmds(struct dpa_ipsec_sa *sa,
				      unsigned int sec_era,
				      unsigned int move_size)
{
	uint32_t *desc, off, len, opt, *no_sg_jump;
	uint32_t sg_mask = SEQ_OUT_PTR_SGF_MASK;

	BUG_ON(!sa);

	desc = (uint32_t *) sa->sec_desc->desc;

	/* insert cmds to copy SEQ_IN/OUT_PTR - offset will be updated later */
	insert_ptr_copy_cmds(desc, 0, 0, true);

	/* detect & handle scatter / gather frames */

	/*
	 * the SEQ OUT PTR command is now in math reg 1, so the SGF bit can be
	 * checked using a math command;
	 */
	append_math_and_imm_u32(desc, NONE, REG1, IMM, sg_mask);

	opt = CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_COND_MATH_Z | JUMP_TEST_ALL;
	no_sg_jump = append_jump(desc, opt);

	if (sec_era == 2) {
		/* disable iNFO FIFO entries for p4080rev2 & ??? */
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 */
		opt = MOVE_SRC_MATH3 | MOVE_DEST_CLASS1INFIFO;
		off = 127 << MOVE_OFFSET_SHIFT;
		len = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off | len);

		/* enable iNFO FIFO entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);
	} else {
		/* ????? */
		opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | opt | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 */
		opt = MOVE_SRC_MATH3 | MOVE_DEST_INFIFO_NOINFO;
		off = 127 << MOVE_OFFSET_SHIFT;
		len = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off | len);
	}

	/*
	 * throw away the first part of the S/G table and keep only the buffer
	 * address;
	 * offset = undefined memory after MATH3;
	 * len =
	 */
	opt = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off = 8 << MOVE_OFFSET_SHIFT;
	len = 41 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off | len);

	/* put the buffer address (still in the IN FIFO) in MATH2 */
	opt = MOVE_SRC_INFIFO | MOVE_DEST_MATH2;
	off = 0 << MOVE_OFFSET_SHIFT;
	len = 8 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off | len);

	/* update no S/G jump location */
	set_jump_tgt_here(desc, no_sg_jump);

	/* save input pointer to predefined location in descriptor */
	opt = MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF;
	off = ((desc_len(desc) + IN_PTR_REL_OFF) << 2) << MOVE_OFFSET_SHIFT;
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | off | len);

	/* save output pointer to predefined location in descriptor */
	opt = MOVE_WAITCOMP | MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF;
	off += (CAAM_PTR_SZ +  2 * CAAM_CMD_SZ) << MOVE_OFFSET_SHIFT;
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | off | len);

	/* fix LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off = 0x40 << LDST_OFFSET_SHIFT; /* SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | off);

	/* actual move commands - pointers will be updated at runtime */

	/* load the data to be moved - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_load(desc, DUMMY_PTR_VAL, len, opt | off);

	/* wait for completion */
	opt = JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT);
	append_jump(desc, opt);

	/* store the data to the output fifo - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_store(desc, DUMMY_PTR_VAL, len, opt | off);

	/* fix LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off = 0x80 << LDST_OFFSET_SHIFT; /* NON_SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | off);
}

int build_shared_descriptor(struct dpa_ipsec_sa *sa,
			    dma_addr_t auth_key_dma,
			    dma_addr_t crypto_key_dma, u32 bytes_to_copy)
{
	uint32_t *desc, *key_jump_cmd, copy_ptr_index = 0;
	int opthdrsz;
	size_t pdb_len = 0;

	desc = (u32 *) sa->sec_desc->desc;

	/* Reserve 2 words for statistics */
	if (sa->enable_stats)
		pdb_len = DPA_IPSEC_STATS_LEN * sizeof(u32);

	if (sa->sa_dir == DPA_IPSEC_OUTBOUND) {
		/* Compute optional header size, rounded up to descriptor
		 * word size */
		opthdrsz = (caam16_to_cpu(sa->sec_desc->pdb_en.ip_hdr_len) +
				3) & ~3;
		pdb_len += sizeof(struct ipsec_encap_pdb) + opthdrsz;
		init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL, pdb_len);
	} else {
		pdb_len += sizeof(struct ipsec_decap_pdb);
		init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL, pdb_len);
	}

	/* Key jump */
	key_jump_cmd = append_jump(desc, CLASS_BOTH | JUMP_TEST_ALL |
				   JUMP_COND_SHRD | JUMP_COND_SELF);

	/* check whether a split of a normal key is used */
	if (sa->auth_data.split_key_len)
		/* Append split authentication key */
		append_key(desc, auth_key_dma, sa->auth_data.split_key_len,
			   CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else
		/* Append normal authentication key */
		append_key(desc, auth_key_dma, sa->auth_data.auth_key_len,
			   CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	append_key(desc, crypto_key_dma, sa->cipher_data.cipher_key_len,
		   CLASS_1 | KEY_DEST_CLASS_REG);

	set_jump_tgt_here(desc, key_jump_cmd);

	/* copy frame meta data (IC) to enable DSCP / ECN propagation */
	if (sa->dscp_copy || sa->ecn_copy) {
		/* save location of ptr copy commands to update offset later */
		copy_ptr_index = desc_len(desc);
		build_meta_data_desc_cmds(sa, sa->dpa_ipsec->sec_era, 64);
	}

	if (bytes_to_copy == 0)
		goto skip_byte_copy;

	/* Copy L2 header from the original packet to the outer packet */

	/* ld: deco-deco-ctrl len=0 offs=8 imm -auto-nfifo-entries */
	append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

	/* seqfifold: both msgdata-last2-last1-flush1 len=4 */
	append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_TYPE_MSG |
			     FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

	/* ld: deco-deco-ctrl len=0 offs=4 imm +auto-nfifo-entries */
	append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* move: ififo->deco-alnblk -> ofifo, len=4 */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | bytes_to_copy);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, bytes_to_copy);

	/* Done coping L2 header from the original packet to the outer packet */

skip_byte_copy:

	if (sa->enable_stats)
		build_stats_descriptor_part(sa, pdb_len);

	/* Protocol specific operation */
	append_operation(desc, OP_PCLID_IPSEC |
			 get_ipsec_op_type(sa->sa_dir) |
			 sa->cipher_data.cipher_type | sa->auth_data.auth_type);

	if (sa->enable_stats)
		save_stats_in_external_mem(sa);

	if (sa->dscp_copy || sa->ecn_copy)
		/* insert cmds to copy SEQ_IN/OUT_PTR - with updated offset */
		insert_ptr_copy_cmds(desc, copy_ptr_index,
				     desc_len(desc), false);

	if (desc_len(desc) >= MAX_CAAM_SHARED_DESCSIZE) {
		if (sa->enable_stats)
			memset((uint8_t *)desc + sa->stats_offset, 0,
				MAX_CAAM_DESCSIZE * sizeof(u32) -
				sa->stats_offset);
		return -EPERM;
	}

	return 0;
}

/* Move size should be set to 64 bytes */
int built_encap_extra_material(struct dpa_ipsec_sa *sa,
			       dma_addr_t auth_key_dma,
			       dma_addr_t crypto_key_dma,
			       unsigned int move_size)
{
	uint32_t *extra_cmds, *padding_jump, *key_jump_cmd;
	uint32_t len, off_b, off_w, off, opt;
	unsigned char job_desc_len, block_size;

	/*
	 * sec_desc_extra_cmds is the address were the first SEC extra command
	 * is located, from here SEC will overwrite Job descriptor part. Need
	 * to insert a dummy command because the LINUX CAAM API uses first word
	 * for storing the length of the descriptor.
	 */
	extra_cmds = sa->sec_desc_extra_cmds - 1;

	/*
	 * Dummy command - will not be executed at all. Only for setting to 1
	 * the length of the extra_cmds descriptor so that first extra material
	 * command will be located exactly at sec_desc_extra_cmds address.
	 */
	append_cmd(extra_cmds, 0xdead0000);

	/* Start Extra Material Group 1 */
	/* Load from the input address 64 bytes into internal register */
	/* load the data to be moved - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_load(extra_cmds, DUMMY_PTR_VAL, len, opt | off);

	/* Wait to finish previous operation */
	opt = JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT);
	append_jump(extra_cmds, opt);

	/* Store the data to the output FIFO - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_store(extra_cmds, DUMMY_PTR_VAL, len, opt | off);

	/* Fix LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off = 0x80 << LDST_OFFSET_SHIFT; /* NON_SEQ LIODN */
	append_cmd(extra_cmds, CMD_LOAD | opt | off);

	/* MATH0 += 1 (packet counter) */
	append_math_add(extra_cmds, REG0, REG0, ONE, MATH_LEN_8BYTE);

	/* Overwrite the job-desc location (word 51 or 53) with the second
	 * group (10 words) */
	job_desc_len = sa->job_desc_len;
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF | MOVE_WAITCOMP;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (10 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(extra_cmds, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Jump to the beginning of the JOB Descriptor to start executing
	 * the extra material group 2
	 */
	append_cmd(extra_cmds, 0xa00000f6);

	/* End of Extra Material Group 1 */

	/* Start Extra Material Group 2 */
	/* MATH REG 2 = Sequence in length + 2; 2 for pad-len and NH field */
	append_math_add_imm_u32(extra_cmds, REG2, SEQINLEN, IMM, 2);

	switch (sa->cipher_data.cipher_type) {
	case OP_PCL_IPSEC_3DES:
		block_size = 8; /* block size in bytes */
		break;
	case OP_PCL_IPSEC_AES_CBC:
	case OP_PCL_IPSEC_AES_CTR:
	case OP_PCL_IPSEC_AES_XTS:
	case OP_PCL_IPSEC_AES_CCM8:
	case OP_PCL_IPSEC_AES_CCM12:
	case OP_PCL_IPSEC_AES_CCM16:
	case OP_PCL_IPSEC_AES_GCM8:
	case OP_PCL_IPSEC_AES_GCM12:
	case OP_PCL_IPSEC_AES_GCM16:
		block_size = 16; /* block size in bytes */
		break;
	default:
		pr_crit("Invalid cipher algorithm for SA %d\n", sa->id);
		return -EINVAL;
	}

	/* Adding padding to byte counter */
	append_math_and_imm_u32(extra_cmds, REG3, REG2, IMM, block_size - 1);

	/* Previous operation result is 0 i.e padding added to bytes count */
	padding_jump = append_jump(extra_cmds, CLASS_BOTH | JUMP_TEST_ALL |
				   JUMP_COND_MATH_Z);

	/* MATH REG 2 = MATH REG 2 + 1 */
	append_math_add(extra_cmds, REG2, REG2, ONE, MATH_LEN_4BYTE);

	/* jump back to adding padding i.e jump back 4 words */
	off = (-4) & 0x000000FF;
	append_jump(extra_cmds, (off << JUMP_OFFSET_SHIFT));

	set_jump_tgt_here(extra_cmds, padding_jump);
	/* Done adding padding to byte counter */

	/*
	 * Perform 32-bit left shift of DEST and concatenate with left 32 bits
	 * of SRC1 i.e MATH REG 2 = 0x00bytecount_00000000
	 */
	append_math_shld(extra_cmds, REG2, REG0, REG2, MATH_LEN_8BYTE);

	/* MATH REG 0  = MATH REG 0 + MATH REG 2 */
	append_math_add(extra_cmds, REG0, REG0, REG2, MATH_LEN_8BYTE);

	/*
	 * Overwrite the job-desc location (word 51 or 53) with the third
	 * group (11 words)
	 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF | MOVE_WAITCOMP;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (11 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(extra_cmds, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Jump to the beginning of the JOB Descriptor to start executing
	 * the extra material group 3. The command for jumping back is already
	 * here from extra material group 1
	 */

	/* End of Extra Material Group 2 */

	/* Start Extra Material Group 3 */

	if (sa->enable_stats) {
		/* Store statistics in the CAAM internal descriptor */
		off_b = sa->stats_indx * CAAM_CMD_SZ;
		append_move(extra_cmds, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF |
			    (off_b << MOVE_OFFSET_SHIFT) |
			    sizeof(uint64_t));
	} else {
		/* Statistics are disabled. Do not update descriptor counter */
		append_cmd(extra_cmds, 0xA0000001); /* NOP for SEC */
	}

	/* Key jump */
	key_jump_cmd = append_jump(extra_cmds, CLASS_BOTH | JUMP_TEST_ALL |
				   JUMP_COND_SHRD);

	/* check whether a split of a normal key is used */
	if (sa->auth_data.split_key_len)
		/* Append split authentication key */
		append_key(extra_cmds, auth_key_dma,
			   sa->auth_data.split_key_len,
			   CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else
		/* Append normal authentication key */
		append_key(extra_cmds, auth_key_dma, sa->auth_data.auth_key_len,
			   CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	append_key(extra_cmds, crypto_key_dma, sa->cipher_data.cipher_key_len,
		   CLASS_1 | KEY_DEST_CLASS_REG);

	set_jump_tgt_here(extra_cmds, key_jump_cmd);

	/* Protocol specific operation */
	append_operation(extra_cmds, OP_PCLID_IPSEC | OP_TYPE_ENCAP_PROTOCOL |
			 sa->cipher_data.cipher_type | sa->auth_data.auth_type);

	if (sa->enable_stats) {
		/*
		 * Store command: in the case of the Descriptor Buffer the
		 * length is specified in 4-byte words, but in all other cases
		 * the length is specified in bytes. Offset in 4 byte words
		 */
		off_w = sa->stats_indx;
		append_store(extra_cmds, 0, DPA_IPSEC_STATS_LEN,
			     LDST_CLASS_DECO | (off_w << LDST_OFFSET_SHIFT) |
			     LDST_SRCDST_WORD_DESCBUF_SHARED);
	} else {
		/* Do not store lifetime counter in external memory */
		append_cmd(extra_cmds, 0xA0000001); /* NOP for SEC */
	}

	/* Jump with CALM to be sure previous operation was finished */
	append_jump(extra_cmds, JUMP_TYPE_HALT_USER | JUMP_COND_CALM);

	/* End of Extra Material Group 3 */

	return 0;
}

/* Move size should be set to 64 bytes */
void built_decap_extra_material(struct dpa_ipsec_sa *sa,
			       dma_addr_t auth_key_dma,
			       dma_addr_t crypto_key_dma)
{
	uint32_t *extra_cmds;
	uint32_t off_b, off_w, data;

	/*
	 * sec_desc_extra_cmds is the address were the first SEC extra command
	 * is located, from here SEC will overwrite Job descriptor part. Need
	 * to insert a dummy command because the LINUX CAAM API uses first word
	 * for storing the length of the descriptor.
	 */
	extra_cmds = sa->sec_desc_extra_cmds - 1;

	/*
	 * Dummy command - will not be executed at all. Only for setting to 1
	 * the length of the extra_cmds descriptor so that first extra material
	 * command will be located exactly at sec_desc_extra_cmds address.
	 */
	append_cmd(extra_cmds, 0xdead0000);

	data = 16;
	append_math_rshift_imm_u64(extra_cmds, REG2, REG2, IMM, data);

	/* math: (math1 - math2)->math1 len=8 */
	append_math_sub(extra_cmds, REG1, REG1, REG2, MATH_LEN_8BYTE);

	/* math: (math0 + 1)->math0 len=8 */
	append_math_add(extra_cmds, REG0, REG0, ONE, MATH_LEN_8BYTE);

	append_math_shld(extra_cmds, REG1, REG0, REG1, MATH_LEN_8BYTE);

	append_math_add(extra_cmds, REG0, REG0, REG1, MATH_LEN_8BYTE);

	append_cmd(extra_cmds, 0x7883c824);

	/* Store in the descriptor but not in external memory */
	off_b = sa->stats_offset;
	append_move(extra_cmds, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF |
		    MOVE_WAITCOMP | (off_b << MOVE_OFFSET_SHIFT) | sizeof(u64));

	append_cmd(extra_cmds, 0xa70040fe);

	append_cmd(extra_cmds, 0xa00000f7);

	/* check whether a split of a normal key is used */
	if (sa->auth_data.split_key_len)
		/* Append split authentication key */
		append_key(extra_cmds, auth_key_dma,
			   sa->auth_data.split_key_len,
			   CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else
		/* Append normal authentication key */
		append_key(extra_cmds, auth_key_dma, sa->auth_data.auth_key_len,
			   CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	append_key(extra_cmds, crypto_key_dma, sa->cipher_data.cipher_key_len,
		   CLASS_1 | KEY_DEST_CLASS_REG);

	/* Protocol specific operation */
	append_operation(extra_cmds, OP_PCLID_IPSEC | OP_TYPE_DECAP_PROTOCOL |
			 sa->cipher_data.cipher_type | sa->auth_data.auth_type);

	/*
	 * Store command: in the case of the Descriptor Buffer the length
	 * is specified in 4-byte words, but in all other cases the length
	 * is specified in bytes. Offset in 4 byte words
	 */
	off_w = sa->stats_indx;
	append_store(extra_cmds, 0, DPA_IPSEC_STATS_LEN,
		     LDST_CLASS_DECO | (off_w << LDST_OFFSET_SHIFT) |
		     LDST_SRCDST_WORD_DESCBUF_SHARED);

	append_jump(extra_cmds, JUMP_TYPE_HALT_USER | JUMP_COND_CALM);
}

int build_extended_encap_shared_descriptor(struct dpa_ipsec_sa *sa,
				     dma_addr_t auth_key_dma,
				     dma_addr_t crypto_key_dma,
				     uint32_t bytes_to_copy,
				     int sec_era)
{
	uint32_t *desc, *no_sg_jump, *extra_cmds;
	uint32_t len, off_b, off_w, opt, stats_off_b, sg_mask;
	struct device *jrdev;
	unsigned int extra_cmds_len;
	unsigned char job_desc_len;
	dma_addr_t dma_extra_cmds;
	int ret;

	desc = (uint32_t *)sa->sec_desc->desc;

	if (sec_era == 2) {
		if (sa->enable_stats)
			sa->stats_indx = 27;
		sa->next_cmd_indx = 29;
	} else {
		if (sa->enable_stats)
			sa->stats_indx = 28;
		sa->next_cmd_indx = 30;
	}

	/* This code only works when SEC is configured to use PTR on 64 bit
	 * so the Job Descriptor length is 13 words long when DPOWRD is set */
	job_desc_len = 13;

	/* Set CAAM Job Descriptor length */
	sa->job_desc_len = job_desc_len;

	/* Set lifetime counter stats offset */
	sa->stats_offset = sa->stats_indx * sizeof(uint32_t);

	ret = built_encap_extra_material(sa, auth_key_dma, crypto_key_dma, 64);
	if (ret < 0) {
		log_err("Failed to create extra CAAM commands\n");
		return -EAGAIN;
	}

	extra_cmds = sa->sec_desc_extra_cmds - 1;
	extra_cmds_len = desc_len(extra_cmds) - 1;

	/* get the jr device  */
	jrdev = get_jrdev(sa->dpa_ipsec);
	if (!jrdev) {
		log_err("Failed to get the job ring device, check the dts\n");
		return -EINVAL;
	}

	dma_extra_cmds = dma_map_single(jrdev, sa->sec_desc_extra_cmds,
					extra_cmds_len * sizeof(uint32_t),
					DMA_TO_DEVICE);
	if (!dma_extra_cmds) {
		log_err("Could not DMA map extra CAAM commands\n");
		return -ENXIO;
	}

	init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL,
			 (sa->next_cmd_indx - 1) * sizeof(uint32_t));

	if (sec_era == 2) {
		/* disable iNFO FIFO entries for p4080rev2 & ??? */
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 * Offset refers to SRC
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_CLASS1INFIFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_TYPE_MSG |
				     FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
				     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				 extra_cmds_len * sizeof(uint32_t),
				 FIFOLD_TYPE_MSG | FIFOLD_CLASS_BOTH |
				 FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_LAST2 |
				 FIFOLD_TYPE_FLUSH1);

		/* enable iNFO FIFO entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);
	} else {
		/* ????? */
		opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | opt | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_INFIFO_NOINFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes. No information FIFO entry even if automatic
		 * iNformation FIFO entries are enabled.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_CLASS_BOTH |
				     FIFOLD_TYPE_NOINFOFIFO);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				 extra_cmds_len * sizeof(uint32_t),
				 FIFOLD_CLASS_BOTH | FIFOLD_TYPE_NOINFOFIFO);
	}

	/*
	 * throw away the first part of the S/G table and keep only the buffer
	 * address;
	 * offset = undefined memory after MATH3; Refers to the destination.
	 * len = 41 bytes to discard
	 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 8 << MOVE_OFFSET_SHIFT;
	len   = 41 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/* put the buffer address (still in the IN FIFO) in MATH2 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 0 << MOVE_OFFSET_SHIFT;
	len   = 8 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/* copy 15 bytes starting at 4 bytes before the OUT-PTR-CMD in
	 * the job-desc into math1
	 * i.e. in the low-part of math1 we have the out-ptr-cmd and
	 * in the math2 we will have the address of the out-ptr
	 */
	opt = MOVE_SRC_DESCBUF | MOVE_DEST_MATH1;
	off_b = (MAX_CAAM_DESCSIZE - job_desc_len + PTR_LEN) * sizeof(uint32_t);
	len = (8 + 4 * PTR_LEN - 1) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Copy 7 bytes of the in-ptr into math0 */
	opt   = MOVE_SRC_DESCBUF | MOVE_DEST_MATH0;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len + 1 + 3 + 2 * PTR_LEN;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * the SEQ OUT PTR command is now in math reg 1, so the SGF bit can be
	 * checked using a math command;
	 */
	sg_mask = SEQ_OUT_PTR_SGF_MASK;
	append_math_and_imm_u32(desc, NONE, REG1, IMM, sg_mask);

	opt = CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_COND_MATH_Z | JUMP_TEST_ALL;
	no_sg_jump = append_jump(desc, opt);

	append_math_add(desc, REG2, ZERO, REG3, MATH_LEN_8BYTE);

	/* update no S/G jump location */
	set_jump_tgt_here(desc, no_sg_jump);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, bytes_to_copy);

	/* move: ififo->deco-alnblk -> ofifo, len=4 */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | bytes_to_copy);

	/* Overwrite the job-desc location (word 51 or 53) with the first
	 * group (11 words)*/
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (11 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math0 (input address) to words 52+53 or 54+56
	 * depending where the Job Descriptor starts.
	 * They will be used later by the load command.
	 */
	opt = MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len + 1; /* 52 + 53 or 54 + 55 */
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math2 (output address) to words 56+57 or 58+59
	 * depending where the Job Descriptor starts.
	 * They will be used later by the store command.
	 */
	opt = MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len + 5; /* 56 + 57 or 58 + 59 */
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Fix LIODN - OFFSET[0:1] - 01 = SEQ LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off_b = 0x40; /* SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | (off_b << LDST_OFFSET_SHIFT));

	/* Copy the context of the counters from word 29 into math0 */
	/* Copy from descriptor to MATH REG 0 the current statistics */
	stats_off_b = sa->stats_indx * CAAM_CMD_SZ;
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 |
		    (stats_off_b << MOVE_OFFSET_SHIFT) | sizeof(uint64_t));

	dma_unmap_single(sa->dpa_ipsec->jrdev, dma_extra_cmds,
			 extra_cmds_len * sizeof(uint32_t), DMA_TO_DEVICE);

	return 0;
}

int build_extended_decap_shared_descriptor(struct dpa_ipsec_sa *sa,
					   dma_addr_t auth_key_dma,
					   dma_addr_t crypto_key_dma,
					   uint32_t bytes_to_copy,
					   uint8_t move_size,
					   int sec_era)
{
	uint32_t *desc, *no_sg_jump, *extra_cmds;
	uint32_t len, off_b, off_w, opt, stats_off_b, sg_mask, extra_cmds_len,
		 esp_length, iv_length, icv_length, max_pad, data;
	dma_addr_t dma_extra_cmds;
	struct device *jrdev;

	desc = (uint32_t *)sa->sec_desc->desc;

	/* CAAM hdr cmd + PDB size in words */
	sa->next_cmd_indx =
		sizeof(struct ipsec_decap_pdb) / sizeof(uint32_t) + 1;
	if (sa->enable_stats) {
		sa->stats_indx = sa->next_cmd_indx;
		sa->next_cmd_indx += 2;
		if (sec_era != 2) {
			sa->stats_indx += 1;
			sa->next_cmd_indx += 1;
		}
	}

	/* Set lifetime counter stats offset */
	sa->stats_offset = sa->stats_indx * sizeof(uint32_t);

	built_decap_extra_material(sa, auth_key_dma, crypto_key_dma);

	extra_cmds = sa->sec_desc_extra_cmds - 1;
	extra_cmds_len = desc_len(extra_cmds) - 1;

	/* get the jr device  */
	jrdev = get_jrdev(sa->dpa_ipsec);
	if (!jrdev) {
		log_err("Failed to get the job ring device, check the dts\n");
		return -EINVAL;
	}

	dma_extra_cmds = dma_map_single(jrdev, sa->sec_desc_extra_cmds,
					extra_cmds_len * sizeof(uint32_t),
					DMA_TO_DEVICE);
	if (!dma_extra_cmds) {
		log_err("Could not DMA map extra CAAM commands\n");
		return -ENXIO;
	}

	init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL,
			 (sa->next_cmd_indx - 1) * sizeof(uint32_t));

	if (sec_era == 2) {
		/* disable iNFO FIFO entries for p4080rev2 & ??? */
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 * Offset refers to SRC
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_CLASS1INFIFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_TYPE_MSG |
				     FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
				     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				 extra_cmds_len * sizeof(uint32_t),
				 FIFOLD_TYPE_MSG | FIFOLD_CLASS_BOTH |
				 FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_LAST2 |
				 FIFOLD_TYPE_FLUSH1);

		/* enable iNFO FIFO entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);
	} else {
		/* ????? */
		opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | opt | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_INFIFO_NOINFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes. No information FIFO entry even if automatic
		 * iNformation FIFO entries are enabled.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_CLASS_BOTH |
				     FIFOLD_TYPE_NOINFOFIFO);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				 extra_cmds_len * sizeof(uint32_t),
				 FIFOLD_CLASS_BOTH | FIFOLD_TYPE_NOINFOFIFO);
	}

	/*
	 * throw away the first part of the S/G table and keep only the buffer
	 * address;
	 * offset = undefined memory after MATH3; Refers to the destination.
	 * len = 41 bytes to discard
	 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 8 << MOVE_OFFSET_SHIFT;
	len   = 41 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/* put the buffer address (still in the IN FIFO) in MATH2 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 0 << MOVE_OFFSET_SHIFT;
	len   = 8 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/*
	 * Copy 15 bytes starting at 4 bytes before the OUT-PTR-CMD in
	 * the job-desc into math1
	 * i.e. in the low-part of math1 we have the out-ptr-cmd and
	 * in the math2 we will have the address of the out-ptr
	 */
	opt = MOVE_SRC_DESCBUF | MOVE_DEST_MATH1;
	off_b = (50 + 1 * PTR_LEN) * sizeof(uint32_t);
	len = (8 + 4 * PTR_LEN - 1) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Copy 7 bytes of the in-ptr into math0 */
	opt   = MOVE_SRC_DESCBUF | MOVE_DEST_MATH0;
	off_w = 50 + 1 + 3 + 2 * PTR_LEN;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * the SEQ OUT PTR command is now in math reg 1, so the SGF bit can be
	 * checked using a math command;
	 */
	sg_mask = SEQ_OUT_PTR_SGF_MASK;
	append_math_and_imm_u32(desc, NONE, REG1, IMM, sg_mask);

	opt = CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_COND_MATH_Z | JUMP_TEST_ALL;
	no_sg_jump = append_jump(desc, opt);

	append_math_add(desc, REG2, ZERO, REG3, MATH_LEN_8BYTE);

	/* update no S/G jump location */
	set_jump_tgt_here(desc, no_sg_jump);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, bytes_to_copy);

	/* move: ififo->deco-alnblk -> ofifo, len */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | bytes_to_copy);

	/* Overwrite the job-desc location (word 50) with the first
	 * group (10 words)*/
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF;
	off_w = 50;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (10 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math0 (input address) to words 32+33
	 * They will be used later by the load command.
	 */
	opt = MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF;
	off_w = 32;
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math2 (output address) to words 56+57 or 58+59
	 * depending where the Job Descriptor starts.
	 * They will be used later by the store command.
	 */
	opt = MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF | MOVE_WAITCOMP;
	off_w = 36;
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Fix LIODN - OFFSET[0:1] - 01 = SEQ LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off_b = 0x40; /* SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | (off_b << LDST_OFFSET_SHIFT));

	/* Load from the input address 64 bytes into internal register */
	/* load the data to be moved - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off_b = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_load(desc, DUMMY_PTR_VAL, len, opt | off_b);

	/* Wait to finish previous operation */
	opt = JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT);
	append_jump(desc, opt);

	/* Store the data to the output FIFO - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off_b = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_store(desc, DUMMY_PTR_VAL, len, opt | off_b);

	/* Fix LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off_b = 0x80 << LDST_OFFSET_SHIFT; /* NON_SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | off_b);

	/* Copy from descriptor to MATH REG 0 the current statistics */
	stats_off_b = sa->stats_indx * CAAM_CMD_SZ;
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | MOVE_WAITCOMP |
		    (stats_off_b << MOVE_OFFSET_SHIFT) | sizeof(uint64_t));

	/* Remove unnecessary headers
	 * MATH1 = 0 - (esp_length + iv_length + icv_length) */
	esp_length = 8; /* SPI + SEQ NUM */
	get_cipher_params(sa->alg_suite, &iv_length, &icv_length, &max_pad);
	data = (uint32_t) (esp_length + iv_length + icv_length);
	append_math_sub_imm_u64(desc, REG1, ZERO, IMM, data);

	/* MATH1 += SIL (bytes counter) */
	append_math_add(desc, REG1, SEQINLEN, REG1, MATH_LEN_8BYTE);

	/* data = outer IP header - should be read from DPOVRD register
	 * MATH 2 = outer IP header length */
	data = cpu_to_caam32(20);
	opt = LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH2;
	len = sizeof(data) << LDST_LEN_SHIFT;
	append_load_as_imm(desc, &data, len, opt);

	off_w = 7;
	append_jump(desc, (off_w << JUMP_OFFSET_SHIFT));

	/* jump: all-match[] always-jump offset=0 local->[00] */
	append_jump(desc, (0 << JUMP_OFFSET_SHIFT));

	/* jump: all-match[] always-jump offset=0 local->[00] */
	append_jump(desc, (0 << JUMP_OFFSET_SHIFT));

	data = 0x00ff0000;
	append_math_and_imm_u64(desc, REG2, DPOVRD, IMM, data);

	dma_unmap_single(sa->dpa_ipsec->jrdev, dma_extra_cmds,
			 extra_cmds_len * sizeof(uint32_t), DMA_TO_DEVICE);

	return 0;
}


int create_sec_descriptor(struct dpa_ipsec_sa *sa)
{
	struct sec_descriptor *sec_desc;
	struct device *jrdev;
	dma_addr_t auth_key_dma;
	dma_addr_t crypto_key_dma;
	int ret = 0;

	/* get the jr device  */
	jrdev = get_jrdev(sa->dpa_ipsec);
	if (!jrdev) {
		log_err("Failed to get the job ring device, check the dts\n");
		return -EINVAL;
	}

	/* check whether a split of a normal key is used */
	if (sa->auth_data.split_key_len)
		auth_key_dma = dma_map_single(jrdev, sa->auth_data.split_key,
					      sa->auth_data.split_key_pad_len,
					      DMA_TO_DEVICE);
	else
		auth_key_dma = dma_map_single(jrdev, sa->auth_data.auth_key,
					      sa->auth_data.auth_key_len,
					      DMA_TO_DEVICE);
	if (!auth_key_dma) {
		log_err("Could not DMA map authentication key\n");
		return -EINVAL;
	}

	crypto_key_dma = dma_map_single(jrdev, sa->cipher_data.cipher_key,
					sa->cipher_data.cipher_key_len,
					DMA_TO_DEVICE);
	if (!crypto_key_dma) {
		log_err("Could not DMA map cipher key\n");
		return -EINVAL;
	}

	/*
	 * Build the shared descriptor and see if its length is less than
	 * 64 words. If build_shared_descriptor returns -EPERM than it is
	 * required to build the extended shared descriptor in order to have
	 * all the SA features that were required.
	 */
	ret = build_shared_descriptor(sa, auth_key_dma, crypto_key_dma,
				      sa->l2_hdr_size);
	switch (ret) {
	case 0:
		sa->sec_desc_extended = false;
		goto done_shared_desc;
	case -EPERM:
		sa->sec_desc_extended = true;
		goto build_extended_shared_desc;
	default:
		log_err("Failed to create SEC descriptor for SA %d\n", sa->id);
		return -EFAULT;
	}

build_extended_shared_desc:
	/* Build the extended shared descriptor */
	if (sa->sa_dir == DPA_IPSEC_INBOUND)
		ret = build_extended_decap_shared_descriptor(sa, auth_key_dma,
				crypto_key_dma, sa->l2_hdr_size, 64,
				sa->dpa_ipsec->sec_era);
	else
		ret = build_extended_encap_shared_descriptor(sa, auth_key_dma,
				crypto_key_dma, sa->l2_hdr_size,
				sa->dpa_ipsec->sec_era);
	if (ret < 0) {
		log_err("Failed to create SEC descriptor for SA %d\n", sa->id);
		return -EFAULT;
	}

done_shared_desc:
	sec_desc = sa->sec_desc;
	/* setup preheader */
	PREHEADER_PREP_IDLEN(sec_desc->preheader, desc_len(sec_desc->desc));
	PREHEADER_PREP_BPID(sec_desc->preheader, sa->sa_bpid);
	PREHEADER_PREP_BSIZE(sec_desc->preheader, sa->sa_bufsize);
	if (sa->sa_dir == DPA_IPSEC_INBOUND)
		PREHEADER_PREP_OFFSET(sec_desc->preheader,
			sa->dpa_ipsec->config.post_sec_in_params.data_off);
	else
		PREHEADER_PREP_OFFSET(sec_desc->preheader,
			sa->dpa_ipsec->config.post_sec_out_params.data_off);

	sec_desc->preheader = cpu_to_caam64(sec_desc->preheader);

	dma_unmap_single(jrdev, auth_key_dma,
			 sa->auth_data.split_key_pad_len, DMA_TO_DEVICE);
	dma_unmap_single(jrdev, crypto_key_dma,
			 sa->cipher_data.cipher_key_len, DMA_TO_DEVICE);
	return 0;
}

/*
 * Create descriptor for updating the anti replay window size
 * [21] B0951A1D       jobhdr: shrsz=21 shr share=serial reo len=29
 * [22] 00000000               sharedesc->@0x029a9a608
 * [23] 29A9A608
 * [24] 79340008         move: descbuf+0[00] -> math0, len=8 wait
 * [25] A82CC108         math: (0 - 1)->math1 len=8
 * [26] AC214108         math: (math1 - imm1)->math1 len=8 ifb
 * [27] 000000C0               imm1=192
 * [28] A8501008         math: (math0 & math1)->math0 len=8
 * [29] 1640180A           ld: deco-descbuf len=10 offs=24
 * [30] 00000000               ptr->@0x02965ca34
 * [31] 2965CA34
 * [32] A1001001         jump: jsl1 all-match[calm] offset=1 local->[33]
 * [33] A00000F7         jump: all-match[] always-jump offset=-9 local->[24]
 * [34] AC404008         math: (math0 | imm1)->math0 len=8 ifb
 * [35] 000000C0               imm1=192
 * [36] 79430008         move: math0 -> descbuf+0[00], len=8 wait
 * [37] 79631804         move: math2 -> descbuf+24[06], len=4 wait
 * [38] 56420107          str: deco-shrdesc+1 len=7
 * [39] 16401806           ld: deco-descbuf len=6 offs=24
 * [40] 00000000               ptr->@0x02965ca5c
 * [41] 2965CA5C
 * [42] A1001001         jump: jsl1 all-match[calm] offset=1 local->[43]
 * [43] A00000F7         jump: all-match[] always-jump offset=-9 local->[34]
 * [44] 16860800           ld: deco-ctrl len=0 offs=8 imm -auto-nfifo-entries
 * [45] 2E17000A    seqfifold: both msgdata-last2-last1-flush1 len=10
 * [46] 16860400           ld: deco-ctrl len=0 offs=4 imm +auto-nfifo-entries
 * [47] 7882000A         move: ififo->deco-alnblk -> ofifo, len=10
 * [48] 6830000A   seqfifostr: msgdata len=10
 * [49] A1C01002         jump: jsl1 all-match[calm] halt-user status=2
 *
 * The msg_len represent the length of the message written in the output frame
 * in order to differentiate between modify operations
 */
int build_rjob_desc_ars_update(struct dpa_ipsec_sa *sa, enum dpa_ipsec_arw arw,
			       u32 msg_len)
{
	uint32_t *desc, *rjobd, off;
	uint8_t options;
	enum dpa_ipsec_arw c_arw;
	size_t ars_off;
	dma_addr_t dma_shdesc;

	/* Check input parameters */
	BUG_ON(!sa);
	BUG_ON(!sa->sec_desc);
	desc = (uint32_t *)sa->sec_desc->desc;
	options = (uint8_t)(be32_to_cpu(*(desc + 1)) & 0x000000FF);
	c_arw = options >> 6;
	if (c_arw == arw) {
		log_err("SA %d has already set this ARS %d\n", sa->id, arw);
		return -EALREADY;
	}

	/* Get DMA address for this SA shared descriptor */
	dma_shdesc = dma_map_single(sa->dpa_ipsec->jrdev, sa->sec_desc->desc,
				    desc_len(sa->sec_desc->desc) * sizeof(u32),
				    DMA_BIDIRECTIONAL);
	if (!dma_shdesc) {
		log_err("Failed DMA map shared descriptor for SA %d\n", sa->id);
		return -ENXIO;
	}

	/* Create replacement job descriptor for ARS update */
	BUG_ON(!sa->rjob_desc);
	rjobd = sa->rjob_desc;

	init_job_desc(rjobd, HDR_SHARE_SERIAL | HDR_SHARED | HDR_REVERSE |
		      (desc_len(sa->sec_desc->desc) << HDR_START_IDX_SHIFT));

	/* Set DMA address of the shared descriptor */
	append_ptr(rjobd, dma_shdesc);

	/* Retrieve header and options from PDB in MATH 0 */
	append_move(rjobd, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | MOVE_WAITCOMP |
		    (0 << MOVE_OFFSET_SHIFT) | sizeof(u64));

	/* MATH_REG1 = 0xFFFFFFFF_FFFFFFFF */
	append_math_sub(rjobd, REG1, ZERO, ONE, MATH_LEN_8BYTE);

	/* MATH_REG1 = 0xFFFFFFFF_FFFFFF3F */
	append_math_sub_imm_u64(rjobd, REG1, REG1, IMM, 0xC0);

	/* Reset ARS bits */
	append_math_and(rjobd, REG0, REG0, REG1, MATH_LEN_8BYTE);

	/*
	 * Overwrite RJD immediately after the SHD pointer i.e shared descriptor
	 * length plus 1 plus another 3 words
	 * Offset and length are expressed in words
	 * 3w - RJD header + SHD pointer
	 * 5w - five instructions for doing some part of ARS modification
	 * 3w - load instruction + pointer
	 * 1w - jump calm
	 * 1w - jump back to the remaining descriptor
	 */
	append_load(rjobd, virt_to_phys((void *)(rjobd + 3 + 5 + 3 + 1 + 1)),
		    10, LDST_CLASS_DECO | LDST_SRCDST_WORD_DESCBUF |
		    ((desc_len(sa->sec_desc->desc) + 3) << LDST_OFFSET_SHIFT));

	/* wait for completion o previous operation */
	append_jump(rjobd, JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT));

	/* jump back to remaining descriptor i.e jump back 9 words */
	off = (-9) & 0x000000FF;
	append_jump(rjobd, (off << JUMP_OFFSET_SHIFT));

	/* Convert PDB ARS to new size */
	switch (arw) {
	case DPA_IPSEC_ARSNONE:
		/*
		 * nothing to do because previous command reseted ARS bits
		 * add 2 NOPs to conserve descriptor size
		 */
		append_cmd(rjobd, 0xA0000001); /* NOP for SEC */
		append_cmd(rjobd, 0xA0000001); /* NOP for SEC */
		break;
	case DPA_IPSEC_ARS32:
		append_math_or_imm_u64(rjobd, REG0, REG0, IMM,
				       PDBOPTS_ESP_ARS32);
		break;
	case DPA_IPSEC_ARS64:
		append_math_or_imm_u64(rjobd, REG0, REG0, IMM,
				       PDBOPTS_ESP_ARS64);
		break;
	default:
		log_err("Invalid ARS\n");
		BUG();
	}

	/* Put header and options back to PDB */
	append_move(rjobd, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF | MOVE_WAITCOMP |
		    (0 << MOVE_OFFSET_SHIFT) | sizeof(u64));

	/*
	 * anti_replay[0] - used for 32ARS - LS bit represent the frame with
	 * highest SEQ number that has been successfully authenticated so far
	 * i.e the frame that had SEQ/ESN from PDB seq_num/seq_num_ext_hi
	 *
	 * anti_replay[1] - used when 64ARS is configured - LS bit represent
	 * a frame with a immediate older SEQ number than the MS bit of the
	 * anti_replay[0] i.e
	 * SEQ(LS bit of anti_replay[1]) = SEQ(MS bit of anti_replay[0]) - 1;
	 *
	 * always reset to 0 all bits from anti_replay[1]
	 * reset to 0 all bits from anti_replay[0] only if updating from ARS to
	 * no ARS.
	 * MOVE_SRC_MATH2 was not used until now i.e has value 0
	 */
	ars_off = offsetof(struct ipsec_decap_pdb, anti_replay);
	if (arw == DPA_IPSEC_ARSNONE)
		append_move(rjobd, MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF |
			    MOVE_WAITCOMP | (ars_off << MOVE_OFFSET_SHIFT) |
			    sizeof(u64));
	else
		append_move(rjobd, MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF |
			    MOVE_WAITCOMP |
			    ((ars_off + 4) << MOVE_OFFSET_SHIFT) | sizeof(u32));

	/*
	 * Update shared descriptor in memory - only PDB
	 * special case - offset and length are in words
	 */
	append_store(rjobd, 0, sizeof(struct ipsec_decap_pdb) / sizeof(u32),
		     LDST_CLASS_DECO | (1 << LDST_OFFSET_SHIFT) |
		     LDST_SRCDST_WORD_DESCBUF_SHARED);

	append_load(rjobd,
		    virt_to_phys((void *)(rjobd + 3 + 5 + 3 + 1 + 1 + 10)), 6,
		    LDST_CLASS_DECO | LDST_SRCDST_WORD_DESCBUF |
		    ((desc_len(sa->sec_desc->desc) + 3) << LDST_OFFSET_SHIFT));

	/* wait for completion of the previous operation */
	append_jump(rjobd, JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT));

	/* jump back to remaining descriptor i.e jump back 9 words */
	off = (-9) & 0x000000FF;
	append_jump(rjobd, (off << JUMP_OFFSET_SHIFT));

	/* ld: deco-deco-ctrl len=0 offs=8 imm -auto-nfifo-entries */
	append_cmd(rjobd, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

	/* seqfifold: both msgdata-last2-last1-flush1 len=4 */
	append_seq_fifo_load(rjobd, msg_len, FIFOLD_TYPE_MSG |
			     FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

	/* ld: deco-deco-ctrl len=0 offs=4 imm +auto-nfifo-entries */
	append_cmd(rjobd, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* message "Modify anti replay window for SA n" */
	append_move(rjobd, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | msg_len);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(rjobd, FIFOST_TYPE_MESSAGE_DATA, msg_len);

	/*
	 * Exit replacement job descriptor, halt with user error
	 * FD status will be a special user error, generated only on request by
	 * a descriptor command (not by any other circumstance) i.e no confusing
	 * this frame for any other error. Jump with CALM to be sure previous
	 * operation was finished
	 */
	append_cmd(rjobd, 0xA1C01002);

	dma_unmap_single(sa->dpa_ipsec->jrdev, dma_shdesc,
			 desc_len(sa->sec_desc->desc) * sizeof(u32),
			 DMA_BIDIRECTIONAL);

	return 0;
}

/*
 * The SEQ number value will be placed at the address specified by SEQ pointer
 */
int build_rjob_desc_seq_read(struct dpa_ipsec_sa *sa, u32 msg_len)
{
	uint32_t *rjobd, off_b = 0, off;
	dma_addr_t dma_shdesc, out_addr;

	/* Check input parameters */
	BUG_ON(!sa);
	BUG_ON(!sa->sec_desc);

	/* Get DMA address for this SA shared descriptor */
	dma_shdesc = dma_map_single(sa->dpa_ipsec->jrdev, sa->sec_desc->desc,
				    desc_len(sa->sec_desc->desc) * sizeof(u32),
				    DMA_BIDIRECTIONAL);
	if (!dma_shdesc) {
		log_err("Failed DMA map shared descriptor for SA %d\n", sa->id);
		return -ENXIO;
	}

	/* Get DMA address for this SA shared descriptor */
	out_addr = dma_map_single(sa->dpa_ipsec->jrdev, &sa->r_seq_num,
				  sizeof(sa->r_seq_num), DMA_BIDIRECTIONAL);
	if (!out_addr) {
		log_err("Failed DMA map output address for SA %d\n", sa->id);
		dma_unmap_single(sa->dpa_ipsec->jrdev, dma_shdesc,
				 desc_len(sa->sec_desc->desc) * sizeof(u32),
				 DMA_BIDIRECTIONAL);
		return -ENXIO;
	}

	/* Create replacement job descriptor for SEQ/ESEQ Number update */
	BUG_ON(!sa->rjob_desc);
	rjobd = sa->rjob_desc;

	init_job_desc(rjobd, HDR_SHARE_SERIAL | HDR_SHARED | HDR_REVERSE |
		      (desc_len(sa->sec_desc->desc) << HDR_START_IDX_SHIFT));

	/* Set DMA address of the shared descriptor */
	append_ptr(rjobd, dma_shdesc);

	/* Retrieve SEQ number from PDB in MATH 0 - offset is in bytes */
	off_b = sa_is_inbound(sa) ?
		offsetof(struct ipsec_decap_pdb, seq_num_ext_hi) + sizeof(u32) :
		offsetof(struct ipsec_encap_pdb, seq_num_ext_hi) + sizeof(u32);

	append_move(rjobd, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | MOVE_WAITCOMP |
		    (off_b << MOVE_OFFSET_SHIFT) | sizeof(u64));

	/* Store SEQ number - length is in bytes */
	append_store(rjobd, out_addr, sizeof(sa->r_seq_num),
		     LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

	/* wait for completion of previous operation */
	append_jump(rjobd, JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT));

	/*
	 * Overwrite RJD immediately after the SHD pointer i.e shared descriptor
	 * length plus 1 plus another 3 words
	 * Offset and length are expressed in words
	 * 3w - RJD header + SHD pointer
	 * 5w - five instructions for doing some part of SEQ number modification
	 * 3w - load instruction + pointer
	 * 1w - jump calm
	 * 1w - jump back to the remaining descriptor
	 */
	append_load(rjobd, virt_to_phys((void *)(rjobd + 3 + 5 + 3 + 1 + 1)),
		    6, LDST_CLASS_DECO | LDST_SRCDST_WORD_DESCBUF |
		    ((desc_len(sa->sec_desc->desc) + 3) << LDST_OFFSET_SHIFT));

	/* wait for completion of previous operation */
	append_jump(rjobd, JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT));

	/* jump back to remaining descriptor i.e jump back 9 words */
	off = (-9) & 0x000000FF;
	append_jump(rjobd, (off << JUMP_OFFSET_SHIFT));

	/*
	 * The following instructions are used to copy the completion
	 * message into the output frame
	 */

	/* ld: deco-deco-ctrl len=0 offs=8 imm -auto-nfifo-entries */
	append_cmd(rjobd, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

	/* seqfifold: both msgdata-last2-last1-flush1 len=4 */
	append_seq_fifo_load(rjobd, msg_len, FIFOLD_TYPE_MSG |
			     FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

	/* ld: deco-deco-ctrl len=0 offs=4 imm +auto-nfifo-entries */
	append_cmd(rjobd, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* copy completion message */
	append_move(rjobd, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | msg_len);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(rjobd, FIFOST_TYPE_MESSAGE_DATA, msg_len);

	/*
	 * Exit replacement job descriptor, halt with user error
	 * FD status will be a special user error, generated only on request by
	 * a descriptor command
	 */
	append_cmd(rjobd, 0xA1C01002);

	dma_unmap_single(sa->dpa_ipsec->jrdev, dma_shdesc,
			 desc_len(sa->sec_desc->desc) * sizeof(u32),
			 DMA_BIDIRECTIONAL);

	dma_unmap_single(sa->dpa_ipsec->jrdev, out_addr,
			 sizeof(sa->r_seq_num),
			 DMA_BIDIRECTIONAL);

	return 0;
}

/*
 * The SEQ number value will be read from the SA structure and written to PDB of
 * the shared descriptor corresponding to this SA
 */
int build_rjob_desc_seq_write(struct dpa_ipsec_sa *sa, u32 msg_len)
{
	uint32_t *rjobd, off_b, off = 0;
	dma_addr_t dma_shdesc, in_addr;

	/* Check input parameters */
	BUG_ON(!sa);
	BUG_ON(!sa->sec_desc);

	/* Get DMA address for this SA shared descriptor */
	dma_shdesc = dma_map_single(sa->dpa_ipsec->jrdev, sa->sec_desc->desc,
				    desc_len(sa->sec_desc->desc) * sizeof(u32),
				    DMA_BIDIRECTIONAL);
	if (!dma_shdesc) {
		log_err("Failed DMA map shared descriptor for SA %d\n", sa->id);
		return -ENXIO;
	}

	in_addr = dma_map_single(sa->dpa_ipsec->jrdev, &sa->w_seq_num,
				 sizeof(sa->w_seq_num), DMA_BIDIRECTIONAL);
	if (!in_addr) {
		log_err("Failed DMA map output address for SA %d\n", sa->id);
		dma_unmap_single(sa->dpa_ipsec->jrdev, dma_shdesc,
				 desc_len(sa->sec_desc->desc) * sizeof(u32),
				 DMA_BIDIRECTIONAL);
		return -ENXIO;
	}

	/* Create replacement job descriptor for SEQ/ESEQ Number update */
	BUG_ON(!sa->rjob_desc);
	rjobd = sa->rjob_desc;

	init_job_desc(rjobd, HDR_SHARE_SERIAL | HDR_SHARED | HDR_REVERSE |
		      (desc_len(sa->sec_desc->desc) << HDR_START_IDX_SHIFT));

	/* Set DMA address of the shared descriptor */
	append_ptr(rjobd, dma_shdesc);

	/* Copy from SA SEQ to descriptor - offset & length is in words */
	off_b = sa_is_inbound(sa) ?
		offsetof(struct ipsec_decap_pdb, seq_num_ext_hi) + sizeof(u32) :
		offsetof(struct ipsec_encap_pdb, seq_num_ext_hi) + sizeof(u32);

	append_load(rjobd, in_addr, sizeof(sa->w_seq_num) / sizeof(u32),
		    LDST_CLASS_DECO | LDST_SRCDST_WORD_DESCBUF |
		    (off_b / sizeof(u32)) << LDST_OFFSET_SHIFT);

	/* wait for completion of previous operation */
	append_jump(rjobd, JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT));

	/*
	 * Update shared descriptor in memory - only PDB
	 * special case - offset and length are in words
	 */
	append_store(rjobd, 0, sizeof(sa->w_seq_num) / sizeof(u32),
		     LDST_CLASS_DECO |
		     (off_b / sizeof(u32) << LDST_OFFSET_SHIFT) |
		     LDST_SRCDST_WORD_DESCBUF_SHARED);

	/*
	 * Overwrite RJD immediately after the SHD pointer i.e shared descriptor
	 * length plus 1 plus another 3 words
	 * Offset and length are expressed in words
	 * 3w - RJD header + SHD pointer
	 * 5w - five instructions for doing some part of SEQ number modification
	 * 3w - load instruction + pointer
	 * 1w - jump calm
	 * 1w - jump back to the remaining descriptor
	 */
	append_load(rjobd, virt_to_phys((void *)(rjobd + 3 + 5 + 3 + 1 + 1)),
		    6, LDST_CLASS_DECO | LDST_SRCDST_WORD_DESCBUF |
		    ((desc_len(sa->sec_desc->desc) + 3) << LDST_OFFSET_SHIFT));

	/* wait for completion o previous operation */
	append_jump(rjobd, JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT));

	/* jump back to remaining descriptor i.e jump back 9 words */
	off = (-9) & 0x000000FF;
	append_jump(rjobd, (off << JUMP_OFFSET_SHIFT));

	/*
	 * The following instructions are used to copy the completion
	 * message into the output frame
	 */

	/* ld: deco-deco-ctrl len=0 offs=8 imm -auto-nfifo-entries */
	append_cmd(rjobd, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

	/* seqfifold: both msgdata-last2-last1-flush1 len=4 */
	append_seq_fifo_load(rjobd, msg_len, FIFOLD_TYPE_MSG |
			     FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

	/* ld: deco-deco-ctrl len=0 offs=4 imm +auto-nfifo-entries */
	append_cmd(rjobd, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* copy completion message */
	append_move(rjobd, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | msg_len);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(rjobd, FIFOST_TYPE_MESSAGE_DATA, msg_len);

	/*
	 * Exit replacement job descriptor, halt with user error
	 * FD status will be a special user error, generated only on request by
	 * a descriptor command (not by any other error)
	 */
	append_cmd(rjobd, 0xA1C01002);

	dma_unmap_single(sa->dpa_ipsec->jrdev, dma_shdesc,
			 desc_len(sa->sec_desc->desc) * sizeof(u32),
			 DMA_BIDIRECTIONAL);

	dma_unmap_single(sa->dpa_ipsec->jrdev, in_addr,
			 sizeof(sa->w_seq_num),
			 DMA_BIDIRECTIONAL);

	return 0;
}

static void split_key_done(struct device *dev, u32 *desc, u32 err,
			   void *context)
{
	register atomic_t *done = context;

	if (err)
		caam_jr_strstatus(dev, err);

	atomic_set(done, 1);
}

/* determine the HASH algorithm and the coresponding split key length */
int get_split_key_info(struct auth_params *auth_param, u32 *hmac_alg)
{
	/*
	 * Sizes for MDHA pads (*not* keys): MD5, SHA1, 224, 256, 384, 512
	 * Running digest size
	 */
	const u8 mdpadlen[] = {16, 20, 32, 32, 64, 64};

	switch (auth_param->auth_type) {
	case OP_PCL_IPSEC_HMAC_MD5_96:
	case OP_PCL_IPSEC_HMAC_MD5_128:
		*hmac_alg = OP_ALG_ALGSEL_MD5;
		break;
	case OP_PCL_IPSEC_HMAC_SHA1_96:
	case OP_PCL_IPSEC_HMAC_SHA1_160:
		*hmac_alg = OP_ALG_ALGSEL_SHA1;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_256_128:
		*hmac_alg = OP_ALG_ALGSEL_SHA256;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_384_192:
		*hmac_alg = OP_ALG_ALGSEL_SHA384;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_512_256:
		*hmac_alg = OP_ALG_ALGSEL_SHA512;
		break;
	case OP_PCL_IPSEC_AES_XCBC_MAC_96:
		*hmac_alg = 0;
		auth_param->split_key_len = 0;
		break;
	default:
		log_err("Unsupported authentication algorithm\n");
		return -EINVAL;
	}

	if (*hmac_alg)
		auth_param->split_key_len =
				mdpadlen[(*hmac_alg & OP_ALG_ALGSEL_SUBMASK) >>
					 OP_ALG_ALGSEL_SHIFT] * 2;

	return 0;
}

int generate_split_key(struct auth_params *auth_param)
{
	struct device *jrdev;
	dma_addr_t dma_addr_in, dma_addr_out;
	u32 *desc, timeout = 1000000, alg_sel = 0;
	struct dpa_ipsec_sa *sa;
	atomic_t done;
	int ret = 0;

	sa = container_of(auth_param, struct dpa_ipsec_sa, auth_data);
	BUG_ON(!sa->dpa_ipsec);

	ret = get_split_key_info(auth_param, &alg_sel);
	/* exit if error or there is no need to compute a split key */
	if (ret < 0 || alg_sel == 0)
		return ret;

	jrdev = get_jrdev(sa->dpa_ipsec);
	if (!jrdev) {
		log_err("Could not get job ring device, please check dts\n");
		return -ENODEV;
	}

	desc = kmalloc(CAAM_CMD_SZ * 6 + CAAM_PTR_SZ * 2, GFP_KERNEL | GFP_DMA);
	if (!desc) {
		log_err("Allocate memory failed for split key desc\n");
		return -ENOMEM;
	}

	auth_param->split_key_pad_len = ALIGN(auth_param->split_key_len, 16);

	dma_addr_in = dma_map_single(jrdev, auth_param->auth_key,
				     auth_param->auth_key_len, DMA_TO_DEVICE);
	if (dma_mapping_error(jrdev, dma_addr_in)) {
		dev_err(jrdev, "Unable to DMA map the input key address\n");
		kfree(desc);
		return -ENOMEM;
	}

	dma_addr_out = dma_map_single(jrdev, auth_param->split_key,
				      auth_param->split_key_pad_len,
				      DMA_FROM_DEVICE);
	if (dma_mapping_error(jrdev, dma_addr_out)) {
		dev_err(jrdev, "Unable to DMA map the output key address\n");
		dma_unmap_single(jrdev, dma_addr_in, auth_param->auth_key_len,
				 DMA_TO_DEVICE);
		kfree(desc);
		return -ENOMEM;
	}

	init_job_desc(desc, 0);

	append_key(desc, dma_addr_in, auth_param->auth_key_len,
		   CLASS_2 | KEY_DEST_CLASS_REG);

	/* Sets MDHA up into an HMAC-INIT */
	append_operation(desc, (OP_ALG_TYPE_CLASS2 << OP_ALG_TYPE_SHIFT) |
			 alg_sel | OP_ALG_AAI_HMAC |
			OP_ALG_DECRYPT | OP_ALG_AS_INIT);

	/* Do a FIFO_LOAD of zero, this will trigger the internal key expansion
	   into both pads inside MDHA */
	append_fifo_load_as_imm(desc, NULL, 0, LDST_CLASS_2_CCB |
				FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/* FIFO_STORE with the explicit split-key content store
	 * (0x26 output type) */
	append_fifo_store(desc, dma_addr_out, auth_param->split_key_len,
			  LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);

	atomic_set(&done, 0);
	ret = caam_jr_enqueue(jrdev, desc, split_key_done, &done);

	while (!atomic_read(&done) && --timeout) {
		udelay(1);
		cpu_relax();
	}

	if (timeout == 0)
		log_err("Timeout waiting for job ring to complete\n");

	dma_unmap_single(jrdev, dma_addr_out, auth_param->split_key_pad_len,
			 DMA_FROM_DEVICE);
	dma_unmap_single(jrdev, dma_addr_in, auth_param->auth_key_len,
			 DMA_TO_DEVICE);
	kfree(desc);
	return ret;
}
