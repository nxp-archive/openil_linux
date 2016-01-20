/*
 * \file - pkc_desc.c
 * \brief - Freescale FSL CAAM support for Public Key Cryptography descriptor
 *
 * Author: Yashpal Dutta <yashpal.dutta@freescale.com>
 *
 * Copyright 2012 Freescale Semiconductor, Inc.
 *
 * There is no shared descriptor for PKC but Job descriptor must carry
 * all the desired key parameters, input and output pointers
 *
 */
#include "pkc_desc.h"

/*#define CAAM_DEBUG */
/* Descriptor for RSA Public operation */
void *caam_rsa_pub_desc(struct rsa_edesc *edesc)
{
	u32 start_idx, desc_size;
	struct rsa_pub_desc_s *rsa_pub_desc =
	    (struct rsa_pub_desc_s *)edesc->hw_desc;
	struct rsa_pub_edesc_s *pub_edesc = &edesc->dma_u.rsa_pub_edesc;
#ifdef CAAM_DEBUG
	uint32_t i;
	uint32_t *buf = (uint32_t *)rsa_pub_desc;
#endif

	desc_size = sizeof(struct rsa_pub_desc_s) / sizeof(u32);
	start_idx = desc_size - 1;
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(edesc->hw_desc, (start_idx << HDR_START_IDX_SHIFT) |
		      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
	rsa_pub_desc->n_dma = pub_edesc->n_dma;
	rsa_pub_desc->e_dma = pub_edesc->e_dma;
	rsa_pub_desc->f_dma = pub_edesc->f_dma;
	rsa_pub_desc->g_dma = pub_edesc->g_dma;
	rsa_pub_desc->sgf_flg = (pub_edesc->sg_flgs.e_len << RSA_PDB_E_SHIFT)
	    | pub_edesc->sg_flgs.n_len;
	rsa_pub_desc->msg_len = pub_edesc->f_len;
	rsa_pub_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
	    OP_PCLID_RSAENC_PUBKEY;
#ifdef CAAM_DEBUG
	for (i = 0; i < desc_size; i++)
		pr_debug("[%d] %x\n", i, buf[i]);
#endif
	return rsa_pub_desc;
}

/* Descriptor for RSA Private operation Form1 */
void *caam_rsa_priv_f1_desc(struct rsa_edesc *edesc)
{
	u32 start_idx, desc_size;
	struct rsa_priv_frm1_desc_s *rsa_priv_desc =
	    (struct rsa_priv_frm1_desc_s *)edesc->hw_desc;
	struct rsa_priv_frm1_edesc_s *priv_edesc =
	    &edesc->dma_u.rsa_priv_f1_edesc;

	desc_size = sizeof(struct rsa_priv_frm1_desc_s) / sizeof(u32);
	start_idx = desc_size - 1;
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(edesc->hw_desc, (start_idx << HDR_START_IDX_SHIFT) |
		      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
	rsa_priv_desc->n_dma = priv_edesc->n_dma;
	rsa_priv_desc->d_dma = priv_edesc->d_dma;
	rsa_priv_desc->f_dma = priv_edesc->f_dma;
	rsa_priv_desc->g_dma = priv_edesc->g_dma;
	/* TBD. Support SG flags */
	rsa_priv_desc->sgf_flg = (priv_edesc->sg_flgs.d_len << RSA_PDB_D_SHIFT)
	    | priv_edesc->sg_flgs.n_len;
	rsa_priv_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
	    OP_PCLID_RSADEC_PRVKEY | RSA_PRIV_KEY_FRM_1;
	return rsa_priv_desc;
}

/* Descriptor for RSA Private operation Form2 */
void *caam_rsa_priv_f2_desc(struct rsa_edesc *edesc)
{
	u32 start_idx, desc_size;
	struct rsa_priv_frm2_desc_s *rsa_priv_desc =
	    (struct rsa_priv_frm2_desc_s *)edesc->hw_desc;
	struct rsa_priv_frm2_edesc_s *priv_edesc =
	    &edesc->dma_u.rsa_priv_f2_edesc;

	desc_size = sizeof(struct rsa_priv_frm2_desc_s) / sizeof(u32);
	start_idx = desc_size - 1;
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(edesc->hw_desc, (start_idx << HDR_START_IDX_SHIFT) |
		      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
	rsa_priv_desc->p_dma = priv_edesc->p_dma;
	rsa_priv_desc->q_dma = priv_edesc->q_dma;
	rsa_priv_desc->d_dma = priv_edesc->d_dma;
	rsa_priv_desc->f_dma = priv_edesc->f_dma;
	rsa_priv_desc->g_dma = priv_edesc->g_dma;
	rsa_priv_desc->tmp1_dma = priv_edesc->tmp1_dma;
	rsa_priv_desc->tmp2_dma = priv_edesc->tmp2_dma;
	rsa_priv_desc->sgf_flg = (priv_edesc->sg_flgs.d_len << RSA_PDB_D_SHIFT)
	    | priv_edesc->sg_flgs.n_len;
	rsa_priv_desc->p_q_len = (priv_edesc->q_len << RSA_PDB_Q_SHIFT)
	    | priv_edesc->p_len;
	rsa_priv_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
	    OP_PCLID_RSADEC_PRVKEY | RSA_PRIV_KEY_FRM_2;
	return rsa_priv_desc;
}

/* Descriptor for RSA Private operation Form3 */
void *caam_rsa_priv_f3_desc(struct rsa_edesc *edesc)
{
	u32 start_idx, desc_size;
	struct rsa_priv_frm3_desc_s *rsa_priv_desc =
	    (struct rsa_priv_frm3_desc_s *)edesc->hw_desc;
	struct rsa_priv_frm3_edesc_s *priv_edesc =
	    &edesc->dma_u.rsa_priv_f3_edesc;
#ifdef CAAM_DEBUG
	uint32_t *buf = (uint32_t *)rsa_priv_desc;
	uint32_t i;
#endif

	desc_size = sizeof(struct rsa_priv_frm3_desc_s) / sizeof(u32);
	start_idx = desc_size - 1;
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(edesc->hw_desc, (start_idx << HDR_START_IDX_SHIFT) |
		      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
	rsa_priv_desc->p_dma = priv_edesc->p_dma;
	rsa_priv_desc->q_dma = priv_edesc->q_dma;
	rsa_priv_desc->dp_dma = priv_edesc->dp_dma;
	rsa_priv_desc->dq_dma = priv_edesc->dq_dma;
	rsa_priv_desc->c_dma = priv_edesc->c_dma;
	rsa_priv_desc->f_dma = priv_edesc->f_dma;
	rsa_priv_desc->g_dma = priv_edesc->g_dma;
	rsa_priv_desc->tmp1_dma = priv_edesc->tmp1_dma;
	rsa_priv_desc->tmp2_dma = priv_edesc->tmp2_dma;
	rsa_priv_desc->p_q_len = (priv_edesc->q_len << RSA_PDB_Q_SHIFT)
	    | priv_edesc->p_len;
	/* TBD: SG Flags to be filled */
	rsa_priv_desc->sgf_flg = priv_edesc->sg_flgs.n_len;
	rsa_priv_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
	    OP_PCLID_RSADEC_PRVKEY | RSA_PRIV_KEY_FRM_3;
#ifdef CAAM_DEBUG
	for (i = 0; i < desc_size; i++)
		pr_debug("[%d] %x\n", i, buf[i]);
#endif
	return rsa_priv_desc;
}

/* DH sign CAAM descriptor */
void *caam_dh_key_desc(struct dh_edesc_s *edesc)
{
	u32 start_idx, desc_size;
	void *desc;
#ifdef CAAM_DEBUG
	uint32_t i;
	uint32_t *buf;
#endif
	struct dh_key_desc_s *dh_desc =
	    (struct dh_key_desc_s *)edesc->hw_desc;
	desc_size = sizeof(struct dh_key_desc_s) / sizeof(u32);
	start_idx = desc_size - 1;
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(edesc->hw_desc, (start_idx << HDR_START_IDX_SHIFT) |
		      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
	dh_desc->sgf_ln = (edesc->l_len << DH_PDB_L_SHIFT) |
		((edesc->n_len & DH_PDB_N_MASK));
	dh_desc->q_dma = edesc->q_dma;
	dh_desc->w_dma = edesc->w_dma;
	dh_desc->s_dma = edesc->s_dma;
	dh_desc->z_dma = edesc->z_dma;
	dh_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
	    OP_PCLID_DH;
	if (edesc->req_type == ECDH_COMPUTE_KEY) {
		dh_desc->ab_dma = edesc->ab_dma;
		dh_desc->op |= OP_PCL_PKPROT_ECC;
		if (edesc->curve_type == ECC_BINARY)
			dh_desc->op |= OP_PCL_PKPROT_F2M;
	}

	desc = dh_desc;
#ifdef CAAM_DEBUG
	buf = desc;
	pr_debug("%d DH Descriptor is:\n", desc_size);
	for (i = 0; i < desc_size; i++)
		pr_debug("[%d] %x\n", i, buf[i]);
#endif
	return desc;
}

/* DSA sign CAAM descriptor */
void *caam_dsa_sign_desc(struct dsa_edesc_s *edesc)
{
	u32 start_idx, desc_size;
	void *desc;
#ifdef CAAM_DEBUG
	uint32_t i;
	uint32_t *buf;
#endif

	if (edesc->req_type == ECDSA_SIGN) {
		struct ecdsa_sign_desc_s *ecdsa_desc =
		    (struct ecdsa_sign_desc_s *)edesc->hw_desc;
		desc_size = sizeof(struct ecdsa_sign_desc_s) / sizeof(u32);
		start_idx = desc_size - 1;
		start_idx &= HDR_START_IDX_MASK;
		init_job_desc(edesc->hw_desc,
			      (start_idx << HDR_START_IDX_SHIFT) |
			      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
		ecdsa_desc->sgf_ln = (edesc->l_len << DSA_PDB_L_SHIFT) |
			((edesc->n_len & DSA_PDB_N_MASK));
		ecdsa_desc->q_dma = edesc->q_dma;
		ecdsa_desc->r_dma = edesc->r_dma;
		ecdsa_desc->g_dma = edesc->g_dma;
		ecdsa_desc->s_dma = edesc->key_dma;
		ecdsa_desc->f_dma = edesc->f_dma;
		ecdsa_desc->c_dma = edesc->c_dma;
		ecdsa_desc->d_dma = edesc->d_dma;
		ecdsa_desc->ab_dma = edesc->ab_dma;
		ecdsa_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
		    OP_PCLID_DSASIGN | OP_PCL_PKPROT_ECC;
		if (edesc->curve_type == ECC_BINARY)
			ecdsa_desc->op |= OP_PCL_PKPROT_F2M;

		desc = ecdsa_desc;
	} else {
		struct dsa_sign_desc_s *dsa_desc =
		    (struct dsa_sign_desc_s *)edesc->hw_desc;
		desc_size = sizeof(struct dsa_sign_desc_s) / sizeof(u32);
		start_idx = desc_size - 1;
		start_idx &= HDR_START_IDX_MASK;
		init_job_desc(edesc->hw_desc,
			      (start_idx << HDR_START_IDX_SHIFT) |
			      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
		dsa_desc->sgf_ln = (edesc->l_len << DSA_PDB_L_SHIFT) |
			((edesc->n_len & DSA_PDB_N_MASK));
		dsa_desc->q_dma = edesc->q_dma;
		dsa_desc->r_dma = edesc->r_dma;
		dsa_desc->g_dma = edesc->g_dma;
		dsa_desc->s_dma = edesc->key_dma;
		dsa_desc->f_dma = edesc->f_dma;
		dsa_desc->c_dma = edesc->c_dma;
		dsa_desc->d_dma = edesc->d_dma;
		dsa_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
		    OP_PCLID_DSASIGN;
		desc = dsa_desc;
	}
#ifdef CAAM_DEBUG
	buf = desc;
	pr_debug("DSA Descriptor is:");
	for (i = 0; i < desc_size; i++)
		pr_debug("[%d] %x ", i, buf[i]);
	pr_debug("\n");
#endif

	return desc;
}

/* DSA/ECDSA/DH/ECDH keygen CAAM descriptor */
void *caam_keygen_desc(struct dsa_edesc_s *edesc)
{
	u32 start_idx, desc_size;
	void *desc;
#ifdef CAAM_DEBUG
	uint32_t i;
	uint32_t *buf;
#endif

	if (edesc->req_type == ECC_KEYGEN) {
		struct ecc_keygen_desc_s *ecc_desc =
		    (struct ecc_keygen_desc_s *)edesc->hw_desc;
		desc_size = sizeof(struct ecc_keygen_desc_s) / sizeof(u32);
		start_idx = desc_size - 1;
		start_idx &= HDR_START_IDX_MASK;
		init_job_desc(edesc->hw_desc,
			      (start_idx << HDR_START_IDX_SHIFT) |
			      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
		ecc_desc->sgf_ln = (edesc->l_len << DSA_PDB_L_SHIFT) |
				   (edesc->n_len & DSA_PDB_N_MASK);
		if (edesc->erratum_A_006899) {
			ecc_desc->sgf_ln |= DSA_PDB_SGF_G;
			ecc_desc->g_dma = edesc->g_sg_dma;
		} else {
			ecc_desc->g_dma = edesc->g_dma;
		}
		ecc_desc->q_dma = edesc->q_dma;
		ecc_desc->r_dma = edesc->r_dma;
		ecc_desc->s_dma = edesc->s_dma;
		ecc_desc->w_dma = edesc->key_dma;
		ecc_desc->ab_dma = edesc->ab_dma;
		ecc_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
		    OP_PCLID_PUBLICKEYPAIR | OP_PCL_PKPROT_ECC;
		if (edesc->curve_type == ECC_BINARY)
			ecc_desc->op |= OP_PCL_PKPROT_F2M;

		desc = ecc_desc;
	} else {
		struct dlc_keygen_desc_s *key_desc =
		    (struct dlc_keygen_desc_s *)edesc->hw_desc;
		desc_size = sizeof(struct dlc_keygen_desc_s) / sizeof(u32);
		start_idx = desc_size - 1;
		start_idx &= HDR_START_IDX_MASK;
		init_job_desc(edesc->hw_desc,
			      (start_idx << HDR_START_IDX_SHIFT) |
			      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
		key_desc->sgf_ln = (edesc->l_len << DSA_PDB_L_SHIFT) |
			((edesc->n_len & DSA_PDB_N_MASK));
		key_desc->q_dma = edesc->q_dma;
		key_desc->r_dma = edesc->r_dma;
		key_desc->g_dma = edesc->g_dma;
		key_desc->s_dma = edesc->s_dma;
		key_desc->w_dma = edesc->key_dma;
		key_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
		    OP_PCLID_PUBLICKEYPAIR;
		desc = key_desc;
	}
#ifdef CAAM_DEBUG
	buf = desc;
	pr_debug("DSA Keygen Descriptor is:");
	for (i = 0; i < desc_size; i++)
		pr_debug("[%d] %x ", i, buf[i]);
	pr_debug("\n");
#endif

	return desc;
}

/* DSA verify CAAM descriptor */
void *caam_dsa_verify_desc(struct dsa_edesc_s *edesc)
{
	u32 start_idx, desc_size;
	void *desc;
#ifdef CAAM_DEBUG
	uint32_t i;
	uint32_t *buf;
#endif

	if (edesc->req_type == ECDSA_VERIFY) {
		struct ecdsa_verify_desc_s *ecdsa_desc =
		    (struct ecdsa_verify_desc_s *)edesc->hw_desc;
		desc_size = sizeof(struct ecdsa_verify_desc_s) / sizeof(u32);
		start_idx = desc_size - 1;
		start_idx &= HDR_START_IDX_MASK;
		init_job_desc(edesc->hw_desc,
			      (start_idx << HDR_START_IDX_SHIFT) |
			      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
		ecdsa_desc->sgf_ln = (edesc->l_len << DSA_PDB_L_SHIFT) |
			((edesc->n_len & DSA_PDB_N_MASK));
		ecdsa_desc->q_dma = edesc->q_dma;
		ecdsa_desc->r_dma = edesc->r_dma;
		ecdsa_desc->g_dma = edesc->g_dma;
		ecdsa_desc->w_dma = edesc->key_dma;
		ecdsa_desc->f_dma = edesc->f_dma;
		ecdsa_desc->c_dma = edesc->c_dma;
		ecdsa_desc->d_dma = edesc->d_dma;
		ecdsa_desc->tmp_dma = edesc->tmp_dma;
		ecdsa_desc->ab_dma = edesc->ab_dma;
		ecdsa_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
		    OP_PCLID_DSAVERIFY | OP_PCL_PKPROT_ECC;
		if (edesc->curve_type == ECC_BINARY)
			ecdsa_desc->op |= OP_PCL_PKPROT_F2M;
		desc = ecdsa_desc;
	} else {
		struct dsa_verify_desc_s *dsa_desc =
		    (struct dsa_verify_desc_s *)edesc->hw_desc;
		desc_size = sizeof(struct dsa_verify_desc_s) / sizeof(u32);
		start_idx = desc_size - 1;
		start_idx &= HDR_START_IDX_MASK;
		init_job_desc(edesc->hw_desc,
			      (start_idx << HDR_START_IDX_SHIFT) |
			      (start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
		dsa_desc->sgf_ln = (edesc->l_len << DSA_PDB_L_SHIFT) |
			((edesc->n_len & DSA_PDB_N_MASK));
		dsa_desc->q_dma = edesc->q_dma;
		dsa_desc->r_dma = edesc->r_dma;
		dsa_desc->g_dma = edesc->g_dma;
		dsa_desc->w_dma = edesc->key_dma;
		dsa_desc->f_dma = edesc->f_dma;
		dsa_desc->c_dma = edesc->c_dma;
		dsa_desc->d_dma = edesc->d_dma;
		dsa_desc->tmp_dma = edesc->tmp_dma;
		dsa_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
		    OP_PCLID_DSAVERIFY;
		desc = dsa_desc;
	}
#ifdef CAAM_DEBUG
	buf = desc;
	pr_debug("DSA Descriptor is:\n");
	for (i = 0; i < desc_size; i++)
		pr_debug("[%d] %x\n", i, buf[i]);
#endif
	return desc;
}
