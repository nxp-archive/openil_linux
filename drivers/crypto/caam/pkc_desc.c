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
	struct rsa_pub_edesc_s *pub_edesc = &edesc->dma_u.rsa_pub_edesc;
	u32 *desc = edesc->hw_desc;
#ifdef CAAM_DEBUG
	u32 i;
#endif

	init_job_desc_pdb(desc, 0, sizeof(struct rsa_pub_desc_s) -
			  2 * CAAM_CMD_SZ);
	append_cmd(desc, (pub_edesc->sg_flgs.e_len << RSA_PDB_E_SHIFT) |
		   pub_edesc->sg_flgs.n_len);
	append_ptr(desc, pub_edesc->f_dma);
	append_ptr(desc, pub_edesc->g_dma);
	append_ptr(desc, pub_edesc->n_dma);
	append_ptr(desc, pub_edesc->e_dma);
	append_cmd(desc, pub_edesc->f_len);
	append_operation(desc, OP_TYPE_UNI_PROTOCOL | OP_PCLID_RSAENC_PUBKEY);

#ifdef CAAM_DEBUG
	for (i = 0; i < desc_len(desc); i++)
		pr_debug("[%d] %x\n", i, desc[i]);
#endif
	return desc;
}

/* Descriptor for RSA Private operation Form1 */
void *caam_rsa_priv_f1_desc(struct rsa_edesc *edesc)
{
	u32 *desc = edesc->hw_desc;
	struct rsa_priv_frm1_edesc_s *priv_edesc =
			&edesc->dma_u.rsa_priv_f1_edesc;

	init_job_desc_pdb(desc, 0, sizeof(struct rsa_priv_frm1_desc_s) -
			  2 * CAAM_CMD_SZ);
	append_cmd(desc, (priv_edesc->sg_flgs.d_len << RSA_PDB_D_SHIFT) |
		   priv_edesc->sg_flgs.n_len);
	append_ptr(desc, priv_edesc->g_dma);
	append_ptr(desc, priv_edesc->f_dma);
	append_ptr(desc, priv_edesc->n_dma);
	append_ptr(desc, priv_edesc->d_dma);
	append_operation(desc, OP_TYPE_UNI_PROTOCOL | OP_PCLID_RSADEC_PRVKEY |
			 RSA_PRIV_KEY_FRM_1);
	return desc;
}

/* Descriptor for RSA Private operation Form2 */
void *caam_rsa_priv_f2_desc(struct rsa_edesc *edesc)
{
	u32 *desc = edesc->hw_desc;
	struct rsa_priv_frm2_edesc_s *priv_edesc =
			&edesc->dma_u.rsa_priv_f2_edesc;

	init_job_desc_pdb(desc, 0, sizeof(struct rsa_priv_frm2_desc_s) -
			  2 * CAAM_CMD_SZ);
	append_cmd(desc, (priv_edesc->sg_flgs.d_len << RSA_PDB_D_SHIFT) |
			 priv_edesc->sg_flgs.n_len);
	append_ptr(desc, priv_edesc->g_dma);
	append_ptr(desc, priv_edesc->f_dma);
	append_ptr(desc, priv_edesc->d_dma);
	append_ptr(desc, priv_edesc->p_dma);
	append_ptr(desc, priv_edesc->q_dma);
	append_ptr(desc, priv_edesc->tmp1_dma);
	append_ptr(desc, priv_edesc->tmp2_dma);
	append_cmd(desc, (priv_edesc->q_len << RSA_PDB_Q_SHIFT) |
			 priv_edesc->p_len);
	append_operation(desc, OP_TYPE_UNI_PROTOCOL | OP_PCLID_RSADEC_PRVKEY |
			 RSA_PRIV_KEY_FRM_2);
	return desc;
}

/* Descriptor for RSA Private operation Form3 */
void *caam_rsa_priv_f3_desc(struct rsa_edesc *edesc)
{
	u32 *desc = edesc->hw_desc;
	struct rsa_priv_frm3_edesc_s *priv_edesc =
			&edesc->dma_u.rsa_priv_f3_edesc;
#ifdef CAAM_DEBUG
	u32 i;
#endif

	init_job_desc_pdb(desc, 0, sizeof(struct rsa_priv_frm3_desc_s) -
			  2 * CAAM_CMD_SZ);
	append_cmd(desc, priv_edesc->sg_flgs.n_len);
	append_ptr(desc, priv_edesc->g_dma);
	append_ptr(desc, priv_edesc->f_dma);
	append_ptr(desc, priv_edesc->c_dma);
	append_ptr(desc, priv_edesc->p_dma);
	append_ptr(desc, priv_edesc->q_dma);
	append_ptr(desc, priv_edesc->dp_dma);
	append_ptr(desc, priv_edesc->dq_dma);
	append_ptr(desc, priv_edesc->tmp1_dma);
	append_ptr(desc, priv_edesc->tmp2_dma);
	append_cmd(desc, (priv_edesc->q_len << RSA_PDB_Q_SHIFT) |
		   priv_edesc->p_len);
	append_operation(desc, OP_TYPE_UNI_PROTOCOL | OP_PCLID_RSADEC_PRVKEY |
			 RSA_PRIV_KEY_FRM_3);

#ifdef CAAM_DEBUG
	for (i = 0; i < desc_len(desc); i++)
		pr_debug("[%d] %x\n", i, desc[i]);
#endif
	return desc;
}

/* DH sign CAAM descriptor */
void *caam_dh_key_desc(struct dh_edesc_s *edesc)
{
	u32 *desc = edesc->hw_desc;
	u32 op = OP_TYPE_UNI_PROTOCOL | OP_PCLID_DH;
#ifdef CAAM_DEBUG
	u32 i;
#endif

	init_job_desc_pdb(desc, 0, sizeof(struct dh_key_desc_s) -
			  2 * CAAM_CMD_SZ);
	append_cmd(desc, (edesc->l_len << DH_PDB_L_SHIFT) |
			 (edesc->n_len & DH_PDB_N_MASK));
	append_ptr(desc, edesc->q_dma);
	/* pointer to r (unused) */
	append_ptr(desc, 0);
	append_ptr(desc, edesc->w_dma);
	append_ptr(desc, edesc->s_dma);
	append_ptr(desc, edesc->z_dma);
	if (edesc->req_type == ECDH_COMPUTE_KEY) {
		append_ptr(desc, edesc->ab_dma);
		op |= OP_PCL_PKPROT_ECC;
		if (edesc->curve_type == ECC_BINARY)
			op |= OP_PCL_PKPROT_F2M;
	}
	append_operation(desc, op);

#ifdef CAAM_DEBUG
	pr_debug("DH Descriptor:\n");
	for (i = 0; i < desc_len(desc); i++)
		pr_debug("[%d] %x\n", i, desc[i]);
#endif
	return desc;
}

/* DSA sign CAAM descriptor */
void *caam_dsa_sign_desc(struct dsa_edesc_s *edesc)
{
	u32 *desc = edesc->hw_desc;
	u32 op = OP_TYPE_UNI_PROTOCOL | OP_PCLID_DSASIGN;
#ifdef CAAM_DEBUG
	uint32_t i;
#endif

	if (edesc->req_type == ECDSA_SIGN) {
		op |= OP_PCL_PKPROT_ECC;
		if (edesc->curve_type == ECC_BINARY)
			op |= OP_PCL_PKPROT_F2M;

		init_job_desc_pdb(desc, 0, sizeof(struct ecdsa_sign_desc_s) -
				  2 * CAAM_CMD_SZ);
		append_cmd(desc, (edesc->l_len << DSA_PDB_L_SHIFT) |
				 (edesc->n_len & DSA_PDB_N_MASK));
		append_ptr(desc, edesc->q_dma);
		append_ptr(desc, edesc->r_dma);
		append_ptr(desc, edesc->g_dma);
		append_ptr(desc, edesc->key_dma);
		append_ptr(desc, edesc->f_dma);
		append_ptr(desc, edesc->c_dma);
		append_ptr(desc, edesc->d_dma);
		append_ptr(desc, edesc->ab_dma);
		append_operation(desc, op);
	} else {
		init_job_desc_pdb(desc, 0, sizeof(struct dsa_sign_desc_s) -
				  2 * CAAM_CMD_SZ);
		append_cmd(desc, (edesc->l_len << DSA_PDB_L_SHIFT) |
				 (edesc->n_len & DSA_PDB_N_MASK));
		append_ptr(desc, edesc->q_dma);
		append_ptr(desc, edesc->r_dma);
		append_ptr(desc, edesc->g_dma);
		append_ptr(desc, edesc->key_dma);
		append_ptr(desc, edesc->f_dma);
		append_ptr(desc, edesc->c_dma);
		append_ptr(desc, edesc->d_dma);
		append_operation(desc, op);
	}

#ifdef CAAM_DEBUG
	pr_debug("DSA Descriptor:\n");
	for (i = 0; i < desc_len(desc); i++)
		pr_debug("[%d] %x\n", i, desc[i]);
#endif
	return desc;
}

/* DSA/ECDSA/DH/ECDH keygen CAAM descriptor */
void *caam_keygen_desc(struct dsa_edesc_s *edesc)
{
	u32 *desc = edesc->hw_desc;
	u32 sgf_len = (edesc->l_len << DSA_PDB_L_SHIFT) |
		      (edesc->n_len & DSA_PDB_N_MASK);
	u32 op = OP_TYPE_UNI_PROTOCOL | OP_PCLID_PUBLICKEYPAIR;
	dma_addr_t g_dma = edesc->g_dma;
#ifdef CAAM_DEBUG
	u32 i;
#endif

	if (edesc->req_type == ECC_KEYGEN) {
		if (edesc->erratum_A_006899) {
			sgf_len |= DSA_PDB_SGF_G;
			g_dma = edesc->g_sg_dma;
		}

		op |= OP_PCL_PKPROT_ECC;
		if (edesc->curve_type == ECC_BINARY)
			op |= OP_PCL_PKPROT_F2M;

		init_job_desc_pdb(desc, 0, sizeof(struct ecc_keygen_desc_s) -
				  2 * CAAM_CMD_SZ);
		append_cmd(desc, sgf_len);
		append_ptr(desc, edesc->q_dma);
		append_ptr(desc, edesc->r_dma);
		append_ptr(desc, g_dma);
		append_ptr(desc, edesc->s_dma);
		append_ptr(desc, edesc->key_dma);
		append_ptr(desc, edesc->ab_dma);
		append_operation(desc, op);
	} else {
		init_job_desc_pdb(desc, 0, sizeof(struct dlc_keygen_desc_s) -
				  2 * CAAM_CMD_SZ);
		append_cmd(desc, sgf_len);
		append_ptr(desc, edesc->q_dma);
		append_ptr(desc, edesc->r_dma);
		append_ptr(desc, g_dma);
		append_ptr(desc, edesc->s_dma);
		append_ptr(desc, edesc->key_dma);
		append_operation(desc, op);
	}

#ifdef CAAM_DEBUG
	pr_debug("DSA Keygen Descriptor:\n");
	for (i = 0; i < desc_len(desc); i++)
		pr_debug("[%d] %x ", i, desc[i]);
#endif
	return desc;
}

/* DSA verify CAAM descriptor */
void *caam_dsa_verify_desc(struct dsa_edesc_s *edesc)
{
	u32 *desc = edesc->hw_desc;
	u32 op = OP_TYPE_UNI_PROTOCOL | OP_PCLID_DSAVERIFY;
#ifdef CAAM_DEBUG
	u32 i;
#endif

	if (edesc->req_type == ECDSA_VERIFY) {
		op |= OP_PCL_PKPROT_ECC;
		if (edesc->curve_type == ECC_BINARY)
			op |= OP_PCL_PKPROT_F2M;

		init_job_desc_pdb(desc, 0, sizeof(struct ecdsa_verify_desc_s) -
				  2 * CAAM_CMD_SZ);
		append_cmd(desc, (edesc->l_len << DSA_PDB_L_SHIFT) |
				 (edesc->n_len & DSA_PDB_N_MASK));
		append_ptr(desc, edesc->q_dma);
		append_ptr(desc, edesc->r_dma);
		append_ptr(desc, edesc->g_dma);
		append_ptr(desc, edesc->key_dma);
		append_ptr(desc, edesc->f_dma);
		append_ptr(desc, edesc->c_dma);
		append_ptr(desc, edesc->d_dma);
		append_ptr(desc, edesc->tmp_dma);
		append_ptr(desc, edesc->ab_dma);
		append_operation(desc, op);
	} else {
		init_job_desc_pdb(desc, 0, sizeof(struct dsa_verify_desc_s) -
				  2 * CAAM_CMD_SZ);
		append_cmd(desc, (edesc->l_len << DSA_PDB_L_SHIFT) |
				 (edesc->n_len & DSA_PDB_N_MASK));
		append_ptr(desc, edesc->q_dma);
		append_ptr(desc, edesc->r_dma);
		append_ptr(desc, edesc->g_dma);
		append_ptr(desc, edesc->key_dma);
		append_ptr(desc, edesc->f_dma);
		append_ptr(desc, edesc->c_dma);
		append_ptr(desc, edesc->d_dma);
		append_ptr(desc, edesc->tmp_dma);
		append_operation(desc, op);
	}

#ifdef CAAM_DEBUG
	pr_debug("DSA Descriptor:\n");
	for (i = 0; i < desc_len(desc); i++)
		pr_debug("[%d] %x\n", i, desc[i]);
#endif
	return desc;
}
