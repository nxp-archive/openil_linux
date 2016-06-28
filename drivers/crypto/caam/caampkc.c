/*
 * \file - caampkc.c
 * \brief - Freescale FSL CAAM support for Public Key Cryptography
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

/* PKC Priority */
#define CAAM_PKC_PRIORITY 3000

#ifdef DEBUG
/* for print_hex_dumps with line references */
#define debug(format, arg...) pr_debug(format, arg)
#else
#define debug(format, arg...)
#endif

/* Internal context of CAAM driver. May carry session specific
     PKC information like key */
struct caam_pkc_context_s {
	/* Job Ring Device pointer for current request */
	struct device *dev;
};

struct caam_pkc_alg {
	struct list_head entry;
	struct device *ctrldev;
	struct crypto_alg crypto_alg;
};

static void rsa_unmap(struct device *dev,
		      struct rsa_edesc *edesc, struct pkc_request *req)
{
	switch (req->type) {
	case RSA_PUB:
		{
			struct rsa_pub_req_s *pub_req = &req->req_u.rsa_pub_req;
			struct rsa_pub_edesc_s *pub_edesc =
					&edesc->dma_u.rsa_pub_edesc;

			dma_unmap_single(dev, pub_edesc->n_dma, pub_req->n_len,
					 DMA_TO_DEVICE);
			dma_unmap_single(dev, pub_edesc->e_dma, pub_req->e_len,
					 DMA_TO_DEVICE);
			dma_unmap_single(dev, pub_edesc->g_dma, pub_req->g_len,
					 DMA_FROM_DEVICE);
			dma_unmap_single(dev, pub_edesc->f_dma, pub_req->f_len,
					 DMA_TO_DEVICE);
			break;
		}
	case RSA_PRIV_FORM1:
		{
			struct rsa_priv_frm1_req_s *priv_req =
			    &req->req_u.rsa_priv_f1;
			struct rsa_priv_frm1_edesc_s *priv_edesc =
					&edesc->dma_u.rsa_priv_f1_edesc;

			dma_unmap_single(dev, priv_edesc->n_dma,
					 priv_req->n_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->d_dma,
					 priv_req->d_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->f_dma,
					 priv_req->f_len, DMA_FROM_DEVICE);
			dma_unmap_single(dev, priv_edesc->g_dma,
					 priv_req->g_len, DMA_TO_DEVICE);
			break;
		}
	case RSA_PRIV_FORM2:
		{
			struct rsa_priv_frm2_req_s *priv_req =
			    &req->req_u.rsa_priv_f2;
			struct rsa_priv_frm2_edesc_s *priv_edesc =
					&edesc->dma_u.rsa_priv_f2_edesc;

			dma_unmap_single(dev, priv_edesc->p_dma,
					 priv_req->p_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->q_dma,
					 priv_req->q_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->d_dma,
					 priv_req->d_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->g_dma,
					 priv_req->g_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->f_dma,
					 priv_req->f_len, DMA_FROM_DEVICE);
			dma_unmap_single(dev, priv_edesc->tmp1_dma,
					 priv_req->p_len, DMA_BIDIRECTIONAL);
			dma_unmap_single(dev, priv_edesc->tmp2_dma,
					 priv_req->q_len, DMA_BIDIRECTIONAL);
			kfree(edesc->dma_u.rsa_priv_f2_edesc.tmp1);
			kfree(edesc->dma_u.rsa_priv_f2_edesc.tmp2);
			break;
		}
	case RSA_PRIV_FORM3:
		{
			struct rsa_priv_frm3_req_s *priv_req =
			    &req->req_u.rsa_priv_f3;
			struct rsa_priv_frm3_edesc_s *priv_edesc =
					&edesc->dma_u.rsa_priv_f3_edesc;

			dma_unmap_single(dev, priv_edesc->p_dma,
					 priv_req->p_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->q_dma,
					 priv_req->q_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->dq_dma,
					 priv_req->dq_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->dp_dma,
					 priv_req->dp_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->c_dma,
					 priv_req->c_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->g_dma,
					 priv_req->g_len, DMA_TO_DEVICE);
			dma_unmap_single(dev, priv_edesc->f_dma,
					 priv_req->f_len, DMA_FROM_DEVICE);
			dma_unmap_single(dev, priv_edesc->tmp1_dma,
					 priv_req->p_len, DMA_BIDIRECTIONAL);
			dma_unmap_single(dev, priv_edesc->tmp2_dma,
					 priv_req->q_len, DMA_BIDIRECTIONAL);
			kfree(edesc->dma_u.rsa_priv_f3_edesc.tmp1);
			kfree(edesc->dma_u.rsa_priv_f3_edesc.tmp2);
			break;
		}
	default:
		dev_err(dev, "Unable to find request type\n");
	}
}

/* RSA Job Completion handler */
static void rsa_op_done(struct device *dev, u32 *desc, u32 err, void *context)
{
	struct pkc_request *req = context;
	struct rsa_edesc *edesc;

	edesc = (struct rsa_edesc *)((char *)desc -
				     offsetof(struct rsa_edesc, hw_desc));

	if (err)
		caam_jr_strstatus(dev, err);

	rsa_unmap(dev, edesc, req);
	kfree(edesc);

	pkc_request_complete(req, err);
}

static void dh_unmap(struct device *dev,
		      struct dh_edesc_s *edesc, struct pkc_request *req)
{
	struct dh_key_req_s *dh_req = &req->req_u.dh_req;

	dma_unmap_single(dev, edesc->q_dma,
			 dh_req->q_len, DMA_TO_DEVICE);
	dma_unmap_single(dev, edesc->w_dma,
			 dh_req->pub_key_len, DMA_TO_DEVICE);
	dma_unmap_single(dev, edesc->s_dma,
			 dh_req->s_len, DMA_TO_DEVICE);
	dma_unmap_single(dev, edesc->z_dma,
			 dh_req->z_len, DMA_FROM_DEVICE);
	if (edesc->req_type == ECDH_COMPUTE_KEY)
		dma_unmap_single(dev, edesc->ab_dma,
				 dh_req->ab_len, DMA_TO_DEVICE);
}

static void dsa_unmap(struct device *dev,
		       struct dsa_edesc_s *edesc, struct pkc_request *req)
{
	switch (req->type) {
	case DSA_SIGN:
	case ECDSA_SIGN:
	{
		struct dsa_sign_req_s *dsa_req = &req->req_u.dsa_sign;

		dma_unmap_single(dev, edesc->q_dma,
				 dsa_req->q_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->r_dma,
				 dsa_req->r_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->g_dma,
				 dsa_req->g_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->s_dma,
				 dsa_req->priv_key_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->f_dma,
				 dsa_req->m_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->c_dma,
				 dsa_req->d_len, DMA_FROM_DEVICE);
		dma_unmap_single(dev, edesc->d_dma,
				 dsa_req->d_len, DMA_FROM_DEVICE);
		if (req->type == ECDSA_SIGN)
			dma_unmap_single(dev, edesc->ab_dma,
					 dsa_req->ab_len, DMA_TO_DEVICE);
	}
	break;
	case DSA_VERIFY:
	case ECDSA_VERIFY:
	{
		struct dsa_verify_req_s *dsa_req = &req->req_u.dsa_verify;

		dma_unmap_single(dev, edesc->q_dma,
				 dsa_req->q_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->r_dma,
				 dsa_req->r_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->g_dma,
				 dsa_req->g_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->key_dma,
				 dsa_req->pub_key_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->f_dma,
				 dsa_req->m_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->c_dma,
				 dsa_req->d_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->d_dma,
				 dsa_req->d_len, DMA_TO_DEVICE);
		if (req->type == ECDSA_VERIFY) {
			dma_unmap_single(dev, edesc->tmp_dma,
					 2*edesc->l_len, DMA_BIDIRECTIONAL);
			dma_unmap_single(dev, edesc->ab_dma,
					 dsa_req->ab_len, DMA_TO_DEVICE);
		} else {
			dma_unmap_single(dev, edesc->tmp_dma,
					 edesc->l_len, DMA_BIDIRECTIONAL);
		}
		kfree(edesc->tmp);
	}
	break;
	case DLC_KEYGEN:
	case ECC_KEYGEN:
	{
		struct keygen_req_s *key_req = &req->req_u.keygen;

		dma_unmap_single(dev, edesc->q_dma,
				 key_req->q_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->r_dma,
				 key_req->r_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->g_dma,
				 key_req->g_len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->s_dma,
				 key_req->priv_key_len, DMA_FROM_DEVICE);
		dma_unmap_single(dev, edesc->key_dma,
				 key_req->pub_key_len, DMA_FROM_DEVICE);
		if (req->type == ECC_KEYGEN)
			dma_unmap_single(dev, edesc->ab_dma,
					 key_req->ab_len, DMA_TO_DEVICE);
	}
	break;
	default:
		dev_err(dev, "Unable to find request type\n");
	}
}

/* DSA Job Completion handler */
static void dsa_op_done(struct device *dev, u32 *desc, u32 err, void *context)
{
	struct pkc_request *req = context;
	struct dsa_edesc_s *edesc;

	edesc = (struct dsa_edesc_s *)((char *)desc -
				     offsetof(struct dsa_edesc_s, hw_desc));

	if (err)
		caam_jr_strstatus(dev, err);

	dsa_unmap(dev, edesc, req);
	kfree(edesc);

	pkc_request_complete(req, err);
}
static int caam_dsa_sign_edesc(struct pkc_request *req,
				struct dsa_edesc_s *edesc)
{
	struct crypto_pkc *tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(tfm);
	struct device *dev = ctxt->dev;
	struct dsa_sign_req_s *dsa_req = &req->req_u.dsa_sign;

	edesc->l_len = dsa_req->q_len;
	edesc->n_len = dsa_req->r_len;
	edesc->req_type = req->type;
	edesc->curve_type = req->curve_type;
	edesc->q_dma = dma_map_single(dev, dsa_req->q, dsa_req->q_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->q_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto q_map_fail;
	}

	edesc->r_dma = dma_map_single(dev, dsa_req->r, dsa_req->r_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->r_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto r_map_fail;
	}

	edesc->g_dma = dma_map_single(dev, dsa_req->g, dsa_req->g_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->g_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto g_map_fail;
	}

	edesc->f_dma = dma_map_single(dev, dsa_req->m, dsa_req->m_len,
				      DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->f_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto m_map_fail;
	}

	edesc->key_dma = dma_map_single(dev, dsa_req->priv_key,
					dsa_req->priv_key_len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->key_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto key_map_fail;
	}

	edesc->c_dma = dma_map_single(dev, dsa_req->c, dsa_req->d_len,
					  DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->c_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto c_map_fail;
	}

	edesc->d_dma = dma_map_single(dev, dsa_req->d, dsa_req->d_len,
					  DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->d_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto d_map_fail;
	}

	if (edesc->req_type == ECDSA_SIGN) {
		edesc->ab_dma = dma_map_single(dev, dsa_req->ab,
					       dsa_req->ab_len, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, edesc->ab_dma)) {
			dev_err(dev, "Unable to map  memory\n");
			goto ab_map_fail;
		}
	}
	return 0;
ab_map_fail:
	if (edesc->req_type == ECDSA_SIGN)
		dma_unmap_single(dev, edesc->d_dma, dsa_req->d_len,
				 DMA_TO_DEVICE);
d_map_fail:
	dma_unmap_single(dev, edesc->c_dma, dsa_req->d_len, DMA_FROM_DEVICE);
c_map_fail:
	dma_unmap_single(dev, edesc->key_dma, dsa_req->priv_key_len,
			 DMA_TO_DEVICE);
key_map_fail:
	dma_unmap_single(dev, edesc->f_dma, dsa_req->m_len, DMA_FROM_DEVICE);
m_map_fail:
	dma_unmap_single(dev, edesc->g_dma, dsa_req->g_len, DMA_TO_DEVICE);
g_map_fail:
	dma_unmap_single(dev, edesc->r_dma, dsa_req->r_len, DMA_TO_DEVICE);
r_map_fail:
	dma_unmap_single(dev, edesc->q_dma, dsa_req->q_len, DMA_TO_DEVICE);
q_map_fail:
	return -EINVAL;
}

static int caam_dsa_verify_edesc(struct pkc_request *req,
				  struct dsa_edesc_s *edesc)
{
	struct crypto_pkc *tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(tfm);
	struct device *dev = ctxt->dev;
	uint32_t tmp_len;
	struct dsa_verify_req_s *dsa_req = &req->req_u.dsa_verify;

	edesc->l_len = dsa_req->q_len;
	edesc->n_len = dsa_req->r_len;
	edesc->req_type = req->type;
	edesc->curve_type = req->curve_type;
	if (edesc->req_type == ECDSA_VERIFY)
		tmp_len = 2*dsa_req->q_len;
	else
		tmp_len = dsa_req->q_len;

	edesc->tmp = kzalloc(tmp_len, GFP_DMA);
	if (!edesc->tmp) {
		pr_debug("Failed to allocate temp buffer for DSA Verify\n");
		return -ENOMEM;
	}

	edesc->tmp_dma = dma_map_single(dev, edesc->tmp, tmp_len,
					  DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, edesc->tmp_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto tmp_map_fail;
	}

	edesc->q_dma = dma_map_single(dev, dsa_req->q, dsa_req->q_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->q_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto q_map_fail;
	}

	edesc->r_dma = dma_map_single(dev, dsa_req->r, dsa_req->r_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->r_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto r_map_fail;
	}

	edesc->g_dma = dma_map_single(dev, dsa_req->g, dsa_req->g_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->g_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto g_map_fail;
	}

	edesc->f_dma = dma_map_single(dev, dsa_req->m, dsa_req->m_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->f_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto m_map_fail;
	}

	edesc->key_dma = dma_map_single(dev, dsa_req->pub_key,
					dsa_req->pub_key_len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->key_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto key_map_fail;
	}

	edesc->c_dma = dma_map_single(dev, dsa_req->c, dsa_req->d_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->c_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto c_map_fail;
	}

	edesc->d_dma = dma_map_single(dev, dsa_req->d, dsa_req->d_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->d_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto d_map_fail;
	}

	if (edesc->req_type == ECDSA_VERIFY) {
		edesc->ab_dma = dma_map_single(dev, dsa_req->ab,
					       dsa_req->ab_len, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, edesc->ab_dma)) {
			dev_err(dev, "Unable to map  memory\n");
			goto ab_map_fail;
		}
	}
	return 0;
ab_map_fail:
	if (edesc->req_type == ECDSA_VERIFY)
		dma_unmap_single(dev, edesc->d_dma, dsa_req->d_len,
				 DMA_TO_DEVICE);
d_map_fail:
	dma_unmap_single(dev, edesc->c_dma, dsa_req->d_len, DMA_TO_DEVICE);
c_map_fail:
	dma_unmap_single(dev, edesc->key_dma, dsa_req->pub_key_len,
			 DMA_TO_DEVICE);
key_map_fail:
	dma_unmap_single(dev, edesc->f_dma, dsa_req->m_len, DMA_TO_DEVICE);
m_map_fail:
	dma_unmap_single(dev, edesc->g_dma, dsa_req->g_len, DMA_TO_DEVICE);
g_map_fail:
	dma_unmap_single(dev, edesc->r_dma, dsa_req->r_len, DMA_TO_DEVICE);
r_map_fail:
	dma_unmap_single(dev, edesc->q_dma, dsa_req->q_len, DMA_TO_DEVICE);
q_map_fail:
	dma_unmap_single(dev, edesc->tmp_dma, tmp_len, DMA_BIDIRECTIONAL);
tmp_map_fail:
	kfree(edesc->tmp);
	return -EINVAL;
}

static int caam_keygen_edesc(struct pkc_request *req,
				struct dsa_edesc_s *edesc)
{
	struct crypto_pkc *tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(tfm);
	struct crypto_alg *alg = crypto_pkc_tfm(tfm)->__crt_alg;
	struct caam_pkc_alg *caam_alg =
			container_of(alg, struct caam_pkc_alg, crypto_alg);
	struct caam_drv_private *caam_priv = dev_get_drvdata(caam_alg->ctrldev);
	struct device *dev = ctxt->dev;
	struct keygen_req_s *key_req = &req->req_u.keygen;

	edesc->l_len = key_req->q_len;
	edesc->n_len = key_req->r_len;
	edesc->req_type = req->type;
	edesc->curve_type = req->curve_type;
	edesc->erratum_A_006899 = caam_priv->errata & SEC_ERRATUM_A_006899;

	edesc->q_dma = dma_map_single(dev, key_req->q, key_req->q_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->q_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto q_map_fail;
	}

	edesc->r_dma = dma_map_single(dev, key_req->r, key_req->r_len,
				DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->r_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto r_map_fail;
	}

	edesc->g_dma = dma_map_single(dev, key_req->g, key_req->g_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->g_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto g_map_fail;
	}

	if (edesc->erratum_A_006899) {
		dma_to_sec4_sg_one(&(edesc->g_sg), edesc->g_dma,
				   key_req->g_len, 0);
		edesc->g_sg.len |= cpu_to_caam32(SEC4_SG_LEN_FIN);

		edesc->g_sg_dma = dma_map_single(dev, &(edesc->g_sg),
						 sizeof(struct sec4_sg_entry),
						 DMA_TO_DEVICE);
		if (dma_mapping_error(dev, edesc->g_sg_dma)) {
			dev_err(dev, "unable to map S/G table\n");
			goto g_sg_dma_fail;
		}
	}

	edesc->key_dma = dma_map_single(dev, key_req->pub_key,
					key_req->pub_key_len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->key_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto key_map_fail;
	}

	edesc->s_dma = dma_map_single(dev, key_req->priv_key,
				      key_req->priv_key_len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->s_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto s_map_fail;
	}

	if (edesc->req_type == ECC_KEYGEN) {
		edesc->ab_dma = dma_map_single(dev, key_req->ab,
						key_req->ab_len, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, edesc->ab_dma)) {
			dev_err(dev, "Unable to map  memory\n");
			goto ab_map_fail;
		}
	}

	return 0;
ab_map_fail:
	if (edesc->req_type == ECC_KEYGEN)
		dma_unmap_single(dev, edesc->s_dma, key_req->priv_key_len,
				 DMA_FROM_DEVICE);
s_map_fail:
	dma_unmap_single(dev, edesc->key_dma, key_req->pub_key_len,
			 DMA_FROM_DEVICE);
key_map_fail:
	if (edesc->erratum_A_006899)
		dma_unmap_single(dev, edesc->g_sg_dma, key_req->g_len,
				 DMA_TO_DEVICE);
g_sg_dma_fail:
	dma_unmap_single(dev, edesc->g_dma, key_req->g_len, DMA_TO_DEVICE);
g_map_fail:
	dma_unmap_single(dev, edesc->r_dma, key_req->r_len, DMA_TO_DEVICE);
r_map_fail:
	dma_unmap_single(dev, edesc->q_dma, key_req->q_len, DMA_TO_DEVICE);
q_map_fail:
	return -EINVAL;
}

static int caam_rsa_pub_edesc(struct pkc_request *req, struct rsa_edesc *edesc)
{
	struct crypto_pkc *tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(tfm);
	struct device *dev = ctxt->dev;
	struct rsa_pub_req_s *pub_req = &req->req_u.rsa_pub_req;
	struct rsa_pub_edesc_s *pub_edesc = &edesc->dma_u.rsa_pub_edesc;

	if (pub_req->n_len > pub_req->g_len) {
		pr_err("Output buffer length less than parameter n\n");
		return -EINVAL;
	}

	pub_edesc->n_dma = dma_map_single(dev, pub_req->n, pub_req->n_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, pub_edesc->n_dma)) {
		dev_err(dev, "Unable to map  modulus memory\n");
		goto n_pub_fail;
	}

	pub_edesc->e_dma = dma_map_single(dev, pub_req->e, pub_req->e_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, pub_edesc->e_dma)) {
		dev_err(dev, "Unable to map exponent memory\n");
		goto e_pub_fail;
	}

	pub_edesc->f_dma = dma_map_single(dev, pub_req->f, pub_req->f_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, pub_edesc->f_dma)) {
		dev_err(dev, "Unable to map input buffer memory\n");
		goto f_pub_fail;
	}

	pub_edesc->g_dma = dma_map_single(dev, pub_req->g, pub_req->g_len,
					  DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, pub_edesc->g_dma)) {
		dev_err(dev, "Unable to map output memory\n");
		goto g_pub_fail;
	}

	/* TBD: Set SG flags in case input is SG */
	pub_edesc->sg_flgs.e_len = pub_req->e_len;
	pub_edesc->sg_flgs.n_len = pub_req->n_len;
	pub_edesc->f_len = pub_req->f_len;
/* Enable once we check SG */
#ifdef SG_ENABLED
	pub_edesc->sg_flgs.sg_f = 1;
	pub_edesc->sg_flgs.sg_g = 1;
	pub_edesc->sg_flgs.sg_e = 1;
	pub_edesc->sg_flgs.sg_n = 1;
#endif

	return 0;
g_pub_fail:
	dma_unmap_single(dev, pub_edesc->f_dma, pub_req->f_len, DMA_TO_DEVICE);
f_pub_fail:
	dma_unmap_single(dev, pub_edesc->e_dma, pub_req->e_len, DMA_TO_DEVICE);
e_pub_fail:
	dma_unmap_single(dev, pub_edesc->n_dma, pub_req->n_len, DMA_TO_DEVICE);
n_pub_fail:
	return -EINVAL;
}

static int caam_rsa_priv_f1_edesc(struct pkc_request *req,
				  struct rsa_edesc *edesc)
{
	struct crypto_pkc *tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(tfm);
	struct device *dev = ctxt->dev;
	struct rsa_priv_frm1_req_s *priv_req = &req->req_u.rsa_priv_f1;
	struct rsa_priv_frm1_edesc_s *priv_edesc =
	    &edesc->dma_u.rsa_priv_f1_edesc;

	priv_edesc->n_dma = dma_map_single(dev, priv_req->n, priv_req->n_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->n_dma)) {
		dev_err(dev, "Unable to map  modulus memory\n");
		goto n_f1_fail;
	}

	priv_edesc->d_dma = dma_map_single(dev, priv_req->d, priv_req->d_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->d_dma)) {
		dev_err(dev, "Unable to map exponent memory\n");
		goto d_f1_fail;
	}

	priv_edesc->f_dma = dma_map_single(dev, priv_req->f, priv_req->f_len,
					   DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->f_dma)) {
		dev_err(dev, "Unable to map output buffer memory\n");
		goto f_f1_fail;
	}

	priv_edesc->g_dma = dma_map_single(dev, priv_req->g, priv_req->g_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->g_dma)) {
		dev_err(dev, "Unable to map input memory\n");
		goto g_f1_fail;
	}

/* Enable once we check SG */
#ifdef SG_ENABLED
	priv_edesc->sg_flgs.sg_f = 1;
	priv_edesc->sg_flgs.sg_g = 1;
	priv_edesc->sg_flgs.sg_d = 1;
	priv_edesc->sg_flgs.sg_n = 1;
#endif
	priv_edesc->sg_flgs.d_len =  priv_req->d_len;
	priv_edesc->sg_flgs.n_len = priv_req->n_len;

	return 0;
g_f1_fail:
	dma_unmap_single(dev, priv_edesc->f_dma, priv_req->f_len,
			 DMA_FROM_DEVICE);
f_f1_fail:
	dma_unmap_single(dev, priv_edesc->d_dma, priv_req->d_len,
			 DMA_TO_DEVICE);
d_f1_fail:
	dma_unmap_single(dev, priv_edesc->n_dma, priv_req->n_len,
			 DMA_TO_DEVICE);
n_f1_fail:
	return -EINVAL;
}

static int caam_rsa_priv_f2_edesc(struct pkc_request *req,
				  struct rsa_edesc *edesc)
{
	struct crypto_pkc *tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(tfm);
	struct device *dev = ctxt->dev;
	struct rsa_priv_frm2_req_s *priv_req = &req->req_u.rsa_priv_f2;
	struct rsa_priv_frm2_edesc_s *priv_edesc =
	    &edesc->dma_u.rsa_priv_f2_edesc;

	/* tmp1 must be as long as p */
	priv_edesc->tmp1 = kzalloc(priv_req->p_len, GFP_DMA);

	if (!priv_edesc->tmp1)
		return -ENOMEM;

	/* tmp2 must be as long as q */
	priv_edesc->tmp2 = kzalloc(priv_req->q_len, GFP_DMA);
	if (!priv_edesc->tmp2) {
		kfree(priv_edesc->tmp1);
		return -ENOMEM;
	}

	priv_edesc->tmp1_dma =
	    dma_map_single(dev, priv_edesc->tmp1, priv_req->p_len,
			   DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, priv_edesc->tmp1_dma)) {
		dev_err(dev, "Unable to map  modulus memory\n");
		goto tmp1_f2_fail;
	}

	priv_edesc->tmp2_dma =
	    dma_map_single(dev, priv_edesc->tmp2, priv_req->q_len,
			   DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, priv_edesc->tmp2_dma)) {
		dev_err(dev, "Unable to map  modulus memory\n");
		goto tmp2_f2_fail;
	}

	priv_edesc->p_dma = dma_map_single(dev, priv_req->p, priv_req->p_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->p_dma)) {
		dev_err(dev, "Unable to map  modulus memory\n");
		goto p_f2_fail;
	}

	priv_edesc->q_dma = dma_map_single(dev, priv_req->q, priv_req->q_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->q_dma)) {
		dev_err(dev, "Unable to map exponent memory\n");
		goto q_f2_fail;
	}

	priv_edesc->d_dma = dma_map_single(dev, priv_req->d, priv_req->d_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->d_dma)) {
		dev_err(dev, "Unable to map exponent memory\n");
		goto d_f2_fail;
	}

	priv_edesc->f_dma = dma_map_single(dev, priv_req->f, priv_req->f_len,
					   DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->f_dma)) {
		dev_err(dev, "Unable to map output buffer memory\n");
		goto f_f2_fail;
	}

	priv_edesc->g_dma = dma_map_single(dev, priv_req->g, priv_req->g_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->g_dma)) {
		dev_err(dev, "Unable to map input memory\n");
		goto g_f2_fail;
	}
	priv_edesc->sg_flgs.d_len = priv_req->d_len;
	priv_edesc->sg_flgs.n_len = priv_req->n_len;
	priv_edesc->q_len = priv_req->q_len;
	priv_edesc->p_len = priv_req->p_len;

	/* TBD: Set SG flags in case input is SG */
	return 0;
g_f2_fail:
	dma_unmap_single(dev, priv_edesc->f_dma, priv_req->f_len,
			 DMA_FROM_DEVICE);
f_f2_fail:
	dma_unmap_single(dev, priv_edesc->d_dma, priv_req->d_len,
			 DMA_TO_DEVICE);
d_f2_fail:
	dma_unmap_single(dev, priv_edesc->q_dma, priv_req->q_len,
			 DMA_TO_DEVICE);
q_f2_fail:
	dma_unmap_single(dev, priv_edesc->p_dma, priv_req->p_len,
			 DMA_TO_DEVICE);
p_f2_fail:
	dma_unmap_single(dev, priv_edesc->tmp2_dma, priv_req->q_len,
			 DMA_TO_DEVICE);
tmp2_f2_fail:
	dma_unmap_single(dev, priv_edesc->tmp1_dma, priv_req->p_len,
			 DMA_BIDIRECTIONAL);
	kfree(priv_edesc->tmp2);
tmp1_f2_fail:
	kfree(priv_edesc->tmp1);
	return -EINVAL;
}

static int caam_rsa_priv_f3_edesc(struct pkc_request *req,
				  struct rsa_edesc *edesc)
{
	struct crypto_pkc *tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(tfm);
	struct device *dev = ctxt->dev;
	struct rsa_priv_frm3_req_s *priv_req = &req->req_u.rsa_priv_f3;
	struct rsa_priv_frm3_edesc_s *priv_edesc =
	    &edesc->dma_u.rsa_priv_f3_edesc;

	priv_edesc->tmp1 = kzalloc(priv_req->p_len, GFP_DMA);

	if (!priv_edesc->tmp1)
		return -ENOMEM;

	priv_edesc->tmp2 = kzalloc(priv_req->q_len, GFP_DMA);
	if (!priv_edesc->tmp2) {
		kfree(priv_edesc->tmp1);
		return -ENOMEM;
	}

	priv_edesc->tmp1_dma =
	    dma_map_single(dev, priv_edesc->tmp1, priv_req->p_len,
			   DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, priv_edesc->tmp1_dma)) {
		dev_err(dev, "Unable to map  modulus memory\n");
		goto tmp1_f2_fail;
	}

	priv_edesc->tmp2_dma =
	    dma_map_single(dev, priv_edesc->tmp2, priv_req->q_len,
			   DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, priv_edesc->tmp2_dma)) {
		dev_err(dev, "Unable to map  modulus memory\n");
		goto tmp2_f2_fail;
	}

	priv_edesc->p_dma = dma_map_single(dev, priv_req->p, priv_req->p_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->p_dma)) {
		dev_err(dev, "Unable to map  modulus memory\n");
		goto p_f3_fail;
	}

	priv_edesc->q_dma = dma_map_single(dev, priv_req->q, priv_req->q_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->q_dma)) {
		dev_err(dev, "Unable to map exponent memory\n");
		goto q_f3_fail;
	}

	priv_edesc->dp_dma =
	    dma_map_single(dev, priv_req->dp, priv_req->dp_len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->dp_dma)) {
		dev_err(dev, "Unable to map dp memory\n");
		goto dp_f3_fail;
	}

	priv_edesc->dq_dma =
	    dma_map_single(dev, priv_req->dq, priv_req->dq_len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->dq_dma)) {
		dev_err(dev, "Unable to map dq memory\n");
		goto dq_f3_fail;
	}

	priv_edesc->c_dma = dma_map_single(dev, priv_req->c, priv_req->c_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->c_dma)) {
		dev_err(dev, "Unable to map Coefficient memory\n");
		goto c_f3_fail;
	}

	priv_edesc->f_dma = dma_map_single(dev, priv_req->f, priv_req->f_len,
					   DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->f_dma)) {
		dev_err(dev, "Unable to map output buffer memory\n");
		goto f_f3_fail;
	}

	priv_edesc->g_dma = dma_map_single(dev, priv_req->g, priv_req->g_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(dev, priv_edesc->g_dma)) {
		dev_err(dev, "Unable to map input memory\n");
		goto g_f3_fail;
	}

	priv_edesc->sg_flgs.n_len = priv_req->f_len;
	priv_edesc->q_len = priv_req->q_len;
	priv_edesc->p_len = priv_req->p_len;

	return 0;
g_f3_fail:
	dma_unmap_single(dev, priv_edesc->f_dma, priv_req->f_len,
			 DMA_FROM_DEVICE);
f_f3_fail:
	dma_unmap_single(dev, priv_edesc->c_dma, priv_req->c_len,
			 DMA_TO_DEVICE);
c_f3_fail:
	dma_unmap_single(dev, priv_edesc->dq_dma, priv_req->dq_len,
			 DMA_TO_DEVICE);
dq_f3_fail:
	dma_unmap_single(dev, priv_edesc->dp_dma, priv_req->dp_len,
			 DMA_TO_DEVICE);
dp_f3_fail:
	dma_unmap_single(dev, priv_edesc->q_dma, priv_req->q_len,
			 DMA_TO_DEVICE);
q_f3_fail:
	dma_unmap_single(dev, priv_edesc->p_dma, priv_req->p_len,
			 DMA_TO_DEVICE);
p_f3_fail:
	dma_unmap_single(dev, priv_edesc->tmp2_dma, priv_req->q_len,
			 DMA_TO_DEVICE);
tmp2_f2_fail:
	dma_unmap_single(dev, priv_edesc->tmp1_dma, priv_req->p_len,
			 DMA_BIDIRECTIONAL);
	kfree(priv_edesc->tmp2);
tmp1_f2_fail:
	kfree(priv_edesc->tmp1);

	return -EINVAL;
}

/* CAAM Descriptor creator for RSA Public Key operations */
static void *caam_rsa_desc_init(struct pkc_request *req)
{
	void *desc = NULL;
	struct rsa_edesc *edesc = NULL;

	switch (req->type) {
	case RSA_PUB:
		{
			edesc =
			    kzalloc(sizeof(*edesc) +
				    sizeof(struct rsa_pub_desc_s), GFP_DMA);

			if (!edesc)
				return NULL;

			if (caam_rsa_pub_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}

			desc = caam_rsa_pub_desc(edesc);
			break;
		}
	case RSA_PRIV_FORM1:
		{
			edesc =
			    kzalloc(sizeof(*edesc) +
				    sizeof(struct rsa_priv_frm1_desc_s),
				    GFP_DMA);
			if (!edesc)
				return NULL;

			if (caam_rsa_priv_f1_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}

			desc = caam_rsa_priv_f1_desc(edesc);
			break;
		}
	case RSA_PRIV_FORM2:
		{
			edesc =
			    kzalloc(sizeof(*edesc) +
				    sizeof(struct rsa_priv_frm2_desc_s),
				    GFP_DMA);
			if (!edesc)
				return NULL;

			if (caam_rsa_priv_f2_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}

			desc = caam_rsa_priv_f2_desc(edesc);
			break;
		}
	case RSA_PRIV_FORM3:
		{
			edesc = kzalloc(sizeof(*edesc) +
					sizeof(struct rsa_priv_frm3_desc_s),
					GFP_DMA);
			if (!edesc)
				return NULL;

			if (caam_rsa_priv_f3_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}

			desc = caam_rsa_priv_f3_desc(edesc);
			break;
		}
	default:
		pr_debug("Unknown request type\n");
		return NULL;
	}

	edesc->req_type = req->type;
	return desc;
}

/* CAAM Descriptor creator for RSA Public Key operations */
static void *caam_dsa_desc_init(struct pkc_request *req)
{
	void *desc = NULL;
	struct dsa_edesc_s *edesc = NULL;

	switch (req->type) {
	case DSA_SIGN:
		{
			edesc = kzalloc(sizeof(*edesc) +
					sizeof(struct dsa_sign_desc_s),
					GFP_DMA);
			if (!edesc)
				return NULL;

			if (caam_dsa_sign_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}

			desc = caam_dsa_sign_desc(edesc);
		}
		break;
	case DSA_VERIFY:
		{
			edesc = kzalloc(sizeof(*edesc) +
					sizeof(struct dsa_verify_desc_s),
					GFP_DMA);
			if (!edesc)
				return NULL;

			if (caam_dsa_verify_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}

			desc = caam_dsa_verify_desc(edesc);
		}
		break;
	case DLC_KEYGEN:
		{
			edesc = kzalloc(sizeof(*edesc) +
					sizeof(struct dlc_keygen_desc_s),
					GFP_DMA);
			if (!edesc)
				return NULL;

			if (caam_keygen_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}

			desc = caam_keygen_desc(edesc);
		}
		break;
	case ECDSA_SIGN:
		{
			edesc = kzalloc(sizeof(*edesc) +
					sizeof(struct ecdsa_sign_desc_s),
					GFP_DMA);
			if (!edesc)
				return NULL;

			if (caam_dsa_sign_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}

			desc = caam_dsa_sign_desc(edesc);
		}
		break;
	case ECDSA_VERIFY:
		{
			edesc = kzalloc(sizeof(*edesc) +
					sizeof(struct ecdsa_verify_desc_s),
					GFP_DMA);
			if (!edesc)
				return NULL;

			if (caam_dsa_verify_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}

			desc = caam_dsa_verify_desc(edesc);
		}
		break;
	case ECC_KEYGEN:
		{
			edesc = kzalloc(sizeof(*edesc) +
					sizeof(struct ecc_keygen_desc_s),
					GFP_DMA);
			if (!edesc)
				return NULL;

			if (caam_keygen_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}

			desc = caam_keygen_desc(edesc);
		}
		break;
	default:
		pr_debug("Unknown DSA Desc init request\n");
		return NULL;
	}
	edesc->req_type = req->type;
	return desc;
}

static int caam_dh_key_edesc(struct pkc_request *req, struct dh_edesc_s *edesc)
{
	struct crypto_pkc *tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(tfm);
	struct device *dev = ctxt->dev;
	struct dh_key_req_s *dh_req = &req->req_u.dh_req;

	edesc->l_len = dh_req->q_len;
	edesc->n_len = dh_req->s_len;
	edesc->req_type = req->type;
	edesc->curve_type = req->curve_type;
	edesc->q_dma = dma_map_single(dev, dh_req->q, dh_req->q_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->q_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto q_map_fail;
	}

	edesc->w_dma = dma_map_single(dev, dh_req->pub_key, dh_req->pub_key_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->w_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto w_map_fail;
	}

	edesc->s_dma = dma_map_single(dev, dh_req->s, dh_req->s_len,
					  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->s_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto s_map_fail;
	}

	edesc->z_dma = dma_map_single(dev, dh_req->z, dh_req->z_len,
					  DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->z_dma)) {
		dev_err(dev, "Unable to map  memory\n");
		goto z_map_fail;
	}
	if (req->type == ECDH_COMPUTE_KEY) {
		edesc->ab_dma = dma_map_single(dev, dh_req->ab, dh_req->ab_len,
					  DMA_TO_DEVICE);
		if (dma_mapping_error(dev, edesc->ab_dma)) {
			dev_err(dev, "Unable to map  memory\n");
			goto ab_map_fail;
		}
	}
	return 0;
ab_map_fail:
	dma_unmap_single(dev, edesc->z_dma, dh_req->z_len, DMA_FROM_DEVICE);
z_map_fail:
	dma_unmap_single(dev, edesc->s_dma, dh_req->s_len, DMA_TO_DEVICE);
s_map_fail:
	dma_unmap_single(dev, edesc->w_dma, dh_req->pub_key_len, DMA_TO_DEVICE);
w_map_fail:
	dma_unmap_single(dev, edesc->q_dma, dh_req->q_len, DMA_TO_DEVICE);
q_map_fail:
	return -EINVAL;
}

/* DSA operation Handler */
static int dsa_op(struct pkc_request *req)
{
	struct crypto_pkc *pkc_tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(pkc_tfm);
	struct device *dev = ctxt->dev;
	int ret = 0;
	void *desc = NULL;

	desc = caam_dsa_desc_init(req);
	if (!desc) {
		dev_err(dev, "Unable to allocate descriptor\n");
		return -ENOMEM;
	}

	ret = caam_jr_enqueue(dev, desc, dsa_op_done, req);
	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/* CAAM Descriptor creator for DH Public Key operations */
static void *caam_dh_desc_init(struct pkc_request *req)
{
	void *desc = NULL;
	struct dh_edesc_s *edesc = NULL;

	switch (req->type) {
	case DH_COMPUTE_KEY:
	case ECDH_COMPUTE_KEY:
		{
			edesc = kzalloc(sizeof(*edesc) +
					sizeof(struct dh_key_desc_s),
					GFP_DMA);
			if (!edesc)
				return NULL;

			if (caam_dh_key_edesc(req, edesc)) {
				kfree(edesc);
				return NULL;
			}
			desc = caam_dh_key_desc(edesc);
		}
		break;
	default:
		pr_debug("Unknown DH Desc init request\n");
		return NULL;
	}
	edesc->req_type = req->type;
	return desc;
}

/* DH Job Completion handler */
static void dh_op_done(struct device *dev, u32 *desc, u32 err, void *context)
{
	struct pkc_request *req = context;
	struct dh_edesc_s *edesc;

	edesc = (struct dh_edesc_s *)((char *)desc -
				     offsetof(struct dh_edesc_s, hw_desc));

	if (err)
		caam_jr_strstatus(dev, err);

	dh_unmap(dev, edesc, req);
	kfree(edesc);

	pkc_request_complete(req, err);
}

static int dh_op(struct pkc_request *req)
{
	struct crypto_pkc *pkc_tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(pkc_tfm);
	struct device *dev = ctxt->dev;
	int ret = 0;
	void *desc = NULL;
	desc = caam_dh_desc_init(req);
	if (!desc) {
		dev_err(dev, "Unable to allocate descriptor\n");
		return -ENOMEM;
	}

	ret = caam_jr_enqueue(dev, desc, dh_op_done, req);
	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/* RSA operation Handler */
static int rsa_op(struct pkc_request *req)
{
	struct crypto_pkc *pkc_tfm = crypto_pkc_reqtfm(req);
	struct caam_pkc_context_s *ctxt = crypto_pkc_ctx(pkc_tfm);
	struct device *dev = ctxt->dev;
	int ret = 0;
	void *desc = NULL;

	desc = caam_rsa_desc_init(req);
	if (!desc) {
		dev_err(dev, "Unable to allocate descriptor\n");
		return -ENOMEM;
	}

	ret = caam_jr_enqueue(dev, desc, rsa_op_done, req);
	if (!ret)
		ret = -EINPROGRESS;

	return ret;
}

/* PKC Descriptor Template */
struct caam_pkc_template {
	char name[CRYPTO_MAX_ALG_NAME];
	char driver_name[CRYPTO_MAX_ALG_NAME];
	char pkc_name[CRYPTO_MAX_ALG_NAME];
	char pkc_driver_name[CRYPTO_MAX_ALG_NAME];
	u32 type;
	struct pkc_alg template_pkc;
};

static struct caam_pkc_template driver_pkc[] = {
	/* RSA driver registeration hooks */
	{
	 .name = "rsa",
	 .driver_name = "rsa-caam",
	 .pkc_name = "pkc(rsa)",
	 .pkc_driver_name = "pkc-rsa-caam",
	 .type = CRYPTO_ALG_TYPE_PKC_RSA,
	 .template_pkc = {
			  .pkc_op = rsa_op,
			  .min_keysize = 512,
			  .max_keysize = 4096,
			  },
	 },
	/* DSA driver registeration hooks */
	{
	 .name = "dsa",
	 .driver_name = "dsa-caam",
	 .pkc_name = "pkc(dsa)",
	 .pkc_driver_name = "pkc-dsa-caam",
	 .type = CRYPTO_ALG_TYPE_PKC_DSA,
	 .template_pkc = {
			  .pkc_op = dsa_op,
			  .min_keysize = 512,
			  .max_keysize = 4096,
			  },
	 },
	/* DH driver registeration hooks */
	{
	 .name = "dh",
	 .driver_name = "dh-caam",
	 .pkc_name = "pkc(dh)",
	 .pkc_driver_name = "pkc-dh-caam",
	 .type = CRYPTO_ALG_TYPE_PKC_DH,
	 .template_pkc = {
			  .pkc_op = dh_op,
			  .min_keysize = 512,
			  .max_keysize = 4096,
			  },
	 }
};

/* Per session pkc's driver context creation function */
static int caam_pkc_cra_init(struct crypto_tfm *tfm)
{
	struct caam_pkc_context_s *ctx = crypto_tfm_ctx(tfm);

	ctx->dev = caam_jr_alloc();

	if (IS_ERR(ctx->dev)) {
		pr_err("Job Ring Device allocation for transform failed\n");
		return PTR_ERR(ctx->dev);
	}
	return 0;
}

/* Per session pkc's driver context cleanup function */
static void caam_pkc_cra_exit(struct crypto_tfm *tfm)
{
	/* Nothing to cleanup in private context */
}

static struct caam_pkc_alg *caam_pkc_alloc(struct device *ctrldev,
					   struct caam_pkc_template *template,
					   bool keyed)
{
	struct caam_pkc_alg *t_alg;
	struct crypto_alg *alg;

	t_alg = kzalloc(sizeof(*t_alg), GFP_KERNEL);
	if (!t_alg) {
		dev_err(ctrldev, "failed to allocate t_alg\n");
		return NULL;
	}

	alg = &t_alg->crypto_alg;
	alg->cra_pkc = template->template_pkc;

	if (keyed) {
		snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->pkc_name);
		snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->pkc_driver_name);
	} else {
		snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->name);
		snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->driver_name);
	}
	alg->cra_module = THIS_MODULE;
	alg->cra_init = caam_pkc_cra_init;
	alg->cra_exit = caam_pkc_cra_exit;
	alg->cra_ctxsize = sizeof(struct caam_pkc_context_s);
	alg->cra_priority = CAAM_PKC_PRIORITY;
	alg->cra_alignmask = 0;
	alg->cra_flags = CRYPTO_ALG_ASYNC | template->type;
	alg->cra_type = &crypto_pkc_type;
	t_alg->ctrldev = ctrldev;

	return t_alg;
}

/* Public Key Cryptography module initialization handler */
static int __init caam_pkc_init(void)
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
	if (!pdev)
		return -ENODEV;

	ctrldev = &pdev->dev;
	priv = dev_get_drvdata(ctrldev);
	of_node_put(dev_node);

	/*
	 * If priv is NULL, it's probably because the caam driver wasn't
	 * properly initialized (e.g. RNG4 init failed). Thus, bail out here.
	 */
	if (!priv)
		return -ENODEV;

	INIT_LIST_HEAD(&priv->pkc_list);

	/* register crypto algorithms the device supports */
	for (i = 0; i < ARRAY_SIZE(driver_pkc); i++) {
		/* TODO: check if h/w supports alg */
		struct caam_pkc_alg *t_alg;

		/* register pkc algorithm */
		t_alg = caam_pkc_alloc(ctrldev, &driver_pkc[i], true);
		if (IS_ERR(t_alg)) {
			err = PTR_ERR(t_alg);
			dev_warn(ctrldev, "%s alg allocation failed\n",
				 driver_pkc[i].driver_name);
			continue;
		}

		err = crypto_register_alg(&t_alg->crypto_alg);
		if (err) {
			dev_warn(ctrldev, "%s alg registration failed\n",
				 t_alg->crypto_alg.cra_driver_name);
			kfree(t_alg);
		} else {
			list_add_tail(&t_alg->entry, &priv->pkc_list);
		}
	}

	if (!list_empty(&priv->pkc_list))
		dev_info(ctrldev, "%s algorithms registered in /proc/crypto\n",
			 (char *)of_get_property(dev_node, "compatible", NULL));

	return err;
}

static void __exit caam_pkc_exit(void)
{
	struct device_node *dev_node;
	struct platform_device *pdev;
	struct device *ctrldev;
	struct caam_drv_private *priv;
	struct caam_pkc_alg *t_alg, *n;

	dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec-v4.0");

	if (!dev_node) {
		dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec4.0");
		if (!dev_node)
			return;
	}

	pdev = of_find_device_by_node(dev_node);

	if (!pdev)
		return;

	ctrldev = &pdev->dev;
	of_node_put(dev_node);
	priv = dev_get_drvdata(ctrldev);

	if (!priv->pkc_list.next)
		return;

	list_for_each_entry_safe(t_alg, n, &priv->pkc_list, entry) {
		crypto_unregister_alg(&t_alg->crypto_alg);
		list_del(&t_alg->entry);
		kfree(t_alg);
	}
}

module_init(caam_pkc_init);
module_exit(caam_pkc_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FSL CAAM support for PKC functions of crypto API");
MODULE_AUTHOR("Yashpal Dutta <yashpal.dutta@freescale.com>");
