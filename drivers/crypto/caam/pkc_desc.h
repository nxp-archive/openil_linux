/*
 * \file - pkc_desc.h
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
#ifndef _PKC_DESC_H_
#define _PKC_DESC_H_

#include "compat.h"

#include "regs.h"
#include "intern.h"
#include "desc_constr.h"
#include "jr.h"
#include "error.h"
#include "sg_sw_sec4.h"
#include <linux/crypto.h>
#include "pdb.h"

/* Public key SG Flags and e, n lengths */
struct sg_public_flg_s {
	uint32_t sg_f:1;
	uint32_t sg_g:1;
	uint32_t sg_n:1;
	uint32_t sg_e:1;
	uint32_t reserved:4;
	uint32_t e_len:12;
	uint32_t n_len:12;
};

/* RSA public Extended Descriptor fields
 @n_dma - n, e represents the public key
 @e_dma - Public key exponent,  n is modulus
 @g_dma - Output RSA-encrypted value
 @f_dma - Input RSA-Plain value
 @n_len, e_len - Public key param length
 @ f_len - input data len
 */
struct rsa_pub_edesc_s {
	dma_addr_t n_dma;
	dma_addr_t e_dma;
	dma_addr_t g_dma;
	dma_addr_t f_dma;
	struct sg_public_flg_s sg_flgs;
	uint32_t reserved:20;
	uint32_t f_len:12;
};

/* Private key Form1 SG Flags and d, n lengths */
struct sg_priv_f1_flg_s {
	uint32_t sg_g:1;
	uint32_t sg_f:1;
	uint32_t sg_n:1;
	uint32_t sg_d:1;
	uint32_t reserved:4;
	uint32_t d_len:12;
	uint32_t n_len:12;
};

/* RSA PrivKey Form1 Extended Descriptor fields
 @n_dma - n, d represents the private key form1 representation
 @d_dma - d is the private exponent, n is the modules
 @g_dma - Input RSA-encrypted value
 @f_dma - Output RSA-Plain value
 */
struct rsa_priv_frm1_edesc_s {
	dma_addr_t n_dma;
	dma_addr_t d_dma;
	dma_addr_t f_dma;
	dma_addr_t g_dma;
	struct sg_priv_f1_flg_s sg_flgs;
};

/* Private key Form2 SG Flags and d, n lengths */
struct sg_priv_f2_flg_s {
	uint32_t sg_g:1;
	uint32_t sg_f:1;
	uint32_t sg_d:1;
	uint32_t sg_p:1;
	uint32_t sg_q:1;
	uint32_t sg_tmp1:1;
	uint32_t sg_tmp2:1;
	uint32_t reserved:1;
	uint32_t d_len:12;
	uint32_t n_len:12;
};

/* RSA PrivKey Form2
 @p, q, d represents the private key form2 representation
 @d - d is private exponent, p and q are the two primes
 @f - output pointer
 @g - input pointer
 */
struct rsa_priv_frm2_edesc_s {
	dma_addr_t p_dma;
	dma_addr_t q_dma;
	dma_addr_t d_dma;
	dma_addr_t f_dma;
	dma_addr_t g_dma;
	int8_t *tmp1;
	int8_t *tmp2;
	dma_addr_t tmp1_dma;
	dma_addr_t tmp2_dma;
	struct sg_priv_f2_flg_s sg_flgs;
	uint32_t reserved:8;
	uint32_t q_len:12;
	uint32_t p_len:12;
};

/* Private key Form3 SG Flags and d, n lengths */
struct sg_priv_f3_flg_s {
	uint32_t sg_g:1;
	uint32_t sg_f:1;
	uint32_t sg_c:1;
	uint32_t sg_p:1;
	uint32_t sg_q:1;
	uint32_t sg_dp:1;
	uint32_t sg_dq:1;
	uint32_t sg_tmp1:1;
	uint32_t sg_tmp2:1;
	uint32_t reserved:11;
	uint32_t n_len:12;
};

/* RSA PrivKey Form3
 @n - p, q, dp, dq, c represents the private key form3 representation
 @dp - First CRT exponent factor
 @dq - Second CRT exponent factor
 @c - CRT Coefficient
 @f - output pointer
 @g - input pointer
 */
struct rsa_priv_frm3_edesc_s {
	dma_addr_t p_dma;
	dma_addr_t q_dma;
	dma_addr_t dp_dma;
	dma_addr_t dq_dma;
	dma_addr_t c_dma;
	dma_addr_t f_dma;
	dma_addr_t g_dma;
	int8_t *tmp1;
	int8_t *tmp2;
	dma_addr_t tmp1_dma;
	dma_addr_t tmp2_dma;
	struct sg_priv_f3_flg_s sg_flgs;
	uint32_t reserved:8;
	uint32_t q_len:12;
	uint32_t p_len:12;
};

/*
 * rsa_edesc - s/w-extended rsa descriptor
 * @hw_desc: the h/w job descriptor
 */
struct rsa_edesc {
	enum pkc_req_type req_type;
	union {
		struct rsa_pub_edesc_s rsa_pub_edesc;
		struct rsa_priv_frm1_edesc_s rsa_priv_f1_edesc;
		struct rsa_priv_frm2_edesc_s rsa_priv_f2_edesc;
		struct rsa_priv_frm3_edesc_s rsa_priv_f3_edesc;
	} dma_u;
	u32 hw_desc[];
};

/*
 * dsa_edesc - s/w-extended for dsa and ecdsa descriptors
 * @hw_desc: the h/w job descriptor
 */
struct dsa_edesc_s {
	enum pkc_req_type req_type;
	enum curve_t curve_type;
	uint32_t l_len;
	uint32_t n_len;
	dma_addr_t key_dma;
	dma_addr_t s_dma;
	dma_addr_t f_dma;
	dma_addr_t q_dma;
	dma_addr_t r_dma;
	dma_addr_t c_dma;
	dma_addr_t d_dma;
	dma_addr_t ab_dma;
	dma_addr_t g_dma;
	dma_addr_t g_sg_dma;
	dma_addr_t tmp_dma;
	uint8_t *tmp; /* Allocate locally for dsa_verify */
	struct sec4_sg_entry g_sg;
	bool erratum_A_006899;
	u32 hw_desc[];
};

/*
 * dh_edesc - s/w-extended for dh and ecdh descriptors
 * @hw_desc: the h/w job descriptor
 */
struct dh_edesc_s {
	enum pkc_req_type req_type;
	enum curve_t curve_type;
	uint32_t l_len;
	uint32_t n_len;
	dma_addr_t q_dma;
	dma_addr_t ab_dma;
	dma_addr_t w_dma;
	dma_addr_t s_dma;
	dma_addr_t z_dma;
	u32 hw_desc[];
};

void *caam_rsa_pub_desc(struct rsa_edesc *);
void *caam_rsa_priv_f1_desc(struct rsa_edesc *);
void *caam_rsa_priv_f2_desc(struct rsa_edesc *);
void *caam_rsa_priv_f3_desc(struct rsa_edesc *);
void *caam_dsa_sign_desc(struct dsa_edesc_s *);
void *caam_dsa_verify_desc(struct dsa_edesc_s *);
void *caam_keygen_desc(struct dsa_edesc_s *);
void *caam_dh_key_desc(struct dh_edesc_s *);

#endif
