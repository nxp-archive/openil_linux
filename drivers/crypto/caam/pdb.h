/*
 * CAAM Protocol Data Block (PDB) definition header file
 *
 * Copyright 2008-2012 Freescale Semiconductor, Inc.
 *
 */

#ifndef CAAM_PDB_H
#define CAAM_PDB_H

/*
 * PDB- IPSec ESP Header Modification Options
 */
#define PDBHMO_ESP_DECAP_SHIFT	12
#define PDBHMO_ESP_ENCAP_SHIFT	4
/*
 * Encap and Decap - Decrement TTL (Hop Limit) - Based on the value of the
 * Options Byte IP version (IPvsn) field:
 * if IPv4, decrement the inner IP header TTL field (byte 8);
 * if IPv6 decrement the inner IP header Hop Limit field (byte 7).
*/
#define PDBHMO_ESP_DECAP_DEC_TTL	(0x02 << PDBHMO_ESP_DECAP_SHIFT)
#define PDBHMO_ESP_ENCAP_DEC_TTL	(0x02 << PDBHMO_ESP_ENCAP_SHIFT)
/*
 * Decap - DiffServ Copy - Copy the IPv4 TOS or IPv6 Traffic Class byte
 * from the outer IP header to the inner IP header.
 */
#define PDBHMO_ESP_DIFFSERV		(0x01 << PDBHMO_ESP_DECAP_SHIFT)
/*
 * Encap- Copy DF bit -if an IPv4 tunnel mode outer IP header is coming from
 * the PDB, copy the DF bit from the inner IP header to the outer IP header.
 */
#define PDBHMO_ESP_DFBIT		(0x04 << PDBHMO_ESP_ENCAP_SHIFT)

/*
 * PDB - IPSec ESP Encap/Decap Options
 */
#define PDBOPTS_ESP_ARSNONE	0x00 /* no antireplay window */
#define PDBOPTS_ESP_ARS32	0x40 /* 32-entry antireplay window */
#define PDBOPTS_ESP_ARS64	0xc0 /* 64-entry antireplay window */
#define PDBOPTS_ESP_IVSRC	0x20 /* IV comes from internal random gen */
#define PDBOPTS_ESP_ESN		0x10 /* extended sequence included */
#define PDBOPTS_ESP_OUTFMT	0x08 /* output only decapsulation (decap) */
#define PDBOPTS_ESP_IPHDRSRC	0x08 /* IP header comes from PDB (encap) */
#define PDBOPTS_ESP_INCIPHDR	0x04 /* Prepend IP header to output frame */
#define PDBOPTS_ESP_IPVSN	0x02 /* process IPv6 header */
#define PDBOPTS_ESP_AOFL	0x04 /* adjust out frame len (decap, SEC>=5.3)*/
#define PDBOPTS_ESP_TUNNEL	0x01 /* tunnel mode next-header byte */
#define PDBOPTS_ESP_IPV6	0x02 /* ip header version is V6 */
#define PDBOPTS_ESP_DIFFSERV	0x40 /* copy TOS/TC from inner iphdr */
#define PDBOPTS_ESP_UPDATE_CSUM 0x80 /* encap-update ip header checksum */
#define PDBOPTS_ESP_VERIFY_CSUM 0x20 /* decap-validate ip header checksum */

/*
 * General IPSec encap/decap PDB definitions
 */
struct ipsec_encap_cbc {
	u32 iv[4];
};

struct ipsec_encap_ctr {
	u32 ctr_nonce;
	u32 ctr_initial;
	u32 iv[2];
};

struct ipsec_encap_ccm {
	u32 salt; /* lower 24 bits */
#ifndef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
	u8 b0_flags;
	u8 ctr_flags;
	u16 ctr_initial;
#else /* CONFIG_CRYPTO_DEV_FSL_CAAM_LE */
	u16 ctr_initial;
	u8 ctr_flags;
	u8 b0_flags;
#endif /* !defined(CONFIG_CRYPTO_DEV_FSL_CAAM_LE) */
	u32 iv[2];
};

struct ipsec_encap_gcm {
	u32 salt; /* lower 24 bits */
	u32 rsvd1;
	u32 iv[2];
};

struct ipsec_encap_pdb {
#ifndef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
	u8 hmo_rsvd;
	u8 ip_nh;
	u8 ip_nh_offset;
	u8 options;
#else /* CONFIG_CRYPTO_DEV_FSL_CAAM_LE */
	u8 options;
	u8 ip_nh_offset;
	u8 ip_nh;
	u8 hmo_rsvd;
#endif /* !defined(CONFIG_CRYPTO_DEV_FSL_CAAM_LE) */
	u32 seq_num_ext_hi;
	u32 seq_num;
	union {
		struct ipsec_encap_cbc cbc;
		struct ipsec_encap_ctr ctr;
		struct ipsec_encap_ccm ccm;
		struct ipsec_encap_gcm gcm;
	};
	u32 spi;
#ifndef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
	u16 rsvd1;
	u16 ip_hdr_len;
#else /* CONFIG_CRYPTO_DEV_FSL_CAAM_LE */
	u16 ip_hdr_len;
	u16 rsvd1;
#endif /* !defined(CONFIG_CRYPTO_DEV_FSL_CAAM_LE) */
	u32 ip_hdr[0]; /* optional IP Header content */
};

struct ipsec_decap_cbc {
	u32 rsvd[2];
};

struct ipsec_decap_ctr {
	u32 salt;
	u32 ctr_initial;
};

struct ipsec_decap_ccm {
	u32 salt;
#ifndef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
	u8 iv_flags;
	u8 ctr_flags;
	u16 ctr_initial;
#else /* CONFIG_CRYPTO_DEV_FSL_CAAM_LE */
	u16 ctr_initial;
	u8 ctr_flags;
	u8 iv_flags;
#endif /* !defined(CONFIG_CRYPTO_DEV_FSL_CAAM_LE) */
};

struct ipsec_decap_gcm {
	u32 salt;
	u32 resvd;
};

struct ipsec_decap_pdb {
#ifndef CONFIG_CRYPTO_DEV_FSL_CAAM_LE
	u16 hmo_ip_hdr_len;
	u8 ip_nh_offset;
	u8 options;
#else /* CONFIG_CRYPTO_DEV_FSL_CAAM_LE */
	u8 options;
	u8 ip_nh_offset;
	u16 hmo_ip_hdr_len;
#endif /* !defined(CONFIG_CRYPTO_DEV_FSL_CAAM_LE) */
	union {
		struct ipsec_decap_cbc cbc;
		struct ipsec_decap_ctr ctr;
		struct ipsec_decap_ccm ccm;
		struct ipsec_decap_gcm gcm;
	};
	u32 seq_num_ext_hi;
	u32 seq_num;
	u32 anti_replay[2];
	u32 end_index[0];
};

/*
 * IPSec ESP Datapath Protocol Override Register (DPOVRD)
 */
struct ipsec_deco_dpovrd {
#define IPSEC_ENCAP_DECO_DPOVRD_USE 0x80
	u8 ovrd_ecn;
	u8 ip_hdr_len;
	u8 nh_offset;
	u8 next_header; /* reserved if decap */
};

/*
 * IEEE 802.11i WiFi Protocol Data Block
 */
#define WIFI_PDBOPTS_FCS	0x01
#define WIFI_PDBOPTS_AR		0x40

struct wifi_encap_pdb {
	u16 mac_hdr_len;
	u8 rsvd;
	u8 options;
	u8 iv_flags;
	u8 pri;
	u16 pn1;
	u32 pn2;
	u16 frm_ctrl_mask;
	u16 seq_ctrl_mask;
	u8 rsvd1[2];
	u8 cnst;
	u8 key_id;
	u8 ctr_flags;
	u8 rsvd2;
	u16 ctr_init;
};

struct wifi_decap_pdb {
	u16 mac_hdr_len;
	u8 rsvd;
	u8 options;
	u8 iv_flags;
	u8 pri;
	u16 pn1;
	u32 pn2;
	u16 frm_ctrl_mask;
	u16 seq_ctrl_mask;
	u8 rsvd1[4];
	u8 ctr_flags;
	u8 rsvd2;
	u16 ctr_init;
};

/*
 * IEEE 802.16 WiMAX Protocol Data Block
 */
#define WIMAX_PDBOPTS_FCS	0x01
#define WIMAX_PDBOPTS_AR	0x40 /* decap only */

struct wimax_encap_pdb {
	u8 rsvd[3];
	u8 options;
	u32 nonce;
	u8 b0_flags;
	u8 ctr_flags;
	u16 ctr_init;
	/* begin DECO writeback region */
	u32 pn;
	/* end DECO writeback region */
};

struct wimax_decap_pdb {
	u8 rsvd[3];
	u8 options;
	u32 nonce;
	u8 iv_flags;
	u8 ctr_flags;
	u16 ctr_init;
	/* begin DECO writeback region */
	u32 pn;
	u8 rsvd1[2];
	u16 antireplay_len;
	u64 antireplay_scorecard;
	/* end DECO writeback region */
};

/*
 * IEEE 801.AE MacSEC Protocol Data Block
 */
#define MACSEC_PDBOPTS_FCS	0x01
#define MACSEC_PDBOPTS_AR	0x40 /* used in decap only */

struct macsec_encap_pdb {
	u16 aad_len;
	u8 rsvd;
	u8 options;
	u64 sci;
	u16 ethertype;
	u8 tci_an;
	u8 rsvd1;
	/* begin DECO writeback region */
	u32 pn;
	/* end DECO writeback region */
};

struct macsec_decap_pdb {
	u16 aad_len;
	u8 rsvd;
	u8 options;
	u64 sci;
	u8 rsvd1[3];
	/* begin DECO writeback region */
	u8 antireplay_len;
	u32 pn;
	u64 antireplay_scorecard;
	/* end DECO writeback region */
};

/*
 * SSL/TLS/DTLS Protocol Data Blocks
 */

#define TLS_PDBOPTS_ARS32	0x40
#define TLS_PDBOPTS_ARS64	0xc0
#define TLS_PDBOPTS_OUTFMT	0x08
#define TLS_PDBOPTS_IV_WRTBK	0x02 /* 1.1/1.2/DTLS only */
#define TLS_PDBOPTS_EXP_RND_IV	0x01 /* 1.1/1.2/DTLS only */

struct tls_block_encap_pdb {
	u8 type;
	u8 version[2];
	u8 options;
	u64 seq_num;
	u32 iv[4];
};

struct tls_stream_encap_pdb {
	u8 type;
	u8 version[2];
	u8 options;
	u64 seq_num;
	u8 i;
	u8 j;
	u8 rsvd1[2];
};

struct dtls_block_encap_pdb {
	u8 type;
	u8 version[2];
	u8 options;
	u16 epoch;
	u16 seq_num[3];
	u32 iv[4];
};

struct tls_block_decap_pdb {
	u8 rsvd[3];
	u8 options;
	u64 seq_num;
	u32 iv[4];
};

struct tls_stream_decap_pdb {
	u8 rsvd[3];
	u8 options;
	u64 seq_num;
	u8 i;
	u8 j;
	u8 rsvd1[2];
};

struct dtls_block_decap_pdb {
	u8 rsvd[3];
	u8 options;
	u16 epoch;
	u16 seq_num[3];
	u32 iv[4];
	u64 antireplay_scorecard;
};

/*
 * SRTP Protocol Data Blocks
 */
#define SRTP_PDBOPTS_MKI	0x08
#define SRTP_PDBOPTS_AR		0x40

struct srtp_encap_pdb {
	u8 x_len;
	u8 mki_len;
	u8 n_tag;
	u8 options;
	u32 cnst0;
	u8 rsvd[2];
	u16 cnst1;
	u16 salt[7];
	u16 cnst2;
	u32 rsvd1;
	u32 roc;
	u32 opt_mki;
};

struct srtp_decap_pdb {
	u8 x_len;
	u8 mki_len;
	u8 n_tag;
	u8 options;
	u32 cnst0;
	u8 rsvd[2];
	u16 cnst1;
	u16 salt[7];
	u16 cnst2;
	u16 rsvd1;
	u16 seq_num;
	u32 roc;
	u64 antireplay_scorecard;
};

/*
 * DSA/ECDSA Protocol Data Blocks
 * Two of these exist: DSA-SIGN, and DSA-VERIFY. They are similar
 * except for the treatment of "w" for verify, "s" for sign,
 * and the placement of "a,b".
 */
#define DSA_PDB_SGF_SHIFT	24
#define DSA_PDB_SGF_MASK	(0xff << DSA_PDB_SGF_SHIFT)
#define DSA_PDB_SGF_Q		(0x80 << DSA_PDB_SGF_SHIFT)
#define DSA_PDB_SGF_R		(0x40 << DSA_PDB_SGF_SHIFT)
#define DSA_PDB_SGF_G		(0x20 << DSA_PDB_SGF_SHIFT)
#define DSA_PDB_SGF_W		(0x10 << DSA_PDB_SGF_SHIFT)
#define DSA_PDB_SGF_S		(0x10 << DSA_PDB_SGF_SHIFT)
#define DSA_PDB_SGF_F		(0x08 << DSA_PDB_SGF_SHIFT)
#define DSA_PDB_SGF_C		(0x04 << DSA_PDB_SGF_SHIFT)
#define DSA_PDB_SGF_D		(0x02 << DSA_PDB_SGF_SHIFT)
#define DSA_PDB_SGF_AB_SIGN	(0x02 << DSA_PDB_SGF_SHIFT)
#define DSA_PDB_SGF_AB_VERIFY	(0x01 << DSA_PDB_SGF_SHIFT)

#define DSA_PDB_L_SHIFT		7
#define DSA_PDB_L_MASK		(0x3ff << DSA_PDB_L_SHIFT)

#define DSA_PDB_N_MASK		0x7f

struct dsa_sign_desc_s {
	uint32_t	desc_hdr;
	uint32_t sgf_ln; /* Use DSA_PDB_ definitions per above */
	dma_addr_t q_dma;
	dma_addr_t r_dma;
	dma_addr_t g_dma;	/* or Gx,y */
	dma_addr_t s_dma;
	dma_addr_t f_dma;
	dma_addr_t c_dma;
	dma_addr_t d_dma;
	uint32_t	op;
} __packed;

struct dsa_verify_desc_s {
	uint32_t	desc_hdr;
	uint32_t sgf_ln;
	dma_addr_t q_dma;
	dma_addr_t r_dma;
	dma_addr_t g_dma;	/* or Gx,y */
	dma_addr_t w_dma; /* or Wx,y */
	dma_addr_t f_dma;
	dma_addr_t c_dma;
	dma_addr_t d_dma;
	dma_addr_t tmp_dma; /* temporary data block */
	uint32_t	op;
} __packed;

struct dlc_keygen_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_ln;
	dma_addr_t q_dma;
	dma_addr_t r_dma;
	dma_addr_t g_dma;
	dma_addr_t s_dma;
	dma_addr_t w_dma;
	uint32_t op;
} __packed;

struct ecdsa_sign_desc_s {
	uint32_t	desc_hdr;
	uint32_t sgf_ln; /* Use ECDSA_PDB_ definitions per above */
	dma_addr_t q_dma;
	dma_addr_t r_dma;
	dma_addr_t g_dma;	/* or Gx,y */
	dma_addr_t s_dma;
	dma_addr_t f_dma;
	dma_addr_t c_dma;
	dma_addr_t d_dma;
	dma_addr_t ab_dma;
	uint32_t	op;
} __packed;

struct ecdsa_verify_desc_s {
	uint32_t	desc_hdr;
	uint32_t sgf_ln;
	dma_addr_t q_dma;
	dma_addr_t r_dma;
	dma_addr_t g_dma;	/* or Gx,y */
	dma_addr_t w_dma; /* or Wx,y */
	dma_addr_t f_dma;
	dma_addr_t c_dma;
	dma_addr_t d_dma;
	dma_addr_t tmp_dma; /* temporary data block */
	dma_addr_t ab_dma;
	uint32_t	op;
} __packed;

struct ecc_keygen_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_ln;
	dma_addr_t q_dma;
	dma_addr_t r_dma;
	dma_addr_t g_dma;
	dma_addr_t s_dma;
	dma_addr_t w_dma;
	dma_addr_t ab_dma;
	uint32_t op;
} __packed;

#define DH_PDB_L_SHIFT         7
#define DH_PDB_L_MASK          (0x3ff << DH_PDB_L_SHIFT)
#define DH_PDB_N_MASK          0x7f
#define DH_PDB_SGF_SHIFT       24
#define DH_PDB_SGF_MASK        (0xff << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_Q           (0x80 << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_R           (0x40 << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_W           (0x20 << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_S           (0x10 << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_Z           (0x08 << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_AB          (0x04 << DH_PDB_SGF_SHIFT)

struct dh_key_desc_s {
	uint32_t	desc_hdr;
	uint32_t sgf_ln; /* Use DH_PDB_ definitions per above */
	dma_addr_t q_dma;
	dma_addr_t r_dma;
	dma_addr_t w_dma;
	dma_addr_t s_dma;
	dma_addr_t z_dma;
	dma_addr_t ab_dma;
	uint32_t	op;
} __packed;

/* DSA/ECDSA Protocol Data Blocks */
#define RSA_PDB_SGF_SHIFT       28
#define RSA_PDB_MSG_FMT_SHIFT   12
#define RSA_PDB_E_SHIFT       12
#define RSA_PDB_E_MASK        (0xFFF << RSA_PDB_E_SHIFT)
#define RSA_PDB_D_SHIFT       12
#define RSA_PDB_D_MASK        (0xFFF << RSA_PDB_D_SHIFT)
#define RSA_PDB_Q_SHIFT       12
#define RSA_PDB_Q_MASK        (0xFFF << RSA_PDB_Q_SHIFT)


#define RSA_PDB_SGF_F		(0x8 << RSA_PDB_SGF_SHIFT)
#define RSA_PDB_SGF_G		(0x4 << RSA_PDB_SGF_SHIFT)
#define RSA_PDB_SGF_N		(0x2 << RSA_PDB_SGF_SHIFT)
#define RSA_PDB_SGF_E		(0x1 << RSA_PDB_SGF_SHIFT)

#define RSA_PRIV_KEY_FRM_1	0
#define RSA_PRIV_KEY_FRM_2	1
#define RSA_PRIV_KEY_FRM_3	2

#define RSA_PDB_PVT_FRM1_SGF_SHIFT  28
#define RSA_PDB_PVT_FRM1_D_SHIFT 10

#define RSA_PDB_PVT_MSG_FMT_SHIFT   12
#define RSA_PDB_PVT_FRM3_SGF_SHIFT  23
#define RSA_PDB_PVT_FRM3_Q_SHIFT  12

/* RSA Pub_Key Descriptor */
struct rsa_pub_desc_s {
	uint32_t	desc_hdr;
	uint32_t	sgf_flg;
	dma_addr_t	f_dma;
	dma_addr_t	g_dma;
	dma_addr_t	n_dma;
	dma_addr_t	e_dma;
	uint32_t	msg_len;
	uint32_t	op;
} __packed;

/*
 * Form1 Priv_key Decryption Descriptor
 * Private key is represented by (n,d)
 * f is decrypted data pointer while g is pointer
 * of encrypted data
 */
struct rsa_priv_frm1_desc_s {
	uint32_t	desc_hdr;
	uint32_t	sgf_flg;
	dma_addr_t	g_dma;
	dma_addr_t	f_dma;
	dma_addr_t	n_dma;
	dma_addr_t	d_dma;
	uint32_t	op;
} __packed;

/*
 * Form2 Priv_key Decryption Descriptor
 * Private key is represented by (p,q,d)
 * f is decrypted data pointer while g is pointer
 * of encrypted data
 */
struct rsa_priv_frm2_desc_s {
	uint32_t	desc_hdr;
	uint32_t	sgf_flg;
	dma_addr_t	g_dma;
	dma_addr_t	f_dma;
	dma_addr_t	d_dma;
	dma_addr_t	p_dma;
	dma_addr_t	q_dma;
	dma_addr_t	tmp1_dma;
	dma_addr_t	tmp2_dma;
	uint32_t	p_q_len;
	uint32_t	op;
} __packed;

/*
 * Form3 Priv_key Decryption Descriptor
 * Private key is represented by (p,q,dp,dq,c)
 * f is decrypted data pointer while g is input pointer
 * of encrypted data
 */
struct rsa_priv_frm3_desc_s {
	uint32_t	desc_hdr;
	uint32_t	sgf_flg;
	dma_addr_t	g_dma;
	dma_addr_t	f_dma;
	dma_addr_t	c_dma;
	dma_addr_t	p_dma;
	dma_addr_t	q_dma;
	dma_addr_t	dp_dma;
	dma_addr_t	dq_dma;
	dma_addr_t	tmp1_dma;
	dma_addr_t	tmp2_dma;
	uint32_t	p_q_len;
	uint32_t	op;
} __packed;

#endif
