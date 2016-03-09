/* Copyright 2008-2013 Freescale Semiconductor, Inc.
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

#ifndef __DPA_IPSEC_H__
#define __DPA_IPSEC_H__

#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include <linux/fsl_dpa_ipsec.h>

/* From Linux for Shared Descriptor auxiliary structures */
#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/workqueue.h>

/*For IP header structure definition */
#include <linux/ip.h>
#include <linux/ipv6.h>

/*For UDP header structure definition */
#include <linux/udp.h>

#include "desc.h"

#include "fm_pcd_ext.h"
#include "cq.h"

#define OP_PCL_IPSEC_INVALID_ALG_ID	0xFFFF

#define IPSEC_ALGS_ENTRY(enc, auth)	{		\
		.enc_alg = OP_PCL_IPSEC_ ## enc,	\
		.auth_alg = OP_PCL_IPSEC_ ## auth	\
	}

#define IPSEC_ALGS	{					\
	/* DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_MD5_128 */	\
	IPSEC_ALGS_ENTRY(3DES, HMAC_MD5_96),			\
	/* DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_SHA_160 */	\
	IPSEC_ALGS_ENTRY(3DES, HMAC_SHA1_96),			\
	/* DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_MD5_128 */	\
	IPSEC_ALGS_ENTRY(3DES, HMAC_MD5_128),			\
	/* DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_160 */	\
	IPSEC_ALGS_ENTRY(3DES, HMAC_SHA1_160),			\
	/* DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_256_128 */	\
	IPSEC_ALGS_ENTRY(3DES, HMAC_SHA2_256_128),		\
	/* DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_384_192 */	\
	IPSEC_ALGS_ENTRY(3DES, HMAC_SHA2_384_192),		\
	/* DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_512_256 */	\
	IPSEC_ALGS_ENTRY(3DES, HMAC_SHA2_512_256),		\
	/* DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_96_MD5_128 */	\
	IPSEC_ALGS_ENTRY(NULL_ENC, HMAC_MD5_96),		\
	/* DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_96_SHA_160 */	\
	IPSEC_ALGS_ENTRY(NULL_ENC, HMAC_SHA1_96),		\
	/* DPA_IPSEC_CIPHER_ALG_NULL_ENC_AES_XCBC_MAC_96 */	\
	IPSEC_ALGS_ENTRY(NULL_ENC, AES_XCBC_MAC_96),	\
	/* DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_MD5_128 */	\
	IPSEC_ALGS_ENTRY(NULL_ENC, HMAC_MD5_128),		\
	/* DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_160 */	\
	IPSEC_ALGS_ENTRY(NULL_ENC, HMAC_SHA1_160),	\
	/* DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_256_128 */	\
	IPSEC_ALGS_ENTRY(NULL_ENC, HMAC_SHA2_256_128),	\
	/* DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_384_192 */	\
	IPSEC_ALGS_ENTRY(NULL_ENC, HMAC_SHA2_384_192),	\
	/* DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_512_256 */	\
	IPSEC_ALGS_ENTRY(NULL_ENC, HMAC_SHA2_512_256),	\
	/* DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_MD5_128 */	\
	IPSEC_ALGS_ENTRY(AES_CBC, HMAC_MD5_96),			\
	/* DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_SHA_160 */	\
	IPSEC_ALGS_ENTRY(AES_CBC, HMAC_SHA1_96),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CBC_AES_XCBC_MAC_96 */	\
	IPSEC_ALGS_ENTRY(AES_CBC, AES_XCBC_MAC_96),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_MD5_128 */		\
	IPSEC_ALGS_ENTRY(AES_CBC, HMAC_MD5_128),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_160 */		\
	IPSEC_ALGS_ENTRY(AES_CBC, HMAC_SHA1_160),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_256_128 */	\
	IPSEC_ALGS_ENTRY(AES_CBC, HMAC_SHA2_256_128),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_384_192 */	\
	IPSEC_ALGS_ENTRY(AES_CBC, HMAC_SHA2_384_192),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_512_256 */	\
	IPSEC_ALGS_ENTRY(AES_CBC, HMAC_SHA2_512_256),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_MD5_128 */	\
	IPSEC_ALGS_ENTRY(AES_CTR, HMAC_MD5_96),			\
	/* DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_SHA_160 */	\
	IPSEC_ALGS_ENTRY(AES_CTR, HMAC_SHA1_96),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CTR_AES_XCBC_MAC_96 */	\
	IPSEC_ALGS_ENTRY(AES_CTR, AES_XCBC_MAC_96),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_MD5_128 */		\
	IPSEC_ALGS_ENTRY(AES_CTR, HMAC_MD5_128),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_160 */		\
	IPSEC_ALGS_ENTRY(AES_CTR, HMAC_SHA1_160),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_256_128 */	\
	IPSEC_ALGS_ENTRY(AES_CTR, HMAC_SHA2_256_128),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_384_192 */	\
	IPSEC_ALGS_ENTRY(AES_CTR, HMAC_SHA2_384_192),		\
	/* DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_512_256 */	\
	IPSEC_ALGS_ENTRY(AES_CTR, HMAC_SHA2_512_256)		\
}

#define GET_POL_TABLE_IDX(_proto, _ip_ver)				\
	((_proto == IPPROTO_TCP)  ? DPA_IPSEC_PROTO_TCP_##_ip_ver :	\
	 (_proto == IPPROTO_UDP)  ? DPA_IPSEC_PROTO_UDP_##_ip_ver :	\
	((_proto == IPPROTO_ICMP) ||					\
	 (_proto == IPPROTO_ICMPV6)) ? DPA_IPSEC_PROTO_ICMP_##_ip_ver :	\
	 (_proto == IPPROTO_SCTP) ? DPA_IPSEC_PROTO_SCTP_##_ip_ver :	\
	  DPA_IPSEC_PROTO_ANY_##_ip_ver)

#define DPA_IPSEC_ADDR_T_IPv4	4
#define DPA_IPSEC_ADDR_T_IPv6	6

#define IP_ADDR_TYPE_IPV4(_ipAddr) (_ipAddr.version == DPA_IPSEC_ADDR_T_IPv4)
#define IP_ADDR(_ipAddr) \
	(IP_ADDR_TYPE_IPV4(_ipAddr) ? \
	(_ipAddr.addr.ipv4.byte) : (_ipAddr.addr.ipv6.byte))
#define IP_ADDR_LEN(_ipAddr) \
	(IP_ADDR_TYPE_IPV4(_ipAddr) ? \
	(DPA_OFFLD_IPv4_ADDR_LEN_BYTES) : (DPA_OFFLD_IPv6_ADDR_LEN_BYTES))

#define SET_BYTE_VAL_IN_ARRAY(_key, _off, _val) (_key[_off] = _val)
#define SET_IP_PROTO_MASK(_mask, _off, _is_masked) \
		(_mask[_off] = _is_masked ? 0x00 : 0xFF)
#define SET_L4_PORT_MASK(_mask, _off, _val) \
		(*(uint16_t *) &(_mask[_off]) = _val)

#define TABLE_KEY_SIZE(_tbl_params) \
	((_tbl_params.type == DPA_CLS_TBL_HASH) ? \
		tbl_params.hash_params.key_size : \
		(_tbl_params.type == DPA_CLS_TBL_EXACT_MATCH) ?	\
			 tbl_params.exact_match_params.key_size : 0)

#define GET_SA_TABLE_IDX(_dest_addr, _use_udp_encap) \
	(!IP_ADDR_TYPE_IPV4(_dest_addr) ? DPA_IPSEC_SA_IPV6 :  \
	 _use_udp_encap ? DPA_IPSEC_SA_IPV4_NATT :  DPA_IPSEC_SA_IPV4)

#define SEQ_NUM_HI_MASK		0xFFFFFFFF00000000
#define SEQ_NUM_LOW_MASK	0x00000000FFFFFFFF

#define MAX_DPA_IPSEC_INSTANCES		10

#define MAX_NUM_OF_SA       1000
#define MAX_CIPHER_KEY_LEN  100
#define MAX_AUTH_KEY_LEN    256
#define MAX_BUFFER_POOL_ID  63

/* number of FQs that will be created internally for each SA */
#define NUM_FQS_PER_SA		2

#define UDP_HEADER_LEN		8
#define NEXT_HEADER_IS_IPv4	0x04

#define WAIT4_FQ_EMPTY_TIMEOUT	100000 /* Time in microseconds */
#define REKEY_SCHED_DELAY	100   /* Time in microseconds */

#define INVALID_INB_FLOW_ID	0xFFFF

/* The maximum length (in bytes) for the CAAM extra commands */
#define MAX_EXTRA_DESC_COMMANDS		(64 * sizeof(uint32_t))

#define NIA_OPCODE_MASK		0x0F

#define SEC_DEF_VER 40 /* like in P4080 */

/* DPA IPSec Encryption & authentication algorithm identifiers */
struct ipsec_alg_suite {
	uint16_t	enc_alg;
	uint16_t	auth_alg;
};

/* DPA IPsec PCD management operation types */
enum mng_op_type {
	MNG_OP_ADD = 0,
	MNG_OP_REMOVE,
	MNG_OP_MODIFY
};

/* DPA IPsec Cipher Parameters */
struct cipher_params {
	uint16_t cipher_type;	 /* Algorithm type as defined by SEC driver   */
	uint8_t *cipher_key;	 /* Address to the encryption key	      */
	uint32_t cipher_key_len; /* Length in bytes of the normal key         */
};

/* DPA IPsec Authentication Parameters */
struct auth_params {
	uint16_t auth_type;	/* Algorithm type as defined by SEC driver    */
	uint8_t *auth_key;	/* Address to the normal key		      */
	uint32_t auth_key_len;	/* Length in bytes of the normal key          */
	uint8_t *split_key;	/* Address to the generated split key         */
	uint32_t split_key_len;	/* Length in bytes of the split key           */
	uint32_t split_key_pad_len;/* Length in bytes of the padded split key */
};

/*
 * DPA IPsec Security Association
 * This structure will represent a SA. All SA structures will be allocated
 * in the initialization part for performance reasons.
 */
struct dpa_ipsec_sa {
	struct dpa_ipsec *dpa_ipsec;	    /* Pointer to DPA_IPSEC           */
	enum dpa_ipsec_direction sa_dir;    /* SA direction		      */
	uint32_t id;			    /* Used to index in circular queue*/
	enum dpa_ipsec_cipher_alg alg_suite; /* DPA IPSEC algorithm suite     */
	struct cipher_params cipher_data;   /* Encryption parameters	      */
	struct auth_params auth_data;	    /* Authentication key parameters  */
	struct sec_descriptor *sec_desc_unaligned; /* Allocated at init time.
					  * When releasing memory only free
					  * this pointer and do not act on
					  * sec_desc address		      */
	struct sec_descriptor *sec_desc; /* 64 byte aligned address where is
					  * computed the SEC 4.x descriptor
					  * according to the SA information.
					  * do not free this pointer!	      */
	uint32_t *sec_desc_extra_cmds_unaligned;
	uint32_t *sec_desc_extra_cmds; /* aligned to CORE cache line size     */
	bool	 sec_desc_extended; /* true if SEC descriptor is extended     */
	uint32_t *rjob_desc_unaligned;
	uint32_t *rjob_desc; /* replacement job descriptor address	      */
	uint64_t w_seq_num; /* RJD will write this SEQ number when modify     */
	uint64_t r_seq_num; /* RJD will read here the SEQ number for this SA  */
	bool	 read_seq_in_progress; /* true if a request came but a get not*/
	uint32_t stats_offset; /* Offset of the statistics (in bytes)	      */
	uint32_t stats_indx; /* Index of the lifetime counter in descriptor   */
	uint32_t next_cmd_indx; /* Next command index after SHD header	      */
	uint8_t  job_desc_len; /* Number of words CAAM Job Descriptor occupies
				* form the CAAM Descriptor length
				* MAX_CAAM_DESCSIZE			      */
	bool enable_stats; /* Enable counting packets and bytes processed     */
	bool enable_extended_stats; /* Enable extended statistics per SA      */
	bool dscp_copy; /* Enable DSCP propagation support		      */
	bool ecn_copy; /* Enable DSCP propagation support		      */
	bool enable_dpovrd; /* Enable DECO Protocol Override Register	      */
	struct qman_fq *to_sec_fq; /*From this Frame Queue SEC consumes frames*/
	struct qman_fq *from_sec_fq; /*In this Frame Queue SEC will enqueue the
				encryption/decryption result (FD).            */
	uint16_t sa_wqid; /* Work queue id in which the TO SEC FQ will be put */
	uint8_t sa_bpid;  /* Buffer pool id used by SEC for acquiring buffers,
			     comes from user. Default buffer pool 63	      */
	uint16_t sa_bufsize;	/* Buffer pool buffer size		      */
	uint32_t spi;	/* IPsec Security parameter index		      */
	struct dpa_offload_ip_address src_addr;  /* Source IP address	      */
	struct dpa_offload_ip_address dest_addr; /* Destination IP address    */
	uint16_t outbound_flowid; /* Value used to classify frames encrypted
				 with this SA				      */
	bool use_udp_encap;   /* NAT-T is activated for this SA.	      */
	uint16_t udp_src_port;	/* Source UDP port (for UDP encapsulated ESP)
				   Only for inbound  SAs.		      */
	uint16_t udp_dest_port;	/* Destination UDP port (for UDP encap ESP)
				   Only for inbound  SAs.                     */
	uint16_t inbound_flowid; /* Value used for identifying an inbound SA. */
	bool valid_flowid_entry; /* Valid entry in the flowID table	      */
	int inbound_hash_entry;	/* Entry in the hash table
				   corresponding to SPI extended key	      */
	int inbound_sa_td; /* Descriptor for the SA lookup table in which this
			    * SA's key will be placed */
	struct dpa_cls_tbl_action def_sa_action;
	struct list_head policy_headlist; /* Head of the policy param list
			 used to store all the in/out policy parameters in order
			 to know how to remove the corresponding PCD entries  */
	struct dpa_cls_tbl_action policy_miss_action; /* Action for frames that
						       * fail inbound policy
						       * verification	      */
	int em_inpol_td; /* Exact match table descriptor for inbound policy
			    check					      */
	struct dpa_ipsec_sa *parent_sa;	/* Address of the parent SA or NULL   */
	struct dpa_ipsec_sa *child_sa;	/* Address of the child SA or NULL    */
	struct list_head sa_rekeying_node; /* For linking in SA rekeying list */
	int used_sa_index; /* Index in the used_sa_ids vector of the dpa ipsec
			      instance this SA is part of.		      */
	bool use_var_iphdr_len; /* Enable variable IP header length support   */
	int ipsec_hmd;		/* Manip object for special IPSec functions   */
	dpa_ipsec_rekey_event_cb rekey_event_cb;
	uint32_t l2_hdr_size; /* Size of the Ethernet header, including any
			      * VLAN information.			      */
	uint8_t dscp_start; /* DSCP range start value */
	uint8_t dscp_end; /* DSCP range end value */
	struct mutex lock; /* Lock for this SA structure */
};

/*
 * Parameters for inbound policy verification tables
 * Global list lock - inpol_tables_lock from SA manager
 */
struct inpol_tbl {
	void *cc_node; /* Cc node handle on top of which the table is created */
	int td;	 /* Exact match table used for inbound policy verification    */
	bool used;
	struct list_head table_list;
};

/*
 * Parameters for IPsec special manipulations eg. DSCP/ECN update
 * Global list lock - ipsec_manip_node_lock from SA manager
 */
struct ipsec_manip_node {
	/*
	 * IPsec manip node handle; returned by FM_PCD_ManipNodeSet
	 */
	void *hm;
	bool used;
	struct list_head ipsec_manip_node_list;
};

/* DPA IPSEC - Security Associations Management */
struct dpa_ipsec_sa_mng {
	struct dpa_ipsec_sa *sa; /* Array of SAs. Use indexes from sa_id_cq   */
	struct cq *sa_id_cq;	/* Circular Queue with id's for SAs           */
	uint32_t max_num_sa;	/* Maximum number of SAs                      */

	/* Circular queue with flow IDs for identifying an inbound SA */
	struct cq *inbound_flowid_cq;

	/* Inbound policy verification tables key size.*/
	uint8_t inpol_key_size;

	/*
	 * Head list of tables used for inbound
	 * policy verification. List of inpol_tbl structures.
	 * Populated only if inbound policy verification is enabled
	 */
	struct list_head inpol_tables;
	struct mutex inpol_tables_lock; /* List lock inbound policy table */

	/* ipsec_manip_node head list */
	struct list_head ipsec_manip_node_list;

	/* Lock for IPsec manip node list */
	struct mutex ipsec_manip_node_lock;
	struct delayed_work sa_rekeying_work;

	/* Work queue used to defer the work to be done during rekeying */
	struct workqueue_struct *sa_rekeying_wq;

	/* Head list with inbound SA's currently in the rekeying process */
	struct list_head sa_rekeying_headlist;
	struct mutex sa_rekeying_headlist_lock; /* Lock for the rekeying list */
	struct cq *fqid_cq; /* Circular queue with FQIDs for internal FQs     */
};

/* DPA IPsec - Control Block */
struct dpa_ipsec {
	int id; /* the instance ID */
	/* Configuration parameters as provided in dap_ipsec_config_and_init */
	struct dpa_ipsec_params config;
	struct dpa_ipsec_sa_mng sa_mng;	/* Internal DPA IPsec SA manager      */
	int *used_sa_ids;	/* SA IDs used by this DPA IPsec instance     */
	int num_used_sas;  /* The current number of sa's used by this instance*/
	int sec_era; /* SEC ERA information */
	struct device *jrdev; /* Job ring device */
	atomic_t ref;
	atomic_t valid;
	struct mutex lock; /* Lock for this dpa_ipsec instance */
};

struct hmd_entry {
	int hmd;
	bool hmd_special_op;
};

/* DPA IPSEC - Security Policy Parameter Entry */
struct dpa_ipsec_policy_entry {
	/* Policy parameters */
	struct dpa_ipsec_policy_params pol_params;

	/* Entry id array that is set by dpa_classif_table_insert_entry */
	int *entry_id;

	/*
	 * Header manip for IPSec special operation or
	 * if none Header manip for fragmentation or
	 * manipulation
	 */
	int hmd;

	/*
	 * true is hmd is IPSec special operation, false
	 * is hmd refers to an outside manip object
	 */
	bool hmd_special_op;

	/* Node in linked list */
	struct list_head node;
};

void sa_rekeying_work_func(struct work_struct *work);

static inline int sa_currently_on_rekeying_list(struct dpa_ipsec_sa *sa)
{
	return (sa->sa_rekeying_node.next == LIST_POISON1 &&
		sa->sa_rekeying_node.prev == LIST_POISON2) ? FALSE : TRUE;
}

static inline int sa_currently_in_rekeying(struct dpa_ipsec_sa *sa)
{
	return (sa->parent_sa || sa->child_sa) ? TRUE : FALSE;
}

static inline int sa_is_parent(struct dpa_ipsec_sa *sa)
{
	return sa->child_sa ? TRUE : FALSE;
}

static inline int sa_is_child(struct dpa_ipsec_sa *sa)
{
	return sa->parent_sa ? TRUE : FALSE;
}

static inline int sa_is_single(struct dpa_ipsec_sa *sa)
{
	return (!sa_is_parent(sa) && !sa_is_child(sa)) ? TRUE : FALSE;
}

static inline int sa_is_outbound(struct dpa_ipsec_sa *sa)
{
	return sa->sa_dir == DPA_IPSEC_OUTBOUND ? TRUE : FALSE;
}

static inline int sa_is_inbound(struct dpa_ipsec_sa *sa)
{
	return sa->sa_dir == DPA_IPSEC_INBOUND ? TRUE : FALSE;
}

static inline int schedule_sa(struct dpa_ipsec_sa *sa)
{
	enum qman_fq_state state;
	u32 flags;
	int err;

	qman_fq_state(sa->to_sec_fq, &state, &flags);
	if (state == qman_fq_state_parked) {
		err = qman_schedule_fq(sa->to_sec_fq);
		if (unlikely(err < 0))
			return -EIO;
		return 0;
	}

	return state == qman_fq_state_sched ? 0 : -EPERM;
}

static inline void rekey_err_report(dpa_ipsec_rekey_event_cb rekey_event_cb,
				int dpa_ipsec_id, uint32_t sa_id, int err)
{
	if (rekey_event_cb)
		rekey_event_cb(dpa_ipsec_id, sa_id, err);
}

/* If index table is invalid the IPsec action per inbound SA will be ignored  */
static inline int ignore_post_ipsec_action(struct dpa_ipsec *dpa_ipsec)
{
	if (dpa_ipsec->config.post_sec_in_params.dpa_cls_td > 0)
		return FALSE;
	return TRUE;
}

static inline void instance_refinc(struct dpa_ipsec *instance)
{
	BUG_ON(atomic_read(&instance->ref) <= 0);
	atomic_inc(&instance->ref);
}

static inline void instance_refdec(struct dpa_ipsec *instance)
{
	atomic_dec(&instance->ref);
}

static inline int sa_id_to_instance_id(int sa_id)
{
	return sa_id / MAX_NUM_OF_SA;
}

/* SA index refers to the position of SA with id sa_id in the sa_mng.sa */
static inline int sa_id_to_sa_index(int sa_id)
{
	if (sa_id_to_instance_id(sa_id) == 0)
		return sa_id;

	return sa_id % (sa_id_to_instance_id(sa_id) * MAX_NUM_OF_SA);
}

/* Check if SA ID is in possible range */
static inline int valid_sa_id(int sa_id)
{
	if (sa_id < 0 || sa_id >= MAX_DPA_IPSEC_INSTANCES * MAX_NUM_OF_SA) {
		log_err("Invalid SA id %d provided\n", sa_id);
		return false;
	}

	return true;
}

static inline int valid_instance_id(int instance_id)
{
	if (instance_id < 0 || instance_id >= MAX_DPA_IPSEC_INSTANCES) {
		log_err("Invalid DPA IPsec instance ID\n");
		return false;
	}

	return true;
}

/* Check if SA is being used i.e created */
static inline int sa_in_use(struct dpa_ipsec_sa *sa)
{
	if (sa->used_sa_index == -1)
		return false;

	return true;
}

#endif	/* __DPA_IPSEC_H__ */
