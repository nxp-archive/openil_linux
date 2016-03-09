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

/*
 * DPA-IPSec Application Programming Interface.
 */

#ifndef __FSL_DPA_IPSEC_H
#define __FSL_DPA_IPSEC_H

#include "fsl_dpa_classifier.h"

/* General DPA-IPSec defines */
#define IP_PROTO_FIELD_LEN		1
#define ESP_SPI_FIELD_LEN		4
#define PORT_FIELD_LEN			2
#define ICMP_HDR_FIELD_LEN		1
#define DSCP_FIELD_LEN_IPv4		1
/*
 * In order to extract Traffic Class in case of IPv6, the keygen will add two
 * bytes to the key, which hold: IPv6 version(4bits), TC(8bits) and 4 bits zero.
 */
#define DSCP_FIELD_LEN_IPv6		2

#define MAX_SIZE_IP_UDP_SPI_KEY	\
		(1 * DPA_OFFLD_IPv6_ADDR_LEN_BYTES + \
		IP_PROTO_FIELD_LEN + \
		2 * PORT_FIELD_LEN + \
		ESP_SPI_FIELD_LEN)

#define MAX_SIZE_IP_UDP_SPI_KEY_IPV4 \
		(1 * DPA_OFFLD_IPv4_ADDR_LEN_BYTES + \
		IP_PROTO_FIELD_LEN + \
		2 * PORT_FIELD_LEN + \
		ESP_SPI_FIELD_LEN)

#define MAX_SIZE_POLICY_KEY \
		(2 * DPA_OFFLD_IPv6_ADDR_LEN_BYTES + \
		IP_PROTO_FIELD_LEN + \
		2 * PORT_FIELD_LEN)

#define MAX_SIZE_POLICY_KEY_IPV4 \
		(2 * DPA_OFFLD_IPv4_ADDR_LEN_BYTES + \
		IP_PROTO_FIELD_LEN + \
		2 * PORT_FIELD_LEN)


#define DPA_IPSEC_MAX_IV_LEN         16   /* Maximum length of IV(in bytes) */
#define DPA_IPSEC_MAX_POL_PER_SA     255  /* Maximum supported number of
					   * policies per  SA              */

/*
 * IPSec Special Operations
 */
#define DPA_IPSEC_HDR_COPY_TOS		0x01 /* Copy TOS / DiffServ byte from
					      * inner / outer header to outer /
					      * inner header		      */
#define	DPA_IPSEC_HDR_COPY_DF		0x02 /* Copy DF bit from outer header
					      * to outer / inner header	      */
#define DPA_IPSEC_HDR_DEC_TTL		0x04 /* Automatically decrment the TTL
					      * value in the inner / outer hdr*/
#define DPA_IPSEC_HDR_COPY_DSCP		0x08 /* Copy DSCP bits from inner /
					      * outer header to outer / inner
					      * header			      */
#define DPA_IPSEC_HDR_COPY_ECN		0x10 /* Copy ECN bits from inner /
					      * outer header to outer / inner
					      * header			      */

#define DPA_IPSEC_KEY_FIELD_SIP		0x01 /* Use source IP address in key  */
#define DPA_IPSEC_KEY_FIELD_DIP		0x02 /* Use destination IP in key     */
#define	DPA_IPSEC_KEY_FIELD_PROTO	0x04 /* Use IP protocol field in key  */
#define DPA_IPSEC_KEY_FIELD_DSCP	0x08 /* Use DSCP field in key         */
#define DPA_IPSEC_KEY_FIELD_SPORT	0x10 /* Use source port in key        */
#define DPA_IPSEC_KEY_FIELD_ICMP_TYPE	0x10 /* Use ICMP type field in key    */
#define DPA_IPSEC_KEY_FIELD_DPORT	0x20 /* Use destination port in key   */
#define DPA_IPSEC_KEY_FIELD_ICMP_CODE	0x20 /* Use ICMP code field in key    */
#define	DPA_IPSEC_MAX_KEY_FIELDS	6    /* Maximum key components        */

#define DPA_IPSEC_DEF_PAD_VAL		0xAA /* Value to be used as padding in
					      * classification keys           */

/* DPA-IPSec Supported Protocols (for policy offloading) */
enum dpa_ipsec_proto {
	DPA_IPSEC_PROTO_TCP_IPV4 = 0,
	DPA_IPSEC_PROTO_TCP_IPV6,
	DPA_IPSEC_PROTO_UDP_IPV4,
	DPA_IPSEC_PROTO_UDP_IPV6,
	DPA_IPSEC_PROTO_ICMP_IPV4,
	DPA_IPSEC_PROTO_ICMP_IPV6,
	DPA_IPSEC_PROTO_SCTP_IPV4,
	DPA_IPSEC_PROTO_SCTP_IPV6,
	DPA_IPSEC_PROTO_ANY_IPV4,
	DPA_IPSEC_PROTO_ANY_IPV6,
	DPA_IPSEC_MAX_SUPPORTED_PROTOS
};

/* DPA IPSec supported types of SAs */
enum dpa_ipsec_sa_type {
	DPA_IPSEC_SA_IPV4 = 0,
	DPA_IPSEC_SA_IPV4_NATT,
	DPA_IPSEC_SA_IPV6,
	DPA_IPSEC_MAX_SA_TYPE
};

/*
 * DPA-IPSec Post SEC Data Offsets. 1 BURST = 32 or 64 bytes
 * depending on SEC configuration. Default BURST size = 64 bytes
 */
enum dpa_ipsec_data_off {
	DPA_IPSEC_DATA_OFF_NONE = 0,
	DPA_IPSEC_DATA_OFF_1_BURST,
	DPA_IPSEC_DATA_OFF_2_BURST,
	DPA_IPSEC_DATA_OFF_3_BURST
};

/* DPA IPSec outbound policy lookup table parameters */
struct dpa_ipsec_pol_table {
	int	dpa_cls_td; /* DPA Classifier table descriptor		      */
	uint8_t	key_fields; /* Flags indicating policy key components.
			     * (use DPA_IPSEC_KEY_FIELD* macros to configure) */
};

/* DPA-IPSec Pre-Sec Inbound Parameters */
struct dpa_ipsec_pre_sec_in_params {
	int dpa_cls_td[DPA_IPSEC_MAX_SA_TYPE]; /* SA lookup tables descriptors*/
};

/* DPA-IPSec Pre-Sec Outbound Parameters */
struct dpa_ipsec_pre_sec_out_params {
	/* Oubound policy lookup tables parameters */
	struct dpa_ipsec_pol_table table[DPA_IPSEC_MAX_SUPPORTED_PROTOS];
};

/* DPA-IPSec Post-Sec-Inbound Parameters */
struct dpa_ipsec_post_sec_in_params {
	enum dpa_ipsec_data_off data_off;/*Data offset in the decrypted buffer*/
	uint16_t qm_tx_ch;   /* QMan channel of the post decryption OH port   */
	int dpa_cls_td;	     /* Index table descriptor			      */
	bool do_pol_check;   /* Enable inbound policy verification	      */
	uint8_t key_fields;  /* Flags indicating policy key components.
			      * (use DPA_IPSEC_KEY_FIELD* macros to configure)
			      *  Relevant only if do_pol_check = TRUE	      */
	bool use_ipv6_pol;   /* Activate support for IPv6 policies. Allows
			      * better MURAM management. Relevant only if
			      * do_pol_check = TRUE			      */
	uint16_t base_flow_id; /* The start value of the range of flow ID values
				* used by this instance in post decryption    */
};

/* DPA-IPSec Post-Sec-Inbound Parameters */
struct dpa_ipsec_post_sec_out_params {
	enum dpa_ipsec_data_off data_off;/*Data offset in the decrypted buffer*/
	uint16_t qm_tx_ch; /* QMan channel of the post encrytion OH port      */
};

/* DPA IPSec FQID range parameters */
struct dpa_ipsec_fqid_range {
	uint32_t	start_fqid;
	uint32_t	end_fqid;
};

/* IPsec parameters used to configure the DPA IPsec instance */
struct dpa_ipsec_params {
	struct dpa_ipsec_pre_sec_in_params pre_sec_in_params;
	struct dpa_ipsec_post_sec_in_params post_sec_in_params;
	struct dpa_ipsec_pre_sec_out_params pre_sec_out_params;
	struct dpa_ipsec_post_sec_out_params post_sec_out_params;
	void *fm_pcd;		/* Handle of the PCD object		      */
	uint16_t qm_sec_ch;	/* QMan channel# for the SEC		      */
	uint16_t max_sa_pairs;	/* Maximum number of SA pairs
				 * (1 SA Pair = 1 In SA + 1 Out SA)	      */

	/*
	 * Maximum number of special IPSec
	 * manipulation operations that can be
	 * enabled. eg DSCP/ECN update, IP variable
	 * length. The max_sa_manip_ops
	 * should be incremented with the number
	 * of manipulations per every outbound
	 * policy
	 */
	uint32_t max_sa_manip_ops;
	struct dpa_ipsec_fqid_range *fqid_range; /* FQID range to be used by
						  * DPA IPSec for allocating
						  * FQIDs for internal FQs    */
	uint8_t ipf_bpid;	/* Scratch buffer pool for IP Frag.	      */
};

/* Initialize a DPA-IPSec instance. */
int dpa_ipsec_init(const struct dpa_ipsec_params *params, int *dpa_ipsec_id);

/* Free a DPA-IPSec instance */
int dpa_ipsec_free(int dpa_ipsec_id);

/* DPA-IPSec data flow source specification */
enum dpa_ipsec_direction {
	DPA_IPSEC_INBOUND = 0,	/* Inbound				      */
	DPA_IPSEC_OUTBOUND	/* Outbound				      */
};

/* DPA-IPSec Supported Cipher Suites */
enum dpa_ipsec_cipher_alg {
	DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_MD5_128,
	DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_SHA_160,
	DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_MD5_128,
	DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_160,
	DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_256_128,
	DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_384_192,
	DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_512_256,
	DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_96_MD5_128,
	DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_96_SHA_160,
	DPA_IPSEC_CIPHER_ALG_NULL_ENC_AES_XCBC_MAC_96,
	DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_MD5_128,
	DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_160,
	DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_256_128,
	DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_384_192,
	DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_512_256,
	DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_MD5_128,
	DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_SHA_160,
	DPA_IPSEC_CIPHER_ALG_AES_CBC_AES_XCBC_MAC_96,
	DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_MD5_128,
	DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_160,
	DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_256_128,
	DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_384_192,
	DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_512_256,
	DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_MD5_128,
	DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_SHA_160,
	DPA_IPSEC_CIPHER_ALG_AES_CTR_AES_XCBC_MAC_96,
	DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_MD5_128,
	DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_160,
	DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_256_128,
	DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_384_192,
	DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_512_256
};

/* DPA-IPSec Initialization Vector */
struct dpa_ipsec_init_vector {
	uint8_t *init_vector;	/* Pointer to the initialization vector	      */
	uint8_t length;		/* Length in bytes. May be 8 or 16 bytes      */
};

/* DPA IPSEC Anti Replay Window Size */
enum dpa_ipsec_arw {
	DPA_IPSEC_ARSNONE = 0,	/* No Anti Replay Protection		      */
	DPA_IPSEC_ARS32   = 1,	/* 32 bit Anti Replay Window size	      */
	DPA_IPSEC_ARS64   = 3,	/* 64 bit Anti Replay Window size	      */
};

/* DPA-IPSec Security Association Cryptographic Parameters */
struct dpa_ipsec_sa_crypto_params {
	enum dpa_ipsec_cipher_alg alg_suite;	/* Algorithm suite specifying
						 * encryption and authentication
						 * algorithms to be used      */
	uint8_t *cipher_key;	/* Address of the encryption key	      */
	uint8_t cipher_key_len;	/* Length of the encryption key in bytes      */
	uint8_t *auth_key;	/* Address of the authentication key	      */
	uint8_t auth_key_len;	/* Length of the authentication key in bytes  */
};

/* DPA-IPSec SA Modes */
enum dpa_ipsec_sa_mode {
	DPA_IPSEC_SA_MODE_TUNNEL = 0,
	DPA_IPSEC_SA_MODE_TRANSPORT
};

/* DPA-IPSec SA Protocols */
enum dpa_ipsec_sa_proto {
	DPA_IPSEC_SA_PROTO_ESP = 0,
	DPA_IPSEC_SA_PROTO_AH
};

/* DPA-IPSec Security Association Out Parameters */
struct dpa_ipsec_sa_out_params {
	/*
	 * Initialization vector (IV). Null for using the internal random
	 * number generator
	 */
	struct dpa_ipsec_init_vector *init_vector;
	unsigned int ip_ver;	/* IPv4 or IPv6 address type		      */
	uint16_t ip_hdr_size;	/* IP header size including any IP options    */
	void *outer_ip_header;	/* IP encapsulation header		      */
	/* UDP encapsulation header (for SAs using NAT-T)		      */
	void *outer_udp_header;
	/* Flow ID used to mark frames encrypted using this SA		      */
	uint16_t post_sec_flow_id;
	uint8_t dscp_start;	/* DSCP range start value; ignored if the DSCP
				 * selector wasn't enabled for this SA */
	uint8_t dscp_end;	/* DSCP range end value; ignored if the DSCP
				 * selector wasn't enabled for this SA */
};

/* DPA-IPSec Security Association In Parameters */
struct dpa_ipsec_sa_in_params {
	enum dpa_ipsec_arw arw;	/* Anti replay window			      */
	bool use_var_iphdr_len; /* Enable variable IP header length support   */
	struct dpa_offload_ip_address src_addr;	/* Source IP address	      */
	struct dpa_offload_ip_address dest_addr; /* Destination IP address    */
	bool use_udp_encap;	/* NAT-T is activated (UDP encapsulated ESP)  */
	uint16_t src_port;	/* Source UDP port (UDP encapsulated ESP)     */
	uint16_t dest_port;	/* Destination UDP port (UDP encapsulated ESP)*/
	/* Action for frames that fail inbound policy verification	      */
	struct dpa_cls_tbl_action policy_miss_action;
	/*
	 * Action to be performed on the frames after inbound IPSec processing
	 * is completed
	 */
	struct dpa_cls_tbl_action post_ipsec_action;
};

/* DPA-IPSec Security Association Parameters */
struct dpa_ipsec_sa_params {
	uint32_t spi;		/* IPSec Security parameter index	      */
	bool use_ext_seq_num;	/* Enable extended sequence number	      */
	uint64_t start_seq_num;	/* Sequence number to start with	      */
	uint32_t l2_hdr_size;	/* Size of the Ethernet header, including any
				 * VLAN information.			      */
	enum dpa_ipsec_sa_mode sa_mode;	/* Tunnel or transport mode selection */
	enum dpa_ipsec_sa_proto sa_proto; /* Protocol to be used (AH or ESP)-
					   * Only ESP supported currently     */
	uint8_t hdr_upd_flags;	/* Flags for propagating information from inner
				 * to outer header and vice versa	      */
	uint8_t sa_wqid;	/* Work queue Id for all the queues in this SA*/
	uint8_t sa_bpid;	/* Buffer Pool ID to be used with this SA     */
	uint16_t sa_bufsize;	/* Buffer Pool buffer size		      */
	bool	enable_stats;	/* Enable counting packets and bytes processed*/
	/*
	 * Enable extended statistics per SA, beside counting IPSec processed
	 * packets the dpa offload will also count the input packets that
	 * require IPSec processing.
	 */
	bool  enable_extended_stats;
	struct dpa_ipsec_sa_crypto_params crypto_params;/* IPSec crypto params*/
	enum dpa_ipsec_direction sa_dir;  /* SA direction: Outbound/Inbound   */
	union {
		struct dpa_ipsec_sa_in_params sa_in_params; /* Inb SA params  */
		struct dpa_ipsec_sa_out_params sa_out_params; /* Out SA params*/
	};
};

/* DPA-IPSEC Rekeying error callback */
typedef int (*dpa_ipsec_rekey_event_cb) (int dpa_ipsec_id, int sa_id,
					 int error);

/* Offload an SA. */
int dpa_ipsec_create_sa(int dpa_ipsec_id,
			struct dpa_ipsec_sa_params *sa_params, int *sa_id);

/* This function will be used when rekeying a SA.
 *	- The new SA will inherit the old SA's policies.
 *	- To SEC FQ of the new SA will be created in parked mode and
 *	  will be scheduled after the to SEC FQ of the old SA is empty,
 *	  exception only when auto_rmv_old_sa if false.
 *	  This will ensure the preservation of the frame order.
 *	- To SEC FQ of the old SA will be retired and destroyed when it
 *	  has no purpose.
 *	- Memory allocated for old SA will be returned to the SA memory pool
 *	- auto_rmv_old_sa
 *		- relevant only for an inbound SA.
 *		- if true:
 *			- the old SA will be removed automatically when
 *			  encrypted traffic starts flowing on the new SA
 *			- the new SA is not scheduled until traffic arrives on
 *			  its TO SEC FQ.
 *		- if false:
 *			- the old and new SA will be active in the same time.
 *			- the old SA has to be removed using the
 *			  dpa_ipsec_remove_sa function when the hard SA
 *			  expiration time limit is reached
 *			- Since the difference between soft and hard limit
 *			  can be several seconds it is required to schedule the
 *			  TO SEC FQ of the new SA.
 *
 *	- rekey_event_cb (UNUSED parameter)
 */
int dpa_ipsec_sa_rekeying(int sa_id,
			  struct dpa_ipsec_sa_params *sa_params,
			  dpa_ipsec_rekey_event_cb rekey_event_cb,
			  bool auto_rmv_old_sa, int *new_sa_id);

/*
 * Disables a SA before removal (no more packets will be processed
 * using this SA). The resource associated with this SA are not
 * freed until dpa_ipsec_remove_sa is called.
 */
int dpa_ipsec_disable_sa(int sa_id);

/* Unregister a SA and destroys the accelerated path. */
int dpa_ipsec_remove_sa(int sa_id);

/*
 * This function will remove all SAs (in a specified DPA IPSec
 * instance)that were offloaded using the DPA IPsec API
 */
int dpa_ipsec_flush_all_sa(int dpa_ipsec_id);

struct dpa_ipsec_l4_params {
	uint16_t src_port;	/* Source port				      */
	uint16_t src_port_mask;	/* Source port mask			      */
	uint16_t dest_port;	/* Destination port			      */
	uint16_t dest_port_mask;/* Destination port mask		      */
};

struct dpa_ipsec_icmp_params {
	uint8_t	icmp_type;	/* Type of ICMP message			      */
	uint8_t	icmp_type_mask; /* Mask for ICMP type field		      */
	uint8_t	icmp_code;	/* ICMP message code			      */
	uint8_t	icmp_code_mask; /* Mask for ICMP code field		      */
};

/* DPA IPSec direction specific policy params types */
enum dpa_ipsec_pol_dir_params_type {
	/*
	 * No direction specific params
	 */
	DPA_IPSEC_POL_DIR_PARAMS_NONE = 0,

	 /*
	  * Fragmentation or header manipulation
	  * params (outbound policies only)
	  */
	DPA_IPSEC_POL_DIR_PARAMS_MANIP,

	 /*
	  * Action params (inbound policies only)
	  */
	DPA_IPSEC_POL_DIR_PARAMS_ACT
};

/* DPA IPSec direction specific parameters for Security Policies */
struct dpa_ipsec_pol_dir_params {
	enum dpa_ipsec_pol_dir_params_type type;
	union {
		 /*
		  * Manipulation descriptor for fragmentation or
		  * header manipulation
		  */
		int manip_desc;
		struct dpa_cls_tbl_action in_action; /* Action to be performed
						      * for frames matching
						      * the policy selectors  */
	};
};

/* DPA-IPSec Security Policy Parameters */
struct dpa_ipsec_policy_params {
	struct dpa_offload_ip_address src_addr;	/* Source IP address	      */
	uint8_t src_prefix_len;	/* Source network prefix		      */
	struct dpa_offload_ip_address dest_addr; /**< Destination IP address  */
	uint8_t dest_prefix_len; /* Destination network prefix		      */
	uint8_t protocol;	/* Protocol				      */
	bool masked_proto;	/* Mask the entire protocol field	      */
	bool use_dscp;		/* Enable DSCP value in policy selector       */
	union {
		struct dpa_ipsec_l4_params	l4;	/* L4 protos params   */
		struct dpa_ipsec_icmp_params	icmp;	/* ICMP proto params  */
	};
	struct dpa_ipsec_pol_dir_params dir_params;
	int priority;		/* Policy priority			      */
};

/* Add a new rule for policy verification / lookup. */
int dpa_ipsec_sa_add_policy(int sa_id,
			    struct dpa_ipsec_policy_params *policy_params);

/* Removes a rule for policy verification / lookup. */
int dpa_ipsec_sa_remove_policy(int sa_id,
			       struct dpa_ipsec_policy_params *policy_params);

/*
 * Retrieves all the policies linked to the specified SA. In order
 * to determine the size of the policy_params array, the function
 * must first be called with policy_params = NULL. In this case it
 * will only return the number of policy entries linked to the SA.
 * num_pol must not be greater than DPA_IPSEC_MAX_POL_PER_SA
 */
int dpa_ipsec_sa_get_policies(int sa_id,
			      struct dpa_ipsec_policy_params *policy_params,
			      int *num_pol);

/* This function will remove all policies associated with the specified SA */
int dpa_ipsec_sa_flush_policies(int sa_id);

/* DPA-IPSec SA Statistics */
struct dpa_ipsec_sa_stats {
	uint32_t packets_count; /* Number of IPSec processed packets */
	uint32_t bytes_count;   /* Number of IPSec processed bytes   */
	/*
	 * Number of packets which required IPSec processing
	 * for inbound SA: number of packets received
	 * for outbound SA: number of packets sent
	 */
	uint32_t input_packets;
};

/* DPA-IPSec Global Statistics */
struct dpa_ipsec_stats {
	/* Packets that missed inbound SA lookup */
	uint32_t inbound_miss_pkts;

	/* Bytes that missed inbound SA lookup */
	uint32_t inbound_miss_bytes;

	/* Packets that missed outbound policy lookup */
	uint32_t outbound_miss_pkts;

	/* Bytes that missed outbound policy lookup */
	uint32_t outbound_miss_bytes;
};

/* This function will populate sa_stats with SEC statistics for SA with sa_id */
int dpa_ipsec_sa_get_stats(int sa_id, struct dpa_ipsec_sa_stats *sa_stats);

/* Return IPSec global statistics in the "stats" data structure */
int dpa_ipsec_get_stats(int dpa_ipsec_id, struct dpa_ipsec_stats *stats);

enum dpa_ipsec_sa_modify_type {
	DPA_IPSEC_SA_MODIFY_ARS = 0, /* Set the anti replay window size	      */
	DPA_IPSEC_SA_MODIFY_SEQ_NUM, /* Set the sequence number for this SA   */
	DPA_IPSEC_SA_MODIFY_EXT_SEQ_NUM, /* Set the extended sequence number  */
	DPA_IPSEC_SA_MODIFY_CRYPTO /* Reset the crypto algorithms for this SA */
};

struct dpa_ipsec_sa_modify_prm {

	/* Use to select a modify operation */
	enum dpa_ipsec_sa_modify_type type;

	union {
		/* Anti replay window size */
		enum dpa_ipsec_arw arw;

		/*
		 * 32 bit or extended sequence number depending on how the
		 * SA was created by dpa_ipsec_create_sa
		 * Only the least significant word is used for 32 bit SEQ
		 */
		uint64_t seq_num;

		/* New cryptographic parameters for this SA */
		struct dpa_ipsec_sa_crypto_params crypto_params;
	};
};

/*
 * Modify an SA asynchronous
 *
 * SEC will dequeue a frame with RDJ, run it and after this create an
 * output frame with status of user error. The frame will have always the
 * length of 5 bytes, first one representing the operation code that has
 * finished and the next 4 will determine the SA id on which the operation took
 * place.
 *
 * Returned error code:
 *	0 if successful;
 *	-EBUSY if can't acquire lock for this SA
 *	-EINVAL if input parameters are wrong
 *	-ENXIO if failed to DMA map Replacement Job Descriptor or SHD
 *	-ETXTBSY if failed to enqueue to SEC the FD with RJD
 *	-EALREADY if ARS is already set to the required value
 *
 */
int dpa_ipsec_sa_modify(int sa_id, struct dpa_ipsec_sa_modify_prm *modify_prm);

/*
 * Request the sequence number of an SA asynchronous
 *
 * SEC will dequeue a frame with RJD, run it and after this create an
 * output frame with status of user error. The frame will have always the
 * length of 5 bytes, first one representing the operation code that has
 * finished and the next 4 will determine the SA id on which the operation took
 * place.
 *
 *
 * Returned error code:
 *	0 if successful;
 *	-EBUSY if can't acquire lock for this SA
 *	-ENXIO if failed to DMA map Replacement Job Descriptor
 *	-ETXTBSY if failed to enqueue to SEC the FD with RJD
 */
int dpa_ipsec_sa_request_seq_number(int sa_id);

int dpa_ipsec_sa_get_seq_number(int sa_id, uint64_t *seq);

/*
 * The dpa_ipsec_sa_modify and dpa_ipsec_sa_get_seq_number are asynchronous
 * operations.
 *
 * When finished the frame exiting the SEC will have the status
 * of user error and inside the frame (total length 5 bytes) the first byte will
 * be the code of the operation that has finished followed by the SA id in the
 * next 4 bytes.
 *
 * Use this enumeration to know what asynchronous operation has finished and on
 * what SA.
 */
enum dpa_ipsec_sa_operation_code {
	DPA_IPSEC_SA_MODIFY_ARS_DONE = 0,
	DPA_IPSEC_SA_MODIFY_SEQ_NUM_DONE,
	DPA_IPSEC_SA_MODIFY_EXT_SEQ_NUM_DONE,
	DPA_IPSEC_SA_MODIFY_CRYPTO_DONE,
	DPA_IPSEC_SA_GET_SEQ_NUM_DONE
};

/*
 * Get frame queue id to IPSec for a specified SA in order to bypass outbound
 * policy lookup and directly apply IPSec processing.
 */
int dpa_ipsec_sa_get_out_path(int sa_id, uint32_t *fqid);

#endif	/* __FSL_DPA_IPSEC_H */
