
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
 * DPA IPsec Wrapper Application Programming Interface
 */

#ifndef __DPA_IPSEC_IOCTL_H
#define __DPA_IPSEC_IOCTL_H

#include "linux/ioctl.h"
#ifdef CONFIG_COMPAT
#include "linux/compat.h"
#include "dpa_classifier_ioctl.h"
#endif

struct ioc_dpa_ipsec_params {
	struct dpa_ipsec_params dpa_ipsec_params;
	int dpa_ipsec_id;
};

#ifdef CONFIG_COMPAT
struct ioc_compat_ipsec_init_params {
	struct dpa_ipsec_pre_sec_in_params pre_sec_in_params;
	struct dpa_ipsec_post_sec_in_params post_sec_in_params;
	struct dpa_ipsec_pre_sec_out_params pre_sec_out_params;
	struct dpa_ipsec_post_sec_out_params post_sec_out_params;
	compat_uptr_t fm_pcd;
	uint16_t qm_sec_ch;
	uint16_t max_sa_pairs;
	uint32_t max_sa_manip_ops;
	compat_uptr_t fqid_range;
	uint8_t ipf_bpid;
};

struct ioc_compat_dpa_ipsec_params {
	struct ioc_compat_ipsec_init_params dpa_ipsec_params;
	int dpa_ipsec_id;
};
#endif

struct ioc_dpa_ipsec_sa_params {
	int dpa_ipsec_id;
	struct dpa_ipsec_sa_params sa_params;
	int sa_id;
};

#ifdef CONFIG_COMPAT
struct ioc_compat_sa_init_vector {
	compat_uptr_t init_vector;
	uint8_t length;
};

struct ioc_compat_sa_crypto_params {
	enum dpa_ipsec_cipher_alg alg_suite;
	compat_uptr_t cipher_key;
	uint8_t cipher_key_len;
	compat_uptr_t auth_key;
	uint8_t auth_key_len;
};

struct ioc_compat_sa_out_params {
	compat_uptr_t init_vector;
	unsigned int ip_ver;
	uint16_t ip_hdr_size;
	compat_uptr_t outer_ip_header;
	compat_uptr_t outer_udp_header;
	uint16_t post_sec_flow_id;
	uint8_t dscp_start;
	uint8_t dscp_end;
};

struct ioc_compat_sa_in_params {
	enum dpa_ipsec_arw arw;
	bool use_var_iphdr_len;
	struct dpa_offload_ip_address src_addr;
	struct dpa_offload_ip_address dest_addr;
	bool use_udp_encap;
	uint16_t src_port;
	uint16_t dest_port;
	struct dpa_cls_compat_tbl_action policy_miss_action;
	struct dpa_cls_compat_tbl_action post_ipsec_action;
};

struct ioc_compat_sa_params {
	uint32_t spi;
	bool use_ext_seq_num;
	uint64_t start_seq_num;
	uint32_t l2_hdr_size;
	enum dpa_ipsec_sa_mode sa_mode;
	enum dpa_ipsec_sa_proto sa_proto;
	uint8_t hdr_upd_flags;
	uint8_t sa_wqid;
	uint8_t sa_bpid;
	uint16_t sa_bufsize;
	bool enable_stats;
	bool enable_extended_stats;
	struct ioc_compat_sa_crypto_params crypto_params;
	enum dpa_ipsec_direction sa_dir;
	union {
		struct ioc_compat_sa_in_params sa_in_params;
		struct ioc_compat_sa_out_params sa_out_params;
	};
};

struct ioc_compat_dpa_ipsec_sa_params {
	int dpa_ipsec_id;
	struct ioc_compat_sa_params sa_params;
	int sa_id;
};
#endif

struct ioc_dpa_ipsec_add_rem_policy {
	struct dpa_ipsec_policy_params pol_params;
	int sa_id;
};

#ifdef CONFIG_COMPAT
struct ioc_compat_pol_dir_params {
	enum dpa_ipsec_pol_dir_params_type type;
	union {
		int manip_desc;
		struct dpa_cls_compat_tbl_action in_action;
	};
};

struct ioc_compat_policy_params {
	struct dpa_offload_ip_address src_addr;
	uint8_t src_prefix_len;
	struct dpa_offload_ip_address dest_addr;
	uint8_t dest_prefix_len;
	uint8_t protocol;
	bool masked_proto;
	bool use_dscp;
	union {
		struct dpa_ipsec_l4_params	l4;
		struct dpa_ipsec_icmp_params	icmp;
	};
	struct ioc_compat_pol_dir_params dir_params;
	int priority;		/* Policy priority			      */
};

struct ioc_compat_dpa_ipsec_add_rem_policy {
	struct ioc_compat_policy_params pol_params;
	int sa_id;
};
#endif

struct ioc_dpa_ipsec_rekey_prm {
	struct dpa_ipsec_sa_params sa_params;
	int auto_rmv_old_sa;
	int sa_id;		/* old sa id */
	int new_sa_id;		/* newly created sa id */
};

#ifdef CONFIG_COMPAT
struct ioc_compat_dpa_ipsec_rekey_prm {
	struct ioc_compat_sa_params sa_params;
	int auto_rmv_old_sa;
	int sa_id;		/* old sa id */
	int new_sa_id;		/* newly created sa id */
};
#endif

struct ioc_dpa_ipsec_get_policies {
	int sa_id;		/* sa id */
	struct dpa_ipsec_policy_params *policy_params;
	int num_pol;		/* number of policies */
};

#ifdef CONFIG_COMPAT
struct ioc_compat_dpa_ipsec_get_policies {
	int sa_id;		/* sa id */
	compat_uptr_t policy_params;
	int num_pol;		/* number of policies */
};
#endif

struct ioc_dpa_ipsec_sa_get_stats {
	int sa_id;		/* sa id */
	struct dpa_ipsec_sa_stats sa_stats;
};

struct ioc_dpa_ipsec_instance_stats {
	int instance_id;
	struct dpa_ipsec_stats stats;
};

struct ioc_dpa_ipsec_sa_modify_prm {
	int sa_id;		/* security association id */
	struct dpa_ipsec_sa_modify_prm modify_prm;
};

struct ioc_dpa_ipsec_sa_get_seq_num {
	int sa_id;	/* security association id */
	uint64_t seq;	/* where to write the SEQ number */
};

#ifdef CONFIG_COMPAT
struct compat_dpa_ipsec_sa_modify_prm {
	enum dpa_ipsec_sa_modify_type type;
	union {
		enum dpa_ipsec_arw arw;
		uint32_t seq;
		uint64_t ext_seq;
		struct ioc_compat_sa_crypto_params crypto_params;
	};
};

struct ioc_compat_dpa_ipsec_sa_modify_prm {
	int sa_id;		/* security association id */
	struct compat_dpa_ipsec_sa_modify_prm modify_prm;
};
#endif

struct ioc_dpa_ipsec_sa_get_out_path {
	int sa_id;	/* security association id */
	uint32_t fqid;	/* where to write the frame queue id number */
};

#define DPA_IPSEC_IOC_MAGIC	0xee

#define DPA_IPSEC_IOC_INIT \
		_IOWR(DPA_IPSEC_IOC_MAGIC, 0, struct ioc_dpa_ipsec_params)
#ifdef CONFIG_COMPAT
#define DPA_IPSEC_IOC_INIT_COMPAT \
		_IOWR(DPA_IPSEC_IOC_MAGIC, 0, \
		      struct ioc_compat_dpa_ipsec_params)
#endif

#define DPA_IPSEC_IOC_FREE \
		_IOW(DPA_IPSEC_IOC_MAGIC, 1, int)

#define DPA_IPSEC_IOC_CREATE_SA \
		_IOWR(DPA_IPSEC_IOC_MAGIC, 2, struct ioc_dpa_ipsec_sa_params)
#ifdef CONFIG_COMPAT
#define DPA_IPSEC_IOC_CREATE_SA_COMPAT \
		_IOWR(DPA_IPSEC_IOC_MAGIC, 2, \
		      struct ioc_compat_dpa_ipsec_sa_params)
#endif

#define DPA_IPSEC_IOC_REMOVE_SA \
		_IOW(DPA_IPSEC_IOC_MAGIC, 3, int)

#define DPA_IPSEC_IOC_ADD_POLICY \
	_IOW(DPA_IPSEC_IOC_MAGIC, 4, struct ioc_dpa_ipsec_add_rem_policy)
#ifdef CONFIG_COMPAT
#define DPA_IPSEC_IOC_ADD_POLICY_COMPAT \
	_IOW(DPA_IPSEC_IOC_MAGIC, 4, struct ioc_compat_dpa_ipsec_add_rem_policy)
#endif

#define DPA_IPSEC_IOC_REMOVE_POLICY \
	_IOW(DPA_IPSEC_IOC_MAGIC, 5, struct ioc_dpa_ipsec_add_rem_policy)
#ifdef CONFIG_COMPAT
#define DPA_IPSEC_IOC_REMOVE_POLICY_COMPAT \
	_IOW(DPA_IPSEC_IOC_MAGIC, 5, struct ioc_compat_dpa_ipsec_add_rem_policy)
#endif

#define DPA_IPSEC_IOC_SA_REKEYING \
	_IOWR(DPA_IPSEC_IOC_MAGIC, 6, struct ioc_dpa_ipsec_rekey_prm)
#ifdef CONFIG_COMPAT
#define DPA_IPSEC_IOC_SA_REKEYING_COMPAT \
	_IOWR(DPA_IPSEC_IOC_MAGIC, 6, struct ioc_compat_dpa_ipsec_rekey_prm)
#endif

#define DPA_IPSEC_IOC_FLUSH_ALL_SA \
		_IOW(DPA_IPSEC_IOC_MAGIC, 7, int)

#define DPA_IPSEC_IOC_GET_SA_POLICIES \
	_IOWR(DPA_IPSEC_IOC_MAGIC, 8, struct ioc_dpa_ipsec_get_policies)
#ifdef CONFIG_COMPAT
#define DPA_IPSEC_IOC_GET_SA_POLICIES_COMPAT \
	_IOWR(DPA_IPSEC_IOC_MAGIC, 8, struct ioc_compat_dpa_ipsec_get_policies)
#endif

#define DPA_IPSEC_IOC_FLUSH_SA_POLICIES \
	_IOW(DPA_IPSEC_IOC_MAGIC, 9, int)

#define DPA_IPSEC_IOC_DISABLE_SA \
	_IOW(DPA_IPSEC_IOC_MAGIC, 10, int)

#define DPA_IPSEC_IOC_GET_SA_STATS \
	_IOWR(DPA_IPSEC_IOC_MAGIC, 11, struct ioc_dpa_ipsec_sa_get_stats)

#define DPA_IPSEC_IOC_SA_MODIFY \
	_IOW(DPA_IPSEC_IOC_MAGIC, 12, struct ioc_dpa_ipsec_sa_modify_prm)
#ifdef CONFIG_COMPAT
#define DPA_IPSEC_IOC_SA_MODIFY_COMPAT \
	_IOW(DPA_IPSEC_IOC_MAGIC, 12, \
	     struct ioc_compat_dpa_ipsec_sa_modify_prm)
#endif

#define DPA_IPSEC_IOC_GET_STATS \
	_IOWR(DPA_IPSEC_IOC_MAGIC, 13, struct ioc_dpa_ipsec_instance_stats)

#define DPA_IPSEC_IOC_SA_REQUEST_SEQ_NUMBER \
	_IOW(DPA_IPSEC_IOC_MAGIC, 14, int)

#define DPA_IPSEC_IOC_SA_GET_SEQ_NUMBER \
	_IOWR(DPA_IPSEC_IOC_MAGIC, 15, struct ioc_dpa_ipsec_sa_get_seq_num)

#define DPA_IPSEC_IOC_SA_GET_OUT_PATH \
	_IOWR(DPA_IPSEC_IOC_MAGIC, 16, struct ioc_dpa_ipsec_sa_get_out_path)

#endif	/* __DPA_IPSEC_IOCTL_H */
