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
 * DPA Classifier Wrapper Application Programming Interface
 */

#ifndef __DPA_CLASSIFIER_IOCTL_H
#define __DPA_CLASSIFIER_IOCTL_H


/* Other includes */
#include "linux/ioctl.h"
#include <linux/compat.h>


#define DPA_CLS_IOC_MAGIC				0xbe


struct ioc_dpa_cls_tbl_params {
	struct dpa_cls_tbl_params table_params;
	int td;
};

struct ioc_dpa_cls_tbl_miss_action {
	int td;
	struct dpa_cls_tbl_action miss_action;
};

struct ioc_dpa_cls_tbl_entry_params {
	int td;
	struct dpa_offload_lookup_key key;
	struct dpa_cls_tbl_action action;
	int priority;
	int entry_id;
};

struct ioc_dpa_cls_tbl_entry_mod_by_key {
	int td;
	struct dpa_offload_lookup_key key;
	struct dpa_cls_tbl_entry_mod_params mod_params;
};

struct ioc_dpa_cls_tbl_entry_mod_by_ref {
	int td;
	int entry_id;
	struct dpa_cls_tbl_entry_mod_params mod_params;
};

struct ioc_dpa_cls_tbl_entry_by_key {
	int td;
	struct dpa_offload_lookup_key key;
};

struct ioc_dpa_cls_tbl_entry_by_ref {
	int td;
	int entry_id;
};

struct ioc_dpa_cls_tbl_lookup_by_key {
	int td;
	struct dpa_offload_lookup_key key;
	struct dpa_cls_tbl_action action;
};

struct ioc_dpa_cls_tbl_lookup_by_ref {
	int td;
	int entry_id;
	struct dpa_cls_tbl_action action;
};

struct ioc_dpa_cls_tbl_entry_stats_by_key {
	int td;
	struct dpa_offload_lookup_key key;
	struct dpa_cls_tbl_entry_stats stats;
};

struct ioc_dpa_cls_tbl_entry_stats_by_ref {
	int td;
	int entry_id;
	struct dpa_cls_tbl_entry_stats stats;
};

struct ioc_dpa_cls_tbl_miss_stats {
	int td;
	struct dpa_cls_tbl_entry_stats stats;
};

struct ioc_dpa_cls_hm_remove_params {
	struct dpa_cls_hm_remove_params rm_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_hm_remove_resources res;
	bool chain_head;
	int modify_flags;
};

struct ioc_dpa_cls_hm_insert_params {
	struct dpa_cls_hm_insert_params ins_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_hm_insert_resources res;
	bool chain_head;
	int modify_flags;
};

struct ioc_dpa_cls_hm_vlan_params {
	struct dpa_cls_hm_vlan_params vlan_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_hm_vlan_resources res;
	bool chain_head;
	int modify_flags;
};

struct ioc_dpa_cls_hm_nat_params {
	struct dpa_cls_hm_nat_params nat_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_hm_nat_resources res;
	bool chain_head;
	int modify_flags;
};

struct ioc_dpa_cls_hm_update_params {
	struct dpa_cls_hm_update_params update_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_hm_update_resources res;
	bool chain_head;
	int modify_flags;
};

struct ioc_dpa_cls_hm_fwd_params {
	struct dpa_cls_hm_fwd_params fwd_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_hm_fwd_resources res;
	bool chain_head;
	int modify_flags;
};

struct ioc_dpa_cls_hm_mpls_params {
	struct dpa_cls_hm_mpls_params mpls_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_hm_mpls_resources res;
	bool chain_head;
	int modify_flags;
};

struct ioc_dpa_cls_mcast_group_params {
	struct dpa_cls_mcast_group_params mcast_grp_params;
	int grpd;
	struct dpa_cls_mcast_group_resources res;
};

struct ioc_dpa_cls_mcast_member_params {
	int grpd;
	struct dpa_cls_tbl_enq_action_desc member_params;
	int md;
};

struct ioc_dpa_cls_mcast_remove_params {
	int grpd;
	int md;
};


#ifdef CONFIG_COMPAT

struct dpa_cls_compat_tbl_params {
	compat_uptr_t			cc_node;
	enum dpa_cls_tbl_type		type;
	enum dpa_cls_tbl_entry_mgmt	entry_mgmt;
	union {
		struct dpa_cls_tbl_hash_params		hash_params;
		struct dpa_cls_tbl_indexed_params	indexed_params;
		struct dpa_cls_tbl_exact_match_params	exact_match_params;
	};
	unsigned int			prefilled_entries;
};

struct compat_ioc_dpa_cls_tbl_params {
	struct dpa_cls_compat_tbl_params table_params;
	int td;
};

struct dpa_cls_compat_tbl_enq_action_desc {
	bool		override_fqid;
	uint32_t	new_fqid;
	compat_uptr_t	policer_params;
	int		hmd;
	uint8_t		new_rel_vsp_id;
	compat_uptr_t	distribution;
};

struct dpa_cls_compat_tbl_action {
	enum dpa_cls_tbl_action_type	type;
	bool				enable_statistics;
	union {
		struct dpa_cls_compat_tbl_enq_action_desc enq_params;
		struct dpa_cls_tbl_next_table_desc	next_table_params;
		struct dpa_cls_tbl_mcast_group_desc	mcast_params;
	};
};

struct compat_ioc_dpa_cls_tbl_miss_action {
	int td;
	struct dpa_cls_compat_tbl_action miss_action;
};

struct compat_ioc_dpa_offld_lookup_key {
	compat_uptr_t byte;
	compat_uptr_t mask;
	uint8_t size;
};

struct compat_ioc_dpa_cls_tbl_entry_by_key {
	int td;
	struct compat_ioc_dpa_offld_lookup_key key;
};

struct compat_ioc_dpa_cls_tbl_entry_stats_by_key {
	int td;
	struct compat_ioc_dpa_offld_lookup_key key;
	struct dpa_cls_tbl_entry_stats stats;
};

struct compat_ioc_dpa_cls_tbl_entry_params {
	int td;
	struct compat_ioc_dpa_offld_lookup_key key;
	struct dpa_cls_compat_tbl_action action;
	int priority;
	int entry_id;
};

struct dpa_cls_compat_tbl_entry_mod_params {
	enum dpa_cls_tbl_modify_type	type;
	compat_uptr_t			key;
	compat_uptr_t			action;
};

struct compat_ioc_dpa_cls_tbl_entry_mod_by_key {
	int td;
	struct compat_ioc_dpa_offld_lookup_key key;
	struct dpa_cls_compat_tbl_entry_mod_params mod_params;
};

struct compat_ioc_dpa_cls_tbl_entry_mod_by_ref {
	int td;
	int entry_id;
	struct dpa_cls_compat_tbl_entry_mod_params mod_params;
};

struct compat_ioc_dpa_cls_tbl_lookup_by_key {
	int td;
	struct compat_ioc_dpa_offld_lookup_key key;
	struct dpa_cls_compat_tbl_action action;
};

struct compat_ioc_dpa_cls_tbl_lookup_by_ref {
	int td;
	int entry_id;
	struct dpa_cls_compat_tbl_action action;
};

struct dpa_cls_compat_hm_remove_resources {
	compat_uptr_t	remove_node;
};

struct dpa_cls_compat_hm_remove_params {
	enum dpa_cls_hm_remove_type	type;
	struct dpa_cls_hm_custom_rm_params custom;
	compat_uptr_t fm_pcd;
	bool reparse;
};

struct compat_ioc_dpa_cls_hm_remove_params {
	struct dpa_cls_compat_hm_remove_params rm_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_compat_hm_remove_resources res;
	bool chain_head;
	int modify_flags;
};

struct dpa_cls_compat_hm_insert_resources {
	compat_uptr_t	insert_node;
};

struct dpa_cls_compat_hm_custom_ins_params {
	uint8_t		offset;
	uint8_t		size;
	compat_uptr_t	data;
};

struct dpa_cls_compat_hm_insert_params {
	enum dpa_cls_hm_insert_type type;
	union {
		struct dpa_cls_hm_eth_ins_params eth;
		struct pppoe_header pppoe_header;
		uint16_t ppp_pid;
		struct dpa_cls_compat_hm_custom_ins_params custom;
	};
	compat_uptr_t fm_pcd;
	bool reparse;
};

struct compat_ioc_dpa_cls_hm_insert_params {
	struct dpa_cls_compat_hm_insert_params ins_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_compat_hm_insert_resources res;
	bool chain_head;
	int modify_flags;
};

struct dpa_cls_compat_hm_vlan_params {
	enum dpa_cls_hm_vlan_type	type;
	union {
		struct dpa_cls_hm_ingress_vlan_params	ingress;
		struct dpa_cls_hm_egress_vlan_params	egress;
	};
	compat_uptr_t	fm_pcd;
	bool reparse;
};

struct dpa_cls_compat_hm_vlan_resources {
	compat_uptr_t	vlan_node;
};

struct compat_ioc_dpa_cls_hm_vlan_params {
	struct dpa_cls_compat_hm_vlan_params vlan_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_compat_hm_vlan_resources res;
	bool chain_head;
	int modify_flags;
};

struct compat_ipv4_header {
	struct iphdr			header;
	compat_uptr_t			options;
	uint8_t				options_size;
};

struct dpa_cls_compat_hm_nat_pt_params {
	enum dpa_cls_hm_nat_pt_type		type;

	union {
		struct compat_ipv4_header	ipv4;
		struct ipv6_header		ipv6;
	} new_header;
};

struct dpa_cls_compat_hm_nat_params {
	int		flags;
	enum dpa_cls_hm_nat_proto	proto;
	enum dpa_cls_hm_nat_type	type;
	union {
		struct dpa_cls_hm_traditional_nat_params	nat;
		struct dpa_cls_compat_hm_nat_pt_params		nat_pt;
	};
	uint16_t	sport;
	uint16_t	dport;
	compat_uptr_t	fm_pcd;
	bool		reparse;
};

struct dpa_cls_compat_hm_nat_resources {
	compat_uptr_t	l3_update_node;
	compat_uptr_t	l4_update_node;
};

struct compat_ioc_dpa_cls_hm_nat_params {
	struct dpa_cls_compat_hm_nat_params nat_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_compat_hm_nat_resources res;
	bool chain_head;
	int modify_flags;
};

struct dpa_cls_compat_hm_update_params {
	int					op_flags;
	union {
		struct compat_ipv4_header	new_ipv4_hdr;
		struct ipv6_header		new_ipv6_hdr;
	} replace;
	union {
		struct dpa_cls_hm_l3_update_params	l3;
		struct dpa_cls_hm_l4_update_params	l4;
	} update;
	struct dpa_cls_hm_ip_frag_params	ip_frag_params;
	compat_uptr_t				fm_pcd;
	bool					reparse;
};

struct dpa_cls_compat_hm_update_resources {
	compat_uptr_t	update_node;
	compat_uptr_t	ip_frag_node;

};

struct compat_ioc_dpa_cls_hm_update_params {
	struct dpa_cls_compat_hm_update_params update_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_compat_hm_update_resources res;
	bool chain_head;
	int modify_flags;
};

struct dpa_cls_compat_hm_fwd_params {
	enum dpa_cls_hm_out_if_type	out_if_type;
	union {
		struct dpa_cls_hm_fwd_l2_param		eth;
		struct dpa_cls_hm_fwd_pppoe_param	pppoe;
		struct dpa_cls_hm_fwd_ppp_param		ppp;
	};
	struct dpa_cls_hm_ip_frag_params	ip_frag_params;
	compat_uptr_t				fm_pcd;
	bool					reparse;
};

struct dpa_cls_compat_hm_fwd_resources {
	compat_uptr_t	fwd_node;
	compat_uptr_t	pppoe_node;
	compat_uptr_t	ip_frag_node;
};

struct compat_ioc_dpa_cls_hm_fwd_params {
	struct dpa_cls_compat_hm_fwd_params fwd_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_compat_hm_fwd_resources res;
	bool chain_head;
	int modify_flags;
};

struct dpa_cls_compat_hm_mpls_params {
	enum dpa_cls_hm_mpls_type	type;
	struct mpls_header		mpls_hdr[DPA_CLS_HM_MAX_MPLS_LABELS];
	unsigned int			num_labels;
	compat_uptr_t			fm_pcd;
	bool				reparse;
};

struct dpa_cls_compat_hm_mpls_resources {
	compat_uptr_t	ins_rm_node;
};

struct compat_ioc_dpa_cls_hm_mpls_params {
	struct dpa_cls_compat_hm_mpls_params mpls_params;
	int next_hmd;
	int hmd;
	struct dpa_cls_compat_hm_mpls_resources res;
	bool chain_head;
	int modify_flags;
};

struct dpa_cls_compat_mcast_group_params {
	uint8_t	max_members;
	compat_uptr_t	fm_pcd;
	struct	dpa_cls_compat_tbl_enq_action_desc first_member_params;
	unsigned int prefilled_members;
};

struct dpa_cls_compat_mcast_group_resources {
	compat_uptr_t   group_node;
};

struct compat_ioc_dpa_cls_mcast_group_params {
	struct dpa_cls_compat_mcast_group_params mcast_grp_params;
	int grpd;
	struct dpa_cls_compat_mcast_group_resources res;
};

struct compat_ioc_dpa_cls_mcast_member_params {
	int grpd;
	struct dpa_cls_compat_tbl_enq_action_desc member_params;
	int md;
};

int dpa_cls_tbl_entry_params_compatcpy(
	struct ioc_dpa_cls_tbl_entry_params			*kparam,
	const struct compat_ioc_dpa_cls_tbl_entry_params	*uparam);

int dpa_cls_tbl_params_compatcpy(
		struct ioc_dpa_cls_tbl_params			*kparam,
		const struct compat_ioc_dpa_cls_tbl_params	*uparam);

int dpa_cls_tbl_params_rcompatcpy(
		struct compat_ioc_dpa_cls_tbl_params		*uparam,
		const struct ioc_dpa_cls_tbl_params		*kparam);

int dpa_cls_tbl_miss_action_params_compatcpy(
		struct ioc_dpa_cls_tbl_miss_action		*kparam,
		const struct compat_ioc_dpa_cls_tbl_miss_action	*uparam);

int dpa_cls_tbl_action_params_compatcpy(
		struct dpa_cls_tbl_action			*kparam,
		const struct dpa_cls_compat_tbl_action		*uparam);

int dpa_cls_tbl_action_params_rcompatcpy(
		struct dpa_cls_compat_tbl_action		*uparam,
		const struct dpa_cls_tbl_action			*kparam);

int dpa_cls_tbl_entry_mod_by_key_params_compatcpy(
	struct ioc_dpa_cls_tbl_entry_mod_by_key			*kparam,
	const struct compat_ioc_dpa_cls_tbl_entry_mod_by_key	*uparam);

int dpa_cls_tbl_entry_mod_by_ref_params_compatcpy(
		struct ioc_dpa_cls_tbl_entry_mod_by_ref *kparam,
		const struct compat_ioc_dpa_cls_tbl_entry_mod_by_ref *uparam);

int dpa_cls_tbl_entry_mod_params_compatcpy(
		struct dpa_cls_tbl_entry_mod_params *kparam,
		const struct dpa_cls_compat_tbl_entry_mod_params *uparam);

int dpa_cls_tbl_entry_by_key_params_compatcpy(
	struct ioc_dpa_cls_tbl_entry_by_key			*kparam,
	const struct compat_ioc_dpa_cls_tbl_entry_by_key	*uparam);

int dpa_cls_tbl_lookup_by_key_params_compatcpy(
		struct ioc_dpa_cls_tbl_lookup_by_key *kparam,
		const struct compat_ioc_dpa_cls_tbl_lookup_by_key *uparam);

int dpa_cls_tbl_lookup_by_ref_params_compatcpy(
		struct ioc_dpa_cls_tbl_lookup_by_ref *kparam,
		const struct compat_ioc_dpa_cls_tbl_lookup_by_ref *uparam);

int dpa_cls_tbl_entry_stats_by_key_params_compatcpy(
	struct ioc_dpa_cls_tbl_entry_stats_by_key		*kparam,
	const struct compat_ioc_dpa_cls_tbl_entry_stats_by_key	*uparam);

int dpa_lookup_key_params_compatcpy(
		struct dpa_offload_lookup_key			*kparam,
		const struct compat_ioc_dpa_offld_lookup_key	*uparam);

int dpa_cls_hm_remove_params_compatcpy(
	struct ioc_dpa_cls_hm_remove_params			*kparam,
	const struct compat_ioc_dpa_cls_hm_remove_params	*uparam);

int dpa_cls_hm_insert_params_compatcpy(
	struct ioc_dpa_cls_hm_insert_params			*kparam,
	const struct compat_ioc_dpa_cls_hm_insert_params	*uparam);

int dpa_cls_hm_vlan_params_compatcpy(
	struct ioc_dpa_cls_hm_vlan_params			*kparam,
	const struct compat_ioc_dpa_cls_hm_vlan_params		*uparam);

int dpa_cls_hm_nat_params_compatcpy(
	struct ioc_dpa_cls_hm_nat_params			*kparam,
	const struct compat_ioc_dpa_cls_hm_nat_params		*uparam);

int dpa_cls_hm_update_params_compatcpy(
	struct ioc_dpa_cls_hm_update_params			*kparam,
	const struct compat_ioc_dpa_cls_hm_update_params	*uparam);

int dpa_cls_hm_fwd_params_compatcpy(
	struct ioc_dpa_cls_hm_fwd_params			*kparam,
	const struct compat_ioc_dpa_cls_hm_fwd_params		*uparam);

int dpa_cls_hm_mpls_params_compatcpy(
	struct ioc_dpa_cls_hm_mpls_params			*kparam,
	const struct compat_ioc_dpa_cls_hm_mpls_params		*uparam);

int dpa_cls_mcast_group_params_compatcpy(
	struct ioc_dpa_cls_mcast_group_params			*kparam,
	const struct compat_ioc_dpa_cls_mcast_group_params	*uparam);

int dpa_cls_mcast_member_params_compatcpy(
	struct ioc_dpa_cls_mcast_member_params			*kparam,
	const struct compat_ioc_dpa_cls_mcast_member_params	*uparam);
#endif /* CONFIG_COMPAT */


#define DPA_CLS_IOC_TBL_CREATE				\
	_IOWR(DPA_CLS_IOC_MAGIC, 0, struct ioc_dpa_cls_tbl_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_CREATE			\
	_IOWR(DPA_CLS_IOC_MAGIC, 0, struct compat_ioc_dpa_cls_tbl_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_TBL_FREE				\
	_IOW(DPA_CLS_IOC_MAGIC, 1, int)

#define DPA_CLS_IOC_TBL_MODIFY_MISS_ACTION		\
	_IOW(DPA_CLS_IOC_MAGIC, 2, struct ioc_dpa_cls_tbl_miss_action)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_MODIFY_MISS_ACTION	\
	_IOW(DPA_CLS_IOC_MAGIC, 2, struct compat_ioc_dpa_cls_tbl_miss_action)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_TBL_INSERT_ENTRY			\
	_IOWR(DPA_CLS_IOC_MAGIC, 3, struct ioc_dpa_cls_tbl_entry_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_INSERT_ENTRY		\
	_IOWR(DPA_CLS_IOC_MAGIC, 3, struct compat_ioc_dpa_cls_tbl_entry_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_TBL_MODIFY_ENTRY_BY_KEY		\
	_IOW(DPA_CLS_IOC_MAGIC, 4, struct ioc_dpa_cls_tbl_entry_mod_by_key)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_MODIFY_ENTRY_BY_KEY	\
	_IOW(DPA_CLS_IOC_MAGIC, 4,			\
		struct compat_ioc_dpa_cls_tbl_entry_mod_by_key)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_TBL_MODIFY_ENTRY_BY_REF		\
	_IOW(DPA_CLS_IOC_MAGIC, 5, struct ioc_dpa_cls_tbl_entry_mod_by_ref)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_MODIFY_ENTRY_BY_REF	\
	_IOW(DPA_CLS_IOC_MAGIC, 5,			\
		struct compat_ioc_dpa_cls_tbl_entry_mod_by_ref)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_TBL_DELETE_ENTRY_BY_KEY		\
	_IOW(DPA_CLS_IOC_MAGIC, 6, struct ioc_dpa_cls_tbl_entry_by_key)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_DELETE_ENTRY_BY_KEY	\
	_IOW(DPA_CLS_IOC_MAGIC, 6,			\
		struct compat_ioc_dpa_cls_tbl_entry_by_key)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_TBL_DELETE_ENTRY_BY_REF		\
	_IOW(DPA_CLS_IOC_MAGIC, 7, struct ioc_dpa_cls_tbl_entry_by_ref)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_DELETE_ENTRY_BY_REF	\
	_IOW(DPA_CLS_IOC_MAGIC, 7,			\
		struct compat_ioc_dpa_cls_tbl_entry_by_ref)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_TBL_LOOKUP_BY_KEY			\
	_IOR(DPA_CLS_IOC_MAGIC, 8, struct ioc_dpa_cls_tbl_lookup_by_key)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_LOOKUP_BY_KEY		\
	_IOR(DPA_CLS_IOC_MAGIC, 8, struct compat_ioc_dpa_cls_tbl_lookup_by_key)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_TBL_LOOKUP_BY_REF			\
	_IOR(DPA_CLS_IOC_MAGIC, 9, struct ioc_dpa_cls_tbl_lookup_by_ref)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_LOOKUP_BY_REF		\
	_IOR(DPA_CLS_IOC_MAGIC, 9, struct compat_ioc_dpa_cls_tbl_lookup_by_ref)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_TBL_FLUSH				\
	_IOW(DPA_CLS_IOC_MAGIC, 10, int)

#define DPA_CLS_IOC_TBL_GET_STATS_BY_KEY		\
	_IOR(DPA_CLS_IOC_MAGIC, 11, struct ioc_dpa_cls_tbl_entry_stats_by_key)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_GET_STATS_BY_KEY		\
	_IOR(DPA_CLS_IOC_MAGIC, 11,			\
		struct compat_ioc_dpa_cls_tbl_entry_stats_by_key)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_TBL_GET_STATS_BY_REF		\
	_IOR(DPA_CLS_IOC_MAGIC, 12, struct ioc_dpa_cls_tbl_entry_stats_by_ref)

#define DPA_CLS_IOC_TBL_GET_MISS_STATS			\
	_IOR(DPA_CLS_IOC_MAGIC, 13, struct ioc_dpa_cls_tbl_miss_stats)

#define DPA_CLS_IOC_TBL_GET_PARAMS			\
	_IOWR(DPA_CLS_IOC_MAGIC, 15, struct ioc_dpa_cls_tbl_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_TBL_GET_PARAMS		\
	_IOWR(DPA_CLS_IOC_MAGIC, 15, struct compat_ioc_dpa_cls_tbl_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_SET_REMOVE_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 16, struct ioc_dpa_cls_hm_remove_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_SET_REMOVE_HM		\
	_IOWR(DPA_CLS_IOC_MAGIC, 16,			\
		struct compat_ioc_dpa_cls_hm_remove_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_MODIFY_REMOVE_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 17, struct ioc_dpa_cls_hm_remove_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_MODIFY_REMOVE_HM		\
	_IOWR(DPA_CLS_IOC_MAGIC, 17,			\
		struct compat_ioc_dpa_cls_hm_remove_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_SET_INSERT_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 18, struct ioc_dpa_cls_hm_insert_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_SET_INSERT_HM		\
	_IOWR(DPA_CLS_IOC_MAGIC, 18,			\
		struct compat_ioc_dpa_cls_hm_insert_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_MODIFY_INSERT_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 19, struct ioc_dpa_cls_hm_insert_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_MODIFY_INSERT_HM		\
	_IOWR(DPA_CLS_IOC_MAGIC, 19,			\
		struct compat_ioc_dpa_cls_hm_insert_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_SET_VLAN_HM				\
	_IOWR(DPA_CLS_IOC_MAGIC, 20, struct ioc_dpa_cls_hm_vlan_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_SET_VLAN_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 20, struct compat_ioc_dpa_cls_hm_vlan_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_MODIFY_VLAN_HM				\
	_IOWR(DPA_CLS_IOC_MAGIC, 21, struct ioc_dpa_cls_hm_vlan_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_MODIFY_VLAN_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 21, struct compat_ioc_dpa_cls_hm_vlan_params)
#endif /* CONFIG_COMPAT */


#define DPA_CLS_IOC_SET_NAT_HM				\
	_IOWR(DPA_CLS_IOC_MAGIC, 22, struct ioc_dpa_cls_hm_nat_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_SET_NAT_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 22, struct compat_ioc_dpa_cls_hm_nat_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_MODIFY_NAT_HM				\
	_IOWR(DPA_CLS_IOC_MAGIC, 23, struct ioc_dpa_cls_hm_nat_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_MODIFY_NAT_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 23, struct compat_ioc_dpa_cls_hm_nat_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_SET_UPDATE_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 24, struct ioc_dpa_cls_hm_update_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_SET_UPDATE_HM		\
	_IOWR(DPA_CLS_IOC_MAGIC, 24, struct compat_ioc_dpa_cls_hm_update_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_MODIFY_UPDATE_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 25, struct ioc_dpa_cls_hm_update_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_MODIFY_UPDATE_HM		\
	_IOWR(DPA_CLS_IOC_MAGIC, 25, struct compat_ioc_dpa_cls_hm_update_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_SET_FWD_HM				\
	_IOWR(DPA_CLS_IOC_MAGIC, 26, struct ioc_dpa_cls_hm_fwd_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_SET_FWD_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 26, struct compat_ioc_dpa_cls_hm_fwd_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_MODIFY_FWD_HM				\
	_IOWR(DPA_CLS_IOC_MAGIC, 27, struct ioc_dpa_cls_hm_fwd_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_MODIFY_FWD_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 27, struct compat_ioc_dpa_cls_hm_fwd_params)
#endif /* CONFIG_COMPAT */

#define DPA_CLS_IOC_SET_MPLS_HM				\
	_IOWR(DPA_CLS_IOC_MAGIC, 28, struct ioc_dpa_cls_hm_mpls_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_SET_MPLS_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 28, struct compat_ioc_dpa_cls_hm_mpls_params)
#endif

#define DPA_CLS_IOC_MODIFY_MPLS_HM				\
	_IOWR(DPA_CLS_IOC_MAGIC, 29, struct ioc_dpa_cls_hm_mpls_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_MODIFY_MPLS_HM			\
	_IOWR(DPA_CLS_IOC_MAGIC, 29, struct compat_ioc_dpa_cls_hm_mpls_params)
#endif

#define DPA_CLS_IOC_FREE_HM				\
	_IOR(DPA_CLS_IOC_MAGIC, 30, int)

#define DPA_CLS_IOC_MCAST_CREATE_GROUP				\
	_IOWR(DPA_CLS_IOC_MAGIC, 31, struct ioc_dpa_cls_mcast_group_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_MCAST_CREATE_GROUP			\
	_IOWR(DPA_CLS_IOC_MAGIC, 31,				\
	      struct compat_ioc_dpa_cls_mcast_group_params)
#endif

#define DPA_CLS_IOC_MCAST_ADD_MEMBER				\
	_IOWR(DPA_CLS_IOC_MAGIC, 32, struct ioc_dpa_cls_mcast_member_params)

#ifdef CONFIG_COMPAT
#define DPA_CLS_IOC_COMPAT_MCAST_ADD_MEMBER			\
	_IOWR(DPA_CLS_IOC_MAGIC, 32,				\
	      struct compat_ioc_dpa_cls_mcast_member_params)
#endif

#define DPA_CLS_IOC_MCAST_REMOVE_MEMBER				\
	_IOWR(DPA_CLS_IOC_MAGIC, 33, struct ioc_dpa_cls_mcast_remove_params)

#define DPA_CLS_IOC_MCAST_FREE_GROUP				\
	_IOWR(DPA_CLS_IOC_MAGIC, 34, int)


#endif /* __DPA_CLASSIFIER_IOCTL_H */
