
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
 * DPA Classifier Application Programming Interface.
 */

#ifndef __FSL_DPA_CLASSIFIER_H
#define __FSL_DPA_CLASSIFIER_H


/* DPA offloading layer includes */
#include "fsl_dpa_offload.h"


/* General definitions */

/* Maximum number of VLAN tags supported by the insert header manipulation */
#define DPA_CLS_HM_MAX_VLANs					6
/* Maximum number of MPLS labels supported by the insert header manipulation */
#define DPA_CLS_HM_MAX_MPLS_LABELS				6
/* Standard size of the DSCP-to-VPri mapping table */
#define DPA_CLS_HM_DSCP_TO_VLAN_TABLE_SIZE			32
/* Number of entries in the DSCP-to-VPri mapping table */
#define DPA_CLS_HM_DSCP_TO_VPRI_TABLE_SIZE			64


/* API functions, definitions and enums */

/* Table API */

/* DPA Classifier Table Types */
enum dpa_cls_tbl_type {
	DPA_CLS_TBL_HASH = 0,		/* HASH table */
	DPA_CLS_TBL_INDEXED,		/* Indexed table */
	DPA_CLS_TBL_EXACT_MATCH		/* Exact match table */
};

/* DPA Classifier Table Action Types */
enum dpa_cls_tbl_action_type {

	/* Unspecified action */
	DPA_CLS_TBL_ACTION_NONE = 0,

	/* Drop frame */
	DPA_CLS_TBL_ACTION_DROP,

	/* Send frame into a frame queue (enqueue) */
	DPA_CLS_TBL_ACTION_ENQ,

	/* Go to another table and re-classify the packet */
	DPA_CLS_TBL_ACTION_NEXT_TABLE,

	/* Send frames to a multicast group */
	DPA_CLS_TBL_ACTION_MCAST

};

/* DPA Classifier Table Entry Modification Types */
enum dpa_cls_tbl_modify_type {

	/*
	 * Modify the entry key. This modification is supported only on exact
	 * match tables.
	 */
	DPA_CLS_TBL_MODIFY_KEY = 0,

	/* Modify the entry action */
	DPA_CLS_TBL_MODIFY_ACTION,

	/*
	 * Modify the entry key and action. This modification is supported only
	 * on exact match tables.
	 */
	DPA_CLS_TBL_MODIFY_KEY_AND_ACTION
};

/* DPA Classifier Table Entry Management Types */
enum dpa_cls_tbl_entry_mgmt {
	/*
	 * Manage entries by key (shadow table). The shadow table consumes more
	 * RAM, but allows the user to do software lookups and refer to the
	 * table entries by their key as well as by their reference (Id)
	 */
	DPA_CLS_TBL_MANAGE_BY_KEY = 0,

	/*
	 * Manage entries by reference only (no shadow table). Saves memory and
	 * speeds up runtime operations, but the user cannot do software
	 * lookups and can only refer to the entries by their reference (Id)
	 */
	DPA_CLS_TBL_MANAGE_BY_REF,
};


/* DPA Classifier HASH table parameters */
struct dpa_cls_tbl_hash_params {

	/* Number of sets (buckets) of the HASH table */
	unsigned int	num_sets;

	/* Number of ways of the HASH table (capability to resolve conflicts) */
	unsigned int	max_ways;

	/* HASH offset */
	unsigned int	hash_offs;

	/* Key size in bytes */
	uint8_t		key_size;
};

/* DPA Classifier indexed table parameters */
struct dpa_cls_tbl_indexed_params {

	unsigned int	entries_cnt;	/* Number of entries in the table */
};

/* DPA Classifier exact match table parameters */
struct dpa_cls_tbl_exact_match_params {

	/* Number of entries in the table */
	unsigned int	entries_cnt;

	/* Key size in bytes */
	uint8_t		key_size;

	/* Use priorities for each entry in table if nonzero */
	bool		use_priorities;
};

/* DPA Classifier table parameters */
struct dpa_cls_tbl_params {
	/*
	 * Handle of the initial FM Cc node for this table
	 *
	 * This Cc node must be connected to a Cc tree.
	 */
	void					*cc_node;

	/* The type of the DPA Classifier table */
	enum dpa_cls_tbl_type			type;

	/* Table entry management mechanism for runtime */
	enum dpa_cls_tbl_entry_mgmt		entry_mgmt;

	union {
		/* Parameters for HASH table */
		struct dpa_cls_tbl_hash_params		hash_params;

		/* Parameters for indexed table */
		struct dpa_cls_tbl_indexed_params	indexed_params;

		/* Parameters for exact match table */
		struct dpa_cls_tbl_exact_match_params	exact_match_params;
	};

	/*
	 * Number of entries in the table which are pre-filled from the
	 * skeleton. The assumption is always that these entries are the first
	 * entries in the table and with the highest priority.
	 */
	unsigned int				prefilled_entries;
};

/* Policer parameters */
struct dpa_cls_tbl_policer_params {

	/* [True] if the default policer parameters will be overridden */
	bool		modify_policer_params;

	/* [True] if this policer profile is shared between ports; relevant
	 * only if [modify_policer_params] is set to [true]. */
	bool		shared_profile;

	/*
	 * This parameter should indicate the policer profile offset within the
	 * port's policer profiles or from the SHARED window; relevant only if
	 * [modify_policer_params] is set to [true].
	 */
	unsigned int	new_rel_profile_id;
};

/* Enqueue action parameters */
struct dpa_cls_tbl_enq_action_desc {

	/*
	 * Override the frame queue Id from KeyGen and use the one
	 * specified in this enqueue action descriptor if set to true
	 */
	bool					override_fqid;

	/*
	 * Id of the frame queue where to send the frames in case of
	 * rule hit.
	 */
	uint32_t				new_fqid;

	/*
	 * Pointer to the policer parameters. If NULL, no policing is
	 * applied during the enqueue.
	 */
	struct dpa_cls_tbl_policer_params	*policer_params;

	/*
	 * Descriptor of the header manipulation chain to use with this
	 * entry.
	 */
	int					hmd;

	/*
	 * New virtual storage profile Id. This parameter is mandatory when
	 * [override_fqid] is set to [true] and the port has virtual storage
	 * profiles defined. Otherwise it is not used.
	 */
	uint8_t					new_rel_vsp_id;

	/*
	 * Handle to a FMan distribution to send frames to instead of
	 * enqueuing frames. If this handle is provided (not NULL) the enqueue
	 * action will only select the frame queue, but it will NOT actually
	 * enqueue the frame to the selected frame queue. Instead it will send
	 * the frame to the indicated distribution for further processing.
	 */
	void					*distribution;
};

/* Action parameters to route to a new classifier table */
struct dpa_cls_tbl_next_table_desc {

	/*
	 * Descriptor of the next DPA Classifier table to continue
	 * classification with
	 */
	int		next_td;

	/*
	 * Descriptor of the header manipulation chain to use before sending
	 * the frames to the next table.
	 */
	int		hmd;
};

struct dpa_cls_tbl_mcast_group_desc {

	/*
	 * Descriptor of the multicast group to use with a specific table entry.
	 */
	int		grpd;

	/*
	 * Descriptor of the header manipulation chain that will be performed
	 * before sending the frames to the multicast group
	 */
	int		hmd;
};

/* DPA Classifier action descriptor */
struct dpa_cls_tbl_action {

	/*
	 * Action type specifier. Drop action doesn't require any
	 * further parameters
	 */
	enum dpa_cls_tbl_action_type	type;

	/* Enable statistics for this entry if nonzero */
	bool				enable_statistics;

	union {

		/* Specific parameters for enqueue action */
		struct dpa_cls_tbl_enq_action_desc	enq_params;

		/*
		 * Specific parameters for sending the frames to a new
		 * classifier table
		 */
		struct dpa_cls_tbl_next_table_desc	next_table_params;

		/*
		 * Specific parameters for sending the frame to a multicast
		 * group
		 */
		struct dpa_cls_tbl_mcast_group_desc	mcast_params;

	};
};

/* DPA Classifier entry modification parameters */
struct dpa_cls_tbl_entry_mod_params {

	/* The type of modification */
	enum dpa_cls_tbl_modify_type		type;

	/*
	 * The new key parameters to replace the existing key
	 * parameters of the entry. Ignored for modify types which
	 * do not refer to the key.
	 */
	struct dpa_offload_lookup_key		*key;

	/*
	 * The new action parameters to replace the existing action
	 * parameters of the entry. Ignored for modify types which
	 * do not refer to the action.
	 */
	struct dpa_cls_tbl_action		*action;
};

/* DPA Classifier table entry statistics */
struct dpa_cls_tbl_entry_stats {

	/* The total number of packets that have hit the entry */
	uint32_t	pkts;

	/* The total number of bytes that have hit the entry */
	uint32_t	bytes;
};


/*
 * Creates and initializes a DPA Classifier table using a FMan
 * coarse classification node. Depending on the type of table,
 * this call can result in MURAM allocation.
 *
 * Once the DPA Classifier takes control of a FMan Cc node, all
 * its management must be performed through this API. If
 * applications use different APIs to modify the Cc node's
 * properties in the same time while the DPA Classifier has
 * ownership of the node, unpredictable behavior and data
 * inconsistency can occur.
 */
int dpa_classif_table_create(const struct dpa_cls_tbl_params	*params,
				int				*td);

/*
 * Releases all resources associated with a DPA Classifier table
 * and destroys it.
 */
int dpa_classif_table_free(int td);

/* Modifies the action taken in case of lookup miss condition. */
int dpa_classif_table_modify_miss_action(int			td,
				const struct dpa_cls_tbl_action	*miss_action);

/*
 * Adds an entry (classification rule) in the specified DPA
 * Classifier table. If the MURAM for the table was pre-allocated,
 * this operation doesn't consume MURAM.
 *
 * The hardware currently doesn't support longest prefix match on
 * the exact match tables. If there are more entries in the
 * table that match the lookup (e.g. because of their mask) the
 * first one will always be returned by the hardware lookup.
 *
 * The priority parameter is meaningful only if [td] is an exact match table
 * with priority per entries. The priority value of the entry influences the
 * position of the entry in the table relative to the other entries. Entries
 * with lower priority values go to the top of the table. Priority values can
 * be negative. If two entries with the same priority are inserted in the
 * table, they will be positioned one after the other in the table, and the
 * older one first.
 */
int dpa_classif_table_insert_entry(int				td,
			const struct dpa_offload_lookup_key	*key,
			const struct dpa_cls_tbl_action		*action,
			int					priority,
			int					*entry_id);

/*
 * Modifies an entry in the specified DPA Classifier table. The
 * entry is identified by the lookup key. This function never
 * allocates new MURAM space.
 */
int dpa_classif_table_modify_entry_by_key(int			td,
		const struct dpa_offload_lookup_key		*key,
		const struct dpa_cls_tbl_entry_mod_params	*mod_params);

/*
 * Modifies an entry in the specified DPA Classifier table. The
 * entry is identified by its ref (Id). This function never
 * allocates new MURAM space.
 */
int dpa_classif_table_modify_entry_by_ref(int			td,
		int						entry_id,
		const struct dpa_cls_tbl_entry_mod_params	*mod_params);

/*
 * Removes an entry in the specified DPA Classifier table. The
 * entry is identified by the lookup key. If the MURAM for the
 * table was pre-allocated, this function doesn't free up any
 * MURAM space.
 */
int dpa_classif_table_delete_entry_by_key(int				td,
				const struct dpa_offload_lookup_key	*key);

/*
 * Removes an entry in the specified DPA Classifier table. The
 * entry is identified by its ref (Id). If the MURAM for the
 * table was pre-allocated, this function doesn't free up any
 * MURAM space.
 */
int dpa_classif_table_delete_entry_by_ref(int td, int entry_id);

/*
 * Performs a lookup in the specified table for an entry specified
 * by a key. If successful (i.e. the entry exists in that table)
 * the action descriptor for that entry is returned.
 *
 * Table lookup works only if entry management by key is selected
 * for the DPA Classifier table.
 *
 * This is not a hardware accelerated lookup. This lookup is
 * performed by the DPA Classifier in its internal shadow tables.
 * It is recommended to use this function with consideration.
 */
int dpa_classif_table_lookup_by_key(int				td,
			const struct dpa_offload_lookup_key	*key,
			struct dpa_cls_tbl_action		*action);

/*
 * Performs a lookup in the specified table for an entry specified
 * by its ref (Id). The action descriptor for that entry is
 * returned.
 *
 * Table lookup works only if entry management by key is selected
 * for the DPA Classifier table.
 */
int dpa_classif_table_lookup_by_ref(int				td,
				int				entry_id,
				struct dpa_cls_tbl_action	*action);

/*
 * Removes all the entries in a DPA Classifier Table. After this
 * operation is completed the entries cannot be recovered.
 */
int dpa_classif_table_flush(int td);

/*
 * Returns the statistics for a specified entry in a specified
 * table. The entry is identified by the lookup key.
 */
int dpa_classif_table_get_entry_stats_by_key(int			td,
				const struct dpa_offload_lookup_key	*key,
				struct dpa_cls_tbl_entry_stats		*stats);

/*
 * Returns the statistics for a specified entry in a specified
 * table. The entry is identified by its ref (pointer).
 */
int dpa_classif_table_get_entry_stats_by_ref(int		td,
				int				entry_id,
				struct dpa_cls_tbl_entry_stats	*stats);

/* Returns the miss statistics for the specified table. */
int dpa_classif_table_get_miss_stats(int			td,
				struct dpa_cls_tbl_entry_stats	*stats);


/* Returns the parameters of a classifier table. */
int dpa_classif_table_get_params(int td, struct dpa_cls_tbl_params *params);


/* Header Manipulation API */


/* Supported protocols for NAT header manipulations */
enum dpa_cls_hm_nat_proto {
	DPA_CLS_NAT_PROTO_UDP,
	DPA_CLS_NAT_PROTO_TCP,
	DPA_CLS_NAT_PROTO_ICMP,
	DPA_CLS_NAT_PROTO_LAST_ENTRY
};

/* NAT operation type */
enum dpa_cls_hm_nat_type {
	/* Traditional NAT */
	DPA_CLS_HM_NAT_TYPE_TRADITIONAL,

	/* NAT w/ protocol translation */
	DPA_CLS_HM_NAT_TYPE_NAT_PT,

	DPA_CLS_HM_NAT_TYPE_LAST_ENTRY
};

/*
 * Flag values indicating the possible fields to be updated with the
 * NAT header manipulation
 */
enum dpa_cls_hm_nat_flags {
	DPA_CLS_HM_NAT_UPDATE_SIP	= 0x01,
	DPA_CLS_HM_NAT_UPDATE_DIP	= 0x02,
	DPA_CLS_HM_NAT_UPDATE_SPORT	= 0x04,
	DPA_CLS_HM_NAT_UPDATE_DPORT	= 0x08
};

/* Type of protocol translation for NAT */
enum dpa_cls_hm_nat_pt_type {
	DPA_CLS_HM_NAT_PT_IPv6_TO_IPv4,
	DPA_CLS_HM_NAT_PT_IPv4_TO_IPv6
};

/*
 * Flag values indicating which attributes of the NAT header manipulation to
 * modify
 */
enum dpa_cls_hm_nat_modify_flags {
	DPA_CLS_HM_NAT_MOD_FLAGS	= 0x01,
	DPA_CLS_HM_NAT_MOD_SIP		= 0x02,
	DPA_CLS_HM_NAT_MOD_DIP		= 0x04,
	DPA_CLS_HM_NAT_MOD_SPORT	= 0x08,
	DPA_CLS_HM_NAT_MOD_DPORT	= 0x10,
	DPA_CLS_HM_NAT_MOD_IP_HDR	= 0x20
};

/* NAT header manipulation low level driver resources */
struct dpa_cls_hm_nat_resources {
	/*
	 * Handle to a header manipulation node which may combine a local
	 * IPv4/IPv6 update header manipulation with an IP protocol replace.
	 * This is a FMan driver header manipulation node handle and it is
	 * mandatory for the import to succeed.
	 */
	void	*l3_update_node;

	/*
	 * Handle to the local TCP/UDP update header manipulation node. This is
	 * a FMan driver header manipulation node handle and it is optional
	 * (can be NULL in case no L4 header updates are necessary for this NAT
	 * flow).
	 */
	void	*l4_update_node;
};

/* Traditional NAT parameters */
struct dpa_cls_hm_traditional_nat_params {
	/* New source IP address */
	struct dpa_offload_ip_address		sip;

	/* New destination IP address */
	struct dpa_offload_ip_address		dip;
};

/* NAT-PT parameters */
struct dpa_cls_hm_nat_pt_params {
	/*
	 * Specifies the protocol replacement for NAT-PT: either IPv4-to-IPv6
	 * or IPv6-to-IPv4
	 */
	enum dpa_cls_hm_nat_pt_type		type;

	union {
		/* New IPv4 header data to replace IPv6 with */
		struct ipv4_header		ipv4;

		/* New IPv6 header data to replace IPv4 with */
		struct ipv6_header		ipv6;
	} new_header;
};

/* Definition of a NAT related header manipulation */
struct dpa_cls_hm_nat_params {
	/*
	 * NAT operation flags specify which fields in the packet should be
	 * updated. This is a combination of the values in the
	 * dpa_cls_hm_nat_flags enum.
	 */
	int							flags;

	/* Protocol to perform NAT for */
	enum dpa_cls_hm_nat_proto				proto;

	/* Selects the flavor of NAT to configure */
	enum dpa_cls_hm_nat_type				type;


	union {
		/*
		 * Traditional NAT header manipulation parameters. Used only
		 * when traditional NAT is selected using the [type] attribute.
		 */
		struct dpa_cls_hm_traditional_nat_params	nat;

		/*
		 * NAT-PT header manipulation parameters. Used only when NAT-PT
		 * is selected using the [type] attribute.
		 */
		struct dpa_cls_hm_nat_pt_params			nat_pt;
	};

	/*
	 * New L4 protocol source port number; used when selected using the
	 * flags attribute.
	 */
	uint16_t						sport;

	/*
	 * New L4 protocol destination port number; used only when selected
	 * using the flags attribute
	 */
	uint16_t						dport;

	/*
	 * Handle to the low level driver PCD to use when creating the header
	 * manipulation object.
	 */
	void							*fm_pcd;

	/*
	 * Request re-parsing of the packet headers after this NAT.
	 */
	bool							reparse;
};

/* Output interface type for forwarding */
enum dpa_cls_hm_out_if_type {
	DPA_CLS_HM_IF_TYPE_ETHERNET,
	DPA_CLS_HM_IF_TYPE_PPPoE,
	DPA_CLS_HM_IF_TYPE_PPP,
	DPA_CLS_HM_IF_TYPE_LAST_ENTRY
};

/*
 * Flag values indicating which forwarding header manipulation attributes to
 * modify
 */
enum dpa_cls_hm_fwd_modify_flags {
	DPA_CLS_HM_FWD_MOD_ETH_MACSA		= 0x01,
	DPA_CLS_HM_FWD_MOD_ETH_MACDA		= 0x02,
	DPA_CLS_HM_FWD_MOD_PPPoE_HEADER		= 0x04,
	DPA_CLS_HM_FWD_MOD_PPP_PID		= 0x08,
	DPA_CLS_HM_FWD_MOD_IP_FRAG_MTU		= 0x10,
	DPA_CLS_HM_FWD_MOD_IP_FRAG_SCRATCH_BPID	= 0x20,
	DPA_CLS_HM_FWD_MOD_IP_FRAG_DF_ACTION	= 0x40
};

enum dpa_cls_hm_frag_df_action {
	DPA_CLS_HM_DF_ACTION_FRAG_ANYWAY,
	DPA_CLS_HM_DF_ACTION_DONT_FRAG,
	DPA_CLS_HM_DF_ACTION_DROP
};

/* IP fragmentation parameters */
struct dpa_cls_hm_ip_frag_params {
	/* Maximum Transfer Unit. Use zero to disable IP fragmentation. */
	uint16_t				mtu;

	/*
	 * Scratch buffer pool ID. This is necessary for the IP fragmentation
	 * on FMan v2 devices only. On FMan v3 or newer devices this parameter
	 * is ignored. It is also ignored if IP fragmentation is disabled.
	 */
	uint8_t					scratch_bpid;

	/* Specifies how to deal with packets with DF flag on */
	enum dpa_cls_hm_frag_df_action		df_action;
};

struct dpa_cls_hm_fwd_l2_param {
	/* New Ethernet destination MAC address to update the L2 header */
	uint8_t				macda[ETH_ALEN];

	/* New Ethernet source MAC address to update the L2 header */
	uint8_t				macsa[ETH_ALEN];
};

/* Forwarding header manipulation parameters for a PPPoE output interface */
struct dpa_cls_hm_fwd_pppoe_param {
	/* L2 header update parameters */
	struct dpa_cls_hm_fwd_l2_param		l2;

	/*
	 * PPPoE header to be inserted in the packets. The PPPoE payload length
	 * field is updated automatically (you can set it to zero).
	 */
	struct pppoe_header			pppoe_header;
};

/* Forwarding header manipulation parameters for a PPP output interface */
struct dpa_cls_hm_fwd_ppp_param {
	/* PPP PID value to use in the PPP header to be inserted */
	uint16_t				ppp_pid;
};

/* Forwarding header manipulation low level driver resources */
struct dpa_cls_hm_fwd_resources {
	/*
	 * Handle to the forwarding header manipulation node.
	 *
	 * In case of an Ethernet or a PPPoE output interface this is a local
	 * header replace header manipulation node (for Ethernet MAC addresses).
	 *
	 * In case of a PPP output interface this is a protocol specific header
	 * removal node (for Ethernet and VLAN tags) combined with an internal
	 * header insert.
	 *
	 * This is a FMan driver header manipulation node handle and it is
	 * mandatory for the import to succeed.
	 */
	void	*fwd_node;

	/*
	 * Handle to the PPPoE specific node. This is an internal protocol
	 * specific insert PPPoE header manipulation node. This is a FMan driver
	 * header manipulation node handle and it is optional (can be NULL in
	 * case the output interface type is not PPPoE).
	 */
	void	*pppoe_node;

	/*
	 * Handle to the IP fragmentation node. This is a FMan driver header
	 * manipulation node handle and it is optional (can be NULL in case no
	 * IP fragmentation is enabled for this IP forwarding flow).
	 */
	void	*ip_frag_node;
};

/* Forwarding header manipulation parameters */
struct dpa_cls_hm_fwd_params {
	/*
	 * Output interface type. Based on this selection the DPA Classifier
	 * decides which header manipulations are needed to perform forwarding.
	 */
	enum dpa_cls_hm_out_if_type			out_if_type;

	union {
		/* Necessary parameters for an Ethernet output interface */
		struct dpa_cls_hm_fwd_l2_param		eth;

		/* Necessary parameters for a PPPoE output interface */
		struct dpa_cls_hm_fwd_pppoe_param	pppoe;

		/* Necessary parameters for a PPP output interface */
		struct dpa_cls_hm_fwd_ppp_param		ppp;
	};

	/* Parameters related to optional IP fragmentation */
	struct dpa_cls_hm_ip_frag_params		ip_frag_params;

	/*
	 * Handle to the low level driver PCD to use when creating the header
	 * manipulation object.
	 */
	void						*fm_pcd;

	/*
	 * Request re-parsing of the packet headers after this forwarding
	 * header manipulation.
	 */
	bool						reparse;
};

/* Types of the remove header manipulation operations */
enum dpa_cls_hm_remove_type {
	DPA_CLS_HM_REMOVE_ETHERNET,	/* removes ETH and all QTags */
	DPA_CLS_HM_REMOVE_PPPoE,	/* removes ETH, all QTags and PPPoE */
	DPA_CLS_HM_REMOVE_PPP,
	DPA_CLS_HM_REMOVE_CUSTOM,	/* General remove */
	DPA_CLS_HM_REMOVE_LAST_ENTRY
};

/*
 * Flag values indicating which attributes of the remove header manipulation
 * to modify
 */
enum dpa_cls_hm_remove_modify_flags {
	DPA_CLS_HM_RM_MOD_TYPE		= 0x01,
	DPA_CLS_HM_RM_MOD_CUSTOM_OFFSET	= 0x02,
	DPA_CLS_HM_RM_MOD_CUSTOM_SIZE	= 0x04
};

/* General (custom) remove header manipulation parameters */
struct dpa_cls_hm_custom_rm_params {
	/*
	 * Offset in bytes, relative to the start of the packet, to start
	 * removing data from
	 */
	uint8_t						offset;

	/* The size in bytes of the section to remove */
	uint8_t						size;
};

/* Ingress remove header manipulation low level driver resources */
struct dpa_cls_hm_remove_resources {
	/*
	 * Handle to either a header removal node or a protocol specific header
	 * removal node (for Ethernet and all VLAN tags). This is a FMan driver
	 * header manipulation node handle and it is mandatory for the import
	 * to succeed.
	 */
	void	*remove_node;
};

/* Ingress (remove) header manipulation parameters */
struct dpa_cls_hm_remove_params {

	/*
	 * Selects the type of the remove header manipulation operation  to
	 * perform. Protocol specific header removals don't need any further
	 * parameters.
	 */
	enum dpa_cls_hm_remove_type			type;

	/*
	 * Parameters for the custom remove header manipulation. If [type] is
	 * anything else than "custom remove", these parameters are ignored
	 */
	struct dpa_cls_hm_custom_rm_params		custom;

	/*
	 * Handle to the low level driver PCD to use when creating the header
	 * manipulation object.
	 */
	void						*fm_pcd;

	/*
	 * Request re-parsing of the packet headers after this header remove.
	 */
	bool						reparse;
};

/* Types of insert header manipulation operations */
enum dpa_cls_hm_insert_type {
	DPA_CLS_HM_INSERT_ETHERNET,	/* Insert Ethernet + QTags */
	DPA_CLS_HM_INSERT_PPPoE,	/* Insert PPPoE, ETH and QTags */
	DPA_CLS_HM_INSERT_PPP,
	DPA_CLS_HM_INSERT_CUSTOM,	/* General insert */
	DPA_CLS_HM_INSERT_LAST_ENTRY
};

/*
 * Flag values indicating which attributes of the insert header manipulation
 * to modify
 */
enum dpa_cls_hm_insert_modify_flags {
	/* Ethernet and PPPoE insert group */
	DPA_CLS_HM_INS_MOD_ETH_HEADER		= 0x01,
	DPA_CLS_HM_INS_MOD_QTAGS		= 0x02,
	DPA_CLS_HM_INS_MOD_PPPoE_HEADER		= 0x04,

	/* PPP insert group */
	DPA_CLS_HM_INS_MOD_PPP_PID		= 0x08,

	/* Custom insert group */
	DPA_CLS_HM_INS_MOD_CUSTOM_OFFSET	= 0x10,
	DPA_CLS_HM_INS_MOD_CUSTOM_DATA		= 0x20
};

/* General insert parameters */
struct dpa_cls_hm_custom_ins_params {
	/*
	 * Offset in bytes relative to the start of the frame to insert new
	 * header at.
	 */
	uint8_t		offset;

	/* The size in bytes of the header to insert */
	uint8_t		size;

	/*
	 * The data buffer containing the header to insert. This buffer must be
	 * at least [size] bytes long
	 */
	const uint8_t	*data;
};

/* Egress insert header manipulation low level driver resources */
struct dpa_cls_hm_insert_resources {
	/*
	 * Handle to either an internal header insert or an internal protocol
	 * specific header insert node. This is a FMan driver header
	 * manipulation node handle and it is mandatory for the import to
	 * succeed.
	 */
	void	*insert_node;
};

/* Ethernet header insert params */
struct dpa_cls_hm_eth_ins_params {
	/* Ethernet header to insert */
	struct ethhdr				eth_header;

	/*
	 * Number of VLAN tags to insert. If zero, no VLAN tags will be inserted
	 * in the packet
	 */
	unsigned int				num_tags;

	/*
	 * Relevant only if [num_tags] is not zero. Contains an array with the
	 * data of the VLAN QTags to insert
	 */
	struct vlan_header			qtag[DPA_CLS_HM_MAX_VLANs];
};

/* PPPoE header insert params */
struct dpa_cls_hm_pppoe_ins_params {
	/*
	 * Parameters of the Ethernet header to insert together with PPPoE
	 * header
	 */
	struct dpa_cls_hm_eth_ins_params	eth;

	/* PPPoE header to insert */
	struct pppoe_header			pppoe_header;
};

/* Ethernet header insert params */
struct dpa_cls_hm_insert_params {
	/* Specifies the type of insert header manipulation */
	enum dpa_cls_hm_insert_type			type;

	union {
		/*
		 * Ethernet header insert parameters if type is "insert
		 * Ethernet"
		 */
		struct dpa_cls_hm_eth_ins_params	eth;

		/* PPPoE header insert parameters if type is "insert PPPoE" */
		struct dpa_cls_hm_pppoe_ins_params	pppoe;

		/*
		 * PPP PID value to use in the PPP header if type is "insert
		 * PPP"
		 */
		uint16_t				ppp_pid;

		/*
		 * Custom insert header manipulation operation parameters.
		 * These are relevant only if a custom insert header
		 * manipulation operation is selected.
		 */
		struct dpa_cls_hm_custom_ins_params	custom;
	};

	/*
	 * Handle to the low level driver PCD to use when creating the header
	 * manipulation object.
	 */
	void						*fm_pcd;

	/*
	 * Request re-parsing of the packet headers after this header insert.
	 */
	bool						reparse;
};

/* Update header manipulation op flags */
enum dpa_cls_hm_update_op_flags {
	DPA_CLS_HM_UPDATE_NONE			= 0,

	DPA_CLS_HM_UPDATE_IPv4_UPDATE		= 0x01,
	DPA_CLS_HM_UPDATE_IPv6_UPDATE		= 0x02,
	DPA_CLS_HM_UPDATE_UDP_TCP_UPDATE	= 0x04,

	DPA_CLS_HM_REPLACE_IPv4_BY_IPv6		= 0x08,
	DPA_CLS_HM_REPLACE_IPv6_BY_IPv4		= 0x10
};

/* Update header manipulation field flags */
enum dpa_cls_hm_l3_field_flags {
	DPA_CLS_HM_IP_UPDATE_IPSA		= 0x01,
	DPA_CLS_HM_IP_UPDATE_IPDA		= 0x02,
	DPA_CLS_HM_IP_UPDATE_TOS_TC		= 0x04,
	DPA_CLS_HM_IP_UPDATE_ID			= 0x08,
	DPA_CLS_HM_IP_UPDATE_TTL_HOPL_DECREMENT	= 0x10
};

/* L4 header update field flags */
enum dpa_cls_hm_l4_field_flags {
	DPA_CLS_HM_L4_UPDATE_SPORT		= 0x01,
	DPA_CLS_HM_L4_UPDATE_DPORT		= 0x02,
	DPA_CLS_HM_L4_UPDATE_CALCULATE_CKSUM	= 0x04
};

/*
 * Flag values indicating which attributes of the update header manipulation
 * to modify
 */
enum dpa_cls_hm_update_modify_flags {
	DPA_CLS_HM_UPDATE_MOD_IPHDR		= 0x0001,

	/* L3 protocol flags group */
	DPA_CLS_HM_UPDATE_MOD_SIP		= 0x0002,
	DPA_CLS_HM_UPDATE_MOD_DIP		= 0x0004,
	DPA_CLS_HM_UPDATE_MOD_TOS_TC		= 0x0008,
	DPA_CLS_HM_UPDATE_MOD_IP_ID		= 0x0010,
	DPA_CLS_HM_UPDATE_MOD_L3_FLAGS		= 0x0020,

	/* L4 protocol flags group */
	DPA_CLS_HM_UPDATE_MOD_SPORT		= 0x0040,
	DPA_CLS_HM_UPDATE_MOD_DPORT		= 0x0080,
	DPA_CLS_HM_UPDATE_MOD_L4_FLAGS		= 0x0100,

	DPA_CLS_HM_UPDATE_MOD_IP_FRAG_MTU	= 0x0200,
	DPA_CLS_HM_UPDATE_MOD_IP_FRAG_SCRATCH_BPID = 0x0400,
	DPA_CLS_HM_UPDATE_MOD_IP_FRAG_DF_ACTION = 0x0800
};

/* L3 protocols field update parameters */
struct dpa_cls_hm_l3_update_params {
	/* New source IP address */
	struct dpa_offload_ip_address		ipsa;

	/* New destination IP address */
	struct dpa_offload_ip_address		ipda;

	/* New TOS (for IPv4) or Traffic Class (for IPv6) */
	uint8_t					tos_tc;

	/*
	 * Initial IPv4 ID. This is used only if op_flags selected IPv4 update
	 */
	uint16_t				initial_id;

	/*
	 * A combination of flags designating the header fields to replace. The
	 * available options are defined in the dpa_cls_hm_l3_field_flags enum
	 */
	int					field_flags;
};

/* L4 protocols field update parameters */
struct dpa_cls_hm_l4_update_params {
	uint16_t	sport; /* new L4 source port value */
	uint16_t	dport; /* new L4 destination port value */

	/*
	 * A combination of flags designating the header fields to replace. The
	 * available options are defined in the dpa_cls_hm_l4_field_flags enum
	 */
	int		field_flags;
};

/* Egress update header manipulation low level driver resources */
struct dpa_cls_hm_update_resources {
	/*
	 * Handle to a header manipulation node with different header
	 * manipulations enabled, depending on the options selected in the
	 * parameters: local IPv4/IPv6 update header manipulation, a local
	 * TCP/UDP update header manipulation and an internal IP header replace.
	 * This is a FMan driver header manipulation node handle and it is
	 * optional (can be NULL in case no L3 or L4 field updates or header
	 * replace features are enabled for this flow)
	 */
	void	*update_node;

	/*
	 * Handle to the IP fragmentation node. This is a FMan driver header
	 * manipulation node handle and it is optional (can be NULL in case no
	 * IP fragmentation is enabled for this flow).
	 */
	void	*ip_frag_node;
};

/* Egress update header manipulation parameters */
struct dpa_cls_hm_update_params {
	/*
	 * Flags defining the header manipulation operations to perform. They
	 * are a combination of the flags defined in the
	 * dpa_cls_hm_update_op_flags enum.
	 */
	int						op_flags;

	union {
		/*
		 * IPv4 header data. This header is used for IPv6 to IPv4 header
		 * replace.
		 */
		struct ipv4_header			new_ipv4_hdr;

		/*
		 * IPv6 header data. This header is used for IPv4 to IPv6
		 * header replace.
		 */
		struct ipv6_header			new_ipv6_hdr;
	} replace;

	union {
		/*
		 * L3 protocol field values. This data is used for L3 protocol
		 * header updates
		 */
		struct dpa_cls_hm_l3_update_params	l3;

		/*
		 * L4 protocol field values. This data is used for L4 protocol
		 * header updates.
		 */
		struct dpa_cls_hm_l4_update_params	l4;
	} update;

	/*
	 * IP fragmentation parameters. This is an optional operation and can
	 * be disabled.
	 */
	struct dpa_cls_hm_ip_frag_params		ip_frag_params;

	/*
	 * Handle to the low level driver PCD to use when creating the header
	 * manipulation object.
	 */
	void						*fm_pcd;

	/*
	 * Request re-parsing of the packet headers after this header update.
	 */
	bool						reparse;
};

/* VLAN specific header manipulation operation types */
enum dpa_cls_hm_vlan_type {
	DPA_CLS_HM_VLAN_INGRESS,
	DPA_CLS_HM_VLAN_EGRESS,
	DPA_CLS_HM_VLAN_LAST_ENTRY
};

/* Types of supported VLAN update operations */
enum dpa_cls_hm_vlan_update_type {
	DPA_CLS_HM_VLAN_UPDATE_NONE,
	DPA_CLS_HM_VLAN_UPDATE_VPri,	/* manual VPri update */
	DPA_CLS_HM_VLAN_UPDATE_VPri_BY_DSCP,
	DPA_CLS_HM_VLAN_UPDATE_LAST_ENTRY
};

/* VLAN QTag identifier */
enum dpa_cls_hm_vlan_count {
	DPA_CLS_HM_VLAN_CNT_NONE,
	DPA_CLS_HM_VLAN_CNT_1QTAG,	/* outer QTag */
	DPA_CLS_HM_VLAN_CNT_2QTAGS,	/* outer most 2 QTags */
	DPA_CLS_HM_VLAN_CNT_3QTAGS,	/* outer most 3 QTags */
	DPA_CLS_HM_VLAN_CNT_4QTAGS,	/* outer most 4 QTags */
	DPA_CLS_HM_VLAN_CNT_5QTAGS,	/* outer most 5 QTags */
	DPA_CLS_HM_VLAN_CNT_6QTAGS,	/* outer most 6 QTags */
	DPA_CLS_HM_VLAN_CNT_ALL_QTAGS,
	DPA_CLS_HM_VLAN_CNT_LAST_ENTRY
};

/*
 * Flag values indicating which attributes of the VLAN specific header
 * manipulation to modify
 */
enum dpa_cls_hm_vlan_modify_flags {
	/* This flag cannot be combined with any other flags */
	DPA_CLS_HM_VLAN_MOD_INGRESS_NUM_QTAGS		= 0x01,

	DPA_CLS_HM_VLAN_MOD_EGRESS_QTAGS		= 0x02,
	DPA_CLS_HM_VLAN_MOD_EGRESS_UPDATE_OP		= 0x04,
	DPA_CLS_HM_VLAN_MOD_EGRESS_VPRI			= 0x08,
	DPA_CLS_HM_VLAN_MOD_EGRESS_DSCP_TO_VPRI_ARRAY	= 0x10
};

/* Ingress VLAN specific header manipulation parameters */
struct dpa_cls_hm_ingress_vlan_params {
	/* Number of VLAN tags to remove */
	enum dpa_cls_hm_vlan_count		num_tags;
};

/* Egress VLAN specific header manipulation parameters */
struct dpa_cls_hm_egress_vlan_params {
	enum dpa_cls_hm_vlan_update_type	update_op;

	/*
	 * Number of VLAN tags to insert. If zero, no VLAN tags will be
	 * inserted in the packet.
	 */
	unsigned int				num_tags;

	/*
	 * Relevant only if [num_tags] is not zero. Contains an array with the
	 * data of the VLAN tags to insert.
	 */
	struct vlan_header			qtag[DPA_CLS_HM_MAX_VLANs];

	union {
		/*
		 * New VPri field value if [update_flag] selects manual VPri
		 * update.
		 */
		uint8_t vpri;

		/*
		 * DSCP-to-VPri mapping table to use for VPri field update if
		 * [update_flag] selects VPri update by mapping to DSCP.
		 */
		uint8_t dscp_to_vpri[DPA_CLS_HM_DSCP_TO_VPRI_TABLE_SIZE];

	} update;
};

/* VLAN specific header manipulation low level resources */
struct dpa_cls_hm_vlan_resources {
	/*
	 * Handle to a header manipulation node with different operations
	 * depending on the selected type of VLAN specific header manipulation.
	 *
	 * In case of VLAN ingress header manipulation this is a VLAN protocol
	 * specific removal node.
	 *
	 * In case of VLAN egress header manipulation this is a header
	 * manipulation node which may combine an internal header insert (in
	 * case there are VLANs to insert) with a protocol specific VLAN update
	 * operation.
	 *
	 * This is a FMan driver header manipulation node handle and it is
	 * mandatory for the import to succeed.
	 */
	void	*vlan_node;
};

/* VLAN specific header manipulation parameters */
struct dpa_cls_hm_vlan_params {
	/* Selects the type of the VLAN specific header manipulation */
	enum dpa_cls_hm_vlan_type			type;

	union {
		/* Parameters for ingress VLAN header manipulations */
		struct dpa_cls_hm_ingress_vlan_params	ingress;

		/* Parameters for egress VLAN header manipulations */
		struct dpa_cls_hm_egress_vlan_params	egress;
	};

	/*
	 * Handle to the low level driver PCD to use when creating the header
	 * manipulation object.
	 */
	void						*fm_pcd;

	/*
	 * Request re-parsing of the packet headers after this VLAN header
	 * update.
	 */
	bool						reparse;
};

/* MPLS specific header manipulation operation types */
enum dpa_cls_hm_mpls_type {
	DPA_CLS_HM_MPLS_INSERT_LABELS,
	DPA_CLS_HM_MPLS_REMOVE_ALL_LABELS,
	DPA_CLS_HM_MPLS_LAST_ENTRY
};

/*
 * Flag values indicating which attributes of the MPLS specific header
 * manipulation to modify
 */
enum dpa_cls_hm_mpls_modify_flags {
	DPA_CLS_HM_MPLS_MOD_NUM_LABELS	= 0x01,
	DPA_CLS_HM_MPLS_MOD_HDR_ARRAY	= 0x02,
};

/* MPLS specific header manipulation low level driver resources */
struct dpa_cls_hm_mpls_resources {
	/*
	 * Handle to the protocol specific header insert (MPLS) or to the
	 * protocol specific header removal (MPLS) node. This is a FMan driver
	 * header manipulation node handle and it is mandatory for the import
	 * to succeed.
	 */
	void	*ins_rm_node;
};

/* MPLS specific header manipulation parameters */
struct dpa_cls_hm_mpls_params {
	/* Specifies the type of header manipulation */
	enum dpa_cls_hm_mpls_type	type;

	/*
	 * Stores the MPLS labels to insert if the operation type is "insert
	 * MPLS labels"
	 */
	struct mpls_header		mpls_hdr[DPA_CLS_HM_MAX_MPLS_LABELS];

	/*
	 * Number of MPLS labels to insert. This is relevant only if the
	 * operation type is "insert MPLS labels" */
	unsigned int			num_labels;

	/*
	 * Handle to the low level driver PCD to use when creating the header
	 * manipulation object.
	 */
	void				*fm_pcd;

	/*
	 * Request re-parsing of the packet headers after this MPLS header
	 * update.
	 */
	bool				reparse;
};


/*
 * Creates or imports a NAT type header manipulation object. If the function is
 * successful it returns at the [hmd] location the descriptor of the created
 * header manipulation object.
 *
 * If the [res] parameter is provided, the function will import the low level
 * driver resources specified therein rather than create them. In this case the
 * [fm_pcd] handle in the parameters structure is not used and can be provided
 * as NULL. When working in this mode the function doesn't allocate MURAM.
 */
int dpa_classif_set_nat_hm(const struct dpa_cls_hm_nat_params	*nat_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_nat_resources	*res);

/*
 * Modify the parameters of an existing NAT header manipulation.
 *
 * [modify_flags] is a combination of flags indicating which header manipulation
 * attributes to modify (and hence indicating which of the attributes in the
 * [new_nat_params] data structure are valid). Select the flag values from the
 * dpa_cls_hm_nat_modify_flags enum and combine them using the "or" logical
 * operand.
 */
int dpa_classif_modify_nat_hm(int hmd,
	const struct dpa_cls_hm_nat_params *new_nat_params, int modify_flags);

/*
 * Creates or imports a forwarding type header manipulation object. DPA
 * Classifier takes into account an Ethernet/IP frame to start with and,
 * depending on the selection of output interface type, it decides what header
 * manipulations are necessary.
 *
 * If the [res] parameter is provided, the function will import the low level
 * driver resources specified therein rather than create them. In this case the
 * [fm_pcd] handle in the parameters structure is not used and can be provided
 * as NULL. When working in this mode the function doesn't allocate MURAM.
 */
int dpa_classif_set_fwd_hm(const struct dpa_cls_hm_fwd_params	*fwd_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_fwd_resources	*res);

/*
 * Modify the parameters of an existing forwarding type header manipulation.
 *
 * [modify_flags] is a combination of flags indicating which header manipulation
 * attributes to modify (and hence indicating which of the attributes in the
 * [new_fwd_params] data structure are valid). Select the flag values from the
 * dpa_cls_hm_fwd_modify_flags enum and combine them using the "or" logical
 * operand.
 */
int dpa_classif_modify_fwd_hm(int hmd,
	const struct dpa_cls_hm_fwd_params *new_fwd_params, int modify_flags);

/* Creates or imports a remove type header manipulation object.
 *
 * If the [res] parameter is provided, the function will import the low level
 * driver resources specified therein rather than create them. In this case the
 * [fm_pcd] handle in the parameters structure is not used and can be provided
 * as NULL. When working in this mode the function doesn't allocate MURAM.
 */
int dpa_classif_set_remove_hm(const struct dpa_cls_hm_remove_params
	*remove_params, int next_hmd, int *hmd, bool chain_head,
	const struct dpa_cls_hm_remove_resources *res);

/*
 * Modify the parameters of an existing remove type header manipulation.
 *
 * [modify_flags] is a combination of flags indicating which header manipulation
 * attributes to modify (and hence indicating which of the attributes in the
 * [new_remove_params] data structure are valid). Select the flag values from
 * the dpa_cls_hm_remove_modify_flags enum and combine them using the "or"
 * logical operand.
 */
int dpa_classif_modify_remove_hm(int hmd,
	const struct dpa_cls_hm_remove_params *new_remove_params,
	int modify_flags);

/*
 * Creates or imports an insert type header manipulation object.
 *
 * If the [res] parameter is provided, the function will import the low level
 * driver resources specified therein rather than create them. In this case the
 * [fm_pcd] handle in the parameters structure is not used and can be provided
 * as NULL. When working in this mode the function doesn't allocate MURAM.
 */
int dpa_classif_set_insert_hm(const struct dpa_cls_hm_insert_params
	*insert_params, int next_hmd, int *hmd, bool chain_head,
	const struct dpa_cls_hm_insert_resources *res);

/*
 * Modify the parameters of an existing insert header manipulation.
 *
 * [modify_flags] is a combination of flags indicating which header manipulation
 * attributes to modify (and hence indicating which of the attributes in the
 * [new_insert_params] data structure are valid). Select the flag values from
 * the dpa_cls_hm_insert_modify_flags enum and combine them using the "or"
 * logical operand.
 */
int dpa_classif_modify_insert_hm(int hmd,
	const struct dpa_cls_hm_insert_params *new_insert_params,
	int modify_flags);

/*
 * Creates or imports an update type header manipulation object.
 *
 * If the [res] parameter is provided, the function will import the low level
 * driver resources specified therein rather than create them. In this case the
 * [fm_pcd] handle in the parameters structure is not used and can be provided
 * as NULL. When working in this mode the function doesn't allocate MURAM.
 */
int dpa_classif_set_update_hm(const struct dpa_cls_hm_update_params
	*update_params, int next_hmd, int *hmd, bool chain_head,
	const struct dpa_cls_hm_update_resources *res);

/*
 * Modify the parameters of an existing update header manipulation.
 *
 * [modify_flags] is a combination of flags indicating which header manipulation
 * attributes to modify (and hence indicating which of the attributes in the
 * [new_update_params] data structure are valid). Select the flag values from
 * the dpa_cls_hm_update_modify_flags enum and combine them using the "or"
 * logical operand.
 */
int dpa_classif_modify_update_hm(int hmd,
	const struct dpa_cls_hm_update_params *new_update_params,
	int modify_flags);

/*
 * Creates or imports a VLAN specific header manipulation (either ingress or
 * egress) object.
 *
 * If the [res] parameter is provided, the function will import the low level
 * driver resources specified therein rather than create them. In this case the
 * [fm_pcd] handle in the parameters structure is not used and can be provided
 * as NULL. When working in this mode the function doesn't allocate MURAM.
 */
int dpa_classif_set_vlan_hm(const struct dpa_cls_hm_vlan_params	*vlan_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_vlan_resources	*res);

/*
 * Modify the parameters of an existing VLAN specific header manipulation.
 *
 * [modify_flags] is a combination of flags indicating which header manipulation
 * attributes to modify (and hence indicating which of the attributes in the
 * [new_vlan_params] data structure are valid). Select the flag values from the
 * dpa_cls_hm_vlan_modify_flags enum and combine them using the "or" logical
 * operand.
 */
int dpa_classif_modify_vlan_hm(int hmd,
	const struct dpa_cls_hm_vlan_params *new_vlan_params, int modify_flags);

/*
 * Creates or imports a MPLS specific header manipulation object.
 *
 * If the [res] parameter is provided, the function will import the low level
 * driver resources specified therein rather than create them. In this case the
 * [fm_pcd] handle in the parameters structure is not used and can be provided
 * as NULL. When working in this mode the function doesn't allocate MURAM.
 */
int dpa_classif_set_mpls_hm(const struct dpa_cls_hm_mpls_params	*mpls_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_mpls_resources	*res);

/*
 * Modify the parameters of an existing MPLS specific header manipulation.
 *
 * [modify_flags] is a combination of flags indicating which header manipulation
 * attributes to modify (and hence indicating which of the attributes in the
 * [new_mpls_params] data structure are valid). Select the flag values from the
 * dpa_cls_hm_mpls_modify_flags enum and combine them using the "or" logical
 * operand.
 */
int dpa_classif_modify_mpls_hm(int hmd,
	const struct dpa_cls_hm_mpls_params *new_mpls_params, int modify_flags);

/*
 * Releases a header manipulation object and frees up all related resources
 * allocated for it. The header manipulation operations must be removed in the
 * reverse order they were created in (i.e. starting with the header
 * manipulation chain head and working towards the tail).
 */
int dpa_classif_free_hm(int hmd);


/*
 * Multicast API
 */

/*
 * Multicast group parameters
 */
struct dpa_cls_mcast_group_params {
	/*
	 * Maximum number of members in group
	 */
	uint8_t		max_members;

	/*
	 * Handle of the FM PCD that owns the Cc node that will
	 * point to the group
	 */
	void		*fm_pcd;

	/*
	 * Member parameters. A group must have at least
	 * one member
	 */
	struct		dpa_cls_tbl_enq_action_desc first_member_params;

	/*
	 * Number of members that already exist in the imported group
	 */
	unsigned int prefilled_members;
};

/* Multicast group external resource */
struct dpa_cls_mcast_group_resources {
	/*
	 * Multicast group handle used when importing an external group node
	 */
	void	*group_node;
};

/*
 * Creates a multicast group with one member
 */
int dpa_classif_mcast_create_group(
		const struct dpa_cls_mcast_group_params *group_params,
		int *grpd,
		const struct dpa_cls_mcast_group_resources *res);

/*
 * Adds a new member to a multicast group
 */
int dpa_classif_mcast_add_member(int grpd,
		const struct dpa_cls_tbl_enq_action_desc *member_params,
		int *md);

/*
 * Removes a member from a multicast group
 */
int dpa_classif_mcast_remove_member(int grpd, int md);

/*
 * Removes an existing group
 */
int dpa_classif_mcast_free_group(int grpd);


#endif /* __FSL_DPA_CLASSIFIER_H */
