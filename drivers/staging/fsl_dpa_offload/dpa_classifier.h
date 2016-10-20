
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
 * Internal DPA Classifier Application Programming Interface
 */

#ifndef __DPA_CLASSIFIER_H
#define __DPA_CLASSIFIER_H


/* DPA offloading layer includes */
#include "linux/fsl_dpa_classifier.h"

/* FMD includes */
#include "fm_pcd_ext.h"


/* API functions, definitions and enums */

/* Internal API functions, definitions and enums */


/*
 * The maximum possible size of a shadow table. A DPA Classifier
 * table can have multiple shadow tables depending on its type
 * and size.
 */
#define DPA_CLS_TBL_MAXSHADOWTABLESIZE				256

/*
 * Max number of low level header manip nodes per header manipulation
 * operation.
 */
#define DPA_CLS_HM_MAX_NODES_PER_OP				3

/* Available flags for a header manipulation node: */

/* HM node is external (i.e. not created by DPA Classifier) */
#define DPA_CLS_HM_NODE_EXTERNAL				0x0
/* HM node is internal (i.e. created & managed by DPA Classifier) */
#define DPA_CLS_HM_NODE_INTERNAL				0x1

/* Available flags for an index management entry: */

/* Indication that the entry is valid */
#define DPA_CLS_TBL_ENTRY_VALID					0x1

#define unused(x)						(x = x)


#if (DPAA_VERSION >= 11)
#define DPA_CLS_MCAST_MAX_NUM_OF_ENTRIES			64
#endif
/* Index management entry */
struct dpa_cls_tbl_entry {

	/* Entry flags */
	unsigned			flags;

	/* Internal Cc node index where this entry resides */
	unsigned int			int_cc_node_index;

	/* The index of this entry in the Cc node table */
	uint8_t				entry_index;

	/* The priority value of this entry in the table */
	int				priority;

	/* Header manipulation descriptor associated with this entry (if any) */
	int				hmd;

	/*
	 * Pointer to the shadow entry (if there is one) associated
	 * with this index management entry
	 */
	struct list_head		*shadow_entry;

	/*
	 * List node which allows linking this entry in the index
	 * management list.
	 */
	struct list_head		list_node;
};

/*
 * Shadow Table Entry (for all types of tables except indexed
 * tables)
 */
struct dpa_cls_tbl_shadow_entry {

	struct dpa_offload_lookup_key	key;		/* Lookup key info */

	struct dpa_cls_tbl_action	action;		/* Action info */

	/* Id of this entry (helps find the index management entry faster) */
	int				entry_id;

	/* Pointers to other shadow entries in the current set (bucket) */
	struct list_head		list_node;
};

/* Shadow Table Entry for indexed tables */
struct dpa_cls_tbl_shadow_entry_indexed {

	struct dpa_cls_tbl_action	action;		/* Action info */

	/* Pointers to other shadow entries in the current set (bucket) */
	struct list_head		list_node;
};

/* Shadow Table */
struct dpa_cls_tbl_shadow_table {

	/* Shadow table sets (buckets) */
	struct list_head		*shadow_entry;

	/* The size of the shadow table in number of sets (buckets) */
	unsigned int			size;
};

/* Internal FMan Cc Node Management Info */
struct dpa_cls_tbl_cc_node_info {

	/* Low level driver (FMD) handle of the Cc node */
	void				*cc_node;

	/* The size of this Cc node's lookup table */
	unsigned int			table_size;

	/*
	 * Number of entries in the lookup table that are
	 * currently in use
	 */
	unsigned int			used;
};

/* DPA Classifier Table Control Data Structure */
struct dpa_cls_table {

	/* Array of shadow tables. NULL if there are none. */
	struct dpa_cls_tbl_shadow_table		*shadow_table;

	/*
	 * Array of internally managed FMan Cc nodes. NULL
	 * if there are none beside the initial Cc node (provided
	 * by the application).
	 */
	struct dpa_cls_tbl_cc_node_info		*int_cc_node;

	/*
	 * Number of internally managed FMan Cc nodes in the
	 * int_cc_node array
	 */
	unsigned int				int_cc_nodes_count;

	/*
	 * The mask that is used on the CRC64 HASH result to find
	 * the HASH set for DPA Classifier HASH tables. This is of
	 * no use for types of DPA Classifier tables other than
	 * HASH.
	 */
	uint64_t				hash_mask;

	/* Index management array. */
	struct dpa_cls_tbl_entry		*entry;

	/* Number of entries in the index management array. */
	unsigned int				entries_cnt;

	/*
	 * Linked list storing the index management entries
	 * which are in use.
	 */
	struct list_head			entry_list;

	/* (Initial) parameters of the DPA Classifier table. */
	struct dpa_cls_tbl_params		params;

	/* Table miss action. */
	struct dpa_cls_tbl_action		miss_action;

	/* Access control object for this table to avoid race conditions. */
	struct mutex				access;
};

/* Definition of a generic descriptor table */
struct dpa_cls_descriptor_table {
	/* Total number of descriptors in the table */
	unsigned int	num_descriptors;

	/* Number of currently used descriptors */
	unsigned int	used_descriptors;

	/* Array of descriptors */
	void		**object;

	/*
	 * Access control object for this descriptor table to avoid race
	 * conditions
	 */
	struct mutex	*access;
};

struct dpa_cls_hm_node {
	/* Handle to the FMan header manip node */
	void			*node;

	/* The flags indicate certain properties of the current nodes */
	unsigned		flags;

	/* Used to keep count of the references to this header manip node */
	unsigned		ref;

	/* Stores the low level driver parameters of this header manip node */
	t_FmPcdManipParams	params;

	/* Links to other header manip nodes in the current chain */
	struct list_head	list_node;
};

enum dpa_cls_hm_node_type {
	DPA_CLS_HM_NODE_IPv4_HDR_UPDATE,
	DPA_CLS_HM_NODE_IPv6_HDR_UPDATE,
	DPA_CLS_HM_NODE_TCPUDP_HDR_UPDATE,
	DPA_CLS_HM_NODE_HDR_REPLACE_IPv4_BY_IPv6,
	DPA_CLS_HM_NODE_HDR_REPLACE_IPv6_BY_IPv4,
	DPA_CLS_HM_NODE_LAST_ENTRY
};

enum dpa_cls_hm_type {
	DPA_CLS_HM_TYPE_NAT,
	DPA_CLS_HM_TYPE_FORWARDING,
	DPA_CLS_HM_TYPE_REMOVE,
	DPA_CLS_HM_TYPE_INSERT,
	DPA_CLS_HM_TYPE_UPDATE,
	DPA_CLS_HM_TYPE_VLAN,
	DPA_CLS_HM_TYPE_MPLS,
	DPA_CLS_HM_TYPE_STATIC,
	DPA_CLS_HM_LAST_ENTRY
};

struct dpa_cls_hm {
	/* Type of this high level HM operation */
	enum dpa_cls_hm_type				type;

	/* Indicates whether this op is the chain head or not */
	bool						chain_head;

	union {
		/* Stores parameters for a NAT type header manipulation op */
		struct dpa_cls_hm_nat_params		nat_params;

		/*
		 * Stores parameters for a Forwarding type header manipulation
		 * op
		 */
		struct dpa_cls_hm_fwd_params		fwd_params;

		/* Stores parameters for a remove header manipulation op */
		struct dpa_cls_hm_remove_params		remove_params;

		/* Stores parameters for an insert header manipulation op */
		struct dpa_cls_hm_insert_params		insert_params;

		/* Stores parameters for an update header manipulation op */
		struct dpa_cls_hm_update_params		update_params;

		/*
		 * Stores parameters for a VLAN specific header manipulation
		 * op
		 */
		struct dpa_cls_hm_vlan_params		vlan_params;

		/*
		 * Stores parameters for a MPLS specific header manipulation
		 * op
		 */
		struct dpa_cls_hm_mpls_params		mpls_params;
	};

	/*
	 * Holds references to the low level driver manip nodes used to
	 * implement the current high level header manipulation op
	 */
	struct dpa_cls_hm_node		*hm_node[DPA_CLS_HM_MAX_NODES_PER_OP];

	/* Specifies the number of used items in the [hm_node] array */
	unsigned int			num_nodes;

	/* Pointer to the low level driver HM manip node chain */
	struct list_head		*hm_chain;

	/*
	 * Links to other high level header manipulation ops in the current
	 * chain
	 */
	struct list_head		list_node;

	/*
	 * Access control object for this header manipulation op to avoid race
	 * conditions.
	 */
	struct mutex			access;
};

#if (DPAA_VERSION >= 11)

struct members {
	bool used;
	int hmd;
};

struct dpa_cls_mcast_group {
	/*
	 * Group descriptor
	 */
	int		grpd;

	/*
	 * Group parameters
	 */
	struct		dpa_cls_mcast_group_params group_params;

	/*
	 * Current number of members
	 */
	unsigned int	num_members;

	/*
	 * Members' ids used in the group
	*/
	struct members		*entries;

	/*
	 * Members' id array.
	 */
	int		*member_ids;

	/*
	 * Index of the last member in group
	 */
	int		last_index;

	/*
	 * Group handle
	 */
	void		*group;

	/* Access control object for the group to avoid race conditions. */
	struct mutex				access;
};
#endif /* (DPAA_VERSION >= 11) */

#ifdef __DPA_CLASSIFIER_C
/*
 * Allocates the array of internally managed Cc nodes based on
 * their number. The number of internally managed Cc nodes must
 * be set in the table control structure before calling this
 * function.
 */
static int	alloc_table_management(struct dpa_cls_table *cls_table);

/*
 * Releases resources related to the array of internally managed
 * Cc nodes.
 */
static void	free_table_management(struct dpa_cls_table *cls_table);

/* Initialize an indexed table. */
static int	table_init_indexed(struct dpa_cls_table *cls_table);

/* Initialize a hash table. */
static int	table_init_hash(struct dpa_cls_table *cls_table);

/* Initialize an exact match table. */
static int	table_init_exact_match(struct dpa_cls_table *cls_table);

/* Clean up after an indexed table */
static void table_cleanup_indexed(struct dpa_cls_table *cls_table);

/*
 * Runs a verification of the table parameters against certain
 * ranges and limitations.
 */
static int	verify_table_params(const struct dpa_cls_tbl_params *params);

static int	flush_table(struct dpa_cls_table *ptable);

static int	table_modify_entry_by_ref(struct dpa_cls_table	*ptable,
		int						entry_id,
		const struct dpa_cls_tbl_entry_mod_params	*mod_params);

static int	table_delete_entry_by_ref(struct dpa_cls_table	*ptable,
				int				entry_id);

static int	table_get_entry_stats_by_ref(struct dpa_cls_table *ptable,
				int				entry_id,
				struct dpa_cls_tbl_entry_stats	*stats);

/*
 * Finds a specified entry in the shadow tables. The entry is
 * identified by its lookup key.
 */
static struct list_head *find_shadow_entry(const struct dpa_cls_table
			*cls_table, const struct dpa_offload_lookup_key *key);

/* Add a new entry in an exact match table. */
static int table_insert_entry_exact_match(struct dpa_cls_table	*cls_table,
			const struct dpa_offload_lookup_key	*key,
			const struct dpa_cls_tbl_action		*action,
			int					priority,
			int					*entry_id);

/* Add a new entry in a hash table. */
static int table_insert_entry_hash(struct dpa_cls_table		*cls_table,
			const struct dpa_offload_lookup_key	*key,
			const struct dpa_cls_tbl_action		*action,
			int					*entry_id);

/*
 * Translates action parameters into next engine parameters for use with the
 * low level driver (FMD).
 */
static int	action_to_next_engine_params(const struct dpa_cls_tbl_action
	*action, t_FmPcdCcNextEngineParams *next_engine_params, int *hmd);

/*
 * Translates next engine parameters (from FMD) into action parameters for use
 * with the DPA Classifier.
 */
static int	next_engine_params_to_action(const t_FmPcdCcNextEngineParams
	*next_engine_params, struct dpa_cls_tbl_action *action);

/*
 * Finds the entry_id reference of a table entry specified
 * by key. This works only on tables managed by key.
 */
static int	key_to_entry_id(const struct dpa_cls_table *cls_table,
	const struct dpa_offload_lookup_key *key);

/*
 * Finds the table which is based on a specified Cc node and returns its
 * descriptor.
 */
static int	handle_to_td(void *cc_node);

static inline void lock_desc_table(struct dpa_cls_descriptor_table
								*desc_table);

static inline void release_desc_table(struct dpa_cls_descriptor_table
								*desc_table);

static void	*desc_to_object(struct dpa_cls_descriptor_table *desc_table,
								int desc);

/*
 * Gets the first free descriptor in the indicated descriptor table and fills
 * it with the provided object pointer. In case there are no available
 * descriptors (or the descriptor table doesn't exist at all), the function
 * will attempt to extend the descriptor table (or create it).
 */
static int	acquire_descriptor(struct dpa_cls_descriptor_table
					*desc_table, void *object, int *desc);

/*
 * Releases a descriptor to a descriptor table. In case the descriptor table
 * is completely empty, the function removes the descriptor table.
 */
static inline void put_descriptor(struct dpa_cls_descriptor_table *desc_table,
								int desc);

/*
 * Applies the key mask on the key and provides the updated key
 * in a new buffer.
 */
static inline void key_apply_mask(const struct dpa_offload_lookup_key *key,
	uint8_t *new_key);

/*
 * Import a set of low level header manipulation nodes into an existing
 * low level header manipulation nodes list (associated with a classifier
 * header manipulation op).
 */
static int import_hm_nodes_to_chain(void * const *node_array,
	unsigned int num_nodes, struct dpa_cls_hm *hm);

/* Initializes a chain (list) of low level header manipulation nodes. */
static int init_hm_chain(void *fm_pcd, struct list_head *chain_head,
						struct list_head *item);

/* Removes a chain (list) of low level header manipulation nodes. */
static int remove_hm_chain(struct list_head	*chain_head,
			struct list_head	*item);

/*
 * Releases the resources used by a low level (FMD) header manipulation node
 * parameters.
 */
static void release_hm_node_params(struct dpa_cls_hm_node *node);

/*
 * Creates a new classifier header manipulation object and links it to an
 * existing object if needed.
 */
static int create_new_hm_op(int *hmd, int next_hmd);

static void remove_hm_op(int hmd);

/*
 * Verifies that the parameters provided for a NAT type header manipulation op
 * are correct.
 */
static int nat_hm_check_params(const struct dpa_cls_hm_nat_params *nat_params);

/*
 * Prepares (creates or imports) the header manipulation nodes for a NAT type
 * header manipulation op.
 */
static int nat_hm_prepare_nodes(struct dpa_cls_hm *pnat_hm,
				const struct dpa_cls_hm_nat_resources *res);

/* Fills in the parameters of the header manipulation nodes */
static int nat_hm_update_params(struct dpa_cls_hm *pnat_hm);

/*
 * Verifies that the parameters provided for a Forwarding type header
 * manipulation op are correct.
 */
static int fwd_hm_check_params(const struct dpa_cls_hm_fwd_params *fwd_params);

/*
 * Prepares (creates or imports) the header manipulation nodes for a Forwarding
 * type header manipulation op.
 */
static int fwd_hm_prepare_nodes(struct dpa_cls_hm *pfwd_hm,
				const struct dpa_cls_hm_fwd_resources *res);

/* Fills in the parameters of the header manipulation nodes */
static int fwd_hm_update_params(struct dpa_cls_hm *pfwd_hm);

/*
 * Verifies that the parameters provided for a header remove header
 * manipulation op are correct.
 */
static int remove_hm_check_params(const struct dpa_cls_hm_remove_params
	*remove_params);

/*
 * Prepares (creates or imports) the header manipulation nodes for a remove
 * header manipulation op.
 */
static int remove_hm_prepare_nodes(struct dpa_cls_hm *premove_hm,
				const struct dpa_cls_hm_remove_resources *res);

/* Fills in the parameters of the header manipulation nodes */
static int remove_hm_update_params(struct dpa_cls_hm *premove_hm);

/*
 * Verifies that the parameters provided for a header insert header
 * manipulation op are correct.
 */
static int insert_hm_check_params(const struct dpa_cls_hm_insert_params
	*insert_params);

/*
 * Prepares (creates or imports) the header manipulation nodes for an insert
 * header manipulation op.
 */
static int insert_hm_prepare_nodes(struct dpa_cls_hm *pinsert_hm,
				const struct dpa_cls_hm_insert_resources *res);

/* Fills in the parameters of the header manipulation nodes */
static int insert_hm_update_params(struct dpa_cls_hm *pinsert_hm);

/*
 * Verifies that the parameters provided for a header update header
 * manipulation op are correct.
 */
static int update_hm_check_params(const struct dpa_cls_hm_update_params
	*update_params);

/*
 * Prepares (creates or imports) the header manipulation nodes for an update
 * header manipulation op.
 */
static int update_hm_prepare_nodes(struct dpa_cls_hm *pupdate_hm,
				const struct dpa_cls_hm_update_resources *res);

/* Fills in the parameters of the header manipulation nodes */
static int update_hm_update_params(struct dpa_cls_hm *pupdate_hm);

/*
 * Verifies that the parameters provided for a VLAN specific header
 * manipulation op are correct.
 */
static int
	vlan_hm_check_params(const struct dpa_cls_hm_vlan_params *vlan_params);

/*
 * Prepares (creates or imports) the header manipulation nodes for a VLAN
 * specific header manipulation.
 */
static int vlan_hm_prepare_nodes(struct dpa_cls_hm *pvlan_hm,
				const struct dpa_cls_hm_vlan_resources *res);

/* Fills in the parameters of the header manipulation nodes */
static int vlan_hm_update_params(struct dpa_cls_hm *pvlan_hm);

/*
 * Verifies that the parameters provided for a MPLS specific header
 * manipulation op are correct.
 */
static int mpls_hm_check_params(const struct dpa_cls_hm_mpls_params
	*mpls_params);

/*
 * Prepares (creates or imports) the header manipulation nodes for a MPLS
 * specific header manipulation.
 */
static int mpls_hm_prepare_nodes(struct dpa_cls_hm *pmpls_hm,
				const struct dpa_cls_hm_mpls_resources *res);

/* Fills in the parameters of the header manipulation nodes */
static int mpls_hm_update_params(struct dpa_cls_hm *pmpls_hm);


#endif /*__DPA_CLASSIFIER_C */

/* Display a lookup key and its mask */
void dump_lookup_key(const struct dpa_offload_lookup_key *key);

/*
 * Imports a header manipulation defined using the low level driver (FMD) API,
 * for use with DPA Classifier
 */
int dpa_classif_import_static_hm(void *hm, int next_hmd, int *hmd);

/*
 * Provides the FMan driver handle of the static header manipulation associated
 * with a specified header manipulation descriptor
 */
void *dpa_classif_get_static_hm_handle(int hmd);

/*
 * Provides details about the miss action configured on a classification
 * table.
 */
int dpa_classif_get_miss_action(int td, struct dpa_cls_tbl_action *miss_action);

/*
 * Locks a header manipulation chain (marks as "used"). The header manipulation
 * operations cannot be removed as long as they are locked. The function
 * provides the FMan driver handle of the manip node which is chain head.
 */
void *dpa_classif_hm_lock_chain(int hmd);

/* Releases a locked header manipulation chain. */
void dpa_classif_hm_release_chain(int hmd);

/* Tells whether a specific header manipulation operation is a chain head */
bool dpa_classif_hm_is_chain_head(int hmd);

/*
 * Given a header manipulation object descriptor, this function searches
 * through the header manipulation chain that this object belongs to and
 * provides the FMan driver handle of the IP fragmentation header manipulation
 * node.
 */
void *dpa_classif_get_frag_hm_handle(int hmd);


#endif /* __DPA_CLASSIFIER_H */
