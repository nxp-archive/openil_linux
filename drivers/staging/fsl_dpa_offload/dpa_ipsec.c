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

#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/wait.h>

#include "dpa_ipsec.h"
#include "dpa_ipsec_desc.h"
#include "dpa_classifier.h"

#include "fm_common.h"
#include "fm_pcd.h"

/* DPA IPsec Mapping between API algorithm suites and SEC algorithm IDs */
struct ipsec_alg_suite ipsec_algs[] = IPSEC_ALGS;

/* globally allocated because of performance constraints */
static t_FmPcdCcNodeParams cc_node_prms;

/* Global dpa_ipsec component */
struct dpa_ipsec *gbl_dpa_ipsec[MAX_DPA_IPSEC_INSTANCES];

/* Spinlock protecting the global dpa ipsec vector */
DEFINE_SPINLOCK(gbl_dpa_ipsec_lock);

/* Wait for other tasks to finish when doing instance free */
DECLARE_WAIT_QUEUE_HEAD(wait_queue);

static int sa_flush_policies(struct dpa_ipsec_sa *sa);
static int sa_rekeying_outbound(struct dpa_ipsec_sa *new_sa);
static void *alloc_ipsec_manip(struct dpa_ipsec *dpa_ipsec);
static void mark_unused_gbl_dpa_ipsec(int instance);
static int remove_inbound_sa(struct dpa_ipsec_sa *sa);
static int remove_outbound_sa(struct dpa_ipsec_sa *sa);
static inline bool table_in_use(int td);

/* Debug support functions */

#ifdef DEBUG_PARAM
int print_sa_sec_param(struct dpa_ipsec_sa *sa)
{
	int i;
	struct dpa_ipsec_policy_entry *policy_entry, *tmp_policy_entry;
	struct dpa_ipsec_policy_selectors *policy_selectors;

	BUG_ON(!sa);

	pr_info("\n Printing SA SEC PARAM for sa %p\n", sa);
	pr_info("\n sa_dir = %d\n", sa->sa_dir);
	pr_info("\n id = %d\n", sa->id);
	pr_info(" dpa_ipsec addr = %p\n", sa->dpa_ipsec);
	pr_info(" from_sec_fq addr = %p\n", sa->from_sec_fq);

	pr_info("\n auth_data.auth_type = %d\n", sa->auth_data.auth_type);
	pr_info("auth_data.auth_key_len = %d\n",
		sa->auth_data.auth_key_len);
	pr_info("auth_data.auth_key is\n");
	for (i = 0; i < sa->auth_data.auth_key_len; i++)
		pr_info("%x, ", sa->auth_data.auth_key[i]);

	pr_info("\n cipher_data.cipher_type = %d\n",
		sa->cipher_data.cipher_type);
	pr_info("cipher_data.cipher_key_len = %d\n",
		sa->cipher_data.cipher_key_len);
	pr_info("cipher_data.cipher_key is\n");
	for (i = 0; i < sa->cipher_data.cipher_key_len; i++)
		pr_info("%x, ", sa->cipher_data.cipher_key[i]);

	pr_info("\n sa_bpid = %d\n", sa->sa_bpid);
	pr_info("\n sa_bufsize = %d\n", sa->sa_bufsize);
	pr_info(" spi = %d\n", sa->spi);
	pr_info(" sa_wqid = %d\n", sa->sa_wqid);
	pr_info(" outbound_flowid = %d\n", sa->outbound_flowid);

	pr_info("dest_addr.version = %d\n", sa->dest_addr.version);
	pr_info("dest_addr = %x.%x.%x.%x\n",
		sa->dest_addr.ipv4.byte[0],
		sa->dest_addr.ipv4.byte[1],
		sa->dest_addr.ipv4.byte[2], sa->dest_addr.ipv4.byte[3]);
	pr_info("src_addr.version = %d\n", sa->src_addr.version);
	pr_info("src_addr = %x.%x.%x.%x\n",
		sa->src_addr.ipv4.byte[0],
		sa->src_addr.ipv4.byte[1],
		sa->src_addr.ipv4.byte[2], sa->src_addr.ipv4.byte[3]);

	if (sa_is_outbound(sa)) {
		uint8_t *out_hdr;
		out_hdr = &sa->sec_desc->pdb_en.ip_hdr[0];
		pr_info("Outer Header length  %d\n",
			sa->sec_desc->pdb_en.ip_hdr_len);
		pr_info("Outer Header is:\n");
		for (i = 0; i < sa->sec_desc->pdb_en.ip_hdr_len; i++)
			pr_info("%x, ", *(out_hdr + i));

		pr_info("pdb_en.ip_hdr_len %d\n",
			sa->sec_desc->pdb_en.ip_hdr_len);
		pr_info("pdb_en.spi = %d\n", sa->sec_desc->pdb_en.spi);
		pr_info("pdb_en.seq_num = %d\n",
			sa->sec_desc->pdb_en.seq_num);
		pr_info("pdb_en.options = 0x%x\n",
			sa->sec_desc->pdb_en.options);
		pr_info("pdb_en.desc_hdr = 0x%x\n",
			sa->sec_desc->pdb_en.desc_hdr);
		pr_info("pdb_en.ip_nh = 0x%x\n",
			sa->sec_desc->pdb_en.ip_nh);
	} else {
		pr_info("pdb_dec.hmo_ip_hdr_len %d\n",
			sa->sec_desc->pdb_dec.hmo_ip_hdr_len);
		pr_info("pdb_dec.options %d\n",
			sa->sec_desc->pdb_dec.options);
		pr_info("pdb_dec.seq_num %d\n",
			sa->sec_desc->pdb_dec.seq_num);
	}

	pr_info("\n Printing all policies from this SA policy_list\n");
	list_for_each_entry_safe(policy_entry, tmp_policy_entry,
				 &sa->policy_headlist, node) {
		policy_selectors = &policy_entry->policy_selectors;
		pr_info("policy_selectors src_addr.version = %d\n",
			policy_selectors->src_addr.version);
		pr_info("policy_selectors src_addr = %x.%x.%x.%x\n",
			policy_selectors->src_addr.ipv4.byte[0],
			policy_selectors->src_addr.ipv4.byte[1],
			policy_selectors->src_addr.ipv4.byte[2],
			policy_selectors->src_addr.ipv4.byte[3]);
		pr_info("\n policy_selectors dest_addr.version = %d\n",
			policy_selectors->dest_addr.version);
		pr_info("policy_selectors dest_addr = %x.%x.%x.%x\n",
			policy_selectors->dest_addr.ipv4.byte[0],
			policy_selectors->dest_addr.ipv4.byte[1],
			policy_selectors->dest_addr.ipv4.byte[2],
			policy_selectors->dest_addr.ipv4.byte[3]);

		pr_info("\n policy_selectors dest_port = %d\n",
			policy_selectors->dest_port);
		pr_info(" policy_selectors src_port = %d\n",
			policy_selectors->src_port);
		pr_info(" policy_selectors dest_port = %d\n",
			policy_selectors->dest_port_mask);
		pr_info(" policy_selectors dest_port = %d\n",
			policy_selectors->src_port_mask);
		pr_info(" policy_selectors proto = %d\n",
			policy_selectors->protocol);
		pr_info(" policy_selectors dest_prefix_len = %d\n",
			policy_selectors->dest_prefix_len);
		pr_info(" policy_selectors src_prefix_len = %d\n",
			policy_selectors->src_prefix_len);
	}
	pr_info("\n Done printing SA SEC PARAM for sa %p\n", sa);

	return 0;
}
#endif

/* Initialization functions */

/* store params needed during runtime or free */
static inline void store_ipsec_params(struct dpa_ipsec *dpa_ipsec,
				      const struct dpa_ipsec_params *params)
{
	struct dpa_ipsec_pre_sec_out_params *pre_sec_out_params;
	struct dpa_ipsec_pol_table *any_ipv4_table, *any_ipv6_table;
	int i;

	/* copy config params */
	dpa_ipsec->config = *params;

	/*
	 * reconfigure the array of outbound policy table parameters, in order
	 * to simplify the process of choosing the correct table during runtime
	 * add / remove policies operations
	 */

	pre_sec_out_params = &dpa_ipsec->config.pre_sec_out_params;
	/* get the desc for the ANY tables */
	any_ipv4_table = &pre_sec_out_params->table[DPA_IPSEC_PROTO_ANY_IPV4];
	any_ipv6_table = &pre_sec_out_params->table[DPA_IPSEC_PROTO_ANY_IPV6];

	/*
	 * replace the parameters of a table for a specific protocol, if an
	 * invalid table desc was provided, with those of the corresponding ANY
	 * table for that IP version
	 */
	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS - 2; i++) {
		if (pre_sec_out_params->table[i].dpa_cls_td ==
							DPA_OFFLD_DESC_NONE) {
			/* IPV4 table desc are at even indexes (IPV6 at odd) */
			if (i & 0x01)
				pre_sec_out_params->table[i] = *any_ipv6_table;
			else
				pre_sec_out_params->table[i] = *any_ipv4_table;
		}
	}
}

/* check that the provided params are valid */
static int check_ipsec_params(const struct dpa_ipsec_params *prms)
{
	const struct dpa_ipsec_pre_sec_out_params *pre_sec_out_prms;
	const struct dpa_ipsec_pre_sec_in_params *pre_sec_in_prms;
	struct dpa_cls_tbl_params table_params;
	int i, err, valid_tables = 0, fqid_range_size, min_fqid_num;

	if (!prms) {
		log_err("Invalid DPA IPsec parameters handle\n");
		return -EINVAL;
	}

	if ((prms->post_sec_in_params.do_pol_check) && (!prms->fm_pcd)) {
		log_err("Provide a valid PCD handle to enable inbound policy check!\n");
		return -EINVAL;
	}

	/*
	 * check that all required table descriptors were provided:
	 * - at least one table for outbound policy lookup
	 * - one table for index lookup after decryption
	 * - one table for SA lookup
	 */

	/* check outbound policy tables */
	pre_sec_out_prms = &prms->pre_sec_out_params;
	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS; i++) {
		int dpa_cls_td = pre_sec_out_prms->table[i].dpa_cls_td;
		if (dpa_cls_td != DPA_OFFLD_DESC_NONE) {
			/* verify that a valid key structure was configured */
			if (!pre_sec_out_prms->table[i].key_fields) {
				log_err("Invalid key struct. for out table %d\n",
				       i);
				return -EINVAL;
			}

			/* verify that it is not an indexed table */
			err = dpa_classif_table_get_params(dpa_cls_td,
							   &table_params);
			if (err < 0) {
				log_err("Couldn't check type of outbound policy lookup table\n");
				return -EINVAL;
			}

			if (table_params.type == DPA_CLS_TBL_INDEXED) {
				log_err("Outbound policy lookup table cannot be of type INDEXED\n");
				return -EINVAL;
			}
			valid_tables++;

			/* Check if this table is in use on other DPA instance*/
			if (table_in_use(dpa_cls_td)) {
				log_err("Table with ID %d is in use by another DPA IPsec instance\n",
					dpa_cls_td);
				return -EINVAL;
			}
		}
	}

	if (!valid_tables) {
		log_err("Specify at least one table for outbound policy lookup\n");
		return -EINVAL;
	}

	/*
	 * In classification base on SA that decrypted traffic is not required
	 * than the post decryption classification table could be invalid.
	 * In this case inbound policy verification is not supported.
	 */
	if (prms->post_sec_in_params.dpa_cls_td == DPA_OFFLD_DESC_NONE) {
		if (prms->post_sec_in_params.do_pol_check) {
			log_err("Index table required policy check enabled\n");
			return -EINVAL;
		}
		goto skip_post_decryption_check;
	}

	/* get post decryption table parameters */
	err = dpa_classif_table_get_params(prms->post_sec_in_params.dpa_cls_td,
					   &table_params);
	if (err < 0) {
		log_err("Could not check type of post decryption table\n");
		return -EINVAL;
	}

	/* verify that it is an indexed table */
	if (table_params.type != DPA_CLS_TBL_INDEXED) {
		log_err("Post decryption table must be of type INDEXED\n");
		return -EINVAL;
	}

	/*
	 * verify that it can hold a flow ID value for each possible IN SA plus
	 * the reserved number of flow ID values (base_flow_id)
	 */
	if (table_params.indexed_params.entries_cnt <
	    (prms->max_sa_pairs + prms->post_sec_in_params.base_flow_id)) {
		log_err("The post decryption table size is to small!\n");
		return -EINVAL;
	}

	if (prms->post_sec_in_params.dpa_cls_td > 0 &&
	    table_in_use(prms->post_sec_in_params.dpa_cls_td)) {
		log_err("Table with ID %d is in use by another DPA IPsec instance\n",
			prms->post_sec_in_params.dpa_cls_td);
		return -EINVAL;
	}


skip_post_decryption_check:
	/* check pre decryption SA lookup tables */
	valid_tables = 0;
	pre_sec_in_prms = &prms->pre_sec_in_params;
	for (i = 0; i < DPA_IPSEC_MAX_SA_TYPE; i++)
		if (pre_sec_in_prms->dpa_cls_td[i] != DPA_OFFLD_DESC_NONE) {
			if (table_in_use(pre_sec_in_prms->dpa_cls_td[i])) {
				log_err("Table with ID %d is in use by another DPA IPsec instance\n",
					pre_sec_in_prms->dpa_cls_td[i]);
				return -EINVAL;
			}

			/* verify that it is not an indexed table */
			err = dpa_classif_table_get_params(
						pre_sec_in_prms->dpa_cls_td[i],
						&table_params);
			if (err < 0) {
				log_err("Couldn't check type of SA table\n");
				return -EINVAL;
			}

			if (table_params.type == DPA_CLS_TBL_INDEXED) {
				log_err("SA tables mustn't be of type index\n");
				return -EINVAL;
			}
			valid_tables++;
		}
	if (!valid_tables) {
		log_err("Specify at least one valid table for SA lookup\n");
		return -EINVAL;
	}

	/*
	 * verify that at least one field was selected for building inbound
	 * policy keys
	 */
	if (prms->post_sec_in_params.do_pol_check &&
	    prms->post_sec_in_params.key_fields == 0) {
		log_err("At least one field must be specified IN policy keys\n");
		return -EINVAL;
	}

	/*
	 * verify that the instance is configured
	 * for offloading at least one SA pair
	 */
	if (prms->max_sa_pairs == 0) {
		log_err("The instance must be configured for offloading at least one SA pair\n");
		return -EINVAL;
	}

	/* Verify the parameters of the FQID range - if one was provided */
	if (prms->fqid_range) {
		fqid_range_size = prms->fqid_range->end_fqid -
						prms->fqid_range->start_fqid;
		min_fqid_num = prms->max_sa_pairs * 2 * NUM_FQS_PER_SA;
		if (fqid_range_size <= 0 || fqid_range_size <  min_fqid_num) {
			log_err("Insufficient number of FQIDs in range!\n");
			return -EINVAL;
		}
	}

	return 0;
}

static void calc_in_pol_key_size(struct dpa_ipsec *dpa_ipsec, uint8_t *key_size)
{
	uint8_t key_fields, field_mask = 0;
	int i;

	BUG_ON(!dpa_ipsec);
	BUG_ON(!key_size);

	/* default value for key_size (set now in case a failure occurs later)*/
	*key_size = 0;

	key_fields = dpa_ipsec->config.post_sec_in_params.key_fields;

	for (i = 0; i < DPA_IPSEC_MAX_KEY_FIELDS; i++) {
		field_mask = (uint8_t)(1 << i);
		switch (key_fields & field_mask) {
		case DPA_IPSEC_KEY_FIELD_SIP:
			if (dpa_ipsec->config.post_sec_in_params.use_ipv6_pol)
				*key_size += DPA_OFFLD_IPv6_ADDR_LEN_BYTES;
			else
				*key_size += DPA_OFFLD_IPv4_ADDR_LEN_BYTES;
			break;

		case DPA_IPSEC_KEY_FIELD_DIP:
			if (dpa_ipsec->config.post_sec_in_params.use_ipv6_pol)
				*key_size += DPA_OFFLD_IPv6_ADDR_LEN_BYTES;
			else
				*key_size += DPA_OFFLD_IPv4_ADDR_LEN_BYTES;
			break;

		case DPA_IPSEC_KEY_FIELD_PROTO:
			*key_size += IP_PROTO_FIELD_LEN;
			break;

		case DPA_IPSEC_KEY_FIELD_SPORT:
			*key_size += PORT_FIELD_LEN;
			break;

		case DPA_IPSEC_KEY_FIELD_DPORT:
			*key_size += PORT_FIELD_LEN;
			break;
		case DPA_IPSEC_KEY_FIELD_DSCP:
			if (dpa_ipsec->config.post_sec_in_params.use_ipv6_pol)
				*key_size += DSCP_FIELD_LEN_IPv4;
			else
				*key_size += DSCP_FIELD_LEN_IPv6;
			break;
		}
	}
}

static int create_inpol_node(struct dpa_ipsec *dpa_ipsec, void **cc_node)
{
	t_FmPcdCcNextEngineParams *next_engine_miss_action;

	BUG_ON(!dpa_ipsec);
	BUG_ON(!cc_node);

	/* default value for cc_node (set now in case a failure occurs later) */
	*cc_node = NULL;

	memset(&cc_node_prms, 0, sizeof(cc_node_prms));
	cc_node_prms.extractCcParams.type = e_FM_PCD_EXTRACT_NON_HDR;
	cc_node_prms.extractCcParams.extractNonHdr.src =
						e_FM_PCD_EXTRACT_FROM_KEY;
	cc_node_prms.extractCcParams.extractNonHdr.action =
						e_FM_PCD_ACTION_EXACT_MATCH;
	cc_node_prms.extractCcParams.extractNonHdr.offset = 0;
	cc_node_prms.extractCcParams.extractNonHdr.size =
					      dpa_ipsec->sa_mng.inpol_key_size;

	cc_node_prms.keysParams.numOfKeys = 0;
	cc_node_prms.keysParams.keySize = dpa_ipsec->sa_mng.inpol_key_size;

	next_engine_miss_action =
			&cc_node_prms.keysParams.ccNextEngineParamsForMiss;
	next_engine_miss_action->nextEngine = e_FM_PCD_DONE;

	*cc_node = FM_PCD_MatchTableSet(dpa_ipsec->config.fm_pcd,
					&cc_node_prms);
	if (!*cc_node) {
		log_err("%s: FM_PCD_MatchTableSet failed!\n", __func__);
		return -EBUSY;
	}

	return 0;
}

static inline void destroy_inpol_node(struct dpa_ipsec *dpa_ipsec,
				      void *cc_node)
{
	t_Error fmd_err;

	BUG_ON(!dpa_ipsec);
	BUG_ON(!cc_node);

	fmd_err = FM_PCD_MatchTableDelete(cc_node);
	if (fmd_err != E_OK) {
		log_err("%s: FM_PCD_MatchTableDelete failed!\n", __func__);
		log_err("Could not free policy check CC Node\n");
	}
}

static int create_inpol_cls_tbl(struct dpa_ipsec *dpa_ipsec,
				void *cc_node,
				int *td)
{
	struct dpa_cls_tbl_params params;
	int err;

	BUG_ON(!dpa_ipsec);
	BUG_ON(!cc_node);
	BUG_ON(!td);

	*td = DPA_OFFLD_DESC_NONE;

	memset(&params, 0, sizeof(params));
	params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_REF;
	params.type = DPA_CLS_TBL_EXACT_MATCH;
	params.exact_match_params.entries_cnt = DPA_IPSEC_MAX_POL_PER_SA;
	params.exact_match_params.key_size = dpa_ipsec->sa_mng.inpol_key_size;
	params.exact_match_params.use_priorities = true;
	params.cc_node = cc_node;
	err = dpa_classif_table_create(&params, td);
	if (err < 0) {
		log_err("Could not create exact match tbl");
		return err;
	}

	return 0;
}

static inline void destroy_inpol_cls_tbl(int td)
{
	int err;

	if (td != DPA_OFFLD_DESC_NONE) {
		err = dpa_classif_table_free(td);
		if (err < 0)
			log_err("Could not free EM table\n");
	}
}

static int get_inbound_flowid(struct dpa_ipsec *dpa_ipsec, uint16_t *flowid)
{
	BUG_ON(!dpa_ipsec);
	BUG_ON(!dpa_ipsec->sa_mng.inbound_flowid_cq);
	BUG_ON(!flowid);

	if (cq_get_2bytes(dpa_ipsec->sa_mng.inbound_flowid_cq, flowid) < 0) {
		log_err("Could not retrieve a valid inbound flow ID\n");
		return -EDOM;
	}

	return 0;
}

static int put_inbound_flowid(struct dpa_ipsec *dpa_ipsec, uint16_t flowid)
{
	BUG_ON(!dpa_ipsec);
	BUG_ON(!dpa_ipsec->sa_mng.inbound_flowid_cq);

	if (cq_put_2bytes(dpa_ipsec->sa_mng.inbound_flowid_cq, flowid) < 0) {
		log_err("Could not release inbound flow id\n");
		return -EDOM;
	}

	return 0;
}

static int create_inbound_flowid_cq(struct dpa_ipsec *dpa_ipsec)
{
	void *cq;
	uint16_t base_flow_id;
	int i, err;

	BUG_ON(!dpa_ipsec);

	cq = cq_new(dpa_ipsec->sa_mng.max_num_sa / 2, sizeof(uint16_t));
	if (!cq) {
		log_err("Could not create inbound flow ID management CQ\n");
		return -ENOMEM;
	}

	dpa_ipsec->sa_mng.inbound_flowid_cq = cq;

	/* Populate the created CQ with flow ids */
	base_flow_id = dpa_ipsec->config.post_sec_in_params.base_flow_id;
	for (i = base_flow_id;
	     i < dpa_ipsec->sa_mng.max_num_sa / 2 + base_flow_id; i++) {
		err = put_inbound_flowid(dpa_ipsec, (uint16_t) i);
		if (err < 0) {
			log_err("Couldn't fill flow id management queue\n");
			cq_delete(cq);
			dpa_ipsec->sa_mng.inbound_flowid_cq = NULL;
			return err;
		}
	}

	return 0;
}

static inline void destroy_inbound_flowid_cq(struct cq *inbound_flowid_cq)
{
	/* sanity checks */
	if (inbound_flowid_cq)
		cq_delete(inbound_flowid_cq);
}

static int get_free_inbpol_tbl(struct dpa_ipsec *dpa_ipsec, int *table_desc)
{
	struct inpol_tbl *inpol_tbl;
	struct list_head *head;
	int ret = 0;

	BUG_ON(!dpa_ipsec);
	BUG_ON(!table_desc);

	/* Lock inbound policy list */
	mutex_lock(&dpa_ipsec->sa_mng.inpol_tables_lock);

	head = &dpa_ipsec->sa_mng.inpol_tables;

	list_for_each_entry(inpol_tbl, head, table_list)
		if (!inpol_tbl->used)
			break;

	if (!inpol_tbl->used) {
		BUG_ON(inpol_tbl->td < 0);
		inpol_tbl->used = true;
		*table_desc = inpol_tbl->td;
	} else {
		log_err("No more free EM tables for inbound policy verification\n");
		ret = -ENOMEM;
	}

	/* Unlock inbound policy list */
	mutex_unlock(&dpa_ipsec->sa_mng.inpol_tables_lock);

	return ret;
}

static void put_free_inbpol_tbl(struct dpa_ipsec *dpa_ipsec, int table_desc)
{
	struct inpol_tbl *inpol_tbl;
	struct list_head *head;

	BUG_ON(!dpa_ipsec);
	BUG_ON(table_desc < 0);

	/* Lock inbound policy list */
	mutex_lock(&dpa_ipsec->sa_mng.inpol_tables_lock);

	head = &dpa_ipsec->sa_mng.inpol_tables;

	list_for_each_entry(inpol_tbl, head, table_list)
	    if (inpol_tbl->td == table_desc)
		break;

	if (inpol_tbl->used)
		inpol_tbl->used = FALSE;
	else
		pr_warn("Exact match table %d is not used\n", table_desc);

	/* Unlock inbound policy list */
	mutex_unlock(&dpa_ipsec->sa_mng.inpol_tables_lock);
}

static int get_free_ipsec_manip_node(struct dpa_ipsec *dpa_ipsec, void **hm)
{
	struct ipsec_manip_node *ipsec_manip_node;
	struct list_head *head;
	int ret = 0;

	BUG_ON(!dpa_ipsec);
	BUG_ON(!hm);

	mutex_lock(&dpa_ipsec->lock);

	/* Lock IPSec manip node list */
	mutex_lock(&dpa_ipsec->sa_mng.ipsec_manip_node_lock);

	head = &dpa_ipsec->sa_mng.ipsec_manip_node_list;

	list_for_each_entry(ipsec_manip_node, head, ipsec_manip_node_list)
		if (!ipsec_manip_node->used)
			break;

	if (!ipsec_manip_node->used) {
		BUG_ON(!ipsec_manip_node->hm);
		ipsec_manip_node->used = true;
		*hm = ipsec_manip_node->hm;
	} else {
		log_err("No more free IPSec manip nodes for special operations\n");
		ret = -ENOMEM;
	}

	/* Unlock IPSec manip node list */
	mutex_unlock(&dpa_ipsec->sa_mng.ipsec_manip_node_lock);
	mutex_unlock(&dpa_ipsec->lock);

	return ret;
}

static void put_free_ipsec_manip_node(struct dpa_ipsec *dpa_ipsec, void *hm)
{
	struct ipsec_manip_node *ipsec_manip_node;
	struct list_head *head;
	bool found = false;

	BUG_ON(!dpa_ipsec);
	BUG_ON(!hm);

	mutex_lock(&dpa_ipsec->lock);

	/* Lock IPSec manip node list */
	mutex_lock(&dpa_ipsec->sa_mng.ipsec_manip_node_lock);

	head = &dpa_ipsec->sa_mng.ipsec_manip_node_list;

	list_for_each_entry(ipsec_manip_node, head, ipsec_manip_node_list)
		if (ipsec_manip_node->hm == hm) {
			found = true;
			break;
		}

	BUG_ON(!found);

	if (ipsec_manip_node->used)
		ipsec_manip_node->used = false;
	else
		pr_warn("IPSec manip node %p is not used\n", hm);

	/* Unlock IPSec manip node list */
	mutex_unlock(&dpa_ipsec->sa_mng.ipsec_manip_node_lock);
	mutex_unlock(&dpa_ipsec->lock);
}

static void replace_ipsec_manip_node(struct dpa_ipsec *dpa_ipsec, void *hm_old,
				     void *hm_new)
{
	struct ipsec_manip_node *ipsec_manip_node;
	struct list_head *head;
	bool found = false;

	BUG_ON(!dpa_ipsec);
	BUG_ON(!hm_old);
	BUG_ON(!hm_new);

	/*
	 * Lock IPSec manip node list
	 */
	mutex_lock(&dpa_ipsec->sa_mng.ipsec_manip_node_lock);

	head = &dpa_ipsec->sa_mng.ipsec_manip_node_list;

	list_for_each_entry(ipsec_manip_node, head, ipsec_manip_node_list)
		if (ipsec_manip_node->hm == hm_old) {
			found = true;
			break;
		}

	BUG_ON(!found);

	if (ipsec_manip_node->used)
		ipsec_manip_node->hm = hm_new;
	else
		pr_warn("IPSec manip node %p is not used\n", hm_old);

	/*
	 * Unlock IPSec manip node list
	 */
	mutex_unlock(&dpa_ipsec->sa_mng.ipsec_manip_node_lock);
}

/* initialize fqid management CQ */
static int create_fqid_cq(struct dpa_ipsec *dpa_ipsec)
{
	struct dpa_ipsec_fqid_range *fqid_range;
	struct cq *fqid_cq;
	int i;

	BUG_ON(!dpa_ipsec);

	if (dpa_ipsec->config.fqid_range) {
		fqid_range = dpa_ipsec->config.fqid_range;
		fqid_cq = cq_new(fqid_range->end_fqid - fqid_range->start_fqid,
				 sizeof(uint32_t));
		if (!fqid_cq) {
			log_err("Could not create CQ for FQID management!\n");
			return -ENOMEM;
		}

		dpa_ipsec->sa_mng.fqid_cq = fqid_cq;

		/* fill the CQ */
		for (i = fqid_range->start_fqid; i < fqid_range->end_fqid; i++)
			if (cq_put_4bytes(fqid_cq, (uint16_t)i) < 0) {
				log_err("Could not fill fqid management CQ!\n");
				return -EDOM;
			}
	}

	return 0;
}

/* destroy the FQID management CQ - if one was initialized */
static inline void destroy_fqid_cq(struct dpa_ipsec *dpa_ipsec)
{
	if (dpa_ipsec->sa_mng.fqid_cq) {
		cq_delete(dpa_ipsec->sa_mng.fqid_cq);
		dpa_ipsec->sa_mng.fqid_cq = NULL;
	}
}

/* Determine if get_instance returned error */
static inline int check_instance(struct dpa_ipsec *instance)
{
	if (PTR_ERR(instance) == -EPERM) {
		log_err("Instance is not initialized\n");
		return -EPERM;
	}

	if (PTR_ERR(instance) == -EINVAL) {
		log_err("Instance is being freed\n");
		return -EINVAL;
	}

	return 0;
}

static struct dpa_ipsec *get_instance(int instance_id)
{
	struct dpa_ipsec *dpa_ipsec;
	int ret = 0;

	BUG_ON(instance_id < 0 || instance_id >= MAX_DPA_IPSEC_INSTANCES);

	spin_lock(&gbl_dpa_ipsec_lock);

	if (!gbl_dpa_ipsec[instance_id])
		ret = -EPERM;

	dpa_ipsec = gbl_dpa_ipsec[instance_id];

	if (ret == 0 && !atomic_read(&dpa_ipsec->valid))
		ret = -EINVAL;

	if (!ret)
		instance_refinc(dpa_ipsec);

	spin_unlock(&gbl_dpa_ipsec_lock);

	return !ret ? dpa_ipsec : ERR_PTR(ret);
}

static void put_instance(struct dpa_ipsec *dpa_ipsec)
{
	BUG_ON(!dpa_ipsec);
	instance_refdec(dpa_ipsec);
	if (atomic_read(&dpa_ipsec->ref) == 1)
		wake_up(&wait_queue);
}

/* Returns true it table is in use on other DPA instance */
static inline bool table_in_use(int td)
{
	struct dpa_ipsec *instance;
	int i, j;

	for (i = 0; i < MAX_DPA_IPSEC_INSTANCES; i++) {
		struct dpa_ipsec_pre_sec_out_params *pre_sec_out_prms;
		struct dpa_ipsec_pre_sec_in_params  *pre_sec_in_params;

		instance = get_instance(i);
		if (IS_ERR(instance))
			continue;

		/* Acquire instance lock */
		mutex_lock(&instance->lock);

		pre_sec_out_prms = &instance->config.pre_sec_out_params;
		for (j = 0; j < DPA_IPSEC_MAX_SUPPORTED_PROTOS; j++) {
			int dpa_cls_td = pre_sec_out_prms->table[i].dpa_cls_td;
			if (td == dpa_cls_td) {
				mutex_unlock(&instance->lock);
				put_instance(instance);
				return true;
			}
		}

		if (!ignore_post_ipsec_action(instance) &&
		    td == instance->config.post_sec_in_params.dpa_cls_td) {
			mutex_unlock(&instance->lock);
			put_instance(instance);
			return true;
		}

		pre_sec_in_params = &instance->config.pre_sec_in_params;
		for (j = 0; j < DPA_IPSEC_MAX_SA_TYPE; j++) {
			int dpa_cls_td = pre_sec_in_params->dpa_cls_td[j];
			if (td == dpa_cls_td) {
				mutex_unlock(&instance->lock);
				put_instance(instance);
				return true;
			}
		}

		/* Release the instance lock */
		mutex_unlock(&instance->lock);
		put_instance(instance);
	}

	return false;
}

/*
 * Create a circular queue with id's for aquiring SA's handles
 * Allocate a maximum number of SA internal structures to be used at runtime.
 * Param[in]	dpa_ipsec - Instance for which SA manager is initialized
 * Return value	0 on success. Error code otherwise.
 * Cleanup provided by free_sa_mng().
 */
static int init_sa_manager(struct dpa_ipsec *dpa_ipsec)
{
	struct dpa_ipsec_sa_mng *sa_mng;
	struct dpa_ipsec_sa *sa;
	int i = 0, err, start_sa_id;

	BUG_ON(!dpa_ipsec);

	sa_mng = &dpa_ipsec->sa_mng;
	sa_mng->max_num_sa = dpa_ipsec->config.max_sa_pairs * 2;

	/* Initialize the SA IPSec manip node list and its protective lock */
	INIT_LIST_HEAD(&dpa_ipsec->sa_mng.ipsec_manip_node_list);
	mutex_init(&sa_mng->ipsec_manip_node_lock);

	INIT_LIST_HEAD(&sa_mng->inpol_tables);

	/* create queue that holds free SA IDs */
	sa_mng->sa_id_cq = cq_new(sa_mng->max_num_sa, sizeof(int));
	if (!sa_mng->sa_id_cq) {
		log_err("Could not create SA IDs circular queue\n");
		return -ENOMEM;
	}

	/* fill with IDs */
	start_sa_id = dpa_ipsec->id * MAX_NUM_OF_SA;
	for (i = start_sa_id; i < start_sa_id + sa_mng->max_num_sa; i++)
		if (cq_put_4bytes(sa_mng->sa_id_cq, i) < 0) {
			log_err("Could not fill SA ID management CQ\n");
			return -EDOM;
		}

	/* initialize the circular queue for FQIDs management */
	err = create_fqid_cq(dpa_ipsec);
	if (err < 0) {
		log_err("Could not initialize FQID management mechanism!\n");
		return err;
	}

	/* alloc SA array */
	sa = kzalloc(sa_mng->max_num_sa * sizeof(*sa_mng->sa), GFP_KERNEL);
	if (!sa) {
		log_err("Could not allocate memory for SAs\n");
		return -ENOMEM;
	}
	sa_mng->sa = sa;

	/* alloc cipher/auth stuff */
	for (i = 0; i < sa_mng->max_num_sa; i++) {
		mutex_init(&sa_mng->sa[i].lock);
		sa[i].cipher_data.cipher_key =
					kzalloc(MAX_CIPHER_KEY_LEN, GFP_KERNEL);
		if (!sa[i].cipher_data.cipher_key) {
			log_err("Could not allocate memory for cipher key\n");
			return -ENOMEM;
		}
		sa[i].auth_data.auth_key =
					kzalloc(MAX_AUTH_KEY_LEN, GFP_KERNEL);
		if (!sa[i].auth_data.auth_key) {
			log_err("Could not allocate memory for authentication key\n");
			return -ENOMEM;
		}

		sa[i].auth_data.split_key =
					kzalloc(MAX_AUTH_KEY_LEN, GFP_KERNEL);
		if (!sa[i].auth_data.split_key) {
			log_err("Could not allocate memory for authentication split key\n");
			return -ENOMEM;
		}

		sa[i].from_sec_fq = kzalloc(sizeof(struct qman_fq), GFP_KERNEL);
		if (!sa[i].from_sec_fq) {
			log_err("Can't allocate space for 'from SEC FQ'\n");
			return -ENOMEM;
		}

		sa[i].to_sec_fq = kzalloc(sizeof(struct qman_fq), GFP_KERNEL);
		if (!sa[i].to_sec_fq) {
			log_err("Can't allocate space for 'to SEC FQ'\n");
			return -ENOMEM;
		}

		/*
		 * Allocate space for the SEC descriptor which is holding the
		 * preheader information and the share descriptor.
		 * Required 64 byte align.
		 */
		sa[i].sec_desc_unaligned =
			kzalloc(sizeof(struct sec_descriptor) + 64, GFP_KERNEL);
		if (!sa[i].sec_desc_unaligned) {
			log_err("Could not allocate memory for SEC descriptor\n");
			return -ENOMEM;
		}
		sa[i].sec_desc = PTR_ALIGN(sa[i].sec_desc_unaligned, 64);

		/* Allocate space for extra material space in case when the
		 * descriptor is greater than 64 words */
		sa[i].sec_desc_extra_cmds_unaligned =
			kzalloc(2 * MAX_EXTRA_DESC_COMMANDS + L1_CACHE_BYTES,
				GFP_KERNEL);
		if (!sa[i].sec_desc_extra_cmds_unaligned) {
			log_err("Allocation failed for CAAM extra commands\n");
			return -ENOMEM;
		}
		sa[i].sec_desc_extra_cmds =
				PTR_ALIGN(sa[i].sec_desc_extra_cmds_unaligned,
					  L1_CACHE_BYTES);
		if (sa[i].sec_desc_extra_cmds_unaligned ==
		    sa[i].sec_desc_extra_cmds)
			sa[i].sec_desc_extra_cmds += L1_CACHE_BYTES / 4;

		/*
		 * Allocate space for the SEC replacement job descriptor
		 * Required 64 byte alignment
		 */
		sa[i].rjob_desc_unaligned =
			kzalloc(MAX_CAAM_DESCSIZE * sizeof(uint32_t) + 64,
				GFP_KERNEL);
		if (!sa[i].rjob_desc_unaligned) {
			log_err("No memory for replacement job descriptor\n");
			return -ENOMEM;
		}
		sa[i].rjob_desc = PTR_ALIGN(sa[i].rjob_desc_unaligned, 64);

		/*
		 * Initialize the policy parameter list which will hold all
		 * inbound or outbound policy parameters which were use to
		 * generate PCD entries
		 */
		INIT_LIST_HEAD(&sa[i].policy_headlist);

		/* init the inbound SA lookup table desc with an invalid value*/
		sa[i].inbound_sa_td = DPA_OFFLD_DESC_NONE;
		sa[i].used_sa_index = -1;
	}

	/*
	 * Inbound flow id circular queue is required only if a valid index
	 * table is set.
	 */
	if (!ignore_post_ipsec_action(dpa_ipsec)) {
		err = create_inbound_flowid_cq(dpa_ipsec);
		if (err < 0) {
			log_err("Could not create inbound policy flow id cq\n");
			return err;
		}
	} else {
		/* Not required */
		dpa_ipsec->sa_mng.inbound_flowid_cq = NULL;
	}

	/*
	 * If policy check is enabled than for every possible inbound SA create
	 * an Exact Match Table and link it to the Inbound Index Table
	 */
	if (dpa_ipsec->config.post_sec_in_params.do_pol_check == true) {
		struct inpol_tbl *pol_table;
		void *cc_node;

		/* calculate key size for policy verification tables */
		calc_in_pol_key_size(dpa_ipsec,
				     &dpa_ipsec->sa_mng.inpol_key_size);

		if (dpa_ipsec->sa_mng.inpol_key_size == 0) {
			log_err("Invalid argument: in policy table key size\n");
			return -EFAULT;
		}

		mutex_init(&sa_mng->inpol_tables_lock);

		mutex_lock(&sa_mng->inpol_tables_lock);
		for (i = 0; i < dpa_ipsec->config.max_sa_pairs; i++) {
			pol_table = kzalloc(sizeof(*pol_table), GFP_KERNEL);
			if (!pol_table) {
				log_err("Could not allocate memory for policy table");
				mutex_unlock(&sa_mng->inpol_tables_lock);
				return -ENOMEM;
			}

			/* create cc node for inbound policy */
			err = create_inpol_node(dpa_ipsec, &cc_node);
			if (err < 0) {
				log_err("Could not create cc node for EM table\n");
				kfree(pol_table);
				mutex_unlock(&sa_mng->inpol_tables_lock);
				return err;
			}
			pol_table->cc_node = cc_node;
			err = create_inpol_cls_tbl(dpa_ipsec,
						   cc_node,
						   &pol_table->td);
			if (err < 0) {
				log_err("Failed create in policy table\n");
				destroy_inpol_node(dpa_ipsec, cc_node);
				kfree(pol_table);
				mutex_unlock(&sa_mng->inpol_tables_lock);
				return err;
			}

			list_add(&pol_table->table_list,
				 &dpa_ipsec->sa_mng.inpol_tables);
		}
		mutex_unlock(&sa_mng->inpol_tables_lock);
	}

	/* Populate the list of IPSec manip node */
	mutex_lock(&sa_mng->ipsec_manip_node_lock);
	for (i = 0; i < dpa_ipsec->config.max_sa_manip_ops; i++) {
		struct ipsec_manip_node *node;
		node = kzalloc(sizeof(*node), GFP_KERNEL);
		if (!node) {
			log_err("Could not allocate memory for IPSec manip node\n");
			mutex_unlock(&sa_mng->ipsec_manip_node_lock);
			return -ENOMEM;
		}

		node->hm = alloc_ipsec_manip(dpa_ipsec);
		if (!node->hm) {
			log_err("Could not create IPSec manip node\n");
			kfree(node);
			mutex_unlock(&sa_mng->ipsec_manip_node_lock);
			return -ENOMEM;
		}

		node->used = false;
		list_add(&node->ipsec_manip_node_list,
			 &dpa_ipsec->sa_mng.ipsec_manip_node_list);

	}
	mutex_unlock(&sa_mng->ipsec_manip_node_lock);

	/* Initialize the SA rekeying list and its protective lock */
	INIT_LIST_HEAD(&dpa_ipsec->sa_mng.sa_rekeying_headlist);
	mutex_init(&sa_mng->sa_rekeying_headlist_lock);

	/*
	 * Creating a single thread work queue used to defer work when there are
	 * inbound SAs in rekeying process
	 */
	dpa_ipsec->sa_mng.sa_rekeying_wq =
		create_singlethread_workqueue("sa_rekeying_wq");
	if (!dpa_ipsec->sa_mng.sa_rekeying_wq) {
		log_err("Creating SA rekeying work queue failed\n");
		return -ENOSPC;
	}

	/* Initialize the work needed to be done rekeying inbound process */
	INIT_DELAYED_WORK(&dpa_ipsec->sa_mng.sa_rekeying_work,
			  sa_rekeying_work_func);

	return 0;
}

/* cleanup SA manager */
static void free_sa_mng(struct dpa_ipsec *dpa_ipsec)
{
	struct dpa_ipsec_sa_mng *sa_mng;
	struct inpol_tbl *pol_tbl, *tmp;
	struct list_head *head;
	struct list_head *pos, *n;
	struct ipsec_manip_node *node;
	int i = 0;

	/* sanity checks */
	if (!dpa_ipsec) {
		log_err("Invalid argument: NULL DPA IPSec instance\n");
		return;
	}

	sa_mng = (struct dpa_ipsec_sa_mng *)&dpa_ipsec->sa_mng;
	/* Remove the DPA IPsec created tables for policy verification */
	if (dpa_ipsec->config.post_sec_in_params.do_pol_check) {
		head = &sa_mng->inpol_tables;
		list_for_each_entry_safe(pol_tbl, tmp, head, table_list) {
			destroy_inpol_cls_tbl(pol_tbl->td);
			list_del(&pol_tbl->table_list);
			destroy_inpol_node(dpa_ipsec, pol_tbl->cc_node);
			kfree(pol_tbl);
		}
	}

	/* dealloc cipher/auth stuff */
	if (sa_mng->sa) {
		for (i = 0; i < sa_mng->max_num_sa; i++) {
			kfree(sa_mng->sa[i].cipher_data.cipher_key);
			sa_mng->sa[i].cipher_data.cipher_key = NULL;

			kfree(sa_mng->sa[i].auth_data.auth_key);
			sa_mng->sa[i].auth_data.auth_key = NULL;

			kfree(sa_mng->sa[i].auth_data.split_key);
			sa_mng->sa[i].auth_data.split_key = NULL;

			kfree(sa_mng->sa[i].from_sec_fq);
			sa_mng->sa[i].from_sec_fq = NULL;

			kfree(sa_mng->sa[i].to_sec_fq);
			sa_mng->sa[i].to_sec_fq = NULL;

			kfree(sa_mng->sa[i].sec_desc_unaligned);
			sa_mng->sa[i].sec_desc_unaligned = NULL;
			sa_mng->sa[i].sec_desc = NULL;

			kfree(sa_mng->sa[i].sec_desc_extra_cmds_unaligned);
			sa_mng->sa[i].sec_desc_extra_cmds_unaligned = NULL;

			kfree(sa_mng->sa[i].rjob_desc_unaligned);
			sa_mng->sa[i].rjob_desc_unaligned = NULL;

			mutex_destroy(&sa_mng->sa[i].lock);
		}

		kfree(sa_mng->sa);
		sa_mng->sa = NULL;
	}

	/* release SA ID management CQ */
	if (sa_mng->sa_id_cq) {
		cq_delete(sa_mng->sa_id_cq);
		sa_mng->sa_id_cq = NULL;
	}

	/* destroy fqid management CQ */
	destroy_fqid_cq(dpa_ipsec);

	/* release inbound flow ID management CQ */
	destroy_inbound_flowid_cq(dpa_ipsec->sa_mng.inbound_flowid_cq);
	dpa_ipsec->sa_mng.inbound_flowid_cq = NULL;

	/* destroy rekeying workqueue */
	if (sa_mng->sa_rekeying_wq) {
		destroy_workqueue(sa_mng->sa_rekeying_wq);
		sa_mng->sa_rekeying_wq = NULL;
	}

	/* cleanup hmanips */
	list_for_each_safe(pos, n, &dpa_ipsec->sa_mng.ipsec_manip_node_list) {
		node = container_of(pos, struct ipsec_manip_node,
				    ipsec_manip_node_list);
		list_del(&node->ipsec_manip_node_list);
		kfree(node->hm);
		kfree(node);
	}

	mutex_destroy(&sa_mng->inpol_tables_lock);
	mutex_destroy(&sa_mng->sa_rekeying_headlist_lock);
	mutex_destroy(&sa_mng->ipsec_manip_node_lock);

}

/* Cleanup for DPA IPsec instance */
static void free_resources(int dpa_ipsec_id)
{
	struct dpa_ipsec *dpa_ipsec;

	BUG_ON(dpa_ipsec_id < 0 || dpa_ipsec_id >= MAX_DPA_IPSEC_INSTANCES);

	dpa_ipsec = gbl_dpa_ipsec[dpa_ipsec_id];

	/* free all SA related stuff */
	free_sa_mng(dpa_ipsec);

	kfree(dpa_ipsec->used_sa_ids);

	mutex_destroy(&dpa_ipsec->lock);
	kfree(dpa_ipsec);

	mark_unused_gbl_dpa_ipsec(dpa_ipsec_id);
}

/* Runtime functions */

/* Convert prefixLen into IP address's netmask. */
static int set_ip_addr_mask(uint8_t *mask, uint8_t prefix_len,
			     uint8_t mask_len)
{
	static const uint8_t mask_bits[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8,
					    0xfc, 0xfe, 0xff};
	uint8_t bit, off;

	BUG_ON(!mask);

	off = prefix_len / 8;
	bit = prefix_len % 8;
	while (off--)
		*mask++ = 0xff;
	if (bit)
		*mask = mask_bits[bit];

	return 0;
}

static int set_flow_id_action(struct dpa_ipsec_sa *sa,
			      struct dpa_cls_tbl_action *action)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_offload_lookup_key tbl_key;
	struct dpa_cls_tbl_entry_mod_params mod_params;
	int table, err;
	uint8_t key_data;

	BUG_ON(!sa);
	BUG_ON(!action);

	dpa_ipsec = sa->dpa_ipsec;

	/* Currently the flowid cannot be greater than 255 */
	key_data	= (uint8_t)sa->inbound_flowid;

	memset(&tbl_key, 0, sizeof(tbl_key));
	tbl_key.byte	= &key_data;
	tbl_key.mask	= NULL;
	tbl_key.size	= sizeof(uint8_t);

	memset(&mod_params, 0, sizeof(mod_params));
	mod_params.action = action;
	mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;
	table = dpa_ipsec->config.post_sec_in_params.dpa_cls_td;
	err = dpa_classif_table_modify_entry_by_key(table, &tbl_key,
						    &mod_params);
	if (err < 0) {
		log_err("Couldn't set flowID action for SA id %d\n", sa->id);
		return err;
	}
	sa->valid_flowid_entry = true;

	return 0;
}

static inline void fill_dscp_field(struct dpa_ipsec_policy_params *pol_params,
				  uint8_t *key, uint8_t *mask, uint8_t *offset,
				  uint8_t dscp)
{
	uint16_t mask_val = 0xFC;
	uint16_t dscp_val;
	switch (pol_params->src_addr.version) {
	case DPA_IPSEC_ADDR_T_IPv4:
		if (pol_params->use_dscp) {
			*(uint8_t *)(key + *offset) = dscp << 2;
			SET_BYTE_VAL_IN_ARRAY(mask, *offset, mask_val);
		} else {
			*(uint8_t *)(key + *offset) = 0;
			SET_BYTE_VAL_IN_ARRAY(mask, *offset, 0);
		}
		*offset += DSCP_FIELD_LEN_IPv4;
		break;
	case DPA_IPSEC_ADDR_T_IPv6:
		/*
		 * In order to extract Traffic Class in case of IPv6, the keygen
		 * will add two bytes to the key, which hold: IPv6 version (4
		 * bits), TC (8 bits) and 4 bits zero.
		 */
		dscp_val = dscp << 6;
		mask_val = mask_val << 4;
		if (pol_params->use_dscp) {
			memcpy(key + *offset, &dscp_val, DSCP_FIELD_LEN_IPv6);
			memcpy(mask + *offset, &mask_val, DSCP_FIELD_LEN_IPv6);
		} else {
			memset(key + *offset, 0, DSCP_FIELD_LEN_IPv6);
			memset(mask + *offset, 0, DSCP_FIELD_LEN_IPv6);
		}
		*offset += DSCP_FIELD_LEN_IPv6;
		break;
	default:
		break;
	}
}

static int fill_policy_key(int td,
			   struct dpa_ipsec_policy_params *pol_params,
			   uint8_t key_fields,
			   uint8_t *key, uint8_t *mask, uint8_t *key_len,
			   uint8_t dscp_value)
{
	struct dpa_cls_tbl_params tbl_params;
	uint8_t offset = 0, field_mask = 0, tbl_key_size = 0;
	int err = 0, i;

	BUG_ON(!pol_params);
	BUG_ON(!key);
	BUG_ON(!mask);
	BUG_ON(!key_len);

	/* Fill in the key components */
	for (i = 0; i < DPA_IPSEC_MAX_KEY_FIELDS; i++) {
		field_mask = (uint8_t) (1 << i);
		switch (key_fields & field_mask) {
		case DPA_IPSEC_KEY_FIELD_SIP:
			memcpy(key + offset,
			       IP_ADDR(pol_params->src_addr),
			       IP_ADDR_LEN(pol_params->src_addr));
			err = set_ip_addr_mask(mask + offset,
					     pol_params->src_prefix_len,
					     IP_ADDR_LEN(pol_params->src_addr));
			if (err < 0)
				return err;
			offset += IP_ADDR_LEN(pol_params->src_addr);
			break;

		case DPA_IPSEC_KEY_FIELD_DIP:
			memcpy(key + offset,
			       IP_ADDR(pol_params->dest_addr),
			       IP_ADDR_LEN(pol_params->dest_addr));
			err = set_ip_addr_mask(mask + offset,
					    pol_params->dest_prefix_len,
					    IP_ADDR_LEN(pol_params->dest_addr));
			if (err < 0)
				return err;
			offset += IP_ADDR_LEN(pol_params->dest_addr);
			break;

		case DPA_IPSEC_KEY_FIELD_PROTO:
		      SET_BYTE_VAL_IN_ARRAY(key, offset, pol_params->protocol);
		      SET_IP_PROTO_MASK(mask, offset, pol_params->masked_proto);
			offset += IP_PROTO_FIELD_LEN;
			break;

		/* case DPA_IPSEC_KEY_FIELD_ICMP_TYPE: */
		case DPA_IPSEC_KEY_FIELD_SPORT:
			if ((pol_params->protocol == IPPROTO_ICMP) ||
			   (pol_params->protocol == IPPROTO_ICMPV6)) {
				SET_BYTE_VAL_IN_ARRAY(key, offset,
						    pol_params->icmp.icmp_type);
				SET_BYTE_VAL_IN_ARRAY(mask, offset,
					       pol_params->icmp.icmp_type_mask);
				offset += ICMP_HDR_FIELD_LEN;
			} else {
				memcpy(key + offset,
				       (uint8_t *) &(pol_params->l4.src_port),
				       PORT_FIELD_LEN);
				SET_L4_PORT_MASK(mask, offset,
						 pol_params->l4.src_port_mask);
				offset += PORT_FIELD_LEN;
			}
			break;

		/* case DPA_IPSEC_KEY_FIELD_ICMP_CODE: */
		case DPA_IPSEC_KEY_FIELD_DPORT:
			if ((pol_params->protocol == IPPROTO_ICMP) ||
			   (pol_params->protocol == IPPROTO_ICMPV6)) {
				SET_BYTE_VAL_IN_ARRAY(key, offset,
						    pol_params->icmp.icmp_code);
				SET_BYTE_VAL_IN_ARRAY(mask, offset,
					       pol_params->icmp.icmp_code_mask);
				offset += ICMP_HDR_FIELD_LEN;
			} else {
				memcpy(key + offset,
				       (uint8_t *) &(pol_params->l4.dest_port),
				       PORT_FIELD_LEN);
				SET_L4_PORT_MASK(mask, offset,
						 pol_params->l4.dest_port_mask);
				offset += PORT_FIELD_LEN;
			}
			break;

		case DPA_IPSEC_KEY_FIELD_DSCP:
			fill_dscp_field(pol_params, key, mask, &offset,
					dscp_value);
			break;
		}
	}

	/*
	 * Add padding to compensate difference in size between table maximum
	 * key size and computed key size.
	 */

	/* get table params (including maximum key size) */
	err = dpa_classif_table_get_params(td, &tbl_params);
	if (err < 0) {
		log_err("Could not retrieve table maximum key size\n");
		return -EINVAL;
	}
	tbl_key_size = TABLE_KEY_SIZE(tbl_params);

	if (tbl_key_size < offset) {
		log_err("Policy key is greater than maximum table key size\n");
		return -EINVAL;
	}

	if (tbl_key_size > offset) {
		for (i = 0; i < tbl_key_size - offset; i++) {
			*(key + offset + i) = DPA_IPSEC_DEF_PAD_VAL;
			/* ignore padding during classification (mask it) */
			*(mask + offset + i) = 0x00;
		}
		offset = tbl_key_size;
	}

	/* Store key length */
	*key_len = offset;

	return 0;
}

/*
 * fill dpa_cls_action structure with common values
 * if new_fqid = 0, the FQID will not be overridden
 */
static inline void fill_cls_action_enq(struct dpa_cls_tbl_action *action_prm,
				       int en_stats, uint32_t new_fqid,
				       int hmd)
{
	action_prm->type = DPA_CLS_TBL_ACTION_ENQ;
	action_prm->enable_statistics = en_stats;
	if (new_fqid != 0) {
		action_prm->enq_params.new_fqid = new_fqid;
		action_prm->enq_params.override_fqid = true;
	} else
		action_prm->enq_params.override_fqid = FALSE;
	action_prm->enq_params.policer_params = NULL;
	action_prm->enq_params.hmd = hmd;
}

static inline void fill_cls_action_drop(struct dpa_cls_tbl_action *action,
					int en_stats)
{
	memset(action, 0, sizeof(struct dpa_cls_tbl_action));
	action->type = DPA_CLS_TBL_ACTION_DROP;
	action->enable_statistics = en_stats;
}

/* Used at runtime when preallocation of IPSec manip node is not enabled */
static int create_ipsec_manip(struct dpa_ipsec_sa *sa, int next_hmd, int *hmd)
{
	t_FmPcdManipParams pcd_manip_params;
	t_FmPcdManipSpecialOffloadParams *offld_params;
	t_Handle hm;
	int err;

	BUG_ON(!sa);
	BUG_ON(!hmd);

	if (!sa->use_var_iphdr_len && !sa->dscp_copy && !sa->ecn_copy &&
	    !(sa_is_outbound(sa) && sa->enable_dpovrd)) {
		/* no need to create a new manipulation objects chain */
		*hmd = next_hmd;
		return 0;
	}

	memset(&pcd_manip_params, 0, sizeof(struct t_FmPcdManipParams));
	pcd_manip_params.type = e_FM_PCD_MANIP_SPECIAL_OFFLOAD;
	offld_params = &pcd_manip_params.u.specialOffload;
	offld_params->type = e_FM_PCD_MANIP_SPECIAL_OFFLOAD_IPSEC;
	if (sa_is_inbound(sa)) {
		offld_params->u.ipsec.decryption = true;
		offld_params->u.ipsec.variableIpHdrLen = sa->use_var_iphdr_len;
	} else {
		offld_params->u.ipsec.variableIpVersion = true;
		offld_params->u.ipsec.outerIPHdrLen = (uint8_t)
				caam16_to_cpu(sa->sec_desc->pdb_en.ip_hdr_len);
	}
	offld_params->u.ipsec.ecnCopy = sa->ecn_copy;
	offld_params->u.ipsec.dscpCopy = sa->dscp_copy;

	pcd_manip_params.h_NextManip = dpa_classif_hm_lock_chain(next_hmd);
	dpa_classif_hm_release_chain(next_hmd);

	hm = FM_PCD_ManipNodeSet(sa->dpa_ipsec->config.fm_pcd,
				 &pcd_manip_params);
	if (!hm) {
		log_err("%s: FM_PCD_ManipNodeSet failed!\n", __func__);
		return -EBUSY;
	}

	err = dpa_classif_import_static_hm(hm, next_hmd, hmd);
	if (err < 0)
		log_err("Failed to import header manipulation into DPA Classifier.\n");

	return err;
}

/*
 * If preallocation of IPSec manip node(s) was specified the code is using this
 * function to allocate and populate the list of IPSec manip objects
 */
static void *alloc_ipsec_manip(struct dpa_ipsec *dpa_ipsec)
{
	t_FmPcdManipParams pcd_manip_params;
	t_FmPcdManipSpecialOffloadParams *offld_params;
	t_Handle hm;

	BUG_ON(!dpa_ipsec);

	memset(&pcd_manip_params, 0, sizeof(struct t_FmPcdManipParams));
	pcd_manip_params.type = e_FM_PCD_MANIP_SPECIAL_OFFLOAD;
	offld_params = &pcd_manip_params.u.specialOffload;
	offld_params->type = e_FM_PCD_MANIP_SPECIAL_OFFLOAD_IPSEC;
	offld_params->u.ipsec.decryption = true;
	offld_params->u.ipsec.variableIpHdrLen = false;
	offld_params->u.ipsec.ecnCopy = false;
	offld_params->u.ipsec.dscpCopy = false;
	offld_params->u.ipsec.variableIpVersion = false;
	offld_params->u.ipsec.outerIPHdrLen = 0;
	pcd_manip_params.h_NextManip = NULL;

	hm = FM_PCD_ManipNodeSet(dpa_ipsec->config.fm_pcd, &pcd_manip_params);
	if (!hm) {
		log_err("%s: FM_PCD_ManipSetNode failed!\n", __func__);
		return NULL;
	}

	return hm;
}

/* Used at runtime when preallocation of IPSec manip nodes was enabled */
static int update_ipsec_manip(struct dpa_ipsec_sa *sa, int next_hmd, int *hmd)
{
	t_FmPcdManipParams pcd_manip_params;
	t_FmPcdManipSpecialOffloadParams *offld_params;
	t_Handle ipsec_hm = NULL, new_hm = NULL;
	t_Error err;
	int ret;

	BUG_ON(!sa);
	BUG_ON(!hmd);

	if (!sa->use_var_iphdr_len && !sa->dscp_copy && !sa->ecn_copy &&
	    !(sa_is_outbound(sa) && sa->enable_dpovrd)) {
		/* no need to create a new manipulation objects chain */
		*hmd = next_hmd;
		return 0;
	}

	memset(&pcd_manip_params, 0, sizeof(struct t_FmPcdManipParams));
	pcd_manip_params.type = e_FM_PCD_MANIP_SPECIAL_OFFLOAD;
	offld_params = &pcd_manip_params.u.specialOffload;
	offld_params->type = e_FM_PCD_MANIP_SPECIAL_OFFLOAD_IPSEC;
	if (sa_is_inbound(sa)) {
		offld_params->u.ipsec.decryption = true;
		offld_params->u.ipsec.variableIpHdrLen = sa->use_var_iphdr_len;
	} else {
		offld_params->u.ipsec.variableIpVersion = true;
		offld_params->u.ipsec.outerIPHdrLen = (uint8_t)
				caam16_to_cpu(sa->sec_desc->pdb_en.ip_hdr_len);
	}
	offld_params->u.ipsec.ecnCopy = sa->ecn_copy;
	offld_params->u.ipsec.dscpCopy = sa->dscp_copy;

	pcd_manip_params.h_NextManip = dpa_classif_hm_lock_chain(next_hmd);
	dpa_classif_hm_release_chain(next_hmd);

	ret = get_free_ipsec_manip_node(sa->dpa_ipsec, &ipsec_hm);
	if (ret < 0) {
		log_err("%s: get_free_ipsec_manip_node failed for %s SA %d!\n",
			__func__, sa_is_inbound(sa) ?
			"inbound" : "outbound", sa->id);
		return ret;
	}

	/* Should not be NULL */
	BUG_ON(!ipsec_hm);

	new_hm = FM_PCD_ManipNodeSet(sa->dpa_ipsec->config.fm_pcd,
				     &pcd_manip_params);
	if (!new_hm) {
		log_err("%s: FM_PCD_ManipSetNode failed!\n", __func__);
		put_free_ipsec_manip_node(sa->dpa_ipsec, ipsec_hm);
		return -EBUSY;
	}

	replace_ipsec_manip_node(sa->dpa_ipsec, ipsec_hm, new_hm);

	err = FM_PCD_ManipNodeDelete(ipsec_hm);
	if (err != E_OK) {
		log_err("%s: FM_PCD_ManipNodeDelete failed for %s SA %d!\n",
			__func__, sa_is_inbound(sa) ?
			"inbound" : "outbound", sa->id);
		put_free_ipsec_manip_node(sa->dpa_ipsec, new_hm);
		return -EBUSY;
	}

	ret = dpa_classif_import_static_hm(new_hm, next_hmd, hmd);
	if (ret < 0) {
		log_err("Failed to import header manipulation into DPA Classifier.\n");
		put_free_ipsec_manip_node(sa->dpa_ipsec, new_hm);
	}

	return ret;
}

/* Destroy the DPA IPSec Special header manip or put it in the pool */
static int destroy_recycle_manip(struct dpa_ipsec_sa *sa,
				 struct hmd_entry *entry)
{
	t_Handle hm;
	int hmd, err = 0;

	BUG_ON(!sa);
	BUG_ON(!entry);

	hmd = entry->hmd;
	BUG_ON(hmd == DPA_OFFLD_DESC_NONE);

	hm = dpa_classif_get_static_hm_handle(hmd);
	BUG_ON(!hm);

	if (sa->dpa_ipsec->config.max_sa_manip_ops > 0)
		/* return to pool */
		put_free_ipsec_manip_node(sa->dpa_ipsec, hm);

	err = dpa_classif_free_hm(hmd);
	if (err < 0) {
		log_err("%s: Failed to remove header manip!\n", __func__);
		return err;
	}

	if (entry->hmd_special_op) {
		/*
		 * Destroy only the IPSec special operation that was created
		 * inside IPSec
		 */
		err = FM_PCD_ManipNodeDelete(hm);
		if (err != E_OK) {
			log_err("%s: FM_PCD_ManipNodeDelete failed for SA %d!\n",
				__func__, sa->id);
			return -EBUSY;
		}
	}

	return 0;
}

static int update_inbound_policy(struct dpa_ipsec_sa *sa,
				 struct dpa_ipsec_policy_entry *policy_entry,
				 enum mng_op_type op_type)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_policy_params *pol_params;
	uint8_t key_len;
	struct dpa_cls_tbl_action *action;
	struct dpa_offload_lookup_key tbl_key;
	uint8_t key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	int entry_id, err;

	BUG_ON(!sa);
	BUG_ON(!policy_entry);

	memset(key_data, 0, DPA_OFFLD_MAXENTRYKEYSIZE);
	memset(mask_data, 0, DPA_OFFLD_MAXENTRYKEYSIZE);
	if (sa->em_inpol_td < 0) {
		log_err("Invalid exact match table for SA %d.\n", sa->id);
		return -EINVAL;
	}

	dpa_ipsec = sa->dpa_ipsec;
	BUG_ON(!dpa_ipsec);
	pol_params = &policy_entry->pol_params;

	switch (op_type) {
	case MNG_OP_ADD:
		tbl_key.byte = key_data;
		tbl_key.mask = mask_data;

		/*
		 * Key contains:
		 * IP SRC ADDR	- from Policy handle
		 * IP DST ADDR	- from Policy handle
		 * IP_PROTO	- from Policy handle
		 * SRC_PORT	- from Policy handle (for UDP & TCP)
		 * DST_PORT	- from Policy handle (for UDP & TCP)
		 */
		err = fill_policy_key(sa->em_inpol_td,
				      pol_params,
				      dpa_ipsec->config.post_sec_in_params.
				      key_fields, tbl_key.byte, tbl_key.mask,
				      &key_len, 0);
		if (err < 0)
			return err;

		tbl_key.size = key_len;

		if (pol_params->dir_params.type == DPA_IPSEC_POL_DIR_PARAMS_ACT)
			action = &pol_params->dir_params.in_action;
		else
			action = &sa->def_sa_action;
		err = dpa_classif_table_insert_entry(sa->em_inpol_td, &tbl_key,
					      action,
					      policy_entry->pol_params.priority,
					      &entry_id);
		if (err < 0) {
			log_err("Could not insert key in EM table\n");
			return err;
		}
		*policy_entry->entry_id = entry_id;
		break;
	case MNG_OP_REMOVE:
		entry_id = *policy_entry->entry_id;
		err = dpa_classif_table_delete_entry_by_ref(sa->em_inpol_td,
							    entry_id);
		if (err < 0) {
			log_err("Could not remove key in EM table\n");
			return err;
		}
		break;
	case MNG_OP_MODIFY:
		log_err("Modify operation unsupported for IN Policy PCD\n");
		return -EINVAL;
	}

	return 0;
}

static inline int remove_dscp_policy(struct dpa_ipsec_sa *sa,
				     struct dpa_ipsec_policy_entry *pol_entry,
				     int table)
{
	int dscp_idx = 0, err = 0, ret = 0;
	do {
		ret = dpa_classif_table_delete_entry_by_ref(
						table,
						pol_entry->entry_id[dscp_idx]);
		if (ret < 0) {
			log_err("Cannot remove key from EM table\n");
			err = ret;
		}
		dscp_idx += 1;
	} while (dscp_idx <= sa->dscp_end - sa->dscp_start);

	return err;
}

static int update_outbound_policy(struct dpa_ipsec_sa *sa,
				  struct dpa_ipsec_policy_entry *policy_entry,
				  enum mng_op_type op_type)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_pre_sec_out_params *pre_sec_out_params;
	struct dpa_ipsec_policy_params *pol_params;
	uint8_t key_len, table_idx, key_fields, dscp_value;
	struct dpa_offload_lookup_key tbl_key;
	struct dpa_cls_tbl_action action;
	struct dpa_cls_tbl_entry_mod_params params;
	int table, err, dscp_idx = 0;
	int manip_hmd = DPA_OFFLD_DESC_NONE, pol_hmd = DPA_OFFLD_DESC_NONE;
	uint8_t key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];

	BUG_ON(!sa);
	BUG_ON(!policy_entry);

	memset(key_data, 0, DPA_OFFLD_MAXENTRYKEYSIZE);
	memset(mask_data, 0, DPA_OFFLD_MAXENTRYKEYSIZE);
	dpa_ipsec = sa->dpa_ipsec;
	BUG_ON(!dpa_ipsec);
	pre_sec_out_params = &dpa_ipsec->config.pre_sec_out_params;

	pol_params = &policy_entry->pol_params;
	if (IP_ADDR_TYPE_IPV4(pol_params->dest_addr))
		table_idx = GET_POL_TABLE_IDX(pol_params->protocol, IPV4);
	else
		table_idx = GET_POL_TABLE_IDX(pol_params->protocol, IPV6);
	table = pre_sec_out_params->table[table_idx].dpa_cls_td;
	key_fields = pre_sec_out_params->table[table_idx].key_fields;

	/*
	 * check if a valid desc for a proto specific table or an ANY table was
	 * provided
	 */
	if (table == DPA_OFFLD_DESC_NONE) {
		log_err("No suitable table found for this policy type!\n");
		return -EBADF;
	}

	switch (op_type) {
	case MNG_OP_ADD:
		dscp_value = sa->dscp_start;
		tbl_key.byte = key_data;
		tbl_key.mask = mask_data;

		/* Configure fragmentation */
		if (pol_params->dir_params.type ==
					DPA_IPSEC_POL_DIR_PARAMS_MANIP) {
			manip_hmd = pol_params->dir_params.manip_desc;
			/*
			 * check_policy_params validated manip descriptor
			 */
			BUG_ON(manip_hmd < 0);
		}

		/* Init IPSec Manip. object (if required) for outbound policy */
		if (manip_hmd == DPA_OFFLD_DESC_NONE)
			goto no_frag_or_manip;

		/* need to chain the IPSec Manip and Frag/Manip */
		if (sa->dpa_ipsec->config.max_sa_manip_ops == 0)
			err = create_ipsec_manip(sa, manip_hmd,
						 &policy_entry->hmd);
		else
			err = update_ipsec_manip(sa, manip_hmd,
						 &policy_entry->hmd);
		if (err < 0) {
			log_err("Couldn't create policy manip chain!\n");
			return err;
		}

		pol_hmd = policy_entry->hmd;
		if (pol_hmd == manip_hmd)
			policy_entry->hmd_special_op = false;
		else
			policy_entry->hmd_special_op = true;

		goto set_manipulation;

no_frag_or_manip:
		if (sa->ipsec_hmd == DPA_OFFLD_DESC_NONE) {
			/*
			 * need to create the IPSec Manip (per SA),
			 * if it was not created earlier
			 */
			if (sa->dpa_ipsec->config.max_sa_manip_ops == 0)
				err = create_ipsec_manip(sa,
							 DPA_OFFLD_DESC_NONE,
							 &sa->ipsec_hmd);
			else
				err = update_ipsec_manip(sa,
							 DPA_OFFLD_DESC_NONE,
							 &sa->ipsec_hmd);
			if (err < 0) {
				log_err("Couldn't create SA manip!\n");
				return err;
			}
		}
		pol_hmd = sa->ipsec_hmd;

set_manipulation:
		memset(&action, 0, sizeof(action));
		fill_cls_action_enq(&action,
				    sa->enable_extended_stats ? true : false,
				    qman_fq_fqid(sa->to_sec_fq), pol_hmd);
		/*
		 * Key may contain:
		 * IP SRC ADDR  - from Policy handle
		 * IP DST ADDR  - from Policy handle
		 * IP_PROTO     - from Policy handle
		 * DSCP         - from Policy handle
		 * SRC_PORT     - from Policy handle (for UDP & TCP & SCTP)
		 * DST_PORT     - from Policy handle (for UDP & TCP & SCTP)
		 */

		/*
		 * If SA per DSCP feature is disabled only one key is inserted
		 * and then will go out
		 */
		if (!pol_params->use_dscp) {
			err = fill_policy_key(table, pol_params, key_fields,
					      tbl_key.byte, tbl_key.mask,
					      &key_len, 0);
			if (err < 0)
				return err;

			tbl_key.size = key_len;

			err = dpa_classif_table_insert_entry(table, &tbl_key,
					&action,
					policy_entry->pol_params.priority,
					&policy_entry->entry_id[dscp_idx]);
			if (err < 0) {
				log_err("Could not add key in exact match table\n");
				return err;
			}
			break;
		}

		/*
		 * In case the SA per DSCP feature will be used, it will iterate
		 * through all DSCP values and insert a key for each one.
		 */
		do {
			err = fill_policy_key(table, pol_params, key_fields,
					      tbl_key.byte, tbl_key.mask,
					      &key_len, dscp_value);
			if (err < 0)
				return err;

			tbl_key.size = key_len;

			err = dpa_classif_table_insert_entry(table, &tbl_key,
					&action,
					policy_entry->pol_params.priority,
					&policy_entry->entry_id[dscp_idx]);
			if (err < 0) {
				log_err("Could not add key in exact match table\n");
				return err;
			}

			dscp_value += 1;
			dscp_idx += 1;
		} while (dscp_value <= sa->dscp_end);

		break;
	case MNG_OP_REMOVE:
		if (pol_params->use_dscp) {
			err = remove_dscp_policy(sa, policy_entry, table);
			if (err < 0)
				return err;

		} else {
			err = dpa_classif_table_delete_entry_by_ref(table,
					*policy_entry->entry_id);
			if (err < 0) {
				log_err("Could not remove key from EM table\n");
				return err;
			}
		}

		if (policy_entry->hmd != DPA_OFFLD_DESC_NONE) {
			struct hmd_entry hmd_entry;
			hmd_entry.hmd = policy_entry->hmd;
			hmd_entry.hmd_special_op = policy_entry->hmd_special_op;
			err = destroy_recycle_manip(sa, &hmd_entry);
			if (err < 0) {
				log_err("Couldn't delete frag & ipsec manip\n");
				return err;
			}
			policy_entry->hmd = DPA_OFFLD_DESC_NONE;
		}

		break;
	case MNG_OP_MODIFY:
		if (policy_entry->hmd != DPA_OFFLD_DESC_NONE)
			pol_hmd = policy_entry->hmd;
		else
			pol_hmd = sa->ipsec_hmd;

		memset(&action, 0, sizeof(action));
		fill_cls_action_enq(&action,
				    sa->enable_extended_stats ? true : false,
				    qman_fq_fqid(sa->to_sec_fq), pol_hmd);

		memset(&params, 0, sizeof(params));
		params.type = DPA_CLS_TBL_MODIFY_ACTION;
		params.key = NULL;
		params.action = &action;

		err = dpa_classif_table_modify_entry_by_ref(table,
							*policy_entry->entry_id,
							&params);
		if (err < 0) {
			log_err("Could not modify key in EM table\n");
			return err;
		}
		break;
	}

	return 0;
}

static int update_pre_sec_inbound_table(struct dpa_ipsec_sa *sa,
					enum mng_op_type op_type)
{
	struct dpa_ipsec *dpa_ipsec;
	int table, table_idx, entry_id, offset, err = 0, tbl_key_size = 0, i;
	struct dpa_offload_lookup_key tbl_key;
	struct dpa_cls_tbl_action action;
	struct dpa_cls_tbl_params tbl_params;
	struct dpa_cls_tbl_entry_mod_params mod_params;
	uint8_t key[DPA_OFFLD_MAXENTRYKEYSIZE];

	BUG_ON(!sa);

	dpa_ipsec = sa->dpa_ipsec;
	BUG_ON(!dpa_ipsec);

	switch (op_type) {
	case MNG_OP_ADD:
		/* Determine the correct table to be used for this type of SA */
		table_idx = GET_SA_TABLE_IDX(sa->dest_addr, sa->use_udp_encap);
		table =
		      dpa_ipsec->config.pre_sec_in_params.dpa_cls_td[table_idx];
		if (table == DPA_OFFLD_DESC_NONE) {
			log_err("No SA table defined for this type of SA\n");
			return -EBADF;
		}

		/* Store the table descriptor to be used in subsequent ops */
		sa->inbound_sa_td = table;

		/*
		 * Mark classifier entry id as invalid until it's properly
		 * inserted
		 */
		sa->inbound_hash_entry = DPA_OFFLD_INVALID_OBJECT_ID;
		sa->valid_flowid_entry = false;

		tbl_key.byte = key;
		/* Key masks are not supported by HASH tables*/
		tbl_key.mask = NULL;

		/*
		 * Key contains:
		 * IP DST ADDR  - from SA handle
		 * IP_PROTO     - always ESP (SEC limitation)
		 * UDP_SPORT    - in case of UDP encapsulated ESP
		 * UDP_DPORT    - in case of UDP encapsulated ESP
		 * SPI          - from SA handle
		 */

		/* Fill in the key components */
		memcpy(key, IP_ADDR(sa->dest_addr), IP_ADDR_LEN(sa->dest_addr));

		offset = IP_ADDR_LEN(sa->dest_addr);
		if (sa->use_udp_encap) {
			SET_BYTE_VAL_IN_ARRAY(key, offset, IPPROTO_UDP);
			offset += IP_PROTO_FIELD_LEN;
			memcpy(key + offset, (uint8_t *) &(sa->udp_src_port),
			       PORT_FIELD_LEN);
			offset += PORT_FIELD_LEN;
			memcpy(key + offset, (uint8_t *) &(sa->udp_dest_port),
			       PORT_FIELD_LEN);
			offset += PORT_FIELD_LEN;
		} else {
			SET_BYTE_VAL_IN_ARRAY(key, offset, IPPROTO_ESP);
			offset += IP_PROTO_FIELD_LEN;
		}

		*(uint32_t *)(key + offset) = cpu_to_be32(sa->spi);
		offset += sizeof(sa->spi);

		/* determine padding length based on the table params */
		err = dpa_classif_table_get_params(table, &tbl_params);
		if (err < 0) {
			log_err("Could not get table maximum key size\n");
			return err;
		}
		tbl_key_size = TABLE_KEY_SIZE(tbl_params);

		if (tbl_key_size < offset) {
			log_err("SA lookup key is greater than maximum table key size\n");
			return -EINVAL;
		}

		if (tbl_key_size > offset) {
			for (i = 0; i < tbl_key_size - offset; i++)
				*(key + offset + i) = DPA_IPSEC_DEF_PAD_VAL;
			offset = tbl_key_size;
		}

		/* Key size cannot be greater than 56 bytes */
		tbl_key.size = (uint8_t)offset;

		/* Complete the parameters for table insert function */
		memset(&action, 0, sizeof(action));
		fill_cls_action_enq(&action,
			sa->enable_extended_stats ? true : false,
			qman_fq_fqid(sa->to_sec_fq), sa->ipsec_hmd);

		err = dpa_classif_table_insert_entry(table, &tbl_key, &action,
						     0, &entry_id);
		if (err < 0) {
			log_err("Could not add key for inbound SA!\n");
			return err;
		}
		sa->inbound_hash_entry = entry_id;
		break;

	case MNG_OP_REMOVE:
		entry_id = sa->inbound_hash_entry;
		err = dpa_classif_table_delete_entry_by_ref(sa->inbound_sa_td,
							    entry_id);
		if (err < 0) {
			log_err("Could not remove key for inbound SA!\n");
			return err;
		}
		sa->inbound_hash_entry = DPA_OFFLD_INVALID_OBJECT_ID;
		break;

	case MNG_OP_MODIFY:
		fill_cls_action_drop(&action, FALSE);

		memset(&mod_params, 0, sizeof(mod_params));
		mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;
		mod_params.key = NULL;
		mod_params.action = &action;

		entry_id = sa->inbound_hash_entry;
		err = dpa_classif_table_modify_entry_by_ref(sa->inbound_sa_td,
							    entry_id,
							    &mod_params);
		if (err < 0) {
			log_err("Failed set drop action for inbound SA %d\n",
				  sa->id);
			return err;
		}
		sa->inbound_hash_entry = DPA_OFFLD_INVALID_OBJECT_ID;
		break;
	}

	return err;
}

static int remove_inbound_hash_entry(struct dpa_ipsec_sa *sa)
{
	int err;

	BUG_ON(!sa);

	err = update_pre_sec_inbound_table(sa, MNG_OP_REMOVE);
	if (unlikely(err < 0)) {
		pr_crit("Failed to remove inbound key for SA %d\n", sa->id);
		return -ENOTRECOVERABLE;
	}

	return 0;
}

static inline int remove_inbound_flow_id_classif(struct dpa_ipsec_sa *sa)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_cls_tbl_action action;
	int err;

	dpa_ipsec = sa->dpa_ipsec;

	memset(&action, 0, sizeof(action));
	action.type = DPA_CLS_TBL_ACTION_DROP;
	err = set_flow_id_action(sa, &action);
	if (err < 0) {
		log_err("Could not remove SA entry in indexed table\n");
		return err;
	}

	if (dpa_ipsec->config.post_sec_in_params.do_pol_check)
		put_free_inbpol_tbl(dpa_ipsec, sa->em_inpol_td);

	sa->valid_flowid_entry = false;

	return 0;
}

static int get_new_fqid(struct dpa_ipsec *dpa_ipsec, uint32_t *fqid)
{
	int err = 0;

	BUG_ON(!dpa_ipsec);
	BUG_ON(!fqid);

	if (dpa_ipsec->sa_mng.fqid_cq != NULL) {
		err = cq_get_4bytes(dpa_ipsec->sa_mng.fqid_cq, fqid);
		if (err < 0)
			log_err("FQID allocation (from range) failure.\n");
		return err;
	}

	/* No pool defined. Get FQID from default allocator. */
	err = qman_alloc_fqid(fqid);
	if (err < 0) {
		log_err("FQID allocation (no pool) failure.\n");
		return -ERANGE;
	}

	return 0;
}

static void put_free_fqid(struct dpa_ipsec *dpa_ipsec, uint32_t fqid)
{
	int err;

	BUG_ON(!dpa_ipsec);

	/* recycle the FQID */
	if (dpa_ipsec->sa_mng.fqid_cq != NULL) {
		err = cq_put_4bytes(dpa_ipsec->sa_mng.fqid_cq, fqid);
		BUG_ON(err < 0);
	} else {
		qman_release_fqid(fqid);
	}
}

static int wait_until_fq_empty(struct qman_fq *fq, int timeout)
{
	struct qm_mcr_queryfq_np queryfq_np;

	BUG_ON(!fq);

	do {
		qman_query_fq_np(fq, &queryfq_np);
		cpu_relax();
		udelay(1);
		timeout = timeout - 1;
	} while (queryfq_np.frm_cnt && timeout);

	if (timeout == 0) {
		log_err("Timeout. Fq with id %d not empty.\n", fq->fqid);
		return -EBUSY;
	}

	return 0;
}

static int remove_sa_sec_fq(struct dpa_ipsec_sa *sa, struct qman_fq *sec_fq)
{
	int err, flags, timeout = WAIT4_FQ_EMPTY_TIMEOUT;

	BUG_ON(!sa);
	BUG_ON(!sa->dpa_ipsec);
	BUG_ON(!sec_fq);

	/* Check if already removed, and return success if so. */
	if (sec_fq->fqid == 0)
		return 0;

	err = wait_until_fq_empty(sec_fq, timeout);
	if (err < 0)
		return err;

	err = qman_retire_fq(sec_fq, &flags);
	if (err < 0) {
		log_err("Failed to retire FQ %d\n", sec_fq->fqid);
		return err;
	}

	err = qman_oos_fq(sec_fq);
	if (err < 0) {
		log_err("Failed to OOS FQ %d\n", sec_fq->fqid);
		return err;
	}

	qman_destroy_fq(sec_fq, 0);

	/* release FQID */
	put_free_fqid(sa->dpa_ipsec, sec_fq->fqid);

	/* Clean the FQ structure for reuse */
	memset(sec_fq, 0, sizeof(struct qman_fq));

	return 0;
}

static int remove_sa_fq_pair(struct dpa_ipsec_sa *sa)
{
	int err;

	BUG_ON(!sa);

	err = remove_sa_sec_fq(sa, sa->to_sec_fq);
	if (err < 0)
		return err;

	if (sa_is_single(sa)) {
		err = remove_sa_sec_fq(sa, sa->from_sec_fq);
		if (err < 0)
			return err;
	}

	return 0;
}

static int create_sec_frame_queue(uint32_t fq_id, uint16_t channel,
				  uint16_t wq_id, uint32_t ctx_a_hi,
				  uint32_t ctx_a_lo, uint32_t ctxB,
				  uint32_t sp_op, void *fm_pcd, bool parked,
				  struct qman_fq *fq)
{
	struct qm_mcc_initfq fq_opts;
	uint32_t flags;
	int err = 0;

	BUG_ON(!fq);

	memset(fq, 0, sizeof(struct qman_fq));

	flags = QMAN_FQ_FLAG_LOCKED | QMAN_FQ_FLAG_TO_DCPORTAL;

	err = qman_create_fq(fq_id, flags, fq);
	if (unlikely(err < 0)) {
		log_err("Could not create FQ with ID: %u\n", fq_id);
		goto create_sec_fq_err;
	}

	/*
	 * generate a parked queue or a scheduled one depending on the function
	 * input parameters.
	 */
	flags = (parked == true) ? 0 : QMAN_INITFQ_FLAG_SCHED;
	memset(&fq_opts, 0, sizeof(fq_opts));
	fq_opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA |
			  QM_INITFQ_WE_CONTEXTB;
	if (ctx_a_lo) {
		fq_opts.fqd.context_a.hi = ctx_a_hi;
		fq_opts.fqd.context_a.lo = ctx_a_lo;
		fq_opts.fqd.context_b = ctxB;
	} else {
		uint8_t sp_op_code = 0;
		t_Error error;

		/*
		 * configure uCode commands for handling flowID and other update
		 * operations:
		 * - retrieve special operation code (for IPSec and possibly
		 *   other updates on UDP header fields)
		 * - enable ctxB;
		 * - set ctxA override;
		 * - set in ctxB the FlowID and special operation code
		 */
		if (sp_op) {
			void *fm = NULL;

			/* get FMan handle from the PCD handle*/
			fm = ((t_FmPcd *)fm_pcd)->h_Fm;

			error = FM_GetSpecialOperationCoding(fm, sp_op,
							     &sp_op_code);
			if (error != E_OK) {
				log_err("FM_GetSpecialOperationCoding failed\n");
				log_err("Could not retrieve special op code");
				goto create_sec_fq_err;
			}
			/* the opcode is a 4-bit value */
			sp_op_code &= NIA_OPCODE_MASK;
		}
#if (DPAA_VERSION == 10)
		/* FMAN v2 devices: opcode and flow id are stored in contextB */
		fq_opts.fqd.context_a.hi |= FM_CONTEXTA_OVERRIDE_MASK;
		FM_CONTEXTB_SET_FQID(&(fq_opts.fqd.context_b), ctxB |
					(sp_op_code << 20));
#elif (DPAA_VERSION == 11)
		/* FMAN v3 devices: opcode and flow id are stored in contextA */
		fq_opts.fqd.context_a.hi &= ~FM_CONTEXTA_A1_MASK;
		fq_opts.fqd.context_a.hi |= (ctxB << 4) | sp_op_code;
		fq_opts.fqd.context_a.hi |= FM_CONTEXTA_A1_VALID_MASK;
#endif
	}

	fq_opts.fqd.dest.wq = wq_id;
	fq_opts.fqd.dest.channel = channel;

	err = qman_init_fq(fq, flags, &fq_opts);
	if (unlikely(err < 0)) {
		log_err("Could not init FQ with ID: %u\n", fq->fqid);
		goto create_sec_fq_err;
	}

	return 0;

 create_sec_fq_err:
	/*Reset all fields of FQ structure (including FQID) to mark it invalid*/
	memset(fq, 0, sizeof(struct qman_fq));

	return err;
}

static int create_sa_fq_pair(struct dpa_ipsec_sa *sa,
			     bool reuse_from_secfq, bool parked_to_secfq)
{
	void *ctxtA;
	uint32_t ctxtA_hi, ctxtA_lo;
	phys_addr_t addr;
	struct dpa_ipsec *dpa_ipsec;
	uint32_t fqid_from_sec = 0, fqid_to_sec = 0;
	int err;

	BUG_ON(!sa);

	dpa_ipsec = sa->dpa_ipsec;
	BUG_ON(!dpa_ipsec);

	err = create_sec_descriptor(sa);
	if (err < 0) {
		log_err("Could not create sec descriptor\n");
		return err;
	}

	ctxtA = sa->sec_desc;
	addr = virt_to_phys(ctxtA);
	ctxtA_hi = (uint32_t) (addr >> 32);
	ctxtA_lo = (uint32_t) (addr);

	/*
	 * If reuse FROM SEC FQ is false than create other FROM SEC FQ
	 * and set it as output frame queue for this SA. Otherwise
	 * profit that you poses a valid FROM SEC FQ from the OLD SA
	 * and use it accordingly.
	 */
	if (!reuse_from_secfq) {
		uint16_t chan, flow_id;
		uint32_t sp_op = 0;

		sp_op = FM_SP_OP_IPSEC;
		if (sa_is_outbound(sa) && sa->use_udp_encap)
			sp_op |= FM_SP_OP_IPSEC_UPDATE_UDP_LEN;
		if (sa->dscp_copy || sa->ecn_copy)
			sp_op |= FM_SP_OP_IPSEC_MANIP | FM_SP_OP_RPD;

		/* acquire fqid for 'FROM SEC' fq */
		err = get_new_fqid(dpa_ipsec, &fqid_from_sec);
		if (err < 0)
			return err;

		if (sa_is_outbound(sa)) {
			chan = dpa_ipsec->config.post_sec_out_params.qm_tx_ch;
			flow_id = sa->outbound_flowid;
		} else {
			chan = dpa_ipsec->config.post_sec_in_params.qm_tx_ch;
			flow_id = sa->inbound_flowid;
		}

		err = create_sec_frame_queue(fqid_from_sec,
					     chan, sa->sa_wqid, 0, 0, /* ctxA */
					     flow_id, /*ctxB forwarding info*/
					     sp_op,
					     sa->dpa_ipsec->config.fm_pcd,
					     FALSE, sa->from_sec_fq);
		if (err < 0) {
			log_err("From SEC FQ couldn't be created\n");
			goto create_fq_pair_err;
		}
	}

	/* acquire fqid for 'TO SEC' fq */
	err = get_new_fqid(dpa_ipsec, &fqid_to_sec);
	if (err < 0)
		goto create_fq_pair_err;

	err = create_sec_frame_queue(fqid_to_sec,
			dpa_ipsec->config.qm_sec_ch,
			sa->sa_wqid, ctxtA_hi, ctxtA_lo, /* ctxA */
			qman_fq_fqid(sa->from_sec_fq), /*ctxB - output SEC fq*/
			0, NULL, parked_to_secfq, sa->to_sec_fq);
	if (err < 0) {
		log_err("%s FQ (to SEC) couldn't be created\n",
			sa_is_outbound(sa) ? "Encrypt" : "Decrypt");
		goto create_fq_pair_err;
	}

	return 0;

 create_fq_pair_err:
	if (qman_fq_fqid(sa->from_sec_fq) != 0)
		remove_sa_sec_fq(sa, sa->from_sec_fq);
	else
		put_free_fqid(dpa_ipsec, fqid_from_sec); /* recycle the FQID */

	if (fqid_to_sec != 0)
		put_free_fqid(dpa_ipsec, fqid_to_sec); /*recycle the FQID */

	return err;
}

static inline int set_cipher_auth_alg(enum dpa_ipsec_cipher_alg alg_suite,
				      uint16_t *cipher, uint16_t *auth)
{
	*cipher = ipsec_algs[alg_suite].enc_alg;
	*auth = ipsec_algs[alg_suite].auth_alg;

	if (*cipher == OP_PCL_IPSEC_INVALID_ALG_ID ||
	    *auth == OP_PCL_IPSEC_INVALID_ALG_ID) {
		log_err("Invalid algorithm suite selected\n");
		return -EINVAL;
	}

	return 0;
}

static int copy_sa_params_to_out_sa(struct dpa_ipsec_sa *sa,
				    struct dpa_ipsec_sa_params *sa_params)
{
	struct iphdr *outer_ip_hdr;
	unsigned int ip_addr_type;
	int err;

	BUG_ON(!sa);
	BUG_ON(!sa_params);

	sa->sa_dir = DPA_IPSEC_OUTBOUND;
	sa->sa_bpid = sa_params->sa_bpid;
	sa->sa_bufsize = sa_params->sa_bufsize;
	sa->sa_wqid = sa_params->sa_wqid;
	ip_addr_type = sa_params->sa_out_params.ip_ver;

	sa->alg_suite = sa_params->crypto_params.alg_suite;
	err = set_cipher_auth_alg(sa_params->crypto_params.alg_suite,
				  &sa->cipher_data.cipher_type,
				  &sa->auth_data.auth_type);
	if (err < 0)
		return err;

	sa->auth_data.auth_key_len = sa_params->crypto_params.auth_key_len;
	memcpy(sa->auth_data.auth_key,
	       sa_params->crypto_params.auth_key,
	       sa_params->crypto_params.auth_key_len);

	sa->cipher_data.cipher_key_len =
		sa_params->crypto_params.cipher_key_len;
	memcpy(sa->cipher_data.cipher_key,
	       sa_params->crypto_params.cipher_key,
	       sa_params->crypto_params.cipher_key_len);
	sa->sec_desc->pdb_en.spi = cpu_to_caam32(sa_params->spi);
	sa->sec_desc->pdb_en.options = PDBOPTS_ESP_TUNNEL |
				       PDBOPTS_ESP_INCIPHDR |
				       PDBOPTS_ESP_IPHDRSRC;
	if (sa_params->hdr_upd_flags) {
		if (sa_params->hdr_upd_flags & DPA_IPSEC_HDR_COPY_TOS)
			sa->sec_desc->pdb_en.options |= PDBOPTS_ESP_DIFFSERV;
		if (sa_params->hdr_upd_flags & DPA_IPSEC_HDR_COPY_DF) {
			if (ip_addr_type == DPA_IPSEC_ADDR_T_IPv4)
				sa->sec_desc->pdb_en.hmo_rsvd |=
							PDBHMO_ESP_DFBIT;
			else
				pr_warn("Copy DF not supported for IPv6 SA");
		}
		if (sa_params->hdr_upd_flags & DPA_IPSEC_HDR_DEC_TTL)
			sa->sec_desc->pdb_en.hmo_rsvd |=
					PDBHMO_ESP_ENCAP_DEC_TTL;

		sa->dscp_copy =
			sa_params->hdr_upd_flags & DPA_IPSEC_HDR_COPY_DSCP;
		sa->ecn_copy =
			sa_params->hdr_upd_flags & DPA_IPSEC_HDR_COPY_ECN;
	}

	sa->enable_dpovrd = true;

	if (sa_params->use_ext_seq_num) {
		sa->sec_desc->pdb_en.seq_num_ext_hi =
			cpu_to_caam32((sa_params->start_seq_num & SEQ_NUM_HI_MASK) >> 32);
		sa->sec_desc->pdb_en.options |= PDBOPTS_ESP_ESN;
	}
	sa->sec_desc->pdb_en.seq_num =
		cpu_to_caam32(sa_params->start_seq_num & SEQ_NUM_LOW_MASK);

	if (ip_addr_type == DPA_IPSEC_ADDR_T_IPv6)
		sa->sec_desc->pdb_en.options |= PDBOPTS_ESP_IPV6;
	else
		sa->sec_desc->pdb_en.options |= PDBOPTS_ESP_UPDATE_CSUM;

	if (!sa_params->sa_out_params.init_vector)
		sa->sec_desc->pdb_en.options |= PDBOPTS_ESP_IVSRC;
	else
		memcpy(&sa->sec_desc->pdb_en.cbc,
		       sa_params->sa_out_params.init_vector->init_vector,
		       sa_params->sa_out_params.init_vector->length);

	sa->outbound_flowid = sa_params->sa_out_params.post_sec_flow_id;

	/* Copy the outer header and generate the original header checksum */
	memcpy(&sa->sec_desc->pdb_en.ip_hdr[0],
	       sa_params->sa_out_params.outer_ip_header,
	       sa_params->sa_out_params.ip_hdr_size);

	if (sa_params->sa_out_params.outer_udp_header) {
		uint8_t *tmp;
		struct udphdr *udp_hdr;

		tmp = (uint8_t *) &sa->sec_desc->pdb_en.ip_hdr[0];
		memcpy(tmp + sa_params->sa_out_params.ip_hdr_size,
		       sa_params->sa_out_params.outer_udp_header,
		       UDP_HEADER_LEN);
		sa->sec_desc->pdb_en.ip_hdr_len =
			sa_params->sa_out_params.ip_hdr_size + UDP_HEADER_LEN;
		sa->use_udp_encap = true;

		/* disable UDP checksum calculation, because for now there is
		 * no mechanism for UDP checksum update */
		udp_hdr = (struct udphdr *) (tmp +
				sa_params->sa_out_params.ip_hdr_size);
		udp_hdr->check = 0x0000;

		if (ip_addr_type == DPA_IPSEC_ADDR_T_IPv4) {
			outer_ip_hdr = (struct iphdr *)
						&sa->sec_desc->pdb_en.ip_hdr[0];
			outer_ip_hdr->protocol = IPPROTO_UDP;
		} else {
			/*
			 * this should never be reached - it should be checked
			 * before in check SA params function
			 */
			log_err("NAT-T is not supported for IPv6 SAs\n");
			return -EINVAL;
		}
	} else {
		sa->sec_desc->pdb_en.ip_hdr_len =
				sa_params->sa_out_params.ip_hdr_size;
	}
	/* Update endianness of this value to match SEC endianness: */
	sa->sec_desc->pdb_en.ip_hdr_len =
				cpu_to_caam16(sa->sec_desc->pdb_en.ip_hdr_len);

	if (ip_addr_type == DPA_IPSEC_ADDR_T_IPv4) {
		outer_ip_hdr = (struct iphdr *) &sa->sec_desc->pdb_en.ip_hdr[0];
		outer_ip_hdr->check =
			ip_fast_csum((unsigned char *)outer_ip_hdr,
				     outer_ip_hdr->ihl);
	}

	/* Only IPv4 inner packets are currently supported */
	sa->sec_desc->pdb_en.ip_nh = 0x04;

	sa->l2_hdr_size = sa_params->l2_hdr_size;
	sa->enable_stats = sa_params->enable_stats;
	sa->enable_extended_stats = sa_params->enable_extended_stats;
	if (sa_params->sa_out_params.dscp_end <
					sa_params->sa_out_params.dscp_start) {
		log_err("Wrong DSCP interval, dscp_start (%d) cannot be greater than dscp_end (%d)\n",
			 sa_params->sa_out_params.dscp_start,
			 sa_params->sa_out_params.dscp_end);
		return -EINVAL;
	}
	sa->dscp_start = sa_params->sa_out_params.dscp_start;
	sa->dscp_end = sa_params->sa_out_params.dscp_end;
#ifdef DEBUG_PARAM
	/* Printing all the parameters */
	print_sa_sec_param(sa);
#endif

	return 0;
}

static int copy_sa_params_to_in_sa(struct dpa_ipsec_sa *sa,
				   struct dpa_ipsec_sa_params *sa_params,
				   bool rekeying)
{
	struct dpa_ipsec *dpa_ipsec;
	int err;

	BUG_ON(!sa);
	BUG_ON(!sa_params);

	dpa_ipsec = sa->dpa_ipsec;
	BUG_ON(!dpa_ipsec);

	/* reserve a FlowID for this SA only if we are not rekeying */
	if (!ignore_post_ipsec_action(dpa_ipsec) && !rekeying) {
		err = get_inbound_flowid(dpa_ipsec, &sa->inbound_flowid);
		if (err < 0) {
			log_err("Can't get valid inbound flow id\n");
			sa->inbound_flowid = INVALID_INB_FLOW_ID;
			return -EINVAL;
		}
	}

	sa->sa_dir = DPA_IPSEC_INBOUND;
	sa->sa_bpid = sa_params->sa_bpid;
	sa->sa_bufsize = sa_params->sa_bufsize;
	sa->sa_wqid = sa_params->sa_wqid;
	sa->spi = sa_params->spi;

	sa->alg_suite = sa_params->crypto_params.alg_suite;
	err = set_cipher_auth_alg(sa_params->crypto_params.alg_suite,
				  &sa->cipher_data.cipher_type,
				  &sa->auth_data.auth_type);
	if (err < 0)
		return err;

	sa->auth_data.auth_key_len = sa_params->crypto_params.auth_key_len;
	memcpy(sa->auth_data.auth_key,
	       sa_params->crypto_params.auth_key,
	       sa_params->crypto_params.auth_key_len);

	sa->cipher_data.cipher_key_len =
			sa_params->crypto_params.cipher_key_len;
	memcpy(sa->cipher_data.cipher_key,
	       sa_params->crypto_params.cipher_key,
	       sa_params->crypto_params.cipher_key_len);

	sa->use_udp_encap = sa_params->sa_in_params.use_udp_encap;
	sa->udp_src_port  = sa_params->sa_in_params.src_port;
	sa->udp_dest_port = sa_params->sa_in_params.dest_port;
	sa->use_var_iphdr_len = sa_params->sa_in_params.use_var_iphdr_len;

	memcpy(&sa->def_sa_action,
	       &sa_params->sa_in_params.post_ipsec_action,
	       sizeof(struct dpa_cls_tbl_action));

	if (sa->def_sa_action.type == DPA_CLS_TBL_ACTION_ENQ &&
	    sa->def_sa_action.enq_params.policer_params) {
		struct dpa_cls_tbl_policer_params	*policer_params;
		policer_params = kzalloc(sizeof(*policer_params), GFP_KERNEL);
		if (!policer_params) {
			log_err("Could not allocate memory for policer parameters\n");
			return -ENOMEM;
		}
		memcpy(policer_params,
		       sa->def_sa_action.enq_params.policer_params,
		       sizeof(*policer_params));
		sa->def_sa_action.enq_params.policer_params = policer_params;
	}

	sa->sec_desc->pdb_dec.seq_num =
		cpu_to_caam32(sa_params->start_seq_num & SEQ_NUM_LOW_MASK);
	sa->sec_desc->pdb_dec.options = PDBOPTS_ESP_TUNNEL |
					PDBOPTS_ESP_OUTFMT;

	if (dpa_ipsec->sec_era > 4)
		sa->sec_desc->pdb_dec.options |= PDBOPTS_ESP_AOFL;

	if (sa_params->use_ext_seq_num) {
		sa->sec_desc->pdb_dec.seq_num_ext_hi =
			cpu_to_caam32((sa_params->start_seq_num & SEQ_NUM_HI_MASK) >> 32);
		sa->sec_desc->pdb_dec.options |= PDBOPTS_ESP_ESN;
	}

	if (sa_params->sa_in_params.dest_addr.version ==
							DPA_IPSEC_ADDR_T_IPv6)
		sa->sec_desc->pdb_dec.options |= PDBOPTS_ESP_IPVSN;
	else
		sa->sec_desc->pdb_dec.options |= PDBOPTS_ESP_VERIFY_CSUM;

	switch (sa_params->sa_in_params.arw) {
	case DPA_IPSEC_ARSNONE:
		sa->sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARSNONE;
		break;
	case DPA_IPSEC_ARS32:
		sa->sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARS32;
		break;
	case DPA_IPSEC_ARS64:
		sa->sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARS64;
		break;
	default:
		log_err("Invalid ARS mode specified\n");
		return -EINVAL;
	}

	/*
	 * Updated the offset to the point in frame were the encrypted
	 * stuff starts.
	 */
	if (sa_params->sa_in_params.dest_addr.version ==
							DPA_IPSEC_ADDR_T_IPv6)
		sa->sec_desc->pdb_dec.hmo_ip_hdr_len =
					(uint16_t) sizeof(struct ipv6hdr);
	else
		sa->sec_desc->pdb_dec.hmo_ip_hdr_len =
					(uint16_t) sizeof(struct iphdr);
	if (sa->use_udp_encap)
		sa->sec_desc->pdb_dec.hmo_ip_hdr_len += UDP_HEADER_LEN;

	if (sa_params->hdr_upd_flags) {
		if (sa_params->hdr_upd_flags & DPA_IPSEC_HDR_COPY_TOS)
			sa->sec_desc->pdb_dec.hmo_ip_hdr_len |=
					PDBHMO_ESP_DIFFSERV;
		if (sa_params->hdr_upd_flags & DPA_IPSEC_HDR_DEC_TTL)
			sa->sec_desc->pdb_dec.hmo_ip_hdr_len |=
					PDBHMO_ESP_DECAP_DEC_TTL;
		if (sa_params->hdr_upd_flags & DPA_IPSEC_HDR_COPY_DF)
			pr_info("Copy DF bit not supported for inbound SAs");

		sa->dscp_copy =
			sa_params->hdr_upd_flags & DPA_IPSEC_HDR_COPY_DSCP;
		sa->ecn_copy =
			sa_params->hdr_upd_flags & DPA_IPSEC_HDR_COPY_ECN;
	}
	sa->sec_desc->pdb_dec.hmo_ip_hdr_len =
			cpu_to_caam16(sa->sec_desc->pdb_dec.hmo_ip_hdr_len);

	/* Only for outbound */
	sa->enable_dpovrd = false;

	memcpy(&sa->src_addr,
	       &sa_params->sa_in_params.src_addr,
	       sizeof(struct dpa_offload_ip_address));

	memcpy(&sa->dest_addr,
	       &sa_params->sa_in_params.dest_addr,
	       sizeof(struct dpa_offload_ip_address));

	sa->policy_miss_action = sa_params->sa_in_params.policy_miss_action;
	sa->l2_hdr_size = sa_params->l2_hdr_size;
	sa->enable_stats = sa_params->enable_stats;
	sa->enable_extended_stats = sa_params->enable_extended_stats;
#ifdef DEBUG_PARAM
	/* Printing all the parameters */
	print_sa_sec_param(sa);
#endif

	return 0;
}

static int check_policy_params(struct dpa_ipsec_sa *sa,
			       struct dpa_ipsec_policy_params *pol_params)
{
	BUG_ON(!sa);
	BUG_ON(!pol_params);

	/* check if both IP address are of the same type */
	if (pol_params->src_addr.version != pol_params->dest_addr.version) {
		log_err("Src and dest IP address types must be the same!\n");
		return -EINVAL;
	}

	/* check if IP address version is valid */
	if (pol_params->src_addr.version != DPA_IPSEC_ADDR_T_IPv4 &&
	    pol_params->src_addr.version != DPA_IPSEC_ADDR_T_IPv6) {
		log_err("Src and dest IP address types either 4 or 6!\n");
		return -EINVAL;
	}

	/* check if fragmentation is enabled for inbound SAs */
	if (pol_params->dir_params.type == DPA_IPSEC_POL_DIR_PARAMS_MANIP &&
	    sa_is_inbound(sa)) {
		log_err("Fragmentation or header manipulation can't be enabled for inbound policy!\n");
		return -EINVAL;
	}

	if (pol_params->dir_params.type == DPA_IPSEC_POL_DIR_PARAMS_MANIP &&
	    pol_params->dir_params.manip_desc < 0) {
		log_err("Invalid manip descriptor for SA id %d\n", sa->id);
		return -EINVAL;
	}

	/*
	 * check if post inbound policy verification action was configured for
	 * outbound policies
	 */
	if (pol_params->dir_params.type == DPA_IPSEC_POL_DIR_PARAMS_ACT &&
	    sa_is_outbound(sa)) {
		log_err("Action cannot be configured for outbound policy!\n");
		return -EINVAL;
	}

	/* check if DF bit was set and an IPv6 policy is being offloaded */
	if (sa_is_outbound(sa) &&
	    sa->sec_desc->pdb_en.hmo_rsvd == PDBHMO_ESP_DFBIT &&
	    pol_params->src_addr.version == DPA_IPSEC_ADDR_T_IPv6) {
		log_err("Can't add IPv6 policy to IPv4 SA w/ DF bit copy set\n");
		return -EINVAL;
	}

	return 0;
}

static int store_policy_param_to_sa_pol_list(struct dpa_ipsec_sa *sa,
				struct dpa_ipsec_policy_params *policy_params,
				struct dpa_ipsec_policy_entry **policy_entry)
{
	struct dpa_ipsec_policy_entry *pol_entry;
	struct dpa_ipsec_pol_dir_params *dir = NULL;
	int size = 1; /* By default the size of the entry_id array is one */

	BUG_ON(!sa);
	BUG_ON(!policy_params);
	BUG_ON(!policy_entry);

	pol_entry = kzalloc(sizeof(*pol_entry), GFP_KERNEL);
	if (!pol_entry) {
		log_err("Could not allocate memory for policy\n");
		return -ENOMEM;
	}

	/* Initialize the policy Manip handle to an invalid value */
	pol_entry->hmd = DPA_OFFLD_DESC_NONE;

	/* copy policy parameters */
	pol_entry->pol_params = *policy_params;

	/* if necessary, allocate memory to hold policer parameters */
	dir = &policy_params->dir_params;
	if (dir->type == DPA_IPSEC_POL_DIR_PARAMS_ACT &&
	    dir->in_action.type == DPA_CLS_TBL_ACTION_ENQ &&
	    dir->in_action.enq_params.policer_params) {
		struct dpa_cls_tbl_policer_params *plcr = NULL;

		plcr = kzalloc(sizeof(*plcr), GFP_KERNEL);
		if (!plcr) {
			log_err("Could not allocate memory for policer\n");
			kfree(pol_entry);
			return -ENOMEM;
		}
		memcpy(plcr, dir->in_action.enq_params.policer_params,
		       sizeof(*plcr));
		pol_entry->pol_params.dir_params.in_action.
		       enq_params.policer_params = plcr;
	}

	if (policy_params->use_dscp)
		size = sa->dscp_end - sa->dscp_start + 1;

	/*
	 * allocate memory for entry id: a single value or an array in case
	 * of SA per DSCP
	 */
	pol_entry->entry_id = kcalloc(size, sizeof(int), GFP_KERNEL);

	/* add policy to the SA's policy list */
	list_add(&pol_entry->node, &sa->policy_headlist);

	*policy_entry = pol_entry;

	return 0;
}

static inline int addr_match(struct dpa_offload_ip_address *addr1,
			     struct dpa_offload_ip_address *addr2)
{
	if (addr1->version != addr2->version)
		return false;

	switch (addr1->version) {
	case DPA_IPSEC_ADDR_T_IPv4:
		if (addr1->addr.ipv4.word != addr2->addr.ipv4.word)
			return false;
		break;
	case DPA_IPSEC_ADDR_T_IPv6:
		if (memcmp(&addr1->addr.ipv6.byte, &addr2->addr.ipv6.byte,
			   DPA_OFFLD_IPv6_ADDR_LEN_BYTES))
			return false;
		break;
	default:
		/*
		 * IP's version was checked for validity when policy was
		 * off-loaded so it can be invalid only if DPA IPsec component
		 * messed it up.
		 */
		log_err("Invalid IP version\n");
		BUG();
	}

	return true;
}


static int find_policy(struct dpa_ipsec_sa *sa,
		       struct dpa_ipsec_policy_params *pol,
		       struct dpa_ipsec_policy_entry **policy_entry)
{
	struct dpa_ipsec_policy_entry *pol_entry, *tmp;

	BUG_ON(!sa);
	BUG_ON(!pol);
	BUG_ON(!policy_entry);

	if (list_empty(&sa->policy_headlist)) {
		log_err("Policy list is empty\n");
		return -EDOM;
	}

	list_for_each_entry_safe(pol_entry, tmp, &sa->policy_headlist, node) {
		struct dpa_ipsec_policy_params *cpol;
		uint8_t cproto;

		cpol = &pol_entry->pol_params;
		cproto = cpol->protocol;

		if (cpol->dest_prefix_len != pol->dest_prefix_len ||
		    cpol->src_prefix_len != pol->src_prefix_len ||
		    !addr_match(&cpol->dest_addr, &pol->dest_addr) ||
		    !addr_match(&cpol->src_addr, &pol->src_addr) ||
		    cpol->protocol != pol->protocol ||
		    cpol->masked_proto != pol->masked_proto ||
		    cpol->priority != pol->priority)
			continue;

		if (cproto == IPPROTO_UDP || cproto == IPPROTO_TCP ||
		    cproto == IPPROTO_SCTP)
			if (cpol->l4.dest_port != pol->l4.dest_port ||
			    cpol->l4.dest_port_mask != pol->l4.dest_port_mask ||
			    cpol->l4.src_port != pol->l4.src_port ||
			    cpol->l4.src_port_mask != pol->l4.src_port_mask)
				continue;

		if (cproto == IPPROTO_ICMP || cproto == IPPROTO_ICMPV6) {
			struct dpa_ipsec_icmp_params *c;
			c = &cpol->icmp;
			if (c->icmp_code != pol->icmp.icmp_code ||
			    c->icmp_code_mask != pol->icmp.icmp_code_mask ||
			    c->icmp_type != pol->icmp.icmp_type ||
			    c->icmp_type_mask != pol->icmp.icmp_type_mask)
				continue;
		}

		/* found entry matching the input policy parameters */
		*policy_entry = pol_entry;
		return 0;
	}

	/* did not find the entry that matches the input policy parameters */
	return -EDOM;
}

static inline int get_policy_count_for_sa(struct dpa_ipsec_sa *sa)
{
	struct dpa_ipsec_policy_entry *policy_entry, *tmp_policy_entry;
	int pol_count = 0;

	if (list_empty(&sa->policy_headlist)) {
		pr_debug("Policy parameter list is empty\n");
		return 0;
	}


	list_for_each_entry_safe(policy_entry, tmp_policy_entry,
				 &sa->policy_headlist, node)
		pol_count++;

	return pol_count;
}

static int copy_all_policies(struct dpa_ipsec_sa *sa,
			     struct dpa_ipsec_policy_params *policy_params,
			     int num_pol)
{
	struct dpa_ipsec_policy_entry *policy_entry, *tmp_policy_entry;
	int pol_count = 0;

	BUG_ON(!sa);
	BUG_ON(!policy_params);

	if (list_empty(&sa->policy_headlist)) {
		log_err("Policy parameter list is empty\n");
		return 0;
	}

	list_for_each_entry_safe(policy_entry, tmp_policy_entry,
				 &sa->policy_headlist, node) {
		pol_count++;
		if (pol_count > num_pol) {
			log_err("Num policies in this SA greater than %d",
				num_pol);
			return -EAGAIN;
		}

		policy_params[pol_count - 1] = policy_entry->pol_params;
	}

	return 0;
}

static int remove_policy_from_sa_policy_list(struct dpa_ipsec_sa *sa,
					     struct dpa_ipsec_policy_entry
					     *policy_entry)
{
	struct dpa_ipsec_pol_dir_params *dir = NULL;

	BUG_ON(!sa);
	BUG_ON(!policy_entry);

	if (list_empty(&sa->policy_headlist)) {
		log_err("Policy parameter list is empty\n");
		return -EINVAL;
	}

	/* unlink this policy from SA's list */
	list_del(&policy_entry->node);

	/* release memory used for holding policer parameters */
	dir = &policy_entry->pol_params.dir_params;
	if (dir->type == DPA_IPSEC_POL_DIR_PARAMS_ACT &&
	    dir->in_action.type == DPA_CLS_TBL_ACTION_ENQ &&
	    dir->in_action.enq_params.policer_params)
		kfree(dir->in_action.enq_params.policer_params);

	/* release memory used for holding policy entry id array*/
	kfree(policy_entry->entry_id);
	/* release memory used for holding policy general parameters */
	kfree(policy_entry);

	return 0;
}

static int remove_policy(struct dpa_ipsec_sa *sa,
			 struct dpa_ipsec_policy_entry *policy_entry)
{
	int err;

	BUG_ON(!sa);
	BUG_ON(!policy_entry);

	if (sa_is_inbound(sa)) {
		err = update_inbound_policy(sa, policy_entry, MNG_OP_REMOVE);
		if (err < 0) {
			log_err("Could not remove the inbound policy\n");
			return err;
		}

		err = remove_policy_from_sa_policy_list(sa, policy_entry);
		if (err < 0) {
			log_err("Couldn't remove inbound policy from SA policy list\n");
			return err;
		}
	} else {  /* DPA_IPSEC_OUTBOUND */
		err = update_outbound_policy(sa, policy_entry, MNG_OP_REMOVE);
		if (err < 0) {
			log_err("Could not remove the outbound policy\n");
			return err;
		}

		err = remove_policy_from_sa_policy_list(sa, policy_entry);
		if (err < 0) {
			log_err("Could not remove outbound policy from SA policy list\n");
			return err;
		}
	}

	return 0;
}

static struct dpa_ipsec_sa *get_sa_from_sa_id(struct dpa_ipsec *dpa_ipsec,
					      int sa_id)
{
	struct dpa_ipsec_sa_mng *sa_mng;
	struct dpa_ipsec_sa *sa = NULL;

	BUG_ON(!dpa_ipsec);

	sa_mng = &dpa_ipsec->sa_mng;

	if (sa_id < dpa_ipsec->id * MAX_NUM_OF_SA ||
	    sa_id >= dpa_ipsec->id * MAX_NUM_OF_SA + sa_mng->max_num_sa) {
		log_err("Invalid SA id %d provided\n", sa_id);
		return NULL;
	}

	sa = &sa_mng->sa[sa_id_to_sa_index(sa_id)];

	return sa;
}

static int check_sa_params(struct dpa_ipsec_sa_params *sa_params)
{
	uint16_t cipher_alg, auth_alg;
	int err = 0;

	/* sanity checks */
	if (!sa_params) {
		log_err("Invalid SA parameters handle\n");
		return -EINVAL;
	}

	if (sa_params->crypto_params.alg_suite <
	     DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_MD5_128 ||
	    sa_params->crypto_params.alg_suite >
	     DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_512_256) {
		log_err("Invalid alg_suite value\n");
		return -EINVAL;
	}
	/*
	 * check crypto params:
	 * - an authentication key must always be provided
	 * - a cipher key must be provided if algorithm != NULL encryption
	 */

	err = set_cipher_auth_alg(sa_params->crypto_params.alg_suite,
				  &cipher_alg, &auth_alg);
	if (err < 0)
		return err;

	if (!sa_params->crypto_params.auth_key ||
	    sa_params->crypto_params.auth_key_len == 0) {
		log_err("A valid authentication key must be provided\n");
		return -EINVAL;
	}

	/* Check cipher_key only if the cipher algorithm isn't NULL encryption*/
	if (cipher_alg != OP_PCL_IPSEC_NULL_ENC &&
	    (!sa_params->crypto_params.cipher_key ||
	    sa_params->crypto_params.cipher_key_len == 0)) {
		log_err("A valid cipher key must be provided\n");
		return -EINVAL;
	}

	if (sa_params->sa_dir == DPA_IPSEC_OUTBOUND) {
		if (sa_params->sa_out_params.ip_hdr_size == 0 ||
		    !sa_params->sa_out_params.outer_ip_header) {
			log_err("Transport mode is not currently supported. Specify a valid encapsulation header\n");
			return -EINVAL;
		}

		if (sa_params->sa_out_params.outer_udp_header &&
			sa_params->sa_out_params.ip_ver ==
				DPA_IPSEC_ADDR_T_IPv6) {
			log_err("NAT-T is not supported for IPV6 SAs\n");
			return -EINVAL;
		}
	} else {
		/* Inbound SA */
		if (sa_params->sa_in_params.src_addr.version !=
		    sa_params->sa_in_params.dest_addr.version) {
			log_err("Source and destination IP address must be of same type\n");
			return -EINVAL;
		}

		if (sa_params->sa_in_params.use_udp_encap &&
			sa_params->sa_in_params.src_addr.version ==
				DPA_IPSEC_ADDR_T_IPv6) {
			log_err("NAT-T is not supported for IPV6 SAs\n");
			return -EINVAL;
		}
	}

	/* check buffer pool ID validity */
	if (sa_params->sa_bpid > MAX_BUFFER_POOL_ID) {
		log_err("Invalid SA buffer pool ID.\n");
		return -EINVAL;
	}

	return 0;
}

static int get_new_sa(struct dpa_ipsec *dpa_ipsec,
		      struct dpa_ipsec_sa **new_sa,
		      uint32_t *sa_id)
{
	struct dpa_ipsec_sa *sa;
	uint32_t id;
	int i;

	BUG_ON(!dpa_ipsec);

	BUG_ON(!new_sa);
	*new_sa = NULL;

	BUG_ON(!sa_id);

	/* Acquire DPA IPSec instance lock */
	mutex_lock(&dpa_ipsec->lock);

	/* Get an id for new SA */
	if (cq_get_4bytes(dpa_ipsec->sa_mng.sa_id_cq, &id) < 0) {
		log_err("No more unused SA handles\n");
		/* Release DPA IPSec instance lock */
		mutex_unlock(&dpa_ipsec->lock);
		return -EDOM;
	}

	for (i = 0; i < dpa_ipsec->sa_mng.max_num_sa; i++)
		if (dpa_ipsec->used_sa_ids[i] == DPA_OFFLD_INVALID_OBJECT_ID)
			break;
	if (i == dpa_ipsec->sa_mng.max_num_sa) {
		log_err("No more unused SAs ID holders");
		cq_put_4bytes(dpa_ipsec->sa_mng.sa_id_cq, id);
		/* Release DPA IPSec instance lock */
		mutex_unlock(&dpa_ipsec->lock);
		return -EDOM;
	}

	/* Acquire a preallocated SA structure */
	sa = &dpa_ipsec->sa_mng.sa[sa_id_to_sa_index(id)];
	sa->id = id;
	sa->used_sa_index = i;
	dpa_ipsec->used_sa_ids[sa->used_sa_index] = sa->id;
	dpa_ipsec->num_used_sas++;

	/* Release DPA IPSec instance lock */
	mutex_unlock(&dpa_ipsec->lock);

	*sa_id = id;
	*new_sa = sa;

	return 0;
}

/*
 * Expects that SA lock is acquired for this SA structure and parent/child SA.
 * Always acquire parent SA lock before child SA lock.
 */
static int put_sa(struct dpa_ipsec_sa *sa)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa_mng *sa_mng;
	int err;

	BUG_ON(!sa);

	dpa_ipsec = sa->dpa_ipsec;
	BUG_ON(!dpa_ipsec);

	if (sa->used_sa_index < 0) {
		pr_crit("Invalid used_sa_index for SA with id %d\n", sa->id);
		return -EFAULT;
	}

	/* Acquire DPA IPSec instance lock */
	mutex_lock(&dpa_ipsec->lock);
	sa_mng = &dpa_ipsec->sa_mng;

	/*
	 * AV's TODO: create a cleaning function for preallocated SA structure
	 * and call here that function
	 */

	/* Release the SA id in the SA IDs circular queue */
	err = cq_put_4bytes(sa_mng->sa_id_cq, sa->id);
	if (err < 0) {
		log_err("Could not release the sa id %d\n", sa->id);
		/* Release DPA IPSec instance lock */
		mutex_unlock(&dpa_ipsec->lock);
		return -EDOM;
	}

	/* Release the flow ID - only for inbound SAs */
	if (sa_is_inbound(sa) && !ignore_post_ipsec_action(dpa_ipsec) &&
	    sa->inbound_flowid != INVALID_INB_FLOW_ID && !sa_is_parent(sa)) {
		err = put_inbound_flowid(dpa_ipsec, sa->inbound_flowid);
		if (err < 0) {
			log_err("Could not put flow id in circular queue.\n");
			mutex_unlock(&dpa_ipsec->lock);
			return err;
		}
		sa->inbound_flowid = INVALID_INB_FLOW_ID;
	}

	sa->child_sa = NULL;

	/* Mark as free index in used SA IDs vector of this DPA IPSEC instance*/
	dpa_ipsec->used_sa_ids[sa->used_sa_index] = DPA_OFFLD_INVALID_OBJECT_ID;
	dpa_ipsec->num_used_sas--;
	sa->used_sa_index = -1;

	/* Release DPA IPSec instance lock */
	mutex_unlock(&dpa_ipsec->lock);

	return 0;
}

static int rollback_create_sa(struct dpa_ipsec_sa *sa)
{
	struct dpa_ipsec *dpa_ipsec;
	int err_rb;

	BUG_ON(!sa);
	dpa_ipsec = sa->dpa_ipsec;
	BUG_ON(!dpa_ipsec);

	if (sa_is_outbound(sa))
		goto remove_fq_pair;

	/* Inbound SA */
	if (sa->inbound_hash_entry != DPA_OFFLD_INVALID_OBJECT_ID) {
		err_rb = update_pre_sec_inbound_table(sa, MNG_OP_REMOVE);
		if (err_rb < 0) {
			log_err("Couln't remove SA lookup table entry\n");
			return err_rb;
		}
	}

	if (sa->ipsec_hmd != DPA_OFFLD_DESC_NONE) {
		struct hmd_entry hmd_entry;
		hmd_entry.hmd = sa->ipsec_hmd;
		hmd_entry.hmd_special_op = true;
		err_rb = destroy_recycle_manip(sa, &hmd_entry);
		if (err_rb < 0) {
			log_err("Could not delete manip object!\n");
			return err_rb;
		}
		sa->ipsec_hmd = DPA_OFFLD_DESC_NONE;
	}

	if (dpa_ipsec->config.post_sec_in_params.do_pol_check == true &&
	    sa->valid_flowid_entry) {
		err_rb = remove_inbound_flow_id_classif(sa);
		if (err_rb < 0) {
			log_err("Couldn't remove post decrypt tbl entry\n");
			return err_rb;
		}
	}

remove_fq_pair:
	err_rb = remove_sa_fq_pair(sa);
	if (err_rb < 0) {
		log_err("Could not remove SA FQs.\n");
		return err_rb;
	}

	/* Release the SA */
	err_rb = put_sa(sa);

	return err_rb;
}

static int rollback_rekeying_sa(struct dpa_ipsec_sa *sa)
{
	struct dpa_ipsec *dpa_ipsec;
	int err_rb;

	BUG_ON(!sa);
	dpa_ipsec = sa->dpa_ipsec;
	BUG_ON(!dpa_ipsec);

	if (sa_is_outbound(sa))
		goto remove_fq_pair;

	/* Inbound SA */
	if (sa->inbound_hash_entry != DPA_OFFLD_INVALID_OBJECT_ID) {
		err_rb = update_pre_sec_inbound_table(sa, MNG_OP_REMOVE);
		if (err_rb < 0) {
			log_err("Couln't remove SA lookup table entry\n");
			return err_rb;
		}
	}

	if (sa->ipsec_hmd != DPA_OFFLD_DESC_NONE) {
		struct hmd_entry hmd_entry;
		hmd_entry.hmd = sa->ipsec_hmd;
		hmd_entry.hmd_special_op = true;
		err_rb = destroy_recycle_manip(sa, &hmd_entry);
		if (err_rb < 0) {
			log_err("Could not delete manip object!\n");
			return err_rb;
		}
		sa->ipsec_hmd = DPA_OFFLD_DESC_NONE;
	}

remove_fq_pair:
	err_rb = remove_sa_fq_pair(sa);
	if (err_rb < 0) {
		log_err("Could not remove SA FQs.\n");
		return err_rb;
	}

	err_rb = put_sa(sa);

	return err_rb;
}

/* Find unused global DPA IPsec instance holder */
int find_unused_gbl_dpa_ipsec(void)
{
	int i, instance_id = -1;

	spin_lock(&gbl_dpa_ipsec_lock);

	for (i = 0; i < MAX_DPA_IPSEC_INSTANCES; i++)
		if (!gbl_dpa_ipsec[i]) {
			instance_id = i;
			/* mark this as used */
			gbl_dpa_ipsec[i] = (struct dpa_ipsec *)i;
			break;
		}

	spin_unlock(&gbl_dpa_ipsec_lock);

	return instance_id;
}

/* Mark unused global DPA IPsec instance holder */
static void mark_unused_gbl_dpa_ipsec(int instance)
{
	BUG_ON(instance < 0 || instance >= MAX_DPA_IPSEC_INSTANCES);

	spin_lock(&gbl_dpa_ipsec_lock);

	gbl_dpa_ipsec[instance] = NULL;

	spin_unlock(&gbl_dpa_ipsec_lock);
}

int dpa_ipsec_init(const struct dpa_ipsec_params *params, int *dpa_ipsec_id)
{
	struct dpa_ipsec *dpa_ipsec = NULL;
	uint32_t max_num_sa;
	int err = 0, instance_id;

	/* make sure all user params are OK and init can start */
	err = check_ipsec_params(params);
	if (err < 0)
		return err;

	instance_id = find_unused_gbl_dpa_ipsec();
	if (instance_id < 0) {
		log_err("The limit of active DPA IPsec instances has been reached\n");
		return -EDOM;
	}

	/* alloc control block */
	dpa_ipsec = kzalloc(sizeof(*dpa_ipsec), GFP_KERNEL);
	if (!dpa_ipsec) {
		log_err("Could not allocate memory for control block.\n");
		mark_unused_gbl_dpa_ipsec(instance_id);
		return -ENOMEM;
	}

	/* Set instance reference count to 1 */
	atomic_set(&dpa_ipsec->ref, 1);

	/* store the control block */
	spin_lock(&gbl_dpa_ipsec_lock);
	gbl_dpa_ipsec[instance_id] = dpa_ipsec;
	spin_unlock(&gbl_dpa_ipsec_lock);
	dpa_ipsec->id = instance_id;

	/* Initialize DPA IPSec instance lock */
	mutex_init(&dpa_ipsec->lock);

	/* store parameters */
	store_ipsec_params(dpa_ipsec, params);

	/* init SA manager */
	err = init_sa_manager(dpa_ipsec);
	if (err < 0) {
		free_resources(instance_id);
		return err;
	}

	/* Init used sa vector */
	max_num_sa = dpa_ipsec->sa_mng.max_num_sa;
	dpa_ipsec->used_sa_ids = kmalloc(max_num_sa * sizeof(u32), GFP_KERNEL);
	if (!dpa_ipsec->used_sa_ids) {
		log_err("No more memory for used sa id's vector ");
		free_resources(instance_id);
		return -ENOMEM;
	}
	memset(dpa_ipsec->used_sa_ids, DPA_OFFLD_INVALID_OBJECT_ID,
	       max_num_sa * sizeof(uint32_t));
	dpa_ipsec->num_used_sas = 0;

	/* retrieve and store SEC ERA information */
	err = get_sec_info(dpa_ipsec);
	if (err < 0) {
		free_resources(instance_id);
		return err;
	}

	/* Give to the user the valid DPA IPsec instance ID */
	*dpa_ipsec_id = instance_id;
	atomic_set(&dpa_ipsec->valid, 1);

	return 0;
}
EXPORT_SYMBOL(dpa_ipsec_init);

int dpa_ipsec_free(int dpa_ipsec_id)
{
	struct dpa_ipsec *instance;
	struct dpa_ipsec_sa *sa;
	int i, sa_id;
	DEFINE_WAIT(wait);

	instance = get_instance(dpa_ipsec_id);
	if (PTR_ERR(instance) == -EPERM || PTR_ERR(instance) == -EINVAL)
		return PTR_ERR(instance);

	/* Invalidate instance */
	atomic_set(&instance->valid, 0);

	put_instance(instance);

	add_wait_queue(&wait_queue, &wait);
	while (1) {
		prepare_to_wait(&wait_queue, &wait, TASK_UNINTERRUPTIBLE);
		/* Avoid sleeping if condition became true */
		if (atomic_dec_and_test(&instance->ref))
			break;
		schedule();
	}
	finish_wait(&wait_queue, &wait);

	/* destroy all SAs offloaded in this DPA IPsec instance */
	flush_delayed_work(&instance->sa_mng.sa_rekeying_work);
	for (i = 0; i < instance->sa_mng.max_num_sa; i++) {
		sa_id = instance->used_sa_ids[i];
		if (sa_id != DPA_OFFLD_INVALID_OBJECT_ID) {
			sa = get_sa_from_sa_id(instance, sa_id);
			BUG_ON(!sa);
			if (sa_is_inbound(sa)) {
				if (sa_is_child(sa))
					remove_inbound_sa(sa->parent_sa);
				remove_inbound_sa(sa);
			} /* outbound */
			else {
				if (sa_is_child(sa))
					remove_outbound_sa(sa->parent_sa);
				remove_outbound_sa(sa);
			}
		}
	}

	free_resources(dpa_ipsec_id);

	return 0;
}
EXPORT_SYMBOL(dpa_ipsec_free);

int dpa_ipsec_create_sa(int dpa_ipsec_id,
			struct dpa_ipsec_sa_params *sa_params, int *sa_id)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	uint32_t id;
	int err = 0, err_rb = 0;

	if (!valid_instance_id(dpa_ipsec_id))
		return -EINVAL;

	if (!sa_id) {
		log_err("Invalid SA ID holder\n");
		return -EINVAL;
	}
	*sa_id = DPA_OFFLD_INVALID_OBJECT_ID;

	/* Get the DPA IPsec instance */
	dpa_ipsec = get_instance(dpa_ipsec_id);
	err = check_instance(dpa_ipsec);
	if (unlikely(err < 0))
		return err;

	err = check_sa_params(sa_params);
	if (err < 0) {
		put_instance(dpa_ipsec);
		return err;
	}

	err = get_new_sa(dpa_ipsec, &sa, &id);
	if (err < 0) {
		log_err("Failed retrieving a preallocated SA\n");
		put_instance(dpa_ipsec);
		return err;
	}

	/* Update internal SA structure. First acquire its lock */
	mutex_lock(&sa->lock);

	sa->sa_dir = sa_params->sa_dir;
	sa->dpa_ipsec = dpa_ipsec;
	sa->parent_sa = NULL;
	sa->child_sa = NULL;
	sa->sa_rekeying_node.next = LIST_POISON1;
	sa->sa_rekeying_node.prev = LIST_POISON2;
	sa->read_seq_in_progress = false;

	/* Copy SA params into the internal SA structure */
	if (sa_is_outbound(sa))
		err = copy_sa_params_to_out_sa(sa, sa_params);
	else /* DPA_IPSEC_INBOUND */
		err = copy_sa_params_to_in_sa(sa, sa_params, FALSE);

	if (err < 0) {
		log_err("Could not copy SA parameters into SA\n");
		goto create_sa_err;
	}

	/* Initialize the SA Manip handle to an invalid value */
	sa->ipsec_hmd = DPA_OFFLD_DESC_NONE;

	/* Initialize the IPSec Manip. object (if required) for inbound SAs */
	if (sa_is_inbound(sa)) {
		if (sa->dpa_ipsec->config.max_sa_manip_ops == 0)
			err = create_ipsec_manip(sa, DPA_OFFLD_DESC_NONE,
						 &sa->ipsec_hmd);
		else
			err = update_ipsec_manip(sa, DPA_OFFLD_DESC_NONE,
						 &sa->ipsec_hmd);
		if (err < 0) {
			log_err("Could not create Manip object for in SA!\n");
			goto create_sa_err;
		}
	}

	/* Generate the split key from the normal auth key */
	err = generate_split_key(&sa->auth_data);
	if (err < 0)
		goto create_sa_err;

	/* Call internal function to create SEC FQ according to SA parameters */
	err = create_sa_fq_pair(sa, FALSE, FALSE);
	if (err < 0) {
		log_err("Could not create SEC frame queues\n");
		goto create_sa_err;
	}

	if (sa_is_inbound(sa)) {
		err = update_pre_sec_inbound_table(sa, MNG_OP_ADD);
		if (err < 0) {
			log_err("Could not update PCD entry\n");
			goto create_sa_err;
		}

		if (dpa_ipsec->config.post_sec_in_params.do_pol_check) {
			int inbpol_td;
			struct dpa_cls_tbl_action action;

			err = get_free_inbpol_tbl(dpa_ipsec, &inbpol_td);
			if (err < 0) {
				log_err("Could not get a free EM table\n");
				goto create_sa_err;
			}
			sa->em_inpol_td = inbpol_td;

			/*
			 * Link Exact Match table with the index table on
			 * inbound_flowid
			 */
			memset(&action, 0, sizeof(action));
			action.type = DPA_CLS_TBL_ACTION_NEXT_TABLE;
			action.next_table_params.next_td = inbpol_td;
			action.next_table_params.hmd = DPA_OFFLD_DESC_NONE;
			action.enable_statistics = FALSE;
			err = set_flow_id_action(sa, &action);
			if (err < 0) {
				log_err("Can't link EM table with index table\n");
				goto create_sa_err;
			}

			err = dpa_classif_table_modify_miss_action(inbpol_td,
						       &sa->policy_miss_action);
			if (err < 0) {
				log_err("Can't set policy miss action\n");
				goto create_sa_err;
			}
		} else {
			if (ignore_post_ipsec_action(sa->dpa_ipsec))
				goto sa_done;

			/* Set the post decryption default action */
			err = set_flow_id_action(sa, &sa->def_sa_action);
			if (err < 0) {
				log_err("Could not set default action for post decryption\n");
				goto create_sa_err;
			}
		}
	}

	/* SA done OK. Return the SA id */
sa_done:
	*sa_id = id;

	/* Unlock the SA structure */
	mutex_unlock(&sa->lock);

	/* Release the DPA IPsec instance */
	put_instance(dpa_ipsec);

	return 0;

	/* Something went wrong. Begin roll-back */
 create_sa_err:

	/* A invalid SA ID is returned if roll-back succeeds and the actual
	 * reserved SA ID if it fails. The SA ID can be used to try again to
	 * free resources by calling dpa_ipsec_remove_sa
	 */
	err_rb = rollback_create_sa(sa);
	if (err_rb < 0)
		*sa_id = id;

	/* Unlock the SA structure */
	mutex_unlock(&sa->lock);

	/* Release the DPA IPsec instance */
	put_instance(dpa_ipsec);

	return err;
}
EXPORT_SYMBOL(dpa_ipsec_create_sa);

/*
 * Expects that locks are acquired for this SA and its child if any.
 * Expects that no child SA is passed to it
 *
 * Function description:
 * Steps done for a parent SA:
 * 1. Remove the PCD entry that makes traffic to go to SEC
 * 2. Wait until SEC consumes the frames in the TO_SEC queue of this SA
 * 3. Schedule the TO SEC FQ of the child SA even if no traffic arrived on it
 * 4. Inherit parent SA's inbound post decryption classification
 * 5. If policy verification is enabled inherit parent SA's policies.
 * 6. Remove the child SA for the rekeying list
 * 7. Remove the parent SA's TO_SEC FQ
 * 8. Free all memory used for this SA i.e recycle this SA
 *
 * Steps done for a single SA:
 * 1. Remove the PCD entries that make traffic to go to SEC
 * 2. Remove TO_SEC FQ and FROM_SEC FQ
 *	2.1. Wait until SEC consumes the frames in the TO_SEC queue of this SA
 *	2.2. Wait until FROM_SEC queue gets empty, frames are distributed by the
 *	     post SEC offline port according to its PCD entries
 * 3. If policy verification is enabled, flush SA policies.
 * 4. Remove the index entry from the post SEC offline port index table
 * 5. Free all memory used for this SA i.e recycle this SA
 */
static int remove_inbound_sa(struct dpa_ipsec_sa *sa)
{
	struct dpa_ipsec_sa *child_sa;
	int err, timeout = WAIT4_FQ_EMPTY_TIMEOUT;

	if (sa_is_parent(sa)) {
		child_sa = sa->child_sa;
		/* Remove PCD entry that makes traffic go to SEC */
		if (sa->inbound_hash_entry != DPA_OFFLD_INVALID_OBJECT_ID) {
			err = remove_inbound_hash_entry(sa);
			if (err == -ENOTRECOVERABLE)
				return err;
		}

		/* destroy SA manip */
		if (sa->ipsec_hmd != DPA_OFFLD_DESC_NONE) {
			struct hmd_entry hmd_entry;
			hmd_entry.hmd = sa->ipsec_hmd;
			hmd_entry.hmd_special_op = true;
			err = destroy_recycle_manip(sa, &hmd_entry);
			if (err < 0) {
				log_err("Could not delete manip object!\n");
				return err;
			}
			sa->ipsec_hmd = DPA_OFFLD_DESC_NONE;
		}

		err = wait_until_fq_empty(sa->to_sec_fq, timeout);
		if (err < 0) {
			log_err("Waiting old SA's TO SEC FQ to get empty\n");
			return -ETIME;
		}

		/* schedule child SA */
		err = schedule_sa(child_sa);
		if (unlikely(err < 0)) {
			log_err("Scheduling child SA %d failed\n",
				child_sa->id);
			return -EIO;
		}

		/* Update the child SA with parent SA's inbound indx entry */
		child_sa->valid_flowid_entry = sa->valid_flowid_entry;

		/* Inherit parent SA's policy list and then set it empty */
		if (sa->dpa_ipsec->config.post_sec_in_params.do_pol_check)
			list_splice_init(&sa->policy_headlist,
					 &child_sa->policy_headlist);

		/* Acquire protective lock for the SA rekeying list */
		mutex_lock(&sa->dpa_ipsec->sa_mng.sa_rekeying_headlist_lock);

		child_sa->parent_sa = NULL;

		/* Remove the child SA from rekeying list */
		if (child_sa->sa_rekeying_node.next != LIST_POISON1 &&
		    child_sa->sa_rekeying_node.prev != LIST_POISON2)
			list_del(&child_sa->sa_rekeying_node);

		/* Invalidate the FROM SEC FQ of parent SA */
		memset(sa->from_sec_fq, 0, sizeof(struct qman_fq));
		sa->from_sec_fq->fqid = 0;

		/* Release the list lock so other threads may use it */
		mutex_unlock(&sa->dpa_ipsec->sa_mng.sa_rekeying_headlist_lock);

		/* Call rekeying callback to inform upper layer that rekeying
		 * process was finished for this SA and is ready for use */
		if (child_sa->rekey_event_cb)
			child_sa->rekey_event_cb(0, child_sa->id, 0);

		/* Now free the parent SA structure and all its resources */
		err = remove_sa_sec_fq(sa, sa->to_sec_fq);
		if (err < 0) {
			log_err("Couln't remove SA %d TO SEC FQ\n", sa->id);
			return -EUCLEAN;
		}

		/* Recycle parent SA memory */
		err = put_sa(sa);
		if (unlikely(err < 0)) {
			log_err("Could not recycle parent SA.\n");
			return -EDQUOT;
		}

		return 0;
	}

	BUG_ON(sa_is_child(sa));

	/* SA is single i.e has no child and can't be child for other SA */

	/* Remove PCD entry that makes traffic go to SEC entry is valid */
	if (sa->inbound_hash_entry != DPA_OFFLD_INVALID_OBJECT_ID) {
		err = remove_inbound_hash_entry(sa);
		if (err == -ENOTRECOVERABLE)
			return err;
	}

	/* destroy SA manip */
	if (sa->ipsec_hmd != DPA_OFFLD_DESC_NONE) {
		struct hmd_entry hmd_entry;
		hmd_entry.hmd = sa->ipsec_hmd;
		hmd_entry.hmd_special_op = true;
		err = destroy_recycle_manip(sa, &hmd_entry);
		if (err < 0) {
			log_err("Could not delete manip object!\n");
			return err;
		}
		sa->ipsec_hmd = DPA_OFFLD_DESC_NONE;
	}

	/* Destroy the TO_SEC and FROM_SEC queues */
	err = remove_sa_fq_pair(sa);
	if (err != 0) {
		log_err("Could not remove the SEC frame queues\n");
		return err;
	}

	/* Flush policy if policy check is enabled */
	if (sa->dpa_ipsec->config.post_sec_in_params.do_pol_check) {
		err = sa_flush_policies(sa);
		if (err < 0) {
			log_err("Could not flush inbound policies");
			return err;
		}
	}

	/* Remove the flow id classification after decryption */
	if (!ignore_post_ipsec_action(sa->dpa_ipsec) &&
	    sa->valid_flowid_entry) {
		err = remove_inbound_flow_id_classif(sa);
		if (err < 0)
			return err;
	}

	/* Free policer pointer */
	if (sa->def_sa_action.type == DPA_CLS_TBL_ACTION_ENQ &&
	    sa->def_sa_action.enq_params.policer_params)
		kfree(sa->def_sa_action.enq_params.policer_params);

	/* Mark SA as free */
	err = put_sa(sa);
	if (err < 0) {
		log_err("Could not recycle the sa with id %d\n", sa->id);
		return err;
	}

	return 0;
}

/*
 * Expects that locks are acquired for this SA and its child if any.
 * Expects that no child SA is passed to it
 *
 * Function description:
 * Steps done for a parent SA:
 * 1. Call the sa_rekeying_outbound function which is going to:
 *	a. wait until TO SEC FQ is empty or timeout
 *	b. schedule the child TO SEC FQ
 *	c. remove the parent TO SEC FQ
 *	d. free all memory used for this SA i.e recycle this SA
 * 2. In case error code is telling that child SA is ready to use, i.e
 *    sa_rekeying_outbound returned 0, -EUCLEAN, -EDQUOT:
 *	a. lock SA rekeying list
 *	b. set as single the parent SA and child SA i.e parent SA has no child
 *	   and child SA has no parent
 *	c. remove the child SA from the rekeying list, rekeying was complete
 *	d. invalidate parent SA's TO SEC FQ
 *	e. unlock SA rekeying list
 *	f. if child SA has a valid callback trigger this call to inform upper
 *	   layer that this SA was rekeyed successfully.
 *
 * Steps done for a single SA:
 * 1. Flush SA policies i.e remove the PCD entries that direct traffic to SEC
 * 2. Remove TO_SEC FQ and FROM_SEC FQ
 *	2.1. Wait until SEC consumes the frames in the TO_SEC queue of this SA
 *	2.2. Wait until FROM_SEC queue gets empty, frames are distributed by the
 *	     post SEC offline port according to its PCD entries
 * 3. Free all memory used for this SA i.e recycle this SA
 */
static int remove_outbound_sa(struct dpa_ipsec_sa *sa)
{
	struct dpa_ipsec_sa *child_sa;
	int err;

	if (sa_is_parent(sa)) {
		struct dpa_ipsec_sa_mng *sa_mng;

		BUG_ON(!sa->dpa_ipsec);
		sa_mng = &sa->dpa_ipsec->sa_mng;

		child_sa = sa->child_sa;

		err = sa_rekeying_outbound(child_sa);

		/* Remove child SA from rekeying list if processing was OK */
		if (err == 0 || err == -EUCLEAN || err == -EDQUOT) {
			/* Acquire protective lock for the SA rekeying list */
			mutex_lock(&sa_mng->sa_rekeying_headlist_lock);

			sa->child_sa = NULL;
			child_sa->parent_sa = NULL;

			/* Remove the child SA from rekeying list */
			list_del(&child_sa->sa_rekeying_node);

			/* Invalidate the FROM SEC FQ of parent SA */
			memset(sa->from_sec_fq, 0, sizeof(struct qman_fq));
			sa->from_sec_fq->fqid = 0;

			/* Release the list lock so other threads may use it */
			mutex_unlock(&sa_mng->sa_rekeying_headlist_lock);

			/*
			 * Call rekeying callback to inform upper layer that
			 * rekeying process was finished for this SA and is
			 * ready for used
			 */
			if (child_sa->rekey_event_cb)
				child_sa->rekey_event_cb(0, child_sa->id, 0);
		}

		return err;
	}

	BUG_ON(sa_is_child(sa));

	/* SA is single i.e has no child and can't be child for other SA */

	/* Flush policies i.e remove PCD entries that direct traffic to SEC */
	err = sa_flush_policies(sa);
	if (err < 0) {
		log_err("Could not flush outbound policies\n");
		return err;
	}

	/* destroy SA manip, if one was initialized */
	if (sa->ipsec_hmd != DPA_OFFLD_DESC_NONE) {
		struct hmd_entry hmd_entry;
		hmd_entry.hmd = sa->ipsec_hmd;
		hmd_entry.hmd_special_op = true;
		err = destroy_recycle_manip(sa, &hmd_entry);
		if (err < 0) {
			log_err("Couldn't delete SA manip\n");
			return err;
		}
		sa->ipsec_hmd = DPA_OFFLD_DESC_NONE;
	}

	/* Destroy the TO_SEC and FROM_SEC queues */
	err = remove_sa_fq_pair(sa);
	if (err < 0) {
		log_err("Could not remove the SEC frame queues\n");
		return err;
	}

	/* Mark SA as free */
	err = put_sa(sa);
	if (err < 0) {
		log_err("Could not recycle the SA id %d\n", sa->id);
		return err;
	}

	return 0;
}

/*
 * Function description:
 *
 * SA is single (has no child SA and its not a child for other SA):
 *	- acquire lock for SA, return -EAGAIN if lock is contended.
 * SA is child:
 *	- return error code -EINPROGRESS since this SA is in rekeying process
 *	- to remove this SA first must be removed its parent SA using API or the
 *	  rekeying process finished successfully for this SA
 * SA is parent:
 *	- always acquire parent SA lock before child SA lock
 *	- acquire lock for SA, return -EAGAIN if lock is contended
 *	- acquire lock for SA's child, return -EAGAIN if lock is contended
 *	- call remove_inbound_sa or remove_outbound_sa depending on the SA
 *	  direction, which will do the work required and call the rekeying
 *	  callback to inform upper layer about the child SA success.
 *	  Returned code:
 *		a. -ENOTRECOVERABLE if failed to removed the
 *		    PCD entry of the inbound SA that makes traffic go to SEC.
 *		    recommended action: recall this function for several times
 *		    and if the returned code is the same, then reboot the system
 *		b. -ETIME if the parent SA's TO SEC FQ is not yet empty
 *		c. -EIO if failed to schedule the child's TO SEC FQ. Unlikely.
 *		d. -EUCLEAN if parent SA needs cleaning (its TO SEC FQ couldn't
 *		    be removed)
 *		e. -EDQUOT if failed to recycle the parent SA.
 *	  In case of -EUCLEAN and -EDQUOT the recommended action is to call
 *	  dpa_ipsec_remove with the parent SA id. Child SA id is ready to work.
 *	- release SA's child lock
 *	- release SA lock
 */
int dpa_ipsec_remove_sa(int sa_id)
{
	struct dpa_ipsec_sa *sa, *child_sa = NULL;
	struct dpa_ipsec *dpa_ipsec;
	int ret = 0;

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	/* Always acquire parent lock before child's lock */
	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		log_err("Failed to acquire lock for SA %d\n", sa->id);
		ret = -EAGAIN;
		goto out;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -ENODEV;
		goto out;
	}

	if (sa_is_child(sa)) {
		log_err("This SA %d is a child in rekeying process\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -EINPROGRESS;
		goto out;
	}

	/* SA is parent? If so acquire its child's lock */
	if (sa_is_parent(sa)) {
		child_sa = sa->child_sa;
		ret = mutex_trylock(&child_sa->lock);
		if (ret == 0) {
			mutex_unlock(&sa->lock);
			ret = -EAGAIN;
			goto out;
		}
	}

	if (sa_is_inbound(sa))
		ret = remove_inbound_sa(sa);
	else
		ret = remove_outbound_sa(sa);

	/* Release child's lock first */
	if (child_sa)
		mutex_unlock(&child_sa->lock);

	/* Release parent lock */
	mutex_unlock(&sa->lock);

out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_remove_sa);

int dpa_ipsec_sa_add_policy(int sa_id,
			    struct dpa_ipsec_policy_params *policy_params)
{
	struct dpa_ipsec_policy_entry *policy_entry;
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	int ret = 0;

	if (!policy_params) {
		log_err("Invalid policy params handle\n");
		return -EINVAL;
	}

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		log_err("Failed to acquire lock for SA %d\n", sa->id);
		ret = -EAGAIN;
		goto out;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -ENODEV;
		goto out;
	}

	BUG_ON(!sa->dpa_ipsec);
	mutex_lock(&sa->dpa_ipsec->lock);
	if (sa_is_inbound(sa) &&
	    !sa->dpa_ipsec->config.post_sec_in_params.do_pol_check) {
		log_err("Inbound policy verification is disabled.\n");
		mutex_unlock(&sa->dpa_ipsec->lock);
		mutex_unlock(&sa->lock);
		ret = -EPERM;
		goto out;
	}
	mutex_unlock(&sa->dpa_ipsec->lock);

	ret = check_policy_params(sa, policy_params);
	if (ret < 0) {
		mutex_unlock(&sa->lock);
		goto out;
	}

	if (sa_is_parent(sa) && sa_is_outbound(sa)) {
		log_err("Illegal to set out policy - parent SA %d\n", sa->id);
		mutex_unlock(&sa->lock);
		ret = -EPERM;
		goto out;
	}

	if (sa_is_child(sa) && sa_is_inbound(sa)) {
		log_err("Illegal to set in policy on child SA %d\n", sa->id);
		mutex_unlock(&sa->lock);
		ret = -EPERM;
		goto out;
	}

	/*
	 * One SA could have more in/out policies
	 * Store all the in/out policies into the SA policy param list in order
	 * to know what to remove when SA expires.
	 */
	ret = store_policy_param_to_sa_pol_list(sa, policy_params,
						&policy_entry);
	if (ret < 0) {
		log_err("Could not store the policy in the SA\n");
		mutex_unlock(&sa->lock);
		goto out;
	}

	/*Insert inbound or outbound policy for this SA depending on it's type*/
	if (sa_is_inbound(sa)) {
		ret = update_inbound_policy(sa, policy_entry, MNG_OP_ADD);
		if (ret < 0) {
			remove_policy_from_sa_policy_list(sa, policy_entry);
			log_err("Could not add the inbound policy\n");
		}
	} else {  /* DPA_IPSEC_OUTBOUND */
		ret = update_outbound_policy(sa, policy_entry, MNG_OP_ADD);
		if (ret < 0) {
			remove_policy_from_sa_policy_list(sa, policy_entry);
			log_err("Could not add the outbound policy\n");
		}
	}

	mutex_unlock(&sa->lock);
out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_sa_add_policy);

int dpa_ipsec_sa_remove_policy(int sa_id,
			       struct dpa_ipsec_policy_params *policy_params)
{
	struct dpa_ipsec_policy_entry *policy_entry;
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	int ret = 0;

	if (!policy_params) {
		log_err("Invalid policy parameters handle\n");
		return -EINVAL;
	}

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		log_err("Failed to acquire lock for SA %d\n", sa->id);
		ret = -EAGAIN;
		goto out;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -ENODEV;
		goto out;
	}

	if (sa_is_inbound(sa) &&
	    !sa->dpa_ipsec->config.post_sec_in_params.do_pol_check) {
		log_err("Inbound policy verification is disabled.\n");
		mutex_unlock(&sa->lock);
		ret = -EPERM;
		goto out;
	}

	if (sa_is_parent(sa) && sa_is_outbound(sa)) {
		log_err("Illegal removing out policy parent SA %d\n", sa->id);
		mutex_unlock(&sa->lock);
		ret = -EPERM;
		goto out;
	}

	if (sa_is_child(sa) && sa_is_inbound(sa)) {
		log_err("Illegal removing in policy, child SA %d\n", sa->id);
		mutex_unlock(&sa->lock);
		ret = -EPERM;
		goto out;
	}

	ret = find_policy(sa, policy_params, &policy_entry);
	if (ret < 0) {
		log_err("Could not find policy entry in SA policy list\n");
		mutex_unlock(&sa->lock);
		goto out;
	}

	/*
	 * found the policy entry in SA policy parameter list;
	 * depending on the type of the SA remove the PCD entry for this policy
	 * and afterwards remove the policy param from SA policy param list
	 */
	ret = remove_policy(sa, policy_entry);

	mutex_unlock(&sa->lock);

out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_sa_remove_policy);

/*
 * Returned error code: -EUSERS
 *	- if both parent SA and child SA are in invalid state, some or none of
 *	  the old's policies were safely transfered to the child SA but some
 *	  policies remained offloaded through parent SA.
 */
int dpa_ipsec_sa_rekeying(int sa_id,
			  struct dpa_ipsec_sa_params *sa_params,
			  dpa_ipsec_rekey_event_cb rekey_event_cb,
			  bool auto_rmv_old_sa,
			  int *new_sa_id)
{
	struct dpa_ipsec *dpa_ipsec = NULL;
	struct dpa_ipsec_sa_mng *sa_mng = NULL;
	struct dpa_ipsec_sa *old_sa, *new_sa;
	struct dpa_ipsec_policy_entry *policy_entry, *tmp_policy_entry;
	struct timeval timeval;
	unsigned long jiffies_to_wait;
	uint32_t id;
	int ret = 0, err_rb;

	if (!new_sa_id) {
		log_err("Invalid SA ID holder\n");
		return -EINVAL;
	}
	*new_sa_id = DPA_OFFLD_INVALID_OBJECT_ID;

	ret = check_sa_params(sa_params);
	if (ret < 0)
		return ret;

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	old_sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!old_sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		put_instance(dpa_ipsec);
		return -EINVAL;
	}

	/* Acquire parent SA's lock */
	ret = mutex_trylock(&old_sa->lock);
	if (ret == 0) {
		log_err("Failed to acquire lock for SA %d\n", old_sa->id);
		put_instance(dpa_ipsec);
		return -EBUSY;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(old_sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		mutex_unlock(&old_sa->lock);
		put_instance(dpa_ipsec);
		return -ENODEV;
	}

	/* Check if SA is currently in rekeying process */
	if (sa_currently_in_rekeying(old_sa)) {
		log_err("SA with id %d is already in rekeying process\n",
			  old_sa->id);
		mutex_unlock(&old_sa->lock);
		put_instance(dpa_ipsec);
		return -EEXIST;
	}

	/* Check if new SA parameters are matching the rekeyed SA */
	if (old_sa->sa_dir != sa_params->sa_dir) {
		log_err("New SA parameters don't match the parent SA %d\n",
			  old_sa->sa_dir);
		mutex_unlock(&old_sa->lock);
		put_instance(dpa_ipsec);
		return -EINVAL;
	}

	ret = get_new_sa(dpa_ipsec, &new_sa, &id);
	if (ret < 0) {
		log_err("Failed retrieving a preallocated SA\n");
		mutex_unlock(&old_sa->lock);
		put_instance(dpa_ipsec);
		return ret;
	}

	/* Update the new SA structure */
	mutex_lock(&new_sa->lock);
	new_sa->dpa_ipsec = old_sa->dpa_ipsec;
	new_sa->inbound_flowid = old_sa->inbound_flowid;
	new_sa->ipsec_hmd = old_sa->ipsec_hmd;
	new_sa->valid_flowid_entry = false;
	new_sa->rekey_event_cb = rekey_event_cb;
	new_sa->parent_sa = old_sa;
	new_sa->child_sa  = NULL;
	new_sa->sa_rekeying_node.next = LIST_POISON1;
	new_sa->sa_rekeying_node.prev = LIST_POISON2;
	old_sa->child_sa = new_sa;
	old_sa->parent_sa = NULL;

	/* Copy SA params into the internal SA structure */
	if (sa_is_outbound(old_sa))
		ret = copy_sa_params_to_out_sa(new_sa, sa_params);
	else
		ret = copy_sa_params_to_in_sa(new_sa, sa_params, true);

	if (ret < 0) {
		log_err("Could not copy SA parameters into SA\n");
		goto rekey_sa_err;
	}

	/* Initialize the IPSec Manip. object (if required) for inbound SAs */
	if (sa_is_inbound(new_sa)) {
		if (new_sa->dpa_ipsec->config.max_sa_manip_ops == 0)
			ret = create_ipsec_manip(new_sa, DPA_OFFLD_DESC_NONE,
						 &new_sa->ipsec_hmd);
		else
			ret = update_ipsec_manip(new_sa, DPA_OFFLD_DESC_NONE,
						 &new_sa->ipsec_hmd);
		if (ret < 0) {
			log_err("Could not create Manip object for in SA!\n");
			goto rekey_sa_err;
		}
	}

	/* Generate the split key from the normal auth key */
	ret = generate_split_key(&new_sa->auth_data);
	if (ret < 0)
		goto rekey_sa_err;

	/*
	 * Update the new SA with information from the old SA
	 * The from SEC frame queue of the old SA will be used by the new SA
	 */
	memcpy(new_sa->from_sec_fq, old_sa->from_sec_fq,
	       sizeof(struct qman_fq));

	/* Exact match table will be reused by the new SA. */
	new_sa->em_inpol_td = old_sa->em_inpol_td;

	/* Create SEC queues according to SA parameters */
	ret = create_sa_fq_pair(new_sa, true, true);
	if (ret < 0) {
		log_err("Could not create SEC frame queues\n");
		goto rekey_sa_err;
	}

	timeval.tv_sec = 0;
	timeval.tv_usec = REKEY_SCHED_DELAY;
	jiffies_to_wait = timeval_to_jiffies(&timeval);

	/*
	 * AV's note: Since we have reused the FROM SEC FQ it is not needed to
	 * make another entry in the table of the post SEC OH PORT.
	 */
	if (sa_is_outbound(new_sa)) {
		INIT_LIST_HEAD(&new_sa->policy_headlist);

		/* Update child's SA policies if its parent SA has policies */
		list_for_each_entry_safe(policy_entry, tmp_policy_entry,
					 &old_sa->policy_headlist, node) {
			ret = update_outbound_policy(new_sa, policy_entry,
						     MNG_OP_MODIFY);
			if (ret < 0) {
				/* Keep both SAs and delete the using remove*/
				*new_sa_id = new_sa->id;
				log_err("Could't modify outbound policy for rekeying SA %d\n",
					new_sa->id);
				new_sa->parent_sa = NULL;
				new_sa->child_sa  = NULL;
				old_sa->child_sa  = NULL;
				old_sa->parent_sa = NULL;
				/*
				 * AV's note TODO: investigate the removal of FQ
				 * to SEC even is it has frames in it and is in
				 * parked state
				 */
				mutex_unlock(&new_sa->lock);
				mutex_unlock(&old_sa->lock);
				put_instance(dpa_ipsec);
				return -EUSERS;
			}
			list_del(&policy_entry->node);
			list_add(&policy_entry->node, &new_sa->policy_headlist);
		}

		/*
		 * Need to destroy the old SA. Have to wail until its TO SEC
		 * FQ is empty. This is done in work queue, schedule it.
		 */
		sa_mng = &dpa_ipsec->sa_mng;

		mutex_lock(&sa_mng->sa_rekeying_headlist_lock);
		list_add_tail(&new_sa->sa_rekeying_node,
			      &sa_mng->sa_rekeying_headlist);
		mutex_unlock(&sa_mng->sa_rekeying_headlist_lock);

		queue_delayed_work(sa_mng->sa_rekeying_wq,
				   &sa_mng->sa_rekeying_work,
				   jiffies_to_wait);
	} else {	/* DPA_IPSEC_INBOUND */
		/* Need to update the IN SA PCD entry */
		ret = update_pre_sec_inbound_table(new_sa, MNG_OP_ADD);
		if (ret < 0) {
			log_err("Could not add PCD entry for new SA\n");
			goto rekey_sa_err;
		}

		if (auto_rmv_old_sa) {
			sa_mng = &dpa_ipsec->sa_mng;
			/* Add new SA into the sa_rekeying_headlist */
			mutex_lock(&sa_mng->sa_rekeying_headlist_lock);
			list_add_tail(&new_sa->sa_rekeying_node,
				      &sa_mng->sa_rekeying_headlist);
			mutex_unlock(&sa_mng->sa_rekeying_headlist_lock);

			/* schedule inbound SA's rekeying */
			queue_delayed_work(sa_mng->sa_rekeying_wq,
					   &sa_mng->sa_rekeying_work,
					   jiffies_to_wait);
		} else {
			/*
			 * The old SA has to be removed using the
			 * dpa_ipsec_remove_sa function when the hard SA
			 * expiration time limit is reached.
			 *
			 * Since the difference between soft and hard limit
			 * can be several seconds it is required to schedule the
			 * TO SEC FQ of the new SA.
			 */
			ret = qman_schedule_fq(new_sa->to_sec_fq);
			if (ret < 0) {
				mutex_unlock(&new_sa->lock);
				mutex_unlock(&old_sa->lock);
				put_instance(dpa_ipsec);
				return ret;
			}
		}
	}

	/* Rekeying done ok. */
	*new_sa_id = new_sa->id;
	mutex_unlock(&new_sa->lock);
	mutex_unlock(&old_sa->lock);

	put_instance(dpa_ipsec);

	return 0;

/*
 * Rekeying failed before updating/adding any table entry.
 * It is safe to remove new SA
 */
rekey_sa_err:
	/*
	 * If rollback was successful return an invalid ID for new SA,
	 * otherwise return the acquired SA id so that upper layer could use it
	 * in subsequent attempts of removing it by calling dpa_ipsec_remove_sa
	 */

	err_rb = rollback_rekeying_sa(new_sa);
	if (err_rb < 0)
		*new_sa_id = new_sa->id;

	mutex_unlock(&new_sa->lock);
	mutex_unlock(&old_sa->lock);

	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_sa_rekeying);

/*
 * Expects that SA's parent and SA's lock are acquired in this order.
 *
 * Function description:
 *	1. wait until TO SEC FQ is empty or timeout
 *	2. schedule the child TO SEC FQ
 *	3. remove the parent TO SEC FQ
 *	4. free all memory used for this SA i.e recycle this SA
 *
 * Rekeying process successful if the returned error was: 0, -EUCLEAN, -EDQUOT
 *	- error code 0 for perfect rekeying
 *	- error code -EUCLEAN if during rekeying process the removal of the
 *	  TO SEC FQ of old SA failed. Upper layer has to call the
 *	  dpa_ipsec_remove_sa at a later time (not from callback) to try again
 *	  freeing old SA resources. New SA is working perfectly.
 *	- error code -EDQUOT if failed to recycle old SA memory. Upper layer
 *	  has to call the dpa_ipsec_remove_sa at a later time (not from
 *	  callback)to try again recycling old SA.
 *
 * Rekeying process in progress if the returned error is: -ETIME or -EIO.
 *	- error code -ETIME if timeout occurred when waiting for old SA TO SEC
 *	  FQ to get empty. Upper layer has nothing to do since the old SA TO
 *	  SEC FQ will get empty eventually.
 *	- error code -EIO if rekeying failed to schedule the new SA. Upper layer
 *	  has nothing to do since the new SA TO SEC FQ will get scheduled
 *	  eventually.
 */
static int sa_rekeying_outbound(struct dpa_ipsec_sa *new_sa)
{
	struct dpa_ipsec_sa *old_sa;
	int err, timeout = WAIT4_FQ_EMPTY_TIMEOUT; /* microseconds */

	old_sa = new_sa->parent_sa;
	BUG_ON(!old_sa);

	err = wait_until_fq_empty(old_sa->to_sec_fq, timeout);
	if (err < 0) {
		log_err("Waiting old SA's TO SEC FQ to get empty. Timeout\n");
		return -ETIME;
	}

	/* Schedule the new SA */
	err = qman_schedule_fq(new_sa->to_sec_fq);
	if (unlikely(err < 0)) {
		log_err("Scheduling the new SA %d failed\n", new_sa->id);
		return -EIO;
	}

	/* Now free the old SA structure and all its resources */
	err = remove_sa_sec_fq(old_sa, old_sa->to_sec_fq);
	if (err < 0) {
		log_err("Couln't remove old SA's %d TO SEC FQ\n", old_sa->id);
		rekey_err_report(new_sa->rekey_event_cb, 0, new_sa->id,
				 -EUCLEAN);
		return -EUCLEAN;
	}

	/* Recycle SA memory */
	err = put_sa(old_sa);
	if (unlikely(err < 0)) {
		log_err("Could not recycle parent SA.\n");
		rekey_err_report(new_sa->rekey_event_cb, 0, new_sa->id,
				 -EDQUOT);
		return -EDQUOT;
	}

	return 0;
}

/*
 * Expects that SA's parent and SA's lock are acquired in this order.
 *
 * Function description:
 * Rekeying process successful if the returned error was: 0, -EUCLEAN, -EDQUOT
 *	- error code 0 for perfect rekeying
 *	- error code -EUCLEAN if during rekeying process the removal of the
 *	  TO SEC FQ of old SA failed. Upper layer has to call the
 *	  dpa_ipsec_remove_sa at a later time (not from callback) to try again
 *	  freeing old SA resources. New SA is working perfectly.
 *	- error code -EDQUOT if failed to recycle old SA memory. Upper layer
 *	  has to call the dpa_ipsec_remove_sa at a later time (not from
 *	  callback)to try again recycling old SA.
 *
 * Rekeying process in progress if the returned error is: -EINPROGRESS, -ETIME
 *	  or -EIO.
 *	- error code -EINPROGRESS if no frame arrived on the new SA TO SEC FQ.
 *	  If HARD expiration event occurs on the old SA and rekeying is still
 *	  in progress the upper layer should call the dpa_ipsec_remove_sa with
 *	  old SA id which will remove old SA and will automatically schedule
 *	  new SA even if no frames have arrived on the new SA TO SEC FQ.
 *	- error code -ETIME if timeout occurred when waiting for old SA TO SEC
 *	  FQ to get empty. Upper layer has nothing to do since the old SA TO
 *	  SEC FQ will get empty eventually.
 *	- error code -EIO if rekeying failed to schedule the new SA. Upper layer
 *	  has nothing to do since the old SA TO SEC FQ will get scheduled
 *	  eventually.
 *
 * Rekeying in critical state: -ENOTRECOVERABLE
 *	- Failed to delete the hash entry formed by old SA (SPI, ...)
 *	- If an attacker would sent frames matching the old SA (SPI, ...) than
 *	  FMAN will direct those frames to old SA FQ. In this case the wait
 *	  until old SA FQ is empty is not valid, since being attacked this FQ
 *	  might not get empty.
 *	  There is a tiny probability that above scenario to happen, but if it
 *	  does for several times on the same SA the recommended action would
 *	  be to call the dpa_ipsec_remove_sa with the parent SA id. In case this
 *	  function also fails several times then we recommend to reboot the
 *	  system.
 */
static int sa_rekeying_inbound(struct dpa_ipsec_sa *new_sa)
{
	struct dpa_ipsec_sa *old_sa;
	struct qm_mcr_queryfq_np queryfq_np;
	int err = 0, timeout = WAIT4_FQ_EMPTY_TIMEOUT; /* microseconds */

	/* Check if the new SA TO SEC FQ has frame descriptors enqueued in it */
	qman_query_fq_np(new_sa->to_sec_fq, &queryfq_np);
	if (queryfq_np.frm_cnt == 0)
		return -EINPROGRESS;

	/*
	 * Received at least one packet encrypted with the new SA.
	 * Remove PCD entry that makes traffic go to SEC if the entry is valid.
	 */
	old_sa = new_sa->parent_sa;
	BUG_ON(!old_sa);

	if (old_sa->inbound_hash_entry != DPA_OFFLD_INVALID_OBJECT_ID) {
		err = remove_inbound_hash_entry(old_sa);
		if (err < 0) {
			rekey_err_report(new_sa->rekey_event_cb, 0, new_sa->id,
					 err);
			if (err == -ENOTRECOVERABLE)
				return err;
		}

		/* destroy SA manip */
		if (old_sa->ipsec_hmd != DPA_OFFLD_DESC_NONE) {
			struct hmd_entry hmd_entry;
			hmd_entry.hmd = old_sa->ipsec_hmd;
			hmd_entry.hmd_special_op = true;
			err = destroy_recycle_manip(old_sa, &hmd_entry);
			if (err < 0) {
				log_err("Could not delete manip object!\n");
				return err;
			}
			old_sa->ipsec_hmd = DPA_OFFLD_DESC_NONE;
		}
	}

	err = wait_until_fq_empty(old_sa->to_sec_fq, timeout);
	if (err < 0) {
		log_err("Waiting old SA's TO SEC FQ to get empty. Timeout\n");
		return -ETIME;
	}

	/* schedule new inbound SA */
	err = qman_schedule_fq(new_sa->to_sec_fq);
	if (unlikely(err < 0)) {
		log_err("Scheduling the new SA %d failed\n", new_sa->id);
		return -EIO;
	}

	/* Update the new SA with old SA's inbound indx entry */
	new_sa->valid_flowid_entry = old_sa->valid_flowid_entry;

	/* Inherit old SA policy list and then set it empty */
	if (old_sa->dpa_ipsec->config.post_sec_in_params.do_pol_check)
		list_splice_init(&old_sa->policy_headlist,
				 &new_sa->policy_headlist);

	/* Now free the old SA structure and all its resources */
	err = remove_sa_sec_fq(old_sa, old_sa->to_sec_fq);
	if (err < 0) {
		log_err("Couln't remove old SA's %d TO SEC FQ\n", old_sa->id);
		rekey_err_report(new_sa->rekey_event_cb, 0, new_sa->id,
				 -EUCLEAN);
		return -EUCLEAN;
	}

	/* Recycle SA memory */
	err = put_sa(old_sa);
	if (unlikely(err < 0)) {
		log_err("Could not recycle parent SA.\n");
		rekey_err_report(new_sa->rekey_event_cb, 0, new_sa->id,
				 -EDQUOT);
		return -EDQUOT;
	}

	return 0;
}

static inline struct dpa_ipsec_sa *find_and_lock_sa_to_work_on(
					struct dpa_ipsec_sa *child_sa,
					struct dpa_ipsec_sa_mng *sa_mng)
{
	struct dpa_ipsec_sa *parent_sa;
	struct list_head *head;
	int err;

	head = &sa_mng->sa_rekeying_headlist;

	list_for_each_entry_continue(child_sa, head, sa_rekeying_node) {
		parent_sa = child_sa->parent_sa;
		BUG_ON(!parent_sa);

		/* Always acquire parent SA lock before child SA lock */
		err = mutex_trylock(&parent_sa->lock);
		if (err == 0)
			continue;

		/* Acquire child SA lock */
		err = mutex_trylock(&child_sa->lock);
		if (err == 0) {
			mutex_unlock(&parent_sa->lock);
			continue;
		}

		return child_sa;
	}

	return NULL;
}

void sa_rekeying_work_func(struct work_struct *work)
{
	struct dpa_ipsec_sa_mng *sa_mng;
	struct dpa_ipsec_sa *child_sa, *parent_sa, *next_child_sa, *pos;
	struct list_head *head;
	int err;

	sa_mng = container_of((struct delayed_work *)work,
			      struct dpa_ipsec_sa_mng, sa_rekeying_work);

	/* Acquire protective lock for the SA rekeying list */
	mutex_lock(&sa_mng->sa_rekeying_headlist_lock);

	head = &sa_mng->sa_rekeying_headlist;
	pos = container_of(head, struct dpa_ipsec_sa, sa_rekeying_node);

	child_sa = find_and_lock_sa_to_work_on(pos, sa_mng);

	/* Release the list lock so other threads may use it */
	mutex_unlock(&sa_mng->sa_rekeying_headlist_lock);

	while (child_sa) {
		parent_sa = child_sa->parent_sa;
		BUG_ON(!parent_sa);

		/* Process this child SA accordingly */
		if (sa_is_outbound(child_sa))
			err = sa_rekeying_outbound(child_sa);
		else /* DPA_IPSEC_INBOUND */
			err = sa_rekeying_inbound(child_sa);

		/* Acquire protective lock for the SA rekeying list */
		mutex_lock(&sa_mng->sa_rekeying_headlist_lock);

		next_child_sa = find_and_lock_sa_to_work_on(child_sa, sa_mng);

		/* Remove child SA from rekeying list if processing was OK */
		if (err == 0 || err == -EUCLEAN || err == -EDQUOT) {
			parent_sa->child_sa = NULL;
			child_sa->parent_sa = NULL;
			list_del(&child_sa->sa_rekeying_node);
		}

		/* Release the list lock so other threads may use it */
		mutex_unlock(&sa_mng->sa_rekeying_headlist_lock);

		if (err == 0 && child_sa->rekey_event_cb)
			child_sa->rekey_event_cb(0, child_sa->id, err);

		/*
		 * Parent SA lock is always acquired before child SA lock so
		 * unlocking them is done backwards
		 */
		mutex_unlock(&child_sa->lock);
		mutex_unlock(&parent_sa->lock);

		child_sa = next_child_sa;
	}

	/* Acquire protective lock for the sa rekeying list */
	mutex_lock(&sa_mng->sa_rekeying_headlist_lock);

	/* Reschedule work if there is at least one SA in rekeying process */
	if (!list_empty(head)) {
		struct dpa_ipsec *instance;
		struct timeval timeval;
		unsigned long jiffies_to_wait;

		timeval.tv_sec = 0;
		timeval.tv_usec = REKEY_SCHED_DELAY;
		jiffies_to_wait = timeval_to_jiffies(&timeval);

		instance = container_of(sa_mng, struct dpa_ipsec, sa_mng);
		if (atomic_read(&instance->valid))
			queue_delayed_work(sa_mng->sa_rekeying_wq,
					   &sa_mng->sa_rekeying_work,
					   jiffies_to_wait);
	}

	/* Release protective lock for the SA rekeying list */
	mutex_unlock(&sa_mng->sa_rekeying_headlist_lock);

	return;
}

/*
 * Functional description:
 *
 * Removes the PCD entries that make traffic go to SEC for the SA given as input
 *
 * Returns:
 *	- operation successful, returned code 0
 *	- resource currently busy try again, returned code -EAGAIN
 *	- remove inbound entry failed, returned code -ENOTRECOVERABLE
 *	- remove outbound policies failed, at least one policy for this SA is
 *	  still in the system, returned code -EBADSLT
 */
int dpa_ipsec_disable_sa(int sa_id)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	int ret = 0, err = 0;

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	/* Acquire protective lock for this SA */
	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		ret = -EAGAIN;
		goto out;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -ENODEV;
		goto out;
	}

	if (!sa_is_single(sa)) {
		log_err("SA %d is a parent or child in rekeying\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -EINPROGRESS;
		goto out;
	}

	if (sa_is_inbound(sa) &&
	    sa->inbound_hash_entry != DPA_OFFLD_INVALID_OBJECT_ID)
		ret = remove_inbound_hash_entry(sa);
	else { /* DPA_IPSEC_OUTBOUND */
		err = sa_flush_policies(sa);
		if (err < 0)
			ret = -EBADSLT;
	}

	/* Release protective lock for this SA */
	mutex_unlock(&sa->lock);
out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_disable_sa);

/*
 * Flush all SAs. If an error occurs while removing an SA, the flush process
 * will continue with the next SAs and the return value will be -EAGAIN,
 * which informs the upper layer that there is still at least one SA left
 */
int dpa_ipsec_flush_all_sa(int dpa_ipsec_id)
{
	struct dpa_ipsec *dpa_ipsec;
	uint32_t i, sa_id;
	int err = 0, ret;

	dpa_ipsec = get_instance(dpa_ipsec_id);
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	flush_delayed_work(&dpa_ipsec->sa_mng.sa_rekeying_work);

	for (i = 0; i < dpa_ipsec->sa_mng.max_num_sa; i++) {
		mutex_lock(&dpa_ipsec->lock);
		sa_id = dpa_ipsec->used_sa_ids[i];
		mutex_unlock(&dpa_ipsec->lock);

		if (sa_id != DPA_OFFLD_INVALID_OBJECT_ID) {
			ret = dpa_ipsec_remove_sa(sa_id);
			if (ret < 0)
				err = -EAGAIN;
		}
	}

	put_instance(dpa_ipsec);

	return err;
}
EXPORT_SYMBOL(dpa_ipsec_flush_all_sa);

int dpa_ipsec_sa_get_policies(int sa_id,
			      struct dpa_ipsec_policy_params *policy_params,
			      int *num_pol)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	int ret;

	if (!num_pol) {
		log_err("Invalid num_pol parameter handle\n");
		return -EINVAL;
	}

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		log_err("Failed to acquire lock for SA %d\n", sa->id);
		ret = -EBUSY;
		goto out;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -ENODEV;
		goto out;
	}

	if (sa_is_inbound(sa) &&
	    !sa->dpa_ipsec->config.post_sec_in_params.do_pol_check) {
		log_err("Inbound policy verification is disabled.\n");
		mutex_unlock(&sa->lock);
		ret = -EPERM;
		goto out;
	}

	if (!policy_params) {
		/* get the number of policies for SA with id sa_id */
		*num_pol = get_policy_count_for_sa(sa);
		mutex_unlock(&sa->lock);
		ret = 0;
		goto out;
	}

	ret = copy_all_policies(sa, policy_params, *num_pol);

	mutex_unlock(&sa->lock);
out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_sa_get_policies);

/* Expects that SA structure is locked */
static int sa_flush_policies(struct dpa_ipsec_sa *sa)
{
	struct dpa_ipsec_policy_entry *pol_entry, *tmp;
	int err = 0, ret = 0;

	BUG_ON(!sa);

	list_for_each_entry_safe(pol_entry, tmp, &sa->policy_headlist, node) {
		err = remove_policy(sa, pol_entry);
		if (err < 0) {
			log_err("Failed remove policy entry SA %d\n", sa->id);
			ret = -EAGAIN;
			/*
			 * continue with the other policies even if error
			 * occured for this policy
			 */
		}
	}

	return ret;
}

int dpa_ipsec_sa_flush_policies(int sa_id)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	int ret = 0;

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		log_err("Failed to acquire lock for SA %d\n", sa->id);
		ret = -EBUSY;
		goto out;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -ENODEV;
		goto out;
	}

	if (sa_is_inbound(sa) &&
	    !sa->dpa_ipsec->config.post_sec_in_params.do_pol_check) {
		log_err("Inbound policy verification is disabled.\n");
		mutex_unlock(&sa->lock);
		ret = -EPERM;
		goto out;
	}

	ret = sa_flush_policies(sa);

	mutex_unlock(&sa->lock);
out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_sa_flush_policies);

int dpa_ipsec_sa_get_stats(int sa_id, struct dpa_ipsec_sa_stats *sa_stats)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	int ret = 0, dscp_idx = 0;
	uint32_t *desc;
	struct dpa_cls_tbl_entry_stats stats;

	if (!sa_stats) {
		log_err("Invalid SA statistics storage pointer\n");
		return -EINVAL;
	}

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		log_err("Failed to acquire lock for SA %d\n", sa->id);
		ret = -EBUSY;
		goto out;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		ret = -ENODEV;
		goto sa_get_stats_return;
	}

	memset(sa_stats, 0, sizeof(*sa_stats));

	if (!sa->enable_stats) {
		log_err("Statistics are not enabled for SA id %d\n", sa_id);
		ret = -EPERM;
		goto sa_get_stats_return;
	}

	desc = (uint32_t *)sa->sec_desc->desc;
	if (!sa->sec_desc_extended) {
		sa_stats->packets_count =
				be32_to_cpu(*(desc + sa->stats_offset / 4));
		sa_stats->bytes_count =
				be32_to_cpu(*(desc + sa->stats_offset / 4 + 1));
	} else {
		sa_stats->bytes_count =
				be32_to_cpu(*(desc + sa->stats_offset / 4));
		sa_stats->packets_count =
				be32_to_cpu(*(desc + sa->stats_offset / 4 + 1));
	}

	if (!sa->enable_extended_stats)
		goto sa_get_stats_return;

	if (sa_is_inbound(sa)) { /* Inbound SA */
		memset(&stats, 0, sizeof(stats));
		ret = dpa_classif_table_get_entry_stats_by_ref(
					sa->inbound_sa_td,
					sa->inbound_hash_entry,
					&stats);
		if (ret != 0) {
			log_err("Failed to acquire total packets counter for inbound SA Id=%d.\n",
				sa_id);
			goto sa_get_stats_return;
		}

		sa_stats->input_packets	= stats.pkts;
	} else { /* Outbound SA */
		struct dpa_ipsec_policy_entry *out_policy;
		struct dpa_ipsec_policy_params *policy_params;
		struct dpa_ipsec_pre_sec_out_params *psop;
		int table_idx, td;

		psop = &sa->dpa_ipsec->config.pre_sec_out_params;

		list_for_each_entry(out_policy, &sa->policy_headlist, node) {
			policy_params = &out_policy->pol_params;
			if (IP_ADDR_TYPE_IPV4(policy_params->dest_addr))
				table_idx = GET_POL_TABLE_IDX(
						policy_params->protocol,
						IPV4);
			else
				table_idx = GET_POL_TABLE_IDX(
						policy_params->protocol,
						IPV6);
			td = psop->table[table_idx].dpa_cls_td;

			/*
			 * In case the SA per DSCP feature is disabled, will
			 * acquire statistics for the policy and exit
			 */
			if (!policy_params->use_dscp) {
				memset(&stats, 0, sizeof(stats));
				ret = dpa_classif_table_get_entry_stats_by_ref(
						td,
						*out_policy->entry_id,
						&stats);
				if (ret != 0) {
					log_err("Failed to acquire total packets counter for outbound SA Id=%d. Failure occured on outbound policy table %d (td=%d).\n",
						sa_id, table_idx, td);
					goto sa_get_stats_return;
				}

				sa_stats->input_packets	+= stats.pkts;
				continue;
			}

			/*
			 * In case the SA per DSCP feature is enabled,
			 * will iterate through all DSCP values
			 * defined for the SA and totalize statistics
			 */
			do {
				memset(&stats, 0, sizeof(stats));
				ret = dpa_classif_table_get_entry_stats_by_ref(
					td,
					out_policy->entry_id[dscp_idx++],
					&stats);

				if (ret != 0) {
					/*
					 * In case of error just print the
					 * message and get to the next value
					 */
					log_err("Failed to acquire packets counter for outbound SA Id=%d. Failure occured on outbound policy table %d (td=%d).\n",
						sa_id, table_idx, td);
					goto sa_get_stats_return;
				}
				sa_stats->input_packets	+= stats.pkts;
			} while (dscp_idx <= sa->dscp_end - sa->dscp_start);
		}
	}

sa_get_stats_return:
	mutex_unlock(&sa->lock);
/* fall through */
out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_sa_get_stats);

int dpa_ipsec_get_stats(int dpa_ipsec_id, struct dpa_ipsec_stats *stats)
{
	t_FmPcdCcKeyStatistics		miss_stats;
	struct dpa_cls_tbl_params	table_params;
	int				i, j, td, ret;
	t_Error				err;
	struct dpa_ipsec		*dpa_ipsec;

	if (!stats) {
		log_err("\"stats\" cannot be NULL.\n");
		return -EINVAL;
	}
	memset(stats, 0, sizeof(*stats));

	dpa_ipsec = get_instance(dpa_ipsec_id);
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	mutex_lock(&dpa_ipsec->lock);

	/* On inbound add up miss counters from all inbound pre-SEC tables: */
	for (i = 0; i < DPA_IPSEC_MAX_SA_TYPE; i++) {
		td = dpa_ipsec->config.pre_sec_in_params.dpa_cls_td[i];

		/*
		 * Check if this policy table is defined by the user. If not,
		 * skip to the next.
		 */
		if (td == DPA_OFFLD_DESC_NONE)
			continue;

		if (dpa_classif_table_get_params(td, &table_params)) {
			log_err("Failed to acquire params for inbound table type %d (td=%d).\n",
				i, td);
			mutex_unlock(&dpa_ipsec->lock);
			put_instance(dpa_ipsec);
			return -EINVAL;
		}
		if (table_params.type == DPA_CLS_TBL_HASH)
			err = FM_PCD_HashTableGetMissStatistics(
						table_params.cc_node,
						&miss_stats);
		else
			err = FM_PCD_MatchTableGetMissStatistics(
					table_params.cc_node,
					&miss_stats);
		if (err != E_OK) {
			log_err("Failed to acquire miss statistics for inbound table type %d (td=%d, Cc node handle=0x%p).\n",
				i, td, table_params.cc_node);
			mutex_unlock(&dpa_ipsec->lock);
			put_instance(dpa_ipsec);
			return -EINVAL;
		} else {
			stats->inbound_miss_pkts += miss_stats.frameCount;
			stats->inbound_miss_bytes += miss_stats.byteCount;
		}
	}

	/* On outbound add miss statistics from all outbound pre-SEC tables: */
	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS; i++) {
		td = dpa_ipsec->config.pre_sec_out_params.table[i].dpa_cls_td;

		/*
		 * Check if this protocol table is defined by the user. If not,
		 * skip to the next.
		 */
		if (td == DPA_OFFLD_DESC_NONE)
			continue;

		/*
		 * Some applications are using the same tables in more than one
		 * role on the outbound, hence we need to check whether we
		 * haven't already processed this table:
		 */
		for (j = 0; j < i; j++) {
			if (td == dpa_ipsec->config.pre_sec_out_params.
							table[j].dpa_cls_td)
				break;
		}

		if (j < i)
			continue;

		if (dpa_classif_table_get_params(td, &table_params)) {
			log_err("Failed to acquire table params for outbound proto type #%d (td=%d).\n",
				i, td);
			mutex_unlock(&dpa_ipsec->lock);
			put_instance(dpa_ipsec);
			return -EINVAL;
		}
		if (table_params.type == DPA_CLS_TBL_HASH)
			err = FM_PCD_HashTableGetMissStatistics(
						table_params.cc_node,
						&miss_stats);
		else
			err = FM_PCD_MatchTableGetMissStatistics(
						table_params.cc_node,
						&miss_stats);
		if (err != E_OK) {
			log_err("Failed to acquire miss statistics for outbound proto type %d (td=%d, Cc node handle=0x%p).\n",
				i, td, table_params.cc_node);
			mutex_unlock(&dpa_ipsec->lock);
			put_instance(dpa_ipsec);
			return -EINVAL;
		} else {
			stats->outbound_miss_pkts += miss_stats.frameCount;
			stats->outbound_miss_bytes += miss_stats.byteCount;
		}
	}

	mutex_unlock(&dpa_ipsec->lock);
	put_instance(dpa_ipsec);

	return 0;
}
EXPORT_SYMBOL(dpa_ipsec_get_stats);

int dpa_ipsec_sa_modify(int sa_id, struct dpa_ipsec_sa_modify_prm *modify_prm)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	dma_addr_t dma_rjobd;
	uint32_t *rjobd;
	struct qm_fd fd;
	char msg[5];
	const size_t msg_len = 5;
	int ret;

	if (!modify_prm) {
		log_err("Invalid modify SA parameter\n");
		return -EINVAL;
	}

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		log_err("SA %d is being used\n", sa->id);
		ret = -EBUSY;
		goto out;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -ENODEV;
		goto out;
	}

	BUG_ON(!sa->dpa_ipsec);

	/* Set the SA id in the message that will be in the output SEC frame */
	*(u32 *)(&msg[1]) = sa->id;

	switch (modify_prm->type) {
	case DPA_IPSEC_SA_MODIFY_ARS:
		msg[0] = DPA_IPSEC_SA_MODIFY_ARS_DONE;
		if (sa_is_outbound(sa)) {
			log_err("ARS update supported only for inbound SA\n");
			ret = -EINVAL;
			goto out;
		}
		ret = build_rjob_desc_ars_update(sa, modify_prm->arw, msg_len);
		if (ret < 0)
			goto out;
		break;
	case DPA_IPSEC_SA_MODIFY_SEQ_NUM:
		msg[0] = DPA_IPSEC_SA_MODIFY_SEQ_NUM_DONE;
		sa->w_seq_num = modify_prm->seq_num;

		ret = build_rjob_desc_seq_write(sa, msg_len);
		if (ret < 0)
			goto out;
		break;
	case DPA_IPSEC_SA_MODIFY_EXT_SEQ_NUM:
		msg[0] = DPA_IPSEC_SA_MODIFY_EXT_SEQ_NUM_DONE;
		sa->w_seq_num = modify_prm->seq_num;

		ret = build_rjob_desc_seq_write(sa, msg_len);
		if (ret < 0)
			goto out;
		break;
	case DPA_IPSEC_SA_MODIFY_CRYPTO:
		log_err("Modifying cryptographic parameters is unsupported\n");
		ret = -EOPNOTSUPP;
		goto out;
	default:
		log_err("Invalid type for modify parameters\n");
		mutex_unlock(&sa->lock);
		ret = -EINVAL;
		goto out;
	}

	rjobd = sa->rjob_desc;

	/* Copy completion message to the end of the RJOB */
	memcpy(((char *)rjobd) + desc_len(rjobd) * CAAM_CMD_SZ, msg, msg_len);

	dma_rjobd = dma_map_single(sa->dpa_ipsec->jrdev, rjobd,
				   desc_len(rjobd) * CAAM_CMD_SZ + msg_len,
				   DMA_BIDIRECTIONAL);
	if (!dma_rjobd) {
		log_err("Failed DMA mapping the RJD for SA %d\n", sa->id);
		mutex_unlock(&sa->lock);
		ret = -ENXIO;
		goto out;
	}

	memset(&fd, 0x00, sizeof(struct qm_fd));
	/* fill frame descriptor parameters */
	fd.format = qm_fd_contig;
	qm_fd_addr_set64(&fd, dma_rjobd);
	fd.length20 = desc_len(rjobd) * sizeof(uint32_t) + msg_len;
	fd.offset = 0;
	fd.bpid = 0;
	fd.cmd = FD_CMD_REPLACE_JOB_DESC;
	ret = qman_enqueue(sa->to_sec_fq, &fd, 0);
	if (ret != 0) {
		log_err("Could not enqueue frame with RJAD for SA %d\n",
			sa->id);
		ret = -ETXTBSY;
	}

	dma_unmap_single(sa->dpa_ipsec->jrdev, dma_rjobd,
			 desc_len(rjobd) * CAAM_CMD_SZ + msg_len,
			 DMA_BIDIRECTIONAL);

	mutex_unlock(&sa->lock);
out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_sa_modify);

int dpa_ipsec_sa_request_seq_number(int sa_id)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	dma_addr_t dma_rjobd;
	uint32_t *rjobd;
	struct qm_fd fd;
	char msg[5];
	const size_t msg_len = 5;
	int ret;

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		log_err("SA %d is being used\n", sa->id);
		ret = -EBUSY;
		goto out;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -ENODEV;
		goto out;
	}

	BUG_ON(!sa->dpa_ipsec);

	if (sa->read_seq_in_progress) {
		log_err("A new request for SA %d can be done only after a get SEQ is done\n",
			sa->id);
		mutex_unlock(&sa->lock);
		ret = -EBUSY;
		goto out;
	}

	msg[0] = DPA_IPSEC_SA_GET_SEQ_NUM_DONE;
	*(u32 *)(&msg[1]) = sa->id;

	ret = build_rjob_desc_seq_read(sa, msg_len);
	if (ret < 0) {
		log_err("Failed to create RJOB for reading SEQ number\n");
		mutex_unlock(&sa->lock);
		goto out;
	}

	rjobd = sa->rjob_desc;

	/* Copy completion message to the end of the RJOB */
	memcpy(((char *)rjobd) + desc_len(rjobd) * CAAM_CMD_SZ, msg, msg_len);

	dma_rjobd = dma_map_single(sa->dpa_ipsec->jrdev, rjobd,
				   desc_len(rjobd) * CAAM_CMD_SZ + msg_len,
				   DMA_BIDIRECTIONAL);
	if (!dma_rjobd) {
		log_err("Failed DMA mapping the RJD for SA %d\n", sa->id);
		mutex_unlock(&sa->lock);
		ret = -ENXIO;
		goto out;
	}

	memset(&fd, 0x00, sizeof(struct qm_fd));
	/* fill frame descriptor parameters */
	fd.format = qm_fd_contig;
	qm_fd_addr_set64(&fd, dma_rjobd);
	fd.length20 = desc_len(rjobd) * sizeof(uint32_t) + msg_len;
	fd.offset = 0;
	fd.bpid = 0;
	fd.cmd = FD_CMD_REPLACE_JOB_DESC;
	ret = qman_enqueue(sa->to_sec_fq, &fd, 0);
	if (ret != 0) {
		log_err("Could not enqueue frame with RJAD for SA %d\n",
			sa->id);
		ret = -ETXTBSY;
	}

	/* Request has been done successfully */
	sa->read_seq_in_progress = true;

	dma_unmap_single(sa->dpa_ipsec->jrdev, dma_rjobd,
			 desc_len(rjobd) * CAAM_CMD_SZ + msg_len,
			 DMA_BIDIRECTIONAL);

	mutex_unlock(&sa->lock);

out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_sa_request_seq_number);

int dpa_ipsec_sa_get_seq_number(int sa_id, uint64_t *seq)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	int ret;

	if (!seq) {
		log_err("Invalid SEQ parameter handle\n");
		return -EINVAL;
	}

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA id %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		log_err("SA %d is being used\n", sa_id);
		ret = -EBUSY;
		goto out;
	}

	/* Abort if this SA is not being used */
	if (!sa_in_use(sa)) {
		log_err("SA with id %d is not in use\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -ENODEV;
		goto out;
	}

	BUG_ON(!sa->dpa_ipsec);

	if (!sa->read_seq_in_progress) {
		log_err("Prior to getting the SEQ number for SA %d a request must be made\n",
			sa->id);
		mutex_unlock(&sa->lock);
		ret = -EBUSY;
		goto out;
	}

	*seq = sa->r_seq_num;
	sa->read_seq_in_progress = false;

	mutex_unlock(&sa->lock);
out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_sa_get_seq_number);

int dpa_ipsec_sa_get_out_path(int sa_id, uint32_t *fqid)
{
	struct dpa_ipsec *dpa_ipsec;
	struct dpa_ipsec_sa *sa;
	int ret;

	if (!fqid) {
		log_err("Invalid fqid handle\n");
		return -EINVAL;
	}

	if (!valid_sa_id(sa_id))
		return -EINVAL;

	dpa_ipsec = get_instance(sa_id_to_instance_id(sa_id));
	ret = check_instance(dpa_ipsec);
	if (unlikely(ret < 0))
		return ret;

	sa = get_sa_from_sa_id(dpa_ipsec, sa_id);
	if (!sa) {
		log_err("Invalid SA handle for SA %d\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	ret = mutex_trylock(&sa->lock);
	if (ret == 0) {
		log_err("SA %d is being used\n", sa_id);
		ret = -EBUSY;
		goto out;
	}

	if (!sa_in_use(sa)) {
		log_err("SA %d is not in use\n", sa_id);
		mutex_unlock(&sa->lock);
		ret = -ENODEV;
		goto out;
	}

	if (sa_is_inbound(sa)) {
		log_err("Illegal to acquire the to SEC frame queue ID for inbound SA %d.\n",
				sa_id);
		mutex_unlock(&sa->lock);
		ret = -EPERM;
		goto out;
	}

	*fqid = qman_fq_fqid(sa->to_sec_fq);

	mutex_unlock(&sa->lock);
	ret = 0;
out:
	put_instance(dpa_ipsec);

	return ret;
}
EXPORT_SYMBOL(dpa_ipsec_sa_get_out_path);
