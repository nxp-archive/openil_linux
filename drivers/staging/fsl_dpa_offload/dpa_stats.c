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

/*
 * DPA Statistics Application Programming Interface implementation
 */

#include <linux/module.h>
#include <linux/of_platform.h>
#include "lnxwrp_fm.h"
#include "mac.h"
#include <linux/fsl_qman.h>

/* DPA offloading layer includes */
#include "dpa_stats.h"
#include "dpa_classifier.h"

/* FMD includes */
#include "fm_pcd_ext.h"

#define UNSUPPORTED_CNT_SEL -1
#define CLASSIF_STATS_SHIFT 4
#define WORKQUEUE_MAX_ACTIVE 3

#define DPA_STATS_US_CNT 0x80000000

#define CHECK_INSTANCE_ZERO \
		if (dpa_stats_id != 0) { \
			log_err("DPA Stats supports only instance zero\n"); \
			return -ENOSYS; \
		}

/* Global dpa_stats component */
struct dpa_stats *gbl_dpa_stats;

static int alloc_cnt_stats(struct stats_info *stats_info,
				unsigned int num_members);

static void init_cnt_32bit_stats(struct stats_info *stats_info,
				 void *stats, uint32_t idx);

static void init_cnt_64bit_stats(struct stats_info *stats_info,
				 void *stats, uint32_t idx);

static int get_cnt_cls_tbl_frag_stats(struct dpa_stats_req_cb *req_cb,
				      struct dpa_stats_cnt_cb *cnt_cb);

static int get_cnt_cls_tbl_match_stats(struct dpa_stats_req_cb *req_cb,
				       struct dpa_stats_cnt_cb *cnt_cb);

static int get_cnt_cls_tbl_hash_stats(struct dpa_stats_req_cb *req_cb,
				      struct dpa_stats_cnt_cb *cnt_cb);

static int get_cnt_cls_tbl_index_stats(struct dpa_stats_req_cb *req_cb,
				       struct dpa_stats_cnt_cb *cnt_cb);

static int get_cnt_ccnode_match_stats(struct dpa_stats_req_cb *req_cb,
				      struct dpa_stats_cnt_cb *cnt_cb);

static int get_cnt_ccnode_hash_stats(struct dpa_stats_req_cb *req_cb,
				     struct dpa_stats_cnt_cb *cnt_cb);

static int get_cnt_ccnode_index_stats(struct dpa_stats_req_cb *req_cb,
				      struct dpa_stats_cnt_cb *cnt_cb);

static int get_cnt_traffic_mng_cq_stats(struct dpa_stats_req_cb *req_cb,
					struct dpa_stats_cnt_cb *cnt_cb);

static int get_cnt_traffic_mng_ccg_stats(struct dpa_stats_req_cb *req_cb,
					 struct dpa_stats_cnt_cb *cnt_cb);

static int get_cnt_us_stats(struct dpa_stats_req_cb *req_cb,
			    struct dpa_stats_cnt_cb *cnt_cb);

static void async_req_work_func(struct work_struct *work);

/* check that the provided params are valid */
static int check_dpa_stats_params(const struct dpa_stats_params *params)
{
	/* Check init parameters */
	if (!params) {
		log_err("DPA Stats instance parameters cannot be NULL\n");
		return -EINVAL;
	}

	/* There must be at least one counter */
	if (params->max_counters == 0 ||
	    params->max_counters > DPA_STATS_MAX_NUM_OF_COUNTERS) {
		log_err("Parameter max_counters %d must be in range (1 - %d)\n",
			params->max_counters, DPA_STATS_MAX_NUM_OF_COUNTERS);
		return -EDOM;
	}

	if (!params->storage_area) {
		log_err("Parameter storage_area cannot be NULL\n");
		return -EINVAL;
	}

	/* Check user-provided storage area length */
	if (params->storage_area_len < DPA_STATS_CNT_SEL_LEN ||
	    params->storage_area_len > DPA_STATS_MAX_STORAGE_AREA_SIZE) {
		log_err("Parameter storage_area_len %d must be in range (%d - %d)\n",
			params->storage_area_len,
			DPA_STATS_CNT_SEL_LEN, DPA_STATS_MAX_STORAGE_AREA_SIZE);
		return -EINVAL;
	}

	return 0;
}

static int set_cnt_classif_tbl_retrieve_func(struct dpa_stats_cnt_cb *cnt_cb)
{
	switch (cnt_cb->tbl_cb.type) {
	case DPA_CLS_TBL_HASH:
		cnt_cb->f_get_cnt_stats = get_cnt_cls_tbl_hash_stats;
		break;
	case DPA_CLS_TBL_INDEXED:
		cnt_cb->f_get_cnt_stats = get_cnt_cls_tbl_index_stats;
		break;
	case DPA_CLS_TBL_EXACT_MATCH:
		cnt_cb->f_get_cnt_stats = get_cnt_cls_tbl_match_stats;
		break;
	default:
		log_err("Unsupported DPA Classifier table type %d\n",
			cnt_cb->tbl_cb.type);
		return -EINVAL;
	}
	return 0;
}

static int set_cnt_classif_node_retrieve_func(struct dpa_stats_cnt_cb *cnt_cb,
				enum dpa_stats_classif_node_type ccnode_type)
{
	switch (ccnode_type) {
	case DPA_STATS_CLASSIF_NODE_HASH:
		cnt_cb->f_get_cnt_stats = get_cnt_ccnode_hash_stats;
		break;
	case DPA_STATS_CLASSIF_NODE_INDEXED:
		cnt_cb->f_get_cnt_stats = get_cnt_ccnode_index_stats;
		break;
	case DPA_STATS_CLASSIF_NODE_EXACT_MATCH:
		cnt_cb->f_get_cnt_stats = get_cnt_ccnode_match_stats;
		break;
	default:
		log_err("Unsupported Classification Node type %d", ccnode_type);
		return -EINVAL;
	}
	return 0;
}


static int get_classif_tbl_key_stats(struct dpa_stats_cnt_cb *cnt_cb,
				     uint32_t idx)
{
	struct dpa_stats_lookup_key *entry = &cnt_cb->tbl_cb.keys[idx];
	t_FmPcdCcKeyStatistics stats;
	uint8_t *mask_data;
	int err;

	switch (cnt_cb->tbl_cb.type) {
	case DPA_CLS_TBL_HASH:
		err = FM_PCD_HashTableFindNGetKeyStatistics(entry->cc_node,
				entry->key.data.size, entry->key.data.byte,
				&stats);
		if (err != 0) {
			log_err("Check failed for Classifier Hash Table counter id %d due to incorrect parameters: handle=0x%p, keysize=%d, keybyte=\n",
				cnt_cb->id, entry->cc_node,
				entry->key.data.size);
			dump_lookup_key(&entry->key.data);
			return -EIO;
		}
		break;
	case DPA_CLS_TBL_INDEXED:
		err = FM_PCD_MatchTableGetKeyStatistics(
				entry->cc_node, entry->key.data.byte[0],
				&stats);
		if (err != 0) {
			log_err("Check failed for Classifier Indexed Table counter id %d due to incorrect parameters: handle=0x%p, keysize=%d keybyte=\n",
				cnt_cb->id, entry->cc_node,
				entry->key.data.size);
			dump_lookup_key(&entry->key.data);
			return -EIO;
		}
		break;
	case DPA_CLS_TBL_EXACT_MATCH:
		if (entry->key.valid_mask)
			mask_data = entry->key.data.mask;
		else
			mask_data = NULL;
		err = FM_PCD_MatchTableFindNGetKeyStatistics(entry->cc_node,
				entry->key.data.size, entry->key.data.byte,
				mask_data, &stats);
		if (err != 0) {
			log_err("Check failed for Classifier Exact Match Table counter id %d due to incorrect parameters: handle=0x%p, keysize=%d, keybyte=\n",
				cnt_cb->id, entry->cc_node,
				entry->key.data.size);
			dump_lookup_key(&entry->key.data);
			return -EINVAL;
		}
		break;
	default:
		log_err("Unsupported DPA Classifier table type %d\n",
			cnt_cb->tbl_cb.type);
		return -EINVAL;
	}

	init_cnt_32bit_stats(&cnt_cb->info, &stats, idx);

	return 0;
}

static int get_ccnode_key_stats(struct dpa_stats_cnt_cb *cnt_cb,
				enum dpa_stats_classif_node_type ccnode_type,
				uint32_t idx)
{
	struct dpa_stats_allocated_lookup_key *key =
						&cnt_cb->ccnode_cb.keys[idx];
	t_FmPcdCcKeyStatistics stats;
	int err;
	uint8_t *mask_data;

	switch (ccnode_type) {
	case DPA_STATS_CLASSIF_NODE_HASH:
		err = FM_PCD_HashTableFindNGetKeyStatistics(
				cnt_cb->ccnode_cb.cc_node,
				key->data.size, key->data.byte, &stats);
		if (err != 0) {
			log_err("Check failed for Classification Node counter id %d due to incorrect parameters: handle=0x%p, keysize=%d, keybyte=\n",
				cnt_cb->id, cnt_cb->ccnode_cb.cc_node,
				key->data.size);
			dump_lookup_key(&key->data);
			return -EINVAL;
		}
		break;
	case DPA_STATS_CLASSIF_NODE_INDEXED:
		err = FM_PCD_MatchTableGetKeyStatistics(
				cnt_cb->ccnode_cb.cc_node,
				key->data.byte[0], &stats);
		if (err != 0) {
			log_err("Check failed for Classification Node counter id %d due to incorrect parameters: handle=0x%p, keysize=%d, keybyte=\n",
				cnt_cb->id, cnt_cb->ccnode_cb.cc_node,
				key->data.size);
			dump_lookup_key(&key->data);
			return -EINVAL;
		}
		break;
	case DPA_STATS_CLASSIF_NODE_EXACT_MATCH:
		if (key->valid_mask)
			mask_data = key->data.mask;
		else
			mask_data = NULL;
		err = FM_PCD_MatchTableFindNGetKeyStatistics(
				cnt_cb->ccnode_cb.cc_node, key->data.size,
				key->data.byte, mask_data, &stats);
		if (err != 0) {
			log_err("Check failed for Classification Node counter id %d due to incorrect parameters: handle=0x%p, keysize=%d, keybyte=\n",
				cnt_cb->id, cnt_cb->ccnode_cb.cc_node,
				key->data.size);
			dump_lookup_key(&key->data);
			return -EINVAL;
		}
		break;
	default:
		log_err("Unsupported Classification Node type %d",
			cnt_cb->tbl_cb.type);
		return -EINVAL;
	}

	init_cnt_32bit_stats(&cnt_cb->info, &stats, idx);

	return 0;
}

static int get_classif_tbl_miss_stats(struct dpa_stats_cnt_cb *cnt_cb,
				      uint32_t idx)
{
	struct dpa_stats_lookup_key *key = &cnt_cb->tbl_cb.keys[idx];
	t_FmPcdCcKeyStatistics stats;
	int err;

	switch (cnt_cb->tbl_cb.type) {
	case DPA_CLS_TBL_HASH:
		err = FM_PCD_HashTableGetMissStatistics(key->cc_node, &stats);
		if (err != 0) {
			log_err("Check failed for Classifier Table counter id %d due to incorrect parameters: handle=0x%p\n",
				cnt_cb->id, key->cc_node);
			return -EINVAL;
		}
		break;
	case DPA_CLS_TBL_INDEXED:
		err = FM_PCD_MatchTableGetMissStatistics(key->cc_node, &stats);
		if (err != 0) {
			log_err("Check failed for Classifier Table counter id %d due to incorrect parameters: handle=0x%p\n",
				cnt_cb->id, key->cc_node);
			return -EINVAL;
		}
		break;
	case DPA_CLS_TBL_EXACT_MATCH:
		err = FM_PCD_MatchTableGetMissStatistics(key->cc_node, &stats);
		if (err != 0) {
			log_err("Check failed for Classifier Table counter id %d due to incorrect parameters: handle=0x%p\n",
				cnt_cb->id, key->cc_node);
			return -EINVAL;
		}
		break;
	default:
		log_err("Unsupported Classifier Table type %d",
				cnt_cb->tbl_cb.type);
		return -EINVAL;
	}

	init_cnt_32bit_stats(&cnt_cb->info, &stats, idx);

	return 0;
}


static int get_ccnode_miss_stats(struct dpa_stats_cnt_cb *cnt_cb,
				 enum dpa_stats_classif_node_type type,
				 uint32_t idx)
{
	t_FmPcdCcKeyStatistics stats;
	int err;

	switch (type) {
	case DPA_STATS_CLASSIF_NODE_HASH:
		err = FM_PCD_HashTableGetMissStatistics(
					cnt_cb->ccnode_cb.cc_node, &stats);
		if (err != 0) {
			log_err("Check failed for Classification Node counter id %d due to incorrect parameters: handle=0x%p\n",
				cnt_cb->id, cnt_cb->ccnode_cb.cc_node);
			return -EINVAL;
		}
		break;
	case DPA_STATS_CLASSIF_NODE_INDEXED:
		err = FM_PCD_MatchTableGetMissStatistics(
					cnt_cb->ccnode_cb.cc_node, &stats);
		if (err != 0) {
			log_err("Check failed for Classification Node counter id %d due to incorrect parameters: handle=0x%p\n",
				cnt_cb->id, cnt_cb->ccnode_cb.cc_node);
			return -EINVAL;
		}
		break;
	case DPA_STATS_CLASSIF_NODE_EXACT_MATCH:
		err = FM_PCD_MatchTableGetMissStatistics(
					cnt_cb->ccnode_cb.cc_node, &stats);
		if (err != 0) {
			log_err("Check failed for Classification Node counter id %d due to incorrect parameters: handle=0x%p\n",
				cnt_cb->id, cnt_cb->ccnode_cb.cc_node);
			return -EINVAL;
		}
		break;
	default:
		log_err("Unsupported Classification Node type %d", type);
		return -EINVAL;
	}

	init_cnt_32bit_stats(&cnt_cb->info, &stats, idx);

	return 0;
}

static int get_new_cnt(struct dpa_stats *dpa_stats,
		       struct dpa_stats_cnt_cb **cnt_cb)
{
	struct dpa_stats_cnt_cb *new_cnt;
	uint32_t id;
	int i;

	/* Acquire DPA Stats instance lock */
	mutex_lock(&dpa_stats->lock);

	/* Get an id for new Counter */
	if (cq_get_4bytes(dpa_stats->cnt_id_cq, &id) < 0) {
		log_err("Cannot create new counter, no more free counter ids available\n");
		mutex_unlock(&dpa_stats->lock);
		return -EDOM;
	}

	/*
	 * Use 'used_cnt_ids' array in order to store counter ids that are
	 * 'in use' . Array can be further used to remove counters
	 */
	for (i = 0; i < dpa_stats->config.max_counters; i++)
		if (dpa_stats->used_cnt_ids[i] == DPA_OFFLD_INVALID_OBJECT_ID)
			break;

	if (i == dpa_stats->config.max_counters) {
		log_err("Maximum number of available counters %d was reached\n",
			dpa_stats->config.max_counters);
		cq_put_4bytes(dpa_stats->cnt_id_cq, id);
		mutex_unlock(&dpa_stats->lock);
		return -EDOM;
	}

	/* Acquire a preallocated Counter Control Block  */
	new_cnt = &dpa_stats->cnts_cb[id];
	new_cnt->id = id;
	new_cnt->index = i;

	/* Store on the current position the counter id */
	dpa_stats->used_cnt_ids[i] = id;

	/* Release DPA Stats instance lock */
	mutex_unlock(&dpa_stats->lock);

	*cnt_cb = new_cnt;

	return 0;
}

static int get_new_req(struct dpa_stats *dpa_stats,
		       int *dpa_stats_req_id,
		       struct dpa_stats_req_cb **req_cb)
{
	struct dpa_stats_req_cb *new_req;
	uint32_t id;
	int i;

	/* Acquire DPA Stats instance lock */
	mutex_lock(&dpa_stats->lock);

	/* Get an id for a new request */
	if (cq_get_4bytes(dpa_stats->req_id_cq, &id) < 0) {
		log_err("Cannot create new request, no more free request ids available\n");
		mutex_unlock(&dpa_stats->lock);
		return -EDOM;
	}

	/*
	 * Use 'used_req_ids' array in order to store requests ids that are
	 * 'in use' . Array can be further used to remove requests
	 */
	for (i = 0; i < DPA_STATS_MAX_NUM_OF_REQUESTS; i++)
		if (dpa_stats->used_req_ids[i] == DPA_OFFLD_INVALID_OBJECT_ID)
			break;

	if (i == DPA_STATS_MAX_NUM_OF_REQUESTS) {
		log_err("Maximum number of available requests %d was reached\n",
			DPA_STATS_MAX_NUM_OF_REQUESTS);
		cq_put_4bytes(dpa_stats->req_id_cq, id);
		mutex_unlock(&dpa_stats->lock);
		return -EDOM;
	}

	/* Acquire a preallocated Request Control Block  */
	new_req = &dpa_stats->reqs_cb[id];
	new_req->id = id;
	new_req->index = i;

	/* Store on the current position the request id */
	dpa_stats->used_req_ids[i] = id;

	/* Release DPA Stats instance lock */
	mutex_unlock(&dpa_stats->lock);

	*req_cb = new_req;
	*dpa_stats_req_id = id;

	return 0;
}

static int put_cnt(struct dpa_stats *dpa_stats, struct dpa_stats_cnt_cb *cnt_cb)
{
	int err = 0;

	/* Acquire DPA Stats instance lock */
	mutex_lock(&dpa_stats->lock);

	/* Release the Counter id in the Counter IDs circular queue */
	err = cq_put_4bytes(dpa_stats->cnt_id_cq, cnt_cb->id);
	if (err < 0) {
		log_err("Cannot release the counter id %d\n", cnt_cb->id);
		return -EDOM;
	}

	/* Mark the Counter id as 'not used' */
	dpa_stats->used_cnt_ids[cnt_cb->index] = DPA_OFFLD_INVALID_OBJECT_ID;

	/* Clear all 'cnt_cb' information  */
	cnt_cb->index = DPA_OFFLD_INVALID_OBJECT_ID;
	cnt_cb->id = DPA_STATS_MAX_NUM_OF_COUNTERS;
	cnt_cb->bytes_num = 0;
	cnt_cb->f_get_cnt_stats = NULL;

	switch (cnt_cb->type) {
	case DPA_STATS_CNT_ETH:
	case DPA_STATS_CNT_REASS:
	case DPA_STATS_CNT_FRAG:
	case DPA_STATS_CNT_POLICER:
		memset(&cnt_cb->gen_cb, 0, sizeof(cnt_cb->gen_cb));
		break;
	case DPA_STATS_CNT_CLASSIF_TBL:
		memset(&cnt_cb->tbl_cb, 0, sizeof(cnt_cb->tbl_cb));
		break;
	case DPA_STATS_CNT_CLASSIF_NODE:
		memset(&cnt_cb->ccnode_cb, 0, sizeof(cnt_cb->ccnode_cb));
		break;
	case DPA_STATS_CNT_IPSEC:
		memset(&cnt_cb->ipsec_cb, 0, sizeof(cnt_cb->ipsec_cb));
		break;
	default:
		break;
	}

	/* Release DPA Stats instance lock */
	mutex_unlock(&dpa_stats->lock);

	return 0;
}

static int put_req(struct dpa_stats *dpa_stats, struct dpa_stats_req_cb *req_cb)
{
	int err = 0;

	/* Acquire DPA Stats instance lock */
	mutex_lock(&dpa_stats->lock);

	/* Release the Counter id in the Counter IDs circular queue */
	err = cq_put_4bytes(dpa_stats->req_id_cq, req_cb->id);
	if (err < 0) {
		log_err("Cannot release the request id %d\n", req_cb->id);
		mutex_unlock(&dpa_stats->lock);
		return -EDOM;
	}

	/* Mark the Counter id as 'not used' */
	dpa_stats->used_req_ids[req_cb->index] = DPA_OFFLD_INVALID_OBJECT_ID;

	/* Clear all 'req_cb' information by setting them to a maximum value */
	req_cb->index = DPA_OFFLD_INVALID_OBJECT_ID;
	req_cb->id = DPA_STATS_MAX_NUM_OF_REQUESTS;
	req_cb->bytes_num = 0;
	req_cb->cnts_num = 0;
	req_cb->request_area = NULL;
	req_cb->request_done = NULL;

	/* Release DPA Stats instance lock */
	mutex_unlock(&dpa_stats->lock);

	return 0;
}

static int init_cnts_resources(struct dpa_stats *dpa_stats)
{
	struct dpa_stats_params config = dpa_stats->config;
	int i;

	/* Create circular queue that holds free counter IDs */
	dpa_stats->cnt_id_cq = cq_new(config.max_counters, sizeof(int));
	if (!dpa_stats->cnt_id_cq) {
		log_err("Cannot create circular queue to store counter ids\n");
		return -ENOMEM;
	}

	/* Fill the circular queue with ids */
	for (i = 0; i < config.max_counters; i++)
		if (cq_put_4bytes(dpa_stats->cnt_id_cq, i) < 0) {
			log_err("Cannot fill circular queue with counter ids\n");
			return -EDOM;
		}

	/* Allocate array to store counter ids that are 'in use' */
	dpa_stats->used_cnt_ids = kcalloc(
			config.max_counters, sizeof(uint32_t), GFP_KERNEL);
	if (!dpa_stats->used_cnt_ids) {
		log_err("Cannot allocate memory to store %d \'in use\' counter ids\n",
			config.max_counters);
		return -ENOMEM;
	}
	memset(dpa_stats->used_cnt_ids, DPA_OFFLD_INVALID_OBJECT_ID,
			config.max_counters * sizeof(uint32_t));

	/* Allocate array to store counter ids scheduled for retrieve */
	dpa_stats->sched_cnt_ids = kcalloc(
			config.max_counters, sizeof(bool), GFP_KERNEL);
	if (!dpa_stats->sched_cnt_ids) {
		log_err("Cannot allocate memory to store %d scheduled counter ids\n",
			config.max_counters);
		return -ENOMEM;
	}

	/* Allocate array of counters control blocks */
	dpa_stats->cnts_cb = kzalloc(config.max_counters *
			sizeof(struct dpa_stats_cnt_cb), GFP_KERNEL);
	if (!dpa_stats->cnts_cb) {
		log_err("Cannot allocate memory to store %d internal counter structures\n",
			config.max_counters);
		return -ENOMEM;
	}

	/* Initialize every counter control block */
	for (i = 0; i < config.max_counters; i++) {
		/* Initialize counter lock */
		mutex_init(&dpa_stats->cnts_cb[i].lock);
		/* Store dpa_stats instance */
		dpa_stats->cnts_cb[i].dpa_stats = dpa_stats;
		/* Counter is not initialized, set the index to invalid value */
		dpa_stats->cnts_cb[i].index = DPA_OFFLD_INVALID_OBJECT_ID;
	}
	return 0;
}

static int free_cnts_resources(struct dpa_stats *dpa_stats)
{
	uint32_t id, i;
	int err = 0;

	for (i = 0; i < dpa_stats->config.max_counters; i++) {
		mutex_lock(&dpa_stats->lock);
		id = dpa_stats->used_cnt_ids[i];
		mutex_unlock(&dpa_stats->lock);

		if (id != DPA_OFFLD_INVALID_OBJECT_ID) {
			/* Release the counter id in the Counter IDs cq */
			err = dpa_stats_remove_counter(id);
			BUG_ON(err < 0);
		}
	}

	/* Release counters IDs circular queue */
	if (dpa_stats->cnt_id_cq) {
		cq_delete(dpa_stats->cnt_id_cq);
		dpa_stats->cnt_id_cq = NULL;
	}

	/* Release counters control blocks */
	kfree(dpa_stats->cnts_cb);
	dpa_stats->cnts_cb = NULL;

	/* Release counters 'used ids' array */
	kfree(dpa_stats->used_cnt_ids);
	dpa_stats->used_cnt_ids = NULL;

	/* Release scheduled counters ids array */
	kfree(dpa_stats->sched_cnt_ids);
	dpa_stats->sched_cnt_ids = NULL;

	return 0;
}

static int init_reqs_resources(struct dpa_stats *dpa_stats)
{
	int i;

	/*
	 * Create work queue to defer work when asynchronous
	 * counters requests are received
	 */
	dpa_stats->async_req_workqueue = alloc_workqueue("async_req_workqueue",
			WQ_UNBOUND | WQ_MEM_RECLAIM, WORKQUEUE_MAX_ACTIVE);
	if (!dpa_stats->async_req_workqueue) {
		log_err("Cannot allocate asynchronous requests work queue\n");
		return -ENOSPC;
	}

	/* Create circular queue that holds free counter request IDs */
	dpa_stats->req_id_cq = cq_new(
			DPA_STATS_MAX_NUM_OF_REQUESTS, sizeof(int));
	if (!dpa_stats->req_id_cq) {
		log_err("Cannot create circular queue to store request ids\n");
		return -ENOMEM;
	}

	/* Fill the circular queue with ids */
	for (i = 0; i < DPA_STATS_MAX_NUM_OF_REQUESTS; i++)
		if (cq_put_4bytes(dpa_stats->req_id_cq, i) < 0) {
			log_err("Cannot fill circular queue with request ids\n");
			return -EDOM;
		}

	/* Allocate array to store requests ids that are 'in use' */
	dpa_stats->used_req_ids = kmalloc(DPA_STATS_MAX_NUM_OF_REQUESTS *
			sizeof(uint32_t), GFP_KERNEL);
	if (!dpa_stats->used_req_ids) {
		log_err("Cannot allocate memory to store \'in use\' request ids\n");
		return -ENOMEM;
	}
	memset(dpa_stats->used_req_ids, DPA_OFFLD_INVALID_OBJECT_ID,
			DPA_STATS_MAX_NUM_OF_REQUESTS * sizeof(uint32_t));

	/* Allocate array to store requests control blocks */
	dpa_stats->reqs_cb = kzalloc(DPA_STATS_MAX_NUM_OF_REQUESTS *
				sizeof(struct dpa_stats_req_cb), GFP_KERNEL);
	if (!dpa_stats->reqs_cb) {
		log_err("Cannot allocate memory to store internal requests structure\n");
		return -ENOMEM;
	}

	/* Allocate array to store the counter ids */
	for (i = 0; i < DPA_STATS_MAX_NUM_OF_REQUESTS; i++) {
		dpa_stats->reqs_cb[i].cnts_ids =
				kzalloc(dpa_stats->config.max_counters *
						sizeof(int), GFP_KERNEL);
		if (!dpa_stats->reqs_cb[i].cnts_ids) {
			log_err("Cannot allocate memory for array of counter ids\n");
			return -ENOMEM;
		}

		/* Initialize work to be done for each request */
		INIT_WORK(&dpa_stats->reqs_cb[i].async_req_work,
						async_req_work_func);
	}

	return 0;
}

static int free_reqs_resources(struct dpa_stats *dpa_stats)
{
	struct dpa_stats_req_cb *req_cb = NULL;
	uint32_t id, i;
	int err = 0;

	for (i = 0; i <  DPA_STATS_MAX_NUM_OF_REQUESTS; i++) {
		mutex_lock(&dpa_stats->lock);
		id = dpa_stats->used_req_ids[i];
		mutex_unlock(&dpa_stats->lock);

		if (id != DPA_OFFLD_INVALID_OBJECT_ID) {
			req_cb = &dpa_stats->reqs_cb[id];

			flush_work(&req_cb->async_req_work);

			/* Release the request id in the Requests IDs cq */
			err = put_req(dpa_stats, req_cb);
			BUG_ON(err < 0);

			/* Release the array of counter ids */
			kfree(req_cb->cnts_ids);
			req_cb->cnts_ids = NULL;
		}
	}

	/* Release requests IDs circular queue */
	if (dpa_stats->req_id_cq) {
		cq_delete(dpa_stats->req_id_cq);
		dpa_stats->req_id_cq = NULL;
	}

	/* Release requests control blocks */
	kfree(dpa_stats->reqs_cb);
	dpa_stats->reqs_cb = NULL;

	/* Release requests 'used ids' array */
	kfree(dpa_stats->used_req_ids);
	dpa_stats->used_req_ids = NULL;

	/* destroy asynchronous requests workqueue */
	if (dpa_stats->async_req_workqueue) {
		destroy_workqueue(dpa_stats->async_req_workqueue);
		dpa_stats->async_req_workqueue = NULL;
	}

	return 0;
}

/* cleanup DPA Stats */
static int free_resources(void)
{
	struct dpa_stats *dpa_stats;
	int err = 0;

	/* Sanity check */
	if (!gbl_dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return 0;
	}
	dpa_stats = gbl_dpa_stats;

	/* free resources occupied by counters control blocks */
	err = free_cnts_resources(dpa_stats);
	if (err < 0)
		return err;

	/* free resources occupied by requests control blocks */
	err = free_reqs_resources(dpa_stats);
	if (err < 0)
		return err;

	kfree(dpa_stats);
	gbl_dpa_stats = NULL;
	return 0;
}

static int treat_cnts_request(struct dpa_stats *dpa_stats,
			      struct dpa_stats_req_cb *req_cb)
{
	struct dpa_stats_cnt_request_params params = req_cb->config;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	int err = 0;
	uint32_t i = 0;

	for (i = 0; i < params.cnts_ids_len; i++) {

		/* Get counter's control block */
		cnt_cb = &dpa_stats->cnts_cb[req_cb->cnts_ids[i]];

		/* Acquire counter lock */
		mutex_lock(&cnt_cb->lock);

		cnt_cb->info.reset = req_cb->config.reset_cnts;

		/* Call counter's retrieve function */
		err = cnt_cb->f_get_cnt_stats(req_cb, cnt_cb);
		if (err < 0) {
			log_err("Cannot retrieve the value for counter id %d\n",
				req_cb->cnts_ids[i]);
			mutex_unlock(&cnt_cb->lock);
			unblock_sched_cnts(dpa_stats, req_cb->cnts_ids,
					   params.cnts_ids_len);
			return err;
		}

		/*
		 * Update number of bytes and number of counters
		 * successfully written so far
		 */
		req_cb->bytes_num += cnt_cb->bytes_num;
		req_cb->cnts_num += 1;

		mutex_unlock(&cnt_cb->lock);
	}

	unblock_sched_cnts(dpa_stats, req_cb->cnts_ids, params.cnts_ids_len);

	return 0;
}

static void create_cnt_eth_stats(struct dpa_stats *dpa_stats)
{
	/* DPA_STATS_CNT_ETH_DROP_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][0] =
			offsetof(struct t_FmMacStatistics, eStatsDropEvents);
	/* DPA_STATS_CNT_ETH_BYTES */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][1] =
			offsetof(struct t_FmMacStatistics, ifInOctets);
	/* DPA_STATS_CNT_ETH_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][2] =
			offsetof(struct t_FmMacStatistics, ifInPkts);
	/* DPA_STATS_CNT_ETH_BC_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][3] =
			offsetof(struct t_FmMacStatistics, ifInBcastPkts);
	/* DPA_STATS_CNT_ETH_MC_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][4] =
			offsetof(struct t_FmMacStatistics, ifInMcastPkts);
	/* DPA_STATS_CNT_ETH_CRC_ALIGN_ERR */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][5] =
			offsetof(struct t_FmMacStatistics, eStatCRCAlignErrors);
	/* DPA_STATS_CNT_ETH_UNDERSIZE_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][6] =
			offsetof(struct t_FmMacStatistics, eStatUndersizePkts);
	/* DPA_STATS_CNT_ETH_OVERSIZE_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][7] =
			offsetof(struct t_FmMacStatistics, eStatOversizePkts);
	/* DPA_STATS_CNT_ETH_FRAGMENTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][8] =
			offsetof(struct t_FmMacStatistics, eStatFragments);
	/* DPA_STATS_CNT_ETH_JABBERS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][9] =
			offsetof(struct t_FmMacStatistics, eStatJabbers);
	/* DPA_STATS_CNT_ETH_64BYTE_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][10] =
			offsetof(struct t_FmMacStatistics, eStatPkts64);
	/* DPA_STATS_CNT_ETH_65_127BYTE_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][11] =
			offsetof(struct t_FmMacStatistics, eStatPkts65to127);
	/* DPA_STATS_CNT_ETH_128_255BYTE_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][12] =
			offsetof(struct t_FmMacStatistics, eStatPkts128to255);
	/* DPA_STATS_CNT_ETH_256_511BYTE_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][13] =
			offsetof(struct t_FmMacStatistics, eStatPkts256to511);
	/* DPA_STATS_CNT_ETH_512_1023BYTE_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][14] =
			offsetof(struct t_FmMacStatistics, eStatPkts512to1023);
	/* DPA_STATS_CNT_ETH_1024_1518BYTE_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][15] =
			offsetof(struct t_FmMacStatistics, eStatPkts1024to1518);
	/* DPA_STATS_CNT_ETH_OUT_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][16] =
			offsetof(struct t_FmMacStatistics, ifOutPkts);
	/* DPA_STATS_CNT_ETH_OUT_DROP_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][17] =
			offsetof(struct t_FmMacStatistics, ifOutDiscards);
	/* DPA_STATS_CNT_ETH_OUT_BYTES */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][18] =
			offsetof(struct t_FmMacStatistics, ifOutOctets);
	/* DPA_STATS_CNT_ETH_IN_ERRORS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][19] =
			offsetof(struct t_FmMacStatistics, ifInErrors);
	/* DPA_STATS_CNT_ETH_OUT_ERRORS */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][20] =
			offsetof(struct t_FmMacStatistics, ifOutErrors);
	/* DPA_STATS_CNT_ETH_IN_UNICAST_PKTS : not supported on dTSEC MAC */
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][21] =
			offsetof(struct t_FmMacStatistics, ifInUcastPkts);
	/* DPA_STATS_CNT_ETH_OUT_UNICAST_PKTS : not supported on dTSEC MAC*/
	dpa_stats->stats_sel[DPA_STATS_CNT_ETH][22] =
			offsetof(struct t_FmMacStatistics, ifOutUcastPkts);
}

static void create_cnt_reass_stats(struct dpa_stats *dpa_stats)
{
	/* DPA_STATS_CNT_REASS_TIMEOUT */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][0] =
			offsetof(struct t_FmPcdManipReassemIpStats, timeout);
	/* DPA_STATS_CNT_REASS_RFD_POOL_BUSY */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][1] = offsetof(
			struct t_FmPcdManipReassemIpStats, rfdPoolBusy);
	/* DPA_STATS_CNT_REASS_INT_BUFF_BUSY */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][2] = offsetof(
			struct t_FmPcdManipReassemIpStats, internalBufferBusy);
	/* DPA_STATS_CNT_REASS_EXT_BUFF_BUSY */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][3] = offsetof(
			struct t_FmPcdManipReassemIpStats, externalBufferBusy);
	/* DPA_STATS_CNT_REASS_SG_FRAGS */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][4] = offsetof(
			struct t_FmPcdManipReassemIpStats, sgFragments);
	/* DPA_STATS_CNT_REASS_DMA_SEM */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][5] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			dmaSemaphoreDepletion);
#if (DPAA_VERSION >= 11)
	/* DPA_STATS_CNT_REASS_NON_CONSISTENT_SP */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][6] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			nonConsistentSp);
#else
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][6] = UNSUPPORTED_CNT_SEL;
#endif /* (DPAA_VERSION >= 11) */
	/* DPA_STATS_CNT_REASS_IPv4_FRAMES */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][8] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[0].successfullyReassembled);
	/* DPA_STATS_CNT_REASS_IPv4_FRAGS_VALID */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][9] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[0].validFragments);
	/* DPA_STATS_CNT_REASS_IPv4_FRAGS_TOTAL */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][10] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[0].processedFragments);
	/* DPA_STATS_CNT_REASS_IPv4_FRAGS_MALFORMED */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][11] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[0].malformedFragments);
	/* DPA_STATS_CNT_REASS_IPv4_FRAGS_DISCARDED */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][12] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[0].discardedFragments);
	/* DPA_STATS_CNT_REASS_IPv4_AUTOLEARN_BUSY */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][13] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[0].autoLearnBusy);
	/* DPA_STATS_CNT_REASS_IPv4_EXCEED_16FRAGS */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][14] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[0].moreThan16Fragments);
	/* DPA_STATS_CNT_REASS_IPv6_FRAMES */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][16] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[1].successfullyReassembled);
	/* DPA_STATS_CNT_REASS_IPv6_FRAGS_VALID */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][17] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[1].validFragments);
	/* DPA_STATS_CNT_REASS_IPv6_FRAGS_TOTAL */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][18] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[1].processedFragments);
	/* DPA_STATS_CNT_REASS_IPv6_FRAGS_MALFORMED */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][19] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[1].malformedFragments);
	/* DPA_STATS_CNT_REASS_IPv6_FRAGS_DISCARDED */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][20] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[1].discardedFragments);
	/* DPA_STATS_CNT_REASS_IPv6_AUTOLEARN_BUSY */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][21] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[1].autoLearnBusy);
	/* DPA_STATS_CNT_REASS_IPv6_EXCEED_16FRAGS */
	dpa_stats->stats_sel[DPA_STATS_CNT_REASS][22] = offsetof(
			struct t_FmPcdManipReassemIpStats,
			specificHdrStatistics[1].moreThan16Fragments);
}

static void create_cnt_frag_stats(struct dpa_stats *dpa_stats)
{
	/* DPA_STATS_CNT_FRAG_TOTAL_FRAMES */
	dpa_stats->stats_sel[DPA_STATS_CNT_FRAG][0] =
			offsetof(struct t_FmPcdManipFragIpStats, totalFrames);
	/* DPA_STATS_CNT_FRAG_FRAMES */
	dpa_stats->stats_sel[DPA_STATS_CNT_FRAG][1] = offsetof(
			struct t_FmPcdManipFragIpStats, fragmentedFrames);
	/* DPA_STATS_CNT_FRAG_GEN_FRAGS */
	dpa_stats->stats_sel[DPA_STATS_CNT_FRAG][2] = offsetof(
			struct t_FmPcdManipFragIpStats, generatedFragments);
}

static void create_cnt_plcr_stats(struct dpa_stats *dpa_stats)
{
	/* DPA_STATS_CNT_PLCR_GREEN_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_POLICER][0] =
			e_FM_PCD_PLCR_PROFILE_GREEN_PACKET_TOTAL_COUNTER;
	/* DPA_STATS_CNT_PLCR_YELLOW_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_POLICER][1] =
			e_FM_PCD_PLCR_PROFILE_YELLOW_PACKET_TOTAL_COUNTER;
	/* DPA_STATS_CNT_PLCR_RED_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_POLICER][2] =
			e_FM_PCD_PLCR_PROFILE_RED_PACKET_TOTAL_COUNTER;
	/* DPA_STATS_CNT_PLCR_RECOLOR_YELLOW_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_POLICER][3] =
		e_FM_PCD_PLCR_PROFILE_RECOLOURED_YELLOW_PACKET_TOTAL_COUNTER;
	/* DPA_STATS_CNT_PLCR_RECOLOR_RED_PKTS */
	dpa_stats->stats_sel[DPA_STATS_CNT_POLICER][4] =
		e_FM_PCD_PLCR_PROFILE_RECOLOURED_RED_PACKET_TOTAL_COUNTER;
}

static void create_classif_stats(struct dpa_stats *dpa_stats)
{
	/* DPA_STATS_CNT_CLASSIF_BYTES */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][0] =
			offsetof(struct t_FmPcdCcKeyStatistics, byteCount);
	/* DPA_STATS_CNT_CLASSIF_PACKETS */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][1] =
			offsetof(struct t_FmPcdCcKeyStatistics, frameCount);
#if (DPAA_VERSION >= 11)
	/* DPA_STATS_CNT_CLASSIF_RANGE1 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][2] = offsetof(
			struct t_FmPcdCcKeyStatistics,
			frameLengthRangeCount[0]);
	/* DPA_STATS_CNT_CLASSIF_RANGE2 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][3] = offsetof(
			struct t_FmPcdCcKeyStatistics,
			frameLengthRangeCount[1]);
	/* DPA_STATS_CNT_CLASSIF_RANGE3 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][4] = offsetof(
			struct t_FmPcdCcKeyStatistics,
			frameLengthRangeCount[2]);
	/* DPA_STATS_CNT_CLASSIF_RANGE4 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][5] = offsetof(
			struct t_FmPcdCcKeyStatistics,
			frameLengthRangeCount[3]);
	/* DPA_STATS_CNT_CLASSIF_RANGE5 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][6] = offsetof(
			struct t_FmPcdCcKeyStatistics,
			frameLengthRangeCount[4]);
	/* DPA_STATS_CNT_CLASSIF_RANGE6 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][7] = offsetof(
			struct t_FmPcdCcKeyStatistics,
			frameLengthRangeCount[5]);
	/* DPA_STATS_CNT_CLASSIF_RANGE7 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][8] = offsetof(
			struct t_FmPcdCcKeyStatistics,
			frameLengthRangeCount[6]);
	/* DPA_STATS_CNT_CLASSIF_RANGE8 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][9] = offsetof(
			struct t_FmPcdCcKeyStatistics,
			frameLengthRangeCount[7]);
	/* DPA_STATS_CNT_CLASSIF_RANGE9 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][10] = offsetof(
			struct t_FmPcdCcKeyStatistics,
			frameLengthRangeCount[8]);
	/* DPA_STATS_CNT_CLASSIF_RANGE10 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][11] = offsetof(
			struct t_FmPcdCcKeyStatistics,
			frameLengthRangeCount[9]);
#else
	/* DPA_STATS_CNT_CLASSIF_RANGE1 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][2] =
			UNSUPPORTED_CNT_SEL;
	/* DPA_STATS_CNT_CLASSIF_RANGE2 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][3] =
			UNSUPPORTED_CNT_SEL;
	/* DPA_STATS_CNT_CLASSIF_RANGE3 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][4] =
			UNSUPPORTED_CNT_SEL;
	/* DPA_STATS_CNT_CLASSIF_RANGE4 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][5] =
			UNSUPPORTED_CNT_SEL;
	/* DPA_STATS_CNT_CLASSIF_RANGE5 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][6] =
			UNSUPPORTED_CNT_SEL;
	/* DPA_STATS_CNT_CLASSIF_RANGE6 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][7] =
			UNSUPPORTED_CNT_SEL;
	/* DPA_STATS_CNT_CLASSIF_RANGE7 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][8] =
			UNSUPPORTED_CNT_SEL;
	/* DPA_STATS_CNT_CLASSIF_RANGE8 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][9] =
			UNSUPPORTED_CNT_SEL;
	/* DPA_STATS_CNT_CLASSIF_RANGE9 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][10] =
			UNSUPPORTED_CNT_SEL;
	/* DPA_STATS_CNT_CLASSIF_RANGE10 */
	dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE][11] =
			UNSUPPORTED_CNT_SEL;
#endif
}

static void create_cnt_ipsec_stats(struct dpa_stats *dpa_stats)
{
	/* DPA_STATS_CNT_NUM_OF_BYTES */
	dpa_stats->stats_sel[DPA_STATS_CNT_IPSEC][0] = offsetof(
			struct dpa_ipsec_sa_stats, bytes_count);
	/* DPA_STATS_CNT_NUM_OF_PACKETS */
	dpa_stats->stats_sel[DPA_STATS_CNT_IPSEC][1] = offsetof(
			struct dpa_ipsec_sa_stats, packets_count);
}

static void create_cnt_traffic_mng_stats(struct dpa_stats *dpa_stats)
{
	/* DPA_STATS_CNT_NUM_OF_BYTES */
	dpa_stats->stats_sel[DPA_STATS_CNT_TRAFFIC_MNG][0] =
				DPA_STATS_CNT_NUM_OF_BYTES * sizeof(uint64_t);
	/* DPA_STATS_CNT_NUM_OF_PACKETS */
	dpa_stats->stats_sel[DPA_STATS_CNT_TRAFFIC_MNG][1] =
				DPA_STATS_CNT_NUM_OF_PACKETS * sizeof(uint64_t);
}

static int copy_key_descriptor(const struct dpa_offload_lookup_key *src,
			       struct dpa_stats_allocated_lookup_key *dst)
{
	/* Check that key byte pointer is valid */
	if (!src->byte) {
		log_err("Lookup key descriptor byte cannot be NULL\n");
		return -EINVAL;
	}

	/* Check that key size is not zero */
	if ((src->size == 0) || (src->size > DPA_OFFLD_MAXENTRYKEYSIZE)) {
		log_err("Lookup key descriptor size (%d) must be in range (1 - %d) bytes\n",
			src->size, DPA_OFFLD_MAXENTRYKEYSIZE);
		return -EINVAL;
	}

	BUG_ON(dst->data.byte == NULL);
	memcpy(dst->data.byte, src->byte, src->size);
	dst->valid_key = true;

	/* If there is a valid key mask pointer */
	if (src->mask) {
		BUG_ON(dst->data.mask == NULL);
		memcpy(dst->data.mask, src->mask, src->size);
		dst->valid_mask = true;
	} else
		dst->valid_mask = false;

	/* Store the key size */
	dst->data.size = src->size;

	return 0;
}

static t_Handle get_fman_mac_handle(struct device_node *parent_dev_node,
				    int port_id,
				    char *mac_name,
				    bool xg_port)
{
	struct device_node *dev_node, *tmp_node = NULL;
	struct mac_device *mac_dev = NULL;
	const uint32_t *cell_index;
	const char *phy_connection;
	struct platform_device *device;
	int lenp;

	while ((dev_node = of_find_compatible_node(tmp_node, NULL,
			mac_name)) != NULL) {

		if (parent_dev_node != of_get_parent(dev_node)) {
			tmp_node = dev_node;
			continue;
		}

		cell_index = of_get_property(dev_node, "cell-index", &lenp);
		if (be32_to_cpu(*cell_index) != port_id) {
			tmp_node = dev_node;
			continue;
		}

		phy_connection = of_get_property(dev_node,
						"phy-connection-type",
						&lenp);
		if (((xg_port) && (strcmp(phy_connection, "xgmii") == 0)) ||
			((!xg_port) &&
				(strcmp(phy_connection, "xgmii") != 0))) {

			device = of_find_device_by_node(dev_node);
			if (!device)
				return NULL;
			mac_dev = dev_get_drvdata(&device->dev);
			if (!mac_dev)
				return NULL;

			return mac_dev->get_mac_handle(mac_dev);
		}

		tmp_node = dev_node;
	}

	return NULL;
}

static struct device_node *get_fman_dev_node(int fman_id)
{
	struct device_node *dev_node, *tmp_node = NULL;
	const uint32_t *cell_index;
	int lenp;

	while ((dev_node = of_find_compatible_node(tmp_node, NULL, "fsl,fman"))
			!= NULL) {
		cell_index = of_get_property(dev_node, "cell-index", &lenp);
		if (be32_to_cpu(*cell_index) == fman_id)
			break;

		tmp_node = dev_node;
	}

	return dev_node;
}

static int get_fm_mac(struct dpa_stats_cnt_eth_src src, void **mac)
{
	struct device_node *dev_node = NULL;
	t_Handle *fm_mac = NULL;
	char *mac_name;

	/* Get FMAN device node */
	dev_node = get_fman_dev_node(src.engine_id);
	if (!dev_node) {
		log_err("Cannot find FMan device node\n");
		return -EINVAL;
	}

	if (src.eth_id > DPA_STATS_ETH_1G_PORT5) {
		/* Get Ethernet device node first for DTSEC case 10G port*/
		mac_name = "fsl,fman-10g-mac";
		src.eth_id -= DPA_STATS_ETH_10G_PORT0;

		fm_mac = get_fman_mac_handle(dev_node,
					src.eth_id,
					mac_name,
					true);
		if (!fm_mac) {
			/* Get Ethernet device node for MEMAC case 10G port */
			mac_name = "fsl,fman-memac";
			fm_mac = get_fman_mac_handle(
					dev_node, src.eth_id, mac_name, true);
			if (!fm_mac) {
				log_err("Cannot find Ethernet device node\n");
				return -EINVAL;
			}
		}
	} else {
		/* Get Ethernet device node first for DTSEC case 1G port*/
		mac_name = "fsl,fman-1g-mac";

		fm_mac = get_fman_mac_handle(dev_node,
					src.eth_id,
					mac_name,
					false);
		if (!fm_mac) {
			/* Get Ethernet device node for MEMAC case 1G port*/
			mac_name = "fsl,fman-memac";
			fm_mac = get_fman_mac_handle(
					dev_node, src.eth_id, mac_name, false);
			if (!fm_mac) {
				log_err("Cannot find Ethernet device node\n");
				return -EINVAL;
			}
		}
	}

	/* Return FM MAC handle */
	*mac = fm_mac;

	return 0;
}

static int cnt_sel_to_stats(struct stats_info *stats_info,
			     int *stats_sel,
			     uint32_t cnt_sel)
{
	uint32_t bit_val = 0, bit_pos = 0, cnt_pos = 1;
	int stats_off[MAX_NUM_OF_STATS];

	memset(stats_off, 0, sizeof(int) * MAX_NUM_OF_STATS);

	while (cnt_sel > 0) {
		bit_val = cnt_sel & 0x00000001;
		stats_off[cnt_pos - bit_val] = stats_sel[bit_pos++];
		cnt_pos += bit_val;
		cnt_sel >>= 1;
	}

	stats_info->stats_num = cnt_pos - 1;

	/*
	 * Allocate the stats offsets array and copy the calculated offsets
	 * into it
	 */
	stats_info->stats_off = kcalloc(stats_info->stats_num, sizeof(int),
					GFP_KERNEL);
	if (!stats_info->stats_off) {
		log_err("Failed to allocate stats offsets for new counter\n");
		return -ENOMEM;
	}

	memcpy(stats_info->stats_off, stats_off,
				stats_info->stats_num * sizeof(int));
	return 0;
}

static int cnt_gen_sel_to_stats(struct dpa_stats_cnt_cb *cnt_cb,
				enum dpa_stats_cnt_sel cnt_sel)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	int stats_off[MAX_NUM_OF_STATS];

	if (cnt_sel == DPA_STATS_CNT_NUM_OF_BYTES) {
		stats_off[0] =
		dpa_stats->stats_sel[cnt_cb->type][DPA_STATS_CNT_NUM_OF_BYTES];
		cnt_cb->info.stats_num = 1;
	} else if (cnt_sel == DPA_STATS_CNT_NUM_OF_PACKETS) {
		stats_off[0] =
	dpa_stats->stats_sel[cnt_cb->type][DPA_STATS_CNT_NUM_OF_PACKETS];
		cnt_cb->info.stats_num = 1;
	} else if (cnt_sel == DPA_STATS_CNT_NUM_ALL) {
		stats_off[0] =
		dpa_stats->stats_sel[cnt_cb->type][DPA_STATS_CNT_NUM_OF_BYTES];
		stats_off[1] =
	dpa_stats->stats_sel[cnt_cb->type][DPA_STATS_CNT_NUM_OF_PACKETS];
		cnt_cb->info.stats_num = 2;
	} else {
		log_err("Parameter cnt_sel %d must be in range (%d - %d) for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_NUM_OF_BYTES,
			DPA_STATS_CNT_NUM_ALL, cnt_cb->id);
		return -EINVAL;
	}

	/*
	 * Allocate the stats offsets array and copy the calculated offsets
	 * into it
	 */
	cnt_cb->info.stats_off = kcalloc(cnt_cb->info.stats_num,
						sizeof(int), GFP_KERNEL);
	if (!cnt_cb->info.stats_off) {
		log_err("Failed to allocate stats offsets for new counter\n");
		return -ENOMEM;
	}

	memcpy(cnt_cb->info.stats_off, stats_off,
				cnt_cb->info.stats_num * sizeof(int));

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
			DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	return 0;
}

static int set_frag_manip(int td, struct dpa_stats_lookup_key *entry)
{
	struct dpa_cls_tbl_action action;
	struct t_FmPcdManipStats stats;
	struct dpa_offload_lookup_key local_key;
	int err = 0;

	if (entry->miss_key) {
		err = dpa_classif_get_miss_action(td, &action);
		if (err != 0) {
			log_err("Cannot retrieve miss action parameters from table %d\n",
				td);
			return -EINVAL;
		}
	} else {
		local_key.byte = entry->key.data.byte;
		local_key.size = entry->key.data.size;
		if (entry->key.valid_mask)
			local_key.mask = entry->key.data.mask;
		else
			local_key.mask = NULL;

		err = dpa_classif_table_lookup_by_key(td, &local_key, &action);
		if (err != 0) {
			log_err("Cannot retrieve next action parameters from table %d\n",
				td);
			return -EINVAL;
		}
	}

	if (action.type != DPA_CLS_TBL_ACTION_ENQ) {
		log_err("Fragmentation statistics per flow are supported only for action enqueue\n");
		return -EINVAL;
	}

	entry->frag = dpa_classif_get_frag_hm_handle(action.enq_params.hmd);
	if (!entry->frag) {
		log_err("Cannot retrieve Fragmentation handle from hmd %d\n",
			action.enq_params.hmd);
		return -EINVAL;
	}

	/* Check the user-provided fragmentation handle */
	err = FM_PCD_ManipGetStatistics(entry->frag, &stats);
	if (err < 0) {
		log_err("Invalid Fragmentation manip handle\n");
		return -EINVAL;
	}
	return 0;
}

static int alloc_cnt_stats(struct stats_info *stats_info,
						unsigned int num_members)
{
	/* Allocate array of currently read statistics */
	stats_info->stats = kcalloc(num_members * stats_info->stats_num,
						sizeof(uint64_t), GFP_KERNEL);
	if (!stats_info->stats) {
		log_err("Cannot allocate memory to store array of statistics\n");
		return -ENOMEM;
	}

	/* Allocate array of previously read statistics */
	stats_info->last_stats = kcalloc(num_members * stats_info->stats_num,
						sizeof(uint64_t), GFP_KERNEL);
	if (!stats_info->last_stats) {
		log_err("Cannot allocate memory to store array of previous read statistics for all members\n");
		return -ENOMEM;
	}

	return 0;
}

static int set_cnt_eth_cb(struct dpa_stats_cnt_cb *cnt_cb,
			  const struct dpa_stats_cnt_params *params)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	uint32_t cnt_sel = params->eth_params.cnt_sel;
	t_FmMacStatistics stats;
	t_Handle fm_mac = NULL;
	int	 err = 0;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check Ethernet counter selection */
	if (cnt_sel == 0 || cnt_sel > DPA_STATS_CNT_ETH_ALL) {
		log_err("Parameter cnt_sel %d must be in range (1 - %d) for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_ETH_ALL, cnt_cb->id);
		return -EINVAL;
	}

	/* Decrease one to obtain the mask for all statistics */
	if (cnt_sel == DPA_STATS_CNT_ETH_ALL)
		cnt_sel -= 1;

	if (params->eth_params.src.eth_id < DPA_STATS_ETH_1G_PORT0 ||
	    params->eth_params.src.eth_id > DPA_STATS_ETH_10G_PORT1) {
		log_err("Parameter src.eth_id %d must be in range (%d - %d) for counter id %d\n",
			params->eth_params.src.eth_id, DPA_STATS_ETH_1G_PORT0,
			DPA_STATS_ETH_10G_PORT1, cnt_cb->id);
		return -EINVAL;
	}

	cnt_cb->members_num = 1;

	/* Map Ethernet counter selection to FM MAC statistics */
	err = cnt_sel_to_stats(&cnt_cb->info,
			 dpa_stats->stats_sel[DPA_STATS_CNT_ETH], cnt_sel);
	if (err)
		return err;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	/* Get FM MAC handle */
	err = get_fm_mac(params->eth_params.src, &fm_mac);
	if (err != 0) {
		log_err("Cannot retrieve Ethernet MAC handle for counter id %d\n",
			cnt_cb->id);
		return -EINVAL;
	}
	cnt_cb->gen_cb.objs = kzalloc(sizeof(t_Handle), GFP_KERNEL);
	if (!cnt_cb->gen_cb.objs) {
		log_err("No more memory for new Ethernet counter\n");
		return -ENOMEM;
	}
	cnt_cb->gen_cb.objs[0] = fm_mac;

	err = FM_MAC_GetStatistics(cnt_cb->gen_cb.objs[0], &stats);
	if (err != 0) {
		log_err("Invalid Ethernet counter source for counter id %d\n",
			cnt_cb->id);
		return -ENOENT;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	init_cnt_64bit_stats(&cnt_cb->info, &stats, 0);

	return 0;
}

static int set_cnt_reass_cb(struct dpa_stats_cnt_cb *cnt_cb,
			    const struct dpa_stats_cnt_params *params)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	uint32_t cnt_sel = params->reass_params.cnt_sel;
	struct t_FmPcdManipStats stats;
	int err;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* User can combine counters only from a group */
	if (!((cnt_sel != 0 && cnt_sel <= DPA_STATS_CNT_REASS_GEN_ALL) ||
		(cnt_sel >= DPA_STATS_CNT_REASS_IPv4_FRAMES &&
		cnt_sel <= DPA_STATS_CNT_REASS_IPv4_ALL) ||
		(cnt_sel >= DPA_STATS_CNT_REASS_IPv6_FRAMES &&
		cnt_sel <= DPA_STATS_CNT_REASS_IPv6_ALL))) {
		log_err("Parameter cnt_sel %d must be in one of the ranges (1 -%d), (%d - %d), (%d - %d) for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_REASS_GEN_ALL,
			DPA_STATS_CNT_REASS_IPv4_FRAMES,
			DPA_STATS_CNT_REASS_IPv4_ALL,
			DPA_STATS_CNT_REASS_IPv6_FRAMES,
			DPA_STATS_CNT_REASS_IPv6_ALL, cnt_cb->id);
		return -EINVAL;
	}

	if (!params->reass_params.reass) {
		log_err("Parameter Reassembly handle cannot be NULL for counter id %d\n",
			cnt_cb->id);
		return -EFAULT;
	}

	cnt_cb->gen_cb.objs = kzalloc(sizeof(t_Handle), GFP_KERNEL);
	if (!cnt_cb->gen_cb.objs) {
		log_err("No more memory for new IP reass counter\n");
		return -ENOMEM;
	}
	cnt_cb->gen_cb.objs[0] = params->reass_params.reass;
	cnt_cb->members_num = 1;

	/* Based on user option, change mask to all statistics in one group */
	if (cnt_sel == DPA_STATS_CNT_REASS_GEN_ALL)
		cnt_sel -= 1;
	else if (cnt_sel == DPA_STATS_CNT_REASS_IPv4_ALL)
		cnt_sel = (cnt_sel - 1) &
			~(DPA_STATS_CNT_REASS_IPv4_FRAMES - 1);
	else if (cnt_sel == DPA_STATS_CNT_REASS_IPv6_ALL)
		cnt_sel = (cnt_sel - 1) &
			~(DPA_STATS_CNT_REASS_IPv6_FRAMES - 1);

	/* Map Reassembly counter selection to Manip statistics */
	err = cnt_sel_to_stats(&cnt_cb->info,
			 dpa_stats->stats_sel[DPA_STATS_CNT_REASS], cnt_sel);
	if (err)
		return err;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	/* Check the user-provided reassembly manip */
	err = FM_PCD_ManipGetStatistics(params->reass_params.reass, &stats);
	if (err < 0) {
		log_err("Invalid Reassembly manip handle for counter id %d\n",
			cnt_cb->id);
		return -EINVAL;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	init_cnt_32bit_stats(&cnt_cb->info, &stats, 0);

	return 0;
}

static int set_cnt_frag_cb(struct dpa_stats_cnt_cb *cnt_cb,
			   const struct dpa_stats_cnt_params *params)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	uint32_t cnt_sel = params->frag_params.cnt_sel;
	struct t_FmPcdManipStats stats;
	int err;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check Fragmentation counter selection */
	if (cnt_sel == 0 || cnt_sel > DPA_STATS_CNT_FRAG_ALL) {
		log_err("Parameter cnt_sel %d must be in range (1 - %d) for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_FRAG_ALL, cnt_cb->id);
		return -EINVAL;
	}

	if (!params->frag_params.frag) {
		log_err("Parameter Fragmentation handle cannot be NULL for counter id %d\n",
			cnt_cb->id);
		return -EFAULT;
	}

	cnt_cb->gen_cb.objs = kzalloc(sizeof(t_Handle), GFP_KERNEL);
	if (!cnt_cb->gen_cb.objs) {
		log_err("No more memory for new IP frag counter\n");
		return -ENOMEM;
	}
	cnt_cb->gen_cb.objs[0] = params->frag_params.frag;
	cnt_cb->members_num = 1;

	/* Decrease one to obtain the mask for all statistics */
	if (cnt_sel == DPA_STATS_CNT_FRAG_ALL)
		cnt_sel -= 1;

	/* Map Fragmentation counter selection to Manip statistics */
	err = cnt_sel_to_stats(&cnt_cb->info,
			 dpa_stats->stats_sel[DPA_STATS_CNT_FRAG], cnt_sel);
	if (err)
		return err;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	/* Check the user-provided fragmentation handle */
	err = FM_PCD_ManipGetStatistics(params->frag_params.frag, &stats);
	if (err < 0) {
		log_err("Invalid Fragmentation manip handle for counter id %d\n",
			cnt_cb->id);
		return -EINVAL;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	init_cnt_32bit_stats(&cnt_cb->info, &stats, 0);

	return 0;
}

static int set_cnt_plcr_cb(struct dpa_stats_cnt_cb *cnt_cb,
			   const struct dpa_stats_cnt_params *params)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	uint32_t cnt_sel = params->plcr_params.cnt_sel;
	uint64_t stats_val;
	uint32_t i;
	int err;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check Policer counter selection */
	if (cnt_sel == 0 || cnt_sel > DPA_STATS_CNT_PLCR_ALL) {
		log_err("Parameter cnt_sel %d must be in range (1 - %d) for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_PLCR_ALL, cnt_cb->id);
		return -EINVAL;
	}

	if (!params->plcr_params.plcr) {
		log_err("Parameter Policer handle cannot be NULL for counter id %d\n",
			cnt_cb->id);
		return -EFAULT;
	}

	cnt_cb->gen_cb.objs = kzalloc(sizeof(t_Handle), GFP_KERNEL);
	if (!cnt_cb->gen_cb.objs) {
		log_err("No more memory for new policer counter\n");
		return -ENOMEM;
	}
	cnt_cb->gen_cb.objs[0] = params->plcr_params.plcr;
	cnt_cb->members_num = 1;

	/* Decrease one to obtain the mask for all statistics */
	if (cnt_sel == DPA_STATS_CNT_PLCR_ALL)
		cnt_sel -= 1;

	/* Map Policer counter selection to policer statistics */
	err = cnt_sel_to_stats(&cnt_cb->info,
			 dpa_stats->stats_sel[DPA_STATS_CNT_POLICER], cnt_sel);
	if (err)
		return err;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	for (i = 0; i < cnt_cb->info.stats_num; i++) {
		stats_val = (uint64_t)FM_PCD_PlcrProfileGetCounter(
			cnt_cb->gen_cb.objs[0], cnt_cb->info.stats_off[i]);

		/* Store the current value as the last read value */
		cnt_cb->info.stats[i] = 0;
		cnt_cb->info.last_stats[i] = stats_val;
	}
	return 0;
}

static int set_cnt_classif_tbl_cb(struct dpa_stats_cnt_cb *cnt_cb,
				  const struct dpa_stats_cnt_params *params)
{
	struct dpa_stats_cnt_classif_tbl_cb *cnt_tbl_cb = &cnt_cb->tbl_cb;
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	struct dpa_stats_cnt_classif_tbl prm = params->classif_tbl_params;
	struct dpa_cls_tbl_params cls_tbl;
	uint32_t cnt_sel = prm.cnt_sel;
	int err = 0, frag_stats = -1;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check Classifier Table counter selection */
	if (cnt_sel >= DPA_STATS_CNT_CLASSIF_BYTES &&
	    cnt_sel <= DPA_STATS_CNT_CLASSIF_ALL) {

		/* Entire group of counters was selected */
		if (cnt_sel == DPA_STATS_CNT_CLASSIF_ALL)
			cnt_sel -= 1;

		/* Map Classifier Table counter selection to CcNode stats */
		err = cnt_sel_to_stats(&cnt_cb->info,
			dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE],
			cnt_sel >> CLASSIF_STATS_SHIFT);
		if (err)
			return err;

		frag_stats = 0;

	} else if (cnt_sel >= DPA_STATS_CNT_FRAG_TOTAL_FRAMES &&
		   cnt_sel <= DPA_STATS_CNT_FRAG_ALL) {

		/* Entire group of counters was selected */
		if (cnt_sel == DPA_STATS_CNT_FRAG_ALL)
			cnt_sel -= 1;

		/* Map Classifier Table counter selection to Frag stats */
		err = cnt_sel_to_stats(&cnt_cb->info,
			dpa_stats->stats_sel[DPA_STATS_CNT_FRAG], cnt_sel);
		if (err)
			return err;

		frag_stats = 1;

	} else {
		log_err("Parameter cnt_sel %d must be in one of the ranges (%d - %d), (%d - %d), for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_CLASSIF_BYTES,
			DPA_STATS_CNT_CLASSIF_ALL,
			DPA_STATS_CNT_FRAG_TOTAL_FRAMES, DPA_STATS_CNT_FRAG_ALL,
			cnt_cb->id);
		return -EINVAL;
	}

	if (prm.td == DPA_OFFLD_DESC_NONE) {
		log_err("Invalid table descriptor %d for counter id %d\n",
			prm.td, cnt_cb->id);
		return -EINVAL;
	}
	err = dpa_classif_table_get_params(prm.td, &cls_tbl);
	if (err != 0) {
		log_err("Invalid table descriptor %d for counter id %d\n",
			prm.td, cnt_cb->id);
		return -EINVAL;
	}
	/* Allocate memory for one key descriptor */
	cnt_tbl_cb->keys = kzalloc(sizeof(*cnt_tbl_cb->keys), GFP_KERNEL);
	if (!cnt_tbl_cb->keys) {
		log_err("Cannot allocate memory for key descriptor for counter id %d\n",
			cnt_cb->id);
		return -ENOMEM;
	}

	/* Store CcNode handle and set number of keys to one */
	cnt_tbl_cb->keys[0].cc_node = cls_tbl.cc_node;
	cnt_tbl_cb->keys[0].valid = TRUE;
	cnt_cb->members_num = 1;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	/* Store DPA Classifier Table type */
	cnt_tbl_cb->type = cls_tbl.type;

	/* Set retrieve function depending on table type */
	err = set_cnt_classif_tbl_retrieve_func(cnt_cb);
	if (err != 0)
		return -EINVAL;

	/* Allocate the single key: */
	cnt_tbl_cb->keys[0].key.data.byte = kzalloc(
			DPA_OFFLD_MAXENTRYKEYSIZE, GFP_KERNEL);
	if (!cnt_tbl_cb->keys[0].key.data.byte)
		log_err("Cannot allocate memory for the key of for counter id %d\n",
				cnt_cb->id);
	cnt_tbl_cb->keys[0].key.data.mask = kzalloc(
			DPA_OFFLD_MAXENTRYKEYSIZE, GFP_KERNEL);
	if (!cnt_tbl_cb->keys[0].key.data.mask)
		log_err("Cannot allocate memory for the mask of counter id %d\n",
				cnt_cb->id);

	if (!prm.key) {
		cnt_tbl_cb->keys[0].miss_key = TRUE;
	} else {
		/* Copy the key descriptor */
		err = copy_key_descriptor(prm.key, &cnt_tbl_cb->keys[0].key);
		if (err != 0) {
			log_err("Cannot copy key descriptor from user parameters\n");
			return -EINVAL;
		}
	}

	if (!frag_stats) {
		if (cnt_tbl_cb->keys[0].miss_key) {
			/*
			 * Retrieve Classifier Table counter statistics for
			 * 'miss'
			 */
			err = get_classif_tbl_miss_stats(cnt_cb, 0);
			if (err != 0)
				return -EINVAL;
		} else {
			/*
			 * Retrieve Classifier Table counter statistics for a
			 * key
			 */
			err = get_classif_tbl_key_stats(cnt_cb, 0);
			if (err != 0)
				return err;
		}
	} else {
		err = set_frag_manip(prm.td, &cnt_tbl_cb->keys[0]);
		if (err < 0) {
			log_err("Invalid Fragmentation manip handle for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}
		/* Change the retrieve routine */
		cnt_cb->f_get_cnt_stats = get_cnt_cls_tbl_frag_stats;
	}
	return 0;
}

static int set_cnt_ccnode_cb(struct dpa_stats_cnt_cb *cnt_cb,
			     const struct dpa_stats_cnt_params *params)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	struct dpa_stats_cnt_classif_node prm = params->classif_node_params;
	int err = 0;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check Classification Node counter selection */
	if (prm.cnt_sel == 0 ||  prm.cnt_sel > DPA_STATS_CNT_CLASSIF_ALL) {
		log_err("Parameter cnt_sel %d must be in range (1 - %d) for counter id %d\n",
			prm.cnt_sel, DPA_STATS_CNT_CLASSIF_ALL, cnt_cb->id);
		return -EINVAL;
	}

	if (!params->classif_node_params.cc_node) {
		log_err("Parameter classification CC Node handle cannot be NULL for counter id %d\n",
			cnt_cb->id);
		return -EFAULT;
	}

	/* Store CcNode handle and set number of keys to one */
	cnt_cb->ccnode_cb.cc_node = prm.cc_node;
	cnt_cb->members_num = 1;

	/* Map Classif Node counter selection to CcNode statistics */
	err = cnt_sel_to_stats(&cnt_cb->info,
		dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE],
		prm.cnt_sel >> CLASSIF_STATS_SHIFT);
	if (err)
		return err;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	/* Allocate memory for one key descriptor */
	cnt_cb->ccnode_cb.keys = kzalloc(sizeof(*cnt_cb->ccnode_cb.keys),
								GFP_KERNEL);
	if (!cnt_cb->ccnode_cb.keys) {
		log_err("Cannot allocate memory for key descriptor for counter id %d\n",
			cnt_cb->id);
		return -ENOMEM;
	}

	/* Set retrieve function depending on counter type */
	err = set_cnt_classif_node_retrieve_func(cnt_cb, prm.ccnode_type);
	if (err != 0)
		return -EINVAL;

	/* Allocate memory for every key */
	cnt_cb->ccnode_cb.keys[0].data.byte = kzalloc(
			DPA_OFFLD_MAXENTRYKEYSIZE, GFP_KERNEL);
	if (!cnt_cb->ccnode_cb.keys[0].data.byte)
		log_err("Cannot allocate memory for the key of the counter id %d\n",
				cnt_cb->id);
	cnt_cb->ccnode_cb.keys[0].data.mask = kzalloc(
			DPA_OFFLD_MAXENTRYKEYSIZE, GFP_KERNEL);
	if (!cnt_cb->ccnode_cb.keys[0].data.mask)
		log_err("Cannot allocate memory for the mask of the counter id %d\n",
				cnt_cb->id);

	if (!params->classif_node_params.key) {
		/* Set the key byte to NULL, to mark it for 'miss' entry */
		cnt_cb->ccnode_cb.keys[0].valid_key = false;

		/* Retrieve Classifier Node counter statistics for 'miss' */
		err = get_ccnode_miss_stats(cnt_cb, prm.ccnode_type, 0);
	} else {
		/* Copy the key descriptor */
		err = copy_key_descriptor(prm.key, &cnt_cb->ccnode_cb.keys[0]);
		if (err != 0) {
			log_err("Cannot copy key descriptor from user parameters\n");
			return -EINVAL;
		}
		/* Retrieve Classifier Node counter statistics for key */
		err = get_ccnode_key_stats(cnt_cb, prm.ccnode_type, 0);
	}
	return err;
}

static int set_cnt_ipsec_cb(struct dpa_stats_cnt_cb *cnt_cb,
			    const struct dpa_stats_cnt_params *params)
{
	struct dpa_ipsec_sa_stats stats;
	int err = 0;

	if (!cnt_cb->dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Allocate memory for one security association id */
	cnt_cb->ipsec_cb.sa_id = kzalloc(sizeof(*cnt_cb->ipsec_cb.sa_id),
					GFP_KERNEL);
	if (!cnt_cb->ipsec_cb.sa_id) {
		log_err("Cannot allocate memory for security association id for counter id %d\n",
			cnt_cb->id);
		return -ENOMEM;
	}

	/* Allocate memory to store if security association is valid */
	cnt_cb->ipsec_cb.valid = kzalloc(sizeof(*cnt_cb->ipsec_cb.valid),
					 GFP_KERNEL);
	if (!cnt_cb->ipsec_cb.valid) {
		log_err("Cannot allocate memory to store if security association is valid for counter id %d\n",
			cnt_cb->id);
		return -ENOMEM;
	}

	cnt_cb->ipsec_cb.sa_id[0] = params->ipsec_params.sa_id;
	cnt_cb->ipsec_cb.valid[0] = TRUE;
	cnt_cb->members_num = 1;

	/* Map IPSec counter selection to statistics */
	err = cnt_gen_sel_to_stats(cnt_cb, params->ipsec_params.cnt_sel);
	if (err < 0)
		return err;

	err = dpa_ipsec_sa_get_stats(cnt_cb->ipsec_cb.sa_id[0], &stats);
	if (err < 0) {
		log_err("Check failed for IPSec counter id %d due to incorrect parameters: sa_id=%d\n",
			cnt_cb->id, cnt_cb->ipsec_cb.sa_id[0]);
		return -EINVAL;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	init_cnt_32bit_stats(&cnt_cb->info, &stats, 0);

	return 0;
}

static int set_cnt_traffic_mng_cb(struct dpa_stats_cnt_cb *cnt_cb,
			    const struct dpa_stats_cnt_params *params)
{
	uint32_t cnt_sel = params->traffic_mng_params.cnt_sel;
	uint32_t cnt_src = params->traffic_mng_params.src;
	uint64_t stats[2];
	int err = 0;
	bool us_cnt = FALSE;

	if (!cnt_cb->dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check if this is an users-space counter and if so, reset the flag */
	if (cnt_sel & DPA_STATS_US_CNT) {
		us_cnt = TRUE;
		cnt_sel &= ~DPA_STATS_US_CNT;
	}

	if (!params->traffic_mng_params.traffic_mng && !us_cnt) {
		log_err("Parameter traffic_mng handle cannot be NULL for counter id %d\n",
			cnt_cb->id);
		return -EINVAL;
	}

	/* Check and store the counter source */
	if (cnt_src > DPA_STATS_CNT_TRAFFIC_CG) {
		log_err("Parameter src %d must be in range (%d - %d) for counter id %d\n",
			cnt_src, DPA_STATS_CNT_TRAFFIC_CLASS,
			DPA_STATS_CNT_TRAFFIC_CG, cnt_cb->id);
		return -EINVAL;
	}

	cnt_cb->gen_cb.objs = kzalloc(sizeof(t_Handle), GFP_KERNEL);
	if (!cnt_cb->gen_cb.objs) {
		log_err("No more memory for new policer counter\n");
		return -ENOMEM;
	}
	cnt_cb->gen_cb.objs[0] = params->traffic_mng_params.traffic_mng;
	cnt_cb->members_num = 1;

	/* Map Traffic Manager counter selection to statistics */
	err = cnt_gen_sel_to_stats(cnt_cb, cnt_sel);
	if (err < 0)
		return err;

	/* For user-space counters there is a different retrieve function */
	if (us_cnt) {
		cnt_cb->f_get_cnt_stats = get_cnt_us_stats;
		return 0;
	}

	/* Check the counter source and the Traffic Manager object */
	switch (cnt_src) {
	case DPA_STATS_CNT_TRAFFIC_CLASS:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_cq_stats;
		err = qman_ceetm_cq_get_dequeue_statistics(
				params->traffic_mng_params.traffic_mng,
				0, &stats[0], &stats[1]);
		if (err < 0) {
			log_err("Invalid Traffic Manager qm_ceetm_cq object for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}
		break;
	case DPA_STATS_CNT_TRAFFIC_CG:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_ccg_stats;
		err = qman_ceetm_ccg_get_reject_statistics(
				params->traffic_mng_params.traffic_mng,
				0, &stats[0], &stats[1]);
		if (err < 0) {
			log_err("Invalid Traffic Manager qm_ceetm_ccg object for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}
		break;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	init_cnt_64bit_stats(&cnt_cb->info, &stats, 0);

	return 0;
}

static int set_cls_cnt_eth_cb(struct dpa_stats_cnt_cb *cnt_cb,
			      const struct dpa_stats_cls_cnt_params *params)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	uint32_t cnt_sel = params->eth_params.cnt_sel;
	t_FmMacStatistics stats;
	t_Handle fm_mac = NULL;
	uint32_t i = 0;
	int err = 0;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check Ethernet counter selection */
	if (params->eth_params.cnt_sel == 0 ||
	    params->eth_params.cnt_sel > DPA_STATS_CNT_ETH_ALL) {
		log_err("Parameter cnt_sel %d must be in range (1 - %d) for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_ETH_ALL, cnt_cb->id);
		return -EINVAL;
	}

	/* Decrease one to obtain the mask for all statistics */
	if (cnt_sel == DPA_STATS_CNT_ETH_ALL)
		cnt_sel -= 1;

	cnt_cb->members_num = params->class_members;

	/* Map Ethernet counter selection to FM MAC statistics */
	err = cnt_sel_to_stats(&cnt_cb->info,
			 dpa_stats->stats_sel[DPA_STATS_CNT_ETH], cnt_sel);
	if (err)
		return err;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
			DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	cnt_cb->gen_cb.objs = kcalloc(cnt_cb->members_num, sizeof(t_Handle),
								GFP_KERNEL);
	if (!cnt_cb->gen_cb.objs) {
		log_err("No more memory for new Ethernet class counter\n");
		return -ENOMEM;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	for (i = 0; i < params->class_members; i++) {
		/* Get FM MAC handle */
		err = get_fm_mac(params->eth_params.src[i], &fm_mac);
		if (err != 0) {
			log_err("Cannot obtain Ethernet MAC handle for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}

		cnt_cb->gen_cb.objs[i] = fm_mac;

		err = FM_MAC_GetStatistics(cnt_cb->gen_cb.objs[i], &stats);
		if (err != 0) {
			log_err("Invalid Ethernet counter source for counter id %d\n",
				cnt_cb->id);
			return -ENOENT;
		}
		init_cnt_64bit_stats(&cnt_cb->info, &stats, i);
	}
	return 0;
}

static int set_cls_cnt_reass_cb(struct dpa_stats_cnt_cb *cnt_cb,
				const struct dpa_stats_cls_cnt_params *params)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	struct t_FmPcdManipStats stats;
	uint32_t cnt_sel = params->reass_params.cnt_sel;
	uint32_t i = 0;
	int err = 0;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* User can combine counters only from a group */
	if (!((cnt_sel != 0 && cnt_sel <= DPA_STATS_CNT_REASS_GEN_ALL) ||
	      (cnt_sel >= DPA_STATS_CNT_REASS_IPv4_FRAMES &&
	       cnt_sel <= DPA_STATS_CNT_REASS_IPv4_ALL) ||
	      (cnt_sel >= DPA_STATS_CNT_REASS_IPv6_FRAMES &&
	       cnt_sel <= DPA_STATS_CNT_REASS_IPv6_ALL))) {
		log_err("Parameter cnt_sel %d must be in one of the ranges (1 - %d), (%d - %d), (%d - %d) for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_REASS_GEN_ALL,
			DPA_STATS_CNT_REASS_IPv4_FRAMES,
			DPA_STATS_CNT_REASS_IPv4_ALL,
			DPA_STATS_CNT_REASS_IPv6_FRAMES,
			DPA_STATS_CNT_REASS_IPv6_ALL, cnt_cb->id);
		return -EINVAL;
	}

	cnt_cb->members_num = params->class_members;

	/* Based on user option, change mask to all statistics in one group */
	if (cnt_sel == DPA_STATS_CNT_REASS_GEN_ALL)
		cnt_sel -= 1;
	else if (cnt_sel == DPA_STATS_CNT_REASS_IPv4_ALL)
		cnt_sel = (cnt_sel - 1) &
			~(DPA_STATS_CNT_REASS_IPv4_FRAMES - 1);
	else if (cnt_sel == DPA_STATS_CNT_REASS_IPv6_ALL)
		cnt_sel = (cnt_sel - 1) &
			~(DPA_STATS_CNT_REASS_IPv6_FRAMES - 1);

	/* Map Reassembly counter selection to Manip statistics */
	err = cnt_sel_to_stats(&cnt_cb->info,
			 dpa_stats->stats_sel[DPA_STATS_CNT_REASS], cnt_sel);
	if (err)
		return err;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
			DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	cnt_cb->gen_cb.objs = kcalloc(cnt_cb->members_num, sizeof(t_Handle),
								GFP_KERNEL);
	if (!cnt_cb->gen_cb.objs) {
		log_err("No more memory for new IP reass class counter\n");
		return -ENOMEM;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	for (i = 0; i < params->class_members; i++) {
		if (!params->reass_params.reass[i]) {
			log_err("Parameter Reassembly handle cannot be NULL for member %d, counter id %d\n",
				i, cnt_cb->id);
			return -EFAULT;
		}
		cnt_cb->gen_cb.objs[i] = params->reass_params.reass[i];

		/* Check the user-provided reassembly manip */
		err = FM_PCD_ManipGetStatistics(cnt_cb->gen_cb.objs[i], &stats);
		if (err < 0) {
			log_err("Invalid Reassembly manip handle for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}
		init_cnt_32bit_stats(&cnt_cb->info, &stats, i);
	}

	return 0;
}

static int set_cls_cnt_frag_cb(struct dpa_stats_cnt_cb *cnt_cb,
			       const struct dpa_stats_cls_cnt_params *params)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	uint32_t cnt_sel = params->frag_params.cnt_sel, i;
	struct t_FmPcdManipStats stats;
	int err;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check Fragmentation counter selection */
	if ((cnt_sel == 0) || (cnt_sel > DPA_STATS_CNT_FRAG_ALL)) {
		log_err("Parameter cnt_sel %d must be in range (1 - %d) for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_FRAG_ALL, cnt_cb->id);
		return -EINVAL;
	}

	cnt_cb->members_num = params->class_members;

	/* Decrease one to obtain the mask for all statistics */
	if (cnt_sel == DPA_STATS_CNT_FRAG_ALL)
		cnt_sel -= 1;

	/* Map Fragmentation counter selection to Manip statistics */
	err = cnt_sel_to_stats(&cnt_cb->info,
			 dpa_stats->stats_sel[DPA_STATS_CNT_FRAG], cnt_sel);
	if (err)
		return err;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
			DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	cnt_cb->gen_cb.objs = kcalloc(cnt_cb->members_num, sizeof(t_Handle),
								GFP_KERNEL);
	if (!cnt_cb->gen_cb.objs) {
		log_err("No more memory for new IP frag class counter\n");
		return -ENOMEM;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	for (i = 0; i < params->class_members; i++) {
		if (!params->frag_params.frag[i]) {
			log_err("Parameter Fragmentation handle cannot be NULL for member %d, counter id %d\n",
				i, cnt_cb->id);
			return -EFAULT;
		}
		cnt_cb->gen_cb.objs[i] = params->frag_params.frag[i];

		/* Check the user-provided fragmentation handle */
		err = FM_PCD_ManipGetStatistics(cnt_cb->gen_cb.objs[i], &stats);
		if (err < 0) {
			log_err("Invalid Fragmentation manip handle for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}
		init_cnt_32bit_stats(&cnt_cb->info, &stats, i);
	}

	return 0;
}

static int set_cls_cnt_plcr_cb(struct dpa_stats_cnt_cb *cnt_cb,
			       const struct dpa_stats_cls_cnt_params *params)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	uint32_t cnt_sel = params->plcr_params.cnt_sel;
	uint32_t i, j, stats_idx, stats_base_idx;
	uint64_t stats;
	int err;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check Policer counter selection */
	if (cnt_sel == 0 || cnt_sel > DPA_STATS_CNT_PLCR_ALL) {
		log_err("Parameter cnt_sel %d must be in range (1 - %d) for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_PLCR_ALL, cnt_cb->id);
		return -EINVAL;
	}

	/* Decrease one to obtain the mask for all statistics */
	if (cnt_sel == DPA_STATS_CNT_PLCR_ALL)
		cnt_sel -= 1;

	cnt_cb->members_num = params->class_members;

	/* Map Policer counter selection to policer statistics */
	err = cnt_sel_to_stats(&cnt_cb->info,
			 dpa_stats->stats_sel[DPA_STATS_CNT_POLICER], cnt_sel);
	if (err)
		return err;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
			DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	cnt_cb->gen_cb.objs = kcalloc(cnt_cb->members_num, sizeof(t_Handle),
								GFP_KERNEL);
	if (!cnt_cb->gen_cb.objs) {
		log_err("No more memory for new policer class counter\n");
		return -ENOMEM;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	for (i = 0; i < params->class_members; i++) {
		if (!params->plcr_params.plcr[i]) {
			log_err("Parameter Policer handle cannot be NULL for member %d, counter id %d\n",
				i, cnt_cb->id);
			return -EFAULT;
		}
		cnt_cb->gen_cb.objs[i] = params->plcr_params.plcr[i];

		stats_base_idx = cnt_cb->info.stats_num * i;
		for (j = 0; j < cnt_cb->info.stats_num; j++) {
			stats = (uint64_t)FM_PCD_PlcrProfileGetCounter(
				cnt_cb->gen_cb.objs[i],
				cnt_cb->info.stats_off[j]);

			/* Store the current value as the last read value */
			stats_idx = stats_base_idx + j;
			cnt_cb->info.stats[stats_idx] = 0;
			cnt_cb->info.last_stats[stats_idx] = stats;
		}
	}

	return 0;
}

static int set_cls_cnt_classif_tbl_pair(
		struct dpa_stats_cnt_cb *cnt_cb, int td,
		const struct dpa_offload_lookup_key_pair *pair,
		uint32_t idx)
{
	struct dpa_stats_cnt_classif_tbl_cb *cnt_tbl_cb = &cnt_cb->tbl_cb;
	struct dpa_stats_lookup_key *lookup_key = &cnt_tbl_cb->keys[idx];
	struct dpa_cls_tbl_params cls_tbl;
	struct dpa_cls_tbl_action action;
	int err = 0;

	/* If either the entire 'pair' or the first key is NULL, then retrieve
	 * the action associated with the 'miss action '*/
	if ((!pair) || (pair && !pair->first_key)) {
		err = dpa_classif_get_miss_action(td, &action);
		if (err != 0) {
			log_err("Cannot retrieve miss action parameters for table descriptor %d\n",
				td);
			return -EINVAL;
		}
	} else {
		/* Check that key byte is not NULL */
		if (!pair->first_key->byte) {
			log_err("First key descriptor byte of the user pair cannot be NULL for table descriptor %d\n",
				td);
			return -EFAULT;
		}

		/* Use the first key of the pair to lookup in the classifier
		 * table the next table connected on a "next-action" */
		err = dpa_classif_table_lookup_by_key(td, pair->first_key,
						&action);
		if (err != 0) {
			log_err("Cannot retrieve next action parameters for table descriptor %d\n",
				td);
			return -EINVAL;
		}
	}

	if (action.type != DPA_CLS_TBL_ACTION_NEXT_TABLE) {
		log_err("Pair key is supported only if two tables are connected");
		return -EINVAL;
	}

	/* Get CcNode from new table descriptor */
	err = dpa_classif_table_get_params(
			action.next_table_params.next_td, &cls_tbl);
	if (err != 0) {
		log_err("Cannot retrieve next table %d parameters\n", td);
		return -EINVAL;
	}

	/* Store DPA Classifier Table type */
	cnt_tbl_cb->type = cls_tbl.type;

	/* Set retrieve function depending on table type */
	set_cnt_classif_tbl_retrieve_func(cnt_cb);

	/* Store CcNode handle */
	lookup_key->cc_node = cls_tbl.cc_node;

	if (!pair || (pair && !pair->second_key)) {
		/* Set as the key as "for miss" */
		lookup_key->miss_key = TRUE;
	} else {
		lookup_key->miss_key = FALSE;

		/* Set as lookup key the second key descriptor from the pair */
		err = copy_key_descriptor(pair->second_key,
							&lookup_key->key);
		if (err != 0) {
			log_err("Cannot copy second key descriptor of the user pair\n");
			return -EINVAL;
		}
	}

	return err;
}

static int set_cls_cnt_classif_tbl_cb(struct dpa_stats_cnt_cb *cnt_cb,
				 const struct dpa_stats_cls_cnt_params *params)
{
	struct dpa_stats_cnt_classif_tbl_cb *tbl_cb = &cnt_cb->tbl_cb;
	struct dpa_stats_cls_cnt_classif_tbl prm = params->classif_tbl_params;
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	struct dpa_cls_tbl_params cls_tbl;
	uint32_t i = 0, cnt_sel = prm.cnt_sel;
	int err = 0, frag_stats = -1;

	/* Check Classifier Table descriptor */
	if (params->classif_tbl_params.td == DPA_OFFLD_INVALID_OBJECT_ID) {
		log_err("Invalid table descriptor %d for counter id %d\n",
			params->classif_tbl_params.td, cnt_cb->id);
		return -EINVAL;
	}

	/* Check Classifier Table counter selection */
	if (cnt_sel >= DPA_STATS_CNT_CLASSIF_BYTES &&
	    cnt_sel <= DPA_STATS_CNT_CLASSIF_ALL) {

		/* Entire group of counters was selected */
		if (cnt_sel == DPA_STATS_CNT_CLASSIF_ALL)
			cnt_sel -= 1;

		/* Map Classif Node counter selection to CcNode statistics */
		err = cnt_sel_to_stats(&cnt_cb->info,
			dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE],
			cnt_sel >> CLASSIF_STATS_SHIFT);
		if (err)
			return err;

		frag_stats = 0;

	} else if (cnt_sel >= DPA_STATS_CNT_FRAG_TOTAL_FRAMES &&
		 cnt_sel <= DPA_STATS_CNT_FRAG_ALL) {

		/* Entire group of counters was selected */
		if (cnt_sel == DPA_STATS_CNT_FRAG_ALL)
			cnt_sel -= 1;

		/* Map Classif Node counter selection to fragmentation stats */
		err = cnt_sel_to_stats(&cnt_cb->info,
			dpa_stats->stats_sel[DPA_STATS_CNT_FRAG], cnt_sel);
		if (err)
			return err;

		frag_stats = 1;

	} else {
		log_err("Parameter cnt_sel %d must be in one of the ranges (%d - %d), (%d - %d), for counter id %d\n",
			cnt_sel, DPA_STATS_CNT_CLASSIF_BYTES,
			DPA_STATS_CNT_CLASSIF_ALL,
			DPA_STATS_CNT_FRAG_TOTAL_FRAMES, DPA_STATS_CNT_FRAG_ALL,
			cnt_cb->id);
		return -EINVAL;
	}

	tbl_cb->td = params->classif_tbl_params.td;
	cnt_cb->members_num = params->class_members;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
			DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	/* Allocate memory for key descriptors */
	tbl_cb->keys = kcalloc(params->class_members, sizeof(*tbl_cb->keys),
								GFP_KERNEL);
	if (!tbl_cb->keys) {
		log_err("Cannot allocate memory for array of key descriptors for counter id %d\n",
			cnt_cb->id);
		return -ENOMEM;
	}

	for (i = 0; i < cnt_cb->members_num; i++) {
		/* Allocate memory for every key */
		tbl_cb->keys[i].key.data.byte = kzalloc(
				DPA_OFFLD_MAXENTRYKEYSIZE, GFP_KERNEL);
		if (!tbl_cb->keys[i].key.data.byte)
			log_err("Cannot allocate memory for key %d of counter id %d\n",
					i, cnt_cb->id);
		tbl_cb->keys[i].key.data.mask = kzalloc(
				DPA_OFFLD_MAXENTRYKEYSIZE, GFP_KERNEL);
		if (!tbl_cb->keys[i].key.data.mask)
			log_err("Cannot allocate memory for mask %d of counter id %d\n",
					i, cnt_cb->id);
	}

	switch (prm.key_type) {
	case DPA_STATS_CLASSIF_SINGLE_KEY:
		if (!prm.keys) {
			log_err("Pointer to the array of keys cannot be NULL for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}

		/* Get CcNode from table descriptor */
		err = dpa_classif_table_get_params(prm.td, &cls_tbl);
		if (err != 0) {
			log_err("Invalid table descriptor %d for counter id %d\n",
				prm.td, cnt_cb->id);
			return -EINVAL;
		}

		/* Store DPA Classifier Table type */
		tbl_cb->type = cls_tbl.type;

		/* Set retrieve function depending on table type */
		set_cnt_classif_tbl_retrieve_func(cnt_cb);

		for (i = 0; i < params->class_members; i++) {
			/* Store CcNode handle */
			tbl_cb->keys[i].cc_node = cls_tbl.cc_node;

			/* Determine if key represents a 'miss' entry */
			if (!prm.keys[i]) {
				tbl_cb->keys[i].miss_key = TRUE;
				tbl_cb->keys[i].valid = TRUE;
				continue;
			}
			/* Key is not valid for now */
			if (!prm.keys[i]->byte) {
				tbl_cb->keys[i].valid = FALSE;
				continue;
			}
			/* Copy the key descriptor */
			err = copy_key_descriptor(prm.keys[i],
						  &tbl_cb->keys[i].key);
			if (err != 0) {
				log_err("Cannot copy key descriptor from user parameters\n");
				return -EINVAL;
			}
			tbl_cb->keys[i].valid = TRUE;
		}
		break;
	case DPA_STATS_CLASSIF_PAIR_KEY:
		if (!prm.pairs) {
			log_err("Pointer to the array of pairs cannot be NULL for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}

		for (i = 0; i < params->class_members; i++) {
			if (prm.pairs[i]) {
				if (prm.pairs[i]->first_key) {
					if (!prm.pairs[i]->first_key->byte) {
						/* Key is not valid for now */
						tbl_cb->keys[i].valid = FALSE;
						continue;
					}
				}
			}

			err = set_cls_cnt_classif_tbl_pair(cnt_cb, prm.td,
							prm.pairs[i], i);
			if (err != 0) {
				log_err("Cannot set classifier table pair key for counter id %d\n",
					cnt_cb->id);
				return -EINVAL;
			}
			tbl_cb->keys[i].valid = TRUE;
		}
		break;
	default:
		log_err("Parameter key_type %d must be in range (%d - %d) for counter id %d\n",
			prm.key_type, DPA_STATS_CLASSIF_SINGLE_KEY,
			DPA_STATS_CLASSIF_PAIR_KEY, cnt_cb->id);
		return -EINVAL;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	if (!frag_stats) {
		for (i = 0; i < params->class_members; i++) {
			if (!tbl_cb->keys[i].valid)
				continue;

			/* Get Classif Table counter stats for 'miss' */
			if (tbl_cb->keys[i].miss_key) {
				err = get_classif_tbl_miss_stats(cnt_cb, i);
				if (err != 0)
					return -EINVAL;
			} else {
				/*
				 * Get Classifier Table counter statistics for
				 * a key
				 */
				err = get_classif_tbl_key_stats(cnt_cb, i);
				if (err != 0)
					return -EINVAL;
			}
		}
	} else {
		/* For every valid key, retrieve the hmcd */
		for (i = 0; i < params->class_members; i++) {
			if (!tbl_cb->keys[i].valid)
				continue;

			err = set_frag_manip(prm.td, &cnt_cb->tbl_cb.keys[i]);
			if (err < 0) {
				log_err("Invalid Fragmentation manip handle for counter id %d\n",
					cnt_cb->id);
				return -EINVAL;
			}
		}
		/* Set the retrieve routine */
		cnt_cb->f_get_cnt_stats = get_cnt_cls_tbl_frag_stats;
	}

	return 0;
}

static int set_cls_cnt_ccnode_cb(struct dpa_stats_cnt_cb *cnt_cb,
				 const struct dpa_stats_cls_cnt_params *params)
{
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	struct dpa_stats_cls_cnt_classif_node prm = params->classif_node_params;
	uint32_t i = 0;
	int err = 0;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check Classification Cc Node counter selection */
	if (prm.cnt_sel == 0 ||  prm.cnt_sel > DPA_STATS_CNT_CLASSIF_ALL) {
		log_err("Parameter cnt_sel %d must be in range (1 - %d) for counter id %d\n",
			prm.cnt_sel, DPA_STATS_CNT_CLASSIF_ALL, cnt_cb->id);
		return -EINVAL;
	}

	if (!params->classif_node_params.cc_node) {
		log_err("Parameter classification CC Node handle cannot be NULL for counter id %d\n",
			cnt_cb->id);
		return -EFAULT;
	}

	if (!prm.keys) {
		log_err("Pointer to the array of keys cannot be NULL for counter id %d\n",
			cnt_cb->id);
		return -EINVAL;
	}

	cnt_cb->ccnode_cb.cc_node = prm.cc_node;
	cnt_cb->members_num = params->class_members;

	/* Map Classif Node counter selection to CcNode statistics */
	err = cnt_sel_to_stats(&cnt_cb->info,
			 dpa_stats->stats_sel[DPA_STATS_CNT_CLASSIF_NODE],
			 prm.cnt_sel >> CLASSIF_STATS_SHIFT);
	if (err)
		return err;

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
			DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

	/* Set retrieve function depending on counter type */
	err = set_cnt_classif_node_retrieve_func(cnt_cb, prm.ccnode_type);
	if (err != 0)
		return -EINVAL;

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	/* Allocate memory for one key descriptor */
	cnt_cb->ccnode_cb.keys = kcalloc(cnt_cb->members_num,
					sizeof(*cnt_cb->ccnode_cb.keys),
								GFP_KERNEL);
	if (!cnt_cb->ccnode_cb.keys) {
		log_err("Cannot allocate memory for key descriptors for class counter id %d\n",
			cnt_cb->id);
		return -ENOMEM;
	}

	for (i = 0; i < cnt_cb->members_num; i++) {
		/* Allocate memory for every key */
		cnt_cb->ccnode_cb.keys[i].data.byte = kzalloc(
				DPA_OFFLD_MAXENTRYKEYSIZE, GFP_KERNEL);
		if (!cnt_cb->ccnode_cb.keys[i].data.byte)
			log_err("Cannot allocate memory for key %d of counter id %d\n",
					i, cnt_cb->id);
		cnt_cb->ccnode_cb.keys[i].data.mask = kzalloc(
				DPA_OFFLD_MAXENTRYKEYSIZE, GFP_KERNEL);
		if (!cnt_cb->ccnode_cb.keys[i].data.mask)
			log_err("Cannot allocate memory for mask %d of counter id %d\n",
					i, cnt_cb->id);
	}

	for (i = 0; i < params->class_members; i++) {
		if (!prm.keys[i]) {
			/* Invalidate key data, to mark it for 'miss' */
			cnt_cb->ccnode_cb.keys[i].valid_key = false;

			/* Retrieve Classif Node counter statistics for 'miss'*/
			err = get_ccnode_miss_stats(cnt_cb, prm.ccnode_type, i);
			if (err != 0)
				return err;
		} else {
			/* Copy the key descriptor */
			err = copy_key_descriptor(prm.keys[i],
						  &cnt_cb->ccnode_cb.keys[i]);
			if (err != 0) {
				log_err("Cannot copy key descriptor from user parameters\n");
				return -EINVAL;
			}

			/* Retrieve Classifier Node counter statistics for key*/
			err = get_ccnode_key_stats(cnt_cb, prm.ccnode_type, i);
			if (err != 0)
				return err;
		}
	}

	return 0;
}

static int set_cls_cnt_ipsec_cb(struct dpa_stats_cnt_cb *cnt_cb,
				const struct dpa_stats_cls_cnt_params *prm)
{
	struct dpa_stats_cnt_ipsec_cb *cnt_ipsec_cb = &cnt_cb->ipsec_cb;
	struct dpa_stats *dpa_stats = cnt_cb->dpa_stats;
	struct dpa_ipsec_sa_stats stats;
	uint32_t i = 0;
	int err = 0;

	if (!dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Allocate memory for array of security association ids */
	cnt_cb->ipsec_cb.sa_id = kcalloc(prm->class_members,
				  sizeof(*cnt_cb->ipsec_cb.sa_id), GFP_KERNEL);
	if (!cnt_cb->ipsec_cb.sa_id) {
		log_err("Cannot allocate memory for array of security association ids, for counter id %d\n",
			cnt_cb->id);
		return -ENOMEM;
	}

	/* Allocate memory for array that stores if SA id is valid */
	cnt_cb->ipsec_cb.valid = kcalloc(prm->class_members,
				  sizeof(*cnt_cb->ipsec_cb.valid), GFP_KERNEL);
	if (!cnt_cb->ipsec_cb.valid) {
		log_err("Cannot allocate memory for array that stores if security association ids are valid for counter id %d\n",
			cnt_cb->id);
		return -ENOMEM;
	}

	cnt_cb->members_num = prm->class_members;

	/* Map IPSec counter selection to statistics */
	err = cnt_gen_sel_to_stats(cnt_cb, prm->ipsec_params.cnt_sel);
	if (err < 0)
		return err;

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	for (i = 0; i < prm->class_members; i++) {
		if (prm->ipsec_params.sa_id[i] != DPA_OFFLD_INVALID_OBJECT_ID) {
			cnt_ipsec_cb->sa_id[i] = prm->ipsec_params.sa_id[i];
			cnt_ipsec_cb->valid[i] = TRUE;

			err = dpa_ipsec_sa_get_stats(cnt_cb->ipsec_cb.sa_id[i],
					&stats);
			if (err < 0) {
				log_err("Check failed for IPSec counter id %d due to incorrect parameters: sa_id=%d\n",
					cnt_cb->id, cnt_cb->ipsec_cb.sa_id[i]);
				return -EINVAL;
			}
			init_cnt_32bit_stats(&cnt_cb->info, &stats, i);
		} else
			cnt_ipsec_cb->valid[i] = FALSE;
	}

	return 0;
}

static int set_cls_cnt_traffic_mng_cb(struct dpa_stats_cnt_cb *cnt_cb,
		const struct dpa_stats_cls_cnt_params *params)
{
	struct dpa_stats_cls_cnt_traffic_mng prm = params->traffic_mng_params;
	uint32_t cnt_sel = prm.cnt_sel, i;
	uint64_t stats[2];
	int err = 0;
	bool us_cnt = FALSE;

	if (!cnt_cb->dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EFAULT;
	}

	/* Check if this is an users-space counter and if so, reset the flag */
	if (cnt_sel & DPA_STATS_US_CNT) {
		us_cnt = TRUE;
		cnt_sel &= ~DPA_STATS_US_CNT;
	}

	cnt_cb->members_num = params->class_members;

	/* Map Traffic Manager counter selection to statistics */
	err = cnt_gen_sel_to_stats(cnt_cb, cnt_sel);
	if (err < 0)
		return err;

	/* For user-space counters there is a different retrieve function */
	if (us_cnt) {
		cnt_cb->f_get_cnt_stats = get_cnt_us_stats;
		return 0;
	}

	err = alloc_cnt_stats(&cnt_cb->info, cnt_cb->members_num);
	if (err)
		return err;

	cnt_cb->gen_cb.objs = kcalloc(cnt_cb->members_num, sizeof(t_Handle),
								GFP_KERNEL);
	if (!cnt_cb->gen_cb.objs) {
		log_err("No more memory for new traffic manager class counter\n");
		return -ENOMEM;
	}

	/* Check the counter source and the Traffic Manager object */
	switch (prm.src) {
	case DPA_STATS_CNT_TRAFFIC_CLASS:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_cq_stats;
		for (i = 0; i < params->class_members; i++) {
			if (!prm.traffic_mng[i]) {
				log_err("Parameter traffic_mng handle cannot be NULL for member %d\n",
					i);
				return -EFAULT;
			}

			/* Check the provided Traffic Manager object */
			err = qman_ceetm_cq_get_dequeue_statistics(
				prm.traffic_mng[i], 0, &stats[0], &stats[1]);
			if (err < 0) {
				log_err("Invalid traffic_mng handle for counter id %d\n",
					cnt_cb->id);
				return -EINVAL;
			}
			init_cnt_64bit_stats(&cnt_cb->info, &stats, i);
			cnt_cb->gen_cb.objs[i] = prm.traffic_mng[i];
		}
		break;
	case DPA_STATS_CNT_TRAFFIC_CG:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_ccg_stats;
		for (i = 0; i < params->class_members; i++) {
			if (!prm.traffic_mng[i])	{
				log_err("Parameter traffic_mng handle cannot be NULL for member %d\n",
					i);
				return -EFAULT;
			}

			/* Check the provided Traffic Manager object */
			err = qman_ceetm_ccg_get_reject_statistics(
				prm.traffic_mng[i], 0, &stats[0], &stats[1]);
			if (err < 0) {
				log_err("Invalid traffic_mng handle for counter id %d\n",
					cnt_cb->id);
				return -EINVAL;
			}
			init_cnt_64bit_stats(&cnt_cb->info, &stats, i);
			cnt_cb->gen_cb.objs[i] = prm.traffic_mng[i];
		}
		break;
	default:
		log_err("Parameter src %d must be in range (%d - %d) for counter id %d\n",
			prm.src, DPA_STATS_CNT_TRAFFIC_CLASS,
			DPA_STATS_CNT_TRAFFIC_CG, cnt_cb->id);
		return -EINVAL;
	}

	return 0;
}

int set_classif_tbl_member(const struct dpa_stats_cls_member_params *prm,
			   int mbr_idx, struct dpa_stats_cnt_cb *cnt_cb)
{
	struct dpa_stats_cnt_classif_tbl_cb *tbl_cb = &cnt_cb->tbl_cb;
	struct dpa_stats_lookup_key *lookup_key = &tbl_cb->keys[mbr_idx];
	struct dpa_stats_allocated_lookup_key *key = &lookup_key->key;
	uint32_t i = 0;
	uint32_t stats_base_idx;
	int err = 0;

	/* Check that counter is of type Classifier table */
	if (cnt_cb->type != DPA_STATS_CNT_CLASSIF_TBL) {
		log_err("Operation permitted only on counter type DPA_STATS_CNT_CLASSIF_TBL %d for counter id %d\n",
			DPA_STATS_CNT_CLASSIF_TBL, cnt_cb->id);
		return -EINVAL;
	}

	/* Check that member index does not exceeds class size */
	if (mbr_idx < 0 || mbr_idx >= cnt_cb->members_num) {
		log_err("Parameter member_index %d must be in range (0 - %d) for counter id %d\n",
			mbr_idx, cnt_cb->members_num - 1, cnt_cb->id);
		return -EINVAL;
	}

	if (prm->type == DPA_STATS_CLS_MEMBER_SINGLE_KEY) {
		if (!prm->key) {
			/* Mark the key as 'miss' entry */
			tbl_cb->keys[mbr_idx].miss_key = TRUE;
			tbl_cb->keys[mbr_idx].valid = TRUE;
		} else if (!prm->key->byte) {
			/* Mark the key as invalid */
			tbl_cb->keys[mbr_idx].valid = FALSE;
			tbl_cb->keys[mbr_idx].miss_key = FALSE;
			/* Reset the statistics */
			stats_base_idx = cnt_cb->info.stats_num * mbr_idx;
			for (i = 0; i < cnt_cb->info.stats_num; i++) {
				cnt_cb->info.stats[stats_base_idx + i] = 0;
				cnt_cb->info.last_stats[stats_base_idx + i] = 0;
			}
			return 0;
		} else {
			/* Copy the key descriptor */
			err = copy_key_descriptor(prm->key, key);
			if (err != 0) {
				log_err("Cannot copy key descriptor from user parameters\n");
				return -EINVAL;
			}
			tbl_cb->keys[mbr_idx].miss_key = FALSE;
			tbl_cb->keys[mbr_idx].valid = TRUE;
		}
	} else {
		if (prm->pair)
			if (prm->pair->first_key)
				if (!prm->pair->first_key->byte) {
					/* Mark the key as invalid */
					tbl_cb->keys[mbr_idx].valid = FALSE;
					tbl_cb->keys[mbr_idx].miss_key = FALSE;

					/* Reset the statistics */
					stats_base_idx =
						cnt_cb->info.stats_num *
								mbr_idx;
					for (i = 0; i < cnt_cb->info.stats_num;
						i++) {

						cnt_cb->info.stats[
							stats_base_idx + i] = 0;
						cnt_cb->info.last_stats[
							stats_base_idx + i] = 0;

					}
					return 0;
				}
		err = set_cls_cnt_classif_tbl_pair(cnt_cb, tbl_cb->td,
						   prm->pair, mbr_idx);
		if (err != 0) {
			log_err("Cannot configure the pair key for counter id %d of member %d\n",
				cnt_cb->id, mbr_idx);
			return -EINVAL;
		}
	}

	if (cnt_cb->f_get_cnt_stats != get_cnt_cls_tbl_frag_stats) {
		if (tbl_cb->keys[mbr_idx].miss_key) {
			/* Get Classifier Table counter statistics for 'miss' */
			return get_classif_tbl_miss_stats(cnt_cb, mbr_idx);
		} else {
			/* Get Classifier Table counter statistics for a key */
			return get_classif_tbl_key_stats(cnt_cb, mbr_idx);
		}
	} else{
		err = set_frag_manip(tbl_cb->td, &tbl_cb->keys[mbr_idx]);
		if (err < 0) {
			log_err("Invalid Fragmentation manip handle for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}
	}
	return 0;
}

int set_ipsec_member(const struct dpa_stats_cls_member_params *params,
		     int mbr_idx,
		     struct dpa_stats_cnt_cb *cnt_cb)
{
	struct dpa_stats_cnt_ipsec_cb *ipsec_cb = &cnt_cb->ipsec_cb;
	struct dpa_ipsec_sa_stats stats;
	uint32_t i = 0;
	uint32_t stats_base_idx;
	int err = 0;

	/* Check that counter is of type IPSec */
	if (cnt_cb->type != DPA_STATS_CNT_IPSEC) {
		log_err("Operation permitted only on counter type DPA_STATS_CNT_IPSEC %d for counter id %d\n",
			DPA_STATS_CNT_IPSEC, cnt_cb->id);
		return -EINVAL;
	}

	/* Check that member index does not exceeds class size */
	if (mbr_idx < 0 || mbr_idx >= cnt_cb->members_num) {
		log_err("Parameter member_index %d must be in range (0 - %d) for counter id %d\n",
			mbr_idx, cnt_cb->members_num - 1, cnt_cb->id);
		return -EINVAL;
	}

	if (params->sa_id == DPA_OFFLD_INVALID_OBJECT_ID) {
		/* Mark that corresponding SA id as invalid */
		ipsec_cb->valid[mbr_idx] = FALSE;
		/* Reset the statistics */
		stats_base_idx = cnt_cb->info.stats_num * mbr_idx;
		for (i = 0; i < cnt_cb->info.stats_num; i++) {
			cnt_cb->info.stats[stats_base_idx + i] = 0;
			cnt_cb->info.last_stats[stats_base_idx + i] = 0;
		}
	} else {
		/* Mark the corresponding SA id as valid */
		ipsec_cb->valid[mbr_idx] = TRUE;
		ipsec_cb->sa_id[mbr_idx] = params->sa_id;

		err = dpa_ipsec_sa_get_stats(
				cnt_cb->ipsec_cb.sa_id[mbr_idx], &stats);
		if (err < 0) {
			log_err("Get failed for IPSec counter id %d due to incorrect parameters: sa_id=%d\n",
				cnt_cb->id, cnt_cb->ipsec_cb.sa_id[mbr_idx]);
			return -EINVAL;
		}
		init_cnt_32bit_stats(&cnt_cb->info, &stats, 0);
	}
	return 0;
}

static void init_cnt_32bit_stats(struct stats_info *stats_info,
				 void *stats, uint32_t idx)
{
	uint32_t j = 0;
	uint32_t stats_val, stats_base_idx;

	stats_base_idx = stats_info->stats_num * idx;

	for (j = 0; j < stats_info->stats_num; j++) {
		if (stats_info->stats_off[j] == UNSUPPORTED_CNT_SEL)
			continue;

		/* Get statistics value */
		stats_val = *((uint32_t *)(stats + stats_info->stats_off[j]));

		/* Store the current value as the last read value */
		stats_info->stats[stats_base_idx + j] = 0;
		stats_info->last_stats[stats_base_idx + j] = stats_val;
	}
}

static void init_cnt_64bit_stats(struct stats_info *stats_info,
				 void *stats, uint32_t idx)
{
	uint32_t j = 0;
	uint32_t stats_base_idx;
	uint64_t stats_val;

	stats_base_idx = stats_info->stats_num * idx;

	for (j = 0; j < stats_info->stats_num; j++) {
		/* Get statistics value */
		stats_val = *((uint64_t *)(stats + stats_info->stats_off[j]));

		/* Store the current value as the last read value */
		stats_info->stats[stats_base_idx + j] = 0;
		stats_info->last_stats[stats_base_idx + j] = stats_val;
	}
}

static inline void get_cnt_32bit_stats(struct dpa_stats_req_cb *req_cb,
				       struct stats_info *stats_info,
				       void *stats, uint32_t idx)
{
	uint32_t j = 0;
	uint32_t stats_val;
	uint32_t stats_base_idx, stats_index;

	stats_base_idx = stats_info->stats_num * idx;

	for (j = 0; j < stats_info->stats_num; j++) {
		if (stats_info->stats_off[j] == UNSUPPORTED_CNT_SEL) {
			/* Write the memory location */
			memset(req_cb->request_area, 0, DPA_STATS_CNT_SEL_LEN);

			/* Update the memory pointer */
			req_cb->request_area += DPA_STATS_CNT_SEL_LEN;
			continue;
		}

		/* Get statistics value */
		stats_val = *((uint32_t *)(stats + stats_info->stats_off[j]));

		stats_index = stats_base_idx + j;

		/* Check for rollover */
		if (stats_val < stats_info->last_stats[stats_index])
			stats_info->stats[stats_index] +=
				((unsigned long int)0xffffffff -
				stats_info->last_stats[stats_index]) +
								stats_val;
		else
			stats_info->stats[stats_index] += stats_val -
				stats_info->last_stats[stats_index];

		/* Store the current value as the last read value */
		stats_info->last_stats[stats_index] = stats_val;

		/* Write the memory location */
		*(uint32_t *)(req_cb->request_area) =
					stats_info->stats[stats_index];

		/* Update the memory pointer */
		req_cb->request_area += DPA_STATS_CNT_SEL_LEN;

		if (stats_info->reset)
			stats_info->stats[stats_index] = 0;
	}
}

static inline void get_cnt_64bit_stats(struct dpa_stats_req_cb *req_cb,
				       struct stats_info *stats_info,
				       void *stats, uint32_t idx)
{
	uint32_t j = 0;
	uint64_t stats_val;
	uint32_t stats_base_idx, stats_index;

	stats_base_idx = stats_info->stats_num * idx;

	for (j = 0; j < stats_info->stats_num; j++) {
		/* Get statistics value */
		stats_val = *((uint64_t *)(stats + stats_info->stats_off[j]));

		stats_index = stats_base_idx + j;

		/* Check for rollover */
		if (stats_val < stats_info->last_stats[stats_index])
			stats_info->stats[stats_index] +=
				((unsigned long int)0xffffffff -
				stats_info->last_stats[stats_index]) +
				stats_val;
		else
			stats_info->stats[stats_index] += stats_val -
				stats_info->last_stats[stats_index];

		/* Store the current value as the last read value */
		stats_info->last_stats[stats_index] = stats_val;

		/* Write the memory location */
		*(uint32_t *)(req_cb->request_area) =
				(uint32_t)stats_info->stats[stats_index];

		/* Update the memory pointer */
		req_cb->request_area += DPA_STATS_CNT_SEL_LEN;

		if (stats_info->reset)
			stats_info->stats[stats_index] = 0;
	}
}

static int get_cnt_eth_stats(struct dpa_stats_req_cb *req_cb,
			     struct dpa_stats_cnt_cb *cnt_cb)
{
	t_FmMacStatistics stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		err = FM_MAC_GetStatistics(cnt_cb->gen_cb.objs[i], &stats);
		if (err != 0) {
			log_err("Cannot retrieve Ethernet statistics for counter id %d\n",
				cnt_cb->id);
			return -ENOENT;
		}

		get_cnt_64bit_stats(req_cb, &cnt_cb->info, (void *)&stats, i);
	}

	return 0;
}

static int get_cnt_reass_stats(struct dpa_stats_req_cb *req_cb,
			       struct dpa_stats_cnt_cb *cnt_cb)
{
	struct t_FmPcdManipStats stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		err = FM_PCD_ManipGetStatistics(cnt_cb->gen_cb.objs[i], &stats);
		if (err < 0) {
			log_err("Cannot retrieve Reassembly statistics for counter id %d\n",
				cnt_cb->id);
			return -ESRCH;
		}

		get_cnt_32bit_stats(req_cb, &cnt_cb->info,
				&stats.u.reassem.u.ipReassem, i);
	}

	return 0;
}

static int get_cnt_frag_stats(struct dpa_stats_req_cb *req_cb,
			      struct dpa_stats_cnt_cb *cnt_cb)
{
	struct t_FmPcdManipStats stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		err = FM_PCD_ManipGetStatistics(cnt_cb->gen_cb.objs[i], &stats);
		if (err < 0) {
			log_err("Cannot retrieve Fragmentation statistics for counter id %d\n",
				cnt_cb->id);
			return -EINTR;
		}

		get_cnt_32bit_stats(req_cb, &cnt_cb->info,
				&stats.u.frag.u.ipFrag, i);
	}

	return 0;
}

static int get_cnt_plcr_stats(struct dpa_stats_req_cb *req_cb,
			      struct dpa_stats_cnt_cb *cnt_cb)
{
	struct stats_info *info = &cnt_cb->info;
	uint64_t stats_val = 0;
	uint32_t i = 0, j = 0;
	uint32_t stats_index, stats_base_idx;

	for (i = 0; i < cnt_cb->members_num; i++) {

		stats_base_idx = info->stats_num * i;

		for (j = 0; j < info->stats_num; j++) {
			stats_val = (uint64_t)FM_PCD_PlcrProfileGetCounter(
				cnt_cb->gen_cb.objs[i], info->stats_off[j]);

			stats_index = stats_base_idx + j;

			/* Check for rollover */
			if (stats_val < info->last_stats[stats_index])
				info->stats[stats_index] +=
					((unsigned long int)0xffffffff -
					info->last_stats[stats_index]) +
					stats_val;
			else
				info->stats[stats_index] += stats_val -
					info->last_stats[stats_index];

			/* Store the current value as the last read value */
			info->last_stats[stats_index] = stats_val;

			/* Write the memory location */
			*(uint32_t *)(req_cb->request_area) =
					(uint32_t)info->stats[stats_index];

			/* Update the memory pointer */
			req_cb->request_area += DPA_STATS_CNT_SEL_LEN;

			if (info->reset)
				info->stats[stats_index] = 0;
		}
	}

	return 0;
}

static int get_cnt_cls_tbl_match_stats(struct dpa_stats_req_cb *req_cb,
				       struct dpa_stats_cnt_cb *cnt_cb)
{
	t_FmPcdCcKeyStatistics stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		if (!cnt_cb->tbl_cb.keys[i].valid) {
			/* Write the memory location */
			memset(req_cb->request_area, 0,
				cnt_cb->info.stats_num * DPA_STATS_CNT_SEL_LEN);

			/* Update the memory pointer */
			req_cb->request_area +=
				DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;
			continue;
		}

		if (cnt_cb->tbl_cb.keys[i].miss_key) {
			err = FM_PCD_MatchTableGetMissStatistics(
					cnt_cb->tbl_cb.keys[i].cc_node, &stats);
		} else {
			uint8_t *mask_data;

			if (cnt_cb->tbl_cb.keys[i].key.valid_mask)
				mask_data =
					cnt_cb->tbl_cb.keys[i].key.data.mask;
			else
				mask_data = NULL;

			err = FM_PCD_MatchTableFindNGetKeyStatistics(
					cnt_cb->tbl_cb.keys[i].cc_node,
					cnt_cb->tbl_cb.keys[i].key.data.size,
					cnt_cb->tbl_cb.keys[i].key.data.byte,
					mask_data,
					&stats);
		}

		if (err != 0) {
			log_err("Cannot retrieve Classifier Exact Match Table statistics for counter id %d\n",
				cnt_cb->id);
			return -EIO;
		}
		get_cnt_32bit_stats(req_cb, &cnt_cb->info, &stats, i);
	}

	return 0;
}

static int get_cnt_cls_tbl_hash_stats(struct dpa_stats_req_cb *req_cb,
				      struct dpa_stats_cnt_cb *cnt_cb)
{
	t_FmPcdCcKeyStatistics stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		if (!cnt_cb->tbl_cb.keys[i].valid) {
			/* Write the memory location */
			memset(req_cb->request_area, 0,
				cnt_cb->info.stats_num * DPA_STATS_CNT_SEL_LEN);

			/* Update the memory pointer */
			req_cb->request_area +=
				DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;
			continue;
		}

		if (cnt_cb->tbl_cb.keys[i].miss_key) {
			err = FM_PCD_HashTableGetMissStatistics(
					cnt_cb->tbl_cb.keys[i].cc_node, &stats);
		} else {
			err = FM_PCD_HashTableFindNGetKeyStatistics(
					cnt_cb->tbl_cb.keys[i].cc_node,
					cnt_cb->tbl_cb.keys[i].key.data.size,
					cnt_cb->tbl_cb.keys[i].key.data.byte,
					&stats);
		}
		if (err != 0) {
			log_err("Cannot retrieve Classifier Hash Table statistics for counter id %d\n",
				cnt_cb->id);
			return -EIO;
		}
		get_cnt_32bit_stats(req_cb, &cnt_cb->info, &stats, i);
	}

	return 0;
}

static int get_cnt_cls_tbl_index_stats(struct dpa_stats_req_cb *req_cb,
				       struct dpa_stats_cnt_cb *cnt_cb)
{
	t_FmPcdCcKeyStatistics stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		if (!cnt_cb->tbl_cb.keys[i].valid) {
			/* Write the memory location */
			memset(req_cb->request_area, 0,
				cnt_cb->info.stats_num * DPA_STATS_CNT_SEL_LEN);

			/* Update the memory pointer */
			req_cb->request_area +=
				DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;
			continue;
		}

		if (cnt_cb->tbl_cb.keys[i].miss_key) {
			err = FM_PCD_MatchTableGetMissStatistics(
					cnt_cb->tbl_cb.keys[i].cc_node, &stats);
		} else {
			err = FM_PCD_MatchTableGetKeyStatistics(
					cnt_cb->tbl_cb.keys[i].cc_node,
					cnt_cb->tbl_cb.keys[i].key.data.byte[0],
					&stats);
		}

		if (err != 0) {
			log_err("Cannot retrieve Classifier Indexed Table statistics for counter id %d\n",
				cnt_cb->id);
			return -EIO;
		}
		get_cnt_32bit_stats(req_cb, &cnt_cb->info, &stats, i);
	}

	return 0;
}

static int get_cnt_cls_tbl_frag_stats(struct dpa_stats_req_cb *req_cb,
				      struct dpa_stats_cnt_cb *cnt_cb)
{
	struct t_FmPcdManipStats stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		if (!cnt_cb->tbl_cb.keys[i].valid) {
			/* Write the memory location */
			memset(req_cb->request_area, 0,
				cnt_cb->info.stats_num * DPA_STATS_CNT_SEL_LEN);

			/* Update the memory pointer */
			req_cb->request_area +=
				DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;
			continue;
		}

		err = FM_PCD_ManipGetStatistics(
				cnt_cb->tbl_cb.keys[i].frag, &stats);
		if (err < 0) {
			log_err("Cannot retrieve Fragmentation statistics for counter id %d\n",
				cnt_cb->id);
			return -EINTR;
		}
		get_cnt_32bit_stats(req_cb,
				&cnt_cb->info, &stats.u.frag.u.ipFrag, i);
	}

	return 0;
}

static int get_cnt_ccnode_match_stats(struct dpa_stats_req_cb *req_cb,
				      struct dpa_stats_cnt_cb *cnt_cb)
{
	t_FmPcdCcKeyStatistics stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		if (!cnt_cb->ccnode_cb.keys[i].valid_key) {
			err = FM_PCD_MatchTableGetMissStatistics(
					cnt_cb->ccnode_cb.cc_node, &stats);
		} else {
			uint8_t *mask_data;

			if (cnt_cb->ccnode_cb.keys[i].valid_mask)
				mask_data = cnt_cb->ccnode_cb.keys[i].data.mask;
			else
				mask_data = NULL;

			err = FM_PCD_MatchTableFindNGetKeyStatistics(
				cnt_cb->ccnode_cb.cc_node,
				cnt_cb->ccnode_cb.keys[i].data.size,
				cnt_cb->ccnode_cb.keys[i].data.byte,
				mask_data, &stats);
		}
		if (err != 0) {
			log_err("Cannot retrieve Classification Cc Node Exact Match statistics for counter id %d\n",
				cnt_cb->id);
			return -ENXIO;
		}

		get_cnt_32bit_stats(req_cb, &cnt_cb->info, (void *)&stats, i);
	}
	return 0;
}

static int get_cnt_ccnode_hash_stats(struct dpa_stats_req_cb *req_cb,
				     struct dpa_stats_cnt_cb *cnt_cb)
{
	t_FmPcdCcKeyStatistics stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		if (!cnt_cb->ccnode_cb.keys[i].valid_key) {
			err = FM_PCD_HashTableGetMissStatistics(
					cnt_cb->ccnode_cb.cc_node, &stats);
		} else {
			err = FM_PCD_HashTableFindNGetKeyStatistics(
				cnt_cb->ccnode_cb.cc_node,
				cnt_cb->ccnode_cb.keys[i].data.size,
				cnt_cb->ccnode_cb.keys[i].data.byte, &stats);
		}

		if (err != 0) {
			log_err("Cannot retrieve Classification Cc Node Hash statistics for counter id %d\n",
				cnt_cb->id);
			return -ENXIO;
		}

		get_cnt_32bit_stats(req_cb, &cnt_cb->info, (void *)&stats, i);
	}
	return 0;
}

static int get_cnt_ccnode_index_stats(struct dpa_stats_req_cb *req_cb,
				      struct dpa_stats_cnt_cb *cnt_cb)
{
	t_FmPcdCcKeyStatistics stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		if (!cnt_cb->ccnode_cb.keys[i].valid_key) {
			err = FM_PCD_MatchTableGetMissStatistics(
					cnt_cb->ccnode_cb.cc_node, &stats);
		} else {
			err = FM_PCD_MatchTableGetKeyStatistics(
				cnt_cb->ccnode_cb.cc_node,
				cnt_cb->ccnode_cb.keys[i].data.byte[0], &stats);
		}
		if (err != 0) {
			log_err("Cannot retrieve Classification Cc Node Index statistics for counter id %d\n",
				cnt_cb->id);
			return -ENXIO;
		}

		get_cnt_32bit_stats(req_cb, &cnt_cb->info, (void *)&stats, i);
	}
	return 0;
}

static int get_cnt_ipsec_stats(struct dpa_stats_req_cb *req_cb,
			       struct dpa_stats_cnt_cb *cnt_cb)
{
	struct dpa_ipsec_sa_stats stats;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		if (!cnt_cb->ipsec_cb.valid[i]) {
			/* Write the memory location */
			memset(req_cb->request_area, 0,
				cnt_cb->info.stats_num * DPA_STATS_CNT_SEL_LEN);

			/* Update the memory pointer */
			req_cb->request_area +=
				DPA_STATS_CNT_SEL_LEN * cnt_cb->info.stats_num;

			continue;
		}

		err = dpa_ipsec_sa_get_stats(cnt_cb->ipsec_cb.sa_id[i], &stats);
		if (err < 0) {
			log_err("Cannot retrieve IPSec statistics for counter id %d\n",
				cnt_cb->id);
			return -E2BIG;
		}

		get_cnt_32bit_stats(req_cb, &cnt_cb->info, &stats, i);
	}

	return 0;
}

static int get_cnt_traffic_mng_cq_stats(struct dpa_stats_req_cb *req_cb,
					struct dpa_stats_cnt_cb *cnt_cb)
{
	uint32_t i = 0;
	u64 stats_val[2];
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		/* Retrieve statistics for the current member */
		err = qman_ceetm_cq_get_dequeue_statistics(
				cnt_cb->gen_cb.objs[i], 0,
				&stats_val[1], &stats_val[0]);
		if (err < 0) {
			log_err("Cannot retrieve Traffic Manager Class Queue statistics for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}
		get_cnt_64bit_stats(req_cb, &cnt_cb->info, stats_val, i);
	}
	return 0;
}

static int get_cnt_traffic_mng_ccg_stats(struct dpa_stats_req_cb *req_cb,
					 struct dpa_stats_cnt_cb *cnt_cb)
{
	uint32_t i = 0;
	u64 stats_val[2];
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		err = qman_ceetm_ccg_get_reject_statistics(
				cnt_cb->gen_cb.objs[i], 0,
				&stats_val[1], &stats_val[0]);
		if (err < 0) {
			log_err("Cannot retrieve Traffic Manager Class Congestion Group statistics for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}
		get_cnt_64bit_stats(req_cb, &cnt_cb->info, stats_val, i);
	}
	return 0;
}

static int get_cnt_us_stats(struct dpa_stats_req_cb *req_cb,
			    struct dpa_stats_cnt_cb *cnt_cb)
{
	uint32_t i = 0, j = 0;
	req_cb->config.cnts_ids[req_cb->cnts_num] = req_cb->bytes_num;

	for (i = 0; i < cnt_cb->members_num; i++) {
		for (j = 0; j < cnt_cb->info.stats_num; j++) {
			/* Write the memory location */
			*(uint32_t *)(req_cb->request_area) = 0;
			/* Update the memory pointer */
			req_cb->request_area += DPA_STATS_CNT_SEL_LEN;
		}
	}
	return 0;
}

static void async_req_work_func(struct work_struct *work)
{
	struct dpa_stats_req_cb *req_cb = NULL;
	struct dpa_stats *dpa_stats = NULL;
	int err = 0;

	dpa_stats = gbl_dpa_stats;

	req_cb = container_of(work, struct dpa_stats_req_cb, async_req_work);
	BUG_ON(!req_cb);

	err = treat_cnts_request(dpa_stats, req_cb);
	if (err < 0) {
		log_err("Cannot obtain counter values in asynchronous mode\n");
		req_cb->bytes_num = err;
	}

	/* Notify the application */
	req_cb->request_done(0, req_cb->config.storage_area_offset,
			req_cb->cnts_num, req_cb->bytes_num);

	/* Release the request control block */
	err = put_req(dpa_stats, req_cb);
	if (err < 0)
		log_err("Cannot release internal request structure\n");

	return;
}

int dpa_stats_init(const struct dpa_stats_params *params, int *dpa_stats_id)
{
	struct dpa_stats *dpa_stats = NULL;
	int err = 0;

	/* Sanity checks */
	if (gbl_dpa_stats) {
		log_err("DPA Stats component already initialized. Multiple DPA Stats instances are not supported.\n");
		return -EPERM;
	}

	/*
	 * Multiple DPA Stats instances are not currently supported. The only
	 * supported instance instance is zero.
	 */
	*dpa_stats_id = 0;

	/* Check user-provided parameters */
	err = check_dpa_stats_params(params);
	if (err < 0)
		return err;

	/* Control block allocation */
	dpa_stats = kzalloc(sizeof(struct dpa_stats), GFP_KERNEL);
	if (!dpa_stats) {
		log_err("Cannot allocate memory for internal DPA Stats structure.\n");
		return -ENOMEM;
	}

	/* Store parameters */
	dpa_stats->config = *params;

	/* Initialize DPA Stats instance lock */
	mutex_init(&dpa_stats->lock);
	mutex_init(&dpa_stats->sched_cnt_lock);

	/* Allocate and initialize resources occupied by counters */
	err = init_cnts_resources(dpa_stats);
	if (err < 0) {
		free_resources();
		return err;
	}

	/* Allocate and initialize requests control block  */
	err = init_reqs_resources(dpa_stats);
	if (err < 0) {
		free_resources();
		return err;
	}

	/* Map each Ethernet counter selection to a FM-MAC statistics */
	create_cnt_eth_stats(dpa_stats);

	/* Map Reassembly counters to FMAN Reassembly statistics */
	create_cnt_reass_stats(dpa_stats);

	/* Map Fragmentation counters to FMAN Fragmentation statistics */
	create_cnt_frag_stats(dpa_stats);

	/* Map Policer counters to FMAN Policer statistics */
	create_cnt_plcr_stats(dpa_stats);

	/* Map Classifier counters to FMAN Classifier statistics */
	create_classif_stats(dpa_stats);

	/* Map IPSec counters  */
	create_cnt_ipsec_stats(dpa_stats);

	/* Map Traffic Manager counters to QMan CEETM statistics */
	create_cnt_traffic_mng_stats(dpa_stats);

	gbl_dpa_stats = dpa_stats;

	return 0;
}
EXPORT_SYMBOL(dpa_stats_init);

int dpa_stats_create_counter(int dpa_stats_id,
			     const struct dpa_stats_cnt_params *params,
			     int *dpa_stats_cnt_id)
{
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	int err = 0, err_rb = 0;

	/* multiple DPA Stats instances are not currently supported */
	CHECK_INSTANCE_ZERO;

	if (!gbl_dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EPERM;
	}

	if (!dpa_stats_cnt_id) {
		log_err("Parameter dpa_stats_cnt_id cannot be NULL\n");
		return -EINVAL;
	}
	*dpa_stats_cnt_id = DPA_OFFLD_INVALID_OBJECT_ID;

	if (!params) {
		log_err("Parameter params cannot be NULL\n");
		return -EFAULT;
	}

	dpa_stats = gbl_dpa_stats;

	err = get_new_cnt(dpa_stats, &cnt_cb);
	if (err < 0) {
		log_err("Cannot retrieve preallocated internal counter structure\n");
		return err;
	}

	/* Acquire the lock for the counter control block */
	mutex_lock(&cnt_cb->lock);

	switch (params->type) {
	case DPA_STATS_CNT_ETH:
		cnt_cb->type = DPA_STATS_CNT_ETH;
		cnt_cb->f_get_cnt_stats = get_cnt_eth_stats;

		err = set_cnt_eth_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Ethernet counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_REASS:
		cnt_cb->type = DPA_STATS_CNT_REASS;
		cnt_cb->f_get_cnt_stats = get_cnt_reass_stats;

		err = set_cnt_reass_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Reassembly counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_FRAG:
		cnt_cb->type = DPA_STATS_CNT_FRAG;
		cnt_cb->f_get_cnt_stats = get_cnt_frag_stats;

		err = set_cnt_frag_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Fragmentation counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_POLICER:
		cnt_cb->type = DPA_STATS_CNT_POLICER;
		cnt_cb->f_get_cnt_stats = get_cnt_plcr_stats;

		err = set_cnt_plcr_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Policer counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_CLASSIF_TBL:
		cnt_cb->type = DPA_STATS_CNT_CLASSIF_TBL;

		err = set_cnt_classif_tbl_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Classifier Table counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_CLASSIF_NODE:
		cnt_cb->type = DPA_STATS_CNT_CLASSIF_NODE;

		err = set_cnt_ccnode_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Classification Cc Node counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_IPSEC:
		cnt_cb->type = DPA_STATS_CNT_IPSEC;
		cnt_cb->f_get_cnt_stats = get_cnt_ipsec_stats;

		err = set_cnt_ipsec_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create IPSec counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_TRAFFIC_MNG:
		cnt_cb->type = DPA_STATS_CNT_TRAFFIC_MNG;

		err = set_cnt_traffic_mng_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot crate Traffic Manager counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	default:
		log_err("Unsupported counter type %d for counter id %d\n",
			params->type, cnt_cb->id);
		mutex_unlock(&cnt_cb->lock);
		return -EINVAL;
	};

	/* Counter was created. Return the counter id */
	*dpa_stats_cnt_id = cnt_cb->id;

	/* Unlock the counter control block structure */
	mutex_unlock(&cnt_cb->lock);

	return 0;

create_counter_err:
	/*
	 * An invalid Counter ID is returned if 'put_cnt' succeeds and the
	 * actual reserved Counter ID if it fails. The Counter ID can be used
	 * to try again to free resources by calling dpa_stats_remove_counter
	 */

	*dpa_stats_cnt_id = cnt_cb->id;

	err_rb = put_cnt(dpa_stats, cnt_cb);
	if (!err_rb)
		*dpa_stats_cnt_id = DPA_OFFLD_INVALID_OBJECT_ID;

	/* Unlock the counter control block structure */
	mutex_unlock(&cnt_cb->lock);

	return err;
}
EXPORT_SYMBOL(dpa_stats_create_counter);

int dpa_stats_create_class_counter(int dpa_stats_id,
				  const struct dpa_stats_cls_cnt_params *params,
				  int *dpa_stats_cnt_id)
{
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	int err = 0, err_rb = 0;

	/* multiple DPA Stats instances are not currently supported */
	CHECK_INSTANCE_ZERO;

	if (!gbl_dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EPERM;
	}

	if (!dpa_stats_cnt_id) {
		log_err("Parameter dpa_stats_cnt_id cannot be NULL\n");
		return -EINVAL;
	}
	*dpa_stats_cnt_id = DPA_OFFLD_INVALID_OBJECT_ID;

	if (!params) {
		log_err("Parameter params cannot be NULL\n");
		return -EFAULT;
	}

	if (params->class_members > DPA_STATS_MAX_NUM_OF_CLASS_MEMBERS) {
		log_err("Parameter class_members %d exceeds maximum number of class members: %d\n",
			params->class_members,
			DPA_STATS_MAX_NUM_OF_CLASS_MEMBERS);
		return -EINVAL;
	}

	dpa_stats = gbl_dpa_stats;

	err = get_new_cnt(dpa_stats, &cnt_cb);
	if (err < 0) {
		log_err("Cannot retrieve preallocated internal counter structure\n");
		return err;
	}

	/* Acquire the lock for the counter control block */
	mutex_lock(&cnt_cb->lock);

	switch (params->type) {
	case DPA_STATS_CNT_ETH:
		cnt_cb->type = DPA_STATS_CNT_ETH;
		cnt_cb->f_get_cnt_stats = get_cnt_eth_stats;

		err = set_cls_cnt_eth_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Ethernet counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_REASS:
		cnt_cb->type = DPA_STATS_CNT_REASS;
		cnt_cb->f_get_cnt_stats = get_cnt_reass_stats;

		err = set_cls_cnt_reass_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Reassembly counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_FRAG:
		cnt_cb->type = DPA_STATS_CNT_FRAG;
		cnt_cb->f_get_cnt_stats = get_cnt_frag_stats;

		err = set_cls_cnt_frag_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Fragmentation counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_POLICER:
		cnt_cb->type = DPA_STATS_CNT_POLICER;
		cnt_cb->f_get_cnt_stats = get_cnt_plcr_stats;

		err = set_cls_cnt_plcr_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Policer counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_CLASSIF_TBL:
		cnt_cb->type = DPA_STATS_CNT_CLASSIF_TBL;
		cnt_cb->f_get_cnt_stats = get_cnt_cls_tbl_match_stats;

		err = set_cls_cnt_classif_tbl_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Classifier Table counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_CLASSIF_NODE:
		cnt_cb->type = DPA_STATS_CNT_CLASSIF_NODE;

		err = set_cls_cnt_ccnode_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Classification Cc Node counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_IPSEC:
		cnt_cb->type = DPA_STATS_CNT_IPSEC;
		cnt_cb->f_get_cnt_stats = get_cnt_ipsec_stats;

		err = set_cls_cnt_ipsec_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create IPSec counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	case DPA_STATS_CNT_TRAFFIC_MNG:
		cnt_cb->type = DPA_STATS_CNT_TRAFFIC_MNG;

		err = set_cls_cnt_traffic_mng_cb(cnt_cb, params);
		if (err != 0) {
			log_err("Cannot create Traffic Manager counter id %d\n",
				cnt_cb->id);
			goto create_counter_err;
		}
		break;
	default:
		log_err("Unsupported counter type %d for counter id %d\n",
			params->type, cnt_cb->id);
		mutex_unlock(&cnt_cb->lock);
		return -EINVAL;
	};

	/* Counter was created. Return the counter id */
	*dpa_stats_cnt_id = cnt_cb->id;

	/* Unlock the counter control block */
	mutex_unlock(&cnt_cb->lock);

	return 0;

create_counter_err:
	/*
	 * An invalid Counter ID is returned if 'put_cnt' succeeds and the
	 * actual reserved Counter ID if it fails. The Counter ID can be used
	 * to try again to free resources by calling dpa_stats_remove_counter
	 */
	*dpa_stats_cnt_id = cnt_cb->id;

	err_rb = put_cnt(dpa_stats, cnt_cb);
	if (!err_rb)
		*dpa_stats_cnt_id = DPA_OFFLD_INVALID_OBJECT_ID;

	/* Unlock the counter control block */
	mutex_unlock(&cnt_cb->lock);

	return err;
}
EXPORT_SYMBOL(dpa_stats_create_class_counter);

int dpa_stats_modify_class_counter(int dpa_stats_cnt_id,
			const struct dpa_stats_cls_member_params *params,
			int member_index)
{
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	int err = 0;

	if (!gbl_dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EPERM;
	}

	dpa_stats = gbl_dpa_stats;

	if (dpa_stats_cnt_id < 0 ||
			dpa_stats_cnt_id > dpa_stats->config.max_counters) {
		log_err("Parameter dpa_stats_cnt_id %d must be in range (0 - %d)\n",
			dpa_stats_cnt_id, dpa_stats->config.max_counters - 1);
		return -EINVAL;
	}

	if (!params) {
		log_err("Parameter params cannot be NULL\n");
		return -EFAULT;
	}

	/* Counter scheduled for the retrieve mechanism can't be modified */
	if (cnt_is_sched(dpa_stats, dpa_stats_cnt_id)) {
		log_err("Counter id %d is in use\n", dpa_stats_cnt_id);
		return -EBUSY;
	}

	/* Get counter control block */
	cnt_cb = &dpa_stats->cnts_cb[dpa_stats_cnt_id];

	/* Acquire counter control block lock */
	err = mutex_trylock(&cnt_cb->lock);
	if (err == 0)
		return -EAGAIN;

	/* Validity check for this counter */
	if (cnt_cb->index == DPA_OFFLD_INVALID_OBJECT_ID) {
		log_err("Counter id %d is not initialized\n", dpa_stats_cnt_id);
		mutex_unlock(&cnt_cb->lock);
		return -EINVAL;
	}

	if (params->type == DPA_STATS_CLS_MEMBER_SINGLE_KEY ||
	    params->type == DPA_STATS_CLS_MEMBER_PAIR_KEY) {
		/* Modify classifier table class member */
		err = set_classif_tbl_member(params, member_index, cnt_cb);
		if (err < 0) {
			log_err("Cannot modify member %d of counter id %d\n",
				member_index, dpa_stats_cnt_id);
			mutex_unlock(&cnt_cb->lock);
			return -EINVAL;
		}

	} else if (params->type == DPA_STATS_CLS_MEMBER_SA_ID) {
		/* Modify IPSec class member */
		err = set_ipsec_member(params, member_index, cnt_cb);
		if (err < 0) {
			log_err("Cannot modify member %d of counter id %d\n",
				member_index, dpa_stats_cnt_id);
			mutex_unlock(&cnt_cb->lock);
			return -EINVAL;
		}
	} else {
		log_err("Parameter type %d for counter id %d must be in range (%d - %d)\n",
			params->type, dpa_stats_cnt_id,
			DPA_STATS_CLS_MEMBER_SINGLE_KEY,
			DPA_STATS_CLS_MEMBER_SA_ID);
		mutex_unlock(&cnt_cb->lock);
		return -EINVAL;
	}

	/* Unlock the counter control block */
	mutex_unlock(&cnt_cb->lock);

	return 0;
}
EXPORT_SYMBOL(dpa_stats_modify_class_counter);

int dpa_stats_remove_counter(int dpa_stats_cnt_id)
{
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	int err = 0;
	uint32_t i;

	if (!gbl_dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EPERM;
	}

	dpa_stats = gbl_dpa_stats;

	if (dpa_stats_cnt_id < 0 ||
			dpa_stats_cnt_id > dpa_stats->config.max_counters) {
		log_err("Parameter dpa_stats_cnt_id %d must be in range (0 - %d)\n",
			dpa_stats_cnt_id, dpa_stats->config.max_counters - 1);
		return -EINVAL;
	}

	/* Counter scheduled for the retrieve mechanism can't be removed */
	if (cnt_is_sched(dpa_stats, dpa_stats_cnt_id)) {
		log_err("Counter id %d is in use\n", dpa_stats_cnt_id);
		return -EBUSY;
	}

	/* Get counter control block */
	cnt_cb = &dpa_stats->cnts_cb[dpa_stats_cnt_id];

	/* Acquire counter control block lock */
	err = mutex_trylock(&cnt_cb->lock);
	if (err == 0)
		return -EAGAIN;

	/* Validity check for this counter */
	if (cnt_cb->index == DPA_OFFLD_INVALID_OBJECT_ID) {
		log_err("Counter id %d is not initialized\n", dpa_stats_cnt_id);
		mutex_unlock(&cnt_cb->lock);
		return -EINVAL;
	}

	switch (cnt_cb->type) {
	case DPA_STATS_CNT_ETH:
	case DPA_STATS_CNT_REASS:
	case DPA_STATS_CNT_FRAG:
	case DPA_STATS_CNT_POLICER:
	case DPA_STATS_CNT_TRAFFIC_MNG:
		kfree(cnt_cb->gen_cb.objs);
		break;
	case DPA_STATS_CNT_CLASSIF_NODE:
		/* Remove the allocated memory for keys bytes and masks */
		for (i = 0; i < cnt_cb->members_num; i++) {
			kfree(cnt_cb->ccnode_cb.keys[i].data.byte);
			kfree(cnt_cb->ccnode_cb.keys[i].data.mask);
		}
		kfree(cnt_cb->ccnode_cb.keys);
		break;
	case DPA_STATS_CNT_CLASSIF_TBL:
		/* Remove the allocated memory for keys bytes, masks and keys */
		for (i = 0; i < cnt_cb->members_num; i++) {
			kfree(cnt_cb->tbl_cb.keys[i].key.data.byte);
			kfree(cnt_cb->tbl_cb.keys[i].key.data.mask);
		}
		kfree(cnt_cb->tbl_cb.keys);
		break;
	case DPA_STATS_CNT_IPSEC:
		/* Remove the allocated memory for security associations */
		kfree(cnt_cb->ipsec_cb.sa_id);
		kfree(cnt_cb->ipsec_cb.valid);
		break;
	default:
		break;
	}

	/*
	 * In case of user space counters, the [stats] and [last_stats] members
	 * may not be initialized.
	 */
	if (cnt_cb->info.stats) {
		kfree(cnt_cb->info.last_stats);
		kfree(cnt_cb->info.stats);
		cnt_cb->info.stats	= NULL;
		cnt_cb->info.last_stats	= NULL;
	}
	kfree(cnt_cb->info.stats_off);

	/* Release the counter id in the Counter IDs circular queue */
	err = put_cnt(dpa_stats, cnt_cb);
	if (err < 0) {
		log_err("Cannot release preallocated internal structure\n");
		mutex_unlock(&cnt_cb->lock);
		return -EINVAL;
	}

	/* Release counter lock */
	mutex_unlock(&cnt_cb->lock);

	return 0;
}
EXPORT_SYMBOL(dpa_stats_remove_counter);

int dpa_stats_get_counters(struct dpa_stats_cnt_request_params params,
			   int *cnts_len,
			   dpa_stats_request_cb request_done)
{
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_req_cb *req_cb = NULL;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	int err = 0, cnt_id = 0, req_id = 0;
	uint32_t i = 0;

	if (!gbl_dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EPERM;
	}

	/* Check user-provided size for array of counters */
	if (params.cnts_ids_len == 0 ||
	    params.cnts_ids_len > DPA_STATS_REQ_CNTS_IDS_LEN) {
		log_err("Number of requested counter ids (%d) must be in range (1 - %d)\n",
			params.cnts_ids_len, DPA_STATS_REQ_CNTS_IDS_LEN);
		return -EINVAL;
	}

	/* Check user-provided cnts_len pointer */
	if (!cnts_len) {
		log_err("Parameter cnts_len cannot be NULL\n");
		return -EINVAL;
	}

	/* Check user-provided params.cnts_ids pointer */
	if (!params.cnts_ids) {
		log_err("Parameter cnts_ids cannot be NULL\n");
		return -EINVAL;
	}

	dpa_stats = gbl_dpa_stats;

	*cnts_len = 0;

	for (i = 0; i < params.cnts_ids_len; i++) {
		if (params.cnts_ids[i] == DPA_OFFLD_INVALID_OBJECT_ID ||
		    params.cnts_ids[i] >= dpa_stats->config.max_counters) {
			log_err("Counter id (cnt_ids[%d]) %d is not initialized or is greater than maximum counter id %d\n",
				i, params.cnts_ids[i],
				dpa_stats->config.max_counters - 1);
			return -EINVAL;
		}
	}

	block_sched_cnts(dpa_stats, params.cnts_ids, params.cnts_ids_len);

	/* Calculate number of bytes occupied by the counters */
	for (i = 0; i < params.cnts_ids_len; i++) {
		cnt_id = params.cnts_ids[i];

		/* Get counter's control block */
		cnt_cb = &dpa_stats->cnts_cb[cnt_id];

		/* Acquire counter lock */
		mutex_lock(&cnt_cb->lock);

		/* Check if counter control block is initialized */
		if (cnt_cb->index == DPA_OFFLD_INVALID_OBJECT_ID) {
			log_err("Counter id (cnt_ids[%d]) %d is not initialized\n",
				i, cnt_id);
			mutex_unlock(&cnt_cb->lock);
			unblock_sched_cnts(dpa_stats, params.cnts_ids,
					   params.cnts_ids_len);
			return -EINVAL;
		}

		*cnts_len += cnt_cb->bytes_num;
		mutex_unlock(&cnt_cb->lock);
	}

	/* Check user-provided parameters */
	if ((params.storage_area_offset + *cnts_len) >
		dpa_stats->config.storage_area_len) {
		log_err("Parameter storage_area_offset %d and counters length %d exceeds configured storage_area_len %d\n",
			params.storage_area_offset, *cnts_len,
			dpa_stats->config.storage_area_len);
		unblock_sched_cnts(dpa_stats, params.cnts_ids,
				   params.cnts_ids_len);
		return -EINVAL;
	}

	/* Create a new request */
	err = get_new_req(dpa_stats, &req_id, &req_cb);
	if (err < 0) {
		log_err("Cannot retrieve preallocated internal request structure\n");
		/* Release counters locks */
		unblock_sched_cnts(dpa_stats, params.cnts_ids,
				   params.cnts_ids_len);
		return err;
	}

	req_cb->config.cnts_ids = params.cnts_ids;
	req_cb->config.reset_cnts = params.reset_cnts;
	req_cb->config.storage_area_offset = params.storage_area_offset;
	req_cb->config.cnts_ids_len = params.cnts_ids_len;
	req_cb->request_done = request_done;

	/* Copy user-provided array of counter ids */
	memcpy(req_cb->cnts_ids,
	       params.cnts_ids, params.cnts_ids_len * sizeof(int));

	/* Set memory area where the request should write */
	req_cb->request_area = dpa_stats->config.storage_area +
					params.storage_area_offset;

	if (!req_cb->request_done) {
		/* Call is synchronous */
		err = treat_cnts_request(dpa_stats, req_cb);
		if (err < 0)
			log_err("Cannot retrieve counter values\n");

		err = put_req(dpa_stats, req_cb);

		return err;
	} else {
		/* Call is asynchronous */
		queue_work(dpa_stats->async_req_workqueue,
			   &req_cb->async_req_work);
	}

	return 0;
}
EXPORT_SYMBOL(dpa_stats_get_counters);

int dpa_stats_reset_counters(int *cnts_ids, unsigned int cnts_ids_len)
{
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	uint32_t i = 0;
	int err = 0;

	if (!gbl_dpa_stats) {
		log_err("DPA Stats component is not initialized\n");
		return -EPERM;
	}

	/* Check user-provided cnts_len pointer */
	if (cnts_ids_len == 0 || cnts_ids_len > DPA_STATS_REQ_CNTS_IDS_LEN) {
		log_err("Parameter cnts_ids_len %d must be in range (1 - %d)\n",
			cnts_ids_len, DPA_STATS_REQ_CNTS_IDS_LEN);
		return -EINVAL;
	}

	/* Check user-provided cnts_ids pointer */
	if (!cnts_ids) {
		log_err("Parameter cnts_ids cannot be NULL\n");
		return -EINVAL;
	}

	dpa_stats = gbl_dpa_stats;

	for (i = 0; i < cnts_ids_len; i++)
		if (cnts_ids[i] == DPA_OFFLD_INVALID_OBJECT_ID ||
		    cnts_ids[i] >= dpa_stats->config.max_counters) {
			log_err("Counter id (cnt_ids[%d]) %d is not initialized or is greater than maximum counter id %d\n",
				i, cnts_ids[i],
				dpa_stats->config.max_counters - 1);
			return -EINVAL;
		}

	block_sched_cnts(dpa_stats, cnts_ids, cnts_ids_len);

	/* Calculate number of bytes occupied by the counters */
	for (i = 0; i < cnts_ids_len; i++) {
		/* Get counter's control block */
		cnt_cb = &dpa_stats->cnts_cb[cnts_ids[i]];

		/* Acquire counter lock */
		err = mutex_trylock(&cnt_cb->lock);
		if (err == 0) {
			log_err("Counter id (cnt_ids[%d]) %d is in use\n", i,
				cnts_ids[i]);
			unblock_sched_cnts(dpa_stats,
					   cnts_ids, cnts_ids_len);
			return -EBUSY;
		}

		/* Check if counter control block is initialized */
		if (cnt_cb->index == DPA_OFFLD_INVALID_OBJECT_ID) {
			log_err("Counter id (cnt_ids[%d]) %d is not initialized\n",
				i, cnts_ids[i]);
			mutex_unlock(&cnt_cb->lock);
			unblock_sched_cnts(dpa_stats,
					   cnts_ids, cnts_ids_len);
			return -EINVAL;
		}

		/* User space counters make no sense in being reset. */
		if (cnt_cb->info.stats) {
			/* Reset stored statistics values */
			memset(cnt_cb->info.stats, 0,
				(cnt_cb->members_num * cnt_cb->info.stats_num) *
				sizeof(uint64_t));
		}

		mutex_unlock(&cnt_cb->lock);
	}

	unblock_sched_cnts(dpa_stats, cnts_ids, cnts_ids_len);

	return 0;
}
EXPORT_SYMBOL(dpa_stats_reset_counters);

int dpa_stats_free(int dpa_stats_id)
{
	/* multiple DPA Stats instances are not currently supported */
	CHECK_INSTANCE_ZERO;

	return free_resources();
}
EXPORT_SYMBOL(dpa_stats_free);
