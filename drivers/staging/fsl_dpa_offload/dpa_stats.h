
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
 * Internal DPA Statistics Application Programming Interface
 */

#ifndef __DPA_STATS_H
#define __DPA_STATS_H

/* DPA offloading layer includes */
#include "linux/fsl_dpa_stats.h"
#include "linux/fsl_dpa_ipsec.h"
#include "cq.h"

#define MAX_NUM_OF_STATS 23
#define NUM_OF_CNT_TYPES (DPA_STATS_CNT_TRAFFIC_MNG + 1)
#define MAX_NUM_OF_MEMBERS DPA_STATS_MAX_NUM_OF_CLASS_MEMBERS


/* DPA Stats - Control Block */
struct dpa_stats {
	struct dpa_stats_params config;	/* Configuration parameters */
	struct cq *cnt_id_cq;	/* Circular Queue with ids for stats counters */
	int *used_cnt_ids;	/* Counter ids used by this dpa_stats instance*/
	struct dpa_stats_cnt_cb *cnts_cb; /* Array of counters control blocks */

	int *used_req_ids;	/* Request ids used by this dpa_stats instance*/
	struct dpa_stats_req_cb *reqs_cb; /* Array of counter requests */
	struct cq *req_id_cq; /* Circular Queue with ids for counters request */
	 /*
	  * Array that stores the mapping
	  * between counter selection and statistics values
	  */
	int stats_sel[NUM_OF_CNT_TYPES][MAX_NUM_OF_STATS];
	 /*
	  * Multi threaded work queue used to defer the work to be
	  * done when an asynchronous counters request is received
	  */
	struct workqueue_struct *async_req_workqueue;
	struct mutex lock; /* Lock for this dpa_stats instance */
	bool *sched_cnt_ids; /* Counters scheduled for a retrieve operation */
	struct mutex sched_cnt_lock; /* Lock for array of scheduled counters */
};

/* DPA Stats  request control block */
struct dpa_stats_req_cb {
	struct work_struct async_req_work; /* Asynchronous request work */
	struct dpa_stats_cnt_request_params config;
				/* Parameters provided to the request */
	int *cnts_ids; /* Copy of user-provided array of counter IDs */
	uint32_t id; /* Request id */
	int index; /* Request index in the 'used_req_ids'*/
	void *request_area;
		  /* Address in the storage area associated with this request */
	uint32_t bytes_num; /* Number of bytes written by this request */
	uint32_t cnts_num; /* Number of counters written by this request */
	dpa_stats_request_cb request_done; /* Callback to notify upper layer */
};

/* DPA Stats - statistics information */
struct stats_info {
	 /*
	  * Array of statistics offsets relative to
	  * corresponding statistics area
	  */
	int *stats_off;
	unsigned int stats_num; /* Number of statistics to retrieve */
	uint64_t *stats; /* Array to store statistics values */
	uint64_t *last_stats; /* Array to store previous statistics values */
	bool reset; /* Reset counter's statistics */
};

/* DPA Stats General Counter control block */
struct dpa_stats_cnt_gen_cb {
	/* Array of objects for which to retrieve statistics */
	void **objs;
};

/*
 * DPA Stats allocated lookup key descriptor. This is used in the context of
 * lookup keys being preallocated for the classification type counters. In this
 * case, the pointers to key data or key mask will always exist, hence there
 * is no more way to tell whether the key data or mask are valid except by using
 * a set of individual indicators like "valid_mask" and "valid_key".
 */
struct dpa_stats_allocated_lookup_key {
	/* The key data (preallocated key & mask). */
	struct dpa_offload_lookup_key data;

	/* Indicates whether the mask is present or not. */
	bool valid_mask;

	/* Indicates whether the key data is present or not. */
	bool valid_key;
};

/* DPA Stats Classifier Table key descriptor */
struct dpa_stats_lookup_key {
	void *cc_node;  /* Handle of Cc Node the lookup key belongs to */
	struct dpa_stats_allocated_lookup_key key; /* Key descriptor */
	bool valid; /* Lookup key is valid */
	void *frag; /* Fragmentation handle corresponding to this key */
	bool miss_key; /* Provide statistics for miss entry */
};

/* DPA Stats Classif Table control block */
struct dpa_stats_cnt_classif_tbl_cb {
	int td; /* Table descriptor */
	enum dpa_cls_tbl_type type; /* The type of the DPA Classifier table */
	struct dpa_stats_lookup_key *keys; /* Array of
			 key descriptors for which to provide statistics */
};

/* DPA Stats Classif Node control block */
struct dpa_stats_cnt_classif_cb {
	void *cc_node;  /* Handle of Cc Node the lookup keys belong to */
	struct dpa_stats_allocated_lookup_key *keys;
		 /* Array of key descriptors for which to provide statistics */
};

/* DPA Stats IPSec Counter control block */
struct dpa_stats_cnt_ipsec_cb {
	int *sa_id; /* Array of Security Association ids */
	bool *valid; /* Security Association id is valid */
};

typedef int get_cnt_stats(struct dpa_stats_req_cb *req_cb,
			  struct dpa_stats_cnt_cb *cnt_cb);

/* DPA Stats counter control block */
struct dpa_stats_cnt_cb {
	struct dpa_stats *dpa_stats; /* Pointer to DPA Stats */
	uint32_t id;  /* Counter identifier */
	int index; /* Counter index in the 'used_cnt_ids'*/
	uint32_t bytes_num; /* Number of bytes occupied by this counter */
	struct mutex lock; /* Lock for this counter control block */
	bool used; /* Counter has been scheduled for retrieve */
	enum dpa_stats_cnt_type type; /* Counter type */
	struct stats_info info; /* Counter's statistics information */
	unsigned int members_num; /* Number of objects to retrieve statistics */
	union {
		struct dpa_stats_cnt_gen_cb gen_cb;
		struct dpa_stats_cnt_classif_tbl_cb tbl_cb;
		struct dpa_stats_cnt_classif_cb ccnode_cb;
		struct dpa_stats_cnt_ipsec_cb ipsec_cb;
	};
	/* Function used to retrieve the statistics for a specific counter */
	get_cnt_stats *f_get_cnt_stats;
};

static inline void block_sched_cnts(struct dpa_stats *dpa_stats,
				    int *cnts_ids, int cnts_ids_len)
{
	int i;

	mutex_lock(&dpa_stats->sched_cnt_lock);
	for (i = 0; i < cnts_ids_len; i++)
		dpa_stats->sched_cnt_ids[cnts_ids[i]] = TRUE;
	mutex_unlock(&dpa_stats->sched_cnt_lock);
}

static inline void unblock_sched_cnts(struct dpa_stats *dpa_stats,
				      int *cnts_ids, int cnts_ids_len)
{
	int i;

	mutex_lock(&dpa_stats->sched_cnt_lock);
	for (i = 0; i < cnts_ids_len; i++)
		dpa_stats->sched_cnt_ids[cnts_ids[i]] = FALSE;
	mutex_unlock(&dpa_stats->sched_cnt_lock);
}

static inline int cnt_is_sched(struct dpa_stats *dpa_stats, int cnt_id)
{
	int ret = 0;

	mutex_lock(&dpa_stats->sched_cnt_lock);
	ret = dpa_stats->sched_cnt_ids[cnt_id];
	mutex_unlock(&dpa_stats->sched_cnt_lock);

	return ret;
}

#endif /* __DPA_STATS_H */
