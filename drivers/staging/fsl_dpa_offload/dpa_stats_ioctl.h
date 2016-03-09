
/* Copyright 2013 Freescale Semiconductor, Inc.
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
 * DPA Stats Wrapper Application Programming Interface
 */

#ifndef __DPA_STATS_IOCTL_H
#define __DPA_STATS_IOCTL_H

/* Other includes */
#include "linux/ioctl.h"
#include <linux/compat.h>

struct ioc_dpa_stats_params {
	unsigned int max_counters;
	void *virt_stg_area;
	uint64_t phys_stg_area;
	bool stg_area_mapped;
	unsigned int storage_area_len;
	int dpa_stats_id;
};

struct ioc_dpa_stats_cnt_params {
	int stats_id;
	struct dpa_stats_cnt_params cnt_params;
	int cnt_id;
};

struct ioc_dpa_stats_cls_cnt_params {
	int stats_id;
	struct dpa_stats_cls_cnt_params cnt_params;
	int cnt_id;
};

struct ioc_dpa_stats_cls_member_params {
	int cnt_id;
	struct dpa_stats_cls_member_params params;
	int member_index;
};

struct ioc_dpa_stats_cnt_request_params {
	struct dpa_stats_cnt_request_params req_params;
	int cnts_len;
	bool async_req;
};

struct ioc_dpa_stats_cnts_reset_params {
	int *cnts_ids;
	unsigned int cnts_ids_len;
};

#ifdef CONFIG_COMPAT
struct dpa_stats_compat_params {
	unsigned int max_counters;
	compat_uptr_t virt_stg_area;
	uint64_t phys_stg_area;
	bool stg_area_mapped;
	unsigned int storage_area_len;
};

struct compat_ioc_dpa_stats_params {
	struct dpa_stats_compat_params stats_params;
	int dpa_stats_id;
};

struct dpa_stats_compat_cnt_reass {
	compat_uptr_t reass;
	unsigned int cnt_sel;
};

struct dpa_stats_compat_cnt_frag {
	compat_uptr_t frag;
	unsigned int cnt_sel;
};

struct dpa_stats_compat_cnt_plcr {
	compat_uptr_t plcr;
	unsigned int cnt_sel;
};

struct compat_ioc_dpa_offld_lookup_key {
	compat_uptr_t byte;
	compat_uptr_t mask;
	uint8_t size;
};

struct dpa_stats_compat_cnt_classif_tbl {
	int td;
	compat_uptr_t key;
	unsigned int cnt_sel;
};

struct dpa_stats_compat_cnt_classif_node {
	compat_uptr_t cc_node;
	enum dpa_stats_classif_node_type ccnode_type;
	compat_uptr_t key;
	unsigned int cnt_sel;
};

struct dpa_stats_compat_cnt_traffic_mng {
	enum dpa_stats_cnt_traffic_mng_src src;
	compat_uptr_t traffic_mng;
	enum dpa_stats_cnt_sel cnt_sel;
};

struct dpa_stats_compat_cnt_params {
	enum dpa_stats_cnt_type type;
	union {
		struct dpa_stats_cnt_eth eth_params;
		struct dpa_stats_compat_cnt_reass reass_params;
		struct dpa_stats_compat_cnt_frag frag_params;
		struct dpa_stats_compat_cnt_plcr plcr_params;
		struct dpa_stats_compat_cnt_classif_tbl classif_tbl_params;
		struct dpa_stats_compat_cnt_classif_node classif_node_params;
		struct dpa_stats_cnt_ipsec ipsec_params;
		struct dpa_stats_compat_cnt_traffic_mng traffic_mng_params;
	};
};

struct compat_ioc_dpa_stats_cnt_params {
	int stats_id;
	struct dpa_stats_compat_cnt_params cnt_params;
	int cnt_id;
};

struct dpa_stats_compat_cls_cnt_eth {
	compat_uptr_t src;
	enum dpa_stats_cnt_eth_sel cnt_sel;
};

struct dpa_stats_compat_cls_cnt_classif_tbl {
	int td;
	enum dpa_stats_classif_key_type   key_type;
	union {
		compat_uptr_t keys;
		compat_uptr_t pairs;
	};
	unsigned int cnt_sel;
};

struct dpa_stats_compat_cls_cnt_classif_node {
	compat_uptr_t cc_node;
	enum dpa_stats_classif_node_type ccnode_type;
	compat_uptr_t keys;
	unsigned int cnt_sel;
};

struct dpa_stats_compat_cls_cnt_ipsec {
	compat_uptr_t sa_id;
	enum dpa_stats_cnt_sel cnt_sel;
};

struct dpa_stats_compat_cls_cnt_params {
	unsigned int class_members;
	enum dpa_stats_cnt_type type;
	union {
		struct dpa_stats_compat_cls_cnt_eth eth_params;
		struct dpa_stats_compat_cnt_reass reass_params;
		struct dpa_stats_compat_cnt_frag frag_params;
		struct dpa_stats_compat_cnt_plcr plcr_params;
		struct dpa_stats_compat_cls_cnt_classif_tbl classif_tbl_params;
		struct dpa_stats_compat_cls_cnt_classif_node ccnode_params;
		struct dpa_stats_compat_cls_cnt_ipsec ipsec_params;
		struct dpa_stats_compat_cnt_traffic_mng traffic_mng_params;
	};
};

struct compat_ioc_dpa_stats_cls_cnt_params {
	int stats_id;
	struct dpa_stats_compat_cls_cnt_params cnt_params;
	int cnt_id;
};

struct compat_ioc_dpa_offld_lookup_key_pair {
	compat_uptr_t first_key;
	compat_uptr_t second_key;
};

struct dpa_stats_compat_cls_member_params {
	enum dpa_stats_cls_member_type type;
	union {
		compat_uptr_t key;
		compat_uptr_t pair;
		int sa_id;
	};
};

struct compat_ioc_dpa_stats_cls_member_params {
	int cnt_id;
	struct dpa_stats_compat_cls_member_params params;
	int member_index;
};

struct dpa_stats_compat_cnt_request_params {
	compat_uptr_t cnts_ids;
	unsigned int cnts_ids_len;
	bool reset_cnts;
	unsigned int storage_area_offset;
};

struct compat_ioc_dpa_stats_cnt_request_params {
	struct dpa_stats_compat_cnt_request_params req_params;
	int cnts_len;
	bool async_req;
};

struct compat_ioc_dpa_stats_cnts_reset_params {
	compat_uptr_t cnts_ids;
	unsigned int cnts_ids_len;
};
#endif
#define DPA_STATS_IOC_MAGIC				0xde

#define DPA_STATS_IOC_INIT						\
	_IOWR(DPA_STATS_IOC_MAGIC, 0, struct ioc_dpa_stats_params)

#ifdef CONFIG_COMPAT
#define DPA_STATS_IOC_COMPAT_INIT					\
	_IOWR(DPA_STATS_IOC_MAGIC, 0, struct compat_ioc_dpa_stats_params)
#endif /* CONFIG_COMPAT */

#define DPA_STATS_IOC_FREE						\
	_IOW(DPA_STATS_IOC_MAGIC, 1, int)

#define DPA_STATS_IOC_CREATE_COUNTER					\
	_IOWR(DPA_STATS_IOC_MAGIC, 2, struct ioc_dpa_stats_cnt_params)

#ifdef CONFIG_COMPAT
#define DPA_STATS_IOC_COMPAT_CREATE_COUNTER				\
	_IOWR(DPA_STATS_IOC_MAGIC, 2, struct compat_ioc_dpa_stats_cnt_params)
#endif /* CONFIG_COMPAT */

#define DPA_STATS_IOC_CREATE_CLASS_COUNTER				\
	_IOWR(DPA_STATS_IOC_MAGIC, 3, struct ioc_dpa_stats_cls_cnt_params)

#ifdef CONFIG_COMPAT
#define DPA_STATS_IOC_COMPAT_CREATE_CLASS_COUNTER			\
	_IOWR(DPA_STATS_IOC_MAGIC, 3,					\
				struct compat_ioc_dpa_stats_cls_cnt_params)
#endif /* CONFIG_COMPAT */

#define DPA_STATS_IOC_MODIFY_CLASS_COUNTER				\
	_IOWR(DPA_STATS_IOC_MAGIC, 4, struct ioc_dpa_stats_cls_member_params)

#ifdef CONFIG_COMPAT
#define DPA_STATS_IOC_COMPAT_MODIFY_CLASS_COUNTER			\
	_IOWR(DPA_STATS_IOC_MAGIC, 4,					\
				struct compat_ioc_dpa_stats_cls_member_params)
#endif /* CONFIG_COMPAT */

#define DPA_STATS_IOC_REMOVE_COUNTER					\
	_IOW(DPA_STATS_IOC_MAGIC, 5, int)

#define DPA_STATS_IOC_GET_COUNTERS					\
	_IOWR(DPA_STATS_IOC_MAGIC, 6, struct ioc_dpa_stats_cnt_request_params)

#ifdef CONFIG_COMPAT
#define DPA_STATS_IOC_COMPAT_GET_COUNTERS				\
	_IOWR(DPA_STATS_IOC_MAGIC, 6,					\
				struct compat_ioc_dpa_stats_cnt_request_params)
#endif

#define DPA_STATS_IOC_RESET_COUNTERS					\
	_IOWR(DPA_STATS_IOC_MAGIC, 7, struct ioc_dpa_stats_cnts_reset_params)

#ifdef CONFIG_COMPAT
#define DPA_STATS_IOC_COMPAT_RESET_COUNTERS				\
	_IOWR(DPA_STATS_IOC_MAGIC, 7,					\
				struct compat_ioc_dpa_stats_cnts_reset_params)
#endif

#endif /* __DPA_STATS_IOCTL_H */
