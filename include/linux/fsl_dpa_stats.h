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
 * SOFTWARE, EVEN IF ADVISED OF THE  POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * DPA Statistics Application Programming Interface.
 */

#ifndef __FSL_DPA_STATS_H
#define __FSL_DPA_STATS_H

/* DPA offloading layer includes */
#include "fsl_dpa_offload.h"

/* Other includes */
#include <linux/types.h>

/* Maximum number simultaneous counters requests */
#define DPA_STATS_MAX_NUM_OF_REQUESTS      256

/* Maximum number of single and class counters */
#define DPA_STATS_MAX_NUM_OF_COUNTERS      512

/* Maximum number of class counter members */
#define DPA_STATS_MAX_NUM_OF_CLASS_MEMBERS 256

/* Number of bytes occupied by one counter selection */
#define DPA_STATS_CNT_SEL_LEN		   4

/* Maximum size occupied by storage area: 10 MB */
#define DPA_STATS_MAX_STORAGE_AREA_SIZE	(10 * (1 << 20))

/* Maximum number of counters that can be processed in a request. Each counter
 * can be repeated a maximum of two times in a request */
#define DPA_STATS_REQ_CNTS_IDS_LEN	(2 * DPA_STATS_MAX_NUM_OF_COUNTERS)

/* DPA Stats instance parameters */
struct dpa_stats_params {

	/* Maximum number of counters managed by DPA Stats instance */
	unsigned int max_counters;

	/* Pointer to the memory area where the values of the counters
	 * will be written by the DPA Stats instance */
	void *storage_area;

	/* Length in bytes of the storage memory area (must be between
	 * DPA_STATS_CNT_SEL_LEN and DPA_STATS_MAX_STORAGE_AREA_SIZE) */
	unsigned int storage_area_len;
};

/*
 * Callback used to notify the upper layer that the requested counters values
 * were written in the storage area. The 'storage_area_offset' is the offset
 * in the storage_area and the 'cnts_written' represents the number of counters
 * successfully written. The 'bytes_written' parameter can have a positive value
 * and in this case it's value the size of the memory area written or it can
 * have a negative value and contain the code of the error that occurred.
 */
typedef void (*dpa_stats_request_cb)(int dpa_stats_id,
				     unsigned int storage_area_offset,
				     unsigned int cnts_written,
				     int bytes_written);

/* DPA Stats Request parameters */
struct dpa_stats_cnt_request_params {
	/* Array of counter IDs to retrieve values for */
	int *cnts_ids;

	/* Size of array of counters to retrieve values for (must be between
	 * 1 and DPA_STATS_REQ_CNTS_IDS_LEN) */
	unsigned int cnts_ids_len;

	/* Reset counters after the retrieve operation */
	bool reset_cnts;

	/* Storage area offset, expressed in bytes */
	unsigned int storage_area_offset;
};

/* DPA Stats counter types */
enum dpa_stats_cnt_type {
	DPA_STATS_CNT_ETH = 0,		/* Ethernet counter		*/
	DPA_STATS_CNT_REASS,		/* IP Reassembly counter	*/
	DPA_STATS_CNT_FRAG,		/* IP Fragmentation counter	*/
	DPA_STATS_CNT_POLICER,		/* Policer counter		*/
	DPA_STATS_CNT_CLASSIF_TBL,	/* Classification Table counter	*/
	DPA_STATS_CNT_CLASSIF_NODE,	/* Classification Node counter	*/
	DPA_STATS_CNT_IPSEC,		/* IPSec counter		*/
	DPA_STATS_CNT_TRAFFIC_MNG,	/* Traffic Manager counter	*/
#ifdef DPA_STATS_UNDER_CONSTRUCTION
	DPA_STATS_CNT_RAPIDIO		/* RapidIO counter		*/
#endif
};

/* DPA Stats counter selection */
enum dpa_stats_cnt_sel {
	/* Total number of bytes */
	DPA_STATS_CNT_NUM_OF_BYTES = 0,
	/* Total number of packets */
	DPA_STATS_CNT_NUM_OF_PACKETS,
	/* Total number of bytes and total number of packets */
	DPA_STATS_CNT_NUM_ALL
};

/* DPA Stats Ethernet counter selection */
enum dpa_stats_cnt_eth_sel {
	/* Total number of dropped packets on receive */
	DPA_STATS_CNT_ETH_DROP_PKTS		= 0x00000001,
	/* Total number of received bytes of data */
	DPA_STATS_CNT_ETH_BYTES			= 0x00000002,
	/* Total number of received packets */
	DPA_STATS_CNT_ETH_PKTS			= 0x00000004,
	/* Total number of received broadcast packets */
	DPA_STATS_CNT_ETH_BC_PKTS		= 0x00000008,
	/* Total number of received multicast packets */
	DPA_STATS_CNT_ETH_MC_PKTS		= 0x00000010,
	/* Total number of received frames with alignment error or invalid FCS*/
	DPA_STATS_CNT_ETH_CRC_ALIGN_ERR		= 0x00000020,
	/*
	 * Total number of received packets that were
	 * less than 64 bytes and were well formed
	 */
	DPA_STATS_CNT_ETH_UNDERSIZE_PKTS	= 0x00000040,
	/*
	 * Total number of received packets that were above 1518 bytes
	 * (non-VLAN) or 1522 (VLAN) or above a configured maximum frame
	 * length and were well formed
	 */
	DPA_STATS_CNT_ETH_OVERSIZE_PKTS		= 0x00000080,
	/*
	 * Total number of received packets that were less than
	 * 64 bytes and had a bad FCS
	 */
	DPA_STATS_CNT_ETH_FRAGMENTS		= 0x00000100,
	/*
	 * Total number of received packets with size above 1518 bytes
	 * (non-VLAN) or 1522 (VLAN) or a configured maximum frame length
	 * and with an invalid FCS or an alignment error
	 */
	DPA_STATS_CNT_ETH_JABBERS		= 0x00000200,
	/* Total number of received packets with size below 64 bytes*/
	DPA_STATS_CNT_ETH_64BYTE_PKTS		= 0x00000400,
	/* Total number of received packets with size between 65 and 127bytes */
	DPA_STATS_CNT_ETH_65_127BYTE_PKTS	= 0x00000800,
	/* Total number of received packets with size between 128-255bytes */
	DPA_STATS_CNT_ETH_128_255BYTE_PKTS	= 0x00001000,
	/* Total number of received packets with size between 256-511bytes */
	DPA_STATS_CNT_ETH_256_511BYTE_PKTS	= 0x00002000,
	/* Total number of received packets with size between 512-1023bytes */
	DPA_STATS_CNT_ETH_512_1023BYTE_PKTS	= 0x00004000,
	/* Total number of received packets with size between 1024-1518bytes */
	DPA_STATS_CNT_ETH_1024_1518BYTE_PKTS	= 0x00008000,
	/* Total number of packets on transmit */
	DPA_STATS_CNT_ETH_OUT_PKTS		= 0x00010000,
	/* Total number of dropped packets on transmit */
	DPA_STATS_CNT_ETH_OUT_DROP_PKTS		= 0x00020000,
	/* Total number of transmitted bytes of data */
	DPA_STATS_CNT_ETH_OUT_BYTES		= 0x00040000,
	/* Total number of received frames with errors */
	DPA_STATS_CNT_ETH_IN_ERRORS		= 0x00080000,
	/* Total number of transmitted frames with errors */
	DPA_STATS_CNT_ETH_OUT_ERRORS		= 0x00100000,
	/* Total number of unicast packets on receive */
	DPA_STATS_CNT_ETH_IN_UNICAST_PKTS	= 0x00200000,
	/* Total number of unicast packets on transmit */
	DPA_STATS_CNT_ETH_OUT_UNICAST_PKTS	= 0x00400000,
	/* Select all counters */
	DPA_STATS_CNT_ETH_ALL			= 0x00800000
};

/* DPA Stats Ethernet id */
enum dpa_stats_cnt_eth_id {
	DPA_STATS_ETH_1G_PORT0 = 0,	/* 1G port, ETH id 0 */
	DPA_STATS_ETH_1G_PORT1,		/* 1G port, ETH id 1 */
	DPA_STATS_ETH_1G_PORT2,		/* 1G port, ETH id 2 */
	DPA_STATS_ETH_1G_PORT3,		/* 1G port, ETH id 3 */
	DPA_STATS_ETH_1G_PORT4,		/* 1G port, ETH id 4 */
	DPA_STATS_ETH_1G_PORT5,		/* 1G port, ETH id 5 */
	DPA_STATS_ETH_10G_PORT0,	/* 10G port, ETH id 0 */
	DPA_STATS_ETH_10G_PORT1		/* 10G port, ETH id 1 */
};

/* DPA Stats Ethernet counter source definition */
struct dpa_stats_cnt_eth_src {
	/* Index of the engine device the Ethernet interface belongs to */
	uint8_t engine_id;

	/* Index of the Ethernet interface, relative to the engine */
	enum dpa_stats_cnt_eth_id eth_id;
};

/* DPA Stats Ethernet counter parameters */
struct dpa_stats_cnt_eth {
	/* Ethernet counter source */
	struct dpa_stats_cnt_eth_src src;

	/*
	 * Single or multiple selections of Ethernet counters
	 * from enumeration dpa_stats_cnt_eth_sel
	 */
	uint32_t cnt_sel;
};

/*
 * DPA Stats IP Reassembly selection of counters that provide
 * common information for both IPv4 and IPv6 protocols
 */
enum dpa_stats_cnt_reass_gen_sel {
	/* Number of timeout occurrences */
	DPA_STATS_CNT_REASS_TIMEOUT			= 0x00000001,
	/* Number of failed attempts to allocate a Reassembly Frame Descriptor*/
	DPA_STATS_CNT_REASS_RFD_POOL_BUSY		= 0x00000002,
	/* Number of internal buffer busy occurrences */
	DPA_STATS_CNT_REASS_INT_BUFF_BUSY		= 0x00000004,
	/* Number of external buffer busy occurrences */
	DPA_STATS_CNT_REASS_EXT_BUFF_BUSY		= 0x00000008,
	/* Number of Scatter/Gather fragments */
	DPA_STATS_CNT_REASS_SG_FRAGS			= 0x00000010,
	/* Number of failed attempts to allocate a DMA semaphore */
	DPA_STATS_CNT_REASS_DMA_SEM			= 0x00000020,
	/*
	 * Number of Non Consistent Storage Profile occurrences for successfully
	 * reassembled frames
	 */
	DPA_STATS_CNT_REASS_NON_CONSISTENT_SP		= 0x00000040,
	/* Select all counters from dpa_stats_cnt_reass_gen_sel */
	DPA_STATS_CNT_REASS_GEN_ALL			= 0x00000080
};

/*
 * DPA Stats IP Reassembly selection of counters that provide
 * information only for IPv4 protocol
 */
enum dpa_stats_cnt_reass_ipv4_sel {
	/* Number of successfully reassembled IPv4 frames */
	DPA_STATS_CNT_REASS_IPv4_FRAMES		= 0x00000100,
	/* Number of valid IPv4 fragments */
	DPA_STATS_CNT_REASS_IPv4_FRAGS_VALID	 = 0x00000200,
	/* Number of processed IPv4 fragments */
	DPA_STATS_CNT_REASS_IPv4_FRAGS_TOTAL	 = 0x00000400,
	/* Number of malformed IPv4 fragments */
	DPA_STATS_CNT_REASS_IPv4_FRAGS_MALFORMED = 0x00000800,
	/* Number of discarded IPv4 fragments except Timeout condition */
	DPA_STATS_CNT_REASS_IPv4_FRAGS_DISCARDED = 0x00001000,
	/* Number of busy conditions due to Automatic Learning Hash access */
	DPA_STATS_CNT_REASS_IPv4_AUTOLEARN_BUSY	 = 0x00002000,
	/*
	 * Number of IPv4 fragments occurrences when the number of
	 * fragments-per-frame exceeds 16
	 */
	DPA_STATS_CNT_REASS_IPv4_EXCEED_16FRAGS  = 0x00004000,
	/* Select all counters from dpa_stats_cnt_reass_ipv4_sel */
	DPA_STATS_CNT_REASS_IPv4_ALL		 = 0x00008000
};

/*
 * DPA Stats IP Reassembly selection of counters that provide
 * information only for IPv6 protocol
 */
enum dpa_stats_cnt_reass_ipv6_sel {
	/* Number of successfully reassembled IPv6 frames*/
	DPA_STATS_CNT_REASS_IPv6_FRAMES		= 0x00010000,
	/* Number of valid IPv6 fragments */
	DPA_STATS_CNT_REASS_IPv6_FRAGS_VALID	 = 0x00020000,
	/* Number of processed IPv6 fragments */
	DPA_STATS_CNT_REASS_IPv6_FRAGS_TOTAL	 = 0x00040000,
	/* Number of malformed IPv6 fragments */
	DPA_STATS_CNT_REASS_IPv6_FRAGS_MALFORMED = 0x00080000,
	/* Number of discarded IPv6 fragments except Timeout condition */
	DPA_STATS_CNT_REASS_IPv6_FRAGS_DISCARDED = 0x00100000,
	/* Number of busy conditions due to Automatic Learning Hash access */
	DPA_STATS_CNT_REASS_IPv6_AUTOLEARN_BUSY  = 0x00200000,
	/*
	 * Number of IPv6 fragments occurrences when the number of
	 * fragments-per-frame exceeds 16
	 */
	DPA_STATS_CNT_REASS_IPv6_EXCEED_16FRAGS  = 0x00400000,
	/* Select all counters from dpa_stats_cnt_reass_ipv6_sel */
	DPA_STATS_CNT_REASS_IPv6_ALL		 = 0x00800000
};

/* DPA Stats IP Reassembly counter parameters */
struct dpa_stats_cnt_reass {
	/* Pointer to the IP Reassembly object*/
	void	*reass;

	/*
	 * Single or multiple selection of IP Reassembly counters from one of
	 * the enums: dpa_stats_cnt_reass_gen_sel, dpa_stats_cnt_reass_ipv4_sel
	 * or dpa_stats_cnt_reass_ipv6_sel
	 */
	unsigned int cnt_sel;
};

/* DPA Stats Fragmentation counters */
enum dpa_stats_cnt_frag_sel {
	/* Number of frames processed by fragmentation manipulation */
	DPA_STATS_CNT_FRAG_TOTAL_FRAMES = 0x00000001,
	/* Number of fragmented frames */
	DPA_STATS_CNT_FRAG_FRAMES	= 0x00000002,
	/* Number of generated fragments */
	DPA_STATS_CNT_FRAG_GEN_FRAGS	= 0x00000004,
	/* Select all counters from dpa_stats_cnt_frag_sel */
	DPA_STATS_CNT_FRAG_ALL		= 0x00000008
};

/* DPA Stats Fragmentation counter parameters */
struct dpa_stats_cnt_frag {
	/* Pointer to the IP Fragmentation object*/
	void	*frag;

	/*
	 * Single or multiple selection of Fragmentation
	 * counters from enum dpa_stats_cnt_frag_sel
	 */
	unsigned int cnt_sel;
};

/* DPA Stats Policer counters */
enum dpa_stats_cnt_plcr_sel {
	/* Number of 'green' frames */
	DPA_STATS_CNT_PLCR_GREEN_PKTS		= 0x00000001,
	/* Number of 'yellow' frames */
	DPA_STATS_CNT_PLCR_YELLOW_PKTS		= 0x00000002,
	/* Number of 'red' frames */
	DPA_STATS_CNT_PLCR_RED_PKTS		= 0x00000004,
	/* Number of recolored 'yellow' frames */
	DPA_STATS_CNT_PLCR_RECOLOR_YELLOW_PKTS	= 0x00000008,
	/* Number of recolored 'red' frames */
	DPA_STATS_CNT_PLCR_RECOLOR_RED_PKTS	= 0x00000010,
	/* Select all counters */
	DPA_STATS_CNT_PLCR_ALL			= 0x00000020
};

/* DPA Stats Policer counter parameters */
struct dpa_stats_cnt_plcr {
	/* Pointer to the Policer object */
	void	*plcr;

	/*
	 * Single or multiple selection of Policer counters
	 * from enum dpa_stats_cnt_plcr_sel
	 */
	unsigned int cnt_sel;
};

/* DPA Stats Classification counters */
enum dpa_stats_cnt_classif_sel {
	/* Number of bytes processed by classification entry */
	DPA_STATS_CNT_CLASSIF_BYTES		= 0x00000010,
	/* Number of frames processed by classification entry */
	DPA_STATS_CNT_CLASSIF_PACKETS		= 0x00000020,
	/* Number of frames for frame length range 0 */
	DPA_STATS_CNT_CLASSIF_RMON_RANGE0	= 0x00000040,
	/* Number of frames for frame length range 1 */
	DPA_STATS_CNT_CLASSIF_RMON_RANGE1	= 0x00000080,
	/* Number of frames for frame length range 2 */
	DPA_STATS_CNT_CLASSIF_RMON_RANGE2	= 0x00000100,
	/* Number of frames for frame length range 3 */
	DPA_STATS_CNT_CLASSIF_RMON_RANGE3	= 0x00000200,
	/* Number of frames for frame length range 4 */
	DPA_STATS_CNT_CLASSIF_RMON_RANGE4	= 0x00000400,
	/* Number of frames for frame length range 5 */
	DPA_STATS_CNT_CLASSIF_RMON_RANGE5	= 0x00000800,
	/* Number of frames for frame length range 6 */
	DPA_STATS_CNT_CLASSIF_RMON_RANGE6	= 0x00001000,
	/* Number of frames for frame length range 7 */
	DPA_STATS_CNT_CLASSIF_RMON_RANGE7	= 0x00002000,
	/* Number of frames for frame length range 8 */
	DPA_STATS_CNT_CLASSIF_RMON_RANGE8	= 0x00004000,
	/* Number of frames for frame length range 9 */
	DPA_STATS_CNT_CLASSIF_RMON_RANGE9	= 0x00008000,
	/* Select all counters */
	DPA_STATS_CNT_CLASSIF_ALL		= 0x00010000
};

/* DPA Stats Classifier Table counter parameters */
struct dpa_stats_cnt_classif_tbl {

	/* Table descriptor */
	int td;

	/*
	 * Pointer to a key that identifies a specific entry or NULL in order
	 * to obtain statistics for miss entry
	 */
	struct dpa_offload_lookup_key *key;

	/*
	 * Single or multiple selection of Classifier Table counters
	 * from one of the enums: dpa_stats_cnt_classif_sel or
	 * dpa_stats_cnt_frag_sel
	 */
	unsigned int cnt_sel;
};

/* DPA Stats Classification Node Type */
enum dpa_stats_classif_node_type {
	/* Classification Node type HASH */
	DPA_STATS_CLASSIF_NODE_HASH = 0,
	/* Classification Node type Indexed */
	DPA_STATS_CLASSIF_NODE_INDEXED,
	/* Classification Node type Exact match */
	DPA_STATS_CLASSIF_NODE_EXACT_MATCH
};

/* DPA Stats Classification Node parameters */
struct dpa_stats_cnt_classif_node {
	/*
	 * Handle of the FMAN Cc node, more precisely handle of
	 * the classification element previously created in the
	 * distribution XML file
	 */
	void *cc_node;

	/* The type of FMAN Classification Node */
	enum dpa_stats_classif_node_type ccnode_type;

	/*
	 * Pointer to a key that identifies a specific entry or NULL in order
	 * to obtain statistics for miss entry
	 */
	struct dpa_offload_lookup_key *key;

	/*
	 * Single or multiple selection of Classifier
	 * counters from enum: dpa_stats_cnt_classif_sel
	 */
	unsigned int cnt_sel;
};

/* DPA Stats IPSec counter parameters */
struct dpa_stats_cnt_ipsec {

	/* Security Association id */
	int sa_id;

	/* Select IPSec counter */
	enum dpa_stats_cnt_sel cnt_sel;
};

/* DPA Stats Traffic Manager counter source */
enum dpa_stats_cnt_traffic_mng_src {
	/* Traffic Manager Class counter */
	DPA_STATS_CNT_TRAFFIC_CLASS = 0,
	/* Traffic Manager Congestion Group counter */
	DPA_STATS_CNT_TRAFFIC_CG
};

/* DPA Stats Traffic Manager counter parameters */
struct dpa_stats_cnt_traffic_mng {
	/* Traffic Manager counter source */
	enum dpa_stats_cnt_traffic_mng_src src;

	/*
	 * Depending on the Traffic Manager source, the 'traffic_mng' has a
	 * different meaning: it represents a pointer to a structure of type
	 * 'qm_ceetm_cq' in case the traffic source is a "Class Queue" or a
	 * pointer to a structure of type 'qm_ceetm_ccg' in case the traffic
	 * source is a "Class Congestion Group"
	 */
	void *traffic_mng;

	/*
	 * Traffic Manager Class: Number of bytes/frames dequeued from a Class
	 * Traffic Manager Congestion Group: Number of bytes/frames whose
	 * enqueues was rejected in all Class queues that belong to the
	 * Congestion Group
	 */
	enum dpa_stats_cnt_sel cnt_sel;
};

/* DPA Stats counter parameters */
struct dpa_stats_cnt_params {

	/* The type of DPA Stats counter */
	enum dpa_stats_cnt_type type;

	union {
		/* Parameters for Ethernet counter */
		struct dpa_stats_cnt_eth eth_params;

		/* Parameters for IP Reassembly counter */
		struct dpa_stats_cnt_reass reass_params;

		/* Parameters for IP Fragmentation counter */
		struct dpa_stats_cnt_frag frag_params;

		/* Parameters for Policer counter */
		struct dpa_stats_cnt_plcr plcr_params;

		/* Parameters for Classification Table counter */
		struct dpa_stats_cnt_classif_tbl classif_tbl_params;

		/* Parameters for Classification Node counter */
		struct dpa_stats_cnt_classif_node classif_node_params;

		/* Parameters for IPSec counter */
		struct dpa_stats_cnt_ipsec ipsec_params;

		/* Parameters for Traffic Manager counter */
		struct dpa_stats_cnt_traffic_mng traffic_mng_params;
	};
};

/* DPA Stats Ethernet class counter parameters */
struct dpa_stats_cls_cnt_eth {
	/* Array of Ethernet counters sources */
	struct dpa_stats_cnt_eth_src *src;

	/* Single selection of Ethernet counter */
	enum dpa_stats_cnt_eth_sel cnt_sel;
};

/* DPA Stats IP Reassembly class counter parameters */
struct dpa_stats_cls_cnt_reass {
	/* Array of pointers of IP Reassembly objects */
	void	**reass;

	/*
	 * Single or multiple selections of IP Reassembly counters
	 * from one of the enums dpa_stats_cnt_reass_gen_sel,
	 * dpa_stats_cnt_reass_ipv4_sel or dpa_stats_cnt_reass_ipv6_sel
	 */
	unsigned int cnt_sel;
};

/* DPA Stats IP Fragmentation counter parameters */
struct dpa_stats_cls_cnt_frag {
	/* Array of pointers of IP Fragmentation objects */
	void	**frag;

	/*
	 * Single or multiple selection of Fragmentation
	 * counters from enum dpa_stats_cnt_frag_sel
	 */
	unsigned int cnt_sel;
};

/* DPA Stats Policer class counter parameters */
struct dpa_stats_cls_cnt_plcr {
	/* Array of pointers of Policer objects */
	void	**plcr;

	/*
	 * Single or multiple selection of Policer counters
	 * from enum dpa_stats_cnt_plcr_sel
	 */
	unsigned int cnt_sel;
};

/* DPA Stats Classification key type */
enum dpa_stats_classif_key_type {

	/* Entry identified through a single key */
	DPA_STATS_CLASSIF_SINGLE_KEY = 0,

	/*
	 * Entry identified through a pair of keys: the first key
	 * uniquely identifies the first entry, while the second key
	 * identifies the entry connected to the first entry
	 */
	DPA_STATS_CLASSIF_PAIR_KEY
};

/* DPA Stats Classification counter - pair of keys */
struct dpa_offload_lookup_key_pair {

	/*
	 * Pointer to a key that identifies the first entry or NULL in order
	 * to identify the miss entry of the first table
	 */
	struct dpa_offload_lookup_key *first_key;

	/*
	 * Pointer to a key that identifies the entry connected to the first
	 * entry first entry or NULL in order to identify the miss entry
	 */
	struct dpa_offload_lookup_key *second_key;
};

/* DPA Stats Classifier Table class counter parameters */
struct dpa_stats_cls_cnt_classif_tbl {

	/* Table descriptor */
	int td;

	/* Mechanism used to identify an entry */
	enum dpa_stats_classif_key_type   key_type;

	union {
		/*
		 * Invalid keys can be provided during class counter creation
		 * and the statistics values for such keys will be 0. Function
		 * 'dpa_stats_modify_class_counter' can be further used to
		 * modify a specific key.
		 */

		/*
		 * Pointer to an array of keys, where each element of the array
		 * can either be a key that identifies a specific entry or NULL
		 * in order to obtain the statistics for the miss entry. A key
		 * can be'invalidated' by providing the 'byte' pointer set
		 * to NULL.
		 */
		struct dpa_offload_lookup_key **keys;

		/*
		 * Array of 'pair-keys' to identify specific entries. A key pair
		 * can be 'invalidated' by providing the 'byte' and 'mask'
		 * pointers of the first key set to NULL
		 */

		/*
		 * Pointer to an array of ‘pair-keys’, where each element of the
		 * array can either be a ‘pair-key’ that identifies a specific
		 * entry or NULL in in order to obtain the statistics for the
		 * miss entry. A key pair can be 'invalidated' by providing the
		 * 'byte' pointer of the first key set to NULL.
		 */
		struct dpa_offload_lookup_key_pair **pairs;
	};

	/*
	 * Single or multiple selection of Classifier Table counters
	 * from one of the enums: dpa_stats_cnt_classif_sel or
	 * dpa_stats_cnt_frag_sel
	 */
	unsigned int cnt_sel;
};

/* DPA Stats Classification Node class counter parameters */
struct dpa_stats_cls_cnt_classif_node {
	/*
	 * Handle of the FMAN Cc node, more precisely handle of
	 * the classification element previously created in the
	 * distribution XML file
	 */
	void *cc_node;

	/* The type of FMAN Classification Node */
	enum dpa_stats_classif_node_type ccnode_type;

	/* Array of keys to identify specific entries */
	struct dpa_offload_lookup_key **keys;

	/*
	 * Single or multiple selection of Classifier counters
	 * from enum dpa_stats_cnt_classif_sel
	 */
	unsigned int cnt_sel;
};

/* DPA Stats IPSec class counter parameters */
struct dpa_stats_cls_cnt_ipsec {

	/*
	 * Array of security association IDs. Invalid security association
	 * identifiers(DPA_OFFLD_INVALID_OBJECT_ID) can be provided during
	 * class counter creation and the statistics values for such ids will
	 * be 0. Function 'dpa_stats_modify_class_counter' can be further used
	 * to modify a specific security association identifier.
	 */
	int *sa_id;

	/* Select IPSec counter */
	enum dpa_stats_cnt_sel cnt_sel;
};

/* DPA Stats Traffic Manager class counter parameters */
struct dpa_stats_cls_cnt_traffic_mng {

	/* Traffic Manager source */
	enum dpa_stats_cnt_traffic_mng_src src;

	/*
	 * Depending on the Traffic Manager source, the 'traffic_mng' has a
	 * different meaning: it represents an array of pointers to structures
	 * of type 'qm_ceetm_cq' in case the traffic source is a "Class Queue"
	 * or an array of pointers to structures of type 'qm_ceetm_ccg' in case
	 * the traffic source is a "Class Congestion Group"
	 */
	void **traffic_mng;

	/*
	 * Traffic Manager Class: Number of bytes/frames dequeued from a Class
	 * Traffic Manager Congestion Group: Number of bytes/frames whose
	 * enqueues was rejected in all Class queues that belong to the
	 * Congestion Group
	 */
	enum dpa_stats_cnt_sel cnt_sel;
};

/* DPA Stats class counter parameters */
struct dpa_stats_cls_cnt_params {

	/* Number of members the class can have */
	unsigned int class_members;

	/* The type of DPA Stats class counter */
	enum dpa_stats_cnt_type type;

	union {
		/* Parameters for Ethernet class counter */
		struct dpa_stats_cls_cnt_eth eth_params;

		/* Parameters for IP Reassembly class counter */
		struct dpa_stats_cls_cnt_reass reass_params;

		/* Parameters for IP Fragmentation class counter */
		struct dpa_stats_cls_cnt_frag frag_params;

		/* Parameters for Policer class counter */
		struct dpa_stats_cls_cnt_plcr plcr_params;

		/* Parameters for Classifier Table class counter */
		struct dpa_stats_cls_cnt_classif_tbl classif_tbl_params;

		/* Parameters for Classification Node class counter */
		struct dpa_stats_cls_cnt_classif_node classif_node_params;

		/* Parameters for IPSec class counter */
		struct dpa_stats_cls_cnt_ipsec ipsec_params;

		/* Parameters for Traffic Manager class counter */
		struct dpa_stats_cls_cnt_traffic_mng traffic_mng_params;
	};
};

/* DPA Stats class counter member type */
enum dpa_stats_cls_member_type {
	/* Classifier table class member single key */
	DPA_STATS_CLS_MEMBER_SINGLE_KEY = 0,
	/* Classifier table class member pair key */
	DPA_STATS_CLS_MEMBER_PAIR_KEY,
	/* IPSec class member security association id */
	DPA_STATS_CLS_MEMBER_SA_ID
};

/* DPA Stats class member parameters */
struct dpa_stats_cls_member_params {

	/* The type of DPA Stats class counter member */
	enum dpa_stats_cls_member_type type;

	union {
		/*
		 * Pointer to a key to set or update in case the byte pointer is
		 * not NULL, or class member to invalidate otherwise. The
		 * pointer can be NULL, in which case it represents the miss
		 * entry.
		 */
		struct dpa_offload_lookup_key *key;

		/*
		 * Pointer to a 'pair-key' to set or update in case the byte
		 * pointer of the first key is not NULL, or class member to
		 * invalidate otherwise. The pointer can be NULL, in which case
		 * it represents the miss entry.
		 */
		struct dpa_offload_lookup_key_pair *pair;

		/*
		 * Security association identifier to set or update or class
		 * member to invalidate in case the security association has
		 * an invalid value
		 */
		int sa_id;
	};
};

/* Creates and initializes a DPA Stats instance */
int dpa_stats_init(const struct dpa_stats_params *params, int *dpa_stats_id);

/*
 * Create and initialize a DPA Stats counter. The returned 'dpa_stats_cnt_id'
 * will be further used to uniquely identify a counter
 */
int dpa_stats_create_counter(int dpa_stats_id,
			const struct dpa_stats_cnt_params *params,
			int *dpa_stats_cnt_id);

/*
 * Creates and initializes a DPA Stats class counter. The returned
 * 'dpa_stats_cnt_id' will be further used to uniquely identify a counter
 */
int dpa_stats_create_class_counter(int dpa_stats_id,
			const struct dpa_stats_cls_cnt_params *params,
			int *dpa_stats_cnt_id);

/*
 * Modify a specific member of a DPA Stats class counter. The member to be
 * modified is identified through the 'member_index' parameter which represents
 * the member position in the corresponding class counter.
 */
int dpa_stats_modify_class_counter(int dpa_stats_cnt_id,
			const struct dpa_stats_cls_member_params *params,
			int member_index);

/* Remove a DPA Stats counter by releasing all associated resources */
int dpa_stats_remove_counter(int dpa_stats_cnt_id);

/*
 * Create a request to retrieve the values of one or multiple single or class
 * of counters. Counters that are in the 'requested_cnts' array will be
 * retrieved in the order given by the position in the array. The counters
 * values are written in the storage area, at offset defined by
 * 'storage_area_offset' and the user is notified through the callback
 * 'request_done'.
 */
int dpa_stats_get_counters(struct dpa_stats_cnt_request_params params,
			   int *cnts_len,
			   dpa_stats_request_cb request_done);

/* Reset the statistics for a group of counters */
int dpa_stats_reset_counters(int *cnts_ids,
			     unsigned int cnts_ids_len);
/*
 * Releases all resources associated with a DPA Stats instance
 * and destroys it.
 */
int dpa_stats_free(int dpa_stats_id);

int dpa_stats_create_sampling_group(void);

int dpa_stats_remove_sampling_group(void);

#endif	/* __FSL_DPA_STATS_H */
