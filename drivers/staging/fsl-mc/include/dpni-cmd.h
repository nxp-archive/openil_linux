/* Copyright 2013-2015 Freescale Semiconductor Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the above-listed copyright holders nor the
 * names of any contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _FSL_DPNI_CMD_H
#define _FSL_DPNI_CMD_H

#define DPNI_CMD_EXTRACT_EXT_PARAMS		25
#define DPNI_CMD_EARLY_DROP_EXT_PARAMS		13

/* DPNI Version */
#define DPNI_VER_MAJOR				5
#define DPNI_VER_MINOR				0

/* Command IDs */
#define DPNI_CMDID_OPEN				0x801
#define DPNI_CMDID_CLOSE			0x800
#define DPNI_CMDID_CREATE			0x901
#define DPNI_CMDID_DESTROY			0x900

#define DPNI_CMDID_ENABLE			0x002
#define DPNI_CMDID_DISABLE			0x003
#define DPNI_CMDID_GET_ATTR			0x004
#define DPNI_CMDID_RESET			0x005
#define DPNI_CMDID_IS_ENABLED			0x006

#define DPNI_CMDID_SET_IRQ			0x010
#define DPNI_CMDID_GET_IRQ			0x011
#define DPNI_CMDID_SET_IRQ_ENABLE		0x012
#define DPNI_CMDID_GET_IRQ_ENABLE		0x013
#define DPNI_CMDID_SET_IRQ_MASK			0x014
#define DPNI_CMDID_GET_IRQ_MASK			0x015
#define DPNI_CMDID_GET_IRQ_STATUS		0x016
#define DPNI_CMDID_CLEAR_IRQ_STATUS		0x017

#define DPNI_CMDID_SET_POOLS			0x200
#define DPNI_CMDID_GET_RX_BUFFER_LAYOUT		0x201
#define DPNI_CMDID_SET_RX_BUFFER_LAYOUT		0x202
#define DPNI_CMDID_GET_TX_BUFFER_LAYOUT		0x203
#define DPNI_CMDID_SET_TX_BUFFER_LAYOUT		0x204
#define DPNI_CMDID_SET_TX_CONF_BUFFER_LAYOUT	0x205
#define DPNI_CMDID_GET_TX_CONF_BUFFER_LAYOUT	0x206
#define DPNI_CMDID_SET_L3_CHKSUM_VALIDATION	0x207
#define DPNI_CMDID_GET_L3_CHKSUM_VALIDATION	0x208
#define DPNI_CMDID_SET_L4_CHKSUM_VALIDATION	0x209
#define DPNI_CMDID_GET_L4_CHKSUM_VALIDATION	0x20A
#define DPNI_CMDID_SET_ERRORS_BEHAVIOR		0x20B

#define DPNI_CMDID_GET_QDID			0x210
#define DPNI_CMDID_GET_SPID			0x211
#define DPNI_CMDID_GET_TX_DATA_OFFSET		0x212
#define DPNI_CMDID_GET_COUNTER			0x213
#define DPNI_CMDID_SET_COUNTER			0x214
#define DPNI_CMDID_GET_LINK_STATE		0x215
#define DPNI_CMDID_SET_MAX_FRAME_LENGTH		0x216
#define DPNI_CMDID_GET_MAX_FRAME_LENGTH		0x217
#define DPNI_CMDID_SET_MTU			0x218
#define DPNI_CMDID_GET_MTU			0x219
#define DPNI_CMDID_SET_LINK_CFG		0x21A

#define DPNI_CMDID_SET_MCAST_PROMISC		0x220
#define DPNI_CMDID_GET_MCAST_PROMISC		0x221
#define DPNI_CMDID_SET_UNICAST_PROMISC		0x222
#define DPNI_CMDID_GET_UNICAST_PROMISC		0x223
#define DPNI_CMDID_SET_PRIM_MAC			0x224
#define DPNI_CMDID_GET_PRIM_MAC			0x225
#define DPNI_CMDID_ADD_MAC_ADDR			0x226
#define DPNI_CMDID_REMOVE_MAC_ADDR		0x227
#define DPNI_CMDID_CLR_MAC_FILTERS		0x228

#define DPNI_CMDID_SET_VLAN_FILTERS		0x230
#define DPNI_CMDID_ADD_VLAN_ID			0x231
#define DPNI_CMDID_REMOVE_VLAN_ID		0x232
#define DPNI_CMDID_CLR_VLAN_FILTERS		0x233
#define DPNI_CMDID_SET_TX_TC			0x234
#define DPNI_CMDID_SET_RX_TC_DIST		0x235
#define DPNI_CMDID_SET_TX_FLOW			0x236
#define DPNI_CMDID_GET_TX_FLOW			0x237
#define DPNI_CMDID_SET_RX_FLOW			0x238
#define DPNI_CMDID_GET_RX_FLOW			0x239
#define DPNI_CMDID_SET_RX_ERR_QUEUE		0x23A
#define DPNI_CMDID_GET_RX_ERR_QUEUE		0x23B
#define DPNI_CMDID_SET_TX_CONF_ERR_QUEUE	0x23C
#define DPNI_CMDID_GET_TX_CONF_ERR_QUEUE	0x23D
#define DPNI_CMDID_SET_RX_TC_POLICING		0x23E
#define DPNI_CMDID_SET_RX_TC_EARLY_DROP		0x23F

#define DPNI_CMDID_SET_QOS_TBL			0x240
#define DPNI_CMDID_ADD_QOS_ENT			0x241
#define DPNI_CMDID_REMOVE_QOS_ENT		0x242
#define DPNI_CMDID_CLR_QOS_TBL			0x243
#define DPNI_CMDID_ADD_FS_ENT			0x244
#define DPNI_CMDID_REMOVE_FS_ENT		0x245
#define DPNI_CMDID_CLR_FS_ENT			0x246
#define DPNI_CMDID_SET_VLAN_INSERTION		0x247
#define DPNI_CMDID_SET_VLAN_REMOVAL		0x248
#define DPNI_CMDID_SET_IPR			0x249
#define DPNI_CMDID_SET_IPF			0x24A

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_OPEN(cmd, dpni_id) \
	MC_CMD_OP(cmd,	 0,	0,	32,	int,	dpni_id)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_CREATE(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,	8,  uint8_t,  cfg->adv.max_tcs); \
	MC_CMD_OP(cmd, 0, 8,	8,  uint8_t,  cfg->adv.max_senders); \
	MC_CMD_OP(cmd, 0, 16,	8,  uint8_t,  cfg->mac_addr[5]); \
	MC_CMD_OP(cmd, 0, 24,	8,  uint8_t,  cfg->mac_addr[4]); \
	MC_CMD_OP(cmd, 0, 32,	8,  uint8_t,  cfg->mac_addr[3]); \
	MC_CMD_OP(cmd, 0, 40,	8,  uint8_t,  cfg->mac_addr[2]); \
	MC_CMD_OP(cmd, 0, 48,	8,  uint8_t,  cfg->mac_addr[1]); \
	MC_CMD_OP(cmd, 0, 56,	8,  uint8_t,  cfg->mac_addr[0]); \
	MC_CMD_OP(cmd, 1, 0,	32, uint32_t, cfg->adv.options); \
	MC_CMD_OP(cmd, 2, 0,	8,  uint8_t,  cfg->adv.max_unicast_filters); \
	MC_CMD_OP(cmd, 2, 8,	8,  uint8_t,  cfg->adv.max_multicast_filters); \
	MC_CMD_OP(cmd, 2, 16,	8,  uint8_t,  cfg->adv.max_vlan_filters); \
	MC_CMD_OP(cmd, 2, 24,	8,  uint8_t,  cfg->adv.max_qos_entries); \
	MC_CMD_OP(cmd, 2, 32,	8,  uint8_t,  cfg->adv.max_qos_key_size); \
	MC_CMD_OP(cmd, 2, 48,	8,  uint8_t,  cfg->adv.max_dist_key_size); \
	MC_CMD_OP(cmd, 2, 56,	8,  enum net_prot, cfg->adv.start_hdr); \
	MC_CMD_OP(cmd, 3, 0,	8,  uint8_t,  cfg->adv.max_dist_per_tc[0]); \
	MC_CMD_OP(cmd, 3, 8,	8,  uint8_t,  cfg->adv.max_dist_per_tc[1]); \
	MC_CMD_OP(cmd, 3, 16,	8,  uint8_t,  cfg->adv.max_dist_per_tc[2]); \
	MC_CMD_OP(cmd, 3, 24,	8,  uint8_t,  cfg->adv.max_dist_per_tc[3]); \
	MC_CMD_OP(cmd, 3, 32,	8,  uint8_t,  cfg->adv.max_dist_per_tc[4]); \
	MC_CMD_OP(cmd, 3, 40,	8,  uint8_t,  cfg->adv.max_dist_per_tc[5]); \
	MC_CMD_OP(cmd, 3, 48,	8,  uint8_t,  cfg->adv.max_dist_per_tc[6]); \
	MC_CMD_OP(cmd, 3, 56,	8,  uint8_t,  cfg->adv.max_dist_per_tc[7]); \
	MC_CMD_OP(cmd, 4, 0,	16, uint16_t, \
				    cfg->adv.ipr_cfg.max_reass_frm_size); \
	MC_CMD_OP(cmd, 4, 16,	16, uint16_t, \
				    cfg->adv.ipr_cfg.min_frag_size_ipv4); \
	MC_CMD_OP(cmd, 4, 32,	16, uint16_t, \
				    cfg->adv.ipr_cfg.min_frag_size_ipv6); \
	MC_CMD_OP(cmd, 4, 48,	8,  uint8_t, cfg->adv.max_policers); \
	MC_CMD_OP(cmd, 4, 56,	8,  uint8_t, cfg->adv.max_congestion_ctrl); \
	MC_CMD_OP(cmd, 5, 0,	16, uint16_t, \
				  cfg->adv.ipr_cfg.max_open_frames_ipv4); \
	MC_CMD_OP(cmd, 5, 16,	16, uint16_t, \
				  cfg->adv.ipr_cfg.max_open_frames_ipv6); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_POOLS(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  8,  uint8_t,  cfg->num_dpbp); \
	MC_CMD_OP(cmd, 0, 32, 32, int,      cfg->pools[0].dpbp_id); \
	MC_CMD_OP(cmd, 4, 32, 16, uint16_t, cfg->pools[0].buffer_size);\
	MC_CMD_OP(cmd, 1, 0,  32, int,      cfg->pools[1].dpbp_id); \
	MC_CMD_OP(cmd, 4, 48, 16, uint16_t, cfg->pools[1].buffer_size);\
	MC_CMD_OP(cmd, 1, 32, 32, int,      cfg->pools[2].dpbp_id); \
	MC_CMD_OP(cmd, 5, 0,  16, uint16_t, cfg->pools[2].buffer_size);\
	MC_CMD_OP(cmd, 2, 0,  32, int,      cfg->pools[3].dpbp_id); \
	MC_CMD_OP(cmd, 5, 16, 16, uint16_t, cfg->pools[3].buffer_size);\
	MC_CMD_OP(cmd, 2, 32, 32, int,      cfg->pools[4].dpbp_id); \
	MC_CMD_OP(cmd, 5, 32, 16, uint16_t, cfg->pools[4].buffer_size);\
	MC_CMD_OP(cmd, 3, 0,  32, int,      cfg->pools[5].dpbp_id); \
	MC_CMD_OP(cmd, 5, 48, 16, uint16_t, cfg->pools[5].buffer_size);\
	MC_CMD_OP(cmd, 3, 32, 32, int,      cfg->pools[6].dpbp_id); \
	MC_CMD_OP(cmd, 6, 0,  16, uint16_t, cfg->pools[6].buffer_size);\
	MC_CMD_OP(cmd, 4, 0,  32, int,      cfg->pools[7].dpbp_id); \
	MC_CMD_OP(cmd, 6, 16, 16, uint16_t, cfg->pools[7].buffer_size);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_IS_ENABLED(cmd, en) \
	MC_RSP_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_IRQ(cmd, irq_index, irq_addr, irq_val, user_irq_id) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, irq_val); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index); \
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, irq_addr); \
	MC_CMD_OP(cmd, 2, 0,  32, int,	     user_irq_id); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_GET_IRQ(cmd, irq_index) \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_IRQ(cmd, type, irq_addr, irq_val, user_irq_id) \
do { \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t, irq_val); \
	MC_RSP_OP(cmd, 1, 0,  64, uint64_t, irq_addr); \
	MC_RSP_OP(cmd, 2, 0,  32, int,      user_irq_id); \
	MC_RSP_OP(cmd, 2, 32, 32, int,	    type); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_IRQ_ENABLE(cmd, irq_index, en) \
do { \
	MC_CMD_OP(cmd, 0, 0,  8,  uint8_t,  en); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_GET_IRQ_ENABLE(cmd, irq_index) \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_IRQ_ENABLE(cmd, en) \
	MC_RSP_OP(cmd, 0, 0,  8,  uint8_t,  en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_IRQ_MASK(cmd, irq_index, mask) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, mask); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_GET_IRQ_MASK(cmd, irq_index) \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_IRQ_MASK(cmd, mask) \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t,  mask)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_GET_IRQ_STATUS(cmd, irq_index) \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_IRQ_STATUS(cmd, status) \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t,  status)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_CLEAR_IRQ_STATUS(cmd, irq_index, status) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, status); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_ATTR(cmd, attr) \
do { \
	MC_RSP_OP(cmd, 0, 0,  32, int,	    attr->id);\
	MC_RSP_OP(cmd, 0, 32, 8,  uint8_t,  attr->max_tcs); \
	MC_RSP_OP(cmd, 0, 40, 8,  uint8_t,  attr->max_senders); \
	MC_RSP_OP(cmd, 0, 48, 8,  enum net_prot, attr->start_hdr); \
	MC_RSP_OP(cmd, 1, 0,  32, uint32_t, attr->options); \
	MC_RSP_OP(cmd, 2, 0,  8,  uint8_t,  attr->max_unicast_filters); \
	MC_RSP_OP(cmd, 2, 8,  8,  uint8_t,  attr->max_multicast_filters);\
	MC_RSP_OP(cmd, 2, 16, 8,  uint8_t,  attr->max_vlan_filters); \
	MC_RSP_OP(cmd, 2, 24, 8,  uint8_t,  attr->max_qos_entries); \
	MC_RSP_OP(cmd, 2, 32, 8,  uint8_t,  attr->max_qos_key_size); \
	MC_RSP_OP(cmd, 2, 40, 8,  uint8_t,  attr->max_dist_key_size); \
	MC_RSP_OP(cmd, 3, 0,  8,  uint8_t,  attr->max_dist_per_tc[0]); \
	MC_RSP_OP(cmd, 3, 8,  8,  uint8_t,  attr->max_dist_per_tc[1]); \
	MC_RSP_OP(cmd, 3, 16, 8,  uint8_t,  attr->max_dist_per_tc[2]); \
	MC_RSP_OP(cmd, 3, 24, 8,  uint8_t,  attr->max_dist_per_tc[3]); \
	MC_RSP_OP(cmd, 3, 32, 8,  uint8_t,  attr->max_dist_per_tc[4]); \
	MC_RSP_OP(cmd, 3, 40, 8,  uint8_t,  attr->max_dist_per_tc[5]); \
	MC_RSP_OP(cmd, 3, 48, 8,  uint8_t,  attr->max_dist_per_tc[6]); \
	MC_RSP_OP(cmd, 3, 56, 8,  uint8_t,  attr->max_dist_per_tc[7]); \
	MC_RSP_OP(cmd, 4, 0,	16, uint16_t, \
				    attr->ipr_cfg.max_reass_frm_size); \
	MC_RSP_OP(cmd, 4, 16,	16, uint16_t, \
				    attr->ipr_cfg.min_frag_size_ipv4); \
	MC_RSP_OP(cmd, 4, 32,	16, uint16_t, \
				    attr->ipr_cfg.min_frag_size_ipv6);\
	MC_RSP_OP(cmd, 4, 48,	8,  uint8_t, attr->max_policers); \
	MC_RSP_OP(cmd, 4, 56,	8,  uint8_t, attr->max_congestion_ctrl); \
	MC_RSP_OP(cmd, 5, 0,	16, uint16_t, \
				  attr->ipr_cfg.max_open_frames_ipv4); \
	MC_RSP_OP(cmd, 5, 16,	16, uint16_t, \
				  attr->ipr_cfg.max_open_frames_ipv6); \
	MC_RSP_OP(cmd, 5, 32, 16, uint16_t, attr->version.major);\
	MC_RSP_OP(cmd, 5, 48, 16, uint16_t, attr->version.minor);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_ERRORS_BEHAVIOR(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, cfg->errors); \
	MC_CMD_OP(cmd, 0, 32, 4,  enum dpni_error_action, cfg->error_action); \
	MC_CMD_OP(cmd, 0, 36, 1,  int,      cfg->set_frame_annotation); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_RX_BUFFER_LAYOUT(cmd, layout) \
do { \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, layout->private_data_size); \
	MC_RSP_OP(cmd, 0, 16, 16, uint16_t, layout->data_align); \
	MC_RSP_OP(cmd, 1, 0,  1,  int,	    layout->pass_timestamp); \
	MC_RSP_OP(cmd, 1, 1,  1,  int,	    layout->pass_parser_result); \
	MC_RSP_OP(cmd, 1, 2,  1,  int,	    layout->pass_frame_status); \
	MC_RSP_OP(cmd, 1, 16, 16, uint16_t, layout->data_head_room); \
	MC_RSP_OP(cmd, 1, 32, 16, uint16_t, layout->data_tail_room); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_RX_BUFFER_LAYOUT(cmd, layout) \
do { \
	MC_CMD_OP(cmd, 0, 0,  16, uint16_t, layout->private_data_size); \
	MC_CMD_OP(cmd, 0, 16, 16, uint16_t, layout->data_align); \
	MC_CMD_OP(cmd, 0, 32, 32, uint32_t, layout->options); \
	MC_CMD_OP(cmd, 1, 0,  1,  int,	    layout->pass_timestamp); \
	MC_CMD_OP(cmd, 1, 1,  1,  int,	    layout->pass_parser_result); \
	MC_CMD_OP(cmd, 1, 2,  1,  int,	    layout->pass_frame_status); \
	MC_CMD_OP(cmd, 1, 16, 16, uint16_t, layout->data_head_room); \
	MC_CMD_OP(cmd, 1, 32, 16, uint16_t, layout->data_tail_room); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_TX_BUFFER_LAYOUT(cmd, layout) \
do { \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, layout->private_data_size); \
	MC_RSP_OP(cmd, 0, 16, 16, uint16_t, layout->data_align); \
	MC_RSP_OP(cmd, 1, 0,  1,  int,      layout->pass_timestamp); \
	MC_RSP_OP(cmd, 1, 1,  1,  int,	    layout->pass_parser_result); \
	MC_RSP_OP(cmd, 1, 2,  1,  int,	    layout->pass_frame_status); \
	MC_RSP_OP(cmd, 1, 16, 16, uint16_t, layout->data_head_room); \
	MC_RSP_OP(cmd, 1, 32, 16, uint16_t, layout->data_tail_room); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_TX_BUFFER_LAYOUT(cmd, layout) \
do { \
	MC_CMD_OP(cmd, 0, 0,  16, uint16_t, layout->private_data_size); \
	MC_CMD_OP(cmd, 0, 16, 16, uint16_t, layout->data_align); \
	MC_CMD_OP(cmd, 0, 32, 32, uint32_t, layout->options); \
	MC_CMD_OP(cmd, 1, 0,  1,  int,	    layout->pass_timestamp); \
	MC_CMD_OP(cmd, 1, 1,  1,  int,	    layout->pass_parser_result); \
	MC_CMD_OP(cmd, 1, 2,  1,  int,	    layout->pass_frame_status); \
	MC_CMD_OP(cmd, 1, 16, 16, uint16_t, layout->data_head_room); \
	MC_CMD_OP(cmd, 1, 32, 16, uint16_t, layout->data_tail_room); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_TX_CONF_BUFFER_LAYOUT(cmd, layout) \
do { \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, layout->private_data_size); \
	MC_RSP_OP(cmd, 0, 16, 16, uint16_t, layout->data_align); \
	MC_RSP_OP(cmd, 1, 0,  1,  int,      layout->pass_timestamp); \
	MC_RSP_OP(cmd, 1, 1,  1,  int,	    layout->pass_parser_result); \
	MC_RSP_OP(cmd, 1, 2,  1,  int,	    layout->pass_frame_status); \
	MC_RSP_OP(cmd, 1, 16, 16, uint16_t, layout->data_head_room); \
	MC_RSP_OP(cmd, 1, 32, 16, uint16_t, layout->data_tail_room); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_TX_CONF_BUFFER_LAYOUT(cmd, layout) \
do { \
	MC_CMD_OP(cmd, 0, 0,  16, uint16_t, layout->private_data_size); \
	MC_CMD_OP(cmd, 0, 16, 16, uint16_t, layout->data_align); \
	MC_CMD_OP(cmd, 0, 32, 32, uint32_t, layout->options); \
	MC_CMD_OP(cmd, 1, 0,  1,  int,	    layout->pass_timestamp); \
	MC_CMD_OP(cmd, 1, 1,  1,  int,	    layout->pass_parser_result); \
	MC_CMD_OP(cmd, 1, 2,  1,  int,	    layout->pass_frame_status); \
	MC_CMD_OP(cmd, 1, 16, 16, uint16_t, layout->data_head_room); \
	MC_CMD_OP(cmd, 1, 32, 16, uint16_t, layout->data_tail_room); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_L3_CHKSUM_VALIDATION(cmd, en) \
	MC_CMD_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_L3_CHKSUM_VALIDATION(cmd, en) \
	MC_RSP_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_L4_CHKSUM_VALIDATION(cmd, en) \
	MC_CMD_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_L4_CHKSUM_VALIDATION(cmd, en) \
	MC_RSP_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_QDID(cmd, qdid) \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, qdid)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_SPID(cmd, spid) \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, spid)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_TX_DATA_OFFSET(cmd, data_offset) \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, data_offset)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_GET_COUNTER(cmd, counter) \
	MC_CMD_OP(cmd, 0, 0,  16, enum dpni_counter, counter)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_COUNTER(cmd, value) \
	MC_RSP_OP(cmd, 1, 0,  64, uint64_t, value)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_COUNTER(cmd, counter, value) \
do { \
	MC_CMD_OP(cmd, 0, 0,  16, enum dpni_counter, counter); \
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, value); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_LINK_CFG(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 1, 0,  32, uint32_t, cfg->rate);\
	MC_CMD_OP(cmd, 2, 0,  64, uint64_t, cfg->options);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_LINK_STATE(cmd, state) \
do { \
	MC_RSP_OP(cmd, 0, 32,  1, int,      state->up);\
	MC_RSP_OP(cmd, 1, 0,  32, uint32_t, state->rate);\
	MC_RSP_OP(cmd, 2, 0,  64, uint64_t, state->options);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_MAX_FRAME_LENGTH(cmd, max_frame_length) \
	MC_CMD_OP(cmd, 0, 0,  16, uint16_t, max_frame_length)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_MAX_FRAME_LENGTH(cmd, max_frame_length) \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, max_frame_length)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_MTU(cmd, mtu) \
	MC_CMD_OP(cmd, 0, 0,  16, uint16_t, mtu)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_MTU(cmd, mtu) \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, mtu)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_MULTICAST_PROMISC(cmd, en) \
	MC_CMD_OP(cmd, 0, 0,  1,  int,      en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_MULTICAST_PROMISC(cmd, en) \
	MC_RSP_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_UNICAST_PROMISC(cmd, en) \
	MC_CMD_OP(cmd, 0, 0,  1,  int,      en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_UNICAST_PROMISC(cmd, en) \
	MC_RSP_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_PRIMARY_MAC_ADDR(cmd, mac_addr) \
do { \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  mac_addr[5]); \
	MC_CMD_OP(cmd, 0, 24, 8,  uint8_t,  mac_addr[4]); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  mac_addr[3]); \
	MC_CMD_OP(cmd, 0, 40, 8,  uint8_t,  mac_addr[2]); \
	MC_CMD_OP(cmd, 0, 48, 8,  uint8_t,  mac_addr[1]); \
	MC_CMD_OP(cmd, 0, 56, 8,  uint8_t,  mac_addr[0]); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_PRIMARY_MAC_ADDR(cmd, mac_addr) \
do { \
	MC_RSP_OP(cmd, 0, 16, 8,  uint8_t,  mac_addr[5]); \
	MC_RSP_OP(cmd, 0, 24, 8,  uint8_t,  mac_addr[4]); \
	MC_RSP_OP(cmd, 0, 32, 8,  uint8_t,  mac_addr[3]); \
	MC_RSP_OP(cmd, 0, 40, 8,  uint8_t,  mac_addr[2]); \
	MC_RSP_OP(cmd, 0, 48, 8,  uint8_t,  mac_addr[1]); \
	MC_RSP_OP(cmd, 0, 56, 8,  uint8_t,  mac_addr[0]); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_ADD_MAC_ADDR(cmd, mac_addr) \
do { \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  mac_addr[5]); \
	MC_CMD_OP(cmd, 0, 24, 8,  uint8_t,  mac_addr[4]); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  mac_addr[3]); \
	MC_CMD_OP(cmd, 0, 40, 8,  uint8_t,  mac_addr[2]); \
	MC_CMD_OP(cmd, 0, 48, 8,  uint8_t,  mac_addr[1]); \
	MC_CMD_OP(cmd, 0, 56, 8,  uint8_t,  mac_addr[0]); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_REMOVE_MAC_ADDR(cmd, mac_addr) \
do { \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  mac_addr[5]); \
	MC_CMD_OP(cmd, 0, 24, 8,  uint8_t,  mac_addr[4]); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  mac_addr[3]); \
	MC_CMD_OP(cmd, 0, 40, 8,  uint8_t,  mac_addr[2]); \
	MC_CMD_OP(cmd, 0, 48, 8,  uint8_t,  mac_addr[1]); \
	MC_CMD_OP(cmd, 0, 56, 8,  uint8_t,  mac_addr[0]); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_CLEAR_MAC_FILTERS(cmd, unicast, multicast) \
do { \
	MC_CMD_OP(cmd, 0, 0,  1,  int,      unicast); \
	MC_CMD_OP(cmd, 0, 1,  1,  int,      multicast); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_VLAN_FILTERS(cmd, en) \
	MC_CMD_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_ADD_VLAN_ID(cmd, vlan_id) \
	MC_CMD_OP(cmd, 0, 32, 16, uint16_t, vlan_id)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_REMOVE_VLAN_ID(cmd, vlan_id) \
	MC_CMD_OP(cmd, 0, 32, 16, uint16_t, vlan_id)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_TX_TC(cmd, tc_id, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  16, uint16_t, cfg->depth_limit); \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  tc_id); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_RX_TC_DIST(cmd, tc_id, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  8,  uint8_t,  cfg->dist_size); \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  tc_id); \
	MC_CMD_OP(cmd, 0, 24, 4,  enum dpni_dist_mode, cfg->dist_mode); \
	MC_CMD_OP(cmd, 0, 28, 4,  enum dpni_fs_miss_action, \
						  cfg->fs_cfg.miss_action); \
	MC_CMD_OP(cmd, 0, 48, 16, uint16_t, cfg->fs_cfg.default_flow_id); \
	MC_CMD_OP(cmd, 6, 0,  64, uint64_t, cfg->key_cfg_iova); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_TX_FLOW(cmd, flow_id, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, int,     \
		cfg->conf_err_cfg.queue_cfg.dest_cfg.dest_id);\
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t, \
		cfg->conf_err_cfg.queue_cfg.dest_cfg.priority);\
	MC_CMD_OP(cmd, 0, 40, 2,  enum dpni_dest, \
		cfg->conf_err_cfg.queue_cfg.dest_cfg.dest_type);\
	MC_CMD_OP(cmd, 0, 42, 1,  int,	    cfg->conf_err_cfg.errors_only);\
	MC_CMD_OP(cmd, 0, 43, 1,  int,	    cfg->l3_chksum_gen);\
	MC_CMD_OP(cmd, 0, 44, 1,  int,	    cfg->l4_chksum_gen);\
	MC_CMD_OP(cmd, 0, 45, 1,  int,	    \
		cfg->conf_err_cfg.use_default_queue);\
	MC_CMD_OP(cmd, 0, 48, 16, uint16_t, flow_id);\
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, \
		cfg->conf_err_cfg.queue_cfg.user_ctx);\
	MC_CMD_OP(cmd, 2, 0,  32, uint32_t, cfg->options);\
	MC_CMD_OP(cmd, 2, 32,  32, uint32_t, \
		cfg->conf_err_cfg.queue_cfg.options);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_SET_TX_FLOW(cmd, flow_id) \
	MC_RSP_OP(cmd, 0, 48, 16, uint16_t, flow_id)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_GET_TX_FLOW(cmd, flow_id) \
	MC_CMD_OP(cmd, 0, 48, 16, uint16_t, flow_id)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_TX_FLOW(cmd, attr) \
do { \
	MC_RSP_OP(cmd, 0, 0,  32, int,      \
			attr->conf_err_attr.queue_attr.dest_cfg.dest_id);\
	MC_RSP_OP(cmd, 0, 32, 8,  uint8_t,  \
			attr->conf_err_attr.queue_attr.dest_cfg.priority);\
	MC_RSP_OP(cmd, 0, 40, 2,  enum dpni_dest, \
			attr->conf_err_attr.queue_attr.dest_cfg.dest_type);\
	MC_RSP_OP(cmd, 0, 42, 1,  int,	    attr->conf_err_attr.errors_only);\
	MC_RSP_OP(cmd, 0, 43, 1,  int,	    attr->l3_chksum_gen);\
	MC_RSP_OP(cmd, 0, 44, 1,  int,	    attr->l4_chksum_gen);\
	MC_RSP_OP(cmd, 0, 45, 1,  int,	    \
			attr->conf_err_attr.use_default_queue);\
	MC_RSP_OP(cmd, 1, 0,  64, uint64_t, \
			attr->conf_err_attr.queue_attr.user_ctx);\
	MC_RSP_OP(cmd, 2, 32, 32, uint32_t, \
			attr->conf_err_attr.queue_attr.fqid);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_RX_FLOW(cmd, tc_id, flow_id, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, int,      cfg->dest_cfg.dest_id); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  cfg->dest_cfg.priority);\
	MC_CMD_OP(cmd, 0, 40, 2,  enum dpni_dest, cfg->dest_cfg.dest_type);\
	MC_CMD_OP(cmd, 0, 48, 16, uint16_t, flow_id); \
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, cfg->user_ctx); \
	MC_CMD_OP(cmd, 2, 16, 8,  uint8_t,  tc_id); \
	MC_CMD_OP(cmd, 2, 32,  32, uint32_t, cfg->options); \
	MC_CMD_OP(cmd, 3, 0,  4,  enum dpni_flc_type, cfg->flc_cfg.flc_type); \
	MC_CMD_OP(cmd, 3, 4,  4,  enum dpni_stash_size, \
		cfg->flc_cfg.frame_data_size);\
	MC_CMD_OP(cmd, 3, 8,  4,  enum dpni_stash_size, \
		cfg->flc_cfg.flow_context_size);\
	MC_CMD_OP(cmd, 3, 32, 32, uint32_t, cfg->flc_cfg.options);\
	MC_CMD_OP(cmd, 4, 0,  64, uint64_t, cfg->flc_cfg.flow_context);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_GET_RX_FLOW(cmd, tc_id, flow_id) \
do { \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  tc_id); \
	MC_CMD_OP(cmd, 0, 48, 16, uint16_t, flow_id); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_RX_FLOW(cmd, attr) \
do { \
	MC_RSP_OP(cmd, 0, 0,  32, int,      attr->dest_cfg.dest_id); \
	MC_RSP_OP(cmd, 0, 32, 8,  uint8_t,  attr->dest_cfg.priority);\
	MC_RSP_OP(cmd, 0, 40, 2,  enum dpni_dest, attr->dest_cfg.dest_type); \
	MC_RSP_OP(cmd, 1, 0,  64, uint64_t, attr->user_ctx); \
	MC_RSP_OP(cmd, 2, 32, 32, uint32_t, attr->fqid); \
	MC_RSP_OP(cmd, 3, 0,  4,  enum dpni_flc_type, attr->flc_cfg.flc_type); \
	MC_RSP_OP(cmd, 3, 4,  4,  enum dpni_stash_size, \
		attr->flc_cfg.frame_data_size);\
	MC_RSP_OP(cmd, 3, 8,  4,  enum dpni_stash_size, \
		attr->flc_cfg.flow_context_size);\
	MC_RSP_OP(cmd, 3, 32, 32, uint32_t, attr->flc_cfg.options);\
	MC_RSP_OP(cmd, 4, 0,  64, uint64_t, attr->flc_cfg.flow_context);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_RX_ERR_QUEUE(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, int,      cfg->dest_cfg.dest_id); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  cfg->dest_cfg.priority);\
	MC_CMD_OP(cmd, 0, 40, 2,  enum dpni_dest, cfg->dest_cfg.dest_type);\
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, cfg->user_ctx); \
	MC_CMD_OP(cmd, 2, 0,  32, uint32_t, cfg->options); \
	MC_CMD_OP(cmd, 3, 0,  4,  enum dpni_flc_type, cfg->flc_cfg.flc_type); \
	MC_CMD_OP(cmd, 3, 4,  4,  enum dpni_stash_size, \
		cfg->flc_cfg.frame_data_size);\
	MC_CMD_OP(cmd, 3, 8,  4,  enum dpni_stash_size, \
		cfg->flc_cfg.flow_context_size);\
	MC_CMD_OP(cmd, 3, 32, 32, uint32_t, cfg->flc_cfg.options);\
	MC_CMD_OP(cmd, 4, 0,  64, uint64_t, cfg->flc_cfg.flow_context);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_RX_ERR_QUEUE(cmd, attr) \
do { \
	MC_RSP_OP(cmd, 0, 0,  32, int,      attr->dest_cfg.dest_id); \
	MC_RSP_OP(cmd, 0, 32, 8,  uint8_t,  attr->dest_cfg.priority);\
	MC_RSP_OP(cmd, 0, 40, 2,  enum dpni_dest, attr->dest_cfg.dest_type);\
	MC_RSP_OP(cmd, 1, 0,  64, uint64_t, attr->user_ctx); \
	MC_RSP_OP(cmd, 2, 32, 32, uint32_t, attr->fqid); \
	MC_RSP_OP(cmd, 3, 0,  4,  enum dpni_flc_type, attr->flc_cfg.flc_type); \
	MC_RSP_OP(cmd, 3, 4,  4,  enum dpni_stash_size, \
		attr->flc_cfg.frame_data_size);\
	MC_RSP_OP(cmd, 3, 8,  4,  enum dpni_stash_size, \
		attr->flc_cfg.flow_context_size);\
	MC_RSP_OP(cmd, 3, 32, 32, uint32_t, attr->flc_cfg.options);\
	MC_RSP_OP(cmd, 4, 0,  64, uint64_t, attr->flc_cfg.flow_context);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_TX_CONF_ERR_QUEUE(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, int,      cfg->dest_cfg.dest_id); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  cfg->dest_cfg.priority);\
	MC_CMD_OP(cmd, 0, 40, 2,  enum dpni_dest, cfg->dest_cfg.dest_type);\
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, cfg->user_ctx); \
	MC_CMD_OP(cmd, 2, 0,  32, uint32_t, cfg->options); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_RSP_GET_TX_CONF_ERR_QUEUE(cmd, attr) \
do { \
	MC_RSP_OP(cmd, 0, 0,  32, int,      attr->dest_cfg.dest_id); \
	MC_RSP_OP(cmd, 0, 32, 8,  uint8_t,  attr->dest_cfg.priority);\
	MC_RSP_OP(cmd, 0, 40, 2,  enum dpni_dest, attr->dest_cfg.dest_type);\
	MC_RSP_OP(cmd, 1, 0,  64, uint64_t, attr->user_ctx); \
	MC_RSP_OP(cmd, 2, 32, 32, uint32_t, attr->fqid); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_QOS_TABLE(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  cfg->default_tc); \
	MC_CMD_OP(cmd, 0, 40, 1,  int,	    cfg->discard_on_miss); \
	MC_CMD_OP(cmd, 6, 0,  64, uint64_t, cfg->key_cfg_iova); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_ADD_QOS_ENTRY(cmd, cfg, tc_id) \
do { \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  tc_id); \
	MC_CMD_OP(cmd, 0, 24, 8,  uint8_t,  cfg->key_size); \
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, cfg->key_iova); \
	MC_CMD_OP(cmd, 2, 0,  64, uint64_t, cfg->mask_iova); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_REMOVE_QOS_ENTRY(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 24, 8,  uint8_t,  cfg->key_size); \
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, cfg->key_iova); \
	MC_CMD_OP(cmd, 2, 0,  64, uint64_t, cfg->mask_iova); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_ADD_FS_ENTRY(cmd, tc_id, cfg, flow_id) \
do { \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  tc_id); \
	MC_CMD_OP(cmd, 0, 48, 16, uint16_t, flow_id); \
	MC_CMD_OP(cmd, 0, 24, 8,  uint8_t,  cfg->key_size); \
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, cfg->key_iova); \
	MC_CMD_OP(cmd, 2, 0,  64, uint64_t, cfg->mask_iova); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_REMOVE_FS_ENTRY(cmd, tc_id, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  tc_id); \
	MC_CMD_OP(cmd, 0, 24, 8,  uint8_t,  cfg->key_size); \
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, cfg->key_iova); \
	MC_CMD_OP(cmd, 2, 0,  64, uint64_t, cfg->mask_iova); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_CLEAR_FS_ENTRIES(cmd, tc_id) \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  tc_id)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_VLAN_INSERTION(cmd, en) \
	MC_CMD_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_VLAN_REMOVAL(cmd, en) \
	MC_CMD_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_IPR(cmd, en) \
	MC_CMD_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_IPF(cmd, en) \
	MC_CMD_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_RX_TC_POLICING(cmd, tc_id, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  4, enum dpni_policer_mode, cfg->mode); \
	MC_CMD_OP(cmd, 0, 4,  4, enum dpni_policer_color, cfg->default_color); \
	MC_CMD_OP(cmd, 0, 8,  4, enum dpni_policer_unit, cfg->units); \
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  tc_id); \
	MC_CMD_OP(cmd, 0, 32, 32, uint32_t,  cfg->options); \
	MC_CMD_OP(cmd, 1, 0,  32, uint32_t, cfg->cir); \
	MC_CMD_OP(cmd, 1, 32, 32, uint32_t, cfg->cbs); \
	MC_CMD_OP(cmd, 2, 0,  32, uint32_t, cfg->eir); \
	MC_CMD_OP(cmd, 2, 32, 32, uint32_t, cfg->ebs);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_EXT_SET_RX_TC_EARLY_DROP(ext, cfg) \
do { \
	MC_EXT_OP(ext, 0, 0,  2, enum dpni_early_drop_mode, cfg->mode); \
	MC_EXT_OP(ext, 0, 2,  2, \
		  enum dpni_early_drop_unit, cfg->units); \
	MC_EXT_OP(ext, 0, 32, 32, uint32_t, cfg->tail_drop_threshold); \
	MC_EXT_OP(ext, 1, 0,  8,  uint8_t,  cfg->green.drop_probability); \
	MC_EXT_OP(ext, 2, 0,  64, uint64_t, cfg->green.max_threshold); \
	MC_EXT_OP(ext, 3, 0,  64, uint64_t, cfg->green.min_threshold); \
	MC_EXT_OP(ext, 5, 0,  8,  uint8_t,  cfg->yellow.drop_probability);\
	MC_EXT_OP(ext, 6, 0,  64, uint64_t, cfg->yellow.max_threshold); \
	MC_EXT_OP(ext, 7, 0,  64, uint64_t, cfg->yellow.min_threshold); \
	MC_EXT_OP(ext, 9, 0,  8,  uint8_t,  cfg->red.drop_probability); \
	MC_EXT_OP(ext, 10, 0,  64, uint64_t, cfg->red.max_threshold); \
	MC_EXT_OP(ext, 11, 0,  64, uint64_t, cfg->red.min_threshold); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPNI_CMD_SET_RX_TC_EARLY_DROP(cmd, tc_id, early_drop_iova) \
do { \
	MC_CMD_OP(cmd, 0, 8,  8,  uint8_t,  tc_id); \
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, early_drop_iova); \
} while (0)
#endif /* _FSL_DPNI_CMD_H */
