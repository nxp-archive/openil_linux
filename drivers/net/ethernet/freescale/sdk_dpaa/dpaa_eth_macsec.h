/* Copyright 2015 Freescale Semiconductor Inc.
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

#ifndef __DPAA_ETH_MACSEC_H
#define __DPAA_ETH_MACSEC_H

#include "mac.h"

#define NETLINK_USER				31
#define MAX_NUM_OF_SECY				1
#define MAX_LEN					100
#define FM_FD_STAT_RX_MACSEC			0x00800000
#define MACSEC_ETH_TX_QUEUES			NR_CPUS
#define MACSEC_REG_OFFSET			0x800
#define ACK					0
#define NACK					-1

extern const struct dpa_fq_cbs_t private_fq_cbs;

extern int dpa_macsec_get_sset_count(struct net_device *net_dev, int type);
extern void
dpa_macsec_get_ethtool_stats(struct net_device *net_dev,
			     struct ethtool_stats *stats, u64 *data);
extern void
dpa_macsec_get_strings(struct net_device *net_dev,
		       u32 stringset, u8 *data);

enum msg_type {ENABLE_MACSEC,
	SET_EXCEPTION,
	ENABLE_SECY,
	TX_SA_CREATE,
	TX_SA_ACTIVATE,
	RX_SC_CREATE,
	RX_SA_CREATE,
	RX_SA_ACTIVATE,
	RX_SA_DISABLE,
	RX_SA_DELETE,
	RX_SC_DELETE,
	TX_SA_DELETE,
	DISABLE_MACSEC,
	DISABLE_SECY,
	DISABLE_ALL,
	GET_REVISION,
	UPDATE_NPN,
	UPDATE_LPN,
	GET_TXSC_PHYS_ID,
	GET_RXSC_PHYS_ID,
	GET_TXSA_AN,
	MODIFY_TXSA_KEY,
	MODIFY_RXSA_KEY,
};

enum macsec_enablement {MACSEC_DISABLED, MACSEC_ENABLED, SECY_ENABLED};

struct enable_secy {
	int macsec_id;

	u64 sci; /* MAC address(48b) + port_id(16b) */

	bool config_insertion_mode;
	fm_macsec_sci_insertion_mode sci_insertion_mode;

	bool config_protect_frames;
	bool protect_frames;

	bool config_replay_window;
	bool replay_protect;
	uint32_t replay_window;

	bool config_validation_mode;
	fm_macsec_valid_frame_behavior validate_frames;

	bool config_confidentiality;
	bool confidentiality_enable;
	uint32_t confidentiality_offset;

	bool config_point_to_point;

	bool config_exception;
	bool enable_exception;
	fm_macsec_secy_exception exception;

	bool config_event;
	bool enable_event;
	fm_macsec_secy_event event;
};

struct macsec_data {
	char *if_name;
	size_t if_name_length; /* including string terminator */

	bool config_unknown_sci_treatment;
	fm_macsec_unknown_sci_frame_treatment unknown_sci_treatment;

	bool config_invalid_tag_treatment;
	bool deliver_uncontrolled;

	bool config_kay_frame_treatment;
	bool discard_uncontrolled;

	bool config_untag_treatment;
	fm_macsec_untag_frame_treatment untag_treatment;

	bool config_pn_exhaustion_threshold;
	uint32_t pn_threshold;

	bool config_keys_unreadable;

	bool config_sectag_without_sci;

	bool config_exception;
	bool enable_exception;
	fm_macsec_exception exception;
};

struct set_exception {
	int macsec_id;
	bool enable_exception;
	fm_macsec_exception exception;
};

struct create_tx_sa {
	int macsec_id;
	u8 an; /* association number */
	u8 *sak; /* secure assoc key */
	u32 sak_len; /* assoc key length */
};

struct modify_tx_sa_key {
	int macsec_id;
	u8 an; /* association number */
	u8 *sak; /* secure assoc key */
	u32 sak_len; /* assoc key length */
};

struct activate_tx_sa {
	int macsec_id;
	u8 an; /* association number */
};

struct create_rx_sc {
	int macsec_id;
	u64 sci;
};

struct delete_rx_sc {
	int macsec_id;
	u32 rx_sc_id;
};

struct get_rx_sc_id {
	int macsec_id;
	u32 rx_sc_id;
};

struct create_rx_sa {
	int macsec_id;
	u32 rx_sc_id;
	u8 an;
	u32 lpn;
	u8 *sak;
	u32 sak_len;
};

struct activate_rx_sa {
	int macsec_id;
	u32 rx_sc_id;
	u8 an;
};

struct disable_rx_sa {
	int macsec_id;
	u32 rx_sc_id;
	u8 an;
};

struct delete_rx_sa {
	int macsec_id;
	u32 rx_sc_id;
	u8 an;
};

struct delete_tx_sa {
	int macsec_id;
	u32 rx_sc_id;
	u8 an;
};

struct update_npn {
	int macsec_id;
	u32 rx_sc_id;
	u8 an;
	u32 pn;
};

struct update_lpn {
	int macsec_id;
	u32 rx_sc_id;
	u8 an;
	u32 pn;
};

struct modify_rx_sa_key {
	int macsec_id;
	u32 rx_sc_id;
	u8 an;
	u8 *sak;
	u32 sak_len;
};

struct generic_msg {
	enum msg_type chf;
	union {
		int macsec_id;
		struct macsec_data en_macsec;
		struct enable_secy secy;
		struct create_tx_sa c_tx_sa;
		struct activate_tx_sa a_tx_sa;
		struct create_rx_sc c_rx_sc;
		struct get_rx_sc_id get_rx_sc_id;
		struct create_rx_sa c_rx_sa;
		struct activate_rx_sa a_rx_sa;
		struct disable_rx_sa d_rx_sa;
		struct delete_rx_sa del_rx_sa;
		struct delete_rx_sc del_rx_sc;
		struct delete_tx_sa del_tx_sa;
		struct update_npn update_npn;
		struct update_lpn update_lpn;
		struct modify_tx_sa_key modify_tx_sa_key;
		struct modify_rx_sa_key modify_rx_sa_key;
		struct set_exception set_ex;
	} payload;
};

struct macsec_percpu_priv_s {
	u64 rx_macsec;
	u64 tx_macsec;
};

struct macsec_priv_s {
	struct macsec_percpu_priv_s        __percpu *percpu_priv;

	struct net_device *net_dev;
	struct mac_device *mac_dev;

	struct qman_fq		*egress_fqs[MACSEC_ETH_TX_QUEUES];
	struct qman_fq		*conf_fqs[MACSEC_ETH_TX_QUEUES];
	struct list_head	 dpa_fq_list;
	uint32_t		 msg_enable;	/* net_device message level */
	uint16_t                 channel;
	struct fm_macsec_dev *fm_macsec;

	struct fm_macsec_secy_dev *fm_ms_secy;
	uint8_t an;

	struct rx_sc_dev *rx_sc_dev[NUM_OF_RX_SC];
	uint8_t *sa_key;
	enum macsec_enablement en_state;

	uintptr_t vaddr;
	struct resource *fman_resource;
};

struct macsec_priv_s *dpa_macsec_get_priv(struct net_device *net_dev);

#endif /* __DPAA_ETH_MACSEC_H */
