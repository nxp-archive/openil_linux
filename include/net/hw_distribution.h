/**
 * Copyright 2014 Freescale Semiconductor Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
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

#ifndef __HARDWARE_DISTRIBUTION_H
#define __HARDWARE_DISTRIBUTION_H

#include <linux/of_platform.h>

#include "bonding.h"
#include "bond_3ad.h"
#include "bond_alb.h"
#include "lnxwrp_fm.h"
#include "offline_port.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
/* FMD includes */
#include "error_ext.h"
#include "fm_pcd_ext.h"
#include "fm_cc.h"
#include "crc64.h"

#define OHFRIENDNAMSIZ	11	/* fman0-oh@1, ...  fman1-oh@6 */
#define OHNODENAMSIZ	24	/* /fsl,dpaa/dpa-fman0-oh@1 */
#define BOND_OH_SUCCESS	0
#define BOND_OH_ERROR	-1
#define NO_POLICY	0xFF	/* this is a magic number */

#define FM1_GB0 0xffe4e0000
#define FM1_10G 0xffe4f0000
#define FM2_GB0 0xffe5e0000
#define FM2_10G 0xffe5f0000

#define DPA_FQ_TD 0x200000

/* There are 4 FMAN Ethernet Ports per T1040, 2 of them are for the
 * Link Aggregation for the L2Swith trunk link, thus there are at
 * most 2 ports left for the other Link Aggregation, this implies
 * 2 MAX_BOND_CNT * SLAVES_PER_BOND = 4 FMAN Ethernet Ports.
 * In fact,we only need numbers of offline port in a DTS:
 * offline port count = min(FM_MAX_NUM_OF_OH_PORTS, MAX_BOND_CNT)
 */
#define MAX_BOND_CNT	2
#define SLAVES_PER_BOND	2

#ifdef CONFIG_HW_LAG_DEBUG
#define hw_lag_dbg(fmt, arg...)  \
	pr_info("LAG:[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), \
			__LINE__, __func__, ##arg)
#else
#define hw_lag_dbg(fmt, arg...) do {} while (0)
#endif

#define IS_UP(dev)					   \
	      ((((dev)->flags & IFF_UP) == IFF_UP)	&& \
	       netif_running(dev)			&& \
	       netif_carrier_ok(dev))

struct oh_port_priv {
	uint16_t oh_channel_id;
	struct	dpa_oh_config_s	*oh_config;
	struct	dpa_fq	*pcd_fqs[SLAVES_PER_BOND];
	struct	dpa_fq *oh_defq, *oh_errq;
	uint16_t p_oh_rcv_channel;
	struct	slave *slave[SLAVES_PER_BOND];
	u32	pcd_fqids_base;
	uint32_t fqid_pcderr, fqid_pcdconf, fqid_ohtxconf;
	struct	dpa_fq *oh_pcderrq, *oh_pcdconfq, *oh_txconfq;
	/* init dynamic particular tx fqs of offline port for LAG xmit,
	 * does not reuse tx fqs initialized by offline port driver.
	 */
	struct	dpa_fq *oh_tx_lag_fqs;
	const	phandle	*p_oh_port_handle;
	struct	platform_device	*oh_of_dev, *of_dev;
	struct	device	*dpa_oh_dev, *oh_dev;
	struct	device_node	*dpa_oh_node, *oh_node;
	struct	dpa_bp *tx_bp;
	struct	dpa_buffer_layout_s *tx_buf_layout;
	uint8_t bpid;	/**< External buffer pool id */
	uint16_t bp_size;	/**< External buffer pool buffer size */
	int	oh_en;	/* enable or disable offline port's help at run-time */
	unsigned char friendname[OHFRIENDNAMSIZ];
	unsigned long cell_index;
	bool allocated_pcd_mem;
	bool applied_pcd;
	t_Handle h_FmPcd;
	t_Handle h_FmPort;
	t_Handle h_NetEnv;

	t_FmPcdNetEnvParams *netEnvParams;
	t_FmPcdKgSchemeParams *scheme;
	t_FmPortPcdParams *pcdParam;
	t_FmPortPcdPrsParams *prsParam;
	t_FmPortPcdKgParams *kgParam;
	int numberof_pre_schemes;
};

enum e_dist_hdr {
	L2_MAC = 0,
	MAC_L3_IPV6,
	MAC_L3_IPV4,
	MAC_IPV6_TCP,
	MAC_IPV6_UDP,
	MAC_IPV4_TCP,
	MAC_IPV4_UDP,
	MAX_SCHEMES
};

extern struct oh_port_priv *poh;
extern int available_num_of_oh_ports;

int get_oh_info(void);
unsigned int to_which_oh_i_attached(struct oh_port_priv *current_poh);
bool are_all_slaves_linkup(struct bonding *bond);
int get_dcp_id_from_dpa_eth_port(struct net_device *netdev);
int export_oh_port_info_to_ceetm(struct bonding *bond, uint16_t *channel,
				 unsigned long *fman_dcpid,
				 unsigned long *oh_offset,
				 unsigned long *cell_index);
int show_dpa_slave_info(struct bonding *bond, struct slave *slave);
int get_dpa_slave_info_ex(struct slave *slave, uint16_t *tx_channel,
			  struct qman_fq **egress_fq, u32 *first_fqid);
int enqueue_pkt_to_oh(struct bonding *bond, struct sk_buff *skb,
		      struct dpa_fq *ceetm_fq);
ssize_t
bonding_show_offline_port_xmit_statistics(struct device *d,
					  struct device_attribute *attr,
					  char *buf);
ssize_t bonding_show_offline_ports(struct device *d,
				   struct device_attribute *attr, char *buf);
ssize_t
bonding_show_oh_needed_for_hw_distribution(struct device *d,
					   struct device_attribute *attr,
					   char *buf);
ssize_t
bonding_store_oh_needed_for_hw_distribution(struct device *d,
					    struct device_attribute *attr,
					    const char *buffer,	size_t count);
ssize_t
bonding_show_oh_enable(struct device *d, struct device_attribute *attr,
		       char *buf);
ssize_t
bonding_store_oh_enable(struct device *d,
			struct device_attribute *attr, const char *buffer,
			size_t count);
int fill_oh_pcd_fqs_with_slave_info(struct bonding *bond, struct slave *slave);
int del_oh_pcd_fqs_with_slave_info(struct bonding *bond, struct slave *slave);
bool apply_pcd(struct bonding *bond, int new_xmit_policy);
int release_pcd_mem(struct bonding *bond);
int init_status(struct net_device *netdev);
void add_statistics(struct bonding *bond, struct rtnl_link_stats64 *stats);
#endif /* __HARDWARE_DISTRIBUTION_H */
