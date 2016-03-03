/* Copyright 2013 Freescale Semiconductor Inc.
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

#ifndef __DPA_ETH_GENERIC_H
#define __DPA_ETH_GENERIC_H

#include "lnxwrp_fsl_fman.h"
#include "dpaa_eth.h"

struct dpa_generic_priv_s {
	struct net_device *net_dev;
	/* use the same percpu_priv as other DPAA Ethernet drivers */
	struct dpa_percpu_priv_s __percpu *percpu_priv;

	/* up to 4 bps supported for RX */
	int rx_bp_count;
	struct dpa_bp *rx_bp;
	struct dpa_buffer_layout_s *rx_buf_layout;

	struct dpa_bp *draining_tx_bp;
	struct dpa_bp *draining_tx_sg_bp;
	struct dpa_buffer_layout_s *tx_buf_layout;

	/* Store here the needed Tx headroom for convenience and speed
	 * (even though it can be computed based on the fields of buf_layout)
	 */
	uint16_t tx_headroom;
	uint16_t rx_headroom;

	/* In some scenarios, when VSP are not enabled on the Tx O/H port,
	 * the buffers will be released by other hardware modules
	 */
	int disable_buff_dealloc;

	struct qman_fq		*egress_fqs[DPAA_ETH_TX_QUEUES];

	struct fm_port		*rx_port;
	struct fm_port		*tx_port;

	/* oNIC can have limited control capabilities over a MAC device */
	struct mac_device	*mac_dev;

	uint16_t		 channel;	/* "fsl,qman-channel-id" */
	struct list_head	 dpa_fq_list;

	uint32_t		 msg_enable;	/* net_device message level */

	struct dpa_buffer_layout_s *buf_layout;
	char if_type[30];

	/* periodic drain */
	struct timer_list timer;
};

extern const struct ethtool_ops dpa_generic_ethtool_ops;

void dpaa_eth_generic_sysfs_init(struct device *dev);
void dpaa_eth_generic_sysfs_remove(struct device *dev);
int __init dpa_generic_debugfs_module_init(void);
void __exit dpa_generic_debugfs_module_exit(void);

#endif /* __DPA_ETH_GENERIC_H */
