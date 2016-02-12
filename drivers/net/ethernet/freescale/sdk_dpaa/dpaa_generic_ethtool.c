/* Copyright 2008-2012 Freescale Semiconductor, Inc.
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

#ifdef CONFIG_FSL_DPAA_ETH_DEBUG
#define pr_fmt(fmt) \
	KBUILD_MODNAME ": %s:%hu:%s() " fmt, \
	KBUILD_BASENAME".c", __LINE__, __func__
#else
#define pr_fmt(fmt) \
	KBUILD_MODNAME ": " fmt
#endif

#include <linux/string.h>

#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "dpaa_eth_generic.h"

static const char dpa_stats_percpu[][ETH_GSTRING_LEN] = {
	"interrupts",
	"rx packets",
	"tx packets",
	"tx recycled",
	"tx confirm",
	"tx S/G",
	"rx S/G (N/A)",
	"tx error",
	"rx error",
	"bp count",
	"bp draining count"
};

static char dpa_stats_global[][ETH_GSTRING_LEN] = {
	/* dpa rx errors */
	"rx dma error",
	"rx frame physical error",
	"rx frame size error",
	"rx header error",
	"rx csum error",

	/* demultiplexing errors */
	"qman cg_tdrop",
	"qman wred",
	"qman error cond",
	"qman early window",
	"qman late window",
	"qman fq tdrop",
	"qman fq retired",
	"qman orp disabled",
};

#define DPA_STATS_PERCPU_LEN ARRAY_SIZE(dpa_stats_percpu)
#define DPA_STATS_GLOBAL_LEN ARRAY_SIZE(dpa_stats_global)

static int __cold dpa_generic_get_settings(struct net_device *net_dev,
					   struct ethtool_cmd *et_cmd)
{
	netdev_info(net_dev, "This interface does not have a MAC device in its control\n");
	return -ENODEV;
}

static int __cold dpa_generic_set_settings(struct net_device *net_dev,
					   struct ethtool_cmd *et_cmd)
{
	netdev_info(net_dev, "This interface does not have a MAC device in its control\n");
	return -ENODEV;
}

static void __cold dpa_generic_get_drvinfo(struct net_device *net_dev,
					   struct ethtool_drvinfo *drvinfo)
{
	int		 _errno;

	strncpy(drvinfo->driver, KBUILD_MODNAME,
		sizeof(drvinfo->driver) - 1)[sizeof(drvinfo->driver)-1] = 0;
	_errno = snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
			  "%X", 0);

	if (unlikely(_errno >= sizeof(drvinfo->fw_version))) {
		/* Truncated output */
		netdev_notice(net_dev, "snprintf() = %d\n", _errno);
	} else if (unlikely(_errno < 0)) {
		netdev_warn(net_dev, "snprintf() = %d\n", _errno);
		memset(drvinfo->fw_version, 0, sizeof(drvinfo->fw_version));
	}
	strncpy(drvinfo->bus_info, dev_name(net_dev->dev.parent->parent),
		sizeof(drvinfo->bus_info)-1)[sizeof(drvinfo->bus_info)-1] = 0;
}

static uint32_t __cold dpa_generic_get_msglevel(struct net_device *net_dev)
{
	return ((struct dpa_generic_priv_s *)netdev_priv(net_dev))->msg_enable;
}

static void __cold dpa_generic_set_msglevel(struct net_device *net_dev,
					    uint32_t msg_enable)
{
	((struct dpa_generic_priv_s *)netdev_priv(net_dev))->msg_enable =
		msg_enable;
}

static int __cold dpa_generic_nway_reset(struct net_device *net_dev)
{
	netdev_info(net_dev, "This interface does not have a MAC device in its control\n");
	return -ENODEV;
}

static int dpa_generic_get_sset_count(struct net_device *net_dev, int type)
{
	unsigned int total_stats, num_stats;

	num_stats   = num_online_cpus() + 1;
	total_stats = num_stats * DPA_STATS_PERCPU_LEN + DPA_STATS_GLOBAL_LEN;

	switch (type) {
	case ETH_SS_STATS:
		return total_stats;
	default:
		return -EOPNOTSUPP;
	}
}

static void copy_stats(struct dpa_percpu_priv_s *percpu_priv,
		       int num_cpus, int crr_cpu, u64 bp_count,
		       u64 bp_drain_count, u64 *data)
{
	int num_values = num_cpus + 1;
	int crr = 0;

	/* update current CPU's stats and also add them to the total values */
	data[crr * num_values + crr_cpu] = percpu_priv->in_interrupt;
	data[crr++ * num_values + num_cpus] += percpu_priv->in_interrupt;

	data[crr * num_values + crr_cpu] = percpu_priv->stats.rx_packets;
	data[crr++ * num_values + num_cpus] += percpu_priv->stats.rx_packets;

	data[crr * num_values + crr_cpu] = percpu_priv->stats.tx_packets;
	data[crr++ * num_values + num_cpus] += percpu_priv->stats.tx_packets;

	data[crr * num_values + crr_cpu] = percpu_priv->tx_returned;
	data[crr++ * num_values + num_cpus] += percpu_priv->tx_returned;

	data[crr * num_values + crr_cpu] = percpu_priv->tx_confirm;
	data[crr++ * num_values + num_cpus] += percpu_priv->tx_confirm;

	data[crr * num_values + crr_cpu] = percpu_priv->tx_frag_skbuffs;
	data[crr++ * num_values + num_cpus] += percpu_priv->tx_frag_skbuffs;

	data[crr * num_values + crr_cpu] = percpu_priv->stats.tx_errors;
	data[crr++ * num_values + num_cpus] += percpu_priv->stats.tx_errors;

	data[crr * num_values + crr_cpu] = percpu_priv->stats.rx_errors;
	data[crr++ * num_values + num_cpus] += percpu_priv->stats.rx_errors;

	data[crr * num_values + crr_cpu] = bp_count;
	data[crr++ * num_values + num_cpus] += bp_count;

	data[crr * num_values + crr_cpu] = bp_drain_count;
	data[crr++ * num_values + num_cpus] += bp_drain_count;
}

static void dpa_generic_get_ethtool_stats(struct net_device *net_dev,
					  struct ethtool_stats *stats,
					  u64 *data)
{
	struct dpa_percpu_priv_s *percpu_priv;
	struct dpa_bp *dpa_bp, *drain_bp;
	struct dpa_generic_priv_s *priv;
	struct dpa_rx_errors rx_errors;
	struct dpa_ern_cnt ern_cnt;
	unsigned int num_cpus, offset;
	u64 bp_cnt, drain_cnt;
	int total_stats, i;

	total_stats  = dpa_generic_get_sset_count(net_dev, ETH_SS_STATS);
	priv         = netdev_priv(net_dev);
	drain_bp = priv->draining_tx_bp;
	dpa_bp       = priv->rx_bp;
	num_cpus = num_online_cpus();
	drain_cnt = 0;
	bp_cnt = 0;

	memset(&rx_errors, 0, sizeof(struct dpa_rx_errors));
	memset(&ern_cnt, 0, sizeof(struct dpa_ern_cnt));
	memset(data, 0, total_stats * sizeof(u64));

	for_each_online_cpu(i) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, i);

		if (dpa_bp->percpu_count)
			bp_cnt = *(per_cpu_ptr(dpa_bp->percpu_count, i));

		if (drain_bp->percpu_count)
			drain_cnt = *(per_cpu_ptr(drain_bp->percpu_count, i));

		rx_errors.dme += percpu_priv->rx_errors.dme;
		rx_errors.fpe += percpu_priv->rx_errors.fpe;
		rx_errors.fse += percpu_priv->rx_errors.fse;
		rx_errors.phe += percpu_priv->rx_errors.phe;
		rx_errors.cse += percpu_priv->rx_errors.cse;

		ern_cnt.cg_tdrop     += percpu_priv->ern_cnt.cg_tdrop;
		ern_cnt.wred         += percpu_priv->ern_cnt.wred;
		ern_cnt.err_cond     += percpu_priv->ern_cnt.err_cond;
		ern_cnt.early_window += percpu_priv->ern_cnt.early_window;
		ern_cnt.late_window  += percpu_priv->ern_cnt.late_window;
		ern_cnt.fq_tdrop     += percpu_priv->ern_cnt.fq_tdrop;
		ern_cnt.fq_retired   += percpu_priv->ern_cnt.fq_retired;
		ern_cnt.orp_zero     += percpu_priv->ern_cnt.orp_zero;

		copy_stats(percpu_priv, num_cpus, i, bp_cnt, drain_cnt, data);
	}

	offset = (num_cpus + 1) * DPA_STATS_PERCPU_LEN;
	memcpy(data + offset, &rx_errors, sizeof(struct dpa_rx_errors));

	offset += sizeof(struct dpa_rx_errors) / sizeof(u64);
	memcpy(data + offset, &ern_cnt, sizeof(struct dpa_ern_cnt));
}

static void dpa_generic_get_strings(struct net_device *net_dev,
				    u32 stringset, u8 *data)
{
	unsigned int i, j, num_cpus, size;
	char string_cpu[ETH_GSTRING_LEN];
	u8 *strings;

	strings   = data;
	num_cpus  = num_online_cpus();
	size      = DPA_STATS_GLOBAL_LEN * ETH_GSTRING_LEN;

	for (i = 0; i < DPA_STATS_PERCPU_LEN; i++) {
		for (j = 0; j < num_cpus; j++) {
			snprintf(string_cpu, ETH_GSTRING_LEN, "%s [CPU %d]",
				 dpa_stats_percpu[i], j);
			memcpy(strings, string_cpu, ETH_GSTRING_LEN);
			strings += ETH_GSTRING_LEN;
		}
		snprintf(string_cpu, ETH_GSTRING_LEN, "%s [TOTAL]",
			 dpa_stats_percpu[i]);
		memcpy(strings, string_cpu, ETH_GSTRING_LEN);
		strings += ETH_GSTRING_LEN;
	}
	memcpy(strings, dpa_stats_global, size);
}

const struct ethtool_ops dpa_generic_ethtool_ops = {
	.get_settings = dpa_generic_get_settings,
	.set_settings = dpa_generic_set_settings,
	.get_drvinfo = dpa_generic_get_drvinfo,
	.get_msglevel = dpa_generic_get_msglevel,
	.set_msglevel = dpa_generic_set_msglevel,
	.nway_reset = dpa_generic_nway_reset,
	.get_link = ethtool_op_get_link,
	.get_sset_count = dpa_generic_get_sset_count,
	.get_ethtool_stats = dpa_generic_get_ethtool_stats,
	.get_strings = dpa_generic_get_strings,
};
