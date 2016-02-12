/* Copyright 2015 Freescale Semiconductor, Inc.
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

#include <linux/string.h>

#include "dpaa_eth.h"
#include "dpaa_eth_macsec.h"

static const char dpa_macsec_stats_percpu[][ETH_GSTRING_LEN] = {
	"interrupts",
	"rx packets",
	"tx packets",
	"tx recycled",
	"tx confirm",
	"tx S/G",
	"rx S/G",
	"tx error",
	"rx error",
	"bp count",
	"tx macsec",
	"rx macsec"
};

static char dpa_macsec_stats_global[][ETH_GSTRING_LEN] = {
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

	/* congestion related stats */
	"congestion time (ms)",
	"entered congestion",
	"congested (0/1)"
};

#define DPA_MACSEC_STATS_PERCPU_LEN ARRAY_SIZE(dpa_macsec_stats_percpu)
#define DPA_MACSEC_STATS_GLOBAL_LEN ARRAY_SIZE(dpa_macsec_stats_global)

static void copy_stats(struct dpa_percpu_priv_s *percpu_priv, int num_cpus,
		       int crr_cpu, u64 bp_count, u64 tx_macsec,
		       u64 rx_macsec, u64 *data)
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

	data[crr * num_values + crr_cpu] = percpu_priv->rx_sg;
	data[crr++ * num_values + num_cpus] += percpu_priv->rx_sg;

	data[crr * num_values + crr_cpu] = percpu_priv->stats.tx_errors;
	data[crr++ * num_values + num_cpus] += percpu_priv->stats.tx_errors;

	data[crr * num_values + crr_cpu] = percpu_priv->stats.rx_errors;
	data[crr++ * num_values + num_cpus] += percpu_priv->stats.rx_errors;

	data[crr * num_values + crr_cpu] = bp_count;
	data[crr++ * num_values + num_cpus] += bp_count;

	data[crr * num_values + crr_cpu] = tx_macsec;
	data[crr++ * num_values + num_cpus] += tx_macsec;

	data[crr * num_values + crr_cpu] = rx_macsec;
	data[crr++ * num_values + num_cpus] += rx_macsec;
}

int dpa_macsec_get_sset_count(struct net_device *net_dev, int type)
{
	unsigned int total_stats, num_stats;

	num_stats   = num_online_cpus() + 1;
	total_stats = num_stats * DPA_MACSEC_STATS_PERCPU_LEN +
		DPA_MACSEC_STATS_GLOBAL_LEN;

	switch (type) {
	case ETH_SS_STATS:
		return total_stats;
	default:
		return -EOPNOTSUPP;
	}
}

void dpa_macsec_get_ethtool_stats(struct net_device *net_dev,
				  struct ethtool_stats *stats, u64 *data)
{
	u64 bp_count, bp_total, cg_time, cg_num, cg_status;
	struct macsec_percpu_priv_s *percpu_priv_macsec;
	struct dpa_percpu_priv_s *percpu_priv;
	struct macsec_priv_s *macsec_priv;
	struct qm_mcr_querycgr query_cgr;
	struct dpa_rx_errors rx_errors;
	struct dpa_ern_cnt ern_cnt;
	struct dpa_priv_s *priv;
	unsigned int num_cpus, offset;
	struct dpa_bp *dpa_bp;
	int total_stats, i;

	macsec_priv = dpa_macsec_get_priv(net_dev);
	if (unlikely(!macsec_priv)) {
		pr_err("selected macsec_priv is NULL\n");
		return;
	}

	total_stats = dpa_macsec_get_sset_count(net_dev, ETH_SS_STATS);
	priv     = netdev_priv(net_dev);
	dpa_bp   = priv->dpa_bp;
	num_cpus = num_online_cpus();
	bp_count = 0;
	bp_total = 0;

	memset(&rx_errors, 0, sizeof(struct dpa_rx_errors));
	memset(&ern_cnt, 0, sizeof(struct dpa_ern_cnt));
	memset(data, 0, total_stats * sizeof(u64));

	for_each_online_cpu(i) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, i);
		percpu_priv_macsec = per_cpu_ptr(macsec_priv->percpu_priv, i);

		if (dpa_bp->percpu_count)
			bp_count = *(per_cpu_ptr(dpa_bp->percpu_count, i));

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

		copy_stats(percpu_priv, num_cpus, i, bp_count,
			   percpu_priv_macsec->tx_macsec,
			   percpu_priv_macsec->rx_macsec,
			   data);
	}

	offset = (num_cpus + 1) * DPA_MACSEC_STATS_PERCPU_LEN;
	memcpy(data + offset, &rx_errors, sizeof(struct dpa_rx_errors));

	offset += sizeof(struct dpa_rx_errors) / sizeof(u64);
	memcpy(data + offset, &ern_cnt, sizeof(struct dpa_ern_cnt));

	/* gather congestion related counters */
	cg_num    = 0;
	cg_status = 0;
	cg_time   = jiffies_to_msecs(priv->cgr_data.congested_jiffies);
	if (qman_query_cgr(&priv->cgr_data.cgr, &query_cgr) == 0) {
		cg_num    = priv->cgr_data.cgr_congested_count;
		cg_status = query_cgr.cgr.cs;

		/* reset congestion stats (like QMan API does */
		priv->cgr_data.congested_jiffies   = 0;
		priv->cgr_data.cgr_congested_count = 0;
	}

	offset += sizeof(struct dpa_ern_cnt) / sizeof(u64);
	data[offset++] = cg_time;
	data[offset++] = cg_num;
	data[offset++] = cg_status;
}

void dpa_macsec_get_strings(struct net_device *net_dev,
			    u32 stringset, u8 *data)
{
	unsigned int i, j, num_cpus, size;
	char string_cpu[ETH_GSTRING_LEN];
	u8 *strings;

	strings   = data;
	num_cpus  = num_online_cpus();
	size      = DPA_MACSEC_STATS_GLOBAL_LEN * ETH_GSTRING_LEN;

	for (i = 0; i < DPA_MACSEC_STATS_PERCPU_LEN; i++) {
		for (j = 0; j < num_cpus; j++) {
			snprintf(string_cpu, ETH_GSTRING_LEN, "%s [CPU %d]",
				 dpa_macsec_stats_percpu[i], j);
			memcpy(strings, string_cpu, ETH_GSTRING_LEN);
			strings += ETH_GSTRING_LEN;
		}
		snprintf(string_cpu, ETH_GSTRING_LEN, "%s [TOTAL]",
			 dpa_macsec_stats_percpu[i]);
		memcpy(strings, string_cpu, ETH_GSTRING_LEN);
		strings += ETH_GSTRING_LEN;
	}
	memcpy(strings, dpa_macsec_stats_global, size);
}

