
/* Copyright 2015 Freescale Semiconductor Inc.
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


#include <linux/module.h>
#include <linux/debugfs.h>
#include "dpaa2-eth.h"
#include "dpaa2-eth-debugfs.h"

#define LDPAA_ETH_DBG_ROOT "dpaa2-eth"


static struct dentry *ldpaa_dbg_root;

static int ldpaa_dbg_cpu_show(struct seq_file *file, void *offset)
{
	struct ldpaa_eth_priv *priv = (struct ldpaa_eth_priv *)file->private;
	struct rtnl_link_stats64 *stats;
	struct ldpaa_eth_stats *extras;
	int i;

	seq_printf(file, "Per-CPU stats for %s\n", priv->net_dev->name);
	seq_printf(file, "%s%16s%16s%16s%16s%16s%16s%16s%16s\n",
		   "CPU", "Rx", "Rx Err", "Rx SG", "Tx", "Tx Err", "Tx conf",
		   "Tx SG", "Enq busy");

	for_each_online_cpu(i) {
		stats = per_cpu_ptr(priv->percpu_stats, i);
		extras = per_cpu_ptr(priv->percpu_extras, i);
		seq_printf(file, "%3d%16llu%16llu%16llu%16llu%16llu%16llu%16llu%16llu\n",
			   i,
			   stats->rx_packets,
			   stats->rx_errors,
			   extras->rx_sg_frames,
			   stats->tx_packets,
			   stats->tx_errors,
			   extras->tx_conf_frames,
			   extras->tx_sg_frames,
			   extras->tx_portal_busy);
	}

	return 0;
}

static int ldpaa_dbg_cpu_open(struct inode *inode, struct file *file)
{
	int err;
	struct ldpaa_eth_priv *priv = (struct ldpaa_eth_priv *)inode->i_private;

	err = single_open(file, ldpaa_dbg_cpu_show, priv);
	if (unlikely(err < 0))
		netdev_err(priv->net_dev, "single_open() failed\n");

	return err;
}

static const struct file_operations ldpaa_dbg_cpu_ops = {
	.open = ldpaa_dbg_cpu_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int ldpaa_dbg_fqs_show(struct seq_file *file, void *offset)
{
	struct ldpaa_eth_priv *priv = (struct ldpaa_eth_priv *)file->private;
	struct ldpaa_eth_fq *fq;
	uint32_t fcnt, bcnt;
	int i, err;

	seq_printf(file, "FQ stats for %s:\n", priv->net_dev->name);
	seq_printf(file, "%s%16s%16s%16s%16s\n",
		   "VFQID", "CPU", "Type", "Frames", "Pending frames");

	for (i = 0; i <  priv->num_fqs; i++) {
		fq = &priv->fq[i];
		err = dpaa_io_query_fq_count(NULL, fq->fqid, &fcnt, &bcnt);
		if (unlikely(err))
			fcnt = 0;

		seq_printf(file, "%5d%16d%16s%16llu%16u\n",
			   fq->fqid,
			   fq->target_cpu,
			   fq->type == LDPAA_RX_FQ ? "Rx" : "Tx conf",
			   fq->stats.frames,
			   fcnt);
	}

	return 0;
}

static int ldpaa_dbg_fqs_open(struct inode *inode, struct file *file)
{
	int err;
	struct ldpaa_eth_priv *priv = (struct ldpaa_eth_priv *)inode->i_private;

	err = single_open(file, ldpaa_dbg_fqs_show, priv);
	if (unlikely(err < 0))
		netdev_err(priv->net_dev, "single_open() failed\n");

	return err;
}

static const struct file_operations ldpaa_dbg_fq_ops = {
	.open = ldpaa_dbg_fqs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int ldpaa_dbg_ch_show(struct seq_file *file, void *offset)
{
	struct ldpaa_eth_priv *priv = (struct ldpaa_eth_priv *)file->private;
	struct ldpaa_eth_channel *ch;
	int i;

	seq_printf(file, "Channel stats for %s:\n", priv->net_dev->name);
	seq_printf(file, "%s%16s%16s%16s%16s%16s\n",
		   "CHID", "CPU", "Deq busy", "Frames", "CDANs",
		   "Avg frm/CDAN");

	for_each_cpu(i, &priv->dpio_cpumask) {
		ch = priv->channel[i];
		seq_printf(file, "%4d%16d%16llu%16llu%16llu%16llu\n",
			   ch->ch_id,
			   i,
			   ch->stats.dequeue_portal_busy,
			   ch->stats.frames,
			   ch->stats.cdan,
			   ch->stats.frames / ch->stats.cdan);
	}

	return 0;
}

static int ldpaa_dbg_ch_open(struct inode *inode, struct file *file)
{
	int err;
	struct ldpaa_eth_priv *priv = (struct ldpaa_eth_priv *)inode->i_private;

	err = single_open(file, ldpaa_dbg_ch_show, priv);
	if (unlikely(err < 0))
		netdev_err(priv->net_dev, "single_open() failed\n");

	return err;
}

static const struct file_operations ldpaa_dbg_ch_ops = {
	.open = ldpaa_dbg_ch_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static ssize_t ldpaa_dbg_reset_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *offset)
{
	struct ldpaa_eth_priv *priv = file->private_data;
	struct rtnl_link_stats64 *percpu_stats;
	struct ldpaa_eth_stats *percpu_extras;
	struct ldpaa_eth_fq *fq;
	struct ldpaa_eth_channel *ch;
	int i;

	for_each_online_cpu(i) {
		percpu_stats = per_cpu_ptr(priv->percpu_stats, i);
		memset(percpu_stats, 0, sizeof(*percpu_stats));

		percpu_extras = per_cpu_ptr(priv->percpu_extras, i);
		memset(percpu_extras, 0, sizeof(*percpu_extras));
	}

	for (i = 0; i < priv->num_fqs; i++) {
		fq = &priv->fq[i];
		memset(&fq->stats, 0, sizeof(fq->stats));
	}

	for_each_cpu(i, &priv->dpio_cpumask) {
		ch = priv->channel[i];
		memset(&ch->stats, 0, sizeof(ch->stats));
	}

	return count;
}

static const struct file_operations ldpaa_dbg_reset_ops = {
	.open = simple_open,
	.write = ldpaa_dbg_reset_write,
};

void ldpaa_dbg_add(struct ldpaa_eth_priv *priv)
{
	if (unlikely(!ldpaa_dbg_root))
		return;

	/* Create a directory for the interface */
	priv->dbg.dir = debugfs_create_dir(priv->net_dev->name,
					   ldpaa_dbg_root);
	if (unlikely(!priv->dbg.dir)) {
		netdev_err(priv->net_dev, "debugfs_create_dir() failed\n");
		return;
	}

	/* per-cpu stats file */
	priv->dbg.cpu_stats = debugfs_create_file("cpu_stats", S_IRUGO,
						  priv->dbg.dir, priv,
						  &ldpaa_dbg_cpu_ops);
	if (unlikely(!priv->dbg.cpu_stats)) {
		netdev_err(priv->net_dev, "debugfs_create_file() failed\n");
		goto err_cpu_stats;
	}

	/* per-fq stats file */
	priv->dbg.fq_stats = debugfs_create_file("fq_stats", S_IRUGO,
						 priv->dbg.dir, priv,
						 &ldpaa_dbg_fq_ops);
	if (unlikely(!priv->dbg.fq_stats)) {
		netdev_err(priv->net_dev, "debugfs_create_file() failed\n");
		goto err_fq_stats;
	}

	/* per-fq stats file */
	priv->dbg.ch_stats = debugfs_create_file("ch_stats", S_IRUGO,
						 priv->dbg.dir, priv,
						 &ldpaa_dbg_ch_ops);
	if (unlikely(!priv->dbg.fq_stats)) {
		netdev_err(priv->net_dev, "debugfs_create_file() failed\n");
		goto err_ch_stats;
	}

	/* reset stats */
	priv->dbg.reset_stats = debugfs_create_file("reset_stats", S_IWUSR,
						    priv->dbg.dir, priv,
						    &ldpaa_dbg_reset_ops);
	if (unlikely(!priv->dbg.reset_stats)) {
		netdev_err(priv->net_dev, "debugfs_create_file() failed\n");
		goto err_reset_stats;
	}

	return;

err_reset_stats:
	debugfs_remove(priv->dbg.ch_stats);
err_ch_stats:
	debugfs_remove(priv->dbg.fq_stats);
err_fq_stats:
	debugfs_remove(priv->dbg.cpu_stats);
err_cpu_stats:
	debugfs_remove(priv->dbg.dir);
}

void ldpaa_dbg_remove(struct ldpaa_eth_priv *priv)
{
	debugfs_remove(priv->dbg.reset_stats);
	debugfs_remove(priv->dbg.fq_stats);
	debugfs_remove(priv->dbg.ch_stats);
	debugfs_remove(priv->dbg.cpu_stats);
	debugfs_remove(priv->dbg.dir);
}

static int __init ldpaa_eth_dbg_init(void)
{
	ldpaa_dbg_root = debugfs_create_dir(LDPAA_ETH_DBG_ROOT, NULL);
	if (unlikely(!ldpaa_dbg_root)) {
		pr_err("DPAA2-ETH: debugfs create failed\n");
		return -ENOMEM;
	}

	pr_info("DPAA2-ETH: debugfs created\n");
	return 0;
}

static void __exit ldpaa_eth_dbg_exit(void)
{
	debugfs_remove(ldpaa_dbg_root);
}

module_init(ldpaa_eth_dbg_init);
module_exit(ldpaa_eth_dbg_exit);
MODULE_LICENSE("Dual BSD/GPL");

