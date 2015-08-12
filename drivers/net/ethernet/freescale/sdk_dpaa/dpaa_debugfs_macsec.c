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
#include "dpaa_eth_macsec.h"
#include "dpaa_eth.h"

#define MACSEC_DEBUGFS_DESCRIPTION "FSL DPAA Ethernet MACsec debugfs entries"
#define MACSEC_DEBUGFS_ROOT "fsl_macsec_dpa"

static int __cold macsec_debugfs_open(struct inode *inode, struct file *file);

static struct dentry *dpa_debugfs_root;
static const struct file_operations macsec_debugfs_fops = {
	.open		= macsec_debugfs_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct macsec_priv_s *macsec_priv[FM_MAX_NUM_OF_MACS];
void set_macsec_priv(struct macsec_priv_s *macsec_priv_src, int index)
{
	macsec_priv[index] = macsec_priv_src;
}
EXPORT_SYMBOL(set_macsec_priv);

void unset_macsec_priv(int index)
{
	macsec_priv[index] = NULL;
}
EXPORT_SYMBOL(unset_macsec_priv);

static int dpa_debugfs_show(struct seq_file *file, void *offset)
{
	int				 i;
	struct macsec_percpu_priv_s	*percpu_priv, total;
	struct net_device *net_dev;
	struct macsec_priv_s *selected_macsec_priv;

	BUG_ON(offset == NULL);

	memset(&total, 0, sizeof(total));

	net_dev = (struct net_device *)file->private;

	selected_macsec_priv = macsec_priv[net_dev->ifindex - 1];
	if (unlikely(!selected_macsec_priv)) {
		pr_err("selected macsec_priv is null\n");
		return -EFAULT;
	}

	/* "Standard" counters */
	seq_printf(file, "\nMacsec counters for %s:\n",
				selected_macsec_priv->net_dev->name);
	seq_printf(file, "%s %8s %8s\n", "CPU", "tx", "rx");


	for_each_online_cpu(i) {
		percpu_priv = per_cpu_ptr(selected_macsec_priv->percpu_priv, i);

		total.tx_macsec += percpu_priv->tx_macsec;
		total.rx_macsec += percpu_priv->rx_macsec;

		seq_printf(file, "%3hu %8llu %8llu\n",
				i,
				percpu_priv->tx_macsec,
				percpu_priv->rx_macsec);
	}
	seq_printf(file, "Total: %5llu %8llu\n",
			total.tx_macsec,
			total.rx_macsec);

	return 0;
}

static int __cold macsec_debugfs_open(struct inode *inode, struct file *file)
{
	int			 _errno;
	const struct net_device	*net_dev;

	_errno = single_open(file, dpa_debugfs_show, inode->i_private);
	if (unlikely(_errno < 0)) {
		net_dev = (struct net_device *)inode->i_private;

		if (netif_msg_drv((struct macsec_priv_s *)netdev_priv(net_dev)))
			netdev_err(net_dev, "single_open() = %d\n",
					_errno);
	}
	return _errno;
}

int macsec_netdev_debugfs_create(struct net_device *net_dev)
{
	char buf[256];
	struct macsec_priv_s *selected_macsec_priv;

	if (unlikely(dpa_debugfs_root == NULL)) {
		pr_err(KBUILD_MODNAME ": %s:%hu:%s(): \t%s\n",
				   KBUILD_BASENAME".c", __LINE__, __func__,
				   "root debugfs missing, possible module ordering issue");
		return -EINVAL;
	}

	sprintf(buf, "%s_macsec", net_dev->name);

	selected_macsec_priv = macsec_priv[net_dev->ifindex - 1];

	if (unlikely(!selected_macsec_priv)) {
		pr_err("selected macsec_priv is null\n");
		return -EFAULT;
	}

	selected_macsec_priv->debugfs_file = debugfs_create_file(
							net_dev->name,
							S_IRUGO,
							dpa_debugfs_root,
							net_dev,
							&macsec_debugfs_fops);
	if (unlikely(selected_macsec_priv->debugfs_file == NULL)) {
		netdev_err(net_dev, "debugfs_create_file(%s/%s)",
				dpa_debugfs_root->d_iname,
				buf);

		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(macsec_netdev_debugfs_create);

void macsec_netdev_debugfs_remove(struct net_device *net_dev)
{
	struct macsec_priv_s *selected_macsec_priv;

	selected_macsec_priv = macsec_priv[net_dev->ifindex - 1];
	debugfs_remove(selected_macsec_priv->debugfs_file);
}
EXPORT_SYMBOL(macsec_netdev_debugfs_remove);

int __init macsec_debugfs_module_init(void)
{
	int	 _errno = 0;

	dpa_debugfs_root = debugfs_create_dir(MACSEC_DEBUGFS_ROOT, NULL);

	if (unlikely(dpa_debugfs_root == NULL)) {
		_errno = -ENOMEM;
		pr_err(KBUILD_MODNAME ": %s:%hu:%s():\n",
				   KBUILD_BASENAME".c", __LINE__, __func__);
		pr_err("\tdebugfs_create_dir(%s/"KBUILD_MODNAME") = %d\n",
			   MACSEC_DEBUGFS_ROOT, _errno);
	}

	return _errno;
}

void __exit macsec_debugfs_module_exit(void)
{
	debugfs_remove(dpa_debugfs_root);
}

