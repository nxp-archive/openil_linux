/* Copyright 2014 Freescale Semiconductor Inc.
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/io.h>
#include <linux/of_net.h>

#include "dpaa_eth_generic.h"
#include "mac.h"		/* struct mac_device */

static ssize_t dpaa_eth_generic_show_addr(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct dpa_generic_priv_s *priv = netdev_priv(to_net_dev(dev));
	struct mac_device *mac_dev = priv->mac_dev;

	if (mac_dev)
		return sprintf(buf, "%llx\n",
				(unsigned long long)mac_dev->res->start);
	else
		return sprintf(buf, "none\n");
}

static ssize_t dpaa_eth_generic_show_type(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t res = 0;
	res = sprintf(buf, "generic\n");

	return res;
}

static ssize_t dpaa_eth_generic_show_fqids(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct dpa_generic_priv_s *priv = netdev_priv(to_net_dev(dev));
	ssize_t bytes = 0;
	int i = 0;
	char *str;
	struct dpa_fq *fq;
	struct dpa_fq *tmp;
	struct dpa_fq *prev = NULL;
	u32 first_fqid = 0;
	u32 last_fqid = 0;
	char *prevstr = NULL;

	list_for_each_entry_safe(fq, tmp, &priv->dpa_fq_list, list) {
		switch (fq->fq_type) {
		case FQ_TYPE_RX_DEFAULT:
			str = "Rx default";
			break;
		case FQ_TYPE_RX_ERROR:
			str = "Rx error";
			break;
		case FQ_TYPE_RX_PCD:
			str = "Rx PCD";
			break;
		case FQ_TYPE_TX_CONFIRM:
			str = "Tx default confirmation";
			break;
		case FQ_TYPE_TX_CONF_MQ:
			str = "Tx confirmation (mq)";
			break;
		case FQ_TYPE_TX_ERROR:
			str = "Tx error";
			break;
		case FQ_TYPE_TX:
			str = "Tx";
			break;
		default:
			str = "Unknown";
		}

		if (prev && (abs(fq->fqid - prev->fqid) != 1 ||
					str != prevstr)) {
			if (last_fqid == first_fqid)
				bytes += sprintf(buf + bytes,
					"%s: %d\n", prevstr, prev->fqid);
			else
				bytes += sprintf(buf + bytes,
					"%s: %d - %d\n", prevstr,
					first_fqid, last_fqid);
		}

		if (prev && abs(fq->fqid - prev->fqid) == 1 && str == prevstr)
			last_fqid = fq->fqid;
		else
			first_fqid = last_fqid = fq->fqid;

		prev = fq;
		prevstr = str;
		i++;
	}

	if (prev) {
		if (last_fqid == first_fqid)
			bytes += sprintf(buf + bytes, "%s: %d\n", prevstr,
					prev->fqid);
		else
			bytes += sprintf(buf + bytes, "%s: %d - %d\n", prevstr,
					first_fqid, last_fqid);
	}

	return bytes;
}

static ssize_t dpaa_eth_generic_show_bpids(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t bytes = 0;
	struct dpa_generic_priv_s *priv = netdev_priv(to_net_dev(dev));
	struct dpa_bp *rx_bp = priv->rx_bp;
	struct dpa_bp *draining_tx_bp = priv->draining_tx_bp;
	int i = 0;

	bytes += snprintf(buf + bytes, PAGE_SIZE, "Rx buffer pools:\n");
	for (i = 0; i < priv->rx_bp_count; i++)
		bytes += snprintf(buf + bytes, PAGE_SIZE, "%u ",
				rx_bp[i].bpid);

	bytes += snprintf(buf + bytes, PAGE_SIZE, "\n");
	bytes += snprintf(buf + bytes, PAGE_SIZE, "Draining buffer pool:\n");
	bytes += snprintf(buf + bytes, PAGE_SIZE, "%u\n", draining_tx_bp->bpid);

	return bytes;
}

static ssize_t dpaa_eth_generic_show_mac_regs(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct dpa_generic_priv_s *priv = netdev_priv(to_net_dev(dev));
	struct mac_device *mac_dev = priv->mac_dev;
	int n = 0;

	if (mac_dev)
		n = fm_mac_dump_regs(mac_dev, buf, n);
	else
		return sprintf(buf, "no mac control\n");

	return n;
}

static struct device_attribute dpaa_eth_generic_attrs[] = {
	__ATTR(device_addr, S_IRUGO, dpaa_eth_generic_show_addr, NULL),
	__ATTR(device_type, S_IRUGO, dpaa_eth_generic_show_type, NULL),
	__ATTR(fqids, S_IRUGO, dpaa_eth_generic_show_fqids, NULL),
	__ATTR(bpids, S_IRUGO, dpaa_eth_generic_show_bpids, NULL),
	__ATTR(mac_regs, S_IRUGO, dpaa_eth_generic_show_mac_regs, NULL),
};

void dpaa_eth_generic_sysfs_init(struct device *dev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dpaa_eth_generic_attrs); i++)
		if (device_create_file(dev, &dpaa_eth_generic_attrs[i])) {
			dev_err(dev, "Error creating sysfs file\n");
			while (i > 0)
				device_remove_file(dev,
						&dpaa_eth_generic_attrs[--i]);
			return;
		}
}

void dpaa_eth_generic_sysfs_remove(struct device *dev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dpaa_eth_generic_attrs); i++)
		device_remove_file(dev, &dpaa_eth_generic_attrs[i]);
}
