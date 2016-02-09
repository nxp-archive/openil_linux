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
	strncpy(drvinfo->version, VERSION,
		sizeof(drvinfo->driver) - 1)[sizeof(drvinfo->version)-1] = 0;
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

static void __cold dpa_generic_get_ringparam(struct net_device *net_dev,
		struct ethtool_ringparam *et_ringparam)
{
	et_ringparam->rx_max_pending	   = 0;
	et_ringparam->rx_mini_max_pending  = 0;
	et_ringparam->rx_jumbo_max_pending = 0;
	et_ringparam->tx_max_pending	   = 0;

	et_ringparam->rx_pending	   = 0;
	et_ringparam->rx_mini_pending	   = 0;
	et_ringparam->rx_jumbo_pending	   = 0;
	et_ringparam->tx_pending	   = 0;
}

const struct ethtool_ops dpa_generic_ethtool_ops = {
	.get_settings = dpa_generic_get_settings,
	.set_settings = dpa_generic_set_settings,
	.get_drvinfo = dpa_generic_get_drvinfo,
	.get_msglevel = dpa_generic_get_msglevel,
	.set_msglevel = dpa_generic_set_msglevel,
	.nway_reset = dpa_generic_nway_reset,
	.get_ringparam = dpa_generic_get_ringparam,
	.get_link = ethtool_op_get_link,
};
