
#include <linux/module.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_vlan.h>

#include <uapi/linux/if_bridge.h>
#include <net/netlink.h>
#include "../../fsl-mc/include/mc.h"
#include "../../fsl-mc/include/mc-sys.h"

#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/phy.h>
#include <linux/phy_fixed.h>

#include "../../fsl-mc/include/dpmac.h"
#include "../../fsl-mc/include/dpmac-cmd.h"


/* big TODOs:
 * mac stats
 */

struct phy_device *fixed_phy_register2(unsigned int irq,
				       struct fixed_phy_status *status,
				       struct device_node *np);


struct ppx_priv {
	struct net_device		*netdev;
	struct fsl_mc_device		*mc_dev;
	struct dpmac_attr		attr;
};

/* TODO: fix the 10G modes, mapping can't be right:
 *  XGMII is paralel
 *  XAUI is serial, using 8b/10b encoding
 *  XFI is also serial but using 64b/66b encoding
 * they can't all map to XGMII...
 */
static phy_interface_t ppx_eth_iface_mode[] __maybe_unused =  {
	/* DPMAC_ETH_IF_MII */
	PHY_INTERFACE_MODE_MII,
	/* DPMAC_ETH_IF_RMII */
	PHY_INTERFACE_MODE_RMII,
	/* DPMAC_ETH_IF_SMII */
	PHY_INTERFACE_MODE_SMII,
	/* DPMAC_ETH_IF_GMII */
	PHY_INTERFACE_MODE_GMII,
	/* DPMAC_ETH_IF_RGMII */
	PHY_INTERFACE_MODE_RGMII,
	/* DPMAC_ETH_IF_SGMII */
	PHY_INTERFACE_MODE_SGMII,
	/* DPMAC_ETH_IF_XGMII */
	PHY_INTERFACE_MODE_XGMII,
	/* DPMAC_ETH_IF_QSGMII */
	PHY_INTERFACE_MODE_QSGMII,
	/* DPMAC_ETH_IF_XAUI */
	PHY_INTERFACE_MODE_XGMII,
	/* DPMAC_ETH_IF_XFI */
	PHY_INTERFACE_MODE_XGMII,

};

static void ppx_link_changed(struct net_device *netdev);

#ifdef CONFIG_FSL_DPAA2_PPX_NETDEVS
static netdev_tx_t ppx_dropframe(struct sk_buff *skb, struct net_device *dev);
static int ppx_open(struct net_device *netdev);
static int ppx_stop(struct net_device *netdev);
static struct rtnl_link_stats64 *ppx_get_stats(struct net_device *,
					       struct rtnl_link_stats64 *);

static int ppx_ethtool_get_settings(struct net_device *, struct ethtool_cmd *);
static int ppx_ethtool_set_settings(struct net_device *, struct ethtool_cmd *);
static int ppx_ethtool_get_sset_count(struct net_device *dev, int sset);
static void ppx_ethtool_get_strings(struct net_device *, u32 stringset, u8 *);
static void ppx_ethtool_get_stats(struct net_device *, struct ethtool_stats *,
				  u64 *);

static const struct net_device_ops ppx_ndo = {
	.ndo_start_xmit		= &ppx_dropframe,
	/* TODO: temporary to force fixed links up and down */
	.ndo_open		= &ppx_open,
	.ndo_stop		= &ppx_stop,
	.ndo_get_stats64	= &ppx_get_stats,
};

static const struct ethtool_ops ppx_ethtool_ops = {
	.get_settings		= &ppx_ethtool_get_settings,
	.set_settings		= &ppx_ethtool_set_settings,
	.get_strings		= &ppx_ethtool_get_strings,
	.get_ethtool_stats	= &ppx_ethtool_get_stats,
	.get_sset_count		= &ppx_ethtool_get_sset_count,
};

static netdev_tx_t ppx_dropframe(struct sk_buff *skb, struct net_device *dev)
{
	/* we don't support I/O for now, drop the frame */
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int ppx_open(struct net_device *netdev)
{
	/* force PHY up */
	phy_start(netdev->phydev);

	return 0;
}

static int ppx_stop(struct net_device *netdev)
{
	/* force PHY down */
	phy_stop(netdev->phydev);

	return 0;
}

static int ppx_ethtool_get_settings(struct net_device *netdev,
				    struct ethtool_cmd *cmd)
{
	return phy_ethtool_gset(netdev->phydev, cmd);
}

static int ppx_ethtool_set_settings(struct net_device *netdev,
				    struct ethtool_cmd *cmd)
{
	return phy_ethtool_sset(netdev->phydev, cmd);
}

static struct rtnl_link_stats64
*ppx_get_stats(struct net_device *netdev, struct rtnl_link_stats64 *storage)
{
	struct ppx_priv		*priv = netdev_priv(netdev);
	u64			tmp;
	int			err;

	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_EGR_MCAST_FRAME,
				&storage->tx_packets);
	if (err)
		goto error;
	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_EGR_BCAST_FRAME, &tmp);
	if (err)
		goto error;
	storage->tx_packets += tmp;
	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_EGR_UCAST_FRAME, &tmp);
	if (err)
		goto error;
	storage->tx_packets += tmp;

	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_EGR_UNDERSIZED, &storage->tx_dropped);
	if (err)
		goto error;
	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_EGR_BYTE, &storage->tx_bytes);
	if (err)
		goto error;
	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_EGR_ERR_FRAME, &storage->tx_errors);
	if (err)
		goto error;

	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_ING_ALL_FRAME, &storage->rx_packets);
	if (err)
		goto error;
	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_ING_MCAST_FRAME, &storage->multicast);
	if (err)
		goto error;
	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_ING_FRAME_DISCARD,
				&storage->rx_dropped);
	if (err)
		goto error;
	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_ING_ALIGN_ERR, &storage->rx_errors);
	if (err)
		goto error;
	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_ING_OVERSIZED, &tmp);
	if (err)
		goto error;
	storage->rx_errors += tmp;
	err = dpmac_get_counter(priv->mc_dev->mc_io, priv->mc_dev->mc_handle,
				DPMAC_CNT_ING_BYTE, &storage->rx_bytes);
	if (err)
		goto error;

	return storage;

error:
	netdev_err(netdev, "dpmac_get_counter err %d\n", err);
	return storage;
}

static struct {
	enum dpmac_counter id;
	char name[ETH_GSTRING_LEN];
} ppx_ethtool_counters[] =  {
	{DPMAC_CNT_ING_ALL_FRAME,		"rx all frames"},
	{DPMAC_CNT_ING_GOOD_FRAME,		"rx frames ok"},
	{DPMAC_CNT_ING_ERR_FRAME,		"rx frame errors"},
	{DPMAC_CNT_ING_FRAME_DISCARD,		"rx frame discards"},
	{DPMAC_CNT_ING_UCAST_FRAME,		"rx u-cast"},
	{DPMAC_CNT_ING_BCAST_FRAME,		"rx b-cast"},
	{DPMAC_CNT_ING_MCAST_FRAME,		"rx m-cast"},
	{DPMAC_CNT_ING_FRAME_64,		"rx 64 bytes"},
	{DPMAC_CNT_ING_FRAME_127,		"rx 65-127 bytes"},
	{DPMAC_CNT_ING_FRAME_255,		"rx 128-255 bytes"},
	{DPMAC_CNT_ING_FRAME_511,		"rx 256-511 bytes"},
	{DPMAC_CNT_ING_FRAME_1023,		"rx 512-1023 bytes"},
	{DPMAC_CNT_ING_FRAME_1518,		"rx 1024-1518 bytes"},
	{DPMAC_CNT_ING_FRAME_1519_MAX,		"rx 1519-max bytes"},
	{DPMAC_CNT_ING_FRAG,			"rx frags"},
	{DPMAC_CNT_ING_JABBER,			"rx jabber"},
	{DPMAC_CNT_ING_ALIGN_ERR,		"rx align errors"},
	{DPMAC_CNT_ING_OVERSIZED,		"rx oversized"},
	{DPMAC_CNT_ING_VALID_PAUSE_FRAME,	"rx pause"},
	{DPMAC_CNT_ING_BYTE,			"rx bytes"},
	{DPMAC_CNT_EGR_UCAST_FRAME,		"tx u-cast"},
	{DPMAC_CNT_EGR_MCAST_FRAME,		"tx m-cast"},
	{DPMAC_CNT_EGR_BCAST_FRAME,		"tx b-cast"},
	{DPMAC_CNT_EGR_ERR_FRAME,		"tx frame errors"},
	{DPMAC_CNT_EGR_UNDERSIZED,		"tx undersized"},
	{DPMAC_CNT_EGR_VALID_PAUSE_FRAME,	"tx b-pause"},
	{DPMAC_CNT_EGR_BYTE,			"tx bytes"},

};

static void ppx_ethtool_get_strings(struct net_device *netdev,
				    u32 stringset, u8 *data)
{
	int i;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < ARRAY_SIZE(ppx_ethtool_counters); i++)
			memcpy(data + i * ETH_GSTRING_LEN,
			       ppx_ethtool_counters[i].name, ETH_GSTRING_LEN);
		break;
	}
}

static void ppx_ethtool_get_stats(struct net_device *netdev,
				  struct ethtool_stats *stats,
				  u64 *data)
{
	struct ppx_priv		*priv = netdev_priv(netdev);
	int			i;
	int			err;

	for (i = 0; i < ARRAY_SIZE(ppx_ethtool_counters); i++) {
		err = dpmac_get_counter(priv->mc_dev->mc_io,
					priv->mc_dev->mc_handle,
					ppx_ethtool_counters[i].id, &data[i]);
		if (err)
			netdev_err(netdev, "dpmac_get_counter[%s] err %d\n",
				   ppx_ethtool_counters[i].name, err);
	}
}

static int ppx_ethtool_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(ppx_ethtool_counters);
	default:
		return -EOPNOTSUPP;
	}
}
#endif /* CONFIG_FSL_DPAA2_PPX_NETDEVS */

#ifdef CONFIG_FSL_DPAA2_FIXED_PHY_HACK
static struct phy_device *ppx_register_fixed_link(struct net_device *netdev)
{
	struct fixed_phy_status status = {
		.link = 1,
		.speed = 100,
		.duplex = 0,
	};
	struct phy_device *phy;
	int err;

	phy = fixed_phy_register2(PHY_POLL, &status, NULL);
	if (!phy)
		return NULL;
	/* disable aneg to let the user fake speeds */
	phy->autoneg = 0;

	/* TODO: interface mode */
	err = phy_connect_direct(netdev, phy, &ppx_link_changed,
				 PHY_INTERFACE_MODE_NA);
	if (err) {
		netdev_err(netdev, "phy_connect_direct err %d\n", err);
		return NULL;
	}

	return phy;
}
#endif /* CONFIG_FSL_DPAA2_FIXED_PHY_HACK */

static void ppx_link_changed(struct net_device *netdev)
{
	struct phy_device	*phydev;
	struct dpmac_link_state	state = { 0 };
	struct ppx_priv		*priv = netdev_priv(netdev);
	int			err;

	/* the PHY just notified us of link state change */
	/* TODO: maybe check that link state actually changed */
	phydev = netdev->phydev;

	state.up = !!phydev->link;
	if (phydev->link) {
		state.rate = phydev->speed;

		if (!phydev->duplex)
			state.options |= DPMAC_LINK_OPT_HALF_DUPLEX;
		if (phydev->autoneg)
			state.options |= DPMAC_LINK_OPT_AUTONEG;
	}
	/* this prints out roughly every second while polling, don't enable
	 * unless absolutely necessary.
	 * phy_print_status(phydev);
	 */

	err = dpmac_set_link_state(priv->mc_dev->mc_io,
				   priv->mc_dev->mc_handle, &state);
	if (err)
		dev_err(&netdev->dev, "dpmac_set_link_state err %d\n", err);
}

static int ppx_configure_link(struct ppx_priv *priv, struct dpmac_link_cfg *cfg)
{
	struct phy_device *phydev = priv->netdev->phydev;

	/* TODO: sanity checks? */
	/* like null PHY :) ignore that error for now */
	if (!phydev) {
		netdev_warn(priv->netdev,
			    "asked to change PHY settings but PHY ref is NULL, ignoring\n");
		return 0;
	}

	phydev->speed = cfg->rate;
	phydev->duplex  = !!(cfg->options & DPMAC_LINK_OPT_HALF_DUPLEX);

	if (cfg->options & DPMAC_LINK_OPT_AUTONEG) {
		phydev->autoneg = 1;
		phydev->advertising |= ADVERTISED_Autoneg;
	} else {
		phydev->autoneg = 0;
		phydev->advertising &= ~ADVERTISED_Autoneg;
	}

	phy_start_aneg(phydev);

	return 0;
}

static irqreturn_t ppx_irq_handler(int irq_num, void *arg)
{
	struct device *dev = (struct device *)arg;
	struct fsl_mc_device *mc_dev = to_fsl_mc_device(dev);
	struct ppx_priv *priv = dev_get_drvdata(dev);
	struct dpmac_link_cfg link_cfg;
	int err;

	dev_dbg(dev, "DPMAC IRQ %d\n", irq_num);
	if (mc_dev->irqs[0]->irq_number != irq_num) {
		dev_err(dev, "received unexpected interrupt %d!\n", irq_num);
		goto err;
	}

	err = dpmac_get_link_cfg(mc_dev->mc_io,
				 priv->mc_dev->mc_handle, &link_cfg);
	if (err) {
		dev_err(dev, "dpmac_get_link_cfg err %d\n", err);
		goto err;
	}

	err = ppx_configure_link(priv, &link_cfg);
	if (err)
		goto err;

	err = dpmac_clear_irq_status(mc_dev->mc_io,
				     priv->mc_dev->mc_handle,
				     0, DPMAC_IRQ_EVENT_LINK_CFG_REQ);
	if (err < 0) {
		dev_err(&mc_dev->dev,
			"dpmac_clear_irq_status() err %d\n", err);
	}

	return IRQ_HANDLED;

err:
	dev_warn(dev, "DPMAC IRQ %d was not handled!\n", irq_num);
	return IRQ_NONE;
}

static int ppx_setup_irqs(struct fsl_mc_device *mc_dev)
{
	static const struct fsl_mc_irq_ops dprc_irq_ops = {
		.mc_set_irq_enable = dpmac_set_irq_enable,
		.mc_clear_irq_status = dpmac_clear_irq_status,
		.mc_set_irq = dpmac_set_irq,
		.mc_set_irq_mask = dpmac_set_irq_mask,
	};

	const struct fsl_mc_irq_config irq_config = {
		.irq_handler = NULL,
		.irq_handler_thread = ppx_irq_handler,
		.irq_name = "FSL MC DPMAC irq0",
		.irq_mask = DPMAC_IRQ_EVENT_LINK_CFG_REQ,
		.data = &mc_dev->dev,
	};
	int err;

	if (mc_dev->obj_desc.irq_count != 1) {
		dev_err(&mc_dev->dev,
			"expected one interrupt, but the device has %d!\n",
			mc_dev->obj_desc.irq_count);
		return -EINVAL;
	}

	err = fsl_mc_setup_irqs(mc_dev, &dprc_irq_ops);
	if (err < 0)
		return err;

	err = fsl_mc_configure_irq(mc_dev, 0, &irq_config);
	if (err < 0)
		return err;

	return 0;
}

static int __cold
ppx_probe(struct fsl_mc_device *mc_dev)
{
	struct device		*dev;
	struct ppx_priv		*priv = NULL;
	struct device_node	*phy_node;
	struct net_device	*netdev;
	/*phy_interface_t		if_mode;*/
	int			err = 0;
	/* HACK */
	static char phy_name[255];
	static int phy_cnt;

	/* just being completely paranoid */
	if (!mc_dev)
		return -EFAULT;

	dev = &mc_dev->dev;

	/* prepare a net_dev structure to make the phy lib API happy */
	netdev = alloc_etherdev(sizeof(*priv));
	if (!netdev) {
		dev_err(dev, "alloc_etherdev error\n");
		err = -ENOMEM;
		goto err_exit;
	}
	priv = netdev_priv(netdev);
	priv->mc_dev = mc_dev;
	priv->netdev = netdev;

	SET_NETDEV_DEV(netdev, dev);
	/* MDIO ID would be better, but we can do that later */
	snprintf(netdev->name, IFNAMSIZ, "phy%d", mc_dev->obj_desc.id);

	dev_set_drvdata(dev, priv);

	err = fsl_mc_portal_allocate(mc_dev, FSL_MC_IO_PORTAL_SHARED,
				     &mc_dev->mc_io);
	if (err) {
		dev_err(dev, "fsl_mc_portal_allocate err %d\n", err);
		goto err_free_netdev;
	}
	if (!mc_dev->mc_io) {
		dev_err(dev,
			"fsl_mc_portal_allocate returned null handle but no error\n");
		goto err_free_netdev;
	}

	err = dpmac_open(mc_dev->mc_io, mc_dev->obj_desc.id,
			 &mc_dev->mc_handle);
	if (err) {
		dev_err(dev, "dpmac_open err %d\n", err);
		goto err_free_mcp;
	}
	if (!mc_dev->mc_handle) {
		dev_err(dev, "dpmac_open returned null handle but no error\n");
		err = -EFAULT;
		goto err_free_mcp;
	}

	err = dpmac_get_attributes(mc_dev->mc_io,
				   mc_dev->mc_handle, &priv->attr);
	if (err) {
		dev_err(dev, "dpmac_get_attributes err %d\n", err);
		goto err_close;
	}

	err = ppx_setup_irqs(mc_dev);
	if (err)
		goto err_close;

#ifdef CONFIG_FSL_DPAA2_PPX_NETDEVS
	/* OPTIONAL, register netdev just to make it visible to the user */
	netdev->netdev_ops = &ppx_ndo;
	netdev->ethtool_ops = &ppx_ethtool_ops;

	err = register_netdev(priv->netdev);
	if (err < 0) {
		dev_err(dev, "register_netdev error %d\n", err);
		goto err_free_irq;
	}
#endif /* CONFIG_FSL_DPAA2_PPX_NETDEVS */

	/* try to connect to the PHY */
	/* phy_node = of_find_node_by_phandle(priv->attr.phy_id); */
	sprintf(phy_name, "mdio_phy%d", phy_cnt);
	phy_node = of_find_node_by_name(NULL, phy_name);
	if (!phy_node) {
		dev_err(dev, "PHY node %s not found, trying another...\n",
			phy_name);

		sprintf(phy_name, "ethernet-phy@%d", phy_cnt);
		phy_node = of_find_node_by_name(NULL, phy_name);
		if (!phy_node) {
			dev_err(dev, "PHY node %s not found, looking for phandle 0x%0x\n",
				phy_name,
				priv->attr.phy_id);
			err = -EFAULT;
			goto err_no_phy;
		}
	}
	pr_info("dpmac %d -> phy %d (%s)\n", priv->attr.id, phy_cnt, phy_name);
	phy_cnt++;
/*
	if (priv->attr.eth_if <
	    sizeof(ppx_eth_iface_mode) / sizeof(ppx_eth_iface_mode[0])) {
		if_mode = ppx_eth_iface_mode[priv->attr.eth_if];
		dev_info(dev, "\tusing if mode %s for eth_if %d\n",
			 phy_modes(if_mode), priv->attr.eth_if);
	} else {
		if_mode = PHY_INTERFACE_MODE_NA;
		dev_warn(dev, "unexpected interface mode %d\n",
			 priv->attr.eth_if);
	}
	netdev->phydev = of_phy_connect(netdev, phy_node, &ppx_link_changed,
					0, if_mode);
*/
	netdev->phydev = of_phy_connect(netdev, phy_node, &ppx_link_changed,
					0, PHY_INTERFACE_MODE_SGMII);
	if (!netdev->phydev) {
		dev_err(dev,
			"ERROR: of_phy_connect returned NULL\n");
		err = -EFAULT;
		goto err_no_phy;
	}

	dev_info(dev, "found a PHY!\n");
	return 0;

err_no_phy:
#ifdef CONFIG_FSL_DPAA2_FIXED_PHY_HACK
	netdev->phydev = ppx_register_fixed_link(netdev);
	if (!netdev->phydev) {
		dev_err(dev, "error trying to register fixed PHY!\n");
		err = -EFAULT;
		goto err_free_irq;
	}

	dev_info(dev, "registered fixed PHY!\n");
	return 0;
#endif /* CONFIG_FSL_DPAA2_FIXED_PHY_HACK */

err_free_irq:
	fsl_mc_teardown_irqs(mc_dev);
err_close:
	dpmac_close(mc_dev->mc_io, mc_dev->mc_handle);
err_free_mcp:
	fsl_mc_portal_free(mc_dev->mc_io);
err_free_netdev:
	free_netdev(netdev);
err_exit:
	return err;
}

static int __cold
ppx_remove(struct fsl_mc_device *devppx)
{
	struct device		*dev = &devppx->dev;
	struct ppx_priv		*priv = dev_get_drvdata(dev);

	unregister_netdev(priv->netdev);
	fsl_mc_teardown_irqs(priv->mc_dev);
	dpmac_close(priv->mc_dev->mc_io, priv->mc_dev->mc_handle);
	fsl_mc_portal_free(priv->mc_dev->mc_io);
	free_netdev(priv->netdev);

	dev_set_drvdata(dev, NULL);
	kfree(priv);

	return 0;
}

static const struct fsl_mc_device_match_id ppx_match_id_table[] = {
	{
		.vendor = FSL_MC_VENDOR_FREESCALE,
		.obj_type = "dpmac",
		.ver_major = DPMAC_VER_MAJOR,
		.ver_minor = DPMAC_VER_MINOR,
	},
	{}
};

static struct fsl_mc_driver ppx_drv = {
	.driver = {
		.name		= KBUILD_MODNAME,
		.owner		= THIS_MODULE,
	},
	.probe		= ppx_probe,
	.remove		= ppx_remove,
	.match_id_table = ppx_match_id_table,
};

module_fsl_mc_driver(ppx_drv);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DPAA2 PHY proxy interface driver (prototype)");
