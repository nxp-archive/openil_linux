// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
/* Copyright 2017-2019 NXP */

#include <linux/module.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include "enetc_pf.h"

#define ENETC_DRV_VER_MAJ 0
#define ENETC_DRV_VER_MIN 8

#define ENETC_DRV_VER_STR __stringify(ENETC_DRV_VER_MAJ) "." \
			  __stringify(ENETC_DRV_VER_MIN)
static const char enetc_drv_ver[] = ENETC_DRV_VER_STR;
#define ENETC_DRV_NAME_STR "ENETC PF driver"
static const char enetc_drv_name[] = ENETC_DRV_NAME_STR;

/* PF driver params */
//module_param(debug, uint, 0000);
static uint prune;
module_param(prune, uint, 0000);

static void enetc_pf_get_primary_mac_addr(struct enetc_hw *hw, int si, u8 *addr)
{
	u32 upper = __raw_readl(hw->port + ENETC_PSIPMAR0(si));
	u16 lower = __raw_readw(hw->port + ENETC_PSIPMAR1(si));

	*(u32 *)addr = upper;
	*(u16 *)(addr + 4) = lower;
}

static void enetc_pf_set_primary_mac_addr(struct enetc_hw *hw, int si,
				       const u8 *addr)
{
	u32 upper = *(const u32 *)addr;
	u16 lower = *(const u16 *)(addr + 4);

	__raw_writel(upper, hw->port + ENETC_PSIPMAR0(si));
	__raw_writew(lower, hw->port + ENETC_PSIPMAR1(si));
}

static void enetc_set_vlan_promisc(struct enetc_hw *hw, char si_map)
{
	u32 val = enetc_port_rd(hw, ENETC_PSIPVMR);

	val &= ~ENETC_PSIPVMR_SET_VP(ENETC_VLAN_PROMISC_MAP_ALL);
	enetc_port_wr(hw, ENETC_PSIPVMR, ENETC_PSIPVMR_SET_VP(si_map) | val);
}

static void enetc_port_setup_primary_mac_address(struct enetc_si *si)
{
	unsigned char mac_addr[MAX_ADDR_LEN];
	struct enetc_pf *pf = enetc_si_priv(si);
	struct enetc_hw *hw = &si->hw;
	int i;

	/* check MAC addresses for PF and all VFs, if any is 0 set it ro rand */
	for (i = 0; i < pf->total_vfs + 1; i++) {
		enetc_pf_get_primary_mac_addr(hw, i, mac_addr);
		if (!is_zero_ether_addr(mac_addr))
			continue;
		eth_random_addr(mac_addr);
		dev_info(&si->pdev->dev, "no MAC address specified for SI%d, using %pM\n",
			 i, mac_addr);
		enetc_pf_set_primary_mac_addr(hw, i, mac_addr);
	}
}

static void enetc_port_alloc_rfs(struct enetc_si *si)
{
	struct enetc_pf *pf = enetc_si_priv(si);
	struct enetc_hw *hw = &si->hw;
	int num_entries, vf_entries, i;

	/* split RFS entries between functions */
	num_entries = enetc_port_rd(hw, ENETC_PRFSCAPR) & 0xf;
	num_entries = 16 * (1 + num_entries);
	vf_entries = num_entries / (pf->total_vfs + 1);

	for (i = 0; i < pf->total_vfs; i++)
		enetc_port_wr(hw, ENETC_PSIRFSCFGR(i + 1), vf_entries);
	enetc_port_wr(hw, ENETC_PSIRFSCFGR(0),
		      num_entries - vf_entries * pf->total_vfs);

	/* enable RFS on port */
	enetc_port_wr(hw, ENETC_PRFSMR, ENETC_PRFSMR_RFSE);
}

static void enetc_port_si_configure(struct enetc_si *si)
{
	struct enetc_pf *pf = enetc_si_priv(si);
	struct enetc_hw *hw = &si->hw;
	int num_rings, i;
	u32 val;

	val = enetc_port_rd(hw, ENETC_PCAPR0);
	num_rings = min(ENETC_PCAPR0_RXBDR(val), ENETC_PCAPR0_TXBDR(val));

	val = ENETC_PSICFGR0_SET_TXBDR(ENETC_PF_NUM_RINGS);
	val |= ENETC_PSICFGR0_SET_RXBDR(ENETC_PF_NUM_RINGS);

	if (unlikely(num_rings < ENETC_PF_NUM_RINGS)) {
		val = ENETC_PSICFGR0_SET_TXBDR(num_rings);
		val |= ENETC_PSICFGR0_SET_RXBDR(num_rings);

		dev_warn(&si->pdev->dev, "Found %d rings, expected %d!\n",
			 num_rings, ENETC_PF_NUM_RINGS);

		num_rings = 0;
	}

	/* Add default one-time settings for SI0 (PF) */
	val |= ENETC_PSICFGR0_SIVC(ENETC_VLAN_TYPE_C | ENETC_VLAN_TYPE_S);
	if (prune)
		val |= ENETC_PSICFGR0_SPE;

	enetc_port_wr(hw, ENETC_PSICFGR0(0), val);

	if (num_rings)
		num_rings -= ENETC_PF_NUM_RINGS;

	/* Configure the SIs for each available VF */
	val = ENETC_PSICFGR0_SIVC(ENETC_VLAN_TYPE_C | ENETC_VLAN_TYPE_S);
	val |= ENETC_PSICFGR0_VTE | ENETC_PSICFGR0_SIVIE;
	if (prune)
		val |= ENETC_PSICFGR0_SPE;

	if (num_rings) {
		num_rings /= pf->total_vfs;
		val |= ENETC_PSICFGR0_SET_TXBDR(num_rings);
		val |= ENETC_PSICFGR0_SET_RXBDR(num_rings);
	}

	for (i = 0; i < pf->total_vfs; i++)
		enetc_port_wr(hw, ENETC_PSICFGR0(i+1), val);

	/* Port level VLAN settings */
	val = ENETC_PVCLCTR_OVTPIDL(ENETC_VLAN_TYPE_C | ENETC_VLAN_TYPE_S);
	enetc_port_wr(hw, ENETC_PVCLCTR, val);
	/* use outer tag for VLAN filtering */
	enetc_port_wr(hw, ENETC_PSIVLANFMR, ENETC_PSIVLANFMR_VS);
}

static void enetc_configure_port_mac(struct enetc_hw *hw)
{
	enetc_port_wr(hw, ENETC_PM0_MAXFRM,
		      ENETC_SET_MAXFRM(ENETC_RX_MAXFRM_SIZE));

	enetc_port_wr(hw, ENETC_PTCMSDUR(0), ENETC_MAC_MAXFRM_SIZE);
	enetc_port_wr(hw, ENETC_PTXMBAR, 2 * ENETC_MAC_MAXFRM_SIZE);

	enetc_port_wr(hw, ENETC_PM0_CMD_CFG, ENETC_PM0_CMD_PHY_TX_EN |
		      ENETC_PM0_CMD_TXP	| ENETC_PM0_PROMISC |
		      ENETC_PM0_TX_EN | ENETC_PM0_RX_EN);

	enetc_port_wr(hw, ENETC_PM1_CMD_CFG, ENETC_PM0_CMD_PHY_TX_EN |
		      ENETC_PM0_CMD_TXP	| ENETC_PM0_PROMISC |
		      ENETC_PM0_TX_EN | ENETC_PM0_RX_EN);
}

static void enetc_configure_port_pmac(struct enetc_hw *hw)
{
	u32 temp;

	/* Set pMAC step lock */
	temp = enetc_port_rd(hw, ENETC_PFPMR);
	enetc_port_wr(hw, ENETC_PFPMR,
			temp|ENETC_PFPMR_PMACE|ENETC_PFPMR_MWLM);

	temp = enetc_port_rd(hw, ENETC_MMCSR);
	enetc_port_wr(hw, ENETC_MMCSR, temp|ENETC_MMCSR_ME);
}

static void enetc_configure_port(struct enetc_pf *pf)
{
	u8 hash_key[ENETC_RSSHASH_KEY_SIZE];
	struct enetc_hw *hw = &pf->si->hw;

	enetc_configure_port_pmac(hw);

	enetc_configure_port_mac(hw);

	enetc_port_si_configure(pf->si);

	/* set up hash key */
	get_random_bytes(hash_key, ENETC_RSSHASH_KEY_SIZE);

	/* split up RFS entries */
	enetc_port_alloc_rfs(pf->si);

	/* fix-up primary MAC addresses, if not set already */
	enetc_port_setup_primary_mac_address(pf->si);

	/* enforce VLAN promisc mode for all SIs */
	pf->vlan_promisc_simap = ENETC_VLAN_PROMISC_MAP_ALL;
	enetc_set_vlan_promisc(hw, pf->vlan_promisc_simap);

	enetc_port_wr(hw, ENETC_PSIPMR, 0);

	/* enable port */
	enetc_port_wr(hw, ENETC_PMR, ENETC_PMR_EN);
}

#ifdef CONFIG_PCI_IOV
static int enetc_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct enetc_si *si = pci_get_drvdata(pdev);
	struct enetc_pf *pf = enetc_si_priv(si);
	int err;

	if (!num_vfs) {
		dev_info(&pdev->dev, "SR-IOV stop\n");
		enetc_msg_psi_free(pf);
		pci_disable_sriov(pdev);
		pf->num_vfs = 0;
	} else {
		dev_info(&pdev->dev, "SR-IOV start, %d VFs\n", num_vfs);
		err = pci_enable_sriov(pdev, num_vfs);
		if (err) {
			dev_err(&pdev->dev, "pci_enable_sriov err %d\n", err);
			return err;
		}

		pf->num_vfs = num_vfs;
		err = enetc_msg_psi_init(pf);
		if (err) {
			dev_err(&pdev->dev, "enetc_msg_psi_init (%d)\n", err);
			goto err_msg_psi;
		}
	}

	return num_vfs;

err_msg_psi:
	pci_disable_sriov(pdev);
	pf->num_vfs = 0;

	return err;
}
#else
#define enetc_sriov_configure(pdev, num_vfs)	(void)0
#endif

static void enetc_pf_netdev_setup(struct enetc_si *si,
		struct rtnet_device *ndev)
{
	struct enetc_netdev_priv *npriv;
	struct enetc_ndev_priv *priv = rtnetdev_priv(ndev);

	/* RTnet: allocate dummy linux netdev structure for phy handling */
	priv->ndev = alloc_etherdev(sizeof(struct enetc_netdev_priv));

	SET_NETDEV_DEV(priv->ndev, &si->pdev->dev);
	npriv = netdev_priv(priv->ndev);
	npriv->rtdev = ndev;
	priv->si = si;
	priv->dev = &si->pdev->dev;
	si->ndev = ndev;
	priv->msg_enable = (NETIF_MSG_WOL << 1) - 1; //TODO: netif_msg_init()
	ndev->features |= NETIF_F_LLTX;

	if (si->errata & ENETC_ERR_TXSG) {
		/* disable Tx SG until final resolution povided by h/w
		 * on Tx fragmentation hang issue
		 */
		ndev->features &= ~NETIF_F_SG;
	}

	ndev->priv_flags |= IFF_UNICAST_FLT;

	/* pick up primary MAC address from SI */
	enetc_get_primary_mac_addr(&si->hw, ndev->dev_addr);
}

static int enetc_of_get_phy(struct enetc_ndev_priv *priv)
{
	struct enetc_pf *pf = enetc_si_priv(priv->si);
	struct device_node *np = priv->dev->of_node;
	int err;

	if (!np) {
		dev_err(priv->dev, "missing ENETC port node\n");
		return -ENODEV;
	}

	priv->phy_node = of_parse_phandle(np, "phy-handle", 0);
	if (!priv->phy_node) {
		if (!of_phy_is_fixed_link(np)) {
			dev_err(priv->dev, "PHY not specified\n");
			return -ENODEV;
		}

		err = of_phy_register_fixed_link(np);
		if (err < 0) {
			dev_err(priv->dev, "fixed link registration failed\n");
			return err;
		}

		priv->phy_node = of_node_get(np);
	}

	if (!of_phy_is_fixed_link(np)) {
		err = enetc_mdio_probe(pf);
		if (err) {
			of_node_put(priv->phy_node);
			return err;
		}
	}

	priv->if_mode = of_get_phy_mode(np);
	if (priv->if_mode < 0) {
		dev_err(priv->dev, "missing phy type\n");
		of_node_put(priv->phy_node);
		if (of_phy_is_fixed_link(np))
			of_phy_deregister_fixed_link(np);
		else
			enetc_mdio_remove(pf);

		return -EINVAL;
	}

	return 0;
}

static void enetc_of_put_phy(struct enetc_ndev_priv *priv)
{
	struct device_node *np = priv->dev->of_node;

	if (np && of_phy_is_fixed_link(np))
		of_phy_deregister_fixed_link(np);
	if (priv->phy_node)
		of_node_put(priv->phy_node);
}


static int enetc_pf_probe(struct pci_dev *pdev,
			  const struct pci_device_id *ent)
{
	struct enetc_ndev_priv *priv;
	struct rtnet_device *ndev;
	struct enetc_si *si;
	struct enetc_pf *pf;
	int err;

	if (pdev->dev.of_node && !of_device_is_available(pdev->dev.of_node)) {
		dev_info(&pdev->dev, "device is disabled, skipping\n");
		return -ENODEV;
	}

	err = enetc_pci_probe(pdev, KBUILD_MODNAME, sizeof(*pf));
	if (err) {
		dev_err(&pdev->dev, "PCI probing failed\n");
		return err;
	}

	si = pci_get_drvdata(pdev);
	if (!si->hw.port || !si->hw.global) {
		err = -ENODEV;
		dev_err(&pdev->dev, "could not map PF space, probing a VF?\n");
		goto err_map_pf_space;
	}

	pf = enetc_si_priv(si);
	pf->si = si;
	pf->total_vfs = pci_sriov_get_totalvfs(pdev);

	enetc_configure_port(pf);

	enetc_get_si_caps(si);

	ndev = rt_alloc_etherdev(sizeof(*priv),
			ENETC_MAX_NUM_TXQS*ENETC_RX_MAXFRM_SIZE*2);
	if (!ndev) {
		err = -ENOMEM;
		dev_err(&pdev->dev, "netdev creation failed\n");
		goto err_alloc_netdev;
	}

	rtdev_alloc_name(ndev, "rteth%d");
	rt_rtdev_connect(ndev, &RTDEV_manager);
	ndev->vers = RTDEV_VERS_2_0;

	enetc_pf_netdev_setup(si, ndev);
	priv = ndev->priv;

	/* construct the net_device struct */
	ndev->open = enetc_open;
	ndev->stop = enetc_close;
	ndev->hard_start_xmit = enetc_xmit;

	enetc_init_si_rings_params(priv);
	err = enetc_alloc_si_resources(priv);
	if (err) {
		dev_err(&pdev->dev, "SI resource alloc failed\n");
		goto err_alloc_si_res;
	}

	err = enetc_alloc_msix(priv);
	if (err) {
		dev_err(&pdev->dev, "MSIX alloc failed\n");
		goto err_alloc_msix;
	}

	err = rt_register_rtnetdev(ndev);
	if (err)
		goto err_reg_netdev;

	err = enetc_setup_irqs(priv);
	if (err)
		goto err_setup_irq;

	err = enetc_of_get_phy(priv);
	if (err)
		dev_warn(&pdev->dev, "Fallback to PHY-less operation\n");

	rtnetif_carrier_on(ndev);

	pr_info("%s v%s\n", enetc_drv_name, enetc_drv_ver);

	return 0;

err_setup_irq:
	rt_unregister_rtnetdev(ndev);
err_reg_netdev:
	enetc_free_msix(priv);
err_alloc_msix:
	enetc_free_si_resources(priv);
err_alloc_si_res:
	si->ndev = NULL;
	rtdev_free(ndev);
err_alloc_netdev:
err_map_pf_space:
	enetc_pci_remove(pdev);

	return err;
}

static void enetc_pf_remove(struct pci_dev *pdev)
{
	struct enetc_si *si = pci_get_drvdata(pdev);
	struct enetc_pf *pf = enetc_si_priv(si);
	struct enetc_ndev_priv *priv;

	if (pf->num_vfs)
		enetc_sriov_configure(pdev, 0);

	priv = rtnetdev_priv(si->ndev);
	pr_info("%s v%s remove\n",
		   enetc_drv_name, enetc_drv_ver);
	rt_unregister_rtnetdev(si->ndev);

	if (pdev->dev.of_node && of_phy_is_fixed_link(pdev->dev.of_node))
		of_phy_deregister_fixed_link(pdev->dev.of_node);
	if (priv->phy_node)
		of_node_put(priv->phy_node);

	enetc_free_irqs(priv);
	enetc_free_msix(priv);

	enetc_free_si_resources(priv);

	rtdev_free(si->ndev);
	free_netdev(priv->ndev);

	enetc_pci_remove(pdev);
}

static const struct pci_device_id enetc_pf_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, ENETC_DEV_ID_PF) },
	{ 0, } /* End of table. */
};
MODULE_DEVICE_TABLE(pci, enetc_pf_id_table);

static struct pci_driver enetc_pf_driver = {
	.name = KBUILD_MODNAME,
	.id_table = enetc_pf_id_table,
	.probe = enetc_pf_probe,
	.remove = enetc_pf_remove,
#ifdef CONFIG_PCI_IOV
	.sriov_configure = enetc_sriov_configure,
#endif
};
module_pci_driver(enetc_pf_driver);

MODULE_DESCRIPTION(ENETC_DRV_NAME_STR);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(ENETC_DRV_VER_STR);
