/*
 *
 *  Copyright (C) 2007 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/of_net.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/clk.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>


#include "pfe_mod.h"

struct comcerto_pfe_platform_data pfe_platform_data;



static int pfe_get_gemac_if_proprties(struct device_node *parent, int port, int if_cnt,
					struct comcerto_pfe_platform_data *pdata)
{
	struct device_node *gem = NULL, *phy = NULL;
	int size;
	int ii = 0, phy_id = 0;
	const u32 *addr;
	const void *mac_addr;

	for (ii = 0; ii < if_cnt; ii++) {
		gem = of_get_next_child(parent, gem);
		if (!gem)
			goto err;
		addr = of_get_property(gem, "reg", &size);
		if (addr && (be32_to_cpup(addr) == port))
			break;
	}

	if (ii >= if_cnt) {
		printk(KERN_ERR "%s:%d Failed to find interface = %d\n", __func__, __LINE__, if_cnt);
		goto err;
	}

	pdata->comcerto_eth_pdata[port].gem_id = port;

	mac_addr = of_get_mac_address(gem);

	if (mac_addr) {
		memcpy(pdata->comcerto_eth_pdata[port].mac_addr, mac_addr, ETH_ALEN);
	}

	if ((pdata->comcerto_eth_pdata[port].mii_config = of_get_phy_mode(gem)) < 0)
		printk(KERN_ERR "%s:%d Incorrect Phy mode....\n", __func__, __LINE__);


	addr = of_get_property(gem, "fsl,gemac-bus-id", &size);
	if (!addr)
		printk(KERN_ERR "%s:%d Invalid gemac-bus-id....\n", __func__, __LINE__);
	else
		pdata->comcerto_eth_pdata[port].bus_id = be32_to_cpup(addr);

	addr = of_get_property(gem, "fsl,gemac-phy-id", &size);
	if (!addr)
		printk(KERN_ERR "%s:%d Invalid gemac-phy-id....\n", __func__, __LINE__);
	else
		phy_id = pdata->comcerto_eth_pdata[port].phy_id = be32_to_cpup(addr);

	addr = of_get_property(gem, "fsl,mdio-mux-val", &size);
	if (!addr)
		printk(KERN_ERR "%s: Invalid mdio-mux-val....\n", __func__);
	else
		phy_id = pdata->comcerto_eth_pdata[port].mdio_muxval= be32_to_cpup(addr);


	addr = of_get_property(gem, "fsl,pfe-phy-if-flags", &size);
	if (!addr)
		printk(KERN_ERR "%s:%d Invalid pfe-phy-if-flags....\n", __func__, __LINE__);
	else
		pdata->comcerto_eth_pdata[port].phy_flags = be32_to_cpup(addr);

	addr = of_get_property(gem, "fsl,pfe-gemac-mode", &size);
	if (!addr)
		printk(KERN_ERR "%s:%d Invalid pfe-gemac-mode....\n", __func__, __LINE__);
	else
		pdata->comcerto_eth_pdata[port].gemac_mode = be32_to_cpup(addr);


	/* If PHY is enabled, read mdio properties */
	if (pdata->comcerto_eth_pdata[port].phy_flags & GEMAC_NO_PHY)
		goto done;

	phy = of_get_next_child(gem, NULL);

	addr = of_get_property(phy, "reg", &size);
        
	if (!addr)
		printk(KERN_ERR "%s:%d Invalid phy enable flag....\n", __func__, __LINE__);
	else
		pdata->comcerto_mdio_pdata[port].enabled = be32_to_cpup(addr);

	addr = of_get_property (phy, "fsl,mdio-phy-mask", &size);
	if (!addr)
		printk(KERN_ERR "%s:%d Unable to read mdio-phy-mask....\n", __func__, __LINE__);
	else
		pdata->comcerto_mdio_pdata[port].phy_mask= be32_to_cpup(addr);
	pdata->comcerto_mdio_pdata[port].irq[0] = PHY_POLL;

done:

	return 0;

err:
	return -1;
}
/**
 * pfe_platform_probe -
 *
 *
 */
static int pfe_platform_probe(struct platform_device *pdev)
{
	struct resource res;
	int ii, rc, interface_count = 0, size = 0;
	const u32 *prop;
	struct device_node  *np;

	printk(KERN_INFO "%s %s %s\n", __func__,__DATE__,__TIME__);

	np = pdev->dev.of_node;

	if (!np) {
		printk(KERN_ERR "Invalid device node\n");
		return -EINVAL;
	}

	pfe = kzalloc(sizeof(struct pfe), GFP_KERNEL);
	if (!pfe) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	platform_set_drvdata(pdev, pfe);

	dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));

	if (of_address_to_resource(np, 2, &res))
	{
		rc = -ENOMEM;
		printk(KERN_ERR "failed to get ddr resource\n");
		goto err_ddr;
	}


	pfe->ddr_phys_baseaddr = res.start;
	pfe->ddr_size = resource_size(&res);

	//pfe->ddr_baseaddr = ioremap(res.start, resource_size(&res));
	pfe->ddr_baseaddr = phys_to_virt(res.start);
	if (!pfe->ddr_baseaddr) {
		printk(KERN_ERR "ioremap() ddr failed\n");
		rc = -ENOMEM;
		goto err_ddr;
	}

	/*printk("%s:%d : DDR Res : Phy addr:len = %x:%x Mapped addr : %x\n", __func__, __LINE__, 
						pfe->ddr_phys_baseaddr, pfe->ddr_size, pfe->ddr_baseaddr);*/

	pfe->scfg = syscon_regmap_lookup_by_phandle(pdev->dev.of_node,"fsl,pfe-scfg");
	if (IS_ERR(pfe->scfg)) {
		dev_err(&pdev->dev, "No syscfg phandle specified\n");
		return PTR_ERR(pfe->scfg);
	}
	/*printk("%s scfg %p\n",__func__,pfe->scfg);*/


#if 1
	if (!(pfe->cbus_baseaddr = of_iomap(np, 1)))
	{
		rc = -ENOMEM;
		printk(KERN_ERR "failed to get axi resource\n");
		goto err_axi;
	}

	/*printk("%s:%d : AXI Mapped addr : %lx\n", __func__, __LINE__, pfe->cbus_baseaddr);
	printk("%s:%d : AXI Mapped addr : phys %lx\n", __func__, __LINE__, virt_to_phys(pfe->cbus_baseaddr));*/
#else

	if (of_address_to_resource(np, 1, &res))
	{
		rc = -ENOMEM;
		printk(KERN_ERR "failed to get AXI resource\n");
		goto err_iram;
	}
	pfe->cbus_baseaddr = ioremap(res.start, resource_size(&res));
	if (!pfe->cbus_baseaddr) {
		printk(KERN_INFO "ioremap() AXI failed %lx %x\n", res.start, resource_size(&res));
		rc = -ENOMEM;
		goto err_iram;
	}
	printk("%s:%d : AXI Mapped addr : %x PHY addr = %x\n", __func__, __LINE__, pfe->cbus_baseaddr, res.start);
#endif

	pfe->hif_irq = platform_get_irq(pdev, 0);
	if (pfe->hif_irq < 0) {
		printk(KERN_ERR "platform_get_irq_byname(hif) failed\n");
		rc = pfe->hif_irq;
		goto err_hif_irq;
	}
	/*printk("hif_irq: %d \n", pfe->hif_irq);*/

	/* Read interface count */
	prop = of_get_property(np, "fsl,pfe-num-interfaces", &size);
	if (!prop) {
		printk(KERN_ERR "Failed to read number of interfaces\n");
		rc = -ENXIO;
		goto err_prop;
	}

	interface_count = be32_to_cpup(prop);
	/*printk(KERN_INFO "%s:%d Number of interfaces : %d\n", __func__, __LINE__, interface_count);*/
	if (interface_count <= 0) {
		printk(KERN_ERR "No ethernet interface count : %d\n", interface_count);
		rc = -ENXIO;
		goto err_prop;
	}

	for (ii = 0; ii < interface_count; ii++) {
		pfe_get_gemac_if_proprties(np, ii, interface_count, &pfe_platform_data);
	}


	pfe->dev = &pdev->dev;

	pfe->dev->platform_data = &pfe_platform_data;

	//FIXME get the correct clock from dts 
	pfe->ctrl.sys_clk = 250000;  // save sys_clk value as KHz

	rc = pfe_probe(pfe);
	if (rc < 0)
		goto err_probe;

	return 0;

err_probe:
err_prop:
	/*TODO complet the code */
err_hif_irq:
	iounmap(pfe->cbus_baseaddr);

err_axi:
	iounmap(pfe->ddr_baseaddr);

err_ddr:
	platform_set_drvdata(pdev, NULL);

	kfree(pfe);

err_alloc:
	return rc;
}


/**
 * pfe_platform_remove -
 *
 *
 */
static int pfe_platform_remove(struct platform_device *pdev)
{
	struct pfe *pfe = platform_get_drvdata(pdev);
	int rc;
	
	printk(KERN_INFO "%s\n", __func__);

	rc = pfe_remove(pfe);

	iounmap(pfe->cbus_baseaddr);
	iounmap(pfe->ddr_baseaddr);

	platform_set_drvdata(pdev, NULL);

	kfree(pfe);

	return rc;
}

static struct of_device_id pfe_match[] = {
	{
		.compatible = "fsl,pfe",
	},
	{},
};
MODULE_DEVICE_TABLE(of, pfe_match);

static struct platform_driver pfe_platform_driver = {
	.probe = pfe_platform_probe,
	.remove = pfe_platform_remove,
	.driver = {
		.name = "pfe",
		.of_match_table = pfe_match,
	},
};

#if 0
static int __init pfe_module_init(void)
{
	printk(KERN_INFO "%s\n", __func__);

	return platform_driver_register(&pfe_platform_driver);
}


static void __exit pfe_module_exit(void)
{
	platform_driver_unregister(&pfe_platform_driver);

	printk(KERN_INFO "%s\n", __func__);
}
module_init(pfe_module_init);
module_exit(pfe_module_exit);
#endif

module_platform_driver(pfe_platform_driver);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PFE Ethernet driver");
MODULE_AUTHOR("NXP DNCPE");
