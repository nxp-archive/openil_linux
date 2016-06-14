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
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/clk.h>

#include "pfe_mod.h"

/**
 * pfe_platform_probe -
 *
 *
 */
static int pfe_platform_probe(struct platform_device *pdev)
{
	struct resource *r;
	int rc;
	struct clk *clk_axi;

	printk(KERN_INFO "%s\n", __func__);

	pfe = kzalloc(sizeof(struct pfe), GFP_KERNEL);
	if (!pfe) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	platform_set_drvdata(pdev, pfe);

	r = platform_get_resource_byname(pdev, IORESOURCE_MEM, "ddr");
	if (!r) {
		printk(KERN_INFO "platform_get_resource_byname(ddr) failed\n");
		rc = -ENXIO;
		goto err_ddr;
	}
	
	pfe->ddr_phys_baseaddr = r->start;
	pfe->ddr_size = resource_size(r);

	pfe->ddr_baseaddr = ioremap(r->start, resource_size(r));
	if (!pfe->ddr_baseaddr) {
		printk(KERN_INFO "ioremap() ddr failed\n");
		rc = -ENOMEM;
		goto err_ddr;
	}
	
	r = platform_get_resource_byname(pdev, IORESOURCE_MEM, "axi");
	if (!r) {
		printk(KERN_INFO "platform_get_resource_byname(axi) failed\n");
		rc = -ENXIO;
		goto err_axi;
	}

	pfe->cbus_baseaddr = ioremap(r->start, resource_size(r));
	if (!pfe->cbus_baseaddr) {
		printk(KERN_INFO "ioremap() axi failed\n");
		rc = -ENOMEM;
		goto err_axi;
	}

	r = platform_get_resource_byname(pdev, IORESOURCE_MEM, "apb");
	if (!r) {
		printk(KERN_INFO "platform_get_resource_byname(apb) failed\n");
		rc = -ENXIO;
		goto err_apb;
	}

	pfe->apb_baseaddr = ioremap(r->start, resource_size(r));
	if (!pfe->apb_baseaddr) {
		printk(KERN_INFO "ioremap() apb failed\n");
		rc = -ENOMEM;
		goto err_apb;
	}

	r = platform_get_resource_byname(pdev, IORESOURCE_MEM, "iram");
	if (!r) {
		printk(KERN_INFO "platform_get_resource_byname(iram) failed\n");
		rc = -ENXIO;
		goto err_iram;
	}

	pfe->iram_phys_baseaddr = r->start;
	pfe->iram_baseaddr = ioremap(r->start, resource_size(r));
	if (!pfe->iram_baseaddr) {
		printk(KERN_INFO "ioremap() iram failed\n");
		rc = -ENOMEM;
		goto err_iram;
	}

        r = platform_get_resource_byname(pdev, IORESOURCE_MEM, "ipsec");
        if (!r) {
                printk(KERN_INFO "platform_get_resource_byname(ipsec) failed\n");
                rc = -ENXIO;
                goto err_ipsec;
        }

        pfe->ipsec_phys_baseaddr = r->start;
	/* Just map only initial 1MB , as its enough to access espah engine
	*/
        //pfe->ipsec_baseaddr = ioremap(r->start, resource_size(r));
        pfe->ipsec_baseaddr = ioremap(r->start, 1*1024*1024);
        if (!pfe->ipsec_baseaddr) {
                printk(KERN_INFO "ioremap() ipsec failed\n");
                rc = -ENOMEM;
                goto err_ipsec;
        }

        printk(KERN_INFO "ipsec: baseaddr :%x --- %x\n",  (u32)pfe->ipsec_phys_baseaddr,  (u32)pfe->ipsec_baseaddr);

	pfe->hif_irq = platform_get_irq_byname(pdev, "hif");
	if (pfe->hif_irq < 0) {
		printk(KERN_INFO "platform_get_irq_byname(hif) failed\n");
		rc = pfe->hif_irq;
		goto err_hif_irq;
	}

#if 0
	pfe->hif_client_irq = platform_get_irq_byname(pdev, "hif_client");
	if (pfe->hif_client_irq < 0) {
		printk(KERN_INFO "platform_get_irq_byname(hif_client) failed\n");
		rc = pfe->hif_client_irq;
		goto err_hif_irq;
	}
#endif

	pfe->dev = &pdev->dev;


	/* Get the system clock */
	clk_axi = clk_get(NULL,"axi");
	if (IS_ERR(clk_axi)) {
		printk(KERN_INFO "clk_get call failed\n");
		rc = -ENXIO;
		goto err_clk;
	}

	/* HFE core clock */
	pfe->hfe_clock = clk_get(NULL, "hfe_core");
	if (IS_ERR(pfe->hfe_clock)) {
		printk(KERN_INFO "clk_get call failed\n");
		rc = -ENXIO;
		goto err_hfe_clock;
	}

	clk_disable(pfe->hfe_clock);
	c2000_block_reset(COMPONENT_PFE_SYS, 1);
	mdelay(1);
	c2000_block_reset(COMPONENT_PFE_SYS, 0);
	clk_enable(pfe->hfe_clock);

	pfe->ctrl.clk_axi = clk_axi;
	pfe->ctrl.sys_clk = clk_get_rate(clk_axi) / 1000;  // save sys_clk value as KHz

	rc = pfe_probe(pfe);
	if (rc < 0)
		goto err_probe;

	return 0;

err_probe:
	clk_put(pfe->hfe_clock);
err_hfe_clock:
	clk_put(clk_axi);
err_clk:
err_hif_irq:
        iounmap(pfe->ipsec_baseaddr);
err_ipsec:
	iounmap(pfe->iram_baseaddr);
err_iram:
	iounmap(pfe->apb_baseaddr);

err_apb:
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

	c2000_block_reset(COMPONENT_PFE_SYS, 1);
	clk_disable(pfe->hfe_clock);
	clk_put(pfe->hfe_clock);
	clk_put(pfe->ctrl.clk_axi);
	iounmap(pfe->ipsec_baseaddr);
	iounmap(pfe->iram_baseaddr);
	iounmap(pfe->apb_baseaddr);
	iounmap(pfe->cbus_baseaddr);
	iounmap(pfe->ddr_baseaddr);

	platform_set_drvdata(pdev, NULL);

	kfree(pfe);

	return rc;
}

#ifdef CONFIG_PM

#ifdef CONFIG_PM_SLEEP
static int pfe_platform_suspend(struct device *dev)
{
	struct pfe *pfe = platform_get_drvdata(to_platform_device(dev));
	struct net_device *netdev;
	int i;

	printk(KERN_INFO "%s\n", __func__);

	pfe->wake = 0;

	for (i = 0; i < (NUM_GEMAC_SUPPORT - 1); i++ ) {
		netdev = pfe->eth.eth_priv[i]->dev;

		netif_device_detach(netdev);

		if (netif_running(netdev))
			if(pfe_eth_suspend(netdev))
				pfe->wake =1;
	}

	/* Shutdown PFE only if we're not waking up the system */
	if (!pfe->wake) {
		pfe_ctrl_suspend(&pfe->ctrl);
		pfe_hif_exit(pfe);
		pfe_hif_lib_exit(pfe);

		class_disable();
		tmu_disable(0xf);
#if !defined(CONFIG_UTIL_DISABLED)
		util_disable();
#endif
		pfe_hw_exit(pfe);
		c2000_block_reset(COMPONENT_PFE_SYS, 1);
		clk_disable(pfe->hfe_clock);
	}

	return 0;
}

static int pfe_platform_resume(struct device *dev)
{
	struct pfe *pfe = platform_get_drvdata(to_platform_device(dev));
	struct net_device *netdev;
	int i;

	printk(KERN_INFO "%s\n", __func__);

	if (!pfe->wake) {
		/* Sequence follows VLSI recommendation (bug 71927) */
		c2000_block_reset(COMPONENT_PFE_SYS, 1);
		mdelay(1);
		c2000_block_reset(COMPONENT_PFE_SYS, 0);
		clk_enable(pfe->hfe_clock);

		pfe_hw_init(pfe, 1);
		pfe_hif_lib_init(pfe);
		pfe_hif_init(pfe);
#if !defined(CONFIG_UTIL_DISABLED)
		util_enable();
#endif
		tmu_enable(0xf);
		class_enable();
		pfe_ctrl_resume(&pfe->ctrl);
	}

	for(i = 0; i < (NUM_GEMAC_SUPPORT - 1); i++) {
		netdev = pfe->eth.eth_priv[i]->dev;

		if (pfe->eth.eth_priv[i]->mii_bus)
			pfe_eth_mdio_reset(pfe->eth.eth_priv[i]->mii_bus);

		if (netif_running(netdev))
			pfe_eth_resume(netdev);

		netif_device_attach(netdev);
	}
	return 0;
}
#else
#define pfe_platform_suspend NULL
#define pfe_platform_resume NULL
#endif

static const struct dev_pm_ops pfe_platform_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(pfe_platform_suspend, pfe_platform_resume)
};

#endif

static struct platform_driver pfe_platform_driver = {
	.probe = pfe_platform_probe,
	.remove = pfe_platform_remove,
	.driver = {
		.name = "pfe",
#ifdef CONFIG_PM
		.pm = &pfe_platform_pm_ops,
#endif
	},
};


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

MODULE_LICENSE("GPL");
module_init(pfe_module_init);
module_exit(pfe_module_exit);
