/*
 * Freescale LayerScape reboot driver
 *
 * Copyright (c) 2015, Freescale Semiconductor.
 * Author: Pankaj Chauhan <pankaj.chauhan@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/io.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <asm/system_misc.h>

struct	ls_reboot_priv {
	struct device *dev;
	u32 *rstcr;
	bool is_big_endian;
};

static struct ls_reboot_priv	*ls_reboot_priv;

static void ls_reboot(enum reboot_mode reboot_mode, const char *cmd)
{
	struct ls_reboot_priv	*priv = ls_reboot_priv;
	u32 val;
	unsigned long timeout;

	if (ls_reboot_priv) {
		if (priv->is_big_endian) {
			val = ioread32be(priv->rstcr);
			val |= 0x02;
			iowrite32be(val, priv->rstcr);
		} else {
			val = readl(priv->rstcr);
			val |= 0x02;
			writel(val, priv->rstcr);
		}
	}

	timeout = jiffies + HZ;
	while (time_before(jiffies, timeout))
		cpu_relax();

}

static int ls_reboot_probe(struct platform_device *pdev)
{
	ls_reboot_priv = devm_kzalloc(&pdev->dev,
				sizeof(*ls_reboot_priv), GFP_KERNEL);
	if (!ls_reboot_priv) {
		dev_err(&pdev->dev, "out of memory for context\n");
		return -ENODEV;
	}

	ls_reboot_priv->rstcr = of_iomap(pdev->dev.of_node, 0);
	if (!ls_reboot_priv->rstcr) {
		devm_kfree(&pdev->dev, ls_reboot_priv);
		dev_err(&pdev->dev, "can not map resource\n");
		return -ENODEV;
	}

	if (of_get_property(pdev->dev.of_node, "big-endian", NULL))
		ls_reboot_priv->is_big_endian = true;
	else
		ls_reboot_priv->is_big_endian = false;

	ls_reboot_priv->dev = &pdev->dev;

	arm_pm_restart = ls_reboot;

	return 0;
}

static struct of_device_id ls_reboot_of_match[] = {
	{ .compatible = "fsl,ls-reset" },
	{}
};

static struct platform_driver ls_reboot_driver = {
	.probe = ls_reboot_probe,
	.driver = {
		.name = "ls-reset",
		.of_match_table = ls_reboot_of_match,
	},
};

static int __init ls_reboot_init(void)
{
	return platform_driver_register(&ls_reboot_driver);
}
device_initcall(ls_reboot_init);
