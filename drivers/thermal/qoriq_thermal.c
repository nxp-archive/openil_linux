/*
 * Copyright 2015 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/thermal.h>

#include "thermal_core.h"

#define SITES_MAX	16

/*
 * QorIQ TMU Registers
 */
struct qoriq_tmu_site_regs {
	__be32 tritsr;		/* Immediate Temperature Site Register */
	__be32 tratsr;		/* Average Temperature Site Register */
	u8 res0[0x8];
} __packed;

struct qoriq_tmu_regs {
	__be32 tmr;		/* Mode Register */
#define TMR_DISABLE	0x0
#define TMR_ME		0x80000000
#define TMR_ALPF	0x0c000000
#define TMR_MSITE	0x00008000	/* Core temperature site */
#define TMR_ALL		(TMR_ME | TMR_ALPF | TMR_MSITE)
	__be32 tsr;		/* Status Register */
	__be32 tmtmir;		/* Temperature measurement interval Register */
#define TMTMIR_DEFAULT	0x0000000f
	u8 res0[0x14];
	__be32 tier;		/* Interrupt Enable Register */
#define TIER_DISABLE	0x0
	__be32 tidr;		/* Interrupt Detect Register */
	__be32 tiscr;		/* Interrupt Site Capture Register */
	__be32 ticscr;		/* Interrupt Critical Site Capture Register */
	u8 res1[0x10];
	__be32 tmhtcrh;		/* High Temperature Capture Register */
	__be32 tmhtcrl;		/* Low Temperature Capture Register */
	u8 res2[0x8];
	__be32 tmhtitr;		/* High Temperature Immediate Threshold */
	__be32 tmhtatr;		/* High Temperature Average Threshold */
	__be32 tmhtactr;	/* High Temperature Average Crit Threshold */
	u8 res3[0x24];
	__be32 ttcfgr;		/* Temperature Configuration Register */
	__be32 tscfgr;		/* Sensor Configuration Register */
	u8 res4[0x78];
	struct qoriq_tmu_site_regs site[SITES_MAX];
	u8 res5[0x9f8];
	__be32 ipbrr0;		/* IP Block Revision Register 0 */
	__be32 ipbrr1;		/* IP Block Revision Register 1 */
	u8 res6[0x310];
	__be32 ttr0cr;		/* Temperature Range 0 Control Register */
	__be32 ttr1cr;		/* Temperature Range 1 Control Register */
	__be32 ttr2cr;		/* Temperature Range 2 Control Register */
	__be32 ttr3cr;		/* Temperature Range 3 Control Register */
};

/*
 * Thermal zone data
 */
struct qoriq_tmu_data {
	struct thermal_zone_device *tz;
	struct qoriq_tmu_regs __iomem *regs;
};

static int tmu_get_temp(void *p, long *temp)
{
	u32 val;
	struct qoriq_tmu_data *data = p;

	val = ioread32be(&data->regs->site[0].tritsr);
	*temp = (val & 0xff) * 1000;

	return 0;
}

static int qoriq_tmu_calibration(struct platform_device *pdev)
{
	int i, val, len;
	u32 range[4];
	const __be32 *calibration;
	struct device_node *node = pdev->dev.of_node;
	struct qoriq_tmu_data *data = platform_get_drvdata(pdev);

	/* Disable monitoring before calibration */
	iowrite32be(TMR_DISABLE, &data->regs->tmr);

	if (of_property_read_u32_array(node, "fsl,tmu-range", range, 4)) {
		dev_err(&pdev->dev, "TMU: missing calibration range.\n");
		return -ENODEV;
	}

	/* Init temperature range registers */
	iowrite32be(range[0], &data->regs->ttr0cr);
	iowrite32be(range[1], &data->regs->ttr1cr);
	iowrite32be(range[2], &data->regs->ttr2cr);
	iowrite32be(range[3], &data->regs->ttr3cr);

	calibration = of_get_property(node, "fsl,tmu-calibration", &len);
	if (calibration == NULL) {
		dev_err(&pdev->dev, "TMU: missing calibration data.\n");
		return -ENODEV;
	}

	for (i = 0; i < len; i += 8, calibration += 2) {
		val = of_read_number(calibration, 1);
		iowrite32be(val, &data->regs->ttcfgr);
		val = of_read_number(calibration + 1, 1);
		iowrite32be(val, &data->regs->tscfgr);
	}

	return 0;
}

static void qoriq_tmu_init_device(struct qoriq_tmu_data *data)
{
	/* Disable interrupt, using polling instead */
	iowrite32be(TIER_DISABLE, &data->regs->tier);

	/* Set update_interval */
	iowrite32be(TMTMIR_DEFAULT, &data->regs->tmtmir);

	/* Enable monitoring */
	iowrite32be(TMR_ALL, &data->regs->tmr);
}

static struct thermal_zone_of_device_ops tmu_tz_ops = {
	.get_temp = tmu_get_temp,
};

static int qoriq_tmu_probe(struct platform_device *pdev)
{
	int ret;
	const struct thermal_trip *trip;
	struct qoriq_tmu_data *data;

	if (!pdev->dev.of_node) {
		dev_err(&pdev->dev, "Device OF-Node is NULL");
		return -ENODEV;
	}

	data = devm_kzalloc(&pdev->dev, sizeof(struct qoriq_tmu_data),
			    GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	platform_set_drvdata(pdev, data);
	data->regs = of_iomap(pdev->dev.of_node, 0);

	if (!data->regs) {
		dev_err(&pdev->dev, "Failed to get memory region\n");
		ret = -ENODEV;
		goto err_iomap;
	}

	ret = qoriq_tmu_calibration(pdev);	/* TMU calibration */
	if (ret < 0)
		goto err_tmu;

	qoriq_tmu_init_device(data);	/* TMU initialization */

	data->tz = thermal_zone_of_sensor_register(&pdev->dev, 0,
				data, &tmu_tz_ops);
	if (IS_ERR(data->tz)) {
		ret = PTR_ERR(data->tz);
		dev_err(&pdev->dev,
			"Failed to register thermal zone device %d\n", ret);
		goto err_tmu;
	}

	trip = of_thermal_get_trip_points(data->tz);

	return 0;

err_tmu:
	iounmap(data->regs);

err_iomap:
	platform_set_drvdata(pdev, NULL);
	devm_kfree(&pdev->dev, data);

	return ret;
}

static int qoriq_tmu_remove(struct platform_device *pdev)
{
	struct qoriq_tmu_data *data = platform_get_drvdata(pdev);

	/* Disable monitoring */
	iowrite32be(TMR_DISABLE, &data->regs->tmr);

	thermal_zone_of_sensor_unregister(&pdev->dev, data->tz);
	iounmap(data->regs);

	platform_set_drvdata(pdev, NULL);
	devm_kfree(&pdev->dev, data);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int qoriq_tmu_suspend(struct device *dev)
{
	struct qoriq_tmu_data *data = dev_get_drvdata(dev);

	/* Disable monitoring */
	iowrite32be(TMR_DISABLE, &data->regs->tmr);
	data->tz->ops->set_mode(data->tz, THERMAL_DEVICE_DISABLED);

	return 0;
}

static int qoriq_tmu_resume(struct device *dev)
{
	struct qoriq_tmu_data *data = dev_get_drvdata(dev);

	/* Enable monitoring */
	iowrite32be(TMR_ALL, &data->regs->tmr);
	data->tz->ops->set_mode(data->tz, THERMAL_DEVICE_ENABLED);

	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(qoriq_tmu_pm_ops,
			 qoriq_tmu_suspend, qoriq_tmu_resume);

static const struct of_device_id qoriq_tmu_match[] = {
	{ .compatible = "fsl,qoriq-tmu", },
	{},
};

static struct platform_driver qoriq_tmu = {
	.driver	= {
		.name		= "qoriq_thermal",
		.pm		= &qoriq_tmu_pm_ops,
		.of_match_table	= qoriq_tmu_match,
	},
	.probe	= qoriq_tmu_probe,
	.remove	= qoriq_tmu_remove,
};
module_platform_driver(qoriq_tmu);

MODULE_AUTHOR("Jia Hongtao <hongtao.jia@freescale.com>");
MODULE_DESCRIPTION("Freescale QorIQ Thermal Monitoring Unit driver");
MODULE_LICENSE("GPL v2");
