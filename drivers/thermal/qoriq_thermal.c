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
#include <linux/regmap.h>
#include <linux/thermal.h>

#include "thermal_core.h"

#define QORIQ_TMU_TMR		0x0	/* Mode Register */
#define QORIQ_TMU_TMR_DISABLE	0x0
#define QORIQ_TMU_TMR_ME	0x80000000
#define QORIQ_TMU_TMR_ALPF	0x0c000000

#define QORIQ_TMU_TSR		0x4	/* Status Register */

#define QORIQ_TMU_TMTMIR	0x8	/* Temp Measurement interval Register */
#define QORIQ_TMU_TMTMIR_DFT	0x0000000f

#define QORIQ_TMU_TIER		0x20	/* Interrupt Enable Register */
#define QORIQ_TMU_TIER_DISABLE	0x0

#define QORIQ_TMU_TTCFGR	0x80	/* Temp Configuration Register */
#define QORIQ_TMU_TSCFGR	0x84	/* Sensor Configuration Register */

#define QORIQ_TMU_TRITSR_BASE	0x100	/* Report Immediate Temp Register */
#define QORIQ_TMU_TRITSR_STEP	0x10

#define QORIQ_TMU_IPBRR0	0xbf8	/* IP Block Revision Register 0 */
#define QORIQ_TMU_IPBRR1	0xbfc	/* IP Block Revision Register 1 */

#define QORIQ_TMU_TTR0CR	0xf10	/* Temp Range 0 Control Register */
#define QORIQ_TMU_TTR1CR	0xf14	/* Temp Range 1 Control Register */
#define QORIQ_TMU_TTR2CR	0xf18	/* Temp Range 2 Control Register */
#define QORIQ_TMU_TTR3CR	0xf1c	/* Temp Range 3 Control Register */

/*
 * Thermal zone data
 */
struct qoriq_tmu_data {
	void __iomem *base;
	struct regmap *regmap;
	struct mutex lock;
	int sensor_id;
	struct thermal_zone_device *tz;
};

static int tmu_get_temp(void *p, long *temp)
{
	u32 val;
	struct qoriq_tmu_data *data = p;

	mutex_lock(&data->lock);
	regmap_read(data->regmap, QORIQ_TMU_TRITSR_BASE +
			QORIQ_TMU_TRITSR_STEP * data->sensor_id, &val);

	*temp = (val & 0xff) * 1000;
	mutex_unlock(&data->lock);

	return 0;
}

static int qoriq_tmu_calibration(struct platform_device *pdev)
{
	int i, val, len;
	u32 range[4];
	const u32 *calibration;
	struct device_node *node = pdev->dev.of_node;
	struct qoriq_tmu_data *data = platform_get_drvdata(pdev);

	/* Disable monitoring before calibration */
	regmap_write(data->regmap, QORIQ_TMU_TMR, QORIQ_TMU_TMR_DISABLE);

	if (of_property_read_u32_array(node, "fsl,tmu-range", range, 4)) {
		dev_err(&pdev->dev, "TMU: missing calibration range.\n");
		return -ENODEV;
	}

	/* Init temperature range registers */
	regmap_write(data->regmap, QORIQ_TMU_TTR0CR, range[0]);
	regmap_write(data->regmap, QORIQ_TMU_TTR1CR, range[1]);
	regmap_write(data->regmap, QORIQ_TMU_TTR2CR, range[2]);
	regmap_write(data->regmap, QORIQ_TMU_TTR3CR, range[3]);

	calibration = of_get_property(node, "fsl,tmu-calibration", &len);
	if (calibration == NULL) {
		dev_err(&pdev->dev, "TMU: missing calibration data.\n");
		return -ENODEV;
	}

	for (i = 0; i < len; i += 8, calibration += 2) {
		val = of_read_number(calibration, 1);
		regmap_write(data->regmap, QORIQ_TMU_TTCFGR, val);
		val = of_read_number(calibration + 1, 1);
		regmap_write(data->regmap, QORIQ_TMU_TSCFGR, val);
	}

	return 0;
}

static void qoriq_tmu_init_device(struct qoriq_tmu_data *data)
{
	/* Disable interrupt, using polling instead */
	regmap_write(data->regmap, QORIQ_TMU_TIER, QORIQ_TMU_TIER_DISABLE);

	/* Set update_interval */
	regmap_write(data->regmap, QORIQ_TMU_TMTMIR, QORIQ_TMU_TMTMIR_DFT);

	/* Disable monitoring */
	regmap_write(data->regmap, QORIQ_TMU_TMR, QORIQ_TMU_TMR_DISABLE);
}

static int qoriq_of_get_sensor_id(struct platform_device *pdev)
{
	struct qoriq_tmu_data *data = platform_get_drvdata(pdev);
	struct device_node *np = pdev->dev.of_node;

	if (of_device_is_compatible(np, "fsl,t102x-tmu"))
		data->sensor_id = 0;
	else if (of_device_is_compatible(np, "fsl,t104x-tmu"))
		data->sensor_id = 2;
	else if (of_device_is_compatible(np, "fsl,ls1021a-tmu"))
		data->sensor_id = 0;
	else if (of_device_is_compatible(np, "fsl,ls1012a-tmu"))
		data->sensor_id = 0;
	else if (of_device_is_compatible(np, "fsl,ls1043a-tmu"))
		data->sensor_id = 3;
	else if (of_device_is_compatible(np, "fsl,ls2080a-tmu"))
		data->sensor_id = 4;
	else
		return -EINVAL;

	return 0;
}

static struct thermal_zone_of_device_ops tmu_tz_ops = {
	.get_temp = tmu_get_temp,
};

static const struct regmap_config qoriq_tmu_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
};

static int qoriq_tmu_probe(struct platform_device *pdev)
{
	int ret;
	const struct thermal_trip *trip;
	struct qoriq_tmu_data *data;
	void __iomem *base;
	u32 tmr = 0;

	if (!pdev->dev.of_node) {
		dev_err(&pdev->dev, "Device OF-Node is NULL");
		return -ENODEV;
	}

	data = devm_kzalloc(&pdev->dev, sizeof(struct qoriq_tmu_data),
			    GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	mutex_init(&data->lock);

	platform_set_drvdata(pdev, data);

	base = of_iomap(pdev->dev.of_node, 0);
	if (!base) {
		dev_err(&pdev->dev, "Failed to get memory region\n");
		ret = -ENODEV;
		goto err_iomap;
	}

	data->base = base;
	data->regmap = devm_regmap_init_mmio(&pdev->dev, base,
						 &qoriq_tmu_regmap_config);
	if (IS_ERR(data->regmap)) {
		dev_err(&pdev->dev, "Regmap init failed\n");
		ret = PTR_ERR(data->regmap);
		goto err_tmu;
	}

	ret = qoriq_tmu_calibration(pdev);	/* TMU calibration */
	if (ret < 0)
		goto err_tmu;

	qoriq_tmu_init_device(data);	/* TMU initialization */

	ret = qoriq_of_get_sensor_id(pdev);
	if (ret < 0)
		goto err_tmu;

	data->tz = thermal_zone_of_sensor_register(&pdev->dev, data->sensor_id,
				data, &tmu_tz_ops);
	if (IS_ERR(data->tz)) {
		ret = PTR_ERR(data->tz);
		dev_err(&pdev->dev,
			"Failed to register thermal zone device %d\n", ret);
		goto err_tmu;
	}

	trip = of_thermal_get_trip_points(data->tz);

	/* Enable monitoring */
	tmr |= 0x1 << (15 - data->sensor_id);
	regmap_write(data->regmap, QORIQ_TMU_TMR, tmr | QORIQ_TMU_TMR_ME |
			QORIQ_TMU_TMR_ALPF);

	return 0;

err_tmu:
	iounmap(base);

err_iomap:
	platform_set_drvdata(pdev, NULL);
	devm_kfree(&pdev->dev, data);

	return ret;
}

static int qoriq_tmu_remove(struct platform_device *pdev)
{
	struct qoriq_tmu_data *data = platform_get_drvdata(pdev);

	/* Disable monitoring */
	regmap_write(data->regmap, QORIQ_TMU_TMR, QORIQ_TMU_TMR_DISABLE);

	thermal_zone_of_sensor_unregister(&pdev->dev, data->tz);

	iounmap(data->base);

	platform_set_drvdata(pdev, NULL);
	devm_kfree(&pdev->dev, data);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int qoriq_tmu_suspend(struct device *dev)
{
	u32 tmr;
	struct qoriq_tmu_data *data = dev_get_drvdata(dev);

	/* Disable monitoring */
	regmap_read(data->regmap, QORIQ_TMU_TMR, &tmr);
	tmr &= ~QORIQ_TMU_TMR_ME;
	regmap_write(data->regmap, QORIQ_TMU_TMR, tmr);

	data->tz->ops->set_mode(data->tz, THERMAL_DEVICE_DISABLED);

	return 0;
}

static int qoriq_tmu_resume(struct device *dev)
{
	u32 tmr;
	struct qoriq_tmu_data *data = dev_get_drvdata(dev);

	/* Enable monitoring */
	regmap_read(data->regmap, QORIQ_TMU_TMR, &tmr);
	tmr |= QORIQ_TMU_TMR_ME;
	regmap_write(data->regmap, QORIQ_TMU_TMR, tmr);

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
