/*
 * Support Power Management feature
 *
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 *
 * Author: Chenhui Zhao <chenhui.zhao@freescale.com>
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/kernel.h>
#include <linux/suspend.h>
#include <linux/of_platform.h>
#include <linux/of_fdt.h>
#include <linux/usb.h>

#include <asm/fsl_pm.h>

static unsigned int pm_modes;
static u32 wake_mask;
static suspend_state_t pm_state;

static int fsl_set_power_except(struct device_node *of_node)
{
	u32 value[2];
	int ret;

	if (!of_node)
		return -EINVAL;

	ret = of_property_read_u32_array(of_node, "rcpm-wakeup", value, 2);
	if (ret)
		return ret;

	/* get the second value, it is a mask */
	wake_mask |= value[1];
	return 0;
}

static void qoriq_set_wakeup_source(struct device *dev, void *enable)
{
	const phandle *phandle_prop;
	struct device_node *mac_node;
	int ret;

	if (!dev || !device_may_wakeup(dev))
		return;

	ret = fsl_set_power_except(dev->of_node);
	if (!ret)
		return;

	/* usb device */
	if (!strncmp(dev->bus->name, "usb", 3)) {
		struct usb_device *udev = container_of(dev,
						struct usb_device, dev);
		struct device *controller = udev->bus->controller;

		ret = fsl_set_power_except(controller->parent->of_node);
		if (!ret)
			return;
	}

	/* fman mac node */
	phandle_prop = of_get_property(dev->of_node, "fsl,fman-mac", NULL);
	if (phandle_prop) {
		mac_node = of_find_node_by_phandle(*phandle_prop);
		ret = fsl_set_power_except(mac_node);
		if (!ret)
			/* enable FMan if one MAC is enabled */
			fsl_set_power_except(mac_node->parent);
	}
}

static int qoriq_suspend_enter(suspend_state_t state)
{
	int ret = 0;

	/* clear the default value */
	qoriq_pm_ops->set_ip_power(false, 0x0ffffffff);
	qoriq_pm_ops->set_ip_power(true, wake_mask);

	switch (state) {
	case PM_SUSPEND_STANDBY:
		ret = qoriq_pm_ops->plat_enter_sleep(FSL_PM_SLEEP);
		break;

	case PM_SUSPEND_MEM:
		ret = qoriq_pm_ops->plat_enter_sleep(FSL_PM_DEEP_SLEEP);
		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}

static int qoriq_suspend_valid(suspend_state_t state)
{
	pm_state = state;

	if (state == PM_SUSPEND_STANDBY && (pm_modes & FSL_PM_SLEEP))
		return 1;

	if (state == PM_SUSPEND_MEM && (pm_modes & FSL_PM_DEEP_SLEEP))
		return 1;

	return 0;
}

static int qoriq_suspend_begin(suspend_state_t state)
{
	wake_mask = 0;
	dpm_for_each_dev(NULL, qoriq_set_wakeup_source);

	return 0;
}

static const char * const boards_deepsleep[] __initconst = {
	"fsl,T1024QDS",
	"fsl,T1024RDB",
	"fsl,T1040QDS",
	"fsl,T1040RDB",
	"fsl,T1040D4RDB",
	"fsl,T1042QDS",
	"fsl,T1042D4RDB",
	"fsl,T1042RDB",
	"fsl,T1042RDB_PI",
};

static const struct platform_suspend_ops qoriq_suspend_ops = {
	.valid = qoriq_suspend_valid,
	.enter = qoriq_suspend_enter,
	.begin = qoriq_suspend_begin,
};

static int __init qoriq_suspend_init(void)
{
	/* support sleep by default */
	pm_modes |= FSL_PM_SLEEP;

	if (of_flat_dt_match(of_get_flat_dt_root(), boards_deepsleep) &&
	    !fsl_deepsleep_init())
		pm_modes |= FSL_PM_DEEP_SLEEP;

	suspend_set_ops(&qoriq_suspend_ops);
	return 0;
}
arch_initcall(qoriq_suspend_init);

suspend_state_t pm_suspend_state(void)
{
	return pm_state;
}
EXPORT_SYMBOL_GPL(pm_suspend_state);
