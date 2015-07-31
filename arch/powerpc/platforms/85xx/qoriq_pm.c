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

#include <asm/fsl_pm.h>

static unsigned int pm_modes;

static int qoriq_suspend_enter(suspend_state_t state)
{
	int ret = 0;

	switch (state) {
	case PM_SUSPEND_STANDBY:
		ret = qoriq_pm_ops->plat_enter_sleep(FSL_PM_SLEEP);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int qoriq_suspend_valid(suspend_state_t state)
{
	if (state == PM_SUSPEND_STANDBY && (pm_modes & FSL_PM_SLEEP))
		return 1;

	return 0;
}

static const struct platform_suspend_ops qoriq_suspend_ops = {
	.valid = qoriq_suspend_valid,
	.enter = qoriq_suspend_enter,
};

static int __init qoriq_suspend_init(void)
{
	/* support sleep by default */
	pm_modes |= FSL_PM_SLEEP;

	suspend_set_ops(&qoriq_suspend_ops);
	return 0;
}
arch_initcall(qoriq_suspend_init);
