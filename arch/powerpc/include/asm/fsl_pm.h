/*
 * Support Power Management
 *
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#ifndef __PPC_FSL_PM_H
#define __PPC_FSL_PM_H
#ifdef __KERNEL__
#include <linux/suspend.h>

#define E500_PM_PH10	1
#define E500_PM_PH15	2
#define E500_PM_PH20	3
#define E500_PM_PH30	4
#define E500_PM_DOZE	E500_PM_PH10
#define E500_PM_NAP	E500_PM_PH15

#define PLAT_PM_SLEEP	20
#define PLAT_PM_LPM20	30
#define PLAT_PM_LPM35	40

#define FSL_PM_SLEEP		BIT(0)
#define FSL_PM_DEEP_SLEEP	BIT(1)

struct fsl_pm_ops {
	/* mask pending interrupts to the RCPM from MPIC */
	void (*irq_mask)(int cpu);

	/* unmask pending interrupts to the RCPM from MPIC */
	void (*irq_unmask)(int cpu);
	void (*cpu_enter_state)(int cpu, int state);
	void (*cpu_exit_state)(int cpu, int state);
	void (*cpu_up_prepare)(int cpu);
	void (*cpu_die)(int cpu);
	int (*plat_enter_sleep)(int state);
	void (*freeze_time_base)(bool freeze);

	/* keep the power of IP blocks during sleep/deep sleep */
	void (*set_ip_power)(bool enable, u32 mask);

	/* get platform supported power management modes */
	unsigned int (*get_pm_modes)(void);
};

extern const struct fsl_pm_ops *qoriq_pm_ops;

int __init fsl_rcpm_init(void);

#ifdef CONFIG_FSL_QORIQ_PM
int fsl_enter_deepsleep(void);
int fsl_deepsleep_init(void);
#else
static inline int fsl_enter_deepsleep(void) { return -1; }
static inline int fsl_deepsleep_init(void) { return -1; }
#endif

void fsl_dp_enter_low(void *priv);
void fsl_booke_deep_sleep_resume(void);

struct fsl_iomap {
	void *ccsr_lcc_base;
	void *ccsr_scfg_base;
	void *ccsr_dcfg_base;
	void *ccsr_rcpm_base;
	void *ccsr_ddr_base;
	void *ccsr_gpio1_base;
	void *ccsr_cpc_base;
	void *dcsr_epu_base;
	void *dcsr_npc_base;
	void *dcsr_rcpm_base;
	void *cpld_base;
	void *fpga_base;
};

#ifdef CONFIG_FSL_QORIQ_PM
suspend_state_t pm_suspend_state(void);
#else
static inline suspend_state_t pm_suspend_state(void)
{
	return PM_SUSPEND_STANDBY;
}
#endif

#endif /* __KERNEL__ */
#endif /* __PPC_FSL_PM_H */
