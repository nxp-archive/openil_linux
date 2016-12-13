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

/* PFE performance monitoring functions */

#include "pfe_ctrl_hal.h"
#include "pfe_perfmon.h"

static TIMER_ENTRY cpumon_timer;

u32 CLASS_DMEM_SH2(cpu_ticks[2]);
u32 TMU_DMEM_SH2(cpu_ticks[2]);
#if !defined(CONFIG_UTIL_DISABLED)
u32 UTIL_DMEM_SH2(cpu_ticks[2]);
#endif

#define compute_active_pct(total_ticks, active_ticks) ((active_ticks * 100 + (total_ticks >> 1)) / total_ticks)

static void cpumon_timer_handler(void)
{
	int id;
	u32 dmem_addr;
	u32 ticks[2];
	u32 total, active;
	struct pfe_ctrl *ctrl = &pfe->ctrl;
	struct pfe_cpumon *cpumon = &pfe->cpumon;

	// Process class PE's
	total = active = 0;
	dmem_addr = virt_to_class_dmem(&class_cpu_ticks[0]);
	for (id = CLASS0_ID; id <= CLASS_MAX_ID; id++)
	{
		cpumon->cpu_usage_pct[id] = 0;
		if (pe_sync_stop(ctrl, (1 << id)) < 0)
			continue;
		ticks[0] = be32_to_cpu(pe_dmem_read(id, dmem_addr, 4));
		ticks[1] = be32_to_cpu(pe_dmem_read(id, dmem_addr + 4, 4));
		pe_dmem_write(id, 0, dmem_addr, 4);
		pe_dmem_write(id, 0, dmem_addr + 4, 4);
		pe_start(ctrl, (1 << id));
		ticks[0] >>= 8;	// divide both values by 256, so multiply by 100 won't overflow
		ticks[1] >>= 8;
		total += ticks[0];
		active += ticks[1];
		if (ticks[0] != 0)
			cpumon->cpu_usage_pct[id] = compute_active_pct(ticks[0], ticks[1]);
	}
	if (total != 0)
		cpumon->class_usage_pct = compute_active_pct(total, active);
	else
		cpumon->class_usage_pct = 0;

	// Process TMU PE's
	total = active = 0;
	dmem_addr = virt_to_tmu_dmem(&tmu_cpu_ticks[0]);
	for (id = TMU0_ID; id <= TMU_MAX_ID; id++)
	{
#if defined(CONFIG_PLATFORM_LS1012A)
		if(id == TMU2_ID) continue;
#endif
		cpumon->cpu_usage_pct[id] = 0;
		if (pe_sync_stop(ctrl, (1 << id)) < 0)
			continue;
		ticks[0] = be32_to_cpu(pe_dmem_read(id, dmem_addr, 4));
		ticks[1] = be32_to_cpu(pe_dmem_read(id, dmem_addr + 4, 4));
		pe_dmem_write(id, 0, dmem_addr, 4);
		pe_dmem_write(id, 0, dmem_addr + 4, 4);
		pe_start(ctrl, (1 << id));
		ticks[0] >>= 8;	// divide both values by 256, so multiply by 100 won't overflow
		ticks[1] >>= 8;
		if (ticks[0] != 0)
			cpumon->cpu_usage_pct[id] = compute_active_pct(ticks[0], ticks[1]);
	}
#if !defined(CONFIG_UTIL_DISABLED)
	// Process Util PE
	dmem_addr = virt_to_util_dmem(&util_cpu_ticks[0]);
	cpumon->cpu_usage_pct[UTIL_ID] = 0;
	if (pe_sync_stop(ctrl, (1 << UTIL_ID)) < 0)
		return;
	ticks[0] = be32_to_cpu(pe_dmem_read(UTIL_ID, dmem_addr, 4));
	ticks[1] = be32_to_cpu(pe_dmem_read(UTIL_ID, dmem_addr + 4, 4));
	pe_dmem_write(UTIL_ID, 0, dmem_addr, 4);
	pe_dmem_write(UTIL_ID, 0, dmem_addr + 4, 4);
	pe_start(ctrl, (1 << UTIL_ID));
	ticks[0] >>= 8;	// divide both values by 256, so multiply by 100 won't overflow
	ticks[1] >>= 8;
	if (ticks[0] != 0)
		cpumon->cpu_usage_pct[UTIL_ID] = compute_active_pct(ticks[0], ticks[1]);
#endif
}

static int pfe_cpumon_init(struct pfe *pfe)
{
	timer_init(&cpumon_timer, cpumon_timer_handler);
	timer_add(&cpumon_timer, CT_CPUMON_INTERVAL);
	return 0;
}

static void pfe_cpumon_exit(struct pfe *pfe)
{
	timer_del(&cpumon_timer);
}


/*********************************************************************************/

// Memory monitor functions

void * pfe_kmalloc(size_t size, int flags)
{
	struct pfe_memmon *memmon = &pfe->memmon;
	void *ptr;
	ptr = kmalloc(size, flags);
	if (ptr)
		memmon->kernel_memory_allocated += ksize(ptr);
	return ptr;
}

void * pfe_kzalloc(size_t size, int flags)
{
	struct pfe_memmon *memmon = &pfe->memmon;
	void *ptr;
	ptr = kzalloc(size, flags);
	if (ptr)
		memmon->kernel_memory_allocated += ksize(ptr);
	return ptr;
}

void pfe_kfree(void *ptr)
{
	struct pfe_memmon *memmon = &pfe->memmon;
	memmon->kernel_memory_allocated -= ksize(ptr);
	kfree(ptr);
}

static int pfe_memmon_init(struct pfe *pfe)
{
	return 0;
}

static void pfe_memmon_exit(struct pfe *pfe)
{
}

/*********************************************************************************/


int pfe_perfmon_init(struct pfe *pfe)
{
	pfe_cpumon_init(pfe);
	pfe_memmon_init(pfe);
	return 0;
}

void pfe_perfmon_exit(struct pfe *pfe)
{
	pfe_cpumon_exit(pfe);
	pfe_memmon_exit(pfe);
}
