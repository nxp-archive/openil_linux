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

#ifndef _PFE_PERFMON_H_
#define _PFE_PERFMON_H_

#define	CT_CPUMON_INTERVAL	(1 * TIMER_TICKS_PER_SEC)

struct pfe_cpumon {
	u32 cpu_usage_pct[MAX_PE];
	u32 class_usage_pct;
};

struct pfe_memmon {
	u32 kernel_memory_allocated;
};

void * pfe_kmalloc(size_t size, int flags);
void * pfe_kzalloc(size_t size, int flags);
void pfe_kfree(void *ptr);

int pfe_perfmon_init(struct pfe *pfe);
void pfe_perfmon_exit(struct pfe *pfe);

#endif /* _PFE_PERFMON_H_ */
