/*
 * arch/arm64/include/asm/arch_timer.h
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software: you can redistribute it and/or modify
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
#ifndef __ASM_ARCH_TIMER_H
#define __ASM_ARCH_TIMER_H

#include <asm/barrier.h>

#include <linux/bug.h>
#include <linux/init.h>
#include <linux/types.h>

#include <clocksource/arm_arch_timer.h>

#ifdef CONFIG_ARCH_LAYERSCAPE
extern bool arm_arch_timer_reread;
#else
#define arm_arch_timer_reread false
#endif

#define ARCH_TIMER_REREAD(reg) ({ \
	u64 _val_old, _val_new; \
	int _timeout = 200; \
	do { \
		asm volatile("mrs %0, " reg ";" \
			     "mrs %1, " reg \
			     : "=r" (_val_old), "=r" (_val_new)); \
		_timeout--; \
	} while (_val_old != _val_new && _timeout); \
	WARN_ON_ONCE(_timeout <= 0 && _val_old != _val_new); \
	_val_old; \
})

#define ARCH_TIMER_READ(reg) ({ \
	u64 _val; \
	if (arm_arch_timer_reread) \
		_val = ARCH_TIMER_REREAD(reg); \
	else \
		asm volatile("mrs %0, " reg : "=r" (_val)); \
	_val; \
})

/*
 * These register accessors are marked inline so the compiler can
 * nicely work out which register we want, and chuck away the rest of
 * the code.
 */
static __always_inline
void arch_timer_reg_write_cp15(int access, enum arch_timer_reg reg, u32 val)
{
	if (access == ARCH_TIMER_PHYS_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("msr cntp_ctl_el0,  %0" : : "r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("msr cntp_tval_el0, %0" : : "r" (val));
			break;
		}
	} else if (access == ARCH_TIMER_VIRT_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("msr cntv_ctl_el0,  %0" : : "r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("msr cntv_tval_el0, %0" : : "r" (val));
			break;
		}
	}

	isb();
}

static __always_inline
u32 arch_timer_reg_read_cp15(int access, enum arch_timer_reg reg)
{
	u32 val;

	if (access == ARCH_TIMER_PHYS_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("mrs %0,  cntp_ctl_el0" : "=r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			val = ARCH_TIMER_READ("cntp_tval_el0");
			break;
		}
	} else if (access == ARCH_TIMER_VIRT_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("mrs %0,  cntv_ctl_el0" : "=r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			val = ARCH_TIMER_READ("cntv_tval_el0");
			break;
		}
	}

	return val;
}

static inline u32 arch_timer_get_cntfrq(void)
{
	u32 val;
	asm volatile("mrs %0,   cntfrq_el0" : "=r" (val));
	return val;
}

static inline u32 arch_timer_get_cntkctl(void)
{
	u32 cntkctl;
	asm volatile("mrs	%0, cntkctl_el1" : "=r" (cntkctl));
	return cntkctl;
}

static inline void arch_timer_set_cntkctl(u32 cntkctl)
{
	asm volatile("msr	cntkctl_el1, %0" : : "r" (cntkctl));
}

static inline u64 arch_counter_get_cntpct(void)
{
	/*
	 * AArch64 kernel and user space mandate the use of CNTVCT.
	 */
	BUG();
	return 0;
}

static inline u64 arch_counter_get_cntvct(void)
{
	isb();
	return ARCH_TIMER_READ("cntvct_el0");
}

static inline int arch_timer_arch_init(void)
{
	return 0;
}

#endif
