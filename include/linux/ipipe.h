/* -*- linux-c -*-
 * include/linux/ipipe.h
 *
 * Copyright (C) 2002-2014 Philippe Gerum.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __LINUX_IPIPE_H
#define __LINUX_IPIPE_H

#include <linux/spinlock.h>
#include <linux/cache.h>
#include <linux/percpu.h>
#include <linux/irq.h>
#include <linux/thread_info.h>
#include <linux/ipipe_base.h>
#include <linux/ipipe_debug.h>
#include <asm/ptrace.h>
#ifdef CONFIG_HAVE_IPIPE_SUPPORT
#include <asm/ipipe.h>
#endif

#ifdef CONFIG_IPIPE

#include <linux/ipipe_domain.h>

struct ipipe_sysinfo {
	int sys_nr_cpus;	/* Number of CPUs on board */
	int sys_hrtimer_irq;	/* hrtimer device IRQ */
	u64 sys_hrtimer_freq;	/* hrtimer device frequency */
	u64 sys_hrclock_freq;	/* hrclock device frequency */
	u64 sys_cpu_freq;	/* CPU frequency (Hz) */
	struct ipipe_arch_sysinfo arch;
};

struct ipipe_work_header {
	size_t size;
	void (*handler)(struct ipipe_work_header *work);
};

extern unsigned int __ipipe_printk_virq;

void __ipipe_set_irq_pending(struct ipipe_domain *ipd, unsigned int irq);

/*
 * Obsolete - no arch implements PIC muting anymore. Null helpers are
 * kept for building legacy co-kernel releases.
 */
static inline void ipipe_mute_pic(void) { }
static inline void ipipe_unmute_pic(void) { }

static inline void __ipipe_nmi_enter(void)
{
	__this_cpu_write(ipipe_percpu.nmi_state, __ipipe_root_status);
	__set_bit(IPIPE_STALL_FLAG, &__ipipe_root_status);
	ipipe_save_context_nmi();
}

static inline void __ipipe_nmi_exit(void)
{
	ipipe_restore_context_nmi();
	if (!test_bit(IPIPE_STALL_FLAG, raw_cpu_ptr(&ipipe_percpu.nmi_state)))
		__clear_bit(IPIPE_STALL_FLAG, &__ipipe_root_status);
}

static inline void __ipipe_sync_pipeline(struct ipipe_domain *top)
{
	if (__ipipe_current_domain != top) {
		__ipipe_do_sync_pipeline(top);
		return;
	}
	if (!test_bit(IPIPE_STALL_FLAG, &ipipe_this_cpu_context(top)->status))
		__ipipe_sync_stage();
}

void ipipe_register_head(struct ipipe_domain *ipd,
			 const char *name);

void ipipe_unregister_head(struct ipipe_domain *ipd);

int ipipe_request_irq(struct ipipe_domain *ipd,
		      unsigned int irq,
		      ipipe_irq_handler_t handler,
		      void *cookie,
		      ipipe_irq_ackfn_t ackfn);

void ipipe_free_irq(struct ipipe_domain *ipd,
		    unsigned int irq);

void ipipe_raise_irq(unsigned int irq);

unsigned int ipipe_alloc_virq(void);

void ipipe_free_virq(unsigned int virq);

static inline void ipipe_post_irq_head(unsigned int irq)
{
	__ipipe_set_irq_pending(ipipe_head_domain, irq);
}

static inline void ipipe_post_irq_root(unsigned int irq)
{
	__ipipe_set_irq_pending(&ipipe_root, irq);
}

static inline void ipipe_stall_head(void)
{
	hard_local_irq_disable();
	__set_bit(IPIPE_STALL_FLAG, &__ipipe_head_status);
}

static inline unsigned long ipipe_test_and_stall_head(void)
{
	hard_local_irq_disable();
	return __test_and_set_bit(IPIPE_STALL_FLAG, &__ipipe_head_status);
}

static inline unsigned long ipipe_test_head(void)
{
	unsigned long flags, ret;

	flags = hard_smp_local_irq_save();
	ret = test_bit(IPIPE_STALL_FLAG, &__ipipe_head_status);
	hard_smp_local_irq_restore(flags);

	return ret;
}

void ipipe_unstall_head(void);

void __ipipe_restore_head(unsigned long x);

static inline void ipipe_restore_head(unsigned long x)
{
	ipipe_check_irqoff();
	if ((x ^ test_bit(IPIPE_STALL_FLAG, &__ipipe_head_status)) & 1)
		__ipipe_restore_head(x);
}

void __ipipe_post_work_root(struct ipipe_work_header *work);

#define ipipe_post_work_root(p, header)			\
	do {						\
		void header_not_at_start(void);		\
		if (offsetof(typeof(*(p)), header)) {	\
			header_not_at_start();		\
		}					\
		__ipipe_post_work_root(&(p)->header);	\
	} while (0)

int ipipe_get_sysinfo(struct ipipe_sysinfo *sysinfo);

unsigned long ipipe_critical_enter(void (*syncfn)(void));

void ipipe_critical_exit(unsigned long flags);

void ipipe_prepare_panic(void);

#ifdef CONFIG_SMP
#ifndef ipipe_smp_p
#define ipipe_smp_p (1)
#endif
void ipipe_set_irq_affinity(unsigned int irq, cpumask_t cpumask);
void ipipe_send_ipi(unsigned int ipi, cpumask_t cpumask);
#else  /* !CONFIG_SMP */
#define ipipe_smp_p (0)
static inline
void ipipe_set_irq_affinity(unsigned int irq, cpumask_t cpumask) { }
static inline void ipipe_send_ipi(unsigned int ipi, cpumask_t cpumask) { }
static inline void ipipe_disable_smp(void) { }
#endif	/* CONFIG_SMP */

static inline void ipipe_restore_root_nosync(unsigned long x)
{
	unsigned long flags;

	flags = hard_smp_local_irq_save();
	__ipipe_restore_root_nosync(x);
	hard_smp_local_irq_restore(flags);
}

/* Must be called hw IRQs off. */
static inline void ipipe_lock_irq(unsigned int irq)
{
	struct ipipe_domain *ipd = __ipipe_current_domain;
	if (ipd == ipipe_root_domain)
		__ipipe_lock_irq(irq);
}

/* Must be called hw IRQs off. */
static inline void ipipe_unlock_irq(unsigned int irq)
{
	struct ipipe_domain *ipd = __ipipe_current_domain;
	if (ipd == ipipe_root_domain)
		__ipipe_unlock_irq(irq);
}

void ipipe_enable_irq(unsigned int irq);

static inline void ipipe_disable_irq(unsigned int irq)
{
	struct irq_desc *desc;
	struct irq_chip *chip;

	desc = irq_to_desc(irq);
	if (desc == NULL)
		return;

	chip = irq_desc_get_chip(desc);

	if (WARN_ON_ONCE(chip->irq_disable == NULL && chip->irq_mask == NULL))
		return;

	if (chip->irq_disable)
		chip->irq_disable(&desc->irq_data);
	else
		chip->irq_mask(&desc->irq_data);
}

static inline void ipipe_end_irq(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (desc)
		desc->ipipe_end(desc);
}

static inline int ipipe_chained_irq_p(struct irq_desc *desc)
{
	void __ipipe_chained_irq(struct irq_desc *desc);

	return desc->handle_irq == __ipipe_chained_irq;
}

static inline void ipipe_handle_demuxed_irq(unsigned int cascade_irq)
{
	__ipipe_dispatch_irq(cascade_irq, IPIPE_IRQF_NOSYNC);
}

static inline void __ipipe_init_threadflags(struct thread_info *ti)
{
	ti->ipipe_flags = 0;
}

static inline
void ipipe_set_ti_thread_flag(struct thread_info *ti, int flag)
{
	set_bit(flag, &ti->ipipe_flags);
}

static inline
void ipipe_clear_ti_thread_flag(struct thread_info *ti, int flag)
{
	clear_bit(flag, &ti->ipipe_flags);
}

static inline
void ipipe_test_and_clear_ti_thread_flag(struct thread_info *ti, int flag)
{
	test_and_clear_bit(flag, &ti->ipipe_flags);
}

static inline
int ipipe_test_ti_thread_flag(struct thread_info *ti, int flag)
{
	return test_bit(flag, &ti->ipipe_flags);
}

#define ipipe_set_thread_flag(flag) \
	ipipe_set_ti_thread_flag(current_thread_info(), flag)

#define ipipe_clear_thread_flag(flag) \
	ipipe_clear_ti_thread_flag(current_thread_info(), flag)

#define ipipe_test_and_clear_thread_flag(flag) \
	ipipe_test_and_clear_ti_thread_flag(current_thread_info(), flag)

#define ipipe_test_thread_flag(flag) \
	ipipe_test_ti_thread_flag(current_thread_info(), flag)

#else	/* !CONFIG_IPIPE */

#define __ipipe_root_p		1
#define ipipe_root_p		1

static inline void __ipipe_init_threadflags(struct thread_info *ti) { }

static inline void __ipipe_nmi_enter(void) { }

static inline void __ipipe_nmi_exit(void) { }

#define ipipe_processor_id()	smp_processor_id()

static inline void ipipe_lock_irq(unsigned int irq) { }

static inline void ipipe_unlock_irq(unsigned int irq) { }

#endif	/* !CONFIG_IPIPE */

#endif	/* !__LINUX_IPIPE_H */
