/* -*- linux-c -*-
 * linux/kernel/ipipe/timer.c
 *
 * Copyright (C) 2012 Gilles Chanteperdrix
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
 *
 * I-pipe timer request interface.
 */
#include <linux/ipipe.h>
#include <linux/percpu.h>
#include <linux/irqdesc.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <linux/ipipe_tickdev.h>
#include <linux/interrupt.h>
#include <linux/export.h>

unsigned long __ipipe_hrtimer_freq;

static LIST_HEAD(timers);
static IPIPE_DEFINE_SPINLOCK(lock);

static DEFINE_PER_CPU(struct ipipe_timer *, percpu_timer);

#ifdef CONFIG_GENERIC_CLOCKEVENTS
/*
 * Default request method: switch to oneshot mode if supported.
 */
static void ipipe_timer_default_request(struct ipipe_timer *timer, int steal)
{
	struct clock_event_device *evtdev = timer->host_timer;

	if (!(evtdev->features & CLOCK_EVT_FEAT_ONESHOT))
		return;

	if (evtdev->mode != CLOCK_EVT_MODE_ONESHOT) {
		evtdev->set_mode(CLOCK_EVT_MODE_ONESHOT, evtdev);
		evtdev->set_next_event(timer->freq / HZ, evtdev);
	}
}

/*
 * Default release method: return the timer to the mode it had when
 * starting.
 */
static void ipipe_timer_default_release(struct ipipe_timer *timer)
{
	struct clock_event_device *evtdev = timer->host_timer;

	evtdev->set_mode(evtdev->mode, evtdev);
	if (evtdev->mode == CLOCK_EVT_MODE_ONESHOT)
		evtdev->set_next_event(timer->freq / HZ, evtdev);
}

void ipipe_host_timer_register(struct clock_event_device *evtdev)
{
	struct ipipe_timer *timer = evtdev->ipipe_timer;

	if (timer == NULL)
		return;

	if (timer->request == NULL)
		timer->request = ipipe_timer_default_request;

	/*
	 * By default, use the same method as linux timer, on ARM at
	 * least, most set_next_event methods are safe to be called
	 * from Xenomai domain anyway.
	 */
	if (timer->set == NULL) {
		timer->timer_set = evtdev;
		timer->set = (typeof(timer->set))evtdev->set_next_event;
	}

	if (timer->release == NULL)
		timer->release = ipipe_timer_default_release;

	if (timer->name == NULL)
		timer->name = evtdev->name;

	if (timer->rating == 0)
		timer->rating = evtdev->rating;

	timer->freq = (1000000000ULL * evtdev->mult) >> evtdev->shift;

	if (timer->min_delay_ticks == 0)
		timer->min_delay_ticks =
			(evtdev->min_delta_ns * evtdev->mult) >> evtdev->shift;

	if (timer->cpumask == NULL)
		timer->cpumask = evtdev->cpumask;

	timer->host_timer = evtdev;

	ipipe_timer_register(timer);
}
#endif /* CONFIG_GENERIC_CLOCKEVENTS */

/*
 * register a timer: maintain them in a list sorted by rating
 */
void ipipe_timer_register(struct ipipe_timer *timer)
{
	struct ipipe_timer *t;
	unsigned long flags;

	if (timer->timer_set == NULL)
		timer->timer_set = timer;

	if (timer->cpumask == NULL)
		timer->cpumask = cpumask_of(smp_processor_id());

	spin_lock_irqsave(&lock, flags);

	list_for_each_entry(t, &timers, link) {
		if (t->rating <= timer->rating) {
			__list_add(&timer->link, t->link.prev, &t->link);
			goto done;
		}
	}
	list_add_tail(&timer->link, &timers);
  done:
	spin_unlock_irqrestore(&lock, flags);
}

static void ipipe_timer_request_sync(void)
{
	struct ipipe_timer *timer = __ipipe_raw_cpu_read(percpu_timer);
	struct clock_event_device *evtdev;
	int steal;

	if (!timer)
		return;

	evtdev = timer->host_timer;

#ifdef CONFIG_GENERIC_CLOCKEVENTS
	steal = evtdev != NULL && evtdev->mode != CLOCK_EVT_MODE_UNUSED;
#else /* !CONFIG_GENERIC_CLOCKEVENTS */
	steal = 1;
#endif /* !CONFIG_GENERIC_CLOCKEVENTS */

	timer->request(timer, steal);
}

/* Set up a timer as per-cpu timer for ipipe */
static void install_pcpu_timer(unsigned cpu, unsigned hrclock_freq,
			      struct ipipe_timer *t) {
	unsigned hrtimer_freq;
	unsigned long long tmp;

	if (__ipipe_hrtimer_freq == 0)
		__ipipe_hrtimer_freq = t->freq;

	per_cpu(ipipe_percpu.hrtimer_irq, cpu) = t->irq;
	per_cpu(percpu_timer, cpu) = t;

	hrtimer_freq = t->freq;
	if (__ipipe_hrclock_freq > UINT_MAX)
		hrtimer_freq /= 1000;

	t->c2t_integ = hrtimer_freq / hrclock_freq;
	tmp = (((unsigned long long)
		(hrtimer_freq % hrclock_freq)) << 32)
		+ hrclock_freq - 1;
	do_div(tmp, hrclock_freq);
	t->c2t_frac = tmp;
}

static void select_root_only_timer(unsigned cpu, unsigned hrclock_khz,
				   const struct cpumask *mask,
				   struct ipipe_timer *t) {
	unsigned icpu;
	struct clock_event_device *evtdev;

	/*
	 * If no ipipe-supported CPU shares an interrupt with the
	 * timer, we do not need to care about it.
	 */
	for_each_cpu(icpu, mask) {
		if (t->irq == per_cpu(ipipe_percpu.hrtimer_irq, icpu)) {
#ifdef CONFIG_GENERIC_CLOCKEVENTS
			evtdev = t->host_timer;
			if (evtdev && evtdev->mode == CLOCK_EVT_MODE_SHUTDOWN)
				continue;
#endif /* CONFIG_GENERIC_CLOCKEVENTS */
			goto found;
		}
	}

	return;

found:
	install_pcpu_timer(cpu, hrclock_khz, t);
}

/*
 * Choose per-cpu timers with the highest rating by traversing the
 * rating-sorted list for each CPU.
 */
int ipipe_select_timers(const struct cpumask *mask)
{
	unsigned hrclock_freq;
	unsigned long long tmp;
	struct ipipe_timer *t;
	struct clock_event_device *evtdev;
	unsigned long flags;
	unsigned cpu;
	cpumask_t fixup;

	if (!__ipipe_hrclock_ok()) {
		printk("I-pipe: high-resolution clock not working\n");
		return -ENODEV;
	}

	if (__ipipe_hrclock_freq > UINT_MAX) {
		tmp = __ipipe_hrclock_freq;
		do_div(tmp, 1000);
		hrclock_freq = tmp;
	} else
		hrclock_freq = __ipipe_hrclock_freq;

	spin_lock_irqsave(&lock, flags);

	/* First, choose timers for the CPUs handled by ipipe */
	for_each_cpu(cpu, mask) {
		list_for_each_entry(t, &timers, link) {
			if (!cpumask_test_cpu(cpu, t->cpumask))
				continue;

#ifdef CONFIG_GENERIC_CLOCKEVENTS
			evtdev = t->host_timer;
			if (evtdev && evtdev->mode == CLOCK_EVT_MODE_SHUTDOWN)
				continue;
#endif /* CONFIG_GENERIC_CLOCKEVENTS */
			goto found;
		}

		printk("I-pipe: could not find timer for cpu #%d\n",
		       cpu);
		goto err_remove_all;
found:
		install_pcpu_timer(cpu, hrclock_freq, t);
	}

	/*
	 * Second, check if we need to fix up any CPUs not supported
	 * by ipipe (but by Linux) whose interrupt may need to be
	 * forwarded because they have the same IRQ as an ipipe-enabled
	 * timer.
	 */
	cpumask_andnot(&fixup, cpu_online_mask, mask);

	for_each_cpu(cpu, &fixup) {
		list_for_each_entry(t, &timers, link) {
			if (!cpumask_test_cpu(cpu, t->cpumask))
				continue;

			select_root_only_timer(cpu, hrclock_freq, mask, t);
		}
	}

	spin_unlock_irqrestore(&lock, flags);

	flags = ipipe_critical_enter(ipipe_timer_request_sync);
	ipipe_timer_request_sync();
	ipipe_critical_exit(flags);

	return 0;

err_remove_all:
	spin_unlock_irqrestore(&lock, flags);

	for_each_cpu(cpu, mask) {
		per_cpu(ipipe_percpu.hrtimer_irq, cpu) = -1;
		per_cpu(percpu_timer, cpu) = NULL;
	}
	__ipipe_hrtimer_freq = 0;

	return -ENODEV;
}

static void ipipe_timer_release_sync(void)
{
	struct ipipe_timer *timer = __ipipe_raw_cpu_read(percpu_timer);

	if (timer)
		timer->release(timer);
}

void ipipe_timers_release(void)
{
	unsigned long flags;
	unsigned cpu;

	flags = ipipe_critical_enter(ipipe_timer_release_sync);
	ipipe_timer_release_sync();
	ipipe_critical_exit(flags);

	for_each_online_cpu(cpu) {
		per_cpu(ipipe_percpu.hrtimer_irq, cpu) = -1;
		per_cpu(percpu_timer, cpu) = NULL;
		__ipipe_hrtimer_freq = 0;
	}
}

static void __ipipe_ack_hrtimer_irq(unsigned int irq, struct irq_desc *desc)
{
	struct ipipe_timer *timer = __ipipe_raw_cpu_read(percpu_timer);

	if (desc)
		desc->ipipe_ack(irq, desc);
	if (timer->ack)
		timer->ack();
	if (desc)
		desc->ipipe_end(irq, desc);
}

int ipipe_timer_start(void (*tick_handler)(void),
		      void (*emumode)(enum clock_event_mode mode,
				      struct clock_event_device *cdev),
		      int (*emutick)(unsigned long evt,
				     struct clock_event_device *cdev),
		      unsigned cpu)
{
	struct clock_event_device *evtdev;
	struct ipipe_timer *timer;
	struct irq_desc *desc;
	unsigned long flags;
	int steal, ret;

	timer = per_cpu(percpu_timer, cpu);
	evtdev = timer->host_timer;

	flags = ipipe_critical_enter(NULL);

	ret = ipipe_request_irq(ipipe_head_domain, timer->irq,
				(ipipe_irq_handler_t)tick_handler,
				NULL, __ipipe_ack_hrtimer_irq);
	if (ret < 0 && ret != -EBUSY) {
		ipipe_critical_exit(flags);
		return ret;
	}

#ifdef CONFIG_GENERIC_CLOCKEVENTS
	steal = evtdev != NULL && evtdev->mode != CLOCK_EVT_MODE_UNUSED;
	if (steal && evtdev->ipipe_stolen == 0) {
		timer->real_mult = evtdev->mult;
		timer->real_shift = evtdev->shift;
		timer->real_set_mode = evtdev->set_mode;
		timer->real_set_next_event = evtdev->set_next_event;
		evtdev->mult = 1;
		evtdev->shift = 0;
		evtdev->set_mode = emumode;
		evtdev->set_next_event = emutick;
		evtdev->ipipe_stolen = 1;
	}

	ret = evtdev ? evtdev->mode : CLOCK_EVT_MODE_UNUSED;
#else /* CONFIG_GENERIC_CLOCKEVENTS */
	steal = 1;
	ret = 0;
#endif /* CONFIG_GENERIC_CLOCKEVENTS */

	ipipe_critical_exit(flags);

	desc = irq_to_desc(timer->irq);
	if (desc && irqd_irq_disabled(&desc->irq_data))
		ipipe_enable_irq(timer->irq);

	return ret;
}

void ipipe_timer_stop(unsigned cpu)
{
	unsigned long __maybe_unused flags;
	struct clock_event_device *evtdev;
	struct ipipe_timer *timer;
	struct irq_desc *desc;

	timer = per_cpu(percpu_timer, cpu);
	evtdev = timer->host_timer;

	desc = irq_to_desc(timer->irq);
	if (desc && irqd_irq_disabled(&desc->irq_data))
		ipipe_disable_irq(timer->irq);

#ifdef CONFIG_GENERIC_CLOCKEVENTS
	if (evtdev) {
		flags = ipipe_critical_enter(NULL);

		if (evtdev->ipipe_stolen) {
			evtdev->mult = timer->real_mult;
			evtdev->shift = timer->real_shift;
			evtdev->set_mode = timer->real_set_mode;
			evtdev->set_next_event = timer->real_set_next_event;
			timer->real_mult = timer->real_shift = 0;
			timer->real_set_mode = NULL;
			timer->real_set_next_event = NULL;
			evtdev->ipipe_stolen = 0;
		}

		ipipe_critical_exit(flags);
	}
#endif /* CONFIG_GENERIC_CLOCKEVENTS */

	ipipe_free_irq(ipipe_head_domain, timer->irq);
}

void ipipe_timer_set(unsigned long cdelay)
{
	unsigned long tdelay;
	struct ipipe_timer *t;

	t = __ipipe_raw_cpu_read(percpu_timer);

	/*
	 * Even though some architectures may use a 64 bits delay
	 * here, we voluntarily limit to 32 bits, 4 billions ticks
	 * should be enough for now. Would a timer needs more, an
	 * extra call to the tick handler would simply occur after 4
	 * billions ticks.
	 */
	if (cdelay > UINT_MAX)
		cdelay = UINT_MAX;

	tdelay = cdelay;
	if (t->c2t_integ != 1)
		tdelay *= t->c2t_integ;
	if (t->c2t_frac)
		tdelay += ((unsigned long long)cdelay * t->c2t_frac) >> 32;

	if (tdelay < t->min_delay_ticks
	    || t->set(tdelay, t->timer_set) < 0)
		ipipe_raise_irq(t->irq);
}
EXPORT_SYMBOL_GPL(ipipe_timer_set);

const char *ipipe_timer_name(void)
{
	return per_cpu(percpu_timer, 0)->name;
}
EXPORT_SYMBOL_GPL(ipipe_timer_name);

unsigned ipipe_timer_ns2ticks(struct ipipe_timer *timer, unsigned ns)
{
	unsigned long long tmp;
	BUG_ON(!timer->freq);
	tmp = (unsigned long long)ns * timer->freq;
	do_div(tmp, 1000000000);
	return tmp;
}

#ifdef CONFIG_IPIPE_HAVE_HOSTRT
/*
 * NOTE: The architecture specific code must only call this function
 * when a clocksource suitable for CLOCK_HOST_REALTIME is enabled.
 * The event receiver is responsible for providing proper locking.
 */
void ipipe_update_hostrt(struct timekeeper *tk)
{
	struct tk_read_base *tkr = &tk->tkr_mono;
	struct clocksource *clock = tkr->clock;
	struct ipipe_hostrt_data data;
	struct timespec xt;

	xt.tv_sec = tk->xtime_sec;
	xt.tv_nsec = (long)(tkr->xtime_nsec >> tkr->shift);
	ipipe_root_only();
	data.live = 1;
	data.cycle_last = tkr->cycle_last;
	data.mask = clock->mask;
	data.mult = tkr->mult;
	data.shift = tkr->shift;
	data.wall_time_sec = xt.tv_sec;
	data.wall_time_nsec = xt.tv_nsec;
	data.wall_to_monotonic.tv_sec = tk->wall_to_monotonic.tv_sec;
	data.wall_to_monotonic.tv_nsec = tk->wall_to_monotonic.tv_nsec;
	__ipipe_notify_kevent(IPIPE_KEVT_HOSTRT, &data);
}

#endif /* CONFIG_IPIPE_HAVE_HOSTRT */
