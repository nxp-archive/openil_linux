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

/* OS abstraction functions used by PFE control code */

#include <linux/slab.h>

#include "pfe_ctrl_hal.h"

#include "pfe_mod.h"

extern char *__class_dmem_sh;
extern char *__tmu_dmem_sh;
#if !defined(CONFIG_UTIL_DISABLED)
extern char *__util_dmem_sh;
extern char *__util_ddr_sh;
#endif

HostMessage msg_buf;
static int msg_buf_used = 0;
unsigned long virt_to_class_dmem(void *p)
{
	struct pfe_ctrl *ctrl = &pfe->ctrl;

	if (p)
		return (unsigned long)p - (unsigned long)&__class_dmem_sh + ctrl->class_dmem_sh;
	else
		return 0;
}
unsigned long virt_to_tmu_dmem(void *p)
{
	struct pfe_ctrl *ctrl = &pfe->ctrl;

	if (p)
		return (unsigned long)p - (unsigned long)&__tmu_dmem_sh + ctrl->tmu_dmem_sh;
	else
		return 0;
}


#if !defined(CONFIG_UTIL_DISABLED)
unsigned long virt_to_util_dmem(void *p)
{
	struct pfe_ctrl *ctrl = &pfe->ctrl;

	if (p)
		return (unsigned long)p - (unsigned long)&__util_dmem_sh + ctrl->util_dmem_sh;
	else
		return 0;
}

/** Returns the DDR physical address of a Util PE shared DDR variable.
 *
 * @param p	pointer (kernel space, virtual) to be converted to a physical address.
 */
unsigned long virt_to_util_ddr(void *p)
{
	struct pfe_ctrl *ctrl = &pfe->ctrl;

	if (p)
		return (unsigned long)p - (unsigned long)&__util_ddr_sh + ctrl->util_ddr_sh;
	else
		return 0;
}
/** Returns the virtual address of a Util PE shared DDR variable.
 *
 * @param p pointer (kernel space, virtual) to be converted to a pointer (usable in kernel space)
 * pointing to the actual data.
 */

void * virt_to_util_virt(void *p)
{
	if (p)
		return DDR_PHYS_TO_VIRT(virt_to_util_ddr(p));
	else
		return NULL;
}
#endif
unsigned long virt_to_phys_iram(void *p)
{
	if (p)
		return (p - pfe->iram_baseaddr) + pfe->iram_phys_baseaddr;
	else
		return 0;
}

unsigned long virt_to_phys_ipsec_lmem(void *p)
{
	struct pfe_ctrl *ctrl = &pfe->ctrl;

	if (p)
		return (p - ctrl->ipsec_lmem_baseaddr) + ctrl->ipsec_lmem_phys_baseaddr;
	else
		return 0;
}

unsigned long virt_to_phys_ipsec_axi(void *p)
{
	if (p)
		return (p - pfe->ipsec_baseaddr) + pfe->ipsec_phys_baseaddr;
	else
		return 0;
}


HostMessage *msg_alloc(void)
{
	if (msg_buf_used)
	{
		printk(KERN_ERR "%s: failed\n", __func__);
		return NULL;
	}

	msg_buf_used = 1;

	return &msg_buf;
}

void msg_free(HostMessage *msg)
{
	if (!msg_buf_used)
		printk(KERN_ERR "%s: freing already free msg buffer\n", __func__);

	msg_buf_used = 0;
}

int msg_send(HostMessage *msg)
{
	struct pfe_ctrl *ctrl = &pfe->ctrl;
	int rc = -1;

	if (!ctrl->event_cb)
		goto out;

	if (ctrl->event_cb(msg->code, msg->length, msg->data) < 0)
		goto out;

	rc = 0;

out:
	msg_free(msg);

	return rc;
}


void timer_init(TIMER_ENTRY *timer, TIMER_HANDLER handler)
{
	timer->handler = handler;
	timer->running = 0;
}


void timer_add(TIMER_ENTRY *timer, u16 granularity)
{
	struct pfe_ctrl *ctrl = &pfe->ctrl;


	timer->period = granularity;
	timer->timeout = jiffies + timer->period;

	if (!timer->running)
	{
		list_add(&timer->list, &ctrl->timer_list);
		timer->running = 1;
	}
}


void timer_del(TIMER_ENTRY *timer)
{

	if (timer->running)
	{
		list_del(&timer->list);
		timer->running = 0;
	}
}


void *Heap_Alloc(int size)
{
	/* FIXME we may want to use dma API's and use non cacheable memory */
	return pfe_kmalloc(size, GFP_KERNEL);
}


void Heap_Free(void *p)
{
	pfe_kfree(p);
}
