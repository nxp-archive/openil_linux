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

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kthread.h>
#else
#include "platform.h"
#endif

#include "pfe_mod.h"
#include "pfe_ctrl.h"

#include "pfe_ctrl_hal.h"

static struct pe_sync_mailbox CLASS_DMEM_SH2(sync_mailbox);
static struct pe_sync_mailbox TMU_DMEM_SH2(sync_mailbox);

static struct pe_msg_mailbox CLASS_DMEM_SH2(msg_mailbox);
static struct pe_msg_mailbox TMU_DMEM_SH2(msg_mailbox);

#if !defined(CONFIG_PLATFORM_LS1012A)
static u32 CLASS_DMEM_SH2(resume);
static u32 TMU_DMEM_SH2(resume);
#endif

#if !defined(CONFIG_UTIL_DISABLED)
static struct pe_sync_mailbox UTIL_DMEM_SH2(sync_mailbox);
static struct pe_msg_mailbox UTIL_DMEM_SH2(msg_mailbox);
static u32 UTIL_DMEM_SH2(resume);
#endif

static int pfe_ctrl_timer(void *data);

static int initialized = 0;

#define TIMEOUT_MS	1000

int relax(unsigned long end)
{
#ifdef __KERNEL__
	if (time_after(jiffies, end)) {
		if (time_after(jiffies, end + (TIMEOUT_MS * HZ) / 1000)) {
			return -1;
		}

		if (need_resched())
			schedule();
	}
#else
                udelay(1);
#endif

	return 0;
}

#if !defined(CONFIG_PLATFORM_LS1012A)
void pfe_ctrl_suspend(struct pfe_ctrl *ctrl)
{
	int id;

	kthread_stop(ctrl->timer_thread);

	mutex_lock(&ctrl->mutex);

	initialized = 0;
	for (id = CLASS0_ID; id <= CLASS_MAX_ID; id++)
			pe_dmem_write(id, cpu_to_be32(0x1), (unsigned long)virt_to_class_dmem(&class_resume), 4);

	for (id = TMU0_ID; id <= TMU_MAX_ID; id++) {
#if defined(CONFIG_PLATFORM_LS1012A)
		if(id == TMU2_ID) continue;
#endif
		pe_dmem_write(id, cpu_to_be32(0x1), (unsigned long)virt_to_class_dmem(&tmu_resume), 4);
	}

#if !defined(CONFIG_UTIL_DISABLED)
	pe_dmem_write(UTIL_ID, cpu_to_be32(0x1), (unsigned long)virt_to_class_dmem(&util_resume), 4);
#endif

	pe_sync_stop(&pfe->ctrl, 0xFF);

	mutex_unlock(&ctrl->mutex);
}

void pfe_ctrl_resume(struct pfe_ctrl *ctrl)
{
	mutex_lock(&ctrl->mutex);
	initialized = 1;
	pe_start(&pfe->ctrl, 0xFF);
	mutex_unlock(&ctrl->mutex);

	ctrl->timer_thread = kthread_create(pfe_ctrl_timer, ctrl, "pfe_ctrl_timer");

	wake_up_process(ctrl->timer_thread);
}
#endif

/** PE sync stop.
* Stops packet processing for a list of PE's (specified using a bitmask).
* The caller must hold ctrl->mutex.
*
* @param ctrl		Control context
* @param pe_mask	Mask of PE id's to stop
*
*/
int pe_sync_stop(struct pfe_ctrl *ctrl, int pe_mask)
{
	struct pe_sync_mailbox *mbox;
	int pe_stopped = 0;
	unsigned long end = jiffies + 2;
	int i;

#if defined(CONFIG_PLATFORM_LS1012A)
	//TODO Util should be removed after IPSec is ported
	pe_mask &= 0x2FF;  //Exclude Util + TMU2 
#endif
	for (i = 0; i < MAX_PE; i++)
		if (pe_mask & (1 << i)) {
			mbox = (void *)ctrl->sync_mailbox_baseaddr[i];

			pe_dmem_write(i, cpu_to_be32(0x1), (unsigned long)&mbox->stop, 4);
		}

	while (pe_stopped != pe_mask) {
		for (i = 0; i < MAX_PE; i++)
			if ((pe_mask & (1 << i)) && !(pe_stopped & (1 << i))) {
				mbox = (void *)ctrl->sync_mailbox_baseaddr[i];

				if (pe_dmem_read(i, (unsigned long)&mbox->stopped, 4) & cpu_to_be32(0x1))
					pe_stopped |= (1 << i);
			}

		if (relax(end) < 0)
			goto err;
	}

	return 0;

err:
	printk(KERN_ERR "%s: timeout, %x %x\n", __func__, pe_mask, pe_stopped);

	for (i = 0; i < MAX_PE; i++)
		if (pe_mask & (1 << i)) {
			mbox = (void *)ctrl->sync_mailbox_baseaddr[i];

			pe_dmem_write(i, cpu_to_be32(0x0), (unsigned long)&mbox->stop, 4);
	}

	return -EIO;
}

/** PE start.
* Starts packet processing for a list of PE's (specified using a bitmask).
* The caller must hold ctrl->mutex.
*
* @param ctrl		Control context
* @param pe_mask	Mask of PE id's to start
*
*/
void pe_start(struct pfe_ctrl *ctrl, int pe_mask)
{
	struct pe_sync_mailbox *mbox;
	int i;

#if defined(CONFIG_PLATFORM_LS1012A)
	//TODO Util should be removed after IPSec is ported
	pe_mask &= 0x2FF;  //Exclude Util + TMU2 
#endif
	for (i = 0; i < MAX_PE; i++)
		if (pe_mask & (1 << i)) {

			mbox = (void *)ctrl->sync_mailbox_baseaddr[i];

			pe_dmem_write(i, cpu_to_be32(0x0), (unsigned long)&mbox->stop, 4);
		}
}


/** Sends a control request to a given PE (to copy data to/from internal memory from/to DDR).
* The caller must hold ctrl->mutex.
*
* @param ctrl		Control context
* @param id		PE id
* @param dst		Physical destination address of data
* @param src		Physical source address of data
* @param len		Data length
*
*/
int pe_request(struct pfe_ctrl *ctrl, int id, unsigned short cmd_type, unsigned long dst, unsigned long src, int len)
{
	struct pe_msg_mailbox mbox = {
		.dst = cpu_to_be32(dst),
		.src = cpu_to_be32(src),
		.len = cpu_to_be32(len),
		.request = cpu_to_be32((cmd_type << 16) | 0x1),
	};
	struct pe_msg_mailbox *pmbox = (void *)ctrl->msg_mailbox_baseaddr[id];
	unsigned long end = jiffies + 2;
	u32 rc;

	/* This works because .request is written last */
	pe_dmem_memcpy_to32(id, (unsigned long)pmbox, &mbox, sizeof(mbox));

	while ((rc = pe_dmem_read(id, (unsigned long)&pmbox->request, 4)) & cpu_to_be32(0xffff)) {
		if (relax(end) < 0)
			goto err;
	}

	rc = be32_to_cpu(rc);

	return rc >> 16;

err:
	printk(KERN_ERR "%s: timeout, %x\n", __func__, be32_to_cpu(rc));
	pe_dmem_write(id, cpu_to_be32(0), (unsigned long)&pmbox->request, 4);
	return -EIO;
}


/** Control code timer thread.
*
* A kernel thread is used so that the timer code can be run under the control path mutex.
* The thread wakes up regularly and checks if any timer in the timer list as expired.
* The timers are re-started automatically.
* The code tries to keep the number of times a timer runs per unit time constant on average,
* if the thread scheduling is delayed, it's possible for a particular timer to be scheduled in
* quick succession to make up for the lost time.
*
* @param data	Pointer to the control context structure
*
* @return	0 on sucess, a negative value on error
*
*/
static int pfe_ctrl_timer(void *data)
{
	struct pfe_ctrl *ctrl = data;
	TIMER_ENTRY *timer, *next;

	printk(KERN_INFO "%s\n", __func__);

	while (1)
	{
		schedule_timeout_uninterruptible(ctrl->timer_period);

		mutex_lock(&ctrl->mutex);

		list_for_each_entry_safe(timer, next, &ctrl->timer_list, list)
		{
			if (time_after(jiffies, timer->timeout))
			{
				timer->timeout += timer->period;

				timer->handler();
			}
		}

		mutex_unlock(&ctrl->mutex);

		if (kthread_should_stop())
			break;
	}

	printk(KERN_INFO "%s exiting\n", __func__);

	return 0;
}


int pfe_ctrl_init(struct pfe *pfe)
{
	struct pfe_ctrl *ctrl = &pfe->ctrl;
	int id;
	int rc;

	printk(KERN_INFO "%s\n", __func__);

	mutex_init(&ctrl->mutex);
	spin_lock_init(&ctrl->lock);

	ctrl->timer_period = HZ / TIMER_TICKS_PER_SEC;

	INIT_LIST_HEAD(&ctrl->timer_list);

	/*INIT_WORK(&ctrl->work, comcerto_fpp_workqueue);*/

	INIT_LIST_HEAD(&ctrl->msg_list);

	for (id = CLASS0_ID; id <= CLASS_MAX_ID; id++) {
		ctrl->sync_mailbox_baseaddr[id] = virt_to_class_dmem(&class_sync_mailbox);
		ctrl->msg_mailbox_baseaddr[id] = virt_to_class_dmem(&class_msg_mailbox);
	}

	for (id = TMU0_ID; id <= TMU_MAX_ID; id++) {
#if defined(CONFIG_PLATFORM_LS1012A)
		if(id == TMU2_ID) continue;
#endif
		ctrl->sync_mailbox_baseaddr[id] = virt_to_tmu_dmem(&tmu_sync_mailbox);
		ctrl->msg_mailbox_baseaddr[id] = virt_to_tmu_dmem(&tmu_msg_mailbox);
	}

#if !defined(CONFIG_UTIL_DISABLED)
	ctrl->sync_mailbox_baseaddr[UTIL_ID] = virt_to_util_dmem(&util_sync_mailbox);
	ctrl->msg_mailbox_baseaddr[UTIL_ID] = virt_to_util_dmem(&util_msg_mailbox);
#endif

	ctrl->hash_array_baseaddr = pfe->ddr_baseaddr + ROUTE_TABLE_BASEADDR;
	ctrl->hash_array_phys_baseaddr = pfe->ddr_phys_baseaddr + ROUTE_TABLE_BASEADDR;
	ctrl->ipsec_lmem_phys_baseaddr =  CBUS_VIRT_TO_PFE(LMEM_BASE_ADDR + IPSEC_LMEM_BASEADDR);
	ctrl->ipsec_lmem_baseaddr = (LMEM_BASE_ADDR + IPSEC_LMEM_BASEADDR);

	ctrl->timer_thread = kthread_create(pfe_ctrl_timer, ctrl, "pfe_ctrl_timer");
	if (IS_ERR(ctrl->timer_thread))
	{
		printk (KERN_ERR "%s: kthread_create() failed\n", __func__);
		rc = PTR_ERR(ctrl->timer_thread);
		goto err0;
	}
	
	ctrl->dev = pfe->dev;

	wake_up_process(ctrl->timer_thread);

	printk(KERN_INFO "%s finished\n", __func__);

	initialized = 1;

	return 0;

err0:
	return rc;
}


void pfe_ctrl_exit(struct pfe *pfe)
{
	struct pfe_ctrl *ctrl = &pfe->ctrl;

	printk(KERN_INFO "%s\n", __func__);

	initialized = 0;

	kthread_stop(ctrl->timer_thread);
}
