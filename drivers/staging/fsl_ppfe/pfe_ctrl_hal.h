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

#ifndef _PFE_CTRL_HAL_H_
#define _PFE_CTRL_HAL_H_

#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/slab.h>
#include <asm/byteorder.h>
#include <asm/io.h>

#include "pfe_mod.h"

#define CLASS_DMEM_SH(var) __attribute__((section(".class_dmem_sh_" #var))) var
#define CLASS_PE_LMEM_SH(var) __attribute__((section(".class_pe_lmem_sh_" #var))) var
#define TMU_DMEM_SH(var) __attribute__((section(".tmu_dmem_sh_" #var))) var
#define UTIL_DMEM_SH(var) __attribute__((section(".util_dmem_sh_" #var))) var
#define UTIL_DDR_SH(var) __attribute__((section(".util_ddr_sh_" #var))) var

#define CLASS_DMEM_SH2(var) __attribute__((section(".class_dmem_sh_" #var))) class_##var
#define CLASS_PE_LMEM_SH2(var) __attribute__((section(".class_pe_lmem_sh_" #var))) class_##var
#define TMU_DMEM_SH2(var) __attribute__((section(".tmu_dmem_sh_" #var))) tmu_##var
#define UTIL_DMEM_SH2(var) __attribute__((section(".util_dmem_sh_" #var))) util_##var

/** Translate the name of a shared variable to its PFE counterpart.
 * Those macros may be used to determine the address of a shared variable,
 * and will work even if the variable is accessed through a macro, as is the case
 * with most fields of gFppGlobals.
 */
#define CONCAT(str, var) str##var
#define CLASS_VARNAME2(var) CONCAT(class_, var)
#define UTIL_VARNAME2(var) CONCAT(util_, var)
#define TMU_VARNAME2(var) CONCAT(tmu_, var)

typedef struct tHostMessage {
	u16	length;
	u16	code;
	u16	data[128];
} HostMessage;

HostMessage *msg_alloc(void);
void msg_free(HostMessage *msg);
int msg_send(HostMessage *msg);


unsigned long virt_to_class(void *p);
unsigned long virt_to_class_dmem(void *p);
unsigned long virt_to_class_pe_lmem(void *p);
unsigned long virt_to_tmu_dmem(void *p);
unsigned long virt_to_util_dmem(void *p);
unsigned long virt_to_util_ddr(void *p);
void * virt_to_util_virt(void *p);
unsigned long virt_to_phys_iram(void *p);
unsigned long virt_to_phys_ipsec_lmem(void *p);
unsigned long virt_to_phys_ipsec_axi(void *p);


#define TIMER_TICKS_PER_SEC	100

#if TIMER_TICKS_PER_SEC > HZ
#error TIMER_TICKS_PER_SEC is too high
#endif


typedef void (* TIMER_HANDLER)(void);

typedef struct {
	struct list_head list;
	unsigned long timeout;
	unsigned long period;
	TIMER_HANDLER handler;
	char running;
} TIMER_ENTRY;


/** Initializes a timer structure.
* Must be called once for each TIMER_ENTRY structure.
* The caller must be holding the ctrl->mutex.
*
* @param timer		pointer to the timer to be initialized
* @param handler	timer handler function pointer
*
*/
void timer_init(TIMER_ENTRY *timer, TIMER_HANDLER handler);

/** Adds a timer to the running timer list.
* It's safe to call even if the timer was already running. In this case we just update the granularity.
* The caller must be holding the ctrl->mutex.
*
* @param timer		pointer to the timer to be added
* @param granularity	granularity of the timer (in timer tick units)
*
*/
void timer_add(TIMER_ENTRY *timer, u16 granularity);

/** Deletes a timer from the running timer list.
* It's safe to call even if the timer is no longer running.
* The caller must be holding the ctrl->mutex.
*
* @param timer	pointer to the timer to be removed
*/
void timer_del(TIMER_ENTRY *timer);

void *Heap_Alloc(int size);

#define Heap_Alloc_ARAM(s)	Heap_Alloc(s)
#define __Heap_Alloc(h, s)		Heap_Alloc(s)
void Heap_Free(void *p);

#endif /* _PFE_CTRL_HAL_H_ */
