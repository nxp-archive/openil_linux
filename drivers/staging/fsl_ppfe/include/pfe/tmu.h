/*
 *  Copyright (c) 2011, 2014 Freescale Semiconductor, Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
*/
#ifndef _TMU_H_
#define _TMU_H_

#define TMU_DMEM_BASE_ADDR	0x00000000
#define TMU_PMEM_BASE_ADDR	0x00010000

#define CBUS_BASE_ADDR		0xc0000000
#define TMU_APB_BASE_ADDR	0xc1000000

#if defined (COMCERTO_2000_TMU) || defined (COMCERTO_2000_CONTROL)

#include "cbus.h"

#define GPT_BASE_ADDR		(TMU_APB_BASE_ADDR + 0x00000)
#define UART_BASE_ADDR		(TMU_APB_BASE_ADDR + 0x10000)

#define SHAPER0_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x020000)
#define SHAPER1_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x030000)
#define SHAPER2_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x040000)
#define SHAPER3_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x050000)
#define SHAPER4_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x060000)
#define SHAPER5_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x070000)
#define SHAPER6_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x080000)
#define SHAPER7_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x090000)
#define SHAPER8_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x0a0000)
#define SHAPER9_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x0b0000)

#define SCHED0_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x1c0000)
#define SCHED1_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x1d0000)
#define SCHED2_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x1e0000)
#define SCHED3_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x1f0000)
#define SCHED4_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x200000)
#define SCHED5_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x210000)
#define SCHED6_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x220000)
#define SCHED7_BASE_ADDR	(TMU_APB_BASE_ADDR + 0x230000)

#define SHAPER_STATUS		(TMU_APB_BASE_ADDR + 0x270000) /**< [9:0] bitmask of shapers that have positive credit */

#include "gpt.h"
#include "uart.h"
#include "tmu/shaper.h"
#include "tmu/sched.h"

#endif

#define PHY_QUEUE_BASE_ADDR (TMU_APB_BASE_ADDR + 0x260000)

#include "tmu/phy_queue.h"

#endif /* _TMU_H_ */
