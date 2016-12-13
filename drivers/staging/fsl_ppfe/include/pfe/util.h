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
#ifndef _UTIL_H_
#define _UTIL_H_

#define UTIL_DMEM_BASE_ADDR	0x00000000
#define UTIL_DMEM_SIZE		0x00002000
#define UTIL_DMEM_END		(UTIL_DMEM_BASE_ADDR + UTIL_DMEM_SIZE)

#define IS_DMEM(addr, len)	(((unsigned long)(addr) >= UTIL_DMEM_BASE_ADDR) && (((unsigned long)(addr) + (len)) <= UTIL_DMEM_END))

#define CBUS_BASE_ADDR		0xc0000000
#define UTIL_APB_BASE_ADDR	0xc1000000

#include "cbus.h"

#define GPT_BASE_ADDR		(UTIL_APB_BASE_ADDR + 0x00000)
#define UART_BASE_ADDR		(UTIL_APB_BASE_ADDR + 0x10000)
#define EAPE_BASE_ADDR		(UTIL_APB_BASE_ADDR + 0x20000)
#define INQ_BASE_ADDR		(UTIL_APB_BASE_ADDR + 0x30000)
#define EFET1_BASE_ADDR		(UTIL_APB_BASE_ADDR + 0x40000)
#define EFET2_BASE_ADDR		(UTIL_APB_BASE_ADDR + 0x50000)
#define EFET3_BASE_ADDR		(UTIL_APB_BASE_ADDR + 0x60000)


#include "gpt.h"
#include "uart.h"
#include "util/eape.h"
#include "util/inq.h"
#include "util/efet.h"


#endif /* _UTIL_H_ */
