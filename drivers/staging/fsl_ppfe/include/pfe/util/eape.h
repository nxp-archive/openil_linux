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
#ifndef _EAPE_H_
#define _EAPE_H_

#define EAPE_STATUS		(EAPE_BASE_ADDR + 0x0)
#define EAPE_INT_ENABLE		(EAPE_BASE_ADDR + 0x4)
#define EAPE_INT_SRC		(EAPE_BASE_ADDR + 0x8)
#define EAPE_HOST_INT_ENABLE	(EAPE_BASE_ADDR + 0xc)

/** The following bits represents to enable interrupts from host and to host
* from / to utilpe */

#define IRQ_EN_EFET_TO_UTIL	0x1
#define IRQ_EN_QB_TO_UTIL	0x2
#define IRQ_EN_INQ_TO_UTIL	0x4
#define IRQ_EN_EAPE_TO_UTIL	0x8
#define IRQ_EN_GPT_TMR_TO_UTIL	0x10
#define IRQ_EN_UART_TO_UTIL	0x20
#define IRQ_EN_SYSLP_TO_UTIL	0x40
#define IRQ_EN_UPEGP_TO_UTIL	0x80

/** Out interrupts */

#define IRQ_EN_EFET_OUT		0x100
#define IRQ_EN_QB_OUT		0x200
#define IRQ_EN_INQ_OUT		0x400
#define IRQ_EN_EAPE_OUT		0x800
#define IRQ_EN_GPT_TMR_OUT	0x1000
#define IRQ_EN_UART_OUT		0x2000
#define IRQ_EN_SYSLP_OUT	0x4000
#define IRQ_EN_UPEGP_OUT	0x8000

/** The following bits are enabled in the status register
 * which are mapped to IPSEC status register bits */
#define EAPE_IN_STAT_AVAIL      0x1
#define EAPE_OUT_STAT_AVAIL     0x2
#define EAPE_IN_CMD_AVAIL       0x4
#define EAPE_OUT_CMD_AVAIL      0x8

#endif /* _EAPE_H_ */
