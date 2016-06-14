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
#ifndef _UART_H_
#define _UART_H_

#define UART_THR	(UART_BASE_ADDR + 0x00)
#define UART_IER	(UART_BASE_ADDR + 0x04)
#define UART_IIR	(UART_BASE_ADDR + 0x08)
#define UART_LCR	(UART_BASE_ADDR + 0x0c)
#define UART_MCR	(UART_BASE_ADDR + 0x10)
#define UART_LSR	(UART_BASE_ADDR + 0x14)
#define UART_MDR	(UART_BASE_ADDR + 0x18)
#define UART_SCRATCH	(UART_BASE_ADDR + 0x1c)

#endif /* _UART_H_ */
