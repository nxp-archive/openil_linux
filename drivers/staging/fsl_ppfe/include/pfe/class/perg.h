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
#ifndef _PERG_H_
#define _PERG_H_

#define PERG_QB_BUF_STATUS		(PERG_BASE_ADDR + 0x00)
#define PERG_RO_BUF_STATUS		(PERG_BASE_ADDR + 0x04)
#define PERG_CLR_QB_BUF_STATUS		(PERG_BASE_ADDR + 0x08)
#define PERG_SET_RO_BUF_STATUS		(PERG_BASE_ADDR + 0x0c)
#define PERG_CLR_RO_ERR_PKT		(PERG_BASE_ADDR + 0x10)
#define PERG_CLR_BMU2_ERR_PKT		(PERG_BASE_ADDR + 0x14)

#define PERG_ID				(PERG_BASE_ADDR + 0x18)
#define PERG_TIMER1			(PERG_BASE_ADDR + 0x1c)
//FIXME #define PERG_TIMER2			(PERG_BASE_ADDR + 0x20)
#define PERG_BMU1_CURRDEPTH		(PERG_BASE_ADDR + 0x20)
#define PERG_BMU2_CURRDEPTH		(PERG_BASE_ADDR + 0x24)
#define PERG_HOST_GP			(PERG_BASE_ADDR + 0x2c)
#define PERG_PE_GP			(PERG_BASE_ADDR + 0x30)
#define PERG_INT_ENABLE			(PERG_BASE_ADDR + 0x34)
#define PERG_INT_SRC			(PERG_BASE_ADDR + 0x38)

#endif /* _PERG_H_ */
