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
#ifndef _CLASS_EFET_H_
#define _CLASS_EFET_H_

//#define CLASS_EFET_ASYNC	1

#define CLASS_EFET_ENTRY_ADDR		(EFET_BASE_ADDR + 0x00)
#define CLASS_EFET_ENTRY_SIZE		(EFET_BASE_ADDR + 0x04)
#define CLASS_EFET_ENTRY_DMEM_ADDR	(EFET_BASE_ADDR + 0x08)
#define CLASS_EFET_ENTRY_STATUS		(EFET_BASE_ADDR + 0x0c)
#define CLASS_EFET_ENTRY_ENDIAN		(EFET_BASE_ADDR + 0x10)

#define CBUS2DMEM	0
#define DMEM2CBUS	1

#define EFET2BUS_LE     (1 << 0)
#define PE2BUS_LE	(1 << 1)

#ifdef CLASS_EFET_ASYNC
void class_efet_async(u32 cbus_addr, u32 dmem_addr, u32 len, u32 dir);
#endif

void class_efet_sync(u32 cbus_addr, u32 dmem_addr, u32 len, u32 dir);


#endif /* _CLASS_EFET_H_ */

