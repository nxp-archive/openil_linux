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
#ifndef _MAC_HASH_H_
#define _MAC_HASH_H_

#define MAC_HASH_REQ1_BASE_ADDR		(MAC_HASH_BASE_ADDR + 0x000)
#define MAC_HASH_REQ2_BASE_ADDR		(MAC_HASH_BASE_ADDR + 0x020)
#define MAC_HASH_REQ3_BASE_ADDR		(MAC_HASH_BASE_ADDR + 0x040)
#define MAC_HASH_REQ4_BASE_ADDR		(MAC_HASH_BASE_ADDR + 0x060)
#define MAC_HASH_REQ5_BASE_ADDR		(MAC_HASH_BASE_ADDR + 0x080)
#define MAC_HASH_REQ6_BASE_ADDR		(MAC_HASH_BASE_ADDR + 0x0a0)
#define MAC_HASH_REQ7_BASE_ADDR		(MAC_HASH_BASE_ADDR + 0x0c0)
#define MAC_HASH_REQ8_BASE_ADDR		(MAC_HASH_BASE_ADDR + 0x0e0)

#define MAC_HASH_REQ_CMD(i)		(MAC_HASH_REQ##i##_BASE_ADDR + 0x000)
#define MAC_HASH_REQ_MAC1_ADDR(i)	(MAC_HASH_REQ##i##_BASE_ADDR + 0x004)
#define MAC_HASH_REQ_MAC2_ADDR(i)	(MAC_HASH_REQ##i##_BASE_ADDR + 0x008)
#define MAC_HASH_REQ_MASK1_ADDR(i)	(MAC_HASH_REQ##i##_BASE_ADDR + 0x00c)
#define MAC_HASH_REQ_MASK2_ADDR(i)	(MAC_HASH_REQ##i##_BASE_ADDR + 0x010)
#define MAC_HASH_REQ_ENTRY(i)		(MAC_HASH_REQ##i##_BASE_ADDR + 0x014)
#define MAC_HASH_REQ_STATUS(i)		(MAC_HASH_REQ##i##_BASE_ADDR + 0x018)
#define MAC_HASH_REQ_ENTRY_MAYCH(i)	(MAC_HASH_REQ##i##_BASE_ADDR + 0x01c)


#define MAC_HASH_FREELIST_PTR_HEAD	(MAC_HASH_BASE_ADDR + 0x100)
#define MAC_HASH_FREELIST_PTR_TAIL	(MAC_HASH_BASE_ADDR + 0x104)
#define MAC_HASH_FREELIST_ENTRIES_ADDR	(MAC_HASH_BASE_ADDR + 0x108)


#define HASH_CMD_INIT		1
#define HASH_CMD_ADD		2
#define HASH_CMD_DELETE		3
#define HASH_CMD_UPDATE		4
#define HASH_CMD_SEARCH		5
#define HASH_CMD_MEM_READ	6
#define HASH_CMD_MEM_WRITE	7

#endif /* _MAC_HASH_H_ */

