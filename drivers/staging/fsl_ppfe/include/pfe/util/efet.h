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
#ifndef _UTIL_EFET_H_
#define _UTIL_EFET_H_

#define EFET_ENTRY_ADDR		0x00
#define EFET_ENTRY_SIZE		0x04
#define EFET_ENTRY_DMEM_ADDR	0x08
#define EFET_ENTRY_STATUS	0x0c
#define EFET_ENTRY_ENDIAN	0x10

#define CBUS2DMEM	0
#define DMEM2CBUS	1

#define EFET2BUS_LE     (1 << 0)

#define EFET1		0
#define EFET2		1
#define EFET3		2
#define MAX_UTIL_EFET_LEN	128

extern const unsigned long util_efet_baseaddr[3];
extern u32 util_efet_status;

/* The barrier call is an empirical work-around for an unknown bug: for some unknown reason, it solves
 * a UtilPE crash observed with LRO and packet steering. Other solutions also worked (e.g. barrier,
 * nop calls in other positions). However, no common pattern could be extracted from those solutions
 * to narrow down the source of the crash.
 */

#define __UTIL_EFET(i, cbus_addr, dmem_addr,len,dir) do { \
	__writel((len & 0x3FF) | (dir << 16), util_efet_baseaddr[i] + EFET_ENTRY_SIZE); \
	__writel(dmem_addr, util_efet_baseaddr[i] + EFET_ENTRY_DMEM_ADDR);\
	__writel(cbus_addr, util_efet_baseaddr[i] + EFET_ENTRY_ADDR);\
	nop();\
	}while(0)

#define UTIL_EFET(i, cbus_addr, dmem_addr,len,dir) do { \
	__UTIL_EFET(i, cbus_addr, dmem_addr, len, dir);	\
	util_efet_status |= (1 << i);			\
	} while(0)


/** Waits for the util efet to finish a transaction, blocking the caller
* (without updating the status).
* Can be called at any time.
*
* @param i      Efet index
*
*
*/
static inline void __util_efet_wait(int i)
{
        while (!(readl(util_efet_baseaddr[i] + EFET_ENTRY_STATUS) & 0x1)) ;
}

/** Waits for the util efet to finish a transaction, blocking the caller.
* Can be called at any time.
*
* @param i      Efet index
*
*/
static inline void util_efet_wait(int i)
{
	__util_efet_wait(i);
	
	util_efet_status &= ~(1 << i);
}

/** Asynchronous interface to util efet read/write functions.
* It will wait for the efet to finish previous transaction, but does not wait for the current transaction to finish.
*
* @param i              Efet index
* @param cbus_addr      Cbus address (must be 64bits aligned)
* @param dmem_addr      DMEM address (must be 64bits aligned)
* @param len            Number of bytes to copy (must be 64bits aligned size)
* @param dir            Direction of the transaction (0 - cbus to dmem, 1 - dmem to cbus)
*
*/
static inline void util_efet_async(int i, u32 cbus_addr, u32 dmem_addr, u32 len, u8 dir)
{
	if (util_efet_status & (1 << i))
		util_efet_wait(i);

	UTIL_EFET(i, cbus_addr, dmem_addr, len, dir);
}


static inline void util_efet_async0( u32 cbus_addr, u32 dmem_addr, u32 len, u8 dir)
{
	util_efet_async(0, cbus_addr, dmem_addr, len,dir);
}

/* EFET 2 is aways used for SYNC operations */
static inline void util_efet_sync2(u32 cbus_addr, u32 dmem_addr, u32 len, u8 dir)
{
	__UTIL_EFET(2, cbus_addr, dmem_addr, len,dir);
	__util_efet_wait(2);
}

void util_efet_sync0(u32 cbus_addr, u32 dmem_addr, u32 len, u8 dir);
#endif /* _UTIL_EFET_H_ */

