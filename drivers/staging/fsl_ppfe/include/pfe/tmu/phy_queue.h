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
#ifndef _PHY_QUEUE_H_
#define _PHY_QUEUE_H_

#define PHY_QUEUE_SHAPER_STATUS	(PHY_QUEUE_BASE_ADDR + 0x00)	/**< [28:19] same as SHAPER_STATUS, [18:3] same as QUEUE_STATUS, [2:0] must be zero before a new packet may be dequeued */
#define QUEUE_STATUS		(PHY_QUEUE_BASE_ADDR + 0x04)	/**< [15:0] bit mask of input queues with pending packets */

#define QUEUE0_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x08)
#define QUEUE1_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x0c)
#define QUEUE2_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x10)
#define QUEUE3_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x14)
#define QUEUE4_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x18)
#define QUEUE5_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x1c)
#define QUEUE6_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x20)
#define QUEUE7_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x24)
#define QUEUE8_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x28)
#define QUEUE9_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x2c)
#define QUEUE10_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x30)
#define QUEUE11_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x34)
#define QUEUE12_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x38)
#define QUEUE13_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x3c)
#define QUEUE14_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x40)
#define QUEUE15_PKT_LEN		(PHY_QUEUE_BASE_ADDR + 0x44)
#define QUEUE_RESULT0		(PHY_QUEUE_BASE_ADDR + 0x48)	/**< [7] set to one to indicate output PHY (TMU0->PHY0, TMU1->PHY1, TMU2->PHY2, TMU3->PHY3), [6:0] winner input queue number */
#define QUEUE_RESULT1		(PHY_QUEUE_BASE_ADDR + 0x4c)	/**< [7] set to one to indicate output PHY (TMU0->PHY0, TMU1->PHY1, TMU2->PHY2, TMU3->PHY4), [6:0] winner input queue number */
#define QUEUE_RESULT2		(PHY_QUEUE_BASE_ADDR + 0x50)	/**< [7] set to one to indicate output PHY (TMU0->PHY0, TMU1->PHY1, TMU2->PHY2, TMU3->PHY5), [6:0] winner input queue number */
#define TMU_PE_GP_REG		(PHY_QUEUE_BASE_ADDR + 0x54)
#define QUEUE_GBL_PKTLEN	(PHY_QUEUE_BASE_ADDR + 0x5c)
#define QUEUE_GBL_PKTLEN_MASK	(PHY_QUEUE_BASE_ADDR + 0x60)

#define QUEUE_RESULT0_REGOFFSET	(QUEUE_RESULT0 - QUEUE_RESULT0)
#define QUEUE_RESULT1_REGOFFSET	(QUEUE_RESULT1 - QUEUE_RESULT0)
#define QUEUE_RESULT2_REGOFFSET	(QUEUE_RESULT2 - QUEUE_RESULT0)

#define TEQ_HTD                 (1 << 22)
#define TEQ_HWRED               (1 << 21)


#endif /* _PHY_QUEUE_H_ */
