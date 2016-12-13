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
#ifndef _SCHED_H_
#define _SCHED_H_

/* Offsets from SCHEDx_BASE_ADDR */
#define SCHED_CTRL			0x00
#define SCHED_SLOT_TIME			0x04
#define SCHED_RES			0x08
#define SCHED_QUEUE_ALLOC0		0x0c
#define SCHED_QUEUE_ALLOC1		0x10
#define SCHED_BW			0x14
#define SCHED_GUR_DEF_CTR		0x18
#define SCHED_AVL_CTR			0x1c
#define SCHED_QU0_WGHT			0x20
#define SCHED_QU1_WGHT			0x24
#define SCHED_QU2_WGHT			0x28
#define SCHED_QU3_WGHT			0x2c
#define SCHED_QU4_WGHT			0x30
#define SCHED_QU5_WGHT			0x34
#define SCHED_QU6_WGHT			0x38
#define SCHED_QU7_WGHT			0x3c
#define SCHED_QUE0_DEFICIT_CNT		0x40
#define SCHED_QUE1_DEFICIT_CNT		0x44
#define SCHED_QUE2_DEFICIT_CNT		0x48
#define SCHED_QUE3_DEFICIT_CNT		0x4c
#define SCHED_QUE4_DEFICIT_CNT		0x50
#define SCHED_QUE5_DEFICIT_CNT		0x54
#define SCHED_QUE6_DEFICIT_CNT		0x58
#define SCHED_QUE7_DEFICIT_CNT		0x5c
#define SCHED_PKT_LEN			0x60

#define SCHED_CTRL_ALGOTYPE(x) 		(((x) & 0xf) << 0)
#define SCHED_CTRL_CALQUOTA(x) 		(((x) & 0x1) << 4)
#define SCHED_CTRL_ACTIVE_Q(x) 		(((x) & 0xff) << 8)
#define SCHED_CTRL_SHARE_BW(x) 		(((x) & 0xff) << 16)
#define SCHED_CTRL_BARROW_BW(x) 	(((x) & 0xff) << 24)

#define SCHED_QUEUE_ALLOC(x, b)	 	(((x) & 0x1f) << (b))

#define SCHED_QUEUE_ALLOC0_QUEUEA(x)	(((x) & 0x1f) << 0)
#define SCHED_QUEUE_ALLOC0_QUEUEB(x)	(((x) & 0x1f) << 8)
#define SCHED_QUEUE_ALLOC0_QUEUEC(x)	(((x) & 0x1f) << 16)
#define SCHED_QUEUE_ALLOC0_QUEUED(x)	(((x) & 0x1f) << 24)

#define SCHED_QUEUE_ALLOC0_RES0(x)	(((x) & 0x7) << 5)
#define SCHED_QUEUE_ALLOC0_RES1(x)	(((x) & 0x7) << 13)
#define SCHED_QUEUE_ALLOC0_RES2(x)	(((x) & 0x7) << 21)
#define SCHED_QUEUE_ALLOC0_RES3(x)	(((x) & 0x7) << 29)

#define SCHED_QUEUE_ALLOC1_QUEUEA(x)	(((x) & 0x1f) << 0)
#define SCHED_QUEUE_ALLOC1_QUEUEB(x)	(((x) & 0x1f) << 8)
#define SCHED_QUEUE_ALLOC1_QUEUEC(x)	(((x) & 0x1f) << 16)
#define SCHED_QUEUE_ALLOC1_QUEUED(x)	(((x) & 0x1f) << 24)

#endif /* _SCHED_H_ */
