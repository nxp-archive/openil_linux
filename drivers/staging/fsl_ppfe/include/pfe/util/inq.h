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
#ifndef _INQ_H_
#define _INQ_H_

#define INQ_HOST_GP	(INQ_BASE_ADDR + 0x00) /* FIXME what are these for ? */
#define INQ_UPE_GP	(INQ_BASE_ADDR + 0x04) /* FIXME what are these for ? */

#define INQ_QB_PKTPTR	(INQ_BASE_ADDR + 0x08)
#define INQ_FIFO_CNT	(INQ_BASE_ADDR + 0x0c)

#endif /* _INQ_H_ */
