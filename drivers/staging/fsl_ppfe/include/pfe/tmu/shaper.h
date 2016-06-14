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
#ifndef _SHAPER_H_
#define _SHAPER_H_

/* Offsets from SHAPPERx_BASE_ADDR */
#define SHAPER_CTRL		0x00
#define SHAPER_WEIGHT		0x04
#define SHAPER_PKT_LEN		0x08

#define SHAPER_CTRL_ENABLE(x) 	(((x) & 0x1) << 0)
#define SHAPER_CTRL_QNO(x) 	(((x) & 0x3f) << 1)
#define SHAPER_CTRL_CLKDIV(x) 	(((x) & 0xffff) << 16)

#define SHAPER_WEIGHT_FRACWT(x) 	(((x) & 0xff) << 0)
#define SHAPER_WEIGHT_INTWT(x) 		(((x) & 0x3) << 8)
#define SHAPER_WEIGHT_MAXCREDIT(x) 	(((x) & 0x3fffff) << 10)

#define PORT_SHAPER_MASK (1 << 0)

#endif /* _SHAPER_H_ */
