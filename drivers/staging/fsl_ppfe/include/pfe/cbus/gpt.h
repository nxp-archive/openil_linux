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
#ifndef _CBUS_GPT_H_
#define _CBUS_GPT_H_

#define CBUS_GPT_VERSION	 (CBUS_GPT_BASE_ADDR + 0x00)
#define CBUS_GPT_STATUS		 (CBUS_GPT_BASE_ADDR + 0x04)
#define CBUS_GPT_CONFIG		 (CBUS_GPT_BASE_ADDR + 0x08)
#define CBUS_GPT_COUNTER	 (CBUS_GPT_BASE_ADDR + 0x0c)
#define CBUS_GPT_PERIOD		 (CBUS_GPT_BASE_ADDR + 0x10)
#define CBUS_GPT_WIDTH		 (CBUS_GPT_BASE_ADDR + 0x14)

#endif /* _CBUS_GPT_H_ */
