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
#ifndef _GPT_H_
#define _GPT_H_

#define GPT_VERSION		 (GPT_BASE_ADDR + 0x00)
#define GPT_STATUS		 (GPT_BASE_ADDR + 0x04)
#define GPT_CONFIG		 (GPT_BASE_ADDR + 0x08)
#define GPT_COUNTER		 (GPT_BASE_ADDR + 0x0c)
#define GPT_PERIOD		 (GPT_BASE_ADDR + 0x10)
#define GPT_WIDTH		 (GPT_BASE_ADDR + 0x14)

/*** These bits are defined for GPT_STATUS register */
#define GPT_STAT_IRQ            (1<<0)
#define GPT_STAT_OVERFLOW_ERR   (1<<4)
#define GPT_STAT_TMR_ENABLE     (1<<8)
#define GPT_STAT_TMR_DISABLE    (1<<9)

/*** These bits are defined for GPT_CONFIG register */
#define GPT_CONFIG_PWM_MODE             0x1
#define GPT_CONFIG_WCAP_MODE            0x2
#define GPT_CONFIG_CAP_PULSE_OUT        (1<<2)
#define GPT_CONFIG_PERIOD_CNT           (1<<3)
#define GPT_CONFIG_INTR_ENABLE          (1<<4)
#define GPT_CONFIG_AUX_SEL              (1<<5)


#endif /* _GPT_H_ */
