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
#ifndef _HIF_H_
#define _HIF_H_

/** @file hif.h.
 * hif - PFE hif block control and status register. Mapped on CBUS and accessible from all PE's and ARM.
 */
#define HIF_VERSION		(HIF_BASE_ADDR + 0x00)
#define HIF_TX_CTRL		(HIF_BASE_ADDR + 0x04)
#define HIF_TX_CURR_BD_ADDR	(HIF_BASE_ADDR + 0x08)
#define HIF_TX_ALLOC		(HIF_BASE_ADDR + 0x0c)
#define HIF_TX_BDP_ADDR		(HIF_BASE_ADDR + 0x10)
#define HIF_TX_STATUS		(HIF_BASE_ADDR + 0x14)
#define HIF_RX_CTRL		(HIF_BASE_ADDR + 0x20)
#define HIF_RX_BDP_ADDR		(HIF_BASE_ADDR + 0x24)
#define HIF_RX_STATUS		(HIF_BASE_ADDR + 0x30)
#define HIF_INT_SRC		(HIF_BASE_ADDR + 0x34)
#define HIF_INT_ENABLE		(HIF_BASE_ADDR + 0x38)
#define HIF_POLL_CTRL		(HIF_BASE_ADDR + 0x3c)
#define HIF_RX_CURR_BD_ADDR	(HIF_BASE_ADDR + 0x40)
#define HIF_RX_ALLOC		(HIF_BASE_ADDR + 0x44)
#define HIF_TX_DMA_STATUS	(HIF_BASE_ADDR + 0x48)
#define HIF_RX_DMA_STATUS	(HIF_BASE_ADDR + 0x4c)
#define HIF_INT_COAL		(HIF_BASE_ADDR + 0x50)

/*HIF_INT_SRC/ HIF_INT_ENABLE control bits */
#define HIF_INT        		(1 << 0)
#define HIF_RXBD_INT   		(1 << 1)
#define HIF_RXPKT_INT  		(1 << 2)
#define HIF_TXBD_INT   		(1 << 3)
#define HIF_TXPKT_INT  		(1 << 4)

/*HIF_TX_CTRL bits */
#define HIF_CTRL_DMA_EN			(1<<0)
#define HIF_CTRL_BDP_POLL_CTRL_EN	(1<<1)
#define HIF_CTRL_BDP_CH_START_WSTB	(1<<2)

/*HIF_INT_ENABLE bits */
#define HIF_INT_EN		(1 << 0)
#define HIF_RXBD_INT_EN		(1 << 1)
#define HIF_RXPKT_INT_EN	(1 << 2)
#define HIF_TXBD_INT_EN		(1 << 3)
#define HIF_TXPKT_INT_EN	(1 << 4)

/*HIF_POLL_CTRL bits*/
#define HIF_RX_POLL_CTRL_CYCLE	0x0400
#define HIF_TX_POLL_CTRL_CYCLE	0x0400

/*HIF_INT_COAL bits*/
#define HIF_INT_COAL_ENABLE	(1 << 31)

/*Buffer descriptor control bits */
#define BD_CTRL_BUFLEN_MASK	0x3fff
#define BD_BUF_LEN(x)		(x & BD_CTRL_BUFLEN_MASK)
#define BD_CTRL_CBD_INT_EN	(1 << 16)
#define BD_CTRL_PKT_INT_EN	(1 << 17)
#define BD_CTRL_LIFM		(1 << 18)
#define BD_CTRL_LAST_BD		(1 << 19)
#define BD_CTRL_DIR		(1 << 20)
#define BD_CTRL_LMEM_CPY	(1 << 21) /*Valid only for HIF_NOCPY*/
#define BD_CTRL_PKT_XFER	(1 << 24)
#define BD_CTRL_DESC_EN		(1 << 31)
#define BD_CTRL_PARSE_DISABLE	(1 << 25)
#define BD_CTRL_BRFETCH_DISABLE	(1 << 26)
#define BD_CTRL_RTFETCH_DISABLE	(1 << 27)

/*Buffer descriptor status bits*/
#define BD_STATUS_CONN_ID(x)	((x) & 0xffff)
#define BD_STATUS_DIR_PROC_ID	(1 << 16)
#define BD_STATUS_CONN_ID_EN	(1 << 17))
#define BD_STATUS_PE2PROC_ID(x)	(((x) & 7) << 18)
#define BD_STATUS_LE_DATA	(1 << 21)
#define BD_STATUS_CHKSUM_EN	(1 << 22)

/*HIF Buffer descriptor status bits */
#define DIR_PROC_ID		(1 << 16)
#define PROC_ID(id)		((id) << 18)

#endif /* _HIF_H_ */
