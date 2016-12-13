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
#ifndef _EMAC_H_
#define _EMAC_H_

#define EMAC_NETWORK_CONTROL		0x000
#define EMAC_NETWORK_CONFIG		0x004
#define EMAC_NETWORK_STATUS		0x008
#define EMAC_DMA_CONFIG			0x010

#define EMAC_PHY_MANAGEMENT		0x034

#define EMAC_HASH_BOT			0x080
#define EMAC_HASH_TOP			0x084

#define EMAC_SPEC1_ADD_BOT		0x088
#define EMAC_SPEC1_ADD_TOP		0x08c
#define EMAC_SPEC2_ADD_BOT		0x090
#define EMAC_SPEC2_ADD_TOP		0x094
#define EMAC_SPEC3_ADD_BOT		0x098
#define EMAC_SPEC3_ADD_TOP		0x09c
#define EMAC_SPEC4_ADD_BOT		0x0a0
#define EMAC_SPEC4_ADD_TOP		0x0a4
#define EMAC_WOL				0x0b8

#define	EMAC_STACKED_VLAN_REG		0x0c0

#define EMAC_SPEC1_ADD_MASK_BOT		0x0c8
#define EMAC_SPEC1_ADD_MASK_TOP		0x0cc

#define EMAC_RMON_BASE_OFST		0x100

#define EMAC_SPEC5_ADD_BOT		0x300
#define EMAC_SPEC5_ADD_TOP		0x304
#define EMAC_SPEC6_ADD_BOT		0x308
#define EMAC_SPEC6_ADD_TOP		0x30c
#define EMAC_SPEC7_ADD_BOT		0x310
#define EMAC_SPEC7_ADD_TOP		0x314
#define EMAC_SPEC8_ADD_BOT		0x318
#define EMAC_SPEC8_ADD_TOP		0x31c
#define EMAC_SPEC9_ADD_BOT		0x320
#define EMAC_SPEC9_ADD_TOP		0x324
#define EMAC_SPEC10_ADD_BOT		0x328
#define EMAC_SPEC10_ADD_TOP		0x32c
#define EMAC_SPEC11_ADD_BOT		0x330
#define EMAC_SPEC11_ADD_TOP		0x334
#define EMAC_SPEC12_ADD_BOT		0x338
#define EMAC_SPEC12_ADD_TOP		0x33c
#define EMAC_SPEC13_ADD_BOT		0x340
#define EMAC_SPEC13_ADD_TOP		0x344
#define EMAC_SPEC14_ADD_BOT		0x348
#define EMAC_SPEC14_ADD_TOP		0x34c
#define EMAC_SPEC15_ADD_BOT		0x350
#define EMAC_SPEC15_ADD_TOP		0x354
#define EMAC_SPEC16_ADD_BOT		0x358
#define EMAC_SPEC16_ADD_TOP		0x35c
#define EMAC_SPEC17_ADD_BOT		0x360
#define EMAC_SPEC17_ADD_TOP		0x364
#define EMAC_SPEC18_ADD_BOT		0x368
#define EMAC_SPEC18_ADD_TOP		0x36c
#define EMAC_SPEC19_ADD_BOT		0x370
#define EMAC_SPEC19_ADD_TOP		0x374
#define EMAC_SPEC20_ADD_BOT		0x378
#define EMAC_SPEC20_ADD_TOP		0x37c
#define EMAC_SPEC21_ADD_BOT		0x380
#define EMAC_SPEC21_ADD_TOP		0x384
#define EMAC_SPEC22_ADD_BOT		0x388
#define EMAC_SPEC22_ADD_TOP		0x38c
#define EMAC_SPEC23_ADD_BOT		0x390
#define EMAC_SPEC23_ADD_TOP		0x394
#define EMAC_SPEC24_ADD_BOT		0x398
#define EMAC_SPEC24_ADD_TOP		0x39c
#define EMAC_SPEC25_ADD_BOT		0x3a0
#define EMAC_SPEC25_ADD_TOP		0x3a4
#define EMAC_SPEC26_ADD_BOT		0x3a8
#define EMAC_SPEC26_ADD_TOP		0x3ac
#define EMAC_SPEC27_ADD_BOT		0x3b0
#define EMAC_SPEC27_ADD_TOP		0x3b4
#define EMAC_SPEC28_ADD_BOT		0x3b8
#define EMAC_SPEC28_ADD_TOP		0x3bc
#define EMAC_SPEC29_ADD_BOT		0x3c0
#define EMAC_SPEC29_ADD_TOP		0x3c4
#define EMAC_SPEC30_ADD_BOT		0x3c8
#define EMAC_SPEC30_ADD_TOP		0x3cc
#define EMAC_SPEC31_ADD_BOT		0x3d0
#define EMAC_SPEC31_ADD_TOP		0x3d4
#define EMAC_SPEC32_ADD_BOT		0x3d8
#define EMAC_SPEC32_ADD_TOP		0x3dc

#define EMAC_SPEC_ADDR_MAX		32

#define EMAC_CONTROL			0x7a0

/* GEMAC definitions and settings */

#define EMAC_PORT_0			0
#define EMAC_PORT_1			1
#define EMAC_PORT_2			2

/* The possible operating speeds of the MAC, currently supporting 10, 100 and
 * 1000Mb modes.
 */
typedef enum {SPEED_10M, SPEED_100M, SPEED_1000M, SPEED_1000M_PCS} MAC_SPEED;

#define GMII	1
#define MII	2
#define RMII	3
#define RGMII	4
#define SGMII	5

#define DUP_HALF	0x00
#define DUP_FULL	0x01

/* EMAC_NETWORK_CONTROL bits definition */
#define EMAC_LB_PHY 			(1 << 0)
#define EMAC_LB_MAC 			(1 << 1)
#define EMAC_RX_ENABLE			(1 << 2)
#define EMAC_TX_ENABLE			(1 << 3)
#define EMAC_MDIO_EN         		(1 << 4)      /* Enable MDIO port */

/* WoL (Wake on Lan bit definition) */
#define EMAC_WOL_MAGIC                  (1 << 16)
#define EMAC_WOL_ARP                    (1 << 17)
#define EMAC_WOL_SPEC_ADDR              (1 << 18)
#define EMAC_WOL_MULTI                  (1 << 19)

/* EMAC_NETWORK_CONFIG bits definition */
#define EMAC_SPEED_100		(1 << 0)
#define EMAC_HALF_DUP		(0 << 1)
#define EMAC_FULL_DUP		(1 << 1)
#define EMAC_DUPLEX_MASK	(1 << 1)
#define EMAC_ENABLE_JUMBO_FRAME (1 << 3)
#define EMAC_ENABLE_COPY_ALL	(1 << 4)	
#define EMAC_NO_BROADCAST	(1 << 5)
#define EMAC_ENABLE_MULTICAST	(1 << 6)
#define EMAC_ENABLE_UNICAST	(1 << 7)
#define EMAC_ENABLE_1536_RX	(1 << 8)
#define EMAC_SPEED_1000		(1 << 10)
#define EMAC_PCS_ENABLE		(1 << 11)
#define EMAC_ENABLE_PAUSE_RX	(1 << 13)
#define EMAC_REMOVE_FCS		(1 << 17)
#define EMAC_ENABLE_CHKSUM_RX	(1 << 24)
#define EMAC_MDC_DIV_MASK    (0x7 << 18) /* PCLK divisor for MDC */
#define EMAC_DATA_BUS_WIDTH_SHIFT       21
#define EMAC_DATA_BUS_WIDTH_MASK (0x3 << EMAC_DATA_BUS_WIDTH_SHIFT)
#define EMAC_DATA_BUS_WIDTH_32  (0x00 << EMAC_DATA_BUS_WIDTH_SHIFT)
#define EMAC_DATA_BUS_WIDTH_64  (0x01 << EMAC_DATA_BUS_WIDTH_SHIFT)
#define EMAC_DATA_BUS_WIDTH_128 (0x10 << EMAC_DATA_BUS_WIDTH_SHIFT)
#define EMAC_ENABLE_FCS_RX	(1 << 26)
#define EMAC_SGMII_MODE_ENABLE	(1 << 27)
	
#define EMAC_SPEED_MASK		(EMAC_SPEED_100 | EMAC_SPEED_1000)

/* EMAC_STACKED_VLAN_REG bits definition */
#define EMAC_ENABLE_STACKED_VLAN	(1 << 31)

/* EMAC_CONTROL bits definition */
#define EMAC_TWO_BYTES_IP_ALIGN		(1 << 0) // two bytes IP alignement

/* EMAC_NET_STATUS bits  definition */
#define EMAC_PHY_IDLE        (1<<2)      /* PHY management is idle */
#define EMAC_MDIO_IN         (1<<1)      /* Status of mdio_in pin */
#define EMAC_LINK_STATUS     (1<<0)      /* Status of link pin */

/* EMAC_DMA_CONFIG Bit definitions */
#define EMAC_ENABLE_CHKSUM_TX	(1<<11)

//RMII enable – bit 1 / RGMII enable – bit 2
#define EMAC_RMII_MODE_ENABLE		((1 << 1) | (0 << 2))
#define EMAC_RMII_MODE_DISABLE		(0 << 1)
#define EMAC_RGMII_MODE_ENABLE		((0 << 1) | (1 << 2))
#define EMAC_RGMII_MODE_DISABLE		(0 << 2)
#define EMAC_MII_MODE_ENABLE		(EMAC_RMII_MODE_DISABLE | EMAC_RGMII_MODE_DISABLE)
#define EMAC_GMII_MODE_ENABLE		(EMAC_RMII_MODE_DISABLE | EMAC_RGMII_MODE_DISABLE)
#define EMAC_MODE_MASK			(0x3 << 1)

/* Default configuration */
#define EMAC0_DEFAULT_DUPLEX_MODE	FULLDUPLEX 
#define EMAC0_DEFAULT_EMAC_MODE		RGMII      
#define EMAC0_DEFAULT_EMAC_SPEED	SPEED_1000M   

#define EMAC1_DEFAULT_DUPLEX_MODE	FULLDUPLEX 
#define EMAC1_DEFAULT_EMAC_MODE		RGMII      
#define EMAC1_DEFAULT_EMAC_SPEED	SPEED_1000M   

#define EMAC2_DEFAULT_DUPLEX_MODE	FULLDUPLEX 
#define EMAC2_DEFAULT_EMAC_MODE		RGMII      
#define EMAC2_DEFAULT_EMAC_SPEED	SPEED_1000M   

/* EMAC Hash size */
#define EMAC_HASH_REG_BITS       64

/* The Address organisation for the MAC device.  All addresses are split into
 * two 32-bit register fields.  The first one (bottom) is the lower 32-bits of
 * the address and the other field are the high order bits - this may be 16-bits
 * in the case of MAC addresses, or 32-bits for the hash address.
 * In terms of memory storage, the first item (bottom) is assumed to be at a
 * lower address location than 'top'. i.e. top should be at address location of
 * 'bottom' + 4 bytes.
 */
typedef struct {
	u32 bottom;     /* Lower 32-bits of address. */
	u32 top;        /* Upper 32-bits of address. */
} MAC_ADDR;


/* The following is the organisation of the address filters section of the MAC
 * registers.  The Cadence MAC contains four possible specific address match
 * addresses, if an incoming frame corresponds to any one of these four
 * addresses then the frame will be copied to memory.
 * It is not necessary for all four of the address match registers to be
 * programmed, this is application dependant.
 */
typedef struct {
	MAC_ADDR one;        /* Specific address register 1. */
	MAC_ADDR two;        /* Specific address register 2. */
	MAC_ADDR three;      /* Specific address register 3. */
	MAC_ADDR four;       /* Specific address register 4. */
} SPEC_ADDR;

typedef struct {
	u32 mode; 
	u32 speed;
	u32 duplex;
} GEMAC_CFG;

#endif /* _EMAC_H_ */
