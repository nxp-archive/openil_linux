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
#ifndef _PFE_H_
#define _PFE_H_

#define CLASS_DMEM_BASE_ADDR(i)	(0x00000000 | ((i) << 20))
#define CLASS_IMEM_BASE_ADDR(i)	(0x00000000 | ((i) << 20)) /* Only valid for mem access register interface */
#define CLASS_DMEM_SIZE		0x00002000
#define CLASS_IMEM_SIZE		0x00008000

#define TMU_DMEM_BASE_ADDR(i)	(0x00000000 + ((i) << 20))
#define TMU_IMEM_BASE_ADDR(i)	(0x00000000 + ((i) << 20)) /* Only valid for mem access register interface */
#define TMU_DMEM_SIZE		0x00000800
#define TMU_IMEM_SIZE		0x00002000

#define UTIL_DMEM_BASE_ADDR	0x00000000
#define UTIL_DMEM_SIZE		0x00002000

#define PE_LMEM_BASE_ADDR	0xc3010000
#define PE_LMEM_SIZE		0x8000
#define PE_LMEM_END		(PE_LMEM_BASE_ADDR + PE_LMEM_SIZE)

#define DMEM_BASE_ADDR		0x00000000
#define DMEM_SIZE		0x2000		/**< TMU has less... */
#define DMEM_END		(DMEM_BASE_ADDR + DMEM_SIZE)

#define PMEM_BASE_ADDR		0x00010000
#define PMEM_SIZE		0x8000		/**< TMU has less... */
#define PMEM_END		(PMEM_BASE_ADDR + PMEM_SIZE)


/* These check memory ranges from PE point of view/memory map */
#define IS_DMEM(addr, len)	(((unsigned long)(addr) >= DMEM_BASE_ADDR) && (((unsigned long)(addr) + (len)) <= DMEM_END))
#define IS_PMEM(addr, len)	(((unsigned long)(addr) >= PMEM_BASE_ADDR) && (((unsigned long)(addr) + (len)) <= PMEM_END))
#define IS_PE_LMEM(addr, len)	(((unsigned long)(addr) >= PE_LMEM_BASE_ADDR) && (((unsigned long)(addr) + (len)) <= PE_LMEM_END))

#define IS_PFE_LMEM(addr, len)	(((unsigned long)(addr) >= CBUS_VIRT_TO_PFE(LMEM_BASE_ADDR)) && (((unsigned long)(addr) + (len)) <= CBUS_VIRT_TO_PFE(LMEM_END)))
#define __IS_PHYS_DDR(addr, len)	(((unsigned long)(addr) >= DDR_PHYS_BASE_ADDR) && (((unsigned long)(addr) + (len)) <= DDR_PHYS_END))
#define IS_PHYS_DDR(addr, len)	__IS_PHYS_DDR(DDR_PFE_TO_PHYS(addr), len)

/* If using a run-time virtual address for the cbus base address use this code */
extern void *cbus_base_addr;
extern void *ddr_base_addr;
extern unsigned long ddr_phys_base_addr;
extern unsigned int ddr_size;

#if defined(COMCERTO_2000_CONTROL)
#include <linux/version.h>
#if defined (CONFIG_PLATFORM_C2000)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
/*This is copied from arch/arm/include/asm/system_info.h */
extern unsigned int system_rev;
#endif
#endif
#endif

#define CBUS_BASE_ADDR		cbus_base_addr
#define DDR_PHYS_BASE_ADDR	ddr_phys_base_addr
#define DDR_BASE_ADDR		ddr_base_addr
#define DDR_SIZE		ddr_size

#define DDR_PHYS_END	(DDR_PHYS_BASE_ADDR + DDR_SIZE)

#if defined(CONFIG_PLATFORM_C2000)
#define PFE_CBUS_PHYS_BASE_ADDR	0xc0000000	/**< CBUS physical base address as seen by PE's. */
#define DDR_PHYS_TO_PFE(p)	(p)
#define DDR_PFE_TO_PHYS(p)	(p)
#define CBUS_PHYS_TO_PFE(p)	(p)
#else
#define LS1012A_PFE_RESET_WA	/*PFE doesn't have global reset and re-init should takecare few things to make PFE functional after reset */
#define PFE_CBUS_PHYS_BASE_ADDR	0xc0000000	/**< CBUS physical base address as seen by PE's. */
#define PFE_CBUS_PHYS_BASE_ADDR_FROM_PFE	0xc0000000	/**< CBUS physical base address as seen by PE's. */
#define DDR_PHYS_TO_PFE(p)	(((unsigned long int) (p)) & 0x7FFFFFFF)
#define DDR_PFE_TO_PHYS(p)	(((unsigned long int) (p)) | 0x80000000)
#define CBUS_PHYS_TO_PFE(p)	(((p) - PFE_CBUS_PHYS_BASE_ADDR) + PFE_CBUS_PHYS_BASE_ADDR_FROM_PFE) /*Translates to PFE address map */
#endif

#define DDR_PHYS_TO_VIRT(p)	(((p) - DDR_PHYS_BASE_ADDR) + DDR_BASE_ADDR)
#define DDR_VIRT_TO_PHYS(v)	(((v) - DDR_BASE_ADDR) + DDR_PHYS_BASE_ADDR)
#define DDR_VIRT_TO_PFE(p)	(DDR_PHYS_TO_PFE(DDR_VIRT_TO_PHYS(p)))

#define CBUS_VIRT_TO_PFE(v)	(((v) - CBUS_BASE_ADDR) + PFE_CBUS_PHYS_BASE_ADDR)
#define CBUS_PFE_TO_VIRT(p)	(((p) - PFE_CBUS_PHYS_BASE_ADDR) + CBUS_BASE_ADDR)

/* The below part of the code is used in QOS control driver from host */
#define TMU_APB_BASE_ADDR       0xc1000000      /** TMU base address seen by pe's */

#define SHAPER0_BASE_ADDR       (TMU_APB_BASE_ADDR + 0x020000)
#define SHAPER1_BASE_ADDR       (TMU_APB_BASE_ADDR + 0x030000)
#define SHAPER2_BASE_ADDR       (TMU_APB_BASE_ADDR + 0x040000)
#define SHAPER3_BASE_ADDR       (TMU_APB_BASE_ADDR + 0x050000)
#define SHAPER4_BASE_ADDR       (TMU_APB_BASE_ADDR + 0x060000)
#define SHAPER5_BASE_ADDR       (TMU_APB_BASE_ADDR + 0x070000)
#define SHAPER6_BASE_ADDR       (TMU_APB_BASE_ADDR + 0x080000)
#define SHAPER7_BASE_ADDR       (TMU_APB_BASE_ADDR + 0x090000)
#define SHAPER8_BASE_ADDR       (TMU_APB_BASE_ADDR + 0x0a0000)
#define SHAPER9_BASE_ADDR       (TMU_APB_BASE_ADDR + 0x0b0000)

#define SCHED0_BASE_ADDR        (TMU_APB_BASE_ADDR + 0x1c0000)
#define SCHED1_BASE_ADDR        (TMU_APB_BASE_ADDR + 0x1d0000)
#define SCHED2_BASE_ADDR        (TMU_APB_BASE_ADDR + 0x1e0000)
#define SCHED3_BASE_ADDR        (TMU_APB_BASE_ADDR + 0x1f0000)
#define SCHED4_BASE_ADDR        (TMU_APB_BASE_ADDR + 0x200000)
#define SCHED5_BASE_ADDR        (TMU_APB_BASE_ADDR + 0x210000)
#define SCHED6_BASE_ADDR        (TMU_APB_BASE_ADDR + 0x220000)
#define SCHED7_BASE_ADDR        (TMU_APB_BASE_ADDR + 0x230000)

#define PHY_QUEUE_BASE_ADDR     (TMU_APB_BASE_ADDR + 0x260000)
#define QUEUE_RESULT0           (PHY_QUEUE_BASE_ADDR + 0x48)    /**< [7] set to one to indicate output PHY (TMU0->PHY0, TMU1->PHY1, TMU2->PHY2, TMU3->PHY3), [6:0] winner input queue number */
#define QUEUE_RESULT1           (PHY_QUEUE_BASE_ADDR + 0x4c)    /**< [7] set to one to indicate output PHY (TMU0->PHY0, TMU1->PHY1, TMU2->PHY2, TMU3->PHY4), [6:0] winner input queue number */
#define QUEUE_RESULT2           (PHY_QUEUE_BASE_ADDR + 0x50)    /**< [7] set to one to indicate output PHY (TMU0->PHY0, TMU1->PHY1, TMU2->PHY2, TMU3->PHY5), [6:0] winner input queue number */

#define QUEUE_RESULT0_REGOFFSET	(QUEUE_RESULT0 - QUEUE_RESULT0)
#define QUEUE_RESULT1_REGOFFSET	(QUEUE_RESULT1 - QUEUE_RESULT0)
#define QUEUE_RESULT2_REGOFFSET	(QUEUE_RESULT2 - QUEUE_RESULT0)


#include "cbus.h"

enum {
	CLASS0_ID = 0,
	CLASS1_ID,
	CLASS2_ID,
	CLASS3_ID,
#if !defined(CONFIG_PLATFORM_PCI)
	CLASS4_ID,
	CLASS5_ID,
#endif
#if !defined(CONFIG_TMU_DUMMY)
	TMU0_ID,
	TMU1_ID,
	TMU2_ID,
	TMU3_ID,
#else
	TMU0_ID,
#endif
#if !defined(CONFIG_UTIL_DISABLED)
	UTIL_ID,
#endif
	MAX_PE
};

enum {
	CLASS_TYPE = 0,
	TMU_TYPE,
	UTIL_TYPE
};

#if !defined(CONFIG_PLATFORM_PCI)
#define CLASS_MASK	((1 << CLASS0_ID) | (1 << CLASS1_ID) | (1 << CLASS2_ID) | (1 << CLASS3_ID) | (1 << CLASS4_ID) | (1 << CLASS5_ID))
#define CLASS_MAX_ID	CLASS5_ID
#else
#define CLASS_MASK      ((1 << CLASS0_ID) | (1 << CLASS1_ID) | (1 << CLASS2_ID) | (1 << CLASS3_ID))
#define CLASS_MAX_ID	CLASS3_ID
#endif

#if !defined(CONFIG_TMU_DUMMY)
#if defined(CONFIG_PLATFORM_LS1012A)
#define TMU_MASK	((1 << TMU0_ID) | (1 << TMU1_ID) | (1 << TMU3_ID))
#else
#define TMU_MASK	((1 << TMU0_ID) | (1 << TMU1_ID) | (1 << TMU2_ID) | (1 << TMU3_ID))
#endif
#define TMU_MAX_ID	TMU3_ID
#else
#define TMU_MASK        (1 << TMU0_ID)
#define TMU_MAX_ID	TMU0_ID
#endif

#if !defined(CONFIG_UTIL_DISABLED)
#define UTIL_MASK	(1 << UTIL_ID)
#endif

typedef struct tPE_STATUS
{
	u32	cpu_state;
	u32	activity_counter;
	u32	rx;
	union {
		u32	tx;
		u32	tmu_qstatus;
	};
	u32	drop;
#if defined(CFG_PE_DEBUG)
	u32	debug_indicator;
	u32	debug[16];
#endif
} __attribute__((aligned(16))) PE_STATUS;


struct pe_sync_mailbox
{
	u32 stop;
	u32 stopped;
};

struct pe_msg_mailbox
{
	u32 dst;
	u32 src;
	u32 len;
	u32 request;
};

// Drop counter definitions

#define	CLASS_NUM_DROP_COUNTERS		13
#define	UTIL_NUM_DROP_COUNTERS		8


/** PE information.
 * Structure containing PE's specific information. It is used to create
 * generic C functions common to all PE's.
 * Before using the library functions this structure needs to be initialized with the different registers virtual addresses
 * (according to the ARM MMU mmaping). The default initialization supports a virtual == physical mapping.
 *
 */
struct pe_info
{
	u32 dmem_base_addr;		/**< PE's dmem base address */
	u32 pmem_base_addr;		/**< PE's pmem base address */
	u32 pmem_size;			/**< PE's pmem size */

	void *mem_access_wdata;		/**< PE's _MEM_ACCESS_WDATA register address */
	void *mem_access_addr;		/**< PE's _MEM_ACCESS_ADDR register address */
	void *mem_access_rdata;		/**< PE's _MEM_ACCESS_RDATA register address */
};


void pe_lmem_read(u32 *dst, u32 len, u32 offset);
void pe_lmem_write(u32 *src, u32 len, u32 offset);

void pe_dmem_memcpy_to32(int id, u32 dst, const void *src, unsigned int len);
void pe_pmem_memcpy_to32(int id, u32 dst, const void *src, unsigned int len);

u32 pe_pmem_read(int id, u32 addr, u8 size);

void pe_dmem_write(int id, u32 val, u32 addr, u8 size);
u32 pe_dmem_read(int id, u32 addr, u8 size);
void class_pe_lmem_memcpy_to32(u32 dst, const void *src, unsigned int len);
void class_pe_lmem_memset(u32 dst, int val, unsigned int len);
void class_bus_write(u32 val, u32 addr, u8 size);
u32 class_bus_read(u32 addr, u8 size);


#define class_bus_readl(addr)			class_bus_read(addr, 4)
#define class_bus_readw(addr)			class_bus_read(addr, 2)
#define class_bus_readb(addr)			class_bus_read(addr, 1)

#define class_bus_writel(val, addr)		class_bus_write(val, addr, 4)
#define class_bus_writew(val, addr)		class_bus_write(val, addr, 2)
#define class_bus_writeb(val, addr)		class_bus_write(val, addr, 1)

#define pe_dmem_readl(id, addr)			pe_dmem_read(id, addr, 4)
#define pe_dmem_readw(id, addr)			pe_dmem_read(id, addr, 2)
#define pe_dmem_readb(id, addr)			pe_dmem_read(id, addr, 1)

#define pe_dmem_writel(id, val, addr)		pe_dmem_write(id, val, addr, 4)
#define pe_dmem_writew(id, val, addr)		pe_dmem_write(id, val, addr, 2)
#define pe_dmem_writeb(id, val, addr)		pe_dmem_write(id, val, addr, 1)

//int pe_load_elf_section(int id, const void *data, Elf32_Shdr *shdr);
int pe_load_elf_section(int id, const void *data, Elf32_Shdr *shdr, struct device *dev);

void pfe_lib_init(void *cbus_base, void *ddr_base, unsigned long ddr_phys_base, unsigned int ddr_size);
void bmu_init(void *base, BMU_CFG *cfg);
void bmu_reset(void *base);
void bmu_enable(void *base);
void bmu_disable(void *base);
void bmu_set_config(void *base, BMU_CFG *cfg);

/* An enumerated type for loopback values.  This can be one of three values, no
 * loopback -normal operation, local loopback with internal loopback module of
 * MAC or PHY loopback which is through the external PHY.
 */
#ifndef __MAC_LOOP_ENUM__
#define __MAC_LOOP_ENUM__
typedef enum {LB_NONE, LB_EXT, LB_LOCAL} MAC_LOOP;
#endif


void gemac_init(void *base, void *config);
void gemac_disable_rx_checksum_offload(void *base);
void gemac_enable_rx_checksum_offload(void *base);
void gemac_set_mdc_div(void *base, int mdc_div);
void gemac_set_speed(void *base, MAC_SPEED gem_speed);
void gemac_set_duplex(void *base, int duplex);
void gemac_set_mode(void *base, int mode);
void gemac_enable(void *base);
void gemac_tx_disable(void *base);
void gemac_disable(void *base);
void gemac_reset(void *base);
void gemac_set_address(void *base, SPEC_ADDR *addr);
SPEC_ADDR gemac_get_address(void *base);
void gemac_set_loop( void *base, MAC_LOOP gem_loop );
void gemac_set_laddr1(void *base, MAC_ADDR *address);
void gemac_set_laddr2(void *base, MAC_ADDR *address);
void gemac_set_laddr3(void *base, MAC_ADDR *address);
void gemac_set_laddr4(void *base, MAC_ADDR *address);
void gemac_set_laddrN(void *base, MAC_ADDR *address, unsigned int entry_index);
void gemac_clear_laddr1(void *base);
void gemac_clear_laddr2(void *base);
void gemac_clear_laddr3(void *base);
void gemac_clear_laddr4(void *base);
void gemac_clear_laddrN(void *base, unsigned int entry_index);
MAC_ADDR gemac_get_hash( void *base );
void gemac_set_hash( void *base, MAC_ADDR *hash );
MAC_ADDR gem_get_laddr1(void *base);
MAC_ADDR gem_get_laddr2(void *base);
MAC_ADDR gem_get_laddr3(void *base);
MAC_ADDR gem_get_laddr4(void *base);
MAC_ADDR gem_get_laddrN(void *base, unsigned int entry_index);
void gemac_set_config(void *base, GEMAC_CFG *cfg);
void gemac_allow_broadcast(void *base);
void gemac_no_broadcast(void *base);
void gemac_enable_unicast(void *base);
void gemac_disable_unicast(void *base);
void gemac_enable_multicast(void *base);
void gemac_disable_multicast(void *base);
void gemac_enable_fcs_rx(void *base);
void gemac_disable_fcs_rx(void *base);
void gemac_enable_1536_rx(void *base);
void gemac_disable_1536_rx(void *base);
void gemac_enable_rx_jmb(void *base);
void gemac_disable_rx_jmb(void *base);
void gemac_enable_stacked_vlan(void *base);
void gemac_disable_stacked_vlan(void *base);
void gemac_enable_pause_rx(void *base);
void gemac_disable_pause_rx(void *base);
void gemac_enable_copy_all(void *base);
void gemac_disable_copy_all(void *base);
void gemac_set_bus_width(void *base, int width);
void gemac_set_wol(void *base, u32 wol_conf);

void gpi_init(void *base, GPI_CFG *cfg);
void gpi_reset(void *base);
void gpi_enable(void *base);
void gpi_disable(void *base);
void gpi_set_config(void *base, GPI_CFG *cfg);

void class_init(CLASS_CFG *cfg);
void class_reset(void);
void class_enable(void);
void class_disable(void);
void class_set_config(CLASS_CFG *cfg);

void tmu_reset(void);
void tmu_init(TMU_CFG *cfg);
void tmu_enable(u32 pe_mask);
void tmu_disable(u32 pe_mask);
u32  tmu_qstatus(u32 if_id);
u32  tmu_pkts_processed(u32 if_id);

void util_init(UTIL_CFG *cfg);
void util_reset(void);
void util_enable(void);
void util_disable(void);

void hif_nocpy_init(void);
void hif_nocpy_tx_enable(void);
void hif_nocpy_tx_disable(void);
void hif_nocpy_rx_enable(void);
void hif_nocpy_rx_disable(void);

void hif_init(void);
void hif_tx_enable(void);
void hif_tx_disable(void);
void hif_rx_enable(void);
void hif_rx_disable(void);


/** Get Chip Revision level
*
*/

static inline unsigned int CHIP_REVISION(void)
{
#if defined (CONFIG_PLATFORM_C2000)
#if 1
	return system_rev;
	//return 0;
#else
	return (readl(COMCERTO_GPIO_DEVICE_ID_REG) >> 24) & 0xf;
#endif

#else
	/*For LS1012A return always 1 */
	return 1;
#endif
}

/** Start HIF rx DMA
*
*/
static inline void hif_rx_dma_start(void)
{
	/*TODO not sure poll_cntrl_en is required or not */
	writel(HIF_CTRL_DMA_EN | HIF_CTRL_BDP_CH_START_WSTB, HIF_RX_CTRL);
}

/** Start HIF tx DMA
*
*/
static inline void hif_tx_dma_start(void)
{
	/*TODO not sure poll_cntrl_en is required or not */
	writel(HIF_CTRL_DMA_EN | HIF_CTRL_BDP_CH_START_WSTB, HIF_TX_CTRL);
}

/** Start HIF_NOCPY rx DMA
*
*/
static inline void hif_nocpy_rx_dma_start(void)
{
	/*TODO not sure poll_cntrl_en is required or not */
	writel((HIF_CTRL_DMA_EN | HIF_CTRL_BDP_CH_START_WSTB), HIF_NOCPY_RX_CTRL);
}

/** Start HIF_NOCPY tx DMA
*
*/
static inline void hif_nocpy_tx_dma_start(void)
{
	/*TODO not sure poll_cntrl_en is required or not */
	writel(HIF_CTRL_DMA_EN | HIF_CTRL_BDP_CH_START_WSTB, HIF_NOCPY_TX_CTRL);
}

#endif /* _PFE_H_ */

