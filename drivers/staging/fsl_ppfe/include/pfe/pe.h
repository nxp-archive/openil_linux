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
#ifndef _PE_H_
#define _PE_H_

#include "hal.h"

#if defined(COMCERTO_2000_CLASS)
#include "pfe/class.h"
#elif defined(COMCERTO_2000_TMU)
#include "pfe/tmu.h"
#elif defined(COMCERTO_2000_UTIL)
#include "pfe/util.h"
#endif

enum {
	CLASS0_ID = 0,
	CLASS1_ID,
	CLASS2_ID,
	CLASS3_ID,
	CLASS4_ID,
	CLASS5_ID,
	TMU0_ID,
	TMU1_ID,
	TMU2_ID,
	TMU3_ID,
	UTIL_ID,
	MAX_PE
};
#define PE_ID_ANY MAX_PE

/* Hardware definition of physical ports */
/* CLASS rx header phy number */
enum CLASS_RX_PHY {
	RX_PHY_0 = 0x0,
	RX_PHY_1,
	RX_PHY_2,
	RX_PHY_HIF,
	RX_PHY_HIF_NOCPY,
	RX_PHY_CLASS = 1 << 14, /**< Control bit (in PHYNO field) used to inform CLASS PE that packet comes from Class. */
	RX_PHY_UTIL = 1 << 15 /**< Control bit (in PHYNO field) used to inform CLASS PE that packet comes from UtilPE. */
};

#define RX_PHY_SW_INPUT_PORT_OFFSET		11	/**< Offset in PHYNO field where the original input port will be stored for packets coming directly from software (UtilPE or Class). */


/* CLASS/TMU tx header phy number */
enum TMU_TX_PHY {
	TX_PHY_TMU0 = 0x0,
	TX_PHY_TMU1,
	TX_PHY_TMU2,
	TX_PHY_TMU3
};


// NOTE: Any changes to the following drop counter definitions must also
//	be reflected in the pfe/pfe.h file and in pfe_ctrl/pfe_sysfs.c.

#if defined(COMCERTO_2000_CLASS)

#define	CLASS_DROP_ICC			0
#define	CLASS_DROP_HOST_PKT_ERROR	1
#define	CLASS_DROP_RX_ERROR		2
#define	CLASS_DROP_IPSEC_OUT		3
#define	CLASS_DROP_IPSEC_IN		4
#define	CLASS_DROP_EXPT_IPSEC		5
#define	CLASS_DROP_REASSEMBLY		6
#define	CLASS_DROP_FRAGMENTER		7
#define	CLASS_DROP_NATT			8
#define	CLASS_DROP_SOCKET		9
#define	CLASS_DROP_MULTICAST		10
#define	CLASS_DROP_NATPT		11
#define	CLASS_DROP_TX_DISABLE		12

#define	CLASS_NUM_DROP_COUNTERS		13

extern U32 drop_counter[CLASS_NUM_DROP_COUNTERS];
#define	DROP_PACKET(pmtd, counter) free_packet(pmtd, CLASS_DROP_##counter)
#define DROP_BUFFER(addr, counter) free_buffer(addr, CLASS_DROP_##counter)

#elif defined(COMCERTO_2000_UTIL)

#define	UTIL_DROP_IPSEC_OUT		0
#define	UTIL_DROP_IPSEC_IN		1
#define	UTIL_DROP_IPSEC_RATE_LIMIT	2
#define	UTIL_DROP_FRAGMENTER		3
#define	UTIL_DROP_SOCKET		4
#define	UTIL_DROP_TX_DISABLE		5
#define	UTIL_DROP_RX_ERROR		6
#define	UTIL_DROP_NO_MTD		7

#define	UTIL_NUM_DROP_COUNTERS		8

extern U32 drop_counter[UTIL_NUM_DROP_COUNTERS];
#define	DROP_PACKET(pmtd, counter) free_packet(pmtd, UTIL_DROP_##counter)
#define DROP_BUFFER(addr, counter) free_buffer(addr, UTIL_DROP_##counter)

#endif



#define DDR_BASE_ADDR		0x00020000
#define DDR_END			0x86000000 /* This includes ACP and IRAM areas */
#define IRAM_BASE_ADDR		0x83000000

#define IS_DDR(addr, len)	(((unsigned long)(addr) >= DDR_BASE_ADDR) && (((unsigned long)(addr) + (len)) <= DDR_END))
/* action bits of act_phyno is defined as follows */

#define ACT_SRC_MAC_REPLACE     (1 << (4 + 0))
#define ACT_VLAN_ADD            (1 << (4 + 1))
#define ACT_TCPCHKSUM_REPLACE   (1 << (4 + 2))
#define ACT_VLAN_REPLACE        (1 << (4 + 3))
#define ACT_DONT_FREE_BUFFER    (1 << (4 + 5))
#define ACT_IPCHKSUM_REPLACE    (1 << (4 + 6))

typedef struct {
	u8	start_data_off;		/* packet data start offset, relative to start of this tx pre-header */
	u8	start_buf_off;		/* this tx pre-header start offset, relative to start of DDR buffer */
	u16	pkt_length;		/* total packet length */
	u8	act_phyno;		/* action / phy number */
	u8	queueno;		/* queueno */
	u16	unused;
} class_tx_hdr_t;

typedef struct {
	u8	start_data_off;		/* packet data start offset, relative to start of this tx pre-header */
	u8	start_buf_off;		/* this tx pre-header start offset, relative to start of DDR buffer */
	u16	pkt_length;		/* total packet length */
	u8	act_phyno;		/* action / phy number */
	u8	queueno;		/* queueno */
	u16	src_mac_msb;		/* indicates src_mac 47:32 */
	u32	src_mac_lsb;		/* indicates src_mac 31:0 */
	u32	vlanid;			/* vlanid */
} class_tx_hdr_mc_t;

typedef struct {
        u32     next_ptr;       /* ptr to the start of the first DDR buffer */
        u16     length;         /* total packet length */
        u16     phyno;          /* input physical port number */
        u32     status;         /* gemac status bits bits[32:63]*/
        u32     status2;        /* gemac status bits bits[0:31] */
} class_rx_hdr_t;
/* class_rx_hdr status bits  (status0 bits in hardware blocks)
 * from hif_top/dma_dxr_dtx.v
 * STATUS[9:0] is the encoding of bits in the LMEM buffer as seen by the QB block,
 * NOT the encoding of bits as seen by the Class PEs in the DMEM rx header */
#define STATUS_PARSE_DISABLE		(1 << 0)
#define STATUS_BRFETCH_DISABLE		(1 << 1)
#define STATUS_RTFETCH_DISABLE		(1 << 2)
#define STATUS_DIR_PROC_ID		(1 << 3)
#define STATUS_CONN_ID_EN		(1 << 4))
#define STATUS_PE2PROC_ID(x)		(((x) & 7) << 5)
#define STATUS_LE_DATA			(1 << 8)
#define STATUS_CHKSUM_EN		(1 << 9)

/* from gpi/gpi_rmlf.v */
#define STATUS_CUMULATIVE_ERR		(1 << 16)
#define STATUS_LENGTH_ERR		(1 << 17)
#define STATUS_CRC_ERR			(1 << 18)
#define STATUS_TOO_SHORT_ERR		(1 << 19)
#define STATUS_TOO_LONG_ERR		(1 << 20)
#define STATUS_CODE_ERR			(1 << 21)
#define STATUS_MC_HASH_MATCH		(1 << 22)
#define STATUS_CUMULATIVE_ARC_HIT	(1 << 23)
#define STATUS_UNICAST_HASH_MATCH	(1 << 24)
#define STATUS_IP_CHECKSUM_CORRECT	(1 << 25)
#define STATUS_TCP_CHECKSUM_CORRECT	(1 << 26)
#define STATUS_UDP_CHECKSUM_CORRECT	(1 << 27)
#define STATUS_OVERFLOW_ERR		(1 << 28)

#define UTIL_MAGIC_NUM	0xffd8ffe000104a46
#define UTIL_DDRC_WA

/* The following structure is filled by class-pe when the packet
 * has to be sent to util-pe, by filling the required information */
typedef struct {
	u32 mtd_flags : 16;
	u32 packet_type : 8;
	u32 input_port : 4;
	u32 data_offset : 4;
	u32 word[MTD_PRIV];
#ifdef UTIL_DDRC_WA
	u64 magic_num; // magic_number to verify the data validity in utilpe
#endif
} __attribute__((aligned(8))) util_rx_hdr_t; // Size must be a multiple of 64-bit to allow copies using EFET.

#define UTIL_RX_IPS_IN_PKT		EVENT_IPS_IN
#define UTIL_RX_IPS_OUT_PKT		EVENT_IPS_OUT
#define UTIL_RX_RTP_PKT			EVENT_RTP_RELAY
#define UTIL_RX_RTP_QOS_PKT		EVENT_RTP_QOS
#define UTIL_RX_FRAG4_PKT		EVENT_FRAG4
#define UTIL_RX_FRAG6_PKT		EVENT_FRAG6

/** Structure passed from UtilPE to Class, stored at the end of the LMEM buffer. Defined and used by software only.
 *
 */

typedef struct
{
	void *next;
	u16 next_length;
	u8 next_l3offset;
	u8 next_l4offset;
} frag_info;

typedef struct {
	u8 packet_type	: 6;
	u8 padding	: 2;

	u8 offset	: 3;
	u8 ddr_offset	: 5;

	u16 mtd_flags;
	union {
		u16 half[6];
		u8 byte[12];

		struct {
			u16 sa_handle[2]; // SA_MAX_OP value should be used here instead of 2
			u8 proto;
			S8 sa_op;
			u8 l2hdr_len;
			u8 adj_dmem;
		} ipsec;

		struct {
			u16 l4offset;
			u16 socket_id;
			BOOL update;
			u8 reserved;
			u32 payload_diff;
		} relay;

		struct {
			u16 l3offset;
			u16 l4offset;

			frag_info frag;
		} ipv6;

		struct {
			u16 l3offset;
		} ipv4;

		struct {
			u32 ddr_addr;
			u16 length;
			u8 port;
			u8 queue;
			u8 action;
		} tx;
	};
} lmem_trailer_t;

/* The following values are defined for packet_type of lmem_trailer_t.
 * These represent different types of packets sent from util to class
 * for processing */
enum {
	UTIL_TX_IPS_IN = 0,
	UTIL_TX_IPV4_RTP_PKT,
	UTIL_TX_IPV6_RTP_PKT,
	UTIL_TX_IPV4_PKT,
	UTIL_TX_IPV6_PKT,
	UTIL_TX_EXPT_PKT,
#ifdef CFG_PCAP
	UTIL_TX_PKT,
#endif
	UTIL_TX_MAX_PKT
};


#define UTIL_TX_TRAILER_SIZE	sizeof(lmem_trailer_t)
#define UTIL_TX_TRAILER(mtd)	((lmem_trailer_t *)ROUND_UP32((u32)(mtd)->rx_dmem_end))

typedef struct {
	u32 pkt_ptr;
	u8  phyno;
	u8  queueno;
	u16 len;
} tmu_tx_hdr_t;

struct hif_pkt_hdr {		
	u8	client_id;
	u8	qNo;
	u16	client_ctrl_le_lsw;
	u16	client_ctrl_le_msw;
};


#if defined(CFG_WIFI_OFFLOAD)
#define	MAX_WIFI_VAPS	3
#define PFE_WIFI_PKT_HEADROOM	96 /*PFE inserts this headroom for WiFi tx packets only in lro mode */
#else
#define	MAX_WIFI_VAPS	0
#endif

/* HIF header client id */
enum HIF_CLIENT_ID {
	CLIENT_ID_GEM0 = 0,
	CLIENT_ID_GEM1,
	CLIENT_ID_GEM2,
	CLIENT_ID_WIFI0,
	CLIENT_ID_WIFI_LAST = MAX_WIFI_VAPS + CLIENT_ID_GEM2,
	CLIENT_ID_PCAP,
	CLIENT_ID_UNKNOWN = 0xff,
};


#define IS_WIFI_CLIENT_ID(_clid) (((_clid) >= CLIENT_ID_WIFI0) && ((_clid) <= CLIENT_ID_WIFI_LAST))

/* These match LE definition */
#define HIF_CTRL_TX_TSO_NOCPY		__cpu_to_le32(1 << 8)
#define HIF_CTRL_TX_IPSEC_OUT		__cpu_to_le32(1 << 7)
#define HIF_CTRL_TX_WIFI_OWNMAC		__cpu_to_le32(1 << 6)
#define HIF_CTRL_TX_TSO_END		__cpu_to_le32(1 << 5)
#define HIF_CTRL_TX_TSO6		__cpu_to_le32(1 << 4)
#define HIF_CTRL_TX_TSO			__cpu_to_le32(1 << 3)
#define HIF_CTRL_TX_CHECKSUM		__cpu_to_le32(1 << 2)
#define HIF_CTRL_TX_CSUM_VALIDATE	__cpu_to_le32(1 << 1)
#define HIF_CTRL_TX_WIFI_TXOFLD		__cpu_to_le32(1 << 0)

#define HIF_CTRL_RX_OFFSET_MASK		__cpu_to_le32(0xf << 24)
#define HIF_CTRL_RX_PE_ID_MASK		__cpu_to_le32(0xf << 16)
#define HIF_CTRL_RX_IPSEC_IN		__cpu_to_le32(1 << 4)
#define HIF_CTRL_RX_WIFI_EXPT		__cpu_to_le32(1 << 3)
#define HIF_CTRL_RX_CHECKSUMMED		__cpu_to_le32(1 << 2)
#define HIF_CTRL_RX_CONTINUED		__cpu_to_le32(1 << 1)
#define HIF_CTRL_RX_WIFI_HEADROOM	__cpu_to_le32(1 << 0)

#ifdef CFG_LRO
struct hif_lro_hdr {
	u16 data_offset;
	u16 mss;
};
#endif

struct hif_ipsec_hdr {
	u16 sa_handle[2];
};

#define MAX_TSO_BUF_DESCS 5
struct hif_tso_buf_desc {
	u32     addr;
	u32     ctrl;
#define TSO_CTRL_LAST_BUFFER (1 << 31)
};

struct hif_tso_hdr {
	u16 ip_off;
	u16 ip_id;
	u16 ip_len;
	u16 tcp_off;
	u32 tcp_seq;
};

struct hif_tso_hdr_nocpy {
	u16 ip_off;
	u16 ip_id;
	u16 ip_len;
	u16 tcp_off;
	u32 tcp_seq;
	struct hif_tso_buf_desc bdesc[MAX_TSO_BUF_DESCS];
};

struct hif_pcap_hdr {
        u8      ifindex;
        u8      unused;
        u16     seqno;
        u32     timestamp;
};


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


/** Basic busy loop delay function
*
* @param cycles		Number of cycles to delay (actual cpu cycles should be close to 3 x cycles)
*
*/
static inline void delay(u32 cycles)
{
	volatile int i;

	for (i = 0; i < cycles; i++);
}


/** Read PE id
*
* @return	PE id (0 - 5 for CLASS-PE's, 6 - 9 for TMU-PE's, 10 for UTIL-PE)
*
*/
static inline u32 esi_get_mpid(void)
{
	u32 mpid;

	asm ("rcsr %0, Configuration, MPID" : "=d" (mpid));

	return mpid;
}


#define esi_get_csr(bank, csr) \
({ \
	u32 res; \
	asm ("rcsr %0, " #bank ", " #csr : "=d" (res)); \
	res; \
})

#define esi_get_isa0() esi_get_csr(Configuration, ISA0)
#define esi_get_isa1() esi_get_csr(Configuration, ISA1)
#define esi_get_isa2() esi_get_csr(Configuration, ISA2)
#define esi_get_isa3() esi_get_csr(Configuration, ISA3)
#define esi_get_epc() esi_get_csr(Thread, EPC)
#define esi_get_ecas() esi_get_csr(Thread, ECAS)
#define esi_get_eid() esi_get_csr(Thread, EID)
#define esi_get_ed() esi_get_csr(Thread, ED)

static inline void esi_pe_stop(U32 state)
{
	PESTATUS_SETSTATE(state);
	while (1)
	{
		asm("stop");
	}
}


/** Same 64bit alignment memory copy using efet.
* Either the source or destination address must be in DMEM, the other address can be in LMEM or DDR.
* Both the source and destination must have the same 64bit alignment, length should be more than four bytes
* or dst/src must be 32bit aligned. Otherwise use efet_memcpy_any()
* Uses efet synchronous interface to copy the data.
*
* @param dst	Destination address to write to (must have the same 64bit alignment as src)
* @param src	Source address to read from (must have the same 64bit alignment as dst)
* @param len	Number of bytes to copy
*
*/
void efet_memcpy(void *dst, void *src, unsigned int len);

/** Same 64bit alignment memory copy using efet.
* Either the source or destination address must be in DMEM, the other address can be in LMEM or DDR.
* Both the source and destination must have the same 64bit alignment, there is no restriction on length.
* For UTIL-PE revA0, this function will still fail to handle small/unaligned writes.
* Uses efet synchronous interface to copy the data.
*
* @param dst	Destination address to write to (must have the same 64bit alignment as src)
* @param src	Source address to read from (must have the same 64bit alignment as dst)
* @param len	Number of bytes to copy
*
*/
void efet_memcpy_any(void *dst, void *src, unsigned int len);

/** Same 64bit alignment memory copy using efet.
* Either the source or destination address must be in DMEM, the other address can be in LMEM or DDR.
* Both the source and destination must have the same 64bit alignment, length should be more than four bytes
* or dst/src must be 32bit aligned.
* Uses efet asynchronous interface to copy the data.
*
* @param dst	Destination address to write to (must have the same 64bit alignment as src)
* @param src	Source address to read from (must have the same 64bit alignment as dst)
* @param len	Number of bytes to copy
*
*/
void efet_memcpy_nowait(void *dst, void *src, unsigned int len);

/** Unaligned memory copy using efet.
* Either the source or destination address must be in DMEM, the other address can be in LMEM or DDR.
* There is not restriction on source and destination, nor on length.
*
* @param dst		Destination address to write to
* @param src		Source address to read from
* @param len		Number of bytes to copy
* @param dmem_buf	temp dmem buffer to use, must be 64bit aligned
* @param dmem_len	length of dmem buffer, must be 64bit aligned and at least 16 bytes
*
*/
void efet_memcpy_unaligned(void *dst, void *src, unsigned int len, void *dmem_buf, unsigned int dmem_len);

/** Aligned memory copy of 4 bytes to register address.
* Register address must be 32 bit aligned.
*
* @param val		value to be copied.       
* @param reg_addr	Register address (must be 16bit aligned)
*
*/
void __efet_writel(u32 val, void *addr);

#ifdef REVA_WA
#define efet_writel(val, addr)	__efet_writel((u32)(val), (void *) (addr))
#else
#define efet_writel(val, addr)	writel((u32)(val), (void *) (addr))
#endif


/** 32bit aligned memory copy.
* Source and destination addresses must be 32bit aligned, there is no restriction on the length.
*
* @param dst		Destination address (must be 32bit aligned)
* @param src		Source address (must be 32bit aligned)
* @param len		Number of bytes to copy
*
*/
void memcpy_aligned32(void *dst, void *src, unsigned int len);

/** Aligned memory copy.
* Source and destination addresses must have the same alignment
* relative to 32bit boundaries (but otherwsie may have any alignment),
* there is no restriction on the length.
*
* @param dst		Destination address
* @param src		Source address (must have same 32bit alignment as dst)
* @param len		Number of bytes to copy
*
*/
void memcpy_aligned(void *dst, void *src, unsigned int len);

/** Unaligned memory copy.
* Implements unaligned memory copy. We first align the destination
* to a 32bit boundary (using byte copies) then the src, and finally use a loop
* of read, shift, write
*
* @param dst		Destination address
* @param src		Source address (must have same 32bit alignment as dst)
* @param len		Number of bytes to copy
*
*/
void memcpy_unaligned(void *dst, void *src, unsigned int len);

/** Generic memory set.
* Implements a generic memory set. Not very optimal (uses byte writes for the entire range)
*
*
* @param dst		Destination address
* @param val		Value to set memory to
* @param len		Number of bytes to set
*
*/
void memset(void *dst, u8 val, unsigned int len);

/** Generic memory copy.
* Implements generic memory copy. If source and destination have the same
* alignment memcpy_aligned() is used, otherwise memcpy_unaligned()
*
* @param dst		Destination address
* @param src		Source address
* @param len		Number of bytes to copy
*
*/
void memcpy(void *dst, void *src, unsigned int len);

/** Generic memorymove.
* Implements generic memorymove, where copies across overlapping
* memory regions is supported.
* Uses the dmem_buf passed as a parameter as a temporary buffer.
* Includes two copies, forces one of the copies to be definitely aligned.
* The "dmem_len" being passed should be atleast 3 bytes greater than "len"
* The 3 bytes here are shift bytes used to ensure one aligned copy.
*
* @param dst		Destination address
* @param src		Source address
* @param len		Number of bytes to copy
* @param dmem_buf	temp dmem buffer to use, must be 32bit aligned
* @param dmem_len	length of dmem buffer, must be 32bit aligned and at least 3 bytes greater
*			than @param len
*
*/

void *memorymove(void * dst, void * src, unsigned int len, void *dmem_buf, unsigned int dmem_len);

/** Aligned memory copy in DDR memory.
 * Implements aligned memory copy between two DDR buffers using efet_memcpy64 and DMEM
 * Both the source and destination must have the same 64bit alignment, there is no restriction on length.
 * If start or end are not 64bit aligned, data in destination buffer before start/after end will be corrupted.
 *
 * @param dst 		DDR Destination address
 * @param src		DDR Source address
 * @param len		Number of bytes to copy
 * @param dmem_buf	temp dmem buffer to use, must be 64bit aligned
 * @param dmem_len	length of dmem buffer, must be 64bit aligned and at least 16 bytes
 */
void memcpy_ddr_to_ddr(void *dst, void *src, unsigned int len, void *dmem_buf, unsigned int dmem_len);

/** Unaligned memory copy in DDR memory.
 * Implements generic memory copy between two DDR buffers using efet_memcpy and DMEM
 * There is no restriction on the source, destination and length alignments.
 *
 * @param dst 		DDR Destination address
 * @param src		DDR Source address
 * @param len		Number of bytes to copy
 * @param dmem_buf	temp dmem buffer to use, must be 64bit aligned
 * @param dmem_len	length of dmem buffer, must be 64bit aligned and at least 16 bytes
 */
void memcpy_ddr_to_ddr_unaligned(void *dst, void *src, unsigned int len, void *dmem_buf, unsigned int dmem_len);

#endif /* _PE_H_ */
