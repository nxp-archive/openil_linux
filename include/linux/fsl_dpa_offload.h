
/* Copyright 2008-2012 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * DPA Offloading Driver General Data Types.
 */

#ifndef __FSL_DPA_OFFLOAD_H
#define __FSL_DPA_OFFLOAD_H


#include <linux/if_ether.h>
#include <linux/ip.h>


/* General definitions */
#define DPA_OFFLD_IPv4_ADDR_LEN_BYTES				4
#define DPA_OFFLD_IPv6_ADDR_LEN_BYTES				16
#define DPA_OFFLD_IPv6_ADDR_LEN_WORDS				4
#define DPA_OFFLD_IPv6_ADDR_LEN_LONG				2

/* Maximum size of a lookup key, in bytes */
#define DPA_OFFLD_MAXENTRYKEYSIZE				56

#define DPA_OFFLD_DESC_NONE					-1
#define DPA_OFFLD_INVALID_OBJECT_ID				-1

#define log_err(...) \
		do { \
			pr_err("Error - %s:%d (%s)\n", \
					__FILE__, __LINE__, __func__); \
			pr_err(__VA_ARGS__); \
		} while (0);

#define log_warn(...) \
		do { \
			pr_warn("Warning - %s:%d (%s)\n", \
					__FILE__, __LINE__, __func__); \
			pr_warn(__VA_ARGS__); \
		} while (0);


/* Description of lookup key */
struct dpa_offload_lookup_key {

	/*
	 * The data (bytes) of the key. For indexed tables the index is the
	 * first byte of this array
	 */
	uint8_t		*byte;

	/*
	 * The mask of the key. The bits corresponding to zeros in the mask are
	 * ignored. NULL is the table doesn't have the mask support enabled.
	 */
	uint8_t		*mask;

	/*
	 * The size of the key in bytes. Must not exceed
	 * DPA_OFFLD_MAXENTRYKEYSIZE
	 */
	uint8_t		size;
};

/* Description of the IPv4 address */
union dpa_offload_ipv4_address {
	/* Address as 32bit word */
	uint32_t	word;

	/* Address as byte array*/
	uint8_t		byte[DPA_OFFLD_IPv4_ADDR_LEN_BYTES];
};

/* Description of the IPv6 address */
union dpa_offload_ipv6_address {
	/* Address as byte array*/
	uint8_t		byte[DPA_OFFLD_IPv6_ADDR_LEN_BYTES];

	/* Address as word array */
	uint32_t	word[DPA_OFFLD_IPv6_ADDR_LEN_WORDS];

	/* Address as long word */
	uint64_t	lword[DPA_OFFLD_IPv6_ADDR_LEN_LONG];
};

struct dpa_offload_ip_address {
	/*
	 * IP version. Must be either 4 or 6. No other values are considered
	 * valid.
	 */
	unsigned int		version;

	union {
		union dpa_offload_ipv4_address	ipv4;
		union dpa_offload_ipv6_address	ipv6;
	} addr;
};

/* Description of the well known PPPoE header */
struct pppoe_header {
	uint8_t			version:4;	/* Protocol version */
	uint8_t			type:4;		/* Type */
	uint8_t			code;		/* Packet type code */
	uint16_t		sid;		/* Session Id */
	uint16_t		length;		/* Payload size */
};

/* Description of the MPLS header */
struct mpls_header {
	uint32_t	label:20;		/* Label value */
	uint32_t	exp:3;			/* Experimental */
	uint32_t	s:1;			/* Bottom of stack */
	uint32_t	ttl:8;			/* Time to live */
};

/* Description of the IPv6 header */
struct ipv6_header {
	uint32_t			version:4;	/* Version */
	uint32_t			tc:8;		/* Traffic Class */
	uint32_t			flow_label:20;	/* Label */
	uint16_t			payload_len;	/* Payload size */
	uint8_t				next_hdr;	/* Next protocol */
	uint8_t				hop_limit;	/* Hop Limit */
	union dpa_offload_ipv6_address	ipsa;		/* Source address */
	union dpa_offload_ipv6_address	ipda;		/* Destination addr */
};

struct ipv4_header {
	/* IPv4 header */
	struct iphdr			header;

	/* IPv4 options buffer. NULL for no options. */
	uint8_t				*options;

	/* Size of IPv4 options buffer. Zero for no options. */
	uint8_t				options_size;
};

/* Description of the VLAN header */
struct vlan_header {
	uint16_t			tpid;
	uint16_t			tci;
};


#endif /* __FSL_DPA_OFFLOAD_H */
