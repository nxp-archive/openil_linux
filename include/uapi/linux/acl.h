/* SPDX-License-Identifier: (GPL-2.0 OR MIT) */
/* Microsemi Ocelot Switch driver
 * Copyright (c) 2019 Microsemi Corporation
 * Copyright 2019 NXP
 */

#ifndef _FELIX_ACL_H_
#define _FELIX_ACL_H_

enum felix_vcap_key_type_t {
	FELIX_VCAP_KEY_TYPE_NORMAL,     /**< Half key, SIP only */
	FELIX_VCAP_KEY_TYPE_DOUBLE_TAG, /**< Quarter key, two tags */
	FELIX_VCAP_KEY_TYPE_IP_ADDR,    /**< Half key, SIP and DIP */
	FELIX_VCAP_KEY_TYPE_MAC_IP_ADDR /**< Full key, MAC and IP addresses */
};

struct felix_mac_t {
	uint8_t addr[6];
};

struct felix_vid_mac_t {
	uint16_t vid;
	struct felix_mac_t mac;
};

struct felix_ipv4_t {
	uint8_t addr[4];
};

struct felix_ipv6_t {
	uint8_t addr[16];
};

enum felix_ip_type_t {
	FELIX_IP_TYPE_NONE = 0,
	FELIX_IP_TYPE_IPV4 = 1,
	FELIX_IP_TYPE_IPV6 = 2,
};

struct felix_ip_addr_t {
	enum felix_ip_type_t type;

	union {
		struct felix_ipv4_t ipv4;
		struct felix_ipv6_t ipv6;
	} addr;
};

struct felix_ipv4_network_t {
	struct felix_ipv4_t address;
	uint32_t prefix_size;
};

struct felix_ipv6_network_t {
	struct felix_ipv6_t address;
	uint32_t prefix_size;
};

struct felix_ip_network_t {
	struct felix_ip_addr_t address;
	uint32_t prefix_size;
};

enum felix_vcap_bit_t {
	FELIX_VCAP_BIT_ANY,
	FELIX_VCAP_BIT_0,
	FELIX_VCAP_BIT_1
};

struct felix_vcap_u8_t {
	uint8_t value[1];
	uint8_t mask[1];
};

struct felix_vcap_u16_t {
	uint8_t value[2];
	uint8_t mask[2];
};

struct felix_vcap_u24_t {
	uint8_t value[3];
	uint8_t mask[3];
};

struct felix_vcap_u32_t {
	uint8_t value[4];
	uint8_t mask[4];
};

struct felix_vcap_u40_t {
	uint8_t value[5];
	uint8_t mask[5];
};

struct felix_vcap_u48_t {
	uint8_t value[6];
	uint8_t mask[6];
};

struct felix_vcap_u64_t {
	uint8_t value[8];
	uint8_t mask[8];
};

struct felix_vcap_u128_t {
	uint8_t value[16];
	uint8_t mask[16];
};

struct felix_vcap_vid_t {
	uint16_t value;
	uint16_t mask;
};

struct felix_vcap_ipv4_t {
	struct felix_ipv4_t value;
	struct felix_ipv4_t mask;
};

struct felix_vcap_udp_tcp_t {
	uint16_t value;
	uint16_t mask;
};

enum felix_acl_port_action_t {
	// Ifindex list is not used
	FELIX_ACL_PORT_ACTION_NONE,

	// The list of interfaces is 'anded' with the list of interfaces from
	// the mac-table
	FELIX_ACL_PORT_ACTION_FILTER,

	// The list of interaces is used as-is regardless of what the mac-table
	// says
	FELIX_ACL_PORT_ACTION_REDIR
};

struct felix_acl_action_t {
	/* Forward to CPU */
	uint8_t cpu;

	/* Only first frame forwarded to CPU */
	uint8_t cpu_once;

	/* CPU queue */
	uint32_t cpu_queue;

	/* Allow learning */
	uint8_t learn;

	/* Port action */
	enum felix_acl_port_action_t port_action;

	/* Egress port list */
	uint8_t ifmask;
};

enum felix_ace_type_t {
	FELIX_ACE_TYPE_ANY,
	FELIX_ACE_TYPE_ETYPE,
	FELIX_ACE_TYPE_LLC,
	FELIX_ACE_TYPE_SNAP,
	FELIX_ACE_TYPE_ARP,
	FELIX_ACE_TYPE_IPV4,
	FELIX_ACE_TYPE_IPV6
};

struct felix_ace_vlan_t {
	struct felix_vcap_vid_t vid;    /* VLAN ID (12 bit) */
	struct felix_vcap_u8_t  pcp;    /* PCP (3 bit) */
	enum felix_vcap_bit_t dei;    /* DEI */
	enum felix_vcap_bit_t tagged; /* Tagged/untagged frame */
};

struct felix_ace_frame_etype_t {
	struct felix_vcap_u48_t dmac;
	struct felix_vcap_u48_t smac;
	struct felix_vcap_u16_t etype;
	struct felix_vcap_u16_t data; /* MAC data */
};

struct felix_ace_frame_llc_t {
	struct felix_vcap_u48_t dmac;
	struct felix_vcap_u48_t smac;

	/* LLC header: DSAP at byte 0, SSAP at byte 1, Control at byte 2 */
	struct felix_vcap_u32_t llc;
};

struct felix_ace_frame_snap_t {
	struct felix_vcap_u48_t dmac;
	struct felix_vcap_u48_t smac;

	/* SNAP header: Organization Code at byte 0, Type at byte 3 */
	struct felix_vcap_u40_t snap;
};

struct felix_ace_frame_arp_t {
	struct felix_vcap_u48_t smac;
	enum felix_vcap_bit_t arp;	/* Opcode ARP/RARP */
	enum felix_vcap_bit_t req;	/* Opcode request/reply */
	enum felix_vcap_bit_t unknown;    /* Opcode unknown */
	enum felix_vcap_bit_t smac_match; /* Sender MAC matches SMAC */
	enum felix_vcap_bit_t dmac_match; /* Target MAC matches DMAC */

	/**< Protocol addr. length 4, hardware length 6 */
	enum felix_vcap_bit_t length;

	enum felix_vcap_bit_t ip;       /* Protocol address type IP */
	/* Hardware address type Ethernet */
	enum felix_vcap_bit_t ethernet;
	struct felix_vcap_ipv4_t sip;     /* Sender IP address */
	struct felix_vcap_ipv4_t dip;     /* Target IP address */
};

struct felix_ace_frame_ipv4_t {
	enum felix_vcap_bit_t ttl;      /* TTL zero */
	enum felix_vcap_bit_t fragment; /* Fragment */
	enum felix_vcap_bit_t options;  /* Header options */
	struct felix_vcap_u8_t ds;
	struct felix_vcap_u8_t proto;      /* Protocol */
	struct felix_vcap_ipv4_t sip;      /* Source IP address */
	struct felix_vcap_ipv4_t dip;      /* Destination IP address */
	struct felix_vcap_u48_t data;      /* Not UDP/TCP: IP data */
	struct felix_vcap_udp_tcp_t sport; /* UDP/TCP: Source port */
	struct felix_vcap_udp_tcp_t dport; /* UDP/TCP: Destination port */
	enum felix_vcap_bit_t tcp_fin;
	enum felix_vcap_bit_t tcp_syn;
	enum felix_vcap_bit_t tcp_rst;
	enum felix_vcap_bit_t tcp_psh;
	enum felix_vcap_bit_t tcp_ack;
	enum felix_vcap_bit_t tcp_urg;
	enum felix_vcap_bit_t sip_eq_dip;     /* SIP equals DIP  */
	enum felix_vcap_bit_t sport_eq_dport; /* SPORT equals DPORT  */
	/* TCP sequence number is zero */
	enum felix_vcap_bit_t seq_zero;
};

struct felix_ace_frame_ipv6_t {
	struct felix_vcap_u8_t proto; /* IPv6 protocol */
	/* IPv6 source address (byte 0-7 ignored) */
	struct felix_vcap_u128_t sip;
	enum felix_vcap_bit_t ttl;  /* TTL zero */
	struct felix_vcap_u8_t ds;
	struct felix_vcap_u48_t data; /* Not UDP/TCP: IP data */
	struct felix_vcap_udp_tcp_t sport;
	struct felix_vcap_udp_tcp_t dport;
	enum felix_vcap_bit_t tcp_fin;
	enum felix_vcap_bit_t tcp_syn;
	enum felix_vcap_bit_t tcp_rst;
	enum felix_vcap_bit_t tcp_psh;
	enum felix_vcap_bit_t tcp_ack;
	enum felix_vcap_bit_t tcp_urg;
	enum felix_vcap_bit_t sip_eq_dip;     /* SIP equals DIP  */
	enum felix_vcap_bit_t sport_eq_dport; /* SPORT equals DPORT  */
	/* TCP sequence number is zero */
	enum felix_vcap_bit_t seq_zero;
};

struct felix_ace_t {
	uint16_t id; /* ID of rule */

	struct felix_acl_action_t action;

	uint8_t ifmask;
	enum felix_vcap_bit_t dmac_mc;
	enum felix_vcap_bit_t dmac_bc;
	struct felix_ace_vlan_t vlan;

	enum felix_ace_type_t type;

	union {
		/* FELIX_ACE_TYPE_ANY: No specific fields */
		struct felix_ace_frame_etype_t etype;
		struct felix_ace_frame_llc_t llc;
		struct felix_ace_frame_snap_t snap;
		struct felix_ace_frame_arp_t arp;
		struct felix_ace_frame_ipv4_t ipv4;
		struct felix_ace_frame_ipv6_t ipv6;
	} frame;
};
#endif /* _FELIX_ACL_H_ */
