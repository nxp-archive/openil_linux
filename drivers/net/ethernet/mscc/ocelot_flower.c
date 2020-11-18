// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/* Microsemi Ocelot Switch driver
 * Copyright (c) 2019 Microsemi Corporation
 */

#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <soc/mscc/ocelot_vcap.h>

#include "ocelot_vcap.h"

static int ocelot_flower_parse_action(struct ocelot *ocelot,
				      struct flow_cls_offload *f,
				      struct ocelot_vcap_filter *filter)
{
	struct netlink_ext_ack *extack = f->common.extack;
	const struct flow_action_entry *a;
	enum ocelot_tag_tpid_sel tpid;
	s64 burst;
	u64 rate;
	int i;

	flow_action_for_each(i, a, &f->rule->action) {
		switch (a->id) {
		case FLOW_ACTION_DROP:
			filter->action.mask_mode = OCELOT_MASK_MODE_PERMIT_DENY;
			filter->action.port_mask = 0;
			filter->action.police_ena = true;
			filter->action.pol_ix = OCELOT_POLICER_DISCARD;
			filter->vcap_id = VCAP_IS2;
			break;
		case FLOW_ACTION_TRAP:
			filter->action.mask_mode = OCELOT_MASK_MODE_PERMIT_DENY;
			filter->action.port_mask = 0;
			filter->action.cpu_copy_ena = true;
			filter->action.cpu_qu_num = 0;
			filter->vcap_id = VCAP_IS2;
			break;
		case FLOW_ACTION_POLICE:
			filter->action.police_ena = true;
			filter->vcap_id = VCAP_IS2;
			filter->action.pol_ix = a->police.index + ocelot->policer_base;
			rate = a->police.rate_bytes_ps;
			burst = rate * PSCHED_NS2TICKS(a->police.burst);
			filter->action.pol = (struct ocelot_policer) {
				.burst = div_u64(burst, PSCHED_TICKS_PER_SEC),
				.rate = div_u64(rate, 1000) * 8,
			};
			break;
		case FLOW_ACTION_PRIORITY:
			filter->action.qos_ena = true;
			filter->action.qos_val = a->priority;
			filter->vcap_id = VCAP_IS1;
			break;
		case FLOW_ACTION_VLAN_MANGLE:
			filter->vcap_id = VCAP_IS1;
			filter->action.vid_replace_ena = true;
			filter->action.pcp_dei_ena = true;
			filter->action.vid = a->vlan.vid;
			filter->action.pcp = a->vlan.prio;
			break;
		case FLOW_ACTION_VLAN_PUSH:
			filter->vcap_id = VCAP_ES0;
			switch (ntohs(a->vlan.proto)) {
			case ETH_P_8021Q:
				tpid = OCELOT_TAG_TPID_SEL_8021Q;
				filter->action.tag_a_tpid_sel = tpid;
				filter->action.push_outer_tag = OCELOT_ES0_TAG;
				filter->action.tag_a_vid_sel = 1;
				filter->action.vid_a_val = a->vlan.vid;
				filter->action.pcp_a_val = a->vlan.prio;
				break;
			case ETH_P_8021AD:
				tpid = OCELOT_TAG_TPID_SEL_8021AD;
				filter->action.tag_b_tpid_sel = tpid;
				filter->action.push_inner_tag = OCELOT_ES0_TAG;
				filter->action.tag_b_vid_sel = 1;
				filter->action.vid_b_val = a->vlan.vid;
				filter->action.pcp_b_val = a->vlan.prio;
				break;
			default:
				NL_SET_ERR_MSG_MOD(extack,
						   "Cannot push custom TPID");
			}
			break;
		case FLOW_ACTION_VLAN_POP:
			filter->vcap_id = VCAP_IS1;
			filter->action.vlan_pop_cnt_ena = true;
			filter->action.vlan_pop_cnt++;
			if (filter->action.vlan_pop_cnt > 2) {
				NL_SET_ERR_MSG_MOD(extack,
						    "Cannot pop more than 2 VLAN headers");
				return -EOPNOTSUPP;
			}
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack, "Cannot offload action");
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

static int ocelot_flower_parse_key(struct flow_cls_offload *f,
				   struct ocelot_vcap_filter *filter)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_dissector *dissector = rule->match.dissector;
	u16 proto = ntohs(f->common.protocol);
	bool match_protocol = true;

	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT(FLOW_DISSECTOR_KEY_CVLAN) |
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS))) {
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		/* The hw support mac matches only for MAC_ETYPE key,
		 * therefore if other matches(port, tcp flags, etc) are added
		 * then just bail out
		 */
		if ((dissector->used_keys &
		    (BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
		     BIT(FLOW_DISSECTOR_KEY_BASIC) |
		     BIT(FLOW_DISSECTOR_KEY_CONTROL))) !=
		    (BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
		     BIT(FLOW_DISSECTOR_KEY_BASIC) |
		     BIT(FLOW_DISSECTOR_KEY_CONTROL)))
			return -EOPNOTSUPP;

		flow_rule_match_eth_addrs(rule, &match);
		filter->key_type = OCELOT_VCAP_KEY_ETYPE;
		ether_addr_copy(filter->key.etype.dmac.value,
				match.key->dst);
		ether_addr_copy(filter->key.etype.smac.value,
				match.key->src);
		ether_addr_copy(filter->key.etype.dmac.mask,
				match.mask->dst);
		ether_addr_copy(filter->key.etype.smac.mask,
				match.mask->src);
		goto finished_key_parsing;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		if (ntohs(match.key->n_proto) == ETH_P_IP) {
			filter->key_type = OCELOT_VCAP_KEY_IPV4;
			filter->key.ipv4.proto.value[0] =
				match.key->ip_proto;
			filter->key.ipv4.proto.mask[0] =
				match.mask->ip_proto;
			match_protocol = false;
		}
		if (ntohs(match.key->n_proto) == ETH_P_IPV6) {
			filter->key_type = OCELOT_VCAP_KEY_IPV6;
			filter->key.ipv6.proto.value[0] =
				match.key->ip_proto;
			filter->key.ipv6.proto.mask[0] =
				match.mask->ip_proto;
			match_protocol = false;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS) &&
	    proto == ETH_P_IP) {
		struct flow_match_ipv4_addrs match;
		u8 *tmp;

		flow_rule_match_ipv4_addrs(rule, &match);
		tmp = &filter->key.ipv4.sip.value.addr[0];
		memcpy(tmp, &match.key->src, 4);

		tmp = &filter->key.ipv4.sip.mask.addr[0];
		memcpy(tmp, &match.mask->src, 4);

		tmp = &filter->key.ipv4.dip.value.addr[0];
		memcpy(tmp, &match.key->dst, 4);

		tmp = &filter->key.ipv4.dip.mask.addr[0];
		memcpy(tmp, &match.mask->dst, 4);
		match_protocol = false;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS) &&
	    proto == ETH_P_IPV6) {
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		filter->key.ipv4.sport.value = ntohs(match.key->src);
		filter->key.ipv4.sport.mask = ntohs(match.mask->src);
		filter->key.ipv4.dport.value = ntohs(match.key->dst);
		filter->key.ipv4.dport.mask = ntohs(match.mask->dst);
		match_protocol = false;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_vlan(rule, &match);
		filter->key_type = OCELOT_VCAP_KEY_ANY;
		filter->vlan.vid.value = match.key->vlan_id;
		filter->vlan.vid.mask = match.mask->vlan_id;
		filter->vlan.pcp.value[0] = match.key->vlan_priority;
		filter->vlan.pcp.mask[0] = match.mask->vlan_priority;
		match_protocol = false;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_cvlan(rule, &match);
		filter->key_type = OCELOT_VCAP_KEY_ANY;
		filter->cvlan.vid.value = match.key->vlan_id;
		filter->cvlan.vid.mask = match.mask->vlan_id;
		filter->cvlan.pcp.value[0] = match.key->vlan_priority;
		filter->cvlan.pcp.mask[0] = match.mask->vlan_priority;
		match_protocol = false;
	}

finished_key_parsing:
	if (match_protocol && proto != ETH_P_ALL) {
		/* TODO: support SNAP, LLC etc */
		if (proto < ETH_P_802_3_MIN)
			return -EOPNOTSUPP;
		filter->key_type = OCELOT_VCAP_KEY_ETYPE;
		*(u16 *)filter->key.etype.etype.value = htons(proto);
		*(u16 *)filter->key.etype.etype.mask = 0xffff;
	}
	/* else, a rule of type OCELOT_VCAP_TYPE_ANY is implicitly added */

	return 0;
}

static int ocelot_flower_parse(struct ocelot *ocelot,
			       struct flow_cls_offload *f,
			       struct ocelot_vcap_filter *filter)
{
	int ret;

	filter->prio = f->common.prio;
	filter->id = f->cookie;

	ret = ocelot_flower_parse_action(ocelot, f, filter);
	if (ret)
		return ret;

	return ocelot_flower_parse_key(f, filter);
}

static struct ocelot_vcap_filter
	*ocelot_vcap_filter_create(struct ocelot *ocelot, int port,
				   bool ingress, struct flow_cls_offload *f)
{
	struct ocelot_vcap_filter *filter;

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return NULL;

	if (ingress)
		filter->ingress_port_mask = BIT(port);
	else
		filter->egress_port = port;
	return filter;
}

int ocelot_cls_flower_replace(struct ocelot *ocelot, int port,
			      struct flow_cls_offload *f, bool ingress)
{
	struct ocelot_vcap_filter *filter;
	int ret;

	filter = ocelot_vcap_filter_create(ocelot, port, ingress, f);
	if (!filter)
		return -ENOMEM;

	ret = ocelot_flower_parse(ocelot, f, filter);
	if (ret) {
		kfree(filter);
		return ret;
	}

	return ocelot_vcap_filter_add(ocelot, filter, f->common.extack);
}
EXPORT_SYMBOL_GPL(ocelot_cls_flower_replace);

int ocelot_cls_flower_destroy(struct ocelot *ocelot, int port,
			      struct flow_cls_offload *f, bool ingress)
{
	struct ocelot_vcap_block *block;
	struct ocelot_vcap_filter *filter;
	int i;

	for (i = 0; i < VCAP_CORE_MAX; i++) {
		block = &ocelot->block[i];
		filter = ocelot_vcap_block_find_filter_by_id(block, f->cookie);
		if (filter)
			break;
	}
	if (!filter)
		return 0;

	return ocelot_vcap_filter_del(ocelot, filter);
}
EXPORT_SYMBOL_GPL(ocelot_cls_flower_destroy);

int ocelot_cls_flower_stats(struct ocelot *ocelot, int port,
			    struct flow_cls_offload *f, bool ingress)
{
	struct ocelot_vcap_block *block;
	struct ocelot_vcap_filter *filter;
	int ret, i;

	for (i = 0; i < VCAP_CORE_MAX; i++) {
		block = &ocelot->block[i];
		filter = ocelot_vcap_block_find_filter_by_id(block, f->cookie);
		if (filter)
			break;
	}
	if (!filter)
		return 0;

	ret = ocelot_vcap_filter_stats_update(ocelot, filter);
	if (ret)
		return ret;

	flow_stats_update(&f->stats, 0x0, filter->stats.pkts, 0x0);
	return 0;
}
EXPORT_SYMBOL_GPL(ocelot_cls_flower_stats);

int ocelot_setup_tc_cls_flower(struct ocelot_port_private *priv,
			       struct flow_cls_offload *f,
			       bool ingress)
{
	struct ocelot *ocelot = priv->port.ocelot;
	int port = priv->chip_port;

	if (!ingress)
		return -EOPNOTSUPP;

	switch (f->command) {
	case FLOW_CLS_REPLACE:
		return ocelot_cls_flower_replace(ocelot, port, f, ingress);
	case FLOW_CLS_DESTROY:
		return ocelot_cls_flower_destroy(ocelot, port, f, ingress);
	case FLOW_CLS_STATS:
		return ocelot_cls_flower_stats(ocelot, port, f, ingress);
	default:
		return -EOPNOTSUPP;
	}
}
