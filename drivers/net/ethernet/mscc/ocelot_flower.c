// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/* Microsemi Ocelot Switch driver
 * Copyright (c) 2019 Microsemi Corporation
 */

#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <soc/mscc/ocelot_vcap.h>

#include "ocelot_ace.h"

static int ocelot_flower_parse_action(struct flow_cls_offload *f,
				      struct ocelot_ace_rule *ace)
{
	struct netlink_ext_ack *extack = f->common.extack;
	const struct flow_action_entry *a;
	s64 burst;
	u64 rate;
	int i;

	flow_action_for_each(i, a, &f->rule->action) {
		switch (a->id) {
		case FLOW_ACTION_DROP:
			if (ace->vcap_id && ace->vcap_id != VCAP_IS2)
				goto out_mix_disallowed;

			ace->is2_action.drop_ena = true;
			ace->vcap_id = VCAP_IS2;
			break;
		case FLOW_ACTION_TRAP:
			if (ace->vcap_id && ace->vcap_id != VCAP_IS2)
				goto out_mix_disallowed;

			ace->is2_action.trap_ena = true;
			ace->vcap_id = VCAP_IS2;
			break;
		case FLOW_ACTION_POLICE:
			if (ace->vcap_id && ace->vcap_id != VCAP_IS2)
				goto out_mix_disallowed;

			ace->is2_action.police_ena = true;
			ace->vcap_id = VCAP_IS2;
			rate = a->police.rate_bytes_ps;
			burst = rate * PSCHED_NS2TICKS(a->police.burst);
			ace->is2_action.pol = (struct ocelot_policer) {
				.burst = div_u64(burst, PSCHED_TICKS_PER_SEC),
				.rate = div_u64(rate, 1000) * 8,
			};
			break;
		case FLOW_ACTION_PRIORITY:
			if (ace->vcap_id && ace->vcap_id != VCAP_IS1)
				goto out_mix_disallowed;

			ace->is1_action.qos_ena = true;
			ace->is1_action.qos_val = a->priority;
			ace->vcap_id = VCAP_IS1;
			break;
		case FLOW_ACTION_VLAN_MANGLE:
			if (ace->vcap_id && ace->vcap_id != VCAP_IS1)
				goto out_mix_disallowed;

			ace->vcap_id = VCAP_IS1;
			ace->is1_action.vlan_modify_ena = true;
			ace->is1_action.vid = a->vlan.vid;
			ace->is1_action.pcp = a->vlan.prio;
			break;
		case FLOW_ACTION_VLAN_PUSH:
			if (ace->vcap_id && ace->vcap_id != VCAP_ES0)
				goto out_mix_disallowed;

			ace->vcap_id = VCAP_ES0;
			ace->es0_action.vlan_push_ena = true;
			ace->es0_action.vid = a->vlan.vid;
			ace->es0_action.pcp = a->vlan.prio;
			break;
		default:
			return -EOPNOTSUPP;
		}
	}

	return 0;

out_mix_disallowed:
	NL_SET_ERR_MSG_MOD(extack,
			   "Cannot mix actions for multiple VCAPs in the same rule");
	return -EOPNOTSUPP;
}

static int ocelot_flower_parse(struct flow_cls_offload *f,
			       struct ocelot_ace_rule *ace)
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
		ace->type = OCELOT_ACE_TYPE_ETYPE;
		ether_addr_copy(ace->frame.etype.dmac.value,
				match.key->dst);
		ether_addr_copy(ace->frame.etype.smac.value,
				match.key->src);
		ether_addr_copy(ace->frame.etype.dmac.mask,
				match.mask->dst);
		ether_addr_copy(ace->frame.etype.smac.mask,
				match.mask->src);
		goto finished_key_parsing;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		if (ntohs(match.key->n_proto) == ETH_P_IP) {
			ace->type = OCELOT_ACE_TYPE_IPV4;
			ace->frame.ipv4.proto.value[0] =
				match.key->ip_proto;
			ace->frame.ipv4.proto.mask[0] =
				match.mask->ip_proto;
			match_protocol = false;
		}
		if (ntohs(match.key->n_proto) == ETH_P_IPV6) {
			ace->type = OCELOT_ACE_TYPE_IPV6;
			ace->frame.ipv6.proto.value[0] =
				match.key->ip_proto;
			ace->frame.ipv6.proto.mask[0] =
				match.mask->ip_proto;
			match_protocol = false;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS) &&
	    proto == ETH_P_IP) {
		struct flow_match_ipv4_addrs match;
		u8 *tmp;

		flow_rule_match_ipv4_addrs(rule, &match);
		tmp = &ace->frame.ipv4.sip.value.addr[0];
		memcpy(tmp, &match.key->src, 4);

		tmp = &ace->frame.ipv4.sip.mask.addr[0];
		memcpy(tmp, &match.mask->src, 4);

		tmp = &ace->frame.ipv4.dip.value.addr[0];
		memcpy(tmp, &match.key->dst, 4);

		tmp = &ace->frame.ipv4.dip.mask.addr[0];
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
		ace->frame.ipv4.sport.value = ntohs(match.key->src);
		ace->frame.ipv4.sport.mask = ntohs(match.mask->src);
		ace->frame.ipv4.dport.value = ntohs(match.key->dst);
		ace->frame.ipv4.dport.mask = ntohs(match.mask->dst);
		match_protocol = false;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_vlan(rule, &match);
		ace->type = OCELOT_ACE_TYPE_ANY;
		ace->vlan.vid.value = match.key->vlan_id;
		ace->vlan.vid.mask = match.mask->vlan_id;
		ace->vlan.pcp.value[0] = match.key->vlan_priority;
		ace->vlan.pcp.mask[0] = match.mask->vlan_priority;
		match_protocol = false;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_cvlan(rule, &match);
		ace->type = OCELOT_ACE_TYPE_ANY;
		ace->cvlan.vid.value = match.key->vlan_id;
		ace->cvlan.vid.mask = match.mask->vlan_id;
		ace->cvlan.pcp.value[0] = match.key->vlan_priority;
		ace->cvlan.pcp.mask[0] = match.mask->vlan_priority;
		match_protocol = false;
	}

finished_key_parsing:
	if (match_protocol && proto != ETH_P_ALL) {
		/* TODO: support SNAP, LLC etc */
		if (proto < ETH_P_802_3_MIN)
			return -EOPNOTSUPP;
		ace->type = OCELOT_ACE_TYPE_ETYPE;
		*(u16 *)ace->frame.etype.etype.value = htons(proto);
		*(u16 *)ace->frame.etype.etype.mask = 0xffff;
	}
	/* else, a rule of type OCELOT_ACE_TYPE_ANY is implicitly added */

	ace->prio = f->common.prio;
	ace->id = f->cookie;
	return ocelot_flower_parse_action(f, ace);
}

static
struct ocelot_ace_rule *ocelot_ace_rule_create(struct ocelot *ocelot, int port,
					       bool ingress,
					       struct flow_cls_offload *f)
{
	struct ocelot_ace_rule *ace;

	ace = kzalloc(sizeof(*ace), GFP_KERNEL);
	if (!ace)
		return NULL;

	if (ingress)
		ace->ingress_port_mask = BIT(port);
	else
		ace->egress_port = port;
	return ace;
}

int ocelot_cls_flower_replace(struct ocelot *ocelot, int port,
			      struct flow_cls_offload *f, bool ingress)
{
	struct ocelot_ace_rule *ace;
	int ret;

	ace = ocelot_ace_rule_create(ocelot, port, ingress, f);
	if (!ace)
		return -ENOMEM;

	ret = ocelot_flower_parse(f, ace);
	if (ret) {
		kfree(ace);
		return ret;
	}

	return ocelot_ace_rule_offload_add(ocelot, ace, f->common.extack);
}
EXPORT_SYMBOL_GPL(ocelot_cls_flower_replace);

int ocelot_cls_flower_destroy(struct ocelot *ocelot, int port,
			      struct flow_cls_offload *f, bool ingress)
{
	struct ocelot_ace_rule ace;

	ace.prio = f->common.prio;
	ace.id = f->cookie;
	if (ingress)
		ace.vcap_id = VCAP_IS2;
	else
		ace.vcap_id = VCAP_ES0;

	return ocelot_ace_rule_offload_del(ocelot, &ace);
}
EXPORT_SYMBOL_GPL(ocelot_cls_flower_destroy);

int ocelot_cls_flower_stats(struct ocelot *ocelot, int port,
			    struct flow_cls_offload *f, bool ingress)
{
	struct ocelot_ace_rule ace;
	int ret;

	ace.prio = f->common.prio;
	ace.id = f->cookie;
	if (ingress)
		ace.vcap_id = VCAP_IS2;
	else
		ace.vcap_id = VCAP_ES0;

	ret = ocelot_ace_rule_stats_update(ocelot, &ace);
	if (ret)
		return ret;

	flow_stats_update(&f->stats, 0x0, ace.stats.pkts, 0x0);
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
