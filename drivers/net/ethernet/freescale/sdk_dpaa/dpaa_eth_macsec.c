/* Copyright 2015 Freescale Semiconductor Inc.
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "dpaa_eth_macsec.h"
#include "dpaa_eth_common.h"

#ifdef CONFIG_FSL_DPAA_1588
#include "dpaa_1588.h"
#endif

static struct sock *nl_sk;
static struct macsec_priv_s *macsec_priv[FM_MAX_NUM_OF_MACS];
static char *macsec_ifs[FM_MAX_NUM_OF_MACS];
static int macsec_ifs_cnt;

static char ifs[MAX_LEN];
const struct ethtool_ops *dpa_ethtool_ops_prev;
static struct ethtool_ops dpa_macsec_ethtool_ops;

module_param_string(ifs, ifs, MAX_LEN, 0000);
MODULE_PARM_DESC(ifs, "Comma separated interface list");

struct macsec_priv_s *dpa_macsec_get_priv(struct net_device *net_dev)
{
	return macsec_priv[net_dev->ifindex - 1];
}

static void macsec_setup_ethtool_ops(struct net_device *net_dev)
{
	/* remember private driver's ethtool ops just once */
	if (!dpa_ethtool_ops_prev) {
		dpa_ethtool_ops_prev = net_dev->ethtool_ops;

		memcpy(&dpa_macsec_ethtool_ops, net_dev->ethtool_ops,
		       sizeof(struct ethtool_ops));
		dpa_macsec_ethtool_ops.get_sset_count =
		    dpa_macsec_get_sset_count;
		dpa_macsec_ethtool_ops.get_ethtool_stats =
		    dpa_macsec_get_ethtool_stats;
		dpa_macsec_ethtool_ops.get_strings =
		    dpa_macsec_get_strings;
	}

	net_dev->ethtool_ops = &dpa_macsec_ethtool_ops;
}

static void macsec_restore_ethtool_ops(struct net_device *net_dev)
{
	net_dev->ethtool_ops = dpa_ethtool_ops_prev;
}


static int ifname_to_id(char *ifname)
{
	int i;

	for (i = 0; i < FM_MAX_NUM_OF_MACS; i++) {
		if (macsec_priv[i]->net_dev &&
			(strcmp(ifname, macsec_priv[i]->net_dev->name) == 0)) {
			return i;
		}
	}

	return -1;
}

static void deinit_macsec(int macsec_id)
{
	struct macsec_priv_s *selected_macsec_priv;
	int i;

	selected_macsec_priv = macsec_priv[macsec_id];

	if (selected_macsec_priv->en_state == SECY_ENABLED) {
		for (i = 0; i < NUM_OF_RX_SC; i++) {
			if (!selected_macsec_priv->rx_sc_dev[i])
				continue;
			fm_macsec_secy_rxsa_disable_receive(
					selected_macsec_priv->fm_ms_secy,
					selected_macsec_priv->rx_sc_dev[i],
					selected_macsec_priv->an);
			pr_debug("disable rx_sa done\n");

			fm_macsec_secy_delete_rx_sa(
					selected_macsec_priv->fm_ms_secy,
					selected_macsec_priv->rx_sc_dev[i],
					selected_macsec_priv->an);
			pr_debug("delete rx_sa done\n");

			fm_macsec_secy_delete_rxsc(
					selected_macsec_priv->fm_ms_secy,
					selected_macsec_priv->rx_sc_dev[i]);
			pr_debug("delete rx_sc done\n");
		}

		fm_macsec_secy_delete_tx_sa(selected_macsec_priv->fm_ms_secy,
					selected_macsec_priv->an);
		pr_debug("delete tx_sa done\n");

		fm_macsec_secy_free(selected_macsec_priv->fm_ms_secy);
		selected_macsec_priv->fm_ms_secy = NULL;
		pr_debug("secy free done\n");
	}

	if (selected_macsec_priv->en_state != MACSEC_DISABLED) {
		fm_macsec_disable(selected_macsec_priv->fm_macsec);
		fm_macsec_free(selected_macsec_priv->fm_macsec);
		selected_macsec_priv->fm_macsec = NULL;
		pr_debug("macsec disable and free done\n");
	}
}

static void parse_ifs(void)
{
	char *token, *strpos = ifs;

	while ((token = strsep(&strpos, ","))) {
		if (strlen(token) == 0)
			return;
		else
			macsec_ifs[macsec_ifs_cnt] = token;
		macsec_ifs_cnt++;
	}
}

static void macsec_exception(handle_t _macsec_priv_s,
				fm_macsec_exception exception)
{
	struct macsec_priv_s *priv;
	priv = (struct macsec_priv_s *)_macsec_priv_s;

	switch (exception) {
	case (SINGLE_BIT_ECC):
		dev_warn(priv->mac_dev->dev, "%s:%s SINGLE_BIT_ECC exception\n",
				KBUILD_BASENAME".c", __func__);
		break;
	case (MULTI_BIT_ECC):
		dev_warn(priv->mac_dev->dev, "%s:%s MULTI_BIT_ECC exception\n",
				KBUILD_BASENAME".c", __func__);
		break;
	default:
		dev_warn(priv->mac_dev->dev, "%s:%s exception %d\n",
				KBUILD_BASENAME".c", __func__, exception);
		break;
	}
}


static void macsec_secy_exception(handle_t _macsec_priv_s,
				fm_macsec_secy_exception exception)
{
	struct macsec_priv_s *priv;
	priv = (struct macsec_priv_s *)_macsec_priv_s;

	switch (exception) {
	case (SECY_EX_FRAME_DISCARDED):
		dev_warn(priv->mac_dev->dev,
				"%s:%s SECY_EX_FRAME_DISCARDED exception\n",
				KBUILD_BASENAME".c", __func__);
		break;
	default:
		dev_warn(priv->mac_dev->dev, "%s:%s exception %d\n",
				KBUILD_BASENAME".c", __func__, exception);
		break;
	}
}

static void macsec_secy_events(handle_t _macsec_priv_s,
				fm_macsec_secy_event event)
{
	struct macsec_priv_s *priv;
	priv = (struct macsec_priv_s *)_macsec_priv_s;

	switch (event) {
	case (SECY_EV_NEXT_PN):
		dev_dbg(priv->mac_dev->dev, "%s:%s SECY_EV_NEXT_PN event\n",
				KBUILD_BASENAME".c", __func__);
		break;
	default:
		dev_dbg(priv->mac_dev->dev, "%s:%s event %d\n",
				KBUILD_BASENAME".c", __func__, event);
		break;
	}
}

static struct qman_fq *macsec_get_tx_conf_queue(
				const struct macsec_priv_s *macsec_priv,
				struct qman_fq *tx_fq)
{
	int i;

	for (i = 0; i < MACSEC_ETH_TX_QUEUES; i++)
		if (macsec_priv->egress_fqs[i] == tx_fq)
			return macsec_priv->conf_fqs[i];
	return NULL;
}

/* Initialize qman fqs. Still need to set context_a, specifically the bits
 * that identify the secure channel.
 */
static int macsec_fq_init(struct dpa_fq *dpa_fq)
{
	struct qman_fq *fq;
	struct device *dev;
	struct qm_mcc_initfq initfq;
	uint32_t sc_phys_id;
	int _errno, macsec_id;

	dev = dpa_fq->net_dev->dev.parent;
	macsec_id = dpa_fq->net_dev->ifindex - 1;

	if (dpa_fq->fqid == 0)
		dpa_fq->flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;

	dpa_fq->init = !(dpa_fq->flags & QMAN_FQ_FLAG_NO_MODIFY);
	_errno = qman_create_fq(dpa_fq->fqid, dpa_fq->flags, &dpa_fq->fq_base);

	if (_errno) {
		dev_err(dev, "qman_create_fq() failed\n");
		return _errno;
	}

	fq = &dpa_fq->fq_base;

	if (dpa_fq->init) {
		initfq.we_mask = QM_INITFQ_WE_FQCTRL;
		initfq.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;

		if (dpa_fq->fq_type == FQ_TYPE_TX_CONFIRM)
			initfq.fqd.fq_ctrl |= QM_FQCTRL_HOLDACTIVE;

		initfq.we_mask |= QM_INITFQ_WE_DESTWQ;

		initfq.fqd.dest.channel = dpa_fq->channel;
		initfq.fqd.dest.wq = dpa_fq->wq;

		if (dpa_fq->fq_type == FQ_TYPE_TX) {
			initfq.we_mask |= QM_INITFQ_WE_CONTEXTA;

			/* Obtain the TX scId from fman */
			_errno = fm_macsec_secy_get_txsc_phys_id(
					macsec_priv[macsec_id]->fm_ms_secy,
					&sc_phys_id);
			if (unlikely(_errno < 0)) {
				dev_err(dev, "fm_macsec_secy_get_txsc_phys_id = %d\n",
								_errno);
				return _errno;
			}

			/* Write the TX SC-ID in the context of the FQ.
			 * A2V=1 (use the A2 field)
			 * A0V=1 (use the A0 field)
			 * OVOM=1
			 * MCV=1 (MACsec controlled frames)
			 * MACCMD=the TX scId
			 */
			initfq.fqd.context_a.hi = 0x1a100000 |
						sc_phys_id << 16;
			initfq.fqd.context_a.lo = 0x80000000;
		}

		_errno = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &initfq);
		if (_errno < 0) {
			dev_err(dev, "qman_init_fq(%u) = %d\n",
				qman_fq_fqid(fq), _errno);
			qman_destroy_fq(fq, 0);
			return _errno;
		}
	}

	dpa_fq->fqid = qman_fq_fqid(fq);

	return 0;
}

/* Configure and enable secy. */
static int enable_secy(struct generic_msg *gen, int *macsec_id)
{
	struct enable_secy *sec;
	int _errno;
	struct fm_macsec_secy_params secy_params;
	struct dpa_fq *dpa_fq, *tmp;
	struct macsec_priv_s *selected_macsec_priv;

	sec = &gen->payload.secy;

	if (sec->macsec_id < 0 || sec->macsec_id >= FM_MAX_NUM_OF_MACS) {
		_errno = -EINVAL;
		goto _return;
	}
	*macsec_id = sec->macsec_id;
	selected_macsec_priv = macsec_priv[sec->macsec_id];

	if (selected_macsec_priv->fm_ms_secy) {
		pr_err("Secy has already been enabled\n");
		return -EINVAL;
	}

	memset(&secy_params, 0, sizeof(secy_params));
	secy_params.fm_macsec_h = selected_macsec_priv->fm_macsec;
	secy_params.num_receive_channels = NUM_OF_RX_SC;
	secy_params.tx_sc_params.sci = sec->sci;

	/* Set encryption method */
	secy_params.tx_sc_params.cipher_suite = SECY_GCM_AES_128;
#if (DPAA_VERSION >= 11)
	secy_params.tx_sc_params.cipher_suite = SECY_GCM_AES_256;
#endif /* (DPAA_VERSION >= 11) */
	secy_params.exception_f        = macsec_secy_exception;
	secy_params.event_f            = macsec_secy_events;
	secy_params.app_h              = selected_macsec_priv;

	selected_macsec_priv->fm_ms_secy =
					fm_macsec_secy_config(&secy_params);

	if (unlikely(selected_macsec_priv->fm_ms_secy == NULL)) {
		_errno = -EINVAL;
		goto _return;
	}

	/* Configure the insertion mode */
	if (sec->config_insertion_mode) {
		_errno = fm_macsec_secy_config_sci_insertion_mode(
				selected_macsec_priv->fm_ms_secy,
				sec->sci_insertion_mode);
		if (unlikely(_errno < 0))
			goto _return;
	}

	/* Configure the frame protection */
	if (sec->config_protect_frames) {
		_errno = fm_macsec_secy_config_protect_frames(
				selected_macsec_priv->fm_ms_secy,
				sec->protect_frames);
		if (unlikely(_errno < 0))
			goto _return;
	}

	/* Configure the replay window */
	if (sec->config_replay_window) {
		_errno = fm_macsec_secy_config_replay_window(
				selected_macsec_priv->fm_ms_secy,
				sec->replay_protect,
				sec->replay_window);
		if (unlikely(_errno < 0))
			goto _return;
	}

	/* Configure the validation mode */
	if (sec->config_validation_mode) {
		_errno = fm_macsec_secy_config_validation_mode(
				selected_macsec_priv->fm_ms_secy,
				sec->validate_frames);
		if (unlikely(_errno < 0))
			goto _return;
	}

	/* Select the exceptions that will be signaled */
	if (sec->config_exception) {
		_errno = fm_macsec_secy_config_exception(
					selected_macsec_priv->fm_ms_secy,
					sec->exception,
					sec->enable_exception);
		if (unlikely(_errno < 0))
			goto _return;
	}

	/* Select the events that will be signaled */
	if (sec->config_event) {
		_errno = fm_macsec_secy_config_event(
					selected_macsec_priv->fm_ms_secy,
					sec->event,
					sec->enable_event);
		if (unlikely(_errno < 0))
			goto _return;
	}

	/* Configure a point-to-point connection */
	if (sec->config_point_to_point) {
		_errno = fm_macsec_secy_config_point_to_point(
				selected_macsec_priv->fm_ms_secy);
		if (unlikely(_errno < 0))
			goto _return;
	}

	/* Configure the connection's confidentiality state */
	if (sec->config_confidentiality) {
		_errno = fm_macsec_secy_config_confidentiality(
				selected_macsec_priv->fm_ms_secy,
				sec->confidentiality_enable,
				sec->confidentiality_offset);
		if (unlikely(_errno < 0))
			goto _return;
	}

	_errno = fm_macsec_secy_init(selected_macsec_priv->fm_ms_secy);
	if (unlikely(_errno < 0))
		goto _return_fm_macsec_secy_free;

	list_for_each_entry_safe(dpa_fq,
				tmp,
				&selected_macsec_priv->dpa_fq_list,
				list) {
		_errno = macsec_fq_init(dpa_fq);
		if (_errno < 0)
			goto _return;
	}

	return 0;

_return_fm_macsec_secy_free:
	fm_macsec_secy_free(selected_macsec_priv->fm_ms_secy);
	selected_macsec_priv->fm_ms_secy = NULL;
_return:
	return _errno;
}

static int set_macsec_exception(struct generic_msg *gen)
{
	struct set_exception *set_ex;
	struct macsec_priv_s *selected_macsec_priv;
	int rv;

	set_ex = &(gen->payload.set_ex);

	selected_macsec_priv = macsec_priv[set_ex->macsec_id];

	rv = fm_macsec_set_exception(selected_macsec_priv->fm_macsec,
				set_ex->exception,
				set_ex->enable_exception);
	if (unlikely(rv < 0))
		pr_err("error when setting the macsec exception mask\n");

	return rv;
}

static int create_tx_sa(struct generic_msg *gen)
{
	struct create_tx_sa *c_tx_sa;
	macsec_sa_key_t sa_key;
	int rv;
	struct macsec_priv_s *selected_macsec_priv;

	c_tx_sa = &(gen->payload.c_tx_sa);

	if (c_tx_sa->macsec_id < 0 ||
			c_tx_sa->macsec_id >= FM_MAX_NUM_OF_MACS) {
		kfree(c_tx_sa);
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[c_tx_sa->macsec_id];

	/* set macsec_priv field */
	selected_macsec_priv->an = c_tx_sa->an;

	/* because of the algorithms used */
	if (unlikely(c_tx_sa->sak_len > 32)) {
		pr_warn("size of secure key is greater than 32 bytes!\n");
		kfree(c_tx_sa);
		return -EINVAL;
	}

	rv = copy_from_user(&sa_key,
			c_tx_sa->sak,
			c_tx_sa->sak_len);
	if (unlikely(rv != 0)) {
		pr_err("copy_from_user could not copy %i bytes\n", rv);
		return -EFAULT;
	}

	rv = fm_macsec_secy_create_tx_sa(selected_macsec_priv->fm_ms_secy,
					c_tx_sa->an,
					sa_key);
	if (unlikely(rv < 0))
		pr_err("error when creating tx sa\n");

	return rv;
}

static int modify_tx_sa_key(struct generic_msg *gen)
{
	struct modify_tx_sa_key *tx_sa_key;
	struct macsec_priv_s *selected_macsec_priv;
	macsec_sa_key_t sa_key;
	int rv;

	tx_sa_key = &(gen->payload.modify_tx_sa_key);

	if (tx_sa_key->macsec_id < 0 ||
			tx_sa_key->macsec_id >= FM_MAX_NUM_OF_MACS)
		return -EINVAL;
	selected_macsec_priv = macsec_priv[tx_sa_key->macsec_id];

	/* set macsec_priv field */
	selected_macsec_priv->an = tx_sa_key->an;

	if (unlikely(tx_sa_key->sak_len > 32)) {
		pr_warn("size of secure key is greater than 32 bytes!\n");
		kfree(tx_sa_key);
		return -EINVAL;
	}

	rv = copy_from_user(&sa_key,
			tx_sa_key->sak,
			tx_sa_key->sak_len);
	if (unlikely(rv != 0)) {
		pr_err("copy_from_user could not copy %i bytes\n", rv);
		return -EFAULT;
	}

	rv = fm_macsec_secy_txsa_modify_key(selected_macsec_priv->fm_ms_secy,
					tx_sa_key->an,
					sa_key);
	if (unlikely(rv < 0))
		pr_err("error while modifying the tx sa key\n");

	return rv;
}

static int activate_tx_sa(struct generic_msg *gen)
{
	struct activate_tx_sa *a_tx_sa;
	struct macsec_priv_s *selected_macsec_priv;
	int rv;

	a_tx_sa = &(gen->payload.a_tx_sa);

	if (a_tx_sa->macsec_id < 0 ||
			a_tx_sa->macsec_id >= FM_MAX_NUM_OF_MACS) {
		kfree(a_tx_sa);
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[a_tx_sa->macsec_id];

	rv = fm_macsec_secy_txsa_set_active(selected_macsec_priv->fm_ms_secy,
					a_tx_sa->an);
	if (unlikely(rv < 0))
		pr_err("error when creating tx sa\n");

	return rv;
}

static int get_tx_sa_an(struct generic_msg *gen, macsec_an_t *an)
{
	struct macsec_priv_s *selected_macsec_priv;

	if (gen->payload.macsec_id < 0 ||
			gen->payload.macsec_id >= FM_MAX_NUM_OF_MACS)
		return -EINVAL;

	selected_macsec_priv = macsec_priv[gen->payload.macsec_id];

	fm_macsec_secy_txsa_get_active(selected_macsec_priv->fm_ms_secy, an);

	return 0;
}

static int create_rx_sc(struct generic_msg *gen)
{
	struct fm_macsec_secy_sc_params params;
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *rx_sc_dev;
	uint32_t sc_phys_id;
	int i;

	if (gen->payload.c_rx_sc.macsec_id < 0 ||
			gen->payload.c_rx_sc.macsec_id >= FM_MAX_NUM_OF_MACS)
		return -EINVAL;
	selected_macsec_priv = macsec_priv[gen->payload.c_rx_sc.macsec_id];

	for (i = 0; i < NUM_OF_RX_SC; i++)
		if (!selected_macsec_priv->rx_sc_dev[i])
			break;
	if (i == NUM_OF_RX_SC) {
		pr_err("number of maximum RX_SC's has been reached\n");
		return -EINVAL;
	}

	params.sci = gen->payload.c_rx_sc.sci;
	params.cipher_suite = SECY_GCM_AES_128;
#if (DPAA_VERSION >= 11)
	params.cipher_suite = SECY_GCM_AES_256;
#endif /* (DPAA_VERSION >= 11) */

	rx_sc_dev = fm_macsec_secy_create_rxsc(selected_macsec_priv->fm_ms_secy,
					&params);

	fm_macsec_secy_get_rxsc_phys_id(selected_macsec_priv->fm_ms_secy,
					rx_sc_dev,
					&sc_phys_id);

	selected_macsec_priv->rx_sc_dev[sc_phys_id] = rx_sc_dev;

	return sc_phys_id;
}

static int create_rx_sa(struct generic_msg *gen)
{
	struct create_rx_sa *c_rx_sa;
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *selected_rx_sc_dev;
	macsec_sa_key_t sak;
	int rv;

	c_rx_sa = &(gen->payload.c_rx_sa);

	if (unlikely(c_rx_sa->sak_len > 32)) {
		pr_warn("size of secure key is greater than 32 bytes!\n");
		return -EINVAL;
	}
	rv = copy_from_user(&sak,
			c_rx_sa->sak,
			c_rx_sa->sak_len);
	if (unlikely(rv != 0)) {
		pr_err("copy_from_user could not copy %i bytes\n", rv);
		return -EFAULT;
	}

	if (c_rx_sa->macsec_id < 0 ||
			c_rx_sa->macsec_id >= FM_MAX_NUM_OF_MACS)
		return -EINVAL;

	selected_macsec_priv = macsec_priv[c_rx_sa->macsec_id];

	if (c_rx_sa->rx_sc_id < 0 || c_rx_sa->rx_sc_id >= NUM_OF_RX_SC)
		return -EINVAL;

	selected_rx_sc_dev = selected_macsec_priv->rx_sc_dev[c_rx_sa->rx_sc_id];

	rv = fm_macsec_secy_create_rx_sa(selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev,
					c_rx_sa->an,
					c_rx_sa->lpn,
					sak);
	if (unlikely(rv < 0)) {
		pr_err("fm_macsec_secy_create_rx_sa failed\n");
		return -EBUSY;
	}

	return 0;
}

static int modify_rx_sa_key(struct generic_msg *gen)
{
	struct modify_rx_sa_key *rx_sa_key;
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *selected_rx_sc;
	macsec_sa_key_t sa_key;
	int rv;

	rx_sa_key = &(gen->payload.modify_rx_sa_key);

	if (rx_sa_key->macsec_id < 0 ||
			rx_sa_key->macsec_id >= FM_MAX_NUM_OF_MACS)
		return -EINVAL;
	selected_macsec_priv = macsec_priv[rx_sa_key->macsec_id];

	if (rx_sa_key->rx_sc_id < 0 || rx_sa_key->rx_sc_id >= NUM_OF_RX_SC)
		return -EINVAL;
	selected_rx_sc = selected_macsec_priv->rx_sc_dev[rx_sa_key->rx_sc_id];

	/* set macsec_priv field */
	selected_macsec_priv->an = rx_sa_key->an;

	if (unlikely(rx_sa_key->sak_len > 32)) {
		pr_warn("size of secure key is greater than 32 bytes!\n");
		kfree(rx_sa_key);
		return -EINVAL;
	}

	rv = copy_from_user(&sa_key,
			rx_sa_key->sak,
			rx_sa_key->sak_len);
	if (unlikely(rv != 0)) {
		pr_err("copy_from_user could not copy %i bytes\n", rv);
		return -EFAULT;
	}

	rv = fm_macsec_secy_rxsa_modify_key(selected_macsec_priv->fm_ms_secy,
					selected_rx_sc,
					rx_sa_key->an,
					sa_key);
	if (unlikely(rv < 0))
		pr_err("error while modifying the rx sa key\n");

	return rv;
}

static int update_npn(struct generic_msg *gen)
{
	struct update_npn *update_npn;
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *selected_rx_sc_dev;
	int err;

	update_npn = &(gen->payload.update_npn);

	if (update_npn->macsec_id < 0 ||
			update_npn->macsec_id >= FM_MAX_NUM_OF_MACS)
		return -EINVAL;
	selected_macsec_priv = macsec_priv[update_npn->macsec_id];

	if (update_npn->rx_sc_id < 0 || update_npn->rx_sc_id >= NUM_OF_RX_SC)
		return -EINVAL;

	selected_rx_sc_dev =
			selected_macsec_priv->rx_sc_dev[update_npn->rx_sc_id];

	err = fm_macsec_secy_rxsa_update_next_pn(
					selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev,
					update_npn->an,
					update_npn->pn);
	if (unlikely(err < 0)) {
		pr_err("fm_macsec_secy_rxsa_update_next_pn failed\n");
		return -EBUSY;
	}

	return 0;
}

static int update_lpn(struct generic_msg *gen)
{
	struct update_lpn *update_lpn;
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *selected_rx_sc_dev;
	int err;

	update_lpn = &(gen->payload.update_lpn);

	if (update_lpn->macsec_id < 0 ||
			update_lpn->macsec_id >= FM_MAX_NUM_OF_MACS)
		return -EINVAL;
	selected_macsec_priv = macsec_priv[update_lpn->macsec_id];

	if (update_lpn->rx_sc_id < 0 || update_lpn->rx_sc_id >= NUM_OF_RX_SC)
		return -EINVAL;
	selected_rx_sc_dev =
			selected_macsec_priv->rx_sc_dev[update_lpn->rx_sc_id];

	err = fm_macsec_secy_rxsa_update_lowest_pn(
					selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev,
					update_lpn->an,
					update_lpn->pn);
	if (unlikely(err < 0)) {
		pr_err("fm_macsec_secy_rxsa_update_lowest_pn failed\n");
		return -EBUSY;
	}

	return 0;
}

static int activate_rx_sa(struct generic_msg *gen)
{
	struct activate_rx_sa *a_rx_sa;
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *selected_rx_sc_dev;
	int err;

	a_rx_sa = &(gen->payload.a_rx_sa);

	if (a_rx_sa->macsec_id < 0 ||
			a_rx_sa->macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[a_rx_sa->macsec_id];

	if (a_rx_sa->rx_sc_id < 0 || a_rx_sa->rx_sc_id >= NUM_OF_RX_SC)
		return -EINVAL;
	selected_rx_sc_dev = selected_macsec_priv->rx_sc_dev[a_rx_sa->rx_sc_id];

	err = fm_macsec_secy_rxsa_enable_receive(
					selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev,
					a_rx_sa->an);
	if (unlikely(err < 0)) {
		pr_err("fm_macsec_secy_rxsa_enable_receive failed\n");
		return -EBUSY;
	}

	return 0;
}

static int get_tx_sc_phys_id(struct generic_msg *gen, uint32_t *sc_id)
{
	struct macsec_priv_s *selected_macsec_priv;
	int err;

	if (gen->payload.macsec_id < 0 ||
		gen->payload.macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[gen->payload.macsec_id];

	err = fm_macsec_secy_get_txsc_phys_id(selected_macsec_priv->fm_ms_secy,
			sc_id);

	if (unlikely(err < 0)) {
		pr_err("fm_macsec_secy_get_txsc_phys_id failed\n");
		return err;
	}

	return 0;
}

static int get_rx_sc_phys_id(struct generic_msg *gen, uint32_t *sc_id)
{
	struct get_rx_sc_id *get_rx_sc_id;
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *selected_rx_sc_dev;
	int err;

	get_rx_sc_id = &(gen->payload.get_rx_sc_id);

	if (get_rx_sc_id->macsec_id < 0 ||
			get_rx_sc_id->macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[get_rx_sc_id->macsec_id];

	if (get_rx_sc_id->rx_sc_id < 0 ||
			get_rx_sc_id->rx_sc_id >= NUM_OF_RX_SC)
		return -EINVAL;
	selected_rx_sc_dev =
			selected_macsec_priv->rx_sc_dev[get_rx_sc_id->rx_sc_id];

	err = fm_macsec_secy_get_rxsc_phys_id(selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev,
					sc_id);
	if (unlikely(err < 0)) {
		pr_err("fm_macsec_secy_get_rxsc_phys_id failed\n");
		return err;
	}

	return 0;
}

static int get_macsec_revision(struct generic_msg *gen, int *macsec_revision)
{
	struct macsec_priv_s *selected_macsec_priv;
	int err;

	if (gen->payload.macsec_id < 0 ||
		gen->payload.macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[gen->payload.macsec_id];

	err = fm_macsec_get_revision(selected_macsec_priv->fm_macsec,
					macsec_revision);
	if (unlikely(err < 0)) {
		pr_err("fm_macsec_get_revision failed\n");
		return err;
	}

	return 0;
}

static int rx_sa_disable(struct generic_msg *gen)
{
	struct disable_rx_sa *disable_rx_sa;
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *selected_rx_sc_dev;
	int err;

	disable_rx_sa = &(gen->payload.d_rx_sa);

	if (disable_rx_sa->macsec_id < 0 ||
			disable_rx_sa->macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[disable_rx_sa->macsec_id];

	if (disable_rx_sa->rx_sc_id < 0 ||
			disable_rx_sa->rx_sc_id >= NUM_OF_RX_SC)
		return -EINVAL;
	selected_rx_sc_dev =
		selected_macsec_priv->rx_sc_dev[disable_rx_sa->rx_sc_id];

	err = fm_macsec_secy_rxsa_disable_receive(
					selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev,
					selected_macsec_priv->an);

	if (unlikely(err < 0)) {
		pr_err("fm_macsec_secy_rxsa_disable_receive failed\n");
		return err;
	}

	return 0;
}

static int rx_sa_delete(struct generic_msg *gen)
{
	struct delete_rx_sa *delete_rx_sa;
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *selected_rx_sc_dev;
	int err;

	delete_rx_sa = &(gen->payload.del_rx_sa);

	if (delete_rx_sa->macsec_id < 0 ||
			delete_rx_sa->macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[delete_rx_sa->macsec_id];

	if (delete_rx_sa->rx_sc_id < 0 ||
			delete_rx_sa->rx_sc_id >= NUM_OF_RX_SC)
		return -EINVAL;
	selected_rx_sc_dev =
			selected_macsec_priv->rx_sc_dev[delete_rx_sa->rx_sc_id];

	err = fm_macsec_secy_delete_rx_sa(selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev,
					selected_macsec_priv->an);

	if (unlikely(err < 0)) {
		pr_err("fm_macsec_secy_delete_rx_sa failed\n");
		return err;
	}

	return 0;
}

static int rx_sc_delete(struct generic_msg *gen)
{
	struct delete_rx_sc *delete_rx_sc;
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *selected_rx_sc_dev;
	int err;

	delete_rx_sc = &(gen->payload.del_rx_sc);

	if (delete_rx_sc->macsec_id < 0 ||
			delete_rx_sc->macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[delete_rx_sc->macsec_id];

	if (delete_rx_sc->rx_sc_id < 0 ||
			delete_rx_sc->rx_sc_id >= NUM_OF_RX_SC)
		return -EINVAL;
	selected_rx_sc_dev =
			selected_macsec_priv->rx_sc_dev[delete_rx_sc->rx_sc_id];

	err = fm_macsec_secy_delete_rxsc(selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev);

	if (unlikely(err < 0)) {
		pr_err("fm_macsec_secy_delete_rxsc failed\n");
		return err;
	}

	return 0;
}

static int tx_sa_delete(struct generic_msg *gen)
{
	struct macsec_priv_s *selected_macsec_priv;
	int err;

	if (gen->payload.del_tx_sa.macsec_id < 0 ||
		gen->payload.del_tx_sa.macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[gen->payload.del_tx_sa.macsec_id];

	err = fm_macsec_secy_delete_tx_sa(selected_macsec_priv->fm_ms_secy,
					selected_macsec_priv->an);

	if (unlikely(err < 0)) {
		pr_err("fm_macsec_secy_delete_tx_sa failed\n");
		return err;
	}

	return 0;
}

static int disable_secy(struct generic_msg *gen, int *macsec_id)
{
	struct macsec_priv_s *selected_macsec_priv;
	int err;

	if (gen->payload.macsec_id < 0 ||
		gen->payload.macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}
	selected_macsec_priv = macsec_priv[gen->payload.macsec_id];
	*macsec_id = gen->payload.macsec_id;

	err = fm_macsec_secy_free(selected_macsec_priv->fm_ms_secy);
	selected_macsec_priv->fm_ms_secy = NULL;

	if (unlikely(err < 0)) {
		pr_err("fm_macsec_secy_free failed\n");
		return err;
	}

	return 0;
}

static int disable_macsec(struct generic_msg *gen, int *macsec_id)
{
	struct macsec_priv_s *selected_macsec_priv;
	int err;

	if (gen->payload.macsec_id < 0 ||
		gen->payload.macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}

	selected_macsec_priv =
			macsec_priv[gen->payload.macsec_id];
	*macsec_id = gen->payload.macsec_id;

	err = fm_macsec_disable(selected_macsec_priv->fm_macsec);
	err += fm_macsec_free(selected_macsec_priv->fm_macsec);
	selected_macsec_priv->fm_macsec = NULL;

	if (unlikely(err < 0)) {
		pr_err("macsec disable failed\n");
		return err;
	}

	return 0;

}

static int disable_all(struct generic_msg *gen, int *macsec_id)
{
	struct macsec_priv_s *selected_macsec_priv;
	struct rx_sc_dev *selected_rx_sc_dev;
	int err = 0, i;

	if (gen->payload.macsec_id < 0 ||
			gen->payload.macsec_id >= FM_MAX_NUM_OF_MACS) {
		return -EINVAL;
	}

	selected_macsec_priv = macsec_priv[gen->payload.macsec_id];
	*macsec_id = gen->payload.macsec_id;

	for (i = 0; i < NUM_OF_RX_SC; i++) {
		selected_rx_sc_dev = selected_macsec_priv->rx_sc_dev[i];

		if (!selected_rx_sc_dev)
			continue;

		err += fm_macsec_secy_rxsa_disable_receive(
					selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev,
					selected_macsec_priv->an);

		err += fm_macsec_secy_delete_rx_sa(
					selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev,
					selected_macsec_priv->an);

		err += fm_macsec_secy_delete_rxsc(
					selected_macsec_priv->fm_ms_secy,
					selected_rx_sc_dev);
	}

	err += fm_macsec_secy_delete_tx_sa(
				selected_macsec_priv->fm_ms_secy,
				selected_macsec_priv->an);

	err += fm_macsec_secy_free(selected_macsec_priv->fm_ms_secy);
	selected_macsec_priv->fm_ms_secy = NULL;

	err += fm_macsec_disable(selected_macsec_priv->fm_macsec);

	err += fm_macsec_free(selected_macsec_priv->fm_macsec);
	selected_macsec_priv->fm_macsec = NULL;

	if (unlikely(err < 0)) {
		pr_err("macsec disable failed\n");
		return err;
	}

	return 0;
}

static inline void macsec_setup_ingress(struct macsec_priv_s *macsec_priv,
	struct dpa_fq *fq,
	const struct qman_fq *template)
{
	fq->fq_base = *template;
	fq->net_dev = macsec_priv->net_dev;

	fq->flags = QMAN_FQ_FLAG_NO_ENQUEUE;
	fq->channel = macsec_priv->channel;
}

static inline void macsec_setup_egress(struct macsec_priv_s *macsec_priv,
	struct dpa_fq *fq,
	struct fm_port *port,
	const struct qman_fq *template)
{
	fq->fq_base = *template;
	fq->net_dev = macsec_priv->net_dev;

	if (port) {
		fq->flags = QMAN_FQ_FLAG_TO_DCPORTAL;
		fq->channel = (uint16_t)fm_get_tx_port_channel(port);
	} else {
		fq->flags = QMAN_FQ_FLAG_NO_MODIFY;
	}
}

/* At the moment, we don't create recycle queues. */
static void macsec_fq_setup(struct macsec_priv_s *macsec_priv,
		     const struct dpa_fq_cbs_t *fq_cbs,
		     struct fm_port *tx_port)
{
	struct dpa_fq *fq;
	int egress_cnt = 0, conf_cnt = 0;

	/* Initialize each FQ in the list */
	list_for_each_entry(fq, &macsec_priv->dpa_fq_list, list) {
		switch (fq->fq_type) {
		/* Normal TX queues */
		case FQ_TYPE_TX:
			macsec_setup_egress(macsec_priv, fq, tx_port,
				&fq_cbs->egress_ern);
			/* If we have more Tx queues than the number of cores,
			 * just ignore the extra ones.
			 */
			if (egress_cnt < MACSEC_ETH_TX_QUEUES)
				macsec_priv->egress_fqs[egress_cnt++] =
					&fq->fq_base;
			break;
		case FQ_TYPE_TX_CONFIRM:
			BUG_ON(!macsec_priv->mac_dev);
			macsec_setup_ingress(macsec_priv, fq, &fq_cbs->tx_defq);
			break;
		/* TX confirm multiple queues */
		case FQ_TYPE_TX_CONF_MQ:
			BUG_ON(!macsec_priv->mac_dev);
			macsec_setup_ingress(macsec_priv, fq, &fq_cbs->tx_defq);
			macsec_priv->conf_fqs[conf_cnt++] = &fq->fq_base;
			break;
		case FQ_TYPE_TX_ERROR:
			BUG_ON(!macsec_priv->mac_dev);
			macsec_setup_ingress(macsec_priv, fq, &fq_cbs->tx_errq);
			break;
		default:
			dev_warn(macsec_priv->net_dev->dev.parent,
				"Unknown FQ type detected!\n");
			break;
		}
	}

	/* The number of Tx queues may be smaller than the number of cores, if
	* the Tx queue range is specified in the device tree instead of being
	* dynamically allocated.
	* Make sure all CPUs receive a corresponding Tx queue.
	*/
	while (egress_cnt < MACSEC_ETH_TX_QUEUES) {
		list_for_each_entry(fq, &macsec_priv->dpa_fq_list, list) {
			if (fq->fq_type != FQ_TYPE_TX)
				continue;
			macsec_priv->egress_fqs[egress_cnt++] = &fq->fq_base;
			if (egress_cnt == MACSEC_ETH_TX_QUEUES)
				break;
		}
	}

}

static const struct fqid_cell tx_fqids[] = {
	{0, MACSEC_ETH_TX_QUEUES}
};

static const struct fqid_cell tx_confirm_fqids[] = {
	{0, MACSEC_ETH_TX_QUEUES}
};

/* Allocate percpu priv. This is used to keep track of rx and tx packets on
 * each cpu (take into consideration that the number of queues is equal to the
 * number of cpus, so there is one queue/cpu).
 */
static void alloc_priv(struct macsec_percpu_priv_s *percpu_priv,
		struct macsec_priv_s *macsec_priv, struct device *dev)
{
	int i, err;

	macsec_priv->percpu_priv = alloc_percpu(*macsec_priv->percpu_priv);

	if (unlikely(macsec_priv->percpu_priv == NULL)) {
		dev_err(dev, "alloc_percpu() failed\n");
		err = -ENOMEM;
		dpa_fq_free(dev, &macsec_priv->dpa_fq_list);
	}

	for_each_possible_cpu(i) {
		percpu_priv = per_cpu_ptr(macsec_priv->percpu_priv, i);
		memset(percpu_priv, 0, sizeof(*percpu_priv));
	}

}

/* On RX, we only need to retain the information about frames, if they were
 * encrypted or not. Statistics regarding this will be printed in a log file.
 */
static int macsec_rx_hook(void *ptr, struct net_device *net_dev, u32 fqid)
{

	struct qm_fd *rx_fd  = (struct qm_fd *)ptr;
	struct macsec_percpu_priv_s *percpu_priv_m;
	struct macsec_priv_s *selected_macsec_priv;

	selected_macsec_priv = macsec_priv[net_dev->ifindex - 1];

	percpu_priv_m = raw_cpu_ptr(selected_macsec_priv->percpu_priv);

	if ((rx_fd->status & FM_FD_STAT_RX_MACSEC) != 0) {
		if (netif_msg_hw(selected_macsec_priv) && net_ratelimit())
			netdev_warn(net_dev, "FD status = 0x%u\n",
			    rx_fd->status & FM_FD_STAT_RX_MACSEC);
		percpu_priv_m->rx_macsec++;
	}

	return DPAA_ETH_CONTINUE;
}

/* Split TX traffic. If encryption enabled, send packets on specific QMAN frame
 * queues. Other way, let them be handled by dpa eth. Also, keep track of the
 * number of packets that are walking away through "macsec" queues.
 */
static enum dpaa_eth_hook_result macsec_tx_hook(struct sk_buff *skb,
						struct net_device *net_dev)
{
	struct dpa_priv_s *dpa_priv;
	struct qm_fd fd;
	struct macsec_percpu_priv_s *macsec_percpu_priv;
	struct dpa_percpu_priv_s *dpa_percpu_priv;
	int i, err = 0;
	int *countptr, offset = 0;
	const bool nonlinear = skb_is_nonlinear(skb);
	struct qman_fq *egress_fq;
	struct macsec_priv_s *selected_macsec_priv;

	selected_macsec_priv = macsec_priv[net_dev->ifindex - 1];

	if (!selected_macsec_priv->net_dev ||
		(selected_macsec_priv->en_state != SECY_ENABLED) ||
		(ntohs(skb->protocol) == ETH_P_PAE))
		return DPAA_ETH_CONTINUE;

	dpa_priv = netdev_priv(net_dev);
	/* Non-migratable context, safe to use raw_cpu_ptr */
	macsec_percpu_priv = raw_cpu_ptr(selected_macsec_priv->percpu_priv);
	dpa_percpu_priv = raw_cpu_ptr(dpa_priv->percpu_priv);

	countptr = raw_cpu_ptr(dpa_priv->dpa_bp->percpu_count);

	clear_fd(&fd);

#ifdef CONFIG_FSL_DPAA_1588
	if (dpa_priv->tsu && dpa_priv->tsu->valid &&
			dpa_priv->tsu->hwts_tx_en_ioctl)
		fd.cmd |= FM_FD_CMD_UPD;
#endif
#ifdef CONFIG_FSL_DPAA_TS
	if (unlikely(dpa_priv->ts_tx_en &&
			skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))
		fd.cmd |= FM_FD_CMD_UPD;
	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
#endif /* CONFIG_FSL_DPAA_TS */

	/* MAX_SKB_FRAGS is larger than our DPA_SGT_MAX_ENTRIES; make sure
	 * we don't feed FMan with more fragments than it supports.
	 * Btw, we're using the first sgt entry to store the linear part of
	 * the skb, so we're one extra frag short.
	 */
	if (nonlinear &&
		likely(skb_shinfo(skb)->nr_frags < DPA_SGT_MAX_ENTRIES)) {
		/* Just create a S/G fd based on the skb */
		err = skb_to_sg_fd(dpa_priv, skb, &fd);
		dpa_percpu_priv->tx_frag_skbuffs++;
	} else {
		/* Make sure we have enough headroom to accommodate private
		 * data, parse results, etc. Normally this shouldn't happen if
		 * we're here via the standard kernel stack.
		 */
		if (unlikely(skb_headroom(skb) < dpa_priv->tx_headroom)) {
			struct sk_buff *skb_new;

			skb_new = skb_realloc_headroom(skb,
						dpa_priv->tx_headroom);
			if (unlikely(!skb_new)) {
				dev_kfree_skb(skb);
				dpa_percpu_priv->stats.tx_errors++;
				return DPAA_ETH_STOLEN;
			}
			dev_kfree_skb(skb);
			skb = skb_new;
		}

		/* We're going to store the skb backpointer at the beginning
		 * of the data buffer, so we need a privately owned skb
		 */

		/* Code borrowed from skb_unshare(). */
		if (skb_cloned(skb)) {
			struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
			kfree_skb(skb);
			skb = nskb;
			/* skb_copy() has now linearized the skbuff. */
		} else if (unlikely(nonlinear)) {
			/* We are here because the egress skb contains
			 * more fragments than we support. In this case,
			 * we have no choice but to linearize it ourselves.
			 */
			err = __skb_linearize(skb);
		}
		if (unlikely(!skb || err < 0)) {
			/* Common out-of-memory error path */
			goto enomem;
		}

		/* Finally, create a contig FD from this skb */
		err = skb_to_contig_fd(dpa_priv, skb, &fd, countptr, &offset);
	}
	if (unlikely(err < 0))
		goto skb_to_fd_failed;

	if (fd.bpid != 0xff) {
		skb_recycle(skb);
		/* skb_recycle() reserves NET_SKB_PAD as skb headroom,
		 * but we need the skb to look as if returned by build_skb().
		 * We need to manually adjust the tailptr as well.
		 */
		skb->data = skb->head + offset;
		skb_reset_tail_pointer(skb);

		(*countptr)++;
		dpa_percpu_priv->tx_returned++;
	}

	egress_fq = selected_macsec_priv->egress_fqs[smp_processor_id()];
	if (fd.bpid == 0xff)
		fd.cmd |= qman_fq_fqid(macsec_get_tx_conf_queue(
							selected_macsec_priv,
							egress_fq));

	for (i = 0; i < 100000; i++) {
		err = qman_enqueue(egress_fq, &fd, 0);
		if (err != -EBUSY)
			break;
	}

	if (unlikely(err < 0)) {
		dpa_percpu_priv->stats.tx_errors++;
		dpa_percpu_priv->stats.tx_fifo_errors++;
		goto xmit_failed;
	}

	macsec_percpu_priv->tx_macsec++;
	dpa_percpu_priv->stats.tx_packets++;
	dpa_percpu_priv->stats.tx_bytes += dpa_fd_length(&fd);

	net_dev->trans_start = jiffies;
	return DPAA_ETH_STOLEN;

xmit_failed:
	if (fd.bpid != 0xff) {
		(*countptr)--;
		dpa_percpu_priv->tx_returned--;
		dpa_fd_release(net_dev, &fd);
		dpa_percpu_priv->stats.tx_errors++;
		return DPAA_ETH_STOLEN;
	}
	_dpa_cleanup_tx_fd(dpa_priv, &fd);
skb_to_fd_failed:
enomem:
	dpa_percpu_priv->stats.tx_errors++;
	dev_kfree_skb(skb);
	return DPAA_ETH_STOLEN;
}

/* Allocate and initialize macsec priv and fqs. Also, create debugfs entry for
 * a spcific interface. Iterate thourgh existing devices in order to find the
 * one we want to have macsec for.
 */
static int macsec_setup(void)
{
	struct net_device *net_dev;
	struct macsec_percpu_priv_s *percpu_priv = NULL;
	struct dpa_priv_s *dpa_priv = NULL;
	struct dpa_fq *dpa_fq;
	struct device *dev = NULL;
	int err, i, j, macsec_id;

	pr_debug("Entering: %s\n", __func__);

	for (i = 0; i < FM_MAX_NUM_OF_MACS; i++) {
		macsec_priv[i] = kzalloc(sizeof(*(macsec_priv[i])), GFP_KERNEL);

		if (unlikely(macsec_priv[i] == NULL)) {
			int j;
			for (j = 0; j < i; j++)
				kfree(macsec_priv[j]);
			pr_err("could not allocate\n");
			return -ENOMEM;
		}
	}

	for (i = 0; i < macsec_ifs_cnt; i++) {
		net_dev = first_net_device(&init_net);
		macsec_id = net_dev->ifindex - 1;
		while (net_dev) {
			macsec_id = net_dev->ifindex - 1;

			/* to maintain code readability and less than
			 * 80 characters per line
			 */
			if (strcmp(net_dev->name, macsec_ifs[i]) != 0) {
				net_dev = next_net_device(net_dev);
				continue;
			}

			/* strcmp(net_dev->name, macsec_ifs[i]) == 0 */
			macsec_priv[macsec_id]->en_state = MACSEC_DISABLED;
			macsec_priv[macsec_id]->net_dev = net_dev;
			dpa_priv = netdev_priv(net_dev);
			macsec_priv[macsec_id]->mac_dev = dpa_priv->mac_dev;
			macsec_priv[macsec_id]->channel = dpa_priv->channel;
			dev = net_dev->dev.parent;

			INIT_LIST_HEAD(&macsec_priv[macsec_id]->dpa_fq_list);

			dpa_fq = dpa_fq_alloc(dev,
					      tx_fqids->start, tx_fqids->count,
					      &macsec_priv[macsec_id]->dpa_fq_list,
					      FQ_TYPE_TX);
			if (unlikely(dpa_fq == NULL)) {
				dev_err(dev, "dpa_fq_alloc() failed\n");
				return -ENOMEM;
			}

			dpa_fq = dpa_fq_alloc(dev,
					      tx_confirm_fqids->start,
					      tx_confirm_fqids->count,
					      &macsec_priv[macsec_id]->dpa_fq_list,
					      FQ_TYPE_TX_CONF_MQ);
			if (unlikely(dpa_fq == NULL)) {
				dev_err(dev, "dpa_fq_alloc() failed\n");
				return -ENOMEM;
			}

			macsec_fq_setup(macsec_priv[macsec_id], &private_fq_cbs,
				macsec_priv[macsec_id]->mac_dev->port_dev[TX]);

			alloc_priv(percpu_priv, macsec_priv[macsec_id], dev);

			break;
		}
		if (macsec_priv[macsec_id]->net_dev == NULL) {
			pr_err("Interface unknown\n");
			err = -EINVAL;
			goto _error;
		}

		/* setup specific ethtool ops for macsec */
		macsec_setup_ethtool_ops(net_dev);
	}
	return 0;

_error:
	for (j = 0; j < i; i++) {
		net_dev = first_net_device(&init_net);
		while (net_dev) {
			macsec_id = net_dev->ifindex - 1;
			if (strcmp(net_dev->name, macsec_ifs[j]) != 0) {
				net_dev = next_net_device(net_dev);
				continue;
			}
			dpa_fq_free(net_dev->dev.parent,
				&macsec_priv[macsec_id]->dpa_fq_list);
			break;
		}
		macsec_restore_ethtool_ops(macsec_priv[j]->net_dev);
		kfree(macsec_priv[j]);
	}
	for (j = i; j < FM_MAX_NUM_OF_MACS; j++)
		kfree(macsec_priv[j]);
	return err;
}

static int enable_macsec(struct generic_msg *gen)
{
	struct fm_macsec_params macsec_params;
	int rv, macsec_id;
	void __iomem *mac_dev_base_addr;
	uintptr_t macsec_reg_addr;
	struct macsec_data *mdata;
	char if_name[IFNAMSIZ];
	struct macsec_priv_s *selected_macsec_priv;

	mdata = &gen->payload.en_macsec;

	if (unlikely(mdata->if_name_length > IFNAMSIZ)) {
		pr_err("interface name too long\n");
		return -EINVAL;
	}

	rv = copy_from_user(if_name, mdata->if_name, mdata->if_name_length);
	if (unlikely(rv != 0)) {
		pr_err("copy_from_user could not copy %i bytes\n", rv);
		return -EFAULT;
	}

	macsec_id = ifname_to_id(if_name);
	if (macsec_id < 0 || macsec_id >= FM_MAX_NUM_OF_MACS) {
		pr_err("error on converting to macsec_id\n");
		return -ENXIO;
	}

	selected_macsec_priv = macsec_priv[macsec_id];

	if (selected_macsec_priv->fm_macsec) {
		pr_err("macsec has already been configured\n");
		return -EINVAL;
	}

	mac_dev_base_addr = selected_macsec_priv->mac_dev->vaddr;

	macsec_reg_addr = (uintptr_t)(mac_dev_base_addr + MACSEC_REG_OFFSET);

	memset(&macsec_params, 0, sizeof(macsec_params));
	macsec_params.fm_h = (handle_t)selected_macsec_priv->mac_dev->fm;
	macsec_params.guest_mode = FALSE;
	/* The MACsec offset relative to the memory mapped MAC device */
	macsec_params.non_guest_params.base_addr = macsec_reg_addr;
	macsec_params.non_guest_params.fm_mac_h =
		(handle_t)selected_macsec_priv->mac_dev->get_mac_handle(
						selected_macsec_priv->mac_dev);
	macsec_params.non_guest_params.exception_f = macsec_exception;
	macsec_params.non_guest_params.app_h = selected_macsec_priv->mac_dev;

	selected_macsec_priv->fm_macsec = fm_macsec_config(&macsec_params);
	if (unlikely(selected_macsec_priv->fm_macsec == NULL))
		return -EINVAL;

	if (mdata->config_unknown_sci_treatment) {
		rv = fm_macsec_config_unknown_sci_frame_treatment(
				selected_macsec_priv->fm_macsec,
				mdata->unknown_sci_treatment);
		if (unlikely(rv < 0))
			goto _return_fm_macsec_free;
	}

	if (mdata->config_invalid_tag_treatment) {
		rv = fm_macsec_config_invalid_tags_frame_treatment(
				selected_macsec_priv->fm_macsec,
				mdata->deliver_uncontrolled);
		if (unlikely(rv < 0))
			goto _return_fm_macsec_free;
	}

	if (mdata->config_kay_frame_treatment) {
		rv = fm_macsec_config_kay_frame_treatment(
				selected_macsec_priv->fm_macsec,
				mdata->discard_uncontrolled);
		if (unlikely(rv < 0))
			goto _return_fm_macsec_free;
	}

	if (mdata->config_untag_treatment) {
		rv = fm_macsec_config_untag_frame_treatment(
				selected_macsec_priv->fm_macsec,
				mdata->untag_treatment);
		if (unlikely(rv < 0))
			goto _return_fm_macsec_free;
	}

	if (mdata->config_pn_exhaustion_threshold) {
		rv = fm_macsec_config_pn_exhaustion_threshold(
				selected_macsec_priv->fm_macsec,
				mdata->pn_threshold);
		if (unlikely(rv < 0))
			goto _return_fm_macsec_free;
	}

	if (mdata->config_keys_unreadable) {
		rv = fm_macsec_config_keys_unreadable(
					selected_macsec_priv->fm_macsec);
		if (unlikely(rv < 0))
			goto _return_fm_macsec_free;
	}

	if (mdata->config_sectag_without_sci) {
		rv = fm_macsec_config_sectag_without_sci(
				selected_macsec_priv->fm_macsec);
		if (unlikely(rv < 0))
			goto _return_fm_macsec_free;
	}

	if (mdata->config_exception) {
		rv = fm_macsec_config_exception(selected_macsec_priv->fm_macsec,
						mdata->exception,
						mdata->enable_exception);
		if (unlikely(rv < 0))
			goto _return_fm_macsec_free;
	}

	rv = fm_macsec_init(selected_macsec_priv->fm_macsec);
	if (unlikely(rv < 0))
		goto _return_fm_macsec_free;

	rv = fm_macsec_enable(selected_macsec_priv->fm_macsec);
	if (unlikely(rv < 0))
		goto _return_fm_macsec_free;

	return macsec_id;

_return_fm_macsec_free:
	fm_macsec_free(selected_macsec_priv->fm_macsec);
	selected_macsec_priv->fm_macsec = NULL;
	return rv;
}

static int send_result(struct nlmsghdr *nlh, int pid, int result)
{
	int res;
	struct sk_buff *skb_out;
	size_t msg_size = sizeof(result);

	skb_out = nlmsg_new(msg_size, 0);
	if (unlikely(!skb_out)) {
		pr_err("Failed to allocate new skb\n");
		goto _ret_err;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	if (unlikely(!nlh)) {
		pr_err("Failed to send\n");
		goto _ret_err;
	}

	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	memcpy(nlmsg_data(nlh), &result, msg_size);

	res = nlmsg_unicast(nl_sk, skb_out, pid);
	if (unlikely(res < 0)) {
		pr_err("Error while sending back to user\n");
		goto _ret_err;
	}

	return 0;

_ret_err:
	return -1;
}

/* Kernel communicates with user space through netlink sockets. This function
 * implements the responses of the kernel. The generic struct is used for
 * easier handling of the code, which otherwise would have been duplicated.
 */
static void switch_messages(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int pid, rv;
	enum msg_type cmd;

	struct dpa_fq *dpa_fq, *tmp;
	struct device *dev;

	struct dpaa_eth_hooks_s macsec_dpaa_eth_hooks;

	struct generic_msg *check;
	int macsec_id = 0;
	uint32_t sc_id, macsec_revision;
	macsec_an_t ret_an;
	int i;

	pr_debug("Entering: %s\n", __func__);

	if (unlikely(!skb)) {
		pr_err("skb null\n");
		return;
	}

	nlh = (struct nlmsghdr *)skb->data;
	check = kmalloc(sizeof(*check), GFP_KERNEL);
	memcpy(check, nlmsg_data(nlh), sizeof(*check));
	pid = nlh->nlmsg_pid; /*pid of sending process */
	cmd = check->chf;

	switch (cmd) {
	case ENABLE_MACSEC:
		pr_debug("ENABLE_MACSEC\n");

		macsec_id = enable_macsec(check);

		if (macsec_id >= 0)
			macsec_priv[macsec_id]->en_state = MACSEC_ENABLED;

		rv = send_result(nlh, pid, (macsec_id < 0) ? NACK : macsec_id);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case SET_EXCEPTION:
		pr_debug("SET_EXCEPTION\n");

		rv =  set_macsec_exception(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case ENABLE_SECY:
		pr_debug("ENABLE_SECY\n");

		rv = enable_secy(check, &macsec_id);

		if (rv == 0)
			macsec_priv[macsec_id]->en_state = SECY_ENABLED;

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case GET_REVISION:
		pr_debug("GET_REVISION\n");

		rv = get_macsec_revision(check, &macsec_revision);

		rv = send_result(nlh, pid,
				(rv < 0) ? NACK : (int)macsec_revision);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case GET_TXSC_PHYS_ID:
		pr_debug("GET_TXSC_PHYS_ID\n");

		rv = get_tx_sc_phys_id(check, &sc_id);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : (int)sc_id);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case TX_SA_CREATE:
		pr_debug("TX_SA_CREATE\n");

		rv = create_tx_sa(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case MODIFY_TXSA_KEY:
		pr_debug("MODIFY_TXSA_KEY\n");

		rv = modify_tx_sa_key(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case TX_SA_ACTIVATE:
		pr_debug("TX_SA_ACTIVATE\n");

		rv = activate_tx_sa(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case GET_TXSA_AN:
		pr_debug("GET_TXSA_AN\n");

		rv = get_tx_sa_an(check, &ret_an);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : (int)ret_an);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case RX_SC_CREATE:
		pr_debug("RX_SC_CREATE\n");

		sc_id = create_rx_sc(check);

		rv = send_result(nlh, pid, (sc_id < 0) ? NACK : (int)sc_id);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case GET_RXSC_PHYS_ID:
		pr_debug("GET_RXSC_PHYS_ID\n");

		rv = get_rx_sc_phys_id(check, &sc_id);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : (int)sc_id);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case RX_SA_CREATE:
		pr_debug("RX_SA_CREATE\n");

		rv = create_rx_sa(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case MODIFY_RXSA_KEY:
		pr_debug("MODIFY_RXSA_KEY\n");

		rv = modify_rx_sa_key(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case UPDATE_NPN:
		pr_debug("UPDATE_NPN\n");

		rv = update_npn(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case UPDATE_LPN:
		pr_debug("UPDATE_LPN\n");

		rv = update_lpn(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case RX_SA_ACTIVATE:
		pr_debug("RX_SA_ACTIVATE\n");

		rv = activate_rx_sa(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case RX_SA_DISABLE:
		pr_debug("RX_SA_DISABLE\n");

		rv = rx_sa_disable(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case RX_SA_DELETE:
		pr_debug("RX_SA_DELETE\n");

		rv = rx_sa_delete(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case RX_SC_DELETE:
		pr_debug("RX_SC_DELETE\n");

		rv = rx_sc_delete(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case TX_SA_DELETE:
		pr_debug("TX_SA_DELETE\n");

		rv = tx_sa_delete(check);

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case DISABLE_SECY:
		pr_debug("DISABLE_SECY\n");

		rv = disable_secy(check, &macsec_id);

		if (unlikely(rv < 0))
			macsec_priv[macsec_id]->en_state = SECY_ENABLED;
		else
			macsec_priv[macsec_id]->en_state = MACSEC_ENABLED;

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case DISABLE_MACSEC:
		pr_debug("DISABLE_MACSEC\n");

		rv = disable_macsec(check, &macsec_id);

		macsec_priv[macsec_id]->en_state = MACSEC_DISABLED;

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;

		break;

	case DISABLE_ALL:
		pr_debug("DISABLE_ALL\n");

		rv = disable_all(check, &macsec_id);

		macsec_priv[macsec_id]->en_state = MACSEC_DISABLED;

		rv = send_result(nlh, pid, (rv < 0) ? NACK : ACK);
		if (unlikely(rv < 0))
			goto _release;
		break;

	default:
		/* should never get here */
		pr_err("not a state\n");
		break;
	}

	return;

_release:
	for (i = 0; i < FM_MAX_NUM_OF_MACS; i++)
		deinit_macsec(i);

	/* Reset the TX hooks */
	memset(&macsec_dpaa_eth_hooks, 0, sizeof(macsec_dpaa_eth_hooks));
	fsl_dpaa_eth_set_hooks(&macsec_dpaa_eth_hooks);

	for (i = 0; i < FM_MAX_NUM_OF_MACS; i++) {

		if (!macsec_priv[i]->net_dev)
			continue;

		free_percpu(macsec_priv[i]->percpu_priv);

		/* Delete the fman queues */
		list_for_each_entry_safe(dpa_fq,
					tmp,
					&macsec_priv[i]->dpa_fq_list,
					list) {
			dev = dpa_fq->net_dev->dev.parent;
			rv = _dpa_fq_free(dev, (struct qman_fq *)dpa_fq);
			if (unlikely(rv < 0))
				pr_err("_dpa_fq_fre=%d\n", rv);
		}

		macsec_restore_ethtool_ops(macsec_priv[i]->net_dev);
		kfree(macsec_priv[i]);
		macsec_priv[i] = NULL;
	}

	kfree(check);

	netlink_kernel_release(nl_sk);
}

struct netlink_kernel_cfg ms_cfg = {
	.groups = 1,
	.input = switch_messages,
};

static int __init macsec_init(void)
{
	struct dpaa_eth_hooks_s macsec_dpaa_eth_hooks;
	int ret, i;

	pr_debug("Entering: %s\n", __func__);

	/* If there is no interface we want macsec on, just exit. */
	parse_ifs();
	for (i = 0; i < macsec_ifs_cnt; i++) {
		if (!macsec_ifs[i]) {
			pr_err("Interface unknown\n");
			return -EINVAL;
		}
	}

	/* Actually send the info to the user through a given socket. */
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &ms_cfg);
	if (unlikely(!nl_sk)) {
		pr_err("Error creating socket.\n");
		ret = -ENOMEM;
		goto _release;
	}

	ret = macsec_setup();
	if (unlikely(ret != 0)) {
		pr_err("Setup of macsec failed\n");
		goto _release;
	}

	/* set dpaa hooks for default queues */
	memset(&macsec_dpaa_eth_hooks, 0, sizeof(macsec_dpaa_eth_hooks));
	macsec_dpaa_eth_hooks.tx = (dpaa_eth_egress_hook_t)(macsec_tx_hook);
	macsec_dpaa_eth_hooks.rx_default =
		(dpaa_eth_ingress_hook_t)(macsec_rx_hook);

	fsl_dpaa_eth_set_hooks(&macsec_dpaa_eth_hooks);

	return 0;

_release:
	memset(&macsec_dpaa_eth_hooks, 0, sizeof(macsec_dpaa_eth_hooks));
	fsl_dpaa_eth_set_hooks(&macsec_dpaa_eth_hooks);
	netlink_kernel_release(nl_sk);
	return ret;
}

static void __exit macsec_exit(void)
{
	int _errno;
	struct dpa_fq *dpa_fq, *tmp;
	struct device *dev;
	struct dpaa_eth_hooks_s macsec_dpaa_eth_hooks;
	int i;

	pr_debug("exiting macsec module\n");

	for (i = 0; i < FM_MAX_NUM_OF_MACS; i++) {
		/* release has already been done, due to errors,
		 * in switch_messages we will return to exit the module properly
		 */
		if (!macsec_priv[i]->net_dev) {
			pr_debug("no release needed\n");
			continue;
		}
		deinit_macsec(i);
	}

	/* Reset the TX hooks before exiting */
	memset(&macsec_dpaa_eth_hooks, 0, sizeof(macsec_dpaa_eth_hooks));
	fsl_dpaa_eth_set_hooks(&macsec_dpaa_eth_hooks);

	for (i = 0; i < FM_MAX_NUM_OF_MACS; i++) {

		if (!macsec_priv[i]->net_dev) {
			pr_debug("no release needed\n");
			continue;
		}

		free_percpu(macsec_priv[i]->percpu_priv);

		/* Delete the fman queues */
		list_for_each_entry_safe(dpa_fq, tmp,
					&macsec_priv[i]->dpa_fq_list, list) {
			if (dpa_fq) {
				dev = dpa_fq->net_dev->dev.parent;
				_errno = _dpa_fq_free(dev,
					(struct qman_fq *)dpa_fq);
				if (unlikely(_errno < 0))
					pr_err("_dpa_fq_fre=%d\n", _errno);
			}
		}

		/* restore ethtool ops to the previous private ones */
		macsec_restore_ethtool_ops(macsec_priv[i]->net_dev);

		kfree(macsec_priv[i]);
	}

	netlink_kernel_release(nl_sk);

	pr_debug("exited macsec module\n");
}

module_init(macsec_init);
module_exit(macsec_exit);

MODULE_LICENSE("Dual BSD/GPL");
