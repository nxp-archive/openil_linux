
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
 * DPA IPsec Wrapper implementation.
 */

#include <linux/uaccess.h>
#include <linux/export.h>

#include <linux/fsl_dpa_ipsec.h>
#include "dpa_ipsec_ioctl.h"
#include "wrp_dpa_ipsec.h"

/* Other includes */
#include <linux/fdtable.h>
#include "lnxwrp_fm.h"

#define UDP_HDR_SIZE 8

static const struct file_operations dpa_ipsec_fops = {
	.owner = THIS_MODULE,
	.open = wrp_dpa_ipsec_open,
	.read = NULL,
	.write = NULL,
	.unlocked_ioctl = wrp_dpa_ipsec_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = wrp_dpa_ipsec_ioctl_compat,
#endif
	.release = wrp_dpa_ipsec_release
};

static int dpa_ipsec_cdev_major = -1;
static struct class  *ipsec_class;
static struct device *ipsec_dev;

static long wrp_dpa_ipsec_do_ioctl(struct file *filp, unsigned int cmd,
				   unsigned long args);

#ifdef CONFIG_COMPAT
static long wrp_dpa_ipsec_do_compat_ioctl(struct file *filp, unsigned int cmd,
				   unsigned long args);

static void compat_copy_dpa_ipsec_init(struct ioc_dpa_ipsec_params *prm,
				struct ioc_compat_dpa_ipsec_params *compat_prm)
{
	struct ioc_compat_ipsec_init_params *init_compat_prm;
	struct dpa_ipsec_params	*init_prm;

	init_compat_prm = &compat_prm->dpa_ipsec_params;
	init_prm = &prm->dpa_ipsec_params;

	init_prm->fm_pcd = (void *)compat_ptr(init_compat_prm->fm_pcd);
	init_prm->fqid_range = (struct dpa_ipsec_fqid_range *)
				compat_ptr(init_compat_prm->fqid_range);
	init_prm->ipf_bpid = init_compat_prm->ipf_bpid;
	init_prm->max_sa_pairs = init_compat_prm->max_sa_pairs;
	init_prm->post_sec_in_params = init_compat_prm->post_sec_in_params;
	init_prm->max_sa_manip_ops = init_compat_prm->max_sa_manip_ops;
	init_prm->post_sec_out_params = init_compat_prm->post_sec_out_params;
	init_prm->pre_sec_in_params = init_compat_prm->pre_sec_in_params;
	init_prm->pre_sec_out_params = init_compat_prm->pre_sec_out_params;
	init_prm->qm_sec_ch = init_compat_prm->qm_sec_ch;
}

static void compat_copy_sa_in_params(struct dpa_ipsec_sa_in_params *prm,
				     struct ioc_compat_sa_in_params *compat_prm)
{
	prm->arw = compat_prm->arw;
	prm->use_var_iphdr_len = compat_prm->use_var_iphdr_len;
	prm->src_addr = compat_prm->src_addr;
	prm->dest_addr = compat_prm->dest_addr;
	prm->use_udp_encap = compat_prm->use_udp_encap;
	prm->src_port = compat_prm->src_port;
	prm->dest_port = compat_prm->dest_port;
	dpa_cls_tbl_action_params_compatcpy(&prm->policy_miss_action,
				&compat_prm->policy_miss_action);
	dpa_cls_tbl_action_params_compatcpy(&prm->post_ipsec_action,
				&compat_prm->post_ipsec_action);
}
static void compat_copy_sa_out_params(struct dpa_ipsec_sa_out_params *prm,
				struct ioc_compat_sa_out_params *compat_prm)
{
	prm->init_vector = (struct dpa_ipsec_init_vector *)
				compat_ptr(compat_prm->init_vector);
	prm->ip_ver = compat_prm->ip_ver;
	prm->ip_hdr_size = compat_prm->ip_hdr_size;
	prm->outer_ip_header = (void *)compat_ptr(compat_prm->outer_ip_header);
	prm->outer_udp_header =	(void *)
				compat_ptr(compat_prm->outer_udp_header);
	prm->post_sec_flow_id = compat_prm->post_sec_flow_id;
	prm->dscp_start = compat_prm->dscp_start;
	prm->dscp_end = compat_prm->dscp_end;
}

static void compat_copy_sa_crypto_params(struct dpa_ipsec_sa_crypto_params *prm,
				struct ioc_compat_sa_crypto_params *compat_prm)
{
	prm->alg_suite = compat_prm->alg_suite;
	prm->auth_key = (uint8_t *)compat_ptr(compat_prm->auth_key);
	prm->auth_key_len = compat_prm->auth_key_len;
	prm->cipher_key = (uint8_t *)compat_ptr(compat_prm->cipher_key);
	prm->cipher_key_len = compat_prm->cipher_key_len;
}

static void compat_copy_sa_params(struct dpa_ipsec_sa_params *sa_prm,
				  struct ioc_compat_sa_params *sa_compat_prm)
{
	/* copy common (both IN & OUT SA) parameters */
	sa_prm->spi = sa_compat_prm->spi;
	sa_prm->use_ext_seq_num = sa_compat_prm->use_ext_seq_num;
	sa_prm->start_seq_num = sa_compat_prm->start_seq_num;
	sa_prm->l2_hdr_size = sa_compat_prm->l2_hdr_size;
	sa_prm->sa_mode = sa_compat_prm->sa_mode;
	sa_prm->sa_proto = sa_compat_prm->sa_proto;
	sa_prm->hdr_upd_flags = sa_compat_prm->hdr_upd_flags;
	sa_prm->sa_wqid = sa_compat_prm->sa_wqid;
	sa_prm->sa_bpid = sa_compat_prm->sa_bpid;
	sa_prm->sa_bufsize = sa_compat_prm->sa_bufsize;
	sa_prm->enable_stats = sa_compat_prm->enable_stats;
	sa_prm->enable_extended_stats = sa_compat_prm->enable_extended_stats;
	sa_prm->sa_dir = sa_compat_prm->sa_dir;

	/* copy crypto parameters (containing multiple pointers) */
	compat_copy_sa_crypto_params(&sa_prm->crypto_params,
				     &sa_compat_prm->crypto_params);

	/* copy direction specific (IN / OUT) parameters */
	if (sa_prm->sa_dir == DPA_IPSEC_INBOUND)
		compat_copy_sa_in_params(&sa_prm->sa_in_params,
					 &sa_compat_prm->sa_in_params);
	else
		compat_copy_sa_out_params(&sa_prm->sa_out_params,
					&sa_compat_prm->sa_out_params);
}

static int compat_copy_sa_out_iv(struct dpa_ipsec_init_vector *sa_iv,
				 compat_uptr_t compat_iv_ptr)
{
	struct ioc_compat_sa_init_vector *compat_sa_iv, tmp_sa_iv;

	compat_sa_iv =
		(struct ioc_compat_sa_init_vector *)compat_ptr(compat_iv_ptr);

	if (copy_from_user(&tmp_sa_iv, compat_sa_iv, sizeof(tmp_sa_iv)))
		return -EINVAL;

	sa_iv->init_vector = (uint8_t *) compat_ptr(tmp_sa_iv.init_vector);
	sa_iv->length = tmp_sa_iv.length;

	return 0;
}

static void compat_copy_dpa_ipsec_rekey_sa(struct ioc_dpa_ipsec_rekey_prm *prm,
			struct ioc_compat_dpa_ipsec_rekey_prm *compat_prm)
{
	/* copy rekeying specific params */
	prm->auto_rmv_old_sa = compat_prm->auto_rmv_old_sa;
	prm->sa_id = compat_prm->sa_id;

	/* copy SA params from userspace */
	compat_copy_sa_params(&prm->sa_params, &compat_prm->sa_params);
}

static void compat_copy_dpa_ipsec_add_rem_policy(
			struct ioc_dpa_ipsec_add_rem_policy *prm,
			struct ioc_compat_dpa_ipsec_add_rem_policy *compat_prm,
			bool copy_from_us)
{
	if (copy_from_us) {
		prm->sa_id = compat_prm->sa_id;
		prm->pol_params.src_addr = compat_prm->pol_params.src_addr;
		prm->pol_params.src_prefix_len =
					  compat_prm->pol_params.src_prefix_len;
		prm->pol_params.dest_addr = compat_prm->pol_params.dest_addr;
		prm->pol_params.dest_prefix_len =
					 compat_prm->pol_params.dest_prefix_len;
		prm->pol_params.protocol = compat_prm->pol_params.protocol;
		prm->pol_params.masked_proto =
					    compat_prm->pol_params.masked_proto;
		prm->pol_params.use_dscp = compat_prm->pol_params.use_dscp;
		prm->pol_params.l4 = compat_prm->pol_params.l4;
		if (compat_prm->pol_params.dir_params.type ==
						DPA_IPSEC_POL_DIR_PARAMS_MANIP)
			prm->pol_params.dir_params.manip_desc =
				   compat_prm->pol_params.dir_params.manip_desc;
		else if (compat_prm->pol_params.dir_params.type ==
						 DPA_IPSEC_POL_DIR_PARAMS_ACT) {
			dpa_cls_tbl_action_params_compatcpy(
				  &prm->pol_params.dir_params.in_action,
				  &compat_prm->pol_params.dir_params.in_action);
		}
		prm->pol_params.dir_params.type =
					 compat_prm->pol_params.dir_params.type;
		prm->pol_params.priority =
					 compat_prm->pol_params.priority;
	} else {
		compat_prm->sa_id = prm->sa_id;
		compat_prm->pol_params.src_addr = prm->pol_params.src_addr;
		compat_prm->pol_params.src_prefix_len =
						 prm->pol_params.src_prefix_len;
		compat_prm->pol_params.dest_addr = prm->pol_params.dest_addr;
		compat_prm->pol_params.dest_prefix_len =
						prm->pol_params.dest_prefix_len;
		compat_prm->pol_params.protocol = prm->pol_params.protocol;
		compat_prm->pol_params.masked_proto =
						   prm->pol_params.masked_proto;
		compat_prm->pol_params.use_dscp = prm->pol_params.use_dscp;
		compat_prm->pol_params.l4 = prm->pol_params.l4;
		if (prm->pol_params.dir_params.type ==
						DPA_IPSEC_POL_DIR_PARAMS_MANIP)
			compat_prm->pol_params.dir_params.manip_desc =
					  prm->pol_params.dir_params.manip_desc;
		else if (prm->pol_params.dir_params.type ==
						 DPA_IPSEC_POL_DIR_PARAMS_ACT) {
			dpa_cls_tbl_action_params_rcompatcpy(
				  &compat_prm->pol_params.dir_params.in_action,
				  &prm->pol_params.dir_params.in_action);
		}
		compat_prm->pol_params.dir_params.type =
						prm->pol_params.dir_params.type;
		compat_prm->pol_params.priority =
						prm->pol_params.priority;
	}
}

static void compat_copy_dpa_ipsec_get_pols(
			struct ioc_dpa_ipsec_get_policies *prm,
			struct ioc_compat_dpa_ipsec_get_policies *compat_prm)
{
	prm->num_pol = compat_prm->num_pol;
	prm->sa_id = compat_prm->sa_id;
	prm->policy_params = (struct dpa_ipsec_policy_params *)
				compat_ptr(compat_prm->policy_params);
}

static int compat_alloc_plcr_params(struct dpa_cls_tbl_action	*kparam,
			const struct dpa_cls_compat_tbl_action	*uparam)
{
	if (uparam->type == DPA_CLS_TBL_ACTION_ENQ &&
	    compat_ptr(uparam->enq_params.policer_params)) {
		kparam->enq_params.policer_params = kmalloc(
				sizeof(struct dpa_cls_tbl_policer_params),
				GFP_KERNEL);
		if (!kparam->enq_params.policer_params) {
			log_err("Error alloc CLS POL param\n");
			return -ENOMEM;
		}
	}
	return 0;
}
#endif

static int copy_policer_params(struct dpa_cls_tbl_action *cls_action)
{
	struct dpa_cls_tbl_policer_params *policer_params = NULL;
	int err = 0;

	if (cls_action->type == DPA_CLS_TBL_ACTION_ENQ &&
	    cls_action->enq_params.policer_params != NULL) {
		policer_params = kmalloc(sizeof(*policer_params), GFP_KERNEL);
		if (!policer_params) {
			log_err("Error alloc CLS POL param\n");
			err = -ENOMEM;
			goto clean_policer_params;
		}
		if (copy_from_user(policer_params,
				  cls_action->enq_params.policer_params,
				  sizeof(*policer_params))) {
			log_err("Error - copy CLS POL param\n");
			err = -EINVAL;
			goto clean_policer_params;
		}
		cls_action->enq_params.policer_params = policer_params;
		return 0;
	}

clean_policer_params:
	cls_action->enq_params.policer_params = NULL;
	kfree(policer_params);

	return err;
}

/* free memory allocated for copying SA params from US */
static void free_sa_params(struct dpa_ipsec_sa_params *prm)
{
	struct dpa_ipsec_sa_crypto_params *crypto_params;

	if (prm->sa_dir == DPA_IPSEC_OUTBOUND) {
		struct dpa_ipsec_sa_out_params *sa_out_prm;

		sa_out_prm = &prm->sa_out_params;
		if (sa_out_prm->init_vector) {
			kfree(sa_out_prm->init_vector->init_vector);
			kfree(sa_out_prm->init_vector);
		}
		kfree(sa_out_prm->outer_ip_header);
		kfree(sa_out_prm->outer_udp_header);
	} else {
		struct dpa_cls_tbl_action *cls_action;

		cls_action = &prm->sa_in_params.policy_miss_action;
		if (cls_action->type == DPA_CLS_TBL_ACTION_ENQ)
			kfree(cls_action->enq_params.policer_params);

		cls_action = &prm->sa_in_params.post_ipsec_action;
		if (cls_action->type == DPA_CLS_TBL_ACTION_ENQ)
			kfree(cls_action->enq_params.policer_params);
	}

	crypto_params = &prm->crypto_params;
	kfree(crypto_params->auth_key);
	kfree(crypto_params->cipher_key);
}

/* handle any required memory transfers (US to K) when creating/rekeying a SA */
static int do_copy_sa_params(struct dpa_ipsec_sa_params *prm, void *args)
{
	struct dpa_ipsec_sa_out_params *sa_out_prm;
	struct dpa_ipsec_sa_crypto_params *crypto_params;
	struct dpa_ipsec_init_vector *sa_out_iv = NULL;
	uint8_t *auth_key =  NULL, *cipher_key = NULL, *iv_array = NULL;
	void *out_ip_hdr = NULL, *out_udp_hdr = NULL;
	int err = 0;
#ifdef CONFIG_COMPAT
	struct ioc_compat_sa_params *compat_prm =
					(struct ioc_compat_sa_params *)args;
#endif
	/* allocate memory and copy SA out params (if required)*/
	if (prm->sa_dir == DPA_IPSEC_OUTBOUND) {
		sa_out_prm = &prm->sa_out_params;
		if (sa_out_prm->outer_ip_header) {
			out_ip_hdr = kmalloc(sa_out_prm->ip_hdr_size,
					     GFP_KERNEL);
			if (!out_ip_hdr) {
				log_err("Error - alloc SA out hdr\n");
				return -ENOMEM;
			}
			if (copy_from_user(out_ip_hdr,
					   sa_out_prm->outer_ip_header,
					   sa_out_prm->ip_hdr_size)) {
				log_err("Error - copy SA out hdr\n");
				err = -EINVAL;
				goto free_create_copied_sa_mem;
			}
			sa_out_prm->outer_ip_header = out_ip_hdr;
		}
		if (sa_out_prm->outer_udp_header) {
			out_udp_hdr = kmalloc(UDP_HDR_SIZE, GFP_KERNEL);
			if (!out_udp_hdr) {
				log_err("Error - alloc SA out udp hdr\n");
				err = -ENOMEM;
				goto free_create_copied_sa_mem;
			}
			if (copy_from_user(out_udp_hdr,
					   sa_out_prm->outer_udp_header,
					   UDP_HDR_SIZE)) {
				log_err("Error - copy SA out udp hdr\n");
				err = -EINVAL;
				goto free_create_copied_sa_mem;
			}
			sa_out_prm->outer_udp_header = out_udp_hdr;
		}
		if (sa_out_prm->init_vector) {
			sa_out_iv = kmalloc(sizeof(*sa_out_iv), GFP_KERNEL);
			if (!sa_out_iv) {
				log_err("Error - alloc SA out IV struct\n");
				err = -ENOMEM;
				goto free_create_copied_sa_mem;
			}
#ifdef CONFIG_COMPAT
			err = compat_copy_sa_out_iv(sa_out_iv,
					compat_prm->sa_out_params.init_vector);
#else
			if (copy_from_user(sa_out_iv, sa_out_prm->init_vector,
					   sizeof(*sa_out_iv)))
				err = -EINVAL;
#endif
			if (err < 0) {
				log_err("Error - copy SA out IV struct\n");
				kfree(sa_out_iv);
				return err;
			}

			if (sa_out_iv->length > DPA_IPSEC_MAX_IV_LEN) {
				err = -EINVAL;
				log_err("Error - IV length greater than %d\n",
					DPA_IPSEC_MAX_IV_LEN);
				kfree(sa_out_iv);
				return err;
			}

			sa_out_prm->init_vector = sa_out_iv;

			/* if the IV array is NULL, don't bother to copy it */
			if (!sa_out_iv->init_vector)
				goto copy_crypto_keys;

			iv_array = kmalloc(sa_out_iv->length, GFP_KERNEL);
			if (!iv_array) {
				log_err("Error - alloc SA out IV array\n");
				err = -ENOMEM;
				goto free_create_copied_sa_mem;
			}
			if (copy_from_user(iv_array, sa_out_iv->init_vector,
					   sa_out_iv->length)) {
				log_err("Error - copy SA out IV array\n");
				err = -EINVAL;
				goto free_create_copied_sa_mem;
			}
			sa_out_iv->init_vector = iv_array;
		}
	}

copy_crypto_keys:
	/*
	 * allocate memory and copy the keys from userspace
	 * (if required - if keys are not NULL)
	 */
	crypto_params = &prm->crypto_params;
	if (crypto_params->auth_key) {
		auth_key = kmalloc(crypto_params->auth_key_len, GFP_KERNEL);
		if (!auth_key) {
			log_err("Couldn't allocate memory for SA auth key\n");
			err = -ENOMEM;
			goto free_create_sa_keys_mem;
		}
		if (copy_from_user(auth_key, crypto_params->auth_key,
				   crypto_params->auth_key_len)) {
			log_err("Could not copy SA auth key!\n");
			err = -EINVAL;
			goto free_create_sa_keys_mem;
		}
		crypto_params->auth_key = auth_key;
	}

	if (crypto_params->cipher_key) {
		cipher_key = kmalloc(crypto_params->cipher_key_len, GFP_KERNEL);
		if (!cipher_key) {
			log_err("Couldn't allocate memory for SA cipher key\n");
			err = -ENOMEM;
			goto free_create_sa_keys_mem;
		}
		if (copy_from_user(cipher_key, crypto_params->cipher_key,
				   crypto_params->cipher_key_len)) {
			log_err("Could not copy SA auth key!\n");
			err = -EINVAL;
			goto free_create_sa_keys_mem;
		}
		crypto_params->cipher_key = cipher_key;
	}

	return 0;

free_create_sa_keys_mem:
	kfree(auth_key);
	kfree(cipher_key);

free_create_copied_sa_mem:
	if (prm->sa_dir == DPA_IPSEC_OUTBOUND) {
		kfree(iv_array);
		kfree(sa_out_iv);
		kfree(out_ip_hdr);
		kfree(out_udp_hdr);
	}

	return err;
}

static int do_init_ioctl(struct ioc_dpa_ipsec_params *kprm)
{
	struct dpa_ipsec_fqid_range *fqid_range = NULL;
	struct file *fm_pcd_file;
	t_LnxWrpFmDev *fm_wrapper_dev;
	int err;

	/* copy FQID range params - if configured */
	if (kprm->dpa_ipsec_params.fqid_range) {
		fqid_range = kmalloc(sizeof(*fqid_range), GFP_KERNEL);
		if (!fqid_range) {
			log_err("FQID range allocation failed!\n");
			return -EINVAL;
		}
		if (copy_from_user(fqid_range,
				   kprm->dpa_ipsec_params.fqid_range,
				   sizeof(*fqid_range))) {
			log_err("Could not copy FQID range params!\n");
			err = -EINVAL;
			goto free_ipsec_init_mem;
		}
		kprm->dpa_ipsec_params.fqid_range = fqid_range;
	}

	/* Translate FM_PCD file descriptor */
	fm_pcd_file = fcheck((unsigned long)kprm->dpa_ipsec_params.fm_pcd);
	if (!fm_pcd_file) {
		log_err("Could not acquire PCD handle\n");
		err = -EINVAL;
		goto free_ipsec_init_mem;
	}
	fm_wrapper_dev = ((t_LnxWrpFmDev *)fm_pcd_file->private_data);
	kprm->dpa_ipsec_params.fm_pcd = (void *)fm_wrapper_dev->h_PcdDev;
	err = dpa_ipsec_init(&kprm->dpa_ipsec_params,
			     &kprm->dpa_ipsec_id);
	if (err < 0)
		goto free_ipsec_init_mem;

free_ipsec_init_mem:
	kfree(fqid_range);

	return err;
}

static int do_create_sa_ioctl(void *args)
{
	struct ioc_dpa_ipsec_sa_params prm;
	int err = 0;

	if (copy_from_user(&prm, args, sizeof(prm))) {
		log_err("Could not copy SA parameters\n");
		return -EINVAL;
	}

	if (prm.sa_params.sa_dir == DPA_IPSEC_INBOUND) {
		struct dpa_ipsec_sa_in_params *sa_in_params = NULL;

		sa_in_params = &prm.sa_params.sa_in_params;
		/* copy policer params for policy miss action - if any */
		err = copy_policer_params(&sa_in_params->policy_miss_action);
		if (err < 0)
			goto free_create_sa_mem;

		/* copy policer params for post decryption action - if any */
		err = copy_policer_params(&sa_in_params->post_ipsec_action);
		if (err < 0)
			goto free_create_sa_mem;
	}

	err = do_copy_sa_params(&prm.sa_params, NULL);
	if (err < 0)
		return err;

	err = dpa_ipsec_create_sa(prm.dpa_ipsec_id, &prm.sa_params, &prm.sa_id);
	if (err < 0)
		goto free_create_sa_mem;

	if (copy_to_user((void *)args, &prm, sizeof(prm))) {
		log_err("Could not copy to user the SA ID\n");
		err = -EINVAL;
	}

free_create_sa_mem:
	free_sa_params(&prm.sa_params);

	return err;
}

#ifdef CONFIG_COMPAT
static int do_create_sa_compat_ioctl(void *args)
{
	struct ioc_dpa_ipsec_sa_params prm;
	struct ioc_compat_dpa_ipsec_sa_params compat_prm;
	int err = 0;

	if (copy_from_user(&compat_prm, args, sizeof(compat_prm))) {
		log_err("Could not copy SA parameters\n");
		return -EINVAL;
	}

	memset(&prm, 0, sizeof(struct ioc_dpa_ipsec_sa_params));

	/* allocate memory for policer parameters */
	if (compat_prm.sa_params.sa_dir == DPA_IPSEC_INBOUND) {
		memset(&prm.sa_params.sa_in_params.policy_miss_action,
				0, sizeof(struct dpa_cls_tbl_action));
		err = compat_alloc_plcr_params(
			&prm.sa_params.sa_in_params.policy_miss_action,
			&compat_prm.sa_params.sa_in_params.policy_miss_action);
		if (err < 0)
			goto free_create_sa_mem;

		memset(&prm.sa_params.sa_in_params.post_ipsec_action,
				0, sizeof(struct dpa_cls_tbl_action));
		err = compat_alloc_plcr_params(
			&prm.sa_params.sa_in_params.post_ipsec_action,
			&compat_prm.sa_params.sa_in_params.post_ipsec_action);
		if (err < 0)
			goto free_create_sa_mem;
	}

	/* copy SA params from userspace */
	prm.dpa_ipsec_id = compat_prm.dpa_ipsec_id;
	compat_copy_sa_params(&prm.sa_params, &compat_prm.sa_params);

	err = do_copy_sa_params(&prm.sa_params, &compat_prm.sa_params);
	if (err < 0)
		return err;

	err = dpa_ipsec_create_sa(prm.dpa_ipsec_id, &prm.sa_params, &prm.sa_id);
	if (err < 0)
		goto free_create_sa_mem;

	/* copy the ID of the newly created DPA IPSec SA */
	compat_prm.sa_id = prm.sa_id;

	if (copy_to_user((void *)args, &compat_prm, sizeof(compat_prm))) {
		log_err("Could not copy to user the SA ID\n");
		err = -EINVAL;
	}

free_create_sa_mem:
	free_sa_params(&prm.sa_params);

	return err;
}
#endif

static int do_sa_rekey_ioctl(void *args)
{
	struct ioc_dpa_ipsec_rekey_prm prm;
	int err = 0;

	if (copy_from_user(&prm, args, sizeof(prm))) {
		log_err("Could not copy SA rekeying params\n");
		return -EINVAL;
	}

	err = do_copy_sa_params(&prm.sa_params, NULL);
	if (err < 0)
		return err;

	err = dpa_ipsec_sa_rekeying(prm.sa_id, &prm.sa_params,
				    default_rekey_event_cb, prm.auto_rmv_old_sa,
				    &prm.new_sa_id);
	if (err < 0)
		goto free_rekey_sa_mem;

	if (copy_to_user((void *)args, &prm, sizeof(prm))) {
		log_err("Could not copy to user new SA ID\n");
		err = -EINVAL;
	}

free_rekey_sa_mem:
	free_sa_params(&prm.sa_params);

	return err;
}

#ifdef CONFIG_COMPAT
static int do_sa_rekey_compat_ioctl(void *args)
{
	struct ioc_dpa_ipsec_rekey_prm prm;
	struct ioc_compat_dpa_ipsec_rekey_prm compat_prm;
	int err = 0;

	if (copy_from_user(&compat_prm, args, sizeof(compat_prm))) {
		log_err("Could not copy SA rekeying params\n");
		return -EINVAL;
	}
	compat_copy_dpa_ipsec_rekey_sa(&prm, &compat_prm);

	err = do_copy_sa_params(&prm.sa_params, &compat_prm.sa_params);
	if (err < 0)
		return err;

	err = dpa_ipsec_sa_rekeying(prm.sa_id, &prm.sa_params,
				    default_rekey_event_cb, prm.auto_rmv_old_sa,
				    &prm.new_sa_id);
	if (err < 0)
		goto free_rekey_sa_mem;

	compat_prm.new_sa_id = prm.new_sa_id;
	if (copy_to_user((void *)args, &compat_prm, sizeof(compat_prm))) {
		log_err("Could not copy to user new SA ID\n");
		err = -EINVAL;
	}

free_rekey_sa_mem:
	free_sa_params(&prm.sa_params);

	return err;
}
#endif

static int do_add_rem_policy_ioctl(void *args, bool add_pol)
{
	struct ioc_dpa_ipsec_add_rem_policy prm;
	int err;

	if (copy_from_user(&prm,
			   (struct ioc_dpa_ipsec_add_rem_policy *)args,
			   sizeof(prm))) {
		log_err("Could not copy parameters\n");
		return -EINVAL;
	}

	if (prm.pol_params.dir_params.type == DPA_IPSEC_POL_DIR_PARAMS_ACT) {
		err = copy_policer_params(&prm.pol_params.dir_params.in_action);
		if (err < 0)
			return err;
	}

	if (add_pol)
		err = dpa_ipsec_sa_add_policy(prm.sa_id, &prm.pol_params);
	else
		err = dpa_ipsec_sa_remove_policy(prm.sa_id, &prm.pol_params);

	if (prm.pol_params.dir_params.type == DPA_IPSEC_POL_DIR_PARAMS_ACT)
		kfree(prm.pol_params.dir_params.in_action.enq_params.policer_params);

	return err;
}

#ifdef CONFIG_COMPAT
static int do_add_rem_policy_compat_ioctl(void *args, bool add_pol)
{
	struct ioc_dpa_ipsec_add_rem_policy kprm;
	struct ioc_compat_dpa_ipsec_add_rem_policy uprm;
	struct dpa_cls_tbl_action *in_action = NULL;
	int err;

	if (copy_from_user(&uprm,
		   (struct ioc_compat_dpa_ipsec_add_rem_policy *)args,
		    sizeof(uprm))) {
		log_err("Could not copy parameters\n");
		return -EINVAL;
	}

	memset(&kprm, 0, sizeof(struct ioc_dpa_ipsec_add_rem_policy));

	in_action = &kprm.pol_params.dir_params.in_action;
	if (uprm.pol_params.dir_params.type == DPA_IPSEC_POL_DIR_PARAMS_ACT) {
		err = compat_alloc_plcr_params(in_action,
					&uprm.pol_params.dir_params.in_action);
		if (err < 0)
			return err;
	}

	compat_copy_dpa_ipsec_add_rem_policy(&kprm, &uprm, true);

	if (add_pol)
		err = dpa_ipsec_sa_add_policy(kprm.sa_id, &kprm.pol_params);
	else
		err = dpa_ipsec_sa_remove_policy(kprm.sa_id, &kprm.pol_params);

	if (uprm.pol_params.dir_params.type == DPA_IPSEC_POL_DIR_PARAMS_ACT)
		kfree(in_action->enq_params.policer_params);

	return err;
}
#endif

static int do_sa_get_policies_ioctl(void *args)
{
	struct ioc_dpa_ipsec_get_policies prm;
	struct dpa_ipsec_policy_params *policy_params = NULL;
	struct dpa_cls_tbl_policer_params **uplcr = NULL, **kplcr = NULL;
	struct dpa_ipsec_pol_dir_params *dir;
	int sa_id, num_pol = 0, err = 0, i;

	if (copy_from_user(&prm, args, sizeof(prm))) {
		log_err("Could not copy params for policy retrieval\n");
		return -EINVAL;
	}

	if (prm.sa_id < 0) {
		log_err("Invalid input SA id\n");
		return -EINVAL;
	}

	sa_id = prm.sa_id;
	if (!prm.policy_params) {
		err = dpa_ipsec_sa_get_policies(sa_id, NULL, &num_pol);
		if (err < 0) {
			log_err("Get policies count failed\n");
			return err;
		}

		prm.num_pol = num_pol;

		if (copy_to_user(args, &prm, sizeof(prm))) {
			log_err("Cannot copy policy count to user\n");
			return -EINVAL;
		}
		return 0;
	}

	num_pol = prm.num_pol;
	if (num_pol <= 0 || num_pol > DPA_IPSEC_MAX_POL_PER_SA) {
		log_err("Invalid number of policies for SA ID# %d\n", sa_id);
		return -EINVAL;
	}

	policy_params =	kzalloc(num_pol * sizeof(*policy_params), GFP_KERNEL);
	if (!policy_params) {
		log_err("Could not allocate memory for policy array\n");
		return -ENOMEM;
	}

	err = dpa_ipsec_sa_get_policies(sa_id, policy_params, &num_pol);
	if (err < 0 && err != -EAGAIN) {
		log_err("Could not retrieve SA policies\n");
		goto err_pol_cleanup;
	} else if (err == -EAGAIN)
		log_err("Not all SA policies could be retrieved\n");

	kplcr = kzalloc(num_pol * sizeof(*kplcr), GFP_KERNEL);
	if (!kplcr) {
		log_err("Could not allocate memory for policer array\n");
		err = -ENOMEM;
		goto err_pol_cleanup;
	}

	uplcr = kzalloc(num_pol * sizeof(*uplcr), GFP_KERNEL);
	if (!uplcr) {
		log_err("Could not allocate memory for policer array\n");
		err = -ENOMEM;
		goto err_pol_cleanup;
	}

	/* User needs to provide policer parameters pointer */
	for (i = 0; i < num_pol; i++) {
		dir = &prm.policy_params[i].dir_params;
		if (dir->in_action.enq_params.policer_params != NULL)
			uplcr[i] = dir->in_action.enq_params.policer_params;
	}

	for (i = 0; i < num_pol; i++) {
		dir = &policy_params[i].dir_params;
		if (dir->type == DPA_IPSEC_POL_DIR_PARAMS_ACT &&
		    dir->in_action.type == DPA_CLS_TBL_ACTION_ENQ &&
		    dir->in_action.enq_params.policer_params != NULL)
			kplcr[i] = dir->in_action.enq_params.policer_params;
	}

	if (copy_to_user(prm.policy_params, policy_params,
			 num_pol * sizeof(*policy_params))) {
		log_err("Could not return policy parameters\n");
		err = -EINVAL;
	}

	for (i = 0; i < num_pol; i++) {
		if (uplcr[i] && kplcr[i]) {
			if (copy_to_user(uplcr[i], kplcr[i], sizeof(**uplcr))) {
				log_err("Could not return policy parameters\n");
				err = -EINVAL;
			}
		}
		prm.policy_params[i].dir_params.in_action.
					enq_params.policer_params = uplcr[i];
	}

	/*
	 * None of the values of the members in the input structure have been
	 * modified, so there is no need to copy the input structure back to the
	 * user
	 */

err_pol_cleanup:
	kfree(policy_params);
	kfree(uplcr);
	kfree(kplcr);

	return err;
}

#ifdef CONFIG_COMPAT
static int do_sa_get_policies_compat_ioctl(void *args)
{
	struct ioc_dpa_ipsec_get_policies prm;
	struct dpa_ipsec_policy_params *policy_params = NULL;
	struct ioc_dpa_ipsec_add_rem_policy kparam;
	struct ioc_compat_dpa_ipsec_get_policies compat_prm;
	struct ioc_compat_policy_params *compat_pol_params = NULL;
	struct ioc_compat_dpa_ipsec_add_rem_policy compat_uparam;
	struct ioc_compat_policy_params *pol = NULL;
	int i, sa_id, num_pol, err = 0;

	if (copy_from_user(&compat_prm, args, sizeof(compat_prm))) {
		log_err("Could not copy params for policy retrieval\n");
		return -EINVAL;
	}
	compat_copy_dpa_ipsec_get_pols(&prm, &compat_prm);

	if (prm.sa_id < 0) {
		log_err("Invalid input SA id\n");
		return -EINVAL;
	}

	sa_id = prm.sa_id;
	if (!prm.policy_params) {
		err = dpa_ipsec_sa_get_policies(sa_id, NULL, &num_pol);
		if (err < 0) {
			log_err("Get policies count failed\n");
			return err;
		}

		prm.num_pol = num_pol;

		compat_prm.num_pol = prm.num_pol;
		if (copy_to_user(args, &compat_prm, sizeof(compat_prm))) {
				log_err("Cannot copy policy count to user\n");
				return -EINVAL;
		}
		return 0;
	}

	num_pol = prm.num_pol;
	if (num_pol <= 0 || num_pol > DPA_IPSEC_MAX_POL_PER_SA) {
		log_err("Invalid number of policies for SA ID# %d\n", sa_id);
		return -EINVAL;
	}

	policy_params =	kzalloc(num_pol * sizeof(*policy_params), GFP_KERNEL);
	if (!policy_params) {
		log_err("Could not allocate memory for policy array\n");
		return -ENOMEM;
	}

	err = dpa_ipsec_sa_get_policies(sa_id, policy_params, &num_pol);
	if (err < 0 && err != -EAGAIN) {
		log_err("Could not retrieve SA policies\n");
		goto err_pol_cleanup;
	} else if (err == -EAGAIN)
		log_err("Not all SA policies could be retrieved\n");

	compat_pol_params = kzalloc(num_pol * sizeof(*compat_pol_params),
				    GFP_KERNEL);
	if (!compat_pol_params) {
		log_err("Could not allocate memory for compat policy array!\n");
		kfree(policy_params);
		return -ENOMEM;
	}

	/* Allocate memory to store the array of policy objects */
	pol = kzalloc(sizeof(*pol) * num_pol, GFP_KERNEL);
	if (!pol) {
		log_err("No more memory for array of policies\n");
		err = -ENOMEM;
		goto err_pol_cleanup;
	}

	if (copy_from_user(pol, compat_ptr(compat_prm.policy_params),
			  (sizeof(*pol) * num_pol))) {
		log_err("Could not copy array of objects\n");
		err = -EBUSY;
		goto err_pol_cleanup;
	}

	for (i = 0; i < num_pol; i++) {
		memcpy(&kparam.pol_params, &policy_params[i],
			sizeof(kparam.pol_params));
		memset(&compat_uparam, 0,
			sizeof(struct ioc_compat_dpa_ipsec_add_rem_policy));

		compat_uparam.pol_params.dir_params.in_action.
			enq_params.policer_params = pol[i].dir_params.
			in_action.enq_params.policer_params;

		compat_copy_dpa_ipsec_add_rem_policy(&kparam,
						     &compat_uparam,
						     false);
		memcpy(&compat_pol_params[i], &compat_uparam.pol_params,
			sizeof(compat_uparam.pol_params));
	}
	if (copy_to_user(prm.policy_params, compat_pol_params,
			 num_pol * sizeof(*compat_pol_params))) {
		log_err("Could not return policy parameters\n");
		err = -EINVAL;
	}

	/*
	 * None of the values of the members in the input structure have been
	 * modified, so there is no need to copy the input structure back to the
	 * user
	 */

err_pol_cleanup:
	kfree(compat_pol_params);
	kfree(policy_params);
	kfree(pol);

	return err;
}
#endif

/* Set mprm - no compat case */
static int do_sa_modify_ioctl(unsigned long args, int *sa_id,
			      struct dpa_ipsec_sa_modify_prm *mprm)
{
	struct ioc_dpa_ipsec_sa_modify_prm prm;

	if (copy_from_user(&prm,
			   (struct ioc_dpa_ipsec_sa_modify_prm *)args,
			   sizeof(prm))) {
		log_err("Could not copy from user modify parameters\n");
		return -EINVAL;
	}

	if (prm.sa_id < 0) {
		log_err("Invalid input SA id\n");
		return -EINVAL;
	}

	*sa_id = prm.sa_id;

	if (prm.modify_prm.type == DPA_IPSEC_SA_MODIFY_CRYPTO) {
		struct dpa_ipsec_sa_crypto_params *crypto_prm;
		crypto_prm = &prm.modify_prm.crypto_params;
		mprm->crypto_params.cipher_key =
			kmalloc(crypto_prm->cipher_key_len, GFP_KERNEL);
		if (!mprm->crypto_params.cipher_key) {
			log_err("Allocation failed for cipher key\n");
			return -ENOMEM;
		}

		mprm->crypto_params.auth_key =
			kmalloc(crypto_prm->auth_key_len, GFP_KERNEL);
		if (!mprm->crypto_params.auth_key) {
			log_err("Allocation failed for authentication key\n");
			return -ENOMEM;
		}

		mprm->type = prm.modify_prm.type;
		memcpy(mprm->crypto_params.cipher_key,
		       crypto_prm->cipher_key,
		       crypto_prm->cipher_key_len);
		memcpy(mprm->crypto_params.auth_key,
		       crypto_prm->auth_key,
		       crypto_prm->auth_key_len);
	} else {
		memcpy(mprm, &prm.modify_prm, sizeof(prm.modify_prm));
	}

	return 0;
}

#ifdef CONFIG_COMPAT
/* Set mprm - compat case */
static int do_sa_modify_ioctl_compat(unsigned long args, int *sa_id,
				     struct dpa_ipsec_sa_modify_prm *mprm)
{
	struct ioc_compat_dpa_ipsec_sa_modify_prm prm;

	if (copy_from_user(&prm,
			   (struct ioc_compat_dpa_ipsec_sa_modify_prm *)args,
			   sizeof(prm))) {
		log_err("Could not copy from user modify parameters\n");
		return -EINVAL;
	}

	if (prm.sa_id < 0) {
		log_err("Invalid input SA id\n");
		return -EINVAL;
	}

	*sa_id = prm.sa_id;

	if (prm.modify_prm.type == DPA_IPSEC_SA_MODIFY_CRYPTO) {
		struct ioc_compat_sa_crypto_params *crypto_prm;
		crypto_prm = &prm.modify_prm.crypto_params;
		mprm->crypto_params.cipher_key =
			kmalloc(crypto_prm->cipher_key_len, GFP_KERNEL);
		if (!mprm->crypto_params.cipher_key) {
			log_err("Allocation failed for cipher key\n");
			return -ENOMEM;
		}

		mprm->crypto_params.auth_key =
			kmalloc(crypto_prm->auth_key_len, GFP_KERNEL);
		if (!mprm->crypto_params.auth_key) {
			log_err("Allocation failed for authentication key\n");
			return -ENOMEM;
		}

		mprm->type = prm.modify_prm.type;
		memcpy(mprm->crypto_params.cipher_key,
		       compat_ptr(crypto_prm->cipher_key),
		       crypto_prm->cipher_key_len);
		memcpy(mprm->crypto_params.auth_key,
		       compat_ptr(crypto_prm->auth_key),
		       crypto_prm->auth_key_len);
	} else {
		memcpy(mprm, &prm.modify_prm, sizeof(prm.modify_prm));
	}

	return 0;
}
#endif

int wrp_dpa_ipsec_init(void)
{
	/* Cannot initialize the wrapper twice */
	if (dpa_ipsec_cdev_major >= 0)
		return -EBUSY;

	dpa_ipsec_cdev_major =
	    register_chrdev(0, DPA_IPSEC_CDEV, &dpa_ipsec_fops);
	if (dpa_ipsec_cdev_major < 0) {
		log_err("Could not register Dpa IPSec character device\n");
		return dpa_ipsec_cdev_major;
	}

	ipsec_class = class_create(THIS_MODULE, DPA_IPSEC_CDEV);
	if (IS_ERR(ipsec_class)) {
		log_err("Cannot create DPA IPsec class device\n");
		unregister_chrdev(dpa_ipsec_cdev_major, DPA_IPSEC_CDEV);
		dpa_ipsec_cdev_major = -1;
		return PTR_ERR(ipsec_class);
	}

	ipsec_dev = device_create(ipsec_class, NULL,
				  MKDEV(dpa_ipsec_cdev_major, 0), NULL,
				  DPA_IPSEC_CDEV);
	if (IS_ERR(ipsec_dev)) {
		log_err("Cannot create DPA IPsec device\n");
		class_destroy(ipsec_class);
		unregister_chrdev(dpa_ipsec_cdev_major, DPA_IPSEC_CDEV);
		dpa_ipsec_cdev_major = -1;
		return PTR_ERR(ipsec_dev);
	}

	return 0;
}


int wrp_dpa_ipsec_exit(void)
{
	if (dpa_ipsec_cdev_major < 0)
		return 0;

	device_destroy(ipsec_class, MKDEV(dpa_ipsec_cdev_major, 0));
	class_destroy(ipsec_class);
	unregister_chrdev(dpa_ipsec_cdev_major, DPA_IPSEC_CDEV);
	dpa_ipsec_cdev_major = -1;

	return 0;
}


int wrp_dpa_ipsec_open(struct inode *inode, struct file *filp)
{
	return 0;
}


int wrp_dpa_ipsec_release(struct inode *inode, struct file *filp)
{
	return 0;
}

long wrp_dpa_ipsec_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long args)
{
	return wrp_dpa_ipsec_do_ioctl(filp, cmd, args);
}

#ifdef CONFIG_COMPAT
long wrp_dpa_ipsec_ioctl_compat(struct file *filp, unsigned int cmd,
				unsigned long args)
{

	return wrp_dpa_ipsec_do_compat_ioctl(filp, cmd, args);
}
#endif

long wrp_dpa_ipsec_do_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long args)
{
	long ret = 0;

	switch (cmd) {
	case DPA_IPSEC_IOC_INIT: {
		struct ioc_dpa_ipsec_params kprm;

		/* Copy parameters from user-space */
		if (copy_from_user(&kprm, (void *)args, sizeof(kprm))) {
			log_err("Could not copy DPA IPSec init parameters\n");
			return -EINVAL;
		}

		ret = do_init_ioctl(&kprm);
		if (ret < 0)
			return ret;

		if (copy_to_user((void *)args, &kprm, sizeof(kprm))) {
			log_err("Could not copy to user the ID\n");
			return -EINVAL;
		}
		break;
	}

	case DPA_IPSEC_IOC_FREE: {
		int dpa_ipsec_id;
		if (copy_from_user(&dpa_ipsec_id, (int *)args, sizeof(int))) {
			log_err("Could not copy parameters\n");
			return -EINVAL;
		}
		ret = dpa_ipsec_free(dpa_ipsec_id);
		break;
	}

	case DPA_IPSEC_IOC_CREATE_SA: {
		ret = do_create_sa_ioctl((void *)args);
		break;
	}

	case DPA_IPSEC_IOC_REMOVE_SA: {
		int sa_id;
		if (copy_from_user(&sa_id, (int *)args, sizeof(int))) {
			log_err("Could not copy parameters\n");
			return -EINVAL;
		}
		ret = dpa_ipsec_remove_sa(sa_id);
		break;
	}

	case DPA_IPSEC_IOC_ADD_POLICY: {
		ret = do_add_rem_policy_ioctl((void *)args, true);
		break;
	}

	case DPA_IPSEC_IOC_REMOVE_POLICY: {
		ret = do_add_rem_policy_ioctl((void *)args, false);
		break;
	}

	case DPA_IPSEC_IOC_SA_REKEYING: {
		ret = do_sa_rekey_ioctl((void *)args);
		break;
	}

	case DPA_IPSEC_IOC_FLUSH_ALL_SA: {
		int dpa_ipsec_id;

		if (copy_from_user(&dpa_ipsec_id, (int *)args, sizeof(int))) {
			log_err("Could not copy parameters\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_flush_all_sa(dpa_ipsec_id);
		break;
	}

	case DPA_IPSEC_IOC_GET_SA_POLICIES: {
		ret = do_sa_get_policies_ioctl((void *)args);
		break;
	}

	case DPA_IPSEC_IOC_FLUSH_SA_POLICIES: {
		int sa_id;

		if (copy_from_user(&sa_id, (int *)args, sizeof(int))) {
			log_err("Could not copy SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_sa_flush_policies(sa_id);
		break;
	}

	case DPA_IPSEC_IOC_DISABLE_SA: {
		int sa_id;

		if (copy_from_user(&sa_id, (int *)args, sizeof(int))) {
			log_err("Could not copy SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_disable_sa(sa_id);
		break;
	}

	case DPA_IPSEC_IOC_GET_SA_STATS: {
		struct ioc_dpa_ipsec_sa_get_stats prm;

		if (copy_from_user(&prm,
				   (struct ioc_dpa_ipsec_sa_get_stats *)args,
				   sizeof(prm))) {
			log_err("Could not copy from user stats params\n");
			return -EINVAL;
		}

		if (prm.sa_id < 0) {
			log_err("Invalid input SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_sa_get_stats(prm.sa_id, &prm.sa_stats);
		if (ret < 0) {
			log_err("Getting stats failed\n");
			break;
		}

		if (copy_to_user((struct ioc_dpa_ipsec_sa_get_stats *)args,
				 &prm, sizeof(prm))) {
			log_err("Could not copy stats to user\n");
			return -EINVAL;
		}
		break;
	}

	case DPA_IPSEC_IOC_GET_STATS: {
		struct ioc_dpa_ipsec_instance_stats prm;

		if (copy_from_user(&prm,
				   (struct ioc_dpa_ipsec_instance_stats *)args,
				   sizeof(prm))) {
			log_err("Could not copy from user stats params\n");
			return -EINVAL;
		}

		if (prm.instance_id < 0) {
			log_err("Invalid instance id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_get_stats(prm.instance_id, &prm.stats);
		if (ret < 0) {
			log_err("Failed to get statistics for instance %d\n",
				prm.instance_id);
			break;
		}

		if (copy_to_user((struct ioc_dpa_ipsec_instance_stats *)args,
				 &prm, sizeof(prm))) {
			log_err("Could not copy stats to user\n");
			return -EINVAL;
		}
		break;
	}

	case DPA_IPSEC_IOC_SA_MODIFY: {
		struct dpa_ipsec_sa_modify_prm modify_prm;
		int sa_id, ret;

		ret = do_sa_modify_ioctl(args, &sa_id, &modify_prm);

		if (IS_ERR_VALUE(ret))
			goto free;

		ret = dpa_ipsec_sa_modify(sa_id, &modify_prm);
		if (IS_ERR_VALUE(ret))
			log_err("Modifying SA %d failed\n", sa_id);
free:
		if (modify_prm.type == DPA_IPSEC_SA_MODIFY_CRYPTO) {
			kfree(modify_prm.crypto_params.cipher_key);
			kfree(modify_prm.crypto_params.auth_key);
		}
		break;
	}

	case DPA_IPSEC_IOC_SA_REQUEST_SEQ_NUMBER: {
		int sa_id;

		if (copy_from_user(&sa_id, (int *)args, sizeof(int))) {
			log_err("Could not copy SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_sa_request_seq_number(sa_id);
		break;
	}

	case DPA_IPSEC_IOC_SA_GET_SEQ_NUMBER: {
		struct ioc_dpa_ipsec_sa_get_seq_num prm;

		if (copy_from_user(&prm,
				   (struct ioc_dpa_ipsec_sa_get_seq_num *)args,
				   sizeof(prm))) {
			log_err("Could not copy from user stats params\n");
			return -EINVAL;
		}

		if (prm.sa_id < 0) {
			log_err("Invalid input SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_sa_get_seq_number(prm.sa_id, &prm.seq);
		if (ret < 0) {
			log_err("Get SEQ number for SA %d failed\n", prm.sa_id);
			break;
		}

		if (copy_to_user((struct ioc_dpa_ipsec_sa_get_seq_num *)args,
				 &prm, sizeof(prm))) {
			log_err("Could not copy SEQ number to user for SA %d\n",
				prm.sa_id);
			return -EINVAL;
		}
		break;
	}

	case DPA_IPSEC_IOC_SA_GET_OUT_PATH: {
		struct ioc_dpa_ipsec_sa_get_out_path prm;

		if (copy_from_user(&prm,
				(struct ioc_dpa_ipsec_sa_get_out_path *)args,
				sizeof(prm))) {
			log_err("Could not copy from user out_path params\n");
			return -EINVAL;
		}

		if (prm.sa_id < 0) {
			log_err("Invalid input SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_sa_get_out_path(prm.sa_id, &prm.fqid);
		if (ret < 0) {
			log_err("Get out path for SA %d failed\n", prm.sa_id);
			break;
		}

		if (copy_to_user((struct ioc_dpa_ipsec_sa_get_out_path *)args,
				 &prm, sizeof(prm))) {
			log_err("Could not copy out_path to user for SA %d\n",
				prm.sa_id);
			return -EINVAL;
		}

		break;
	}

	default:
		log_err("Invalid DPA IPsec ioctl (0x%x)\n", cmd);
		ret = -EINVAL;
		break;
	}

	return ret;
}

#ifdef CONFIG_COMPAT
long wrp_dpa_ipsec_do_compat_ioctl(struct file *filp, unsigned int cmd,
				   unsigned long args)
{
	long ret = 0;

	switch (cmd) {
	case DPA_IPSEC_IOC_INIT_COMPAT: {
		struct ioc_dpa_ipsec_params kprm;
		struct ioc_compat_dpa_ipsec_params uprm;

		if (copy_from_user(&uprm, (void *)args, sizeof(uprm))) {
			log_err("Could not copy DPA IPSec init parameters\n");
			return -EINVAL;
		}
		compat_copy_dpa_ipsec_init(&kprm, &uprm);

		ret = do_init_ioctl(&kprm);
		if (ret < 0)
			return ret;

		uprm.dpa_ipsec_id = kprm.dpa_ipsec_id;
		if (copy_to_user((void *)args, &uprm, sizeof(uprm))) {
			log_err("Could not copy to user the DPA IPSec ID\n");
			return -EINVAL;
		}
		break;
	}

	case DPA_IPSEC_IOC_FREE: {
		int dpa_ipsec_id;
		if (copy_from_user(&dpa_ipsec_id, (int *)args, sizeof(int))) {
			log_err("Could not copy parameters\n");
			return -EINVAL;
		}
		ret = dpa_ipsec_free(dpa_ipsec_id);
		break;
	}

	case DPA_IPSEC_IOC_CREATE_SA_COMPAT: {
		ret = do_create_sa_compat_ioctl((void *)args);
		break;
	}

	case DPA_IPSEC_IOC_REMOVE_SA: {
		int sa_id;
		if (copy_from_user(&sa_id, (int *)args, sizeof(int))) {
			log_err("Could not copy parameters\n");
			return -EINVAL;
		}
		ret = dpa_ipsec_remove_sa(sa_id);
		break;
	}

	case DPA_IPSEC_IOC_ADD_POLICY_COMPAT: {
		ret = do_add_rem_policy_compat_ioctl((void *)args, true);
		break;
	}

	case DPA_IPSEC_IOC_REMOVE_POLICY_COMPAT: {
		ret = do_add_rem_policy_compat_ioctl((void *)args, false);
		break;
	}

	case DPA_IPSEC_IOC_SA_REKEYING_COMPAT: {
		ret = do_sa_rekey_compat_ioctl((void *)args);
		break;
	}

	case DPA_IPSEC_IOC_FLUSH_ALL_SA: {
		int dpa_ipsec_id;

		if (copy_from_user(&dpa_ipsec_id,
				    (int *)args, sizeof(int))) {
			log_err("Could not copy parameters\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_flush_all_sa(dpa_ipsec_id);
		break;
	}

	case DPA_IPSEC_IOC_GET_SA_POLICIES_COMPAT: {
		ret = do_sa_get_policies_compat_ioctl((void *)args);
		break;
	}

	case DPA_IPSEC_IOC_FLUSH_SA_POLICIES: {
		int sa_id;

		if (copy_from_user(&sa_id, (int *)args, sizeof(int))) {
			log_err("Could not copy SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_sa_flush_policies(sa_id);
		break;
	}

	case DPA_IPSEC_IOC_DISABLE_SA: {
		int sa_id;

		if (copy_from_user(&sa_id, (int *)args, sizeof(int))) {
			log_err("Could not copy SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_disable_sa(sa_id);
		break;
	}

	case DPA_IPSEC_IOC_GET_SA_STATS: {
		struct ioc_dpa_ipsec_sa_get_stats prm;

		if (copy_from_user(&prm,
				(struct ioc_dpa_ipsec_sa_get_stats *)args,
				sizeof(prm))) {
			log_err("Could not copy from user stats params\n");
			return -EINVAL;
		}

		if (prm.sa_id < 0) {
			log_err("Invalid input SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_sa_get_stats(prm.sa_id, &prm.sa_stats);
		if (ret < 0) {
			log_err("Getting stats failed\n");
			break;
		}

		if (copy_to_user((struct ioc_dpa_ipsec_sa_get_stats *)args,
				 &prm, sizeof(prm))) {
			log_err("Could not copy stats to user\n");
			return -EINVAL;
		}

		break;
	}

	case DPA_IPSEC_IOC_GET_STATS: {
		struct ioc_dpa_ipsec_instance_stats prm;

		if (copy_from_user(&prm,
				   (struct ioc_dpa_ipsec_instance_stats *)args,
				   sizeof(prm))) {
			log_err("Could not copy from user stats params\n");
			return -EINVAL;
		}

		if (prm.instance_id < 0) {
			log_err("Invalid instance id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_get_stats(prm.instance_id, &prm.stats);
		if (ret < 0) {
			log_err("Failed to get statistics for instance %d\n",
				prm.instance_id);
			break;
		}

		if (copy_to_user((struct ioc_dpa_ipsec_instance_stats *)args,
				 &prm, sizeof(prm))) {
			log_err("Could not copy stats to user\n");
			return -EINVAL;
		}
		break;


	}

	case DPA_IPSEC_IOC_SA_MODIFY_COMPAT: {
		struct dpa_ipsec_sa_modify_prm modify_prm;
		int sa_id, ret;

		ret = do_sa_modify_ioctl_compat(args, &sa_id, &modify_prm);
		if (IS_ERR_VALUE(ret))
			goto free;

		ret = dpa_ipsec_sa_modify(sa_id, &modify_prm);
		if (IS_ERR_VALUE(ret))
			log_err("Modifying SA %d failed\n", sa_id);
free:
		if (modify_prm.type == DPA_IPSEC_SA_MODIFY_CRYPTO) {
			kfree(modify_prm.crypto_params.cipher_key);
			kfree(modify_prm.crypto_params.auth_key);
		}

		break;
	}

	case DPA_IPSEC_IOC_SA_REQUEST_SEQ_NUMBER: {
		int sa_id;

		if (copy_from_user(&sa_id, (int *)args, sizeof(int))) {
			log_err("Could not copy SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_sa_request_seq_number(sa_id);
		break;
	}

	case DPA_IPSEC_IOC_SA_GET_SEQ_NUMBER: {
		struct ioc_dpa_ipsec_sa_get_seq_num prm;

		if (copy_from_user(&prm,
				   (struct ioc_dpa_ipsec_sa_get_seq_num *)args,
				   sizeof(prm))) {
			log_err("Could not copy from user stats params\n");
			return -EINVAL;
		}

		if (prm.sa_id < 0) {
			log_err("Invalid input SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_sa_get_seq_number(prm.sa_id, &prm.seq);
		if (ret < 0) {
			log_err("Get SEQ number for SA %d failed\n", prm.sa_id);
			break;
		}

		if (copy_to_user((struct ioc_dpa_ipsec_sa_get_seq_num *)args,
				 &prm, sizeof(prm))) {
			log_err("Could not copy SEQ number to user for SA %d\n",
				prm.sa_id);
			return -EINVAL;
		}
		break;
	}

	case DPA_IPSEC_IOC_SA_GET_OUT_PATH: {
		struct ioc_dpa_ipsec_sa_get_out_path prm;

		if (copy_from_user(&prm,
				(struct ioc_dpa_ipsec_sa_get_out_path *)args,
				sizeof(prm))) {
			log_err("Could not copy from user out_path params\n");
			return -EINVAL;
		}

		if (prm.sa_id < 0) {
			log_err("Invalid input SA id\n");
			return -EINVAL;
		}

		ret = dpa_ipsec_sa_get_out_path(prm.sa_id, &prm.fqid);
		if (ret < 0) {
			log_err("Get out path for SA %d failed\n", prm.sa_id);
			break;
		}

		if (copy_to_user((struct ioc_dpa_ipsec_sa_get_out_path *)args,
				 &prm, sizeof(prm))) {
			log_err("Could not copy out_path to user for SA %d\n",
				prm.sa_id);
			return -EINVAL;
		}

		break;
	}

	default:
		log_err("Invalid DPA IPsec ioctl (0x%x)\n", cmd);
		ret = -EINVAL;
		break;
	}

	return ret;
}
#endif

int default_rekey_event_cb(int dpa_ipsec_id, int sa_id, int error)
{
	pr_info("DPA IPSec Instance %d || new sa_id %d || error %d\n",
		dpa_ipsec_id, sa_id, error);
	return 0;
}
