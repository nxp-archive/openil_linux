
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
 * DPA Classifier Wrapper implementation.
 */

/* DPA offloading layer includes */
#include <linux/fsl_dpa_classifier.h>
#include "wrp_dpa_classifier.h"
#include "dpa_classifier_ioctl.h"

/* Other includes */
#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include <linux/export.h>
#include "lnxwrp_fm.h"
#include "fm_pcd_ioctls.h"
#include "fm_port_ioctls.h"
#ifdef CONFIG_COMPAT
#include "lnxwrp_ioctls_fm_compat.h"
#endif /* CONFIG_COMPAT */


#define COPY_KEY_PARAMS							\
do {									\
	if ((kparam.key.size <= 0) ||					\
			(kparam.key.size > DPA_OFFLD_MAXENTRYKEYSIZE)) { \
		log_err("Invalid lookup key size (%d bytes).\n",	\
			kparam.key.size);				\
		return -EINVAL;						\
	}								\
									\
	if (copy_from_user(key_buf, kparam.key.byte,			\
						kparam.key.size)) {	\
		log_err("Read failed: lookup key.\n");			\
		return -EBUSY;						\
	}								\
	kparam.key.byte = key_buf;					\
									\
	if (kparam.key.mask) {						\
		if (copy_from_user(mask_buf, kparam.key.mask,		\
						kparam.key.size)) {	\
			log_err("Read failed: key mask.\n");		\
			return -EBUSY;					\
		}							\
									\
		kparam.key.mask = mask_buf;				\
	}								\
} while (0)

#define COPY_NEW_KEY_PARAMS						\
do {									\
	if (kparam.mod_params.key) {					\
		if (copy_from_user(&new_key,				\
				kparam.mod_params.key,			\
			sizeof(struct dpa_offload_lookup_key))) {	\
			log_err("Read failed: new lookup key.\n");	\
			return -EBUSY;					\
		}							\
		kparam.mod_params.key = &new_key;			\
									\
		if ((kparam.mod_params.key->size <= 0) ||		\
			(kparam.mod_params.key->size >			\
				DPA_OFFLD_MAXENTRYKEYSIZE)) {		\
			log_err("Invalid new lookup key size (%d "	\
				"bytes).\n",				\
				kparam.mod_params.key->size);		\
			return -EINVAL;					\
		}							\
									\
		if (kparam.mod_params.key->byte) {			\
			if (copy_from_user(new_key_buf,			\
				kparam.mod_params.key->byte,		\
				kparam.mod_params.key->size)) {		\
				log_err("Read failed: new lookup key "	\
					"data.\n");			\
				return -EBUSY;				\
			}						\
			kparam.mod_params.key->byte = new_key_buf;	\
		}							\
		if (kparam.mod_params.key->mask) {			\
			if (copy_from_user(new_mask_buf,		\
				kparam.mod_params.key->mask,		\
				kparam.mod_params.key->size)) {		\
				log_err("Read failed: new key mask.\n");\
				return -EBUSY;				\
			}						\
			kparam.mod_params.key->mask = new_mask_buf;	\
		}							\
	}								\
} while (0)

#ifdef DPA_CLASSIFIER_WRP_DEBUG
#define dpa_cls_wrp_dbg(message) printk message
#else
#define dpa_cls_wrp_dbg(message)
#endif /* DPA_CLASSIFIER_DEBUG */


static long do_ioctl_table_create(unsigned long args, bool compat_mode);

static long do_ioctl_table_modify_miss_action(unsigned long	args,
						bool		compat_mode);

static long do_ioctl_table_insert_entry(unsigned long args, bool compat_mode);

static long do_ioctl_table_modify_entry_by_key(unsigned long	args,
						bool		compat_mode);

static long do_ioctl_table_modify_entry_by_ref(unsigned long	args,
						bool		compat_mode);

static long do_ioctl_table_lookup_by_key(unsigned long args, bool compat_mode);

static long do_ioctl_table_lookup_by_ref(unsigned long args, bool compat_mode);

static long do_ioctl_table_delete_entry_by_key(unsigned long	args,
						bool		compat_mode);

static long do_ioctl_table_get_stats_by_key(unsigned long	args,
						bool		compat_mode);

static long do_ioctl_set_remove_hm(unsigned long	args,
				bool			compat_mode);

static long do_ioctl_modify_remove_hm(unsigned long	args,
				bool			compat_mode);

static long do_ioctl_set_insert_hm(unsigned long	args,
				bool			compat_mode);

static long do_ioctl_modify_insert_hm(unsigned long	args,
				bool			compat_mode);

static long do_ioctl_set_vlan_hm(unsigned long args, bool compat_mode);

static long do_ioctl_modify_vlan_hm(unsigned long args, bool compat_mode);

static long do_ioctl_set_nat_hm(unsigned long args, bool compat_mode);

static long do_ioctl_modify_nat_hm(unsigned long args, bool compat_mode);

static long do_ioctl_set_update_hm(unsigned long args, bool compat_mode);

static long do_ioctl_modify_update_hm(unsigned long args, bool compat_mode);

static long do_ioctl_set_fwd_hm(unsigned long args, bool compat_mode);

static long do_ioctl_modify_fwd_hm(unsigned long args, bool compat_mode);

static long do_ioctl_set_mpls_hm(unsigned long args, bool compat_mode);

static long do_ioctl_modify_mpls_hm(unsigned long args, bool compat_mode);

static long do_ioctl_mcast_create_group(unsigned long args, bool compat_mode);

static long do_ioctl_mcast_add_member(unsigned long args, bool compat_mode);

void *translate_fm_pcd_handle(void *fm_pcd);

static const struct file_operations dpa_classif_fops = {
	.owner			= THIS_MODULE,
	.open			= wrp_dpa_classif_open,
	.read			= wrp_dpa_classif_read,
	.write			= wrp_dpa_classif_write,
	.unlocked_ioctl		= wrp_dpa_classif_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= wrp_dpa_classif_compat_ioctl,
#endif /* CONFIG_COMPAT */
	.release		= wrp_dpa_classif_release
};

static int dpa_cls_cdev_major = -1;
static struct class *classifier_class;
static struct device *classifier_dev;


int	wrp_dpa_classif_init(void)
{
	/* Cannot initialize the wrapper twice */
	if (dpa_cls_cdev_major >= 0)
		return 0;

	dpa_cls_cdev_major = register_chrdev(
					0,
					WRP_DPA_CLS_CDEVNAME,
					&dpa_classif_fops);
	if (dpa_cls_cdev_major < 0) {
		log_err("Could not register DPA Classifier Control Device.\n");
		return -EBUSY;
	}

	classifier_class = class_create(THIS_MODULE, WRP_DPA_CLS_CLASS_NAME);
	if (IS_ERR(classifier_class)) {
		log_err("Failed to create the DPA classifier class device\n");
		unregister_chrdev(dpa_cls_cdev_major, WRP_DPA_CLS_CDEVNAME);
		dpa_cls_cdev_major = -1;
		return PTR_ERR(classifier_class);
	}

	classifier_dev = device_create(	classifier_class,
					NULL,
					MKDEV(dpa_cls_cdev_major, 0),
					NULL,
					WRP_DPA_CLS_CDEVNAME);
	if (IS_ERR(classifier_dev)) {
		log_err("Failed to create the DPA Classifier device\n");
		class_destroy(classifier_class);
		unregister_chrdev(dpa_cls_cdev_major, WRP_DPA_CLS_CDEVNAME);
		dpa_cls_cdev_major = -1;
		return PTR_ERR(classifier_dev);
	}

	return 0;
}


int wrp_dpa_classif_exit(void)
{
	if (dpa_cls_cdev_major < 0)
		return 0;

	device_destroy(classifier_class, MKDEV(dpa_cls_cdev_major, 0));
	class_destroy(classifier_class);

	unregister_chrdev(dpa_cls_cdev_major, WRP_DPA_CLS_CDEVNAME);

	dpa_cls_cdev_major = -1;

	return 0;
}


int wrp_dpa_classif_open(struct inode *inode, struct file *filp)
{
	return 0;
}


int wrp_dpa_classif_release(struct inode *inode, struct file *filp)
{
	return 0;
}


ssize_t wrp_dpa_classif_read(
			struct file	*filp,
			char __user	*buf,
			size_t		len,
			loff_t		*offp)
{
	return 0;
}


ssize_t wrp_dpa_classif_write(
			struct file		*filp,
			const char __user	*buf,
			size_t			len,
			loff_t			*offp)
{
	return 0;
}


#ifdef CONFIG_COMPAT
long wrp_dpa_classif_compat_ioctl(
		struct file	*filp,
		unsigned int	cmd,
		unsigned long	args)
{
	return wrp_dpa_classif_do_ioctl(filp, cmd, args, true);
}
#endif /* CONFIG_COMPAT */


long wrp_dpa_classif_ioctl(
		struct file	*filp,
		unsigned int	cmd,
		unsigned long	args)
{
	return wrp_dpa_classif_do_ioctl(filp, cmd, args, false);
}


long wrp_dpa_classif_do_ioctl(
			struct file	*filp,
			unsigned int	cmd,
			unsigned long	args,
			bool		compat_mode)
{
	long ret = 0;


	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) --> Processing ioctl "
		"cmd=0x%x\n", __func__, __LINE__, cmd));

	switch (cmd) {
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_TBL_CREATE:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_TBL_CREATE:
		ret = do_ioctl_table_create(args, compat_mode);
		break;

	case DPA_CLS_IOC_TBL_FREE:
		ret = dpa_classif_table_free((int)args);
		break;

#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_TBL_MODIFY_MISS_ACTION:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_TBL_MODIFY_MISS_ACTION:
		ret = do_ioctl_table_modify_miss_action(args, compat_mode);
		break;

#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_TBL_INSERT_ENTRY:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_TBL_INSERT_ENTRY:
		ret = do_ioctl_table_insert_entry(args, compat_mode);
		break;

#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_TBL_MODIFY_ENTRY_BY_KEY:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_TBL_MODIFY_ENTRY_BY_KEY:
		ret = do_ioctl_table_modify_entry_by_key(args, compat_mode);
		break;

#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_TBL_MODIFY_ENTRY_BY_REF:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_TBL_MODIFY_ENTRY_BY_REF:
		ret = do_ioctl_table_modify_entry_by_ref(args, compat_mode);
		break;

#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_TBL_DELETE_ENTRY_BY_KEY:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_TBL_DELETE_ENTRY_BY_KEY:
		ret = do_ioctl_table_delete_entry_by_key(args, compat_mode);
		break;

	case DPA_CLS_IOC_TBL_DELETE_ENTRY_BY_REF:
	{
		struct ioc_dpa_cls_tbl_entry_by_ref param;

		dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d): "
			"delete_entry_by_ref\n", __func__, __LINE__));

		/* Prepare arguments */
		if (copy_from_user(&param, (void *) args, sizeof(param))) {
			log_err("Read failed: "
				"dpa_classif_table_delete_entry_by_ref user "
				"space args.\n");
			return -EBUSY;
		}

		/* Call function */
		ret = dpa_classif_table_delete_entry_by_ref(param.td,
							    param.entry_id);

		break;
	}

#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_TBL_LOOKUP_BY_KEY:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_TBL_LOOKUP_BY_KEY:
		ret = do_ioctl_table_lookup_by_key(args, compat_mode);
		break;

#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_TBL_LOOKUP_BY_REF:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_TBL_LOOKUP_BY_REF:
		ret = do_ioctl_table_lookup_by_ref(args, compat_mode);
		break;

	case DPA_CLS_IOC_TBL_FLUSH:
		ret = dpa_classif_table_flush((int)args);
		break;

#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_TBL_GET_STATS_BY_KEY:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_TBL_GET_STATS_BY_KEY:
		ret = do_ioctl_table_get_stats_by_key(args, compat_mode);
		break;

	case DPA_CLS_IOC_TBL_GET_STATS_BY_REF:
	{
		struct ioc_dpa_cls_tbl_entry_stats_by_ref param;

		dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d): "
			"get_stats_by_ref\n", __func__, __LINE__));

		/* Prepare arguments */
		if (copy_from_user(&param, (void *) args, sizeof(param))) {
			log_err("Read failed: "
				"dpa_classif_table_get_entry_stats_by_ref user "
				"space args.\n");
			return -EBUSY;
		}

		/* Call function */
		ret = dpa_classif_table_get_entry_stats_by_ref(param.td,
							       param.entry_id,
							       &param.stats);
		if (ret < 0)
			return ret;

		/* Return results to user space */
		if (copy_to_user((void *) args, &param, sizeof(param))) {
			log_err("Write failed: "
				"dpa_classif_table_get_entry_stats_by_ref "
				"result.\n");
			return -EBUSY;
		}

		break;
	}

	case DPA_CLS_IOC_TBL_GET_MISS_STATS:
	{
		struct ioc_dpa_cls_tbl_miss_stats param;

		dpa_cls_wrp_dbg((
			"DEBUG: classifier_wrp %s (%d): get_miss_stats\n",
			__func__, __LINE__));

		/* Prepare arguments */
		if (copy_from_user(&param, (void *) args, sizeof(param))) {
			log_err("Read failed: dpa_classif_table_get_miss_stats user space args.\n");
			return -EBUSY;
		}

		/* Call function */
		ret = dpa_classif_table_get_miss_stats(param.td, &param.stats);
		if (ret < 0)
			return ret;

		/* Return results to user space */
		if (copy_to_user((void *) args, &param, sizeof(param))) {
			log_err("Write failed: dpa_classif_table_get_miss_stats result.\n");
			return -EBUSY;
		}

		break;
	}

#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_TBL_GET_PARAMS:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_TBL_GET_PARAMS:
	{
		struct ioc_dpa_cls_tbl_params kparam;
#ifdef CONFIG_COMPAT
		struct compat_ioc_dpa_cls_tbl_params uparam;

		/* Prepare arguments */
		if (compat_mode) {
			if (copy_from_user(&uparam, (void *) args,
							sizeof(uparam))) {
				log_err("Read failed: "
					"dpa_classif_table_lookup_by_key user "
					"space args.\n");
				return -EBUSY;
			}

			/* Transfer the data into the kernel space params: */
			kparam.td = uparam.td;
		} else
#endif /* CONFIG_COMPAT */
		/* Prepare arguments */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: "
				"dpa_classif_table_lookup_by_key user space "
				"args.\n");
			return -EBUSY;
		}

		dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d): "
			"table_get_params\n", __func__, __LINE__));

		/* Call function */
		ret = dpa_classif_table_get_params(kparam.td,
						&kparam.table_params);
		if (ret < 0)
			return ret;

#ifdef CONFIG_COMPAT
	if (compat_mode) {
		ret = dpa_cls_tbl_params_rcompatcpy(&uparam, &kparam);
		if (ret < 0)
			return ret;

		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: "
				"dpa_classif_table_get_params result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		/* Return results to user space */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: "
				"dpa_classif_table_get_params result.\n");
			return -EBUSY;
		}

		break;
	}
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_SET_REMOVE_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_SET_REMOVE_HM:
		ret = do_ioctl_set_remove_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_MODIFY_REMOVE_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_MODIFY_REMOVE_HM:
		ret = do_ioctl_modify_remove_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_SET_INSERT_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_SET_INSERT_HM:
		ret = do_ioctl_set_insert_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_MODIFY_INSERT_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_MODIFY_INSERT_HM:
		ret = do_ioctl_modify_insert_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_SET_VLAN_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_SET_VLAN_HM:
		ret = do_ioctl_set_vlan_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_MODIFY_VLAN_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_MODIFY_VLAN_HM:
		ret = do_ioctl_modify_vlan_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_SET_NAT_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_SET_NAT_HM:
		ret = do_ioctl_set_nat_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_MODIFY_NAT_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_MODIFY_NAT_HM:
		ret = do_ioctl_modify_nat_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_SET_UPDATE_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_SET_UPDATE_HM:
		ret = do_ioctl_set_update_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_MODIFY_UPDATE_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_MODIFY_UPDATE_HM:
		ret = do_ioctl_modify_update_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_SET_FWD_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_SET_FWD_HM:
		ret = do_ioctl_set_fwd_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_MODIFY_FWD_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_MODIFY_FWD_HM:
		ret = do_ioctl_modify_fwd_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_SET_MPLS_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_SET_MPLS_HM:
		ret = do_ioctl_set_mpls_hm(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_MODIFY_MPLS_HM:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_MODIFY_MPLS_HM:
		ret = do_ioctl_modify_mpls_hm(args, compat_mode);
		break;
	case DPA_CLS_IOC_FREE_HM:
		ret = dpa_classif_free_hm((int)args);
		break;
#ifdef CONFIG_COMPAT
	case	DPA_CLS_IOC_COMPAT_MCAST_CREATE_GROUP:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_MCAST_CREATE_GROUP:
		ret = do_ioctl_mcast_create_group(args, compat_mode);
		break;
#ifdef CONFIG_COMPAT
	case DPA_CLS_IOC_COMPAT_MCAST_ADD_MEMBER:
#endif /* CONFIG_COMPAT */
	case DPA_CLS_IOC_MCAST_ADD_MEMBER:
		ret = do_ioctl_mcast_add_member(args, compat_mode);
		break;
	case DPA_CLS_IOC_MCAST_REMOVE_MEMBER: {
		struct ioc_dpa_cls_mcast_remove_params params;
		int sz;
		sz = sizeof(struct ioc_dpa_cls_mcast_remove_params);
		if (copy_from_user(&params,
				 (struct ioc_dpa_cls_mcast_remove_params *)args,
				 sz)) {
			log_err("Could not copy parameters.\n");
			return -EINVAL;
			}
#if (DPAA_VERSION >= 11)
		ret = dpa_classif_mcast_remove_member(params.grpd,
						      params.md);
#else
		log_err("Multicast not supported on this platform.\n");
		ret = -EINVAL;
		return ret;
#endif
		break;
	}
	case DPA_CLS_IOC_MCAST_FREE_GROUP: {
		int grpd;
		if (copy_from_user(&grpd, (int *)args, sizeof(int))) {
			log_err("Could not copy parameters.\n");
			return -EINVAL;
		}
#if (DPAA_VERSION >= 11)
		ret = dpa_classif_mcast_free_group(grpd);
		if (ret < 0)
			return ret;
#else
		log_err("Multicast not supported  on this platform.\n");
		ret = -EINVAL;
		return ret;
#endif
		break;
	}
	default:
		log_err("DPA Classifier ioctl command (0x%x) not supported.\n",
			cmd);
		return -EINVAL;
	}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d): Done <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_table_create(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_tbl_params kparam;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_tbl_params uparam;

	/* Prepare arguments */
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		memset(&kparam, 0, sizeof(struct ioc_dpa_cls_tbl_params));
		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_tbl_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;
	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	/* Call function */
	ret = dpa_classif_table_create(&kparam.table_params,
					&kparam.td);
	if (ret < 0)
		return ret;

	/* Return results to user space */
#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.td = kparam.td;
		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_set_remove_hm(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_hm_remove_params kparam;
	struct dpa_cls_hm_remove_resources *p_res = NULL;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_hm_remove_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_remove_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	if (kparam.res.remove_node)
		p_res = &kparam.res;

	/* Translate FM_PCD file descriptor */
	if (!p_res) {
		kparam.rm_params.fm_pcd =
			translate_fm_pcd_handle(kparam.rm_params.fm_pcd);
		if (!kparam.rm_params.fm_pcd)
			return -EINVAL;
	}

	ret = dpa_classif_set_remove_hm(&kparam.rm_params, kparam.next_hmd,
					&kparam.hmd, kparam.chain_head,
					p_res);
	if (ret < 0)
		return ret;

	/* Return results to user space */
#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.hmd = kparam.hmd;
		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_modify_remove_hm(unsigned long args, bool compat_mode)
{
	struct ioc_dpa_cls_hm_remove_params kparam;
#ifdef CONFIG_COMPAT
	long ret = 0;
	struct compat_ioc_dpa_cls_hm_remove_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_remove_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d)\n", __func__,
		__LINE__));

	return dpa_classif_modify_remove_hm(kparam.hmd, &kparam.rm_params,
					   kparam.modify_flags);
}

static long do_ioctl_set_insert_hm(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_hm_insert_params kparam;
	struct dpa_cls_hm_insert_resources *p_res = NULL;
	uint8_t *data = NULL;
	uint8_t sz;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_hm_insert_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_insert_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	if (kparam.res.insert_node)
		p_res = &kparam.res;

	/* Translate FM_PCD file descriptor */
	if (!p_res) {
		kparam.ins_params.fm_pcd =
			translate_fm_pcd_handle(kparam.ins_params.fm_pcd);
		if (!kparam.ins_params.fm_pcd)
			return -EINVAL;
	}

	if (kparam.ins_params.type == DPA_CLS_HM_INSERT_CUSTOM) {
		sz = kparam.ins_params.custom.size;
		data =	kzalloc(sz * sizeof(*data), GFP_KERNEL);
		if (!data) {
			log_err("Failed to allocate memory for  data param for "
				"DPA_CLS_HM_INSERT_CUSTOM parameter type.\n");
			return -ENOMEM;
		}

		copy_from_user(data, kparam.ins_params.custom.data, sz);
		kparam.ins_params.custom.data = data;
	}

	ret = dpa_classif_set_insert_hm(&kparam.ins_params, kparam.next_hmd,
					&kparam.hmd, kparam.chain_head,
					p_res);
	kfree(data);
	if (ret < 0)
			return ret;

#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.hmd = kparam.hmd;
		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_modify_insert_hm(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_hm_insert_params kparam;
	uint8_t *data = NULL;
	uint8_t sz;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_hm_insert_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_insert_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	if (kparam.ins_params.type == DPA_CLS_HM_INSERT_CUSTOM) {
		sz = kparam.ins_params.custom.size;
		data =	kzalloc(sz * sizeof(*data), GFP_KERNEL);
		if (!data) {
			log_err("Failed to allocate memory for data param for "
				"DPA_CLS_HM_INSERT_CUSTOM parameter type.\n");
			return -ENOMEM;
		}

		copy_from_user(data, kparam.ins_params.custom.data, sz);
		kparam.ins_params.custom.data = data;
	}

	ret = dpa_classif_modify_insert_hm(kparam.hmd, &kparam.ins_params,
					   kparam.modify_flags);
	kfree(data);

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long  do_ioctl_set_vlan_hm(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_hm_vlan_params kparam;
	struct dpa_cls_hm_vlan_resources *p_res = NULL;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_hm_vlan_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_vlan_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	if (kparam.res.vlan_node)
		p_res = &kparam.res;

	/* Translate FM_PCD file descriptor */
	if (!p_res) {
		kparam.vlan_params.fm_pcd =
			translate_fm_pcd_handle(kparam.vlan_params.fm_pcd);
		if (!kparam.vlan_params.fm_pcd)
			return -EINVAL;
	}

	ret = dpa_classif_set_vlan_hm(&kparam.vlan_params, kparam.next_hmd,
				      &kparam.hmd, kparam.chain_head,
				      p_res);
	if (ret < 0)
			return ret;

#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.hmd = kparam.hmd;
		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;

}

static long do_ioctl_modify_vlan_hm(unsigned long args, bool compat_mode)
{
	struct ioc_dpa_cls_hm_vlan_params kparam;
#ifdef CONFIG_COMPAT
	long ret = 0;
	struct compat_ioc_dpa_cls_hm_vlan_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_vlan_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif
	if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
		log_err("Read failed: user space args.\n");
		return -EBUSY;
	}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d)\n", __func__,
		__LINE__));

	return dpa_classif_modify_vlan_hm(kparam.hmd, &kparam.vlan_params,
					kparam.modify_flags);
}

static long do_ioctl_set_nat_hm(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_hm_nat_params kparam;
	struct dpa_cls_hm_nat_resources *p_res = NULL;
	int type;
	unsigned int sz;
	uint8_t *options = NULL;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_hm_nat_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_nat_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	if (kparam.res.l3_update_node || kparam.res.l4_update_node)
		p_res = &kparam.res;

	/* Translate FM_PCD file descriptor */
	if (!p_res) {
		kparam.nat_params.fm_pcd =
			translate_fm_pcd_handle(kparam.nat_params.fm_pcd);
		if (!kparam.nat_params.fm_pcd)
			return -EINVAL;
	}

	if (kparam.nat_params.type == DPA_CLS_HM_NAT_TYPE_NAT_PT) {
		type = kparam.nat_params.nat_pt.type;
		if (type == DPA_CLS_HM_NAT_PT_IPv6_TO_IPv4) {
			sz = kparam.nat_params.nat_pt.new_header.ipv4.
				options_size;
			options = kzalloc(sz * sizeof(*options), GFP_KERNEL);
			if (!options) {
				log_err("Failed to allocate memory for "
					"options param for "
					"DPA_CLS_HM_NAT_TYPE_NAT_PT parameter "
					"type.\n");
				return -ENOMEM;
			}
			copy_from_user(options,
					kparam.nat_params.nat_pt.new_header.
					ipv4.options, sz);
			kparam.nat_params.nat_pt.new_header.ipv4.options =
									options;
		}
	}

	ret =  dpa_classif_set_nat_hm(&kparam.nat_params, kparam.next_hmd,
				      &kparam.hmd, kparam.chain_head,
				      p_res);
	kfree(options);
	if (ret < 0)
			return ret;

#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.hmd = kparam.hmd;
		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_modify_nat_hm(unsigned long args, bool compat_mode)
{
	struct ioc_dpa_cls_hm_nat_params kparam;
	uint8_t *options = NULL;
	long ret = 0;
	int type;
	unsigned int sz;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_hm_nat_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_nat_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	if (kparam.nat_params.type == DPA_CLS_HM_NAT_TYPE_NAT_PT) {
		type = kparam.nat_params.nat_pt.type;
		if (type == DPA_CLS_HM_NAT_PT_IPv6_TO_IPv4) {
			sz = kparam.nat_params.nat_pt.new_header.ipv4.
				options_size;
			options = kzalloc(sz * sizeof(*options), GFP_KERNEL);
			if (!options) {
				log_err("Failed to allocate memory for "
					"options param for "
					"DPA_CLS_HM_NAT_TYPE_NAT_PT parameter "
					"type.\n");
				return -ENOMEM;
			}
			copy_from_user(options,
					kparam.nat_params.nat_pt.new_header.
					ipv4.options, sz);
			kparam.nat_params.nat_pt.new_header.ipv4.options =
									options;
		}
	}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d)\n", __func__,
		__LINE__));

	ret = dpa_classif_modify_nat_hm(kparam.hmd, &kparam.nat_params,
					kparam.modify_flags);
	kfree(options);

	return ret;
}

static long do_ioctl_set_update_hm(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_hm_update_params kparam;
	struct dpa_cls_hm_update_resources *p_res = NULL;
	unsigned int sz;
	uint8_t *options = NULL;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_hm_update_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_update_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	if (kparam.res.ip_frag_node || kparam.res.update_node)
		p_res = &kparam.res;

	/* Translate FM_PCD file descriptor */
	if (!p_res) {
		kparam.update_params.fm_pcd =
			translate_fm_pcd_handle(kparam.update_params.fm_pcd);
		if (!kparam.update_params.fm_pcd)
			return -EINVAL;
	}

	if (kparam.update_params.op_flags == DPA_CLS_HM_REPLACE_IPv6_BY_IPv4) {
		sz = kparam.update_params.replace.new_ipv4_hdr.options_size;
		options = kzalloc(sz * sizeof(*options), GFP_KERNEL);
		if (!options) {
			log_err("Failed to allocate memory for options param "
				"for DPA_CLS_HM_REPLACE_IPv6_BY_IPv4 "
				"parameter type.\n");
			return -ENOMEM;
		}

		copy_from_user(options,
				kparam.update_params.replace.new_ipv4_hdr.
				options, sz);
		kparam.update_params.replace.new_ipv4_hdr.options = options;
	}

	ret =  dpa_classif_set_update_hm(&kparam.update_params, kparam.next_hmd,
					&kparam.hmd, kparam.chain_head,
					p_res);
	kfree(options);
	if (ret < 0)
			return ret;

#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.hmd = kparam.hmd;
		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_modify_update_hm(unsigned long args, bool compat_mode)
{
	struct ioc_dpa_cls_hm_update_params kparam;
	uint8_t *options = NULL;
	long ret = 0;
	unsigned int sz;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_hm_update_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_update_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d)\n", __func__,
		__LINE__));

	if (kparam.update_params.op_flags == DPA_CLS_HM_REPLACE_IPv6_BY_IPv4) {
		sz = kparam.update_params.replace.new_ipv4_hdr.options_size;
		options = kzalloc(sz * sizeof(*options), GFP_KERNEL);
		if (!options) {
			log_err("Failed to allocate memory for options param "
				"for DPA_CLS_HM_REPLACE_IPv6_BY_IPv4 "
				"parameter type.\n");
			return -ENOMEM;
		}

		copy_from_user(options,
				kparam.update_params.replace.new_ipv4_hdr.
				options, sz);
		kparam.update_params.replace.new_ipv4_hdr.options = options;
	}

	ret = dpa_classif_modify_update_hm(kparam.hmd, &kparam.update_params,
					   kparam.modify_flags);

	kfree(options);

	return ret;
}

static long do_ioctl_set_fwd_hm(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_hm_fwd_params kparam;
	struct dpa_cls_hm_fwd_resources *p_res = NULL;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_hm_fwd_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_fwd_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	if (kparam.res.ip_frag_node || kparam.res.fwd_node ||
	    kparam.res.pppoe_node)
		p_res = &kparam.res;

	/* Translate FM_PCD file descriptor */
	if (!p_res) {
		kparam.fwd_params.fm_pcd =
			translate_fm_pcd_handle(kparam.fwd_params.fm_pcd);
		if (!kparam.fwd_params.fm_pcd)
			return -EINVAL;
	}

	ret = dpa_classif_set_fwd_hm(&kparam.fwd_params, kparam.next_hmd,
				&kparam.hmd, kparam.chain_head,
				p_res);
	if (ret < 0)
			return ret;

#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.hmd = kparam.hmd;
		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_modify_fwd_hm(unsigned long args, bool compat_mode)
{
	struct ioc_dpa_cls_hm_fwd_params kparam;
#ifdef CONFIG_COMPAT
	long ret = 0;
	struct compat_ioc_dpa_cls_hm_fwd_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_fwd_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d)\n", __func__,
		__LINE__));

	return dpa_classif_modify_fwd_hm(kparam.hmd, &kparam.fwd_params,
					kparam.modify_flags);
}

static long  do_ioctl_set_mpls_hm(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_hm_mpls_params kparam;
	struct dpa_cls_hm_mpls_resources *p_res = NULL;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_hm_mpls_params uparam;
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_mpls_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	if (kparam.res.ins_rm_node)
		p_res = &kparam.res;

	/* Translate FM_PCD file descriptor */
	if (!p_res) {
		kparam.mpls_params.fm_pcd =
			translate_fm_pcd_handle(kparam.mpls_params.fm_pcd);
		if (!kparam.mpls_params.fm_pcd)
			return -EINVAL;
	}

	ret = dpa_classif_set_mpls_hm(&kparam.mpls_params, kparam.next_hmd,
				&kparam.hmd, kparam.chain_head,
				p_res);
	if (ret < 0)
		return ret;

#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.hmd = kparam.hmd;
		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long  do_ioctl_modify_mpls_hm(unsigned long args, bool compat_mode)
{
	struct ioc_dpa_cls_hm_mpls_params kparam;
#ifdef CONFIG_COMPAT
	long ret = 0;
	struct compat_ioc_dpa_cls_hm_mpls_params uparam;

	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_hm_mpls_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d)\n", __func__,
		__LINE__));

	return dpa_classif_modify_mpls_hm(kparam.hmd, &kparam.mpls_params,
					kparam.modify_flags);
}

static long do_ioctl_mcast_create_group(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_mcast_group_params kparam;
	struct dpa_cls_tbl_policer_params policer_params;
	struct dpa_cls_mcast_group_resources *p_res = NULL;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_mcast_group_params uparam;
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		kparam.mcast_grp_params.first_member_params.policer_params =
								&policer_params;
		/*
		 * Transfer the data into the kernel space params:
		 */
		ret = dpa_cls_mcast_group_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
	{
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		if (kparam.mcast_grp_params.first_member_params.
							policer_params) {
			if (copy_from_user(&policer_params,
					kparam.mcast_grp_params.
					first_member_params.policer_params,
				sizeof(policer_params))) {
				log_err("Read failed: policer params.\n");
				return -EBUSY;
			}
			kparam.mcast_grp_params.first_member_params.
							policer_params =
								&policer_params;
		}
	}

	if (kparam.res.group_node)
		p_res = &kparam.res;
	/*
	 * Translate FM_PCD file descriptor
	 */
	if (!p_res) {
		kparam.mcast_grp_params.fm_pcd =
				translate_fm_pcd_handle(kparam.
						       mcast_grp_params.fm_pcd);
		if (!kparam.mcast_grp_params.fm_pcd)
			return -EINVAL;
	}

#if (DPAA_VERSION >= 11)
	ret = dpa_classif_mcast_create_group(&kparam.mcast_grp_params,
					     &kparam.grpd, p_res);
#else
	log_err("Multicast not supported on this platform.\n");
	return -EINVAL;
#endif

	if (ret < 0)
		return ret;

#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.grpd = kparam.grpd;
		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_mcast_add_member(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_mcast_member_params kparam;
	struct dpa_cls_tbl_policer_params policer_params;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_mcast_member_params uparam;
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		kparam.member_params.policer_params = &policer_params;
		/*
		 * Transfer the data into the kernel space params:
		 */
		ret = dpa_cls_mcast_member_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;

	} else
#endif /* CONFIG_COMPAT */
	{
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		if (kparam.member_params.policer_params) {
			if (copy_from_user(&policer_params,
					kparam.member_params.policer_params,
						sizeof(policer_params))) {
				log_err("Read failed: policer params.\n");
				return -EBUSY;
			}

			kparam.member_params.policer_params = &policer_params;
		}
	}
#if (DPAA_VERSION >= 11)
	ret = dpa_classif_mcast_add_member(kparam.grpd, &kparam.member_params,
					    &kparam.md);
	if (ret < 0)
		return ret;
#else
	log_err("Multicast not supported on this platform.\n");
	return -EINVAL;
#endif

#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.md = kparam.md;
		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}


static long do_ioctl_table_modify_miss_action(unsigned long	args,
					bool			compat_mode)
{
	struct ioc_dpa_cls_tbl_miss_action kparam;
	struct dpa_cls_tbl_policer_params policer_params;
#ifdef CONFIG_COMPAT
	long ret = 0;
	struct compat_ioc_dpa_cls_tbl_miss_action uparam;

	/* Prepare arguments */
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		kparam.miss_action.enq_params.policer_params = &policer_params;
		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_tbl_miss_action_params_compatcpy(&kparam,
								&uparam);
		if (ret < 0)
			return ret;
	} else
#endif /* CONFIG_COMPAT */
	{
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		if (kparam.miss_action.enq_params.policer_params) {
			if (copy_from_user(&policer_params,
				   kparam.miss_action.enq_params.policer_params,
						sizeof(policer_params))) {
				log_err("Read failed: policer params.\n");
				return -EBUSY;
			}

			kparam.miss_action.enq_params.policer_params =
								&policer_params;
		}
	}
	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d)\n", __func__,
		__LINE__));

	/* Call function */
	return dpa_classif_table_modify_miss_action(kparam.td,
						&kparam.miss_action);
}

static long do_ioctl_table_insert_entry(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_tbl_entry_params kparam;
	struct dpa_cls_tbl_policer_params policer_params;
	uint8_t key_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_tbl_entry_params uparam;

	/* Prepare arguments */
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		kparam.key.byte = key_buf;
		kparam.key.mask = mask_buf;
		kparam.key.size = DPA_OFFLD_MAXENTRYKEYSIZE;

		kparam.action.enq_params.policer_params = &policer_params;

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_tbl_entry_params_compatcpy(&kparam, &uparam);
		if (ret < 0)
			return ret;
	} else
#endif /* CONFIG_COMPAT */
	{
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		COPY_KEY_PARAMS;

		/* Check if we need to copy also the policer params */
		if ((kparam.action.type == DPA_CLS_TBL_ACTION_ENQ) &&
				(kparam.action.enq_params.policer_params)) {
			if (copy_from_user(&policer_params,
				kparam.action.enq_params.policer_params,
				sizeof(policer_params))) {
				log_err("Read failed: policer params.\n");
				return -EBUSY;
			}
		kparam.action.enq_params.policer_params = &policer_params;
		}
	}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	/* Call function */
	ret = dpa_classif_table_insert_entry(kparam.td,
					&kparam.key,
					&kparam.action,
					kparam.priority,
					&kparam.entry_id);
	if (ret < 0)
		return ret;

	/* In case of success return results to user space */
#ifdef CONFIG_COMPAT
	if (compat_mode) {
		uparam.entry_id = kparam.entry_id;

		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_table_modify_entry_by_key(unsigned long	args,
					bool			compat_mode)
{
	struct ioc_dpa_cls_tbl_entry_mod_by_key kparam;
	struct dpa_offload_lookup_key new_key;
	struct dpa_cls_tbl_action action;
	struct dpa_cls_tbl_policer_params policer_params;
	uint8_t key_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t new_key_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t new_mask_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
#ifdef CONFIG_COMPAT
	long ret = 0;
	struct compat_ioc_dpa_cls_tbl_entry_mod_by_key uparam;

	/* Prepare arguments */
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		kparam.key.byte = key_buf;
		kparam.key.mask = mask_buf;
		kparam.key.size = DPA_OFFLD_MAXENTRYKEYSIZE;

		new_key.byte = new_key_buf;
		new_key.mask = new_mask_buf;
		new_key.size = DPA_OFFLD_MAXENTRYKEYSIZE;

		kparam.mod_params.key		= &new_key;
		kparam.mod_params.action	= &action;
		kparam.mod_params.action->enq_params.policer_params =
							&policer_params;

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_tbl_entry_mod_by_key_params_compatcpy(&kparam,
								&uparam);
		if (ret < 0)
			return ret;
	} else
#endif /* CONFIG_COMPAT */
	{
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		COPY_KEY_PARAMS;

		/* Check if we need to copy the new key */
		COPY_NEW_KEY_PARAMS;

		if (kparam.mod_params.action) {
			if (copy_from_user(&action,
				kparam.mod_params.action,
				sizeof(struct dpa_cls_tbl_action))) {
				log_err("Read failed: new action params.\n");
				return -EBUSY;
			}
			kparam.mod_params.action = &action;

			/* Check if we need to copy policer params */
			if ((kparam.mod_params.action->type ==
				DPA_CLS_TBL_ACTION_ENQ) &&
				(kparam.mod_params.action->enq_params.
					policer_params)) {
				if (copy_from_user(&policer_params,
					kparam.mod_params.
					action->enq_params.
					policer_params,
					sizeof(policer_params))) {
					log_err("Read failed: new policer "
						"params.\n");
					return -EBUSY;
				}
				kparam.mod_params.action->enq_params.
					policer_params =
					&policer_params;
			}
		}
	}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d)\n", __func__,
		__LINE__));

	/* Call function */
	return dpa_classif_table_modify_entry_by_key(kparam.td,
						&kparam.key,
						&kparam.mod_params);

}

static long do_ioctl_table_modify_entry_by_ref(unsigned long	args,
					bool			compat_mode)
{
	struct ioc_dpa_cls_tbl_entry_mod_by_ref kparam;
	struct dpa_offload_lookup_key new_key;
	struct dpa_cls_tbl_action action;
	struct dpa_cls_tbl_policer_params policer_params;
	uint8_t new_key_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t new_mask_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
#ifdef CONFIG_COMPAT
	long ret = 0;
	struct compat_ioc_dpa_cls_tbl_entry_mod_by_ref uparam;

	/* Prepare arguments */
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		new_key.byte = new_key_buf;
		new_key.mask = new_mask_buf;
		new_key.size = DPA_OFFLD_MAXENTRYKEYSIZE;

		memset(&kparam, 0,
			sizeof(struct ioc_dpa_cls_tbl_entry_mod_by_ref));
		kparam.mod_params.key		= &new_key;
		kparam.mod_params.action	= &action;
		kparam.mod_params.action->enq_params.policer_params =
							&policer_params;

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_tbl_entry_mod_by_ref_params_compatcpy(&kparam,
			&uparam);
		if (ret < 0)
			return ret;
	} else
#endif /* CONFIG_COMPAT */
	{
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Check if we need to copy the new key */
		COPY_NEW_KEY_PARAMS;

		if (kparam.mod_params.action) {
			if (copy_from_user(&action,
				kparam.mod_params.action,
				sizeof(struct dpa_cls_tbl_action))) {
				log_err("Read failed: new action params.\n");
				return -EBUSY;
			}
			kparam.mod_params.action = &action;

			/* Check if we need to copy policer params */
			if ((kparam.mod_params.action->type ==
				DPA_CLS_TBL_ACTION_ENQ) &&
				(kparam.mod_params.action->enq_params.
					policer_params)) {
				if (copy_from_user(&policer_params,
					kparam.mod_params.
					action->enq_params.
					policer_params,
					sizeof(policer_params))) {
					log_err("Read failed: new policer "
						"params.\n");
					return -EBUSY;
				}
				kparam.mod_params.action->enq_params.
					policer_params =
					&policer_params;
			}
		}
	}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d)\n", __func__,
		__LINE__));

	/* Call function */
	return dpa_classif_table_modify_entry_by_ref(kparam.td,
						kparam.entry_id,
						&kparam.mod_params);
}

static long do_ioctl_table_lookup_by_key(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_tbl_lookup_by_key kparam;
	uint8_t key_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_tbl_lookup_by_key uparam;

	/* Prepare arguments */
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		kparam.key.byte = key_buf;
		kparam.key.mask = mask_buf;
		kparam.key.size = DPA_OFFLD_MAXENTRYKEYSIZE;

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_tbl_lookup_by_key_params_compatcpy(&kparam,
			&uparam);
		if (ret < 0)
			return ret;
	} else
#endif /* CONFIG_COMPAT */
	{
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		COPY_KEY_PARAMS;
	}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	/* Call function */
	ret = dpa_classif_table_lookup_by_key(kparam.td,
					      &kparam.key,
					      &kparam.action);
	if (ret < 0)
		return ret;

	/* Return results to user space */
#ifdef CONFIG_COMPAT
	if (compat_mode) {
		ret = dpa_cls_tbl_action_params_rcompatcpy(&uparam.action,
			&kparam.action);
		if (ret < 0)
			return ret;

		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_table_lookup_by_ref(unsigned long args, bool compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_tbl_lookup_by_ref kparam;
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_tbl_lookup_by_ref uparam;

	/* Prepare arguments */
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_tbl_lookup_by_ref_params_compatcpy(&kparam,
			&uparam);
		if (ret < 0)
			return ret;
	} else
#endif /* CONFIG_COMPAT */
		/* Prepare arguments */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	/* Call function */
	ret = dpa_classif_table_lookup_by_ref(kparam.td,
					      kparam.entry_id,
					      &kparam.action);
	if (ret < 0)
		return ret;

	/* Return results to user space */
#ifdef CONFIG_COMPAT
	if (compat_mode) {
		ret = dpa_cls_tbl_action_params_rcompatcpy(&uparam.action,
			&kparam.action);
		if (ret < 0)
			return ret;

		if (copy_to_user((void *)args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

static long do_ioctl_table_delete_entry_by_key(unsigned long	args,
					bool			compat_mode)
{
	struct ioc_dpa_cls_tbl_entry_by_key kparam;
	uint8_t key_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
#ifdef CONFIG_COMPAT
	long ret = 0;
	struct compat_ioc_dpa_cls_tbl_entry_by_key uparam;

	/* Prepare arguments */
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		kparam.key.byte = key_buf;
		kparam.key.mask = mask_buf;
		kparam.key.size = DPA_OFFLD_MAXENTRYKEYSIZE;

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_tbl_entry_by_key_params_compatcpy(&kparam,
								&uparam);
		if (ret < 0)
			return ret;
	} else
#endif /* CONFIG_COMPAT */
	{
		/* Prepare arguments */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		COPY_KEY_PARAMS;
	}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d)\n", __func__,
		__LINE__));

	/* Call function */
	return dpa_classif_table_delete_entry_by_key(kparam.td,
						    &kparam.key);
}

static long do_ioctl_table_get_stats_by_key(unsigned long	args,
					bool			compat_mode)
{
	long ret = 0;
	struct ioc_dpa_cls_tbl_entry_stats_by_key kparam;
	uint8_t key_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_buf[DPA_OFFLD_MAXENTRYKEYSIZE];
#ifdef CONFIG_COMPAT
	struct compat_ioc_dpa_cls_tbl_entry_stats_by_key uparam;

	/* Prepare arguments */
	if (compat_mode) {
		if (copy_from_user(&uparam, (void *) args, sizeof(uparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		kparam.key.byte = key_buf;
		kparam.key.mask = mask_buf;
		kparam.key.size = DPA_OFFLD_MAXENTRYKEYSIZE;

		/* Transfer the data into the kernel space params: */
		ret = dpa_cls_tbl_entry_stats_by_key_params_compatcpy(&kparam,
			&uparam);
		if (ret < 0)
			return ret;
	} else
#endif /* CONFIG_COMPAT */
	{
		/* Prepare arguments */
		if (copy_from_user(&kparam, (void *) args, sizeof(kparam))) {
			log_err("Read failed: user space args.\n");
			return -EBUSY;
		}

		COPY_KEY_PARAMS;
	}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) -->\n", __func__,
		__LINE__));

	/* Call function */
	ret = dpa_classif_table_get_entry_stats_by_key(kparam.td,
						       &kparam.key,
						       &kparam.stats);
	if (ret < 0)
		return ret;

	/* Return results to user space */
#ifdef CONFIG_COMPAT
	if (compat_mode) {
		memcpy(&uparam.stats, &kparam.stats,
				sizeof(struct dpa_cls_tbl_entry_stats));

		if (copy_to_user((void *) args, &uparam, sizeof(uparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}
	} else
#endif /* CONFIG_COMPAT */
		if (copy_to_user((void *) args, &kparam, sizeof(kparam))) {
			log_err("Write failed: result.\n");
			return -EBUSY;
		}

	dpa_cls_wrp_dbg(("DEBUG: classifier_wrp %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

void *translate_fm_pcd_handle(void *fm_pcd)
{
	struct file *fm_pcd_file;
	t_LnxWrpFmDev *fm_wrapper_dev;

	fm_pcd_file = fcheck((unsigned long)fm_pcd);
	if (!fm_pcd_file) {
		log_err("Could not translate PCD handle fm_pcd=0x%p.\n",
			fm_pcd);
		return NULL;
	}
	fm_wrapper_dev = (t_LnxWrpFmDev *)fm_pcd_file->private_data;
	BUG_ON(!fm_wrapper_dev);
	BUG_ON(!fm_wrapper_dev->h_PcdDev);

	return (void *)fm_wrapper_dev->h_PcdDev;
}

#ifdef CONFIG_COMPAT

int dpa_cls_tbl_entry_by_key_params_compatcpy(
	struct ioc_dpa_cls_tbl_entry_by_key			*kparam,
	const struct compat_ioc_dpa_cls_tbl_entry_by_key	*uparam)
{
	kparam->td = uparam->td;
	return dpa_lookup_key_params_compatcpy(&kparam->key, &uparam->key);
}

int dpa_cls_tbl_entry_stats_by_key_params_compatcpy(
	struct ioc_dpa_cls_tbl_entry_stats_by_key		*kparam,
	const struct compat_ioc_dpa_cls_tbl_entry_stats_by_key	*uparam)
{
	int err = 0;

	kparam->td	= uparam->td;

	err = dpa_lookup_key_params_compatcpy(&kparam->key, &uparam->key);
	if (err < 0)
		return err;

	memcpy(&kparam->stats,
		&uparam->stats,
		sizeof(struct dpa_cls_tbl_entry_stats));

	return 0;
}

int dpa_lookup_key_params_compatcpy(
		struct dpa_offload_lookup_key			*kparam,
		const struct compat_ioc_dpa_offld_lookup_key	*uparam)
{
	BUG_ON(!uparam->byte);
	BUG_ON(!kparam->byte);
	BUG_ON(kparam->size < uparam->size);
	BUG_ON(uparam->size <= 0);

	kparam->size = uparam->size;
	if (copy_from_user(kparam->byte, compat_ptr(uparam->byte),
		uparam->size)) {
		log_err("Read failed: lookup key.\n");
		return -EBUSY;
	}

	if (compat_ptr(uparam->mask)) {
		BUG_ON(!kparam->mask);
		if (copy_from_user(kparam->mask, compat_ptr(uparam->mask),
			uparam->size)) {
			log_err("Read failed: key mask.\n");
			return -EBUSY;
		}
	} else
		kparam->mask = NULL;

	return 0;
}

int dpa_cls_tbl_entry_params_compatcpy(
	struct ioc_dpa_cls_tbl_entry_params			*kparam,
	const struct compat_ioc_dpa_cls_tbl_entry_params	*uparam)
{
	int err;

	kparam->td		= uparam->td;
	kparam->priority	= uparam->priority;
	kparam->entry_id	= uparam->entry_id;

	err = dpa_lookup_key_params_compatcpy(&kparam->key, &uparam->key);
	if (err < 0)
		return err;

	return dpa_cls_tbl_action_params_compatcpy(&kparam->action,
							&uparam->action);
}

int dpa_cls_tbl_action_params_compatcpy(
		struct dpa_cls_tbl_action			*kparam,
		const struct dpa_cls_compat_tbl_action		*uparam)
{
	kparam->type			= uparam->type;
	kparam->enable_statistics	= uparam->enable_statistics;

	switch (uparam->type) {
	case DPA_CLS_TBL_ACTION_ENQ:
		kparam->enq_params.override_fqid =
				uparam->enq_params.override_fqid;
		kparam->enq_params.new_fqid =
				uparam->enq_params.new_fqid;
		kparam->enq_params.hmd = uparam->enq_params.hmd;
		kparam->enq_params.new_rel_vsp_id =
				uparam->enq_params.new_rel_vsp_id;
		if (compat_ptr(uparam->enq_params.policer_params)) {
			BUG_ON(!kparam->enq_params.policer_params);
			if (copy_from_user(kparam->enq_params.policer_params,
				compat_ptr(uparam->enq_params.policer_params),
				sizeof(struct dpa_cls_tbl_policer_params))) {
				log_err("Read failed: policer params.\n");
				return -EBUSY;
			}
		} else
			kparam->enq_params.policer_params = NULL;
		if (compat_ptr(uparam->enq_params.distribution))
			kparam->enq_params.distribution = compat_get_id2ptr(
					uparam->enq_params.distribution,
					FM_MAP_TYPE_PCD_NODE);
		else
			kparam->enq_params.distribution = NULL;
		break;
	case DPA_CLS_TBL_ACTION_NEXT_TABLE:
		kparam->next_table_params.next_td =
				uparam->next_table_params.next_td;
		kparam->next_table_params.hmd = uparam->next_table_params.hmd;
		break;
	case DPA_CLS_TBL_ACTION_MCAST:
		kparam->mcast_params.grpd = uparam->mcast_params.grpd;
		kparam->mcast_params.hmd = uparam->mcast_params.hmd;
		break;
	default:
		break;
	}

	return 0;
}

int dpa_cls_tbl_action_params_rcompatcpy(
		struct dpa_cls_compat_tbl_action	*uparam,
		const struct dpa_cls_tbl_action		*kparam)
{
	uparam->type			= kparam->type;
	uparam->enable_statistics	= kparam->enable_statistics;

	switch (kparam->type) {
	case DPA_CLS_TBL_ACTION_ENQ:
		uparam->enq_params.override_fqid =
				kparam->enq_params.override_fqid;
		uparam->enq_params.new_fqid =
				kparam->enq_params.new_fqid;
		uparam->enq_params.hmd = kparam->enq_params.hmd;
		uparam->enq_params.new_rel_vsp_id =
				kparam->enq_params.new_rel_vsp_id;
		if (kparam->enq_params.policer_params) {
			BUG_ON(!compat_ptr(uparam->enq_params.policer_params));
			if (copy_to_user(
				compat_ptr(uparam->enq_params.policer_params),
				kparam->enq_params.policer_params,
				sizeof(struct dpa_cls_tbl_policer_params))) {
				log_err("Read failed: policer params.\n");
				return -EBUSY;
			}
		} else
			uparam->enq_params.policer_params = 0;
		if (kparam->enq_params.distribution)
			uparam->enq_params.distribution = compat_get_ptr2id(
					kparam->enq_params.distribution,
					FM_MAP_TYPE_PCD_NODE);
		break;
	case DPA_CLS_TBL_ACTION_NEXT_TABLE:
		uparam->next_table_params.next_td =
				kparam->next_table_params.next_td;
		uparam->next_table_params.hmd = kparam->next_table_params.hmd;
		break;
	case DPA_CLS_TBL_ACTION_MCAST:
		uparam->mcast_params.grpd = kparam->mcast_params.grpd;
		uparam->mcast_params.hmd = kparam->mcast_params.hmd;
		break;
	default:
		break;
	}

	return 0;
}

int dpa_cls_tbl_params_compatcpy(
		struct ioc_dpa_cls_tbl_params			*kparam,
		const struct compat_ioc_dpa_cls_tbl_params	*uparam)
{
	kparam->table_params.cc_node	= compat_get_id2ptr(
					uparam->table_params.cc_node,
					FM_MAP_TYPE_PCD_NODE);
	kparam->table_params.type	= uparam->table_params.type;
	kparam->table_params.entry_mgmt	= uparam->table_params.entry_mgmt;
	kparam->table_params.prefilled_entries =
					uparam->table_params.prefilled_entries;

	switch (uparam->table_params.type) {
	case DPA_CLS_TBL_INDEXED:
		memcpy(&kparam->table_params.indexed_params,
				&uparam->table_params.indexed_params,
				sizeof(struct dpa_cls_tbl_indexed_params));
		break;
	case DPA_CLS_TBL_HASH:
		memcpy(&kparam->table_params.hash_params,
				&uparam->table_params.hash_params,
				sizeof(struct dpa_cls_tbl_hash_params));

		break;
	case DPA_CLS_TBL_EXACT_MATCH:
		memcpy(&kparam->table_params.exact_match_params,
				&uparam->table_params.exact_match_params,
				sizeof(struct dpa_cls_tbl_exact_match_params));

		break;
	}

	return 0;
}

int dpa_cls_tbl_params_rcompatcpy(
		struct compat_ioc_dpa_cls_tbl_params	*uparam,
		const struct ioc_dpa_cls_tbl_params	*kparam)
{
	uparam->table_params.cc_node	= compat_get_ptr2id(
					kparam->table_params.cc_node,
					FM_MAP_TYPE_PCD_NODE);
	uparam->table_params.type	= kparam->table_params.type;
	uparam->table_params.entry_mgmt	= kparam->table_params.entry_mgmt;
	uparam->table_params.prefilled_entries =
					kparam->table_params.prefilled_entries;

	switch (kparam->table_params.type) {
	case DPA_CLS_TBL_INDEXED:
		memcpy(&uparam->table_params.indexed_params,
				&kparam->table_params.indexed_params,
				sizeof(struct dpa_cls_tbl_indexed_params));
		break;
	case DPA_CLS_TBL_HASH:
		memcpy(&uparam->table_params.hash_params,
				&kparam->table_params.hash_params,
				sizeof(struct dpa_cls_tbl_hash_params));

		break;
	case DPA_CLS_TBL_EXACT_MATCH:
		memcpy(&uparam->table_params.exact_match_params,
				&kparam->table_params.exact_match_params,
				sizeof(struct dpa_cls_tbl_exact_match_params));

		break;
	}

	return 0;
}

int dpa_cls_tbl_miss_action_params_compatcpy(
		struct ioc_dpa_cls_tbl_miss_action		*kparam,
		const struct compat_ioc_dpa_cls_tbl_miss_action	*uparam)
{
	kparam->td = uparam->td;

	return dpa_cls_tbl_action_params_compatcpy(&kparam->miss_action,
			&uparam->miss_action);
}

int dpa_cls_tbl_entry_mod_by_key_params_compatcpy(
	struct ioc_dpa_cls_tbl_entry_mod_by_key			*kparam,
	const struct compat_ioc_dpa_cls_tbl_entry_mod_by_key	*uparam)
{
	int err;

	kparam->td = uparam->td;

	err = dpa_lookup_key_params_compatcpy(&kparam->key, &uparam->key);
	if (err < 0)
		return err;

	return dpa_cls_tbl_entry_mod_params_compatcpy(&kparam->mod_params,
		&uparam->mod_params);
}

int dpa_cls_tbl_entry_mod_params_compatcpy(
	struct dpa_cls_tbl_entry_mod_params			*kparam,
	const struct dpa_cls_compat_tbl_entry_mod_params	*uparam)
{
	int err = 0;

	kparam->type = uparam->type;

	if (compat_ptr(uparam->key)) {
		struct compat_ioc_dpa_offld_lookup_key key;

		BUG_ON(!kparam->key);
		if (copy_from_user(&key, compat_ptr(uparam->key),
			sizeof(struct compat_ioc_dpa_offld_lookup_key))) {
			log_err("Read failed: New key parameters.\n");
			return -EBUSY;
		}

		err = dpa_lookup_key_params_compatcpy(kparam->key, &key);
	} else
		kparam->key = NULL;

	if (err < 0)
		return err;

	if (compat_ptr(uparam->action)) {
		struct dpa_cls_compat_tbl_action action;

		BUG_ON(!kparam->action);

		if (copy_from_user(&action, compat_ptr(uparam->action),
			sizeof(struct dpa_cls_compat_tbl_action))) {
			log_err("Read failed: New action parameters.\n");
			return -EBUSY;
		}

		err = dpa_cls_tbl_action_params_compatcpy(kparam->action,
								&action);
	} else
		kparam->action = NULL;

	return err;
}

int dpa_cls_tbl_entry_mod_by_ref_params_compatcpy(
	struct ioc_dpa_cls_tbl_entry_mod_by_ref			*kparam,
	const struct compat_ioc_dpa_cls_tbl_entry_mod_by_ref	*uparam)
{
	kparam->td		= uparam->td;
	kparam->entry_id	= uparam->entry_id;

	return dpa_cls_tbl_entry_mod_params_compatcpy(&kparam->mod_params,
		&uparam->mod_params);
}

int dpa_cls_tbl_lookup_by_key_params_compatcpy(
	struct ioc_dpa_cls_tbl_lookup_by_key			*kparam,
	const struct compat_ioc_dpa_cls_tbl_lookup_by_key	*uparam)
{
	kparam->td = uparam->td;

	return dpa_lookup_key_params_compatcpy(&kparam->key, &uparam->key);
}

int dpa_cls_tbl_lookup_by_ref_params_compatcpy(
	struct ioc_dpa_cls_tbl_lookup_by_ref			*kparam,
	const struct compat_ioc_dpa_cls_tbl_lookup_by_ref	*uparam)
{
	kparam->td		= uparam->td;
	kparam->entry_id	= uparam->entry_id;

	return 0;
}

int dpa_cls_hm_remove_params_compatcpy(
		struct ioc_dpa_cls_hm_remove_params			*kparam,
		const struct compat_ioc_dpa_cls_hm_remove_params	*uparam)
{
	kparam->rm_params.type = uparam->rm_params.type;
	memcpy(&kparam->rm_params.custom, &uparam->rm_params.custom,
		sizeof(struct dpa_cls_hm_custom_rm_params));

	kparam->rm_params.fm_pcd	= compat_ptr(uparam->rm_params.fm_pcd);
	kparam->rm_params.reparse	= uparam->rm_params.reparse;
	kparam->next_hmd		= uparam->next_hmd;
	kparam->hmd			= uparam->hmd;

	if (uparam->res.remove_node)
		kparam->res.remove_node	= compat_get_id2ptr(
						uparam->res.remove_node,
						FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.remove_node	= NULL;

	kparam->chain_head	= uparam->chain_head;
	kparam->modify_flags	= uparam->modify_flags;

	return 0;
}

int dpa_cls_hm_insert_params_compatcpy(
		struct ioc_dpa_cls_hm_insert_params			*kparam,
		const struct compat_ioc_dpa_cls_hm_insert_params	*uparam)
{
	int type;

	kparam->ins_params.type = uparam->ins_params.type;

	type = kparam->ins_params.type;
	switch (type) {
	case DPA_CLS_HM_INSERT_CUSTOM:
		kparam->ins_params.custom.offset = uparam->ins_params.
							custom.offset;
		kparam->ins_params.custom.size = uparam->ins_params.
							custom.size;
		kparam->ins_params.custom.data = compat_ptr(uparam->ins_params.
							custom.data);
		break;
	case DPA_CLS_HM_INSERT_ETHERNET:
		memcpy(&kparam->ins_params.eth, &uparam->ins_params.eth,
			sizeof(struct dpa_cls_hm_eth_ins_params));
		break;
	case DPA_CLS_HM_INSERT_PPPoE:
		memcpy(&kparam->ins_params.pppoe, &uparam->ins_params.pppoe,
			sizeof(struct dpa_cls_hm_pppoe_ins_params));
		break;
	case DPA_CLS_HM_INSERT_PPP:
		kparam->ins_params.ppp_pid = uparam->ins_params.ppp_pid;
		break;
	default:
		break;
	}

	kparam->ins_params.fm_pcd	= compat_ptr(uparam->ins_params.fm_pcd);
	kparam->ins_params.reparse	= uparam->ins_params.reparse;
	kparam->next_hmd		= uparam->next_hmd;
	kparam->hmd			= uparam->hmd;
	if (uparam->res.insert_node)
		kparam->res.insert_node	= compat_get_id2ptr(
							uparam->res.insert_node,
							FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.insert_node	= NULL;

	kparam->chain_head	= uparam->chain_head;
	kparam->modify_flags	= uparam->modify_flags;

	return 0;
}

int dpa_cls_hm_vlan_params_compatcpy(
		struct ioc_dpa_cls_hm_vlan_params			*kparam,
		const struct compat_ioc_dpa_cls_hm_vlan_params		*uparam)
{
	int type;

	kparam->vlan_params.type = uparam->vlan_params.type;
	type = kparam->vlan_params.type;
	switch (type) {
	case DPA_CLS_HM_VLAN_INGRESS:
		memcpy(&kparam->vlan_params.ingress,
			&uparam->vlan_params.ingress,
			sizeof(struct dpa_cls_hm_ingress_vlan_params));
		break;
	case DPA_CLS_HM_VLAN_EGRESS:
		memcpy(&kparam->vlan_params.egress,
			&uparam->vlan_params.egress,
			sizeof(struct dpa_cls_hm_egress_vlan_params));
		break;
	default:
		break;
	}

	kparam->vlan_params.fm_pcd = compat_ptr(uparam->vlan_params.fm_pcd);
	kparam->vlan_params.reparse = uparam->vlan_params.reparse;
	kparam->next_hmd	= uparam->next_hmd;
	kparam->hmd		= uparam->hmd;

	if (uparam->res.vlan_node)
		kparam->res.vlan_node = compat_get_id2ptr(
						uparam->res.vlan_node,
						FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.vlan_node = NULL;

	kparam->chain_head	= uparam->chain_head;
	kparam->modify_flags	= uparam->modify_flags;

	return 0;
}

int dpa_cls_hm_nat_params_compatcpy(
		struct ioc_dpa_cls_hm_nat_params			*kparam,
		const struct compat_ioc_dpa_cls_hm_nat_params		*uparam)
{
	int type;
	kparam->nat_params.flags	= uparam->nat_params.flags;
	kparam->nat_params.proto	= uparam->nat_params.proto;
	kparam->nat_params.type		= uparam->nat_params.type;

	if (kparam->nat_params.type == DPA_CLS_HM_NAT_TYPE_NAT_PT) {
		kparam->nat_params.nat_pt.type = uparam->nat_params.nat_pt.type;
		type = kparam->nat_params.nat_pt.type;
		switch (type) {
		case DPA_CLS_HM_NAT_PT_IPv6_TO_IPv4:
			kparam->nat_params.nat_pt.new_header.ipv4.options_size =
			 uparam->nat_params.nat_pt.new_header.ipv4.options_size;
			kparam->nat_params.nat_pt.new_header.ipv4.options =
			  compat_ptr(uparam->nat_params.nat_pt.new_header.ipv4.
					   options);
			memcpy(&kparam->nat_params.nat_pt.new_header.ipv4.
				header, &uparam->nat_params.nat_pt.new_header.
				ipv4.header, sizeof(struct iphdr));
			break;
		case DPA_CLS_HM_NAT_PT_IPv4_TO_IPv6:
			memcpy(&kparam->nat_params.nat_pt.new_header.ipv6,
				&uparam->nat_params.nat_pt.new_header.ipv6,
				sizeof(struct ipv6_header));
			break;
		default:
			break;
		}
	} else if (kparam->nat_params.type == DPA_CLS_HM_NAT_TYPE_TRADITIONAL)
			memcpy(&kparam->nat_params.nat, &uparam->nat_params.nat,
			      sizeof(struct dpa_cls_hm_traditional_nat_params));

	kparam->nat_params.fm_pcd	= compat_ptr(uparam->nat_params.fm_pcd);
	kparam->nat_params.reparse	= uparam->nat_params.reparse;
	kparam->nat_params.sport	= uparam->nat_params.sport;
	kparam->nat_params.dport	= uparam->nat_params.dport;
	kparam->next_hmd		= uparam->next_hmd;
	kparam->hmd			= uparam->hmd;

	if (uparam->res.l3_update_node)
		kparam->res.l3_update_node = compat_get_id2ptr(
						uparam->res.l3_update_node,
						FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.l3_update_node = NULL;

	if (uparam->res.l4_update_node)
		kparam->res.l4_update_node = compat_get_id2ptr(
						uparam->res.l4_update_node,
						FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.l4_update_node = NULL;

	kparam->chain_head	= uparam->chain_head;
	kparam->modify_flags	= uparam->modify_flags;

	return 0;
}

int dpa_cls_hm_update_params_compatcpy(
		struct ioc_dpa_cls_hm_update_params			*kparam,
		const struct compat_ioc_dpa_cls_hm_update_params	*uparam)
{
	int op_flags;

	kparam->update_params.op_flags = uparam->update_params.op_flags;
	op_flags = kparam->update_params.op_flags;
	memcpy(&kparam->update_params.update, &uparam->update_params.update,
		sizeof(kparam->update_params.update));
	memcpy(&kparam->update_params.ip_frag_params,
		&uparam->update_params.ip_frag_params,
		sizeof(kparam->update_params.ip_frag_params));

	switch (op_flags) {
	case DPA_CLS_HM_REPLACE_IPv4_BY_IPv6:
		memcpy(&kparam->update_params.replace.new_ipv6_hdr,
			&uparam->update_params.replace.new_ipv6_hdr,
			sizeof(struct ipv6_header));
		break;
	case DPA_CLS_HM_REPLACE_IPv6_BY_IPv4:
		kparam->update_params.replace.new_ipv4_hdr.options_size =
			uparam->update_params.replace.new_ipv4_hdr.options_size;
		kparam->update_params.replace.new_ipv4_hdr.options =
			compat_ptr(uparam->update_params.replace.new_ipv4_hdr.
				   options);
		memcpy(&kparam->update_params.replace.new_ipv4_hdr.header,
			&uparam->update_params.replace.new_ipv4_hdr.header,
			sizeof(struct iphdr));
		break;
	default:
		break;
	}


	kparam->update_params.fm_pcd = compat_ptr(uparam->update_params.fm_pcd);
	kparam->update_params.reparse = uparam->update_params.reparse;
	kparam->next_hmd	= uparam->next_hmd;
	kparam->hmd		= uparam->hmd;

	if (uparam->res.update_node)
		kparam->res.update_node = compat_get_id2ptr(
						uparam->res.update_node,
						FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.update_node = NULL;

	if (uparam->res.ip_frag_node)
		kparam->res.ip_frag_node = compat_get_id2ptr(
						uparam->res.ip_frag_node,
						FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.ip_frag_node = NULL;

	kparam->chain_head	= uparam->chain_head;
	kparam->modify_flags	= uparam->modify_flags;

	return 0;
}

int dpa_cls_hm_fwd_params_compatcpy(
		struct ioc_dpa_cls_hm_fwd_params			*kparam,
		const struct compat_ioc_dpa_cls_hm_fwd_params		*uparam)
{
	int type;

	kparam->fwd_params.out_if_type	= uparam->fwd_params.out_if_type;
	kparam->fwd_params.fm_pcd	= compat_ptr(uparam->fwd_params.fm_pcd);
	kparam->fwd_params.reparse	= uparam->fwd_params.reparse;

	type = kparam->fwd_params.out_if_type;
	switch (type) {
	case DPA_CLS_HM_IF_TYPE_ETHERNET:
		memcpy(&kparam->fwd_params.eth, &uparam->fwd_params.eth,
			sizeof(struct dpa_cls_hm_fwd_l2_param));
		break;
	case DPA_CLS_HM_IF_TYPE_PPPoE:
		memcpy(&kparam->fwd_params.pppoe, &uparam->fwd_params.pppoe,
			sizeof(struct dpa_cls_hm_fwd_pppoe_param));
		break;
	case DPA_CLS_HM_IF_TYPE_PPP:
		memcpy(&kparam->fwd_params.ppp, &uparam->fwd_params.ppp,
			sizeof(struct dpa_cls_hm_fwd_ppp_param));
		break;
	default:
		break;
	}

	memcpy(&kparam->fwd_params.ip_frag_params,
		&uparam->fwd_params.ip_frag_params,
		sizeof(struct dpa_cls_hm_ip_frag_params));

	kparam->next_hmd	= uparam->next_hmd;
	kparam->hmd		= uparam->hmd;

	if (uparam->res.fwd_node)
		kparam->res.fwd_node = compat_get_id2ptr(uparam->res.fwd_node,
						FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.fwd_node = NULL;

	if (uparam->res.pppoe_node)
		kparam->res.pppoe_node = compat_get_id2ptr(
						uparam->res.pppoe_node,
						FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.pppoe_node = NULL;

	if (uparam->res.ip_frag_node)
		kparam->res.ip_frag_node = compat_get_id2ptr(
						uparam->res.ip_frag_node,
						FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.ip_frag_node = NULL;

	kparam->chain_head	= uparam->chain_head;
	kparam->modify_flags	= uparam->modify_flags;

	return 0;
}

int dpa_cls_hm_mpls_params_compatcpy(
		struct ioc_dpa_cls_hm_mpls_params			*kparam,
		const struct compat_ioc_dpa_cls_hm_mpls_params		*uparam)
{
	kparam->mpls_params.type = uparam->mpls_params.type;
	memcpy(kparam->mpls_params.mpls_hdr, uparam->mpls_params.mpls_hdr,
		sizeof(struct mpls_header) * DPA_CLS_HM_MAX_MPLS_LABELS);
	kparam->mpls_params.num_labels = uparam->mpls_params.num_labels;
	kparam->mpls_params.fm_pcd = compat_ptr(uparam->mpls_params.fm_pcd);
	kparam->mpls_params.reparse = uparam->mpls_params.reparse;
	kparam->next_hmd	= uparam->next_hmd;
	kparam->hmd		= uparam->hmd;

	if (uparam->res.ins_rm_node)
		kparam->res.ins_rm_node = compat_get_id2ptr(
						uparam->res.ins_rm_node,
						FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.ins_rm_node = NULL;

	kparam->chain_head	= uparam->chain_head;
	kparam->modify_flags	= uparam->modify_flags;

	return 0;
}

int dpa_cls_mcast_group_params_compatcpy(
		struct ioc_dpa_cls_mcast_group_params *kparam,
		const struct compat_ioc_dpa_cls_mcast_group_params *uparam)
{
	kparam->mcast_grp_params.max_members =
					uparam->mcast_grp_params.max_members;
	kparam->mcast_grp_params.fm_pcd = compat_ptr(uparam->mcast_grp_params.
							fm_pcd);
	kparam->mcast_grp_params.first_member_params.override_fqid =
		uparam->mcast_grp_params.first_member_params.override_fqid;
	kparam->mcast_grp_params.first_member_params.new_fqid =
		uparam->mcast_grp_params.first_member_params.new_fqid;
	kparam->mcast_grp_params.first_member_params.new_rel_vsp_id =
		uparam->mcast_grp_params.first_member_params.new_rel_vsp_id;
	if (compat_ptr(uparam->mcast_grp_params.first_member_params.
							policer_params)) {
		if (copy_from_user(kparam->mcast_grp_params.first_member_params.
				policer_params,
			compat_ptr(uparam->mcast_grp_params.first_member_params.
					policer_params),
			sizeof(struct dpa_cls_tbl_policer_params))) {
			log_err("Read failed: policer params.\n");
			return -EBUSY;
		}
	} else
		kparam->mcast_grp_params.first_member_params.policer_params =
									NULL;
	if (compat_ptr(uparam->mcast_grp_params.first_member_params.distribution))
		kparam->mcast_grp_params.first_member_params.distribution =
			compat_get_id2ptr(uparam->mcast_grp_params.
				first_member_params.distribution,
				FM_MAP_TYPE_PCD_NODE);
	else
		kparam->mcast_grp_params.first_member_params.distribution =
									NULL;

	kparam->mcast_grp_params.first_member_params.hmd =
			uparam->mcast_grp_params.first_member_params.hmd;
	kparam->mcast_grp_params.prefilled_members =
			uparam->mcast_grp_params.prefilled_members;

	if (uparam->res.group_node)
		kparam->res.group_node = compat_get_id2ptr(
					uparam->res.group_node,
					FM_MAP_TYPE_PCD_NODE);
	else
		kparam->res.group_node = NULL;

	return 0;
}

int dpa_cls_mcast_member_params_compatcpy(
		struct ioc_dpa_cls_mcast_member_params *kparam,
		const struct compat_ioc_dpa_cls_mcast_member_params *uparam)
{
	kparam->grpd = uparam->grpd;
	kparam->member_params.hmd = uparam->member_params.hmd;
	kparam->member_params.new_fqid = uparam->member_params.new_fqid;
	kparam->member_params.override_fqid =
					uparam->member_params.override_fqid;
	kparam->member_params.new_rel_vsp_id =
					uparam->member_params.new_rel_vsp_id;
	if (compat_ptr(uparam->member_params.policer_params)) {
		if (copy_from_user(kparam->member_params.policer_params,
			compat_ptr(uparam->member_params.policer_params),
			sizeof(struct dpa_cls_tbl_policer_params))) {
			log_err("Read failed: policer params.\n");
			return -EBUSY;
		}
	} else
		kparam->member_params.policer_params = NULL;
	if (compat_ptr(uparam->member_params.distribution))
		kparam->member_params.distribution = compat_get_id2ptr(
				uparam->member_params.distribution,
				FM_MAP_TYPE_PCD_NODE);
	else
		kparam->member_params.distribution = NULL;

	return 0;
}

#endif /* CONFIG_COMPAT */
