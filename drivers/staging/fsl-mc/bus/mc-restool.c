/*
 * Freescale Management Complex (MC) restool driver
 *
 * Copyright (C) 2014 Freescale Semiconductor, Inc.
 * Author: German Rivera <German.Rivera@freescale.com>
 *	   Lijun Pan <Lijun.Pan@freescale.com>
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "../include/mc-private.h"
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include "mc-ioctl.h"
#include "../include/mc-sys.h"
#include "../include/mc-cmd.h"
#include "../include/dpmng.h"

/**
 * Maximum number of DPRCs that can be opened at the same time
 */
#define MAX_DPRC_HANDLES	    64

/**
 * struct fsl_mc_restool - Management Complex (MC) resource manager object
 * @tool_mc_io: pointer to the MC I/O object used by the restool
 */
struct fsl_mc_restool {
	struct fsl_mc_io *tool_mc_io;
};

/**
 * struct global_state - indicating the number of static and dynamic instance
 * @dynamic_instance_count - number of dynamically created instances
 * @static_instance_in_use - static instance is in use or not
 * @mutex - mutex lock to serialze the operations
 */
struct global_state {
	uint32_t dynamic_instance_count;
	bool static_instance_in_use;
	struct mutex mutex;
};

static struct fsl_mc_restool fsl_mc_restool = { 0 };
static struct global_state global_state = { 0 };

static int fsl_mc_restool_dev_open(struct inode *inode, struct file *filep)
{
	struct fsl_mc_device *root_mc_dev;
	int error = 0;
	struct fsl_mc_restool *fsl_mc_restool_new = NULL;

	mutex_lock(&global_state.mutex);

	if (WARN_ON(fsl_mc_bus_type.dev_root == NULL)) {
		error = -EINVAL;
		goto error;
	}

	if (!global_state.static_instance_in_use) {
		global_state.static_instance_in_use = true;
		filep->private_data = &fsl_mc_restool;
	} else {
		fsl_mc_restool_new = kmalloc(sizeof(struct fsl_mc_restool),
						GFP_KERNEL);
		if (fsl_mc_restool_new == NULL) {
			error = -ENOMEM;
			goto error;
		}
		memset(fsl_mc_restool_new, 0, sizeof(*fsl_mc_restool_new));

		root_mc_dev = to_fsl_mc_device(fsl_mc_bus_type.dev_root);
		error = fsl_mc_portal_allocate(root_mc_dev, 0,
				       &fsl_mc_restool_new->tool_mc_io);
		if (error < 0) {
			pr_err("Not able to allocate MC portal\n");
			goto error;
		}
		++global_state.dynamic_instance_count;
		filep->private_data = fsl_mc_restool_new;
	}

	mutex_unlock(&global_state.mutex);
	return 0;
error:
	if (fsl_mc_restool_new != NULL &&
	    fsl_mc_restool_new->tool_mc_io != NULL) {
		fsl_mc_portal_free(fsl_mc_restool_new->tool_mc_io);
		fsl_mc_restool_new->tool_mc_io = NULL;
	}

	kfree(fsl_mc_restool_new);
	mutex_unlock(&global_state.mutex);
	return error;
}

static int fsl_mc_restool_dev_release(struct inode *inode, struct file *filep)
{
	struct fsl_mc_restool *fsl_mc_restool_local = filep->private_data;

	if (WARN_ON(filep->private_data == NULL))
		return -EINVAL;

	mutex_lock(&global_state.mutex);

	if (WARN_ON(global_state.dynamic_instance_count == 0 &&
	    !global_state.static_instance_in_use)) {
		mutex_unlock(&global_state.mutex);
		return -EINVAL;
	}

	/* Globally clean up opened/untracked handles */
	fsl_mc_portal_reset(fsl_mc_restool_local->tool_mc_io);

	pr_debug("dynamic instance count: %d\n",
		global_state.dynamic_instance_count);
	pr_debug("static instance count: %d\n",
		global_state.static_instance_in_use);

	/*
	 * must check
	 * whether fsl_mc_restool_local is dynamic or global instance
	 * Otherwise it will free up the reserved portal by accident
	 * or even not free up the dynamic allocated portal
	 * if 2 or more instances running concurrently
	 */
	if (fsl_mc_restool_local == &fsl_mc_restool) {
		pr_debug("this is reserved portal");
		pr_debug("reserved portal not in use\n");
		global_state.static_instance_in_use = false;
	} else {
		pr_debug("this is dynamically allocated  portal");
		pr_debug("free one dynamically allocated portal\n");
		fsl_mc_portal_free(fsl_mc_restool_local->tool_mc_io);
		kfree(filep->private_data);
		--global_state.dynamic_instance_count;
	}

	filep->private_data = NULL;
	mutex_unlock(&global_state.mutex);
	return 0;
}

static int restool_get_root_dprc_info(unsigned long arg)
{
	int error = -EINVAL;
	uint32_t root_dprc_id;
	struct fsl_mc_device *root_mc_dev;

	root_mc_dev = to_fsl_mc_device(fsl_mc_bus_type.dev_root);
	root_dprc_id = root_mc_dev->obj_desc.id;
	error = copy_to_user((void __user *)arg, &root_dprc_id,
			     sizeof(root_dprc_id));
	if (error < 0) {
		pr_err("copy_to_user() failed with error %d\n", error);
		goto error;
	}

	return 0;
error:
	return error;
}

static int restool_send_mc_command(unsigned long arg,
				struct fsl_mc_restool *fsl_mc_restool)
{
	int error = -EINVAL;
	struct mc_command mc_cmd;

	error = copy_from_user(&mc_cmd, (void __user *)arg, sizeof(mc_cmd));
	if (error < 0) {
		pr_err("copy_to_user() failed with error %d\n", error);
		goto error;
	}

	/*
	 * Send MC command to the MC:
	 */
	error = mc_send_command(fsl_mc_restool->tool_mc_io, &mc_cmd);
	if (error < 0)
		goto error;

	error = copy_to_user((void __user *)arg, &mc_cmd, sizeof(mc_cmd));
	if (error < 0) {
		pr_err("copy_to_user() failed with error %d\n", error);
		goto error;
	}

	return 0;
error:
	return error;
}

static long
fsl_mc_restool_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int error = -EINVAL;

	if (WARN_ON(fsl_mc_bus_type.dev_root == NULL))
		goto out;

	switch (cmd) {
	case RESTOOL_GET_ROOT_DPRC_INFO:
		error = restool_get_root_dprc_info(arg);
		break;

	case RESTOOL_SEND_MC_COMMAND:
		error = restool_send_mc_command(arg, file->private_data);
		break;
	default:
		error = -EINVAL;
	}
out:
	return error;
}

static const struct file_operations fsl_mc_restool_dev_fops = {
	.owner = THIS_MODULE,
	.open = fsl_mc_restool_dev_open,
	.release = fsl_mc_restool_dev_release,
	.unlocked_ioctl = fsl_mc_restool_dev_ioctl,
	.compat_ioctl = fsl_mc_restool_dev_ioctl,
};

static struct miscdevice fsl_mc_restool_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "mc_restool",
	.fops = &fsl_mc_restool_dev_fops
};

static int __init fsl_mc_restool_driver_init(void)
{
	struct fsl_mc_device *root_mc_dev;
	int error = -EINVAL;
	bool restool_dev_registered = false;

	mutex_init(&global_state.mutex);

	if (WARN_ON(fsl_mc_restool.tool_mc_io != NULL))
		goto error;

	if (WARN_ON(global_state.dynamic_instance_count != 0))
		goto error;

	if (WARN_ON(global_state.static_instance_in_use))
		goto error;

	if (fsl_mc_bus_type.dev_root == NULL) {
		pr_err("fsl-mc bus not found, restool driver registration failed\n");
		goto error;
	}

	root_mc_dev = to_fsl_mc_device(fsl_mc_bus_type.dev_root);
	error = fsl_mc_portal_allocate(root_mc_dev, 0,
				       &fsl_mc_restool.tool_mc_io);
	if (error < 0) {
		pr_err("Not able to allocate MC portal\n");
		goto error;
	}

	error = misc_register(&fsl_mc_restool_dev);
	if (error < 0) {
		pr_err("misc_register() failed: %d\n", error);
		goto error;
	}

	restool_dev_registered = true;
	pr_info("%s driver registered\n", fsl_mc_restool_dev.name);
	return 0;
error:
	if (restool_dev_registered)
		misc_deregister(&fsl_mc_restool_dev);

	if (fsl_mc_restool.tool_mc_io != NULL) {
		fsl_mc_portal_free(fsl_mc_restool.tool_mc_io);
		fsl_mc_restool.tool_mc_io = NULL;
	}

	return error;
}

module_init(fsl_mc_restool_driver_init);

static void __exit fsl_mc_restool_driver_exit(void)
{
	if (WARN_ON(fsl_mc_restool.tool_mc_io == NULL))
		return;

	if (WARN_ON(global_state.dynamic_instance_count != 0))
		return;

	if (WARN_ON(global_state.static_instance_in_use))
		return;

	misc_deregister(&fsl_mc_restool_dev);
	fsl_mc_portal_free(fsl_mc_restool.tool_mc_io);
	fsl_mc_restool.tool_mc_io = NULL;
	pr_info("%s driver unregistered\n", fsl_mc_restool_dev.name);
}

module_exit(fsl_mc_restool_driver_exit);

MODULE_AUTHOR("Freescale Semiconductor Inc.");
MODULE_DESCRIPTION("Freescale's MC restool driver");
MODULE_LICENSE("GPL");

