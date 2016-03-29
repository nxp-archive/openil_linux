/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * This software is provided by Freescale Semiconductor "as is" and any
 * express or implied warranties, including, but not limited to, the implied
 * warranties of merchantability and fitness for a particular purpose are
 * disclaimed. In no event shall Freescale Semiconductor be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential damages
 * (including, but not limited to, procurement of substitute goods or services;
 * loss of use, data, or profits; or business interruption) however caused and
 * on any theory of liability, whether in contract, strict liability, or tort
 * (including negligence or otherwise) arising in any way out of the use of
 * this software, even if advised of the possibility of such damage.
 */

#include <linux/of_address.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/of.h>
#include <linux/io.h>
#include <linux/debugfs.h>
#include <linux/module.h>

#define DRV_VERSION "0.1"

static u64 dce_ccsr_start;
static u64 dce_ccsr_size;

/* takes userspace input and converts to upper case */
static int user_input_convert(const char __user *user_buf, size_t count,
				unsigned long *val)
{
	char buf[12];

	if (count > sizeof(buf) - 1)
		return -EINVAL;
	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;
	buf[count] = '\0';
	if (kstrtoul(buf, 0, val))
		return -EINVAL;
	return 0;
}

static struct dentry *dfs_root; /* debugfs root directory */

struct dce_register_s {
	u32 val;
};
static struct dce_register_s dce_register_data;

static int init_ccsrmempeek(void)
{
	struct device_node *dn;
	const u32 *regaddr_p;

	dn = of_find_compatible_node(NULL, NULL, "fsl,dce");
	if (!dn) {
		pr_info("No fsl,dce node\n");
		return -ENODEV;
	}
	regaddr_p = of_get_address(dn, 0, &dce_ccsr_size, NULL);
	if (!regaddr_p) {
		of_node_put(dn);
		return -EINVAL;
	}
	dce_ccsr_start = of_translate_address(dn, regaddr_p);
	of_node_put(dn);
	return 0;
}

/* This function provides access to DCE ccsr memory map */
static int dce_ccsrmem_get(u32 *val, u32 offset)
{
	void __iomem *addr;
	u64 phys_addr;

	if (!dce_ccsr_start)
		return -EINVAL;

	if (offset > (dce_ccsr_size - sizeof(u32)))
		return -EINVAL;

	phys_addr = dce_ccsr_start + offset;
	addr = ioremap(phys_addr, sizeof(u32));
	if (!addr) {
		pr_err("ccsrmem, ioremap failed\n");
		return -EINVAL;
	}
	*val = in_be32(addr);
	iounmap(addr);
	return 0;
}

static int dce_ccsrmem_put(u32 val, u32 offset)
{
	void __iomem *addr;
	u64 phys_addr;

	if (!dce_ccsr_start)
		return -EINVAL;

	if (offset > (dce_ccsr_size - sizeof(u32)))
		return -EINVAL;

	phys_addr = dce_ccsr_start + offset;
	addr = ioremap(phys_addr, sizeof(u32));
	if (!addr) {
		pr_err("ccsrmem, ioremap failed\n");
		return -EINVAL;
	}
	iowrite32be(val, addr);
	iounmap(addr);
	return 0;
}


static int dce_ccsrmem_addr_show(struct seq_file *file, void *offset)
{
	seq_printf(file, "DCE register offset = 0x%x\n",
		   dce_register_data.val);
	return 0;
}

static int dce_ccsrmem_addr_open(struct inode *inode, struct file *file)
{
	return single_open(file, dce_ccsrmem_addr_show, NULL);
}

static ssize_t dce_ccsrmem_addr_write(struct file *f, const char __user *buf,
				size_t count, loff_t *off)
{
	int ret;
	unsigned long val;

	ret = user_input_convert(buf, count, &val);
	if (ret)
		return ret;
	/* multiple of 4 */
	if (val > (dce_ccsr_size - sizeof(u32))) {
		pr_info("Input 0x%lx > 0x%llx\n",
			val, (dce_ccsr_size - sizeof(u32)));
		return -EINVAL;
	}
	if (val & 0x3) {
		pr_info("Input 0x%lx not multiple of 4\n", val);
		return -EINVAL;
	}
	dce_register_data.val = val;
	return count;
}

static const struct file_operations dce_ccsrmem_addr_fops = {
	.owner          = THIS_MODULE,
	.open		= dce_ccsrmem_addr_open,
	.read           = seq_read,
	.write		= dce_ccsrmem_addr_write,
};


static int dce_ccsrmem_rw_show(struct seq_file *file, void *offset)
{
	u32 out_val = 0;
	int ret;

	ret = dce_ccsrmem_get(&out_val, dce_register_data.val);
	if (ret)
		return ret;
	seq_printf(file, "DCE register offset = 0x%x\n",
		   dce_register_data.val);
	seq_printf(file, "value = 0x%08x\n", out_val);

	return 0;
}

static int dce_ccsrmem_rw_open(struct inode *inode, struct file *file)
{
	return single_open(file, dce_ccsrmem_rw_show, NULL);
}

static ssize_t dce_ccsrmem_rw_write(struct file *f, const char __user *buf,
				size_t count, loff_t *off)
{
	int ret;
	unsigned long val;

	ret = user_input_convert(buf, count, &val);
	if (ret)
		return ret;

	ret = dce_ccsrmem_put(val, dce_register_data.val);

	if (ret)
		return ret;

	return count;
}

static const struct file_operations dce_ccsrmem_rw_fops = {
	.owner          = THIS_MODULE,
	.open		= dce_ccsrmem_rw_open,
	.read           = seq_read,
	.write		= dce_ccsrmem_rw_write,
};

#define DCE_DBGFS_ENTRY(name, mode, parent, data, fops) \
	do { \
		d = debugfs_create_file(name, \
			mode, parent, \
			data, \
			fops); \
		if (d == NULL) { \
			ret = -ENOMEM; \
		} \
	} while (0)

/* dfs_root as parent */
#define DCE_DBGFS_ENTRY_ROOT(name, mode, data, fops) \
	DCE_DBGFS_ENTRY(name, mode, dfs_root, data, fops)

static int __init dce_debugfs_module_init(void)
{
	int ret = 0;
	struct dentry *d;

	ret = init_ccsrmempeek();
	if (ret)
		goto fail_init;
	dfs_root = debugfs_create_dir("dce", NULL);
	if (dfs_root == NULL) {
		ret = -ENOMEM;
		pr_err("Cannot create dce debugfs dir\n");
		goto fail_dce_dir;
	}

	DCE_DBGFS_ENTRY_ROOT("ccsrmem_addr", S_IRUGO | S_IWUGO,
			NULL, &dce_ccsrmem_addr_fops);
	if (ret)
		goto fail_dce_dir;

	DCE_DBGFS_ENTRY_ROOT("ccsrmem_rw", S_IRUGO | S_IWUGO,
			NULL, &dce_ccsrmem_rw_fops);
	if (ret)
		goto fail_dce_dir;

	return 0;

fail_dce_dir:
	debugfs_remove_recursive(dfs_root);
fail_init:
	return ret;
}

static void __exit dce_debugfs_module_exit(void)
{
	debugfs_remove_recursive(dfs_root);
}

module_init(dce_debugfs_module_init);
module_exit(dce_debugfs_module_exit);

MODULE_AUTHOR("Jeffrey Ladouceur");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("FSL DCE debugfs accessr");
MODULE_VERSION(DRV_VERSION);

