/*
 *  (C) Copyright 2013
 *  Author : Freescale Technologes
 *
 *  See file CREDITS for list of people who contributed to this
 *  project.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 *  MA 02111-1307 USA
 * */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/platform_device.h>

#include "pfe_mod.h"

static int dmem_show(struct seq_file *s, void *unused)
{
	u32 dmem_addr, val;
	int id = (long int)s->private;
	int i;

	for (dmem_addr = 0; dmem_addr < CLASS_DMEM_SIZE; dmem_addr += 8 * 4) {
		seq_printf(s, "%04x:", dmem_addr);

		for (i = 0; i < 8; i++) {
			val = pe_dmem_read(id, dmem_addr + i * 4, 4);
			seq_printf(s, " %02x %02x %02x %02x", val & 0xff, (val >> 8) & 0xff, (val >> 16) & 0xff, (val >> 24) & 0xff);
		}

		seq_printf(s, "\n");
	}

	return 0;
}

static int dmem_open(struct inode *inode, struct file *file)
{
	return single_open(file, dmem_show, inode->i_private);
}

static const struct file_operations dmem_fops = {
	.open		= dmem_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

int pfe_debugfs_init(struct pfe *pfe)
{
	struct dentry *d;

	printk(KERN_INFO "%s\n", __func__);

	pfe->dentry = debugfs_create_dir("pfe", NULL);
	if (IS_ERR_OR_NULL(pfe->dentry))
		goto err_dir;

	d = debugfs_create_file("pe0_dmem", S_IRUGO, pfe->dentry, (void *)0, &dmem_fops);
	if (IS_ERR_OR_NULL(d))
		goto err_pe;

	d = debugfs_create_file("pe1_dmem", S_IRUGO, pfe->dentry, (void *)1, &dmem_fops);
	if (IS_ERR_OR_NULL(d))
		goto err_pe;

	d = debugfs_create_file("pe2_dmem", S_IRUGO, pfe->dentry, (void *)2, &dmem_fops);
	if (IS_ERR_OR_NULL(d))
		goto err_pe;

	d = debugfs_create_file("pe3_dmem", S_IRUGO, pfe->dentry, (void *)3, &dmem_fops);
	if (IS_ERR_OR_NULL(d))
		goto err_pe;

	d = debugfs_create_file("pe4_dmem", S_IRUGO, pfe->dentry, (void *)4, &dmem_fops);
	if (IS_ERR_OR_NULL(d))
		goto err_pe;

	d = debugfs_create_file("pe5_dmem", S_IRUGO, pfe->dentry, (void *)5, &dmem_fops);
	if (IS_ERR_OR_NULL(d))
		goto err_pe;

	return 0;

err_pe:
	debugfs_remove_recursive(pfe->dentry);

err_dir:
	return -1;
}

void pfe_debugfs_exit(struct pfe *pfe)
{
	debugfs_remove_recursive(pfe->dentry);
}

