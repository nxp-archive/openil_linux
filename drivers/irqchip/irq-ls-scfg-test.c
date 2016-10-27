/*
 * Layerscape MSI(-X) Test
 *
 * Copyright (C) 2016 Freescale Semiconductor.
 *
 * Author: Minghuan Lian <Minghuan.Lian@nxp.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/debugfs.h>

struct msi_test {
	struct list_head	list;
	struct device_node	*dn;
	char			name[16];
	struct irq_domain	*domain;
	struct dentry		*file;
	struct pci_dev		*pdev;
	void __iomem		*base;
	int			count;
	int			available;
};

static LIST_HEAD(msi_test_list);
static char msi_test_ops_buf[256] = "";

static irqreturn_t msi_test_irq_handler(int irq, void *data)
{
	struct msi_test *test = data;

	pr_info("%s: receive an IRQ %d\n", test->dn->full_name, irq);

	return IRQ_HANDLED;
}

static int msi_test_remove(struct msi_test *test)
{
	struct msi_desc *entry, *tmp;

	if (!test->pdev)
		return 0;

	for_each_msi_entry(entry, &test->pdev->dev) {
		if (!test->available)
			break;

		if (entry->irq) {
			free_irq(entry->irq, test);
			test->available--;
		}
	}

	pci_msi_domain_free_irqs(test->domain, test->pdev);

	list_for_each_entry_safe(entry, tmp,
		dev_to_msi_list(&test->pdev->dev), list) {
		list_del(&entry->list);
		kfree(entry);
	}

	kfree(test->base);
	kfree(test->pdev->bus);
	kfree(test->pdev);
	test->pdev = NULL;

	return 0;
}

static int msi_test_create(struct msi_test *test, int count)
{
	int i, ret;
	struct msi_desc *entry;
	struct pci_bus *b;

	if (test->pdev)
		msi_test_remove(test);

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	INIT_LIST_HEAD(&b->node);
	INIT_LIST_HEAD(&b->children);
	INIT_LIST_HEAD(&b->devices);
	INIT_LIST_HEAD(&b->slots);
	INIT_LIST_HEAD(&b->resources);
	b->domain_nr = 0;
	b->number = 0;

	test->pdev = pci_alloc_dev(NULL);
	if (!test->pdev) {
		kfree(b);
		return -ENOMEM;
	}

	test->pdev->bus = b;

	device_initialize(&test->pdev->dev);
	INIT_LIST_HEAD(&test->pdev->dev.msi_list);

	test->base = kmalloc(PAGE_SIZE, GFP_KERNEL);

	test->count = count;
	test->available = 0;

	for (i = 0; i < count; i++) {
		entry = alloc_msi_entry(&test->pdev->dev);
		if (!entry) {
			/* No enough memory. Don't try again */
			return -ENOMEM;
		}

		entry->msi_attrib.is_msix	= 1;
		entry->msi_attrib.is_64		= 1;
		entry->msi_attrib.entry_nr	= i;
		entry->msi_attrib.default_irq	= 0;
		entry->mask_base		= test->base;
		entry->nvec_used		= 1;

		list_add_tail(&entry->list, dev_to_msi_list(&test->pdev->dev));
	}

	ret = pci_msi_domain_alloc_irqs(test->domain, test->pdev,
					count, PCI_CAP_ID_MSIX);

	for_each_msi_entry(entry, &test->pdev->dev) {
		if (entry->irq) {
			ret = request_irq(entry->irq,
					  msi_test_irq_handler,
					  IRQF_SHARED,
					  test->name, test);
			if (ret)
				return ret;

			test->available++;
		}
	}

	return ret;
}

static int msi_test_start(struct msi_test *test)
{
	struct msi_desc *entry;
	u64 phy_addr;
	void __iomem *virt_addr;

	if (!test->pdev) {
		pr_err("Please first create MSI interrupt\n");
		return 0;
	}

	for_each_msi_entry(entry, &test->pdev->dev) {
		if (entry->irq) {
			phy_addr = ((u64) entry->msg.address_hi) << 32 |
				   entry->msg.address_lo;
			virt_addr = ioremap(phy_addr, 4);
			iowrite32(entry->msg.data, virt_addr);
			iounmap(virt_addr);
		}
	}

	return 0;
}

static ssize_t msi_debug_write_file(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	int len;
	struct msi_test *test = file->private_data;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;

	if (count >= sizeof(msi_test_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(msi_test_ops_buf,
				     sizeof(msi_test_ops_buf)-1,
				     ppos,
				     buf,
				     count);
	if (len < 0)
		return len;

	msi_test_ops_buf[len] = '\0';

	if (strncmp(msi_test_ops_buf, "create", 6) == 0) {
		u32 count;
		int ret;

		ret = kstrtouint(&msi_test_ops_buf[7], 0, &count);
		if (ret) {
			pr_info("Try to create all MSIs\n");
			count = 32 * 4 * 3;
		} else
			pr_info("Create %d MSIs\n", count);

		msi_test_create(test, count);
	} else if (strncmp(msi_test_ops_buf, "start", 5) == 0)
		msi_test_start(test);
	else if (strncmp(msi_test_ops_buf, "remove", 6) == 0)
		msi_test_remove(test);
	else {
		pr_info("Unknown command %s\n", msi_test_ops_buf);
		pr_info("Available commands:\n");
		pr_info("   create <count>\n");
		pr_info("   start\n");
		pr_info("   remove\n");
	}

	return count;
}

static ssize_t msi_debug_read_file(struct file *file, char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	struct msi_test *test = file->private_data;
	struct msi_desc *entry;
	char *buf;
	int i = 0, len = 0;
	ssize_t size, buf_sz;
	unsigned long long phy_addr;

	buf_sz = 4 * PAGE_SIZE;
	buf = kmalloc(buf_sz, GFP_KERNEL);
	if (!buf)
		return 0;

	len += snprintf(buf, buf_sz, "%s: Initialized %d MSI interrupts\n",
			test->dn->full_name, test->available);

	if (test->pdev) {
		for_each_msi_entry(entry, &test->pdev->dev) {
			if (entry->irq) {
				phy_addr = ((u64) entry->msg.address_hi) << 32 |
					   entry->msg.address_lo;
				len += snprintf(buf + len, buf_sz - len,
					"\tMSI%d address:0x%llx data:%d\n",
					i, phy_addr, entry->msg.data);
				i++;
			}
		}
	}

	size = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	return size;
}

static const struct file_operations msi_debug_fops = {
	.open = simple_open,
	.read = msi_debug_read_file,
	.write = msi_debug_write_file,
};

static int __init ls_scfg_msi_test_init(void)
{
	struct device_node *dn;
	struct msi_test *test;
	static int index;

	for_each_node_with_property(dn, "msi-controller") {
		test = kzalloc(sizeof(*test), GFP_KERNEL);
		if (!test)
			return -ENOMEM;

		test->dn = dn;
		pr_info("Find msi-controller %s\n",
			dn->full_name);

		index++;
		sprintf(test->name, "MSI%d-TEST", index);

		test->domain = irq_find_host(dn);
		if (!test->domain) {
			pr_err("Failed to find irq domain of %s\n",
				dn->full_name);
			kfree(test);
			return -ENXIO;
		}

		test->file = debugfs_create_file(test->name, 0644, NULL,
						 test, &msi_debug_fops);
		if (!test->file) {
			kfree(test);
			return -ENOMEM;
		}

		list_add(&test->list, &msi_test_list);
	}

	return 0;
}

static void __exit ls_scfg_msi_test_exit(void)
{
	struct msi_test *test, *tmp;

	list_for_each_entry_safe(test, tmp, &msi_test_list, list) {
			list_del(&test->list);
			msi_test_remove(test);
			debugfs_remove(test->file);
			kfree(test);
		}
}

MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@nxp.com>");
MODULE_DESCRIPTION("Freescale Layerscape SCFG MSI Test Driver");
MODULE_LICENSE("GPL v2");

module_init(ls_scfg_msi_test_init);
module_exit(ls_scfg_msi_test_exit);
