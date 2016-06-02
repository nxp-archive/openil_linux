/*
 * Layerscape MSI(-X) support
 *
 * Copyright (C) 2015 Freescale Semiconductor.
 *
 * Author: Minghuan Lian <Minghuan.Lian@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/bitmap.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#define MAX_MSI_IRQS	32

struct ls1_msi {
	char			name[32];
	struct device_node	*of_node;
	spinlock_t		lock;
	struct msi_controller	mchip;
	struct msi_domain_info	info;
	struct irq_chip		chip;
	struct irq_domain	*parent;
	void __iomem		*msir;
	phys_addr_t		msiir_addr;
	unsigned long		*bm;
	u32			nr_irqs;
	int			msi_irq;
};

static void ls1_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct ls1_msi *msi_data = irq_data_get_irq_chip_data(data);
	phys_addr_t addr = msi_data->msiir_addr;

	msg->address_hi = (u32) (addr >> 32);
	msg->address_lo = (u32) (addr);
	msg->data = data->hwirq * 8;
}

static int ls1_msi_set_affinity(struct irq_data *irq_data,
				    const struct cpumask *mask, bool force)
{
	return 0;
}

static struct irq_chip ls1_msi_parent_chip = {
	.name			= "LS1-MSI",
	.irq_compose_msi_msg	= ls1_msi_compose_msg,
	.irq_set_affinity	= ls1_msi_set_affinity,
};

static int ls1_msi_domain_irq_alloc(struct irq_domain *domain, unsigned int virq,
				   unsigned int nr_irqs, void *args)
{
	struct ls1_msi *msi_data = domain->host_data;
	int i, pos;

	spin_lock(&msi_data->lock);
	pos = bitmap_find_free_region(msi_data->bm, msi_data->nr_irqs,
				      order_base_2(nr_irqs));
	spin_unlock(&msi_data->lock);

	if (pos < 0)
		return -ENOSPC;

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_info(domain, virq + i, pos + i,
				    &ls1_msi_parent_chip, msi_data,
				    handle_simple_irq, NULL, NULL);
		set_irq_flags(virq, IRQF_VALID);
	}

	return 0;
}

static void ls1_msi_domain_irq_free(struct irq_domain *domain,
				   unsigned int virq, unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
	struct ls1_msi *msi_data = irq_data_get_irq_chip_data(d);
	int pos;

	pos = d->hwirq;
	if (pos < 0 || pos >= msi_data->nr_irqs) {
		pr_err("Failed to teardown msi. Invalid hwirq %d\n", pos);
		return;
	}

	spin_lock(&msi_data->lock);
	bitmap_release_region(msi_data->bm, pos, order_base_2(nr_irqs));
	spin_unlock(&msi_data->lock);
}

static const struct irq_domain_ops ls1_msi_domain_parent_ops = {
	.alloc			= ls1_msi_domain_irq_alloc,
	.free			= ls1_msi_domain_irq_free,
};

static irqreturn_t ls1_msi_handler(int irq, void *arg)
{
	struct ls1_msi *msi_data = arg;
	unsigned long val;
	int pos, virq;
	irqreturn_t ret = IRQ_NONE;

	val = ioread32be(msi_data->msir);
	pos = 0;

	while ((pos = find_next_bit(&val, 32, pos)) != 32) {
		virq = irq_find_mapping(msi_data->parent, 31 - pos);
		if (virq != NO_IRQ) {
			generic_handle_irq(virq);
			ret = IRQ_HANDLED;
		}
		pos++;
	}

	return ret;
}

static irq_hw_number_t ls1_msi_domain_ops_get_hwirq(struct msi_domain_info *info,
						msi_alloc_info_t *arg)
{
	struct ls1_msi *msi_data = container_of(info, struct ls1_msi, info);

	arg->hwirq = find_first_zero_bit(msi_data->bm, msi_data->nr_irqs);

	return arg->hwirq;
}

static void ls1_msi_domain_ops_free(struct irq_domain *domain,
				    struct msi_domain_info *info,
				    unsigned int virq)
{
	/* Nothing need to do */
}

static struct msi_domain_ops ls1_pci_msi_ops = {
	.get_hwirq	= ls1_msi_domain_ops_get_hwirq,
	.msi_free	= ls1_msi_domain_ops_free,
};

static int ls1_msi_chip_init(struct ls1_msi *msi_data)
{
	int ret;

	/* Initialize MSI domain parent */
	msi_data->parent = irq_domain_add_linear(msi_data->of_node,
						 msi_data->nr_irqs,
						 &ls1_msi_domain_parent_ops,
						 msi_data);
	if (!msi_data->parent) {
		pr_err("MSI domain %s parent init failed\n", msi_data->name);
		return -ENXIO;
	}

	/* Initialize MSI irq chip */
	msi_data->chip.name = msi_data->name;

	/* Initialize MSI domain info */
	msi_data->info.flags = MSI_FLAG_USE_DEF_DOM_OPS |
			       MSI_FLAG_USE_DEF_CHIP_OPS |
			       MSI_FLAG_PCI_MSIX |
			       MSI_FLAG_MULTI_PCI_MSI;
	msi_data->info.chip = &msi_data->chip;
	msi_data->info.ops = &ls1_pci_msi_ops;

	/* Initialize MSI controller */
	msi_data->mchip.of_node = msi_data->of_node;
	msi_data->mchip.domain =
			pci_msi_create_irq_domain(msi_data->of_node,
						  &msi_data->info,
						  msi_data->parent);

	if (!msi_data->mchip.domain) {
		pr_err("Failed to create MSI domain %s\n", msi_data->name);
		ret = -ENOMEM;
		goto _err;
	}

	ret = of_pci_msi_chip_add(&msi_data->mchip);
	if (ret) {
		pr_err("Failed to add msi_chip %s\n", msi_data->name);
		goto _err;
	}

	return 0;

_err:
	if (msi_data->mchip.domain)
		irq_domain_remove(msi_data->mchip.domain);
	if (msi_data->parent)
		irq_domain_remove(msi_data->parent);
	return ret;
}


static int __init ls1_msi_probe(struct platform_device *pdev)
{
	struct ls1_msi *msi_data;
	struct resource *res;
	static int ls1_msi_idx;
	int ret;

	msi_data = devm_kzalloc(&pdev->dev, sizeof(*msi_data), GFP_KERNEL);
	if (!msi_data) {
		dev_err(&pdev->dev, "Failed to allocate struct ls1_msi.\n");
		return -ENOMEM;
	}

	msi_data->of_node = pdev->dev.of_node;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "missing msiir.\n");
		return -ENODEV;
	}

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "msiir");
	if (!res) {
		dev_err(&pdev->dev, "missing *msiir* space\n");
		return -ENODEV;
	}

	msi_data->msiir_addr = res->start;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "msir");
	if (!res) {
		dev_err(&pdev->dev, "missing *msir* space\n");
		return -ENODEV;
	}

	msi_data->msir = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(msi_data->msir))
		return PTR_ERR(msi_data->msir);

	msi_data->msi_irq = platform_get_irq(pdev, 0);
	if (msi_data->msi_irq <= 0) {
		dev_err(&pdev->dev, "failed to get MSI irq\n");
		return -ENODEV;
	}

	msi_data->nr_irqs = MAX_MSI_IRQS;

	msi_data->bm = devm_kzalloc(&pdev->dev, sizeof(long) *
				    BITS_TO_LONGS(msi_data->nr_irqs),
				    GFP_KERNEL);
	if (!msi_data->bm)
		ret = -ENOMEM;

	ls1_msi_idx++;
	snprintf(msi_data->name, sizeof(msi_data->name), "MSI%d", ls1_msi_idx);

	spin_lock_init(&msi_data->lock);

	ret = devm_request_irq(&pdev->dev, msi_data->msi_irq,
			       ls1_msi_handler, IRQF_SHARED,
			       msi_data->name, msi_data);
	if (ret) {
		dev_err(&pdev->dev, "failed to request MSI irq\n");
		return -ENODEV;
	}

	return ls1_msi_chip_init(msi_data);
}

static struct of_device_id ls1_msi_id[] = {
	{ .compatible = "fsl,ls1021a-msi", },
	{ .compatible = "fsl,ls1043a-msi", },
	{},
};

static struct platform_driver ls1_msi_driver = {
	.driver = {
		.name = "ls1-msi",
		.of_match_table = ls1_msi_id,
	},
};

module_platform_driver_probe(ls1_msi_driver, ls1_msi_probe);

MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@freescale.com>");
MODULE_DESCRIPTION("Freescale Layerscape 1 MSI controller driver");
MODULE_LICENSE("GPL v2");
