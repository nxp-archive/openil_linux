/*
 * Layerscape MSI(-X) support
 *
 * Copyright (C) 2015 Freescale Semiconductor.
 *
 * Author: Minghuan Lian <Minghuan.Lian@nxp.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/bitmap.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/spinlock.h>
#include <linux/sys_soc.h>

#define LS_MSIR_NUM_MAX		4 /* MSIIR can index 4 MSI registers */
#define IRQS_32_PER_MSIR	32
#define IRQS_8_PER_MSIR		8

#define MSIR_OFFSET(idx)	((idx) * 0x4)

enum msi_affinity_flag {
	MSI_GROUP_AFFINITY_FLAG,
	MSI_AFFINITY_FLAG
};

struct ls_scfg_msi;
struct ls_scfg_msi_ctrl;

struct ls_scfg_msi_cfg {
	u32 ibs_shift; /* Shift of interrupt bit select */
	u32 msir_irqs; /* The irq number per MSIR */
	u32 msir_base; /* The base address of MSIR */
};

struct ls_scfg_msir {
	struct ls_scfg_msi_ctrl *ctrl;
	int index;
	int virq;
};

struct ls_scfg_msi_ctrl {
	struct list_head		list;
	struct ls_scfg_msi		*msi;
	void __iomem			*regs;
	phys_addr_t			msiir_addr;
	int				irq_base;
	spinlock_t			lock;
	struct ls_scfg_msir		*msir;
	unsigned long			*bm;
};

struct ls_scfg_msi {
	struct device_node		*of_node;
	struct device			*dev;
	struct msi_controller		mchip;
	struct msi_domain_info		info;
	struct irq_chip			chip;
	struct irq_domain		*host;
	struct list_head		ctrl_list;
	const struct ls_scfg_msi_cfg	*cfg;
	u32				cpu_num;
};

static struct ls_scfg_msi_cfg ls1021_msi_cfg = {
	.ibs_shift = 3,
	.msir_irqs = IRQS_32_PER_MSIR,
	.msir_base = 0x4,
};

static struct ls_scfg_msi_cfg ls1043_rev11_msi_cfg = {
	.ibs_shift = 2,
	.msir_irqs = IRQS_8_PER_MSIR,
	.msir_base = 0x10,
};

static struct ls_scfg_msi_cfg ls1046_msi_cfg = {
	.ibs_shift = 2,
	.msir_irqs = IRQS_32_PER_MSIR,
	.msir_base = 0x4,
};

static struct soc_device_attribute soc_msi_matches[] = {
	{ .family = "QorIQ LS1021A",
	  .data = &ls1021_msi_cfg },
	{ .family = "QorIQ LS1012A",
	  .data = &ls1021_msi_cfg },
	{ .family = "QorIQ LS1043A", .revision = "1.0",
	  .data = &ls1021_msi_cfg },
	{ .family = "QorIQ LS1043A", .revision = "1.1",
	  .data = &ls1043_rev11_msi_cfg },
	{ .family = "QorIQ LS1046A",
	  .data = &ls1046_msi_cfg },
	{ },
};

static void ls_scfg_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct ls_scfg_msi_ctrl *ctrl = irq_data_get_irq_chip_data(data);
	phys_addr_t addr = ctrl->msiir_addr;
	u32 ibs, srs;

	msg->address_hi = (u32) (addr >> 32);
	msg->address_lo = (u32) (addr);

	ibs = data->hwirq - ctrl->irq_base;
	srs = cpumask_first(data->affinity);
	if (srs >= ctrl->msi->cpu_num)
		srs = 0;

	msg->data = ibs << ctrl->msi->cfg->ibs_shift | srs;

	pr_debug("%s: ibs %d srs %d address0x%x-0x%x data 0x%x\n",
		 __func__, ibs, srs, msg->address_hi,
		 msg->address_lo, msg->data);
}

static int ls_scfg_msi_set_affinity(struct irq_data *data,
				const struct cpumask *mask, bool force)
{
	struct ls_scfg_msi_ctrl *ctrl = irq_data_get_irq_chip_data(data);
	u32 cpu;

	if (!force)
		cpu = cpumask_any_and(mask, cpu_online_mask);
	else
		cpu = cpumask_first(mask);

	if (cpu >= ctrl->msi->cpu_num)
		return -EINVAL;

	if (ctrl->msir[cpu].virq <= 0) {
		pr_warn("cannot bind the irq to cpu%d\n", cpu);
		return -EINVAL;
	}

	cpumask_copy(data->affinity, mask);

	return IRQ_SET_MASK_OK;
}

static struct irq_chip ls_scfg_msi_chip = {
	.name			= "SCFG-MSI",
	.irq_compose_msi_msg	= ls_scfg_msi_compose_msg,
	.irq_set_affinity	= ls_scfg_msi_set_affinity,
};

static int ls_scfg_msi_domain_irq_alloc(struct irq_domain *domain,
					unsigned int virq,
					unsigned int nr_irqs,
					void *args)
{
	struct ls_scfg_msi *msi = domain->host_data;
	static struct list_head *current_entry;
	struct ls_scfg_msi_ctrl *ctrl;
	int i, hwirq = -ENOMEM;

	if (!current_entry || current_entry->next == &msi->ctrl_list)
		current_entry = &msi->ctrl_list;

	list_for_each_entry(ctrl, current_entry, list) {
		spin_lock(&ctrl->lock);
		hwirq = bitmap_find_free_region(ctrl->bm,
						msi->cfg->msir_irqs,
						order_base_2(nr_irqs));
		spin_unlock(&ctrl->lock);

		if (hwirq >= 0)
			break;
	}

	if (hwirq < 0)
		return hwirq;

	hwirq = hwirq + ctrl->irq_base;

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_info(domain, virq + i, hwirq + i,
				    &ls_scfg_msi_chip, ctrl,
				    handle_simple_irq, NULL, NULL);
		set_irq_flags(virq, IRQF_VALID);
	}

	current_entry = &ctrl->list;

	return 0;
}

static void ls_scfg_msi_domain_irq_free(struct irq_domain *domain,
					unsigned int virq,
					unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
	struct ls_scfg_msi_ctrl *ctrl = irq_data_get_irq_chip_data(d);
	int pos;

	pos = d->hwirq - ctrl->irq_base;

	if (pos < 0 || pos >= ctrl->msi->cfg->msir_irqs) {
		pr_err("Failed to teardown msi. Invalid hwirq %d\n", pos);
		return;
	}

	spin_lock(&ctrl->lock);
	bitmap_release_region(ctrl->bm, pos, order_base_2(nr_irqs));
	spin_unlock(&ctrl->lock);
}

static const struct irq_domain_ops ls_scfg_msi_domain_ops = {
	.alloc = ls_scfg_msi_domain_irq_alloc,
	.free = ls_scfg_msi_domain_irq_free,
};

static struct irq_chip ls_scfg_msi_irq_chip = {
	.name = "MSI",
	.irq_mask = pci_msi_mask_irq,
	.irq_unmask = pci_msi_unmask_irq,
};

static struct msi_domain_info ls_scfg_pci_msi_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		   MSI_FLAG_PCI_MSIX),
	.chip	= &ls_scfg_msi_irq_chip,
};

static int ls_scfg_msi_chip_init(struct ls_scfg_msi *msi_data)
{
	int ret;

	/* Initialize MSI domain parent */
	msi_data->host = irq_domain_add_tree(msi_data->of_node,
					     &ls_scfg_msi_domain_ops,
					     msi_data);
	if (!msi_data->host) {
		pr_err("Failed  to init MSI host domain\n");
		return -ENXIO;
	}

	/* Initialize MSI controller */
	msi_data->mchip.of_node = msi_data->of_node;
	msi_data->mchip.domain =
			pci_msi_create_irq_domain(msi_data->of_node,
						  &ls_scfg_pci_msi_domain_info,
						  msi_data->host);

	if (!msi_data->mchip.domain) {
		pr_err("Failed to create MSI domain\n");
		ret = -ENOMEM;
		goto _err;
	}

	ret = of_pci_msi_chip_add(&msi_data->mchip);
	if (ret) {
		pr_err("Failed to add msi_chip\n");
		goto _err;
	}

	return 0;

_err:
	if (msi_data->mchip.domain)
		irq_domain_remove(msi_data->mchip.domain);
	if (msi_data->host)
		irq_domain_remove(msi_data->host);
	return ret;
}

static irqreturn_t ls_scfg_msi_irq_handler(int irq, void *arg)
{
	struct ls_scfg_msir *msir = arg;
	struct ls_scfg_msi_ctrl *ctrl = msir->ctrl;
	struct ls_scfg_msi *msi = ctrl->msi;
	unsigned long val;
	int pos = 0, hwirq, virq;
	irqreturn_t ret = IRQ_NONE;

	val = ioread32be(ctrl->regs + msi->cfg->msir_base +
			 MSIR_OFFSET(msir->index));

	if (msi->cfg->msir_irqs == IRQS_8_PER_MSIR)
		val = (val << (msir->index * 8)) & 0xff000000;

	for_each_set_bit(pos, &val, IRQS_32_PER_MSIR) {
		hwirq = (IRQS_32_PER_MSIR - 1 - pos) + ctrl->irq_base;
		virq = irq_find_mapping(msi->host, hwirq);
		if (virq) {
			generic_handle_irq(virq);
			ret = IRQ_HANDLED;
		}
	}

	return ret;
}

static void ls_scfg_msi_cascade(unsigned int irq, struct irq_desc *desc)
{
	struct ls_scfg_msir *msir = irq_desc_get_handler_data(desc);
	struct irq_chip *chip = irq_desc_get_chip(desc);

	chained_irq_enter(chip, desc);
	ls_scfg_msi_irq_handler(irq, msir);
	chained_irq_exit(chip, desc);
}

static int ls_scfg_msi_setup_hwirq(struct ls_scfg_msi_ctrl *ctrl,
				   struct device_node *node,
				   int index,
				   enum msi_affinity_flag flag)
{
	struct ls_scfg_msir *msir = &ctrl->msir[index];
	int ret;

	msir->virq = of_irq_get(node, index);
	if (msir->virq <= 0)
		return -ENODEV;

	msir->index = index;
	msir->ctrl = ctrl;

	if (flag == MSI_GROUP_AFFINITY_FLAG) {
		ret = request_irq(msir->virq, ls_scfg_msi_irq_handler,
				  IRQF_NO_THREAD, "MSI-GROUP", msir);
		if (ret) {
			pr_err("failed to request irq %d\n", msir->virq);
			msir->virq = 0;
			return -ENODEV;
		}
	} else {
		irq_set_chained_handler(msir->virq, ls_scfg_msi_cascade);
		irq_set_handler_data(msir->virq, msir);
		irq_set_affinity(msir->virq, get_cpu_mask(index));
	}

	return 0;
}

static void ls_scfg_msi_ctrl_remove(struct ls_scfg_msi_ctrl *ctrl)
{
	if (!ctrl)
		return;

	if (ctrl->regs)
		iounmap(ctrl->regs);

	kfree(ctrl->bm);
	kfree(ctrl->msir);
	kfree(ctrl);
}

static int ls_scfg_msi_ctrl_probe(struct device_node *node,
				  struct ls_scfg_msi *msi)
{
	struct ls_scfg_msi_ctrl *ctrl;
	struct resource res;
	static int ctrl_idx;
	int err, irqs, i;
	enum msi_affinity_flag flag;

	err = of_address_to_resource(node, 0, &res);
	if (err) {
		pr_warn("%s: no regs\n", node->full_name);
		return -ENXIO;
	}

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return  -ENOMEM;

	ctrl->msi = msi;
	ctrl->msiir_addr = res.start;
	spin_lock_init(&ctrl->lock);

	ctrl->regs = ioremap(res.start, resource_size(&res));
	if (!ctrl->regs) {
		pr_err("%s: unable to map registers\n", node->full_name);
		err = -ENOMEM;
		goto _err;
	}

	ctrl->msir = kcalloc(msi->cpu_num, sizeof(struct ls_scfg_msir),
			     GFP_KERNEL);
	if (!ctrl->msir) {
		err = -ENOMEM;
		goto _err;
	}

	ctrl->bm = kcalloc(BITS_TO_LONGS(msi->cfg->msir_irqs), sizeof(long),
			   GFP_KERNEL);
	if (!ctrl->bm) {
		err = -ENOMEM;
		goto _err;
	}

	ctrl->irq_base = msi->cfg->msir_irqs * ctrl_idx;
	ctrl_idx++;

	irqs = of_irq_count(node);
	if (irqs >= msi->cpu_num)
		flag = MSI_AFFINITY_FLAG;
	else
		flag = MSI_GROUP_AFFINITY_FLAG;

	for (i = 0; i < msi->cpu_num; i++)
		ls_scfg_msi_setup_hwirq(ctrl, node, i, flag);

	list_add_tail(&ctrl->list, &msi->ctrl_list);

	return 0;

_err:
	ls_scfg_msi_ctrl_remove(ctrl);
	pr_err("MSI: failed probing %s (%d)\n", node->full_name, err);
	return err;
}

static int __init ls_scfg_msi_probe(struct platform_device *pdev)
{
	struct ls_scfg_msi *msi_data;
	const struct soc_device_attribute *match;
	struct device_node *child;

	msi_data = devm_kzalloc(&pdev->dev, sizeof(*msi_data), GFP_KERNEL);
	if (!msi_data)
		return -ENOMEM;

	msi_data->of_node = pdev->dev.of_node;
	INIT_LIST_HEAD(&msi_data->ctrl_list);

	msi_data->cpu_num = num_possible_cpus();

	match = soc_device_match(soc_msi_matches);
	if (match)
		msi_data->cfg = match->data;
	else
		msi_data->cfg = &ls1046_msi_cfg;

	dev_info(&pdev->dev, "ibs_shift:%d msir_irqs:%d msir_base:0x%x\n",
		 msi_data->cfg->ibs_shift,
		 msi_data->cfg->msir_irqs,
		 msi_data->cfg->msir_base);

	for_each_child_of_node(msi_data->of_node, child)
		ls_scfg_msi_ctrl_probe(child, msi_data);

	ls_scfg_msi_chip_init(msi_data);

	return 0;
}

static const struct of_device_id ls_scfg_msi_id[] = {
	{ .compatible = "fsl,ls-scfg-msi" },
	{},
};

static struct platform_driver ls_scfg_msi_driver = {
	.driver = {
		.name = "ls-scfg-msi",
		.of_match_table = ls_scfg_msi_id,
	},
	.probe = ls_scfg_msi_probe,
};

module_platform_driver(ls_scfg_msi_driver);

MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@nxp.com>");
MODULE_DESCRIPTION("Freescale Layerscape SCFG MSI controller driver");
MODULE_LICENSE("GPL v2");
