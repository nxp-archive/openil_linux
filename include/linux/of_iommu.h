/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __OF_IOMMU_H
#define __OF_IOMMU_H

#include <linux/device.h>
#include <linux/iommu.h>
#include <linux/of.h>

#ifdef CONFIG_OF_IOMMU

extern int of_get_dma_window(struct device_node *dn, const char *prefix,
			     int index, unsigned long *busno, dma_addr_t *addr,
			     size_t *size);

extern const struct iommu_ops *of_iommu_configure(struct device *dev,
					struct device_node *master_np);

int of_map_rid(struct device_node *np, u32 rid,
	       const char *map_name, const char *map_mask_name,
	       struct device_node **target, u32 *id_out);
#else

static inline int of_get_dma_window(struct device_node *dn, const char *prefix,
			    int index, unsigned long *busno, dma_addr_t *addr,
			    size_t *size)
{
	return -EINVAL;
}

static inline const struct iommu_ops *of_iommu_configure(struct device *dev,
					 struct device_node *master_np)
{
	return NULL;
}

static inline int of_map_rid(struct device_node *np, u32 rid,
			const char *map_name, const char *map_mask_name,
			struct device_node **target, u32 *id_out)
{
	return -EINVAL;
}

#endif	/* CONFIG_OF_IOMMU */

extern struct of_device_id __iommu_of_table;

typedef int (*of_iommu_init_fn)(struct device_node *);

#define IOMMU_OF_DECLARE(name, compat, fn) \
	_OF_DECLARE(iommu, name, compat, fn, of_iommu_init_fn)

#endif /* __OF_IOMMU_H */
