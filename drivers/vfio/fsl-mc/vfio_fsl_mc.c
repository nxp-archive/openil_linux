/*
 * Freescale Management Complex (MC) device passthrough using VFIO
 *
 * Copyright (C) 2014 Freescale Semiconductor, Inc.
 * Author: Bharat Bhushan <bharat.bhushan@freescale.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/device.h>
#include <linux/eventfd.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/fs.h>
#include "../../staging/fsl-mc/include/mc.h"
#include "../../staging/fsl-mc/include/mc-sys.h"
#include "../../staging/fsl-mc/include/mc-private.h"

#include "vfio_fsl_mc_private.h"
struct fsl_mc_io *vfio_mc_io = NULL;
struct fsl_mc_io *vfio_atomic_mc_io = NULL;

static DEFINE_MUTEX(driver_lock);

/* Validate that requested address range falls in one of container's
 * device region.
 */
static bool vfio_validate_mmap_addr(struct vfio_fsl_mc_device *vdev,
				    unsigned long addr, unsigned long size)
{
	struct fsl_mc_device *mc_dev = vdev->mc_dev;
	phys_addr_t region_addr;
	size_t region_size;
	int idx;

	/* Do not try to validate if address range wraps */
	if ((addr + size) < addr)
		return false;

	/* Hack to allow mmap GITS_TRANSLATOR Register Page */
	if (addr == 0x6030000)
		return true;

	for (idx = 0; idx < mc_dev->obj_desc.region_count; idx++) {
		region_addr = mc_dev->regions[idx].start;
		region_size = mc_dev->regions[idx].end -
				       mc_dev->regions[idx].start + 1;

		/*
		 * Align search to minimum mappable size of PAGE_SIZE.
		 * Thanks to our hardware that even though the
		 * region_size is less then PAGE_SIZE but there
		 * is no other device maps in this address range.
		 * So no security threat/issue in mapping PAGE_SIZE.
		 */
		if (region_size < PAGE_SIZE)
			region_size = PAGE_SIZE;

		if (addr >= region_addr &&
		    ((addr + size) <= (region_addr + region_size)))
			return true;
	}

	return false;
}

static long vfio_fsl_mc_ioctl(void *device_data,
				  unsigned int cmd, unsigned long arg)
{
	struct vfio_fsl_mc_device *vdev = device_data;
	struct fsl_mc_device *mc_dev = vdev->mc_dev;
	struct device *dev = &mc_dev->dev;
	unsigned long minsz;
	int ret;

	if (WARN_ON(!mc_dev))
		return -ENODEV;

	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
	{
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.flags = VFIO_DEVICE_FLAGS_FSL_MC;
		if (strcmp(mc_dev->obj_desc.type, "dprc") == 0)
			info.flags |= VFIO_DEVICE_FLAGS_RESET;

		info.num_regions = mc_dev->obj_desc.region_count;
		info.num_irqs = mc_dev->obj_desc.irq_count;

		return copy_to_user((void __user *)arg, &info, minsz);
	}
	case VFIO_DEVICE_GET_REGION_INFO:
	{
		struct vfio_region_info info;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.offset = mc_dev->regions[info.index].start;
		info.size = mc_dev->regions[info.index].end -
				mc_dev->regions[info.index].start + 1;
		info.flags = VFIO_REGION_INFO_FLAG_READ |
			      VFIO_REGION_INFO_FLAG_WRITE |
			      VFIO_REGION_INFO_FLAG_MMAP;

		return copy_to_user((void __user *)arg, &info, minsz);
	}
	case VFIO_DEVICE_GET_IRQ_INFO:
	{
		struct vfio_irq_info info;

		minsz = offsetofend(struct vfio_irq_info, count);
		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		if (info.index >= mc_dev->obj_desc.irq_count)
			return -EINVAL;

		if (vdev->mc_irqs[info.index].irq_initialized) {
			info.flags = vdev->mc_irqs[info.index].flags;
			info.count = vdev->mc_irqs[info.index].count;
		} else {
			/*
			 * If IRQs are not initialized then these can not
			 * be configuted and used by user-space/
			 */
			info.flags = 0;
			info.count = 0;
		}

		return copy_to_user((void __user *)arg, &info, minsz);
	}
	case VFIO_DEVICE_SET_IRQS:
	{
		struct vfio_irq_set hdr;
		u8 *data = NULL;
		int ret = 0;

		minsz = offsetofend(struct vfio_irq_set, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		if (hdr.argsz < minsz)
			return -EINVAL;

		if (hdr.index >= mc_dev->obj_desc.irq_count)
			return -EINVAL;

		if (hdr.start != 0 || hdr.count > 1)
			return -EINVAL;

		if (hdr.count == 0 &&
		    (!(hdr.flags & VFIO_IRQ_SET_DATA_NONE) ||
		    !(hdr.flags & VFIO_IRQ_SET_ACTION_TRIGGER)))
			return -EINVAL;

		if (hdr.flags & ~(VFIO_IRQ_SET_DATA_TYPE_MASK |
				  VFIO_IRQ_SET_ACTION_TYPE_MASK))
			return -EINVAL;

		if (!(hdr.flags & VFIO_IRQ_SET_DATA_NONE)) {
			size_t size;

			if (hdr.flags & VFIO_IRQ_SET_DATA_BOOL)
				size = sizeof(uint8_t);
			else if (hdr.flags & VFIO_IRQ_SET_DATA_EVENTFD)
				size = sizeof(int32_t);
			else
				return -EINVAL;

			if (hdr.argsz - minsz < hdr.count * size)
				return -EINVAL;

			data = memdup_user((void __user *)(arg + minsz),
					   hdr.count * size);
			if (IS_ERR(data))
				return PTR_ERR(data);
		}

		ret = vfio_fsl_mc_set_irqs_ioctl(vdev, hdr.flags,
						 hdr.index, hdr.start,
						 hdr.count, data);
		return ret;
	}
	case VFIO_DEVICE_RESET:
	{
		if (strcmp(mc_dev->obj_desc.type, "dprc") != 0)
			return -EINVAL;

		ret = dprc_reset_container(mc_dev->mc_io, 0,
					   mc_dev->mc_handle,
					   mc_dev->obj_desc.id);
		if (ret) {
			dev_err(dev, "Error in resetting container %d\n", ret);
			return ret;
		}

		ret = 0;
		break;
	}
	default:
			ret = -EINVAL;
	}

	return ret;
}

static ssize_t vfio_fsl_mc_read(void *device_data, char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct vfio_fsl_mc_device *vdev = device_data;
	struct fsl_mc_device *mc_dev = vdev->mc_dev;
	struct device *dev = &mc_dev->dev;

	dev_err(dev, "%s: Unimplemented\n", __func__);
	return -EFAULT;
}

static ssize_t vfio_fsl_mc_write(void *device_data, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct vfio_fsl_mc_device *vdev = device_data;
	struct fsl_mc_device *mc_dev = vdev->mc_dev;
	struct device *dev = &mc_dev->dev;

	dev_err(dev, "%s: Unimplemented\n", __func__);
	return -EFAULT;
}

/* Allows mmaping fsl_mc device regions in assigned DPRC */
static int vfio_fsl_mc_mmap(void *device_data, struct vm_area_struct *vma)
{
	struct vfio_fsl_mc_device *vdev = device_data;
	struct fsl_mc_device *mc_dev = vdev->mc_dev;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long addr = vma->vm_pgoff << PAGE_SHIFT;
	int ret;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if (vma->vm_start & ~PAGE_MASK)
		return -EINVAL;
	if (vma->vm_end & ~PAGE_MASK)
		return -EINVAL;
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;

	if (!vfio_validate_mmap_addr(vdev, addr, size))
		return -EINVAL;

	vma->vm_private_data = mc_dev;

#define QBMAN_SWP_CENA_BASE 0x818000000ULL
	if ((addr & 0xFFF000000) == QBMAN_SWP_CENA_BASE)
		vma->vm_page_prot = pgprot_cached(vma->vm_page_prot);
	else
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	ret = remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			      size, vma->vm_page_prot);
	return ret;
}

static void vfio_fsl_mc_release(void *device_data)
{
	struct vfio_fsl_mc_device *vdev = device_data;
	struct fsl_mc_device *mc_dev = vdev->mc_dev;

	if (WARN_ON(mc_dev == NULL))
		return;

	mutex_lock(&driver_lock);
	vdev->refcnt--;

	if (strcmp(mc_dev->obj_desc.type, "dprc") == 0)
		dprc_reset_container(mc_dev->mc_io, 0, mc_dev->mc_handle,
				     mc_dev->obj_desc.id);
	else
		vfio_fsl_mc_unconfigure_irqs(vdev);

	mutex_unlock(&driver_lock);

	module_put(THIS_MODULE);
}

static int vfio_fsl_mc_open(void *device_data)
{
	struct vfio_fsl_mc_device *vdev = device_data;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	mutex_lock(&driver_lock);
	vdev->refcnt++;
	mutex_unlock(&driver_lock);

	return 0;
}

static const struct vfio_device_ops vfio_fsl_mc_ops = {
	.name		= "vfio-fsl-mc",
	.open		= vfio_fsl_mc_open,
	.release	= vfio_fsl_mc_release,
	.ioctl		= vfio_fsl_mc_ioctl,
	.read		= vfio_fsl_mc_read,
	.write		= vfio_fsl_mc_write,
	.mmap		= vfio_fsl_mc_mmap,
};

static int vfio_fsl_mc_device_remove(struct device *dev, void *data)
{
	struct fsl_mc_device *mc_dev;
	WARN_ON(dev == NULL);

	mc_dev = to_fsl_mc_device(dev);
	WARN_ON(mc_dev == NULL);
		return -ENODEV;

	fsl_mc_device_remove(mc_dev);
	return 0;
}

static int vfio_fsl_mc_probe(struct fsl_mc_device *mc_dev)
{
	struct vfio_fsl_mc_device *vdev;
	struct iommu_group *group;
	struct device *dev = &mc_dev->dev;
	struct fsl_mc_bus *mc_bus;
	unsigned int irq_count;
	int ret, i;

	dev_info(dev, "Binding with vfio-fsl_mc driver\n");

	group = iommu_group_get(dev);
	if (!group) {
		dev_err(dev, "%s: VFIO: No IOMMU group\n", __func__);
		return -EINVAL;
	}

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev) {
		iommu_group_put(group);
		return -ENOMEM;
	}

	if (strcmp(mc_dev->obj_desc.type, "dprc") == 0) {
		vdev->mc_dev = mc_dev;

		/* Free inbuilt dprc MC portal if exists */
		if (mc_dev->mc_io  && (mc_dev->mc_io != vfio_mc_io))
			fsl_destroy_mc_io(mc_dev->mc_io);

		/* Use New Allocated MC Portal (DPMCP object) */
		mc_dev->mc_io = vfio_mc_io;

		ret = dprc_open(mc_dev->mc_io,
				0,
				mc_dev->obj_desc.id,
				&mc_dev->mc_handle);
		if (ret) {
			dev_err(dev, "dprc_open() failed: error = %d\n", ret);
			goto free_vfio_device;
		}

		/* Initialize resource pool */
		dprc_init_all_resource_pools(mc_dev);

		mc_bus = to_fsl_mc_bus(mc_dev);
		mutex_init(&mc_bus->scan_mutex);

		mc_bus->atomic_mc_io = vfio_atomic_mc_io;
		ret = dprc_open(mc_bus->atomic_mc_io, 0, mc_dev->obj_desc.id,
				&mc_bus->atomic_dprc_handle);
		if (ret < 0) {
			dev_err(dev, "fail to open dprc with atomic io (%d)\n", ret);
			goto clean_resource_pool;
		}

		if (fsl_mc_interrupts_supported() && !mc_bus->irq_resources) {
			irq_count = FSL_MC_IRQ_POOL_MAX_EXTRA_IRQS;
			ret = fsl_mc_populate_irq_pool(mc_bus, irq_count);
			if (ret < 0) {
				dev_err(dev, "%s: Failed to init irq-pool\n",
				__func__);
				goto free_open_dprc;
			}
		}

		mutex_lock(&mc_bus->scan_mutex);
		ret = dprc_scan_objects(mc_dev, mc_dev->driver_override,
					&irq_count);
		mutex_unlock(&mc_bus->scan_mutex);
		if (ret) {
			dev_err(dev, "dprc_scan_objects() fails (%d)\n", ret);
			goto clean_irq_pool;
		}

		ret = vfio_add_group_dev(dev, &vfio_fsl_mc_ops, vdev);
		if (ret) {
			dev_err(dev, "%s: Failed to add to vfio group\n",
				__func__);
			goto dprc_clean_scan_objects;
		}

		ret = vfio_fsl_mc_init_irqs(vdev);
		if (ret) {
			dev_err(dev, "%s: Failed to setup irqs\n",
				__func__);
			vfio_del_group_dev(dev);
			goto dprc_clean_scan_objects;
		}

		for (i = 0; i < mc_dev->obj_desc.irq_count; i++) {
			ret = vfio_fsl_mc_configure_irq(vdev, i);
			if (ret) {
				dev_err(dev, "Fails (%d) to config irq\n", ret);
				vfio_del_group_dev(dev);
				goto dprc_clean_irqs;
			}
		}
	} else {
		vdev->mc_dev = mc_dev;

		/* Use New Allocated MC Portal (DPMCP object) */
		mc_dev->mc_io = vfio_mc_io;

		ret = vfio_add_group_dev(dev, &vfio_fsl_mc_ops, vdev);
		if (ret) {
			dev_err(dev, "%s: Failed to add to vfio group\n",
				__func__);
			goto free_vfio_device;
		}

		if (mc_dev->obj_desc.irq_count) {
			ret = vfio_fsl_mc_init_irqs(vdev);
			if (ret) {
				dev_err(dev, "%s: Failed to setup irqs\n",
					__func__);
				vfio_del_group_dev(dev);
				goto free_vfio_device;
			}
		}
	}

	return 0;

dprc_clean_irqs:
	vfio_fsl_mc_free_irqs(vdev);

dprc_clean_scan_objects:
	fsl_mc_cleanup_irq_pool(mc_bus);
	device_for_each_child(&mc_dev->dev, NULL, vfio_fsl_mc_device_remove);

clean_irq_pool:
	fsl_mc_cleanup_irq_pool(mc_bus);

free_open_dprc:
	dprc_close(vfio_atomic_mc_io, 0, mc_dev->mc_handle);

clean_resource_pool:
	dprc_cleanup_all_resource_pools(mc_dev);
	dprc_close(mc_dev->mc_io, 0, mc_dev->mc_handle);

free_vfio_device:
	kfree(vdev);
	iommu_group_put(group);
	return ret;
}

static int vfio_fsl_mc_remove(struct fsl_mc_device *mc_dev)
{
	struct vfio_fsl_mc_device *vdev;
	struct fsl_mc_bus *mc_bus;
	int ret;

	dev_info(&mc_dev->dev, "Un-binding with vfio-fsl-mc driver\n");

	vdev = vfio_del_group_dev(&mc_dev->dev);
	if (!vdev)
		return -EINVAL;

	/* Only FSL-MC DPRC device can be unbound */
	if (strcmp(mc_dev->obj_desc.type, "dprc") == 0) {
		device_for_each_child(&mc_dev->dev, NULL,
				      vfio_fsl_mc_device_remove);

		vfio_fsl_mc_free_irqs(vdev);
		dprc_cleanup_all_resource_pools(mc_dev);
		mc_bus = to_fsl_mc_bus(mc_dev);

		if (fsl_mc_interrupts_supported())
			fsl_mc_cleanup_irq_pool(mc_bus);

		ret = dprc_close(mc_dev->mc_io,
				 0,
				 mc_dev->mc_handle);
		if (ret < 0) {
			dev_err(&mc_dev->dev, "dprc_close() fails: error %d\n",
				ret);
		}
	} else
		vfio_fsl_mc_free_irqs(vdev);

	iommu_group_put(mc_dev->dev.iommu_group);
	kfree(vdev);

	return 0;
}

/*
 * vfio-fsl_mc is a meta-driver, so use driver_override interface to
 * bind a fsl_mc container with this driver and match_id_table is NULL.
 */
static struct fsl_mc_driver vfio_fsl_mc_driver = {
	.probe		= vfio_fsl_mc_probe,
	.remove		= vfio_fsl_mc_remove,
	.match_id_table = NULL,
	.driver	= {
		.name	= "vfio-fsl-mc",
		.owner	= THIS_MODULE,
	},
};

static int __init vfio_fsl_mc_driver_init(void)
{
	int err;
	struct fsl_mc_device *root_mc_dev;

	if (fsl_mc_bus_type.dev_root == NULL) {
		pr_err("%s: Driver registration fails as no fsl_mc_bus found\n",
		       __func__);
		return -ENODEV;
	}

	root_mc_dev = to_fsl_mc_device(fsl_mc_bus_type.dev_root);

	/* Allocate a new MC portal (DPMCP object) */
	err = fsl_mc_portal_allocate(root_mc_dev, 0, &vfio_mc_io);
	if (err < 0)
		goto err;

	/* Reset MCP before move on */
	err = fsl_mc_portal_reset(vfio_mc_io);
	if (err < 0)
		return err;

	/* Allocate a new MC portal (DPMCP object) */
	err = fsl_mc_portal_allocate(root_mc_dev,
				     FSL_MC_IO_ATOMIC_CONTEXT_PORTAL,
				     &vfio_atomic_mc_io);
	if (err < 0)
		goto err;

	err = fsl_mc_driver_register(&vfio_fsl_mc_driver);
	if (err < 0)
		goto err;

	return 0;
err:
	if (vfio_mc_io)
		fsl_mc_portal_free(vfio_mc_io);

	if (vfio_atomic_mc_io)
		fsl_mc_portal_free(vfio_atomic_mc_io);

	vfio_atomic_mc_io = NULL;
	vfio_mc_io = NULL;
	return err;
}

static void __exit vfio_fsl_mc_driver_exit(void)
{
	fsl_mc_portal_free(vfio_mc_io);
	fsl_mc_portal_free(vfio_atomic_mc_io);
	fsl_mc_driver_unregister(&vfio_fsl_mc_driver);
}

module_init(vfio_fsl_mc_driver_init);
module_exit(vfio_fsl_mc_driver_exit);

MODULE_AUTHOR("Bharat Bhushan <bharat.bhushan@freescale.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("VFIO for FSL MC devices - User Level meta-driver");
