/*
 * Freescale data path resource container (DPRC) driver
 *
 * Copyright (C) 2014 Freescale Semiconductor, Inc.
 * Author: German Rivera <German.Rivera@freescale.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "../include/mc-private.h"
#include "../include/mc-sys.h"
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include "dprc-cmd.h"
#include "dpmcp.h"

struct dprc_child_objs {
	int child_count;
	struct dprc_obj_desc *child_array;
};

static int __fsl_mc_device_remove_if_not_in_mc(struct device *dev, void *data)
{
	int i;
	struct dprc_child_objs *objs;
	struct fsl_mc_device *mc_dev;

	WARN_ON(!dev);
	WARN_ON(!data);
	mc_dev = to_fsl_mc_device(dev);
	objs = data;

	for (i = 0; i < objs->child_count; i++) {
		struct dprc_obj_desc *obj_desc = &objs->child_array[i];

		if (strlen(obj_desc->type) != 0 &&
		    FSL_MC_DEVICE_MATCH(mc_dev, obj_desc))
			break;
	}

	if (i == objs->child_count)
		fsl_mc_device_remove(mc_dev);

	return 0;
}

static int __fsl_mc_device_remove(struct device *dev, void *data)
{
	WARN_ON(!dev);
	WARN_ON(data);
	fsl_mc_device_remove(to_fsl_mc_device(dev));
	return 0;
}

/**
 * dprc_remove_devices - Removes devices for objects removed from a DPRC
 *
 * @mc_bus_dev: pointer to the fsl-mc device that represents a DPRC object
 * @obj_desc_array: array of object descriptors for child objects currently
 * present in the DPRC in the MC.
 * @num_child_objects_in_mc: number of entries in obj_desc_array
 *
 * Synchronizes the state of the Linux bus driver with the actual state of
 * the MC by removing devices that represent MC objects that have
 * been dynamically removed in the physical DPRC.
 */
static void dprc_remove_devices(struct fsl_mc_device *mc_bus_dev,
				struct dprc_obj_desc *obj_desc_array,
				int num_child_objects_in_mc)
{
	if (num_child_objects_in_mc != 0) {
		/*
		 * Remove child objects that are in the DPRC in Linux,
		 * but not in the MC:
		 */
		struct dprc_child_objs objs;

		objs.child_count = num_child_objects_in_mc;
		objs.child_array = obj_desc_array;
		device_for_each_child(&mc_bus_dev->dev, &objs,
				      __fsl_mc_device_remove_if_not_in_mc);
	} else {
		/*
		 * There are no child objects for this DPRC in the MC.
		 * So, remove all the child devices from Linux:
		 */
		device_for_each_child(&mc_bus_dev->dev, NULL,
				      __fsl_mc_device_remove);
	}
}

static int __fsl_mc_device_match(struct device *dev, void *data)
{
	struct dprc_obj_desc *obj_desc = data;
	struct fsl_mc_device *mc_dev = to_fsl_mc_device(dev);

	return FSL_MC_DEVICE_MATCH(mc_dev, obj_desc);
}

static struct fsl_mc_device *fsl_mc_device_lookup(struct dprc_obj_desc
								*obj_desc,
						  struct fsl_mc_device
								*mc_bus_dev)
{
	struct device *dev;

	dev = device_find_child(&mc_bus_dev->dev, obj_desc,
				__fsl_mc_device_match);

	return dev ? to_fsl_mc_device(dev) : NULL;
}

/**
 * check_plugged_state_change - Check change in an MC object's plugged state
 *
 * @mc_dev: pointer to the fsl-mc device for a given MC object
 * @obj_desc: pointer to the MC object's descriptor in the MC
 *
 * If the plugged state has changed from unplugged to plugged, the fsl-mc
 * device is bound to the corresponding device driver.
 * If the plugged state has changed from plugged to unplugged, the fsl-mc
 * device is unbound from the corresponding device driver.
 */
static void check_plugged_state_change(struct fsl_mc_device *mc_dev,
				       struct dprc_obj_desc *obj_desc)
{
	int error;
	uint32_t plugged_flag_at_mc =
			(obj_desc->state & DPRC_OBJ_STATE_PLUGGED);

	if (plugged_flag_at_mc !=
	    (mc_dev->obj_desc.state & DPRC_OBJ_STATE_PLUGGED)) {
		if (plugged_flag_at_mc) {
			mc_dev->obj_desc.state |= DPRC_OBJ_STATE_PLUGGED;
			error = device_attach(&mc_dev->dev);
			if (error < 0) {
				dev_err(&mc_dev->dev,
					"device_attach() failed: %d\n",
					error);
			}
		} else {
			mc_dev->obj_desc.state &= ~DPRC_OBJ_STATE_PLUGGED;
			device_release_driver(&mc_dev->dev);
		}
	}
}

/**
 * dprc_add_new_devices - Adds devices to the logical bus for a DPRC
 *
 * @mc_bus_dev: pointer to the fsl-mc device that represents a DPRC object
 * @driver_override: driver override to apply to new objects found in the DPRC,
 * or NULL, if none.
 * @obj_desc_array: array of device descriptors for child devices currently
 * present in the physical DPRC.
 * @num_child_objects_in_mc: number of entries in obj_desc_array
 *
 * Synchronizes the state of the Linux bus driver with the actual
 * state of the MC by adding objects that have been newly discovered
 * in the physical DPRC.
 */
static void dprc_add_new_devices(struct fsl_mc_device *mc_bus_dev,
				 const char *driver_override,
				 struct dprc_obj_desc *obj_desc_array,
				 int num_child_objects_in_mc)
{
	int error;
	int i;

	for (i = 0; i < num_child_objects_in_mc; i++) {
		struct fsl_mc_device *child_dev;
		struct dprc_obj_desc *obj_desc = &obj_desc_array[i];

		if (strlen(obj_desc->type) == 0)
			continue;

		/*
		 * Check if device is already known to Linux:
		 */
		child_dev = fsl_mc_device_lookup(obj_desc, mc_bus_dev);
		if (child_dev) {
			check_plugged_state_change(child_dev, obj_desc);
			continue;
		}

		error = fsl_mc_device_add(obj_desc, NULL, &mc_bus_dev->dev,
					  driver_override, &child_dev);
		if (error < 0)
			continue;
	}
}

void dprc_init_all_resource_pools(struct fsl_mc_device *mc_bus_dev)
{
	int pool_type;
	struct fsl_mc_bus *mc_bus = to_fsl_mc_bus(mc_bus_dev);

	for (pool_type = 0; pool_type < FSL_MC_NUM_POOL_TYPES; pool_type++) {
		struct fsl_mc_resource_pool *res_pool =
		    &mc_bus->resource_pools[pool_type];

		res_pool->type = pool_type;
		res_pool->max_count = 0;
		res_pool->free_count = 0;
		res_pool->mc_bus = mc_bus;
		INIT_LIST_HEAD(&res_pool->free_list);
		mutex_init(&res_pool->mutex);
	}
}

static void dprc_cleanup_resource_pool(struct fsl_mc_device *mc_bus_dev,
				       enum fsl_mc_pool_type pool_type)
{
	struct fsl_mc_resource *resource;
	struct fsl_mc_resource *next;
	struct fsl_mc_bus *mc_bus = to_fsl_mc_bus(mc_bus_dev);
	struct fsl_mc_resource_pool *res_pool =
					&mc_bus->resource_pools[pool_type];
	int free_count = 0;

	WARN_ON(res_pool->type != pool_type);
	WARN_ON(res_pool->free_count != res_pool->max_count);

	list_for_each_entry_safe(resource, next, &res_pool->free_list, node) {
		free_count++;
		WARN_ON(resource->type != res_pool->type);
		WARN_ON(resource->parent_pool != res_pool);
		devm_kfree(&mc_bus_dev->dev, resource);
	}

	WARN_ON(free_count != res_pool->free_count);
}

/*
 * Clean up all resource pools other than the IRQ pool
 */
void dprc_cleanup_all_resource_pools(struct fsl_mc_device *mc_bus_dev)
{
	int pool_type;

	for (pool_type = 0; pool_type < FSL_MC_NUM_POOL_TYPES; pool_type++) {
		if (pool_type != FSL_MC_POOL_IRQ)
			dprc_cleanup_resource_pool(mc_bus_dev, pool_type);
	}
}

/**
 * dprc_scan_objects - Discover objects in a DPRC
 *
 * @mc_bus_dev: pointer to the fsl-mc device that represents a DPRC object
 * @driver_override: driver override to apply to new objects found in the DPRC,
 * or NULL, if none.
 * @total_irq_count: total number of IRQs needed by objects in the DPRC.
 *
 * Detects objects added and removed from a DPRC and synchronizes the
 * state of the Linux bus driver, MC by adding and removing
 * devices accordingly.
 * Two types of devices can be found in a DPRC: allocatable objects (e.g.,
 * dpbp, dpmcp) and non-allocatable devices (e.g., dprc, dpni).
 * All allocatable devices needed to be probed before all non-allocatable
 * devices, to ensure that device drivers for non-allocatable
 * devices can allocate any type of allocatable devices.
 * That is, we need to ensure that the corresponding resource pools are
 * populated before they can get allocation requests from probe callbacks
 * of the device drivers for the non-allocatable devices.
 */
int dprc_scan_objects(struct fsl_mc_device *mc_bus_dev,
		      const char *driver_override,
		      unsigned int *total_irq_count)
{
	int num_child_objects;
	int dprc_get_obj_failures;
	int error;
	unsigned int irq_count = mc_bus_dev->obj_desc.irq_count;
	struct dprc_obj_desc *child_obj_desc_array = NULL;

	error = dprc_get_obj_count(mc_bus_dev->mc_io,
				   0,
				   mc_bus_dev->mc_handle,
				   &num_child_objects);
	if (error < 0) {
		dev_err(&mc_bus_dev->dev, "dprc_get_obj_count() failed: %d\n",
			error);
		return error;
	}

	if (num_child_objects != 0) {
		int i;

		child_obj_desc_array =
		    devm_kmalloc_array(&mc_bus_dev->dev, num_child_objects,
				       sizeof(*child_obj_desc_array),
				       GFP_KERNEL);
		if (!child_obj_desc_array)
			return -ENOMEM;

		/*
		 * Discover objects currently present in the physical DPRC:
		 */
		dprc_get_obj_failures = 0;
		for (i = 0; i < num_child_objects; i++) {
			struct dprc_obj_desc *obj_desc =
			    &child_obj_desc_array[i];

			error = dprc_get_obj(mc_bus_dev->mc_io,
					     0,
					     mc_bus_dev->mc_handle,
					     i, obj_desc);

			/*
			 * -ENXIO means object index was invalid.
			 *  This is caused when the DPRC was changed at
			 *  the MC during the scan.  In this case,
			 *  abort the current scan.
			 */
			if (error == -ENXIO)
				return error;

			if (error < 0) {
				dev_err(&mc_bus_dev->dev,
					"dprc_get_obj(i=%d) failed: %d\n",
					i, error);
				/*
				 * Mark the obj entry as "invalid", by using the
				 * empty string as obj type:
				 */
				obj_desc->type[0] = '\0';
				obj_desc->id = error;
				dprc_get_obj_failures++;
				continue;
			}

			/*
			 * for DPRC versions that do not support the
			 * shareability attribute, make simplifying assumption
			 * that only SEC is not shareable.
			 */
			if ((strcmp(obj_desc->type, "dpseci") == 0) &&
			    (obj_desc->ver_major < 4))
				obj_desc->flags |=
					DPRC_OBJ_FLAG_NO_MEM_SHAREABILITY;

			irq_count += obj_desc->irq_count;
			dev_dbg(&mc_bus_dev->dev,
				"Discovered object: type %s, id %d\n",
				obj_desc->type, obj_desc->id);
		}

		if (dprc_get_obj_failures != 0) {
			dev_err(&mc_bus_dev->dev,
				"%d out of %d devices could not be retrieved\n",
				dprc_get_obj_failures, num_child_objects);
		}
	}

	*total_irq_count = irq_count;
	dprc_remove_devices(mc_bus_dev, child_obj_desc_array,
			    num_child_objects);

	dprc_add_new_devices(mc_bus_dev, driver_override, child_obj_desc_array,
			     num_child_objects);

	if (child_obj_desc_array)
		devm_kfree(&mc_bus_dev->dev, child_obj_desc_array);

	return 0;
}
EXPORT_SYMBOL_GPL(dprc_scan_objects);

/**
 * dprc_scan_container - Scans a physical DPRC and synchronizes Linux bus state
 *
 * @mc_bus_dev: pointer to the fsl-mc device that represents a DPRC object
 *
 * Scans the physical DPRC and synchronizes the state of the Linux
 * bus driver with the actual state of the MC by adding and removing
 * devices as appropriate.
 */
static int dprc_scan_container(struct fsl_mc_device *mc_bus_dev)
{
	int error;
	unsigned int irq_count;
	struct fsl_mc_bus *mc_bus = to_fsl_mc_bus(mc_bus_dev);

	dprc_init_all_resource_pools(mc_bus_dev);

	/*
	 * Discover objects in the DPRC:
	 */
	mutex_lock(&mc_bus->scan_mutex);
	error = dprc_scan_objects(mc_bus_dev, NULL, &irq_count);
	mutex_unlock(&mc_bus->scan_mutex);
	if (error < 0)
		goto error;

	if (fsl_mc_interrupts_supported() && !mc_bus->irq_resources) {
		irq_count += FSL_MC_IRQ_POOL_MAX_EXTRA_IRQS;
		error = fsl_mc_populate_irq_pool(mc_bus, irq_count);
		if (error < 0)
			goto error;
	}

	return 0;
error:
	device_for_each_child(&mc_bus_dev->dev, NULL, __fsl_mc_device_remove);
	dprc_cleanup_all_resource_pools(mc_bus_dev);
	return error;
}

/**
 * dprc_irq0_handler - Regular ISR for DPRC interrupt 0
 *
 * @irq: IRQ number of the interrupt being handled
 * @arg: Pointer to device structure
 */
static irqreturn_t dprc_irq0_handler(int irq_num, void *arg)
{
	return IRQ_WAKE_THREAD;
}

/**
 * dprc_irq0_handler_thread - Handler thread function for DPRC interrupt 0
 *
 * @irq: IRQ number of the interrupt being handled
 * @arg: Pointer to device structure
 */
static irqreturn_t dprc_irq0_handler_thread(int irq_num, void *arg)
{
	int error;
	uint32_t status;
	struct device *dev = (struct device *)arg;
	struct fsl_mc_device *mc_dev = to_fsl_mc_device(dev);
	struct fsl_mc_bus *mc_bus = to_fsl_mc_bus(mc_dev);
	struct fsl_mc_io *mc_io = mc_dev->mc_io;
	int irq_index = 0;

	dev_dbg(dev, "DPRC IRQ %d triggered on CPU %u\n",
		irq_num, smp_processor_id());
	if (WARN_ON(!(mc_dev->flags & FSL_MC_IS_DPRC)))
		return IRQ_HANDLED;

	mutex_lock(&mc_bus->scan_mutex);
	if (WARN_ON(mc_dev->irqs[irq_index]->irq_number != (uint32_t)irq_num))
		goto out;

	status = 0;
	error = dprc_get_irq_status(mc_io, 0, mc_dev->mc_handle, irq_index,
				    &status);
	if (error < 0) {
		dev_err(dev,
			"dprc_get_irq_status() failed: %d\n", error);
		goto out;
	}

	error = dprc_clear_irq_status(mc_io, 0, mc_dev->mc_handle, irq_index,
				      status);
	if (error < 0) {
		dev_err(dev,
			"dprc_clear_irq_status() failed: %d\n", error);
		goto out;
	}

	if (status & (DPRC_IRQ_EVENT_OBJ_ADDED |
		      DPRC_IRQ_EVENT_OBJ_REMOVED |
		      DPRC_IRQ_EVENT_CONTAINER_DESTROYED |
		      DPRC_IRQ_EVENT_OBJ_DESTROYED |
		      DPRC_IRQ_EVENT_OBJ_CREATED)) {
		unsigned int irq_count;

		error = dprc_scan_objects(mc_dev, NULL, &irq_count);
		if (error < 0) {
			if (error != -ENXIO) /* don't need to report aborted scan */
				dev_err(dev, "dprc_scan_objects() failed: %d\n", error);
			goto out;
		}

		WARN_ON((int16_t)irq_count < 0);

		if ((int16_t)irq_count >
			mc_bus->resource_pools[FSL_MC_POOL_IRQ].max_count) {
			dev_warn(dev,
				 "IRQs needed (%u) exceed IRQs preallocated (%u)\n",
				 irq_count,
				 mc_bus->resource_pools[FSL_MC_POOL_IRQ].
								max_count);
		}
	}

out:
	mutex_unlock(&mc_bus->scan_mutex);
	return IRQ_HANDLED;
}

/*
 * Disable and clear interrupts for a given DPRC object
 */
static int disable_dprc_irqs(struct fsl_mc_device *mc_dev)
{
	int i;
	int error;
	struct fsl_mc_io *mc_io = mc_dev->mc_io;
	int irq_count = mc_dev->obj_desc.irq_count;

	if (WARN_ON(irq_count == 0))
		return -EINVAL;

	for (i = 0; i < irq_count; i++) {
		/*
		 * Disable generation of interrupt i, while we configure it:
		 */
		error = dprc_set_irq_enable(mc_io, 0, mc_dev->mc_handle, i, 0);
		if (error < 0) {
			dev_err(&mc_dev->dev,
				"Disabling DPRC IRQ %d failed: dprc_set_irq_enable() failed: %d\n",
				i, error);

			return error;
		}

		/*
		 * Disable all interrupt causes for interrupt i:
		 */
		error = dprc_set_irq_mask(mc_io, 0, mc_dev->mc_handle, i, 0x0);
		if (error < 0) {
			dev_err(&mc_dev->dev,
				"Disabling DPRC IRQ %d failed: dprc_set_irq_mask() failed: %d\n",
				i, error);

			return error;
		}

		/*
		 * Clear any leftover interrupt i:
		 */
		error = dprc_clear_irq_status(mc_io, 0, mc_dev->mc_handle, i,
					      ~0x0U);
		if (error < 0) {
			dev_err(&mc_dev->dev,
				"Disabling DPRC IRQ %d failed: dprc_clear_irq_status() failed: %d\n",
				i, error);

			return error;
		}
	}

	return 0;
}

static void unregister_dprc_irq_handlers(struct fsl_mc_device *mc_dev)
{
	int i;
	struct fsl_mc_device_irq *irq;
	int irq_count = mc_dev->obj_desc.irq_count;

	for (i = 0; i < irq_count; i++) {
		irq = mc_dev->irqs[i];
		devm_free_irq(&mc_dev->dev, irq->irq_number,
			      &mc_dev->dev);
	}
}

static int register_dprc_irq_handlers(struct fsl_mc_device *mc_dev)
{
	static const struct irq_handler {
		irq_handler_t irq_handler;
		irq_handler_t irq_handler_thread;
		const char *irq_name;
	} irq_handlers[] = {
		[0] = {
			.irq_handler = dprc_irq0_handler,
			.irq_handler_thread = dprc_irq0_handler_thread,
			.irq_name = "FSL MC DPRC irq0",
		},
	};

	unsigned int i;
	int error;
	struct fsl_mc_device_irq *irq;
	unsigned int num_irq_handlers_registered = 0;
	int irq_count = mc_dev->obj_desc.irq_count;

	if (WARN_ON(irq_count != ARRAY_SIZE(irq_handlers)))
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(irq_handlers); i++) {
		irq = mc_dev->irqs[i];

		/*
		 * NOTE: devm_request_threaded_irq() invokes the device-specific
		 * function that programs the MSI physically in the device
		 */
		error = devm_request_threaded_irq(&mc_dev->dev,
						  irq->irq_number,
						  irq_handlers[i].irq_handler,
						  irq_handlers[i].
							irq_handler_thread,
						  IRQF_NO_SUSPEND |
							IRQF_ONESHOT,
						  irq_handlers[i].irq_name,
						  &mc_dev->dev);
		if (error < 0) {
			dev_err(&mc_dev->dev,
				"devm_request_threaded_irq() failed: %d\n",
				error);
			goto error_unregister_irq_handlers;
		}

		num_irq_handlers_registered++;
	}

	return 0;

error_unregister_irq_handlers:
	for (i = 0; i < num_irq_handlers_registered; i++) {
		irq = mc_dev->irqs[i];
		devm_free_irq(&mc_dev->dev, irq->irq_number,
			      &mc_dev->dev);
	}

	return error;
}

static int enable_dprc_irqs(struct fsl_mc_device *mc_dev)
{
	int i;
	int error;
	int irq_count = mc_dev->obj_desc.irq_count;

	for (i = 0; i < irq_count; i++) {
		/*
		 * Enable all interrupt causes for the interrupt:
		 */
		error = dprc_set_irq_mask(mc_dev->mc_io,
					  0,
					  mc_dev->mc_handle,
					  i,
					  ~0x0u);
		if (error < 0) {
			dev_err(&mc_dev->dev,
				"Enabling DPRC IRQ %d failed: dprc_set_irq_mask() failed: %d\n",
				i, error);

			return error;
		}

		/*
		 * Enable generation of the interrupt:
		 */
		error = dprc_set_irq_enable(mc_dev->mc_io,
					    0,
					    mc_dev->mc_handle,
					    i, 1);
		if (error < 0) {
			dev_err(&mc_dev->dev,
				"Enabling DPRC IRQ %d failed: dprc_set_irq_enable() failed: %d\n",
				i, error);

			return error;
		}
	}

	return 0;
}

/*
 * Setup interrupts for a given DPRC device
 */
static int dprc_setup_irqs(struct fsl_mc_device *mc_dev)
{
	int error;

	error = fsl_mc_allocate_irqs(mc_dev);
	if (error < 0)
		return error;

	error = disable_dprc_irqs(mc_dev);
	if (error < 0)
		goto error_free_irqs;

	error = register_dprc_irq_handlers(mc_dev);
	if (error < 0)
		goto error_free_irqs;

	error = enable_dprc_irqs(mc_dev);
	if (error < 0)
		goto error_unregister_irq_handlers;

	return 0;

error_unregister_irq_handlers:
	unregister_dprc_irq_handlers(mc_dev);

error_free_irqs:
	fsl_mc_free_irqs(mc_dev);
	return error;
}

/*
 * Creates a DPMCP for a DPRC's built-in MC portal
 */
static int dprc_create_dpmcp(struct fsl_mc_device *dprc_dev)
{
	int error;
	struct dpmcp_cfg dpmcp_cfg;
	uint16_t dpmcp_handle;
	struct dprc_res_req res_req;
	struct dpmcp_attr dpmcp_attr;
	struct fsl_mc_bus *mc_bus = to_fsl_mc_bus(dprc_dev);

	dpmcp_cfg.portal_id = mc_bus->dprc_attr.portal_id;
	error = dpmcp_create(dprc_dev->mc_io,
			     MC_CMD_FLAG_INTR_DIS,
			     &dpmcp_cfg,
			     &dpmcp_handle);
	if (error < 0) {
		dev_err(&dprc_dev->dev, "dpmcp_create() failed: %d\n",
			error);
		return error;
	}

	/*
	 * Set the state of the newly created DPMCP object to be "plugged":
	 */

	error = dpmcp_get_attributes(dprc_dev->mc_io,
				     MC_CMD_FLAG_INTR_DIS,
				     dpmcp_handle,
				     &dpmcp_attr);
	if (error < 0) {
		dev_err(&dprc_dev->dev, "dpmcp_get_attributes() failed: %d\n",
			error);
		goto error_destroy_dpmcp;
	}

	if (WARN_ON(dpmcp_attr.id != mc_bus->dprc_attr.portal_id)) {
		error = -EINVAL;
		goto error_destroy_dpmcp;
	}

	strcpy(res_req.type, "dpmcp");
	res_req.num = 1;
	res_req.options =
			(DPRC_RES_REQ_OPT_EXPLICIT | DPRC_RES_REQ_OPT_PLUGGED);
	res_req.id_base_align = dpmcp_attr.id;

	error = dprc_assign(dprc_dev->mc_io,
			    MC_CMD_FLAG_INTR_DIS,
			    dprc_dev->mc_handle,
			    dprc_dev->obj_desc.id,
			    &res_req);

	if (error < 0) {
		dev_err(&dprc_dev->dev, "dprc_assign() failed: %d\n", error);
		goto error_destroy_dpmcp;
	}

	(void)dpmcp_close(dprc_dev->mc_io,
			  MC_CMD_FLAG_INTR_DIS,
			  dpmcp_handle);
	return 0;

error_destroy_dpmcp:
	(void)dpmcp_destroy(dprc_dev->mc_io,
			    MC_CMD_FLAG_INTR_DIS,
			    dpmcp_handle);
	return error;
}

/*
 * Destroys the DPMCP for a DPRC's built-in MC portal
 */
static void dprc_destroy_dpmcp(struct fsl_mc_device *dprc_dev)
{
	int error;
	uint16_t dpmcp_handle;
	struct fsl_mc_bus *mc_bus = to_fsl_mc_bus(dprc_dev);

	if (WARN_ON(!dprc_dev->mc_io || dprc_dev->mc_io->dpmcp_dev))
		return;

	error = dpmcp_open(dprc_dev->mc_io,
			   MC_CMD_FLAG_INTR_DIS,
			   mc_bus->dprc_attr.portal_id,
			   &dpmcp_handle);
	if (error < 0) {
		dev_err(&dprc_dev->dev, "dpmcp_open() failed: %d\n",
			error);
		return;
	}

	error = dpmcp_destroy(dprc_dev->mc_io,
			      MC_CMD_FLAG_INTR_DIS,
			      dpmcp_handle);
	if (error < 0) {
		dev_err(&dprc_dev->dev, "dpmcp_destroy() failed: %d\n",
			error);
		return;
	}
}

/**
 * dprc_probe - callback invoked when a DPRC is being bound to this driver
 *
 * @mc_dev: Pointer to fsl-mc device representing a DPRC
 *
 * It opens the physical DPRC in the MC.
 * It scans the DPRC to discover the MC objects contained in it.
 * It creates the interrupt pool for the MC bus associated with the DPRC.
 * It configures the interrupts for the DPRC device itself.
 */
static int dprc_probe(struct fsl_mc_device *mc_dev)
{
	int error;
	size_t region_size;
	struct fsl_mc_bus *mc_bus = to_fsl_mc_bus(mc_dev);
	bool mc_io_created = false;
	bool dev_root_set = false;

	if (WARN_ON(strcmp(mc_dev->obj_desc.type, "dprc") != 0))
		return -EINVAL;

	if (mc_dev->mc_io) {
		/*
		 * This is the root DPRC
		 */
		if (WARN_ON(fsl_mc_bus_type.dev_root))
			return -EINVAL;

		fsl_mc_bus_type.dev_root = &mc_dev->dev;
		dev_root_set = true;
	} else {
		/*
		 * This is a child DPRC
		 */
		if (WARN_ON(!fsl_mc_bus_type.dev_root))
			return -EINVAL;

		if (WARN_ON(mc_dev->obj_desc.region_count == 0))
			return -EINVAL;

		region_size = mc_dev->regions[0].end -
			      mc_dev->regions[0].start + 1;

		error = fsl_create_mc_io(&mc_dev->dev,
					 mc_dev->regions[0].start,
					 region_size,
					 NULL, 0, &mc_dev->mc_io);
		if (error < 0)
			return error;

		mc_io_created = true;
	}

	error = dprc_open(mc_dev->mc_io, 0, mc_dev->obj_desc.id,
			  &mc_dev->mc_handle);
	if (error < 0) {
		dev_err(&mc_dev->dev, "dprc_open() failed: %d\n", error);
		goto error_cleanup_mc_io;
	}

	error = dprc_get_attributes(mc_dev->mc_io, 0, mc_dev->mc_handle,
				    &mc_bus->dprc_attr);
	if (error < 0) {
		dev_err(&mc_dev->dev, "dprc_get_attributes() failed: %d\n",
			error);
		goto error_cleanup_open;
	}

	if (mc_bus->dprc_attr.version.major < DPRC_MIN_VER_MAJOR ||
	   (mc_bus->dprc_attr.version.major == DPRC_MIN_VER_MAJOR &&
	    mc_bus->dprc_attr.version.minor < DPRC_MIN_VER_MINOR)) {
		dev_err(&mc_dev->dev,
			"ERROR: DPRC version %d.%d not supported\n",
			mc_bus->dprc_attr.version.major,
			mc_bus->dprc_attr.version.minor);
		error = -ENOTSUPP;
		goto error_cleanup_open;
	}

	if (fsl_mc_interrupts_supported()) {
		/*
		 * Create DPMCP for the DPRC's built-in portal:
		 */
		error = dprc_create_dpmcp(mc_dev);
		if (error < 0)
			goto error_cleanup_open;
	}

	mutex_init(&mc_bus->scan_mutex);

	/*
	 * Discover MC objects in the DPRC object:
	 */
	error = dprc_scan_container(mc_dev);
	if (error < 0)
		goto error_destroy_dpmcp;

	if (fsl_mc_interrupts_supported()) {
		/*
		 * The fsl_mc_device object associated with the DPMCP object
		 * created above was created as part of the
		 * dprc_scan_container() call above:
		 */
		if (WARN_ON(!mc_dev->mc_io->dpmcp_dev)) {
			error = -EINVAL;
			goto error_cleanup_dprc_scan;
		}

		/*
		 * Allocate MC portal to be used in atomic context
		 * (e.g., to program MSIs from program_msi_at_mc())
		 */
		error = fsl_mc_portal_allocate(NULL,
					       FSL_MC_IO_ATOMIC_CONTEXT_PORTAL,
					       &mc_bus->atomic_mc_io);
		if (error < 0)
			goto error_cleanup_dprc_scan;

		pr_info("fsl-mc: Allocated dpmcp.%d to dprc.%d for atomic MC I/O\n",
			mc_bus->atomic_mc_io->dpmcp_dev->obj_desc.id,
			mc_dev->obj_desc.id);

		/*
		 * Open DPRC handle to be used with mc_bus->atomic_mc_io:
		 */
		error = dprc_open(mc_bus->atomic_mc_io, 0, mc_dev->obj_desc.id,
				  &mc_bus->atomic_dprc_handle);
		if (error < 0) {
			dev_err(&mc_dev->dev, "dprc_open() failed: %d\n",
				error);
			goto error_cleanup_atomic_mc_io;
		}

		/*
		 * Configure interrupt for the DPMCP object associated with the
		 * DPRC object's built-in portal:
		 *
		 * NOTE: We have to do this after calling dprc_scan_container(),
		 * since dprc_scan_container() populates the IRQ pool for
		 * this DPRC.
		 */
		error = fsl_mc_io_setup_dpmcp_irq(mc_dev->mc_io);
		if (error < 0)
			goto error_cleanup_atomic_dprc_handle;

		/*
		 * Configure interrupts for the DPRC object associated with
		 * this MC bus:
		 */
		error = dprc_setup_irqs(mc_dev);
		if (error < 0)
			goto error_cleanup_atomic_dprc_handle;
	}

	dev_info(&mc_dev->dev, "DPRC device bound to driver");
	return 0;

error_cleanup_atomic_dprc_handle:
	(void)dprc_close(mc_bus->atomic_mc_io, 0, mc_bus->atomic_dprc_handle);

error_cleanup_atomic_mc_io:
	fsl_mc_portal_free(mc_bus->atomic_mc_io);

error_cleanup_dprc_scan:
	fsl_mc_io_unset_dpmcp(mc_dev->mc_io);
	device_for_each_child(&mc_dev->dev, NULL, __fsl_mc_device_remove);
	dprc_cleanup_all_resource_pools(mc_dev);
	if (fsl_mc_interrupts_supported())
		fsl_mc_cleanup_irq_pool(mc_bus);

error_destroy_dpmcp:
	dprc_destroy_dpmcp(mc_dev);

error_cleanup_open:
	(void)dprc_close(mc_dev->mc_io, 0, mc_dev->mc_handle);

error_cleanup_mc_io:
	if (mc_io_created) {
		fsl_destroy_mc_io(mc_dev->mc_io);
		mc_dev->mc_io = NULL;
	}

	if (dev_root_set)
		fsl_mc_bus_type.dev_root = NULL;

	return error;
}

/*
 * Tear down interrupts for a given DPRC object
 */
static void dprc_teardown_irqs(struct fsl_mc_device *mc_dev)
{
	(void)disable_dprc_irqs(mc_dev);
	unregister_dprc_irq_handlers(mc_dev);
	fsl_mc_free_irqs(mc_dev);
}

/**
 * dprc_remove - callback invoked when a DPRC is being unbound from this driver
 *
 * @mc_dev: Pointer to fsl-mc device representing the DPRC
 *
 * It removes the DPRC's child objects from Linux (not from the MC) and
 * closes the DPRC device in the MC.
 * It tears down the interrupts that were configured for the DPRC device.
 * It destroys the interrupt pool associated with this MC bus.
 */
static int dprc_remove(struct fsl_mc_device *mc_dev)
{
	int error;
	struct fsl_mc_bus *mc_bus = to_fsl_mc_bus(mc_dev);

	if (WARN_ON(strcmp(mc_dev->obj_desc.type, "dprc") != 0))
		return -EINVAL;
	if (WARN_ON(!mc_dev->mc_io))
		return -EINVAL;

	if (WARN_ON(!mc_bus->irq_resources))
		return -EINVAL;

	if (fsl_mc_interrupts_supported()) {
		dprc_teardown_irqs(mc_dev);
		error = dprc_close(mc_bus->atomic_mc_io, 0,
				   mc_bus->atomic_dprc_handle);
		if (error < 0) {
			dev_err(&mc_dev->dev, "dprc_close() failed: %d\n",
				error);
		}

		fsl_mc_portal_free(mc_bus->atomic_mc_io);
	}

	fsl_mc_io_unset_dpmcp(mc_dev->mc_io);
	device_for_each_child(&mc_dev->dev, NULL, __fsl_mc_device_remove);
	dprc_cleanup_all_resource_pools(mc_dev);
	dprc_destroy_dpmcp(mc_dev);
	error = dprc_close(mc_dev->mc_io, 0, mc_dev->mc_handle);
	if (error < 0)
		dev_err(&mc_dev->dev, "dprc_close() failed: %d\n", error);

	if (fsl_mc_interrupts_supported())
		fsl_mc_cleanup_irq_pool(mc_bus);

	if (&mc_dev->dev == fsl_mc_bus_type.dev_root)
		fsl_mc_bus_type.dev_root = NULL;

	dev_info(&mc_dev->dev, "DPRC device unbound from driver");
	return 0;
}

static const struct fsl_mc_device_match_id match_id_table[] = {
	{
	 .vendor = FSL_MC_VENDOR_FREESCALE,
	 .obj_type = "dprc"},
	{.vendor = 0x0},
};

static struct fsl_mc_driver dprc_driver = {
	.driver = {
		   .name = FSL_MC_DPRC_DRIVER_NAME,
		   .owner = THIS_MODULE,
		   .pm = NULL,
		   },
	.match_id_table = match_id_table,
	.probe = dprc_probe,
	.remove = dprc_remove,
};

int __init dprc_driver_init(void)
{
	return fsl_mc_driver_register(&dprc_driver);
}

void __exit dprc_driver_exit(void)
{
	fsl_mc_driver_unregister(&dprc_driver);
}
