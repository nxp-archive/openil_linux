/* Copyright 2013-2014 Freescale Semiconductor Inc.
 *
 * I/O services to send MC commands to the MC hardware
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the above-listed copyright holders nor the
 *       names of any contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "../include/mc-sys.h"
#include "../include/mc-cmd.h"
#include "../include/mc.h"
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include "dpmcp.h"

/**
 * Timeout in milliseconds to wait for the completion of an MC command
 */
#define MC_CMD_COMPLETION_TIMEOUT_MS	500

/*
 * usleep_range() min and max values used to throttle down polling
 * iterations while waiting for MC command completion
 */
#define MC_CMD_COMPLETION_POLLING_MIN_SLEEP_USECS    10
#define MC_CMD_COMPLETION_POLLING_MAX_SLEEP_USECS    500

#define MC_CMD_HDR_READ_CMDID(_hdr) \
	((uint16_t)mc_dec((_hdr), MC_CMD_HDR_CMDID_O, MC_CMD_HDR_CMDID_S))

/**
 * dpmcp_irq0_handler - Regular ISR for DPMCP interrupt 0
 *
 * @irq: IRQ number of the interrupt being handled
 * @arg: Pointer to device structure
 */
static irqreturn_t dpmcp_irq0_handler(int irq_num, void *arg)
{
	struct device *dev = (struct device *)arg;
	struct fsl_mc_device *dpmcp_dev = to_fsl_mc_device(dev);

	dev_dbg(dev, "DPMCP IRQ %d triggered on CPU %u\n", irq_num,
		smp_processor_id());

	if (WARN_ON(dpmcp_dev->irqs[0]->irq_number != (uint32_t)irq_num))
		goto out;

	if (WARN_ON(!dpmcp_dev->mc_io))
		goto out;

	/*
	 * NOTE: We cannot invoke MC flib function here
	 */

	complete(&dpmcp_dev->mc_io->mc_command_done_completion);
out:
	return IRQ_HANDLED;
}

/*
 * Disable and clear interrupts for a given DPMCP object
 */
static int disable_dpmcp_irq(struct fsl_mc_device *dpmcp_dev)
{
	int error;

	/*
	 * Disable generation of the DPMCP interrupt:
	 */
	error = dpmcp_set_irq_enable(dpmcp_dev->mc_io,
				     dpmcp_dev->mc_handle,
				     DPMCP_IRQ_INDEX, 0);
	if (error < 0) {
		dev_err(&dpmcp_dev->dev,
			"dpmcp_set_irq_enable() failed: %d\n", error);

		return error;
	}

	/*
	 * Disable all DPMCP interrupt causes:
	 */
	error = dpmcp_set_irq_mask(dpmcp_dev->mc_io, dpmcp_dev->mc_handle,
				   DPMCP_IRQ_INDEX, 0x0);
	if (error < 0) {
		dev_err(&dpmcp_dev->dev,
			"dpmcp_set_irq_mask() failed: %d\n", error);

		return error;
	}

	/*
	 * Clear any leftover interrupts:
	 */
	error = dpmcp_clear_irq_status(dpmcp_dev->mc_io, dpmcp_dev->mc_handle,
				       DPMCP_IRQ_INDEX, ~0x0U);
	if (error < 0) {
		dev_err(&dpmcp_dev->dev,
			"dpmcp_clear_irq_status() failed: %d\n",
			error);
		return error;
	}

	return 0;
}

static void unregister_dpmcp_irq_handler(struct fsl_mc_device *dpmcp_dev)
{
	struct fsl_mc_device_irq *irq = dpmcp_dev->irqs[DPMCP_IRQ_INDEX];

	devm_free_irq(&dpmcp_dev->dev, irq->irq_number, &dpmcp_dev->dev);
}

static int register_dpmcp_irq_handler(struct fsl_mc_device *dpmcp_dev)
{
	int error;
	struct fsl_mc_device_irq *irq = dpmcp_dev->irqs[DPMCP_IRQ_INDEX];

	error = devm_request_irq(&dpmcp_dev->dev,
				 irq->irq_number,
				 dpmcp_irq0_handler,
				 IRQF_NO_SUSPEND | IRQF_ONESHOT,
				 "FSL MC DPMCP irq0",
				 &dpmcp_dev->dev);
	if (error < 0) {
		dev_err(&dpmcp_dev->dev,
			"devm_request_irq() failed: %d\n",
			error);
		return error;
	}

	error = dpmcp_set_irq(dpmcp_dev->mc_io,
			      dpmcp_dev->mc_handle,
			      DPMCP_IRQ_INDEX,
			      irq->msi_paddr,
			      irq->msi_value,
			      irq->irq_number);
	if (error < 0) {
		dev_err(&dpmcp_dev->dev,
			"dpmcp_set_irq() failed: %d\n", error);
		goto error_unregister_irq_handler;
	}

	return 0;

error_unregister_irq_handler:
	devm_free_irq(&dpmcp_dev->dev, irq->irq_number, &dpmcp_dev->dev);
	return error;
}

static int enable_dpmcp_irq(struct fsl_mc_device *dpmcp_dev)
{
	int error;

	/*
	 * Enable MC command completion event to trigger DPMCP interrupt:
	 */
	error = dpmcp_set_irq_mask(dpmcp_dev->mc_io,
				   dpmcp_dev->mc_handle,
				   DPMCP_IRQ_INDEX,
				   DPMCP_IRQ_EVENT_CMD_DONE);
	if (error < 0) {
		dev_err(&dpmcp_dev->dev,
			"dpmcp_set_irq_mask() failed: %d\n", error);

		return error;
	}

	/*
	 * Enable generation of the interrupt:
	 */
	error = dpmcp_set_irq_enable(dpmcp_dev->mc_io,
				     dpmcp_dev->mc_handle,
				     DPMCP_IRQ_INDEX, 1);
	if (error < 0) {
		dev_err(&dpmcp_dev->dev,
			"dpmcp_set_irq_enable() failed: %d\n", error);

		return error;
	}

	return 0;
}

/*
 * Setup MC command completion interrupt for the DPMCP device associated with a
 * given fsl_mc_io object
 */
int fsl_mc_io_setup_dpmcp_irq(struct fsl_mc_io *mc_io)
{
	int error;
	struct fsl_mc_device *dpmcp_dev = mc_io->dpmcp_dev;

	if (WARN_ON(!dpmcp_dev))
		return -EINVAL;

	if (WARN_ON(!fsl_mc_interrupts_supported()))
		return -EINVAL;

	if (WARN_ON(dpmcp_dev->obj_desc.irq_count != 1))
		return -EINVAL;

	if (WARN_ON(!dpmcp_dev->mc_io))
		return -EINVAL;

	error = fsl_mc_allocate_irqs(dpmcp_dev);
	if (error < 0)
		return error;

	error = disable_dpmcp_irq(dpmcp_dev);
	if (error < 0)
		goto error_free_irqs;

	error = register_dpmcp_irq_handler(dpmcp_dev);
	if (error < 0)
		goto error_free_irqs;

	error = enable_dpmcp_irq(dpmcp_dev);
	if (error < 0)
		goto error_unregister_irq_handler;

	mc_io->mc_command_done_irq_armed = true;
	return 0;

error_unregister_irq_handler:
	unregister_dpmcp_irq_handler(dpmcp_dev);

error_free_irqs:
	fsl_mc_free_irqs(dpmcp_dev);
	return error;
}
EXPORT_SYMBOL_GPL(fsl_mc_io_setup_dpmcp_irq);

/*
 * Tear down interrupts for the DPMCP device associated with a given fsl_mc_io
 * object
 */
static void teardown_dpmcp_irq(struct fsl_mc_io *mc_io)
{
	struct fsl_mc_device *dpmcp_dev = mc_io->dpmcp_dev;

	if (WARN_ON(!dpmcp_dev))
		return;
	if (WARN_ON(!fsl_mc_interrupts_supported()))
		return;
	if (WARN_ON(!dpmcp_dev->irqs))
		return;

	mc_io->mc_command_done_irq_armed = false;
	(void)disable_dpmcp_irq(dpmcp_dev);
	unregister_dpmcp_irq_handler(dpmcp_dev);
	fsl_mc_free_irqs(dpmcp_dev);
}

/**
 * Creates an MC I/O object
 *
 * @dev: device to be associated with the MC I/O object
 * @mc_portal_phys_addr: physical address of the MC portal to use
 * @mc_portal_size: size in bytes of the MC portal
 * @resource: Pointer to MC bus object allocator resource associated
 * with this MC I/O object or NULL if none.
 * @flags: flags for the new MC I/O object
 * @new_mc_io: Area to return pointer to newly created MC I/O object
 *
 * Returns '0' on Success; Error code otherwise.
 */
int __must_check fsl_create_mc_io(struct device *dev,
				  phys_addr_t mc_portal_phys_addr,
				  uint32_t mc_portal_size,
				  struct fsl_mc_device *dpmcp_dev,
				  uint32_t flags, struct fsl_mc_io **new_mc_io)
{
	int error;
	struct fsl_mc_io *mc_io;
	void __iomem *mc_portal_virt_addr;
	struct resource *res;

	mc_io = devm_kzalloc(dev, sizeof(*mc_io), GFP_KERNEL);
	if (!mc_io)
		return -ENOMEM;

	mc_io->dev = dev;
	mc_io->flags = flags;
	mc_io->portal_phys_addr = mc_portal_phys_addr;
	mc_io->portal_size = mc_portal_size;
	mc_io->mc_command_done_irq_armed = false;
	if (flags & FSL_MC_IO_ATOMIC_CONTEXT_PORTAL) {
		spin_lock_init(&mc_io->spinlock);
	} else {
		mutex_init(&mc_io->mutex);
		init_completion(&mc_io->mc_command_done_completion);
	}

	res = devm_request_mem_region(dev,
				      mc_portal_phys_addr,
				      mc_portal_size,
				      "mc_portal");
	if (!res) {
		dev_err(dev,
			"devm_request_mem_region failed for MC portal %#llx\n",
			mc_portal_phys_addr);
		return -EBUSY;
	}

	mc_portal_virt_addr = devm_ioremap_nocache(dev,
						   mc_portal_phys_addr,
						   mc_portal_size);
	if (!mc_portal_virt_addr) {
		dev_err(dev,
			"devm_ioremap_nocache failed for MC portal %#llx\n",
			mc_portal_phys_addr);
		return -ENXIO;
	}

	mc_io->portal_virt_addr = mc_portal_virt_addr;
	if (dpmcp_dev) {
		error = fsl_mc_io_set_dpmcp(mc_io, dpmcp_dev);
		if (error < 0)
			goto error_destroy_mc_io;

		if (!(flags & FSL_MC_IO_ATOMIC_CONTEXT_PORTAL) &&
		    fsl_mc_interrupts_supported()) {
			error = fsl_mc_io_setup_dpmcp_irq(mc_io);
			if (error < 0)
				goto error_destroy_mc_io;
		}
	}

	*new_mc_io = mc_io;
	return 0;

error_destroy_mc_io:
	fsl_destroy_mc_io(mc_io);
	return error;

}
EXPORT_SYMBOL_GPL(fsl_create_mc_io);

/**
 * Destroys an MC I/O object
 *
 * @mc_io: MC I/O object to destroy
 */
void fsl_destroy_mc_io(struct fsl_mc_io *mc_io)
{
	struct fsl_mc_device *dpmcp_dev = mc_io->dpmcp_dev;

	if (dpmcp_dev)
		fsl_mc_io_unset_dpmcp(mc_io);

	devm_iounmap(mc_io->dev, mc_io->portal_virt_addr);
	devm_release_mem_region(mc_io->dev,
				mc_io->portal_phys_addr,
				mc_io->portal_size);

	mc_io->portal_virt_addr = NULL;
	devm_kfree(mc_io->dev, mc_io);
}
EXPORT_SYMBOL_GPL(fsl_destroy_mc_io);

int fsl_mc_io_set_dpmcp(struct fsl_mc_io *mc_io,
			struct fsl_mc_device *dpmcp_dev)
{
	int error;

	if (WARN_ON(!dpmcp_dev))
		return -EINVAL;

	if (WARN_ON(mc_io->dpmcp_dev))
		return -EINVAL;

	if (WARN_ON(dpmcp_dev->mc_io))
		return -EINVAL;

	if (!(mc_io->flags & FSL_MC_IO_ATOMIC_CONTEXT_PORTAL)) {
		error = dpmcp_open(mc_io, dpmcp_dev->obj_desc.id,
				   &dpmcp_dev->mc_handle);
		if (error < 0)
			return error;
	}

	mc_io->dpmcp_dev = dpmcp_dev;
	dpmcp_dev->mc_io = mc_io;
	return 0;
}
EXPORT_SYMBOL_GPL(fsl_mc_io_set_dpmcp);

void fsl_mc_io_unset_dpmcp(struct fsl_mc_io *mc_io)
{
	int error;
	struct fsl_mc_device *dpmcp_dev = mc_io->dpmcp_dev;

	if (WARN_ON(!dpmcp_dev))
		return;

	if (WARN_ON(dpmcp_dev->mc_io != mc_io))
		return;

	if (!(mc_io->flags & FSL_MC_IO_ATOMIC_CONTEXT_PORTAL)) {
		if (dpmcp_dev->irqs)
			teardown_dpmcp_irq(mc_io);

		error = dpmcp_close(mc_io, dpmcp_dev->mc_handle);
		if (error < 0) {
			dev_err(&dpmcp_dev->dev, "dpmcp_close() failed: %d\n",
				error);
		}
	}

	mc_io->dpmcp_dev = NULL;
	dpmcp_dev->mc_io = NULL;
}
EXPORT_SYMBOL_GPL(fsl_mc_io_unset_dpmcp);

static int mc_status_to_error(enum mc_cmd_status status)
{
	static const int mc_status_to_error_map[] = {
		[MC_CMD_STATUS_OK] = 0,
		[MC_CMD_STATUS_AUTH_ERR] = -EACCES,
		[MC_CMD_STATUS_NO_PRIVILEGE] = -EPERM,
		[MC_CMD_STATUS_DMA_ERR] = -EIO,
		[MC_CMD_STATUS_CONFIG_ERR] = -ENXIO,
		[MC_CMD_STATUS_TIMEOUT] = -ETIMEDOUT,
		[MC_CMD_STATUS_NO_RESOURCE] = -ENAVAIL,
		[MC_CMD_STATUS_NO_MEMORY] = -ENOMEM,
		[MC_CMD_STATUS_BUSY] = -EBUSY,
		[MC_CMD_STATUS_UNSUPPORTED_OP] = -ENOTSUPP,
		[MC_CMD_STATUS_INVALID_STATE] = -ENODEV,
	};

	if (WARN_ON((u32)status >= ARRAY_SIZE(mc_status_to_error_map)))
		return -EINVAL;

	return mc_status_to_error_map[status];
}

static const char *mc_status_to_string(enum mc_cmd_status status)
{
	static const char *const status_strings[] = {
		[MC_CMD_STATUS_OK] = "Command completed successfully",
		[MC_CMD_STATUS_READY] = "Command ready to be processed",
		[MC_CMD_STATUS_AUTH_ERR] = "Authentication error",
		[MC_CMD_STATUS_NO_PRIVILEGE] = "No privilege",
		[MC_CMD_STATUS_DMA_ERR] = "DMA or I/O error",
		[MC_CMD_STATUS_CONFIG_ERR] = "Configuration error",
		[MC_CMD_STATUS_TIMEOUT] = "Operation timed out",
		[MC_CMD_STATUS_NO_RESOURCE] = "No resources",
		[MC_CMD_STATUS_NO_MEMORY] = "No memory available",
		[MC_CMD_STATUS_BUSY] = "Device is busy",
		[MC_CMD_STATUS_UNSUPPORTED_OP] = "Unsupported operation",
		[MC_CMD_STATUS_INVALID_STATE] = "Invalid state"
	};

	if ((unsigned int)status >= ARRAY_SIZE(status_strings))
		return "Unknown MC error";

	return status_strings[status];
}

/**
 * mc_write_command - writes a command to a Management Complex (MC) portal
 *
 * @portal: pointer to an MC portal
 * @cmd: pointer to a filled command
 */
static inline void mc_write_command(struct mc_command __iomem *portal,
				    struct mc_command *cmd)
{
	int i;

	/* copy command parameters into the portal */
	for (i = 0; i < MC_CMD_NUM_OF_PARAMS; i++)
		writeq(cmd->params[i], &portal->params[i]);

	/* submit the command by writing the header */
	writeq(cmd->header, &portal->header);
}

/**
 * mc_read_response - reads the response for the last MC command from a
 * Management Complex (MC) portal
 *
 * @portal: pointer to an MC portal
 * @resp: pointer to command response buffer
 *
 * Returns MC_CMD_STATUS_OK on Success; Error code otherwise.
 */
static inline enum mc_cmd_status mc_read_response(struct mc_command __iomem *
						  portal,
						  struct mc_command *resp)
{
	int i;
	enum mc_cmd_status status;

	/* Copy command response header from MC portal: */
	resp->header = readq(&portal->header);
	status = MC_CMD_HDR_READ_STATUS(resp->header);
	if (status != MC_CMD_STATUS_OK)
		return status;

	/* Copy command response data from MC portal: */
	for (i = 0; i < MC_CMD_NUM_OF_PARAMS; i++)
		resp->params[i] = readq(&portal->params[i]);

	return status;
}

static int mc_completion_wait(struct fsl_mc_io *mc_io, struct mc_command *cmd,
			      enum mc_cmd_status *mc_status)
{
	enum mc_cmd_status status;
	unsigned long jiffies_left;
	unsigned long timeout_jiffies =
		msecs_to_jiffies(MC_CMD_COMPLETION_TIMEOUT_MS);

	if (WARN_ON(!mc_io->dpmcp_dev))
		return -EINVAL;

	if (WARN_ON(mc_io->flags & FSL_MC_IO_ATOMIC_CONTEXT_PORTAL))
		return -EINVAL;

	if (WARN_ON(!preemptible()))
		return -EINVAL;

	for (;;) {
		status = mc_read_response(mc_io->portal_virt_addr, cmd);
		if (status != MC_CMD_STATUS_READY)
			break;

		jiffies_left = wait_for_completion_timeout(
					&mc_io->mc_command_done_completion,
					timeout_jiffies);
		if (jiffies_left == 0)
			return -ETIMEDOUT;
	}

	*mc_status = status;
	return 0;
}

static int mc_polling_wait(struct fsl_mc_io *mc_io, struct mc_command *cmd,
			   enum mc_cmd_status *mc_status)
{
	enum mc_cmd_status status;
	unsigned long jiffies_until_timeout =
		jiffies + msecs_to_jiffies(MC_CMD_COMPLETION_TIMEOUT_MS);

	for (;;) {
		status = mc_read_response(mc_io->portal_virt_addr, cmd);
		if (status != MC_CMD_STATUS_READY)
			break;

		if (preemptible()) {
			usleep_range(MC_CMD_COMPLETION_POLLING_MIN_SLEEP_USECS,
				     MC_CMD_COMPLETION_POLLING_MAX_SLEEP_USECS);
		} else {
			udelay(MC_CMD_COMPLETION_POLLING_MAX_SLEEP_USECS);
		}

		if (time_after_eq(jiffies, jiffies_until_timeout)) {
			pr_debug("MC command timed out (portal: %#llx, obj handle: %#x, command: %#x)\n",
				 mc_io->portal_phys_addr,
				 (unsigned int)
					MC_CMD_HDR_READ_TOKEN(cmd->header),
				 (unsigned int)
					MC_CMD_HDR_READ_CMDID(cmd->header));

			return -ETIMEDOUT;
		}
	}

	*mc_status = status;
	return 0;
}

/**
 * Sends a command to the MC device using the given MC I/O object
 *
 * @mc_io: MC I/O object to be used
 * @cmd: command to be sent
 *
 * Returns '0' on Success; Error code otherwise.
 */
int mc_send_command(struct fsl_mc_io *mc_io, struct mc_command *cmd)
{
	int error;
	enum mc_cmd_status status;

	if (WARN_ON(in_irq()))
		return -EINVAL;

	if (mc_io->flags & FSL_MC_IO_ATOMIC_CONTEXT_PORTAL)
		spin_lock(&mc_io->spinlock);
	else
		mutex_lock(&mc_io->mutex);

	/*
	 * Send command to the MC hardware:
	 */
	mc_write_command(mc_io->portal_virt_addr, cmd);

	/*
	 * Wait for response from the MC hardware:
	 */
	if (mc_io->mc_command_done_irq_armed)
		error = mc_completion_wait(mc_io, cmd, &status);
	else
		error = mc_polling_wait(mc_io, cmd, &status);

	if (error < 0)
		goto common_exit;

	if (status != MC_CMD_STATUS_OK) {
		pr_debug("MC command failed: portal: %#llx, obj handle: %#x, command: %#x, status: %s (%#x)\n",
			 mc_io->portal_phys_addr,
			 (unsigned int)MC_CMD_HDR_READ_TOKEN(cmd->header),
			 (unsigned int)MC_CMD_HDR_READ_CMDID(cmd->header),
			 mc_status_to_string(status),
			 (unsigned int)status);

		error = mc_status_to_error(status);
		goto common_exit;
	}

	error = 0;

common_exit:
	if (mc_io->flags & FSL_MC_IO_ATOMIC_CONTEXT_PORTAL)
		spin_unlock(&mc_io->spinlock);
	else
		mutex_unlock(&mc_io->mutex);

	return error;
}
EXPORT_SYMBOL(mc_send_command);
