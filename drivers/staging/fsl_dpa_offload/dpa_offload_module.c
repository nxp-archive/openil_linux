/* Copyright 2008-2012 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * DPA Offloading driver implementation
 */

#include <linux/module.h>

#include "dpa_offload_module.h"
#include "wrp_dpa_classifier.h"
#include "wrp_dpa_ipsec.h"
#include "wrp_dpa_stats.h"

static int __init dpa_offload_drv_init(void)
{
	int err;

	/* Initialize DPA Classifier wrapper to listen to [ioctl] calls */
	err = wrp_dpa_classif_init();
	if (err == 0)
		printk(KERN_INFO"DPA Classifier Driver initialized.\n");
	else {
		printk(KERN_ERR"DPA Classifier Driver failed to initialize.\n");
		return err;
	}

	/* Initialize DPA IPSec wrapper to listen to [ioctl] calls */
	err = wrp_dpa_ipsec_init();
	if (err == 0)
		printk(KERN_INFO"DPA IPSec Driver initialized.\n");
	else {
		printk(KERN_ERR"DPA IPSec Driver failed to initialize.\n");
		return err;
	}

	/* Initialize DPA Stats wrapper to listen to [ioctl] calls */
	err = wrp_dpa_stats_init();
	if (err == 0)
		printk(KERN_INFO"DPA Stats Driver initialized.\n");
	else {
		printk(KERN_ERR"DPA Stats Driver failed to initialize.\n");
		return err;
	}

	return err;
}
module_init(dpa_offload_drv_init);

static void __exit dpa_offload_drv_exit(void)
{
	/* Shut down DPA Classifier wrapper */
	if (wrp_dpa_classif_exit() < 0)
		printk(KERN_ERR"DPA Classifier Driver failed to unload.\n");
	else
		printk(KERN_INFO"DPA Classifier Driver unloaded.\n");

	/* Shut down DPA IPSec wrapper */
	if (wrp_dpa_ipsec_exit() < 0)
		printk(KERN_ERR"DPA IPSec Driver failed to unload.\n");
	else
		printk(KERN_INFO"INFO: DPA IPSec Driver unloaded.\n");

	/* Shut down DPA Stats wrapper */
	if (wrp_dpa_stats_exit() < 0)
		printk(KERN_ERR"DPA Stats Driver failed to unload.\n");
	else
		printk(KERN_INFO"INFO: DPA Stats Driver unloaded.\n");
}
module_exit(dpa_offload_drv_exit);

MODULE_AUTHOR("Freescale, <freescale.com>");
MODULE_DESCRIPTION("DPA Offloading Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
