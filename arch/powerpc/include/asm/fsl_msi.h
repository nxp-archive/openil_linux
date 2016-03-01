/*
 * Copyright (C) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: Bharat Bhushan <bharat.bhushan@freescale.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the
 * License.
 *
 */

#ifndef _POWERPC_FSL_MSI_H
#define _POWERPC_FSL_MSI_H

struct msi_region {
	int region_num;
	dma_addr_t addr;
	size_t size;
};

int fsl_msi_get_region_count(void);
int fsl_msi_get_region(int region_num, struct msi_region *region);

#endif /* _POWERPC_FSL_MSI_H */
