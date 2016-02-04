/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) 2013 Freescale Semiconductor, Inc.
 *
 */

#ifndef __FSL_PAMU_STASH_H
#define __FSL_PAMU_STASH_H

/* Define operation mapping indexes */
enum omap_index {
	OMI_QMAN,
	OMI_FMAN,
	OMI_QMAN_PRIV,
	OMI_CAAM,
	OMI_PMAN,
	OMI_DSP,
	OMI_MAX,
};

/* cache stash targets */
enum pamu_stash_target {
	PAMU_ATTR_CACHE_L1 = 1,
	PAMU_ATTR_CACHE_L2,
	PAMU_ATTR_CACHE_L3,
	PAMU_ATTR_CACHE_DSP_L2,
};

/*
 * This attribute allows configuring stashig specific parameters
 * in the PAMU hardware.
 */

struct pamu_stash_attribute {
	u32	cpu;	/* cpu number */
	u32	cache;	/* cache to stash to: L1,L2,L3 */
	u32	window; /* ~0 indicates all windows */
};

struct pamu_omi_attribute {
	u32	omi;	/* index in the operation mapping table */
	u32	window;	/* ~0 indicates all windows */
};

#endif  /* __FSL_PAMU_STASH_H */
