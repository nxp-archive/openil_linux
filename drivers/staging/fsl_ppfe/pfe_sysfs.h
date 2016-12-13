/*
 *
 *  Copyright (C) 2007 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _PFE_SYSFS_H_
#define _PFE_SYSFS_H_

#include <linux/proc_fs.h>

#define	PESTATUS_ADDR_CLASS	0x800
#define	PESTATUS_ADDR_TMU	0x80
#define	PESTATUS_ADDR_UTIL	0x0

#define TMU_CONTEXT_ADDR 	0x3c8
#define IPSEC_CNTRS_ADDR 	0x840

int pfe_sysfs_init(struct pfe *pfe);
void pfe_sysfs_exit(struct pfe *pfe);
#endif /* _PFE_SYSFS_H_ */
