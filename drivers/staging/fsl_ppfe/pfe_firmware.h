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

#ifndef _PFE_FIRMWARE_H_
#define _PFE_FIRMWARE_H_

#if defined(CONFIG_PLATFORM_C2000)
#define CLASS_FIRMWARE_FILENAME		"class_c2000.elf"
#define TMU_FIRMWARE_FILENAME		"tmu_c2000.elf"
#define UTIL_FIRMWARE_FILENAME		"util_c2000.elf"
#define UTIL_REVA0_FIRMWARE_FILENAME	"util_c2000_revA0.elf"
#else
#define CLASS_FIRMWARE_FILENAME		"ppfe_class_ls1012a.elf"
#define TMU_FIRMWARE_FILENAME		"ppfe_tmu_ls1012a.elf"
#endif

#define PFE_FW_CHECK_PASS		0
#define PFE_FW_CHECK_FAIL		1
#define NUM_PFE_FW				3

int pfe_firmware_init(struct pfe *pfe);
void pfe_firmware_exit(struct pfe *pfe);

#endif /* _PFE_FIRMWARE_H_ */

