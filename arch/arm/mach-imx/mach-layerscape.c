/*
 * Copyright 2015-2016 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/mach/arch.h>

#include "common.h"

static const char * const layerscape_dt_compat[] __initconst = {
	"fsl,ls1012a",
	"fsl,ls1043a",
	"fsl,ls1046a",
	NULL,
};

DT_MACHINE_START(LAYERSCAPE_AARCH32, "Freescale LAYERSCAPE")
	.smp		= smp_ops(layerscape_smp_ops),
	.dt_compat	= layerscape_dt_compat,
MACHINE_END
