// SPDX-License-Identifier: GPL-2.0+
/*
 * include/linux/ipi_baremetal.h
 *
 * Copyright 2018-2021 NXP
 *
 */

#ifndef __LINUX_IPI_BAREMETAL_H
#define __LINUX_IPI_BAREMETAL_H

#include <linux/kernel.h>

int ipi_baremetal_handle(u32 irqnr, u32 irqsrc);
#endif	/* !__LINUX_IPI_BAREMETAL_H */
