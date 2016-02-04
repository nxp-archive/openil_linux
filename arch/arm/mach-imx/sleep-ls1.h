/*
 * Copyright 2014 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#ifndef __ARM_SLEEP_LS1_H
#define __ARM_SLEEP_LS1_H

void ls1_do_deepsleep(unsigned long addr);
void ls1_start_fsm(void);
void ls1_deepsleep_resume(void);
void fsl_epu_setup_default(void __iomem *epu_base);

extern int ls1_sram_code_size;

#endif
