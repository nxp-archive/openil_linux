/* SPDX-License-Identifier: (GPL-2.0 OR MIT)
 *
 * TSN_SWITCH driver
 *
 * Copyright 2018-2019 NXP
 */

#ifndef _MSCC_FELIX_SWITCH_TSN_H_
#define _MSCC_FELIX_SWITCH_TSN_H_

void felix_preempt_irq_clean(struct ocelot *ocelot);
void felix_cbs_reset(struct ocelot *ocelot, int port, int speed);
int felix_tsn_enable(struct dsa_switch *ds);
#endif
