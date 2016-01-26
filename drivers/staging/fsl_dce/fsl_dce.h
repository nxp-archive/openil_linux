/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * This software is provided by Freescale Semiconductor "as is" and any
 * express or implied warranties, including, but not limited to, the implied
 * warranties of merchantability and fitness for a particular purpose are
 * disclaimed. In no event shall Freescale Semiconductor be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential damages
 * (including, but not limited to, procurement of substitute goods or services;
 * loss of use, data, or profits; or business interruption) however caused and
 * on any theory of liability, whether in contract, strict liability, or tort
 * (including negligence or otherwise) arising in any way out of the use of
 * this software, even if advised of the possibility of such damage.
 */

#ifndef FSL_DCE_H
#define FSL_DCE_H

/****************/
/* KERNEL SPACE */
/****************/

#ifdef __KERNEL__

/* Does dce have access to ccsr */
int fsl_dce_have_control(void);

/**************************/
/* control-plane only API */
/**************************/

enum fsl_dce_stat_attr {
	DCE_COMP_INPUT_BYTES,
	DCE_COMP_OUTPUT_BYTES,
	DCE_DECOMP_INPUT_BYTES,
	DCE_DECOMP_OUTPUT_BYTES
};

int fsl_dce_get_stat(enum fsl_dce_stat_attr attr, u64 *val, int reset);
int fsl_dce_clear_stat(enum fsl_dce_stat_attr attr);

#endif /* __KERNEL__ */

#endif /* FSL_DCE_H */
