/* Copyright (C) 2015 Freescale Semiconductor, Inc.
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

#ifndef __DCE_FCR_H
#define __DCE_FCR_H

#include "dce-private.h"

/* DCE hw requires FCR to be 64 byte aligned */
#define FCR_ALIGN	64

/* FCR: Flow Context Record */
struct fcr {
	u32 dont_manipulate_directly[32];
};

/*******************************************************************************
 *
 * fcr APIS
 *
 ******************************************************************************/
void fcr_clear(struct fcr *d);

/* Storage Profile Format and Data Placement Controls */
u32 fcr_get_ffdpc_hi(struct fcr *d);
u32 fcr_get_ffdpc_lo(struct fcr *d);

/* BP2 settings: buffer pool id, pool buffer size */
u32 fcr_get_bp2ac(struct fcr *d);
void fcr_set_bp2ac_bmt(struct fcr *d, int enable);
int fcr_get_bp2ac_bmt(struct fcr *d);
void fcr_set_bp2ac_bpid(struct fcr *d, u32 bpid);
u32 fcr_get_bp2ac_bpid(struct fcr *d);
void fcr_set_bp2ac_pbs(struct fcr *d, u32 pbs);
u32 fcr_get_bp2ac_pbs(struct fcr *d);

/* BP1 settings: buffer pool id, pool buffer size */
u32 fcr_get_bp1ac(struct fcr *d);
void fcr_set_bp1ac_bmt(struct fcr *d, int enable);
int fcr_get_bp1ac_bmt(struct fcr *d);
void fcr_set_bp1ac_bpid(struct fcr *d, u32 bpid);
u32 fcr_get_bp1ac_bpid(struct fcr *d);
void fcr_set_bp1ac_pbs(struct fcr *d, u32 pbs);
u32 fcr_get_bp1ac_pbs(struct fcr *d);

/* next_flc */
void fcr_set_next_flc(struct fcr *d, uint64_t addr);
uint64_t fcr_get_next_flc(struct fcr *d);

#endif
