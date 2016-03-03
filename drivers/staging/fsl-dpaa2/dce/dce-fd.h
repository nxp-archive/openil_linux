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

#ifndef __DCE_FD_H
#define __DCE_FD_H

#include "dce-fd.h"
#include <linux/types.h>


struct fd_attr {
	u32 dont_manipulate_directly[8];
};

struct fle_attr {
	u32 dont_manipulate_directly[8];
};

/* Frame Descriptor */
uint64_t fd_attr_get_addr_64(struct fd_attr *d);
void fd_attr_get_addr_49(struct fd_attr *d, u32 *hi, u32 *lo);
void fd_attr_get_addr_64_v2(struct fd_attr *d, u32 *hi, u32 *lo);
u32 fd_attr_get_sw_token(struct fd_attr *d);

u32 fd_attr_get_data_len_18(struct fd_attr *d);
u32 fd_attr_get_data_len_32(struct fd_attr *d);
u32 fd_attr_get_mem(struct fd_attr *d);
u32 fd_attr_get_bpid(struct fd_attr *d);
u32 fd_attr_get_ivp(struct fd_attr *d);
u32 fd_attr_get_bmt(struct fd_attr *d);
u32 fd_attr_get_offset(struct fd_attr *d);
u32 fd_attr_get_frame_format(struct fd_attr *d);
u32 fd_attr_get_sl(struct fd_attr *d);
u32 fd_attr_get_frc(const struct fd_attr *d);
u32 fd_attr_get_frc_status(const struct fd_attr *d);
u32 fd_attr_get_err(struct fd_attr *d);
u32 fd_attr_get_va(struct fd_attr *d);
u32 fd_attr_get_cbmt(struct fd_attr *d);
u32 fd_attr_get_asal(struct fd_attr *d);
u32 fd_attr_get_ptv2(struct fd_attr *d);
u32 fd_attr_get_ptv1(struct fd_attr *d);
u32 fd_attr_get_pta(struct fd_attr *d);
u32 fd_attr_get_dropp(struct fd_attr *d);
u32 fd_attr_get_sc(struct fd_attr *d);
u32 fd_attr_get_dd(struct fd_attr *d);
void pretty_print_fd(struct fd_attr *d);

/* set methods */
void fd_attr_set_flc_64(struct fd_attr *d, uint64_t addr);
uint64_t fd_attr_get_flc_64(struct fd_attr *d);


/*  Frame list entry (FLE) */
uint64_t fle_attr_get_addr_64(struct fle_attr *d);
void fle_attr_get_addr_49(struct fle_attr *d,  u32 *hi, u32 *lo);
void fle_attr_get_addr_64_v2(struct fle_attr *d,  u32 *hi, u32 *lo);
u32 fle_attr_get_sw_token(struct fle_attr *d);
u32 fle_attr_get_data_len_18(struct fle_attr *d);
u32 fle_attr_get_data_len_32(struct fle_attr *d);
u32 fle_attr_get_mem(struct fle_attr *d);
u32 fle_attr_get_bpid(struct fle_attr *d);
u32 fle_attr_get_ivp(struct fle_attr *d);
u32 fle_attr_get_bmt(struct fle_attr *d);
u32 fle_attr_get_offset(struct fle_attr *d);
u32 fle_attr_get_frame_format(struct fle_attr *d);
u32 fle_attr_get_sl(struct fle_attr *d);
u32 fle_attr_get_final(struct fle_attr *d);
u32 fle_attr_get_frc(struct fle_attr *d);
u32 fle_attr_get_err(struct fle_attr *d);
u32 fle_attr_get_fd_compat_1(struct fle_attr *d);
u32 fle_attr_get_cbmt(struct fle_attr *d);
u32 fle_attr_get_asal(struct fle_attr *d);
u32 fle_attr_get_ptv2(struct fle_attr *d);
u32 fle_attr_get_ptv1(struct fle_attr *d);
u32 fle_attr_get_pta(struct fle_attr *d);
u32 fle_attr_get_fd_compat_8(struct fle_attr *d);

void fle_attr_set_flc_64(struct fle_attr *d, uint64_t addr);
uint64_t fle_attr_get_flc_64(struct fle_attr *d);
void fle_attr_get_flc_64_v2(struct fle_attr *d,  u32 *hi, u32 *lo);

void pretty_print_fle(struct fle_attr *d);
void pretty_print_fle_n(struct fle_attr *d, int n);

#endif
