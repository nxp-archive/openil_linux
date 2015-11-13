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

#include "dce-fcr.h"
#include "dce-attr-encoder-decoder.h"

/* DCE_CODE (word_offset, lsb_offset, bit_width) */
static struct dce_attr_code code_ffdpc_lo = DCE_CODE(0, 0, 32);
static struct dce_attr_code code_ffdpc_hi = DCE_CODE(1, 0, 32);
static struct dce_attr_code code_bp2ac = DCE_CODE(2, 0, 32);
static struct dce_attr_code code_bp1ac = DCE_CODE(3, 0, 32);
static struct dce_attr_code code_bp2ac_bmt = DCE_CODE(2, 31, 1);
static struct dce_attr_code code_bp2ac_bpid = DCE_CODE(2, 16, 14);
static struct dce_attr_code code_bp2ac_pbs = DCE_CODE(2, 6, 10);
static struct dce_attr_code code_bp1ac_bmt = DCE_CODE(3, 31, 1);
static struct dce_attr_code code_bp1ac_bpid = DCE_CODE(3, 16, 14);
static struct dce_attr_code code_bp1ac_pbs = DCE_CODE(3, 6, 10);
static struct dce_attr_code code_next_flc_lo = DCE_CODE(4, 0, 32);
static struct dce_attr_code code_next_flc_hi = DCE_CODE(5, 0, 32);

/* fcr accessors */

void fcr_clear(struct fcr *d)
{
	memset(d, 0, sizeof(*d));
}
EXPORT_SYMBOL(fcr_clear);

u32 fcr_get_ffdpc_hi(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_ffdpc_hi, cl);
}
EXPORT_SYMBOL(fcr_get_ffdpc_hi);

u32 fcr_get_ffdpc_lo(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_ffdpc_lo, cl);
}
EXPORT_SYMBOL(fcr_get_ffdpc_lo);

u32 fcr_get_bp2ac(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac, cl);
}
EXPORT_SYMBOL(fcr_get_bp2ac);

u32 fcr_get_bp1ac(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac, cl);
}
EXPORT_SYMBOL(fcr_get_bp1ac);

void fcr_set_bp2ac_bmt(struct fcr *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp2ac_bmt, cl, !!enable);
}
EXPORT_SYMBOL(fcr_set_bp2ac_bmt);

int fcr_get_bp2ac_bmt(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_bmt, cl);
}
EXPORT_SYMBOL(fcr_get_bp2ac_bmt);

void fcr_set_bp2ac_bpid(struct fcr *d, u32 bpid)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp2ac_bpid, cl, bpid);
}
EXPORT_SYMBOL(fcr_set_bp2ac_bpid);

u32 fcr_get_bp2ac_bpid(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_bpid, cl);
}
EXPORT_SYMBOL(fcr_get_bp2ac_bpid);

void fcr_set_bp2ac_pbs(struct fcr *d, u32 pbs)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp2ac_pbs, cl, pbs);
}
EXPORT_SYMBOL(fcr_set_bp2ac_pbs);

u32 fcr_get_bp2ac_pbs(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_pbs, cl);
}
EXPORT_SYMBOL(fcr_get_bp2ac_pbs);

void fcr_set_bp1ac_bmt(struct fcr *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp1ac_bmt, cl, !!enable);
}
EXPORT_SYMBOL(fcr_set_bp1ac_bmt);

int fcr_get_bp1ac_bmt(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_bmt, cl);
}
EXPORT_SYMBOL(fcr_get_bp1ac_bmt);

void fcr_set_bp1ac_bpid(struct fcr *d, u32 bpid)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp1ac_bpid, cl, bpid);
}
EXPORT_SYMBOL(fcr_set_bp1ac_bpid);

u32 fcr_get_bp1ac_bpid(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_bpid, cl);
}
EXPORT_SYMBOL(fcr_get_bp1ac_bpid);

void fcr_set_bp1ac_pbs(struct fcr *d, u32 pbs)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp1ac_pbs, cl, pbs);
}
EXPORT_SYMBOL(fcr_set_bp1ac_pbs);

u32 fcr_get_bp1ac_pbs(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_pbs, cl);
}
EXPORT_SYMBOL(fcr_get_bp1ac_pbs);

void fcr_set_next_flc(struct fcr *d, uint64_t addr)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode_64(&code_next_flc_lo, (uint64_t *)cl, addr);
}
EXPORT_SYMBOL(fcr_set_next_flc);

uint64_t fcr_get_next_flc(struct fcr *d)
{
	const u32 *cl = dce_cl(d);

	return ((uint64_t)dce_attr_code_decode(&code_next_flc_hi, cl) << 32) |
		(uint64_t)dce_attr_code_decode(&code_next_flc_lo, cl);
}
EXPORT_SYMBOL(fcr_get_next_flc);

