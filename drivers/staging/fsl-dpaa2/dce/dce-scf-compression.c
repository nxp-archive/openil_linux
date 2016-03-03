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

#include "dce-scf-compression.h"
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
static struct dce_attr_code code_history_len = DCE_CODE(6, 16, 16);
static struct dce_attr_code code_extra_ptr_lo = DCE_CODE(8, 0, 32);
static struct dce_attr_code code_extra_ptr_hi = DCE_CODE(9, 0, 32);
static struct dce_attr_code code_pending_output_ptr_lo = DCE_CODE(10, 0, 32);
static struct dce_attr_code code_pending_output_ptr_hi = DCE_CODE(11, 0, 32);
static struct dce_attr_code code_history_ptr_lo = DCE_CODE(12, 6, 26);
static struct dce_attr_code code_history_ptr_hi = DCE_CODE(13, 0, 32);
/* the following could be in first or second 64B cache line */
static struct dce_attr_code code_total_in = DCE_CODE(0, 0, 32);
static struct dce_attr_code code_total_out = DCE_CODE(1, 0, 32);
static struct dce_attr_code code_adler32 = DCE_CODE(2, 0, 32);
static struct dce_attr_code code_b64_residue = DCE_CODE(3, 0, 24);
static struct dce_attr_code code_b64_residue_len = DCE_CODE(3, 24, 2);
static struct dce_attr_code code_output_phase = DCE_CODE(3, 26, 3);
static struct dce_attr_code code_pmode = DCE_CODE(3, 31, 1);
static struct dce_attr_code code_flg = DCE_CODE(4, 0, 8);
static struct dce_attr_code code_cm = DCE_CODE(4, 8, 8);
static struct dce_attr_code code_id2 = DCE_CODE(4, 16, 8);
static struct dce_attr_code code_id1 = DCE_CODE(4, 24, 8);
static struct dce_attr_code code_mtime = DCE_CODE(5, 0, 32);
static struct dce_attr_code code_xlen = DCE_CODE(6, 0, 16);
static struct dce_attr_code code_os = DCE_CODE(6, 16, 8);
static struct dce_attr_code code_xfl = DCE_CODE(6, 24, 8);
static struct dce_attr_code code_clen = DCE_CODE(7, 0, 16);
static struct dce_attr_code code_nlen = DCE_CODE(7, 16, 16);
static struct dce_attr_code code_pending_working_idx = DCE_CODE(10, 0, 16);
static struct dce_attr_code code_pending_output_len_dbg = DCE_CODE(10, 16, 16);
static struct dce_attr_code code_residue_data = DCE_CODE(12, 0, 23);
static struct dce_attr_code code_residue_byte_count = DCE_CODE(12, 24, 5);
static struct dce_attr_code code_header_remaining = DCE_CODE(14, 0, 18);
static struct dce_attr_code code_mcplt = DCE_CODE(14, 22, 1);
static struct dce_attr_code code_terminated = DCE_CODE(14, 29, 1);
static struct dce_attr_code code_suspended = DCE_CODE(14, 30, 1);
static struct dce_attr_code code_pmode_dbg = DCE_CODE(14, 31, 1);
static struct dce_attr_code code_crc16 = DCE_CODE(15, 0, 32);
static struct dce_attr_code code_bytes_processed = DCE_CODE(3, 0, 29);
static struct dce_attr_code code_pending_output_len = DCE_CODE(4, 16, 16);


/* scf_c_cfg accessors */

/* TODO: FFDCP */

void scf_c_cfg_clear(struct scf_c_cfg *d)
{
	memset(d, 0, sizeof(*d));
}
EXPORT_SYMBOL(scf_c_cfg_clear);

void scf_c_cfg_set_bp2ac_bmt(struct scf_c_cfg *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp2ac_bmt, cl, !!enable);
}
EXPORT_SYMBOL(scf_c_cfg_set_bp2ac_bmt);

int scf_c_cfg_get_bp2ac_bmt(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_bmt, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_bp2ac_bmt);

void scf_c_cfg_set_bp2ac_bpid(struct scf_c_cfg *d, u32 bpid)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp2ac_bpid, cl, bpid);
}
EXPORT_SYMBOL(scf_c_cfg_set_bp2ac_bpid);

u32 scf_c_cfg_get_bp2ac_bpid(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_bpid, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_bp2ac_bpid);

void scf_c_cfg_set_bp2ac_pbs(struct scf_c_cfg *d, u32 pbs)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp2ac_pbs, cl, pbs);
}
EXPORT_SYMBOL(scf_c_cfg_set_bp2ac_pbs);

u32 scf_c_cfg_get_bp2ac_pbs(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_pbs, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_bp2ac_pbs);

void scf_c_cfg_set_bp1ac_bmt(struct scf_c_cfg *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp1ac_bmt, cl, !!enable);
}
EXPORT_SYMBOL(scf_c_cfg_set_bp1ac_bmt);

int scf_c_cfg_get_bp1ac_bmt(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_bmt, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_bp1ac_bmt);

void scf_c_cfg_set_bp1ac_bpid(struct scf_c_cfg *d, u32 bpid)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp1ac_bpid, cl, bpid);
}
EXPORT_SYMBOL(scf_c_cfg_set_bp1ac_bpid);

u32 scf_c_cfg_get_bp1ac_bpid(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_bpid, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_bp1ac_bpid);

void scf_c_cfg_set_bp1ac_pbs(struct scf_c_cfg *d, u32 pbs)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp1ac_pbs, cl, pbs);
}
EXPORT_SYMBOL(scf_c_cfg_set_bp1ac_pbs);

u32 scf_c_cfg_get_bp1ac_pbs(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_pbs, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_bp1ac_pbs);

void scf_c_cfg_set_next_flc(struct scf_c_cfg *d, uint64_t addr)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode_64(&code_next_flc_lo, (uint64_t *)cl, addr);
}
EXPORT_SYMBOL(scf_c_cfg_set_next_flc);

uint64_t scf_c_cfg_get_next_flc(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl(d);

	return ((uint64_t)dce_attr_code_decode(&code_next_flc_hi, cl) << 32) |
		(uint64_t)dce_attr_code_decode(&code_next_flc_lo, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_next_flc);

void scf_c_cfg_set_extra_ptr(struct scf_c_cfg *d, uint64_t addr)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode_64(&code_extra_ptr_lo, (uint64_t *)cl, addr);
}
EXPORT_SYMBOL(scf_c_cfg_set_extra_ptr);

uint64_t scf_c_cfg_get_extra_ptr(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl(d);

	return ((uint64_t)dce_attr_code_decode(&code_extra_ptr_hi, cl) << 32) |
		(uint64_t)dce_attr_code_decode(&code_extra_ptr_lo, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_extra_ptr);

void scf_c_cfg_set_pending_output_ptr(struct scf_c_cfg *d, uint64_t addr)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode_64(&code_pending_output_ptr_lo, (uint64_t *)cl,
				addr);
}
EXPORT_SYMBOL(scf_c_cfg_set_pending_output_ptr);

uint64_t scf_c_cfg_get_pending_output_ptr(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl(d);

	return ((uint64_t)dce_attr_code_decode(
		&code_pending_output_ptr_hi, cl) << 32) |
		(uint64_t)dce_attr_code_decode(&code_pending_output_ptr_lo, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_pending_output_ptr);

void scf_c_cfg_set_history_ptr(struct scf_c_cfg *d, uint64_t addr)
{
	/*
	 * this pointer must be 64B aligned. Hardware assumes the lower
	 * 6 bits are zero. The lower 6 bits in the structure should are
	 * not defined and should not be interpreted.
	 */
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_pending_output_ptr_lo, cl,
			lower32(addr) >> 6);
	dce_attr_code_encode(&code_history_ptr_hi, cl, upper32(addr));
}
EXPORT_SYMBOL(scf_c_cfg_set_history_ptr);

uint64_t scf_c_cfg_get_history_ptr(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl(d);

	/* see above comment about history pointer lower 6 bits */
	return ((uint64_t)dce_attr_code_decode(
		&code_history_ptr_hi, cl) << 32) |
		(uint64_t)(dce_attr_code_decode(&code_history_ptr_lo, cl) << 6);
}
EXPORT_SYMBOL(scf_c_cfg_get_history_ptr);

void scf_c_cfg_set_total_in(struct scf_c_cfg *d, u32 byte_cnt)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_total_in, cl, byte_cnt);
}
EXPORT_SYMBOL(scf_c_cfg_set_total_in);

u32 scf_c_cfg_get_total_in(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_total_in, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_total_in);

void scf_c_cfg_set_total_out(struct scf_c_cfg *d, u32 byte_cnt)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_total_out, cl, byte_cnt);
}
EXPORT_SYMBOL(scf_c_cfg_set_total_out);

u32 scf_c_cfg_get_total_out(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_total_out, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_total_out);

void scf_c_cfg_set_adler32(struct scf_c_cfg *d, u32 adler32)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_adler32, cl, adler32);
}
EXPORT_SYMBOL(scf_c_cfg_set_adler32);

u32 scf_c_cfg_get_adler32(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_adler32, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_adler32);

void scf_c_cfg_set_pmode(struct scf_c_cfg *d, int mode)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_bp2ac_bmt, cl, mode);
}
EXPORT_SYMBOL(scf_c_cfg_set_pmode);

int scf_c_cfg_get_pmode(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_pmode, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_pmode);

void scf_c_cfg_set_flg(struct scf_c_cfg *d, u32 flg)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_flg, cl, flg);
}
EXPORT_SYMBOL(scf_c_cfg_set_flg);

u32 scf_c_cfg_get_flg(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_flg, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_flg);

void scf_c_cfg_set_cm(struct scf_c_cfg *d, u32 cm)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_cm, cl, cm);
}
EXPORT_SYMBOL(scf_c_cfg_set_cm);

u32 scf_c_cfg_get_cm(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_cm, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_cm);

void scf_c_cfg_set_id2(struct scf_c_cfg *d, u32 id2)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_id2, cl, id2);
}
EXPORT_SYMBOL(scf_c_cfg_set_id2);

u32 scf_c_cfg_get_id2(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_id2, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_id2);

void scf_c_cfg_set_id1(struct scf_c_cfg *d, u32 id1)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_id1, cl, id1);
}
EXPORT_SYMBOL(scf_c_cfg_set_id1);

u32 scf_c_cfg_get_id1(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_id1, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_id1);

void scf_c_cfg_set_mtime(struct scf_c_cfg *d, u32 mtime)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_mtime, cl, mtime);
}
EXPORT_SYMBOL(scf_c_cfg_set_mtime);

u32 scf_c_cfg_get_mtime(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_mtime, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_mtime);

void scf_c_cfg_set_xlen(struct scf_c_cfg *d, u32 xlen)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_mtime, cl, xlen);
}
EXPORT_SYMBOL(scf_c_cfg_set_xlen);

u32 scf_c_cfg_get_xlen(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_xlen, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_xlen);

void scf_c_cfg_set_os(struct scf_c_cfg *d, u32 os)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_os, cl, os);
}
EXPORT_SYMBOL(scf_c_cfg_set_os);

u32 scf_c_cfg_get_os(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_os, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_os);

void scf_c_cfg_set_xfl(struct scf_c_cfg *d, u32 xfl)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_xfl, cl, xfl);
}
EXPORT_SYMBOL(scf_c_cfg_set_xfl);

u32 scf_c_cfg_get_xfl(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_xfl, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_xfl);

void scf_c_cfg_set_clen(struct scf_c_cfg *d, u32 clen)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_clen, cl, clen);
}
EXPORT_SYMBOL(scf_c_cfg_set_clen);

u32 scf_c_cfg_get_clen(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_clen, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_clen);

void scf_c_cfg_set_nlen(struct scf_c_cfg *d, u32 nlen)
{
	u32 *cl = dce_cl2(d);

	dce_attr_code_encode(&code_nlen, cl, nlen);
}
EXPORT_SYMBOL(scf_c_cfg_set_nlen);

u32 scf_c_cfg_get_nlen(struct scf_c_cfg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_nlen, cl);
}
EXPORT_SYMBOL(scf_c_cfg_get_nlen);

/*******************************************************************************
 *
 * scf_c_result APIS
 *
 ******************************************************************************/
void scf_c_result_set_total_in(struct scf_c_result *d, u32 byte_cnt)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_total_in, cl, byte_cnt);
}
EXPORT_SYMBOL(scf_c_result_set_total_in);

u32 scf_c_result_get_total_in(struct scf_c_result *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_total_in, cl);
}
EXPORT_SYMBOL(scf_c_result_get_total_in);

void scf_c_result_set_total_out(struct scf_c_result *d, u32 byte_cnt)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_total_out, cl, byte_cnt);
}
EXPORT_SYMBOL(scf_c_result_set_total_out);

u32 scf_c_result_get_total_out(struct scf_c_result *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_total_out, cl);
}
EXPORT_SYMBOL(scf_c_result_get_total_out);

void scf_c_result_set_adler32(struct scf_c_result *d, u32 adler32)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_adler32, cl, adler32);
}
EXPORT_SYMBOL(scf_c_result_set_adler32);

u32 scf_c_result_get_adler32(struct scf_c_result *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_adler32, cl);
}
EXPORT_SYMBOL(scf_c_result_get_adler32);

void scf_c_result_set_bytes_processed(struct scf_c_result *d, u32 val)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bytes_processed, cl, val);
}
EXPORT_SYMBOL(scf_c_result_set_bytes_processed);

u32 scf_c_result_get_bytes_processed(struct scf_c_result *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bytes_processed, cl);
}
EXPORT_SYMBOL(scf_c_result_get_bytes_processed);

void scf_c_result_set_pending_output_len(struct scf_c_result *d, u32 val)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_pending_output_len, cl, val);
}
EXPORT_SYMBOL(scf_c_result_set_pending_output_len);

u32 scf_c_result_get_pending_output_len(struct scf_c_result *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_pending_output_len, cl);
}
EXPORT_SYMBOL(scf_c_result_get_pending_output_len);

/*******************************************************************************
 *
 * scf_c_result_dbg APIS
 *
 ******************************************************************************/
void scf_c_result_dbg_clear(struct scf_c_result_dbg *d)
{
	memset(d, 0, sizeof(*d));
}
EXPORT_SYMBOL(scf_c_result_dbg_clear);

uint64_t scf_c_result_dbg_get_ffdpc(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return ((uint64_t)dce_attr_code_decode(&code_ffdpc_hi, cl) << 32) |
		(uint64_t)dce_attr_code_decode(&code_ffdpc_lo, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_ffdpc);

u32 scf_c_result_dbg_get_bp2ac(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_bp2ac);

int scf_c_result_dbg_get_bp2ac_bmt(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_bmt, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_bp2ac_bmt);

u32 scf_c_result_dbg_get_bp2ac_bpid(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_bpid, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_bp2ac_bpid);

u32 scf_c_result_dbg_get_bp2ac_pbs(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_pbs, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_bp2ac_pbs);

u32 scf_c_result_dbg_get_bp1ac(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_bp1ac);

int scf_c_result_dbg_get_bp1ac_bmt(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_bmt, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_bp1ac_bmt);

u32 scf_c_result_dbg_get_bp1ac_bpid(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_bpid, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_bp1ac_bpid);

u32 scf_c_result_dbg_get_bp1ac_pbs(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_pbs, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_bp1ac_pbs);

uint64_t scf_c_result_dbg_get_next_flc(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_next_flc((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_next_flc);

u32 scf_c_result_dbg_get_history_len(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_history_len, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_history_len);

uint64_t scf_c_result_dbg_get_extra_ptr(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return ((uint64_t)dce_attr_code_decode(&code_extra_ptr_hi, cl) << 32) |
		(uint64_t)dce_attr_code_decode(&code_extra_ptr_lo, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_extra_ptr);

uint64_t scf_c_result_dbg_get_pending_output_ptr(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	return ((uint64_t)
		dce_attr_code_decode(&code_pending_output_ptr_hi, cl) << 32) |
		(uint64_t)dce_attr_code_decode(&code_pending_output_ptr_lo, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_pending_output_ptr);

uint64_t scf_c_result_dbg_get_history_ptr(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl(d);

	/* see above comment about history pointer lower 6 bits */
	return ((uint64_t)dce_attr_code_decode(
		&code_history_ptr_hi, cl) << 32) |
		(uint64_t)(dce_attr_code_decode(&code_history_ptr_lo, cl) << 6);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_history_ptr);

u32 scf_c_result_dbg_get_total_in(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_total_in((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_total_in);

u32 scf_c_result_dbg_get_total_out(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_total_out((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_total_out);

u32 scf_c_result_dbg_get_adler32(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_adler32((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_adler32);

u32 scf_c_result_dbg_get_b64_residue(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_b64_residue, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_b64_residue);

u32 scf_c_result_dbg_get_b64_residue_len(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_b64_residue_len, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_b64_residue_len);

u32 scf_c_result_dbg_get_output_phase(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_output_phase, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_output_phase);

u32 scf_c_result_dbg_get_flg(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_flg((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_flg);

u32 scf_c_result_dbg_get_cm(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_cm((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_cm);

u32 scf_c_result_dbg_get_id2(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_id2((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_id2);

u32 scf_c_result_dbg_get_id1(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_id1((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_id1);

u32 scf_c_result_dbg_get_mtime(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_mtime((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_mtime);

u32 scf_c_result_dbg_get_xlen(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_xlen((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_xlen);

u32 scf_c_result_dbg_get_os(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_os((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_os);

u32 scf_c_result_dbg_get_xfl(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_xfl((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_xfl);

u32 scf_c_result_dbg_get_clen(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_clen((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_clen);

u32 scf_c_result_dbg_get_nlen(struct scf_c_result_dbg *d)
{
	return scf_c_cfg_get_nlen((struct scf_c_cfg *)d);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_nlen);

u32 scf_c_result_dbg_get_pending_working_idx(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_pending_working_idx, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_pending_working_idx);

u32 scf_c_result_dbg_get_pending_working_len(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_pending_output_len_dbg, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_pending_working_len);

u32 scf_c_result_dbg_get_residue_data(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_residue_data, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_residue_data);

u32 scf_c_result_dbg_get_residue_byte_count(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_residue_byte_count, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_residue_byte_count);

u32 scf_c_result_dbg_get_header_remaining(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_header_remaining, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_header_remaining);

int scf_c_result_dbg_get_mcplt(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_mcplt, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_mcplt);

int scf_c_result_dbg_get_terminated(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_terminated, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_terminated);

int scf_c_result_dbg_get_suspended(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_suspended, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_suspended);

int scf_c_result_dbg_get_pmode(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_pmode_dbg, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_pmode);

u32 scf_c_result_dbg_get_crc16(struct scf_c_result_dbg *d)
{
	const u32 *cl = dce_cl2(d);

	return dce_attr_code_decode(&code_crc16, cl);
}
EXPORT_SYMBOL(scf_c_result_dbg_get_crc16);


