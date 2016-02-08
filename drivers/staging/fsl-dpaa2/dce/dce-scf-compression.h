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

#ifndef __DCE_SCF_COMPRESSION_H
#define __DCE_SCF_COMPRESSION_H

#include "dce-private.h"
#define SCF_C_CFG_ALIGN	64

struct scf_c_cfg {
	u32 dont_manipulate_directly[32];
};

struct scf_c_result {
	u32 dont_manipulate_directly[16];
};

struct scf_c_result_dbg {
	u32 dont_manipulate_directly[32];
};

/*******************************************************************************
 *
 * scf_c_cfg APIS
 *
 ******************************************************************************/
void scf_c_cfg_clear(struct scf_c_cfg *d);
/* BP2 settings: buffer pool id, pool buffer size */
void scf_c_cfg_set_bp2ac_bmt(struct scf_c_cfg *d, int enable);
int scf_c_cfg_get_bp2ac_bmt(struct scf_c_cfg *d);
void scf_c_cfg_set_bp2ac_bpid(struct scf_c_cfg *d, u32 bpid);
u32 scf_c_cfg_get_bp2ac_bpid(struct scf_c_cfg *d);
void scf_c_cfg_set_bp2ac_pbs(struct scf_c_cfg *d, u32 pbs);
u32 scf_c_cfg_get_bp2ac_pbs(struct scf_c_cfg *d);

/* BP1 settings: buffer pool id, pool buffer size */
void scf_c_cfg_set_bp1ac_bmt(struct scf_c_cfg *d, int enable);
int scf_c_cfg_get_bp1ac_bmt(struct scf_c_cfg *d);
void scf_c_cfg_set_bp1ac_bpid(struct scf_c_cfg *d, u32 bpid);
u32 scf_c_cfg_get_bp1ac_bpid(struct scf_c_cfg *d);
void scf_c_cfg_set_bp1ac_pbs(struct scf_c_cfg *d, u32 pbs);
u32 scf_c_cfg_get_bp1ac_pbs(struct scf_c_cfg *d);

/* next_flc */
void scf_c_cfg_set_next_flc(struct scf_c_cfg *d, uint64_t addr);
uint64_t scf_c_cfg_get_next_flc(struct scf_c_cfg *d);

/* extra ptr */
void scf_c_cfg_set_extra_ptr(struct scf_c_cfg *d, uint64_t addr);
uint64_t scf_c_cfg_get_extra_ptr(struct scf_c_cfg *d);

/* pending output ptr */
void scf_c_cfg_set_pending_output_ptr(struct scf_c_cfg *d, uint64_t addr);
uint64_t scf_c_cfg_get_pending_output_ptr(struct scf_c_cfg *d);

/* history ptr */
void scf_c_cfg_set_history_ptr(struct scf_c_cfg *d, uint64_t addr);
uint64_t scf_c_cfg_get_history_ptr(struct scf_c_cfg *d);

/* total in */
void scf_c_cfg_set_total_in(struct scf_c_cfg *d, u32 byte_cnt);
u32 scf_c_cfg_get_total_in(struct scf_c_cfg *d);

/* total out */
void scf_c_cfg_set_total_out(struct scf_c_cfg *d, u32 byte_cnt);
u32 scf_c_cfg_get_total_out(struct scf_c_cfg *d);

void scf_c_cfg_set_adler32(struct scf_c_cfg *d, u32 adler32);
u32 scf_c_cfg_get_adler32(struct scf_c_cfg *d);

void scf_c_cfg_set_pmode(struct scf_c_cfg *d, int mode);
int scf_c_cfg_get_pmode(struct scf_c_cfg *d);

/* gzip,zlib header info */
void scf_c_cfg_set_flg(struct scf_c_cfg *d, u32 flg);
u32 scf_c_cfg_get_flg(struct scf_c_cfg *d);
void scf_c_cfg_set_cm(struct scf_c_cfg *d, u32 cm);
u32 scf_c_cfg_get_cm(struct scf_c_cfg *d);
void scf_c_cfg_set_id2(struct scf_c_cfg *d, u32 id2);
u32 scf_c_cfg_get_id2(struct scf_c_cfg *d);
void scf_c_cfg_set_id1(struct scf_c_cfg *d, u32 id1);
u32 scf_c_cfg_get_id1(struct scf_c_cfg *d);
void scf_c_cfg_set_mtime(struct scf_c_cfg *d, u32 mtime);
u32 scf_c_cfg_get_mtime(struct scf_c_cfg *d);
void scf_c_cfg_set_xlen(struct scf_c_cfg *d, u32 xlen);
u32 scf_c_cfg_get_xlen(struct scf_c_cfg *d);
void scf_c_cfg_set_os(struct scf_c_cfg *d, u32 os);
u32 scf_c_cfg_get_os(struct scf_c_cfg *d);
void scf_c_cfg_set_xfl(struct scf_c_cfg *d, u32 xfl);
u32 scf_c_cfg_get_xfl(struct scf_c_cfg *d);
void scf_c_cfg_set_clen(struct scf_c_cfg *d, u32 clen);
u32 scf_c_cfg_get_clen(struct scf_c_cfg *d);
void scf_c_cfg_set_nlen(struct scf_c_cfg *d, u32 nlen);
u32 scf_c_cfg_get_nlen(struct scf_c_cfg *d);

/*******************************************************************************
 *
 * scf_c_result APIS
 *
 ******************************************************************************/
void scf_c_result_clear(struct scf_c_result *d);
/* total in */
void scf_c_result_set_total_in(struct scf_c_result *d, u32 byte_cnt);
u32 scf_c_result_get_total_in(struct scf_c_result *d);

/* total out */
void scf_c_result_set_total_out(struct scf_c_result *d, u32 byte_cnt);
u32 scf_c_result_get_total_out(struct scf_c_result *d);

/* adler32 */
void scf_c_result_set_adler32(struct scf_c_result *d, u32 adler32);
u32 scf_c_result_get_adler32(struct scf_c_result *d);

void scf_c_result_set_bytes_processed(struct scf_c_result *d, u32 val);
u32 scf_c_result_get_bytes_processed(struct scf_c_result *d);
void scf_c_result_set_pending_output_len(struct scf_c_result *d, u32 val);
u32 scf_c_result_get_pending_output_len(struct scf_c_result *d);


/*******************************************************************************
 *
 * scf_c_result_dbg APIS
 *
 ******************************************************************************/
void scf_c_result_dbg_clear(struct scf_c_result_dbg *d);
/* FFDPC */
uint64_t scf_c_result_dbg_get_ffdpc(struct scf_c_result_dbg *d);
/* BP2 settings */
u32 scf_c_result_dbg_get_bp2ac(struct scf_c_result_dbg *d);
int scf_c_result_dbg_get_bp2ac_bmt(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_bp2ac_bpid(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_bp2ac_pbs(struct scf_c_result_dbg *d);
/* BP1 settings */
u32 scf_c_result_dbg_get_bp1ac(struct scf_c_result_dbg *d);
int scf_c_result_dbg_get_bp1ac_bmt(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_bp1ac_bpid(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_bp1ac_pbs(struct scf_c_result_dbg *d);

/* next_flc */
uint64_t scf_c_result_dbg_get_next_flc(struct scf_c_result_dbg *d);

/* history_len */
u32 scf_c_result_dbg_get_history_len(struct scf_c_result_dbg *d);

/* extra ptr */
uint64_t scf_c_result_dbg_get_extra_ptr(struct scf_c_result_dbg *d);

/* pending output ptr */
uint64_t scf_c_result_dbg_get_pending_output_ptr(struct scf_c_result_dbg *d);

/* history ptr */
uint64_t scf_c_result_dbg_get_history_ptr(struct scf_c_result_dbg *d);

/* total in */
u32 scf_c_result_dbg_get_total_in(struct scf_c_result_dbg *d);

/* total out */
u32 scf_c_result_dbg_get_total_out(struct scf_c_result_dbg *d);

/* adler32 */
u32 scf_c_result_dbg_get_adler32(struct scf_c_result_dbg *d);

/* b64_residue */
u32 scf_c_result_dbg_get_b64_residue(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_b64_residue_len(struct scf_c_result_dbg *d);

/* output phase */
u32 scf_c_result_dbg_get_output_phase(struct scf_c_result_dbg *d);

/* gzip,zlib header info */
u32 scf_c_result_dbg_get_flg(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_cm(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_id2(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_id1(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_mtime(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_xlen(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_os(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_xfl(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_clen(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_nlen(struct scf_c_result_dbg *d);

/* pending output data */
u32 scf_c_result_dbg_get_pending_working_idx(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_pending_working_len(struct scf_c_result_dbg *d);

/* residue info */
u32 scf_c_result_dbg_get_residue_data(struct scf_c_result_dbg *d);
u32 scf_c_result_dbg_get_residue_byte_count(struct scf_c_result_dbg *d);

/* header remaining */
u32 scf_c_result_dbg_get_header_remaining(struct scf_c_result_dbg *d);

int scf_c_result_dbg_get_mcplt(struct scf_c_result_dbg *d);
int scf_c_result_dbg_get_terminated(struct scf_c_result_dbg *d);
int scf_c_result_dbg_get_suspended(struct scf_c_result_dbg *d);
int scf_c_result_dbg_get_pmode(struct scf_c_result_dbg *d);

/* crc16 */
u32 scf_c_result_dbg_get_crc16(struct scf_c_result_dbg *d);

#endif
