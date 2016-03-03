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

#ifndef __DCE_FD_FRC_H
#define __DCE_FD_FRC_H

#include "dce-fd.h"
#include "dce-fd-frc.h"

enum dce_cmd {
	DCE_CMD_PROCESS			= 0,
	DCE_CMD_FQID_SCOPE_FLUSH	= 3,
	DCE_CMD_CTX_INVALIDATE		= 4,
	DCE_CMD_ICID_SCOPE_FLUSH	= 6,
	DCE_CMD_NOP			= 7
};

enum dce_z_flush {
	DCE_Z_FLUSH_NO_FLUSH		= 0,
	DCE_Z_FLUSH_PARTIAL_FLUSH	= 1,
	DCE_Z_FLUSH_SYNC_FLUSH		= 2,
	DCE_Z_FLUSH_FULL_FLUSH		= 3,
	DCE_Z_FLUSH_FINISH		= 4,
	DCE_Z_FLUSH_BLOCK		= 5,
	DCE_Z_FLUSH_TREES		= 6
};

enum dce_comp_fmt {
	DCE_CF_DEFLATE	= 0,
	DCE_CF_ZLIB	= 1,
	DCE_CF_GZIP	= 2
};

enum dce_comp_effort {
	DCE_CE_NONE			= 0,
	DCE_CE_STATIC_HUFF_STRMATCH	= 1,
	DCE_CE_HUFF_ONLY		= 2,
	DCE_CE_BEST_POSSIBLE		= 3,
};

enum dce_scus {
	DCE_SCUS_NORMAL_MODE	= 0,
	DCE_SCUS_UPDATE		= 1,
	DCE_SCUS_UPDATE_DEBUG	= 2
};

enum dce_status {
	FULLY_PROCESSED				= 0x00,
	STREAM_END				= 0x01,
	INPUT_STARVED				= 0x10,
	MEMBER_END_SUSPEND			= 0x11,
	Z_BLOCK_SUSPEND				= 0x12,
	OUTPUT_BLOCKED_SUSPEND			= 0x14,
	ACQUIRE_DATA_BUFFER_DENIED_SUSPEND	= 0x15,
	ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND	= 0x16,
	OLL_REACHED_SUSPEND			= 0x17,
	OUTPUT_BLOCKED_DISCARD			= 0x24,
	ACQUIRE_DATA_BUFFER_DENIED_DISCARD	= 0x25,
	ACQUIRE_TABLE_BUFFER_DENIED_DISCARD	= 0x26,
	OLL_REACHED_DISCARD			= 0x27,
	HCL_REACHED_DISCARD			= 0x28,
	HCL_RELEASE_ABORTED			= 0x2F,
	SKIPPED					= 0x30,
	PREVIOUS_FLOW_TERMINATION		= 0x31,
	SUSPENDED_FLOW_TERMINATION		= 0x32,
	INVALID_FRAME_LIST			= 0x40,
	INVALID_FRC				= 0x41,
	UNSUPPORTED_FRAME			= 0x42,
	FRAME_TOO_SHORT				= 0x44,
	ZLIB_INCOMPLETE_HEADER			= 0x50,
	ZLIB_HEADER_ERROR			= 0x51,
	ZLIB_NEED_DICTIONARY_ERROR		= 0x52,
	GZIP_INCOMPLETE_HEADER			= 0x60,
	GZIP_HEADER_ERROR			= 0x61,
	DEFLATE_INVALID_BLOCK_TYPE		= 0x70,
	DEFLATE_INVALID_BLOCK_LENGTHS		= 0x71,
	DEFLATE_TOO_MANY_LEN_OR_DIST_SYM	= 0x80,
	DEFLATE_INVALID_CODE_LENGTHS_SET	= 0x81,
	DEFLATE_INVALID_BIT_LENGTH_REPEAT	= 0x82,
	DEFLATE_INVALID_LITERAL_LENGTHS_SET	= 0x83,
	DEFLATE_INVALID_DISTANCES_SET		= 0x84,
	DEFLATE_INVALID_LITERAL_LENGTH_CODE	= 0x85,
	DEFLATE_INVALID_DISTANCE_CODE		= 0x86,
	DEFLATE_INVALID_DISTANCE_TOO_FAR_BACK	= 0x87,
	DEFLATE_INCORRECT_DATA_CHECK		= 0x88,
	DEFLATE_INCORRECT_LENGTH_CHECK		= 0x89,
	DEFLATE_INVALID_CODE			= 0x8A,
	CXM_2BIT_ECC_ERROR			= 0xB0,
	CBM_2BIT_ECC_ERROR			= 0xB1,
	DHM_2BIT_ECC_ERROR			= 0xB2,
	INVALID_BASE64_CODE			= 0xC0,
	INVALID_BASE64_PADDING			= 0xC1,
	SCF_SYSTEM_MEM_READ_ERROR		= 0xD5,
	PENDING_OUTPUT_SYSTEM_MEM_READ_ERROR	= 0xD6,
	HISTORY_WINDOW_SYSTEM_MEM_READ_ERROR	= 0xD7,
	CTX_DATA_SYSTEM_MEM_READ_ERROR		= 0xD8,
	FRAME_DATA_SYSTEM_READ_ERROR		= 0xD9,
	INPUT_FRAME_TBL_SYSTEM_READ_ERROR	= 0xDA,
	OUTPUT_FRAME_TBL_SYSTEM_READ_ERROR	= 0xDB,
	SCF_SYSTEM_MEM_WRITE_ERROR		= 0xE5,
	PENDING_OUTPUT_SYSTEM_MEM_WRITE_ERROR	= 0xE6,
	HISTORY_WINDOW_SYSTEM_MEM_WRITE_ERROR	= 0xE7,
	CTX_DATA_SYSTEM_MEM_WRITE_ERROR		= 0xE8,
	FRAME_DATA_SYSTEM_MEM_WRITE_ERROR	= 0xE9,
	FRAME_TBL_SYSTEM_MEM_WRITE_ERROR	= 0xEA
};

void fd_frc_set_cmd(struct fd_attr *d, enum dce_cmd cmd);
enum dce_cmd fd_frc_get_cmd(struct fd_attr *d);

void fd_frc_set_nop_token(struct fd_attr *d, u32 token);
u32 fd_frc_get_nop_token(struct fd_attr *d);

void fd_frc_set_icid_scope_token(struct fd_attr *d, u32 token);
u32 fd_frc_get_icid_scope_token(struct fd_attr *d);

void fd_frc_set_cic_token(struct fd_attr *d, u32 token);
u32 fd_frc_get_cic_token(struct fd_attr *d);

void fd_frc_set_fqflush_token(struct fd_attr *d, u32 token);
u32 fd_frc_get_fqflush_token(struct fd_attr *d);

enum dce_status fd_frc_get_status(struct fd_attr *d);

void fd_frc_set_scus(struct fd_attr *d, enum dce_scus scus);
enum dce_scus fd_frc_get_scus(struct fd_attr *d);

void fd_frc_set_usdc(struct fd_attr *d, int enable);
int fd_frc_get_usdc(struct fd_attr *d);

void fd_frc_set_uspc(struct fd_attr *d, int enable);
int fd_frc_get_uspc(struct fd_attr *d);

void fd_frc_set_uhc(struct fd_attr *d, int enable);
int fd_frc_get_uhc(struct fd_attr *d);

void fd_frc_set_ce(struct fd_attr *d, enum dce_comp_effort ce);
enum dce_comp_effort fd_frc_get_ce(struct fd_attr *d);

void fd_frc_set_cf(struct fd_attr *d, enum dce_comp_fmt cf);
enum dce_comp_fmt fd_frc_get_cf(struct fd_attr *d);

void fd_frc_set_b64(struct fd_attr *d, int enable);
int fd_frc_get_b64(struct fd_attr *d);

void fd_frc_set_rb(struct fd_attr *d, int enable);
int fd_frc_get_rb(struct fd_attr *d);

void fd_frc_set_initial(struct fd_attr *d, int enable);
int fd_frc_get_initial(struct fd_attr *d);

void fd_frc_set_recycle(struct fd_attr *d, int enable);
int fd_frc_get_recycle(struct fd_attr *d);

void fd_frc_set_scrf(struct fd_attr *d, int enable);
int fd_frc_get_scrf(struct fd_attr *d);

void fd_frc_set_z_flush(struct fd_attr *d, enum dce_z_flush flush);
enum dce_z_flush fd_frc_get_z_flush(struct fd_attr *d);

void fd_frc_set_sf(struct fd_attr *d, int enable);
int fd_frc_get_sf(struct fd_attr *d);

void fd_frc_set_se(struct fd_attr *d, int enable);
int fd_frc_get_se(struct fd_attr *d);
#endif
