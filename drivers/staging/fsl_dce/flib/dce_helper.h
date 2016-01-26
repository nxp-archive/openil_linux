/*
 * Copyright 2013 Freescale Semiconductor, Inc.
 */

#ifndef FL_DCE_HELPER_H
#define FL_DCE_HELPER_H

#include "dce_defs.h"

/**
 * get_dce_status - returns lowest 8 bits
 * @fd_status:  frame descriptor 32bit field
 */
static inline enum dce_status fsl_dce_get_status(u32 fd_status)
{
	return (enum dce_status)
		GET_BF32(fd_status, DCE_PROCESS_STATUS);
};

/* stateful dma memory minimum size and alignment requirements */

/* compression or decompression */
#define PENDING_OUTPUT_MIN_SIZE		8192
#define PENDING_OUTPUT_ALIGN		64 /* not required, but optimal */

/* compression only */
#define SCR_COMPRESSION_MIN_SIZE	64
#define SCR_COMPRESSION_ALIGN		64
#define HISTORY_COMPRESSION_MIN_SIZE	4096
#define HISTORY_COMPRESSION_ALIGN	64

/* decompression only */
#define SCR_DECOMPRESSION_MIN_SIZE	128
#define SCR_DECOMPRESSION_ALIGN		64
#define HISTORY_DECOMPRESSION_MIN_SIZE	32768
#define HISTORY_DECOMPRESSION_ALIGN	64
#define DECOMPRESSION_CTX_MIN_SIZE	256
#define DECOMPRESSION_CTX_ALIGN		64 /* not required, but optimal */

/* Various Stream Context Frame Helpers */

/**
 * fsl_dce_statefull_decompression_dma - dma memory required for statefull
 *					decompression
 *
 * @scf: the stream context frame object to set the corresponding dma memory
 *	pointers. This need to be subsequently sent using a process command
 *	while setting the USPC.
 * @pending_output: must be minumum of PENDING_OUTPUT_MIN_SIZE, and optimal
 *	if alignment is PENDING_OUTPUT_ALIGN
 * @history: minimum size is HISTORY_DECOMPRESSION_MIN_SIZE with alignment of
 *	HISTORY_DECOMPRESSION_ALIGN
 * @decomp_ctxt: must be minimum size of DECOMPRESSION_CTX_MIN_SIZE, with
 *	optimal alignment of DECOMPRESSION_CTX_ALIGN
 */
static inline void fsl_dce_statefull_decompression_dma(struct scf_64b *scf,
	dma_addr_t pending_output, dma_addr_t history, dma_addr_t decomp_ctxt)
{
	set_pending_output_ptr(scf, pending_output);
	set_history_ptr(scf, history);
	set_decomp_ctxt_ptr(scf, decomp_ctxt);
}

/**
 * fsl_dce_statefull_compression_dma - dma memory required for statefull
 *					compression
 *
 * @scf: the stream context frame object to set the corresponding dma memory
 *	pointers. This will subsequently be sent using a process command while
 *	setting the USPC.
 * @pending_output: must be minumum of PENDING_OUTPUT_MIN_SIZE, and optimal
 *	if alignment is PENDING_OUTPUT_ALIGN
 * history: minimum size is HISTORY_COMPRESSION_MIN_SIZE with alignment of
 *	HISTORY_COMPRESSION_ALIGN
 */
static inline void fsl_dce_statefull_compression_dma(struct scf_64b *scf,
	dma_addr_t pending_output, dma_addr_t history)
{
	set_pending_output_ptr(scf, pending_output);
	set_history_ptr(scf, history);
}

/* DCE input command helpers */
static inline void fsl_dce_cmd_set_process(u32 *cmd)
{
	SET_BF32_TK(*cmd, DCE_CMD, PROCESS);
}

static inline void fsl_dce_cmd_set_ctx_invalidate(u32 *cmd)
{
	SET_BF32_TK(*cmd, DCE_CMD, CTX_INVALIDATE);
}

static inline void fsl_dce_cmd_set_nop(u32 *cmd)
{
	SET_BF32_TK(*cmd, DCE_CMD, NOP);
}

/* DCE process command helpers */
static inline void fsl_dce_cmd_set_compression_effort_none(u32 *cmd)
{
	SET_BF32_TK(*cmd, DCE_PROCESS_CE, NONE);
}
static inline void fsl_dce_cmd_set_compression_effort_statichuff(u32 *cmd)

{
	SET_BF32_TK(*cmd, DCE_PROCESS_CE, STATIC_HUFF_STRMATCH);
}

#endif /* FL_DCE_HELPER_H */

