/*
 * Copyright 2013 Freescale Semiconductor, Inc.
 */

#ifndef FL_DCE_DEFS_H
#define FL_DCE_DEFS_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stdbool.h>
#endif

#include "bitfield_macros.h"

/*
 * Some interfaces depend on the revision of the DCE HW block. An external
 * dependency has been added which requires this external variable to be
 * set accordingly. If the variable is not set, the interfaces will behave
 * as if the revision is DCE_DEFAULT_REV.
 */
extern u16 dce_ip_rev;
#define DCE_REV10	0x0100
#define DCE_REV11	0x0101
#define DCE_DEFAULT_REV	DCE_REV10

/*
 * QMan defines the dedicated channels serviced by the DCE engine. The first
 * channel is serviced by compression engine while the second channel is
 * is serviced by the decompression engine.
 */
#define DCE_COMPRESSION_CHANNEL_OFFSET		0
#define DCE_DECOMPRESSION_CHANNEL_OFFSET	1

/**
 * struct dce_context_a - context_a field of the qm_fqd for rx frame queue. The
 *	rx frame queue is in the sw portal to dce hw direction.
 *
 * @d64: contains mask of following values:
 *
 * TSIZE: size of BMan buffers used to create s/g tables, each table entry
 *	being 16 bytes in size.
 * DEXP: Specifies the exponent part of BMan buffer size used to output data
 *	using DBPID. All values (0x0 to 0xF) are valid. A coding of 0x0 is
 *	treated as 0x10, so exponent values 1 to 16 are possible.
 * DMANT: Specifies the mantissa part of BMan buffer size used to output data
 *	using DBPID. All values (0x0 to 0xF) are valid. A coding of 0x0 is
 *	treated as 0x10, so mantissa values 1 to 16 are possible.
 * TBPID: Indicates which BMan buffer pool is to be used to create
 *	scatter/gather tables. Typically this will indicate a pool of buffers
 *	that are smaller in size than the buffers used to store Frame data.
 * SCRP: The upper bits of a 40-bit memory pointer to the SCR
 *	The lower bits are presumed to be 0 as the record must be device
 *	virtual address aligned on a 64B address boundary in system memory.
 */
struct dce_context_a {
	u64 d64;
/* TSIZE */
#define DCE_CONTEXT_A_TSIZE_SHIFT	60
#define DCE_CONTEXT_A_TSIZE_MASK	(0x7ULL << DCE_CONTEXT_A_TSIZE_SHIFT)

/* DEXP */
#define DCE_CONTEXT_A_DEXP_SHIFT	56
#define DCE_CONTEXT_A_DEXP_MASK		(0xfULL << DCE_CONTEXT_A_DEXP_SHIFT)

/* DMANT*/
#define DCE_CONTEXT_A_DMANT_SHIFT	52
#define DCE_CONTEXT_A_DMANT_MASK	(0xfULL << DCE_CONTEXT_A_DMANT_SHIFT)

/* TBPID */
#define DCE_CONTEXT_A_TBPID_SHIFT	40
#define DCE_CONTEXT_A_TBPID_MASK	(0xffULL << DCE_CONTEXT_A_TBPID_SHIFT)

/* SCRP */
#define DCE_CONTEXT_A_SCRP_SHIFT	6
#define DCE_CONTEXT_A_SCRP_MASK (0x3ffffffffULL << DCE_CONTEXT_A_SCRP_SHIFT)
};

/**
 * dce_context_a_set_scrp - Set SCRP in context_a field
 *
 * @ctxa: a dce_context_a structure
 * @val: Value to set the scrp field to.
 */
static inline void dce_context_a_set_scrp(struct dce_context_a *ctx_a,
						u64 val)
{
	/* lower 6 bits expected to be zero, since 64 byte aligned */
	SET_BF64(ctx_a->d64, DCE_CONTEXT_A_SCRP,
		(val >> DCE_CONTEXT_A_SCRP_SHIFT));
}

/**
 * dce_context_a_get_scrp - Get SCRP in context_a field
 *
 * @ctxa: a dce_context_a structure
 */
static inline u64 dce_context_a_get_scrp(struct dce_context_a *ctx_a)
{
	/* lower 6 bits expected to be zero, since 64 byte aligned */
	return GET_BF64(ctx_a->d64, DCE_CONTEXT_A_SCRP) <<
		DCE_CONTEXT_A_SCRP_SHIFT;
}

/**
 * struct dce_context_b - context_b field of the qm_fqd for tx frame queue.
 *	contains data buffer pool id and rx fq id. The tx frame queue is in the
 *	dce hw -> sw portal direction.
 *
 * @d32: contains mask of following values:
 *
 * DBPID: Indicates which BMan pool is to be used to create data buffers
 *	(not scatter/gather tables) in output Frames.
 * FQID: DCE output Frames for this Frame Queue pair (Flow) are enqueued on
 *	this FQID
 */
struct dce_context_b {
	u32 d32;
/* DBPID */
#define DCE_CONTEXT_B_DBPID_SHIFT	24
#define DCE_CONTEXT_B_DBPID_MASK	(0xffUL << DCE_CONTEXT_B_DBPID_SHIFT)

/* FQID */
#define DCE_CONTEXT_B_FQID_SHIFT	0
#define DCE_CONTEXT_B_FQID_MASK		(0xffffffUL << DCE_CONTEXT_B_FQID_SHIFT)
};

/**
 * struct dce_cmd - 32-bit frame descritor "cmd/status" field, sent to DCE
 *
 * @d32: mask of command and associated parameters. The bit fields depend
 *	 on the value of the CMD.
 *
 *	The DCE_CMD_*** field identifies the command type.
 *		@DCE_CMD_PROCESS: invokes DCE's misison mode operation. It
 *			indicates to DCE hardware that the provided Frame is to
 *			be processed according to the mode of its Frame Queue
 *			channel (compression vs decompression) and the Frame's
 *			associated Stream Context Record, and/or a Stream
 *			Configuration Frame.
 *		@DCE_CMD_CTX_INVALIDATE: provides a means to invalidate a cached
 *			copy of a Stream Context Record in the DCE hardware.
 *			Only application on stateful stream.
 *		@DCE_CMD_NOP: a frame with this command travel through the DCE's
 *			pipeline without causing any system memory accesses or
 *			other side effects.
 *
 * Additiona fields depend on value of DCE_CMD_***
 * -----------------------------------------
 *  DCE_CMD_NOP		DCE_NOP_TOKEN
 *				The token is not processed by the DCE and is
 *				echoed back in the returned frame.
 *
 *  DCE_CMD_CTX_INVALIDATE	DCE_CIC_TOKEN
 *					The token is not processed by the DCE
 *					and is echoed back in the returned
 *					Frame.
 *
 *  DCE_CMD_PROCESS	DCE_PROCESS_OO_***
 *				Coded value specifying the number of unused
 *				bytes to leave at the beginning of the first
 *				buffer of the output Frame, if it is being
 *				created out of BMan buffers. Note that software
 *				must ensure that non-zero offset values remain
 *				within the size of BMan buffers being used for
 *				the flow. A value that is greater than or equal
 *				to the buffer size will result in an Output
 *				Offset Too Large exception.
 *			DCE_PROCESS_Z_***
 *				Support for zlib flush semantics
 *
 *				@DCE_PROCESS_Z_NO_FLUSH: Normal value for flush
 *				@DCE_PROCESS_Z_PARTIAL_FLUSH: Pending output is
 *					flushed, output not aligned.
 *				@DCE_PROCESS_Z_SYNC_FLUSH: Pending output is
 *					flushed, output is aligned.
 *				@DCE_PROCESS_Z_FULL_FLUSH: All output is flushed
 *					and state reset.
 *				@DCE_PROCESS_Z_FINISH: All pending input is
 *					processed and all output is flushed
 *				@DCE_PROCESS_Z_BLOCK: A compressed block is
 *					completed and emitted, as with
 *					DCE_PROCESS_Z_SYNC_FLUSH, but the output
 *					is not necessarily aligned on a byte
 *					boundary, and up to 7 bits of the
 *					current block are held to be written as
 *					the next byte when the next DEFLATE
 *					block is completed
 *				@DCE_PROCESS_Z_TREES: For decompression, the
 *					DCE_PROCESS_Z_TREES option behaves as
 *					DCE_PROCESS_Z_BLOCK does, but also
 *					returns after the end of each DEFLATE
 *					block header before any data in the
 *					block itself is	decoded, allowing the
 *					caller to determine the length of the
 *					DEFLATE	block header for later use in
 *					random	access within a DEFLATE block.
 *			DCE_PROCESS_SCRF
 *				When set, forces DCE to flush the updated Stream
 *				Context Record to system memory once the Frame
 *				is processed. DCE also invalidates its internal
 *				copy of the Stream Context Record so that it
 *				must be read from system memory before
 *				processing a subsequent Frame on the same
 *				Stream. Note that this is independent of the
 *				Frame data flushing behavior that is controlledi
 *				by the DCE_Z_FLUSH field.
 *			DCE_PROCESS_RECYCLED
 *				Indicates that this Frame is being recycled to
 *				DCE following a previous Output Blocked Suspend
 *				or Acquire Data Buffer Denied Suspend exception.
 *			DCE_PROCESS_INITIAL
 *				When set, indicates that this Frame is
 *				considered to be the first, and possibly only,
 *				Frame of data in the Stream. DCE will disregard
 *				any stale Frame data pointers and residue data
 *				values in the Stream Context Record and
 *				initialize the Stream Context Record prior to
 *				processing the Frame(1). The following Stream
 *				Context Record fields are initialized as
 *				indicated:
 *					TOTAL_IN, TOTAL_OUT, ADLER32 zeroed (2)
 *					XO, NO, and CO zeroed
 *					XLEN, NLEN, and CLEN zeroed
 *						(decompression Flows only)
 *					PENDING_OUTPUT_LEN zeroed
 *					HISTORY_LEN zeroed
 *					RBC zeroed
 *					CRC16 zeroed
 *					HUFFMAN_RBC zeroed
 *					B64_RESIDUE_LEN zeroed
 *					HEADER_REMAINING zeroed
 *				Note that a set I bit does not have any effect
 *				on the Stream Context Record if the Flow is
 *				suspended. A frame received with I=1 on a
 *				suspended flow will either be skipped or
 *				treated as a recycled frame depending on the
 *				value of the Frame’s R bit. On stateless Flows
 *				this flag is ignored (DCE behaves as though I=1
 *				for every Frame).
 *
 *				(1) Stream Context Record initialization does
 *				not happen when an initial (I=1) Frame is
 *				recycled (R=1) due to a previous exception, DCE
 *				will continue processing of the Frame based on
 *				existing context as it would for any recycled
 *				Frame.  Further, an Initial Frame received on a
 *				suspended flow that does not have its recycle
 *				bit set (R=0) will be skipped (i.e.  an I=1
 *				Frame does not clear the SUSP bit).
 *
 *				(2) Unless DCE_PROCESS_USDC is also set, in
 *				which case the DCE_PROCESS_USDC function takes
 *				precedence over the set DCE_PROCESS_INITIAL bit.
 *			DCE_PROCESS_RB
 *				Specifies that the input Frame buffers are to be
 *				released to BMan once their data bytes have been
 *				fully processed.
 *			DCE_PROCESS_B64
 *				Set to indicate that data in this Frame is to be
 *				Base64 encoded following compression, or Base64
 *				decoded prior to decompression.
 *			DCE_PROCESS_CF_***
 *				Specifies the data format to be used for
 *				compressing this Frame (compression Flow) or the
 *				format of the compressed data present in this
 *				Frame (decompression Flow).
 *				This field must remain consistent (keep the same
 *				value) across multiple Frames (chunks) of a
 *				single file within a stateful Flow.
 *
 *				@DCE_DEFLATE: Format is DEFLATE as defined in
 *					RFC 1951
 *				@DCE_ZLIB: Format is ZLIB as defined in RFC 1950
 *				@DCE_GZIP: Format is GXIP as defined in RFC 1952
 *			DCE_PROCESS_CE_***
 *				Specifies the type of compression to be
 *				performed on this Stream. This field is ignored
 *				on decompress Flows.
 *				This field must remain consistent (keep the same
 *				value) across multiple Frames (chunks) of a
 *				single file within a stateful Flow.
 *
 *				@DCE_CE_NONE: No compression
 *				@DCE_CE_STATIC_HUFF_STRMATCH: Static Huffman
 *					coding and string matching only
 *				@DCE_CE_HUFF_ONLY: Huffman only (static or
 *					dynamic, but no string matching).
 *				@DCE_CE_BEST_POSSIBLE: Best possible compression
 *					(static or dynamic Huffman coding may
 *					result).
 *			DCE_PROCESS_UHC
 *				Update Header Context
 *				On stateful Flows, instructs the DCE to update
 *				the Flow’s Stream Context Record’s protocol
 *				header fields with the values found in the
 *				dequeued Frame’s Stream Configuration Frame.
 *				DCE will update the following Stream Context
 *				Record header fields:
 *					ID1, ID2
 *					CM
 *					FLG
 *					MTIME
 *					XFL
 *					OS
 *					XLEN
 *					NLEN
 *					CLEN
 *					EXTRA_LIMIT and EXTRA_PTR
 *				Some or all of these context fields may not be
 *				used depending on the DCE_PROCESS_CF field
 *				setting in the individual Frames that arrive on
 *				the Flow, but all are updated.  On stateless
 *				Flows, this flag is ignored and the appropriate
 *				values from the Stream Configuration Frame are
 *				used unconditionally according to the
 *				DCE_PROCESS_CF field.
 *			DCE_PROCESS_USPC
 *				Update Stream Processing Context. Instructs the
 *				DCE to update the following Stream Context
 *				Record fields with the values found in the
 *				Stream Configuration Frame, or zero them as
 *				indicated:
 *					XO, NO, and CO zeroed
 *					PENDING_OUTPUT_PTR updated
 *					PENDING_OUTPUT_LEN zeroed
 *					HISTORY_PTR updated, HISTORY_LEN zeroed
 *					PMODE updated
 *					SUSP zeroed
 *					RBC zeroed
 *					DECOMP_CTXT_PTR updated
 *					CRC16 zeroed
 *					HUFFMAN_RBC zeroed
 *					B64_RESIDUE_LEN zeroed
 *					HEADER_REMAINING zeroed.
 *			DCE_PROCESS_USDC
 *				Update Stream Data Context
 *				Instructs the DCE to update the following fields
 *				in the Stream Context Record with the value
 *				found in the Stream Configuration Frame prior to
 *				processing the dequeued Frame:
 *					TOTAL_IN
 *					TOTAL_OUT
 *					ADLER32
 *				This bit is included to maintain full zlib
 *				compatibility such that Software is able to
 *				update/modify the incremental total_in,
 *				total_out, and adler32 values (in the z_stream
 *				struct) between inflate() and deflate() calls.
 *				This bit should normally be left unset.
 *				Software should not normally need to modify the
 *				incremental values in these fields between
 *				Frames of a larger entity on a stateful Flow.
 *			DCE_PROCESS_SCUS_***
 *				Stream Configuration Update Select
 *				This field specifies how the DCE performs
 *				updates (writes) to the output Stream
 *				Configuration Frame after processing the
 *				dequeued Frame. SCUS settings only apply when
 *				compound Frames containing a valid (non-null)
 *				Stream Configuration Frame member are used.
 *				The field has no effect for simple Frames or
 *				compound Frames in which the Stream
 *				Configuration Frame member is null.
 *
 *				@DCE_PROCESS_SCUS_NORMAL_MODE:
 *					Stream Context Recor updated, Stream
 *					Configuration Frame not	updated except
 *					in cases of Output Blocked Suspend or
 *					Acquire Data Buffer Denied Suspend
 *					exceptions3. This is the expected
 *					mission mode setting.
 *				@DCE_PROCESS_SCUS_UPDATE:
 *					Stream Context Record updated, Stream
 *					Configuration Frame updated partially.
 *					Note that captured header information
 *					may be partial until the entire header
 *					has been processed.
 *				@DCE_SCUS_UPDATE_DEBUG:
 *					Stream Context Record updated, Stream
 *					Configuration Frame updated with a
 *					Stream Context Record snapshot. This
 *					setting exposes	Stream Context Record
 *					updates by shadowing them in the Stream
 *					Configuration Frame, enabling debug.

 *			DCE_PROCESS_STATUS
 *				This is of type enum dce_status. This value
 *				is set on the output fd received from the DCE.
 */
struct dce_cmd {
	u32 d32;
/* Common to all commands */
#define DCE_CMD_SHIFT		29
#define DCE_CMD_MASK		(0x7UL << DCE_CMD_SHIFT)
/* CMD Tokens */
#define DCE_CMD_PROCESS		0x0UL
#define DCE_CMD_CTX_INVALIDATE	0x4UL
#define DCE_CMD_NOP		0x7UL

/* NOP Input command */
#define DCE_NOP_TOKEN_SHIFT	0
#define DCE_NOP_TOKEN_MASK	(0x1fffffffUL << DCE_NOP_TOKEN_SHIFT)

/* Context Invalidate Command Input command */
#define DCE_CIC_TOKEN_SHIFT	0
#define DCE_CIC_TOKEN_MASK	(0x1fffffffUL << DCE_CIC_TOKEN_SHIFT)

/* Process Input command */
/* Output Offset */
#define DCE_PROCESS_OO_SHIFT		26
#define DCE_PROCESS_OO_MASK		(0x7UL << DCE_PROCESS_OO_SHIFT)
/* Output Offset Tokens */
#define DCE_PROCESS_OO_NONE_LONG	0x0UL
#define DCE_PROCESS_OO_32B		0x1UL
#define DCE_PROCESS_OO_64B		0x2UL
#define DCE_PROCESS_OO_128B		0x3UL
#define DCE_PROCESS_OO_256B		0x4uL
#define DCE_PROCESS_OO_512B		0x5UL
#define DCE_PROCESS_OO_1024B		0x6UL
#define DCE_PROCESS_OO_NON_SHORT	0x7UL
/* Z_FLUSH */
#define DCE_PROCESS_Z_FLUSH_SHIFT	23
#define DCE_PROCESS_Z_FLUSH_MASK	(0x7UL << DCE_PROCESS_Z_FLUSH_SHIFT)
/* Z_FLUSH Tokens */
#define DCE_PROCESS_Z_FLUSH_NO_FLUSH		0x0UL
#define DCE_PROCESS_Z_FLUSH_PARTIAL_FLUSH	0x1UL
#define DCE_PROCESS_Z_FLUSH_SYNC_FLUSH		0x2UL
#define DCE_PROCESS_Z_FLUSH_FULL_FLUSH		0x3UL
#define DCE_PROCESS_Z_FLUSH_FINISH		0x4UL
#define DCE_PROCESS_Z_FLUSH_BLOCK		0x5UL
#define DCE_PROCESS_Z_FLUSH_TREES		0x6UL

#define DCE_PROCESS_SCRF_SHIFT		22
#define DCE_PROCESS_SCRF_MASK		(0x1UL << DCE_PROCESS_SCRF_SHIFT)
/* SCRF Tokens */
#define DCE_PROCESS_SCRF_SET		0x1UL
#define DCE_PROCESS_SCRF_CLEAR		0x0UL

#define DCE_PROCESS_RECYCLED_SHIFT	21
#define DCE_PROCESS_RECYCLED_MASK	(0x1UL << DCE_PROCESS_RECYCLED_SHIFT)
/* Recycle Tokens */
#define DCE_PROCESS_RECYCLED_SET	0x1UL
#define DCE_PROCESS_RECYCLED_CLEAR	0x0UL

#define DCE_PROCESS_INITIAL_SHIFT	20
#define DCE_PROCESS_INITIAL_MASK	(0x1UL << DCE_PROCESS_INITIAL_SHIFT)
/* Initial Tokens */
#define DCE_PROCESS_INITIAL_SET		0x1UL
#define DCE_PROCESS_INITIAL_CLEAR	0x0UL

#define DCE_PROCESS_RB_SHIFT	19
#define DCE_PROCESS_RB_MASK	(0x1UL << DCE_PROCESS_RB_SHIFT)
/* Release Buffers Tokens */
#define DCE_PROCESS_RB_YES	0x1UL
#define DCE_PROCESS_RB_NO	0x0UL

#define DCE_PROCESS_B64_SHIFT	18
#define DCE_PROCESS_B64_MASK	(0x1UL << DCE_PROCESS_B64_SHIFT)
/* Is Base64 encoding Tokens */
#define DCE_PROCESS_B64_YES	0x1UL
#define DCE_PROCESS_B64_NO	0x0UL

/* Compression Format */
#define DCE_PROCESS_CF_SHIFT		16
#define DCE_PROCESS_CF_MASK		(0x3UL << DCE_PROCESS_CF_SHIFT)
/* CF Tokesn */
#define DCE_PROCESS_CF_DEFLATE		0x0UL
#define DCE_PROCESS_CF_ZLIB		0x1UL
#define DCE_PROCESS_CF_GZIP		0x2UL

/* Compression Effort */
#define DCE_PROCESS_CE_SHIFT			13
#define DCE_PROCESS_CE_MASK			(0x3UL << DCE_PROCESS_CE_SHIFT)
/* CE Tokens */
#define DCE_PROCESS_CE_NONE			0x0UL
#define DCE_PROCESS_CE_STATIC_HUFF_STRMATCH	0x1UL
#define DCE_PROCESS_CE_HUFF_ONLY		0x2UL
#define DCE_PROCESS_CE_BEST_POSSIBLE		0x3UL

/* UHC, USPC, and USDC are ignored for stateless flows */
#define DCE_PROCESS_UHC_SHIFT	12
#define DCE_PROCESS_UHC_MASK	(0x1UL << DCE_PROCESS_UHC_SHIFT)
/* Update Header Context Request Tokens */
#define DCE_PROCESS_UHC_YES	0x1UL
#define DCE_PROCESS_UHC_NO	0x0UL

#define DCE_PROCESS_USPC_SHIFT	11
#define DCE_PROCESS_USPC_MASK	(0x1UL << DCE_PROCESS_USPC_SHIFT)
/* Update Stream Processing Context Request Tokens */
#define DCE_PROCESS_USPC_YES	0x1UL
#define DCE_PROCESS_USPC_NO	0x0UL

#define DCE_PROCESS_USDC_SHIFT	10
#define DCE_PROCESS_USDC_MASK	(0x1UL << DCE_PROCESS_USDC_SHIFT)
/* Update Stream Data Context Request Tokens */
#define DCE_PROCESS_USDC_YES	0x1UL
#define DCE_PROCESS_USDC_NO	0x0UL

/* Stream Configuration Update Select */
#define DCE_PROCESS_SCUS_SHIFT		8
#define DCE_PROCESS_SCUS_MASK		(0x3UL << DCE_PROCESS_SCUS_SHIFT)
/* SCUS Tokens */
#define DCE_PROCESS_SCUS_NORMAL_MODE	0x0UL
#define DCE_PROCESS_SCUS_UPDATE		0x1UL
#define DCE_PROCESS_SCUS_UPDATE_DEBUG	0x2UL

/* On output there is a Command Status */
#define DCE_PROCESS_STATUS_SHIFT	0
#define DCE_PROCESS_STATUS_MASK		(0xffUL << DCE_PROCESS_STATUS_SHIFT)
};

/* Various dma memory size and alignment requirements */
#define DCE_SCR_ALIGN			64
#define DCE_COMP_HISTORY_ALIGN		64
#define DCE_COMP_HISTORY_SIZE		4096
#define DCE_DECOMP_HISTORY_ALIGN	64
#define DCE_DECOMP_HISTORY_SIZE		32768
#define DCE_PENDING_OUTPUT_SIZE		8256 /* 8202 bytes for compression */
#define DCE_PENDING_OUTPUT_ALIGN	64
#define DCE_DECOMP_CTXT_ALIGN		64
#define DCE_DECOMP_CTXT_SIZE		256

/* 64 bytes Stream Context Frame, must be 64 byte aligned */
struct scf_64b {
	union {
		u8  opaque_data8[64];
		u16 opaque_data16[32];
		u32 opaque_data32[16];
		u64 opaque_data64[8];
	};
} __aligned(DCE_SCR_ALIGN);

/* 128 byte Stream Context Frame (Record), must be 64 byte aligned */
struct scf_128b {
	union {
		u8  opaque_data8[128];
		u16 opaque_data16[64];
		u32 opaque_data32[32];
		u64 opaque_data64[16];
		struct scf_64b scf[2];
	};
} __aligned(DCE_SCR_ALIGN);

/* Accessors to 64 byte Stream Configuration Frame */

#define SCF_TOTAL_IN_SHIFT	0
#define SCF_TOTAL_IN_MASK	(0xffffffffUL << SCF_TOTAL_IN_SHIFT)
#define SCF_TOTAL_IN_32IDX	0
/**
 * get_total_in - Get total_in field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_total_in(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_TOTAL_IN);
}

/**
 * set_total_in - Set total_in field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the total_in field to.
 */
static inline void set_total_in(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_TOTAL_IN, val);
}

#define SCF_TOTAL_OUT_SHIFT	0
#define SCF_TOTAL_OUT_MASK	(0xffffffffUL << SCF_TOTAL_OUT_SHIFT)
#define SCF_TOTAL_OUT_32IDX	1
/**
 * get_total_out - Get total_out field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_total_out(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_TOTAL_OUT);
}

/**
 * set_total_out - Set total_out field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the total_out field to.
 */
static inline void set_total_out(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_TOTAL_OUT, val);
}

#define SCF_ADLER32_SHIFT	0
#define SCF_ADLER32_MASK	(0xffffffffUL << SCF_ADLER32_SHIFT)
#define SCF_ADLER32_32IDX	2
/**
 * get_adler32 - Get adler32 field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_adler32(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_ADLER32);
}

/**
 * set_adler32 - Set adler32 field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the adler32 field to.
 */
static inline void set_adler32(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_ADLER32, val);
}

#define SCF_ID1_SHIFT	24
#define SCF_ID1_MASK	(0xffUL << SCF_ID1_SHIFT)
#define SCF_ID1_32IDX	4
/**
 * get_id1 - Get id1 field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_id1(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_ID1);
}

/**
 * set_id1 - Set id1 field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the id1 field to.
 */
static inline void set_id1(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_ID1, val);
}

#define SCF_ID2_SHIFT	16
#define SCF_ID2_MASK	(0xffUL << SCF_ID2_SHIFT)
#define SCF_ID2_32IDX	4
/**
 * get_id2 - Get id2 field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_id2(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_ID2);
}

/**
 * set_id2 - Set id2 field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the id2 field to.
 */
static inline void set_id2(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_ID2, val);
}

#define SCF_ID1_ID2_SHIFT	16
#define SCF_ID1_ID2_MASK	(0xffffUL << SCF_ID1_ID2_SHIFT)
#define SCF_ID1_ID2_32IDX	4
/**
 * get_id1id2 - Get both the id1 and id2 fields in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_id1id2(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_ID1_ID2);
}

/**
 * set_id1id2 - Set both the id1 and id2 fields in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the id1 and id2 fields to.
 */
static inline void set_id1id2(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_ID1_ID2, val);
}

#define SCF_CM_SHIFT	8
#define SCF_CM_MASK	(0xffUL << SCF_CM_SHIFT)
#define SCF_CM_32IDX	4
/**
 * get_cm - Get cm field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_cm(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_CM);
}

/**
 * set_cm - Set cm field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the cm field to.
 */
static inline void set_cm(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_CM, val);
}

#define SCF_FLG_SHIFT	0
#define SCF_FLG_MASK	(0xffUL << SCF_FLG_SHIFT)
#define SCF_FLG_32IDX	4
/**
 * get_flg - Get flg field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_flg(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_FLG);
}

/**
 * set_flg - Set flg field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the cm field to.
 */
static inline void set_flg(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_FLG, val);
}

#define SCF_CMFLG_SHIFT	0
#define SCF_CMFLG_MASK	(0xffffUL << SCF_CMFLG_SHIFT)
#define SCF_CMFLG_32IDX	4
/**
 * set_cmflg - Set cm and flg fields in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the cm and flg fields to.
 */
static inline void set_cmflg(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_CMFLG, val);
}

/**
 * get_cmflg - Get the combined cm and flg fields in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_cmflg(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_CMFLG);
}

#define SCF_MTIME_SHIFT	0
#define SCF_MTIME_MASK	(0xffffffffUL << SCF_MTIME_SHIFT)
#define SCF_MTIME_32IDX	5
/**
 * get_mtime - Get mtime field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_mtime(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_MTIME);
}

/**
 * set_mtime - Set mtime field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the mtime field to.
 */
static inline void set_mtime(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_MTIME, val);
}

#define SCF_XFL_SHIFT	24
#define SCF_XFL_MASK	(0xffUL << SCF_XFL_SHIFT)
#define SCF_XFL_32IDX	6
/**
 * get_xfl - Get xfl field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_xfl(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_XFL);
}

/**
 * set_xfl - Set xfl field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the xfl field to.
 */
static inline void set_xfl(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_XFL, val);
}

#define SCF_OS_SHIFT	16
#define SCF_OS_MASK	(0xffUL << SCF_OS_SHIFT)
#define SCF_OS_32IDX	6
/**
 * get_os - Get os field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_os(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_OS);
}

/**
 * set_os - Set os field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the os field to.
 */
static inline void set_os(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_OS, val);
}

#define SCF_XLEN_SHIFT	0
#define SCF_XLEN_MASK	(0xffffUL << SCF_XLEN_SHIFT)
#define SCF_XLEN_32IDX	6
/**
 * get_xlen - Get xlen field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_xlen(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_XLEN);
}

/**
 * set_xlen - Set xlen field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the xlen field to.
 */
static inline void set_xlen(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_XLEN, val);
}

#define SCF_NLEN_SHIFT	16
#define SCF_NLEN_MASK	(0xffffUL << SCF_NLEN_SHIFT)
#define SCF_NLEN_32IDX	7
/**
 * get_nlen - Get nlen field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_nlen(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_NLEN);
}

/**
 * set_nlen - Set nlen field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the nlen field to.
 */
static inline void set_nlen(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_NLEN, val);
}

#define SCF_CLEN_SHIFT	0
#define SCF_CLEN_MASK	(0xffffUL << SCF_CLEN_SHIFT)
#define SCF_CLEN_32IDX	7
/**
 * get_clen - Get clen field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_clen(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_CLEN);
}

/**
 * set_clen - Set clen field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the clen field to.
 */
static inline void set_clen(struct scf_64b *scf, u32 val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_CLEN, val);
}

#define SCF_EXTRA_PTR_SHIFT	0
#define SCF_EXTRA_PTR_MASK	(0xffffffffffULL << SCF_EXTRA_PTR_SHIFT)
#define SCF_EXTRA_PTR_64IDX	4
/**
 * get_extra_ptr - Get extra_ptr field in SCF
 *
 * @scf: stream context frame
 */
static inline u64 get_extra_ptr(const struct scf_64b *scf)
{
	return GET_BF64_IDX(&scf->opaque_data64[0], SCF_EXTRA_PTR);
}

/**
 * set_extra_ptr - Set extra_ptr field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the extra_ptr field to.
 */
static inline void set_extra_ptr(struct scf_64b *scf, u64 val)
{
	SET_BF64_IDX(&scf->opaque_data64[0], SCF_EXTRA_PTR, val);
}

#define SCF_PENDING_OUTPUT_PTR_SHIFT	0
#define SCF_PENDING_OUTPUT_PTR_MASK	\
		(0xffffffffffULL << SCF_PENDING_OUTPUT_PTR_SHIFT)
#define SCF_PENDING_OUTPUT_PTR_64IDX	5
/**
 * get_pending_output_ptr - Get pending_output_ptr field in SCF
 *
 * @scf: stream context frame
 */
static inline u64 get_pending_output_ptr(const struct scf_64b *scf)
{
	return GET_BF64_IDX(&scf->opaque_data64[0], SCF_PENDING_OUTPUT_PTR);
}

/**
 * set_pending_output_ptr - Set pending_output_ptr field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the pending_output_ptr field to.
 */
static inline void set_pending_output_ptr(struct scf_64b *scf, u64 val)
{
	SET_BF64_IDX(&scf->opaque_data64[0], SCF_PENDING_OUTPUT_PTR, val);
}


/*
 * Rev 1.0 BG specifies is a 40bit value, but the lower 6 bits are ignored
 * since the ptr has to be 64B aligned. Rev 1.1 specifies it as a 34 bit value
 * but that the next 6 lowers bits are implied to be zero. No space is
 * reserved for these 6 lower bits. The API will accept the full value
 * and shift accordingly. It will also shift when returning the value.
 */
#define SCF_HISTORY_PTR_SHIFT	6
#define SCF_HISTORY_PTR_MASK	(0x3ffffffffULL << SCF_HISTORY_PTR_SHIFT)
#define SCF_HISTORY_PTR_64IDX	6
/**
 * get_history_ptr - Get history_ptr field in SCF
 *
 * @scf: stream context frame
 */
static inline u64 get_history_ptr(const struct scf_64b *scf)
{
	return GET_BF64_IDX(&scf->opaque_data64[0], SCF_HISTORY_PTR) <<
		SCF_HISTORY_PTR_SHIFT;
}

/**
 * set_history_ptr - Set history_ptr field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the history_ptr field to.
 */
static inline void set_history_ptr(struct scf_64b *scf, u64 val)
{
	/* lower 6 bits expected to be zero, since 64 byte aligned */
	SET_BF64_IDX(&scf->opaque_data64[0], SCF_HISTORY_PTR,
		val >> SCF_HISTORY_PTR_SHIFT);
}

#define SCF_PMODE_SHIFT	31
#define SCF_PMODE_MASK	(0x1UL << SCF_PMODE_SHIFT)
#define SCF_PMODE_32IDX	14
/**
 * get_pmode - Get pmode field in SCF
 *
 * @scf: stream context frame
 */
static inline bool get_pmode(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_PMODE);
}

/**
 * set_pmode - Set pmode field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the pmode field to.
 */
static inline void set_pmode(struct scf_64b *scf, bool val)
{
	SET_BF32_IDX(&scf->opaque_data32[0], SCF_PMODE, val ? 1 : 0);
}


/* Compression, Output SCF attribute accessors */

#define SCF_BYTES_PROCESSED_SHIFT	0
#define SCF_BYTES_PROCESSED_MASK	\
		(0x1fffffffUL << SCF_BYTES_PROCESSED_SHIFT)
#define SCF_BYTES_PROCESSED_32IDX	3
/**
 * get_bytes_processed - Get bytes_processed field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_bytes_processed(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_BYTES_PROCESSED);
}

#define SCF_PENDING_OUTPUT_LEN_SHIFT	16
#define SCF_PENDING_OUTPUT_LEN_MASK	\
		(0xffffUL << SCF_PENDING_OUTPUT_LEN_SHIFT)
#define SCF_PENDING_OUTPUT_LEN_32IDX	10
/**
 * get_pending_output_len - Get pending_output_len field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_pending_output_len(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_PENDING_OUTPUT_LEN);
}

/* Decompression, Input SCF attribute accessors */

/* DEC Rev 1.0 */
#define SCF_EXTRA_LIMIT_SHIFT	16
#define SCF_EXTRA_LIMIT_MASK	(0xffffUL << SCF_EXTRA_LIMIT_SHIFT)
#define SCF_EXTRA_LIMIT_32IDX	8

/* DCE Rev 1.1 */
#define SCF_EXTRA_LIMIT_V11_SHIFT	8
#define SCF_EXTRA_LIMIT_V11_MASK	(0x3ffffUL << SCF_EXTRA_LIMIT_V11_SHIFT)
#define SCF_EXTRA_LIMIT_V11_32IDX	8

/**
 * get_extra_limit - Get extra_limit field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_extra_limit(const struct scf_64b *scf)
{
	u16 local_rev = dce_ip_rev;

	if (local_rev == 0)
		local_rev = DCE_DEFAULT_REV;

	if (local_rev == DCE_REV10)
		return GET_BF32_IDX(&scf->opaque_data32[0], SCF_EXTRA_LIMIT);
	else
		return GET_BF32_IDX(&scf->opaque_data32[0],
					SCF_EXTRA_LIMIT_V11);
}

/**
 * set_extra_limit - Set extra_limit field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the extra_limit field to.
 */
static inline void set_extra_limit(struct scf_64b *scf, u32 val)
{
	u16 local_rev;

	if (!dce_ip_rev)
		local_rev = DCE_DEFAULT_REV;
	else
		local_rev = dce_ip_rev;

	if (local_rev == DCE_REV10)
		SET_BF32_IDX(&scf->opaque_data32[0], SCF_EXTRA_LIMIT, val);
	else
		SET_BF32_IDX(&scf->opaque_data32[0], SCF_EXTRA_LIMIT_V11, val);
}

#define SCF_DECOMP_CTXT_PTR_SHIFT	0
#define SCF_DECOMP_CTXT_PTR_MASK	\
		(0xffffffffffULL << SCF_DECOMP_CTXT_PTR_SHIFT)
#define SCF_DECOMP_CTXT_PTR_64IDX	7
/**
 * get_decomp_ctxt_ptr - Get decomp_ctxt_ptr field in SCF
 *
 * @scf: stream context frame
 */
static inline u64 get_decomp_ctxt_ptr(const struct scf_64b *scf)
{
	return GET_BF64_IDX(&scf->opaque_data64[0], SCF_DECOMP_CTXT_PTR);
}

/**
 * set_decomp_ctxt_ptr - Set decomp_ctxt_ptr field in SCF
 *
 * @scf: stream context frame
 * @val: Value to set the decomp_ctxt_ptr field to.
 */
static inline void set_decomp_ctxt_ptr(struct scf_64b *scf, u64 val)
{
	SET_BF64_IDX(&scf->opaque_data64[0], SCF_DECOMP_CTXT_PTR, val);
}


/*
 * Decompression, Output SCF attribute accessors. Attribute list
 *	TOTAL_IN
 *	TOTAL_OUT
 *	ADLER32
 *	XO
 *	NO
 *	CO
 *	BYTES_PROCESSED
 *	ID1
 *	ID2
 *	CM
 *	FLG
 *	MTIME
 *	XFL
 *	OS
 *	XLEN
 *	NLEN
 *	CLEN
 *	EXTRA_LIMIT
 *	EXTRA_PTR
 *	PENDING_OUTPUT_LEN
 */

#define SCF_XO_SHIFT	31
#define SCF_XO_MASK	(0x1UL << SCF_XO_SHIFT)
#define SCF_XO_32IDX	3
/**
 * get_xo - Get xo field in SCF
 *
 * @scf: stream context frame
 */
static inline bool get_xo(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_XO);
}

#define SCF_NO_SHIFT	30
#define SCF_NO_MASK	(0x1UL << SCF_NO_SHIFT)
#define SCF_NO_32IDX	3
/**
 * get_no - Get no field in SCF
 *
 * @scf: stream context frame
 */
static inline bool get_no(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_NO);
}

#define SCF_CO_SHIFT	29
#define SCF_CO_MASK	(0x1UL << SCF_CO_SHIFT)
#define SCF_CO_32IDX	3
/**
 * get_co - Get co field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_co(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_CO);
}

/* This following accessors is when accessing the full stream context recort */

/*
 * Compression, Output Debug SCF attribute accessors. Attribute list
 *	TOTAL_IN
 *	TOTAL_OUT
 *	ADLER32
 *	OUTPUT_PHASE
 *	B64_RESIDUE_LEN
 *	B64_RESIDUE
 *	ID1
 *	ID2
 *	CM
 *	FLG
 *	MTIME
 *	XFL
 *	OS
 *	XLEN
 *	NLEN
 *	CLEN
 *	RESIDUE_DATA
 *	EXTRA_PTR
 *	PENDING_OUTPUT_LEN
 *	PENDING_WORKING_PTR(_H) (1.0, 1.1)
 *	PENDING_OUTPUT_PTR
 *	HISTORY_LEN
 *	PENDING_WORKING_PTR_L (1.1)
 *	HISTORY_PTR
 *	PMODE
 *	SUSP
 *	TERMINATED
 *	RBC
 *	MCPLT (1.1)
 *	HEADER_REMAINING
 *	CRC16
 */
#define SCF_OUTPUT_PHASE_SHIFT	26
#define SCF_OUTPUT_PHASE_MASK	(0x7UL << SCF_OUTPUT_PHASE_SHIFT)
#define SCF_OUTPUT_PHASE_32IDX	3
/**
 * get_output_phase - Get output_phase field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_output_phase(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_OUTPUT_PHASE);
}

#define SCF_B64_RESIDUE_LEN_SHIFT	24
#define SCF_B64_RESIDUE_LEN_MASK	(0x3UL << SCF_B64_RESIDUE_LEN_SHIFT)
#define SCF_B64_RESIDUE_LEN_32IDX	3
/**
 * get_b64_residue_len - Get b64_residue_len field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_b64_residue_len(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_B64_RESIDUE_LEN);
}

#define SCF_B64_RESIDUE_SHIFT	0
#define SCF_B64_RESIDUE_MASK	(0xffffffUL << SCF_B64_RESIDUE_SHIFT)
#define SCF_B64_RESIDUE_32IDX	3
/**
 * get_b64_residue - Get b64_residue field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_b64_residue(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_B64_RESIDUE);
}

#define SCF_RESIDUE_DATA_SHIFT	9
#define SCF_RESIDUE_DATA_MASK	(0x7fffffUL << SCF_RESIDUE_DATA_SHIFT)
#define SCF_RESIDUE_DATA_32IDX	8
/**
 * get_residue_data - Get residue_data field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_residue_data(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_RESIDUE_DATA);
}

#define SCF_PENDING_WKG_PTR_SHIFT	8
#define SCF_PENDING_WKG_PTR_MASK	(0xffUL << SCF_PENDING_WKG_PTR_SHIFT)
#define SCF_PENDING_WKG_PTR_32IDX	10
#define SCF_PENDING_WKG_L_PTR_SHIFT	8
#define SCF_PENDING_WKG_L_PTR_MASK	(0xffUL << SCF_PENDING_WKG_L_PTR_SHIFT)
#define SCF_PENDING_WKG_L_PTR_32IDX	12
/* This is a Rev 1.0 field, in Rev 1.1 this is the High field */
/*
 * get_pending_working_ptr - Get pending_working_ptr field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_pending_working_ptr(const struct scf_64b *scf)
{
	u16 local_rev = dce_ip_rev;

	if (local_rev == 0)
		local_rev = DCE_DEFAULT_REV;

	if (local_rev == DCE_REV10) {
		return GET_BF32_IDX(&scf->opaque_data32[0],
					SCF_PENDING_WKG_PTR);
	} else {
		u32 val = 0;
		val = GET_BF32_IDX(&scf->opaque_data32[0], SCF_PENDING_WKG_PTR)
				<< 8;
		val |= GET_BF32_IDX(&scf->opaque_data32[0],
				SCF_PENDING_WKG_L_PTR);
		return val;
	}
}

#define SCF_HISTORY_LEN_SHIFT	16
#define SCF_HISTORY_LEN_MASK	(0xffffUL << SCF_HISTORY_LEN_SHIFT)
#define SCF_HISTORY_LEN_32IDX	12
/**
 * get_history_len - Get history_len field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_history_len(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_HISTORY_LEN);
}

#define SCF_SUSP_SHIFT	30
#define SCF_SUSP_MASK	(0x1UL << SCF_SUSP_SHIFT)
#define SCF_SUSP_32IDX	14
/**
 * get_susp - Get susp field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_susp(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_SUSP);
}

#define SCF_TERMINATED_SHIFT	29
#define SCF_TERMINATED_MASK	(0x1UL << SCF_TERMINATED_SHIFT)
#define SCF_TERMINATED_32IDX	14
/**
 * get_terminated - Get terminated field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_terminated(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_TERMINATED);
}

#define SCF_RBC_SHIFT	24
#define SCF_RBC_MASK	(0x1fUL << SCF_RBC_SHIFT)
#define SCF_RBC_32IDX	14
/**
 * get_rbc - Get rbc field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_rbc(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_RBC);
}

#define SCF_MCPLT_SHIFT	22
#define SCF_MCPLT_MASK	(0x1UL << SCF_MCPLT_SHIFT)
#define SCF_MCPLT_32IDX	14
/**
 * get_mcplt - Get mcplt field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_mcplt(const struct scf_64b *scf)
{
	/* only in rev > 1.0 */
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_MCPLT);
}


#define SCF_HEADER_REMAINING_SHIFT	0
#define SCF_HEADER_REMAINING_MASK	\
			(0x3ffffUL << SCF_HEADER_REMAINING_SHIFT)
#define SCF_HEADER_REMAINING_32IDX	14
/**
 * get_header_remaining - Get header_remaining field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_header_remaining(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_HEADER_REMAINING);
}

#define SCF_CRC16_SHIFT	0
#define SCF_CRC16_MASK	(0xffffffffUL << SCF_CRC16_SHIFT)
#define SCF_CRC16_32IDX	15
/**
 * get_crc16 - Get crc16 field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_crc16(const struct scf_64b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCF_CRC16);
}

/*
 * Deompression, Output Debug SCF attribute accessors. Attribute list
 * IMPORTANT: This structure is 128Bytes is size.
 *	TOTAL_IN
 *	TOTAL_OUT
 *	ADLER32
 *	OUTPUT_PHASE
 *	B64_RESIDUE_LEN
 *	B64_RESIDUE
 *	ID1
 *	ID2
 *	CM
 *	FLG
 *	MTIME
 *	XFL
 *	OS
 *	XLEN
 *	NLEN
 *	CLEN
 *	RESIDUE_DATA
 *	EXTRA_PTR
 *	PENDING_OUTPUT_LEN
 *	PENDING_WORKING_PTR(_H) (1.0, 1.1)
 *	PENDING_OUTPUT_PTR
 *	HISTORY_LEN
 *	PENDING_WORKING_PTR_L (1.1)
 *	HISTORY_PTR
 *	PMODE
 *	SUSP
 *	TERMINATED
 *	RBC
 *	MCPLT (1.1)
 *	MC (1.1)
 *	HEADER_REMAINING
 *	CRC16
 *
 *	## second cache line ##
 *	DECOMP_CTXT_PTR
 *	DECOMP_TOTAL_OUT (1.1)
 *	BFINAL
 *	BTYPE
 *	FRAME_PARSE_STATE
 *	NUM_CODE_LEN
 *	PREVIOUS_CODE_LEN (moved location, 1.0, 1.1)
 *	NCBB_REMAINING
 *	HLIT
 *	HDIST
 *	HCLEN
 *	HUFFMAN_RBC
 *	HUFFMAN_RESIDUE
 */

#define SCFCL2_DECOMP_CTXT_PTR_SHIFT	0
#define SCFCL2_DECOMP_CTXT_PTR_MASK	\
			(0xffffffffffULL << SCFCL2_DECOMP_CTXT_PTR_SHIFT)
#define SCFCL2_DECOMP_CTXT_PTR_64IDX	8
/**
 * get_decomp_ctxt_ptr_cl2 - Get decomp_ctxt_ptr field in 128 byte SCF
 *
 * @scf: stream context frame, 128 bytes in size
 *
 * Returns the decomp_ctxt_ptr field in the second cache line.
 */
static inline u64 get_decomp_ctxt_ptr_cl2(const struct scf_128b *scf)
{
	return GET_BF64_IDX(&scf->opaque_data64[0], SCFCL2_DECOMP_CTXT_PTR);
}

#define SCFCL2_DECOMP_TOTAL_OUT_SHIFT	0
#define SCFCL2_DECOMP_TOTAL_OUT_MASK	\
			(0xffffffffUL << SCFCL2_DECOMP_TOTAL_OUT_SHIFT)
#define SCFCL2_DECOMP_TOTAL_OUT_32IDX	17
/**
 * get_decomp_total_out_cl2 - Get decomp_total_out field in 128 byte SCF
 *
 * @scf: stream context frame, 128 bytes in size
 *
 * Returns the decomp_total_out field in the second cache line.
 */
static inline u64 get_decomp_total_out_cl2(const struct scf_128b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCFCL2_DECOMP_TOTAL_OUT);
}

#define SCFCL2_PREVIOUS_CODE_LEN_SHIFT		28
#define SCFCL2_PREVIOUS_CODE_LEN_V11_SHIFT	12
#define SCFCL2_PREVIOUS_CODE_LEN_MASK	\
	(0xfUL << SCFCL2_PREVIOUS_CODE_LEN_SHIFT)
#define SCFCL2_PREVIOUS_CODE_LEN_V11_MASK	\
	(0xfUL << SCFCL2_PREVIOUS_CODE_LEN_V11_SHIFT)
#define SCFCL2_PREVIOUS_CODE_LEN_32IDX	18
#define SCFCL2_PREVIOUS_CODE_LEN_V11_32IDX	20

/**
 * get_previous_code_len_cl2 - Get previous_code_len field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_previous_code_len_cl2(const struct scf_128b *scf)
{
	u16 local_rev = dce_ip_rev;

	if (local_rev == 0)
		local_rev = DCE_DEFAULT_REV;

	if (local_rev == DCE_REV10)
		return GET_BF32_IDX(&scf->opaque_data32[0],
			SCFCL2_PREVIOUS_CODE_LEN);
	else
		return GET_BF32_IDX(&scf->opaque_data32[0],
				 SCFCL2_PREVIOUS_CODE_LEN_V11);
}

#define SCFCL2_BFINAL_SHIFT	30
#define SCFCL2_BFINAL_MASK	(0x1UL << SCFCL2_BFINAL_SHIFT)
#define SCFCL2_BFINAL_32IDX	19
/**
 * get_bfinal_cl2 - Get bfinal field in SCF
 *
 * @scf: stream context frame, 128 bytes in size
 */
static inline u32 get_bfinal_cl2(const struct scf_128b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCFCL2_BFINAL);
}

#define SCFCL2_BTYPE_SHIFT	28
#define SCFCL2_BTYPE_MASK	(0x3UL << SCFCL2_BTYPE_SHIFT)
#define SCFCL2_BTYPE_32IDX	19
/**
 * get_btype_cl2 - Get btype field in SCF
 *
 * @scf: stream context frame, 128 bytes in size
 */
static inline u32 get_btype_cl2(const struct scf_128b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCFCL2_BTYPE);
}

#define SCFCL2_FRAME_PARSE_STATE_SHIFT	27
#define SCFCL2_FRAME_PARSE_STATE_MASK	\
		(0x1fUL << SCFCL2_FRAME_PARSE_STATE_SHIFT)
#define SCFCL2_FRAME_PARSE_STATE_32IDX	20
/**
 * get_frame_parse_state_cl2 - Get frame_parse_state field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_frame_parse_state_cl2(const struct scf_128b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCFCL2_FRAME_PARSE_STATE);
}

#define SCFCL2_NUM_CODE_LEN_SHIFT	18
#define SCFCL2_NUM_CODE_LEN_MASK	(0x1ffUL << SCFCL2_NUM_CODE_LEN_SHIFT)
#define SCFCL2_NUM_CODE_LEN_32IDX	20
/**
 * get_num_code_len_cl2 - Get num_code_len field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_num_code_len_cl2(const struct scf_128b *scf)
{
		return GET_BF32_IDX(&scf->opaque_data32[0],
				SCFCL2_NUM_CODE_LEN);
}

#define SCFCL2_NCBB_REMAINING_SHIFT	16
#define SCFCL2_NCBB_REMAINING_MASK	\
		(0xffffUL << SCFCL2_NCBB_REMAINING_SHIFT)
#define SCFCL2_NCBB_REMAINING_32IDX	21
/**
 * get_ncbb_remaining_cl2 - Get ncbb_remaining field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_ncbb_remaining_cl2(const struct scf_128b *scf)
{
		return GET_BF32_IDX(&scf->opaque_data32[0],
				SCFCL2_NCBB_REMAINING);
}

#define SCFCL2_HLIT_SHIFT	11
#define SCFCL2_HLIT_MASK	(0x1fUL << SCFCL2_HLIT_SHIFT)
#define SCFCL2_HLIT_32IDX	21
/**
 * get_hlit_cl2 - Get hlit field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_hlit_cl2(const struct scf_128b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCFCL2_HLIT);
}

#define SCFCL2_HDIST_SHIFT	6
#define SCFCL2_HDIST_MASK	(0x1fUL << SCFCL2_HDIST_SHIFT)
#define SCFCL2_HDIST_32IDX	21
/**
 * get_hdist_cl2 - Get hdist field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_hdist_cl2(const struct scf_128b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCFCL2_HDIST);
}

#define SCFCL2_HCLEN_SHIFT	2
#define SCFCL2_HCLEN_MASK	(0xfUL << SCFCL2_HCLEN_SHIFT)
#define SCFCL2_HCLEN_32IDX	21
/**
 * get_hclen_cl2 - Get hclen field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_hclen_cl2(const struct scf_128b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCFCL2_HCLEN);
}

#define SCFCL2_HUFFMAN_RBC_SHIFT	24
#define SCFCL2_HUFFMAN_RBC_MASK	(0x3fUL << SCFCL2_HUFFMAN_RBC_SHIFT)
#define SCFCL2_HUFFMAN_RBC_32IDX	22
/**
 * get_huffman_rbc_cl2 - Get huffman_rbc field in SCF
 *
 * @scf: stream context frame
 */
static inline u32 get_huffman_rbc_cl2(const struct scf_128b *scf)
{
	return GET_BF32_IDX(&scf->opaque_data32[0], SCFCL2_HUFFMAN_RBC);
}

#define SCFCL2_HUFFMAN_RESIDUE_SHIFT	0
#define SCFCL2_HUFFMAN_RESIDUE_MASK	\
		(0x7fffffffffffULL << SCFCL2_HUFFMAN_RESIDUE_SHIFT)
#define SCFCL2_HUFFMAN_RESIDUE_64IDX	11
/**
 * get_huffman_residue_cl2 - Get huffman_residue field in SCF
 *
 * @scf: stream context frame
 */
static inline u64 get_huffman_residue_cl2(const struct scf_128b *scf)
{
	return GET_BF64_IDX(&scf->opaque_data64[0], SCFCL2_HUFFMAN_RESIDUE);
}

/**
 * enum dce_status - This enumeration depicts all of the possible status codes
 *	that can appear in the output frame status field.
 *
 * @FULLY_PROCESSED	The work unit data was fully processed without
 *			encountering an exception, and the work unit was not
 *			marked as an end of Stream (no DCE_Z_FINISH parameter).
 * @STREAM_END		The work unit data was fully processed without
 *			encountering an exception, and was marked as an end of
 *			Stream with the DCE_Z_FINISH flush parameter.
 * @INPUT_STARVED	The compressed input Frame did not contain an integral
 *			number of compressed data blocks and/or ended before
 *			the expected number of decompressed bytes were produced.
 *			This exception occurs when an input Frame with
 *			Z_FLUSH = Z_FINISH is received. It indicates a missing
 *			end of block code;
 *			i.e. “invalid code * missing end-of-block” in *msg
 *			(zlib software library equivalent).
 * @MEMBER_END_SUSPEND	The decompresser module halted processing of an input
 *			Frame at the end of a compressed member (after the
 *			BFINAL block and any gzip trailer). This code can only
 *			occur on stateful Flows in recycling mode
 * @Z_BLOCK_SUSPENED	The decompresser module halted processing of an input
 *			Frame at the end of a compressed block (or block header
 *			if Z_FLUSH = Z_BLOCK or Z_TREES). This code can only
 *			occur on stateful Flows in recycling mode
 * @OUTPUT_BLOCKED_SUSPEND	The pre-built output structure was not large
 *			enough to contain all of the (de)compressed input Frame
 *			data. This code can only occur on stateful Flows in
 *			recycling mode
 * @ACQUIRE_DATA_BUFFER_DENIED_SUSPEND	An attempt to acquire a free buffer from
 *			BMan (DBPID) was unsuccessful. This code can only occur
 *			on stateful Flows in recycling mode
 * @ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND	An attempt to acquire a free buffer from
 *			BMan (TBPID) was unsuccessful. This code can only occur
 *			on stateful Flows in recycling mode
 * @OOL_REACHED_SUSPEND	The DCE halted processing so as not to exceed the OLL
 *			setting. This code can only occur on stateful Flows in
 *			recycling mode
 * @HCL_REACHED_SUSPEND	The DCE halted processing so as not to exceed the HCL
 *			setting. This code can only occur on stateful Flows in
 *			recycling mode
 * @OUTPUT_BLOCKED_DISCARD	The pre-built output structure was not large
 *			enough to contain all of the (de)compressed input Frame
 *			data. Some output data has been lost. This code can only
 *			occur on stateless Flows or a stateful Flow in
 *			truncation mode
 * @ACQUIRE_DATA_BUFFER_DENIED_DISCARD	An attempt to acquire a free buffer from
 *			BMan (DBPID) was unsuccessful. Some output data has been
 *			lost. This code can only occur on stateless Flows or a
 *			stateful Flow in truncation mode
 *
 * @ACQUIRE_TABLE_BUFFER_DENIED_DISCARD	An attempt to acquire a free buffer from
 *			BMan (TBPID) was unsuccessful. Some output data has been
 *			lost. This code can only occur on stateless Flows or a
 *			stateful Flow in truncation mode
 * @OLL_REACHED_DISCARD	The DCE halted processing so as not to exceed the OLL
 *			setting. Some output data has been lost. This code can
 *			only occur on stateless Flows or a stateful Flow in
 *			truncation mod
 * @HCL_REACHED_DISCARD	The DCE halted processing so as not to exceed the HCL
 *			setting. Some output data has been lost. This code can
 *			only occur on stateless Flows or a stateful Flow in
 *			truncation mode
 * @SKIPPED	The work unit was not processed due to a previous “suspend”
 *		(i.e. Output Blocked Suspend, etc.) exception on the same
 *		Stream. This code can only occur on stateful Flows in recycling
 *		mode
 * @PREVIOUS_FLOW_TERMINATION	The work unit was not processed due to a
 *		previous exception (other than Input Starved or Output Blocked
 *		Suspend) or completed Z_FINISH Frame on the same Stream. This
 *		exception code will appear in Frames that follow a
 *		non-recoverable exception on a Stream, or in Frames that follow
 *		a Z_FINISH Frame but do not have a set I bit.
 * @INVALID_COMPOUND_FRAME	This status code is generated if the DCE
 *		dequeues a compound Frame that does not contain an {E=0, F=1}
 *		pair in its third member Frame.
 * @INVALID_STATUS_CMD	An invalid field setting was detected in the received
 *		Frame’s STATUS/CMD field. This code results from one of the
 *		following conditions:
 *			Reserved setting in any of the defined fields
 * @UNSUPPORTED_FRAME	This status code is generated if the DCE dequeues a
 *		compound Frame that does not match the supported three member
 *		configuration.
 * @FRAME_TOO_SHORT	This status code is generated if DCE reaches the end of
 *		a multi-buffer input Frame (simple or compound) and determines
 *		that the structure contains fewer than LENGTH bytes of data.
 * @OUTPUT_OFFSET_TOO_LARGE	This status code is generated if the OO field in
 *		the Frame’s STATUS/CMD field specifies an offset that is
 *		greater	than or equal to the BMan buffer size specified for the
 *		Flow. This exception will only occur if buffer acquisition is
 *		necessary; i.e. DCE has some output data to buffer for the
 *		processed Frame.
 * @ZLIB_INCOMPLETE_HEADER
 * @ZLIB_HEADER_ERROR	An error was detected in the ZLIB header of a compressed
 *		work unit. This code results from one of the following
 *		conditions:
 *			Z_FINISH Frame (plus any preceding Frames) did not
 *				contain enough bytes to comprise a complete
 *				header: “incorrect header check” in *msg
 *			Compression method other than DEFLATE specified:
 *				“unknown compression method” in *msg
 *			Invalid window size specified: “invalid window size”
 *				in *msg
 *			Reserved BTYPE: “invalid block type” in *msg
 *			LEN and NLEN fields are not 1’s complement of each
 *				other: “invalid stored block lengths”
 *				in *msg
 * @ZLIB_NEED_DICTIONARY_ERROR	A compressed ZLIB Stream has the FLG.FDICT flag
 *		set.
 * @GZIP_INCOMPLETE_HEADER
 * @GZIP_HEADER_ERROR	An error was detected in the header of a compressed GZIP
 *		work unit. This code results from one of the following
 *		conditions:
 *			ID1/ID2 invalid
 *			Compression method other than DEFLATE
 *			Any of the reserved flags are set: “unknown header
 *				flags set” in *msg.
 *			Header CRC16 value check mismatch: “header crc
 *				mismatch” in *msg.
 * @DEFLATE_INVALID_BLOCK_TYPE	An error was detected in the header of a
 *		compressed DEFLATE block: “invalid block type” in *msg.
 * @DEFLATE_INVALID_BLOCK_LENGTHS	An error was detected in the header of a
 *		compressed DEFLATE block: “invalid stored block lengths” in
 *		*msg
 * @DEFLATE_TOO_MANY_LEN_OR_DIST_SYM	“too many length or distance symbols” in
 *		*msg.
 * @DEFLATE_INVALID_CODE_LENGTHS_SET	“invalid code lengths set” in *msg.
 * @DEFLATE_INVALID_BIT_LENGTH_REPEAT	“invalid bit length repeat” in *msg.
 * @DEFLATE_INVALID_LITERAL_LENGTHS_SET “invalid literal/lengths set” in *msg.
 * @DEFLATE_INVALID_DISTANCES_SET	“invalid distances set” in *msg.
 * @DEFLATE_INVALID_LITERAL_LENGTH_CODE	“invalid literal/length code” in *msg.
 * @DEFLATE_INVALID_DISTANCE_CODE	“invalid distance code” in *msg.
 * @DEFLATE_INVALID_DISTANCE_TOO_FAR_BACK	“invalid distance too far back”
 *		in *msg.
 * @DEFLATE_INCORRECT_DATA_CHECK	“incorrect data check” in *msg.
 * @DEFLATE_INCORRECT_LENGTH_CHECK	“incorrect length check” in *msg.
 * @DEFLATE_INVALID_CODE	“invalid code * missing end of block” in *msg.
 * @CXM_2BIT_ECC_ERROR	A double bit ECC error was detected on an access to the
 *		CXM internal memory while processing this Frame.
 * @CBM_2BIT_ECC_ERROR	A double bit ECC error was detected on an access to the
 *		CBM internal memory while processing this Frame.
 * @DHM_2BIT_ECC_ERROR	A double bit ECC error was detected on an access to the
 *		DHM internal memory while processing this Frame.
 * @INVALID_BASE64_CODE	An invalid Base64 code (bad byte value) was encountered.
 * @INVALID_BASE64_PADDING	In invalid amount of padding was detected on
 *		Base64 encoded input data.
 * @SCF_SYSTEM_MEM_READ_ERROR	A system memory read transaction performed by
 *		the DCE has resulted in a system memory bus error.  This code
 *			 will occur when the error is detected on the following
 *			 read transactions:
 *				* Stream Configuration Frame
 * @PENDING_OUTPUT_SYSTEM_MEM_READ_ERROR	A system memory read transaction
 *		performed by the DCE has resulted in a system memory bus error.
 *		This code will occur when the error is detected on the following
 *		read transactions:
 *			Pending Output Buffer
 * @HISTORY_WINDOW_SYSTEM_MEM_READ_ERROR	A system memory read transaction
 *		performed by the DCE has resulted in a system memory bus error.
 *		This code will occur when the error is detected on the following
 *		read transactions:
 *			* History Window
 * @CTX_DATA_SYSTEM_MEM_READ_ERROR	A system memory read transaction
 *		 performed by the DCE has resulted in a system memory bus error.
 *		 This code will occur when the error is detected on the
 *		 following read transactions:
 *			Stream Context Record
 *			“Extra” data for GZIP header insertion.
 * @FRAME_DATA_SYSTEM_READ_ERROR	A system memory read transaction
 *		 performed by the DCE has resulted in a system memory bus error.
 *		 This code will occur when the error is detected on the
 *		 following read transactions:
 *			Input Frame data buffer
 * @INPUT_FRAME_TBL_SYSTEM_READ_ERROR	A system memory read transaction
 *		 performed by the DCE has resulted in a system memory bus error.
 *		 This code will occur when the error is detected on the
 *		 following read transactions:
 *			Input Frame scatter/gather table entry
 * @OUTPUT_FRAME_TBL_SYSTEM_READ_ERROR	A system memory read transaction
 *		 performed by the DCE has resulted in a system memory bus error.
 *		 This code will occur when the error is detected on the
 *		 following read transactions:
 *			Output Frame scatter/gather table entry (pre-built
 *				Frames only)
 * @SCF_SYSTEM_MEM_WRITE_ERROR	A system memory write transaction performed by
 *		 the DCE has resulted in a system memory bus error.  This code
 *		 will occur when the error is detected on the following write
 *		 transactions:
 *			Stream Configuration Frame
 * @PENDING_OUTPUT_SYSTEM_MEM_WRITE_ERROR	A system memory write
 *		 transaction performed by the DCE has resulted in a system
 *		 memory bus error.  This code will occur when the error is
 *		 detected on the following write transactions:
 *			Pending Output Buffer
 * @HISTORY_WINDOW_SYSTEM_MEM_WRITE_ERROR	A system memory write
 *		 transaction performed by the DCE has resulted in a system
 *		 memory bus error.  This code will occur when the error is
 *		 detected on the following write transactions:
 *			History Window
 * @CTX_DATA_SYSTEM_MEM_WRITE_ERROR	A system memory write transaction
 *		 performed by the DCE has resulted in a system memory bus error.
 *		 This code will occur when the error is detected on the
 *		 following write transactions:
 *			Stream Context Record
 * @FRAME_DATA_SYSTEM_MEM_WRITE_ERROR	A system memory write transaction
 *		 performed by the DCE has resulted in a system memory bus error.
 *		 This code will occur when the error is detected on the
 *		 following write transactions:
 *			Output Frame data buffer
 * @FRAME_TBL_SYSTEM_MEM_WRITE_ERROR	A system memory write transaction
 *		 performed by the DCE has resulted in a system memory bus error.
 *		 This code will occur when the error is detected on the
 *		 following write transactions:
 *			Output Frame scatter/gather table entry
 *
 * @FULLY_PROCESSED and @STREAM_END are successful return code, all other codes
 * are operational error.
 */
enum dce_status {
	FULLY_PROCESSED				= 0x00,
	STREAM_END				= 0x01,
	INPUT_STARVED				= 0x10,
	MEMBER_END_SUSPEND			= 0x11,
	Z_BLOCK_SUSPEND				= 0x12,
	OUTPUT_BLOCKED_SUSPEND			= 0x14,
	ACQUIRE_DATA_BUFFER_DENIED_SUSPEND	= 0x15,
	ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND	= 0x16,
	OOL_REACHED_SUSPEND			= 0x17,
	HCL_REACHED_SUSPEND			= 0x18,
	OUTPUT_BLOCKED_DISCARD			= 0x24,
	ACQUIRE_DATA_BUFFER_DENIED_DISCARD	= 0x25,
	ACQUIRE_TABLE_BUFFER_DENIED_DISCARD	= 0x26,
	OLL_REACHED_DISCARD			= 0x27,
	HCL_REACHED_DISCARD			= 0x28,
	SKIPPED					= 0x30,
	PREVIOUS_FLOW_TERMINATION		= 0x31,
	INVALID_COMPOUND_FRAME			= 0x40,
	INVALID_STATUS_CMD			= 0x41,
	UNSUPPORTED_FRAME			= 0x42,
	FRAME_TOO_SHORT				= 0x44,
	OUTPUT_OFFSET_TOO_LARGE			= 0x46,
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

#endif /* FL_DCE_DEFS_H */
