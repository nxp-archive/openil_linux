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

#ifndef FSL_DCE_STREAM_H
#define FSL_DCE_STREAM_H

#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include "flib/dce_flow.h"

/* (De)Allocate DCE hardware resources */
struct fsl_dce_hw_scr_64b;
struct fsl_dce_hw_scr_128b;
struct fsl_dce_hw_compress_history;
struct fsl_dce_hw_decompress_history;
struct fsl_dce_hw_pending_output;
struct fsl_dce_hw_decomp_ctxt;

struct fsl_dce_hw_scr_64b *fsl_dce_hw_scr_64b_new(void);
void fsl_dce_hw_scr_64b_free(struct fsl_dce_hw_scr_64b *);
struct fsl_dce_hw_scr_128b *fsl_dce_hw_scr_128b_new(void);
void fsl_dce_hw_scr_128b_free(struct fsl_dce_hw_scr_128b *);
struct fsl_dce_hw_compress_history *fsl_dce_hw_compress_history_new(void);
void fsl_dce_hw_compress_history_free(struct fsl_dce_hw_compress_history *);
struct fsl_dce_hw_decompress_history *fsl_dce_hw_decompress_history_new(void);
void fsl_dce_hw_decompress_history_free
	(struct fsl_dce_hw_decompress_history *);
struct fsl_dce_hw_pending_output *fsl_dce_hw_pending_output_new(void);
void fsl_dce_hw_pending_output_free(struct fsl_dce_hw_pending_output *);
struct fsl_dce_hw_decomp_ctxt *fsl_dce_hw_decomp_ctxt_new(void);
void fsl_dce_hw_decomp_ctxt_free(struct fsl_dce_hw_decomp_ctxt *);

/************************/
/* high-level functions */
/************************/
struct fsl_dce_stream;

/**
 * struct fsl_dce_stream - stateful (stream based) (de)compressor object
 *
 * @flow: Underlining dce flib object which contains a pair of QMan frame
 *	queues.
 * @cf: The (de)compression format used for this flow. DCE_CF_DEFLATE,
 *	DCE_CF_ZLIB and DCE_CF_GZIP.
 * @pmode: processing mode. trunction or recycle mode
 * @use_bman_output: (not supported) Use BMan buffers for output. Optional
 *	setting.
 * @process_params: (not used)
 * @hw_comp_scr: This is the stream context record used by hw when compressing
 * @hw_decomp_scr: This is the stream context record used by hw when
 *	decompressing
 * @comp_hist: History window when compressing
 * @decomp_hist: History window when decompressing
 * @pending_output_ptr: pending output data. For decompression it is 8256 bytes
 *	for compression this is 8202 bytes. No hard requirement on alignment but
 *	64 bytes is optimal. Only needed in recycle mode.
 * @decomp_ctx_ptr: decompression context pointer. Used to store the alphabet.
 *	This is a 256 byte buffer with no alignment requirement.
 * @flags: internal state
 * @lock: internal value
 * @queue: internal value
 *
 * A @fsl_dce_stream in DCE HW terminology is an object which is able to perform
 * statful (de)compression in either recycle or truncation processing mode.
 * In recycle mode, only synchronous processing is permitted and therefore
 * a fifo_depth of 1 is only permitted.
 */
struct fsl_dce_stream {
	struct fsl_dce_flow flow;

	enum dce_compression_format cf;
	enum dce_processing_mode pmode;

	bool use_bman_output;
	u32 process_params;

	union {
		struct fsl_dce_hw_scr_64b *hw_comp_scr;
		struct fsl_dce_hw_scr_128b *hw_decomp_scr;
	};

	union {
		struct fsl_dce_hw_compress_history *comp_hist;
		struct fsl_dce_hw_decompress_history *decomp_hist;
	};

	struct fsl_dce_hw_pending_output *pending_output_ptr;
	struct fsl_dce_hw_decomp_ctxt *decomp_ctx_ptr;

	/* internal state */
	u32 flags;
	spinlock_t lock;
	wait_queue_head_t queue;
};

/**
 * fsl_dce_stream_setup - setup for dce stream object
 *
 * @stream: object to setup
 * @flags: (not used)
 * @mode: compression or decompression mode
 * @cf: The (de)compression format used for this flow. DCE_CF_DEFLATE,
 *	DCE_CF_ZLIB and DCE_CF_GZIP.
 * @process_cb: callback function when PROCESS operations are performed.
 * @nop_cb: callback function when NOP operations are performed.
 * @scr_invalidate_cb: callback function when SCR_INVALIDATE operations are
 *	performed.
 *
 * Setup a @stream object for usage
 */
int fsl_dce_stream_setup(struct fsl_dce_stream *stream,
	u32 flags,
	enum dce_mode mode,
	enum dce_compression_format cf,
	fsl_dce_process_cb process_cb,
	fsl_dce_nop_cb nop_cb,
	fsl_dce_scr_invalidate_cb scr_invalidate_cb);

/**
 * fsl_dce_stream_setup2 - Advanced setup for dce stream object
 *
 * @stream: object to setup
 * @flags: (not used)
 * @mode: compression or decompression mode
 * @cf: The (de)compression format used for this flow. DCE_CF_DEFLATE,
 *	DCE_CF_ZLIB and DCE_CF_GZIP.
 * @pmode: truncation or recycle mode (recycle not supported)
 * @bcfg:  optional bman configuration parameters.
 * @process_cb: callback function when PROCESS operations are performed.
 * @nop_cb: callback function when NOP operations are performed.
 * @scr_invalidate_cb: callback function when SCR_INVALIDATE operations are
 *	performed.
 *
 * Returns 0 in success
 */
int fsl_dce_stream_setup2(struct fsl_dce_stream *stream,
	u32 flags,
	enum dce_mode mode,
	enum dce_compression_format cf,
	enum dce_processing_mode pmode,
	struct dce_bman_cfg *bcfg,
	fsl_dce_process_cb process_cb,
	fsl_dce_nop_cb nop_cb,
	fsl_dce_scr_invalidate_cb scr_invalidate_cb);

/**
 * fsl_dce_stream_fifo_len - length of internal outstanding requests to send
 *
 * @stream: the object to query against
 *
 * Returns the number of elements in the list
 */
int fsl_dce_stream_fifo_len(struct fsl_dce_stream *stream);

/**
 * fsl_dce_stream_destroy - terminates a stream object and the underlining
 *	flow object.
 *
 * @stream: object to destroy
 * @flags: (currently not used)
 * @callback_tag: (currently not used)
 *
 * Returns 0 on success
 */
int fsl_dce_stream_destroy(struct fsl_dce_stream *stream, u32 flags,
			void *callback_tag);

/**
 * fsl_dce_stream_deflate_params - set deflate options
 *
 * @stream: object to set options in
 * @bman_output_offset: when using bman output start at an offset.
 * @bman_release_input: release input frame to bman
 * @base64: use base64 (de)coding
 * @ce: compression effort: DCE_PROCESS_CE_*
 *
 * Returns 0 on success
 */
int fsl_dce_stream_deflate_params(struct fsl_dce_stream *stream,
	u32 bman_output_offset,
	bool bman_release_input,
	bool base64,
	u32 ce); /* DCE_PROCESS_CE_* value */

/**
 * fsl_dce_stream_inflate_params - set inflate options
 *
 * @stream: object to set options in
 * @bman_output_offset: when using bman output start at an offset.
 * @bman_release_input: release input frame to bman
 * @base64: use base64 (de)coding
 *
 * Returns 0 on success
 */
int fsl_dce_stream_inflate_params(struct fsl_dce_stream *stream,
	u32 bman_output_offset,
	bool bman_release_input,
	bool base64);

/**
 * fsl_dce_stream_process - de(compression) the input frame via DCE PROCESS
 *
 * @stream: object to send process request
 * @flags: (currently not used)
 * @fd: frame descriptor to enqueue
 * @initial_frame: set to true if this is the first frame of a stream.
 *	Causes the I bit to be set in the PROCESS request.
 * @z_flush: possible values are DCE_PROCESS_Z_* values.
 * @callback_tag: optional, returned to the caller in the associated callback
 *	function.
 *
 * Returns 0 on success
 */
int fsl_dce_stream_process(struct fsl_dce_stream *stream,
	u32 flags,
	struct qm_fd *fd,
	bool initial_frame,
	int z_flush,
	void *callback_tag);

/**
 * fsl_dce_stream_nop - send a DCE NOP request
 *
 * @stream: object to send request
 * @flags: (currently not used)
 * @callback_tag: optional, returned to the caller in the associated callback
 *	function.
 *
 * Returns 0 on success
 */
int fsl_dce_stream_nop(struct fsl_dce_stream *stream, u32 flags,
	void *callback_tag); /* optional callback tag */

int fsl_dce_stream_scr_invalidate(struct fsl_dce_stream *stream,
	u32 flags, void *callback_tag);


/* helper apis */
int fsl_dce_stream_init_scr(struct fsl_dce_stream *stream, struct qm_fd *fd,
	void *callback_tag);
void fsl_dce_attach_3mbr_sgtable_2_fd(struct qm_sg_entry sg_table[3],
					struct qm_fd *fd);
void fsl_dce_attach_scf_128b_2_3mbr_sgtable(struct scf_128b *scf,
	struct qm_sg_entry sg_table[3]);
void fsl_dce_attach_scf_64b_2_3mbr_sgtable(struct scf_64b *scf,
	struct qm_sg_entry sg_table[3]);
void fsl_dce_build_scf_uspc(struct fsl_dce_stream *stream, struct scf_64b *scf);

#endif /* FSL_DCE_STREAM_H */
