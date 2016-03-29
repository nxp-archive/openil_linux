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

#ifndef FSL_DCE_CHUNK_H
#define FSL_DCE_CHUNK_H

#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include "flib/dce_flow.h"

/**
 * struct fsl_dce_chunk - stateless (streamless)
 *
 * @flow: Underlining dce flib object which contains a pair of QMan frame
 *	queues.
 * @cf: The (de)compression format used for this flow. DCE_CF_DEFLATE,
 *	DCE_CF_ZLIB and DCE_CF_GZIP.
 * @use_bman_output: (currently not used) Use BMan buffers for output. Optional
 *	setting.
 * @flags: internal value
 * @lock: internal value
 * @queue: internal value
 *
 * DCE chunk is a stateless (de)compressor object. Each frame which is
 * (de)compressed is one complete work item and doesn't depend on previous
 * frames. For instance a frame should be considered as one complete file.
 */
struct fsl_dce_chunk {
	struct fsl_dce_flow flow;

	enum dce_compression_format cf;
	bool use_bman_output;
	/* internal state */
	u32 flags;
	spinlock_t lock;
	wait_queue_head_t queue;
};

/**
 * fsl_dce_chunk_setup2 - initialize a @chunk object for usage.
 * @chunk: object to initialize
 * @flags: (currently not used)
 * @mode: compression or decompression mode.
 * @cf: The (de)compression format used for this flow. DCE_CF_DEFLATE,
 *	DCE_CF_ZLIB and DCE_CF_GZIP.
 * @bcfg: optional bman configuration parameters.
 * @process_cb: callback function when PROCESS operations are performed.
 * @nop_cb: callback function when NOP operations are performed.
 *
 * This is another version of the @fsl_dce_chunk_setup with more options.
 *
 * Returns 0 on success
 */
int fsl_dce_chunk_setup2(struct fsl_dce_chunk *chunk,
	u32 flags,
	enum dce_mode mode,
	enum dce_compression_format cf,
	struct dce_bman_cfg *bcfg,
	fsl_dce_process_cb process_cb,
	fsl_dce_nop_cb nop_cb);

/**
 * fsl_dce_chunk_fifo_len - length of internal outstanding requests to send
 *
 * @chunk: the object to query against
 *
 * Returns the number of elements in the list
 */
int fsl_dce_chunk_fifo_len(struct fsl_dce_chunk *chunk);

/**
 * fsl_dce_chunk_destroy - terminates a chunk object and the underlining
 *	flow object.
 *
 * @chunk: object to destroy
 * @flags: (currently not used)
 * @callback_tag: (currently not used)
 *
 * Returns 0 on success
 */
int fsl_dce_chunk_destroy(struct fsl_dce_chunk *chunk, u32 flags,
			void *callback_tag);

/**
 * fsl_dce_chunk_deflate_params - set deflate options
 *
 * @chunk: object to set options in
 * @bman_output_offset: when using bman output start at an offset.
 * @bman_release_input: release input frame to bman
 * @base64: use base64 (de)coding
 * @ce: compression effort: DCE_PROCESS_CE_*
 *
 * Returns 0 on success
 */
int fsl_dce_chunk_deflate_params(struct fsl_dce_chunk *chunk,
	u32 bman_output_offset,
	bool bman_release_input,
	bool base64,
	u32 ce);

/**
 * fsl_dce_chunk_inflate_params - set inflate options
 *
 * @chunk: object to set options in
 * @bman_output_offset: when using bman output start at an offset.
 * @bman_release_input: release input frame to bman
 * @base64: use base64 (de)coding
 *
 * Returns 0 on success
 */
int fsl_dce_chunk_inflate_params(struct fsl_dce_chunk *chunk,
	u32 bman_output_offset,
	bool bman_release_input,
	bool base64);

/**
 * fsl_dce_chunk_process - de(compression) the input frame via DCE PROCESS
 *
 * @chunk: object to send process request
 * @flags: (currently not used)
 * @fd: frame descriptor to enqueue
 * @callback_tag: optional, returned to the caller in the associated callback
 *	function.
 *
 * Returns 0 on success
 */
int fsl_dce_chunk_process(struct fsl_dce_chunk *chunk, u32 flags,
	struct qm_fd *fd, void *callback_tag);

/**
 * fsl_dce_chunk_nop - send a DCE NOP request
 *
 * @chunk: object to send request
 * @flags: (currently not used)
 * @callback_tag: optional, returned to the caller in the associated callback
 *	function.
 *
 * Returns 0 on success
 */
int fsl_dce_chunk_nop(struct fsl_dce_chunk *chunk, u32 flags,
	void *callback_tag);

#endif /* FSL_DCE_CHUNK_H */
