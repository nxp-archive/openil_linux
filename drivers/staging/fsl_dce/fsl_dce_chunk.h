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

/*
 *  DCE chunk is a stateless compressor/decompressor object. Each Frame which
 *  is compressed/decompressed is one complete work item and doesn't depend
 *  on previous Frames. As an example a Frame should be considered as one
 *  complete file.
 */
struct fsl_dce_chunk {
	struct fsl_dce_flow flow;

	enum dce_compression_format cf; /* deflate, zlib or gzip */
	/* optional BMan output settings */
	bool use_bman_output;
	uint32_t flags; /* internal state */
	spinlock_t lock;
	wait_queue_head_t queue;
};

int fsl_dce_chunk_setup2(struct fsl_dce_chunk *chunk,
	uint32_t flags,
	enum dce_mode mode,
	enum dce_compression_format cf,
	struct dce_bman_cfg *bcfg,
	fsl_dce_process_cb process_cb,
	fsl_dce_nop_cb nop_cb);

int fsl_dce_chunk_fifo_len(struct fsl_dce_chunk *chunk);

int fsl_dce_chunk_destroy(struct fsl_dce_chunk *chunk, uint32_t flags,
			void *callback_tag);

int fsl_dce_chunk_deflate_params(struct fsl_dce_chunk *chunk,
	uint32_t bman_output_offset,
	bool bman_release_input,
	bool base64,
	uint32_t ce); /* DCE_PROCESS_CE_* value */

int fsl_dce_chunk_inflate_params(struct fsl_dce_chunk *chunk,
	uint32_t bman_output_offset,
	bool bman_release_input,
	bool base64);

int fsl_dce_chunk_process(struct fsl_dce_chunk *chunk, uint32_t flags,
	struct qm_fd *fd, void *callback_tag); /* optional callback tag */

int fsl_dce_chunk_nop(struct fsl_dce_chunk *chunk, uint32_t flags,
	void *callback_tag); /* optional callback tag */

#endif /* FSL_DCE_CHUNK_H */
