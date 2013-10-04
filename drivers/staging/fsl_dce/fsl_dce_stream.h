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

/* DCE stream is a stateful compressor/decompressor object */
struct fsl_dce_stream {
	struct fsl_dce_flow flow;

	enum dce_compression_format cf; /* deflate, zlib or gzip */
	enum dce_processing_mode pmode; /* recycle, trunc */

	/* optional BMan output settings */
	bool use_bman_output;
	uint32_t process_params; /* inflate, deflate parameters */

	/* hw dma scr structure */
	union {
		struct fsl_dce_hw_scr_64b *hw_comp_scr;
		struct fsl_dce_hw_scr_128b *hw_decomp_scr;
	};

	/*
	 * history window
	 *	decompression: 32k size 64B aligned
	 *	compression: 4k size, 64B aligned
	 */
	union {
		struct fsl_dce_hw_compress_history *comp_hist;
		struct fsl_dce_hw_decompress_history *decomp_hist;
	};

	/*
	 * Pending Ouput Data
	 * decomp: 8256 bytes, comp: 8202. No hard requirement on alignment,
	 * but 64 is optimal. Only needed in recycle mode.
	 */
	struct fsl_dce_hw_pending_output *pending_output_ptr;

	/*
	 *  Decompression Context Pointer, used to store the alphabet
	 *  This is a 256 byte buffer with no alignment requirement
	 */
	struct fsl_dce_hw_decomp_ctxt *decomp_ctx_ptr;

	uint32_t flags; /* internal state */
	spinlock_t lock;
	wait_queue_head_t queue;
};
/**
 * fsl_dce_stream_setup - setup for dce stream object
 * @stream:
 * @mode:
 * @cf:
 *
 * Simple dce stream setup function
 */
int fsl_dce_stream_setup(struct fsl_dce_stream *stream,
	uint32_t flags,
	enum dce_mode mode,
	enum dce_compression_format cf,
	fsl_dce_process_cb process_cb,
	fsl_dce_nop_cb nop_cb,
	fsl_dce_scr_invalidate_cb scr_invalidate_cb);

/**
 * fsl_dce_stream_setup2 - Advanced setup for dce stream object
 * @stream:
 * @mode:
 * @cf:
 * @pmode:
 * @bcfg
 *
 * Advanced dce stream setup function.
 * A dce_stream in DCE HW terminology is an object which is able to perform
 * statful (de)compression in either recycle or truncation processing mode.
 * In recycle mode, only synchronous processing is permitted and therefore
 * a fifo_depth of 1 is only permitted.
 */
int fsl_dce_stream_setup2(struct fsl_dce_stream *stream,
	uint32_t flags,
	enum dce_mode mode,
	enum dce_compression_format cf,
	enum dce_processing_mode pmode,
	struct dce_bman_cfg *bcfg,
	fsl_dce_process_cb process_cb,
	fsl_dce_nop_cb nop_cb,
	fsl_dce_scr_invalidate_cb scr_invalidate_cb);

int fsl_dce_stream_fifo_len(struct fsl_dce_stream *stream);

int fsl_dce_stream_destroy(struct fsl_dce_stream *stream, uint32_t flags,
			void *callback_tag);

int fsl_dce_stream_deflate_params(struct fsl_dce_stream *stream,
	uint32_t bman_output_offset,
	bool bman_release_input,
	bool base64,
	uint32_t ce); /* DCE_PROCESS_CE_* value */

int fsl_dce_stream_inflate_params(struct fsl_dce_stream *stream,
	uint32_t bman_output_offset,
	bool bman_release_input,
	bool base64);

/*
 * This is the mission mode api.
 */
int fsl_dce_stream_process(struct fsl_dce_stream *stream,
	uint32_t flags,
	struct qm_fd *fd,
	bool initial_frame, /* if initial frame, sets I bit */
	int z_flush, /* one of DCE_PROCESS_Z_* values */
	void *callback_tag); /* optional callback tag */

int fsl_dce_stream_nop(struct fsl_dce_stream *stream, uint32_t flags,
	void *callback_tag); /* optional callback tag */

int fsl_dce_stream_scr_invalidate(struct fsl_dce_stream *stream,
	uint32_t flags, void *callback_tag);


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
