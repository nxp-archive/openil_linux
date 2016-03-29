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

#include <linux/types.h>
#include <linux/err.h>
#include <linux/spinlock_types.h>
#include <linux/cpumask.h>
#include <linux/rbtree.h>
#include <linux/export.h>
#include "dce_private.h"
#include "fsl_dce_stream.h"

#define DCE_FIFO_DEPTH	256

static void stream_base_cb(struct fsl_dce_flow *flow, const struct qm_fd *fd,
			void *callback_tag)
{
	if (likely(ISEQ_32FTK(fd->cmd, DCE_CMD, PROCESS)))
		flow->cbs.process_cb(flow, fd, callback_tag);
	else if (ISEQ_32FTK(fd->cmd, DCE_CMD, CTX_INVALIDATE))
		flow->cbs.scr_invalidate_cb(flow, fd, callback_tag);
	else if (ISEQ_32FTK(fd->cmd, DCE_CMD, NOP))
		flow->cbs.nop_cb(flow, fd, callback_tag);
}

int fsl_dce_stream_setup(struct fsl_dce_stream *stream,
	u32 flags,
	enum dce_mode mode,
	enum dce_compression_format cf,
	fsl_dce_process_cb process_cb,
	fsl_dce_nop_cb nop_cb,
	fsl_dce_scr_invalidate_cb scr_invalidate_cb)
{
	return fsl_dce_stream_setup2(stream, flags, mode, cf,
		DCE_TRUNCATION, NULL, process_cb, nop_cb, scr_invalidate_cb);
}
EXPORT_SYMBOL(fsl_dce_stream_setup);

static int allocate_stateful_dma_resources(struct fsl_dce_stream *stream,
				enum dce_mode mode,
				enum dce_processing_mode pmode)
{
	int ret = -ENOMEM;

	if (mode == DCE_COMPRESSION) {
		stream->hw_comp_scr = fsl_dce_hw_scr_64b_new();
		if (!stream->hw_comp_scr)
			return ret;
		stream->comp_hist = fsl_dce_hw_compress_history_new();
		if (!stream->comp_hist)
			return ret;
		if (pmode == DCE_RECYCLING) {
			stream->pending_output_ptr =
				fsl_dce_hw_pending_output_new();
			if (!stream->pending_output_ptr)
				return ret;
		}
	} else {
		stream->hw_decomp_scr = fsl_dce_hw_scr_128b_new();
		if (!stream->hw_decomp_scr)
			return ret;
		stream->decomp_hist = fsl_dce_hw_decompress_history_new();
		if (!stream->decomp_hist)
			return ret;
		if (pmode == DCE_RECYCLING) {
			stream->pending_output_ptr =
				fsl_dce_hw_pending_output_new();
			if (!stream->pending_output_ptr)
				return ret;
		}
		stream->decomp_ctx_ptr = fsl_dce_hw_decomp_ctxt_new();
		if (!stream->decomp_ctx_ptr)
			return ret;
	}
	return 0;
}

static void free_stateful_dma_resources(struct fsl_dce_stream *stream,
				enum dce_mode mode,
				enum dce_processing_mode pmode)
{
	if (mode == DCE_COMPRESSION) {
		if (stream->hw_comp_scr)
			fsl_dce_hw_scr_64b_free(stream->hw_comp_scr);
		stream->comp_hist = fsl_dce_hw_compress_history_new();
		if (stream->comp_hist)
			fsl_dce_hw_compress_history_free(stream->comp_hist);
		if (pmode == DCE_RECYCLING) {
			stream->pending_output_ptr =
				fsl_dce_hw_pending_output_new();
			if (stream->pending_output_ptr)
				fsl_dce_hw_pending_output_free(
					stream->pending_output_ptr);
		}
	} else {
		if (stream->hw_decomp_scr)
			fsl_dce_hw_scr_128b_free(stream->hw_decomp_scr);
		if (stream->decomp_hist)
			fsl_dce_hw_decompress_history_free(stream->decomp_hist);
		if (pmode == DCE_RECYCLING) {
			stream->pending_output_ptr =
				fsl_dce_hw_pending_output_new();
			if (stream->pending_output_ptr)
				fsl_dce_hw_pending_output_free(
					stream->pending_output_ptr);
		}
		if (stream->decomp_ctx_ptr)
			fsl_dce_hw_decomp_ctxt_free(stream->decomp_ctx_ptr);
	}
}

void fsl_dce_build_scf_uspc(struct fsl_dce_stream *stream, struct scf_64b *scf)
{
	set_pending_output_ptr(scf, fsl_dce_map(stream->pending_output_ptr));
	if (stream->flow.mode == DCE_COMPRESSION)
		set_history_ptr(scf, fsl_dce_map(stream->comp_hist));
	else {
		set_history_ptr(scf, fsl_dce_map(stream->decomp_hist));
		set_decomp_ctxt_ptr(scf, fsl_dce_map(stream->decomp_ctx_ptr));
	}
	set_pmode(scf, stream->pmode);
}
EXPORT_SYMBOL(fsl_dce_build_scf_uspc);

void fsl_dce_attach_scf_64b_2_3mbr_sgtable(struct scf_64b *scf,
	struct qm_sg_entry sg_table[3])
{
	qm_sg_entry_set64(&sg_table[2], fsl_dce_map(scf));
	sg_table[2].length = sizeof(*scf);
	sg_table[2].final = 1;
}
EXPORT_SYMBOL(fsl_dce_attach_scf_64b_2_3mbr_sgtable);

void fsl_dce_attach_scf_128b_2_3mbr_sgtable(struct scf_128b *scf,
	struct qm_sg_entry sg_table[3])
{
	qm_sg_entry_set64(&sg_table[2], fsl_dce_map(scf));
	sg_table[2].length = sizeof(*scf);
	sg_table[2].final = 1;
}
EXPORT_SYMBOL(fsl_dce_attach_scf_128b_2_3mbr_sgtable);

void fsl_dce_attach_3mbr_sgtable_2_fd(struct qm_sg_entry sg_table[3],
					struct qm_fd *fd)
{
	qm_fd_addr_set64(fd, fsl_dce_map(sg_table));
	fd->format = qm_fd_compound;
}
EXPORT_SYMBOL(fsl_dce_attach_3mbr_sgtable_2_fd);

int fsl_dce_stream_setup2(struct fsl_dce_stream *stream,
	u32 flags,
	enum dce_mode mode,
	enum dce_compression_format cf,
	enum dce_processing_mode pmode,
	struct dce_bman_cfg *bcfg,
	fsl_dce_process_cb process_cb,
	fsl_dce_nop_cb nop_cb,
	fsl_dce_scr_invalidate_cb scr_invalidate_cb)
{
	int ret = 0;
	struct fsl_dce_flow_init_params flow_params;

	if (dce_ip_rev == DCE_REV10) {
		/* only truncation mode supported */
		if (pmode == DCE_RECYCLING) {
			pr_debug("dce: recyle mode unsupported dce rev 1.0\n");
			return -EINVAL;
		}
	}

	memset(&flow_params, 0, sizeof(flow_params));

	if (!stream)
		return -EINVAL;
	memset(stream, 0, sizeof(*stream));

	stream->pmode = pmode;
	stream->cf = cf;

	ret = allocate_stateful_dma_resources(stream, mode, pmode);
	if (ret) {
		free_stateful_dma_resources(stream, mode, pmode);
		return ret;
	}

	/* QMan frame queue ids will be allocated */
	if (bcfg)
		fsl_dce_flow_setopt_bcfg(&stream->flow, *bcfg);
	flow_params.mode = mode;
	flow_params.fifo_depth = DCE_FIFO_DEPTH;
	flow_params.state_config = DCE_STATEFUL;
	flow_params.base_cb = stream_base_cb;
	flow_params.process_cb = process_cb;
	flow_params.nop_cb = nop_cb;
	flow_params.scr_invalidate_cb = scr_invalidate_cb;
	if (mode == DCE_COMPRESSION)
		flow_params.scr =  fsl_dce_map(stream->hw_comp_scr);
	else
		flow_params.scr =  fsl_dce_map(stream->hw_decomp_scr);
	/* RECYCLE mode only supports sychronous mode */
	ret = fsl_dce_flow_init(&stream->flow, &flow_params);
	if (ret) {
		pr_debug("err ret=%d\n", ret);
		free_stateful_dma_resources(stream, mode, pmode);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL(fsl_dce_stream_setup2);

int fsl_dce_stream_fifo_len(struct fsl_dce_stream *stream)
{
	return fsl_dce_flow_fifo_len(&stream->flow);
}
EXPORT_SYMBOL(fsl_dce_stream_fifo_len);

int fsl_dce_stream_destroy(struct fsl_dce_stream *stream, u32 flags,
			void *callback_tag)
{
	int ret;

	ret = fsl_dce_flow_finish(&stream->flow, flags);
	if (!ret)
		free_stateful_dma_resources(stream, stream->flow.mode,
				stream->pmode);
	return 0;
}
EXPORT_SYMBOL(fsl_dce_stream_destroy);


int fsl_dce_stream_init_scr(struct fsl_dce_stream *stream, struct qm_fd *fd,
	void *callback_tag)
{
	SET_BF32_TK(fd->cmd, DCE_PROCESS_USPC, YES);
	return fsl_dce_process(&stream->flow, 0, fd, callback_tag);
}
EXPORT_SYMBOL(fsl_dce_stream_init_scr);

int fsl_dce_stream_process(struct fsl_dce_stream *stream, u32 flags,
	struct qm_fd *fd, bool initial_frame, int z_flush, void *callback_tag)
{
	if (stream->cf == DCE_CF_ZLIB)
		SET_BF32_TK(fd->cmd, DCE_PROCESS_CF, ZLIB);
	else if (stream->cf == DCE_CF_GZIP)
		SET_BF32_TK(fd->cmd, DCE_PROCESS_CF, GZIP);

	switch (z_flush) {
	case DCE_PROCESS_Z_FLUSH_NO_FLUSH:
	case DCE_PROCESS_Z_FLUSH_PARTIAL_FLUSH:
	case DCE_PROCESS_Z_FLUSH_SYNC_FLUSH:
	case DCE_PROCESS_Z_FLUSH_FULL_FLUSH:
	case DCE_PROCESS_Z_FLUSH_FINISH:
	case DCE_PROCESS_Z_FLUSH_BLOCK:
	case DCE_PROCESS_Z_FLUSH_TREES:
		SET_BF32(fd->cmd, DCE_PROCESS_Z_FLUSH, z_flush);
		break;
	default:
		return -EINVAL;
	}

	if (initial_frame)
		SET_BF32_TK(fd->cmd, DCE_PROCESS_INITIAL, SET);
	return fsl_dce_process(&stream->flow, flags, fd, callback_tag);
}
EXPORT_SYMBOL(fsl_dce_stream_process);

int fsl_dce_stream_nop(struct fsl_dce_stream *stream, u32 flags,
	void *callback_tag)
{
	return fsl_dce_nop(&stream->flow, flags, callback_tag);
}
EXPORT_SYMBOL(fsl_dce_stream_nop);

int fsl_dce_stream_scr_invalidate(struct fsl_dce_stream *stream, u32 flags,
	void *callback_tag)
{
	return fsl_dce_scr_invalidate(&stream->flow, flags, callback_tag);
}
EXPORT_SYMBOL(fsl_dce_stream_scr_invalidate);

int fsl_dce_stream_deflate_params(struct fsl_dce_stream *stream,
	u32 bman_output_offset,
	bool bman_release_input,
	bool base64,
	u32 ce)
{
	if (dce_ip_rev == DCE_REV10) {
		/* B64 unsupported */
		if (base64) {
			pr_debug("dce: base64 unsupported in dce rev 1.0\n");
			return -EINVAL;
		}
	}

	fsl_dce_flow_setopt_outputoffset(&stream->flow, bman_output_offset);
	fsl_dce_flow_setopt_release_input(&stream->flow, bman_release_input);
	fsl_dce_flow_setopt_base64(&stream->flow, base64);
	fsl_dce_flow_setopt_compression_effort(&stream->flow, ce);
	return 0;
}
EXPORT_SYMBOL(fsl_dce_stream_deflate_params);

int fsl_dce_stream_inflate_params(struct fsl_dce_stream *stream,
	u32 bman_output_offset,
	bool bman_release_input,
	bool base64)
{
	if (dce_ip_rev == DCE_REV10) {
		/* B64 unsupported */
		if (base64) {
			pr_debug("dce: base64 unsupported in dce rev 1.0\n");
			return -EINVAL;
		}
	}

	fsl_dce_flow_setopt_outputoffset(&stream->flow, bman_output_offset);
	fsl_dce_flow_setopt_release_input(&stream->flow, bman_release_input);
	fsl_dce_flow_setopt_base64(&stream->flow, base64);
	return 0;
}
EXPORT_SYMBOL(fsl_dce_stream_inflate_params);

