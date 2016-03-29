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
#include "fsl_dce_chunk.h"

#define DCE_FIFO_DEPTH	256

static void chunk_base_cb(struct fsl_dce_flow *flow, const struct qm_fd *fd,
			void *callback_tag)
{
	if (likely(ISEQ_32FTK(fd->cmd, DCE_CMD, PROCESS)))
		flow->cbs.process_cb(flow, fd, callback_tag);
	else if (ISEQ_32FTK(fd->cmd, DCE_CMD, CTX_INVALIDATE))
		flow->cbs.scr_invalidate_cb(flow, fd, callback_tag);
	else if (ISEQ_32FTK(fd->cmd, DCE_CMD, NOP))
		flow->cbs.nop_cb(flow, fd, callback_tag);
}

int fsl_dce_chunk_setup2(struct fsl_dce_chunk *chunk,
	u32 flags,
	enum dce_mode mode,
	enum dce_compression_format cf,
	struct dce_bman_cfg *bcfg,
	fsl_dce_process_cb process_cb,
	fsl_dce_nop_cb nop_cb)
{
	int ret = 0;
	struct fsl_dce_flow_init_params flow_params;

	if (!chunk)
		return -EINVAL;

	memset(&flow_params, 0, sizeof(flow_params));
	memset(chunk, 0, sizeof(*chunk));

	chunk->cf = cf;

	/* QMan frame queue ids will be allocated */
	if (bcfg)
		fsl_dce_flow_setopt_bcfg(&chunk->flow, *bcfg);
	flow_params.mode = mode;
	flow_params.fifo_depth = DCE_FIFO_DEPTH;
	flow_params.state_config = DCE_STATELESS;
	flow_params.base_cb = chunk_base_cb;
	flow_params.process_cb = process_cb;
	flow_params.nop_cb = nop_cb;
	ret = fsl_dce_flow_init(&chunk->flow, &flow_params);
	if (ret) {
		pr_debug("dce_chunk: err ret = %d\n", ret);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL(fsl_dce_chunk_setup2);

int fsl_dce_chunk_fifo_len(struct fsl_dce_chunk *chunk)
{
	return fsl_dce_flow_fifo_len(&chunk->flow);
}
EXPORT_SYMBOL(fsl_dce_chunk_fifo_len);


int fsl_dce_chunk_destroy(struct fsl_dce_chunk *chunk, u32 flags,
			void *callback_tag)
{
	return fsl_dce_flow_finish(&chunk->flow, flags);
}
EXPORT_SYMBOL(fsl_dce_chunk_destroy);


int fsl_dce_chunk_process(struct fsl_dce_chunk *chunk, u32 flags,
			struct qm_fd *fd, void *callback_tag)
{
	if (chunk->cf == DCE_CF_ZLIB)
		SET_BF32_TK(fd->cmd, DCE_PROCESS_CF, ZLIB);
	else if (chunk->cf == DCE_CF_GZIP)
		SET_BF32_TK(fd->cmd, DCE_PROCESS_CF, GZIP);

	/* Bug 15470 */
	SET_BF32_TK(fd->cmd, DCE_PROCESS_Z_FLUSH, FINISH);

	/* Bug 14479, see 14477, must set UHC for gzip/zlib */
	SET_BF32_TK(fd->cmd, DCE_PROCESS_UHC, YES);
	return fsl_dce_process(&chunk->flow, flags, fd, callback_tag);
}
EXPORT_SYMBOL(fsl_dce_chunk_process);

int fsl_dce_chunk_nop(struct fsl_dce_chunk *chunk, u32 flags,
	void *callback_tag)
{
	return fsl_dce_nop(&chunk->flow, flags, callback_tag);
}
EXPORT_SYMBOL(fsl_dce_chunk_nop);

int fsl_dce_chunk_deflate_params(struct fsl_dce_chunk *chunk,
	u32 bman_output_offset,
	bool bman_release_input,
	bool base64,
	u32 ce)
{
	fsl_dce_flow_setopt_outputoffset(&chunk->flow, bman_output_offset);
	fsl_dce_flow_setopt_release_input(&chunk->flow, bman_release_input);
	fsl_dce_flow_setopt_base64(&chunk->flow, base64);
	fsl_dce_flow_setopt_compression_effort(&chunk->flow, ce);
	return 0;
}
EXPORT_SYMBOL(fsl_dce_chunk_deflate_params);

int fsl_dce_chunk_inflate_params(struct fsl_dce_chunk *chunk,
	u32 bman_output_offset,
	bool bman_release_input,
	bool base64)
{
	fsl_dce_flow_setopt_outputoffset(&chunk->flow, bman_output_offset);
	fsl_dce_flow_setopt_release_input(&chunk->flow, bman_release_input);
	fsl_dce_flow_setopt_base64(&chunk->flow, base64);
	return 0;
}
EXPORT_SYMBOL(fsl_dce_chunk_inflate_params);

