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

#include <linux/vmalloc.h>
#include "../../dce_sys.h"
#include "../../fsl_dce_chunk.h"
#include "../../flib/dce_helper.h"

#include "../common/bible.txt.128k.h"
#include "../common/bible.txt.64k.h"
#include "../common/bible.txt.32k.h"
#include "../common/bible.txt.16k.h"
#include "../common/bible.txt.8k.h"
#include "../common/bible.txt.4k.h"
#include "../common/bible.txt.2k.h"
#include "../common/bible.txt.1k.h"
#include "../common/bible.txt.128b.h"
#include "../common/test_frame_helpers.h"

MODULE_AUTHOR("Jeffrey Ladouceur");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("FSL DCE test: stateless trunc deflate compoundframes");

static int block_size = 4096;
static int verbose_level; /* 0 low, 1 high */

module_param(block_size, int, 0);
module_param(verbose_level, int, 0);

static void chunk_process_cb(struct fsl_dce_flow *flow,
		const struct qm_fd *fd, void *callback_tag)
{
	struct dce_process_cf_req *req =
		(struct dce_process_cf_req *)callback_tag;

	pr_info("fsl_dce_chunk_process_cb flow = %p, fd = %p, cb_tab = %p\n",
		flow, fd, callback_tag);

	req->output_fd = *fd;
	complete(&req->cb_done);

}

static void chunk_nop_cb(struct fsl_dce_flow *flow,
		const struct qm_fd *fd, void *callback_tag)
{
	struct dce_nop_req *nop_req = (struct dce_nop_req *)callback_tag;
	pr_info("fsl_dce_chunk_nop_cb flow = %p, fd = %p, cb_tab = %p\n",
		flow, fd, callback_tag);

	nop_req->output_fd = *fd;
	complete(&nop_req->cb_done);
}

struct dce_test_ctx {
	struct fsl_dce_chunk deflate_chunk;
	struct fsl_dce_chunk inflate_chunk;
};

static int destroy_test_ctx(struct dce_test_ctx *ctx)
{
	int ret;

	ret = fsl_dce_chunk_destroy(&ctx->deflate_chunk, 0, NULL);
	if (ret) {
		BUG();
		return ret;
	}
	ret = fsl_dce_chunk_destroy(&ctx->inflate_chunk, 0, NULL);
	if (ret) {
		BUG();
		return ret;
	}
	return 0;
}



static int init_test_ctx(struct dce_test_ctx *ctx,
		enum dce_compression_format format)
{
	int ret, ret_fail;
	u32 flags = 0;

	/* initialize a compression deflate stream */
	ret = fsl_dce_chunk_setup2(&ctx->deflate_chunk, flags,
		DCE_COMPRESSION, format, NULL, chunk_process_cb, chunk_nop_cb);

	if (ret) {
		BUG();
		goto fail_deflate_setup;
	}

	ret = fsl_dce_chunk_deflate_params(&ctx->deflate_chunk,
		DCE_PROCESS_OO_NONE_LONG, false, false,
		DCE_PROCESS_CE_BEST_POSSIBLE);

	if (ret) {
		BUG();
		goto fail_deflate_params;
	}

	/* initialize a decompression deflate stream */
	ret = fsl_dce_chunk_setup2(&ctx->inflate_chunk, flags,
		DCE_DECOMPRESSION, format, NULL, chunk_process_cb,
		chunk_nop_cb);

	if (ret) {
		BUG();
		goto fail_inflate_setup;
	}

	ret = fsl_dce_chunk_inflate_params(&ctx->inflate_chunk,
		DCE_PROCESS_OO_NONE_LONG, false, false);

	if (ret) {
		BUG();
		goto fail_inflate_params;
	}

	return 0;

fail_inflate_params:
	ret_fail = fsl_dce_chunk_destroy(&ctx->inflate_chunk, 0, NULL);
	BUG_ON(ret_fail);
fail_inflate_setup:
fail_deflate_params:
	ret_fail = fsl_dce_chunk_destroy(&ctx->deflate_chunk, 0, NULL);
	BUG_ON(ret_fail);
fail_deflate_setup:
	return ret;
}


static int do_test(struct dce_test_ctx *ctx,
		enum dce_compression_format format,
		char *input_data, size_t input_len, size_t block_len,
		size_t output_len)
{
	int ret;
	struct dce_process_cf_req *def_process_req, *inf_process_req;
	struct dce_nop_req *nop_req;

	pr_info("do_test: format %d input_len %zu\n", format, input_len);
	pr_info("  block_len %zu, output_len %zu\n", block_len, output_len);

	ret = init_test_ctx(ctx, format);
	if (ret)
		goto fail_init_test_ctx;

	nop_req = kmalloc(sizeof(*nop_req), GFP_KERNEL);
	if (!nop_req) {
		ret = -ENOMEM;
		goto fail_nop;
	}

	init_completion(&nop_req->cb_done);

	/* send a nop cmd */
	ret = fsl_dce_chunk_nop(&ctx->deflate_chunk, 0, nop_req);
	if (ret) {
		BUG();
		goto fail_nop;
	}
	pr_info("Sent NOP on deflate path\n");

	wait_for_completion(&nop_req->cb_done);

	pr_info("Got NOP on deflate path\n");

	ret = fsl_dce_chunk_nop(&ctx->inflate_chunk, 0, nop_req);
	if (ret) {
		BUG();
		goto fail_nop;
	}
	pr_info("Sent NOP on inflate path\n");

	wait_for_completion(&nop_req->cb_done);

	pr_info("Got NOP on inflate path\n");

	/* Perform a deflate operation */

	def_process_req = kzalloc(sizeof(*def_process_req), GFP_KERNEL);
	if (!def_process_req) {
		BUG();
		ret = -ENOMEM;
		goto fail_nop;
	}
	pr_info("Allocated def_process_req\n");

	def_process_req->v_output = vmalloc(output_len);
	if (!def_process_req->v_output) {
		BUG();
		ret = -ENOMEM;
		goto fail_deflate_v_output;
	}

	init_completion(&def_process_req->cb_done);

	ret = alloc_dce_data(input_len, block_len,
		&def_process_req->input_data);
	if (ret) {
		BUG();
		goto fail_deflate_alloc_dce_data_input;
	}

	if (verbose_level == 1) {
		pr_info("Printing input_list info\n");
		print_dce_data_list(&def_process_req->input_data);
	}

	ret = alloc_dce_data(output_len, block_len,
		&def_process_req->output_data);
	if (ret) {
		BUG();
		goto fail_deflate_alloc_dce_data_output;
	}

	if (verbose_level == 1) {
		pr_info("Printing output_list info\n");
		print_dce_data_list(&def_process_req->output_data);
	}

	ret = copy_input_to_dce_data(input_data, input_len,
					&def_process_req->input_data);
	if (ret) {
		BUG();
		goto fail_deflate_copy_input_to_dce_data;
	}

	if (verbose_level == 1) {
		pr_info("Printing input after copy info\n");
		print_dce_data_list(&def_process_req->input_data);
	}

	ret = dma_map_dce_data(&def_process_req->input_data, DMA_BIDIRECTIONAL);
	if (ret) {
		BUG();
		goto fail_deflate_dma_map_dce_data_input;
	}

	if (verbose_level == 1) {
		pr_info("Printing input after dma_map info\n");
		print_dce_data_list(&def_process_req->input_data);
	}

	ret = dma_map_dce_data(&def_process_req->output_data,
				DMA_BIDIRECTIONAL);
	if (ret) {
		BUG();
		goto fail_deflate_dma_map_dce_data_output;
	}

	if (verbose_level == 1) {
		pr_info("Printing output after dma_map info\n");
		print_dce_data_list(&def_process_req->output_data);
	}

	ret = attach_data_list_to_sg(&def_process_req->dce_cf[0],
			&def_process_req->output_data, true,
			DMA_BIDIRECTIONAL);
	if (ret) {
		BUG();
		goto fail_deflate_attach_data_list_to_sg_output;
	}

	ret = attach_data_list_to_sg(&def_process_req->dce_cf[1],
			&def_process_req->input_data, false,
			DMA_BIDIRECTIONAL);
	if (ret) {
		BUG();
		goto fail_deflate_attach_data_list_to_sg_input;
	}

	def_process_req->dce_cf[2].final = 1;

	def_process_req->input_fd._format2 = qm_fd_compound;
	def_process_req->input_fd.cong_weight = 1;
	qm_fd_addr_set64(&def_process_req->input_fd,
	fsl_dce_map(def_process_req->dce_cf));

	print_dce_fd(def_process_req->input_fd);
	print_dce_sg(def_process_req->dce_cf[0]);
	print_dce_sg(def_process_req->dce_cf[1]);
	print_dce_sg(def_process_req->dce_cf[2]);

	ret = fsl_dce_chunk_process(&ctx->deflate_chunk, 0,
		&def_process_req->input_fd, def_process_req);

	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_deflate_process;
	}

	wait_for_completion(&def_process_req->cb_done);

	if (fsl_dce_get_status(def_process_req->output_fd.status) !=
			STREAM_END) {
		pr_err("Error expected STREAM_END result but got %d\n",
			fsl_dce_get_status(def_process_req->output_fd.status));
		ret = -EINVAL;
		goto fail_deflate_process;
	}

	pr_info("Output FD\n");
	print_dce_fd(def_process_req->output_fd);

	ret = detach_data_list_from_sg(&def_process_req->dce_cf[1],
			&def_process_req->input_data, DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_deflate_attach_data_list_to_sg_input;
	}

	ret = detach_data_list_from_sg(&def_process_req->dce_cf[0],
			&def_process_req->output_data, DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_deflate_attach_data_list_to_sg_output;
	}

	ret = dma_unmap_dce_data(&def_process_req->output_data,
				DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_deflate_dma_map_dce_data_output;
	}

	ret = dma_unmap_dce_data(&def_process_req->input_data,
				DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_deflate_dma_map_dce_data_input;
	}

	pr_info("Got chunk process, status = %d, sg_table[0].length = %d\n",
		def_process_req->output_fd.status,
		def_process_req->dce_cf[0].length);

	print_dce_sg(def_process_req->dce_cf[0]);

	if (verbose_level == 1)
		print_dce_data_list(&def_process_req->output_data);

	/* Save Output */
	pr_info("Saving output\n");
	pr_info("Output length is %u\n", def_process_req->dce_cf[0].length);

	def_process_req->v_output = vmalloc(def_process_req->dce_cf[0].length);
	if (!def_process_req->v_output) {
		pr_err("Error %d\n", __LINE__);
		ret = -ENOMEM;
		goto fail_deflate_copy_input_to_dce_data;
	}

	def_process_req->v_output_size = def_process_req->dce_cf[0].length;

	ret = copy_output_dce_data_to_buffer(&def_process_req->output_data,
		def_process_req->v_output_size,
		def_process_req->v_output, def_process_req->v_output_size);

	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_deflate_copy_input_to_dce_data;
	}

	/* Free dce data deflate operation, but keep vmalloc output */
	free_dce_data(&def_process_req->output_data);
	free_dce_data(&def_process_req->input_data);

	/********** Now inflate the data ************/

	inf_process_req = kzalloc(sizeof(*inf_process_req), GFP_KERNEL);
	if (!inf_process_req) {
		pr_err("Error %d\n", __LINE__);
		ret = -ENOMEM;
		goto fail_inflate_params;
	}
	pr_info("Allocated inf_process_req\n");

	inf_process_req->v_output = vmalloc(input_len);
	if (!inf_process_req->v_output) {
		pr_err("Error %d\n", __LINE__);
		ret = -ENOMEM;
		goto fail_inflate_v_output;
	}

	init_completion(&inf_process_req->cb_done);

	/* Copy the previous output as input */
	ret = alloc_dce_data(def_process_req->v_output_size, block_len,
		&inf_process_req->input_data);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_alloc_dce_data_input;
	}

	if (verbose_level == 1) {
		pr_info("Printing input_list info\n");
		print_dce_data_list(&inf_process_req->input_data);
	}

	ret = alloc_dce_data(input_len, block_len,
			&inf_process_req->output_data);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_alloc_dce_data_output;
	}

	if (verbose_level == 1) {
		pr_info("Printing output_list info\n");
		print_dce_data_list(&inf_process_req->output_data);
	}

	ret = copy_input_to_dce_data(def_process_req->v_output,
		def_process_req->v_output_size, &inf_process_req->input_data);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_copy_input_to_dce_data;
	}

	if (verbose_level == 1) {
		pr_info("Printing inflate input after copy info\n");
		print_dce_data_list(&inf_process_req->input_data);
	}

	ret = dma_map_dce_data(&inf_process_req->input_data, DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_dma_map_dce_data_input;
	}

	if (verbose_level == 1) {
		pr_info("Printing input after dma_map info\n");
		print_dce_data_list(&inf_process_req->input_data);
	}

	ret = dma_map_dce_data(&inf_process_req->output_data,
				DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_dma_map_dce_data_output;
	}

	if (verbose_level == 1) {
		pr_info("Printing output after dma_map info\n");
		print_dce_data_list(&inf_process_req->output_data);
	}

	ret = attach_data_list_to_sg(&inf_process_req->dce_cf[0],
			&inf_process_req->output_data, true, DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_attach_data_list_to_sg_output;
	}

	ret = attach_data_list_to_sg(&inf_process_req->dce_cf[1],
			&inf_process_req->input_data, false, DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_attach_data_list_to_sg_input;
	}

	inf_process_req->dce_cf[2].final = 1;

	inf_process_req->input_fd._format2 = qm_fd_compound;
	qm_fd_addr_set64(&inf_process_req->input_fd,
	fsl_dce_map(inf_process_req->dce_cf));

	print_dce_fd(inf_process_req->input_fd);
	print_dce_sg(inf_process_req->dce_cf[0]);
	print_dce_sg(inf_process_req->dce_cf[1]);
	print_dce_sg(inf_process_req->dce_cf[2]);

	fsl_dce_chunk_process(&ctx->inflate_chunk, 0,
		&inf_process_req->input_fd, inf_process_req);

	wait_for_completion(&inf_process_req->cb_done);

	pr_info("Output FD\n");
	print_dce_fd(inf_process_req->output_fd);

	ret = detach_data_list_from_sg(&inf_process_req->dce_cf[1],
			&inf_process_req->input_data, DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_attach_data_list_to_sg_input;
	}

	ret = detach_data_list_from_sg(&inf_process_req->dce_cf[0],
			&inf_process_req->output_data, DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_attach_data_list_to_sg_output;
	}

	ret = dma_unmap_dce_data(&inf_process_req->output_data,
				DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_dma_map_dce_data_output;
	}

	ret = dma_unmap_dce_data(&inf_process_req->input_data,
				DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_dma_map_dce_data_input;
	}

	pr_info("Got chunk process, status = 0x%x, sg_table[0].length = %d\n",
		inf_process_req->output_fd.status,
		inf_process_req->dce_cf[0].length);

	if (inf_process_req->dce_cf[0].length != input_len) {
		pr_err("Error %d\n", __LINE__);
		ret = -EINVAL;
		goto fail_inflate_copy_input_to_dce_data;
	}

	print_dce_sg(inf_process_req->dce_cf[0]);

	inf_process_req->v_output = vmalloc(inf_process_req->dce_cf[0].length);

	if (!inf_process_req->v_output) {
		pr_err("Error %d\n", __LINE__);
		ret = -ENOMEM;
		goto fail_inflate_copy_input_to_dce_data;
	}
	inf_process_req->v_output_size = inf_process_req->dce_cf[0].length;

	ret = copy_output_dce_data_to_buffer(&inf_process_req->output_data,
		inf_process_req->v_output_size, inf_process_req->v_output,
		input_len);
	if (ret) {
		pr_err("Error %d\n", __LINE__);
		goto fail_inflate_copy_input_to_dce_data;
	}
	/* compare output to original data */
	if (memcmp(inf_process_req->v_output, input_data, input_len)) {
		pr_err("Error %d\n", __LINE__);
		ret = -EINVAL;
		goto fail_inflate_copy_input_to_dce_data;
	}
	pr_info("Output inflate data matched original!\n");

	/* Free dce data deflate operation, but keep vmalloc output */
	free_dce_data(&inf_process_req->output_data);
	free_dce_data(&inf_process_req->input_data);

	vfree(inf_process_req->v_output);
	vfree(def_process_req->v_output);
	kfree(inf_process_req);
	kfree(def_process_req);

	ret = destroy_test_ctx(ctx);
	if (ret) {
		pr_err("Error with test\n");
		return ret;
	}

	pr_info("Done test loop\n");

	return 0;

fail_deflate_process:
	detach_data_list_from_sg(&def_process_req->dce_cf[1],
		&def_process_req->input_data,
		DMA_BIDIRECTIONAL);

fail_deflate_attach_data_list_to_sg_input:
	detach_data_list_from_sg(&def_process_req->dce_cf[0],
		&def_process_req->output_data,
		DMA_BIDIRECTIONAL);

fail_deflate_attach_data_list_to_sg_output:
	dma_unmap_dce_data(&def_process_req->output_data, DMA_BIDIRECTIONAL);

fail_deflate_dma_map_dce_data_output:
	dma_unmap_dce_data(&def_process_req->input_data, DMA_BIDIRECTIONAL);

fail_deflate_dma_map_dce_data_input:
fail_deflate_copy_input_to_dce_data:
	free_dce_data(&def_process_req->output_data);

fail_deflate_alloc_dce_data_output:
	free_dce_data(&def_process_req->input_data);

fail_deflate_alloc_dce_data_input:
	vfree(def_process_req->v_output);

fail_deflate_v_output:
	kfree(def_process_req);

fail_nop:
	destroy_test_ctx(ctx);

fail_init_test_ctx:
	return ret;

/* this section can't be added before deflate fail section
as it would cause seg fault */
fail_inflate_process:
	detach_data_list_from_sg(&inf_process_req->dce_cf[1],
		&inf_process_req->input_data,
		DMA_BIDIRECTIONAL);

fail_inflate_attach_data_list_to_sg_input:
	detach_data_list_from_sg(&inf_process_req->dce_cf[0],
		&inf_process_req->output_data,
		DMA_BIDIRECTIONAL);

fail_inflate_attach_data_list_to_sg_output:
	dma_unmap_dce_data(&inf_process_req->output_data, DMA_BIDIRECTIONAL);

fail_inflate_dma_map_dce_data_output:
	dma_unmap_dce_data(&inf_process_req->input_data, DMA_BIDIRECTIONAL);

fail_inflate_dma_map_dce_data_input:
fail_inflate_copy_input_to_dce_data:
	free_dce_data(&inf_process_req->output_data);

fail_inflate_alloc_dce_data_output:
	free_dce_data(&inf_process_req->input_data);

fail_inflate_alloc_dce_data_input:
	vfree(inf_process_req->v_output);

fail_inflate_v_output:
	kfree(inf_process_req);

fail_inflate_params:
	destroy_test_ctx(ctx);
	return ret;
}

struct test_meta_info_t {
	char *data;
	unsigned int len;
};

static int compression_stateless_truncation_deflate_compoundframes_init(void)
{
	int ret, i;
	struct dce_test_ctx *test_ctx;
	struct cpumask backup_mask = current->cpus_allowed;
	struct cpumask new_mask = *qman_affine_cpus();

	struct test_meta_info_t test_meta_info_array[] = {
		{
		.data = bible_txt_128k,
		.len = bible_txt_128k_len
		},
		{
		.data = bible_txt_64k,
		.len = bible_txt_64k_len
		},
		{
		.data = bible_txt_32k,
		.len = bible_txt_32k_len
		},
		{
		.data = bible_txt_16k,
		.len = bible_txt_16k_len
		},
		{
		.data = bible_txt_8k,
		.len = bible_txt_8k_len
		},
		{
		.data = bible_txt_4k,
		.len = bible_txt_4k_len
		},
		{
		.data = bible_txt_2k,
		.len = bible_txt_2k_len
		},
		{
		.data = bible_txt_1k,
		.len = bible_txt_1k_len
		},
		{
		.data = bible_txt_128b,
		.len = bible_txt_128b_len
		},
	};

	pr_info("DCE TEST Start, cpu_mask = %*pb[l]\n",
		cpumask_pr_args(&new_mask));

	/* need to control on which cpu this module runs on */
	test_ctx = kzalloc(sizeof(*test_ctx), GFP_KERNEL);
	if (!test_ctx) {
		pr_err("DCE Test, no memory\n");
		return -ENOMEM;
	}

	/* Only run on cpus that have qman and bman portals */
	cpumask_and(&new_mask, &new_mask, bman_affine_cpus());
	ret = set_cpus_allowed_ptr(current, &new_mask);
	if (ret) {
		pr_err("DCE: test high: can't set cpumask\n");
		goto fail_test;
	}

	for (i = 0; i < ARRAY_SIZE(test_meta_info_array); i++) {

		pr_info("DCE init test: input size: %d, block len %d\n",
			test_meta_info_array[i].len, block_size);

		ret = do_test(test_ctx, DCE_CF_DEFLATE,
			test_meta_info_array[i].data,
			test_meta_info_array[i].len, block_size,
			test_meta_info_array[i].len + 512);
		if (ret) {
			pr_err("Error %d\n", __LINE__);
			goto fail_test;
		}
	}

	pr_info("DCE TEST FINISHED SUCCESS\n");

fail_test:

	ret = set_cpus_allowed_ptr(current, &backup_mask);
	if (ret)
		pr_err("DCE test high: can't restore cpumask");
	kfree(test_ctx);

	return ret;
}

static void compression_stateless_truncation_deflate_compoundframes_exit(void)
{
}

module_init(compression_stateless_truncation_deflate_compoundframes_init);
module_exit(compression_stateless_truncation_deflate_compoundframes_exit);

