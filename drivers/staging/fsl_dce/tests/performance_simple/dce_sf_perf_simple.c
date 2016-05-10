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
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/of.h>
#include <linux/cpufreq.h>
#include <sysdev/fsl_soc.h>
#include "../../fsl_dce.h"
#include "../../fsl_dce_stream.h"
#include "../../dce_sys.h"
#include "../../flib/dce_helper.h"
#include "../../flib/dce_gzip_helper.h"

#include "../common/test_frame_helpers.h"

#include "../common/paper5_2048.h"
#include "../common/paper5_4096.h"
#include "../common/paper5_8192.h"
#include "../common/paper5_11954.h"

#include "../common/paper6_2K_compressed.gz.h"
#include "../common/paper6_4K_compressed.gz.h"
#include "../common/paper6_8K_compressed.gz.h"
#include "../common/paper6_12K_compressed.gz.h"

MODULE_AUTHOR("Freescale Semiconductor, Inc");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("DCE stateful performance test");

static int test_mode;
module_param(test_mode, int, S_IRUGO);
MODULE_PARM_DESC(test_mode, "test_mode: 0 is compression, 1 is decompression (default=0)");

static int verbose_level; /* 0 low, 1 high */
module_param(verbose_level, int, 0);
MODULE_PARM_DESC(verbose_level, "verbosity level: 0 low, 1 is high (default=0)");

static int bman_output = 1;
module_param(bman_output, int, S_IRUGO);
MODULE_PARM_DESC(test_mode, "bman_output: 0 don't use Bman, 1 use Bman output (default=1)");

static int b_sg_block_size_code = DCE_TSIZE_4096B;
module_param(b_sg_block_size_code, int, S_IRUGO);
MODULE_PARM_DESC(b_sg_block_size_code, "Size of bman buffers used to create s/g tables (default=4096)");

/* This is used for actual kmalloc */
static int b_sg_block_size = 4096;

static int b_sg_block_count = 50;
module_param(b_sg_block_count, int, S_IRUGO);
MODULE_PARM_DESC(b_sg_block_count, "Number of s/g bman buffers to release (default=50)");

static int b_dexp = 12;
module_param(b_dexp, int, S_IRUGO);
MODULE_PARM_DESC(b_dexp, "Bman dexp value, default=12");
static int b_dmant = 1;
module_param(b_dmant, int, S_IRUGO);
MODULE_PARM_DESC(b_dmant, "Bman dmant value, default=1");

static u32 bman_data_buff_size;

static int block_size = 4096;
module_param(block_size, int, S_IRUGO);
MODULE_PARM_DESC(block_size, "Size of individual input data blocks in s/g  (default=4096)");

static int use_local_file;
module_param(use_local_file, int, S_IRUGO);
MODULE_PARM_DESC(use_local_file, "Use the included local header file for (de)compression. The value specifies the input size. Supported value are 0, 2, 4, 8, 12 (default=0)");

static int comp_effort = DCE_PROCESS_CE_STATIC_HUFF_STRMATCH;
module_param(comp_effort, int, S_IRUGO);
MODULE_PARM_DESC(comp_effort, "Compression Effort, default=1");

static char *in_file;
module_param(in_file, charp, 0000);
MODULE_PARM_DESC(in_file, "Input file to (de)compress");

static char *out_file;
module_param(out_file, charp, 0000);
MODULE_PARM_DESC(out_file, "Output file result of (de)compression");

static int comp_ratio = 4;
module_param(comp_ratio, int, S_IRUGO);
MODULE_PARM_DESC(comp_ratio, "The compresstion ratio to be used for allocated output data buffer");

static int output_size;
module_param(output_size, int, S_IRUGO);
MODULE_PARM_DESC(output_size, "The extra output size to allocate");

static int bman_data_size = 22000000;
module_param(bman_data_size, int, S_IRUGO);
MODULE_PARM_DESC(bman_data_size, "The size of the data buffer pool in bytes");

static int chunking_size = 4096;
module_param(chunking_size, int, S_IRUGO);
MODULE_PARM_DESC(chunking_size, "How much input bytes to send at a time");

static int b_data_block_count;

static int global_data_alloc;
static int global_data_free;
static int global_sg_alloc;
static int global_sg_free;

/* Break up data used for each channel to avoid contention for the
 * cache lines */
struct test_data_s {
	struct fsl_dce_stream ctx;

	int mode; /* compression, decompression */
	char *out_data;
	int  out_data_len;
	char *input_data;
	int  input_data_len;
	struct list_head request_list;
} __aligned(32);

static struct test_data_s *test_data;

static u64 start_time, end_time;

/* Loopback support */
static int do_operation(void);

/* Alternate Time Base */
#define SPR_ATBL	526
#define SPR_ATBU	527
static inline u64 mfatb(void)
{
	return mfspr(SPR_ATBL);
}

static struct bman_pool *pool_data;
static struct bman_pool *pool_sg;

static int setup_buffer_pools(void)
{
	struct bman_pool_params pparams = {
		.flags = BMAN_POOL_FLAG_DYNAMIC_BPID,
		.thresholds = {
			0,
			0,
			0,
			0
		}
	};

	pool_data = bman_new_pool(&pparams);
	if (!pool_data) {
		pr_err("can't get data buffer pool\n");
		return -EINVAL;
	}

	pool_sg = bman_new_pool(&pparams);
	if (!pool_sg) {
		pr_err("can't get sg buffer pool\n");
		return -EINVAL;
	}
	return 0;
}

static void release_data_buffer(dma_addr_t addr)
{
	struct bm_buffer bufs_in;

	BUG_ON(addr == 0);

	bm_buffer_set64(&bufs_in, addr);
	if (bman_release(pool_data, &bufs_in, 1, BMAN_RELEASE_FLAG_WAIT))
		panic("bman_release() failed\n");
}

static void release_sg_buffer(dma_addr_t addr)
{
	struct bm_buffer bufs_in;
	bm_buffer_set64(&bufs_in, addr);
	if (bman_release(pool_sg, &bufs_in, 1, BMAN_RELEASE_FLAG_WAIT))
		panic("bman_release() failed\n");
}

static int populate_bman_data_pool(void)
{
	dma_addr_t addr;
	int i, ret;
	void *cpumem;

	for (i = 0; i < b_data_block_count; i++) {
		cpumem = kzalloc(bman_data_buff_size, GFP_KERNEL);
		if (!cpumem) {
			pr_err("Can't allocate data buffers\n");
			return -ENOMEM;
		}
		global_data_alloc++;
		addr = fsl_dce_map(cpumem);
		ret = fsl_dce_map_error(addr);
		if (ret) {
			pr_err("unable to map i/o memory\n");
			kfree(cpumem);
			return ret;
		}
		release_data_buffer(addr);
	}
	pr_info("Released %u data blocks of size %u\n",
		b_data_block_count, bman_data_buff_size);
	return 0;
}

static int empty_bman_data_pool(void)
{
	struct bm_buffer bufs_in;
	int ret;
	int count = 0;

	do {
		ret = bman_acquire(pool_data, &bufs_in, 1, 0);
		if (ret == 1) {
			dma_addr_t addr = bm_buf_addr(&bufs_in);
			fsl_dce_unmap(addr);
			kfree(phys_to_virt(addr));
			global_data_free++;
			count++;
		}
	} while (ret > 0);
	return 0;
}

static int populate_bman_sg_pool(void)
{
	dma_addr_t addr;
	int i;
	void *cpumem;
	int ret;

	for (i = 0; i < b_sg_block_count; i++) {
		cpumem = kzalloc(b_sg_block_size, GFP_KERNEL);
		if (!cpumem) {
			pr_err("Can't allocate s/g buffers\n");
			return -ENOMEM;
		}
		global_sg_alloc++;
		addr = fsl_dce_map(cpumem);
		ret = fsl_dce_map_error(addr);
		if (ret) {
			pr_err("unable to map i/o memory\n");
			kfree(cpumem);
			return ret;
		}
		release_sg_buffer(addr);
	}
	return 0;
}

static int empty_bman_sg_pool(void)
{
	struct bm_buffer bufs_in;
	int ret;
	int count = 0;

	do {
		ret = bman_acquire(pool_sg, &bufs_in, 1, 0);
		if (ret == 1) {
			dma_addr_t addr = bm_buf_addr(&bufs_in);
			fsl_dce_unmap(addr);
			kfree(phys_to_virt(addr));
			global_sg_free++;
			count++;
		}
	} while (ret > 0);
	return 0;
}


static int teardown_buffer_pool(void)
{
	empty_bman_sg_pool();
	empty_bman_data_pool();
	if (pool_data) {
		bman_free_pool(pool_data);
		pool_data = NULL;
	}
	if (pool_sg) {
		bman_free_pool(pool_sg);
		pool_sg = NULL;
	}
	return 0;
}

static int copy_bman_output_to_buffer(struct qm_sg_entry *sg, size_t cpylen,
			char *buffer, size_t buf_size)
{
	dma_addr_t phy_addr;
	void *cpumem;
	u64 cal_total_length = 0;
	char *pos = buffer;
	struct qm_sg_entry *entry;
	u64 remaining = cpylen;

	/*
	 * As per DPAA:
	 * Processing also stops when the number of bytes specified by the
	 * overall length have been processed determine if the s/g entry is
	 * pointing to a s/g table or a simple frame
	 */
	if (sg->extension) {
		struct qm_sg_entry *s_entry;

		/* read in address of sg table */
		phy_addr = qm_sg_addr(sg);
		fsl_dce_unmap(phy_addr);
		cpumem = phys_to_virt(phy_addr);
		s_entry = (struct qm_sg_entry *)cpumem;
		entry = s_entry;
		do {
			if (!entry->extension) {
				u64 to_copy;

				phy_addr = qm_sg_addr(entry);
				fsl_dce_unmap(phy_addr);
				cpumem = phys_to_virt(phy_addr);
				to_copy = min_t(u64, entry->length,
					remaining);
				cal_total_length += to_copy;
				remaining -= to_copy;
				memcpy(pos, cpumem, to_copy);
				pos += to_copy;
				/* release buffer back to bman */
				phy_addr = fsl_dce_map(cpumem);
				if (fsl_dce_map_error(phy_addr))
					pr_err("MAP ERROR\n");
				release_data_buffer(phy_addr);
				if (!entry->final)
					entry++;
				else {
					phy_addr = fsl_dce_map(s_entry);
					if (fsl_dce_map_error(phy_addr))
						pr_err("MAP ERROR\n");
					release_sg_buffer(phy_addr);
					break;
				}
			} else {
				/* address is pointing to another s/g table */
				phy_addr = qm_sg_addr(entry);
				fsl_dce_unmap(phy_addr);
				cpumem = phys_to_virt(phy_addr);
				entry = (struct qm_sg_entry *)cpumem;
				/* free previous table */
				phy_addr = fsl_dce_map(s_entry);
				if (fsl_dce_map_error(phy_addr))
					pr_err("MAP ERROR\n");
				release_sg_buffer(phy_addr);
				s_entry = entry;
			}
		} while (1);

		if (cpylen != cal_total_length)
			pr_info("total frame length != calulated length (%lu) (%llu)\n",
				cpylen, cal_total_length);
	} else {
		phy_addr = qm_sg_addr(sg);
		if (phy_addr != 0) {
			fsl_dce_unmap(phy_addr);
			cpumem = phys_to_virt(phy_addr);
			if (cpylen != sg->length) {
				pr_info("sg len!=frame out length (%lu) (%u)\n",
					cpylen, sg->length);
			}
			memcpy(buffer, cpumem, sg->length);
			/* release buffer back to bman */
			phy_addr = fsl_dce_map(cpumem);
			if (fsl_dce_map_error(phy_addr))
				pr_err("MAP ERROR\n");
			release_data_buffer(phy_addr);
		}
	}
	return 0;
}

static void stream_process_cb(struct fsl_dce_flow *flow,
		const struct qm_fd *fd, void *callback_tag)
{
	struct  dce_process_cf_gzip_req *data =
		(struct  dce_process_cf_gzip_req *)callback_tag;
	static int do_once;

	if ((fsl_dce_get_status(fd->status) != STREAM_END) &&
	(fsl_dce_get_status(fd->status) != FULLY_PROCESSED)) {
		if (!do_once) {
			do_once = 1;
			pr_err("Error result 0x%x\n",
				fsl_dce_get_status(fd->status));
			print_dce_fd(*fd);
			pr_err("Request %lu\n",
				data->extra_data_size);
			print_dce_fd(data->input_fd);
			print_dce_sg(data->dce_cf[0]);
			print_dce_sg(data->dce_cf[1]);
			print_dce_sg(data->dce_cf[2]);

			print_multi_buffer(&data->dce_cf[1], 0);
		}
	}
	data->output_fd = *fd;
	complete(&data->cb_done);
}

static void stream_nop_cb(struct fsl_dce_flow *flow,
		const struct qm_fd *fd, void *callback_tag)
{
}

static void stream_scr_invalidate_cb(struct fsl_dce_flow *flow,
		const struct qm_fd *fd, void *callback_tag)
{
	struct dce_scr_invalidate_req *req =
		(struct  dce_scr_invalidate_req *)callback_tag;

	req->output_fd = *fd;
	complete(&req->cb_done);
}


static int init_scr(struct fsl_dce_stream *ctx)
{
	struct dce_process_cf_gzip_req *req;
	int ret;
	dma_addr_t addr;

	req = kzalloc(sizeof(*req), GFP_KERNEL);

	if (!req)
		return -ENOMEM;

	init_completion(&req->cb_done);

	fsl_dce_build_scf_uspc(ctx, &req->scf);

	ret = attach_scf64_to_sg(&req->dce_cf[2], &req->scf,
			DMA_BIDIRECTIONAL);
	req->dce_cf[2].final = 1;
	req->input_fd._format2 = qm_fd_compound;
	req->input_fd.cong_weight = 1;
	qm_fd_addr_set64(&req->input_fd, fsl_dce_map(req->dce_cf));

	SET_BF32_TK(req->input_fd.cmd, DCE_PROCESS_SCRF, SET);

	fsl_dce_stream_init_scr(ctx, &req->input_fd, req);

	wait_for_completion(&req->cb_done);
	ret = detach_scf64_from_sg(&req->dce_cf[2], &req->scf,
			DMA_BIDIRECTIONAL);
	addr = qm_fd_addr(&req->input_fd);
	fsl_dce_unmap(addr);
	kfree(req);
	return 0;
}

static int read_file(const char *file, char **data, int *data_len)
{
	struct file *filp;
	int rc = -EINVAL;
	struct inode *inode = NULL;
	loff_t	size, pos;

	mm_segment_t oldfs = get_fs();

	filp = filp_open(file, O_RDONLY | O_LARGEFILE, 0);
	if (IS_ERR(filp)) {
		pr_err("unable to open file: %s\n", file);
		return PTR_ERR(filp);
	}

	inode = filp->f_path.dentry->d_inode;
	if ((!S_ISREG(inode->i_mode) && !S_ISBLK(inode->i_mode))) {
		pr_err("invalid file type: %s\n", file);
		goto out;
	}

	size = i_size_read(inode->i_mapping->host);
	if (size < 0) {
		pr_err("unable to find file size: %s\n", file);
		rc = (int)size;
		goto out;
	}

	pr_info("Size of file: %s is %d\n", file, (int)size);

	*data = vmalloc(size);
	if (*data == NULL) {
		pr_err("Out of memory loading file\n");
		goto out;
	}
	pos = 0;
	set_fs(KERNEL_DS);
	if (vfs_read(filp, *data, size, &pos) != size) {
		pr_info("Failed to read '%s'.\n", file);
		rc = -1;
		goto out;
	}

	*data_len = size;
	set_fs(oldfs);
	fput(filp);

	return 0;
out:
	set_fs(oldfs);
	fput(filp);
	if (*data) {
		vfree(*data);
		*data = NULL;
	}
	return rc;
}

static int write_file(const char *file, char *data, size_t data_len)
{
	struct file *filp;
	int rc = -EINVAL;
	loff_t pos;

	mm_segment_t oldfs = get_fs();

	filp = filp_open(file, O_CREAT | O_WRONLY | O_LARGEFILE, 0666);
	if (IS_ERR(filp)) {
		pr_err("unable to open file: %s\n", file);
		return PTR_ERR(filp);
	}

	if (data == NULL) {
		pr_err("No data to write\n");
		goto out;
	}
	pos = 0;
	set_fs(KERNEL_DS);
	rc = vfs_write(filp, data, data_len, &pos);
	if (rc != data_len) {
		pr_info("Failed to write '%s'.\n", file);
		pr_info("Error %d, data_len %lu\n", rc, data_len);
		goto out;
	}

	set_fs(oldfs);
	fput(filp);

	return 0;
out:
	set_fs(oldfs);
	fput(filp);
	return rc;
}

#define COMP_ONLY 0
#define DECOMP_ONLY 1

static int validate_module_params(void)
{
	if (bman_output) {
		if (b_sg_block_size_code < 0 ||
			b_sg_block_size_code > DCE_TSIZE_8192B) {
			pr_err("Invalid b_sg_block_size_code value %d\n",
				b_sg_block_size_code);
			return -ERANGE;
		}
		b_sg_block_size = 1 << (6 + b_sg_block_size_code);

		if (!bman_data_size) {
			pr_err("bman_data_size is zero. This is the size of all the data in the bman data pool.\n");
			return -EINVAL;
		}

		bman_data_buff_size = b_dmant * (1 << b_dexp);

		pr_info("BMan data block size is %u\n", bman_data_buff_size);

		b_data_block_count = (bman_data_size / bman_data_buff_size) + 1;
	}

	if (!in_file && !use_local_file) {
		pr_err("Missing input data\n");
		return -EINVAL;
	}

	return 0;
}

static int get_input_data(struct test_data_s *test)
{
	char *data = NULL;
	int len = 0;

	/* check if we are using included local file */
	if (use_local_file) {
		/* check if we are using included local file */
		if (test_mode == COMP_ONLY) {
			switch (use_local_file) {
			case 2:
				len = paper5_2048_len;
				data =	paper5_2048;
				break;
			case 4:
				len = paper5_4096_len;
				data = paper5_4096;
				break;
			case 8:
				len = paper5_8192_len;
				data = paper5_8192;
				break;
			case 12:
				len =  paper5_11954_len;
				data = paper5_11954;
				break;

			default:
				pr_err("Unvalid use_local_file value %d\n",
					use_local_file);
				return -EINVAL;
			}
		} else {
			test_mode = DECOMP_ONLY;
			switch (use_local_file) {
			case 2:
				len = paper6_2K_compressed_gz_len;
				data = paper6_2K_compressed_gz;
				break;
			case 4:
				len = paper6_4K_compressed_gz_len;
				data = paper6_4K_compressed_gz;
				break;

			case 8:
				len = paper6_8K_compressed_gz_len;
				data = paper6_8K_compressed_gz;
				break;
			case 12:
				len = paper6_8K_compressed_gz_len;
				data = paper6_8K_compressed_gz;
				break;
			default:
				pr_err("Unvalid use_local_file value %d\n",
					use_local_file);
				return -EINVAL;
			}
		}
		if (data && len) {
			test->input_data_len = len;
			test->input_data = vmalloc(len);
			if (!test->input_data)
				return -ENOMEM;
			memcpy(test->input_data, data, len);
		}
	}

	/* If specified input file and NOT use local data, read file */
	if (in_file && !use_local_file) {
		if (read_file(in_file, &test->input_data,
			&test->input_data_len)) {
			pr_err("Error reading in_file file: %s\n", in_file);
			return -EINVAL;
		}
	}
	return 0;
}

int dce_sf_performance_init(void)
{
	int ret;

	pr_info("Loading dce_sf_performance_simple_test module\n");

	ret = validate_module_params();
	if (ret)
		return ret;

	/* create test data */
	test_data = kzalloc(sizeof(*test_data), GFP_KERNEL);
	if (!test_data) {
		pr_info("Error allocating test_data\n");
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&test_data->request_list);

	/* reads input data into vmalloc'd data */
	ret = get_input_data(test_data);

	fsl_dce_clear_stat(DCE_COMP_INPUT_BYTES);
	fsl_dce_clear_stat(DCE_DECOMP_OUTPUT_BYTES);

	if (bman_output) {
		ret = setup_buffer_pools();
		ret = populate_bman_data_pool();
		ret = populate_bman_sg_pool();
	}

	ret = do_operation();

	return 0;
}

void dce_sf_performance_shutdown(void)
{
	u64 run_time_cycle;
	u64 total_compress_bytes = 0;
	u64 total_decompress_bytes = 0;
	u64 comp_Mbps = 0;
	u64 decomp_Mbps = 0;
	unsigned int cpufreq = 0;
	u64 run_time_usec = 0;
	u32 sysfreq = 0, dce_freq = 0;
	u64 dce_max_freq = 400000000; /* Hz */
	u64 scaled_val;
	u64 temp;

	sysfreq = fsl_get_sys_freq();
	dce_freq = sysfreq;
	do_div(dce_freq, 2);
	cpufreq = ppc_proc_freq;
	run_time_cycle = end_time - start_time;

	temp = cpufreq;
	run_time_usec = run_time_cycle;
	do_div(temp, 1000000);
	do_div(run_time_usec, temp);

	/* calculated scalling factor multiple of 1000 */
	/* 400000/300 */
	scaled_val = dce_max_freq * 1000;
	do_div(scaled_val, dce_freq);

	pr_info("DCE Freq = %u hz\n", dce_freq);
	pr_info("CPU Freq: %u\n", cpufreq);
	pr_info("Cycles to complete = %llu\n", run_time_cycle);
	pr_info("Time (usec) to complete = %llu\n", run_time_usec);
	pr_info("Scaling factor (by 1000) = %llu\n", scaled_val);

	fsl_dce_get_stat(DCE_COMP_INPUT_BYTES, &total_compress_bytes, 1);
	fsl_dce_get_stat(DCE_DECOMP_OUTPUT_BYTES, &total_decompress_bytes, 1);

	if (total_compress_bytes) {
		pr_info("Total Input Bytes to Compress:   %llu\n",
			total_compress_bytes);
		pr_info("Input file size compression: %u bytes\n",
			test_data->input_data_len);
	}
	if (total_decompress_bytes) {
		pr_info("Total Input Bytes to Decompress: %llu\n",
			total_decompress_bytes);
		pr_info("Input file size decompression: %u bytes\n",
			test_data->input_data_len);
	}

	/* Calculate Compression Mbps */
	if (total_compress_bytes) {
		u64 estimate_Mbps;

		comp_Mbps = total_compress_bytes * 8;
		do_div(comp_Mbps, run_time_usec);

		estimate_Mbps = comp_Mbps;
		estimate_Mbps *= scaled_val;
		do_div(estimate_Mbps, 1000);

		pr_info("Compression throughput:      %llu Mbps (%llu Mbps for 400 Mhz DCE)\n",
			comp_Mbps, estimate_Mbps);

	} else {
		pr_info("Compression throughput:   None\n");
	}

	/* Calculate Decompression Mbps */
	if (total_decompress_bytes) {
		u64 estimate_Mbps;

		decomp_Mbps = total_decompress_bytes * 8;
		do_div(decomp_Mbps, run_time_usec);

		estimate_Mbps = decomp_Mbps;
		estimate_Mbps *= scaled_val;
		do_div(estimate_Mbps, 1000);

		pr_info("Decompression throughput:    %llu Mbps (%llu Mbps for 400 Mhz DCE)\n",
			decomp_Mbps, estimate_Mbps);
	} else {
		pr_info("Decompression throughput: None\n");
	}
	/* write output date */
	if (out_file) {
		pr_info("About to write %d of data\n", test_data->out_data_len);
		write_file(out_file, test_data->out_data,
			test_data->out_data_len);
	}

	if (bman_output)
		teardown_buffer_pool();
	vfree(test_data->out_data);
	vfree(test_data->input_data);
	kfree(test_data);

	if (bman_output) {
		pr_info("data_alloc = %d, data_free = %d\n",
			global_data_alloc, global_data_free);
		pr_info("sg_alloc = %d, sg_free = %d\n",
			global_sg_alloc, global_sg_free);
	}
	pr_info("DONE\n");
}

/* Module load/unload handlers */
module_init(dce_sf_performance_init);
module_exit(dce_sf_performance_shutdown);

static int do_operation(void)
{
	int ret, i;
	int dce_flags = 0;
	struct dce_process_cf_gzip_req *def_process_req = NULL;
	struct dce_bman_cfg bcfg;
	int chunk_count;
	struct list_head *pos;
	u32 total_out = 0;
	char *p_out;

	pr_info("DCE thread on cpu %d\n", smp_processor_id());

	if (bman_output)
		pr_info("Using BMan for output\n");
	else
		pr_info("Using pre-built for output\n");

	if (bman_output) {
		bcfg.tsize = b_sg_block_size_code;
		bcfg.tbpid = bman_get_params(pool_sg)->bpid;
		bcfg.dbpid = bman_get_params(pool_data)->bpid;
		bcfg.dmant = b_dmant;
		bcfg.dexp = b_dexp;

		pr_info("Bman info: tsize = %u, tbpid = %u, dbpid = %u, dmant = %u, dexp = %u\n",
			(u32)bcfg.tsize,
			(u32)bcfg.tbpid,
			(u32)bcfg.dbpid,
			(u32)bcfg.dmant,
			(u32)bcfg.dexp);
	}

	chunk_count = test_data->input_data_len / chunking_size;
	if ((chunk_count * chunking_size) < test_data->input_data_len)
		chunk_count += 1;

	pr_info("Number of chunks to send %d\n", chunk_count);
	pr_info("chunk size %d\n", chunking_size);

	/* initialize a compression deflate stream */
	if (test_mode == COMP_ONLY) {
		ret = fsl_dce_stream_setup2(&test_data->ctx, dce_flags,
			DCE_COMPRESSION, DCE_CF_GZIP, DCE_TRUNCATION,
			bman_output ? &bcfg : NULL,
			stream_process_cb, stream_nop_cb,
			stream_scr_invalidate_cb);
	} else {
		ret = fsl_dce_stream_setup2(&test_data->ctx, dce_flags,
			DCE_DECOMPRESSION, DCE_CF_GZIP, DCE_TRUNCATION,
			bman_output ? &bcfg : NULL,
			stream_process_cb, stream_nop_cb,
			stream_scr_invalidate_cb);
	}
	if (ret)
		pr_err("fsl_dce_stream_setup2 failed %d\n", ret);

	ret = fsl_dce_stream_deflate_params(&test_data->ctx,
		DCE_PROCESS_OO_NONE_LONG, false, false,
		(test_mode == COMP_ONLY) ? comp_effort : 0);

	if (ret)
		pr_err("fsl_dce_stream_deflate_params failed %d\n", ret);

	/* Need to Initialize the Stream Context Record */
	ret = init_scr(&test_data->ctx);

	pr_info("About to build linked-list of requests..\n");

	for (i = 0; i < chunk_count; i++) {
		def_process_req = kzalloc(sizeof(*def_process_req), GFP_KERNEL);
		if (!def_process_req) {
			pr_err("Line %d\n", __LINE__);
			return -ENOMEM;
		}

		def_process_req->extra_data_size = i;

		init_completion(&def_process_req->cb_done);

		if ((i == 0) && (test_mode == COMP_ONLY)) {
			pr_info("initializing gzip header\n");
			init_gzip_header(&def_process_req->scf);
			ret = attach_scf64_to_sg(&def_process_req->dce_cf[2],
				&def_process_req->scf, DMA_BIDIRECTIONAL);
			SET_BF32_TK(def_process_req->input_fd.cmd,
				DCE_PROCESS_UHC, YES);
		}

		/* allocate input dma memory */
		ret = alloc_dce_data(chunking_size, block_size,
			&def_process_req->input_data);
		if (ret)
			pr_err("Error Allocating input data Line %d\n",
				__LINE__);

		if (!bman_output) {
			/*
			 * allocate output dma contiguous memory. If compression
			 * allocate @output_size more bytes. If decompression,
			 * allocate comp_ratio times more.
			 */
			if (test_mode == COMP_ONLY) {
				/* sg output not supported Rev1 */
				ret = alloc_dce_data(
					chunking_size + output_size,
					chunking_size + output_size,
					&def_process_req->output_data);
			} else {
				/* maximum decompression size is 20 MB */
				ret = alloc_dce_data(
					chunking_size * comp_ratio,
					chunking_size * comp_ratio,
					&def_process_req->output_data);
			}
			if (ret)
				pr_err("Error Allocating %d\n",	__LINE__);
		}

		if (i == (chunk_count - 1)) {
			ret = copy_input_to_dce_data(test_data->input_data +
				(i*chunking_size),
				test_data->input_data_len - (i * chunking_size),
				&def_process_req->input_data);
			def_process_req->input_fd.cong_weight =
				test_data->input_data_len - (i * chunking_size);
			pr_info("DEBUG: fd.cong_weight = %d\n",
					def_process_req->input_fd.cong_weight);
		} else {
			ret = copy_input_to_dce_data(test_data->input_data +
				(i*chunking_size),
				chunking_size,
				&def_process_req->input_data);
			def_process_req->input_fd.cong_weight = chunking_size;
		}
		if (ret)
			pr_err("Line %d\n", __LINE__);

		ret = dma_map_dce_data(&def_process_req->input_data,
				DMA_BIDIRECTIONAL);
		if (ret)
			pr_err("Line %d\n", __LINE__);

		/* If pre-build attache the output data */
		if (!bman_output) {
			ret = dma_map_dce_data(&def_process_req->output_data,
					DMA_BIDIRECTIONAL);
			if (ret)
				pr_err("Line %d\n", __LINE__);

			ret = attach_data_list_to_sg(
				&def_process_req->dce_cf[0],
				&def_process_req->output_data, true,
				DMA_BIDIRECTIONAL);
			if (ret)
				pr_err("Line %d\n", __LINE__);
		}

		ret = attach_data_list_to_sg(&def_process_req->dce_cf[1],
				&def_process_req->input_data, false,
				DMA_BIDIRECTIONAL);
		if (ret)
			pr_err("Line %d\n", __LINE__);


		if (i == 0)
			ret = attach_scf64_to_sg(&def_process_req->dce_cf[2],
				&def_process_req->scf,
				DMA_BIDIRECTIONAL);
		if (ret)
			pr_err("Line %d\n", __LINE__);

		def_process_req->dce_cf[2].final = 1;
		def_process_req->input_fd._format2 = qm_fd_compound;

		if (i == (chunk_count - 1))
			SET_BF32_TK(def_process_req->input_fd.cmd,
				DCE_PROCESS_SCRF, SET);

		qm_fd_addr_set64(&def_process_req->input_fd,
			fsl_dce_map(def_process_req->dce_cf));
		list_add_tail(&def_process_req->node, &test_data->request_list);
	}
	pr_info("About to send requests...\n");
	start_time = mfatb();
	i = 0;

	list_for_each(pos, &test_data->request_list) {
		u32 flags = 0;

		def_process_req = list_entry(
			pos, struct dce_process_cf_gzip_req, node);

try_again:
		ret = fsl_dce_stream_process(&test_data->ctx,
			flags,
			&def_process_req->input_fd,
			(i == 0) ? true : false,
			(i == (chunk_count-1)) ?
				DCE_PROCESS_Z_FLUSH_FINISH :
				DCE_PROCESS_Z_FLUSH_NO_FLUSH,
			def_process_req);

		/* -ENOMEM is returned if FIFO is full, try again */
		if (ret == -ENOMEM)
			goto try_again;
		if (ret) {
			pr_err("fsl_dce_stream_process failed %d\n", ret);
			print_dce_fd(def_process_req->input_fd);
		}
		i++;
	}

	if (!def_process_req) {
		pr_err("Line %d\n", __LINE__);
		return -EINVAL;
	}
	/* wait for last request to be processed */
	wait_for_completion(&def_process_req->cb_done);
	end_time = mfatb();
	pr_info("Processed %lu request\n", def_process_req->extra_data_size);

done:
	if (fsl_dce_stream_fifo_len(&test_data->ctx)) {
		schedule();
		goto done;

	}

	ret = fsl_dce_stream_destroy(&test_data->ctx, 0, NULL);
	if (ret)
		pr_info("Error destroying fsl_stream\n");

	/* calculate output required */
	list_for_each(pos, &test_data->request_list) {
		def_process_req = list_entry(
			pos, struct dce_process_cf_gzip_req, node);
		/* unmap the ouput frame */
		fsl_dce_unmap(qm_fd_addr_get64(&def_process_req->output_fd));
		total_out += def_process_req->dce_cf[0].length;
	}
	pr_info("Total output required %d\n", total_out);
	test_data->out_data_len = total_out;
	test_data->out_data = vmalloc(total_out);
	if (!test_data->out_data) {
		pr_err("vmalloc FAILED\n");
		return -ENOMEM;
	}
	p_out = test_data->out_data;

	/* copy output */
	list_for_each(pos, &test_data->request_list) {
		def_process_req = list_entry(
			pos, struct dce_process_cf_gzip_req, node);
		/* save output */

		/* Need to determine if this output is pre-built or Bman */
		if (!def_process_req->dce_cf[0].bpid) {
			if (def_process_req->dce_cf[0].length) {
				ret = copy_output_dce_data_to_buffer(
					&def_process_req->output_data,
					def_process_req->dce_cf[0].length,
					p_out,
					test_data->out_data_len);
				if (ret)
					pr_err("Error %d\n", __LINE__);
				p_out += def_process_req->dce_cf[0].length;
			}
		} else {
			/*
			 * this copied the data in the bman buffers and also
			 * release the buffers back to BMan
			 */
			ret = copy_bman_output_to_buffer(
				&def_process_req->dce_cf[0],
				def_process_req->dce_cf[0].length,
				p_out,
				def_process_req->dce_cf[0].length);
			p_out += def_process_req->dce_cf[0].length;
			if (ret)
				pr_err("Error %d\n", __LINE__);
		}

		/* detach input SCF frame */
		if (def_process_req->dce_cf[2].length) {
			pr_info("unmapping input scf\n");
			ret = detach_scf64_from_sg(&def_process_req->dce_cf[2],
				&def_process_req->scf,
				DMA_BIDIRECTIONAL);
		}

		/* detach input data */
		ret = detach_data_list_from_sg(&def_process_req->dce_cf[1],
			&def_process_req->input_data, DMA_BIDIRECTIONAL);
		/* unmap input data */
		ret = dma_unmap_dce_data(&def_process_req->input_data,
					DMA_BIDIRECTIONAL);

		/* If not Bman output, detach and unmap input */
		if (!def_process_req->dce_cf[0].bpid) {
			ret = detach_data_list_from_sg(
				&def_process_req->dce_cf[0],
				&def_process_req->output_data,
				DMA_BIDIRECTIONAL);
			ret = dma_unmap_dce_data(&def_process_req->output_data,
					DMA_BIDIRECTIONAL);
			free_dce_data(&def_process_req->output_data);
		}

		free_dce_data(&def_process_req->input_data);
		kfree(def_process_req);
	}
	return 0;
}
