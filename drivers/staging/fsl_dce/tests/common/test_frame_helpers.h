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

#ifndef TEST_FRAME_HELPERS_H
#define TEST_FRAME_HELPERS_H

#include <linux/kernel.h>
#include <linux/fsl_qman.h>
#include <linux/dma-direction.h>
#define AT __stringify(__LINE__)

/**
 * struct dce_data_t - hold cpu virtual address input or output data
 * @is_sg:	Inidcated if @data references a qm_sg_entry array or not.
 * @data:	cpu virtual address of either data or an array of
 *		qm_sq_entry
 * @length	Size of memory pointed by @data.
 */
struct dce_data_item_t {
	void *cpumem;
	size_t size;
	size_t d_size;
};

/**
 * struct dce_data_t - hold cpu virtual address input or output data
 * @sg:		Inidcated if sg is required
 * @nents:	number of entries @sg points to as well as @data_item
 * @data_item:	points to an array of dce_data_item_t. If @sg is NULL then
 *		it will point up to one element. Otherwise it will point to
 *		@nents elements.
 */
struct dce_data_list_t {
	struct qm_sg_entry *sg;
	unsigned int nents;
	struct dce_data_item_t *data_item;
};

void print_compression_input_scf(struct scf_64b *scf);
void print_compression_output_scf(struct scf_64b *scf);
void print_compression_output_scf_debug(struct scf_64b *scf);
void print_decompression_input_scf(struct scf_64b *scf);
void print_decompression_output_scf(struct scf_64b *scf);
void print_decompression_output_scf_debug(struct scf_128b *scf);
void print_dce_data_list(struct dce_data_list_t *data_list);
void print_dce_fd(struct qm_fd fd);
void print_dce_sg(struct qm_sg_entry sg);
void print_multi_buffer(struct qm_sg_entry *sg, int level);

size_t total_allocated_dce_data(struct dce_data_list_t *dce_data);
size_t total_size_dce_data(struct dce_data_list_t *dce_data);

bool is_multi_buffer(struct dce_data_list_t *data);

/**
 * alloc_dce_data - allocate memory to use with dce
 * @length: total bytes to allocates
 * @block_size: contiguous blocks to allocate
 * @dce_data: storage for allocated memory
 */
int alloc_dce_data(size_t length, size_t block_size,
			struct dce_data_list_t *dce_data);

int free_dce_data(struct dce_data_list_t *dce_data);

int copy_input_to_dce_data(char *input, size_t ilen,
			struct dce_data_list_t *data_list);

int copy_output_dce_data_to_buffer(struct dce_data_list_t *data_list,
		size_t cpylen, char *buffer, size_t buf_size);

/**
 * dma_map_dce_data - dma_map the data entries
 * @data_list: list of data items
 * @dir: direction of dma mapping
 *
 * Each data item will have a dma_map invoked and the resulting mapping
 * will be added to the sg table.
 */
int dma_map_dce_data(struct dce_data_list_t *data_list,
		enum dma_data_direction dir);

int dma_unmap_dce_data(struct dce_data_list_t *data_list,
		enum dma_data_direction dir);

/**
 * attach_data_list_to_sg - set the dma address of data list to sg
 * @sg: the sg to attach data_list to. The dma_addr of the data_list
 *	and the length field will be set.
 * @data_list: this can be a single buffer or multi buffer data list.
 * @use_raw_size: if true use the allocated size of data_list when setting
 *	length in @sg. Otherwise calculate the data length in @data_list
 *	and use that value. Typically an input frame will use a value of false
 *	and an output frame will use a value of true.
 * @dir: direction of dma mapping
 */
int attach_data_list_to_sg(struct qm_sg_entry *sg,
			struct dce_data_list_t *data_list,
			bool use_raw_size,
			enum dma_data_direction dir);

int detach_data_list_from_sg(struct qm_sg_entry *sg,
			struct dce_data_list_t *data_list,
			enum dma_data_direction dir);

int attach_scf64_to_sg(struct qm_sg_entry *sg,
			struct scf_64b *scf,
			enum dma_data_direction);

int detach_scf64_from_sg(struct qm_sg_entry *sg,
			struct scf_64b *scf,
			enum dma_data_direction dir);

int attach_scf128_to_sg(struct qm_sg_entry *sg,
			struct scf_128b *scf,
			enum dma_data_direction);

int detach_scf128_from_sg(struct qm_sg_entry *sg,
			struct scf_128b *scf,
			enum dma_data_direction dir);

struct dce_process_cf_req {
	struct qm_sg_entry dce_cf[3];
	struct dce_data_list_t output_data;
	struct dce_data_list_t input_data;
	struct qm_fd input_fd;
	struct qm_fd output_fd;
	struct completion cb_done;
	char *v_output;
	size_t v_output_size;
};

struct dce_process_cf_zlib_req {
	struct qm_sg_entry dce_cf[3];
	struct scf_64b scf;
	struct dce_data_list_t output_data;
	struct dce_data_list_t input_data;
	struct qm_fd input_fd;
	struct qm_fd output_fd;
	struct completion cb_done;
	char *v_output;
	size_t v_output_size;
};

struct dce_process_cf_gzip_req {
	struct qm_sg_entry dce_cf[3];
	struct scf_64b scf;
	struct scf_128b scf_debug;
	struct qm_fd input_fd;
	struct qm_fd output_fd;
	struct completion cb_done;
	char *v_output;
	size_t v_output_size;

	void *extra_data;
	size_t extra_data_size;
	char *filename;
	char *comment;
	struct dce_data_item_t extra_data_ptr;
	struct dce_data_list_t output_data;
	struct dce_data_list_t input_data;
	struct list_head node;
};

struct dce_nop_req {
	struct qm_fd output_fd;
	struct completion cb_done;
};

struct dce_scr_invalidate_req {
	struct qm_fd input_fd;
	struct qm_fd output_fd;
	struct completion cb_done;
};

int alloc_set_gzip_filename(struct dce_process_cf_gzip_req *req, char *name);
int free_clear_gzip_filename(struct dce_process_cf_gzip_req *req);
int alloc_set_gzip_comment(struct dce_process_cf_gzip_req *req, char *name);
int free_clear_gzip_comment(struct dce_process_cf_gzip_req *req);

#endif /* TEST_FRAME_HELPERS_H */
