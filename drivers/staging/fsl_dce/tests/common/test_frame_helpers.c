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
 * on any theory of liability, whether in contract, strict liability, or tort
 * (including negligence or otherwise) arising in any way out of the use of
 * this software, even if advised of the possibility of such damage.
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/cpumask.h>
#include <linux/rbtree.h>
#include <linux/fsl_qman.h>
#include <linux/stringify.h>
#include "../../dce_sys.h"
#include "../../flib/dce_defs.h"
#include "test_frame_helpers.h"

void print_compression_input_scf(struct scf_64b *scf)
{
	pr_info(" Compression Input SCF @ %p:\n", scf);
	pr_info("   TOTAL IN ----------- %u\n", get_total_in(scf));
	pr_info("   TOTAL OUT ---------- %u\n", get_total_out(scf));
	pr_info("   ADLER32 ------------ %#x\n", get_adler32(scf));

	pr_info("   ID1 ---------------- %#x\n", get_id1(scf));
	pr_info("   ID2 ---------------- %#x\n", get_id2(scf));
	pr_info("   CM ----------------- %#x\n", get_cm(scf));
	pr_info("   FLG ---------------- %#x\n", get_flg(scf));
	pr_info("   MTIME -------------- %u\n", get_mtime(scf));
	pr_info("   XFL ---------------- %#x\n", get_xfl(scf));
	pr_info("   OS ----------------- %#x\n", get_os(scf));
	pr_info("   XLEN --------------- %u\n", get_xlen(scf));
	pr_info("   NLEN --------------- %u\n", get_nlen(scf));
	pr_info("   CLEN --------------- %u\n", get_clen(scf));
	pr_info("   EXTRA PTR ---------- %#010llx\n", get_extra_ptr(scf));
	pr_info("   PENDING OUTPUT PTR - %#010llx\n",
						get_pending_output_ptr(scf));
	pr_info("   HISTORY PTR -------- %#010llx\n", get_history_ptr(scf));
	pr_info("   PMODE -------------- %u\n", get_pmode(scf));
}
EXPORT_SYMBOL(print_compression_input_scf);

void print_compression_output_scf_debug(struct scf_64b *scf)
{
	pr_info(" Compression Output DEBUG SCF @ %p:\n", scf);
	pr_info("   TOTAL IN ----------- %u\n", get_total_in(scf));
	pr_info("   TOTAL OUT ---------- %u\n", get_total_out(scf));
	pr_info("   ADLER32 ------------ %#x\n", get_adler32(scf));
	pr_info("   OUTPUT PHASE ------- %u\n", get_output_phase(scf));
	pr_info("   B64 RESIDUE LEN ---- %u\n", get_b64_residue_len(scf));
	pr_info("   B64 RESIDUE -------- %#x\n", get_b64_residue(scf));
	pr_info("   ID1 ---------------- %#x\n", get_id1(scf));
	pr_info("   ID2 ---------------- %#x\n", get_id2(scf));
	pr_info("   CM ----------------- %#x\n", get_cm(scf));
	pr_info("   FLG ---------------- %#x\n", get_flg(scf));
	pr_info("   MTIME -------------- %u\n", get_mtime(scf));
	pr_info("   XFL ---------------- %#x\n", get_xfl(scf));
	pr_info("   OS ----------------- %#x\n", get_os(scf));
	pr_info("   XLEN --------------- %u\n", get_xlen(scf));
	pr_info("   NLEN --------------- %u\n", get_nlen(scf));
	pr_info("   CLEN --------------- %u\n", get_clen(scf));
	pr_info("   RESIDUE DATA ------- %#x\n", get_residue_data(scf));
	pr_info("   EXTRA PTR ---------- %#010llx\n", get_extra_ptr(scf));
	pr_info("   PENDING OUTPUT LEN - %u\n", get_pending_output_len(scf));
	pr_info("   PENDING WRKING PTR - %#x\n", get_pending_working_ptr(scf));
	pr_info("   PENDING_OUTPUT_PTR - %#010llx\n",
						get_pending_output_ptr(scf));
	pr_info("   HISTORY LEN -------- %u\n", get_history_len(scf));
	pr_info("   HISTORY_PTR -------- %#010llx\n", get_history_ptr(scf));
	pr_info("   PMODE -------------- %u\n", get_pmode(scf));
	pr_info("   SUSP --------------- %u\n", get_susp(scf));
	pr_info("   TERMINATED --------- %u\n", get_terminated(scf));
	pr_info("   RBC ---------------- %u\n", get_rbc(scf));
	pr_info("   HEADER REMAINING --- %#x\n", get_header_remaining(scf));
	pr_info("   CRC16 -------------- %#x\n", get_crc16(scf));
}
EXPORT_SYMBOL(print_compression_output_scf_debug);

void print_compression_output_scf(struct scf_64b *scf)
{
	pr_info(" Compression Output SCF @ %p:\n", scf);
	pr_info("   TOTAL IN ----------- %u\n", get_total_in(scf));
	pr_info("   TOTAL OUT ---------- %u\n", get_total_out(scf));
	pr_info("   ADLER32 ------------ %#x\n", get_adler32(scf));
	pr_info("   BYTES PROCESSED ---- %u\n", get_bytes_processed(scf));
}
EXPORT_SYMBOL(print_compression_output_scf);

void print_decompression_input_scf(struct scf_64b *scf)
{
	pr_info(" Decompression Input SCF @ %p:\n", scf);
	pr_info("   TOTAL IN ----------- %u\n", get_total_in(scf));
	pr_info("   TOTAL OUT ---------- %u\n", get_total_out(scf));
	pr_info("   ADLER32 ------------ %#x\n", get_adler32(scf));

	pr_info("   EXTRA_LIMIT -------- %u\n", get_extra_limit(scf));
	pr_info("   EXTRA_PTR ---------- %#010llx\n", get_extra_ptr(scf));
	pr_info("   PENDING_OUTPUT_PTR - %#010llx\n",
						get_pending_output_ptr(scf));
	pr_info("   HISTORY_PTR -------- %#010llx\n", get_history_ptr(scf));
	pr_info("   PMODE -------------- %u\n", get_pmode(scf));
	pr_info("   DECOMP_CTXT_PTR ---- %#010llx\n", get_decomp_ctxt_ptr(scf));
}
EXPORT_SYMBOL(print_decompression_input_scf);

void print_decompression_output_scf(struct scf_64b *scf)
{
	pr_info(" Decompression Output SCF @ %p:\n", scf);
	pr_info("   TOTAL IN ----------- %u\n", get_total_in(scf));
	pr_info("   TOTAL OUT ---------- %u\n", get_total_out(scf));
	pr_info("   ADLER32 ------------ %#x\n", get_adler32(scf));
	pr_info("   XO ----------------- %u\n", get_xo(scf));
	pr_info("   NO ----------------- %u\n", get_no(scf));
	pr_info("   CO ----------------- %u\n", get_co(scf));
	pr_info("   BYTES PROCESSED ---- %u\n", get_bytes_processed(scf));
	pr_info("   ID1 ---------------- %#x\n", get_id1(scf));
	pr_info("   ID2 ---------------- %#x\n", get_id2(scf));
	pr_info("   CM ----------------- %#x\n", get_cm(scf));
	pr_info("   FLG ---------------- %#x\n", get_flg(scf));
	pr_info("   MTIME -------------- %u\n", get_mtime(scf));
	pr_info("   XFL ---------------- %#x\n", get_xfl(scf));
	pr_info("   OS ----------------- %#x\n", get_os(scf));
	pr_info("   XLEN --------------- %u\n", get_xlen(scf));
	pr_info("   NLEN --------------- %u\n", get_nlen(scf));
	pr_info("   CLEN --------------- %u\n", get_clen(scf));
	pr_info("   EXTRA_LIMIT -------- %u\n", get_extra_limit(scf));
	pr_info("   EXTRA_PTR ---------- %#010llx\n", get_extra_ptr(scf));
}
EXPORT_SYMBOL(print_decompression_output_scf);

void print_decompression_output_scf_debug(struct scf_128b *scf)
{
	struct scf_64b *cl1 = (struct scf_64b *)scf;

	pr_info(" Decompression Output DEBUG SCF @ %p:\n", scf);
	pr_info("   TOTAL IN ----------- %u\n", get_total_in(cl1));
	pr_info("   TOTAL OUT ---------- %u\n", get_total_out(cl1));
	pr_info("   ADLER32 ------------ %#x\n", get_adler32(cl1));
	pr_info("   XO ----------------- %u\n", get_xo(cl1));
	pr_info("   NO ----------------- %u\n", get_no(cl1));
	pr_info("   CO ----------------- %u\n", get_co(cl1));
	pr_info("   OUTPUT PHASE ------- %u\n", get_output_phase(cl1));
	pr_info("   B64 RESIDUE LEN ---- %u\n", get_b64_residue_len(cl1));
	pr_info("   B64 RESIDUE -------- %#x\n", get_b64_residue(cl1));
	pr_info("   ID1 ---------------- %#x\n", get_id1(cl1));
	pr_info("   ID2 ---------------- %#x\n", get_id2(cl1));
	pr_info("   CM ----------------- %#x\n", get_cm(cl1));
	pr_info("   FLG ---------------- %#x\n", get_flg(cl1));
	pr_info("   MTIME -------------- %u\n", get_mtime(cl1));
	pr_info("   XFL ---------------- %#x\n", get_xfl(cl1));
	pr_info("   OS ----------------- %#x\n", get_os(cl1));
	pr_info("   XLEN --------------- %u\n", get_xlen(cl1));
	pr_info("   NLEN --------------- %u\n", get_nlen(cl1));
	pr_info("   CLEN --------------- %u\n", get_clen(cl1));
	pr_info("   EXTRA_LIMIT -------- %u\n", get_extra_limit(cl1));
	pr_info("   EXTRA_PTR ---------- %#010llx\n", get_extra_ptr(cl1));
	pr_info("   PENDING OUTPUT LEN - %u\n", get_pending_output_len(cl1));
	pr_info("   PENDING WRKING PTR - %#x\n", get_pending_working_ptr(cl1));
	pr_info("   PENDING_OUTPUT_PTR - %#010llx\n",
						get_pending_output_ptr(cl1));
	pr_info("   HISTORY LEN -------- %u\n", get_history_len(cl1));
	pr_info("   HISTORY_PTR -------- %#010llx\n", get_history_ptr(cl1));
	pr_info("   PMODE -------------- %u\n", get_pmode(cl1));
	pr_info("   SUSP --------------- %u\n", get_susp(cl1));
	pr_info("   TERMINATED --------- %u\n", get_terminated(cl1));
	pr_info("   CRC16 -------------- %#x\n", get_crc16(cl1));

	/* next 64-byte cache line */
	pr_info("   DECOMP CTXT PTR ---- %#010llx\n",
		get_decomp_ctxt_ptr_cl2(scf));
	pr_info("   PREVIOUS CODE LEN -- %u\n", get_previous_code_len_cl2(scf));
	pr_info("   BFINAL ------------- %u\n", get_bfinal_cl2(scf));
	pr_info("   BTYPE -------------- %u\n", get_btype_cl2(scf));
	pr_info("   FRAME PARSE STATE -- %u\n", get_frame_parse_state_cl2(scf));
	pr_info("   NUM CODE LEN ------- %u\n", get_num_code_len_cl2(scf));
	pr_info("   NCBB REMAINING ----- %u\n", get_ncbb_remaining_cl2(scf));
	pr_info("   HLIT --------------- %u\n", get_hlit_cl2(scf));
	pr_info("   HDIST -------------- %u\n", get_hdist_cl2(scf));
	pr_info("   HCLEN -------------- %u\n", get_hclen_cl2(scf));
	pr_info("   HUFFMAN RBC -------- %u\n", get_huffman_rbc_cl2(scf));
	pr_info("   HUFFMAN RESIDUE ---- %#012llx\n",
		get_huffman_residue_cl2(scf));
}
EXPORT_SYMBOL(print_decompression_output_scf_debug);

void print_dce_fd(struct qm_fd fd)
{
	pr_info(" Frame Descriptor:\n");
	pr_info("   DD --------------- %#x\n", fd.dd);
	pr_info("   LIODN ------------ %#x\n", fd.liodn_offset);
	pr_info("   BPID ------------- %#x\n", fd.bpid);
	pr_info("   ELIODN ----------- %#x\n", fd.eliodn_offset);
	pr_info("   ADDRESS ---------- %#010llx\n", (u64)fd.addr);
	if (fd.format == 0 || fd.format == 4)
		pr_info("   - ADDRESS + OFFSET %#010llx\n",
			(u64)fd.addr + fd.offset);
	if (fd.format == 0)
		pr_info("   FORMAT ----------- Short_SingleFrame\n");
	else if (fd.format == 2)
		pr_info("   FORMAT ----------- Long_SingleFrame\n");
	else if (fd.format == 4)
		pr_info("   FORMAT ----------- Short_MultiFrame\n");
	else if (fd.format == 6)
		pr_info("   FORMAT ----------- Long_MultiFrame\n");
	else if (fd.format == 1)
		pr_info("   FORMAT ----------- CompoundFrame\n");
	else
		pr_info("   FORMAT ----------- UNKNOWN Frame\n");
	if (fd.format == 0 || fd.format == 4) {
		pr_info("   OFFSET ----------- %#x\n", fd.offset);
		pr_info("   SHORT LENGTH ----- %#x\n", fd.length20);
	}
	if (fd.format == 2 || fd.format == 6)
		pr_info("   LONG LENGTH ----- %#x\n", fd.length29);
	if (fd.format == 1)
		pr_info("   CONG WEIGHT ----- %#x\n", fd.cong_weight);
		pr_info("   STATUS/CMD ------ %#0x\n", fd.cmd);
}
EXPORT_SYMBOL(print_dce_fd);

void print_dce_sg(struct qm_sg_entry sg)
{
	pr_info(" Scatter/Gather Table Entry:\n");
	pr_info("   RESERVED --------- %#06x\n", sg.__notaddress);
	pr_info("   ADDRESS ---------- %#010llx\n", (u64)sg.addr);
	pr_info("   E ---------------- %#x\n", sg.extension);
	pr_info("   F ---------------- %#x\n", sg.final);
	pr_info("   LENGTH ----------- %#x\n", sg.length);
	pr_info("   RESERVED2 -------- %#02x\n", sg.__reserved2);
	pr_info("   BPID ------------- %#x\n", sg.bpid);
	pr_info("   RESERVED3 -------- %#x\n", sg.__reserved3);
	pr_info("   OFFSET ----------- %#x\n", sg.offset);
}
EXPORT_SYMBOL(print_dce_sg);

void print_multi_buffer(struct qm_sg_entry *sg, int level)
{
	struct qm_sg_entry *entry = sg;

	pr_info("multi-buffer level %d\n", level);
print_next:
	print_dce_sg(*entry);
	if (entry->extension) {
		dma_addr_t phy_addr;
		void *cpumem;

		phy_addr = qm_sg_addr(sg);
		cpumem = phys_to_virt(phy_addr);
		print_multi_buffer(cpumem, ++level);
	} else {
		if (entry->final)
			pr_info("Done level %d\n", level);
		else {
			entry++;
			goto print_next;
		}
	}
}
EXPORT_SYMBOL(print_multi_buffer);

void print_dce_data_list(struct dce_data_list_t *data_list)
{
	int i;

	pr_info("dce_data_list = %p\n", data_list);

	pr_info("  sg = %p, nents = %u, data_item = %p\n",
		data_list->sg, data_list->nents, data_list->data_item);

	if (data_list->data_item == NULL)
		return;

	if (data_list->sg) {
		pr_info("Multi-Buffer\n");
		for (i = 0; i < data_list->nents; i++) {
			pr_info("    cpumem = %p, size = %zu, d_size = %zu\n",
				data_list->data_item[i].cpumem,
				data_list->data_item[i].size,
				data_list->data_item[i].d_size);
			print_hex_dump(KERN_ERR, "      data@"AT": ",
				DUMP_PREFIX_ADDRESS, 16, 4,
				data_list->data_item[i].cpumem, 16, false);
		}
		for (i = 0; i < data_list->nents; i++)
			print_dce_sg(data_list->sg[i]);
	} else {
		pr_info("Single Buffer\n");
		pr_info("    cpumem = %p, size = %zu, d_size = %zu\n",
			data_list->data_item->cpumem,
			data_list->data_item->size,
			data_list->data_item->d_size);
		print_hex_dump(KERN_ERR, "      data@"AT": ",
				DUMP_PREFIX_ADDRESS, 16, 4,
				data_list->data_item->cpumem, 16, false);

	}
}
EXPORT_SYMBOL(print_dce_data_list);

bool is_multi_buffer(struct dce_data_list_t *data)
{
	return (data->sg != NULL);
}
EXPORT_SYMBOL(is_multi_buffer);


int alloc_dce_data(size_t length, size_t block_size,
			struct dce_data_list_t *dce_data)
{
	size_t num_entries;
	struct dce_data_item_t *data_item = NULL;
	size_t last_buf_size;
	int i;

	if ((block_size == 0) || !dce_data)
		return -EINVAL;

	memset(dce_data, 0, sizeof(*dce_data));

	if (block_size >= length) {
		num_entries = 1;
		last_buf_size = block_size;
	} else {
		num_entries = length / block_size;
		last_buf_size = length - (num_entries * block_size);
		if (last_buf_size == 0)
			last_buf_size = block_size;
		else {
			num_entries++;
			last_buf_size = block_size;
		}

	}

	/* determine if multi-buffer or not */
	if (num_entries == 1) {
		dce_data->sg = NULL;
		dce_data->nents = 0;
		dce_data->data_item = kzalloc(sizeof(struct dce_data_item_t),
					GFP_KERNEL);
		if (!dce_data->data_item)
			return -ENOMEM;
		dce_data->data_item->cpumem = kmalloc(last_buf_size,
						GFP_KERNEL);
		if (!dce_data->data_item->cpumem) {
			kfree(dce_data->data_item);
			return -ENOMEM;
		}
		memset(dce_data->data_item->cpumem, 0xff, last_buf_size);
		dce_data->data_item->size = last_buf_size;
		return 0;
	}

	/* create multi-buffer */
	dce_data->sg = kzalloc(sizeof(struct qm_sg_entry) * num_entries,
			GFP_KERNEL);
	if (!dce_data->sg)
		return -ENOMEM;
	dce_data->nents = num_entries;
	dce_data->data_item = kzalloc(
		sizeof(struct dce_data_item_t) * num_entries, GFP_KERNEL);
	if (!dce_data->data_item) {
		kfree(dce_data->sg);
		return -ENOMEM;
	}

	data_item = dce_data->data_item;

	for (i = 0; i < num_entries; i++) {
		size_t size_to_alloc = block_size;

		/* if last entry, only allocate remaining */
		if (i == num_entries-1)  {
			size_to_alloc = last_buf_size;
			dce_data->sg[i].final = 1;
		}

		data_item[i].cpumem = kzalloc(size_to_alloc, GFP_KERNEL);
		if (!data_item[i].cpumem)
			goto fail_allocs;
		data_item[i].size = size_to_alloc;
		dce_data->sg[i].length = size_to_alloc;
	}
	return 0;
fail_allocs:
	/* release all allocated memory */
	for (i = 0; i < dce_data->nents; i++)
		kfree(dce_data->data_item[i].cpumem);
	kfree(dce_data->data_item);
	kfree(dce_data->sg);
	return -EINVAL;
}
EXPORT_SYMBOL(alloc_dce_data);

int free_dce_data(struct dce_data_list_t *dce_data)
{
	int i;

	if (!dce_data)
		return -EINVAL;

	/* release all allocated memory */
	for (i = 0; i < dce_data->nents; i++)
		kfree(dce_data->data_item[i].cpumem);
	kfree(dce_data->data_item);
	kfree(dce_data->sg);
	memset(dce_data, 0, sizeof(*dce_data));
	return 0;
}
EXPORT_SYMBOL(free_dce_data);

size_t total_allocated_dce_data(struct dce_data_list_t *dce_data)
{
	size_t total_size = 0;
	int i;

	if (!dce_data->sg) {
		if (!dce_data->data_item)
			return 0;
		return dce_data->data_item->size;
	}

	for (i = 0; i < dce_data->nents; i++)
		total_size += dce_data->data_item[i].size;

	return total_size;
}
EXPORT_SYMBOL(total_allocated_dce_data);

size_t total_size_dce_data(struct dce_data_list_t *dce_data)
{
	size_t total_size = 0;
	int i;

	if (!dce_data->sg) {
		if (!dce_data->data_item)
			return 0;
		return dce_data->data_item->d_size;
	}

	for (i = 0; i < dce_data->nents; i++)
		total_size += dce_data->data_item[i].d_size;

	return total_size;
}
EXPORT_SYMBOL(total_size_dce_data);

int copy_input_to_dce_data(char *input, size_t ilen,
			struct dce_data_list_t *data_list)
{
	char *data_p = input;
	size_t len = ilen;
	int i = 0;

	if (!data_p || !data_list || !data_list->data_item)
		return -EINVAL;

	if (total_allocated_dce_data(data_list) < ilen)
		return -EINVAL;

	while (len) {
		size_t to_copy = min(data_list->data_item[i].size, len);
		memcpy(data_list->data_item[i].cpumem, data_p, to_copy);
		data_list->data_item[i].d_size = to_copy;
		data_p += to_copy;
		len -= to_copy;
		i++;
	}
	return 0;
}
EXPORT_SYMBOL(copy_input_to_dce_data);

/*
 * @data_list is the source data.
 * @cpylen is how much data from data_list to copy
 * @buffer is the destination.
 * @buf_size is the size of the destination buffer
 */
int copy_output_dce_data_to_buffer(struct dce_data_list_t *data_list,
		size_t cpylen, char *buffer, size_t buf_size)
{
	int i = 0;

	if (!buffer || !data_list || !data_list->data_item) {
		pr_info("%d\n", __LINE__);
		return -EINVAL;
	}

	if (cpylen > total_allocated_dce_data(data_list)) {
		pr_info("%d\n", __LINE__);
		return -EINVAL;
	}

	if (cpylen > buf_size) {
		pr_info("%d\n", __LINE__);
		return -EINVAL;
	}

	if (!is_multi_buffer(data_list)) {
		memcpy(buffer, data_list->data_item->cpumem, cpylen);
		 data_list->data_item->d_size = cpylen;
		return 0;
	}

	while (cpylen) {
		size_t to_copy = min(data_list->data_item[i].size, cpylen);
		memcpy(buffer, data_list->data_item[i].cpumem, to_copy);
		data_list->data_item[i].d_size = to_copy;
		cpylen -= to_copy;
		buffer += to_copy;
		i++;
	}
	return 0;
}
EXPORT_SYMBOL(copy_output_dce_data_to_buffer);

int dma_map_dce_data(struct dce_data_list_t *data_list,
		enum dma_data_direction dir)
{
	int i;
	struct device *dce_device = fsl_dce_get_device();
	dma_addr_t addr;

	if (!data_list || !dce_device)
		return -EINVAL;

	if (data_list->sg == NULL)
		return 0;

	for (i = 0; i < data_list->nents; i++) {
		addr = dma_map_single(dce_device,
			data_list->data_item[i].cpumem,
			data_list->data_item[i].size,
			dir);
		if (dma_mapping_error(dce_device, addr)) {
				pr_err("unable to map i/o memory\n");
				goto fail_map;
		}
		qm_sg_entry_set64(&data_list->sg[i], addr);
	}
	return 0;

fail_map:
	for (i = 0; i < data_list->nents; i++) {
		dma_addr_t addr = qm_sg_addr(&data_list->sg[i]);
		if (addr) {
			dma_unmap_single(dce_device, addr,
				data_list->data_item[i].size, dir);
		}
	}
	return -EINVAL;
}
EXPORT_SYMBOL(dma_map_dce_data);

int dma_unmap_dce_data(struct dce_data_list_t *data_list,
		enum dma_data_direction dir)
{
	int i;
	struct device *dce_device = fsl_dce_get_device();

	if (!data_list || !dce_device)
		return -EINVAL;

	for (i = 0; i < data_list->nents; i++) {
		dma_addr_t addr = qm_sg_addr(&data_list->sg[i]);
		if (addr) {
			dma_unmap_single(dce_device, addr,
				data_list->data_item[i].size, dir);
		}
	}

	return 0;
}
EXPORT_SYMBOL(dma_unmap_dce_data);

int attach_data_list_to_sg(struct qm_sg_entry *sg,
			struct dce_data_list_t *data_list,
			bool use_raw_size,
			enum dma_data_direction dir)
{
	dma_addr_t addr;
	struct device *dce_device = fsl_dce_get_device();

	if (!data_list || !dce_device)
		return -EINVAL;

	if (is_multi_buffer(data_list)) {
		sg->extension = 1;
		addr = dma_map_single(dce_device,
			data_list->sg,
			sizeof(struct qm_sg_entry) * data_list->nents,
			dir);
		if (dma_mapping_error(dce_device, addr)) {
				pr_err("unable to map i/o memory\n");
				return -ENOMEM;
		}
		qm_sg_entry_set64(sg, addr);
	} else {
		sg->extension = 0;
		addr = dma_map_single(dce_device,
			data_list->data_item->cpumem,
			data_list->data_item->size,
			dir);
		if (dma_mapping_error(dce_device, addr)) {
				pr_err("unable to map i/o memory\n");
				return -ENOMEM;
		}
		qm_sg_entry_set64(sg, addr);
	}
	if (use_raw_size)
		sg->length = total_allocated_dce_data(data_list);
	else
		sg->length = total_size_dce_data(data_list);

	return 0;
}
EXPORT_SYMBOL(attach_data_list_to_sg);

int detach_data_list_from_sg(struct qm_sg_entry *sg,
			struct dce_data_list_t *data_list,
			enum dma_data_direction dir)
{
	dma_addr_t addr;
	struct device *dce_device = fsl_dce_get_device();

	if (!data_list || !dce_device)
		return -EINVAL;

	if (data_list->data_item == NULL)
		return 0;

	if (is_multi_buffer(data_list)) {
		addr = qm_sg_addr(sg);
		dma_unmap_single(dce_device, addr,
			sizeof(struct qm_sg_entry) * data_list->nents, dir);
	} else {
		addr =  qm_sg_addr(sg);
		dma_unmap_single(dce_device,  addr,
			data_list->data_item->size, dir);
	}
	return 0;
}
EXPORT_SYMBOL(detach_data_list_from_sg);

int attach_scf64_to_sg(struct qm_sg_entry *sg,
			struct scf_64b *scf,
			enum dma_data_direction dir)
{
	dma_addr_t addr;
	struct device *dce_device = fsl_dce_get_device();

	if (!scf || !dce_device)
		return -EINVAL;

	sg->extension = 0;
	addr = dma_map_single(dce_device, scf, sizeof(*scf), dir);
	if (dma_mapping_error(dce_device, addr)) {
			pr_err("unable to map i/o memory\n");
			return -ENOMEM;
	}
	qm_sg_entry_set64(sg, addr);
	sg->length = sizeof(*scf);
	return 0;
}
EXPORT_SYMBOL(attach_scf64_to_sg);

int detach_scf64_from_sg(struct qm_sg_entry *sg,
			struct scf_64b *scf,
			enum dma_data_direction dir)
{
	dma_addr_t addr;
	struct device *dce_device = fsl_dce_get_device();

	if (!scf || !dce_device)
		return -EINVAL;

	addr =  qm_sg_addr(sg);
	dma_unmap_single(dce_device, addr, sizeof(*scf), dir);
	return 0;
}
EXPORT_SYMBOL(detach_scf64_from_sg);

int attach_scf128_to_sg(struct qm_sg_entry *sg,
			struct scf_128b *scf,
			enum dma_data_direction dir)
{
	dma_addr_t addr;
	struct device *dce_device = fsl_dce_get_device();

	if (!scf || !dce_device)
		return -EINVAL;

	sg->extension = 0;
	addr = dma_map_single(dce_device, scf, sizeof(*scf), dir);
	if (dma_mapping_error(dce_device, addr)) {
			pr_err("unable to map i/o memory\n");
			return -ENOMEM;
	}
	qm_sg_entry_set64(sg, addr);
	sg->length = sizeof(*scf);
	return 0;
}
EXPORT_SYMBOL(attach_scf128_to_sg);

int detach_scf128_from_sg(struct qm_sg_entry *sg,
			struct scf_128b *scf,
			enum dma_data_direction dir)
{
	dma_addr_t addr;
	struct device *dce_device = fsl_dce_get_device();

	if (!scf || !dce_device)
		return -EINVAL;

	addr =  qm_sg_addr(sg);
	dma_unmap_single(dce_device, addr, sizeof(*scf), dir);
	return 0;
}
EXPORT_SYMBOL(detach_scf128_from_sg);

int alloc_set_gzip_filename(struct dce_process_cf_gzip_req *req, char *name)
{
	if (name == NULL) {
		req->filename = NULL;
		return 0;
	}

	req->filename = kmalloc(strlen(name) + 1, GFP_KERNEL);
	if (req->filename == NULL)
		return -ENOMEM;

	memcpy(req->filename, name, strlen(name) + 1);
	return 0;
}
EXPORT_SYMBOL(alloc_set_gzip_filename);

int free_clear_gzip_filename(struct dce_process_cf_gzip_req *req)
{
	kfree(req->filename);
	req->filename = NULL;
	return 0;
}
EXPORT_SYMBOL(free_clear_gzip_filename);

int alloc_set_gzip_comment(struct dce_process_cf_gzip_req *req, char *name)
{
	if (name == NULL) {
		req->comment = NULL;
		return 0;
	}

	req->comment = kmalloc(strlen(name) + 1, GFP_KERNEL);
	if (req->comment == NULL)
		return -ENOMEM;

	memcpy(req->comment, name, strlen(name) + 1);
	return 0;
}
EXPORT_SYMBOL(alloc_set_gzip_comment);

int free_clear_gzip_comment(struct dce_process_cf_gzip_req *req)
{
	kfree(req->comment);
	req->comment = NULL;
	return 0;
}
EXPORT_SYMBOL(free_clear_gzip_comment);



