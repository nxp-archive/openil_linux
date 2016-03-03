/* Copyright (C) 2015 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/sched.h>
#include "dce.h"

/* data set */
#include "dce-test-data.h"

MODULE_AUTHOR("Freescale Semicondictor, Inc");
MODULE_DESCRIPTION("DCE API Time trial test");
MODULE_LICENSE("Dual BSD/GPL");

static DECLARE_WAIT_QUEUE_HEAD(replies_wait);

struct dma_item {
	void *vaddr;
	struct dpaa2_fd fd;
	dma_addr_t paddr;
	size_t size;
};

struct work_ctxt {
	struct dce_session *session;
	uint8_t status;
	struct dpaa2_fd input_fd;
	struct dpaa2_fd output_fd;
	size_t input_consumed;
};

static int test_time = 30;
static int iterations = 40000;
static bool verbose;
static int level = DCE_SESSION_CE_BEST_POSSIBLE; /* best possible = 3 */

static int cb_count, count, cb_j1, cb_j2;
static struct work_ctxt glbl_ctxt;
static int data_len = 8192;

module_param(test_time, int, 0);
MODULE_PARM_DESC(test_time, " The time in seconds to run the test for");

module_param(data_len, int, 0);
MODULE_PARM_DESC(data_len, " The size of work units to pass to DCE");

module_param(verbose, bool, 0);
MODULE_PARM_DESC(verbose, " Run test in verbose mode");

module_param(level, int, 0);
MODULE_PARM_DESC(level, " The compression level from 0 to 3, 3 being highest");

static void global_cb(struct dce_session *session,
			uint8_t status,
			struct dpaa2_fd *input_fd,
			struct dpaa2_fd *output_fd,
			size_t input_consumed,
			void *context)
{
	cb_count++;
	if (cb_count == 1)
		cb_j1 = jiffies;
	/* initially count = 0, we wait till it gets set in main */
	if (!count || cb_count < count)
		return;
	cb_j2 = jiffies;
	glbl_ctxt.session = session;
	glbl_ctxt.status = status;
	glbl_ctxt.input_fd = *input_fd;
	glbl_ctxt.output_fd = *output_fd;
	glbl_ctxt.input_consumed = input_consumed;
	wake_up(&replies_wait);
}

static __init int dce_api_time_trial_init(void)
{
	int err, i;
	unsigned long timeout, eq_time = 0, start_time, end_time, speed, j_1,
				j_2, busy_count = 0, total_time, dq_time,
				compression_percentage;
	struct dce_session_params params = {0};
	struct dce_session session;
	struct dma_item input;
	struct dma_item output;
	struct dpaa2_fd empty_fd = {.words = {0, 0, 0, 0, 0, 0, 0, 0} };
	struct fsl_mc_device *device;
	char *data;

	/* Check that the module parameters are within bounds */
	if (data_len <= dce_test_data_size) {
		data = dce_test_data;
	} else {
		pr_err("Data size requested is unsupported\n");
		return -EINVAL;
	}

	/* Setup a compression session */
	params.engine = DCE_COMPRESSION;
	params.paradigm = DCE_SESSION_STATEFUL_RECYCLE;
	params.compression_format = DCE_SESSION_CF_ZLIB;
	params.compression_effort = level;
	params.callback_frame = global_cb; /* setup callback */

	err = dce_session_create(&session, &params);
	if (err) {
		pr_err("can't get dce session\n");
		return err;
	}

	/* Setup input */
	input.vaddr = kmalloc(data_len, GFP_DMA);
	if (!input.vaddr)
		goto err_alloc_in_data;
	input.size = data_len;
	memcpy(input.vaddr, data, data_len);

	/* setup output */
	output.vaddr = kzalloc(data_len+100, GFP_DMA);
	if (!output.vaddr)
		goto err_alloc_out_data;
	output.size = data_len+100;

	/* setup data to compress, dma mapping */
	device = dce_session_device(&session);
	input.paddr = dma_map_single(&device->dev,
		input.vaddr, input.size,
		DMA_BIDIRECTIONAL);
	output.paddr = dma_map_single(&device->dev,
		output.vaddr, output.size,
		DMA_BIDIRECTIONAL);

	/* Input */
	input.fd = empty_fd; /* Would use {0} initialiser, but gcc bug warn */
	dpaa2_fd_set_addr(&input.fd, input.paddr);
	dpaa2_fd_set_len(&input.fd, input.size);
	if (verbose)
		pr_info("Setting input len to %zu\n",  input.size);
	/* Output */
	output.fd = empty_fd;
	dpaa2_fd_set_addr(&output.fd, output.paddr);
	dpaa2_fd_set_len(&output.fd, output.size);
	if (verbose) {
		pr_info("Setting output len to %zu\n",  output.size);

		pr_info("Before processing compression\n");
		pretty_print_fd((struct fd_attr *)&input.fd);
		pretty_print_fd((struct fd_attr *)&output.fd);
		hexdump(&input.fd, sizeof(input.fd));
		hexdump(&output.fd, sizeof(output.fd));
	}

	pr_info("Running compression test for %d seconds ...\n", test_time);
	test_time *= HZ; /* convert to jiffies */
	start_time = jiffies; /* set the start time */
	while (jiffies < (test_time + start_time)) {
		i = 0;
		j_1 = jiffies; /* read current time */
		/* send frames for processing */
		while (i < iterations) {
			err = dce_process_frame(&session,
						&input.fd,
						&output.fd,
						DCE_Z_FINISH,
						1, /* Initial */
						0, /* Recycle */
						NULL);
			if (err == -EBUSY) {
				busy_count++;
				continue;
			} else if (err) {
				pr_err("Err 0x%x in dce_process_frame\n", err);
				break;
			}
			i++;
		}
		j_2 = jiffies;
		eq_time += j_2 - j_1;
		count += i;
		/* Sleep till number of inflight work units less than 5000 */
		timeout = wait_event_timeout(replies_wait,
				(cb_count > (count - 5000)),
				msecs_to_jiffies(3500));
		if (!timeout) {
			pr_err("Error, didn't get all callbacks\n");
			goto err_timedout;
		}
	}
	/* sleep till all work units are completed */
	timeout = wait_event_timeout(replies_wait, (cb_count == count),
			msecs_to_jiffies(3500));
	end_time = jiffies;
	if (!timeout) {
		pr_err("Error, didn't get all callbacks\n");
		goto err_timedout;
	}

	eq_time = (eq_time * 1000) / HZ; /* elapsed time in msec */
	speed = (count * input.size * 1000 * 8) / eq_time; /* bit/s */

	/* Copy the results back to our FDs */
	input.fd = glbl_ctxt.input_fd;
	output.fd = glbl_ctxt.output_fd;

	input.size = fd_attr_get_data_len_32((struct fd_attr *)&input.fd);
	output.size = fd_attr_get_data_len_32((struct fd_attr *)&output.fd);

	compression_percentage = 100 * output.size / input.size;
	pr_info("Number of work units %d, work unit size %d, compression ratio (out/in) %lu%%\n",
			count, data_len, compression_percentage);
	if (verbose)
		pr_info("DCE Driver API performance = %lu bit/s and time is %lu ms\n",
				speed, eq_time);
	total_time = ((end_time - start_time) * 1000) / HZ;
	speed = (count * input.size * 1000 * 8) / total_time; /* bit/s */
	pr_info("DCE Driver API & DCE performance = %lu bit/s and time is %lu ms\n",
		       speed, total_time);

	dq_time = ((cb_j2 - cb_j1) * 1000) / HZ; /* elapsed time in msec */
	speed = (count * input.size * 1000 * 8) / dq_time; /* bit/s */
	if (verbose)
		pr_info("DCE performance = %lu bit/s and time is %lu ms\n",
			speed, dq_time);
	if (busy_count)
		pr_info("Number of times we received EBUSY %lu\n", busy_count);
	if (verbose) {
		pr_info("Received Final Compression Response\n");
		pr_info("glbl_ctxt: session 0x%p, status 0x%x, input_consumed %zu\n",
			glbl_ctxt.session, glbl_ctxt.status,
			glbl_ctxt.input_consumed);
	}

	/* Process response */
	if (verbose) {
		pr_info("Returned input Fd\n");
		pretty_print_fd((struct fd_attr *)&input.fd);
		pr_info("Returned Output Fd\n");
		pretty_print_fd((struct fd_attr *)&output.fd);
		pr_info("Output FD length is %d\n",
			fd_attr_get_data_len_32((struct fd_attr *)&output.fd));

		pr_info("TEST decode\n");
		pr_info("FRC status = 0x%x\n",
			glbl_ctxt.status);

		pr_info("After enqueue\n");
		pr_info("Received all frames\n");
	}

	dce_session_destroy(&session);

	/*********************************************************************/
	/* Now decompress the compressed data */

	/* Setup a decompression session */
	params.engine = DCE_DECOMPRESSION;
	/* will keep the rest of the parameters as the were from compression */
	err = dce_session_create(&session, &params);
	if (err)
		return err;

	/* This might not be necessary, but it is a good idea to clear the old
	 * input out because it is our test criteria in the end */
	memset(input.vaddr, 0, input.size);

	/* Input */
	dpaa2_fd_set_addr(&input.fd, output.paddr);
	dpaa2_fd_set_len(&input.fd,
		dpaa2_fd_get_len(&output.fd));
	if (verbose) {
		pr_info("Len of input is: %d\n",
			dpaa2_fd_get_len((&input.fd)));
	}
	/* Output */
	dpaa2_fd_set_addr(&output.fd, input.paddr);
	dpaa2_fd_set_len(&output.fd, input.size);
	if (verbose) {
		pr_info("Len of output buffer is: %d\n",
			dpaa2_fd_get_len((&output.fd)));
		pr_info("Before processing decompression\n");
		pretty_print_fd((struct fd_attr *)&input.fd);
		pretty_print_fd((struct fd_attr *)&output.fd);
		hexdump(&input.fd, sizeof(input.fd));
		hexdump(&output.fd, sizeof(output.fd));
	}

	test_time /= HZ; /* Convert time back to seconds */
	pr_info("Running decompression test for %d seconds ...\n", test_time);
	test_time *= HZ; /* Convert time to jiffies */
	cb_count = busy_count = count = eq_time = dq_time = 0;
	start_time = jiffies; /* set the start time */
	while (jiffies < (test_time + start_time)) {
		i = 0;
		j_1 = jiffies; /* read current time */
		/* send frames for processing */
		while (i < iterations) {
			/* send frame for processing */
			err = dce_process_frame(&session,
						&input.fd,
						&output.fd,
						DCE_Z_FINISH,
						1, /* Initial */
						0, /* Recycle */
						NULL);

			if (err == -EBUSY) {
				busy_count++;
				continue;
			} else if (err) {
				pr_err("Err 0x%x in dce_process_frame\n", err);
				break;
			}
			i++;
		}
		j_2 = jiffies;
		eq_time += j_2 - j_1;
		count += i;
		/* Sleep till number of inflight work units less than 5000 */
		timeout = wait_event_timeout(replies_wait,
				(cb_count > (count - 5000)),
				msecs_to_jiffies(3500));
		if (!timeout) {
			pr_err("Error, didn't get all callbacks\n");
			goto err_timedout;
		}
	}
	/* sleep till all work units are completed */
	timeout = wait_event_timeout(replies_wait, (cb_count == count),
			msecs_to_jiffies(3500));
	end_time = jiffies;
	if (!timeout) {
		pr_err("Error, didn't get all callbacks\n");
		goto err_timedout;
	}

	/* Copy the results back to our FDs */
	input.fd = glbl_ctxt.input_fd;
	output.fd = glbl_ctxt.output_fd;

	input.size = fd_attr_get_data_len_32((struct fd_attr *)&input.fd);
	output.size = fd_attr_get_data_len_32((struct fd_attr *)&output.fd);

	eq_time = (eq_time * 1000) / HZ; /* elapsed time in msec */
	/* We calculate the speed using the output size instead of the input
	 * size. This is the opposite of what we do to calculate speed in
	 * compression. The reason we do this is that in decompression, the
	 * output is larger than the input and so it is the limiting factor, in
	 * compression the opposite is true */
	speed = (count * output.size * 1000 * 8) / eq_time; /* bit/s */

	compression_percentage = 100 * output.size / input.size;
	pr_info("Number of work units %d, work unit size %lu, decompression ratio (out/in) %lu%%\n",
			count, input.size, compression_percentage);
	if (verbose)
		pr_info("DCE Driver API performance = %lu bit/s and time is %lu ms\n",
				speed, eq_time);
	total_time = ((end_time - start_time) * 1000) / HZ;
	speed = (count * output.size * 1000 * 8) / total_time; /* bit/s */
	pr_info("DCE Driver API & DCE performance = %lu bit/s and time is %lu ms\n",
		       speed, total_time);

	dq_time = ((cb_j2 - cb_j1) * 1000) / HZ; /* elapsed time in msec */
	speed = (count * output.size * 1000 * 8) / dq_time; /* bit/s */
	if (verbose)
		pr_info("DCE performance = %lu bit/s and time is %lu ms\n",
			speed, dq_time);
	if (busy_count)
		pr_info("Number of times we received EBUSY %lu\n", busy_count);

	if (verbose) {
		pr_info("Received Response\n");
		pr_info("glbl_ctxt: session %p, status %x, input_consumed %zu\n",
			glbl_ctxt.session, glbl_ctxt.status,
			glbl_ctxt.input_consumed);
	}

	/* Process response */
	if (verbose) {
		pr_info("Returned input Fd\n");
		pretty_print_fd((struct fd_attr *)&input.fd);
		pr_info("Returned Output Fd\n");
		pretty_print_fd((struct fd_attr *)&output.fd);
		pr_info("Output FD length is %d\n",
				fd_attr_get_data_len_32(
					(struct fd_attr *)&output.fd));

		pr_info("TEST decode\n");
		pr_info("FRC status = 0x%x\n",
				glbl_ctxt.status);

		pr_info("After enqueue\n");
		pr_info("Received all frames\n");
	}

	/* compare original input */
	if (memcmp(data, input.vaddr, data_len))
		pr_info("Original input does NOT match decompressed data\n");
	else
		pr_info("Original input matches decompressed data\n");

err_timedout:
	err = dce_session_destroy(&session);
	if (err)
		pr_info("Error destroy session %d\n", err);
	dma_unmap_single(&session.device->dev, output.paddr, output.size,
			DMA_BIDIRECTIONAL);
	kfree(output.vaddr);
err_alloc_out_data:
	dma_unmap_single(&session.device->dev, input.paddr, input.size,
			DMA_BIDIRECTIONAL);
	kfree(input.vaddr);
err_alloc_in_data:
	return 0;
}

static void __exit dce_api_time_trial_exit(void)
{
	pr_info("%s\n", __func__);
}

module_init(dce_api_time_trial_init);
module_exit(dce_api_time_trial_exit);
