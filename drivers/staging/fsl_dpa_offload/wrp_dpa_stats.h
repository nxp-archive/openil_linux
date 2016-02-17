
/* Copyright 2008-2013 Freescale Semiconductor, Inc.
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

#ifndef WRP_DPA_STATS_H_
#define WRP_DPA_STATS_H_

/* Other includes */
#include "linux/fs.h"
#include <linux/fsl_dpa_stats.h>
#include <linux/compat.h>

#define DPA_STATS_CDEV				"dpa_stats"

int	wrp_dpa_stats_init(void);

int	wrp_dpa_stats_exit(void);

int	wrp_dpa_stats_open(struct inode *inode, struct file *filp);

int	wrp_dpa_stats_release(struct inode *inode, struct file *filp);

ssize_t wrp_dpa_stats_read(struct file *file,
			   char *buf, size_t count, loff_t *off);

long	wrp_dpa_stats_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long args);

#ifdef CONFIG_COMPAT
long	wrp_dpa_stats_compat_ioctl(struct file *filp, unsigned int cmd,
				   unsigned long args);
#endif

#define QUEUE_MAX_EVENTS 2048

struct dpa_stats_event_params {
	int			dpa_stats_id;
	unsigned int		storage_area_offset;
	unsigned int		cnts_written;
	int			bytes_written;
};

struct dpa_stats_event_queue {
	struct list_head    lh;     /* Double linked list of events */
	wait_queue_head_t   wq;     /* Waitqueue for reader processes */
	atomic_t            count;  /* Number of events in the event queue */
};

struct dpa_stats_event {
	struct dpa_stats_event_params  params;     /* Event data */
	struct list_head    lh;         /* Event queue list head */
	int *us_cnt_ids; /* Request array of counter ids from user-space */
	int *ks_cnt_ids; /* Request array of counter ids from kernel-space */
	unsigned int cnt_ids_len; /* Number of counter ids in array */
};

struct dpa_stats_async_req_ev {
	dpa_stats_request_cb request_done; /* Request done callback */
	unsigned int storage_area_offset; /* Storage offset for this request */
	/* Pointers to other async requests in the current set  */
	struct list_head node;
	int *us_cnt_ids; /* Request array of counter ids from US */
	int *ks_cnt_ids; /* Request array of counter ids from KS */
	unsigned int cnt_ids_len; /* Number of counter ids in array */
};

struct wrp_dpa_stats_cb {
	void  *us_mem; /* Pointer to user-space storage area memory */
	void  *k_mem;  /* Pointer to kernel-space storage area memory */
	struct dpa_stats_event_queue ev_queue; /* Event queue */
	/* Group of asynchronous requests based on CRC collision */
	struct list_head *async_req_group;
	struct list_head async_req_pool; /* List of free async request nodes */
	struct mutex async_req_lock; /* Mutex for operations on async reqs */
	struct mutex event_queue_lock; /* Mutex for operations on async reqs */
};

#endif	/* WRP_DPA_STATS_H_ */
