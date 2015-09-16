/* Copyright 2008-2012 Freescale Semiconductor, Inc.
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

/*
 * External prototypes for the circular queue object.
 */

#ifndef __CQ_H
#define __CQ_H

#include <linux/types.h>
#include <linux/mutex.h>

/* Circular queue structure */
struct cq {
	int max_items;		/* Size of queue */
	int item_size;		/* Size of each item in the queue */
	int items_in_queue;	/* Number of items in the queue */
	int first;			/* Index of first item in queue */
	struct mutex cq_lock;	/* Circular queue lock */
	uint8_t items[0];		/* Holds the elements in the queue -
					 * fake size */
};

/* Allocate and initialize a new circular queue */
struct cq *cq_new(int max_items, int item_size);

/* Delete a circular queue */
void cq_delete(struct cq *cq);

/* Empty the circular queue (clear all items) */
int cq_flush(struct cq *cq);

/*
 * Put a new item in the circular queue
 * Return number of items in the queue (including the added item) is successful
 * or (-1) if failed to put the item (queue is full)
 */
int cq_put(struct cq *cq, void *item);

/* Put a new 1-byte item in the circular queue
 * Return number of items in the queue (including the added item) is successful
 * or (-1) if failed to put the item (queue is full)
 */
int cq_put_1byte(struct cq *cq, uint8_t item);

/*
 * Put a new 2-byte item in the circular queue
 * Return number of items in the queue (including the added item) is successful
 * or (-1) if failed to put the item (queue is full)
 */
int cq_put_2bytes(struct cq *cq, uint16_t item);

/*
 * Put a new 4-byte item in the circular queue
 * Return number of items in the queue (including the added item) is successful
 * or (-1) if failed to put the item (queue is full)
 */
int cq_put_4bytes(struct cq *cq, uint32_t item);

/*
 * Put a new 8-byte item in the circular queue
 * Return number of items in the queue (including the added item) is successful
 * or (-1) if failed to put the item (queue is full)
 */
int cq_put_8bytes(struct cq *cq, uint64_t item);

/* Get (and removes) an item from the circular queue
 * Return number of items left in the queue if successful or (-1) if failed to
 * get an item (queue is empty)
 */
int cq_get(struct cq *cq, void *item);

/*
 * Get and removes a 1-byte item from the circular queue
 * Return number of items left in the queue if successful or (-1) if failed to
 * get an item (queue is empty)
 */
int cq_get_1byte(struct cq *cq, uint8_t *item);

/*
 * Get and removes a 2-byte item from the circular queue
 * Return number of items left in the queue if successful or (-1) if failed to
 * get an item (queue is empty)
 */
int cq_get_2bytes(struct cq *cq, uint16_t *item);

/*
 * Get and removes a 4-byte item from the circular queue
 * Return number of items left in the queue if successful or (-1) if failed to
 * get an item (queue is empty)
 */
int cq_get_4bytes(struct cq *cq, uint32_t *item);

/*
 * Get and removes a 8-byte item from the circular queue
 * Return number of items left in the queue if successful or (-1) if failed to
 * get an item (queue is empty)
 */
int cq_get_8bytes(struct cq *cq, uint64_t *item);

/* Return the number of items that are currently in the queue */
int cq_items_in_queue(struct cq *cq);

/*
 * Read an item in the queue. The contents of the queue are not altered.
 * Return number of items left in the queue if successful or (-1) if failed to
 * read the item (either the queue is empty, or the requested position exceeds
 * number of items)
 */
int cq_read(struct cq *cq, void *item, int position);

#endif /* __CQ_H */
