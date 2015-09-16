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
 * Source file for the Circular Queue object.
 * Elements are put in and taken out of the queue in FIFO order.
 * In addition any position in the queue may be read (without
 * affecting the contents of the queue). The size of each item
 * in the queue is set when the queue is initialized.
 */

#include "cq.h"

#include <linux/slab.h>
#include <linux/delay.h>

struct cq *cq_new(int max_items, int item_size)
{
	struct cq *cq;

	BUG_ON(!max_items);
	BUG_ON(!item_size);

	cq = kmalloc(sizeof(*cq) + max_items * item_size, GFP_KERNEL);
	if (cq) {
		cq->max_items = max_items;
		cq->item_size = item_size;
		cq->items_in_queue = 0;
		cq->first = 0;
		mutex_init(&cq->cq_lock);
		memset(cq->items, 0, max_items * item_size);
	}

	return cq;
}

void cq_delete(struct cq *cq)
{
	BUG_ON(!cq);
	while (mutex_is_locked(&cq->cq_lock)) {
		udelay(100);
		cpu_relax();
	}
	kfree(cq);
}

int cq_flush(struct cq *cq)
{
	int items_in_queue;

	BUG_ON(!cq);

	/* Acquire circular queue lock */
	mutex_lock(&cq->cq_lock);

	items_in_queue = cq->items_in_queue;
	cq->first = 0;
	cq->items_in_queue = 0;
	memset(cq->items, 0, cq->max_items * cq->item_size);

	/* Release circular queue lock */
	mutex_unlock(&cq->cq_lock);

	return items_in_queue;
}

int cq_put(struct cq *cq, void *item)
{
	int put_pos, max_items, first, items_in_queue, item_size;
	uint8_t *byte = (uint8_t *)item;

	BUG_ON(!cq);

	/* Acquire circular queue lock */
	mutex_lock(&cq->cq_lock);

	first = cq->first;
	max_items = cq->max_items;
	items_in_queue = cq->items_in_queue;
	item_size = cq->item_size;

	/* Check if queue is full */
	if (items_in_queue == max_items) {
		mutex_unlock(&cq->cq_lock);
		return -1;
	}

	if ((first + items_in_queue) < max_items)
		put_pos = (first + items_in_queue) * item_size;
	else
		put_pos = (first + items_in_queue - max_items) * item_size;

	/* add element to queue */
	memcpy(cq->items + put_pos, byte, item_size);

	cq->items_in_queue++;

	/* Release circular queue lock */
	mutex_unlock(&cq->cq_lock);

	return items_in_queue + 1;
}

int cq_put_1byte(struct cq *cq, uint8_t item)
{
	BUG_ON(!cq);
	BUG_ON(cq->item_size != 1);

	return cq_put(cq, &item);
}

int cq_put_2bytes(struct cq *cq, uint16_t item)
{
	BUG_ON(!cq);
	BUG_ON(cq->item_size != 2);

	return cq_put(cq, &item);
}

int cq_put_4bytes(struct cq *cq, uint32_t item)
{
	BUG_ON(!cq);
	BUG_ON(cq->item_size != 4);

	return cq_put(cq, &item);
}

int cq_put_8bytes(struct cq *cq, uint64_t item)
{
	BUG_ON(!cq);
	BUG_ON(cq->item_size != 8);

	return cq_put(cq, &item);
}

int cq_get(struct cq *cq, void *item)
{
	int get_pos, items_in_queue, item_size, first;
	uint8_t *byte = (uint8_t *)item;

	BUG_ON(!cq);
	BUG_ON(!item);

	/* Acquire circular queue lock */
	mutex_lock(&cq->cq_lock);

	items_in_queue = cq->items_in_queue;
	/* Check if queue is empty */
	if (items_in_queue == 0) {
		/* Release circular queue lock */
		mutex_unlock(&cq->cq_lock);
		return -1;
	}

	first = cq->first;
	item_size = cq->item_size;
	get_pos = first * item_size;

	/* Get item from queue */
	memcpy(byte, cq->items + get_pos, item_size);
	cq->items_in_queue--;

	if (++first >= cq->max_items)
		first = 0;
	cq->first = first;

	/* Release circular queue lock */
	mutex_unlock(&cq->cq_lock);

	return items_in_queue - 1;
}

int cq_get_1byte(struct cq *cq, uint8_t *item)
{
	BUG_ON(!cq);
	BUG_ON(!item);
	BUG_ON(cq->item_size != 1);

	return cq_get(cq, item);
}

int cq_get_2bytes(struct cq *cq, uint16_t *item)
{
	BUG_ON(!cq);
	BUG_ON(!item);
	BUG_ON(cq->item_size != 2);

	return cq_get(cq, item);
}

int cq_get_4bytes(struct cq *cq, uint32_t *item)
{
	BUG_ON(!cq);
	BUG_ON(!item);
	BUG_ON(cq->item_size != 4);

	return cq_get(cq, item);
}

int cq_get_8bytes(struct cq *cq, uint64_t *item)
{
	BUG_ON(!cq);
	BUG_ON(!item);
	BUG_ON(cq->item_size != 8);

	return cq_get(cq, item);
}

int cq_items_in_queue(struct cq *cq)
{
	int items_in_queue;

	BUG_ON(!cq);

	/* Acquire circular queue lock */
	mutex_lock(&cq->cq_lock);

	items_in_queue = cq->items_in_queue;

	/* Release circular queue lock */
	mutex_unlock(&cq->cq_lock);

	return items_in_queue;
}

int cq_read(struct cq *cq, void *read_item, int position)
{
	int item_size, first, items_in_queue, bytePosition;
	uint8_t *read_byte = (uint8_t *)read_item;

	BUG_ON(!cq);
	BUG_ON(!read_item);

	/* Acquire circular queue lock */
	mutex_lock(&cq->cq_lock);

	items_in_queue = cq->items_in_queue;
	/* Check if queue is empty and if position is valid */
	if (items_in_queue == 0 || position > items_in_queue) {
		mutex_unlock(&cq->cq_lock);
		return -1;
	}

	item_size = cq->item_size;
	first = cq->first;

	/* Find byte position */
	if (first + position - 1 > cq->max_items)
		bytePosition =
			(first + position - 1 - cq->max_items) * item_size;
	else
		bytePosition = (first + position - 1) * item_size;

	/* Read from queue */
	memcpy(read_byte, cq->items + bytePosition, item_size);

	/* Release circular queue lock */
	mutex_unlock(&cq->cq_lock);

	return items_in_queue;
}
