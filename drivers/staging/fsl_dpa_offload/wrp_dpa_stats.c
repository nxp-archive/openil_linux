
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

/*
 * DPA Stats Wrapper implementation.
 */
#include "wrp_dpa_stats.h"
#include "dpa_stats_ioctl.h"

/* Other includes */
#include <linux/crc8.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include <linux/atomic.h>
#include <linux/export.h>
#include <asm/thread_info.h>

#include "lnxwrp_fm.h"
#include "fm_port_ioctls.h"
#ifdef CONFIG_COMPAT
#include "lnxwrp_ioctls_fm_compat.h"
#endif /* CONFIG_COMPAT */

#define CRC8_WCDMA_POLY						0x9b

static const struct file_operations dpa_stats_fops = {
	.owner = THIS_MODULE,
	.open = wrp_dpa_stats_open,
	.read = wrp_dpa_stats_read,
	.write = NULL,
	.unlocked_ioctl = wrp_dpa_stats_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= wrp_dpa_stats_compat_ioctl,
#endif /* CONFIG_COMPAT */
	.release = wrp_dpa_stats_release
};

DECLARE_CRC8_TABLE(crc8_table);

static int dpa_stats_cdev_major = -1;
static struct class *stats_class;
static struct device *stats_dev;

struct wrp_dpa_stats_cb wrp_dpa_stats;

static void wrp_dpa_stats_event_queue_init(
		struct dpa_stats_event_queue *ev_queue);

static void wrp_dpa_stats_event_queue_free(
		struct dpa_stats_event_queue *ev_queue);

static int wrp_dpa_stats_queue_event(
		struct dpa_stats_event_queue *ev_queue,
		struct dpa_stats_event *event);

static struct dpa_stats_event *wrp_dpa_stats_dequeue_event(
		struct dpa_stats_event_queue *ev_queue,
		unsigned int block);

static long wrp_dpa_stats_do_ioctl(struct file *filp,
				   unsigned int cmd, unsigned long args);

static int copy_key_descriptor(struct dpa_offload_lookup_key *src,
			       struct dpa_offload_lookup_key **dst);

static int copy_pair_descriptor(struct dpa_offload_lookup_key_pair *src,
				struct dpa_offload_lookup_key_pair **dst);

static void **copy_class_members(unsigned int size, void **src);

static long store_get_cnts_async_params(
		struct ioc_dpa_stats_cnt_request_params *kprm,
		int *us_cnts);

#ifdef CONFIG_COMPAT
static long wrp_dpa_stats_do_compat_ioctl(struct file *filp,
					  unsigned int cmd,
					  unsigned long args);

static int copy_key_descriptor_compatcpy(
		struct dpa_offload_lookup_key **kprm,
		compat_uptr_t uparam);

static int copy_pair_descriptor_compatcpy(
		struct dpa_offload_lookup_key_pair **ks_pair,
		struct compat_ioc_dpa_offld_lookup_key_pair pair);

static void dpa_stats_init_compatcpy(
		struct ioc_dpa_stats_params *kprm,
		struct compat_ioc_dpa_stats_params *uprm);

static void dpa_stats_reass_cnt_compatcpy(
		struct dpa_stats_cnt_reass *kprm,
		struct dpa_stats_compat_cnt_reass *uprm);

static void dpa_stats_frag_cnt_compatcpy(
		struct dpa_stats_cnt_frag *kprm,
		struct dpa_stats_compat_cnt_frag *uprm);

static void dpa_stats_plcr_cnt_compatcpy(
		struct dpa_stats_cnt_plcr *kprm,
		struct dpa_stats_compat_cnt_plcr *uprm);

static long dpa_stats_tbl_cnt_compatcpy(
		struct dpa_stats_cnt_classif_tbl *kprm,
		struct dpa_stats_compat_cnt_classif_tbl *uprm);

static long dpa_stats_ccnode_cnt_compatcpy(
		struct dpa_stats_cnt_classif_node *kprm,
		struct dpa_stats_compat_cnt_classif_node *uprm);

static long dpa_stats_eth_cls_compatcpy(
		struct dpa_stats_cls_cnt_eth *kprm,
		struct dpa_stats_compat_cls_cnt_eth *uprm,
		uint32_t cls_members);

static long dpa_stats_reass_cls_compatcpy(
		struct dpa_stats_cls_cnt_reass *kprm,
		struct dpa_stats_compat_cnt_reass *uprm,
		uint32_t cls_members);

static long dpa_stats_frag_cls_compatcpy(
		struct dpa_stats_cls_cnt_frag *kprm,
		struct dpa_stats_compat_cnt_frag *uprm,
		uint32_t cls_members);

static long dpa_stats_plcr_cls_compatcpy(
		struct dpa_stats_cls_cnt_plcr *kprm,
		struct dpa_stats_compat_cnt_plcr *uprm,
		uint32_t cls_members);

static long dpa_stats_tbl_cls_compatcpy(
		struct dpa_stats_cls_cnt_classif_tbl *kprm,
		struct dpa_stats_compat_cls_cnt_classif_tbl *uprm,
		uint32_t cls_members);

static long dpa_stats_ccnode_cls_compatcpy(
		struct dpa_stats_cls_cnt_classif_node *kprm,
		struct dpa_stats_compat_cls_cnt_classif_node *uprm,
		uint32_t cls_members);

static long dpa_stats_ipsec_cls_compatcpy(
		struct dpa_stats_cls_cnt_ipsec *kprm,
		struct dpa_stats_compat_cls_cnt_ipsec *uprm,
		uint32_t cls_members);
#endif

int wrp_dpa_stats_init(void)
{
	/* Cannot initialize the wrapper twice */
	if (dpa_stats_cdev_major >= 0)
		return -EBUSY;

	dpa_stats_cdev_major =
	    register_chrdev(0, DPA_STATS_CDEV, &dpa_stats_fops);
	if (dpa_stats_cdev_major < 0) {
		log_err("Cannot register DPA Stats character device\n");
		return dpa_stats_cdev_major;
	}

	stats_class = class_create(THIS_MODULE, DPA_STATS_CDEV);
	if (IS_ERR(stats_class)) {
		log_err("Cannot create DPA Stats class device\n");
		unregister_chrdev(dpa_stats_cdev_major, DPA_STATS_CDEV);
		dpa_stats_cdev_major = -1;
		return PTR_ERR(stats_class);
	}

	stats_dev = device_create(stats_class, NULL,
			MKDEV(dpa_stats_cdev_major, 0), NULL, DPA_STATS_CDEV);
	if (IS_ERR(stats_dev)) {
		log_err("Cannot create DPA Stats device\n");
		class_destroy(stats_class);
		unregister_chrdev(dpa_stats_cdev_major, DPA_STATS_CDEV);
		dpa_stats_cdev_major = -1;
		return PTR_ERR(stats_dev);
	}

	/* Initialize the event queue */
	wrp_dpa_stats_event_queue_init(&wrp_dpa_stats.ev_queue);

	return 0;
}

int wrp_dpa_stats_exit(void)
{
	if (dpa_stats_cdev_major < 0)
		return 0;
	device_destroy(stats_class, MKDEV(dpa_stats_cdev_major, 0));
	class_destroy(stats_class);
	unregister_chrdev(dpa_stats_cdev_major, DPA_STATS_CDEV);
	dpa_stats_cdev_major = -1;

	/* Destroy the event queue */
	wrp_dpa_stats_event_queue_free(&wrp_dpa_stats.ev_queue);

	return 0;
}

int wrp_dpa_stats_open(struct inode *inode, struct file *filp)
{
	return 0;
}


int wrp_dpa_stats_release(struct inode *inode, struct file *filp)
{
	return 0;
}

#ifdef CONFIG_COMPAT
long wrp_dpa_stats_compat_ioctl(struct file *filp, unsigned int	cmd,
				unsigned long args)
{
	return wrp_dpa_stats_do_compat_ioctl(filp, cmd, args);
}
#endif /* CONFIG_COMPAT */

long wrp_dpa_stats_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long args)
{
	return wrp_dpa_stats_do_ioctl(filp, cmd, args);
}

ssize_t wrp_dpa_stats_read(struct file *file, char *buf, size_t count, loff_t *off)
{
	struct dpa_stats_event  *event;
	struct dpa_stats_event_params ev_prm;
	size_t c = 0;

	/*
	 * Make sure that the size of the buffer requested by the user is
	 * at least the size of an event
	 */
	if (count < sizeof(struct dpa_stats_event_params))
		return -EINVAL;

	/* Dequeue first event by using a blocking call */
	event = wrp_dpa_stats_dequeue_event(&wrp_dpa_stats.ev_queue, 0);
	while (event) {
		if (event->params.bytes_written > 0 && wrp_dpa_stats.k_mem) {
			if (copy_to_user(wrp_dpa_stats.us_mem +
					event->params.storage_area_offset,
					wrp_dpa_stats.k_mem +
					event->params.storage_area_offset,
					event->params.bytes_written)) {
				log_err("Cannot copy counter values to storage area\n");
				return -EFAULT;
			}
		}

		ev_prm.bytes_written = event->params.bytes_written;
		ev_prm.cnts_written = event->params.cnts_written;
		ev_prm.dpa_stats_id = event->params.dpa_stats_id;
		ev_prm.storage_area_offset = event->params.storage_area_offset;

		if (copy_to_user(event->us_cnt_ids, event->ks_cnt_ids,
				(event->cnt_ids_len * sizeof(int)))) {
			kfree(event);
			return -EFAULT;
		}

		if (copy_to_user(buf + c, &ev_prm, sizeof(ev_prm)) != 0) {
			kfree(event);
			return -EFAULT;
		}

		kfree(event->ks_cnt_ids);
		kfree(event);

		count   -= sizeof(struct dpa_stats_event_params);
		c       += sizeof(struct dpa_stats_event_params);

		if (count < sizeof(struct dpa_stats_event_params))
			break;

		/* For subsequent events, don't block */
		event = wrp_dpa_stats_dequeue_event(
				&wrp_dpa_stats.ev_queue, O_NONBLOCK);
	}

	return c;
}

static void wrp_dpa_stats_event_queue_init(
		struct dpa_stats_event_queue *event_queue)
{
	INIT_LIST_HEAD(&event_queue->lh);
	mutex_init(&wrp_dpa_stats.event_queue_lock);
	atomic_set(&event_queue->count, 0);
	init_waitqueue_head(&event_queue->wq);
}

static void wrp_dpa_stats_event_queue_free(
		struct dpa_stats_event_queue *event_queue)
{
	struct dpa_stats_event   *entry, *tmp;

	/* Remove remaining events from the event queue */
	mutex_lock(&wrp_dpa_stats.event_queue_lock);
	list_for_each_entry_safe(entry, tmp, &event_queue->lh, lh) {
		list_del(&entry->lh);
		atomic_dec(&event_queue->count);
		kfree(entry);
	}
	mutex_unlock(&wrp_dpa_stats.event_queue_lock);
}

static int wrp_dpa_stats_queue_event(struct dpa_stats_event_queue *event_queue,
				     struct dpa_stats_event *event)
{
	/* If the event queue is already full, abort: */
	if (atomic_read(&event_queue->count) >= QUEUE_MAX_EVENTS) {
		log_err("Cannot enqueue new event, queue is full(%d)\n",
			QUEUE_MAX_EVENTS);
		return -EBUSY;
	}

	/* Add the event to the event queue */
	mutex_lock(&wrp_dpa_stats.event_queue_lock);
	list_add_tail(&event->lh, &event_queue->lh);
	atomic_inc(&event_queue->count);
	mutex_unlock(&wrp_dpa_stats.event_queue_lock);

	/* Wake up consumers */
	wake_up_interruptible(&event_queue->wq);
	return 0;
}

static struct dpa_stats_event *wrp_dpa_stats_dequeue_event(
		struct dpa_stats_event_queue *event_queue, unsigned int block)
{
	struct dpa_stats_event	*event;

	/*
	 * If the event queue is empty we perform an interruptible sleep
	 * until an event is inserted into the queue. We use the event queue
	 * spinlock to protect ourselves from race conditions.
	 */
	mutex_lock(&wrp_dpa_stats.event_queue_lock);

	while (list_empty(&event_queue->lh)) {
		mutex_unlock(&wrp_dpa_stats.event_queue_lock);

		/* If a non blocking action was requested, return failure: */
		if (block & O_NONBLOCK)
			return NULL;

		if (wait_event_interruptible(event_queue->wq,
			!list_empty(&event_queue->lh)))
			/* Woken up by some signal... */
			return NULL;

		mutex_lock(&wrp_dpa_stats.event_queue_lock);
	}

	/* Consume one event */
	event = list_entry((&event_queue->lh)->next,
			struct dpa_stats_event, lh);
	list_del(&event->lh);
	atomic_dec(&event_queue->count);
	mutex_unlock(&wrp_dpa_stats.event_queue_lock);

	return event;
}

void do_ioctl_req_done_cb(int dpa_stats_id,
			  unsigned int storage_area_offset,
			  unsigned int cnts_written, int bytes_written)
{
	struct dpa_stats_event *event = NULL;
	struct dpa_stats_async_req_ev *async_req_ev;
	struct list_head *async_req_grp, *pos;
	uint8_t grp_idx = 0;
	bool found = false;

	/* Obtain the group the request belongs to */
	grp_idx = crc8(crc8_table,
			(uint8_t *)&storage_area_offset,
			sizeof(unsigned int),
			0);
	async_req_grp = &wrp_dpa_stats.async_req_group[grp_idx];
	mutex_lock(&wrp_dpa_stats.async_req_lock);
	BUG_ON(list_empty(async_req_grp));

	/* Search in the request group the request event */
	list_for_each(pos, async_req_grp) {
		async_req_ev = list_entry(pos,
					  struct dpa_stats_async_req_ev, node);

		if (async_req_ev->storage_area_offset == storage_area_offset) {
			list_del(&async_req_ev->node);
			list_add_tail(&async_req_ev->node,
				      &wrp_dpa_stats.async_req_pool);
			found = true;
			break;
		}
	}

	if (!found) {
		log_err("Cannot find event in the event list\n");
		mutex_unlock(&wrp_dpa_stats.async_req_lock);
		return;
	}

	/* Generate new event description: */
	event = kmalloc(sizeof(struct dpa_stats_event), GFP_KERNEL);
	if (!event) {
		log_err("Cannot allocate memory for a new event\n");
		mutex_unlock(&wrp_dpa_stats.async_req_lock);
		return;
	}

	/* Fill up the event parameters data structure */
	event->params.dpa_stats_id = dpa_stats_id;
	event->params.storage_area_offset = storage_area_offset;
	event->params.cnts_written = cnts_written;
	event->params.bytes_written = bytes_written;
	event->ks_cnt_ids = async_req_ev->ks_cnt_ids;
	event->us_cnt_ids = async_req_ev->us_cnt_ids;
	event->cnt_ids_len = async_req_ev->cnt_ids_len;

	mutex_unlock(&wrp_dpa_stats.async_req_lock);

	/* Queue this event */
	if (wrp_dpa_stats_queue_event(&wrp_dpa_stats.ev_queue, event) != 0) {
		log_err("Cannot enqueue a new event\n");
		kfree(event);
		return;
	}

	return;
}

static long do_ioctl_stats_init(struct ioc_dpa_stats_params *prm)
{
	struct dpa_stats_async_req_ev *async_req_ev;
	struct dpa_stats_params params;
	long ret = 0;
	uint16_t i;

	/* Check user-provided storage area length */
	if (prm->storage_area_len < DPA_STATS_CNT_SEL_LEN ||
	    prm->storage_area_len > DPA_STATS_MAX_STORAGE_AREA_SIZE) {
		log_err("Parameter storage_area_len %d must be in range (%d - %d)\n",
			prm->storage_area_len,
			DPA_STATS_CNT_SEL_LEN, DPA_STATS_MAX_STORAGE_AREA_SIZE);
		return -EINVAL;
	}

	/* Save user-provided parameters */
	params.max_counters = prm->max_counters;
	params.storage_area_len = prm->storage_area_len;

	if (prm->stg_area_mapped) {
		/*
		 * Storage area is mapped, obtain the kernel-space memory area
		 * pointer from the physical address
		 */
		params.storage_area = phys_to_virt(prm->phys_stg_area);
		if (!params.storage_area) {
			log_err("Invalid physical memory address for storage area\n");
			return -EINVAL;
		}
		wrp_dpa_stats.k_mem = NULL;
	} else {
		/* Save user-space memory area pointer */
		wrp_dpa_stats.us_mem = prm->virt_stg_area;

		/* Allocate kernel-space memory to store the statistics */
		params.storage_area = kzalloc(
				prm->storage_area_len, GFP_KERNEL);
		if (!params.storage_area) {
			log_err("Cannot allocate memory for kernel storage area\n");
			return -ENOMEM;
		}

		/* Save kernel-space memory area pointer */
		wrp_dpa_stats.k_mem = params.storage_area;
	}

	/* Call init function */
	ret = dpa_stats_init(&params, &prm->dpa_stats_id);
	if (ret < 0)
		return ret;

	/* Init CRC8 table */
	crc8_populate_msb(crc8_table, CRC8_WCDMA_POLY);

	/* Allocate asynchronous requests groups lists */
	wrp_dpa_stats.async_req_group = kmalloc(DPA_STATS_MAX_NUM_OF_REQUESTS *
				sizeof(struct list_head), GFP_KERNEL);
	if (!wrp_dpa_stats.async_req_group) {
		log_err("Cannot allocate memory for asynchronous requests group\n");
		return -ENOMEM;
	}

	/* Initialize list of free async requests nodes */
	INIT_LIST_HEAD(&wrp_dpa_stats.async_req_pool);

	for (i = 0; i < DPA_STATS_MAX_NUM_OF_REQUESTS; i++) {

		/* Initialize the list of async requests in the same group */
		INIT_LIST_HEAD(&wrp_dpa_stats.async_req_group[i]);

		/* Allocate an asynchronous request event node */
		async_req_ev = kzalloc(sizeof(*async_req_ev), GFP_KERNEL);
		if (!async_req_ev) {
			struct dpa_stats_async_req_ev *tmp;

			list_for_each_entry_safe(async_req_ev, tmp,
				&wrp_dpa_stats.async_req_pool, node) {
				list_del(&async_req_ev->node);
				kfree(async_req_ev);
			}
			log_err("Cannot allocate memory for asynchronous request event\n");
			return -ENOMEM;
		}

		list_add_tail(&async_req_ev->node,
			      &wrp_dpa_stats.async_req_pool);
	}

	mutex_init(&wrp_dpa_stats.async_req_lock);

	return ret;
}

static long do_ioctl_stats_free(void *args)
{
	struct dpa_stats_async_req_ev *async_req_ev, *tmp;
	int dpa_stats_id;
	long ret;

	if (copy_from_user(&dpa_stats_id, (int *)args, sizeof(int))) {
		log_err("Cannot copy user parameters\n");
		return -EINVAL;
	}

	/* Release kernel allocated memory */
	kfree(wrp_dpa_stats.k_mem);

	mutex_lock(&wrp_dpa_stats.async_req_lock);
	list_for_each_entry_safe(async_req_ev,
				 tmp, &wrp_dpa_stats.async_req_pool, node) {
		list_del(&async_req_ev->node);
		kfree(async_req_ev);
	}
	mutex_unlock(&wrp_dpa_stats.async_req_lock);

	ret = dpa_stats_free(dpa_stats_id);
	if (ret < 0)
		return ret;

	return ret;
}

static int do_ioctl_stats_create_counter(void *args)
{
	struct ioc_dpa_stats_cnt_params prm;
	struct dpa_offload_lookup_key *us_key = NULL;
	long ret = 0;

	if (copy_from_user(&prm, args, sizeof(prm))) {
		log_err("Could not copy counter parameters\n");
		return -EINVAL;
	}

	if (prm.cnt_params.type == DPA_STATS_CNT_CLASSIF_NODE &&
	    prm.cnt_params.classif_node_params.key) {
		/* Save user-space provided key */
		us_key = prm.cnt_params.classif_node_params.key;

		/* Override user-space pointers with kernel memory */
		ret = copy_key_descriptor(us_key,
			&prm.cnt_params.classif_node_params.key);
		if (ret != 0) {
			log_err("Could not copy the key descriptor\n");
			return ret;
		}
	}

	if (prm.cnt_params.type == DPA_STATS_CNT_CLASSIF_TBL &&
	    prm.cnt_params.classif_tbl_params.key) {
		/* Save user-space provided key */
		us_key = prm.cnt_params.classif_tbl_params.key;

		/* Override user-space pointers with kernel memory */
		ret = copy_key_descriptor(us_key,
			&prm.cnt_params.classif_tbl_params.key);
		if (ret != 0) {
			log_err("Could not copy the key descriptor\n");
			return ret;
		}
	}

	ret = dpa_stats_create_counter(prm.stats_id,
				       &prm.cnt_params, &prm.cnt_id);

	if (prm.cnt_params.type == DPA_STATS_CNT_CLASSIF_NODE &&
	    prm.cnt_params.classif_node_params.key) {
		/* Release kernel-allocated memory */
		kfree(prm.cnt_params.classif_node_params.key->byte);
		kfree(prm.cnt_params.classif_node_params.key->mask);
		kfree(prm.cnt_params.classif_node_params.key);
		/* Restore user-provided key */
		prm.cnt_params.classif_node_params.key = us_key;
	}

	if (prm.cnt_params.type == DPA_STATS_CNT_CLASSIF_TBL &&
	    prm.cnt_params.classif_tbl_params.key) {
		/* Release kernel-allocated memory */
		kfree(prm.cnt_params.classif_tbl_params.key->byte);
		kfree(prm.cnt_params.classif_tbl_params.key->mask);
		kfree(prm.cnt_params.classif_tbl_params.key);
		/* Restore user-provided key */
		prm.cnt_params.classif_tbl_params.key = us_key;
	}

	if (copy_to_user(args, &prm, sizeof(prm))) {
		log_err("Could not copy to user the Counter ID\n");
		ret = -EINVAL;
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static int do_ioctl_stats_compat_create_counter(void *args)
{
	struct ioc_dpa_stats_cnt_params kprm;
	struct compat_ioc_dpa_stats_cnt_params uprm;
	long ret = 0;

	if (copy_from_user(&uprm, args, sizeof(uprm))) {
		log_err("Cannot copy from user counter parameters\n");
		return -EINVAL;
	}

	memset(&kprm, 0, sizeof(struct ioc_dpa_stats_cnt_params));
	kprm.stats_id = uprm.stats_id;
	kprm.cnt_params.type = uprm.cnt_params.type;

	switch (kprm.cnt_params.type) {
	case DPA_STATS_CNT_ETH:
		memcpy(&kprm.cnt_params.eth_params,
		       &uprm.cnt_params.eth_params,
		       sizeof(struct dpa_stats_cnt_eth));
		break;
	case DPA_STATS_CNT_REASS:
		dpa_stats_reass_cnt_compatcpy(&kprm.cnt_params.reass_params,
					      &uprm.cnt_params.reass_params);
		break;
	case DPA_STATS_CNT_FRAG:
		dpa_stats_frag_cnt_compatcpy(&kprm.cnt_params.frag_params,
					     &uprm.cnt_params.frag_params);
		break;
	case DPA_STATS_CNT_POLICER:
		dpa_stats_plcr_cnt_compatcpy(&kprm.cnt_params.plcr_params,
					     &uprm.cnt_params.plcr_params);
		break;
	case DPA_STATS_CNT_CLASSIF_TBL:
		ret = dpa_stats_tbl_cnt_compatcpy(
					&kprm.cnt_params.classif_tbl_params,
					&uprm.cnt_params.classif_tbl_params);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_CNT_CLASSIF_NODE:
		ret = dpa_stats_ccnode_cnt_compatcpy(
					&kprm.cnt_params.classif_node_params,
					&uprm.cnt_params.classif_node_params);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_CNT_IPSEC:
		memcpy(&kprm.cnt_params.ipsec_params,
		       &uprm.cnt_params.ipsec_params,
		       sizeof(struct dpa_stats_cnt_ipsec));
		break;
	case DPA_STATS_CNT_TRAFFIC_MNG:
		kprm.cnt_params.traffic_mng_params.cnt_sel =
				uprm.cnt_params.traffic_mng_params.cnt_sel;
		kprm.cnt_params.traffic_mng_params.src =
				uprm.cnt_params.traffic_mng_params.src;
		break;
	default:
		break;
	}

	ret = dpa_stats_create_counter(kprm.stats_id,
				       &kprm.cnt_params, &kprm.cnt_id);

	if (kprm.cnt_params.type == DPA_STATS_CNT_CLASSIF_NODE &&
	    compat_ptr(uprm.cnt_params.classif_node_params.key)) {
		kfree(kprm.cnt_params.classif_node_params.key->byte);
		kfree(kprm.cnt_params.classif_node_params.key->mask);
		kfree(kprm.cnt_params.classif_node_params.key);
	}

	if (kprm.cnt_params.type == DPA_STATS_CNT_CLASSIF_TBL &&
	    compat_ptr(uprm.cnt_params.classif_tbl_params.key)) {
		kfree(kprm.cnt_params.classif_tbl_params.key->byte);
		kfree(kprm.cnt_params.classif_tbl_params.key->mask);
		kfree(kprm.cnt_params.classif_tbl_params.key);
	}

	uprm.cnt_id = kprm.cnt_id;

	if (copy_to_user(args, &uprm, sizeof(uprm))) {
		log_err("Cannot copy to user counter parameters\n");
		ret = -EINVAL;
	}

	return ret;
}
#endif

static int do_ioctl_stats_create_class_counter(void *args)
{
	struct ioc_dpa_stats_cls_cnt_params prm;
	struct dpa_stats_cls_cnt_classif_node *cnode;
	struct dpa_stats_cls_cnt_classif_tbl  *tbl;
	struct dpa_offload_lookup_key **us_keys = NULL;
	struct dpa_offload_lookup_key_pair **us_pairs = NULL;
	uint32_t i = 0;
	unsigned int cls_mbrs;
	void **cls_objs = NULL;
	int *sa_ids = NULL;
	long ret = 0;

	if (copy_from_user(&prm, args, sizeof(prm))) {
		log_err("Cannot copy from user class counter parameters\n");
		return -EINVAL;
	}

	if (prm.cnt_params.class_members > DPA_STATS_MAX_NUM_OF_CLASS_MEMBERS) {
		log_err("Parameter class_members %d exceeds maximum number of class members: %d\n",
			prm.cnt_params.class_members,
			DPA_STATS_MAX_NUM_OF_CLASS_MEMBERS);
		return -EINVAL;
	}

	cls_mbrs = prm.cnt_params.class_members;

	switch (prm.cnt_params.type) {
	case DPA_STATS_CNT_ETH: {
		struct dpa_stats_cnt_eth_src *eth_src = NULL;

		/* Allocate memory to store the sources array */
		eth_src = kmalloc(sizeof(*eth_src) * cls_mbrs, GFP_KERNEL);
		if (!eth_src) {
			log_err("Cannot allocate memory for Ethernet sources array\n");
			return -ENOMEM;
		}

		if (copy_from_user(eth_src,
				   prm.cnt_params.eth_params.src,
				   sizeof(*eth_src) * cls_mbrs)) {
			log_err("Cannot copy array of Ethernet sources\n");
			kfree(eth_src);
			return -EBUSY;
		}
		prm.cnt_params.eth_params.src = eth_src;
		break;
	}
	case DPA_STATS_CNT_REASS:
		/* Save the user-space pointer */
		cls_objs = prm.cnt_params.reass_params.reass;

		prm.cnt_params.reass_params.reass = copy_class_members(cls_mbrs,
					prm.cnt_params.reass_params.reass);
		if (!prm.cnt_params.reass_params.reass) {
			log_err("Cannot copy array of Reassembly objects\n");
			prm.cnt_params.reass_params.reass = cls_objs;
			return -EBUSY;
		}
		break;
	case DPA_STATS_CNT_FRAG:
		/* Save the user-space pointer */
		cls_objs = prm.cnt_params.frag_params.frag;

		prm.cnt_params.frag_params.frag = copy_class_members(cls_mbrs,
					prm.cnt_params.frag_params.frag);
		if (!prm.cnt_params.frag_params.frag) {
			log_err("Cannot copy array of Fragmentation objects\n");
			prm.cnt_params.frag_params.frag = cls_objs;
			return -EBUSY;
		}
		break;
	case DPA_STATS_CNT_POLICER:
		/* Save the user-space pointer */
		cls_objs = prm.cnt_params.plcr_params.plcr;

		prm.cnt_params.plcr_params.plcr = copy_class_members(cls_mbrs,
					prm.cnt_params.plcr_params.plcr);
		if (!prm.cnt_params.plcr_params.plcr) {
			log_err("Cannot copy array of Policer objects\n");
			prm.cnt_params.plcr_params.plcr = cls_objs;
			return -EBUSY;
		}
		break;
	case DPA_STATS_CNT_CLASSIF_TBL:
		tbl = &prm.cnt_params.classif_tbl_params;

		if (tbl->key_type == DPA_STATS_CLASSIF_SINGLE_KEY) {
			/* Save array of user-space provided key pointers */
			us_keys = tbl->keys;

			/* Override user-space pointers with kernel memory */
			tbl->keys = kzalloc(cls_mbrs *
					    sizeof(*tbl->keys), GFP_KERNEL);
			if (!tbl->keys) {
				log_err("Cannot allocate kernel memory for lookup keys array\n");
				return -ENOMEM;
			}

			for (i = 0; i < cls_mbrs; i++) {
				if (!us_keys[i])
					continue;
				ret = copy_key_descriptor(us_keys[i],
						&tbl->keys[i]);
				if (ret != 0) {
					log_err("Cannot copy key descriptor\n");
					goto create_cls_counter_cleanup;
				}
			}
		} else if (tbl->key_type == DPA_STATS_CLASSIF_PAIR_KEY) {
			/* Save array of user-space provided pairs pointers */
			us_pairs = tbl->pairs;

			/* Override user-space pointers with kernel memory */
			tbl->pairs = kzalloc(cls_mbrs *
					    sizeof(*tbl->pairs), GFP_KERNEL);
			if (!tbl->pairs) {
				log_err("Cannot allocate kernel memory for lookup pairs array\n");
				return -ENOMEM;
			}

			for (i = 0; i < cls_mbrs; i++) {
				if (!us_pairs[i])
					continue;
				ret = copy_pair_descriptor(us_pairs[i],
						&tbl->pairs[i]);
				if (ret != 0) {
					log_err("Could not copy the pair key descriptor\n");
					goto create_cls_counter_cleanup;
				}
			}
		}
		break;
	case DPA_STATS_CNT_CLASSIF_NODE:
		cnode = &prm.cnt_params.classif_node_params;

		if (!cnode->keys) {
			log_err("Pointer to array of keys can't be NULL\n");
			return -EINVAL;
		}
		/* Save array of user-space provided key pointers */
		us_keys = cnode->keys;

		/* Override user-space pointers with kernel memory */
		cnode->keys = kzalloc(cls_mbrs *
				    sizeof(*cnode->keys), GFP_KERNEL);
		if (!cnode->keys) {
			log_err("No more memory to store array of keys\n");
			return -ENOMEM;
		}

		for (i = 0; i < cls_mbrs; i++) {
			if (!us_keys[i])
				continue;
			ret = copy_key_descriptor(us_keys[i], &cnode->keys[i]);
			if (ret != 0) {
				log_err("Cannot copy the key descriptor\n");
				goto create_cls_counter_cleanup;
			}
		}
		break;
	case DPA_STATS_CNT_IPSEC:
		/* Allocate memory to store the sa ids array */
		sa_ids = kmalloc(cls_mbrs * sizeof(*sa_ids), GFP_KERNEL);
		if (!sa_ids) {
			log_err("Cannot allocate memory for SA ids array\n");
			return -ENOMEM;
		}

		if (copy_from_user(sa_ids,
				prm.cnt_params.ipsec_params.sa_id,
				(cls_mbrs * sizeof(*sa_ids)))) {
			log_err("Cannot copy from user array of SA ids\n");
			kfree(sa_ids);
			return -EBUSY;
		}

		prm.cnt_params.ipsec_params.sa_id = sa_ids;
		break;
	default:
		break;
	}

	ret = dpa_stats_create_class_counter(prm.stats_id,
					     &prm.cnt_params, &prm.cnt_id);
create_cls_counter_cleanup:
	switch (prm.cnt_params.type) {
	case DPA_STATS_CNT_ETH:
		kfree(prm.cnt_params.eth_params.src);
		break;
	case DPA_STATS_CNT_REASS:
		kfree(prm.cnt_params.reass_params.reass);
		prm.cnt_params.reass_params.reass = cls_objs;
		break;
	case DPA_STATS_CNT_FRAG:
		kfree(prm.cnt_params.frag_params.frag);
		prm.cnt_params.frag_params.frag = cls_objs;
		break;
	case DPA_STATS_CNT_POLICER:
		kfree(prm.cnt_params.plcr_params.plcr);
		prm.cnt_params.plcr_params.plcr = cls_objs;
		break;
	case DPA_STATS_CNT_CLASSIF_TBL:
		tbl = &prm.cnt_params.classif_tbl_params;

		if (tbl->key_type == DPA_STATS_CLASSIF_SINGLE_KEY) {
			for (i = 0; i < cls_mbrs; i++) {
				if (!tbl->keys[i])
					continue;
				/* Free allocated memory */
				kfree(tbl->keys[i]->byte);
				kfree(tbl->keys[i]->mask);
				kfree(tbl->keys[i]);
			}
			kfree(tbl->keys);
			/* Restore user-space pointers */
			tbl->keys = us_keys;
		}

		if (tbl->key_type == DPA_STATS_CLASSIF_PAIR_KEY) {
			for (i = 0; i < cls_mbrs; i++) {
				if (!tbl->pairs[i])
					continue;

				if (tbl->pairs[i]->first_key) {
					kfree(tbl->pairs[i]->first_key->byte);
					kfree(tbl->pairs[i]->first_key->mask);
					kfree(tbl->pairs[i]->first_key);
				}
				if (tbl->pairs[i]->second_key) {
					kfree(tbl->pairs[i]->second_key->byte);
					kfree(tbl->pairs[i]->second_key->mask);
					kfree(tbl->pairs[i]->second_key);
				}
				kfree(tbl->pairs[i]);
			}
			kfree(tbl->pairs);
			/* Restore user-space pointers */
			tbl->pairs = us_pairs;
		}
		break;
	case DPA_STATS_CNT_CLASSIF_NODE:
		cnode = &prm.cnt_params.classif_node_params;

		for (i = 0; i < cls_mbrs; i++) {
			if (!cnode->keys[i])
				continue;
			/* Free allocated memory */
			kfree(cnode->keys[i]->byte);
			kfree(cnode->keys[i]->mask);
			kfree(cnode->keys[i]);
		}
		kfree(cnode->keys);
		/* Restore user-space pointers */
		cnode->keys = us_keys;
		break;
	case DPA_STATS_CNT_IPSEC:
		kfree(sa_ids);
		break;
	default:
		break;
	}

	if (copy_to_user(args, &prm, sizeof(prm))) {
		log_err("Cannot copy to user class counter parameters\n");
		ret = -EINVAL;
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static int do_ioctl_stats_compat_create_class_counter(void *args)
{
	struct ioc_dpa_stats_cls_cnt_params kprm;
	struct compat_ioc_dpa_stats_cls_cnt_params uprm;
	struct dpa_stats_cls_cnt_params *kprm_cls = &kprm.cnt_params;
	struct dpa_stats_compat_cls_cnt_params *uprm_cls = &uprm.cnt_params;
	long ret = 0;
	uint32_t i = 0;

	if (copy_from_user(&uprm, args, sizeof(uprm))) {
		log_err("Cannot copy from user the class counter parameters\n");
		return -EINVAL;
	}

	if (uprm_cls->class_members > DPA_STATS_MAX_NUM_OF_CLASS_MEMBERS) {
		log_err("Parameter class_members %d exceeds maximum number of class members: %d\n",
			uprm_cls->class_members,
			DPA_STATS_MAX_NUM_OF_CLASS_MEMBERS);
		return -EINVAL;
	}

	memset(&kprm, 0, sizeof(struct ioc_dpa_stats_cls_cnt_params));
	kprm.stats_id = uprm.stats_id;
	kprm_cls->type = uprm_cls->type;
	kprm_cls->class_members = uprm_cls->class_members;

	switch (kprm.cnt_params.type) {
	case DPA_STATS_CNT_ETH:
		ret = dpa_stats_eth_cls_compatcpy(&kprm_cls->eth_params,
			&uprm_cls->eth_params, kprm_cls->class_members);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_CNT_REASS:
		ret = dpa_stats_reass_cls_compatcpy(&kprm_cls->reass_params,
			&uprm_cls->reass_params, kprm_cls->class_members);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_CNT_FRAG:
		ret = dpa_stats_frag_cls_compatcpy(&kprm_cls->frag_params,
			&uprm_cls->frag_params, kprm_cls->class_members);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_CNT_POLICER:
		ret = dpa_stats_plcr_cls_compatcpy(&kprm_cls->plcr_params,
			&uprm_cls->plcr_params, kprm_cls->class_members);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_CNT_CLASSIF_TBL:
		ret = dpa_stats_tbl_cls_compatcpy(&kprm_cls->classif_tbl_params,
			&uprm_cls->classif_tbl_params, kprm_cls->class_members);
		if (!ret)
			break;
		goto compat_create_cls_counter_cleanup;
	case DPA_STATS_CNT_CLASSIF_NODE:
		ret = dpa_stats_ccnode_cls_compatcpy(
			&kprm_cls->classif_node_params,
			&uprm_cls->ccnode_params, kprm_cls->class_members);
		if (!ret)
			break;
		goto compat_create_cls_counter_cleanup;
	case DPA_STATS_CNT_IPSEC:
		ret = dpa_stats_ipsec_cls_compatcpy(&kprm_cls->ipsec_params,
			&uprm_cls->ipsec_params, kprm_cls->class_members);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_CNT_TRAFFIC_MNG:
		kprm_cls->traffic_mng_params.cnt_sel =
				uprm_cls->traffic_mng_params.cnt_sel;
		kprm_cls->traffic_mng_params.src =
				uprm_cls->traffic_mng_params.src;
		break;
	default:
		break;
	}

	ret = dpa_stats_create_class_counter(kprm.stats_id,
					     kprm_cls, &kprm.cnt_id);
compat_create_cls_counter_cleanup:
	switch (uprm.cnt_params.type) {
	case DPA_STATS_CNT_ETH:
		kfree(kprm_cls->eth_params.src);
		break;
	case DPA_STATS_CNT_REASS:
		kfree(kprm_cls->reass_params.reass);
		break;
	case DPA_STATS_CNT_FRAG:
		kfree(kprm_cls->frag_params.frag);
		break;
	case DPA_STATS_CNT_POLICER:
		kfree(kprm_cls->plcr_params.plcr);
		break;
	case DPA_STATS_CNT_CLASSIF_TBL:
	{
		struct dpa_stats_cls_cnt_classif_tbl *tbl =
				&kprm_cls->classif_tbl_params;

		if (tbl->key_type == DPA_STATS_CLASSIF_SINGLE_KEY) {
			if (!tbl->keys)
				break;
			for (i = 0; i < kprm_cls->class_members; i++) {
				if (!tbl->keys[i])
					continue;
				kfree(tbl->keys[i]->byte);
				kfree(tbl->keys[i]->mask);
				kfree(tbl->keys[i]);
			}
			kfree(tbl->keys);

		} else if (tbl->key_type == DPA_STATS_CLASSIF_PAIR_KEY) {
			if (!tbl->pairs)
				break;
			for (i = 0; i < kprm_cls->class_members; i++) {
				if (!tbl->pairs[i])
					continue;
				if (tbl->pairs[i]->first_key) {
					kfree(tbl->pairs[i]->first_key->byte);
					kfree(tbl->pairs[i]->first_key->mask);
					kfree(tbl->pairs[i]->first_key);
				}
				if (tbl->pairs[i]->second_key) {
					kfree(tbl->pairs[i]->second_key->byte);
					kfree(tbl->pairs[i]->second_key->mask);
					kfree(tbl->pairs[i]->second_key);
				}
				kfree(tbl->pairs[i]);
			}
			kfree(tbl->pairs);
		}
		break;
	}
	case DPA_STATS_CNT_CLASSIF_NODE:
		if (!kprm_cls->classif_node_params.keys)
			break;
		for (i = 0; i < kprm_cls->class_members; i++) {
			if (!kprm_cls->classif_node_params.keys[i])
					continue;
			kfree(kprm_cls->classif_node_params.keys[i]->byte);
			kfree(kprm_cls->classif_node_params.keys[i]->mask);
			kfree(kprm_cls->classif_node_params.keys[i]);
		}
		kfree(kprm_cls->classif_node_params.keys);
		break;

	case DPA_STATS_CNT_IPSEC:
		kfree(kprm_cls->ipsec_params.sa_id);
		break;

	default:
		break;
	}

	uprm.cnt_id = kprm.cnt_id;

	if (copy_to_user(args, &uprm, sizeof(uprm))) {
		log_err("Cannot copy to user the counter id\n");
		ret = -EINVAL;
	}

	return ret;
}
#endif

static int do_ioctl_stats_modify_class_counter(void *args)
{
	struct ioc_dpa_stats_cls_member_params prm;
	struct dpa_offload_lookup_key *us_key = NULL;
	struct dpa_offload_lookup_key_pair *us_pair = NULL;
	int ret = 0;

	if (copy_from_user(&prm, args, sizeof(prm))) {
		log_err("Cannot copy from user the class counter parameters\n");
		return -EINVAL;
	}

	switch (prm.params.type) {
	case DPA_STATS_CLS_MEMBER_SINGLE_KEY:
		if (!prm.params.key)
			break;

		/* Save user-space provided key */
		us_key = prm.params.key;

		/* Override user-space pointers with kernel memory */
		ret = copy_key_descriptor(us_key, &prm.params.key);
		if (ret != 0) {
			log_err("Could not copy the key descriptor\n");
			return ret;
		}
		break;
	case DPA_STATS_CLS_MEMBER_PAIR_KEY:
		if (!prm.params.pair)
			break;

		/* Save array of user-space provided pairs pointers */
		us_pair = prm.params.pair;

		/* Override user-space pointers with kernel memory */
		ret = copy_pair_descriptor(us_pair, &prm.params.pair);
		if (ret != 0) {
			log_err("Could not copy the pair key descriptor\n");
			return ret;
		}
		break;
	case DPA_STATS_CLS_MEMBER_SA_ID:
		break;
	default:
		break;
	}

	ret = dpa_stats_modify_class_counter(prm.cnt_id,
					     &prm.params, prm.member_index);

	switch (prm.params.type) {
	case DPA_STATS_CLS_MEMBER_SINGLE_KEY:
		if (prm.params.key) {
			/* Release kernel-allocated memory */
			kfree(prm.params.key->byte);
			kfree(prm.params.key->mask);
			kfree(prm.params.key);
			/* Restore user-provided key */
			prm.params.key = us_key;
		}
		break;
	case DPA_STATS_CLS_MEMBER_PAIR_KEY:
		if (prm.params.pair) {
			if (prm.params.pair->first_key) {
				/* Release kernel-allocated memory */
				kfree(prm.params.pair->first_key->byte);
				kfree(prm.params.pair->first_key->mask);
				kfree(prm.params.pair->first_key);
			}
			if (prm.params.pair->second_key) {
				/* Release kernel-allocated memory */
				kfree(prm.params.pair->second_key->byte);
				kfree(prm.params.pair->second_key->mask);
				kfree(prm.params.pair->second_key);
			}
			kfree(prm.params.pair);
			/* Restore user-provided key */
			prm.params.pair = us_pair;
		}
		break;
	case DPA_STATS_CLS_MEMBER_SA_ID:
		break;
	default:
		log_err("Invalid class member type\n");
		break;
	}

	if (copy_to_user(args, &prm, sizeof(prm))) {
		log_err("Could not write dpa_stats_modify_class_counter result\n");
		ret = -EBUSY;
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static int do_ioctl_stats_compat_modify_class_counter(void *args)
{
	struct ioc_dpa_stats_cls_member_params kprm;
	struct compat_ioc_dpa_stats_cls_member_params uprm;
	struct compat_ioc_dpa_offld_lookup_key_pair pair;
	int ret;

	if (copy_from_user(&uprm, args, sizeof(uprm))) {
		log_err("Cannot copy from user the modify counter parameters\n");
		return -EINVAL;
	}

	memset(&kprm, 0, sizeof(struct ioc_dpa_stats_cls_member_params));
	kprm.cnt_id = uprm.cnt_id;
	kprm.member_index = uprm.member_index;
	kprm.params.type = uprm.params.type;

	switch (kprm.params.type) {
	case DPA_STATS_CLS_MEMBER_SINGLE_KEY:
		if (!compat_ptr(uprm.params.key))
			break;
		/* Copy user-provided key descriptor */
		ret = copy_key_descriptor_compatcpy(&kprm.params.key,
				uprm.params.key);
		if (ret < 0) {
			log_err("Cannot copy the key descriptor\n");
			return ret;
		}
		break;
	case DPA_STATS_CLS_MEMBER_PAIR_KEY:
		if (!compat_ptr(uprm.params.pair))
			break;

		if (copy_from_user(&pair, compat_ptr(uprm.params.pair),
				   (sizeof(pair)))) {
			log_err("Cannot copy from user array of lookup pairs\n");
			return -EBUSY;
		}

		/* Copy user-provided lookup pair descriptor */
		ret = copy_pair_descriptor_compatcpy(&kprm.params.pair, pair);
		if (ret < 0) {
			log_err("Cannot copy the pair key descriptor\n");
			return ret;
		}
		break;
	case DPA_STATS_CLS_MEMBER_SA_ID:
		kprm.params.sa_id = uprm.params.sa_id;
		break;
	default:
		break;
	}

	ret = dpa_stats_modify_class_counter(kprm.cnt_id,
					&kprm.params, kprm.member_index);

	switch (kprm.params.type) {
	case DPA_STATS_CLS_MEMBER_SINGLE_KEY:
		if (!kprm.params.key)
			break;
		kfree(kprm.params.key->byte);
		kfree(kprm.params.key->mask);
		kfree(kprm.params.key);
		break;
	case DPA_STATS_CLS_MEMBER_PAIR_KEY:
		if (!kprm.params.pair)
			break;
		if (kprm.params.pair->first_key) {
			kfree(kprm.params.pair->first_key->byte);
			kfree(kprm.params.pair->first_key->mask);
			kfree(kprm.params.pair->first_key);
		}
		if (kprm.params.pair->second_key) {
			kfree(kprm.params.pair->second_key->byte);
			kfree(kprm.params.pair->second_key->mask);
			kfree(kprm.params.pair->second_key);
		}
		break;
	case DPA_STATS_CLS_MEMBER_SA_ID:
		break;
	default:
		break;
	}
	uprm.cnt_id = kprm.cnt_id;

	if (copy_to_user(args, &uprm, sizeof(uprm))) {
		log_err("Cannot copy to user class counter result\n");
		ret = -EBUSY;
	}

	return ret;
}
#endif

static int do_ioctl_stats_get_counters(void *args)
{
	struct ioc_dpa_stats_cnt_request_params prm;
	int *cnts_ids;
	long ret = 0;

	if (copy_from_user(&prm, args, sizeof(prm))) {
		log_err("Cannot copy from user request parameters\n");
		return -EINVAL;
	}

	if (prm.req_params.cnts_ids_len == 0 ||
	    prm.req_params.cnts_ids_len > DPA_STATS_REQ_CNTS_IDS_LEN) {
		log_err("Number of requested counter ids (%d) must be in range (1 - %d)\n",
			prm.req_params.cnts_ids_len,
			DPA_STATS_REQ_CNTS_IDS_LEN);
		return -EINVAL;
	}

	/* Save the user-space array of counter ids */
	cnts_ids = prm.req_params.cnts_ids;

	/* Allocate kernel-space memory area to copy the counters ids */
	prm.req_params.cnts_ids = kzalloc(prm.req_params.cnts_ids_len *
			sizeof(int), GFP_KERNEL);
	if (!prm.req_params.cnts_ids) {
		log_err("Cannot allocate memory for requested counter ids array\n");
		return -ENOMEM;
	}

	/* Copy the user provided counter ids */
	if (copy_from_user(prm.req_params.cnts_ids, cnts_ids,
			(prm.req_params.cnts_ids_len * sizeof(int)))) {
		log_err("Cannot copy from user array of requested counter ids\n");
		kfree(prm.req_params.cnts_ids);
		return -EINVAL;
	}

	/* If counters request is asynchronous */
	if (prm.async_req) {
		ret = store_get_cnts_async_params(&prm, cnts_ids);
		if (ret < 0) {
			kfree(prm.req_params.cnts_ids);
			return ret;
		}

		/* Replace the application callback with wrapper function */
		ret = dpa_stats_get_counters(prm.req_params, &prm.cnts_len,
							do_ioctl_req_done_cb);
	} else
		ret = dpa_stats_get_counters(prm.req_params, &prm.cnts_len,
									NULL);

	if (ret < 0) {
		kfree(prm.req_params.cnts_ids);
		return ret;
	}

	/* If request is synchronous copy counters length to user space */
	if (!prm.async_req) {
		if (wrp_dpa_stats.k_mem)
			if (copy_to_user((wrp_dpa_stats.us_mem +
					  prm.req_params.storage_area_offset),
					  (wrp_dpa_stats.k_mem +
					  prm.req_params.storage_area_offset),
					  prm.cnts_len)) {
				log_err("Cannot copy counter values to storage area\n");
				kfree(prm.req_params.cnts_ids);
				return -EINVAL;
			}

		if (copy_to_user(args, &prm, sizeof(prm))) {
			log_err("Cannot copy to user the counter parameters\n");
			ret = -EINVAL;
		}

		/*
		 * The user space driver expects some updates in the counters
		 * Ids array. It expects to see there, for the user space
		 * counters, the exact offsets where it needs to fill in the
		 * statistics data. This is why, just un case there are
		 * more user space counters to process, the hopefully updated
		 * counters Ids array will to be copied back to user space.
		 */
		if (copy_to_user(cnts_ids, prm.req_params.cnts_ids,
				prm.req_params.cnts_ids_len * sizeof(int))) {
			log_err("Cannot copy to user the user space counters offsets\n");
			ret = -EINVAL;
		}

		/* Request was sent, release the array of counter ids */
		kfree(prm.req_params.cnts_ids);
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static int do_ioctl_stats_compat_get_counters(void *args)
{
	struct ioc_dpa_stats_cnt_request_params kprm;
	struct compat_ioc_dpa_stats_cnt_request_params uprm;
	long ret = 0;

	if (copy_from_user(&uprm, args, sizeof(uprm))) {
		log_err("Cannot copy from user request parameters\n");
		return -EINVAL;
	}

	if (uprm.req_params.cnts_ids_len == 0 ||
	    uprm.req_params.cnts_ids_len > DPA_STATS_REQ_CNTS_IDS_LEN) {
		log_err("Number of requested counter ids (%d) must be in range (1 - %d)\n",
			uprm.req_params.cnts_ids_len,
			DPA_STATS_REQ_CNTS_IDS_LEN);
		return -EINVAL;
	}

	memset(&kprm, 0, sizeof(struct ioc_dpa_stats_cnt_request_params));
	kprm.async_req = uprm.async_req;
	kprm.req_params.cnts_ids_len = uprm.req_params.cnts_ids_len;
	kprm.req_params.reset_cnts = uprm.req_params.reset_cnts;
	kprm.req_params.storage_area_offset =
			uprm.req_params.storage_area_offset;

	/* Allocate kernel-space memory area to copy the counters ids */
	kprm.req_params.cnts_ids = kzalloc(kprm.req_params.cnts_ids_len *
					   sizeof(int), GFP_KERNEL);
	if (!kprm.req_params.cnts_ids) {
		log_err("Cannot allocate memory for requested counter ids array\n");
		return -ENOMEM;
	}

	/* Copy the user provided counter ids */
	if (copy_from_user(kprm.req_params.cnts_ids,
			   (compat_ptr)(uprm.req_params.cnts_ids),
			   (kprm.req_params.cnts_ids_len * sizeof(int)))) {
		log_err("Cannot copy from user the array of requested counter ids\n");
		kfree(kprm.req_params.cnts_ids);
		return -EINVAL;
	}

	/* If counters request is asynchronous */
	if (kprm.async_req) {
		ret = store_get_cnts_async_params(&kprm,
				(compat_ptr)(uprm.req_params.cnts_ids));
		if (ret < 0) {
			kfree(kprm.req_params.cnts_ids);
			return ret;
		}

		/* Replace the application callback with wrapper function */
		ret = dpa_stats_get_counters(kprm.req_params, &kprm.cnts_len,
							do_ioctl_req_done_cb);
	} else
		ret = dpa_stats_get_counters(kprm.req_params, &kprm.cnts_len,
							NULL);

	if (ret < 0) {
		kfree(kprm.req_params.cnts_ids);
		return ret;
	}

	/* If request is synchronous copy counters length to user space */
	if (!kprm.async_req) {
		if (wrp_dpa_stats.k_mem)
			if (copy_to_user((wrp_dpa_stats.us_mem +
					kprm.req_params.storage_area_offset),
					(wrp_dpa_stats.k_mem +
					kprm.req_params.storage_area_offset),
					kprm.cnts_len)) {
				log_err("Cannot copy counter values to storage area\n");
				kfree(kprm.req_params.cnts_ids);
				return -EINVAL;
			}

		uprm.cnts_len = kprm.cnts_len;

		if (copy_to_user((compat_ptr)(uprm.req_params.cnts_ids),
				kprm.req_params.cnts_ids,
				(kprm.req_params.cnts_ids_len * sizeof(int)))) {
			log_err("Cannot copy to user the array of requested counter ids\n");
			kfree(kprm.req_params.cnts_ids);
			return -EINVAL;
		}

		if (copy_to_user(args, &uprm, sizeof(uprm))) {
			log_err("Cannot copy to user the counter parameters\n");
			ret = -EINVAL;
		}

		/* Request was sent, release the array of counter ids */
		kfree(kprm.req_params.cnts_ids);
	}

	return ret;
}
#endif

static int do_ioctl_stats_reset_counters(void *args)
{
	struct ioc_dpa_stats_cnts_reset_params prm;
	int *cnt_ids;
	long ret = 0;

	if (copy_from_user(&prm, args, sizeof(prm))) {
		log_err("Cannot copy from user reset counter parameters\n");
		return -EINVAL;
	}

	if (prm.cnts_ids_len == 0 ||
	    prm.cnts_ids_len > DPA_STATS_REQ_CNTS_IDS_LEN) {
		log_err("Number of counters to reset %d must be in range (1 - %d)\n",
			prm.cnts_ids_len, DPA_STATS_REQ_CNTS_IDS_LEN);
		return -EINVAL;
	}

	/* Allocate kernel-space memory area to copy the counters ids */
	cnt_ids = kcalloc(prm.cnts_ids_len, sizeof(int), GFP_KERNEL);
	if (!cnt_ids) {
		log_err("Cannot allocate memory for counter ids array\n");
		return -ENOMEM;
	}

	/* Copy the user provided counter ids */
	if (copy_from_user(cnt_ids,
			prm.cnts_ids,
			(prm.cnts_ids_len * sizeof(int)))) {
		log_err("Cannot copy from user array of requested counter ids\n");
		kfree(cnt_ids);
		return -EINVAL;
	}
	prm.cnts_ids = cnt_ids;

	ret = dpa_stats_reset_counters(prm.cnts_ids, prm.cnts_ids_len);
	if (ret < 0) {
		kfree(prm.cnts_ids);
		return ret;
	}

	kfree(cnt_ids);

	if (copy_to_user(args, &prm, sizeof(prm))) {
		log_err("Cannot copy to user the counter parameters\n");
		return -EINVAL;
	}

	return 0;
}

#ifdef CONFIG_COMPAT
static int do_ioctl_stats_compat_reset_counters(void *args)
{
	struct ioc_dpa_stats_cnts_reset_params kprm;
	struct compat_ioc_dpa_stats_cnts_reset_params uprm;
	long ret = 0;

	if (copy_from_user(&uprm, args, sizeof(uprm))) {
		log_err("Cannot copy from user counter reset parameters\n");
		return -EINVAL;
	}

	if (uprm.cnts_ids_len == 0 ||
	    uprm.cnts_ids_len > DPA_STATS_REQ_CNTS_IDS_LEN) {
		log_err("Number of counters to reset %d must be in range (1 - %d)\n",
			uprm.cnts_ids_len, DPA_STATS_REQ_CNTS_IDS_LEN);
		return -EINVAL;
	}

	memset(&kprm, 0, sizeof(struct ioc_dpa_stats_cnts_reset_params));
	kprm.cnts_ids_len = uprm.cnts_ids_len;

	/* Allocate kernel-space memory area to copy the counters ids */
	kprm.cnts_ids = kcalloc(kprm.cnts_ids_len, sizeof(int), GFP_KERNEL);
	if (!kprm.cnts_ids) {
		log_err("Cannot allocate memory for counter ids array\n");
		return -ENOMEM;
	}

	/* Copy the user provided counter ids */
	if (copy_from_user(kprm.cnts_ids,
			(compat_ptr)(uprm.cnts_ids),
			(kprm.cnts_ids_len * sizeof(int)))) {
		log_err("Cannot copy from user array of counter ids\n");
		kfree(kprm.cnts_ids);
		return -EINVAL;
	}

	ret = dpa_stats_reset_counters(kprm.cnts_ids, kprm.cnts_ids_len);
	if (ret < 0) {
		kfree(kprm.cnts_ids);
		return ret;
	}

	kfree(kprm.cnts_ids);

	if (copy_to_user(args, &uprm, sizeof(uprm))) {
		log_err("Cannot copy to user the counter parameters\n");
		return -EINVAL;
	}

	return 0;
}
#endif

static long wrp_dpa_stats_do_ioctl(struct file *filp,
				   unsigned int cmd, unsigned long args)
{
	long ret = 0;

	switch (cmd) {
	case DPA_STATS_IOC_INIT:
	{
		struct ioc_dpa_stats_params kparam;

		/* Copy parameters from user-space */
		if (copy_from_user(&kparam, (void *)args, sizeof(kparam))) {
			log_err("Cannot copy from user dpa_stats_init arguments\n");
			return -EBUSY;
		}

		ret = do_ioctl_stats_init(&kparam);
		if (ret < 0)
			return ret;

		/* Copy paramters to user-space */
		if (copy_to_user((void *)args, &kparam, sizeof(kparam))) {
			log_err("Cannot copy to user dpa_stats_init result\n");
			return -EBUSY;
		}
		break;
	}
	case DPA_STATS_IOC_FREE:
		ret = do_ioctl_stats_free((void *)args);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_IOC_CREATE_COUNTER:
		ret = do_ioctl_stats_create_counter((void *)args);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_IOC_CREATE_CLASS_COUNTER:
		ret = do_ioctl_stats_create_class_counter((void *)args);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_IOC_MODIFY_CLASS_COUNTER:
		ret = do_ioctl_stats_modify_class_counter((void *)args);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_IOC_REMOVE_COUNTER:{
		int dpa_stats_cnt_id;
		if (copy_from_user(&dpa_stats_cnt_id, (int *)args,
				    sizeof(int))) {
			log_err("Cannot copy from user the parameters\n");
			return -EINVAL;
		}

		ret = dpa_stats_remove_counter(dpa_stats_cnt_id);
		if (ret < 0)
			return ret;

		break;
	}
	case DPA_STATS_IOC_GET_COUNTERS:
		ret = do_ioctl_stats_get_counters((void *)args);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_IOC_RESET_COUNTERS:
		ret = do_ioctl_stats_reset_counters((void *)args);
		if (ret < 0)
			return ret;
		break;
	default:
		log_err("Unsupported ioctl 0x%08x, type 0x%02x, nr 0x%02x\n",
			cmd, _IOC_TYPE(cmd), _IOC_NR(cmd));
		ret = -EINVAL;
		break;
	}
	return ret;
}

#ifdef CONFIG_COMPAT
static long wrp_dpa_stats_do_compat_ioctl(struct file *filp,
					  unsigned int cmd,
					  unsigned long args)
{
	long ret = 0;

	switch (cmd) {
	case DPA_STATS_IOC_COMPAT_INIT:
	{
		struct ioc_dpa_stats_params kparam;
		struct compat_ioc_dpa_stats_params uparam;

		/* Copy parameters from user space */
		if (copy_from_user(&uparam, (void *)args, sizeof(uparam))) {
			log_err("Cannot copy from user dpa_stats_init arguments\n");
			return -EBUSY;
		}
		dpa_stats_init_compatcpy(&kparam, &uparam);

		ret = do_ioctl_stats_init(&kparam);
		if (ret < 0)
			return ret;

		/* Copy result to user-space */
		uparam.dpa_stats_id = kparam.dpa_stats_id;
		if (copy_to_user((void *)args, &uparam, sizeof(uparam))) {
			log_err("Cannot copy to user dpa_stats_init result\n");
			return -EBUSY;
		}
		break;
	}
	case DPA_STATS_IOC_FREE:
		ret = do_ioctl_stats_free((void *)args);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_IOC_COMPAT_CREATE_COUNTER:
		ret = do_ioctl_stats_compat_create_counter((void *)args);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_IOC_COMPAT_CREATE_CLASS_COUNTER:
		ret = do_ioctl_stats_compat_create_class_counter((void *)args);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_IOC_COMPAT_MODIFY_CLASS_COUNTER:
		ret = do_ioctl_stats_compat_modify_class_counter((void *)args);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_IOC_REMOVE_COUNTER:{
		int dpa_stats_cnt_id;

		if (copy_from_user(&dpa_stats_cnt_id, (int *)args,
				    sizeof(int))) {
			log_err("Cannot copy from user counter parameters\n");
			return -EINVAL;
		}

		ret = dpa_stats_remove_counter(dpa_stats_cnt_id);
		if (ret < 0)
			return ret;
		break;
	}
	case DPA_STATS_IOC_COMPAT_GET_COUNTERS:
		ret = do_ioctl_stats_compat_get_counters((void *)args);
		if (ret < 0)
			return ret;
		break;
	case DPA_STATS_IOC_COMPAT_RESET_COUNTERS:
		ret = do_ioctl_stats_compat_reset_counters((void *)args);
		if (ret < 0)
			return ret;
		break;
	default:
		log_err("Unsupported ioctl 0x%08x, type 0x%02x, nr 0x%02x\n",
			cmd, _IOC_TYPE(cmd), _IOC_NR(cmd));
		break;
	}
	return ret;
}
#endif

static long store_get_cnts_async_params(
		struct ioc_dpa_stats_cnt_request_params *kprm, int *us_cnts)
{
	struct dpa_stats_async_req_ev *async_req_ev;
	struct list_head *async_req_grp;
	uint8_t grp_idx = 0;

	mutex_lock(&wrp_dpa_stats.async_req_lock);
	if (list_empty(&wrp_dpa_stats.async_req_pool)) {
		log_err("Reached maximum supported number of simultaneous asynchronous requests\n");
		mutex_unlock(&wrp_dpa_stats.async_req_lock);
		return -EDOM;
	}
	/* Add in the associated group the request event */
	grp_idx = crc8(crc8_table,
			(uint8_t *)&kprm->req_params.storage_area_offset,
			sizeof(unsigned int),
			0);
	async_req_grp = &wrp_dpa_stats.async_req_group[grp_idx];

	/* Obtain a free request event and add in the group list */
	async_req_ev = list_entry(wrp_dpa_stats.async_req_pool.next,
			struct dpa_stats_async_req_ev, node);
	list_del(&async_req_ev->node);
	async_req_ev->storage_area_offset =
			kprm->req_params.storage_area_offset;

	async_req_ev->ks_cnt_ids = kprm->req_params.cnts_ids;
	async_req_ev->us_cnt_ids = us_cnts;
	async_req_ev->cnt_ids_len = kprm->req_params.cnts_ids_len;
	list_add_tail(&async_req_ev->node, async_req_grp);
	mutex_unlock(&wrp_dpa_stats.async_req_lock);

	return 0;
}

static int copy_key_descriptor(struct dpa_offload_lookup_key *src,
			       struct dpa_offload_lookup_key **ks_key)
{
	struct dpa_offload_lookup_key *tmp = NULL;

	/* Allocate kernel memory for key descriptor */
	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp) {
		log_err("Cannot allocate kernel memory for key descriptor\n");
		return -ENOMEM;
	}

	if (src->byte) {
		/* Allocate memory to store the key byte array */
		tmp->byte = kmalloc(src->size, GFP_KERNEL);
		if (!tmp->byte) {
			log_err("Cannot allocate memory for key descriptor byte\n");
			kfree(tmp);
			return -ENOMEM;
		}

		if (copy_from_user(tmp->byte, src->byte, src->size)) {
			log_err("Cannot copy from user the key descriptor byte\n");
			kfree(tmp->byte);
			kfree(tmp);
			return -EBUSY;
		}
	}

	if (src->mask) {
		/* Allocate memory to store the key mask array */
		tmp->mask = kmalloc(src->size, GFP_KERNEL);
		if (!tmp->mask) {
			log_err("Cannot allocate memory for key descriptor mask\n");
			kfree(tmp->byte);
			kfree(tmp);
			return -ENOMEM;
		}

		if (copy_from_user(tmp->mask, src->mask, src->size)) {
			log_err("Cannot copy from user the key descriptor mask\n");
			kfree(tmp->byte);
			kfree(tmp->mask);
			kfree(tmp);
			return -EBUSY;
		}
	}

	tmp->size = src->size;
	*ks_key = tmp;
	return 0;
}

static int copy_pair_descriptor(struct dpa_offload_lookup_key_pair *src,
				struct dpa_offload_lookup_key_pair **ks_pair)
{
	struct dpa_offload_lookup_key_pair *tmp;
	int ret = 0;

	/* Allocate kernel memory for pair descriptor*/
	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp) {
		log_err("Cannot allocate kernel memory for pair descriptor\n");
		return -ENOMEM;
	}

	if (src->first_key) {
		ret = copy_key_descriptor(src->first_key, &tmp->first_key);
		if (ret != 0) {
			log_err("Cannot copy the first key descriptor\n");
			kfree(tmp);
			return ret;
		}
	}

	if (src->second_key) {
		ret = copy_key_descriptor(src->second_key, &tmp->second_key);
		if (ret != 0) {
			log_err("Cannot copy the second key descriptor\n");
			if (tmp->first_key) {
				kfree(tmp->first_key->byte);
				kfree(tmp->first_key->mask);
			}
			kfree(tmp);
			return ret;
		}
	}
	*ks_pair = tmp;
	return 0;
}

#ifdef CONFIG_COMPAT
static int copy_key_descriptor_compatcpy(
		struct dpa_offload_lookup_key **ks_key, compat_uptr_t uparam)
{
	struct compat_ioc_dpa_offld_lookup_key key;
	struct dpa_offload_lookup_key *kparam;

	if (copy_from_user(&key, (compat_ptr)(uparam),
			   sizeof(struct compat_ioc_dpa_offld_lookup_key))) {
		log_err("Cannot copy from user key descriptor\n");
		return -EBUSY;
	}

	/* Allocate kernel memory for key descriptor */
	kparam = kzalloc(sizeof(*kparam), GFP_KERNEL);
	if (!kparam) {
		log_err("Cannot allocate kernel memory for key descriptor\n");
		return -ENOMEM;
	}

	if ((compat_ptr(key.byte) || compat_ptr(key.mask))) {
		if (key.size == 0 || key.size > DPA_OFFLD_MAXENTRYKEYSIZE) {
			log_err("Key size should be between %d and %d.\n", 1,
				DPA_OFFLD_MAXENTRYKEYSIZE);
			kfree(kparam);
			return -EINVAL;
		}
	}

	if (compat_ptr(key.byte)) {
		/* Allocate memory to store the key byte array */
		kparam->byte = kmalloc(key.size, GFP_KERNEL);
		if (!kparam->byte) {
			log_err("Cannot allocate memory for key descriptor byte\n");
			kfree(kparam);
			return -ENOMEM;
		}

		if (copy_from_user(kparam->byte,
				   compat_ptr(key.byte), key.size)) {
			log_err("Cannot copy from user the key descriptor byte\n");
			kfree(kparam->byte);
			kfree(kparam);
			return -EBUSY;
		}
	}

	if (compat_ptr(key.mask)) {
		/* Allocate memory to store the key mask array */
		kparam->mask = kmalloc(key.size, GFP_KERNEL);
		if (!kparam->mask) {
			log_err("Cannot allocate memory for key descriptor mask\n");
			kfree(kparam->byte);
			kfree(kparam);
			return -ENOMEM;
		}

		if (copy_from_user(kparam->mask,
				   compat_ptr(key.mask), key.size)) {
			log_err("Cannot copy from user the key descriptor mask\n");
			kfree(kparam->byte);
			kfree(kparam->mask);
			kfree(kparam);
			return -EBUSY;
		}
	}
	kparam->size = key.size;
	*ks_key = kparam;
	return 0;
}

static int copy_pair_descriptor_compatcpy(
		struct dpa_offload_lookup_key_pair **ks_pair,
		struct compat_ioc_dpa_offld_lookup_key_pair pair)
{
	struct dpa_offload_lookup_key_pair *kpair;
	int ret = 0;

	/* Allocate kernel memory for lookup pair descriptor */
	kpair = kzalloc(sizeof(*kpair), GFP_KERNEL);
	if (!kpair) {
		log_err("Cannot allocate kernel memory for pair descriptor\n");
		return -ENOMEM;
	}

	if (compat_ptr(pair.first_key)) {
		/* Copy user-provided key descriptor */
		ret = copy_key_descriptor_compatcpy(
					&kpair->first_key, pair.first_key);
		if (ret != 0) {
			log_err("Cannot copy first key of the pair\n");
			kfree(kpair);
			return ret;
		}
	}

	if (compat_ptr(pair.second_key)) {
		ret = copy_key_descriptor_compatcpy(
					&kpair->second_key, pair.second_key);
		if (ret != 0) {
			log_err("Cannot copy second key of the pair\n");
			if (kpair->first_key) {
				kfree(kpair->first_key->byte);
				kfree(kpair->first_key->mask);
			}
			kfree(kpair);
			return ret;
		}
	}
	*ks_pair = kpair;
	return 0;
}
#endif

static void **copy_class_members(unsigned int size, void **src)
{
	void **objs;

	/* Allocate memory to store the array of objects */
	objs = kcalloc(size, sizeof(void *), GFP_KERNEL);
	if (!objs) {
		log_err("Cannot allocate memory for objects array\n");
		return NULL;
	}

	if (copy_from_user(objs, src, (size * sizeof(void *)))) {
		log_err("Cannot copy from user array of objects\n");
		kfree(objs);
		return NULL;
	}
	return objs;
}

#ifdef CONFIG_COMPAT
static void dpa_stats_init_compatcpy(struct ioc_dpa_stats_params *kparam,
				     struct compat_ioc_dpa_stats_params *uparam)
{
	kparam->dpa_stats_id = uparam->dpa_stats_id;
	kparam->max_counters = uparam->stats_params.max_counters;
	kparam->storage_area_len = uparam->stats_params.storage_area_len;
	kparam->virt_stg_area = compat_ptr(uparam->stats_params.virt_stg_area);
	kparam->phys_stg_area = uparam->stats_params.phys_stg_area;
	kparam->stg_area_mapped = uparam->stats_params.stg_area_mapped;
}

static void dpa_stats_reass_cnt_compatcpy(struct dpa_stats_cnt_reass *kprm,
				struct dpa_stats_compat_cnt_reass *uprm)
{
	kprm->reass = compat_get_id2ptr(uprm->reass, FM_MAP_TYPE_PCD_NODE);
	kprm->cnt_sel = uprm->cnt_sel;
}

static void dpa_stats_frag_cnt_compatcpy(struct dpa_stats_cnt_frag *kprm,
					 struct dpa_stats_compat_cnt_frag *uprm)
{
	kprm->frag = compat_get_id2ptr(uprm->frag, FM_MAP_TYPE_PCD_NODE);
	kprm->cnt_sel = uprm->cnt_sel;
}

static void dpa_stats_plcr_cnt_compatcpy(struct dpa_stats_cnt_plcr *kprm,
					 struct dpa_stats_compat_cnt_plcr *uprm)
{
	kprm->plcr = compat_get_id2ptr(uprm->plcr, FM_MAP_TYPE_PCD_NODE);
	kprm->cnt_sel = uprm->cnt_sel;
}


static long dpa_stats_tbl_cnt_compatcpy(struct dpa_stats_cnt_classif_tbl *kprm,
				struct dpa_stats_compat_cnt_classif_tbl *uprm)
{
	kprm->td = uprm->td;
	kprm->cnt_sel = uprm->cnt_sel;
	kprm->key = NULL;

	if (compat_ptr(uprm->key))
		return copy_key_descriptor_compatcpy(&kprm->key, uprm->key);

	return 0;
}

static long dpa_stats_ccnode_cnt_compatcpy(
		struct dpa_stats_cnt_classif_node *kprm,
		struct dpa_stats_compat_cnt_classif_node *uprm)
{
	kprm->cnt_sel = uprm->cnt_sel;
	kprm->ccnode_type = uprm->ccnode_type;
	kprm->cc_node = compat_get_id2ptr(uprm->cc_node, FM_MAP_TYPE_PCD_NODE);
	kprm->key = NULL;

	if (compat_ptr(uprm->key))
		return copy_key_descriptor_compatcpy(&kprm->key, uprm->key);

	return 0;
}

static long dpa_stats_eth_cls_compatcpy(struct dpa_stats_cls_cnt_eth *kprm,
		struct dpa_stats_compat_cls_cnt_eth *uprm, uint32_t cls_members)
{
	uint32_t size = 0;

	size = cls_members * sizeof(struct dpa_stats_cnt_eth_src);

	/* Allocate memory to store the sources array */
	kprm->src = kzalloc(size, GFP_KERNEL);
	if (!kprm->src) {
		log_err("Cannot allocate kernel memory for Ethernet sources array\n");
		return -ENOMEM;
	}

	if (copy_from_user(kprm->src, compat_ptr(uprm->src), size)) {
		log_err("Cannot copy from user array of Ethernet sources\n");
		kfree(kprm->src);
		return -EBUSY;
	}
	kprm->cnt_sel = uprm->cnt_sel;
	return 0;
}

static long dpa_stats_reass_cls_compatcpy(struct dpa_stats_cls_cnt_reass *kprm,
		struct dpa_stats_compat_cnt_reass *uprm, uint32_t cls_members)
{
	compat_uptr_t *reass;
	uint32_t i = 0;

	/* Allocate memory to store the array of user-space reass objects */
	reass = kzalloc(sizeof(compat_uptr_t) * cls_members, GFP_KERNEL);
	if (!reass) {
		log_err("Cannot allocate memory for Reassembly objects array\n");
		return -ENOMEM;
	}

	if (copy_from_user(reass, compat_ptr(uprm->reass),
			(sizeof(compat_uptr_t) * cls_members))) {
		log_err("Cannot copy from user array of Reassembly objects\n");
		kfree(reass);
		return -EBUSY;
	}

	/* Allocate memory to store the array of kernel space reass objects */
	kprm->reass = kzalloc((sizeof(void *) * cls_members), GFP_KERNEL);
	if (!kprm->reass) {
		log_err("Cannot allocate kernel memory for Reassembly objects array\n");
		kfree(reass);
		return -ENOMEM;
	}

	for (i = 0; i < cls_members; i++)
		kprm->reass[i] = compat_get_id2ptr(
				reass[i], FM_MAP_TYPE_PCD_NODE);

	kprm->cnt_sel = uprm->cnt_sel;
	kfree(reass);
	return 0;
}

static long dpa_stats_frag_cls_compatcpy(struct dpa_stats_cls_cnt_frag *kprm,
					 struct dpa_stats_compat_cnt_frag *uprm,
					 uint32_t cls_members)
{
	compat_uptr_t *ufrag;
	uint32_t i = 0;

	/* Allocate memory to store the array of user-space frag objects */
	ufrag = kzalloc(sizeof(compat_uptr_t) * cls_members, GFP_KERNEL);
	if (!ufrag) {
		log_err("Cannot allocate memory for Fragmentation objects array\n");
		return -ENOMEM;
	}

	if (copy_from_user(ufrag, compat_ptr(uprm->frag),
			(sizeof(compat_uptr_t) * cls_members))) {
		log_err("Cannot copy from user array of Fragmentation objects\n");
		kfree(ufrag);
		return -EBUSY;
	}

	/* Allocate memory to store the array of kernel space frag objects */
	kprm->frag = kzalloc((sizeof(void *) * cls_members), GFP_KERNEL);
	if (!kprm->frag) {
		log_err("Cannot allocate kernel memory for Fragmentation objects array\n");
		kfree(ufrag);
		return -ENOMEM;
	}

	for (i = 0; i < cls_members; i++)
		kprm->frag[i] = compat_get_id2ptr(
				ufrag[i], FM_MAP_TYPE_PCD_NODE);

	kprm->cnt_sel = uprm->cnt_sel;
	kfree(ufrag);
	return 0;
}

static long dpa_stats_plcr_cls_compatcpy(struct dpa_stats_cls_cnt_plcr *kprm,
					 struct dpa_stats_compat_cnt_plcr *uprm,
					 uint32_t cls_members)
{
	compat_uptr_t *uplcr;
	uint32_t i = 0;

	/* Allocate memory to store the array of user-space policer objects */
	uplcr = kzalloc(sizeof(compat_uptr_t) * cls_members, GFP_KERNEL);
	if (!uplcr) {
		log_err("Cannot allocate memory for Policer objects array\n");
		return -ENOMEM;
	}

	if (copy_from_user(uplcr, compat_ptr(uprm->plcr),
			(sizeof(compat_uptr_t) * cls_members))) {
		log_err("Cannot copy from user array of Policer objects\n");
		kfree(uplcr);
		return -EBUSY;
	}

	/* Allocate memory to store the array of kernel space policer objects */
	kprm->plcr = kzalloc((sizeof(void *) * cls_members), GFP_KERNEL);
	if (!kprm->plcr) {
		log_err("Cannot allocate kernel memory for Policer objects array\n");
		kfree(uplcr);
		return -ENOMEM;
	}

	for (i = 0; i < cls_members; i++)
		kprm->plcr[i] = compat_get_id2ptr(
				uplcr[i], FM_MAP_TYPE_PCD_NODE);

	kprm->cnt_sel = uprm->cnt_sel;
	kfree(uplcr);
	return 0;
}

static long dpa_stats_tbl_cls_compatcpy(
		struct dpa_stats_cls_cnt_classif_tbl *kprm,
		struct dpa_stats_compat_cls_cnt_classif_tbl *uprm,
		uint32_t cls_members)
{
	struct compat_ioc_dpa_offld_lookup_key_pair pair;
	compat_uptr_t *us_keys;
	uint32_t i;
	long ret;

	kprm->cnt_sel = uprm->cnt_sel;
	kprm->td = uprm->td;
	kprm->key_type = uprm->key_type;

	/* Allocate memory to store array of user-space keys descriptors */
	us_keys = kzalloc(sizeof(compat_uptr_t) * cls_members, GFP_KERNEL);
	if (!us_keys) {
		log_err("Cannot allocate memory array of lookup keys\n");
		return -ENOMEM;
	}

	if (kprm->key_type == DPA_STATS_CLASSIF_SINGLE_KEY) {
		if (copy_from_user(us_keys, compat_ptr(uprm->keys),
				  (sizeof(compat_uptr_t) * cls_members))) {
			log_err("Cannot copy from user-space array of keys descriptors\n");
			kfree(us_keys);
			return -EBUSY;
		}

		/* Allocate memory for array of kernel-space keys descriptors */
		kprm->keys = kzalloc((sizeof(*kprm->keys) * cls_members),
				     GFP_KERNEL);
		if (!kprm->keys) {
			log_err("Cannot allocate kernel memory for lookup keys array\n");
			kfree(us_keys);
			return -ENOMEM;
		}
		for (i = 0; i < cls_members; i++) {
			if (!compat_ptr(us_keys[i]))
				continue;
			/* Copy user-provided key descriptor */
			ret = copy_key_descriptor_compatcpy(&kprm->keys[i],
							    us_keys[i]);
			if (ret != 0) {
				log_err("Cannot copy the key descriptor\n");
				kfree(us_keys);
				return ret;
			}
		}
	}

	if (kprm->key_type == DPA_STATS_CLASSIF_PAIR_KEY) {
		if (copy_from_user(us_keys, compat_ptr(uprm->pairs),
				  (sizeof(compat_uptr_t) * cls_members))) {
			log_err("Cannot copy from user-space array of pair descriptors\n");
			kfree(us_keys);
			return -EBUSY;
		}

		/* Allocate memory for array of kernel-space pairs descriptors*/
		kprm->pairs = kzalloc((sizeof(*kprm->pairs) * cls_members),
				      GFP_KERNEL);
		if (!kprm->pairs) {
			log_err("Cannot allocate kernel memory for lookup pairs array\n");
			kfree(us_keys);
			return -ENOMEM;
		}

		for (i = 0; i < cls_members; i++) {
			if (!compat_ptr(us_keys[i]))
				continue;

			/* Allocate memory for kernel pair descriptor */
			kprm->pairs[i] = kzalloc(sizeof(*kprm->pairs[i]),
						GFP_KERNEL);
			if (!kprm->pairs[i]) {
				log_err("Cannot allocate kernel memory for pair descriptor\n");
				kfree(us_keys);
				return -ENOMEM;
			}

			if (copy_from_user(&pair, compat_ptr(us_keys[i]),
					   (sizeof(pair)))) {
				log_err("Cannot copy pair descriptor\n");
				kfree(us_keys);
				return -EBUSY;
			}

			if (compat_ptr(pair.first_key)) {
				/* Copy user-provided first key descriptor */
				ret = copy_key_descriptor_compatcpy(
						&kprm->pairs[i]->first_key,
						pair.first_key);
				if (ret != 0) {
					log_err("Cannot copy first key\n");
					kfree(us_keys);
					return ret;
				}
			}

			if (compat_ptr(pair.second_key)) {
				/* Copy user-provided second key descriptor */
				ret = copy_key_descriptor_compatcpy(
						&kprm->pairs[i]->second_key,
						pair.second_key);
				if (ret != 0) {
					log_err("Cannot copy second key\n");
					kfree(us_keys);
					return ret;
				}
			}
		}
	}

	kfree(us_keys);

	return 0;
}

static long dpa_stats_ccnode_cls_compatcpy(
		struct dpa_stats_cls_cnt_classif_node *kprm,
		struct dpa_stats_compat_cls_cnt_classif_node *uprm,
		uint32_t cls_members)
{
	compat_uptr_t *us_keys;
	uint32_t i;
	long ret = 0;

	kprm->cc_node = compat_get_id2ptr(uprm->cc_node, FM_MAP_TYPE_PCD_NODE);
	kprm->cnt_sel = uprm->cnt_sel;
	kprm->ccnode_type = uprm->ccnode_type;

	/* Allocate memory to store array of user-space keys descriptors */
	us_keys = kzalloc(sizeof(compat_uptr_t) * cls_members, GFP_KERNEL);
	if (!us_keys) {
		log_err("Cannot allocate memory array of lookup keys\n");
		return -ENOMEM;
	}

	if (copy_from_user(us_keys, compat_ptr(uprm->keys),
			  (sizeof(compat_uptr_t) * cls_members))) {
		log_err("Cannot copy from user-space array of keys descriptors\n");
		kfree(us_keys);
		return -EBUSY;
	}

	/* Allocate memory to store array of kernel-space keys descriptors */
	kprm->keys = kzalloc((sizeof(*kprm->keys) * cls_members), GFP_KERNEL);
	if (!kprm->keys) {
		log_err("Cannot allocate kernel memory for lookup keys array\n");
		kfree(us_keys);
		return -ENOMEM;
	}
	for (i = 0; i < cls_members; i++) {
		if (!compat_ptr(us_keys[i]))
			continue;
		/* Copy user-provided key descriptor */
		ret = copy_key_descriptor_compatcpy(&kprm->keys[i], us_keys[i]);
		if (ret != 0) {
			log_err("Cannot copy the key descriptor\n");
			kfree(us_keys);
			return ret;
		}
	}
	kfree(us_keys);
	return 0;
}

static long dpa_stats_ipsec_cls_compatcpy(struct dpa_stats_cls_cnt_ipsec *kprm,
		struct dpa_stats_compat_cls_cnt_ipsec *uprm,
		uint32_t cls_members)
{
	kprm->cnt_sel = uprm->cnt_sel;

	/* Allocate memory to store the sa ids array */
	kprm->sa_id = kcalloc(cls_members, sizeof(int), GFP_KERNEL);
	if (!kprm->sa_id) {
		log_err("Cannot allocate memory for SA ids array\n");
		return -ENOMEM;
	}

	if (copy_from_user(kprm->sa_id,
			(compat_ptr)(uprm->sa_id),
			(cls_members * sizeof(int)))) {
		log_err("Cannot copy from user array of SA ids\n");
		kfree(kprm->sa_id);
		return -EBUSY;
	}
	return 0;
}
#endif
