
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
 * DPA Classifier Application Programming Interface implementation
 */


#define __DPA_CLASSIFIER_C


#include <linux/crc8.h>
#include <linux/crc64_ecma.h>
#include <linux/module.h>

/* DPA offloading layer includes */
#include "dpa_classifier.h"

/* FMD includes */
#include "error_ext.h"
#include "fm_pcd_ext.h"
#include "crc64.h"


/* Granularity of the descriptor tables */
#define DPA_CLS_ARRAYSIZEGRANULARITY				10

#define PPP_HEADER_OFFSET					0
#define PPP_HEADER_SIZE						2 /* bytes */
#define ETHERTYPE_OFFSET					12
#define ETHERTYPE_SIZE						2 /* bytes */

#define CRC8_WCDMA_POLY						0x9b

#ifdef DPA_CLASSIFIER_DEBUG
#define dpa_cls_dbg(message) printk message
#else
#define dpa_cls_dbg(message)
#endif /* DPA_CLASSIFIER_DEBUG */

#ifdef DPA_HM_DEBUG
#define dpa_cls_hm_dbg(message) printk message
#else
#define dpa_cls_hm_dbg(message)
#endif /* DPA_HM_DEBUG */

#define LOCK_OBJECT(desc_table, desc, object, einval) \
		lock_desc_table(&(desc_table)); \
		(object) = desc_to_object(&(desc_table), (desc)); \
		if (!(object)) { \
			release_desc_table(&(desc_table)); \
			log_err("Invalid descriptor (%d).\n", (desc)); \
			return (einval); \
		} \
		mutex_lock(&(object)->access); \
		release_desc_table(&(desc_table))

#define RELEASE_OBJECT(object) \
		mutex_unlock(&(object)->access)

#define LOCK_HM_OP_CHAIN(hm) \
	list_for_each_entry(pcurrent, \
		&(hm)->list_node, \
		list_node) { \
			mutex_lock(&pcurrent->access); \
	} \
	mutex_lock(&(hm)->access)

#define RELEASE_HM_OP_CHAIN(hm) \
	list_for_each_entry(pcurrent, \
		&(hm)->list_node, \
		list_node) { \
			mutex_unlock(&pcurrent->access); \
	} \
	mutex_unlock(&(hm)->access)

DEFINE_MUTEX(table_array_lock);
DEFINE_MUTEX(hm_array_lock);
#if (DPAA_VERSION >= 11)
DEFINE_MUTEX(mcast_array_lock);
#endif

/* DPA Classifier table descriptor table */
struct dpa_cls_descriptor_table		table_array = {
	.num_descriptors	= 0,
	.used_descriptors	= 0,
	.object			= NULL,
	.access			= &table_array_lock
};

/* Header manipulation descriptor table */
struct dpa_cls_descriptor_table		hm_array = {
	.num_descriptors	= 0,
	.used_descriptors	= 0,
	.object			= NULL,
	.access			= &hm_array_lock
};

#if (DPAA_VERSION >= 11)
/* Multicast group descriptor table */
struct dpa_cls_descriptor_table		mcast_grp_array = {
	.num_descriptors	= 0,
	.used_descriptors	= 0,
	.object			= NULL,
	.access			= &mcast_array_lock
};
#endif

DECLARE_CRC8_TABLE(crc8_table);
static bool crc8_initialized = false;

/*
 * Gets the first free descriptor in the indicated descriptor table and fills
 * it with the provided object pointer. If there are no available descriptors,
 * the function fails. This function is not thread safe.
 */
static int get_descriptor(struct dpa_cls_descriptor_table *desc_table,
						void *object, int *desc);

/*
 * Extends with one more step an existing descriptor table. The array is
 * reallocated with a constant number of new elements which is defined by the
 * DPA Classifier implementation. This function is not thread safe.
 */
static int	extend_descriptor_table(struct dpa_cls_descriptor_table
								*desc_table);


int dpa_classif_table_create(const struct dpa_cls_tbl_params	*params,
				int				*td)
{
	int err = 0;
	struct dpa_cls_table *ptable;
	unsigned int i;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!params) {
		log_err("\"params\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!td) {
		log_err("\"td\" cannot be NULL.\n");
		return -EINVAL;
	}

	*td = DPA_OFFLD_DESC_NONE;

	err = verify_table_params(params);
	if (err < 0)
		return err;

	ptable = kzalloc(sizeof(*ptable), GFP_KERNEL);
	if (!ptable) {
		log_err("No more memory for DPA classifier table. Requested "
			"table type=%d.\n", params->type);
		err = -ENOMEM;
		goto dpa_classif_table_create_error;
	}

	mutex_init(&ptable->access);

	/* Copy over the table params into the control block */
	memcpy(&ptable->params, params, sizeof(struct dpa_cls_tbl_params));

	switch (ptable->params.type) {
	case DPA_CLS_TBL_INDEXED:
		ptable->int_cc_nodes_count = 1;
		if (ptable->params.entry_mgmt == DPA_CLS_TBL_MANAGE_BY_KEY) {
			ptable->shadow_table =
				kzalloc(sizeof(*ptable->shadow_table),
					GFP_KERNEL);
			if (!ptable->shadow_table) {
				log_err("No more memory for classifier shadow "
					"table while creating INDEXED "
					"table.\n");
				err = -ENOMEM;
				goto dpa_classif_table_create_error;
			}
			/*
			 * Shadow table is directly indexed with the index in
			 * the entry key
			 */
			ptable->shadow_table->size =
				ptable->params.indexed_params.entries_cnt;
		}

		break;

	case DPA_CLS_TBL_EXACT_MATCH:
		ptable->int_cc_nodes_count = 1;
		if (ptable->params.entry_mgmt ==
				DPA_CLS_TBL_MANAGE_BY_KEY) {
			ptable->shadow_table =
				kzalloc(sizeof(*ptable->shadow_table),
					GFP_KERNEL);
			if (!ptable->shadow_table) {
				log_err("No more memory for classifier shadow "
					"table while creating EXACT MATCH "
					"table.\n");
				err = -ENOMEM;
				goto dpa_classif_table_create_error;
			}

			/* Set shadow table size */
			ptable->shadow_table->size =
					DPA_CLS_TBL_MAXSHADOWTABLESIZE;
		}

		break;

	case DPA_CLS_TBL_HASH:
		if (!ptable->params.prefilled_entries) {
			ptable->int_cc_nodes_count =
				ptable->params.hash_params.num_sets;
			if (ptable->params.entry_mgmt ==
						DPA_CLS_TBL_MANAGE_BY_KEY) {
				ptable->shadow_table =
					kzalloc(sizeof(*ptable->shadow_table),
						GFP_KERNEL);
				if (!ptable->shadow_table) {
					log_err("No more memory for classifier "
						"shadow table while creating "
						"HASH table.\n");
					err = -ENOMEM;
					goto dpa_classif_table_create_error;
				}

				/*
				 * Shadow table is indexed using a CRC8 HASH on
				 * the key
				 */
				ptable->shadow_table->size =
					DPA_CLS_TBL_MAXSHADOWTABLESIZE;
			}
		}
		break;
	default:
		log_err("Unsupported DPA Classifier table type (%d).\n",
			ptable->params.type);
		goto dpa_classif_table_create_error;
	}

	/* Init shadow table if necessary */
	if (ptable->shadow_table) {
		/* Allocate entries in the shadow table */
		ptable->shadow_table->shadow_entry =
			kmalloc(ptable->shadow_table->size *
				sizeof(struct list_head), GFP_KERNEL);
		if (!ptable->shadow_table->shadow_entry) {
			log_err("No more memory for DPA Classifier shadow "
				"table buckets (%d buckets). Requested table "
				"type=%d.\n", ptable->shadow_table->size,
				ptable->params.type);
			err = -ENOMEM;
			goto dpa_classif_table_create_error;
		}

		/* Initialize the entries in shadow table */
		for (i = 0; i < ptable->shadow_table->size; i++)
			INIT_LIST_HEAD(&ptable->shadow_table->shadow_entry[i]);
	}

	switch (ptable->params.type) {
	case DPA_CLS_TBL_INDEXED:
		err = table_init_indexed(ptable);
		if (err < 0)
			log_err("Failed to create INDEXED table.\n");
		break;
	case DPA_CLS_TBL_EXACT_MATCH:
		err = table_init_exact_match(ptable);
		if (err < 0)
			log_err("Failed to create EXACT MATCH table.\n");
		break;
	case DPA_CLS_TBL_HASH:
		err = table_init_hash(ptable);
		if (err < 0)
			log_err("Failed to create HASH table.\n");
		break;
	}
	if (err < 0)
		goto dpa_classif_table_create_error;

	if (!crc8_initialized) {
		crc8_populate_msb(crc8_table, CRC8_WCDMA_POLY);
		crc8_initialized = true;
	}

	lock_desc_table(&table_array);
	err = acquire_descriptor(&table_array, ptable, td);
	release_desc_table(&table_array);
	if (err < 0)
		goto dpa_classif_table_create_error;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;

dpa_classif_table_create_error:
	/* Something went wrong. Release allocated memory and exit */
	if (ptable) {
		if (ptable->shadow_table) {
			kfree(ptable->shadow_table->shadow_entry);
			kfree(ptable->shadow_table);
		}

		free_table_management(ptable);

		/* Free entry index management */
		kfree(ptable->entry);
		ptable->entry = NULL;
		ptable->entries_cnt = 0;

		kfree(ptable);
	}

	return err;
}
EXPORT_SYMBOL(dpa_classif_table_create);

int dpa_classif_table_free(int td)
{
	int err;
	struct dpa_cls_table *ptable;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	lock_desc_table(&table_array);
	ptable = desc_to_object(&table_array, td);
	if (!ptable) {
		release_desc_table(&table_array);
		log_err("No such table (td=%d).\n", td);
		return -EINVAL;
	}

	mutex_lock(&ptable->access);

	/* Flush the entries in the table */
	err = flush_table(ptable);

	switch (ptable->params.type) {
	case DPA_CLS_TBL_EXACT_MATCH:
		break;
	case DPA_CLS_TBL_INDEXED:
		table_cleanup_indexed(ptable);
		break;
	case DPA_CLS_TBL_HASH:
		break;
	}

	/* Check shadow table if it exists */
	if (ptable->shadow_table) {
		/* Release shadow table */
		kfree(ptable->shadow_table->shadow_entry);
		kfree(ptable->shadow_table);
	}

	/* Free entry index management */
	kfree(ptable->entry);
	ptable->entry		= NULL;
	ptable->entries_cnt	= 0;

	free_table_management(ptable);

	put_descriptor(&table_array, td);
	release_desc_table(&table_array);

	kfree(ptable);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}
EXPORT_SYMBOL(dpa_classif_table_free);

int dpa_classif_table_modify_miss_action(int			td,
				const struct dpa_cls_tbl_action	*miss_action)
{
	int errno;
	int old_hmd, hmd;
	t_Error err;
	t_FmPcdCcNextEngineParams miss_engine_params;
	struct dpa_cls_table *ptable;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!miss_action) {
		log_err("\"miss_action\" cannot be NULL.\n");
		return -EINVAL;
	}

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	if (ptable->params.type == DPA_CLS_TBL_INDEXED) {
		RELEASE_OBJECT(ptable);
		log_err("Miss Action for DPA Classifier Indexed Tables (td=%d) "
			"is not supported.\n", td);
		return -ENOSYS;
	}

	/*
	 * Check existing header manipulation descriptors and release if
	 * found.
	 */
	switch (ptable->miss_action.type) {
	case DPA_CLS_TBL_ACTION_ENQ:
		old_hmd = ptable->miss_action.enq_params.hmd;
		break;
	case DPA_CLS_TBL_ACTION_NEXT_TABLE:
		old_hmd = ptable->miss_action.next_table_params.hmd;
		break;
#if (DPAA_VERSION >= 11)
	case DPA_CLS_TBL_ACTION_MCAST:
		old_hmd = ptable->miss_action.mcast_params.hmd;
		break;
#endif /* (DPAA_VERSION >= 11) */
	default:
		old_hmd = DPA_OFFLD_DESC_NONE;
		break;
	}
	dpa_classif_hm_release_chain(old_hmd);

	/* Fill the [miss_engine_params] structure w/ data */
	errno = action_to_next_engine_params(miss_action, &miss_engine_params,
					&hmd);
	if (errno < 0) {
		/* Lock back the old HM chain. */
		dpa_classif_hm_lock_chain(old_hmd);
		RELEASE_OBJECT(ptable);
		log_err("Failed verification of miss action params for table "
			"td=%d.\n", td);
		return errno;
	}

	if (ptable->params.type == DPA_CLS_TBL_HASH) {
		err = FM_PCD_HashTableModifyMissNextEngine(ptable->params.
			cc_node, &miss_engine_params);
		if (err != E_OK) {
			/* Lock back the old HM chain. */
			dpa_classif_hm_lock_chain(old_hmd);
			RELEASE_OBJECT(ptable);
			log_err("FMan driver call failed - "
				"FM_PCD_HashTableModifyMissNextEngine "
				"(td=%d, Cc node handle=0x%p).\n", td,
				ptable->params.cc_node);
			return -EBUSY;
		}
	} else {
		err = FM_PCD_MatchTableModifyMissNextEngine((t_Handle)ptable->
			int_cc_node[0].cc_node, &miss_engine_params);
		if (err != E_OK) {
			/* Lock back the old HM chain. */
			dpa_classif_hm_lock_chain(old_hmd);
			RELEASE_OBJECT(ptable);
			log_err("FMan driver call failed - "
				"FM_PCD_MatchTableModifyMissNextEngine (td=%d, "
				"Cc node handle=0x%p).\n", td,
				ptable->int_cc_node[0].cc_node);
			return -EBUSY;
		}
	}

	/* Store Miss Action (including its header manip chain). */
	memcpy(&ptable->miss_action, miss_action, sizeof(*miss_action));

	RELEASE_OBJECT(ptable);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}
EXPORT_SYMBOL(dpa_classif_table_modify_miss_action);

int dpa_classif_table_insert_entry(int				td,
			const struct dpa_offload_lookup_key	*key,
			const struct dpa_cls_tbl_action		*action,
			int					priority,
			int					*entry_id)
{
	int err = 0;
	struct dpa_cls_table *ptable;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!key) {
		log_err("\"key\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!key->byte) {
		log_err("\"key->byte\" cannot be NULL.\n");
		return -EINVAL;
	}
	if ((key->size <= 0) || (key->size > DPA_OFFLD_MAXENTRYKEYSIZE)) {
		log_err("Key size should be between %d and %d.\n", 1,
			DPA_OFFLD_MAXENTRYKEYSIZE);
		return -EINVAL;
	}
	if (!action) {
		log_err("\"action\" cannot be NULL.\n");
		return -EINVAL;
	}

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	if (ptable->params.type == DPA_CLS_TBL_INDEXED) {
		RELEASE_OBJECT(ptable);
		log_err("Insert entry in an indexed table (td=%d) makes no "
			"sense. Please use modify_entry instead.\n", td);
		return -EINVAL;
	}

	/*
	 * Verify if there is already an entry in the table which conflicts with
	 * this one (this verification is only possible if a shadow table is
	 * used)
	 */
	if ((ptable->shadow_table) &&
			(find_shadow_entry(ptable, key) != NULL)) {
		RELEASE_OBJECT(ptable);
		log_err("DPA Classifier table entry already exists in table "
			"td=%d.\n", td);
		dump_lookup_key(key);
		return -EEXIST;
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d): Insert new entry in table td=%d.\n",
		__func__, __LINE__, td));

	switch (ptable->params.type) {
	case DPA_CLS_TBL_HASH:
		err = table_insert_entry_hash(ptable,
						key,
						action,
						entry_id);
		break;
	case DPA_CLS_TBL_EXACT_MATCH:
		err = table_insert_entry_exact_match(ptable,
						key,
						action,
						priority,
						entry_id);
		break;
	default:
		BUG_ON(1);
	}

	RELEASE_OBJECT(ptable);
	if (err < 0) {
		log_err("Failed to insert entry in table td=%d. Table type=%d.\n",
			td, ptable->params.type);
		dump_lookup_key(key);
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}
EXPORT_SYMBOL(dpa_classif_table_insert_entry);

int dpa_classif_table_modify_entry_by_key(int			td,
		const struct dpa_offload_lookup_key		*key,
		const struct dpa_cls_tbl_entry_mod_params	*mod_params)
{
	int entry_id;
	int ret = 0;
	struct dpa_cls_table *ptable;
	t_Error err;
	uint8_t key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t new_key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t new_mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t *mask;
	uint8_t *new_mask;
	t_FmPcdCcKeyParams key_params;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!key) {
		log_err("\"key\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!key->byte) {
		log_err("\"key->byte\" cannot be NULL.\n");
		return -EINVAL;
	}
	if ((key->size <= 0) || (key->size > DPA_OFFLD_MAXENTRYKEYSIZE)) {
		log_err("Key size should be between %d and %d.\n", 1,
			DPA_OFFLD_MAXENTRYKEYSIZE);
		return -EINVAL;
	}
	if (!mod_params) {
		log_err("\"mod_params\" cannot be NULL.\n");
		return -EINVAL;
	}

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	/* Check for unsupported modifications */
	if (ptable->params.type == DPA_CLS_TBL_INDEXED && mod_params->type !=
			DPA_CLS_TBL_MODIFY_ACTION) {
		RELEASE_OBJECT(ptable);
		log_err("Modify entry key is supported only on exact match and hash tables. You attempted to use it on table td=%d which is of type=%d.\n",
			td, ptable->params.type);
		return -ENOSYS;
	}

	entry_id = key_to_entry_id(ptable, key);
	if (entry_id < 0) {
		if ((entry_id == -ENODEV) &&
					(ptable->params.prefilled_entries)) {
			/*
			 * This entry may have been added to the Cc node before
			 * the DPA Classifier was created. Try to modify it by
			 * key directly using the FMan driver.
			 */
			memset(&key_params, 0, sizeof(key_params));
			switch (mod_params->type) {
			case DPA_CLS_TBL_MODIFY_ACTION:
				/* Parameter sanity check: */
				if (!mod_params->action) {
					RELEASE_OBJECT(ptable);
					log_err("\"mod_params->action\" cannot "
						"be NULL.\n");
					return -EINVAL;
				}

				ret = action_to_next_engine_params(
					mod_params->action,
					&key_params.ccNextEngineParams,
					NULL);
				if (ret < 0) {
					RELEASE_OBJECT(ptable);
					log_err("Failed verification of new "
						"action params while modifying "
						"entry by KEY in table td=%d.\n",
						td);
					dump_lookup_key(key);
					return ret;
				}

				memcpy(key_data, key->byte, key->size);
				if (key->mask) {
					memcpy(mask_data, key->mask, key->size);
					mask = mask_data;
				} else
					mask = NULL;

		if (ptable->params.type == DPA_CLS_TBL_EXACT_MATCH) {
			err = FM_PCD_MatchTableFindNModifyNextEngine(
				(t_Handle)ptable->int_cc_node[0].cc_node,
				key->size,
				key_data,
				mask,
				&key_params.ccNextEngineParams);
			if (err != E_OK) {
				RELEASE_OBJECT(ptable);
				log_err("FMan driver call failed - "
					"FM_PCD_MatchTableFindNModifyNextEngine"
					". td=%d, Cc node handle=0x%p.\n", td,
					ptable->int_cc_node[0].cc_node);
				dump_lookup_key(key);
				return -EBUSY;
			}
		} else { /* Table is HASH */
			err = FM_PCD_HashTableModifyNextEngine(
				(t_Handle)ptable->params.cc_node,
				key->size,
				key_data,
				&key_params.ccNextEngineParams);
			if (err != E_OK) {
				RELEASE_OBJECT(ptable);
				log_err("FMan driver call failed - "
					"FM_PCD_HashTableModifyNextEngine. "
					"td=%d, Cc node handle=0x%p.\n", td,
					ptable->params.cc_node);
				dump_lookup_key(key);
				return -EBUSY;
			}
		}

				break;
			case DPA_CLS_TBL_MODIFY_KEY_AND_ACTION:
				/*
				 * Only exact match tables support this type of
				 * modification.
				 */
				BUG_ON(ptable->params.type !=
						DPA_CLS_TBL_EXACT_MATCH);
				/* Parameter sanity check: */
				if (!mod_params->action) {
					log_err("\"mod_params->action\" cannot be NULL.\n");
					return -EINVAL;
				}

				ret = action_to_next_engine_params(
						mod_params->action,
						&key_params.ccNextEngineParams,
						NULL);
				if (ret < 0) {
					RELEASE_OBJECT(ptable);
					log_err("Failed verification of new action params while modifying entry by KEY in table td=%d.\n",
						td);
					dump_lookup_key(key);
					return ret;
				}

				/* Fall into DPA_CLS_TBL_MODIFY_KEY */
			case DPA_CLS_TBL_MODIFY_KEY:
				/*
				 * Only exact match tables support this type of
				 * modification.
				 */
				BUG_ON(ptable->params.type !=
						DPA_CLS_TBL_EXACT_MATCH);
				/* Parameter sanity check: */
				if (!mod_params->key) {
					log_err("\"mod_params->key\" cannot "
						"be NULL.\n");
					return -EINVAL;
				}

				memcpy(key_data, key->byte, key->size);
				if (key->mask) {
					memcpy(mask_data, key->mask, key->size);
					mask = mask_data;
				} else
					mask = NULL;

				memcpy(new_key_data, mod_params->key->byte,
					mod_params->key->size);
				if (mod_params->key->mask) {
					memcpy(new_mask_data,
						mod_params->key->mask,
						mod_params->key->size);
					new_mask = new_mask_data;
				} else
					new_mask = NULL;

		if (mod_params->type == DPA_CLS_TBL_MODIFY_KEY) {
			err = FM_PCD_MatchTableFindNModifyKey(
				(t_Handle)ptable->int_cc_node[0].cc_node,
				key->size,
				key_data,
				mask,
				new_key_data,
				new_mask);
			if (err != E_OK) {
				RELEASE_OBJECT(ptable);
				log_err("FMan driver call failed - "
					"FM_PCD_MatchTableFindNModifyKey. "
					"td=%d, Cc node handle=0x%p.\n",
					td, ptable->int_cc_node[0].cc_node);
				dump_lookup_key(key);
				return -EBUSY;
			}
		} else {
			key_params.p_Key	= new_key_data;
			key_params.p_Mask	= new_mask;
			err = FM_PCD_MatchTableFindNModifyKeyAndNextEngine(
				(t_Handle)ptable->int_cc_node[0].cc_node,
				key->size,
				key_data,
				mask,
				&key_params);
			if (err != E_OK) {
				RELEASE_OBJECT(ptable);
			log_err("FMan driver call failed - "
				"FM_PCD_MatchTableFindNModifyKeyAndNextEngine. "
				"td=%d, Cc node handle=0x%p.\n",
				td, ptable->int_cc_node[0].cc_node);
				dump_lookup_key(key);
				return -EBUSY;
			}
		}

				break;
			}

			RELEASE_OBJECT(ptable);
			return ret;
		} else {
			RELEASE_OBJECT(ptable);
			log_err("Unable to determine entry_id associated with "
				"this lookup key for table td=%d.\n", td);
			dump_lookup_key(key);
			return entry_id;
		}
	}

	ret = table_modify_entry_by_ref(ptable, entry_id, mod_params);
	RELEASE_OBJECT(ptable);
	if (ret < 0) {
		log_err("Failed to MODIFY entry by KEY in table td=%d. "
			"Translated entry ref=%d.\n", td, entry_id);
		dump_lookup_key(key);
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}
EXPORT_SYMBOL(dpa_classif_table_modify_entry_by_key);

void dump_lookup_key(const struct dpa_offload_lookup_key *key)
{
	int i, offset;
	char key_data[3 * FM_PCD_MAX_SIZE_OF_KEY + 10];
	char mask_data[3 * FM_PCD_MAX_SIZE_OF_KEY + 10];

	offset = 0;
	for (i = 0; i < key->size; i++) {
		sprintf(&key_data[offset], " %02x", key->byte[i]);
		offset += 3;
	}
	key_data[offset] = 0;
	offset = 0;
	if (key->mask) {
		for (i = 0; i < key->size; i++) {
			sprintf(&mask_data[offset], " %02x", key->mask[i]);
			offset += 3;
		}
		mask_data[offset] = 0;
	} else
		sprintf(mask_data, "n/a");
	pr_err("Lookup key (hex) (%d bytes): %s.\nMask (hex): %s.\n",
		key->size, key_data, mask_data);
}

int dpa_classif_table_modify_entry_by_ref(int			td,
		int						entry_id,
		const struct dpa_cls_tbl_entry_mod_params	*mod_params)
{
	int err;
	struct dpa_cls_table *ptable;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	/* Check for unsupported modifications */
	if ((mod_params->type != DPA_CLS_TBL_MODIFY_ACTION) &&
			(ptable->params.type == DPA_CLS_TBL_INDEXED)) {
		log_err("Modify entry key is supported only on exact match and hash tables. You attempted to use it on table td=%d which is of type=%d.\n",
				td, ptable->params.type);
		return -ENOSYS;
	}

	err = table_modify_entry_by_ref(ptable, entry_id, mod_params);
	RELEASE_OBJECT(ptable);
	if (err < 0)
		log_err("Failed to MODIFY entry by REF in table td=%d. Entry "
			"ref=%d.\n", td, entry_id);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}
EXPORT_SYMBOL(dpa_classif_table_modify_entry_by_ref);

static int hash_table_modify_entry(
		struct dpa_cls_table *ptable,
		int entry_id,
		const struct dpa_offload_lookup_key *key,
		struct dpa_cls_tbl_action *action)
{
	int hmd, errno;
	unsigned int cc_node_index;
	uint8_t entry_index;
	u64 hash_set_index;
	t_Error err;

	t_Handle cc_node;
	struct list_head *shadow_list_entry;
	t_FmPcdCcKeyParams key_params;

	struct dpa_cls_tbl_shadow_entry *shadow_entry;
	struct dpa_cls_tbl_action *local_action;
	struct list_head *list_current;
	struct dpa_cls_tbl_entry *index_entry;

	hash_set_index = crc64_ecma_seed();
	hash_set_index = crc64_ecma(key->byte,
			ptable->params.hash_params.key_size,
			hash_set_index);
	hash_set_index = (u64)(hash_set_index & ptable->hash_mask) >>
			(8 * (6 - ptable->params.hash_params.hash_offs) + 4);

	/*
	 * Check if there are entries still available in the
	 * selected set
	 */
	if (ptable->int_cc_node[hash_set_index].used >=
			ptable->int_cc_node[hash_set_index].table_size) {
		log_err("Hash set #%llu is full (%d entries). Unable to modify this entry.\n",
				hash_set_index,
				ptable->int_cc_node[hash_set_index].table_size);
		return -ENOSPC;
	}

	memset(&key_params, 0, sizeof(t_FmPcdCcKeyParams));

	cc_node_index = ptable->entry[entry_id].int_cc_node_index;
	entry_index = ptable->entry[entry_id].entry_index;

	cc_node = (t_Handle)ptable->int_cc_node[cc_node_index].cc_node;

	if (!action) {
		/* Save action to next engine params */
		if (ptable->shadow_table) {
			shadow_list_entry =
					ptable->entry[entry_id].shadow_entry;
			shadow_entry = list_entry(shadow_list_entry,
					struct dpa_cls_tbl_shadow_entry,
					list_node);
			local_action	= &shadow_entry->action;
			dpa_classif_hm_release_chain(
					ptable->entry[entry_id].hmd);
			errno = action_to_next_engine_params(
				local_action,
				&key_params.ccNextEngineParams,
				&hmd);
			if (errno < 0)
				return errno;
		} else {
			err = FM_PCD_MatchTableGetNextEngine(
					cc_node,
					entry_index,
					&key_params.ccNextEngineParams);
			if (err)
				return -err;
		}
	} else {
		/*
		 * Release old header manip chain if available and save
		 * the action
		 */
		dpa_classif_hm_release_chain(
				ptable->entry[entry_id].hmd);
		errno = action_to_next_engine_params(
				action,
				&key_params.ccNextEngineParams,
				&hmd);
		if (errno < 0)
			return errno;
	}

	if (hash_set_index != ptable->entry[entry_id].int_cc_node_index) {
		BUG_ON(hash_set_index >= ptable->int_cc_nodes_count);
		key_params.p_Key = key->byte;

		/* Remove the key */
		err = FM_PCD_MatchTableRemoveKey(cc_node, entry_index);
		if (err != E_OK) {
			log_err("FMan driver call failed - FM_PCD_MatchTableRemoveKey. Entry ref=%d, Cc node handle=0x%p, entry index=%d.\n",
					entry_id, cc_node, entry_index);
			return -EBUSY;
		}
	ptable->int_cc_node[ptable->entry[entry_id].int_cc_node_index].used--;

		/* Update position in used entries list */
		list_del(&ptable->entry[entry_id].list_node);
		/* Calculate the new position in the index management list where
		 * this entry should go */
		if ((list_empty(&ptable->entry_list)) ||
			(hash_set_index >= ptable->int_cc_nodes_count - 1))
			/* Just add to the tail of the list. */
			list_current = &ptable->entry_list;
		else {
			/* Sort the index management list based on
			 * [cc_node_index] and [entry_index]. In other words,
			 * add the current entry before the first entry of the
			 * next cc node */
			list_for_each(list_current, &ptable->entry_list) {
				index_entry = list_entry(list_current,
						struct dpa_cls_tbl_entry,
						list_node);
				if (index_entry->int_cc_node_index >
								hash_set_index)
					break;
			}
		}

		/* Insert the new key */
		ptable->entry[entry_id].int_cc_node_index =
				(unsigned int)hash_set_index;
		ptable->entry[entry_id].entry_index =
			(uint8_t)ptable->int_cc_node[hash_set_index].used;

		/* Add the key to the selected Cc node */
		err = FM_PCD_MatchTableAddKey((t_Handle)ptable->
				int_cc_node[hash_set_index].cc_node,
				ptable->entry[entry_id].entry_index,
				ptable->params.hash_params.key_size,
				&key_params);
		if (err != E_OK) {
			log_err("FMan driver call failed - FM_PCD_MatchTableAddKey. Entry ref=%d, HASH set=%llu, Cc node handle=0x%p, entry index=%d.\n",
				entry_id, hash_set_index,
				ptable->int_cc_node[hash_set_index].cc_node,
				ptable->entry[entry_id].entry_index);
			return -EBUSY;
		}

		/* Add the index entry back to the index management list */
		list_add_tail(&ptable->entry[entry_id].list_node, list_current);

		ptable->int_cc_node[hash_set_index].used++;
	} else {
		if (!action) {
			err = FM_PCD_MatchTableModifyKey((t_Handle)ptable->
					int_cc_node[hash_set_index].cc_node,
					ptable->entry[entry_id].entry_index,
					ptable->params.hash_params.key_size,
					key->mask, key->mask);
			if (err != E_OK) {
				log_err("FMan driver call failed - FM_PCD_MatchTableModifyKey. Entry ref=%d, HASH set=%llu, Cc node handle=0x%p, entry index=%d.\n",
				entry_id, hash_set_index,
				ptable->int_cc_node[hash_set_index].cc_node,
				ptable->entry[entry_id].entry_index);
				return -EBUSY;
			}
		} else {
			err = FM_PCD_MatchTableModifyKeyAndNextEngine(
			(t_Handle)ptable->int_cc_node[hash_set_index].cc_node,
			ptable->entry[entry_id].entry_index,
			ptable->params.hash_params.key_size,
			&key_params);
			if (err != E_OK) {
				log_err("FMan driver call failed - FM_PCD_MatchTableModifyKeyAndNextEngine. Entry ref=%d, HASH set=%llu, Cc node handle=0x%p, entry index=%d.\n",
				entry_id, hash_set_index,
				ptable->int_cc_node[hash_set_index].cc_node,
				ptable->entry[entry_id].entry_index);
				return -EBUSY;
			}
		}
	}
	return E_OK;
}

static int hash_table_check_key(struct dpa_cls_table *ptable,
		const struct dpa_offload_lookup_key *key)
{
	int i = 0;
	if (key->size !=
			ptable->params.hash_params.key_size) {
		log_err("New key size (%d bytes) doesn't match the table key size (%d bytes).\n",
				key->size,
				ptable->params.hash_params.key_size);
		return -EINVAL;
	}
	if (key->mask) {
		/* Only full 0xFF masks supported: */
		for (i = 0; i < key->size; i++)
			if (key->mask[i] ^ 0xff) {
				log_err("Only key masks 0xff all over are supported by HASH tables.\n");
				return -EINVAL;
			}
	}
	return E_OK;
}

static int table_modify_entry_by_ref(struct dpa_cls_table	*ptable,
		int						entry_id,
		const struct dpa_cls_tbl_entry_mod_params	*mod_params)
{
	struct dpa_cls_tbl_shadow_entry *shadow_entry = NULL;
	struct dpa_cls_tbl_shadow_entry_indexed *shadow_entry_indexed;
	struct dpa_cls_tbl_action *action;
	struct dpa_offload_lookup_key *key;
	t_FmPcdCcNextEngineParams next_engine_params;
	t_FmPcdCcKeyParams key_params;
	uint8_t key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t masked_key[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t entry_index, shadow_table_index;
	unsigned int cc_node_index, key_size;
	int errno;
	t_Error err;
	t_Handle cc_node;
	struct list_head *shadow_list_entry, *new_bucket_list;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!ptable);

	/* Parameters sanity checks: */
	if ((entry_id < 0) || (entry_id >= ptable->entries_cnt)) {
		log_err("Invalid \"entry_id\" (%d). Should be between %d and "
			"%d for this table.\n", entry_id, 0,
			ptable->entries_cnt-1);
		return -EINVAL;
	}
	if (!(ptable->entry[entry_id].flags & DPA_CLS_TBL_ENTRY_VALID)) {
		log_err("Invalid \"entry_id\" (%d).\n", entry_id);
		return -EINVAL;
	}
	if (!mod_params) {
		log_err("\"mod_params\" cannot be NULL.\n");
		return -EINVAL;
	}

	if (ptable->params.type == DPA_CLS_TBL_INDEXED) {
		cc_node_index	= 0;
		entry_index	= (uint8_t) entry_id;
	} else {
		cc_node_index	= ptable->entry[entry_id].int_cc_node_index;
		entry_index	= ptable->entry[entry_id].entry_index;
	}

	cc_node	= (t_Handle)ptable->int_cc_node[cc_node_index].cc_node;

	if (mod_params->type == DPA_CLS_TBL_MODIFY_ACTION) {
		/* Parameter sanity check: */
		if (!mod_params->action) {
			log_err("\"mod_params->action\" cannot be NULL.\n");
			return -EINVAL;
		}

		/* Release old header manip chain if available */
		dpa_classif_hm_release_chain(ptable->entry[entry_id].hmd);
		errno = action_to_next_engine_params(mod_params->action,
				&next_engine_params,
				&ptable->entry[entry_id].hmd);
		if (errno < 0)
			return errno;

		err = FM_PCD_MatchTableModifyNextEngine(cc_node,
						entry_index,
						&next_engine_params);
		if (err != E_OK) {
			log_err("FMan driver call failed - FM_PCD_MatchTableModifyNextEngine. Entry ref=%d, Cc node handle=0x%p, entry index=%d.\n",
					entry_id, cc_node, entry_index);
			return -EBUSY;
		}
	} else {
		/*
		 * Only exact match and hash tables support this type of
		 * modification.
		 */
		BUG_ON(ptable->params.type == DPA_CLS_TBL_INDEXED);

		/* Parameters sanity checks: */
		if (!mod_params->key) {
			log_err("\"mod_params->key\" cannot be NULL.\n");
			return -EINVAL;
		}

		/*
		 * Have to copy the data from the key and mask because
		 * the FMD is not using const pointers and we cannot
		 * provide it the const pointers that the user provided.
		 */
		memset(&key_params, 0, sizeof(key_params));
		memcpy(key_data, mod_params->key->byte, mod_params->key->size);
		key_params.p_Key = key_data;

		switch (mod_params->type) {
		case DPA_CLS_TBL_MODIFY_ACTION:
			break;
		case DPA_CLS_TBL_MODIFY_KEY:
			switch (ptable->params.type) {
			case DPA_CLS_TBL_EXACT_MATCH:
				key_size =
				ptable->params.exact_match_params.key_size;
				if (mod_params->key->size != key_size) {
					log_err("New key size (%d bytes) doesn't match the table key size (%d bytes).\n",
							mod_params->key->size,
							key_size);
					return -EINVAL;
				}
				if (mod_params->key->mask) {
					memcpy(mask_data, mod_params->key->mask,
							mod_params->key->size);
					key_params.p_Mask = mask_data;
				}
				err = FM_PCD_MatchTableModifyKey(cc_node,
							entry_index,
							key_size,
							key_params.p_Key,
							key_params.p_Mask);
				if (err != E_OK) {
					log_err("FMan driver call failed - FM_PCD_MatchTableModifyKey. Entry ref=%d, Cc node handle=0x%p, entry index=%d.\n",
						entry_id, cc_node, entry_index);
					return -EBUSY;
				}
				break;
			case DPA_CLS_TBL_HASH:
				/* Check the key parameter */
				err = hash_table_check_key(ptable,
							mod_params->key);
				if (err)
					return err;
				err = hash_table_modify_entry(ptable,
							entry_id,
							mod_params->key,
							NULL);
				if (err)
					return err;
				break;
			case DPA_CLS_TBL_INDEXED:
				break;
			}

			break;
		case DPA_CLS_TBL_MODIFY_KEY_AND_ACTION:
				/* Parameter sanity checks */
				if (!mod_params->action) {
					log_err("\"mod_params->action\" cannot be NULL.\n");
					return -EINVAL;
				}

				switch (ptable->params.type) {
				case DPA_CLS_TBL_EXACT_MATCH:
					key_size =
				ptable->params.exact_match_params.key_size;
					if (mod_params->key->size != key_size) {
						log_err("New key size (%d bytes) doesn't match the table key size (%d bytes).\n",
							mod_params->key->size,
							key_size);
						return -EINVAL;
					}
					/*
					 * Have to copy the data from the key
					 * and mask because the FMD is not
					 * using const pointers and we cannot
					 * provide it the const pointers that
					 * the user provided.
					 */
					if (mod_params->key->mask) {
						memcpy(mask_data,
							mod_params->key->mask,
							mod_params->key->size);
						key_params.p_Mask = mask_data;
					}
					/*
					 * Release old header manip chain
					 * if available
					 */
					dpa_classif_hm_release_chain(
						ptable->entry[entry_id].hmd);
					errno = action_to_next_engine_params(
						mod_params->action,
						&key_params.ccNextEngineParams,
						&ptable->entry[entry_id].hmd);
					if (errno < 0)
						return errno;
					err =
					FM_PCD_MatchTableModifyKeyAndNextEngine(
								cc_node,
								entry_index,
								key_size,
								&key_params);
					if (err != E_OK) {
						log_err("FMan driver call failed - FM_PCD_MatchTableModifyKeyAndNextEngine. Entry ref=%d, Cc node handle=0x%p, entry index=%d.\n",
								entry_id,
								cc_node,
								entry_index);
						return -EBUSY;
					}
					break;
				case DPA_CLS_TBL_HASH:
					/* Check the key parameter */
					err = hash_table_check_key(ptable,
							mod_params->key);
					if (err)
						return err;
					err = hash_table_modify_entry(
							ptable,
							entry_id,
							mod_params->key,
							mod_params->action);
					if (err)
						return err;
					break;
				case DPA_CLS_TBL_INDEXED:
					break;
				}
				break;
		}
	}

	/* If a shadow table exists, update the data in the shadow table */
	if (ptable->shadow_table) {
		if (ptable->params.type == DPA_CLS_TBL_INDEXED) {
			shadow_list_entry =
					ptable->shadow_table->
					shadow_entry[entry_index].next;
			shadow_entry_indexed = list_entry(shadow_list_entry,
					struct dpa_cls_tbl_shadow_entry_indexed,
					list_node);

			action	= &shadow_entry_indexed->action;
		} else {
			shadow_list_entry =
					ptable->entry[entry_id].shadow_entry;
			shadow_entry = list_entry(shadow_list_entry,
					struct dpa_cls_tbl_shadow_entry,
					list_node);

			key	= &shadow_entry->key;
			action	= &shadow_entry->action;

			if (mod_params->type == DPA_CLS_TBL_MODIFY_KEY ||
			mod_params->type == DPA_CLS_TBL_MODIFY_KEY_AND_ACTION) {
				/*
				 * The entry needs to be re-hashed with the new
				 * key
				 */
				key_size =
				ptable->params.exact_match_params.key_size;
				key_apply_mask(mod_params->key,
						masked_key);
				shadow_table_index = crc8(crc8_table,
						masked_key,
						key_size,
						0);

				new_bucket_list =
			&ptable->shadow_table->shadow_entry[shadow_table_index];
				list_del(&shadow_entry->list_node);
				list_add(&shadow_entry->list_node,
							new_bucket_list);
			}

			if (mod_params->type == DPA_CLS_TBL_MODIFY_KEY ||
			mod_params->type == DPA_CLS_TBL_MODIFY_KEY_AND_ACTION) {
				memcpy(key->byte, mod_params->key->byte,
								key->size);
				if ((key->mask) && (mod_params->key->mask))
					memcpy(key->mask, mod_params->key->mask,
								key->size);
			}
		}

		if (mod_params->type == DPA_CLS_TBL_MODIFY_ACTION ||
			mod_params->type == DPA_CLS_TBL_MODIFY_KEY_AND_ACTION)
			memcpy(action, mod_params->action,
					sizeof(struct dpa_cls_tbl_action));
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_delete_entry_by_key(int				td,
				const struct dpa_offload_lookup_key	*key)
{
	int entry_id;
	int err = 0;
	t_Error error;
	struct dpa_cls_table *ptable;
	uint8_t key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t *mask;
	struct list_head *list_current;
	struct dpa_cls_tbl_entry *index_entry;

#ifdef DPA_CLASSIFIER_DEBUG
	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) --> Delete entry from table td=%d.\n",
		__func__, __LINE__, td));
	dump_lookup_key(key);
#endif /* DPA_CLASSIFIER_DEBUG */

	/* Parameters sanity checks: */
	if (!key) {
		log_err("\"key\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!key->byte) {
		log_err("\"key->byte\" cannot be NULL.\n");
		return -EINVAL;
	}
	if ((key->size <= 0) || (key->size > DPA_OFFLD_MAXENTRYKEYSIZE)) {
		log_err("Key size should be between %d and %d.\n", 1,
			DPA_OFFLD_MAXENTRYKEYSIZE);
		return -EINVAL;
	}

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	entry_id = key_to_entry_id((struct dpa_cls_table *)
			ptable, key);
	if (entry_id < 0) {
		if ((entry_id == -ENODEV) &&
				(ptable->params.prefilled_entries)) {
			/*
			 * This entry may have been added to the Cc node before
			 * the DPA Classifier was created. Try to delete it by
			 * key directly using the FMan driver.
			 */

			memcpy(key_data, key->byte, key->size);
			if (key->mask) {
				memcpy(mask_data, key->mask, key->size);
				mask = mask_data;
			} else
				mask = NULL;

			switch (ptable->params.type) {
			case DPA_CLS_TBL_EXACT_MATCH:

			error = FM_PCD_MatchTableFindNRemoveKey(
				(t_Handle)ptable->int_cc_node[0].cc_node,
				key->size,
				key_data,
				mask);
			if (error != E_OK) {
				RELEASE_OBJECT(ptable);
				log_err("FMan driver call failed - "
					"FM_PCD_MatchTableFindNRemoveKey. "
					"td=%d, Cc node handle=0x%p.\n", td,
					ptable->int_cc_node[0].cc_node);
				dump_lookup_key(key);
				return -EBUSY;
			}

			/* Update the index management for all entries. */
			list_current = ptable->entry_list.next;
			while (list_current != &ptable->entry_list) {
				index_entry = list_entry(list_current,
						struct dpa_cls_tbl_entry,
						list_node);
				index_entry->entry_index--;
				list_current = list_current->next;
			}

				break;
			case DPA_CLS_TBL_HASH:

				error = FM_PCD_HashTableRemoveKey(
					(t_Handle)ptable->params.cc_node,
					key->size,
					key_data);
				if (error != E_OK) {
					RELEASE_OBJECT(ptable);
					log_err("FMan driver call failed - "
						"FM_PCD_HashTableRemoveKey. "
						"td=%d, Cc node handle=0x%p.\n",
						td, ptable->params.cc_node);
					dump_lookup_key(key);
					return -EBUSY;
				}

				/* No entry management at all. */

				break;
			default:
				BUG_ON(1);
				break;
			}

			RELEASE_OBJECT(ptable);
			return err;
		} else {
			RELEASE_OBJECT(ptable);
			log_err("Unable to determine entry_id.\n");
			dump_lookup_key(key);
			return entry_id;
		}
	}

	err = table_delete_entry_by_ref(ptable, entry_id);
	RELEASE_OBJECT(ptable);
	if (err < 0) {
		log_err("Failed to DELETE entry by KEY in table td=%d. "
			"Translated entry ref=%d.\n", td, entry_id);
		dump_lookup_key(key);
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}
EXPORT_SYMBOL(dpa_classif_table_delete_entry_by_key);

int dpa_classif_table_delete_entry_by_ref(int td, int entry_id)
{
	int err;
	struct dpa_cls_table *ptable;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) --> Delete entry ref=%d from table td=%d.\n",
		__func__, __LINE__, entry_id, td));

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	err = table_delete_entry_by_ref(ptable, entry_id);
	RELEASE_OBJECT(ptable);
	if (err < 0)
		log_err("Failed to DELETE entry by REF in table td=%d. Entry "
			"ref=%d.\n", td, entry_id);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}
EXPORT_SYMBOL(dpa_classif_table_delete_entry_by_ref);

static int table_delete_entry_by_ref(struct dpa_cls_table *ptable, int entry_id)
{
	t_Error err;
	struct dpa_cls_tbl_shadow_entry *shadow_entry;
	uint8_t entry_index;
	unsigned int cc_node_index;
	t_Handle cc_node;
	struct list_head *shadow_list_entry, *list_current;
	struct dpa_cls_tbl_cc_node_info *int_cc_node;
	struct dpa_cls_tbl_entry *index_entry;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!ptable);

	/* Parameters sanity checks: */
	if ((entry_id < 0) || (entry_id >= ptable->entries_cnt)) {
		log_err("Invalid \"entry_id\" (%d). Should be between %d and "
			"%d for this table.\n", entry_id, 0,
			ptable->entries_cnt-1);
		return -EINVAL;
	}
	if (!(ptable->entry[entry_id].flags & DPA_CLS_TBL_ENTRY_VALID)) {
		log_err("Invalid \"entry_id\" (%d).\n", entry_id);
		return -EINVAL;
	}

	cc_node_index	= ptable->entry[entry_id].int_cc_node_index;
	entry_index	= ptable->entry[entry_id].entry_index;

	cc_node	= (t_Handle)ptable->int_cc_node[cc_node_index].cc_node;
	int_cc_node = &ptable->int_cc_node[cc_node_index];
	if (ptable->params.type == DPA_CLS_TBL_INDEXED) {
		log_err("Delete entry is not allowed on an indexed table.\n");
		return -EINVAL;
	} else {
		/* For all the other tables types we can remove the key */
		err = FM_PCD_MatchTableRemoveKey(cc_node,
					entry_index);
		if (err != E_OK) {
			log_err("FMan driver call failed - "
				"FM_PCD_MatchTableRemoveKey. Entry ref=%d, Cc "
				"node handle=0x%p, entry index=%d.\n",
				entry_id, cc_node, entry_index);
			return -EBUSY;
		}

		/*
		 * Update the index management for the Cc node that this entry
		 * was removed from.
		 */
		list_current = ptable->entry[entry_id].list_node.next;
		while (list_current != &ptable->entry_list) {
			index_entry = list_entry(list_current,
					struct dpa_cls_tbl_entry,
					list_node);
			if (index_entry->int_cc_node_index >
					cc_node_index)
				break;
			index_entry->entry_index--;
			list_current = list_current->next;
		}

		list_del(&ptable->entry[entry_id].list_node);
	}

	ptable->entry[entry_id].flags &= (~DPA_CLS_TBL_ENTRY_VALID);
	dpa_classif_hm_release_chain(ptable->entry[entry_id].hmd);

	int_cc_node->used--;

	if (ptable->shadow_table) {
		shadow_list_entry = ptable->entry[entry_id].shadow_entry;
		shadow_entry = list_entry(shadow_list_entry,
						struct dpa_cls_tbl_shadow_entry,
						list_node);

		list_del(&shadow_entry->list_node);

		kfree(shadow_entry->key.byte);
		kfree(shadow_entry->key.mask);
		kfree(shadow_entry);
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_lookup_by_key(int				td,
			const struct dpa_offload_lookup_key	*key,
			struct dpa_cls_tbl_action		*action)
{
	struct list_head *pos;
	struct dpa_cls_tbl_shadow_entry *shadow_entry;
	struct dpa_cls_tbl_shadow_entry_indexed *shadow_entry_indexed;
	struct dpa_cls_table *ptable;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!key) {
		log_err("\"key\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!key->byte) {
		log_err("\"key->byte\" cannot be NULL.\n");
		return -EINVAL;
	}
	if ((key->size <= 0) || (key->size > DPA_OFFLD_MAXENTRYKEYSIZE)) {
		log_err("Key size should be between %d and %d.\n", 1,
			DPA_OFFLD_MAXENTRYKEYSIZE);
		return -EINVAL;
	}
	if (!action) {
		log_err("\"action\" cannot be NULL.\n");
		return -EINVAL;
	}

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	if (!ptable->shadow_table) {
		RELEASE_OBJECT(ptable);
		log_err("Cannot lookup by key in a DPA_CLS_TBL_MANAGE_BY_REF "
			"table (td=%d).\n", td);
		return -ENOSYS;
	}

	pos = find_shadow_entry(ptable, key);
	if (!pos) {
		RELEASE_OBJECT(ptable);
		return -ENODEV;
	}

	if (ptable->params.type == DPA_CLS_TBL_INDEXED) {
		shadow_entry_indexed = list_entry(pos,
					struct dpa_cls_tbl_shadow_entry_indexed,
					list_node);
		memcpy(action, &shadow_entry_indexed->action,
			sizeof(struct dpa_cls_tbl_action));
	} else {
		shadow_entry = list_entry(pos,
					struct dpa_cls_tbl_shadow_entry,
					list_node);
		memcpy(action, &shadow_entry->action,
			sizeof(struct dpa_cls_tbl_action));
	}

	RELEASE_OBJECT(ptable);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}
EXPORT_SYMBOL(dpa_classif_table_lookup_by_key);

int dpa_classif_table_lookup_by_ref(int				td,
				int				entry_id,
				struct dpa_cls_tbl_action	*action)
{
	struct dpa_cls_table *ptable;
	struct dpa_cls_tbl_shadow_entry *shadow_entry;
	struct dpa_cls_tbl_shadow_entry_indexed *shadow_entry_indexed;
	struct list_head *shadow_list_entry;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!action) {
		log_err("\"action\" cannot be NULL.\n");
		return -EINVAL;
	}

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	/* Parameters sanity checks: */
	if ((entry_id < 0) || (entry_id >= ptable->entries_cnt)) {
		RELEASE_OBJECT(ptable);
		log_err("Invalid \"entry_id\" (%d). Should be between %d and "
			"%d for this table.\n", entry_id, 0,
			ptable->entries_cnt-1);
		return -EINVAL;
	}
	if (!(ptable->entry[entry_id].flags & DPA_CLS_TBL_ENTRY_VALID)) {
		RELEASE_OBJECT(ptable);
		log_err("Invalid \"entry_id\" (%d).\n", entry_id);
		return -EINVAL;
	}

	if (!ptable->shadow_table) {
		RELEASE_OBJECT(ptable);
		log_err("Cannot lookup in a DPA_CLS_TBL_MANAGE_BY_REF table "
			"(td=%d).\n", td);
		return -ENOSYS;
	}

	if (ptable->params.type == DPA_CLS_TBL_INDEXED) {
		shadow_list_entry = ptable->shadow_table->
					shadow_entry[entry_id].next;
		shadow_entry_indexed = list_entry(shadow_list_entry,
					struct dpa_cls_tbl_shadow_entry_indexed,
					list_node);

		memcpy(action, &shadow_entry_indexed->action,
			sizeof(struct dpa_cls_tbl_action));
	} else {
		shadow_list_entry = ptable->entry[entry_id].shadow_entry;
		shadow_entry = list_entry(shadow_list_entry,
					struct dpa_cls_tbl_shadow_entry,
					list_node);

		memcpy(action, &shadow_entry->action,
			sizeof(struct dpa_cls_tbl_action));
	}

	RELEASE_OBJECT(ptable);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}
EXPORT_SYMBOL(dpa_classif_table_lookup_by_ref);

int dpa_classif_table_flush(int td)
{
	int err;
	struct dpa_cls_table *ptable;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	err = flush_table(ptable);
	RELEASE_OBJECT(ptable);
	if (err < 0)
		log_err("Failed to flush table td=%d. Table type=%d.\n", td,
			ptable->params.type);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}
EXPORT_SYMBOL(dpa_classif_table_flush);

static int flush_table(struct dpa_cls_table *ptable)
{
	struct dpa_cls_tbl_shadow_entry *shadow_entry;
	unsigned int cc_node_index, i;
	t_Error err;
	t_Handle cc_node;
	struct list_head *list_current, *tmp;
	struct dpa_cls_tbl_cc_node_info *int_cc_node;
	struct dpa_cls_tbl_entry *index_entry;
	t_FmPcdCcNextEngineParams next_engine_params;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	if ((ptable->params.type == DPA_CLS_TBL_HASH) &&
			(ptable->params.prefilled_entries))
		/* Flush not available for pre-filled HASH tables */
		return 0;

	if (list_empty(&ptable->entry_list))
		/* Table is already empty. Nothing to do */
		return 0;

	if (ptable->params.type == DPA_CLS_TBL_INDEXED) {
		cc_node = ptable->params.cc_node;

		/* Replace all indexed entries with DROP */
		memset(&next_engine_params, 0, sizeof(next_engine_params));
		next_engine_params.nextEngine = e_FM_PCD_DONE;
		next_engine_params.params.enqueueParams.action =
						e_FM_PCD_DROP_FRAME;

		for (i = 0; i < ptable->params.indexed_params.entries_cnt;
									i++) {
			err = FM_PCD_MatchTableModifyNextEngine(cc_node,
							(uint16_t)i,
							&next_engine_params);
			if (err != E_OK) {
				log_err("FMan driver call failed - "
					"FM_PCD_MatchTableModifyNextEngine. "
					"Cc node handle=0x%p, entry index=%d.\n",
					cc_node, i);
				return -EBUSY;
			}

			dpa_classif_hm_release_chain(ptable->entry[i].hmd);
			ptable->entry[i].hmd = DPA_OFFLD_DESC_NONE;
		}
	} else {
		/* Flush the table from tail to head to avoid having to update
		 * the remaining entry indexes all the time */
		list_current = ptable->entry_list.prev;
		while (list_current != &ptable->entry_list) {
			index_entry = list_entry(list_current,
						struct dpa_cls_tbl_entry,
						list_node);
			if (index_entry->shadow_entry) {
				/* Clean up shadow entry as well */
				shadow_entry =
					list_entry(index_entry->shadow_entry,
				struct dpa_cls_tbl_shadow_entry,
				list_node);

				list_del(&shadow_entry->list_node);

				kfree(shadow_entry->key.byte);
				kfree(shadow_entry->key.mask);
				kfree(shadow_entry);
			}

			cc_node_index = index_entry->int_cc_node_index;
			cc_node = (t_Handle)ptable->int_cc_node[cc_node_index].
								cc_node;
			int_cc_node = &ptable->int_cc_node[cc_node_index];

			dpa_classif_hm_release_chain(index_entry->hmd);
#ifdef DPA_CLASSIFIER_DEBUG
			dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d): Remove "
				"entry #%d from table cc_node=0x%p.\n",
				__func__, __LINE__, index_entry->entry_index,
				cc_node));
#endif /* DPA_CLASSIFIER_DEBUG */
			err = FM_PCD_MatchTableRemoveKey(cc_node,
						index_entry->entry_index);
			if (err != E_OK) {
				log_err("FMan driver call failed - "
					"FM_PCD_MatchTableRemoveKey. Cc node "
					"handle=0x%p, entry index=%d.\n",
					cc_node, index_entry->entry_index);
				return -EBUSY;
			}

			int_cc_node->used--;
			index_entry->flags &= (~DPA_CLS_TBL_ENTRY_VALID);
			tmp		= list_current;
			list_current	= list_current->prev;
			list_del(tmp);
		}
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_get_entry_stats_by_key(int			td,
				const struct dpa_offload_lookup_key	*key,
				struct dpa_cls_tbl_entry_stats		*stats)
{
	int entry_id;
	int err;
	struct dpa_cls_table *ptable;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!key) {
		log_err("\"key\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!key->byte) {
		log_err("\"key->byte\" cannot be NULL.\n");
		return -EINVAL;
	}
	if ((key->size <= 0) || (key->size > DPA_OFFLD_MAXENTRYKEYSIZE)) {
		log_err("Key size should be between %d and %d.\n", 1,
			DPA_OFFLD_MAXENTRYKEYSIZE);
		return -EINVAL;
	}
	if (!stats) {
		log_err("\"stats\" cannot be NULL.\n");
		return -EINVAL;
	}

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	if ((ptable->params.type == DPA_CLS_TBL_HASH) &&
			(ptable->params.prefilled_entries)) {
		RELEASE_OBJECT(ptable);
		/* get_entry_stats not supported on prefilled HASH tables */
		log_err("get_entry_stats_by_key is not supported on prefilled "
			"HASH tables (td=%d).\n", td);
		return -ENOSYS;
	}
	entry_id = key_to_entry_id(ptable, key);
	if (entry_id < 0) {
		RELEASE_OBJECT(ptable);
		log_err("Unable to determine entry_id.\n");
		dump_lookup_key(key);
		return entry_id;
	}

	err = table_get_entry_stats_by_ref(ptable, entry_id, stats);
	RELEASE_OBJECT(ptable);
	if (err < 0) {
		log_err("Failed to get entry STATS by KEY in table td=%d. "
			"Translated entry ref=%d.\n", td, entry_id);
		dump_lookup_key(key);
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}
EXPORT_SYMBOL(dpa_classif_table_get_entry_stats_by_key);

int dpa_classif_table_get_entry_stats_by_ref(int		td,
				int				entry_id,
				struct dpa_cls_tbl_entry_stats	*stats)
{
	struct dpa_cls_table *ptable;
	int err;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	err = table_get_entry_stats_by_ref(ptable, entry_id, stats);
	RELEASE_OBJECT(ptable);
	if (err < 0)
		log_err("Failed to get entry STATS by REF in table td=%d. "
			"Entry ref=%d.\n", td, entry_id);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}
EXPORT_SYMBOL(dpa_classif_table_get_entry_stats_by_ref);

static int table_get_entry_stats_by_ref(struct dpa_cls_table	*ptable,
				int				entry_id,
				struct dpa_cls_tbl_entry_stats	*stats)
{
	unsigned int cc_node_index;
	uint8_t entry_index;
	t_Handle cc_node;
	struct dpa_cls_tbl_entry *index_entry;
	t_FmPcdCcKeyStatistics key_stats;
	t_Error err;
	int ret = 0;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!ptable);

	/* Parameters sanity checks: */
	if ((entry_id < 0) || (entry_id >= ptable->entries_cnt)) {
		log_err("Invalid \"entry_id\" (%d). Should be between %d and "
			"%d for this table.\n", entry_id, 0,
			ptable->entries_cnt-1);
		return -EINVAL;
	}
	if (!(ptable->entry[entry_id].flags & DPA_CLS_TBL_ENTRY_VALID)) {
		log_err("Invalid \"entry_id\" (%d).\n", entry_id);
		return -EINVAL;
	}
	if (!stats) {
		log_err("\"stats\" cannot be NULL.\n");
		return -EINVAL;
	}

	cc_node_index	= ptable->entry[entry_id].int_cc_node_index;
	index_entry	= &ptable->entry[entry_id];
	entry_index	= index_entry->entry_index;

	cc_node = (t_Handle)ptable->int_cc_node[cc_node_index].cc_node;
	err = FM_PCD_MatchTableGetKeyStatistics(cc_node, entry_index,
								&key_stats);
	if (err != E_OK) {
		log_warn("FMan driver call failed - FM_PCD_MatchTableGetKeyStatistics. Failed to acquire key statistics.\n");
		memset(stats, 0, sizeof(*stats));
		ret = -EPERM;
	} else {
		stats->pkts	= key_stats.frameCount;
		stats->bytes	= key_stats.byteCount;
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}

int dpa_classif_table_get_miss_stats(int			td,
				struct dpa_cls_tbl_entry_stats	*stats)
{
	struct dpa_cls_table *ptable;
	t_FmPcdCcKeyStatistics key_stats;
	t_Error err;
	int i, ret = 0;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n",
			__func__, __LINE__));

	/* Parameters sanity check. */
	if (!stats) {
		log_err("\"stats\" cannot be NULL.\n");
		return -EINVAL;
	}

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);
	memset(stats, 0, sizeof(*stats));
	for (i = 0; i < ptable->int_cc_nodes_count; i++) {
		memset(&key_stats, 0, sizeof(key_stats));
		err = FM_PCD_MatchTableGetMissStatistics(
				(t_Handle)ptable->int_cc_node[i].cc_node,
				&key_stats);
		if (err != E_OK) {
			log_warn("FMan driver call failed - FM_PCD_MatchTableGetMissStatistics. Failed to acquire key statistics.\n");
			memset(stats, 0, sizeof(*stats));
			ret = -EPERM;
			break;
		}
		stats->pkts += key_stats.frameCount;
		stats->bytes += key_stats.byteCount;
	}
	RELEASE_OBJECT(ptable);

	if (ret < 0)
		log_err("Failed to get miss stats in table td=%d.\n", td);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n",
			__func__, __LINE__));

	return ret;
}
EXPORT_SYMBOL(dpa_classif_table_get_miss_stats);

int dpa_classif_table_get_params(int td, struct dpa_cls_tbl_params *params)
{
	struct dpa_cls_table *ptable;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!params) {
		log_err("\"params\" cannot be NULL.\n");
		return -EINVAL;
	}

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);

	memcpy(params, &ptable->params, sizeof(struct dpa_cls_tbl_params));

	RELEASE_OBJECT(ptable);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}
EXPORT_SYMBOL(dpa_classif_table_get_params);

static int alloc_table_management(struct dpa_cls_table *cls_table)
{
	int err = 0;

	BUG_ON(!cls_table);

	/* Allocate the necessary table management tools */
	if (!cls_table->int_cc_nodes_count)
		return 0;

	cls_table->int_cc_node =
		kzalloc(cls_table->int_cc_nodes_count *
			sizeof(*cls_table->int_cc_node), GFP_KERNEL);
	if (!cls_table->int_cc_node) {
		log_err("No more memory for DPA Classifier table "
			"management.\n");
		err = -ENOMEM;
		goto alloc_table_mgmt_error;
	}

	return err;

alloc_table_mgmt_error:
	free_table_management(cls_table);

	return err;
}

static void free_table_management(struct dpa_cls_table *cls_table)
{
	BUG_ON(!cls_table);

	kfree(cls_table->int_cc_node);

	cls_table->int_cc_nodes_count = 0;
}

static int table_init_indexed(struct dpa_cls_table *cls_table)
{
	t_Error err;
	int errno;
	uint8_t i;
	t_FmPcdCcNextEngineParams next_engine_params;
	t_Handle cc_node;
	struct dpa_cls_tbl_shadow_entry_indexed *shadow_entry;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!cls_table);
	BUG_ON(cls_table->params.type != DPA_CLS_TBL_INDEXED);
	BUG_ON(cls_table->int_cc_nodes_count != 1);

	errno = alloc_table_management(cls_table);
	if (errno < 0)
		return errno;

	/* The only managed Cc node is the one provided by the application */
	cls_table->int_cc_node[0].cc_node = cls_table->params.cc_node;
	cls_table->int_cc_node[0].table_size =
		cls_table->params.indexed_params.entries_cnt;
	/* Indexed table is always pre-populated: */
	cls_table->int_cc_node[0].used =
		cls_table->params.indexed_params.entries_cnt;
	cls_table->params.prefilled_entries = 0;

	/* Allocate and initialize the index management array */
	cls_table->entries_cnt = cls_table->params.indexed_params.entries_cnt;
	cls_table->entry =
		kzalloc(cls_table->entries_cnt * sizeof(*cls_table->entry),
			GFP_KERNEL);
	if (!cls_table->entry) {
		log_err("No more memory for DPA Classifier table index "
			"management.\n");
		cls_table->entries_cnt = 0;
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&cls_table->entry_list);

	for (i = 0; i < cls_table->entries_cnt; i++) {
		/* Clean up and prepare the index entry */
		memset(&cls_table->entry[i], 0,
					sizeof(struct dpa_cls_tbl_entry));
		cls_table->entry[i].flags	|= DPA_CLS_TBL_ENTRY_VALID;
		cls_table->entry[i].entry_index	= i;
		cls_table->entry[i].hmd		= DPA_OFFLD_DESC_NONE;

		list_add(&cls_table->entry[i].list_node,
					&cls_table->entry_list);
	}

	/*
	 * If we have a shadow table, import the actions from the indexed Cc
	 * node now
	 */
	if (cls_table->shadow_table) {
		cc_node	= (t_Handle)cls_table->params.cc_node;
		for (i = 0; i < cls_table->params.indexed_params.entries_cnt;
									i++) {
			err = FM_PCD_MatchTableGetNextEngine(cc_node,
							i,
							&next_engine_params);
			if (err != E_OK) {
				log_err("FMan driver call failed - "
					"FM_PCD_MatchTableGetNextEngine. Cc "
					"node handle=0x%p, entry index=%d.\n",
					cc_node, i);
				return -EBUSY;
			}

			shadow_entry = kzalloc(sizeof(*shadow_entry),
								GFP_KERNEL);
			if (!shadow_entry) {
				log_err("Out of memory while populating shadow "
					"table.\n");
				return -ENOMEM;
			}

			next_engine_params_to_action(&next_engine_params,
				&shadow_entry->action);

			cls_table->entry[i].shadow_entry =
						&shadow_entry->list_node;

			/* Add entry to the shadow table. */
			list_add(&shadow_entry->list_node,
				&cls_table->shadow_table->shadow_entry[i]);
		}
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

static int table_init_hash(struct dpa_cls_table *cls_table)
{
	uint16_t i;
	int err = 0;
	t_FmPcdCcNextEngineParams next_engine_params;
	t_Handle cc_node;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!cls_table);
	BUG_ON(cls_table->params.type != DPA_CLS_TBL_HASH);

	err = alloc_table_management(cls_table);
	if (err < 0)
		return err;

	cc_node	= (t_Handle)cls_table->params.cc_node;
	if (!cls_table->params.prefilled_entries) {
		for (i = 0; i < cls_table->params.hash_params.num_sets; i++) {
			/*
			 * Acquire next engine parameters for each index entry
			 * in the main HASH Cc node.
			 */
			if (FM_PCD_MatchTableGetNextEngine(cc_node,
						i,
						&next_engine_params) != E_OK) {
				log_err("FMan driver call failed - "
					"FM_PCD_MatchTableGetNextEngine. Cc "
					"node handle=0x%p, entry index=%d.\n",
					cc_node, i);
				err = -EBUSY;
				goto table_init_hash_error;
			}

			/*
			 * Store the HASH set handle into the internal Cc nodes
			 * data structures.
			 */
			BUG_ON(next_engine_params.nextEngine != e_FM_PCD_CC);
			cls_table->int_cc_node[i].cc_node =
				next_engine_params.params.ccParams.h_CcNode;
			cls_table->int_cc_node[i].table_size =
				cls_table->params.hash_params.max_ways;
		}

		/* Allocate the index management array */
		cls_table->entries_cnt = cls_table->params.hash_params.
			num_sets * cls_table->params.hash_params.max_ways;
		cls_table->entry = kzalloc(cls_table->entries_cnt *
					sizeof(*cls_table->entry), GFP_KERNEL);
		if (!cls_table->entry) {
			log_err("No more memory for DPA Classifier table index "
				"management.\n");
			cls_table->entries_cnt	= 0;
			err			= -ENOMEM;
			goto table_init_hash_error;
		}
		INIT_LIST_HEAD(&cls_table->entry_list);

		cls_table->hash_mask =
			(uint64_t)(cls_table->params.hash_params.num_sets - 1)
			<< (8 * (6 - cls_table->params.hash_params.hash_offs)
			+ 4) ;
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;

table_init_hash_error:
	free_table_management(cls_table);

	return err;
}

static int table_init_exact_match(struct dpa_cls_table *cls_table)
{
	int err = 0;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!cls_table);
	BUG_ON(cls_table->params.type != DPA_CLS_TBL_EXACT_MATCH);

	err = alloc_table_management(cls_table);
	if (err < 0)
		return err;

	/* First Cc node is the one that the user provided */
	cls_table->int_cc_node[0].cc_node = cls_table->params.cc_node;
	cls_table->int_cc_node[0].table_size =
		cls_table->params.exact_match_params.entries_cnt;
	cls_table->int_cc_node[0].used = cls_table->params.prefilled_entries;

	/* Allocate the index management array */
	cls_table->entries_cnt =
		cls_table->params.exact_match_params.entries_cnt;
	cls_table->entry =
		kzalloc(cls_table->entries_cnt * sizeof(*cls_table->entry),
			GFP_KERNEL);
	if (!cls_table->entry) {
		log_err("No more memory for DPA Classifier table index "
			"management.\n");
		cls_table->entries_cnt	= 0;
		err			= -ENOMEM;
		goto table_init_exact_match_error;
	}
	INIT_LIST_HEAD(&cls_table->entry_list);

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;

table_init_exact_match_error:
	free_table_management(cls_table);

	return err;
}

static void table_cleanup_indexed(struct dpa_cls_table *cls_table)
{
	struct dpa_cls_tbl_shadow_entry_indexed *shadow_entry_indexed;
	int i;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!cls_table);
	BUG_ON(cls_table->params.type != DPA_CLS_TBL_INDEXED);

	for (i = 0; i < cls_table->params.indexed_params.entries_cnt; i++)
		if (cls_table->entry[i].shadow_entry) {

			shadow_entry_indexed =
				list_entry(cls_table->entry[i].shadow_entry,
				struct dpa_cls_tbl_shadow_entry_indexed,
				list_node);

			list_del(&shadow_entry_indexed->list_node);
			kfree(shadow_entry_indexed);
		}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));
}

static int verify_table_params(const struct dpa_cls_tbl_params *params)
{
	int err = 0;
	unsigned int num_sets;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!params);

	switch (params->type) {
	case DPA_CLS_TBL_EXACT_MATCH:
		if (params->exact_match_params.entries_cnt >
				FM_PCD_MAX_NUM_OF_KEYS) {
			log_err("Specified number of entries (%d) for exact "
				"match table exceeds the maximum capacity of "
				"this type of table (%d).\n",
				params->exact_match_params.entries_cnt,
				FM_PCD_MAX_NUM_OF_KEYS);
			err = -EINVAL;
			break;
		}

		if (params->exact_match_params.key_size >
				FM_PCD_MAX_SIZE_OF_KEY) {
			log_err("DPA Classifier exact match table key size (%d "
				"bytes) exceeds maximum (%d bytes).\n",
				params->exact_match_params.key_size,
				FM_PCD_MAX_SIZE_OF_KEY);
			err = -EINVAL;
			break;
		}
		break;
	case DPA_CLS_TBL_HASH:
		if (params->hash_params.num_sets > FM_PCD_MAX_NUM_OF_KEYS) {
			log_err("DPA Classifier hash table number of sets (%d) "
				"exceeds maximum (%d).\n",
				params->hash_params.num_sets,
				FM_PCD_MAX_NUM_OF_KEYS);
			err = -EINVAL;
			break;
		}

		/* Verify that the number of sets is a power of 2 */
		num_sets = 0x02; /* 0b00000010  - the smallest acceptable
					value */
		while (num_sets < params->hash_params.num_sets)
			num_sets <<= 1;
		if (num_sets != params->hash_params.num_sets) {
			log_err("DPA Classifier hash table number of sets (%d) "
				"must be a power of 2.\n",
				params->hash_params.num_sets);
			err = -EINVAL;
			break;
		}

		if (params->hash_params.max_ways > FM_PCD_MAX_NUM_OF_KEYS) {
			log_err("DPA Classifier hash table number of ways (%d) "
				"exceeds maximum (%d).\n",
				params->hash_params.max_ways,
				FM_PCD_MAX_NUM_OF_KEYS);
			err = -EINVAL;
			break;
		}

		if (params->hash_params.key_size > FM_PCD_MAX_SIZE_OF_KEY) {
			log_err("DPA Classifier hash table key size (%d bytes) "
				"exceeds maximum (%d bytes).\n",
				params->hash_params.key_size,
				FM_PCD_MAX_SIZE_OF_KEY);
			err = -EINVAL;
			break;
		}
		break;
	case DPA_CLS_TBL_INDEXED:
		if (params->indexed_params.entries_cnt >
				FM_PCD_MAX_NUM_OF_KEYS) {
			log_err("DPA Classifier indexed table size (%d "
				"entries) exceeds maximum (%d entries).\n",
				params->indexed_params.entries_cnt,
				FM_PCD_MAX_NUM_OF_KEYS);
			err = -EINVAL;
			break;
		}

		if (params->indexed_params.entries_cnt == 0) {
			log_err("Indexed table size zero is invalid.\n");
			err = -EINVAL;
			break;
		}
		break;
	default:
		log_err("Unsupported DPA Classifier table type (%d).\n",
			params->type);
		err = -EINVAL;
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}

static struct list_head *find_shadow_entry(const struct dpa_cls_table
			*cls_table, const struct dpa_offload_lookup_key *key)
{
	uint8_t shadow_table_index;
	struct dpa_cls_tbl_shadow_entry *entry;
	bool found = false;
	struct list_head *pos, *bucket_list;
	struct dpa_cls_tbl_shadow_table *shadow_table;
	uint8_t masked_key[DPA_OFFLD_MAXENTRYKEYSIZE];

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!cls_table);
	BUG_ON(!key);
	BUG_ON(!key->byte);
	BUG_ON((key->size <= 0) ||
		(key->size > DPA_OFFLD_MAXENTRYKEYSIZE));
	BUG_ON(!cls_table->shadow_table);

	shadow_table = cls_table->shadow_table;
	if (cls_table->params.type == DPA_CLS_TBL_INDEXED) {
		if (list_empty(&shadow_table->shadow_entry[key->byte[0]]))
			return NULL;
		else
			return shadow_table->shadow_entry[key->byte[0]].next;
	} else {
		key_apply_mask(key, masked_key);
		shadow_table_index = crc8(crc8_table, masked_key, key->size, 0);

		bucket_list =
			&shadow_table->shadow_entry[shadow_table_index];

		if (list_empty(bucket_list))
			return NULL;

		/*
		 * Look into the HASH bucket to find the entry with the
		 * specified key
		 */
	list_for_each(pos, bucket_list) {
		entry = list_entry(pos, struct dpa_cls_tbl_shadow_entry,
				list_node);
		found = false;

		if (entry->key.size != key->size)
			break;

		/* Verify if the key and mask are identical */
		if (memcmp(entry->key.byte, key->byte, key->size) == 0) {
			if (entry->key.mask) {
				if ((key->mask) &&
					(memcmp(entry->key.mask, key->mask,
							key->size) == 0))
					found = true;
			} else
				if (!key->mask)
					found = true;
		}

		if (found)
			break;
	}
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	if (found)
		return pos;

	return NULL;
}

static int table_insert_entry_exact_match(struct dpa_cls_table	*cls_table,
			const struct dpa_offload_lookup_key	*key,
			const struct dpa_cls_tbl_action		*action,
			int					priority,
			int					*entry_id)
{
	t_Error err;
	int errno = 0;
	struct dpa_cls_tbl_shadow_entry *shadow_entry = NULL;
	t_FmPcdCcKeyParams key_params;
	int i = 0;
	int k, hmd;
	uint8_t shadow_table_index;
	uint8_t key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	struct dpa_cls_tbl_shadow_table *shadow_table;
	struct dpa_cls_tbl_entry *index_entry;
	struct list_head *list_current;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!cls_table);
	BUG_ON(!key);
	BUG_ON(!action);
	BUG_ON(cls_table->params.type != DPA_CLS_TBL_EXACT_MATCH);

	if (key->size != cls_table->params.exact_match_params.key_size) {
		log_err("Key size (%d) doesn't match table key size (%d).\n",
			key->size,
			cls_table->params.exact_match_params.key_size);
		return -EINVAL;
	}

	if (cls_table->int_cc_node[0].used >=
		cls_table->int_cc_node[0].table_size) {
		/* No more space to add a new entry */
		log_err("DPA Classifier exact match table is full. Unable to "
			"add a new entry.\n");
		return -ENOSPC;
	}

	memset(&key_params, 0, sizeof(t_FmPcdCcKeyParams));

	/*
	 * Have to copy the data from the key and mask because the FMD is not
	 * using const pointers and we cannot provide it the const pointers that
	 * the user provided.
	 */
	memcpy(key_data, key->byte, key->size);
	key_params.p_Key = key_data;
	if (key->mask) {
		memcpy(mask_data, key->mask, key->size);
		key_params.p_Mask = mask_data;
	}

	errno = action_to_next_engine_params(action,
				&key_params.ccNextEngineParams,
				&hmd);
	if (errno < 0)
		return errno;

	/* Find an empty index management entry */
	for (k = 0; k < cls_table->entries_cnt; k++)
		if (!(cls_table->entry[k].flags & DPA_CLS_TBL_ENTRY_VALID))
			break;

	BUG_ON(k == cls_table->entries_cnt);

	/* Clean up and prepare the index entry */
	memset(&cls_table->entry[k], 0,
		sizeof(struct dpa_cls_tbl_entry));
	cls_table->entry[k].priority = priority;
	cls_table->entry[k].entry_index =
				(uint8_t)cls_table->int_cc_node[0].used;
	cls_table->entry[k].hmd = hmd;

	/* Calculate the position in the index management list where this entry
	 * should go */
	if (list_empty(&cls_table->entry_list))
		/* List is empty. Just add to its tail. */
		list_current = &cls_table->entry_list;
	else {
		if (cls_table->params.exact_match_params.use_priorities) {
			/*
			 * Have to recalculate the position of this entry based
			 * on its priority.
			 */
			/*
			 * Find the first entry with a priority value which is
			 * higher than or equal to the one to add
			 */
			list_for_each_entry(index_entry,
						&cls_table->entry_list,
						list_node) {
				if (index_entry->priority >= priority)
					break;
			}
			/* If there are such entries in the list */
			if (&index_entry->list_node != &cls_table->entry_list) {
				/* We shall add this entry in the position of
				 * the [current] one */
				cls_table->entry[k].entry_index =
					index_entry->entry_index;
				list_current = &index_entry->list_node;
			} else
				/*
				 * Otherwise let the entry be added at the end
				 * of the table
				 */
				list_current = &cls_table->entry_list;
		} else
			/*
			 * If priorities are not used add the entry at the end
			 * of the table
			 */
			list_current = &cls_table->entry_list;
	}

	/* Add the key to the selected Cc node */
#ifdef DPA_CLASSIFIER_DEBUG
	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d): Insert new entry in table "
		"cc_node=0x%p.\n", __func__, __LINE__,
		cls_table->int_cc_node[0].cc_node));
	dpa_cls_dbg(("	index=%d; action type (id)=%d; hmd=%d; h_Manip=0x%p\n",
		cls_table->entry[k].entry_index, action->type, hmd,
		key_params.ccNextEngineParams.h_Manip));
	dump_lookup_key(key);
#endif /* DPA_CLASSIFIER_DEBUG */
	err = FM_PCD_MatchTableAddKey((t_Handle)cls_table->
			int_cc_node[0].cc_node,
		cls_table->entry[k].entry_index,
		cls_table->params.exact_match_params.key_size,
		&key_params);
	if (err != E_OK) {
		log_err("FMan driver call failed - FM_PCD_MatchTableAddKey. "
			"Entry ref=%d, Cc node handle=0x%p, entry index=%d.\n",
			k, cls_table->int_cc_node[0].cc_node,
			cls_table->entry[k].entry_index);
		return -EBUSY;
	}

	/* Add the index entry to the index management list */
	list_add_tail(&cls_table->entry[k].list_node, list_current);

	cls_table->entry[k].flags |= DPA_CLS_TBL_ENTRY_VALID;

	/* Increment all entry indexes in the current cc node starting from
	 * [current] on */
	while (list_current != &cls_table->entry_list) {
		index_entry = list_entry(list_current,
					struct dpa_cls_tbl_entry,
					list_node);
		if (index_entry->int_cc_node_index != i)
			break;

		index_entry->entry_index++;

		list_current = list_current->next;
	}

	cls_table->int_cc_node[0].used++;

	/* If shadow table exists, add the entry to it */
	if (cls_table->shadow_table) {
		shadow_entry = kzalloc(sizeof(*shadow_entry), GFP_KERNEL);
		if (!shadow_entry) {
			log_err("Out of memory while populating shadow "
				"table.\n");
			return -ENOMEM;
		}

		memcpy(&shadow_entry->action, action,
			sizeof(struct dpa_cls_tbl_action));
		shadow_entry->key.byte = kzalloc(key->size, GFP_KERNEL);
		if (!shadow_entry->key.byte) {
			log_err("Out of memory while populating shadow "
				"table.\n");
			kfree(shadow_entry);
			return -ENOMEM;
		}
		memcpy(shadow_entry->key.byte, key->byte, key->size);
		if (key->mask) {
			shadow_entry->key.mask = kzalloc(key->size, GFP_KERNEL);
			if (!shadow_entry->key.mask) {
				log_err("Out of memory while populating shadow "
					"table.\n");
				kfree(shadow_entry->key.byte);
				kfree(shadow_entry);
				return -ENOMEM;
			}
			memcpy(shadow_entry->key.mask, key->mask, key->size);
		}
		shadow_entry->key.size = key->size;

		/* Connect index management entry with the shadow table entry */
		shadow_entry->entry_id = k;
		cls_table->entry[k].shadow_entry = &shadow_entry->list_node;

		/* Add entry to the proper shadow table. */
		key_apply_mask(key, key_data);
		shadow_table_index = crc8(crc8_table,
				key_data,
				cls_table->params.exact_match_params.key_size,
				0);
		shadow_table = cls_table->shadow_table;
		list_add_tail(&shadow_entry->list_node,
			&shadow_table->shadow_entry[shadow_table_index]);
	}

	if (entry_id)
		*entry_id = k;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

static int table_insert_entry_hash(struct dpa_cls_table		*cls_table,
		const struct dpa_offload_lookup_key		*key,
		const struct dpa_cls_tbl_action			*action,
		int						*entry_id)
{
	t_Error err;
	int errno = 0;
	struct dpa_cls_tbl_shadow_entry *shadow_entry = NULL;
	t_FmPcdCcKeyParams key_params;
	uint8_t shadow_table_index;
	u64 hash_set_index;
	uint8_t key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	int j, hmd;
	struct dpa_cls_tbl_shadow_table *shadow_table;
	struct list_head *list_current;
	struct dpa_cls_tbl_entry *index_entry;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!cls_table);
	BUG_ON(!key);
	BUG_ON(!action);
	BUG_ON(cls_table->params.type != DPA_CLS_TBL_HASH);

	if (key->size != cls_table->params.hash_params.key_size) {
		log_err("Key size (%d bytes) doesn't match table key size (%d "
			"bytes).\n", key->size,
			cls_table->params.hash_params.key_size);
		return -EINVAL;
	}

	if (key->mask) {
		/* Only full 0xFF masks supported: */
		for (j = 0; j < key->size; j++)
			if (key->mask[j] ^ 0xff) {
				log_err("Only key masks 0xff all over are supported by HASH tables.\n");
				return -EINVAL;
			}
	}

	memset(&key_params, 0, sizeof(t_FmPcdCcKeyParams));

	/*
	 * Have to copy the data from the key because the FMD is not
	 * using const pointers and we cannot provide it the const pointers that
	 * the user provided.
	 */
	memcpy(key_data, key->byte, key->size);
	key_params.p_Key = key_data;

	if (cls_table->params.prefilled_entries) {
		errno = action_to_next_engine_params(action,
					&key_params.ccNextEngineParams,
					NULL);
		if (errno < 0)
			return errno;

		/*
		 * If pre-filled entries exist, fall through to the low level
		 * driver only
		 */
		err = FM_PCD_HashTableAddKey(
				(t_Handle)cls_table->params.cc_node,
				cls_table->params.hash_params.key_size,
				&key_params);
		if (err != E_OK) {
			log_err("FMan driver call failed - "
				"FM_PCD_HashTableAddKey. HASH table "
				"handle=0x%p.\n", cls_table->params.cc_node);
			return -EBUSY;
		}

		return 0;
	}

	errno = action_to_next_engine_params(action,
				&key_params.ccNextEngineParams,
				&hmd);
	if (errno < 0)
		return errno;

	hash_set_index = crc64_ecma_seed();
	hash_set_index = crc64_ecma(key_data,
				cls_table->params.hash_params.key_size,
				hash_set_index);
	hash_set_index = (u64)(hash_set_index & cls_table->hash_mask) >>
		(8 * (6 - cls_table->params.hash_params.hash_offs) + 4);

	BUG_ON(hash_set_index >= cls_table->int_cc_nodes_count);

	/* Check if there are entries still available in the selected set */
	if (cls_table->int_cc_node[hash_set_index].used >=
			cls_table->int_cc_node[hash_set_index].table_size) {
		log_err("Hash set #%llu is full (%d entries). Unable to add "
			"this entry.\n", hash_set_index,
			cls_table->int_cc_node[hash_set_index].table_size);
		return -ENOSPC;
	}

	/* Find an empty index entry */
	for (j = 0; j < cls_table->entries_cnt; j++)
		if (!(cls_table->entry[j].flags & DPA_CLS_TBL_ENTRY_VALID))
			break;

	BUG_ON(j == cls_table->entries_cnt);

	/* Clean up and prepare the index entry */
	memset(&cls_table->entry[j], 0,
		sizeof(struct dpa_cls_tbl_entry));
	cls_table->entry[j].flags |= DPA_CLS_TBL_ENTRY_VALID;
	cls_table->entry[j].int_cc_node_index = (unsigned int)hash_set_index;
	cls_table->entry[j].entry_index =
			(uint8_t)cls_table->int_cc_node[hash_set_index].used;
	cls_table->entry[j].hmd = hmd;

	/* Calculate the position in the index management list where this entry
	 * should go */
	if ((list_empty(&cls_table->entry_list)) ||
		(hash_set_index >= cls_table->int_cc_nodes_count - 1))
		/* Just add to the tail of the list. */
		list_current = &cls_table->entry_list;
	else {
		/* Sort the index management list based on [cc_node_index] and
		 * [entry_index]. In other words, add the current entry
		 * before the first entry of the next cc node */
		list_for_each(list_current, &cls_table->entry_list) {
			index_entry = list_entry(list_current,
						struct dpa_cls_tbl_entry,
						list_node);
			if (index_entry->int_cc_node_index > hash_set_index)
				break;
		}
	}

	/* Add the key to the selected Cc node */
	err = FM_PCD_MatchTableAddKey((t_Handle)cls_table->
			int_cc_node[hash_set_index].cc_node,
		cls_table->entry[j].entry_index,
		cls_table->params.hash_params.key_size,
		&key_params);
	if (err != E_OK) {
		log_err("FMan driver call failed - FM_PCD_MatchTableAddKey. "
			"Entry ref=%d, HASH set=%llu, Cc node handle=0x%p, "
			"entry index=%d.\n", j, hash_set_index,
			cls_table->int_cc_node[hash_set_index].cc_node,
			cls_table->entry[j].entry_index);
		return -EBUSY;
	}

	/* Add the index entry to the index management list */
	list_add_tail(&cls_table->entry[j].list_node, list_current);

	cls_table->int_cc_node[hash_set_index].used++;

	/* If shadow tables exist, add the entry to them */
	if (cls_table->shadow_table) {
		shadow_entry = kzalloc(sizeof(*shadow_entry), GFP_KERNEL);
		if (!shadow_entry) {
			log_err("Out of memory while populating shadow "
				"table.\n");
			return -ENOMEM;
		}

		memcpy(&shadow_entry->action, action,
			sizeof(struct dpa_cls_tbl_action));
		shadow_entry->key.byte = kzalloc(key->size, GFP_KERNEL);
		if (!shadow_entry->key.byte) {
			log_err("Out of memory while populating shadow table "
				"entry.\n");
			kfree(shadow_entry);
			return -ENOMEM;
		}
		memcpy(shadow_entry->key.byte, key->byte, key->size);
		shadow_entry->key.size = key->size;

		/* Connect index management entry with the shadow table entry */
		shadow_entry->entry_id = j;
		cls_table->entry[j].shadow_entry = &shadow_entry->list_node;

		/* Add entry to the proper shadow table. */
		shadow_table_index = crc8(crc8_table,
				key_data,
				cls_table->params.hash_params.key_size,
				0);
		shadow_table = cls_table->shadow_table;
		list_add_tail(&shadow_entry->list_node,
			&shadow_table->shadow_entry[shadow_table_index]);
	}

	if (entry_id)
		*entry_id = j;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

static int action_to_next_engine_params(const struct dpa_cls_tbl_action *action,
				t_FmPcdCcNextEngineParams *next_engine_params,
				int *hmd)
{
	struct dpa_cls_table *next_table;
#if (DPAA_VERSION >= 11)
	struct dpa_cls_mcast_group *pgroup;
#endif

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!action);
	BUG_ON(!next_engine_params);

	memset(next_engine_params, 0, sizeof(t_FmPcdCcNextEngineParams));

	if (hmd)
		*hmd = DPA_OFFLD_DESC_NONE;

	switch (action->type) {
	case DPA_CLS_TBL_ACTION_DROP:
		next_engine_params->nextEngine = e_FM_PCD_DONE;
		next_engine_params->params.enqueueParams.action =
			e_FM_PCD_DROP_FRAME;
		break;
	case DPA_CLS_TBL_ACTION_ENQ:
		if (action->enq_params.distribution) {
			/* Redirect frames to KeyGen direct scheme */
			next_engine_params->nextEngine = e_FM_PCD_KG;
			next_engine_params->params.kgParams.h_DirectScheme =
				action->enq_params.distribution;
			next_engine_params->params.kgParams.newFqid =
				action->enq_params.new_fqid;
			if (action->enq_params.override_fqid)
				next_engine_params->params.kgParams.
					overrideFqid = TRUE;
		} else {
			if (action->enq_params.policer_params != NULL) {
				next_engine_params->nextEngine = e_FM_PCD_PLCR;
				next_engine_params->params.plcrParams.
					sharedProfile = action->enq_params.
					policer_params->shared_profile;
				next_engine_params->params.plcrParams.
			newRelativeProfileId = (uint16_t)action->enq_params.
				policer_params->new_rel_profile_id;
				next_engine_params->params.plcrParams.
					overrideParams = action->enq_params.
					policer_params->modify_policer_params;
				next_engine_params->params.plcrParams.
					newFqid = action->enq_params.new_fqid;
#if (DPAA_VERSION >= 11)
				next_engine_params->params.plcrParams.
					newRelativeStorageProfileId =
					action->enq_params.new_rel_vsp_id;
#endif /* (DPAA_VERSION >= 11) */
			} else {
				next_engine_params->nextEngine = e_FM_PCD_DONE;
				next_engine_params->params.enqueueParams.
					action = e_FM_PCD_ENQ_FRAME;
				next_engine_params->params.enqueueParams.
					newFqid = action->enq_params.new_fqid;
				if (action->enq_params.override_fqid)
					next_engine_params->params.
						enqueueParams.overrideFqid =
						TRUE;
#if (DPAA_VERSION >= 11)
				next_engine_params->params.enqueueParams.
					newRelativeStorageProfileId =
					action->enq_params.new_rel_vsp_id;
#endif
			}
		}

		if (action->enq_params.hmd != DPA_OFFLD_DESC_NONE) {
			if (!hmd) {
				log_err("Header manipulations are not allowed "
					"on this action.\n");
				return -EINVAL;
			}
			if (!dpa_classif_hm_is_chain_head(
						action->enq_params.hmd)) {
				log_err("hmd=%d is not a header manipulation "
					"chain head. Only chain heads can be "
					"attached to table entries.\n",
					action->enq_params.hmd);
				return -EINVAL;
			}
			next_engine_params->h_Manip = (t_Handle)
		dpa_classif_hm_lock_chain(action->enq_params.hmd);
			if (!next_engine_params->h_Manip) {
				log_err("Failed to attach HM op hmd=%d to "
					"classification entry.\n",
					action->enq_params.hmd);
				return -EINVAL;
			}

			*hmd = action->enq_params.hmd;
		} else
			next_engine_params->h_Manip = NULL;

		break;
	case DPA_CLS_TBL_ACTION_NEXT_TABLE:
		if ((action->next_table_params.next_td >=
				table_array.num_descriptors) ||
			(!table_array.object[action->next_table_params.
								next_td])) {
			log_err("Invalid next table descriptor "
				"(next_td=%d).\n",
				(unsigned)action->next_table_params.next_td);
			return -EINVAL;
		}

		if (action->next_table_params.hmd != DPA_OFFLD_DESC_NONE) {
			if (!hmd) {
				log_err("Header manipulations are not allowed on "
					"this action.\n");
				return -EINVAL;
			}
			if (!dpa_classif_hm_is_chain_head(
						action->next_table_params.hmd)) {
				log_err("hmd=%d is not a header manipulation "
					"chain head. Only chain heads can be "
					"used by the classifier table.\n",
					action->next_table_params.hmd);
				return -EINVAL;
			}
			next_engine_params->h_Manip = (t_Handle)
		dpa_classif_hm_lock_chain(action->next_table_params.hmd);
			if (!next_engine_params->h_Manip) {
				log_err("Failed to attach HM op hmd=%d to "
					"classification entry.",
					action->next_table_params.hmd);
				return -EINVAL;
			}

			*hmd = action->next_table_params.hmd;
		} else
			next_engine_params->h_Manip = NULL;

		next_engine_params->nextEngine = e_FM_PCD_CC;
		next_table = (struct dpa_cls_table *)
			table_array.object[action->next_table_params.next_td];
		next_engine_params->params.ccParams.h_CcNode =
			(t_Handle)next_table->params.cc_node;

		break;
#if (DPAA_VERSION >= 11)
	case DPA_CLS_TBL_ACTION_MCAST:
		if (action->mcast_params.hmd != DPA_OFFLD_DESC_NONE) {
			if (!hmd) {
				log_err("Header manipulations are not allowed "
					"on this action.\n");
				return -EINVAL;
			}
			next_engine_params->h_Manip = (t_Handle)
			dpa_classif_hm_lock_chain(action->mcast_params.hmd);
			if (!next_engine_params->h_Manip) {
				log_err("Failed to attach HM op hmd=%d to "
					"classification entry.\n",
					action->enq_params.hmd);
				return -EINVAL;
			}

			*hmd = action->mcast_params.hmd;
		} else
			next_engine_params->h_Manip = NULL;
		next_engine_params->nextEngine = e_FM_PCD_FR;
		pgroup = desc_to_object(&mcast_grp_array,
					action->mcast_params.grpd);
		if (!pgroup) {
			log_err("No such group (grpd=%d).\n",
				action->mcast_params.grpd);
			return -EINVAL;
		}

		next_engine_params->params.frParams.h_FrmReplic = pgroup->group;
		break;
#endif
	default:
		log_err("Unsupported DPA Classifier action type (%d).\n",
			action->type);
		return -EINVAL;
	}

	if (action->enable_statistics)
		next_engine_params->statisticsEn = TRUE;

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

static int next_engine_params_to_action(const t_FmPcdCcNextEngineParams
	*next_engine_params, struct dpa_cls_tbl_action *action)
{
	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!action);
	BUG_ON(!next_engine_params);

	if (next_engine_params->statisticsEn == TRUE)
		action->enable_statistics = true;

	switch (next_engine_params->nextEngine) {
	case e_FM_PCD_DONE:
		switch (next_engine_params->params.enqueueParams.action) {
		case e_FM_PCD_ENQ_FRAME:
			action->type = DPA_CLS_TBL_ACTION_ENQ;
		action->enq_params.hmd = DPA_OFFLD_DESC_NONE;
		action->enq_params.new_fqid =
			next_engine_params->params.enqueueParams.newFqid;
		if (next_engine_params->params.enqueueParams.overrideFqid ==
			TRUE)
			action->enq_params.override_fqid = true;
		action->enq_params.policer_params = NULL;
			break;
		case e_FM_PCD_DROP_FRAME:
			action->type = DPA_CLS_TBL_ACTION_DROP;
			break;
		default:
			log_warn("DPA Classifier does not directly support "
				"this type of e_FM_PCD_DONE action (%d).\n",
				next_engine_params->params.
				enqueueParams.action);
			action->type = DPA_CLS_TBL_ACTION_NONE;
			break;
		}
		break;
	case e_FM_PCD_PLCR:
		action->type = DPA_CLS_TBL_ACTION_ENQ;
		action->enq_params.new_fqid =
				next_engine_params->params.plcrParams.newFqid;
		action->enq_params.override_fqid = true;
		action->enq_params.hmd = DPA_OFFLD_DESC_NONE;
		if (next_engine_params->params.plcrParams.overrideParams ==
			TRUE)
			action->enq_params.policer_params->
				modify_policer_params = true;
		action->enq_params.policer_params->new_rel_profile_id =
			next_engine_params->params.plcrParams.
				newRelativeProfileId;
		if (next_engine_params->params.plcrParams.sharedProfile ==
			TRUE)
			action->enq_params.policer_params->shared_profile =
				next_engine_params->params.plcrParams.
					sharedProfile;
		break;
	case e_FM_PCD_CC:
	case e_FM_PCD_HASH:
		action->type = DPA_CLS_TBL_ACTION_NEXT_TABLE;
		action->next_table_params.next_td =
			handle_to_td(next_engine_params->params.ccParams.
				h_CcNode);
		break;
	default:
		log_warn("DPA Classifier does not directly support "
			"this type of NextEngine parameters (%d).\n",
			next_engine_params->nextEngine);
		action->type = DPA_CLS_TBL_ACTION_NONE;
	}

	dpa_cls_dbg(("DEBUG: dpa_classifier %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

static int key_to_entry_id(const struct dpa_cls_table *cls_table,
	const struct dpa_offload_lookup_key *key)
{
	struct dpa_cls_tbl_shadow_entry *shadow_entry;
	struct list_head *shadow_list_entry;

	if (cls_table->params.type == DPA_CLS_TBL_INDEXED) {
		if (key->size != 1) {
			log_err("Bad key format for index table. Key size must "
				"be 1.\n");
			return -EINVAL;
		}
		return (int)key->byte[0];
	}

	if ((cls_table->params.type == DPA_CLS_TBL_HASH) &&
			(cls_table->params.prefilled_entries))
		/* Cannot lookup in a prefilled HASH table */
		return -ENODEV;

	if (!cls_table->shadow_table) {
		log_err("No shadow table.\n");
		return -ENOSYS;
	}

	/* Find the shadow entry associated with this key */
	shadow_list_entry = find_shadow_entry(cls_table, key);
	if (shadow_list_entry == NULL)
		return -ENODEV;

	shadow_entry = list_entry(shadow_list_entry,
				struct dpa_cls_tbl_shadow_entry,
				list_node);

	return shadow_entry->entry_id;
}

static int handle_to_td(void *cc_node)
{
	int i;
	struct dpa_cls_table *table;

	for (i = 0; i < table_array.num_descriptors; i++) {
		if (table_array.object[i]) {
			table = (struct dpa_cls_table *) table_array.object[i];
			if ((unsigned long)table->params.cc_node ==
				(unsigned long)cc_node)
				break;
		}
	}

	if (i < table_array.num_descriptors)
		return i;
	else
		/* No matching classification table found */
		return DPA_OFFLD_DESC_NONE;
}

static int extend_descriptor_table(struct dpa_cls_descriptor_table *desc_table)
{
	unsigned int new_table_size = 0;
	void **new_objects_array;

	if (desc_table->object)
		new_table_size = desc_table->num_descriptors;

	new_table_size += DPA_CLS_ARRAYSIZEGRANULARITY;

	new_objects_array = kzalloc(new_table_size * sizeof(void *),
				   GFP_KERNEL);
	if (!new_objects_array) {
		log_err("No more memory for DPA Classifier descriptor "
			"table.\n");
		return -ENOMEM;
	}

	if (desc_table->num_descriptors)
		/*
		 * Transfer pointers to existing objects into the new
		 * descriptor array
		 */
		memcpy(new_objects_array, desc_table->object,
			desc_table->num_descriptors * sizeof(void *));

	kfree(desc_table->object);

	desc_table->object		= new_objects_array;
	desc_table->num_descriptors	= new_table_size;

	return 0;
}

static int get_descriptor(struct dpa_cls_descriptor_table *desc_table,
						void *object, int *desc)
{
	int i;

	if (desc_table->used_descriptors >= desc_table->num_descriptors)
		return -ENOSPC;

	for (i = 0; i < desc_table->num_descriptors; i++)
		if (desc_table->object[i] == NULL) {
			desc_table->object[i] = object;
			*desc = i;
			break;
		}

	desc_table->used_descriptors++;

	return 0;
}

static int acquire_descriptor(struct dpa_cls_descriptor_table *desc_table,
	void *object, int *desc)
{
	int err;

	BUG_ON(!desc_table);
	BUG_ON(!object);
	BUG_ON(!desc);

	if (get_descriptor(desc_table, object, desc) < 0) {
		err = extend_descriptor_table(desc_table);
		if (err < 0)
			return err;

		/*
		 * If extending the table was successful it is impossible for
		 * the following function to fail
		 */
		get_descriptor(desc_table, object, desc);
	}

	return 0;
}

static inline void put_descriptor(struct dpa_cls_descriptor_table *desc_table,
	int desc)
{
	BUG_ON(!desc_table);

	if (desc_table->object[desc] != NULL) {
		if (--desc_table->used_descriptors == 0) {
			kfree(desc_table->object);
			desc_table->object		= NULL;
			desc_table->num_descriptors	= 0;
		} else
			desc_table->object[desc]	= NULL;
	}
}

static inline void lock_desc_table(struct dpa_cls_descriptor_table
								*desc_table)
{
	mutex_lock(desc_table->access);
}

static inline void release_desc_table(struct dpa_cls_descriptor_table
								*desc_table)
{
	mutex_unlock(desc_table->access);
}

static void	*desc_to_object(struct dpa_cls_descriptor_table *desc_table,
								int desc)
{
	BUG_ON(!desc_table);

	if ((desc >= 0) && (desc < desc_table->num_descriptors))
		return desc_table->object[desc];
	else
		return NULL;
}

static inline void key_apply_mask(const struct dpa_offload_lookup_key *key,
	uint8_t *new_key)
{
	int i;

	BUG_ON(!new_key);
	BUG_ON(!key);
	BUG_ON(!key->byte);

	if (key->mask == NULL) {
		memcpy(new_key, key->byte, key->size);
		return;
	}

	memset(new_key, 0, key->size);
	for (i = 0; i < key->size; i++)
		new_key[i] = key->byte[i] & key->mask[i];
}

int dpa_classif_get_miss_action(int td, struct dpa_cls_tbl_action *miss_action)
{
	struct dpa_cls_table *ptable;

	if (!miss_action)
		return -EINVAL;

	LOCK_OBJECT(table_array, td, ptable, -EINVAL);
	if (ptable->miss_action.type == DPA_CLS_TBL_ACTION_NONE) {
		/* No miss action was specified for this table */
		RELEASE_OBJECT(ptable);
		return -ENODEV;
	} else
		memcpy(miss_action, &ptable->miss_action, sizeof(*miss_action));

	RELEASE_OBJECT(ptable);

	return 0;
}

static int nat_hm_check_params(const struct dpa_cls_hm_nat_params *nat_params)
{
	unsigned int ip_ver = 0;

	BUG_ON(!nat_params);

	/* Check that all IP address versions are the same: */
	if (nat_params->type == DPA_CLS_HM_NAT_TYPE_TRADITIONAL) {

		if (nat_params->flags & DPA_CLS_HM_NAT_UPDATE_SIP)
			ip_ver = nat_params->nat.sip.version;
		if (nat_params->flags & DPA_CLS_HM_NAT_UPDATE_DIP) {
			if ((ip_ver) &&
				(ip_ver != nat_params->nat.dip.version)) {
				log_err("Inconsistent SIP DIP address "
					"versions.\n");
				return -EINVAL;
			}
			ip_ver = nat_params->nat.dip.version;
		}

		if ((ip_ver) && (ip_ver != 4) && (ip_ver != 6)) {
			log_err("Unsupported IP version (%d). Only IPv4 and "
				"IPv6 are supported\n", ip_ver);
			return -EINVAL;
		}
	}

	return 0;
}

static int fwd_hm_check_params(const struct dpa_cls_hm_fwd_params *fwd_params)
{
	BUG_ON(!fwd_params);

	if (fwd_params->out_if_type == DPA_CLS_HM_IF_TYPE_PPPoE) {
		log_err("Forwarding HM: PPPoE output interface not supported "
			"yet.\n");
		return -ENOSYS;
	}

	if (fwd_params->ip_frag_params.mtu != 0) {
		log_err("Forwarding HM: IP fragmentation is not supported "
			"yet.\n");
		return -ENOSYS;
	}

	return 0;
}

static int remove_hm_check_params(const struct dpa_cls_hm_remove_params
	*remove_params)
{
	BUG_ON(!remove_params);

	switch (remove_params->type) {
	case DPA_CLS_HM_REMOVE_PPPoE:
		log_err("Unsupported HM: remove PPPoE.\n");
		return -ENOSYS;
		break;
	default:
		break;
	}

	return 0;
}

static int insert_hm_check_params(const struct dpa_cls_hm_insert_params
	*insert_params)
{
	BUG_ON(!insert_params);

	switch (insert_params->type) {
	case DPA_CLS_HM_INSERT_PPPoE:
		log_err("Unsupported HM: insert PPPoE.\n");
		return -ENOSYS;
		break;
	case DPA_CLS_HM_INSERT_ETHERNET:
		if (insert_params->eth.num_tags >
			DPA_CLS_HM_MAX_VLANs) {
			log_err("Insert HM: Can only insert a maximum of %d "
				"VLAN tags.\n", DPA_CLS_HM_MAX_VLANs);
			return -EINVAL;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int update_hm_check_params(const struct dpa_cls_hm_update_params
	*update_params)
{
	const int update_ops_mask =	DPA_CLS_HM_UPDATE_IPv4_UPDATE |
					DPA_CLS_HM_UPDATE_IPv6_UPDATE |
					DPA_CLS_HM_UPDATE_UDP_TCP_UPDATE;
	const int replace_ops_mask =	DPA_CLS_HM_REPLACE_IPv4_BY_IPv6 |
					DPA_CLS_HM_REPLACE_IPv6_BY_IPv4;
	int ops;

	BUG_ON(!update_params);

	if ((update_params->op_flags == DPA_CLS_HM_UPDATE_NONE) &&
		(update_params->ip_frag_params.mtu == 0)) {
		log_err("Cannot create an empty update HM.\n");
		return -EINVAL;
	}

	ops = update_params->op_flags & update_ops_mask;
	if (ops) {
		while ((ops & 0x1) == 0)
			ops >>= 1;
		if (ops > 1) {
			log_err("Only one UPDATE operation is allowed.\n");
			return -EINVAL;
		}

		if (update_params->op_flags & DPA_CLS_HM_UPDATE_IPv4_UPDATE) {
			if ((update_params->update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_IPSA) &&
				(update_params->update.l3.ipsa.version != 4)) {
				log_err("Only IPv4 addresses are accepted for "
					"IPv4 IPSA update.\n");
				return -EINVAL;
			}

			if ((update_params->update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_IPDA) &&
				(update_params->update.l3.ipda.version != 4)) {
				log_err("Only IPv4 addresses are accepted for "
					"IPv4 IPDA update.\n");
				return -EINVAL;
			}
		}

		if (update_params->op_flags & DPA_CLS_HM_UPDATE_IPv6_UPDATE) {
			if ((update_params->update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_IPSA) &&
				(update_params->update.l3.ipsa.version != 6)) {
				log_err("Only IPv6 addresses are accepted for "
					"IPv6 IPSA update.\n");
				return -EINVAL;
			}

			if ((update_params->update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_IPDA) &&
				(update_params->update.l3.ipda.version != 6)) {
				log_err("Only IPv6 addresses are accepted for "
					"IPv6 IPDA update.\n");
				return -EINVAL;
			}
		}
	}

	ops = update_params->op_flags & replace_ops_mask;
	if (ops) {
		while ((ops & 0x1) == 0)
			ops >>= 1;
		if (ops > 1) {
			log_err("Only one REPLACE operation is allowed.\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int
	vlan_hm_check_params(const struct dpa_cls_hm_vlan_params *vlan_params)
{
	BUG_ON(!vlan_params);

	switch (vlan_params->type) {
	case DPA_CLS_HM_VLAN_INGRESS:
		if (vlan_params->ingress.num_tags !=
			DPA_CLS_HM_VLAN_CNT_ALL_QTAGS) {
			log_err("Ingress VLAN QTags remove HM: Only \"remove "
				"all QTags\" is currenly supported.\n");
			return -EINVAL;
		}
		break;
	case DPA_CLS_HM_VLAN_EGRESS:
		if (vlan_params->egress.num_tags >
						DPA_CLS_HM_MAX_VLANs) {
			log_err("Egress VLAN HM: Can only insert a maximum of "
				"%d VLANs.\n", DPA_CLS_HM_MAX_VLANs);
			return -EINVAL;
		}
		break;
	default:
		log_err("Invalid VLAN specific HM type (%d).\n",
			vlan_params->type);
		return -EINVAL;
		break;
	}

	return 0;
}

static int
	mpls_hm_check_params(const struct dpa_cls_hm_mpls_params *mpls_params)
{
	BUG_ON(!mpls_params);

	if ((mpls_params->type == DPA_CLS_HM_MPLS_INSERT_LABELS) &&
		(mpls_params->num_labels > DPA_CLS_HM_MAX_MPLS_LABELS)) {
		log_err("MPLS HM: Can only insert a maximum of %d MPLS "
			"labels.\n", DPA_CLS_HM_MAX_MPLS_LABELS);
		return -EINVAL;
	}

	return 0;
}

static int import_hm_nodes_to_chain(void * const *node_array,
	unsigned int num_nodes, struct dpa_cls_hm *hm)
{
	struct dpa_cls_hm_node *hm_node;
	int i;
	bool found;

	if (!num_nodes)
		/* Nothing to do */
		return 0;

	BUG_ON(!node_array);
	BUG_ON(!hm);

	for (i = num_nodes - 1; i >= 0; i--) {
		/*
		 * If the node is empty, save an empty space and skip
		 * to the next
		 */
		if (!node_array[i]) {
			hm->hm_node[i] = NULL;
			continue;
		}

		/* Check if this node is already in the chain */
		found = false;
		if (!list_empty(&hm->list_node)) {
			list_for_each_entry(hm_node, hm->hm_chain, list_node) {
				if ((unsigned long)hm_node->node ==
					(unsigned long)node_array[i]) {
					/*
					 * This node already exists in the chain
					 */
					found = true;
					break;
				}
			}
		}

		if (found)
			/*
			 * This node already exists in the chain hence
			 * point to the existing node
			 */
			hm->hm_node[i] = hm_node;
		else {
			/* Node does not exist, we need to create it */
			hm->hm_node[i] = kzalloc(sizeof(struct dpa_cls_hm_node),
						 GFP_KERNEL);
			dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n", __func__,
				__LINE__, hm->hm_node[i]));
			if (!hm->hm_node[i]) {
				log_err("Not enough memory for HM node "
					"management.\n");
				return -ENOMEM;
			}

			/* Fill in the node */
			hm->hm_node[i]->node = node_array[i];
			INIT_LIST_HEAD(&hm->hm_node[i]->list_node);

			/* Initialize dontParseAfterManip to TRUE */
			hm->hm_node[i]->params.u.hdr.dontParseAfterManip = TRUE;

			/* Add this new node to the HM chain: */
			list_add(&hm->hm_node[i]->list_node,
				hm->hm_chain);
		}
	}

	return 0;
}

static struct dpa_cls_hm_node *try_compatible_node(const struct dpa_cls_hm *hm)
{
	struct dpa_cls_hm_node *hm_node = NULL;
	const int update_flags = DPA_CLS_HM_UPDATE_IPv4_UPDATE |
					DPA_CLS_HM_UPDATE_IPv6_UPDATE |
					DPA_CLS_HM_UPDATE_UDP_TCP_UPDATE;
	const int replace_flags = DPA_CLS_HM_REPLACE_IPv4_BY_IPv6 |
					DPA_CLS_HM_REPLACE_IPv6_BY_IPv4;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	if (list_empty(hm->hm_chain)) {
		/*
		 * There is nothing in the HM node chain. Don't bother any more
		 * to look for anything:
		 */
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <-- did not find a compatible node.\n",
			__func__, __LINE__));
		return NULL;
	}

	/* Get the last item in the chain */
	hm_node = list_entry(hm->hm_chain->next,
				struct dpa_cls_hm_node, list_node);
	/*
	 * If the previous HM node is not a HDR_MANIP, then it can't be
	 * compatible for aggregation:
	 */
	if (hm_node->params.type != e_FM_PCD_MANIP_HDR) {
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <-- did not find a compatible node.\n",
			__func__, __LINE__));
		return NULL;
	}

	switch (hm->type) {
	case DPA_CLS_HM_TYPE_REMOVE:
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Looking for REMOVE HM compatible nodes...\n",
			__func__, __LINE__));
		/*
		 * If in the previous HM node the remove operation is already
		 * used, then it is not compatible for aggregation:
		 */
		if (hm_node->params.u.hdr.rmv)
			hm_node = NULL;
		break;
	case DPA_CLS_HM_TYPE_INSERT:
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Looking for INSERT HM compatible nodes...\n",
			__func__, __LINE__));
		/*
		 * If in the previous HM node the insert operation is already
		 * used, then it is not compatible for aggregation:
		 */
		if (hm_node->params.u.hdr.insrt)
			hm_node = NULL;
		break;
	case DPA_CLS_HM_TYPE_UPDATE:
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Looking for UPDATE HM compatible nodes...\n",
			__func__, __LINE__));
		/*
		 * If in the previous HM node the update operation is already
		 * used and we also have to do header updates, then it is not
		 * compatible for aggregation:
		 */
		if ((hm->update_params.op_flags & update_flags) &&
			(hm_node->params.u.hdr.fieldUpdate)) {
			hm_node = NULL;
			break;
		}

		/*
		 * If in the previous HM node the custom header replace
		 * operation is already used and we also have to do header
		 * replacement, then it is not compatible for aggregation:
		 */
		if ((hm->update_params.op_flags & replace_flags) &&
			(hm_node->params.u.hdr.custom))
			hm_node = NULL;
		break;
	case DPA_CLS_HM_TYPE_VLAN:
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Looking for VLAN HM compatible nodes...\n",
			__func__, __LINE__));
		switch (hm->vlan_params.type) {
		case DPA_CLS_HM_VLAN_INGRESS:
			/*
			 * If in the previous HM node the remove operation is
			 * already used, then it is not compatible for
			 * aggregation:
			 */
			if (hm_node->params.u.hdr.rmv)
				hm_node = NULL;
			break;
		case DPA_CLS_HM_VLAN_EGRESS:
			/*
			 * If in the previous HM node the insert operation is
			 * already used and we need to insert VLANs, then it is
			 * not compatible for aggregation:
			 */
			if ((hm->vlan_params.egress.num_tags) &&
				(hm_node->params.u.hdr.insrt)) {
				hm_node = NULL;
				break;
			}

			/*
			 * If in the previous HM node the update operation is
			 * already used and we need to do VLAN update, then it
			 * is not compatible for aggregation:
			 */
			if ((hm->vlan_params.egress.update_op) &&
				(hm_node->params.u.hdr.fieldUpdate))
				hm_node = NULL;
			break;
		default:
			hm_node = NULL;
			break;
		}
		break;
	case DPA_CLS_HM_TYPE_MPLS:
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Looking for MPLS HM compatible nodes...\n",
			__func__, __LINE__));
		switch (hm->mpls_params.type) {
		case DPA_CLS_HM_MPLS_INSERT_LABELS:
			/*
			 * If in the previous HM node the insert operation is
			 * already used, then it is not compatible for
			 * aggregation:
			 */
			if (hm_node->params.u.hdr.insrt)
				hm_node = NULL;
			break;
		case DPA_CLS_HM_MPLS_REMOVE_ALL_LABELS:
			/*
			 * If in the previous HM node the remove operation is
			 * already used, then it is not compatible for
			 * aggregation:
			 */
			if (hm_node->params.u.hdr.rmv)
				hm_node = NULL;
			break;
		default:
			hm_node = NULL;
			break;
		}
		break;
	default:
		hm_node = NULL;
		break;
	}

#ifdef DPA_HM_DEBUG
	if (hm_node)
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): FOUND compatible hm_node = 0x%p.\n",
			__func__, __LINE__, hm_node));
	else
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Compatible hm_node NOT FOUND.\n",
			__func__, __LINE__));
#endif /* DPA_HM_DEBUG */

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return hm_node;
}

static int add_local_hm_nodes_to_chain(struct dpa_cls_hm *phm)
{
	int i;

	BUG_ON(!phm);

	for (i = phm->num_nodes - 1; i >= 0; i--)
		/*
		 * If the node exists and it is not already integrated in a HM
		 * chain...
		 */
		if ((phm->hm_node[i]) &&
				(list_empty(&phm->hm_node[i]->list_node)))
			list_add(&phm->hm_node[i]->list_node, phm->hm_chain);

	return 0;
}

static int init_hm_chain(void *fm_pcd, struct list_head *chain_head,
						struct list_head *item)
{
	int err = 0;
	t_Error error;
	struct dpa_cls_hm_node *pcurrent, *pnext;
	t_FmPcdManipParams params;
	static int index = 0;
	static int num_int_nodes;

	BUG_ON(!chain_head);
	BUG_ON(!item);

	if (index++ == 0)
		num_int_nodes = 0;

	if (item->next != chain_head) {
		/* Initialize the rest of the HM chain */
		err = init_hm_chain(fm_pcd, chain_head, item->next);
		if (err)
			return err;
		pnext = list_entry(item->next,
				struct dpa_cls_hm_node,
				list_node);
	} else
		pnext = NULL;

	/* Initialize the current node: */
	pcurrent = list_entry(item, struct dpa_cls_hm_node, list_node);
	pcurrent->params.h_NextManip = (pnext) ? (t_Handle)pnext->node : NULL;

#ifdef DPA_HM_DEBUG
	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Dumping HM node params for hm_node @ 0x%p\n",
		__func__, __LINE__, pcurrent));
	switch (pcurrent->params.type) {
	case e_FM_PCD_MANIP_HDR:
		dpa_cls_hm_dbg(("	hm_node_params.type = "
			"e_FM_PCD_MANIP_HDR\n"));
		dpa_cls_hm_dbg(("	hm_node_params.u.hdr.rmv = %d\n",
			pcurrent->params.u.hdr.rmv));
		if (pcurrent->params.u.hdr.rmv) {
			switch (pcurrent->params.u.hdr.rmvParams.type) {
			case e_FM_PCD_MANIP_RMV_GENERIC:
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.rmvParams"
					".type = e_FM_PCD_MANIP_RMV_GENERIC\n"));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.rmvParams."
					"u.generic.offset = %u\n",
					pcurrent->params.u.hdr.rmvParams.u.generic.offset));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.rmvParams."
					"u.generic.size = %u\n",
					pcurrent->params.u.hdr.rmvParams.u.generic.size));
				break;
			case e_FM_PCD_MANIP_RMV_BY_HDR:
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.rmvParams"
					".type = e_FM_PCD_MANIP_RMV_BY_HDR\n"));
				if (pcurrent->params.u.hdr.rmvParams.u.byHdr.type == e_FM_PCD_MANIP_RMV_BY_HDR_SPECIFIC_L2) {
					dpa_cls_hm_dbg(("	hm_node_params.u.hdr.rmvParams."
						"u.byHdr.type = e_FM_PCD_MANIP_RMV_BY_HDR_SPECIFIC_L2\n"));
					dpa_cls_hm_dbg(("	hm_node_params.u.hdr.rmvParams."
						"u.byHdr.u.specificL2 = %d\n",
						pcurrent->params.u.hdr.rmvParams.u.byHdr.u.specificL2));
				} else {
					dpa_cls_hm_dbg(("	hm_node_params.u.hdr.rmvParams."
						"u.byHdr.type = %d\n",
						pcurrent->params.u.hdr.rmvParams.u.byHdr.type));
				}
				break;
			}
		}
		dpa_cls_hm_dbg(("	hm_node_params.u.hdr.insrt = %d\n",
			pcurrent->params.u.hdr.insrt));
		if (pcurrent->params.u.hdr.insrt) {
			dpa_cls_hm_dbg(("	hm_node_params.u.hdr.insrtParams"
				".type = %d\n",
				pcurrent->params.u.hdr.insrtParams.type));
		}
		dpa_cls_hm_dbg(("	hm_node_params.u.hdr.fieldUpdate = %d\n",
			pcurrent->params.u.hdr.fieldUpdate));
		if (pcurrent->params.u.hdr.fieldUpdate) {
			switch (pcurrent->params.u.hdr.fieldUpdateParams.
								type) {
			case e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN:
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.type = "
					"HDR_FIELD_UPDATE_VLAN\n"));
				break;
			case e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV4:
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.type = "
					"HDR_FIELD_UPDATE_IPv4\n"));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.u.ipv4."
					"validUpdates = 0x%x\n",
					pcurrent->params.u.hdr.
					fieldUpdateParams.u.ipv4.
					validUpdates));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.u.ipv4."
					"tos = 0x%02x\n",
					pcurrent->params.u.hdr.
					fieldUpdateParams.u.ipv4.
					tos));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.u.ipv4."
					"id = 0x%04x\n",
					pcurrent->params.u.hdr.
					fieldUpdateParams.u.ipv4.
					id));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.u.ipv4."
					"src = 0x%08x\n",
					pcurrent->params.u.hdr.
					fieldUpdateParams.u.ipv4.
					src));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.u.ipv4."
					"dst = 0x%08x\n",
					pcurrent->params.u.hdr.
					fieldUpdateParams.u.ipv4.
					dst));
				break;
			case e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV6:
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.type = "
					"HDR_FIELD_UPDATE_IPv6\n"));
				break;
			case e_FM_PCD_MANIP_HDR_FIELD_UPDATE_TCP_UDP:
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.type = "
					"HDR_FIELD_UPDATE_TCP_UDP\n"));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.u.tcpUdp."
					"validUpdates = 0x%x\n",
					pcurrent->params.u.hdr.
					fieldUpdateParams.u.tcpUdp.
					validUpdates));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.u.tcpUdp."
					"src = 0x%04x\n",
					pcurrent->params.u.hdr.
					fieldUpdateParams.u.tcpUdp.
					src));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.u.tcpUdp."
					"dst = 0x%04x\n",
					pcurrent->params.u.hdr.
					fieldUpdateParams.u.tcpUdp.
					dst));
				break;
			default:
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr."
					"fieldUpdateParams.type = %d "
					"(unknown)\n",
					pcurrent->params.u.hdr.
						fieldUpdateParams.type));
			}
		}
		dpa_cls_hm_dbg(("	hm_node_params.u.hdr.custom = %d\n",
			pcurrent->params.u.hdr.custom));
		if (pcurrent->params.u.hdr.custom) {
			if (pcurrent->params.u.hdr.customParams.type ==
					e_FM_PCD_MANIP_HDR_CUSTOM_IP_REPLACE) {
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.customParams."
					"type = e_FM_PCD_MANIP_HDR_CUSTOM_IP_REPLACE\n"));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.customParams.u.ipHdrReplace.replaceType = %d\n",
					pcurrent->params.u.hdr.customParams.u.ipHdrReplace.replaceType));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.customParams.u.ipHdrReplace.decTtlHl = %d\n",
					pcurrent->params.u.hdr.customParams.u.ipHdrReplace.decTtlHl));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.customParams.u.ipHdrReplace.updateIpv4Id = %d\n",
					pcurrent->params.u.hdr.customParams.u.ipHdrReplace.updateIpv4Id));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.customParams.u.ipHdrReplace.id = %u\n",
					pcurrent->params.u.hdr.customParams.u.ipHdrReplace.id));
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.customParams.u.ipHdrReplace.hdrSize = %u\n",
					pcurrent->params.u.hdr.customParams.u.ipHdrReplace.hdrSize));
			} else
				dpa_cls_hm_dbg(("	hm_node_params.u.hdr.customParams.type = %d\n",
					pcurrent->params.u.hdr.customParams.type));
		}
		dpa_cls_hm_dbg(("	hm_node_params.u.hdr.dontParseAfterManip = %d\n",
			pcurrent->params.u.hdr.dontParseAfterManip));
		break;
	case e_FM_PCD_MANIP_FRAG:
		dpa_cls_hm_dbg(("	hm_node_params.type = "
			"e_FM_PCD_MANIP_FRAG\n"));
		break;
	default:
		dpa_cls_hm_dbg(("	hm_node_params.type = %d (unspecified)\n",
			pcurrent->params.type));
		break;
	}
	dpa_cls_hm_dbg(("	hm_node_params.h_NextManip = 0x%p\n",
		pcurrent->params.h_NextManip));
	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): End of HM node params.\n",
		__func__, __LINE__));
#endif /* DPA_HM_DEBUG */
	if (!pcurrent->node) {
		pcurrent->node = (void *) FM_PCD_ManipNodeSet(
							(t_Handle) fm_pcd,
							&pcurrent->params);
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): CREATE new HM "
			"node (h_node=0x%p).\n", __func__, __LINE__,
			pcurrent->node));
		if (!pcurrent->node) {
			log_err("FMan driver call failed - "
				"FM_PCD_ManipNodeSet. Failed to initialize low "
				"level HM #%d from this chain.\n", index);
			err = -EBUSY;
		}

		pcurrent->flags |= DPA_CLS_HM_NODE_INTERNAL;

		num_int_nodes++;
	} else { /* This can be either a STATIC node or an IMPORTED node */
		if (num_int_nodes) {
			/*
			 * When working with header manipulation chains that are
			 * half created / half imported, the imported or static
			 * nodes MUST always be LAST in chain. Rechaining low
			 * level header manipulation nodes that are already
			 * initialized is not possible.
			 */
			log_err("Unsupported hybrid header manipulation chain. "
				"The imported/static HM ops must be LAST in "
				"chain.\n");
			return -EINVAL;
		}
		/* For STATIC HM ops we don't need to do anything here */
		if (pcurrent->params.type != -1) {
			/* Imported HM - need to sync with an existing node */
			dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): REPLACE "
				"existing HM node (h_node=0x%p).\n", __func__,
				__LINE__, pcurrent->node));

			/*
			 * Have to make a copy of the manip node params because
			 * ManipNodeReplace does not accept h_NextManip != NULL.
			 */
			memcpy(&params, &pcurrent->params, sizeof(params));
			params.h_NextManip = NULL;
			error = FM_PCD_ManipNodeReplace(pcurrent->node,
							&params);
			if (error != E_OK) {
				log_err("FMan driver call failed - "
					"FM_PCD_ManipNodeReplace. Failed to "
					"initialize low level HM #%d "
					"from this chain.\n", index);
				err = -EBUSY;
			}
		}
	}

	index--;
	return err;
}

int remove_hm_chain(struct list_head *chain_head, struct list_head *item)
{
	int err = 0;
	struct dpa_cls_hm_node *pcurrent;
	t_Error error;
	static int index = 0;

	BUG_ON(!chain_head);
	BUG_ON(!item);

	index++;
	/* Remove the current node: */
	pcurrent = list_entry(item, struct dpa_cls_hm_node, list_node);

	if ((pcurrent->flags & DPA_CLS_HM_NODE_INTERNAL) && (pcurrent->node)) {
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Removing manip node 0x%p\n",
			__func__, __LINE__, pcurrent->node));
		error = FM_PCD_ManipNodeDelete((t_Handle) pcurrent->node);
		if (error != E_OK) {
			log_warn("Memory leak: failed to remove low "
				"level HM #%d from this chain. Manip node "
				"handle=0x%p.\n", index, pcurrent->node);
			log_warn("FMan driver call failed - "
				"FM_PCD_ManipNodeDelete.\n");
		}
	}

	if (item->next != chain_head) {
		/* Remove the rest of the HM chain */
		err = remove_hm_chain(chain_head, item->next);
		if (err < 0)
			return err;
	}

	list_del(item);

	remove_hm_node(pcurrent);

	index--;

	return err;
}

static void remove_hm_node(struct dpa_cls_hm_node *node)
{
	/* Check and remove all allocated buffers from the HM params: */
	switch (node->params.type) {
	case e_FM_PCD_MANIP_HDR:
		if ((node->params.u.hdr.insrt) &&
				(node->params.u.hdr.insrtParams.type ==
				e_FM_PCD_MANIP_INSRT_GENERIC))
			kfree(node->params.u.hdr.insrtParams.u.generic.p_Data);

		break;
	default:
		break;
	}

	/* Remove the node */
	kfree(node);
}

static int create_new_hm_op(int *hmd, int next_hmd)
{
	int err;
	struct dpa_cls_hm *hm;
	struct dpa_cls_hm *next_hm, *pcurrent;

	BUG_ON(!hmd);

	*hmd = DPA_OFFLD_DESC_NONE;

	/* Allocate header manipulation object */
	hm = kzalloc(sizeof(struct dpa_cls_hm), GFP_KERNEL);
	if (!hm) {
		log_err("No more memory for header manip ops.\n");
		return -ENOMEM;
	}

	lock_desc_table(&hm_array);
	err = acquire_descriptor(&hm_array, hm, hmd);
	if (err < 0) {
		release_desc_table(&hm_array);
		return err;
	}

	INIT_LIST_HEAD(&hm->list_node);

	mutex_init(&hm->access);
	mutex_lock(&hm->access);

	if (next_hmd != DPA_OFFLD_DESC_NONE) {
		/* Check whether [next_hmd] is a valid descriptor */
		if ((next_hmd < 0) || (next_hmd >= hm_array.num_descriptors)) {
			release_desc_table(&hm_array);
			log_err("Invalid next HM descriptor (next_hmd=%d). "
				"Should be between %d and %d.\n",
				next_hmd, 0, hm_array.num_descriptors-1);
			return -EINVAL;
		}
		next_hm = (struct dpa_cls_hm *)hm_array.object[next_hmd];
		if (!next_hm) {
			release_desc_table(&hm_array);
			log_err("Link to an invalid HM (next_hmd=%d).\n",
				next_hmd);
			return -EINVAL;
		}

		/* Lock entire high level HM op chain */
		LOCK_HM_OP_CHAIN(next_hm);
		release_desc_table(&hm_array);

		/*
		 * In case this high level op is chained with another high
		 * level op, add it to the list.
		 */

		list_add_tail(&hm->list_node, &next_hm->list_node);

		hm->hm_chain = next_hm->hm_chain;
	} else { /* Isolated header manip op, or first in chain. */
		hm->hm_chain = kmalloc(sizeof(struct list_head), GFP_KERNEL);
		if (!hm->hm_chain) {
			remove_hm_op(*hmd);
			release_desc_table(&hm_array);
			log_err("No more memory for header manip ops.\n");
			*hmd = DPA_OFFLD_DESC_NONE;
			return -ENOMEM;
		}
		release_desc_table(&hm_array);

		INIT_LIST_HEAD(hm->hm_chain);
	}

	return err;
}

static void remove_hm_op(int hmd)
{
	struct dpa_cls_hm *phm, *pcurrent, *pnext;

	BUG_ON((hmd < 0) || (hmd >= hm_array.num_descriptors));

	phm = (struct dpa_cls_hm *) hm_array.object[hmd];

	if (!phm) {
		/* Descriptor already free. Nothing to do */
		return;
	}

	if (list_empty(&phm->list_node))
		kfree(phm->hm_chain);
	else {
		LOCK_HM_OP_CHAIN(phm);

		pnext = list_entry(phm->list_node.next,
					struct dpa_cls_hm,
					list_node);
		/* If this op is attached to others, detach it from the list */
		list_del(&phm->list_node);

		RELEASE_HM_OP_CHAIN(pnext);
	}

	put_descriptor(&hm_array, hmd);

	kfree(phm);
}

int dpa_classif_set_nat_hm(const struct dpa_cls_hm_nat_params	*nat_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_nat_resources	*res)
{
	int err;
	struct dpa_cls_hm *pnat_hm, *pcurrent;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!nat_params) {
		log_err("\"nat_params\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!hmd) {
		log_err("\"hmd\" cannot be NULL.\n");
		return -EINVAL;
	}

	*hmd = DPA_OFFLD_DESC_NONE;

	err = nat_hm_check_params(nat_params);
	if (err < 0) {
		log_err("Invalid NAT HM parameters.\n");
		return err;
	}

	err = create_new_hm_op(hmd, next_hmd);
	if (err < 0) {
		log_err("Failed to create NAT HM op.\n");
		return err;
	}

	pnat_hm = (struct dpa_cls_hm *) hm_array.object[*hmd];

	pnat_hm->type		= DPA_CLS_HM_TYPE_NAT;
	pnat_hm->chain_head	= chain_head;

	/* Copy the NAT parameters locally */
	memcpy(&pnat_hm->nat_params, nat_params, sizeof(*nat_params));

	err = nat_hm_prepare_nodes(pnat_hm, res);
	if (err < 0) {
		log_err("Failed to acquire necessary HM nodes.\n");
		goto nat_hm_error;
	}

	err = nat_hm_update_params(pnat_hm);
	if (err < 0) {
		log_err("Failed to update low level header manipulation "
			"parameters.\n");
		goto nat_hm_error;
	}

	if (chain_head) {
		err = init_hm_chain(pnat_hm->nat_params.fm_pcd,
				pnat_hm->hm_chain,
				pnat_hm->hm_chain->next);
		if (err < 0)
			log_err("Failed to initialize low level HM chain.\n");
	}

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pnat_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;

nat_hm_error:

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pnat_hm);

	lock_desc_table(&hm_array);
	remove_hm_op(*hmd);
	release_desc_table(&hm_array);

	*hmd = DPA_OFFLD_DESC_NONE;

	return err;
}
EXPORT_SYMBOL(dpa_classif_set_nat_hm);

static int nat_hm_prepare_nodes(struct dpa_cls_hm *pnat_hm,
				const struct dpa_cls_hm_nat_resources *res)
{
	struct dpa_cls_hm_node *hm_node = NULL;
	void * const *phm_nodes;
	int err = 0;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pnat_hm);

	pnat_hm->num_nodes = 2;

	if (res) { /* Import HM nodes */
		phm_nodes = &res->l3_update_node;

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
			__LINE__));

		return import_hm_nodes_to_chain(phm_nodes,
					pnat_hm->num_nodes,
					pnat_hm);
	}

	/* Create a header manip node for this update: */
	hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n",
		__func__, __LINE__, hm_node));
	if (!hm_node) {
		log_err("No more memory for header manip nodes.\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&hm_node->list_node);

	/* Initialize dontParseAfterManip to TRUE */
	hm_node->params.u.hdr.dontParseAfterManip = TRUE;

	pnat_hm->hm_node[0] = hm_node;

	if (pnat_hm->nat_params.flags &
		(DPA_CLS_HM_NAT_UPDATE_SPORT | DPA_CLS_HM_NAT_UPDATE_DPORT)) {
		hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n",
			__func__, __LINE__, hm_node));
		if (!hm_node) {
			log_err("No more memory for header manip nodes.\n");
			return -ENOMEM;
		}

		INIT_LIST_HEAD(&hm_node->list_node);

		/* Initialize dontParseAfterManip to TRUE */
		hm_node->params.u.hdr.dontParseAfterManip = TRUE;

		pnat_hm->hm_node[1] = hm_node;
	}

	add_local_hm_nodes_to_chain(pnat_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}

static int nat_hm_update_params(struct dpa_cls_hm *pnat_hm)
{
	struct dpa_cls_hm_node *hm_node;
	unsigned int ip_ver = 0;

	BUG_ON(!pnat_hm);
	BUG_ON(pnat_hm->num_nodes < 1);
	BUG_ON(pnat_hm->num_nodes > 2);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	if (pnat_hm->hm_node[0]) {
		hm_node = pnat_hm->hm_node[0];

		hm_node->params.type = e_FM_PCD_MANIP_HDR;
		if (pnat_hm->hm_node[1])
			hm_node->params.u.hdr.dontParseAfterManip = TRUE;
		else
			hm_node->params.u.hdr.dontParseAfterManip &=
					(pnat_hm->nat_params.reparse) ? FALSE :
						TRUE;

		if (pnat_hm->nat_params.type ==
					DPA_CLS_HM_NAT_TYPE_TRADITIONAL) {
			hm_node->params.u.hdr.fieldUpdate = TRUE;

			if (pnat_hm->nat_params.flags &
				DPA_CLS_HM_NAT_UPDATE_SIP)
				ip_ver = pnat_hm->nat_params.nat.sip.version;
			if (pnat_hm->nat_params.flags &
				DPA_CLS_HM_NAT_UPDATE_DIP)
				ip_ver = pnat_hm->nat_params.nat.dip.version;

			if (ip_ver == 4) {
				hm_node->params.u.hdr.fieldUpdateParams.type =
					e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV4;

				if (pnat_hm->nat_params.flags &
						DPA_CLS_HM_NAT_UPDATE_SIP) {
					hm_node->params.u.hdr.
						fieldUpdateParams.u.ipv4.
						validUpdates |=
						HDR_MANIP_IPV4_SRC;
					hm_node->params.u.hdr.
						fieldUpdateParams.u.ipv4.
						src =
					be32_to_cpu(pnat_hm->nat_params.nat.
						sip.addr.ipv4.word);
				}

				if (pnat_hm->nat_params.flags &
						DPA_CLS_HM_NAT_UPDATE_DIP) {
					hm_node->params.u.hdr.
						fieldUpdateParams.u.ipv4.
						validUpdates |=
						HDR_MANIP_IPV4_DST;
					hm_node->params.u.hdr.
						fieldUpdateParams.u.ipv4.
						dst =
					be32_to_cpu(pnat_hm->nat_params.nat.
						dip.addr.ipv4.word);
				}
			} else { /* We're dealing with IPv6 */
				hm_node->params.u.hdr.fieldUpdateParams.type =
					e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV6;

				if (pnat_hm->nat_params.flags &
						DPA_CLS_HM_NAT_UPDATE_SIP) {
					hm_node->params.u.hdr.
						fieldUpdateParams.u.ipv6.
						validUpdates |=
						HDR_MANIP_IPV6_SRC;
					memcpy(hm_node->params.u.hdr.
						fieldUpdateParams.u.ipv6.src,
						pnat_hm->nat_params.nat.sip.
						addr.ipv6.byte,
						DPA_OFFLD_IPv6_ADDR_LEN_BYTES);
				}

				if (pnat_hm->nat_params.flags &
						DPA_CLS_HM_NAT_UPDATE_DIP) {
					hm_node->params.u.hdr.
						fieldUpdateParams.u.ipv4.
						validUpdates |=
						HDR_MANIP_IPV6_DST;
					memcpy(hm_node->params.u.hdr.
						fieldUpdateParams.u.ipv6.dst,
						pnat_hm->nat_params.nat.dip.
						addr.ipv6.byte,
						DPA_OFFLD_IPv6_ADDR_LEN_BYTES);
				}
			}
		} else { /* NAT-PT */
			hm_node->params.u.hdr.custom = TRUE;
			hm_node->params.u.hdr.customParams.type =
					e_FM_PCD_MANIP_HDR_CUSTOM_IP_REPLACE;

			if (pnat_hm->nat_params.nat_pt.type ==
					DPA_CLS_HM_NAT_PT_IPv6_TO_IPv4) {
				hm_node->params.u.hdr.customParams.u.
					ipHdrReplace.replaceType =
			e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV6_BY_IPV4;
				hm_node->params.u.hdr.customParams.u.
					ipHdrReplace.hdrSize =
						sizeof(struct iphdr) +
			pnat_hm->nat_params.nat_pt.new_header.ipv4.options_size;
				memcpy(hm_node->params.u.hdr.customParams.u.
					ipHdrReplace.hdr,
					&pnat_hm->nat_params.nat_pt.new_header.
					ipv4.header, sizeof(struct iphdr));
	if ((pnat_hm->nat_params.nat_pt.new_header.ipv4.options_size)
		&& (pnat_hm->nat_params.nat_pt.new_header.ipv4.options)) {
		memcpy(&hm_node->params.u.hdr.customParams.u.ipHdrReplace.
				hdr[sizeof(struct iphdr)],
			&pnat_hm->nat_params.nat_pt.new_header.ipv4.options,
		pnat_hm->nat_params.nat_pt.new_header.ipv4.options_size);
	}
			} else {
				hm_node->params.u.hdr.customParams.u.
					ipHdrReplace.replaceType =
			e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV4_BY_IPV6;
				hm_node->params.u.hdr.customParams.u.
					ipHdrReplace.hdrSize =
					(uint8_t)sizeof(struct ipv6_header);
				memcpy(hm_node->params.u.hdr.customParams.u.
					ipHdrReplace.hdr,
					&pnat_hm->nat_params.nat_pt.new_header.
					ipv6, sizeof(struct ipv6_header));
			}
		}
	}

	if (pnat_hm->hm_node[1]) {
		hm_node = pnat_hm->hm_node[1];

		hm_node->params.type			= e_FM_PCD_MANIP_HDR;
		hm_node->params.u.hdr.fieldUpdate	= TRUE;
		hm_node->params.u.hdr.fieldUpdateParams.type =
				e_FM_PCD_MANIP_HDR_FIELD_UPDATE_TCP_UDP;

		hm_node->params.u.hdr.dontParseAfterManip &=
				(pnat_hm->nat_params.reparse) ? FALSE : TRUE;

		if (pnat_hm->nat_params.flags & DPA_CLS_HM_NAT_UPDATE_SPORT) {
			hm_node->params.u.hdr.fieldUpdateParams.u.tcpUdp.
				validUpdates |= HDR_MANIP_TCP_UDP_SRC;
			hm_node->params.u.hdr.fieldUpdateParams.u.tcpUdp.src =
				pnat_hm->nat_params.sport;
		}

		if (pnat_hm->nat_params.flags & DPA_CLS_HM_NAT_UPDATE_DPORT) {
			hm_node->params.u.hdr.fieldUpdateParams.u.tcpUdp.
				validUpdates |= HDR_MANIP_TCP_UDP_DST;
			hm_node->params.u.hdr.fieldUpdateParams.u.tcpUdp.dst =
				pnat_hm->nat_params.dport;
		}
	}

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_nat_hm(int hmd,
	const struct dpa_cls_hm_nat_params *new_nat_params, int modify_flags)
{
	struct dpa_cls_hm_node *hm_node;
	struct dpa_cls_hm *pnat_hm;
	bool update[2] = { false, false };
	t_Error error;
	int ret = 0;
	int i;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	if (!modify_flags)
		/* Nothing to do */
		return 0;

	/* Parameters sanity checks: */
	if (!new_nat_params) {
		log_err("\"new_nat_params\" cannot be NULL.\n");
		return -EINVAL;
	}

	lock_desc_table(&hm_array);
	pnat_hm = desc_to_object(&hm_array, hmd);
	if (!pnat_hm) {
		release_desc_table(&hm_array);
		log_err("Invalid descriptor (%d).\n", hmd);
		return -EINVAL;
	}
	mutex_lock(&pnat_hm->access);
	/*
	 * Hold the lock on the descriptor table to prevent other runtime
	 * modifications of header manipulations until we're finished. The FMan
	 * driver doesn't allow parallel modification of HM nodes when they
	 * belong to the same PCD.
	 */

	if (pnat_hm->type != DPA_CLS_HM_TYPE_NAT) {
		release_desc_table(&hm_array);
		mutex_unlock(&pnat_hm->access);
		log_err("hmd=%d is not an NAT type header manip.\n", hmd);
		return -EINVAL;
	}

	if (pnat_hm->nat_params.type == DPA_CLS_HM_NAT_TYPE_TRADITIONAL) {
		if (modify_flags & DPA_CLS_HM_NAT_MOD_SIP) {
			if (new_nat_params->nat.sip.version !=
					pnat_hm->nat_params.nat.sip.version) {
				release_desc_table(&hm_array);
				mutex_unlock(&pnat_hm->access);
				log_err("New SIP adress version (%d) in NAT "
					"header manipulation hmd=%d cannot be "
					"different from the old one (%d).\n",
					new_nat_params->nat.sip.version, hmd,
					pnat_hm->nat_params.nat.sip.version);
				return -EINVAL;
			}
			update[0] = true;
			memcpy(&pnat_hm->nat_params.nat.sip,
				&new_nat_params->nat.sip,
				sizeof(struct dpa_offload_ip_address));
		}

		if (modify_flags & DPA_CLS_HM_NAT_MOD_DIP) {
			if (new_nat_params->nat.dip.version !=
					pnat_hm->nat_params.nat.dip.version) {
				release_desc_table(&hm_array);
				mutex_unlock(&pnat_hm->access);
				log_err("New DIP adress version (%d) in NAT "
					"header manipulation hmd=%d cannot be "
					"different from the old one (%d).\n",
					new_nat_params->nat.dip.version, hmd,
					pnat_hm->nat_params.nat.dip.version);
				return -EINVAL;
			}
			update[0] = true;
			memcpy(&pnat_hm->nat_params.nat.dip,
				&new_nat_params->nat.dip,
				sizeof(struct dpa_offload_ip_address));
		}
	} else { /* NAT-PT */
		if (modify_flags & DPA_CLS_HM_NAT_MOD_IP_HDR) {
			if (pnat_hm->nat_params.nat_pt.type ==
					DPA_CLS_HM_NAT_PT_IPv6_TO_IPv4) {
				memcpy(&pnat_hm->nat_params.nat_pt.new_header.
					ipv4.header, &new_nat_params->nat_pt.
					new_header.ipv4.header,
					sizeof(struct iphdr));
				/* Update IPv4 options */
				kfree(pnat_hm->nat_params.nat_pt.new_header.
								ipv4.options);
				if (new_nat_params->nat_pt.new_header.ipv4.
								options_size) {
					pnat_hm->nat_params.nat_pt.new_header.
						ipv4.options = kzalloc(
						new_nat_params->nat_pt.
						new_header.ipv4.options_size,
						GFP_KERNEL);
					if (!pnat_hm->update_params.replace.
						new_ipv4_hdr.options) {
						pnat_hm->nat_params.nat_pt.
							new_header.ipv4.
							options_size = 0;
						release_desc_table(&hm_array);
						mutex_unlock(&pnat_hm->access);
						log_err("Out of memory while "
							"modifying IPv6 header "
							"replace header "
							"manipulation "
							"hmd=%d.\n", hmd);
						return -EINVAL;
					}
				} else
					pnat_hm->nat_params.nat_pt.new_header.
						ipv4.options = NULL;
				pnat_hm->nat_params.nat_pt.new_header.ipv4.
					options_size = new_nat_params->nat_pt.
					new_header.ipv4.options_size;
			} else { /* DPA_CLS_HM_NAT_PT_IPv4_TO_IPv6 */
				memcpy(&pnat_hm->nat_params.nat_pt.new_header.
					ipv6, &new_nat_params->nat_pt.
					new_header.ipv6,
					sizeof(struct ipv6_header));
			}
			update[0] = true;
		}
	}

	if ((modify_flags & DPA_CLS_HM_NAT_MOD_SPORT) &&
			(new_nat_params->sport != pnat_hm->nat_params.sport)) {
		update[1] = true;
		pnat_hm->nat_params.sport = new_nat_params->sport;
	}

	if ((modify_flags & DPA_CLS_HM_NAT_MOD_DPORT) &&
		(new_nat_params->dport != pnat_hm->nat_params.dport)) {
		update[1] = true;
		pnat_hm->nat_params.dport = new_nat_params->dport;
	}

	if ((modify_flags & DPA_CLS_HM_NAT_MOD_FLAGS) &&
		(new_nat_params->flags != pnat_hm->nat_params.flags)) {
		update[0] = true;
		update[1] = true;
		pnat_hm->nat_params.flags = new_nat_params->flags;
	}

	if (update[0] || update[1]) {
		ret = nat_hm_update_params(pnat_hm);
		if (ret == 0) {
			t_FmPcdManipParams new_hm_node_params;

			for (i = 0; i < 2; i++) {
				if (!update[i])
					continue;

				hm_node = pnat_hm->hm_node[i];
				memcpy(&new_hm_node_params,
					&hm_node->params,
					sizeof(t_FmPcdManipParams));
				/*
				 * Must make sure that h_NextManip is NULL
				 * before calling FM_PCD_ManipNodeReplace
				 */
				new_hm_node_params.h_NextManip = NULL;

				error = FM_PCD_ManipNodeReplace(hm_node->node,
							&new_hm_node_params);
				if (error != E_OK) {
					release_desc_table(&hm_array);
					mutex_unlock(&pnat_hm->access);
					log_err("FMan driver call failed - "
						"FM_PCD_ManipNodeReplace, "
						"while trying to modify "
						"hmd=%d, manip node "
						"handle=0x%p (node #%d).\n",
						hmd, hm_node->node, i);
					return -EBUSY;
				}
			}
		}
	}

	release_desc_table(&hm_array);
	mutex_unlock(&pnat_hm->access);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}
EXPORT_SYMBOL(dpa_classif_modify_nat_hm);

int dpa_classif_set_fwd_hm(const struct dpa_cls_hm_fwd_params	*fwd_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_fwd_resources	*res)
{
	int err;
	struct dpa_cls_hm *pfwd_hm, *pcurrent;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!fwd_params) {
		log_err("\"fwd_params\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!hmd) {
		log_err("\"hmd\" cannot be NULL.\n");
		return -EINVAL;
	}

	*hmd = DPA_OFFLD_DESC_NONE;

	err = fwd_hm_check_params(fwd_params);
	if (err < 0) {
		log_err("Invalid forwarding HM parameters.\n");
		return err;
	}

	err = create_new_hm_op(hmd, next_hmd);
	if (err < 0) {
		log_err("Failed to create forwarding HM op.\n");
		return err;
	}

	pfwd_hm = (struct dpa_cls_hm *) hm_array.object[*hmd];

	pfwd_hm->type		= DPA_CLS_HM_TYPE_FORWARDING;
	pfwd_hm->chain_head	= chain_head;

	/* Copy the NAT parameters locally */
	memcpy(&pfwd_hm->fwd_params, fwd_params, sizeof(*fwd_params));

	err = fwd_hm_prepare_nodes(pfwd_hm, res);
	if (err < 0) {
		log_err("Failed to acquire necessary HM nodes.\n");
		goto fwd_hm_error;
	}

	err = fwd_hm_update_params(pfwd_hm);
	if (err < 0) {
		log_err("Failed to update low level header manipulation "
			"parameters.\n");
		goto fwd_hm_error;
	}

	if (chain_head) {
		err = init_hm_chain(pfwd_hm->fwd_params.fm_pcd,
				pfwd_hm->hm_chain,
				pfwd_hm->hm_chain->next);
		if (err < 0)
			log_err("Failed to initialize low level HM chain.\n");
	}

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pfwd_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;

fwd_hm_error:

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pfwd_hm);

	lock_desc_table(&hm_array);
	remove_hm_op(*hmd);
	release_desc_table(&hm_array);

	*hmd = DPA_OFFLD_DESC_NONE;

	return err;
}
EXPORT_SYMBOL(dpa_classif_set_fwd_hm);

static int fwd_hm_prepare_nodes(struct dpa_cls_hm *pfwd_hm,
				const struct dpa_cls_hm_fwd_resources *res)
{
	struct dpa_cls_hm_node *hm_node;
	void * const *phm_nodes;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pfwd_hm);

	pfwd_hm->num_nodes = 3;

	if (res) { /* Import HM nodes */
		phm_nodes = &res->fwd_node;

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
			__LINE__));

		return import_hm_nodes_to_chain(phm_nodes,
					pfwd_hm->num_nodes,
					pfwd_hm);
	}

	/* Create a header manip node: */
	hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n", __func__,
		__LINE__, hm_node));
	if (!hm_node) {
		log_err("No more memory for header manip nodes.\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&hm_node->list_node);

	/* Initialize dontParseAfterManip to TRUE */
	hm_node->params.u.hdr.dontParseAfterManip = TRUE;

	pfwd_hm->hm_node[0] = hm_node;

	if (pfwd_hm->update_params.ip_frag_params.mtu) {
		/* IP fragmentation option is enabled */
		/* Create a header manip node: */
		hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n", __func__,
			__LINE__, hm_node));
		if (!hm_node) {
			log_err("No more memory for header manip nodes.\n");
			return -ENOMEM;
		}

		INIT_LIST_HEAD(&hm_node->list_node);
		pfwd_hm->hm_node[1] = hm_node;
	}

	add_local_hm_nodes_to_chain(pfwd_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

static int fwd_hm_update_params(struct dpa_cls_hm *pfwd_hm)
{
	struct dpa_cls_hm_node *hm_node;
	uint8_t size;
	uint8_t *pdata;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pfwd_hm);
	BUG_ON(pfwd_hm->num_nodes < 1);
	BUG_ON(!pfwd_hm->hm_node[0]);

	hm_node = pfwd_hm->hm_node[0];

	hm_node->params.type = e_FM_PCD_MANIP_HDR;
	hm_node->params.u.hdr.dontParseAfterManip &=
			(pfwd_hm->fwd_params.reparse) ? FALSE : TRUE;

	switch (pfwd_hm->fwd_params.out_if_type) {
	case DPA_CLS_HM_IF_TYPE_ETHERNET:
		/* Update Ethernet MACS */
		hm_node->params.u.hdr.insrt		= TRUE;
		hm_node->params.u.hdr.insrtParams.type	=
						e_FM_PCD_MANIP_INSRT_GENERIC;
		hm_node->params.u.hdr.insrtParams.u.generic.replace = TRUE;

		size = (uint8_t)(sizeof(struct ethhdr) - ETHERTYPE_SIZE);
		pdata = kzalloc(size, GFP_KERNEL);
		if (!pdata) {
			log_err("Not enough memory for forwarding HM.\n");
			return -ENOMEM;
		}

		memcpy(pdata, pfwd_hm->fwd_params.eth.macda, ETH_ALEN);
		memcpy(&pdata[ETH_ALEN], pfwd_hm->fwd_params.eth.macsa,
			ETH_ALEN);

		kfree(hm_node->params.u.hdr.insrtParams.u.generic.p_Data);

		hm_node->params.u.hdr.insrtParams.u.generic.offset	= 0;
		hm_node->params.u.hdr.insrtParams.u.generic.size	= size;
		hm_node->params.u.hdr.insrtParams.u.generic.p_Data	= pdata;
	case DPA_CLS_HM_IF_TYPE_PPPoE:
		/* Update Ethernet MACS; insert PPPoE */
		/* Insert PPPoE is not supported yet */
		break;
	case DPA_CLS_HM_IF_TYPE_PPP:
		/* Remove Ethernet and VLANs; insert PPP */
		hm_node->params.u.hdr.rmv		= TRUE;
		hm_node->params.u.hdr.rmvParams.type	=
					e_FM_PCD_MANIP_RMV_BY_HDR;
		hm_node->params.u.hdr.rmvParams.u.byHdr.type =
					e_FM_PCD_MANIP_RMV_BY_HDR_SPECIFIC_L2;
		hm_node->params.u.hdr.rmvParams.u.byHdr.u.specificL2 =
					e_FM_PCD_MANIP_HDR_RMV_ETHERNET;

		hm_node->params.u.hdr.insrt		= TRUE;
		hm_node->params.u.hdr.insrtParams.type	=
					e_FM_PCD_MANIP_INSRT_GENERIC;

		size	= PPP_HEADER_SIZE;
		pdata	= kzalloc(size, GFP_KERNEL);
		if (!pdata) {
			log_err("Not enough memory for forwarding HM.\n");
			return -ENOMEM;
		}

		memcpy(pdata, &pfwd_hm->fwd_params.ppp.ppp_pid,
			PPP_HEADER_SIZE);

		kfree(hm_node->params.u.hdr.insrtParams.u.generic.p_Data);

		hm_node->params.u.hdr.insrtParams.u.generic.offset	= 0;
		hm_node->params.u.hdr.insrtParams.u.generic.size	= size;
		hm_node->params.u.hdr.insrtParams.u.generic.p_Data	= pdata;
		break;
	default:
		log_err("Forwarding HM: Unknown output port type (%d).\n",
			pfwd_hm->fwd_params.out_if_type);
		return -EINVAL;
	}

	hm_node = pfwd_hm->hm_node[1];

	if (pfwd_hm->fwd_params.ip_frag_params.mtu) {
		/* IP fragmentation option is enabled */
		BUG_ON(!hm_node);

		hm_node->params.type = e_FM_PCD_MANIP_FRAG;
		hm_node->params.u.frag.hdr = HEADER_TYPE_IPv4;
		hm_node->params.u.frag.u.ipFrag.sizeForFragmentation =
				pfwd_hm->fwd_params.ip_frag_params.mtu;
#if (DPAA_VERSION == 10)
		hm_node->params.u.frag.u.ipFrag.scratchBpid =
				pfwd_hm->fwd_params.ip_frag_params.
					scratch_bpid;
#endif /* (DPAA_VERSION == 10) */
		switch (pfwd_hm->fwd_params.ip_frag_params.df_action) {
		case DPA_CLS_HM_DF_ACTION_FRAG_ANYWAY:
			hm_node->params.u.frag.u.ipFrag.dontFragAction =
					e_FM_PCD_MANIP_FRAGMENT_PACKET;
			break;
		case DPA_CLS_HM_DF_ACTION_DONT_FRAG:
			hm_node->params.u.frag.u.ipFrag.dontFragAction =
					e_FM_PCD_MANIP_CONTINUE_WITHOUT_FRAG;
			break;
		case DPA_CLS_HM_DF_ACTION_DROP:
			hm_node->params.u.frag.u.ipFrag.dontFragAction =
				e_FM_PCD_MANIP_ENQ_TO_ERR_Q_OR_DISCARD_PACKET;
			break;
		}
	}

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_fwd_hm(int hmd,
	const struct dpa_cls_hm_fwd_params *new_fwd_params, int modify_flags)
{
	struct dpa_cls_hm_node *hm_node;
	struct dpa_cls_hm *pfwd_hm;
	bool update[3] = { false, false, false };
	t_Error error;
	int ret = 0;
	int i;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	if (!modify_flags)
		/* Nothing to do */
		return 0;

	/* Parameters sanity checks: */
	if (!new_fwd_params) {
		log_err("\"new_fwd_params\" cannot be NULL.\n");
		return -EINVAL;
	}

	lock_desc_table(&hm_array);
	pfwd_hm = desc_to_object(&hm_array, hmd);
	if (!pfwd_hm) {
		release_desc_table(&hm_array);
		log_err("Invalid descriptor (%d).\n", hmd);
		return -EINVAL;
	}
	mutex_lock(&pfwd_hm->access);
	/*
	 * Hold the lock on the descriptor table to prevent other runtime
	 * modifications of header manipulations until we're finished. The FMan
	 * driver doesn't allow parallel modification of HM nodes when they
	 * belong to the same PCD.
	 */

	if (pfwd_hm->type != DPA_CLS_HM_TYPE_FORWARDING) {
		release_desc_table(&hm_array);
		mutex_unlock(&pfwd_hm->access);
		log_err("hmd=%d is not an FORWARDING type header manip.\n",
			hmd);
		return -EINVAL;
	}

	if (modify_flags & DPA_CLS_HM_FWD_MOD_ETH_MACSA) {
		if (pfwd_hm->fwd_params.out_if_type ==
						DPA_CLS_HM_IF_TYPE_PPPoE) {
			memcpy(pfwd_hm->fwd_params.pppoe.l2.macsa,
				new_fwd_params->pppoe.l2.macsa,
				ETH_ALEN);
			update[0] = true;
		}

		if (pfwd_hm->fwd_params.out_if_type ==
						DPA_CLS_HM_IF_TYPE_ETHERNET) {
			memcpy(pfwd_hm->fwd_params.eth.macsa,
				new_fwd_params->eth.macsa,
				ETH_ALEN);
			update[0] = true;
		}
	}

	if (modify_flags & DPA_CLS_HM_FWD_MOD_ETH_MACDA) {
		if (pfwd_hm->fwd_params.out_if_type ==
						DPA_CLS_HM_IF_TYPE_PPPoE) {
			memcpy(pfwd_hm->fwd_params.pppoe.l2.macda,
				new_fwd_params->pppoe.l2.macda,
				ETH_ALEN);
			update[0] = true;
		}

		if (pfwd_hm->fwd_params.out_if_type ==
						DPA_CLS_HM_IF_TYPE_ETHERNET) {
			memcpy(pfwd_hm->fwd_params.eth.macda,
				new_fwd_params->eth.macda,
				ETH_ALEN);
			update[0] = true;
		}
	}

	if ((modify_flags & DPA_CLS_HM_FWD_MOD_PPPoE_HEADER) &&
		(pfwd_hm->fwd_params.out_if_type == DPA_CLS_HM_IF_TYPE_PPPoE)) {
		update[1] = true;
		memcpy(&pfwd_hm->fwd_params.pppoe.pppoe_header,
			&new_fwd_params->pppoe.pppoe_header,
			sizeof(struct pppoe_header));
	}

	if ((modify_flags & DPA_CLS_HM_FWD_MOD_PPP_PID) &&
		(pfwd_hm->fwd_params.out_if_type == DPA_CLS_HM_IF_TYPE_PPP) &&
		(pfwd_hm->fwd_params.ppp.ppp_pid !=
						new_fwd_params->ppp.ppp_pid)) {
		update[0] = true;
		pfwd_hm->fwd_params.ppp.ppp_pid = new_fwd_params->ppp.ppp_pid;
	}

	if (pfwd_hm->fwd_params.ip_frag_params.mtu) {
		if ((modify_flags & DPA_CLS_HM_FWD_MOD_IP_FRAG_MTU) &&
			(pfwd_hm->fwd_params.ip_frag_params.mtu !=
					new_fwd_params->ip_frag_params.mtu)) {
			pfwd_hm->fwd_params.ip_frag_params.mtu =
					new_fwd_params->ip_frag_params.mtu;
			update[2] = true;
		}

		if ((modify_flags & DPA_CLS_HM_FWD_MOD_IP_FRAG_SCRATCH_BPID) &&
			(pfwd_hm->fwd_params.ip_frag_params.scratch_bpid !=
				new_fwd_params->ip_frag_params.scratch_bpid)) {
			pfwd_hm->fwd_params.ip_frag_params.scratch_bpid =
				new_fwd_params->ip_frag_params.scratch_bpid;
			update[2] = true;
		}

		if ((modify_flags & DPA_CLS_HM_FWD_MOD_IP_FRAG_DF_ACTION) &&
			(pfwd_hm->fwd_params.ip_frag_params.df_action !=
				new_fwd_params->ip_frag_params.df_action)) {
			pfwd_hm->fwd_params.ip_frag_params.df_action =
				new_fwd_params->ip_frag_params.df_action;
			update[2] = true;
		}
	}

	if (update[0] || update[1] || update[2]) {
		ret = fwd_hm_update_params(pfwd_hm);
		if (ret == 0) {
			t_FmPcdManipParams new_hm_node_params;

			for (i = 0; i < 3; i++) {
				if (!update[i])
					continue;

				hm_node = pfwd_hm->hm_node[i];
				memcpy(&new_hm_node_params,
					&hm_node->params,
					sizeof(t_FmPcdManipParams));
				/*
				 * Must make sure that h_NextManip is NULL
				 * before calling FM_PCD_ManipNodeReplace
				 */
				new_hm_node_params.h_NextManip = NULL;
				error = FM_PCD_ManipNodeReplace(hm_node->node,
							&new_hm_node_params);
				if (error != E_OK) {
					release_desc_table(&hm_array);
					mutex_unlock(&pfwd_hm->access);
					log_err("FMan driver call failed - "
						"FM_PCD_ManipNodeReplace, "
						"while trying to modify "
						"hmd=%d, manip node "
						"handle=0x%p (node #%d).\n",
						hmd, hm_node->node, i);
					return -EBUSY;
				}
			}
		}
	}

	release_desc_table(&hm_array);
	mutex_unlock(&pfwd_hm->access);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}
EXPORT_SYMBOL(dpa_classif_modify_fwd_hm);

int dpa_classif_set_remove_hm(const struct dpa_cls_hm_remove_params
	*remove_params, int next_hmd, int *hmd, bool chain_head,
	const struct dpa_cls_hm_remove_resources *res)
{
	int err;
	struct dpa_cls_hm *premove_hm, *pcurrent;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!remove_params) {
		log_err("\"remove_params\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!hmd) {
		log_err("\"hmd\" cannot be NULL.\n");
		return -EINVAL;
	}

	*hmd = DPA_OFFLD_DESC_NONE;

	err = remove_hm_check_params(remove_params);
	if (err < 0) {
		log_err("Invalid remove HM parameters.\n");
		return err;
	}

	err = create_new_hm_op(hmd, next_hmd);
	if (err < 0) {
		log_err("Failed to create remove HM op.\n");
		return err;
	}

	premove_hm = (struct dpa_cls_hm *) hm_array.object[*hmd];

	premove_hm->type	= DPA_CLS_HM_TYPE_REMOVE;
	premove_hm->chain_head	= chain_head;

	/* Copy the remove HM parameters locally */
	memcpy(&premove_hm->remove_params, remove_params,
						sizeof(*remove_params));

	err = remove_hm_prepare_nodes(premove_hm, res);
	if (err < 0) {
		log_err("Failed to acquire necessary HM nodes.\n");
		goto remove_hm_error;
	}

	err = remove_hm_update_params(premove_hm);
	if (err < 0) {
		log_err("Failed to update low level header manipulation "
			"parameters.\n");
		goto remove_hm_error;
	}

	if (chain_head) {
		err = init_hm_chain(premove_hm->remove_params.fm_pcd,
				premove_hm->hm_chain,
				premove_hm->hm_chain->next);
		if (err < 0)
			log_err("Failed to initialize low level HM chain.\n");
	}

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(premove_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;

remove_hm_error:

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(premove_hm);

	lock_desc_table(&hm_array);
	remove_hm_op(*hmd);
	release_desc_table(&hm_array);

	*hmd = DPA_OFFLD_DESC_NONE;

	return err;
}
EXPORT_SYMBOL(dpa_classif_set_remove_hm);

static int remove_hm_prepare_nodes(struct dpa_cls_hm *premove_hm,
				const struct dpa_cls_hm_remove_resources *res)
{
	struct dpa_cls_hm_node *hm_node;
	void * const *phm_nodes;
	int err = 0;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!premove_hm);

	premove_hm->num_nodes = 1;

	if (res) { /* Import HM nodes */
		phm_nodes = &res->remove_node;

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
			__LINE__));

		return import_hm_nodes_to_chain(phm_nodes,
					premove_hm->num_nodes,
					premove_hm);
	}

	hm_node = try_compatible_node(premove_hm);
	if (hm_node == NULL) {
		/* Create a header manip node for this remove: */
		hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n", __func__,
			__LINE__, hm_node));
		if (!hm_node) {
			log_err("No more memory for header manip nodes.\n");
			return -ENOMEM;
		}

		INIT_LIST_HEAD(&hm_node->list_node);

		/* Initialize dontParseAfterManip to TRUE */
		hm_node->params.u.hdr.dontParseAfterManip = TRUE;
	}

	premove_hm->hm_node[0] = hm_node;

	add_local_hm_nodes_to_chain(premove_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}

static int remove_hm_update_params(struct dpa_cls_hm *premove_hm)
{
	struct dpa_cls_hm_node *hm_node;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!premove_hm);
	BUG_ON(premove_hm->num_nodes != 1);
	BUG_ON(!premove_hm->hm_node[0]);

	hm_node = premove_hm->hm_node[0];

	hm_node->params.type		= e_FM_PCD_MANIP_HDR;
	hm_node->params.u.hdr.rmv	= TRUE;

	hm_node->params.u.hdr.dontParseAfterManip &=
			(premove_hm->remove_params.reparse) ? FALSE : TRUE;

	switch (premove_hm->remove_params.type) {
	case DPA_CLS_HM_REMOVE_ETHERNET:
		hm_node->params.u.hdr.rmvParams.type =
					e_FM_PCD_MANIP_RMV_BY_HDR;
		hm_node->params.u.hdr.rmvParams.u.byHdr.type =
					e_FM_PCD_MANIP_RMV_BY_HDR_SPECIFIC_L2;
		hm_node->params.u.hdr.rmvParams.u.byHdr.u.specificL2 =
					e_FM_PCD_MANIP_HDR_RMV_ETHERNET;
		break;
	case DPA_CLS_HM_REMOVE_PPP:
		hm_node->params.u.hdr.rmvParams.type =
						e_FM_PCD_MANIP_RMV_GENERIC;
		hm_node->params.u.hdr.rmvParams.u.generic.offset =
						PPP_HEADER_OFFSET;
		hm_node->params.u.hdr.rmvParams.u.generic.size =
						PPP_HEADER_SIZE;
		break;
	case DPA_CLS_HM_REMOVE_CUSTOM:
		hm_node->params.u.hdr.rmvParams.type =
					e_FM_PCD_MANIP_RMV_GENERIC;
		hm_node->params.u.hdr.rmvParams.u.generic.offset =
					premove_hm->remove_params.custom.offset;
		hm_node->params.u.hdr.rmvParams.u.generic.size =
					premove_hm->remove_params.custom.size;
		break;
	default:
		/* Should never get here */
		BUG_ON(1);
		break;
	}

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_remove_hm(int hmd,
	const struct dpa_cls_hm_remove_params *new_remove_params,
	int modify_flags)
{
	struct dpa_cls_hm_node *hm_node;
	struct dpa_cls_hm *premove_hm;
	bool update = false;
	t_Error error;
	int ret = 0;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	if (!modify_flags)
		/* Nothing to do */
		return 0;

	/* Parameters sanity checks: */
	if (!new_remove_params) {
		log_err("\"new_remove_params\" cannot be NULL.\n");
		return -EINVAL;
	}

	lock_desc_table(&hm_array);
	premove_hm = desc_to_object(&hm_array, hmd);
	if (!premove_hm) {
		release_desc_table(&hm_array);
		log_err("Invalid descriptor (%d).\n", hmd);
		return -EINVAL;
	}
	mutex_lock(&premove_hm->access);
	/*
	 * Hold the lock on the descriptor table to prevent other runtime
	 * modifications of header manipulations until we're finished. The FMan
	 * driver doesn't allow parallel modification of HM nodes when they
	 * belong to the same PCD.
	 */

	if (premove_hm->type != DPA_CLS_HM_TYPE_REMOVE) {
		release_desc_table(&hm_array);
		mutex_unlock(&premove_hm->access);
		log_err("hmd=%d is not an REMOVE type header manip.\n", hmd);
		return -EINVAL;
	}

	if ((modify_flags & DPA_CLS_HM_RM_MOD_TYPE) &&
		(new_remove_params->type != premove_hm->remove_params.type)) {
		update = true;
		premove_hm->remove_params.type = new_remove_params->type;
	}

	if ((modify_flags & DPA_CLS_HM_RM_MOD_CUSTOM_OFFSET) &&
		(new_remove_params->custom.offset !=
				premove_hm->remove_params.custom.offset)) {
		update = true;
		premove_hm->remove_params.custom.offset =
				new_remove_params->custom.offset;
	}

	if ((modify_flags & DPA_CLS_HM_RM_MOD_CUSTOM_SIZE) &&
		(new_remove_params->custom.size !=
				premove_hm->remove_params.custom.size)) {
		update = true;
		premove_hm->remove_params.custom.size =
					new_remove_params->custom.size;
	}

	if (update) {
		ret = remove_hm_update_params(premove_hm);
		if (ret == 0) {
			t_FmPcdManipParams new_hm_node_params;

			hm_node = premove_hm->hm_node[0];

			/*
			 * Have to make a copy of the manip node params because
			 * ManipNodeReplace does not accept h_NextManip != NULL.
			 */
			memcpy(&new_hm_node_params, &hm_node->params,
						sizeof(new_hm_node_params));
			new_hm_node_params.h_NextManip = NULL;
			error = FM_PCD_ManipNodeReplace(hm_node->node,
							&new_hm_node_params);
			if (error != E_OK) {
				release_desc_table(&hm_array);
				mutex_unlock(&premove_hm->access);
				log_err("FMan driver call failed - "
					"FM_PCD_ManipNodeReplace, while trying "
					"to modify hmd=%d, manip node "
					"handle=0x%p.\n", hmd, hm_node->node);
				return -EBUSY;
			}
		}
	}

	release_desc_table(&hm_array);
	mutex_unlock(&premove_hm->access);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}
EXPORT_SYMBOL(dpa_classif_modify_remove_hm);

int dpa_classif_set_insert_hm(const struct dpa_cls_hm_insert_params
	*insert_params, int next_hmd, int *hmd, bool chain_head,
	const struct dpa_cls_hm_insert_resources *res)
{
	int err;
	struct dpa_cls_hm *pinsert_hm, *pcurrent;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!insert_params) {
		log_err("\"insert_params\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!hmd) {
		log_err("\"hmd\" cannot be NULL.\n");
		return -EINVAL;
	}

	*hmd = DPA_OFFLD_DESC_NONE;

	err = insert_hm_check_params(insert_params);
	if (err < 0) {
		log_err("Invalid insert HM parameters.\n");
		return err;
	}

	err = create_new_hm_op(hmd, next_hmd);
	if (err < 0) {
		log_err("Failed to create insert HM op.\n");
		return err;
	}

	pinsert_hm = (struct dpa_cls_hm *) hm_array.object[*hmd];

	pinsert_hm->type	= DPA_CLS_HM_TYPE_INSERT;
	pinsert_hm->chain_head	= chain_head;

	/* Copy the insert HM parameters locally */
	memcpy(&pinsert_hm->insert_params, insert_params,
						sizeof(*insert_params));

	err = insert_hm_prepare_nodes(pinsert_hm, res);
	if (err < 0) {
		log_err("Failed to acquire necessary HM nodes.\n");
		goto insert_hm_error;
	}

	err = insert_hm_update_params(pinsert_hm);
	if (err < 0) {
		log_err("Failed to update low level header manipulation "
			"parameters.\n");
		goto insert_hm_error;
	}

	if (chain_head) {
		err = init_hm_chain(pinsert_hm->insert_params.fm_pcd,
				pinsert_hm->hm_chain,
				pinsert_hm->hm_chain->next);
		if (err < 0)
			log_err("Failed to initialize low level HM chain.\n");
	}

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pinsert_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;

insert_hm_error:

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pinsert_hm);

	lock_desc_table(&hm_array);
	remove_hm_op(*hmd);
	release_desc_table(&hm_array);

	*hmd = DPA_OFFLD_DESC_NONE;

	return err;
}
EXPORT_SYMBOL(dpa_classif_set_insert_hm);

static int insert_hm_prepare_nodes(struct dpa_cls_hm *pinsert_hm,
				const struct dpa_cls_hm_insert_resources *res)
{
	struct dpa_cls_hm_node *hm_node;
	void * const *phm_nodes;
	int err = 0;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pinsert_hm);

	pinsert_hm->num_nodes = 1;

	if (res) { /* Import HM nodes */
		phm_nodes = &res->insert_node;

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
			__LINE__));

		return import_hm_nodes_to_chain(phm_nodes,
					pinsert_hm->num_nodes,
					pinsert_hm);
	}

	hm_node = try_compatible_node(pinsert_hm);
	if (hm_node == NULL) {
		/* Create a header manip node for this insert: */
		hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n", __func__,
			__LINE__, hm_node));
		if (!hm_node) {
			log_err("No more memory for header manip nodes.\n");
			return -ENOMEM;
		}

		INIT_LIST_HEAD(&hm_node->list_node);

		/* Initialize dontParseAfterManip to TRUE */
		hm_node->params.u.hdr.dontParseAfterManip = TRUE;
	}

	pinsert_hm->hm_node[0] = hm_node;

	add_local_hm_nodes_to_chain(pinsert_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}

static int insert_hm_update_params(struct dpa_cls_hm *pinsert_hm)
{
	uint8_t size = 0;
	uint8_t offset = 0;
	uint8_t *pdata = NULL;
	struct dpa_cls_hm_node *hm_node;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pinsert_hm);
	BUG_ON(pinsert_hm->num_nodes != 1);
	BUG_ON(!pinsert_hm->hm_node[0]);

	hm_node = pinsert_hm->hm_node[0];

	hm_node->params.type			= e_FM_PCD_MANIP_HDR;
	hm_node->params.u.hdr.insrt		= TRUE;
	hm_node->params.u.hdr.insrtParams.type	= e_FM_PCD_MANIP_INSRT_GENERIC;

	hm_node->params.u.hdr.dontParseAfterManip &=
			(pinsert_hm->insert_params.reparse) ? FALSE : TRUE;

	switch (pinsert_hm->insert_params.type) {
	case DPA_CLS_HM_INSERT_ETHERNET:
		size = (uint8_t) (sizeof(struct ethhdr) +
			(pinsert_hm->insert_params.eth.num_tags *
			sizeof(struct vlan_header)));
		pdata = kzalloc(size, GFP_KERNEL);
		if (!pdata) {
			log_err("Not enough memory for insert HM.\n");
			return -ENOMEM;
		}

		if (pinsert_hm->insert_params.eth.num_tags) {
			/* Copy Ethernet header data except the EtherType */
			memcpy(pdata,
				&pinsert_hm->insert_params.eth.eth_header,
				sizeof(struct ethhdr) - ETHERTYPE_SIZE);
			offset += (uint8_t)(sizeof(struct ethhdr) -
								ETHERTYPE_SIZE);
			/* Copy the VLAN tags */
			memcpy(&pdata[offset],
				&pinsert_hm->insert_params.eth.qtag,
				pinsert_hm->insert_params.eth.num_tags *
				sizeof(struct vlan_header));
			offset += (uint8_t) (pinsert_hm->insert_params.eth.
				num_tags * sizeof(struct vlan_header));
			/* Copy the EtherType */
			memcpy(&pdata[offset],
		&pinsert_hm->insert_params.eth.eth_header.h_proto,
				ETHERTYPE_SIZE);
			offset = 0;
		} else
			/* Copy the entire Ethernet header */
			memcpy(pdata,
				&pinsert_hm->insert_params.eth.eth_header,
				sizeof(struct ethhdr));
		break;
	case DPA_CLS_HM_INSERT_PPP:
		size	= PPP_HEADER_SIZE;
		pdata	= kzalloc(size, GFP_KERNEL);
		if (!pdata) {
			log_err("Not enough memory for insert HM.\n");
			return -ENOMEM;
		}

		/* Copy the PPP PID */
		memcpy(pdata, &pinsert_hm->insert_params.ppp_pid,
			PPP_HEADER_SIZE);
		break;
	case DPA_CLS_HM_INSERT_CUSTOM:
		size	= pinsert_hm->insert_params.custom.size;
		pdata	= kzalloc(size, GFP_KERNEL);
		if (!pdata) {
			log_err("Not enough memory for insert HM.\n");
			return -ENOMEM;
		}
		memcpy(pdata, pinsert_hm->insert_params.custom.data, size);
		offset	= pinsert_hm->insert_params.custom.offset;
		break;
	default:
		/* Should never get here */
		BUG_ON(1);
		break;
	}

	kfree(hm_node->params.u.hdr.insrtParams.u.generic.p_Data);

	hm_node->params.u.hdr.insrtParams.u.generic.offset	= offset;
	hm_node->params.u.hdr.insrtParams.u.generic.size	= size;
	hm_node->params.u.hdr.insrtParams.u.generic.p_Data	= pdata;
	hm_node->params.u.hdr.insrtParams.u.generic.replace	= FALSE;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_insert_hm(int hmd,
	const struct dpa_cls_hm_insert_params *new_insert_params,
	int modify_flags)
{
	struct dpa_cls_hm_node *hm_node;
	struct dpa_cls_hm *pinsert_hm;
	bool update = false;
	t_Error error;
	int ret = 0;
	int mask;
	uint8_t *pdata;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	if (!modify_flags)
		/* Nothing to do */
		return 0;

	/* Parameters sanity checks: */
	if (!new_insert_params) {
		log_err("\"new_insert_params\" cannot be NULL.\n");
		return -EINVAL;
	}

	lock_desc_table(&hm_array);
	pinsert_hm = desc_to_object(&hm_array, hmd);
	if (!pinsert_hm) {
		release_desc_table(&hm_array);
		log_err("Invalid descriptor (%d).\n", hmd);
		return -EINVAL;
	}
	mutex_lock(&pinsert_hm->access);
	/*
	 * Hold the lock on the descriptor table to prevent other runtime
	 * modifications of header manipulations until we're finished. The FMan
	 * driver doesn't allow parallel modification of HM nodes when they
	 * belong to the same PCD.
	 */

	if (pinsert_hm->type != DPA_CLS_HM_TYPE_INSERT) {
		release_desc_table(&hm_array);
		mutex_unlock(&pinsert_hm->access);
		log_err("hmd=%d is not an INSERT type header manip.\n", hmd);
		return -EINVAL;
	}

	mask = DPA_CLS_HM_INS_MOD_ETH_HEADER |
		DPA_CLS_HM_INS_MOD_QTAGS |
		DPA_CLS_HM_INS_MOD_PPPoE_HEADER;
	if ((modify_flags & mask) && (pinsert_hm->insert_params.type !=
			DPA_CLS_HM_INSERT_ETHERNET)) {
		release_desc_table(&hm_array);
		mutex_unlock(&pinsert_hm->access);
		log_err("modify_flags=0x%x doesn't work on hmd=%d. It only "
			"works on INSERT ETHERNET header manipulations.\n",
			modify_flags, hmd);
		return -EINVAL;
	}

	mask = DPA_CLS_HM_INS_MOD_CUSTOM_OFFSET |
		DPA_CLS_HM_INS_MOD_CUSTOM_DATA;
	if ((modify_flags & mask) && (pinsert_hm->insert_params.type !=
			DPA_CLS_HM_INSERT_CUSTOM)) {
		release_desc_table(&hm_array);
		mutex_unlock(&pinsert_hm->access);
		log_err("modify_flags=0x%x doesn't work on hmd=%d. It only "
			"works on CUSTOM INSERT header manipulations.\n",
			modify_flags, hmd);
		return -EINVAL;
	}

	if ((modify_flags & DPA_CLS_HM_INS_MOD_PPP_PID) &&
		(pinsert_hm->insert_params.ppp_pid !=
					new_insert_params->ppp_pid)) {
		if (pinsert_hm->insert_params.type !=
						DPA_CLS_HM_INSERT_PPP) {
			release_desc_table(&hm_array);
			mutex_unlock(&pinsert_hm->access);
			log_err("modify_flags=0x%x doesn't work on hmd=%d. It "
				"only works on INSERT PPP header "
				"manipulations.\n", modify_flags, hmd);
			return -EINVAL;
		}

		update = true;
		pinsert_hm->insert_params.ppp_pid = new_insert_params->ppp_pid;
	}

	if ((modify_flags & DPA_CLS_HM_INS_MOD_CUSTOM_OFFSET) &&
		(pinsert_hm->insert_params.custom.offset !=
					new_insert_params->custom.offset)) {
		update = true;
		pinsert_hm->insert_params.custom.offset =
					new_insert_params->custom.offset;
	}

	if ((modify_flags & DPA_CLS_HM_INS_MOD_CUSTOM_OFFSET) &&
		(pinsert_hm->insert_params.custom.offset !=
					new_insert_params->custom.offset)) {
		update = true;
		pinsert_hm->insert_params.custom.offset =
					new_insert_params->custom.offset;
	}

	if (modify_flags & DPA_CLS_HM_INS_MOD_CUSTOM_DATA) {
		update = true;
		pdata = kzalloc(new_insert_params->custom.size, GFP_KERNEL);
		if (!pdata) {
			release_desc_table(&hm_array);
			mutex_unlock(&pinsert_hm->access);
			log_err("Not enough memory to adjust custom insert "
				"header manipulation.\n");
			return -ENOMEM;
		}
		/* Replace old data buffer with the new data buffer */
		kfree(pinsert_hm->insert_params.custom.data);
		pinsert_hm->insert_params.custom.data = pdata;

		pinsert_hm->insert_params.custom.size =
						new_insert_params->custom.size;
		memcpy(pdata, new_insert_params->custom.data,
					new_insert_params->custom.size);
	}

	if (modify_flags & DPA_CLS_HM_INS_MOD_QTAGS) {
		update = true;
		pinsert_hm->insert_params.eth.num_tags =
					new_insert_params->eth.num_tags;
		memcpy(pinsert_hm->insert_params.eth.qtag,
			new_insert_params->eth.qtag,
			pinsert_hm->insert_params.eth.num_tags *
				sizeof(struct vlan_header));
	}

	if (modify_flags & DPA_CLS_HM_INS_MOD_ETH_HEADER) {
		update = true;
		memcpy(&pinsert_hm->insert_params.eth.eth_header,
			&new_insert_params->eth.eth_header,
			sizeof(struct ethhdr));
	}

	if (update) {
		ret = insert_hm_update_params(pinsert_hm);
		if (ret == 0) {
			t_FmPcdManipParams new_hm_node_params;

			hm_node = pinsert_hm->hm_node[0];

			/*
			 * Have to make a copy of the manip node params because
			 * ManipNodeReplace does not accept h_NextManip != NULL.
			 */
			memcpy(&new_hm_node_params, &hm_node->params,
						sizeof(new_hm_node_params));
			new_hm_node_params.h_NextManip = NULL;
			error = FM_PCD_ManipNodeReplace(hm_node->node,
							&new_hm_node_params);
			if (error != E_OK) {
				release_desc_table(&hm_array);
				mutex_unlock(&pinsert_hm->access);
				log_err("FMan driver call failed - "
					"FM_PCD_ManipNodeReplace, while trying "
					"to modify hmd=%d, manip node "
					"handle=0x%p.\n", hmd, hm_node->node);
				return -EBUSY;
			}
		}
	}

	release_desc_table(&hm_array);
	mutex_unlock(&pinsert_hm->access);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}
EXPORT_SYMBOL(dpa_classif_modify_insert_hm);

int dpa_classif_set_update_hm(const struct dpa_cls_hm_update_params
	*update_params, int next_hmd, int *hmd, bool chain_head,
	const struct dpa_cls_hm_update_resources *res)
{
	int err;
	struct dpa_cls_hm *pupdate_hm, *pcurrent;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!update_params) {
		log_err("\"update_params\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!hmd) {
		log_err("\"hmd\" cannot be NULL.\n");
		return -EINVAL;
	}

	*hmd = DPA_OFFLD_DESC_NONE;

	err = update_hm_check_params(update_params);
	if (err < 0) {
		log_err("Invalid update HM parameters.\n");
		return err;
	}

	err = create_new_hm_op(hmd, next_hmd);
	if (err < 0) {
		log_err("Failed to create update HM op.\n");
		return err;
	}

	pupdate_hm = (struct dpa_cls_hm *) hm_array.object[*hmd];

	pupdate_hm->type	= DPA_CLS_HM_TYPE_UPDATE;
	pupdate_hm->chain_head	= chain_head;

	/* Copy the update HM parameters locally */
	memcpy(&pupdate_hm->update_params, update_params,
						sizeof(*update_params));

	err = update_hm_prepare_nodes(pupdate_hm, res);
	if (err < 0) {
		log_err("Failed to acquire necessary HM nodes.\n");
		goto update_hm_error;
	}

	err = update_hm_update_params(pupdate_hm);
	if (err < 0) {
		log_err("Failed to update low level header manipulation "
			"parameters.\n");
		goto update_hm_error;
	}

	if (chain_head) {
		err = init_hm_chain(pupdate_hm->update_params.fm_pcd,
				pupdate_hm->hm_chain,
				pupdate_hm->hm_chain->next);
		if (err < 0)
			log_err("Failed to initialize low level HM chain.\n");
	}

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pupdate_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;

update_hm_error:

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pupdate_hm);

	lock_desc_table(&hm_array);
	remove_hm_op(*hmd);
	release_desc_table(&hm_array);

	*hmd = DPA_OFFLD_DESC_NONE;

	return err;
}
EXPORT_SYMBOL(dpa_classif_set_update_hm);

static int update_hm_prepare_nodes(struct dpa_cls_hm *pupdate_hm,
				const struct dpa_cls_hm_update_resources *res)
{
	struct dpa_cls_hm_node *hm_node = NULL;
	void * const *phm_nodes;
	int err = 0;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pupdate_hm);

	pupdate_hm->num_nodes = 2;

	if (res) { /* Import HM nodes */
		phm_nodes = &res->update_node;

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
			__LINE__));

		return import_hm_nodes_to_chain(phm_nodes,
					pupdate_hm->num_nodes,
					pupdate_hm);
	}

	if (pupdate_hm->update_params.op_flags != DPA_CLS_HM_UPDATE_NONE) {
		hm_node = try_compatible_node(pupdate_hm);
		if ((pupdate_hm->update_params.ip_frag_params.mtu) ||
				(hm_node == NULL)) {
			/* Create a header manip node for this update: */
			hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);

			dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n",
				__func__, __LINE__, hm_node));
			if (!hm_node) {
				log_err("No more memory for header manip nodes.\n");
				return -ENOMEM;
			}

			INIT_LIST_HEAD(&hm_node->list_node);

			/* Initialize dontParseAfterManip to TRUE */
			hm_node->params.u.hdr.dontParseAfterManip = TRUE;
		}

		pupdate_hm->hm_node[0] = hm_node;
	}

	if (pupdate_hm->update_params.ip_frag_params.mtu) {
		/* IP fragmentation option is enabled */
		/* Create a header manip node: */
		hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);
		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n",
			__func__, __LINE__, hm_node));
		if (!hm_node) {
			log_err("No more memory for header manip nodes.\n");
			return -ENOMEM;
		}

		INIT_LIST_HEAD(&hm_node->list_node);
		pupdate_hm->hm_node[1] = hm_node;
	}

	add_local_hm_nodes_to_chain(pupdate_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}

static int update_hm_update_params(struct dpa_cls_hm *pupdate_hm)
{
	struct dpa_cls_hm_node *hm_node;
	int update_ops, replace_ops;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pupdate_hm);
	BUG_ON(pupdate_hm->num_nodes < 1);

	update_ops = DPA_CLS_HM_UPDATE_IPv4_UPDATE |
			DPA_CLS_HM_UPDATE_IPv6_UPDATE |
			DPA_CLS_HM_UPDATE_UDP_TCP_UPDATE;

	replace_ops = DPA_CLS_HM_REPLACE_IPv4_BY_IPv6 |
			DPA_CLS_HM_REPLACE_IPv6_BY_IPv4;

	hm_node = pupdate_hm->hm_node[0];

	if (pupdate_hm->update_params.op_flags & update_ops) {
		hm_node->params.type			= e_FM_PCD_MANIP_HDR;
		hm_node->params.u.hdr.fieldUpdate	= TRUE;

		hm_node->params.u.hdr.dontParseAfterManip &=
			(pupdate_hm->update_params.reparse) ? FALSE : TRUE;

		if (pupdate_hm->update_params.op_flags &
				DPA_CLS_HM_UPDATE_IPv4_UPDATE) {
			hm_node->params.u.hdr.fieldUpdateParams.type =
					e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV4;

			if (pupdate_hm->update_params.update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_IPSA) {
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv4.
					validUpdates |=
					HDR_MANIP_IPV4_SRC;
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv4.
					src =
					be32_to_cpu(pupdate_hm->update_params.
					update.l3.ipsa.addr.ipv4.word);
			}

			if (pupdate_hm->update_params.update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_IPDA) {
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv4.
					validUpdates |=
					HDR_MANIP_IPV4_DST;
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv4.
					dst =
					be32_to_cpu(pupdate_hm->update_params.
					update.l3.ipda.addr.ipv4.word);
			}

			if (pupdate_hm->update_params.update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_TOS_TC) {
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv4.
					validUpdates |=
					HDR_MANIP_IPV4_TOS;
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv4.
					tos =
					pupdate_hm->update_params.update.l3.
					tos_tc;
			}

			if (pupdate_hm->update_params.update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_ID) {
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv4.
					validUpdates |=
					HDR_MANIP_IPV4_ID;
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv4.
					id =
					pupdate_hm->update_params.update.l3.
					initial_id;
			}

			if (pupdate_hm->update_params.update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_TTL_HOPL_DECREMENT)
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv4.
					validUpdates |=
					HDR_MANIP_IPV4_TTL;
		}

		if (pupdate_hm->update_params.op_flags &
				DPA_CLS_HM_UPDATE_IPv6_UPDATE) {
			hm_node->params.u.hdr.fieldUpdateParams.type =
					e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV6;

			if (pupdate_hm->update_params.update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_IPSA) {
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv6.
					validUpdates |=
					HDR_MANIP_IPV6_SRC;
				memcpy(hm_node->params.u.hdr.fieldUpdateParams.
					u.ipv6.src, pupdate_hm->update_params.
					update.l3.ipsa.addr.ipv6.byte,
					DPA_OFFLD_IPv6_ADDR_LEN_BYTES);
			}

			if (pupdate_hm->update_params.update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_IPDA) {
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv4.
					validUpdates |=
					HDR_MANIP_IPV6_DST;
				memcpy(hm_node->params.u.hdr.fieldUpdateParams.
					u.ipv6.dst, pupdate_hm->update_params.
					update.l3.ipda.addr.ipv6.byte,
					DPA_OFFLD_IPv6_ADDR_LEN_BYTES);
			}

			if (pupdate_hm->update_params.update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_TOS_TC) {
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv6.
					validUpdates |=
					HDR_MANIP_IPV6_TC;
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv6.
					trafficClass =
					pupdate_hm->update_params.update.l3.
					tos_tc;
			}

			if (pupdate_hm->update_params.update.l3.field_flags &
				DPA_CLS_HM_IP_UPDATE_TTL_HOPL_DECREMENT)
				hm_node->params.u.hdr.fieldUpdateParams.u.ipv6.
					validUpdates |=
					HDR_MANIP_IPV6_HL;
		}

		if (pupdate_hm->update_params.op_flags &
				DPA_CLS_HM_UPDATE_UDP_TCP_UPDATE) {
			hm_node->params.u.hdr.fieldUpdateParams.type =
					e_FM_PCD_MANIP_HDR_FIELD_UPDATE_TCP_UDP;

			if (pupdate_hm->update_params.update.l4.field_flags &
				DPA_CLS_HM_L4_UPDATE_SPORT) {
				hm_node->params.u.hdr.fieldUpdateParams.u.
					tcpUdp.validUpdates |=
					HDR_MANIP_TCP_UDP_SRC;
				hm_node->params.u.hdr.fieldUpdateParams.u.
					tcpUdp.src =
					pupdate_hm->update_params.update.l4.
					sport;
			}

			if (pupdate_hm->update_params.update.l4.field_flags &
				DPA_CLS_HM_L4_UPDATE_DPORT) {
				hm_node->params.u.hdr.fieldUpdateParams.u.
					tcpUdp.validUpdates |=
					HDR_MANIP_TCP_UDP_DST;
				hm_node->params.u.hdr.fieldUpdateParams.u.
					tcpUdp.dst =
					pupdate_hm->update_params.update.l4.
					dport;
			}

			if (pupdate_hm->update_params.update.l4.field_flags &
				DPA_CLS_HM_L4_UPDATE_CALCULATE_CKSUM) {
				hm_node->params.u.hdr.fieldUpdateParams.u.
					tcpUdp.validUpdates |=
					HDR_MANIP_TCP_UDP_CHECKSUM;
			}
		}
	}

	if (pupdate_hm->update_params.op_flags & replace_ops) {
		hm_node->params.type			= e_FM_PCD_MANIP_HDR;
		hm_node->params.u.hdr.custom		= TRUE;
		hm_node->params.u.hdr.customParams.type	=
				e_FM_PCD_MANIP_HDR_CUSTOM_IP_REPLACE;

		hm_node->params.u.hdr.dontParseAfterManip &=
			(pupdate_hm->update_params.reparse) ? FALSE : TRUE;

		if (pupdate_hm->update_params.op_flags &
				DPA_CLS_HM_REPLACE_IPv4_BY_IPv6) {

			hm_node->params.u.hdr.customParams.u.ipHdrReplace.
				replaceType =
				e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV4_BY_IPV6;
			hm_node->params.u.hdr.customParams.u.ipHdrReplace.
				hdrSize = (uint8_t)sizeof(struct ipv6_header);

			memcpy(hm_node->params.u.hdr.customParams.u.
				ipHdrReplace.hdr,
				&pupdate_hm->update_params.replace.new_ipv6_hdr,
				sizeof(struct ipv6_header));
		}

		if (pupdate_hm->update_params.op_flags &
				DPA_CLS_HM_REPLACE_IPv6_BY_IPv4) {

			hm_node->params.u.hdr.customParams.u.ipHdrReplace.
				replaceType =
				e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV6_BY_IPV4;
			hm_node->params.u.hdr.customParams.u.ipHdrReplace.
				hdrSize = (uint8_t)sizeof(struct iphdr);
			memcpy(hm_node->params.u.hdr.customParams.u.
				ipHdrReplace.hdr,
			&pupdate_hm->update_params.replace.new_ipv4_hdr.header,
				sizeof(struct iphdr));
	if ((pupdate_hm->update_params.replace.new_ipv4_hdr.options_size)
		&& (pupdate_hm->update_params.replace.new_ipv4_hdr.options)) {
		memcpy(&hm_node->params.u.hdr.customParams.u.ipHdrReplace.
				hdr[sizeof(struct iphdr)],
			&pupdate_hm->update_params.replace.new_ipv4_hdr.options,
		pupdate_hm->update_params.replace.new_ipv4_hdr.options_size);
	}
		}
	}

	hm_node = pupdate_hm->hm_node[1];

	if (pupdate_hm->update_params.ip_frag_params.mtu) {
		/* IP fragmentation option is enabled */
		BUG_ON(!hm_node);

		hm_node->params.type = e_FM_PCD_MANIP_FRAG;
		hm_node->params.u.frag.hdr = HEADER_TYPE_IPv4;
		hm_node->params.u.frag.u.ipFrag.sizeForFragmentation =
				pupdate_hm->update_params.ip_frag_params.mtu;
#if (DPAA_VERSION == 10)
		hm_node->params.u.frag.u.ipFrag.scratchBpid =
				pupdate_hm->update_params.ip_frag_params.
					scratch_bpid;
#endif /* (DPAA_VERSION == 10) */
		switch (pupdate_hm->update_params.ip_frag_params.df_action) {
		case DPA_CLS_HM_DF_ACTION_FRAG_ANYWAY:
			hm_node->params.u.frag.u.ipFrag.dontFragAction =
					e_FM_PCD_MANIP_FRAGMENT_PACKET;
			break;
		case DPA_CLS_HM_DF_ACTION_DONT_FRAG:
			hm_node->params.u.frag.u.ipFrag.dontFragAction =
					e_FM_PCD_MANIP_CONTINUE_WITHOUT_FRAG;
			break;
		case DPA_CLS_HM_DF_ACTION_DROP:
			hm_node->params.u.frag.u.ipFrag.dontFragAction =
				e_FM_PCD_MANIP_ENQ_TO_ERR_Q_OR_DISCARD_PACKET;
			break;
		}
	}

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_update_hm(int hmd,
	const struct dpa_cls_hm_update_params *new_update_params,
	int modify_flags)
{
	struct dpa_cls_hm_node *hm_node;
	struct dpa_cls_hm *pupdate_hm;
	bool update[2] = { false, false };
	t_Error error;
	int ret = 0;
	int ip_update;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	if (!modify_flags)
		/* Nothing to do */
		return 0;

	/* Parameters sanity checks: */
	if (!new_update_params) {
		log_err("\"new_update_params\" cannot be NULL.\n");
		return -EINVAL;
	}

	lock_desc_table(&hm_array);
	pupdate_hm = desc_to_object(&hm_array, hmd);
	if (!pupdate_hm) {
		release_desc_table(&hm_array);
		log_err("Invalid descriptor (%d).\n", hmd);
		return -EINVAL;
	}
	mutex_lock(&pupdate_hm->access);
	/*
	 * Hold the lock on the descriptor table to prevent other runtime
	 * modifications of header manipulations until we're finished. The FMan
	 * driver doesn't allow parallel modification of HM nodes when they
	 * belong to the same PCD.
	 */

	if (pupdate_hm->type != DPA_CLS_HM_TYPE_UPDATE) {
		release_desc_table(&hm_array);
		mutex_unlock(&pupdate_hm->access);
		log_err("hmd=%d is not an UPDATE type header manip.\n", hmd);
		return -EINVAL;
	}

	if (modify_flags & DPA_CLS_HM_UPDATE_MOD_IPHDR) {
		if (pupdate_hm->update_params.op_flags &
					DPA_CLS_HM_REPLACE_IPv4_BY_IPv6) {
			memcpy(&pupdate_hm->update_params.replace.new_ipv6_hdr,
				&new_update_params->replace.new_ipv6_hdr,
				sizeof(struct ipv6_header));
		} else if (pupdate_hm->update_params.op_flags &
					DPA_CLS_HM_REPLACE_IPv6_BY_IPv4) {
			memcpy(&pupdate_hm->update_params.replace.new_ipv4_hdr.
				header, &new_update_params->replace.
				new_ipv4_hdr.header, sizeof(struct iphdr));
			/* Update IPv4 options */
			kfree(pupdate_hm->update_params.replace.new_ipv4_hdr.
				options);
			if (new_update_params->replace.new_ipv4_hdr.
					options_size) {
				pupdate_hm->update_params.replace.new_ipv4_hdr.
					options = kzalloc(new_update_params->
					replace.new_ipv4_hdr.options_size,
					GFP_KERNEL);
				if (!pupdate_hm->update_params.replace.
					new_ipv4_hdr.options) {
					pupdate_hm->update_params.replace.
						new_ipv4_hdr.options_size = 0;
					release_desc_table(&hm_array);
					mutex_unlock(&pupdate_hm->access);
					log_err("Out of memory while modifying "
						"IPv6 header replace header "
						"manipulation hmd=%d.\n", hmd);
					return -EINVAL;
				}
			} else
				pupdate_hm->update_params.replace.new_ipv4_hdr.
					options = NULL;
			pupdate_hm->update_params.replace.new_ipv4_hdr.
				options_size = new_update_params->replace.
				new_ipv4_hdr.options_size;
		} else {
			release_desc_table(&hm_array);
			mutex_unlock(&pupdate_hm->access);
			log_err("modify_flags=0x%x doesn't work on hmd=%d. It "
				"only works on REPLACE header manipulations.\n",
				modify_flags, hmd);
			return -EINVAL;
		}
		update[0] = true;
	}

	ip_update = DPA_CLS_HM_UPDATE_IPv4_UPDATE |
			DPA_CLS_HM_UPDATE_IPv6_UPDATE;
	if (pupdate_hm->update_params.op_flags & ip_update) {
		if (modify_flags & DPA_CLS_HM_UPDATE_MOD_SIP) {
			if (new_update_params->update.l3.ipsa.version !=
				pupdate_hm->update_params.update.l3.ipsa.
				version) {
				release_desc_table(&hm_array);
				mutex_unlock(&pupdate_hm->access);
				log_err("New SIP adress version (%d) in UPDATE "
					"header manipulation hmd=%d cannot be "
					"different from the old one (%d).\n",
					new_update_params->update.l3.ipsa.
					version, hmd, pupdate_hm->
					update_params.update.l3.ipsa.version);
				return -EINVAL;
			}
			memcpy(&pupdate_hm->update_params.update.l3.ipsa,
				&new_update_params->update.l3.ipsa,
				sizeof(struct dpa_offload_ip_address));
			update[0] = true;
		}

		if (modify_flags & DPA_CLS_HM_UPDATE_MOD_DIP) {
			if (new_update_params->update.l3.ipda.version !=
				pupdate_hm->update_params.update.l3.ipda.
				version) {
				release_desc_table(&hm_array);
				mutex_unlock(&pupdate_hm->access);
				log_err("New DIP adress version (%d) in UPDATE "
					"header manipulation hmd=%d cannot be "
					"different from the old one (%d).\n",
					new_update_params->update.l3.ipda.
					version, hmd, pupdate_hm->
					update_params.update.l3.ipda.version);
				return -EINVAL;
			}
			memcpy(&pupdate_hm->update_params.update.l3.ipda,
				&new_update_params->update.l3.ipda,
				sizeof(struct dpa_offload_ip_address));
			update[0] = true;
		}

		if ((modify_flags & DPA_CLS_HM_UPDATE_MOD_TOS_TC) &&
			(new_update_params->update.l3.tos_tc !=
				pupdate_hm->update_params.update.l3.tos_tc)) {
			update[0] = true;
			pupdate_hm->update_params.update.l3.tos_tc =
					new_update_params->update.l3.tos_tc;
		}

		if ((modify_flags & DPA_CLS_HM_UPDATE_MOD_IP_ID) &&
			(new_update_params->update.l3.initial_id !=
			pupdate_hm->update_params.update.l3.initial_id)) {
			update[0] = true;
			pupdate_hm->update_params.update.l3.initial_id =
					new_update_params->update.l3.initial_id;
		}

		if ((modify_flags & DPA_CLS_HM_UPDATE_MOD_L3_FLAGS) &&
			(new_update_params->update.l3.field_flags !=
			pupdate_hm->update_params.update.l3.field_flags)) {
			update[0] = true;
			pupdate_hm->update_params.update.l3.field_flags =
				new_update_params->update.l3.field_flags;
		}
	}

	if (pupdate_hm->update_params.op_flags &
					DPA_CLS_HM_UPDATE_UDP_TCP_UPDATE) {
		if ((modify_flags & DPA_CLS_HM_UPDATE_MOD_SPORT) &&
			(new_update_params->update.l4.sport !=
			pupdate_hm->update_params.update.l4.sport)) {
			update[0] = true;
			pupdate_hm->update_params.update.l4.sport =
					new_update_params->update.l4.sport;
		}

		if ((modify_flags & DPA_CLS_HM_UPDATE_MOD_DPORT) &&
			(new_update_params->update.l4.dport !=
			pupdate_hm->update_params.update.l4.dport)) {
			update[0] = true;
			pupdate_hm->update_params.update.l4.dport =
					new_update_params->update.l4.dport;
		}

		if ((modify_flags & DPA_CLS_HM_UPDATE_MOD_L4_FLAGS) &&
			(new_update_params->update.l4.field_flags !=
			pupdate_hm->update_params.update.l4.field_flags)) {
			update[0] = true;
			pupdate_hm->update_params.update.l4.field_flags =
				new_update_params->update.l4.field_flags;
		}
	}

	if (modify_flags & DPA_CLS_HM_UPDATE_MOD_IP_FRAG_MTU) {
		pupdate_hm->update_params.ip_frag_params.mtu =
				new_update_params->ip_frag_params.mtu;
		update[1] = true;
	}

	if (update[0]) {
		ret = update_hm_update_params(pupdate_hm);
		if (ret == 0) {
			t_FmPcdManipParams new_hm_node_params;

			hm_node = pupdate_hm->hm_node[0];

			/*
			 * Have to make a copy of the manip node params because
			 * ManipNodeReplace does not accept h_NextManip != NULL.
			 */
			memcpy(&new_hm_node_params, &hm_node->params,
						sizeof(new_hm_node_params));
			new_hm_node_params.h_NextManip = NULL;
			error = FM_PCD_ManipNodeReplace(hm_node->node,
							&new_hm_node_params);
			if (error != E_OK) {
				release_desc_table(&hm_array);
				mutex_unlock(&pupdate_hm->access);
				log_err("FMan driver call failed - "
					"FM_PCD_ManipNodeReplace, while trying "
					"to modify hmd=%d, manip node "
					"handle=0x%p.\n", hmd, hm_node->node);
				return -EBUSY;
			}
		}
	}

	if (update[1]) {
		ret = update_hm_update_params(pupdate_hm);
		if (ret == 0) {
			t_FmPcdManipParams new_hm_node_params;

			hm_node = pupdate_hm->hm_node[1];

			/*
			 * Have to make a copy of the manip node params because
			 * ManipNodeReplace does not accept h_NextManip != NULL.
			 */
			memcpy(&new_hm_node_params, &hm_node->params,
						sizeof(new_hm_node_params));
			new_hm_node_params.h_NextManip = NULL;
			error = FM_PCD_ManipNodeReplace(hm_node->node,
							&new_hm_node_params);
			if (error != E_OK) {
				release_desc_table(&hm_array);
				mutex_unlock(&pupdate_hm->access);
				log_err("FMan driver call failed - "
					"FM_PCD_ManipNodeReplace, while trying "
					"to modify hmd=%d, manip node "
					"handle=0x%p.\n", hmd, hm_node->node);
				return -EBUSY;
			}
		}

	}

	release_desc_table(&hm_array);
	mutex_unlock(&pupdate_hm->access);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}
EXPORT_SYMBOL(dpa_classif_modify_update_hm);

int dpa_classif_set_vlan_hm(const struct dpa_cls_hm_vlan_params	*vlan_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_vlan_resources	*res)
{
	int err;
	struct dpa_cls_hm *pvlan_hm, *pcurrent;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!vlan_params) {
		log_err("\"vlan_params\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!hmd) {
		log_err("\"hmd\" cannot be NULL.\n");
		return -EINVAL;
	}

	*hmd = DPA_OFFLD_DESC_NONE;

	err = vlan_hm_check_params(vlan_params);
	if (err < 0) {
		log_err("Invalid VLAN specific HM parameters.\n");
		return err;
	}

	err = create_new_hm_op(hmd, next_hmd);
	if (err < 0) {
		log_err("Failed to create VLAN specific HM op.\n");
		return err;
	}

	pvlan_hm = (struct dpa_cls_hm *) hm_array.object[*hmd];

	pvlan_hm->type		= DPA_CLS_HM_TYPE_VLAN;
	pvlan_hm->chain_head	= chain_head;

	/* Copy the VLAN specific HM parameters locally */
	memcpy(&pvlan_hm->vlan_params, vlan_params, sizeof(*vlan_params));

	err = vlan_hm_prepare_nodes(pvlan_hm, res);
	if (err < 0) {
		log_err("Failed to acquire necessary HM nodes.\n");
		goto vlan_hm_error;
	}

	err = vlan_hm_update_params(pvlan_hm);
	if (err < 0) {
		log_err("Failed to update low level header manipulation "
			"parameters.\n");
		goto vlan_hm_error;
	}

	if (chain_head) {
		err = init_hm_chain(pvlan_hm->vlan_params.fm_pcd,
				pvlan_hm->hm_chain,
				pvlan_hm->hm_chain->next);
		if (err < 0)
			log_err("Failed to initialize low level HM chain.\n");
	}

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pvlan_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;

vlan_hm_error:

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pvlan_hm);

	lock_desc_table(&hm_array);
	remove_hm_op(*hmd);
	release_desc_table(&hm_array);

	*hmd = DPA_OFFLD_DESC_NONE;

	return err;
}
EXPORT_SYMBOL(dpa_classif_set_vlan_hm);

static int vlan_hm_prepare_nodes(struct dpa_cls_hm *pvlan_hm,
				const struct dpa_cls_hm_vlan_resources *res)
{
	struct dpa_cls_hm_node *hm_node;
	void * const *phm_nodes;
	int err = 0;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pvlan_hm);

	pvlan_hm->num_nodes = 1;

	if (res) { /* Import HM nodes */
		phm_nodes = &res->vlan_node;

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
			__LINE__));

		return import_hm_nodes_to_chain(phm_nodes,
					pvlan_hm->num_nodes,
					pvlan_hm);
	}

	hm_node = try_compatible_node(pvlan_hm);
	if (hm_node == NULL) {
		/* Create a header manip node for this insert: */
		hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n",
			__func__, __LINE__, hm_node));
		if (!hm_node) {
			log_err("No more memory for header manip nodes.\n");
			return -ENOMEM;
		}

		INIT_LIST_HEAD(&hm_node->list_node);

		/* Initialize dontParseAfterManip to TRUE */
		hm_node->params.u.hdr.dontParseAfterManip = TRUE;
	}

	pvlan_hm->hm_node[0] = hm_node;

	add_local_hm_nodes_to_chain(pvlan_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}

static int vlan_hm_update_params(struct dpa_cls_hm *pvlan_hm)
{
	struct dpa_cls_hm_node *hm_node;
	uint8_t size;
	uint8_t *pdata;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pvlan_hm);
	BUG_ON(pvlan_hm->num_nodes != 1);
	BUG_ON(!pvlan_hm->hm_node[0]);

	hm_node = pvlan_hm->hm_node[0];

	hm_node->params.type = e_FM_PCD_MANIP_HDR;
	hm_node->params.u.hdr.dontParseAfterManip &=
			(pvlan_hm->vlan_params.reparse) ? FALSE : TRUE;

	switch (pvlan_hm->vlan_params.type) {
	case DPA_CLS_HM_VLAN_INGRESS:
		hm_node->params.u.hdr.rmv = TRUE;
		hm_node->params.u.hdr.rmvParams.type =
					e_FM_PCD_MANIP_RMV_BY_HDR;
		hm_node->params.u.hdr.rmvParams.u.byHdr.type =
					e_FM_PCD_MANIP_RMV_BY_HDR_SPECIFIC_L2;
		hm_node->params.u.hdr.rmvParams.u.byHdr.u.specificL2 =
					e_FM_PCD_MANIP_HDR_RMV_STACKED_QTAGS;

		break;
	case DPA_CLS_HM_VLAN_EGRESS:
		if (pvlan_hm->vlan_params.egress.num_tags) {

			hm_node->params.u.hdr.insrt = TRUE;
			hm_node->params.u.hdr.insrtParams.type =
						e_FM_PCD_MANIP_INSRT_GENERIC;
			hm_node->params.u.hdr.insrtParams.u.generic.offset =
							ETHERTYPE_OFFSET;

			size = (uint8_t) (pvlan_hm->vlan_params.egress.
				num_tags * sizeof(struct vlan_header));
			pdata = kzalloc(size, GFP_KERNEL);
			if (!pdata) {
				log_err("Not enough memory for VLAN specific "
					"egress HM.\n");
				kfree(hm_node);
				return -ENOMEM;
			}

			memcpy(pdata, pvlan_hm->vlan_params.egress.qtag,
				size);

			kfree(hm_node->params.u.hdr.insrtParams.u.generic.
									p_Data);

			hm_node->params.u.hdr.insrtParams.u.generic.size =
									size;
			hm_node->params.u.hdr.insrtParams.u.generic.p_Data =
									pdata;
			hm_node->params.u.hdr.insrtParams.u.generic.replace =
									FALSE;
		}

		if (pvlan_hm->vlan_params.egress.update_op !=
					DPA_CLS_HM_VLAN_UPDATE_NONE) {

			hm_node->params.u.hdr.fieldUpdate = TRUE;
			hm_node->params.u.hdr.fieldUpdateParams.type =
					e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN;

			switch (pvlan_hm->vlan_params.egress.update_op) {
			case DPA_CLS_HM_VLAN_UPDATE_VPri:
				hm_node->params.u.hdr.fieldUpdateParams.u.vlan.
					updateType =
				e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN_VPRI;
				hm_node->params.u.hdr.fieldUpdateParams.u.vlan.
					u.vpri = pvlan_hm->vlan_params.egress.
					update.vpri;
				break;
			case DPA_CLS_HM_VLAN_UPDATE_VPri_BY_DSCP:
				hm_node->params.u.hdr.fieldUpdateParams.u.vlan.
					updateType =
				e_FM_PCD_MANIP_HDR_FIELD_UPDATE_DSCP_TO_VLAN;
				memcpy(hm_node->params.u.hdr.fieldUpdateParams.
					u.vlan.u.dscpToVpri.dscpToVpriTable,
					pvlan_hm->vlan_params.egress.update.
					dscp_to_vpri,
					FM_PCD_MANIP_DSCP_TO_VLAN_TRANS);
				break;
			default:
				log_err("Unknown VLAN update type.\n");
				kfree(hm_node);
				return -EINVAL;
				break;
			}
		}

		break;
	default:
		/* Should never get here */
		BUG_ON(1);
		break;
	}

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_vlan_hm(int hmd,
	const struct dpa_cls_hm_vlan_params *new_vlan_params, int modify_flags)
{
	struct dpa_cls_hm_node *hm_node;
	struct dpa_cls_hm *pvlan_hm;
	bool update = false;
	t_Error error;
	int ret = 0;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	if (!modify_flags)
		/* Nothing to do */
		return 0;

	if ((modify_flags & DPA_CLS_HM_VLAN_MOD_INGRESS_NUM_QTAGS) &&
		(modify_flags != DPA_CLS_HM_VLAN_MOD_INGRESS_NUM_QTAGS)) {
		log_err("MOD_INGRESS_NUM_QTAGS flag cannot be combined with "
			"other flags.\n");
		return -EINVAL;
	}

	/* Parameters sanity checks: */
	if (!new_vlan_params) {
		log_err("\"new_vlan_params\" cannot be NULL.\n");
		return -EINVAL;
	}

	lock_desc_table(&hm_array);
	pvlan_hm = desc_to_object(&hm_array, hmd);
	if (!pvlan_hm) {
		release_desc_table(&hm_array);
		log_err("Invalid descriptor (%d).\n", hmd);
		return -EINVAL;
	}
	mutex_lock(&pvlan_hm->access);
	/*
	 * Hold the lock on the descriptor table to prevent other runtime
	 * modifications of header manipulations until we're finished. The FMan
	 * driver doesn't allow parallel modification of HM nodes when they
	 * belong to the same PCD.
	 */

	if (pvlan_hm->type != DPA_CLS_HM_TYPE_VLAN) {
		release_desc_table(&hm_array);
		mutex_unlock(&pvlan_hm->access);
		log_err("hmd=%d is not an VLAN type header manip.\n", hmd);
		return -EINVAL;
	}

	if (modify_flags == DPA_CLS_HM_VLAN_MOD_INGRESS_NUM_QTAGS) {
		if (pvlan_hm->vlan_params.type != DPA_CLS_HM_VLAN_INGRESS) {
			release_desc_table(&hm_array);
			mutex_unlock(&pvlan_hm->access);
			log_err("hmd=%d is not an INGRESS VLAN type header "
				"manipulation.\n", hmd);
			return -EINVAL;
		}

		if (new_vlan_params->ingress.num_tags !=
				pvlan_hm->vlan_params.ingress.num_tags) {
			update = true;
			pvlan_hm->vlan_params.ingress.num_tags =
					new_vlan_params->ingress.num_tags;
		}
	} else {
		if (pvlan_hm->vlan_params.type != DPA_CLS_HM_VLAN_EGRESS) {
			release_desc_table(&hm_array);
			mutex_unlock(&pvlan_hm->access);
			log_err("hmd=%d is not an EGRESS VLAN type header "
				"manipulation.\n", hmd);
			return -EINVAL;
		}

		if ((modify_flags & DPA_CLS_HM_VLAN_MOD_EGRESS_QTAGS) &&
			(new_vlan_params->egress.num_tags !=
				pvlan_hm->vlan_params.egress.num_tags)) {
			update = true;
			pvlan_hm->vlan_params.egress.num_tags =
					new_vlan_params->egress.num_tags;
			memcpy(pvlan_hm->vlan_params.egress.qtag,
				new_vlan_params->egress.qtag,
				pvlan_hm->vlan_params.egress.num_tags *
					sizeof(struct vlan_header));
		}

		if ((modify_flags & DPA_CLS_HM_VLAN_MOD_EGRESS_UPDATE_OP) &&
			(new_vlan_params->egress.update_op !=
				pvlan_hm->vlan_params.egress.update_op)) {
			update = true;
			pvlan_hm->vlan_params.egress.update_op =
					new_vlan_params->egress.update_op;
		}

		if ((modify_flags & DPA_CLS_HM_VLAN_MOD_EGRESS_VPRI) &&
			(new_vlan_params->egress.update.vpri !=
				pvlan_hm->vlan_params.egress.update.vpri)) {
			update = true;
			pvlan_hm->vlan_params.egress.update.vpri =
					new_vlan_params->egress.update.vpri;
		}

		if (modify_flags &
			DPA_CLS_HM_VLAN_MOD_EGRESS_DSCP_TO_VPRI_ARRAY) {
			update = true;
			memcpy(pvlan_hm->vlan_params.egress.update.dscp_to_vpri,
				new_vlan_params->egress.update.dscp_to_vpri,
				DPA_CLS_HM_DSCP_TO_VPRI_TABLE_SIZE);
		}
	}

	if (update) {
		ret = vlan_hm_update_params(pvlan_hm);
		if (ret == 0) {
			t_FmPcdManipParams new_hm_node_params;

			hm_node = pvlan_hm->hm_node[0];

			/*
			 * Have to make a copy of the manip node params because
			 * ManipNodeReplace does not accept h_NextManip != NULL.
			 */
			memcpy(&new_hm_node_params, &hm_node->params,
						sizeof(new_hm_node_params));
			new_hm_node_params.h_NextManip = NULL;
			error = FM_PCD_ManipNodeReplace(hm_node->node,
							&new_hm_node_params);
			if (error != E_OK) {
				release_desc_table(&hm_array);
				mutex_unlock(&pvlan_hm->access);
				log_err("FMan driver call failed - "
					"FM_PCD_ManipNodeReplace, while trying "
					"to modify hmd=%d, manip node "
					"handle=0x%p.\n", hmd, hm_node->node);
				return -EBUSY;
			}
		}
	}

	release_desc_table(&hm_array);
	mutex_unlock(&pvlan_hm->access);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}
EXPORT_SYMBOL(dpa_classif_modify_vlan_hm);

int dpa_classif_set_mpls_hm(const struct dpa_cls_hm_mpls_params	*mpls_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_mpls_resources	*res)
{
	int err;
	struct dpa_cls_hm *pmpls_hm, *pcurrent;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!mpls_params) {
		log_err("\"mpls_params\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!hmd) {
		log_err("\"hmd\" cannot be NULL.\n");
		return -EINVAL;
	}

	*hmd = DPA_OFFLD_DESC_NONE;

	err = mpls_hm_check_params(mpls_params);
	if (err < 0) {
		log_err("Invalid MPLS specific HM parameters.\n");
		return err;
	}

	err = create_new_hm_op(hmd, next_hmd);
	if (err < 0) {
		log_err("Failed to create MPLS specific HM op.\n");
		return err;
	}

	pmpls_hm = (struct dpa_cls_hm *) hm_array.object[*hmd];

	pmpls_hm->type		= DPA_CLS_HM_TYPE_MPLS;
	pmpls_hm->chain_head	= chain_head;

	/* Copy the VLAN specific HM parameters locally */
	memcpy(&pmpls_hm->mpls_params, mpls_params, sizeof(*mpls_params));

	err = mpls_hm_prepare_nodes(pmpls_hm, res);
	if (err < 0) {
		log_err("Failed to acquire necessary HM nodes.\n");
		goto mpls_hm_error;
	}

	err = mpls_hm_update_params(pmpls_hm);
	if (err < 0) {
		log_err("Failed to update low level header manipulation "
			"parameters.\n");
		goto mpls_hm_error;
	}

	if (chain_head) {
		err = init_hm_chain(pmpls_hm->mpls_params.fm_pcd,
				pmpls_hm->hm_chain,
				pmpls_hm->hm_chain->next);
		if (err < 0)
			log_err("Failed to initialize low level HM chain.\n");
	}

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pmpls_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;

mpls_hm_error:

	/* Release the high level HM op chain */
	RELEASE_HM_OP_CHAIN(pmpls_hm);

	lock_desc_table(&hm_array);
	remove_hm_op(*hmd);
	release_desc_table(&hm_array);

	*hmd = DPA_OFFLD_DESC_NONE;

	return err;
}
EXPORT_SYMBOL(dpa_classif_set_mpls_hm);

static int mpls_hm_prepare_nodes(struct dpa_cls_hm *pmpls_hm,
				const struct dpa_cls_hm_mpls_resources *res)
{
	struct dpa_cls_hm_node *hm_node;
	void * const *phm_nodes;
	int err = 0;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pmpls_hm);

	pmpls_hm->num_nodes = 1;

	if (res) { /* Import HM nodes */
		phm_nodes = &res->ins_rm_node;

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
			__LINE__));

		return import_hm_nodes_to_chain(phm_nodes,
					pmpls_hm->num_nodes,
					pmpls_hm);
	}

	hm_node = try_compatible_node(pmpls_hm);
	if (hm_node == NULL) {
		/* Create a header manip node for this insert: */
		hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);

		dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d): Created new hm_node = 0x%p\n",
			__func__, __LINE__, hm_node));
		if (!hm_node) {
			log_err("No more memory for header manip nodes.\n");
			return -ENOMEM;
		}

		INIT_LIST_HEAD(&hm_node->list_node);

		/* Initialize dontParseAfterManip to TRUE */
		hm_node->params.u.hdr.dontParseAfterManip = TRUE;
	}

	pmpls_hm->hm_node[0] = hm_node;

	add_local_hm_nodes_to_chain(pmpls_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return err;
}

static int mpls_hm_update_params(struct dpa_cls_hm *pmpls_hm)
{
	struct dpa_cls_hm_node *hm_node = NULL;
	uint8_t size;
	uint8_t *pdata;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	BUG_ON(!pmpls_hm);
	BUG_ON(pmpls_hm->num_nodes != 1);
	BUG_ON(!pmpls_hm->hm_node[0]);

	hm_node = pmpls_hm->hm_node[0];

	hm_node->params.type = e_FM_PCD_MANIP_HDR;
	hm_node->params.u.hdr.dontParseAfterManip &=
			(pmpls_hm->mpls_params.reparse) ? FALSE : TRUE;

	switch (pmpls_hm->mpls_params.type) {
	case DPA_CLS_HM_MPLS_REMOVE_ALL_LABELS:
		hm_node->params.u.hdr.rmv = TRUE;
		hm_node->params.u.hdr.rmvParams.type =
					e_FM_PCD_MANIP_RMV_BY_HDR;
		hm_node->params.u.hdr.rmvParams.u.byHdr.type =
					e_FM_PCD_MANIP_RMV_BY_HDR_SPECIFIC_L2;
		hm_node->params.u.hdr.rmvParams.u.byHdr.u.specificL2 =
					e_FM_PCD_MANIP_HDR_RMV_MPLS;

		break;
	case DPA_CLS_HM_MPLS_INSERT_LABELS:
		hm_node->params.u.hdr.insrt = TRUE;
		hm_node->params.u.hdr.insrtParams.type =
					e_FM_PCD_MANIP_INSRT_BY_HDR;
		hm_node->params.u.hdr.insrtParams.u.byHdr.type =
					e_FM_PCD_MANIP_INSRT_BY_HDR_SPECIFIC_L2;
		hm_node->params.u.hdr.insrtParams.u.byHdr.u.specificL2Params.
					specificL2 =
					e_FM_PCD_MANIP_HDR_INSRT_MPLS;

		size = (uint8_t) (pmpls_hm->mpls_params.num_labels *
						sizeof(struct mpls_header));
		pdata = kzalloc(size, GFP_KERNEL);
		if (!pdata) {
			log_err("Not enough memory for MPLS specific HM.\n");
			kfree(hm_node);
			return -ENOMEM;
		}

		memcpy(pdata, pmpls_hm->mpls_params.mpls_hdr, size);

		kfree(hm_node->params.u.hdr.insrtParams.u.byHdr.u.
						specificL2Params.p_Data);

		hm_node->params.u.hdr.insrtParams.u.byHdr.u.specificL2Params.
			size = size;
		hm_node->params.u.hdr.insrtParams.u.byHdr.u.specificL2Params.
			p_Data = pdata;

		break;
	default:
		/* Should never get here */
		BUG_ON(1);
		break;
	}

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_mpls_hm(int hmd,
	const struct dpa_cls_hm_mpls_params *new_mpls_params, int modify_flags)
{
	struct dpa_cls_hm_node *hm_node;
	struct dpa_cls_hm *pmpls_hm;
	bool update = false;
	t_Error error;
	int ret = 0;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	if (!modify_flags)
		/* Nothing to do */
		return 0;

	/* Parameters sanity checks: */
	if (!new_mpls_params) {
		log_err("\"new_mpls_params\" cannot be NULL.\n");
		return -EINVAL;
	}

	lock_desc_table(&hm_array);
	pmpls_hm = desc_to_object(&hm_array, hmd);
	if (!pmpls_hm) {
		release_desc_table(&hm_array);
		log_err("Invalid descriptor (%d).\n", hmd);
		return -EINVAL;
	}
	mutex_lock(&pmpls_hm->access);
	/*
	 * Hold the lock on the descriptor table to prevent other runtime
	 * modifications of header manipulations until we're finished. The FMan
	 * driver doesn't allow parallel modification of HM nodes when they
	 * belong to the same PCD.
	 */

	if (pmpls_hm->type != DPA_CLS_HM_TYPE_MPLS) {
		release_desc_table(&hm_array);
		mutex_unlock(&pmpls_hm->access);
		log_err("hmd=%d is not an MPLS type header manip.\n", hmd);
		return -EINVAL;
	}

	if ((modify_flags && DPA_CLS_HM_MPLS_MOD_NUM_LABELS) &&
		(pmpls_hm->mpls_params.num_labels !=
						new_mpls_params->num_labels)) {
		update = true;
		pmpls_hm->mpls_params.num_labels =
					new_mpls_params->num_labels;
	}

	if (modify_flags && DPA_CLS_HM_MPLS_MOD_HDR_ARRAY) {
		update = true;
		memcpy(pmpls_hm->mpls_params.mpls_hdr,
			new_mpls_params->mpls_hdr,
			pmpls_hm->mpls_params.num_labels *
				sizeof(struct mpls_header));
	}

	if (update) {
		ret = mpls_hm_update_params(pmpls_hm);
		if (ret == 0) {
			t_FmPcdManipParams new_hm_node_params;

			hm_node = pmpls_hm->hm_node[0];

			/*
			 * Have to make a copy of the manip node params because
			 * ManipNodeReplace does not accept h_NextManip != NULL.
			 */
			memcpy(&new_hm_node_params, &hm_node->params,
						sizeof(new_hm_node_params));
			new_hm_node_params.h_NextManip = NULL;
			error = FM_PCD_ManipNodeReplace(hm_node->node,
							&new_hm_node_params);
			if (error != E_OK) {
				release_desc_table(&hm_array);
				mutex_unlock(&pmpls_hm->access);
				log_err("FMan driver call failed - "
					"FM_PCD_ManipNodeReplace, while trying "
					"to modify hmd=%d, manip node "
					"handle=0x%p.\n", hmd, hm_node->node);
				return -EBUSY;
			}
		}
	}

	release_desc_table(&hm_array);
	mutex_unlock(&pmpls_hm->access);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return ret;
}
EXPORT_SYMBOL(dpa_classif_modify_mpls_hm);

int dpa_classif_import_static_hm(void *hm, int next_hmd, int *hmd)
{
	int err;
	struct dpa_cls_hm *pstatic_hm, *pcurrent;
	struct dpa_cls_hm_node *hm_node;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	/* Parameters sanity checks: */
	if (!hm) {
		log_err("\"hm\" cannot be NULL.\n");
		return -EINVAL;
	}
	if (!hmd) {
		log_err("\"hmd\" cannot be NULL.\n");
		return -EINVAL;
	}

	err = create_new_hm_op(hmd, next_hmd);
	if (err < 0) {
		log_err("Failed to create static HM op.\n");
		return err;
	}

	pstatic_hm = (struct dpa_cls_hm *) hm_array.object[*hmd];

	pstatic_hm->type = DPA_CLS_HM_TYPE_STATIC;

	/* Create a header manip node: */
	hm_node = kzalloc(sizeof(*hm_node), GFP_KERNEL);
	if (!hm_node) {
		RELEASE_HM_OP_CHAIN(pstatic_hm);
		log_err("No more memory for header manip nodes.\n");
		return -ENOMEM;
	}

	hm_node->node		= hm;
	hm_node->params.type	= -1; /* to identify an unknown HM */
	INIT_LIST_HEAD(&hm_node->list_node);

	pstatic_hm->hm_node[0]	= hm_node;
	pstatic_hm->num_nodes	= 1;

	add_local_hm_nodes_to_chain(pstatic_hm);

	if (!list_empty(&pstatic_hm->list_node))
		/*
		 * Move the "chain head" flag on the current header
		 * manipulation
		 */
		list_for_each_entry(pcurrent,
				&pstatic_hm->list_node,
				list_node) {
			pcurrent->chain_head = false;
		}
	pstatic_hm->chain_head = true;

	RELEASE_HM_OP_CHAIN(pstatic_hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}

void *dpa_classif_get_static_hm_handle(int hmd)
{
	struct dpa_cls_hm *hm;
	void *node;

	if (hmd == DPA_OFFLD_DESC_NONE)
		/* Nothing to do */
		return NULL;

	LOCK_OBJECT(hm_array, hmd, hm, NULL);

	if (hm->type != DPA_CLS_HM_TYPE_STATIC) {
		RELEASE_OBJECT(hm);
		return NULL;
	}

	node = hm->hm_node[0]->node;

	RELEASE_OBJECT(hm);

	return node;
}

void *dpa_classif_hm_lock_chain(int hmd)
{
	struct dpa_cls_hm *hm, *pcurrent;
	struct dpa_cls_hm_node *hm_node;
	void *node;

	if (hmd == DPA_OFFLD_DESC_NONE)
		/* Nothing to do */
		return NULL;

	lock_desc_table(&hm_array);
	hm = desc_to_object(&hm_array, hmd);
	if (!hm) {
		release_desc_table(&hm_array);
		log_err("Invalid descriptor (%d).\n", hmd);
		return NULL;
	}
	LOCK_HM_OP_CHAIN(hm);
	release_desc_table(&hm_array);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) --> Locking hm chain of hmd=%d.\n",
		__func__, __LINE__, hmd));
	/* Lock all HM nodes */
	list_for_each_entry(hm_node, hm->hm_chain, list_node) {
		hm_node->ref++;
		dpa_cls_hm_dbg(("hm_node=%p INCREASED to ref=%u\n",
			hm_node->node, hm_node->ref));
	}

	/*
	 * Acquire the hm_node structure that is head of the header manipulation
	 * chain
	 */
	hm_node = list_entry(hm->hm_chain->next,
				struct dpa_cls_hm_node,
				list_node);
	node = hm_node->node;

	RELEASE_HM_OP_CHAIN(hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__, __LINE__));

	return node;
}

void dpa_classif_hm_release_chain(int hmd)
{
	struct dpa_cls_hm *hm, *pcurrent;
	struct dpa_cls_hm_node *hm_node;

	if (hmd == DPA_OFFLD_DESC_NONE)
		/* Nothing to do */
		return;

	lock_desc_table(&hm_array);
	hm = desc_to_object(&hm_array, hmd);
	if (!hm) {
		release_desc_table(&hm_array);
		log_err("Invalid descriptor (%d).\n", hmd);
		return;
	}
	LOCK_HM_OP_CHAIN(hm);
	release_desc_table(&hm_array);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) --> Releasing hm chain of hmd=%d.\n",
		__func__, __LINE__, hmd));

	/* Release all HM nodes */
	list_for_each_entry(hm_node, hm->hm_chain, list_node)
		if (hm_node->ref) {
			hm_node->ref--;
			dpa_cls_hm_dbg(("hm_node=%p DECREASED to ref=%u\n",
				hm_node->node, hm_node->ref));
		} else
			log_warn("Unbalanced HM node release on manip "
				"node=0x%p.\n", hm_node->node);

	RELEASE_HM_OP_CHAIN(hm);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__, __LINE__));
}

bool dpa_classif_hm_is_chain_head(int hmd)
{
	struct dpa_cls_hm *hm;
	bool chain_head;

	if (hmd == DPA_OFFLD_DESC_NONE)
		/* Nothing to do */
		return false;

	LOCK_OBJECT(hm_array, hmd, hm, NULL);

	chain_head = hm->chain_head;

	RELEASE_OBJECT(hm);

	return chain_head;
}

void *dpa_classif_get_frag_hm_handle(int hmd)
{
	struct dpa_cls_hm *hm, *pcurrent;
	struct dpa_cls_hm_node *p;
	void *frag_hm_handle = NULL;

	if (hmd == DPA_OFFLD_DESC_NONE)
		/* Nothing to do */
		return NULL;

	lock_desc_table(&hm_array);
	hm = desc_to_object(&hm_array, hmd);
	if (!hm) {
		release_desc_table(&hm_array);
		log_err("Invalid descriptor (%d).\n", hmd);
		return NULL;
	}
	LOCK_HM_OP_CHAIN(hm);
	release_desc_table(&hm_array);

	list_for_each_entry(p, hm->hm_chain, list_node)
		if ((p->node) && (p->params.type ==
							e_FM_PCD_MANIP_FRAG)) {
			frag_hm_handle = p->node;
			break;
		}

	RELEASE_HM_OP_CHAIN(hm);

	return frag_hm_handle;
}

int dpa_classif_free_hm(int hmd)
{
	struct dpa_cls_hm *phm, *pcurrent;
	struct dpa_cls_hm_node *hm_node;
	int i = 1;

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) -->\n", __func__,
		__LINE__));

	lock_desc_table(&hm_array);
	phm = desc_to_object(&hm_array, hmd);
	if (!phm) {
		release_desc_table(&hm_array);
		/* Descriptor already free */
		return 0;
	}
	LOCK_HM_OP_CHAIN(phm);

	/* Verify whether this header manipulation chain is in use */
	list_for_each_entry(hm_node, phm->hm_chain, list_node) {
		if (hm_node->ref) {
			release_desc_table(&hm_array);
			RELEASE_HM_OP_CHAIN(phm);
			log_err("Unable to remove HM chain hmd=%d. Manip node "
				"#%d (0x%p) is still in use by %d "
				"entity(ies).\n", hmd, i, hm_node->node,
				hm_node->ref);
			return -EBUSY;
		}
		i++;
	}

	if (phm->chain_head) {
		/*
		 * This is a header manip chain head, hence remove the entire
		 * chain of low level ops
		 */
		if (remove_hm_chain(phm->hm_chain, phm->hm_chain->next) < 0)
			log_warn("Not all low level HM nodes could be "
				"removed for chain hmd=%d.\n", hmd);
	}

	RELEASE_HM_OP_CHAIN(phm);

	remove_hm_op(hmd);
	release_desc_table(&hm_array);

	dpa_cls_hm_dbg(("DEBUG: dpa_hm %s (%d) <--\n", __func__,
		__LINE__));

	return 0;
}
EXPORT_SYMBOL(dpa_classif_free_hm);

#if (DPAA_VERSION >= 11)
int dpa_classif_mcast_create_group(
		const struct dpa_cls_mcast_group_params *group_params,
		int *grpd,
		const struct dpa_cls_mcast_group_resources *res)
{

	int err = 0;
	struct dpa_cls_mcast_group *pgroup;
	int member_id;
	uint8_t max_members;
	struct dpa_cls_tbl_enq_action_desc	*member_params;
	t_FmPcdFrmReplicGroupParams		*replic_grp_params = NULL;
	t_FmPcdCcNextEngineParams		*next_engine_params;

	if (!group_params) {
		log_err("Invalid value for group params.\n");
		err = -EINVAL;
		return err;
	}

	if (!grpd) {
		log_err("Invalid group desc\n");
		err = -EINVAL;
		return err;
	}

	if (!group_params->max_members) {
		log_err("Invalid value for maximum number of members in a "
			"group\n");
		err = -EINVAL;
		return err;
	}

	if ((group_params->max_members > DPA_CLS_MCAST_MAX_NUM_OF_ENTRIES)) {
		log_err("Maximum number of members in group is greater than "
			"%d\n", DPA_CLS_MCAST_MAX_NUM_OF_ENTRIES);
		err = -EINVAL;
		return err;
	}

	pgroup = kzalloc(sizeof(struct dpa_cls_mcast_group), GFP_KERNEL);
	if (!pgroup) {
		log_err("No more memory for DPA multicast groups.\n");
		err = -ENOMEM;
		goto dpa_classif_mcast_create_group_error;
	}

	mutex_init(&pgroup->access);

	if (group_params->prefilled_members > group_params->max_members) {
		log_err("Number of prefilled members is greater than the "
			"maximum number of members in group. %d > %d\n",
			group_params->prefilled_members,
			group_params->max_members);
		err = -EINVAL;
		goto dpa_classif_mcast_create_group_error;
	}

	max_members = group_params->max_members;
	*grpd = DPA_OFFLD_DESC_NONE;
	lock_desc_table(&mcast_grp_array);
	err = acquire_descriptor(&mcast_grp_array, pgroup, grpd);
	release_desc_table(&mcast_grp_array);
	if (err < 0)
		goto dpa_classif_mcast_create_group_error;

	memcpy(&pgroup->group_params, group_params,
		sizeof(struct dpa_cls_mcast_group_params));

	/*
	 * initialize the array of indexes of used members
	 */
	pgroup->member_ids = kzalloc(sizeof(int) * max_members, GFP_KERNEL);
	if (!pgroup->member_ids) {
		log_err("No more memory for DPA multicast index members array.\n");
		err = -ENOMEM;
		goto dpa_classif_mcast_create_group_error;
	}

	/*
	 * initialize the array of used members
	 */
	pgroup->entries = kzalloc(sizeof(struct members) * max_members,
				  GFP_KERNEL);
	if (!pgroup->entries) {
		log_err("No more memory for DPA multicast member entries.\n");
		err = -ENOMEM;
		goto dpa_classif_mcast_create_group_error;
	}

	for (member_id = 0; member_id < max_members; member_id++) {
		pgroup->entries[member_id].used = false;
		pgroup->entries[member_id].hmd = DPA_OFFLD_DESC_NONE;
		pgroup->member_ids[member_id] = DPA_OFFLD_DESC_NONE;
	}

	/* Group is not imported */
	if (!res) {
		/*
		 * set parameters for the first member
		 */
		member_params = &pgroup->group_params.first_member_params;
		replic_grp_params = kzalloc(sizeof(t_FmPcdFrmReplicGroupParams),
					    GFP_KERNEL);
		if (!replic_grp_params) {
			log_err("No more memory for DPA multicast group "
				"params.\n");
			err = -ENOMEM;
			goto dpa_classif_mcast_create_group_error;
		}

		replic_grp_params->maxNumOfEntries = max_members;
		replic_grp_params->numOfEntries = pgroup->num_members + 1;
		next_engine_params = &replic_grp_params->nextEngineParams[0];

		if (member_params->distribution) {
			/* Redirect frames to KeyGen direct scheme */
			next_engine_params->nextEngine = e_FM_PCD_KG;
			next_engine_params->params.kgParams.h_DirectScheme =
						member_params->distribution;
			next_engine_params->params.kgParams.newFqid =
						member_params->new_fqid;
			if (member_params->override_fqid)
				next_engine_params->params.kgParams.
							overrideFqid = TRUE;
		} else {
			if (member_params->policer_params) {
				next_engine_params->nextEngine = e_FM_PCD_PLCR;
				next_engine_params->params.plcrParams.
					sharedProfile =
				member_params->policer_params->shared_profile;
				next_engine_params->params.plcrParams.
					newRelativeProfileId =
			      member_params->policer_params->new_rel_profile_id;
				next_engine_params->params.plcrParams.
					overrideParams =
			   member_params->policer_params->modify_policer_params;
				next_engine_params->params.plcrParams.
					newFqid =  member_params->new_fqid;
			} else {
				next_engine_params->nextEngine = e_FM_PCD_DONE;
				next_engine_params->params.enqueueParams.
					newRelativeStorageProfileId =
						  member_params->new_rel_vsp_id;
				next_engine_params->params.enqueueParams.
						   action =
							     e_FM_PCD_ENQ_FRAME;
				next_engine_params->params.enqueueParams.
					overrideFqid =
						   member_params->override_fqid;
				next_engine_params->params.enqueueParams.
					newFqid =
						   member_params->new_fqid;
			}

		}
		if (member_params->hmd != DPA_OFFLD_DESC_NONE) {
			pgroup->entries[0].hmd = member_params->hmd;
			next_engine_params->h_Manip = (t_Handle)
				dpa_classif_hm_lock_chain(member_params->hmd);
			if (!next_engine_params->h_Manip) {
				log_err("Failed to attach HM op hmd=%d to "
					"multicast entry.\n",
					member_params->hmd);
				err = -EINVAL;
				goto dpa_classif_mcast_create_group_error;
			}
		} else
			next_engine_params->h_Manip = NULL;

		pgroup->group = FM_PCD_FrmReplicSetGroup(group_params->fm_pcd,
							replic_grp_params);
		/* A newly created group has at least one member - member 0 */
		pgroup->entries[0].used = true;
		pgroup->member_ids[0] = 0;
		pgroup->num_members++;
	} else {
		pgroup->group = res->group_node;
		/* mark prefilled members in index array member */
		for (member_id = 0; member_id < group_params->prefilled_members;
		     member_id++) {
			pgroup->entries[member_id].used = true;
			pgroup->member_ids[member_id] = member_id;
			pgroup->last_index = member_id;
		}
		pgroup->num_members = group_params->prefilled_members;
	}

	kfree(replic_grp_params);
	replic_grp_params = NULL;

	if (!pgroup->group) {
		log_err("Could not create %s group %d\n",
			(group_params->prefilled_members > 0) ? "imported" :
			"", *grpd);
		err = -EINVAL;
		goto dpa_classif_mcast_create_group_error;
	}

	return 0;

dpa_classif_mcast_create_group_error:
	if (pgroup) {
		if (pgroup->entries) {
			dpa_classif_hm_release_chain(pgroup->entries[0].hmd);
			kfree(pgroup->entries);
		}
		kfree(pgroup->member_ids);
		mutex_destroy(&pgroup->access);
		if (*grpd != DPA_OFFLD_DESC_NONE) {
			lock_desc_table(&mcast_grp_array);
			put_descriptor(&mcast_grp_array, *grpd);
			release_desc_table(&mcast_grp_array);
		}
		kfree(pgroup);
	}
	kfree(replic_grp_params);

	*grpd = DPA_OFFLD_DESC_NONE;

	return err;
}
EXPORT_SYMBOL(dpa_classif_mcast_create_group);

int dpa_classif_mcast_add_member(int grpd,
		const struct dpa_cls_tbl_enq_action_desc *member_params,
		int *md)
{
	struct dpa_cls_mcast_group *pgroup;
	int member_id;
	unsigned int prefill_start;
	uint8_t max_members;
	t_Error err = 0;
	t_FmPcdFrmReplicGroupParams	*replic_grp_params = NULL;
	t_FmPcdCcNextEngineParams	*next_engine_params;

	lock_desc_table(&mcast_grp_array);
	pgroup = desc_to_object(&mcast_grp_array, grpd);
	if (!pgroup) {
		release_desc_table(&mcast_grp_array);
		log_err("Invalid group descriptor (grpd=%d).\n", grpd);
		return -EINVAL;
	}

	mutex_lock(&pgroup->access);
	release_desc_table(&mcast_grp_array);

	if (!member_params) {
		mutex_unlock(&pgroup->access);
		log_err("Invalid value for member params.\n");
		return -EINVAL;
	}

	if (!md) {
		mutex_unlock(&pgroup->access);
		log_err("Invalid member desc.\n");
		return -EINVAL;
	}

	*md = DPA_OFFLD_DESC_NONE;
	if (pgroup->num_members == pgroup->group_params.max_members) {
		mutex_unlock(&pgroup->access);
		log_err("Current number of members reached maximum value %d.\n",
			pgroup->group_params.max_members);
		return -ENOSPC;
	}

	max_members = pgroup->group_params.max_members;
	prefill_start = pgroup->group_params.prefilled_members;
	for (member_id = prefill_start; member_id < max_members; member_id++)
		if (pgroup->entries[member_id].used == false) {
			*md = member_id;
			break;
		}

	pgroup->entries[*md].used = true;
	pgroup->num_members++;

	if (unlikely(pgroup->member_ids[*md] != DPA_OFFLD_DESC_NONE)) {
		log_err("Current member index %d is already in use.\n", *md);
		mutex_unlock(&pgroup->access);
		return -ENOSPC;
	}

	/* A newly added member is always the last member in the group */
	pgroup->last_index++;
	pgroup->member_ids[*md] = pgroup->last_index;

	replic_grp_params = kzalloc(sizeof(t_FmPcdFrmReplicGroupParams),
				    GFP_KERNEL);
	if (!replic_grp_params) {
		log_err("No more memory for DPA multicast group params.\n");
		err = -ENOMEM;
		goto dpa_classif_mcast_add_member_error;
	}

	replic_grp_params->maxNumOfEntries = max_members;
	replic_grp_params->numOfEntries = pgroup->num_members;
	next_engine_params = &replic_grp_params->nextEngineParams[0];
	if (member_params->distribution) {
		/* Redirect frames to KeyGen direct scheme */
		next_engine_params->nextEngine = e_FM_PCD_KG;
		next_engine_params->params.kgParams.h_DirectScheme =
						member_params->distribution;
		next_engine_params->params.kgParams.newFqid =
					member_params->new_fqid;
		if (member_params->override_fqid)
			next_engine_params->params.kgParams.
							overrideFqid = TRUE;
	} else {
		if (member_params->policer_params) {
			next_engine_params->nextEngine = e_FM_PCD_PLCR;
			next_engine_params->params.plcrParams.
				sharedProfile =
				member_params->policer_params->shared_profile;

			next_engine_params->params.plcrParams.
				newRelativeProfileId =
			      member_params->policer_params->new_rel_profile_id;
			next_engine_params->params.plcrParams.overrideParams =
			   member_params->policer_params->modify_policer_params;
			next_engine_params->params.plcrParams.newFqid =
							member_params->new_fqid;
		} else {
			next_engine_params->nextEngine = e_FM_PCD_DONE;
			next_engine_params->params.enqueueParams.
				newRelativeStorageProfileId =
						  member_params->new_rel_vsp_id;
			next_engine_params->params.enqueueParams.action =
							     e_FM_PCD_ENQ_FRAME;
			next_engine_params->params.enqueueParams.overrideFqid =
						   member_params->override_fqid;
			next_engine_params->params.enqueueParams.newFqid =
							member_params->new_fqid;
		}
	}

	if (member_params->hmd != DPA_OFFLD_DESC_NONE) {
		pgroup->entries[*md].hmd = member_params->hmd;
		next_engine_params->h_Manip = (t_Handle)
				dpa_classif_hm_lock_chain(member_params->hmd);
		if (!next_engine_params->h_Manip) {
			log_err("Failed to attach HM op hmd=%d to multicast "
				"entry.\n", member_params->hmd);
			err = -EINVAL;
			goto dpa_classif_mcast_add_member_error;
		}
	} else
		next_engine_params->h_Manip = NULL;

	err = FM_PCD_FrmReplicAddMember(pgroup->group,
					pgroup->member_ids[*md],
					next_engine_params);
	if (err != E_OK) {
		log_err("Could not add member (%d) to the group (%d)\n", *md,
			grpd);
		err = -EINVAL;
		goto dpa_classif_mcast_add_member_error;
	}
	mutex_unlock(&pgroup->access);
	kfree(replic_grp_params);
	return 0;

dpa_classif_mcast_add_member_error:

	pgroup->entries[*md].used = false;
	dpa_classif_hm_release_chain(pgroup->entries[*md].hmd);
	pgroup->entries[*md].hmd = DPA_OFFLD_DESC_NONE;
	pgroup->num_members--;
	*md = DPA_OFFLD_DESC_NONE;

	pgroup->member_ids[*md] = DPA_OFFLD_DESC_NONE;
	pgroup->last_index--;
	mutex_unlock(&pgroup->access);
	kfree(replic_grp_params);

	return err;
}
EXPORT_SYMBOL(dpa_classif_mcast_add_member);

int dpa_classif_mcast_remove_member(int grpd, int md)
{
	struct dpa_cls_mcast_group *pgroup;
	int member_id;
	uint8_t max_members;
	t_Error err = 0;

	lock_desc_table(&mcast_grp_array);
	pgroup = desc_to_object(&mcast_grp_array, grpd);
	if (!pgroup) {
		release_desc_table(&mcast_grp_array);
		log_err("Invalid group descriptor (grpd=%d).\n", grpd);
		return -EINVAL;
	}

	mutex_lock(&pgroup->access);
	release_desc_table(&mcast_grp_array);

	if (pgroup->num_members <= 1) {
		mutex_unlock(&pgroup->access);
		log_err("Last member in group cannot be removed (md=%d).\n",
			md);
		return -EINVAL;
	}

	if ((md < 0) || (md > pgroup->group_params.max_members)) {
		mutex_unlock(&pgroup->access);
		log_err("Invalid member descriptor (md=%d).\n", md);
		return -EINVAL;
	}

	if (pgroup->member_ids[md] == DPA_OFFLD_DESC_NONE) {
		mutex_unlock(&pgroup->access);
		log_err("Member was already removed (md=%d).\n", md);
		return -EINVAL;
	}

	err = FM_PCD_FrmReplicRemoveMember(pgroup->group,
					   pgroup->member_ids[md]);
	if (err != E_OK) {
		mutex_unlock(&pgroup->access);
		log_err("Could not remove member %d from group %d\n", md, grpd);
		return -EINVAL;
	}

	pgroup->num_members--;
	pgroup->entries[md].used = false;
	dpa_classif_hm_release_chain(pgroup->entries[md].hmd);
	pgroup->entries[md].hmd = DPA_OFFLD_DESC_NONE;
	max_members = pgroup->group_params.max_members;

	/* update indexes in index array when removing a member */
	for (member_id = 0; member_id < max_members; member_id++) {
		/* update all indexes greater than the removed index */
		if (pgroup->member_ids[member_id] > pgroup->member_ids[md])
				pgroup->member_ids[member_id]--;
	}

	pgroup->member_ids[md] = DPA_OFFLD_DESC_NONE;
	pgroup->last_index--;
	mutex_unlock(&pgroup->access);

	return 0;
}
EXPORT_SYMBOL(dpa_classif_mcast_remove_member);

int dpa_classif_mcast_free_group(int grpd)
{
	struct dpa_cls_mcast_group *pgroup;
	int member_id;
	uint8_t max_members;
	t_Error err = 0;

	lock_desc_table(&mcast_grp_array);
	pgroup = desc_to_object(&mcast_grp_array, grpd);
	if (!pgroup) {
		release_desc_table(&mcast_grp_array);
		log_err("Invalid group descriptor (grpd=%d).\n", grpd);
		return -EINVAL;
	}

	mutex_lock(&pgroup->access);
	/* If no prefilled members are present, the group was not imported*/
	if (!pgroup->group_params.prefilled_members) {
		err = FM_PCD_FrmReplicDeleteGroup(pgroup->group);
		if (err != E_OK) {
			release_desc_table(&mcast_grp_array);
			mutex_unlock(&pgroup->access);
			log_err("Could not delete group (%d)\n", grpd);
			return -EINVAL;
		}
	}

	max_members = pgroup->group_params.max_members;
	for (member_id = 0; member_id < max_members; member_id++)
		dpa_classif_hm_release_chain(pgroup->entries[member_id].hmd);

	kfree(pgroup->entries);
	kfree(pgroup->member_ids);
	put_descriptor(&mcast_grp_array, grpd);
	mutex_unlock(&pgroup->access);
	mutex_destroy(&pgroup->access);
	kfree(pgroup);
	release_desc_table(&mcast_grp_array);
	return 0;
}
EXPORT_SYMBOL(dpa_classif_mcast_free_group);
#endif
