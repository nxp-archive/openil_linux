/*
 * \file: pkc.c
 * \brief: Public Key Cipher operations.
 *
 * This is the Public Key Cipher Implementation
 *
 * Author: Yashpal Dutta <yashpal.dutta@freescale.com>
 *
 * Copyright 2012 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <linux/cpumask.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <crypto/scatterwalk.h>
#include "internal.h"

static unsigned int crypto_pkc_ctxsize(struct crypto_alg *alg, u32 type,
				       u32 mask)
{
	return alg->cra_ctxsize;
}

static int crypto_init_pkc_ops(struct crypto_tfm *tfm, u32 type, u32 mask)
{
	struct pkc_alg *alg = &tfm->__crt_alg->cra_pkc;
	struct pkc_tfm *crt = &tfm->crt_pkc;

	crt->pkc_op = alg->pkc_op;
	crt->min_keysize = alg->min_keysize;
	crt->max_keysize = alg->max_keysize;
	crt->base = tfm;

	return 0;
}

static void crypto_pkc_show(struct seq_file *m, struct crypto_alg *alg)
{
	struct pkc_alg *pkc_alg = &alg->cra_pkc;

	seq_printf(m, "type         : pkc_cipher\n");
	seq_printf(m, "async        : %s\n", alg->cra_flags & CRYPTO_ALG_ASYNC ?
		   "yes" : "no");
	seq_printf(m, "min keysize  : %u\n", pkc_alg->min_keysize);
	seq_printf(m, "max keysize  : %u\n", pkc_alg->max_keysize);
}

const struct crypto_type crypto_pkc_type = {
	.ctxsize = crypto_pkc_ctxsize,
	.init = crypto_init_pkc_ops,
#ifdef CONFIG_PROC_FS
	.show = crypto_pkc_show,
#endif
};
EXPORT_SYMBOL_GPL(crypto_pkc_type);
