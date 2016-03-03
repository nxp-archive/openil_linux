/*
 * Copyright 2013 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/aead.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/authenc.h>
#include <crypto/scatterwalk.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>

struct tls_instance_ctx {
	struct crypto_ahash_spawn auth;
	struct crypto_skcipher_spawn enc;
};

struct crypto_tls_ctx {
	unsigned int reqoff;
	struct crypto_ahash *auth;
	struct crypto_ablkcipher *enc;
};

struct tls_request_ctx {
	/*
	 * cryptlen holds the payload length in the case of encryption or
	 * payload_len + icv_len + padding_len in case of decryption
	 */
	unsigned int cryptlen;
	/* working space for partial results */
	struct scatterlist icv[2];
	struct scatterlist cipher[2];
	char tail[];
};

struct async_op {
	struct completion completion;
	int err;
};

static void tls_async_op_done(struct crypto_async_request *req, int err)
{
	struct async_op *areq = req->data;

	if (err == -EINPROGRESS)
		return;

	areq->err = err;
	complete(&areq->completion);
}

static int crypto_tls_setkey(struct crypto_aead *tls, const u8 *key,
				 unsigned int keylen)
{
	unsigned int authkeylen;
	unsigned int enckeylen;
	struct crypto_tls_ctx *ctx = crypto_aead_ctx(tls);
	struct crypto_ahash *auth = ctx->auth;
	struct crypto_ablkcipher *enc = ctx->enc;
	struct rtattr *rta = (void *)key;
	struct crypto_authenc_key_param *param;
	int err = -EINVAL;

	if (!RTA_OK(rta, keylen))
		goto badkey;
	if (rta->rta_type != CRYPTO_AUTHENC_KEYA_PARAM)
		goto badkey;
	if (RTA_PAYLOAD(rta) < sizeof(*param))
		goto badkey;

	param = RTA_DATA(rta);
	enckeylen = be32_to_cpu(param->enckeylen);

	key += RTA_ALIGN(rta->rta_len);
	keylen -= RTA_ALIGN(rta->rta_len);

	if (keylen < enckeylen)
		goto badkey;

	authkeylen = keylen - enckeylen;

	crypto_ahash_clear_flags(auth, CRYPTO_TFM_REQ_MASK);
	crypto_ahash_set_flags(auth, crypto_aead_get_flags(tls) &
				    CRYPTO_TFM_REQ_MASK);
	err = crypto_ahash_setkey(auth, key, authkeylen);
	crypto_aead_set_flags(tls, crypto_ahash_get_flags(auth) &
				       CRYPTO_TFM_RES_MASK);

	if (err)
		goto out;

	crypto_ablkcipher_clear_flags(enc, CRYPTO_TFM_REQ_MASK);
	crypto_ablkcipher_set_flags(enc, crypto_aead_get_flags(tls) &
					 CRYPTO_TFM_REQ_MASK);
	err = crypto_ablkcipher_setkey(enc, key + authkeylen, enckeylen);
	crypto_aead_set_flags(tls, crypto_ablkcipher_get_flags(enc) &
				       CRYPTO_TFM_RES_MASK);
out:
	return err;

badkey:
	crypto_aead_set_flags(tls, CRYPTO_TFM_RES_BAD_KEY_LEN);
	goto out;
}

/**
 * crypto_tls_genicv - Calculate hmac digest for a TLS record
 * @hash:	(output) buffer to save the digest into
 * @src:	(input) scatterlist with the payload data
 * @srclen:	(input) size of the payload data
 * @req:	(input) aead request (with pointers to associated data)
 **/
static int crypto_tls_genicv(u8 *hash, struct scatterlist *src,
			     unsigned int srclen, struct aead_request *req)
{
	struct crypto_aead *tls = crypto_aead_reqtfm(req);
	struct crypto_tls_ctx *ctx = crypto_aead_ctx(tls);
	struct tls_request_ctx *treq_ctx = aead_request_ctx(req);
	struct scatterlist *assoc = req->assoc;
	struct scatterlist *icv = treq_ctx->icv;
	struct async_op ahash_op;
	struct ahash_request *ahreq = (void *)(treq_ctx->tail + ctx->reqoff);
	unsigned int flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	int err = -EBADMSG;

	/*
	 * Bail out as we have only two maneuvering scatterlists in icv. Check
	 * also if the request assoc len matches the scatterlist len
	 */
	if (!req->assoclen || !sg_is_last(assoc) ||
	    req->assoclen != assoc->length)
		return err;

	/*
	 * Prepend associated data to the source scatterlist. If the source is
	 * empty, use directly the associated data scatterlist
	 */
	if (srclen) {
		sg_init_table(icv, 2);
		sg_set_page(icv, sg_page(assoc), assoc->length, assoc->offset);
		scatterwalk_sg_chain(icv, 2, src);
	} else {
		icv = assoc;
	}
	srclen += assoc->length;

	init_completion(&ahash_op.completion);

	/* the hash transform to be executed comes from the original request */
	ahash_request_set_tfm(ahreq, ctx->auth);
	/* prepare the hash request with input data and result pointer */
	ahash_request_set_crypt(ahreq, icv, hash, srclen);
	/* set the notifier for when the async hash function returns */
	ahash_request_set_callback(ahreq, aead_request_flags(req) & flags,
				   tls_async_op_done, &ahash_op);

	/* Calculate the digest on the given data. The result is put in hash */
	err = crypto_ahash_digest(ahreq);
	if (err == -EINPROGRESS) {
		err = wait_for_completion_interruptible(&ahash_op.completion);
		if (!err)
			err = ahash_op.err;
	}

	return err;
}

/**
 * crypto_tls_gen_padicv - Calculate and pad hmac digest for a TLS record
 * @hash:	(output) buffer to save the digest and padding into
 * @phashlen:	(output) the size of digest + padding
 * @req:	(input) aead request
 **/
static int crypto_tls_gen_padicv(u8 *hash, unsigned int *phashlen,
			     struct aead_request *req)
{
	struct crypto_aead *tls = crypto_aead_reqtfm(req);
	unsigned int hash_size = crypto_aead_authsize(tls);
	unsigned int block_size = crypto_aead_blocksize(tls);
	unsigned int srclen = req->cryptlen + hash_size;
	unsigned int padlen;
	int err;

	err = crypto_tls_genicv(hash, req->src, req->cryptlen, req);
	if (err)
		goto out;

	/* add padding after digest */
	padlen = block_size - (srclen % block_size);
	memset(hash + hash_size, padlen - 1, padlen);

	*phashlen = hash_size + padlen;
out:
	return err;
}

static int crypto_tls_encrypt(struct aead_request *req)
{
	struct crypto_aead *tls = crypto_aead_reqtfm(req);
	struct crypto_tls_ctx *ctx = crypto_aead_ctx(tls);
	struct tls_request_ctx *treq_ctx = aead_request_ctx(req);

	unsigned int cryptlen, phashlen;
	struct scatterlist *cipher = treq_ctx->cipher;
	struct scatterlist *sg, *src_last = NULL;
	int err;
	/*
	 * The hash and the cipher are applied at different times and their
	 * requests can use the same memory space without interference
	 */
	struct ablkcipher_request *abreq = (void *)(treq_ctx->tail +
						    ctx->reqoff);
	/*
	 * The hash result is saved at the beginning of the tls request and is
	 * aligned as required by the hash transform. Enough space was
	 * allocated in crypto_tls_init_tfm to accomodate the difference. The
	 * requests themselves start later at treq_ctx->tail + ctx->reqoff so
	 * the result is not overwritten by the second (cipher) request
	 */
	u8 *hash = treq_ctx->tail;
	hash = (u8 *)ALIGN((unsigned long)hash +
			   crypto_ahash_alignmask(ctx->auth),
			   crypto_ahash_alignmask(ctx->auth) + 1);

	/*
	 * STEP 1: create ICV together with necessary padding
	 */
	err = crypto_tls_gen_padicv(hash, &phashlen, req);
	if (err)
		return err;

	/*
	 * STEP 2: Hash and padding are combined with the payload
	 * depending on the form it arrives. Scatter tables must have at least
	 * one page of data before chaining with another table and can't have
	 * an empty data page. The following code addresses these requirements.
	 *
	 * For same-destination, hash is copied directly after the
	 * payload since the buffers must have enough space for encryption.
	 * For different destination there are several casess to check.
	 * If the payload is empty, only the hash is encrypted, otherwise the
	 * payload scatterlist is merged with the hash. A special merging case
	 * is when the payload has only one page of data. In that case the
	 * payload page is moved to another scatterlist and prepared there for
	 * encryption.
	 */

	if (req->src == req->dst) {
		scatterwalk_map_and_copy(hash, req->src, req->cryptlen,
					 phashlen, 1);
	} else {
		if (req->cryptlen) {
			sg_init_table(cipher, 2);
			sg_set_buf(cipher + 1, hash, phashlen);
			if (sg_is_last(req->src)) {
				sg_set_page(cipher, sg_page(req->src),
					req->src->length, req->src->offset);
				req->src = cipher;
			} else {
				for (sg = req->src; sg; sg = sg_next(sg))
					src_last = sg;
				sg_set_page(cipher, sg_page(src_last),
					src_last->length, src_last->offset);
				scatterwalk_sg_chain(src_last, 1, cipher);
			}
		} else {
			sg_init_one(req->src, hash, phashlen);
		}
	}

	/*
	 * STEP 3: encrypt the frame and return the result
	 */
	cryptlen = req->cryptlen + phashlen;
	ablkcipher_request_set_tfm(abreq, ctx->enc);
	ablkcipher_request_set_crypt(abreq, req->src, req->dst, cryptlen,
				     req->iv);
	/* set the callback for encryption request termination */
	ablkcipher_request_set_callback(abreq, aead_request_flags(req),
					req->base.complete, req->base.data);
	/*
	 * Apply the cipher transform. The result will be in req->dst when the
	 * asynchronuous call terminates
	 */
	err = crypto_ablkcipher_encrypt(abreq);

	return err;
}

static int crypto_tls_decrypt(struct aead_request *req)
{
	struct crypto_aead *tls = crypto_aead_reqtfm(req);
	struct crypto_tls_ctx *ctx = crypto_aead_ctx(tls);
	struct tls_request_ctx *treq_ctx = aead_request_ctx(req);
	struct scatterlist *assoc = req->assoc;
	unsigned int cryptlen = req->cryptlen;
	unsigned int hash_size = crypto_aead_authsize(tls);
	unsigned int block_size = crypto_aead_blocksize(tls);
	struct ablkcipher_request *abreq = (void *)(treq_ctx->tail +
						    ctx->reqoff);
	u8 padding[255]; /* padding can be 0-255 bytes */
	u8 pad_size;
	u16 *len_field;
	u8 *ihash, *hash = treq_ctx->tail;

	int paderr = 0;
	int err = -EINVAL;
	int i;
	struct async_op ciph_op;

	/*
	 * Rule out bad packets. The input packet length must be at least one
	 * byte more than the hash_size
	 */
	if (cryptlen <= hash_size || cryptlen % block_size)
		goto out;

	/*
	 * Step 1 - Decrypt the source
	 */
	init_completion(&ciph_op.completion);

	ablkcipher_request_set_tfm(abreq, ctx->enc);
	ablkcipher_request_set_callback(abreq, aead_request_flags(req),
					tls_async_op_done, &ciph_op);
	ablkcipher_request_set_crypt(abreq, req->src, req->dst, cryptlen,
				     req->iv);
	err = crypto_ablkcipher_decrypt(abreq);
	if (err == -EINPROGRESS) {
		err = wait_for_completion_interruptible(&ciph_op.completion);
		if (!err)
			err = ciph_op.err;
	}
	if (err)
		goto out;

	/*
	 * Step 2 - Verify padding
	 * Retrieve the last byte of the payload; this is the padding size
	 */
	cryptlen -= 1;
	scatterwalk_map_and_copy(&pad_size, req->dst, cryptlen, 1, 0);

	/* RFC recommendation for invalid padding size */
	if (cryptlen < pad_size + hash_size) {
		pad_size = 0;
		paderr = -EBADMSG;
	}
	cryptlen -= pad_size;
	scatterwalk_map_and_copy(padding, req->dst, cryptlen, pad_size, 0);

	/* Padding content must be equal with pad_size. We verify it all */
	for (i = 0; i < pad_size; i++)
		if (padding[i] != pad_size)
			paderr = -EBADMSG;

	/*
	 * Step 3 - Verify hash
	 * Align the digest result as required by the hash transform. Enough
	 * space was allocated in crypto_tls_init_tfm
	 */
	hash = (u8 *)ALIGN((unsigned long)hash +
			   crypto_ahash_alignmask(ctx->auth),
			   crypto_ahash_alignmask(ctx->auth) + 1);
	/*
	 * Two bytes at the end of the associated data make the length field.
	 * It must be updated with the length of the cleartext message before
	 * the hash is calculated.
	 */
	len_field = sg_virt(assoc) + assoc->length - 2;
	cryptlen -= hash_size;
	*len_field = htons(cryptlen);

	/* This is the hash from the decrypted packet. Save it for later */
	ihash = hash + hash_size;
	scatterwalk_map_and_copy(ihash, req->dst, cryptlen, hash_size, 0);

	/* Now compute and compare our ICV with the one from the packet */
	err = crypto_tls_genicv(hash, req->dst, cryptlen, req);
	if (!err)
		err = memcmp(hash, ihash, hash_size) ? -EBADMSG : 0;

	/* return the first found error */
	if (paderr)
		err = paderr;

out:
	aead_request_complete(req, err);
	return err;
}

static int crypto_tls_init_tfm(struct crypto_tfm *tfm)
{
	struct crypto_instance *inst = crypto_tfm_alg_instance(tfm);
	struct tls_instance_ctx *ictx = crypto_instance_ctx(inst);
	struct crypto_tls_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_ahash *auth;
	struct crypto_ablkcipher *enc;
	int err;

	auth = crypto_spawn_ahash(&ictx->auth);
	if (IS_ERR(auth))
		return PTR_ERR(auth);

	enc = crypto_spawn_skcipher(&ictx->enc);
	err = PTR_ERR(enc);
	if (IS_ERR(enc))
		goto err_free_ahash;

	ctx->auth = auth;
	ctx->enc = enc;
	/*
	 * Allow enough space for two digests. The two digests will be compared
	 * during the decryption phase. One will come from the decrypted packet
	 * and the other will be calculated. For encryption, one digest is
	 * padded (up to a cipher blocksize) and chained with the payload
	 */
	ctx->reqoff = ALIGN(crypto_ahash_digestsize(auth) +
			    crypto_ahash_alignmask(auth),
			    crypto_ahash_alignmask(auth) + 1) +
		      max(crypto_ahash_digestsize(auth),
			  crypto_ablkcipher_blocksize(enc));

	tfm->crt_aead.reqsize = sizeof(struct tls_request_ctx) + ctx->reqoff +
		max_t(unsigned int,
		      crypto_ahash_reqsize(auth) +
		      sizeof(struct ahash_request),
		      crypto_ablkcipher_reqsize(enc) +
		      sizeof(struct ablkcipher_request));

	return 0;

err_free_ahash:
	crypto_free_ahash(auth);
	return err;
}

static void crypto_tls_exit_tfm(struct crypto_tfm *tfm)
{
	struct crypto_tls_ctx *ctx = crypto_tfm_ctx(tfm);

	crypto_free_ahash(ctx->auth);
	crypto_free_ablkcipher(ctx->enc);
}

static struct crypto_instance *crypto_tls_alloc(struct rtattr **tb)
{
	struct crypto_attr_type *algt;
	struct crypto_instance *inst;
	struct hash_alg_common *auth;
	struct crypto_alg *auth_base;
	struct crypto_alg *enc;
	struct tls_instance_ctx *ctx;
	const char *enc_name;
	int err;

	algt = crypto_get_attr_type(tb);
	err = PTR_ERR(algt);
	if (IS_ERR(algt))
		return ERR_PTR(err);

	if ((algt->type ^ CRYPTO_ALG_TYPE_AEAD) & algt->mask)
		return ERR_PTR(-EINVAL);

	auth = ahash_attr_alg(tb[1], CRYPTO_ALG_TYPE_HASH,
			       CRYPTO_ALG_TYPE_AHASH_MASK);
	if (IS_ERR(auth))
		return ERR_CAST(auth);

	auth_base = &auth->base;

	enc_name = crypto_attr_alg_name(tb[2]);
	err = PTR_ERR(enc_name);
	if (IS_ERR(enc_name))
		goto out_put_auth;

	inst = kzalloc(sizeof(*inst) + sizeof(*ctx), GFP_KERNEL);
	err = -ENOMEM;
	if (!inst)
		goto out_put_auth;

	ctx = crypto_instance_ctx(inst);

	err = crypto_init_ahash_spawn(&ctx->auth, auth, inst);
	if (err)
		goto err_free_inst;

	crypto_set_skcipher_spawn(&ctx->enc, inst);
	err = crypto_grab_skcipher(&ctx->enc, enc_name, 0,
				   crypto_requires_sync(algt->type,
							algt->mask));
	if (err)
		goto err_drop_auth;

	enc = crypto_skcipher_spawn_alg(&ctx->enc);

	err = -ENAMETOOLONG;
	if (snprintf(inst->alg.cra_name, CRYPTO_MAX_ALG_NAME,
		     "tls10(%s,%s)", auth_base->cra_name, enc->cra_name) >=
	    CRYPTO_MAX_ALG_NAME)
		goto err_drop_enc;

	if (snprintf(inst->alg.cra_driver_name, CRYPTO_MAX_ALG_NAME,
		     "tls10(%s,%s)", auth_base->cra_driver_name,
		     enc->cra_driver_name) >= CRYPTO_MAX_ALG_NAME)
		goto err_drop_enc;

	inst->alg.cra_flags = CRYPTO_ALG_TYPE_AEAD;
	inst->alg.cra_flags |= enc->cra_flags & CRYPTO_ALG_ASYNC;
	/* priority calculation is taken from authenc.c */
	inst->alg.cra_priority = enc->cra_priority * 10 +
				 auth_base->cra_priority;
	inst->alg.cra_blocksize = enc->cra_blocksize;
	inst->alg.cra_alignmask = auth_base->cra_alignmask | enc->cra_alignmask;
	inst->alg.cra_type = &crypto_aead_type;

	inst->alg.cra_aead.ivsize = enc->cra_ablkcipher.ivsize;
	inst->alg.cra_aead.maxauthsize = auth->digestsize;

	inst->alg.cra_ctxsize = sizeof(struct crypto_tls_ctx);

	inst->alg.cra_init = crypto_tls_init_tfm;
	inst->alg.cra_exit = crypto_tls_exit_tfm;

	inst->alg.cra_aead.setkey = crypto_tls_setkey;
	inst->alg.cra_aead.encrypt = crypto_tls_encrypt;
	inst->alg.cra_aead.decrypt = crypto_tls_decrypt;

out:
	crypto_mod_put(auth_base);
	return inst;

err_drop_enc:
	crypto_drop_skcipher(&ctx->enc);
err_drop_auth:
	crypto_drop_ahash(&ctx->auth);
err_free_inst:
	kfree(inst);
out_put_auth:
	inst = ERR_PTR(err);
	goto out;
}

static void crypto_tls_free(struct crypto_instance *inst)
{
	struct tls_instance_ctx *ctx = crypto_instance_ctx(inst);

	crypto_drop_skcipher(&ctx->enc);
	crypto_drop_ahash(&ctx->auth);
	kfree(inst);
}

static struct crypto_template crypto_tls_tmpl = {
	.name = "tls10",
	.alloc = crypto_tls_alloc,
	.free = crypto_tls_free,
	.module = THIS_MODULE,
};

static int __init crypto_tls_module_init(void)
{
	return crypto_register_template(&crypto_tls_tmpl);
}

static void __exit crypto_tls_module_exit(void)
{
	crypto_unregister_template(&crypto_tls_tmpl);
}

module_init(crypto_tls_module_init);
module_exit(crypto_tls_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TLS 1.0 record encryption");
