/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <stdbool.h>

#include <openssl/bn.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_API_LEVEL >= 30000
#include <openssl/core_names.h>
#endif
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_API_LEVEL >= 30000
#include <openssl/param_build.h>
#endif
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
#include <openssl/engine.h>
#endif

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"
#include "openssl_shim.h"

#ifndef NID_X9_62_prime256v1
#error "P-256 group is not known (NID_X9_62_prime256v1)"
#endif /* ifndef NID_X9_62_prime256v1 */
#ifndef NID_secp384r1
#error "P-384 group is not known (NID_secp384r1)"
#endif /* ifndef NID_secp384r1 */

#define DST_RET(a)        \
	{                 \
		ret = a;  \
		goto err; \
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_API_LEVEL >= 30000
static isc_result_t
raw_key_to_ossl(unsigned int key_alg, int private, const unsigned char *key,
		size_t key_len, EVP_PKEY **pkey) {
	isc_result_t ret;
	int status;
	const char *groupname;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	BIGNUM *priv = NULL;
	unsigned char buf[DNS_KEY_ECDSA384SIZE + 1];

	if (key_alg == DST_ALG_ECDSA256) {
		groupname = "P-256";
	} else if (key_alg == DST_ALG_ECDSA384) {
		groupname = "P-384";
	} else {
		DST_RET(ISC_R_NOTIMPLEMENTED);
	}

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		DST_RET(dst__openssl_toresult2("OSSL_PARAM_BLD_new",
					       DST_R_OPENSSLFAILURE));
	}
	status = OSSL_PARAM_BLD_push_utf8_string(
		bld, OSSL_PKEY_PARAM_GROUP_NAME, groupname, 0);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("OSSL_PARAM_BLD_push_"
					       "utf8_string",
					       DST_R_OPENSSLFAILURE));
	}

	if (private) {
		priv = BN_bin2bn(key, key_len, NULL);
		if (priv == NULL) {
			DST_RET(dst__openssl_toresult2("BN_bin2bn",
						       DST_R_OPENSSLFAILURE));
		}

		status = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
						priv);
		if (status != 1) {
			DST_RET(dst__openssl_toresult2("OSSL_PARAM_BLD_push_BN",
						       DST_R_OPENSSLFAILURE));
		}
	} else {
		INSIST(key_len < sizeof(buf));
		buf[0] = POINT_CONVERSION_UNCOMPRESSED;
		memmove(buf + 1, key, key_len);

		status = OSSL_PARAM_BLD_push_octet_string(
			bld, OSSL_PKEY_PARAM_PUB_KEY, buf, 1 + key_len);
		if (status != 1) {
			DST_RET(dst__openssl_toresult2("OSSL_PARAM_BLD_push_"
						       "octet_string",
						       DST_R_OPENSSLFAILURE));
		}
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		DST_RET(dst__openssl_toresult2("OSSL_PARAM_BLD_to_param",
					       DST_R_OPENSSLFAILURE));
	}
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_CTX_new_from_name",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_fromdata_init(ctx);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_fromdata_init",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_fromdata(
		ctx, pkey, private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
		params);
	if (status != 1 || *pkey == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_fromdata",
					       DST_R_OPENSSLFAILURE));
	}

	ret = ISC_R_SUCCESS;

err:
	if (params != NULL) {
		OSSL_PARAM_free(params);
	}
	if (bld != NULL) {
		OSSL_PARAM_BLD_free(bld);
	}
	if (ctx != NULL) {
		EVP_PKEY_CTX_free(ctx);
	}
	if (priv != NULL) {
		BN_clear_free(priv);
	}

	return (ret);
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_API_LEVEL >= 30000 \
	*/

static isc_result_t
opensslecdsa_createctx(dst_key_t *key, dst_context_t *dctx) {
	isc_result_t ret = ISC_R_SUCCESS;
	EVP_MD_CTX *evp_md_ctx;
	const EVP_MD *type = NULL;

	UNUSED(key);
	REQUIRE(dctx->key->key_alg == DST_ALG_ECDSA256 ||
		dctx->key->key_alg == DST_ALG_ECDSA384);
	REQUIRE(dctx->use == DO_SIGN || dctx->use == DO_VERIFY);

	evp_md_ctx = EVP_MD_CTX_create();
	if (evp_md_ctx == NULL) {
		DST_RET(ISC_R_NOMEMORY);
	}
	if (dctx->key->key_alg == DST_ALG_ECDSA256) {
		type = EVP_sha256();
	} else {
		type = EVP_sha384();
	}

	if (dctx->use == DO_SIGN) {
		if (EVP_DigestSignInit(evp_md_ctx, NULL, type, NULL,
				       dctx->key->keydata.pkey) != 1)
		{
			EVP_MD_CTX_destroy(evp_md_ctx);
			DST_RET(dst__openssl_toresult3(dctx->category,
						       "EVP_DigestSignInit",
						       ISC_R_FAILURE));
		}
	} else {
		if (EVP_DigestVerifyInit(evp_md_ctx, NULL, type, NULL,
					 dctx->key->keydata.pkey) != 1)
		{
			EVP_MD_CTX_destroy(evp_md_ctx);
			DST_RET(dst__openssl_toresult3(dctx->category,
						       "EVP_DigestVerifyInit",
						       ISC_R_FAILURE));
		}
	}

	dctx->ctxdata.evp_md_ctx = evp_md_ctx;

err:
	return (ret);
}

static void
opensslecdsa_destroyctx(dst_context_t *dctx) {
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;

	REQUIRE(dctx->key->key_alg == DST_ALG_ECDSA256 ||
		dctx->key->key_alg == DST_ALG_ECDSA384);
	REQUIRE(dctx->use == DO_SIGN || dctx->use == DO_VERIFY);

	if (evp_md_ctx != NULL) {
		EVP_MD_CTX_destroy(evp_md_ctx);
		dctx->ctxdata.evp_md_ctx = NULL;
	}
}

static isc_result_t
opensslecdsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_result_t ret = ISC_R_SUCCESS;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;

	REQUIRE(dctx->key->key_alg == DST_ALG_ECDSA256 ||
		dctx->key->key_alg == DST_ALG_ECDSA384);
	REQUIRE(dctx->use == DO_SIGN || dctx->use == DO_VERIFY);

	if (dctx->use == DO_SIGN) {
		if (EVP_DigestSignUpdate(evp_md_ctx, data->base,
					 data->length) != 1) {
			DST_RET(dst__openssl_toresult3(dctx->category,
						       "EVP_DigestSignUpdate",
						       ISC_R_FAILURE));
		}
	} else {
		if (EVP_DigestVerifyUpdate(evp_md_ctx, data->base,
					   data->length) != 1) {
			DST_RET(dst__openssl_toresult3(dctx->category,
						       "EVP_DigestVerifyUpdate",
						       ISC_R_FAILURE));
		}
	}

err:
	return (ret);
}

static int
BN_bn2bin_fixed(const BIGNUM *bn, unsigned char *buf, int size) {
	int bytes = size - BN_num_bytes(bn);

	while (bytes-- > 0) {
		*buf++ = 0;
	}
	BN_bn2bin(bn, buf);
	return (size);
}

static isc_result_t
opensslecdsa_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	isc_region_t region;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	ECDSA_SIG *ecdsasig = NULL;
	size_t siglen, sigder_len = 0, sigder_alloced = 0;
	unsigned char *sigder = NULL;
	const unsigned char *sigder_copy;
	const BIGNUM *r, *s;

	REQUIRE(key->key_alg == DST_ALG_ECDSA256 ||
		key->key_alg == DST_ALG_ECDSA384);
	REQUIRE(dctx->use == DO_SIGN);

	if (key->key_alg == DST_ALG_ECDSA256) {
		siglen = DNS_SIG_ECDSA256SIZE;
	} else {
		siglen = DNS_SIG_ECDSA384SIZE;
	}

	isc_buffer_availableregion(sig, &region);
	if (region.length < siglen) {
		DST_RET(ISC_R_NOSPACE);
	}

	if (EVP_DigestSignFinal(evp_md_ctx, NULL, &sigder_len) != 1) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestSignFinal", ISC_R_FAILURE));
	}
	if (sigder_len == 0) {
		DST_RET(ISC_R_FAILURE);
	}
	sigder = isc_mem_get(dctx->mctx, sigder_len);
	sigder_alloced = sigder_len;
	if (EVP_DigestSignFinal(evp_md_ctx, sigder, &sigder_len) != 1) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestSignFinal", ISC_R_FAILURE));
	}
	sigder_copy = sigder;
	if (d2i_ECDSA_SIG(&ecdsasig, &sigder_copy, sigder_len) == NULL) {
		DST_RET(dst__openssl_toresult3(dctx->category, "d2i_ECDSA_SIG",
					       ISC_R_FAILURE));
	}

	ECDSA_SIG_get0(ecdsasig, &r, &s);
	BN_bn2bin_fixed(r, region.base, siglen / 2);
	isc_region_consume(&region, siglen / 2);
	BN_bn2bin_fixed(s, region.base, siglen / 2);
	isc_region_consume(&region, siglen / 2);
	ECDSA_SIG_free(ecdsasig);
	isc_buffer_add(sig, siglen);
	ret = ISC_R_SUCCESS;

err:
	if (sigder != NULL && sigder_alloced != 0) {
		isc_mem_put(dctx->mctx, sigder, sigder_alloced);
	}

	return (ret);
}

static isc_result_t
opensslecdsa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	int status;
	unsigned char *cp = sig->base;
	ECDSA_SIG *ecdsasig = NULL;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	size_t siglen, sigder_len = 0, sigder_alloced = 0;
	unsigned char *sigder = NULL;
	unsigned char *sigder_copy;
	BIGNUM *r = NULL, *s = NULL;

	REQUIRE(key->key_alg == DST_ALG_ECDSA256 ||
		key->key_alg == DST_ALG_ECDSA384);
	REQUIRE(dctx->use == DO_VERIFY);

	if (key->key_alg == DST_ALG_ECDSA256) {
		siglen = DNS_SIG_ECDSA256SIZE;
	} else {
		siglen = DNS_SIG_ECDSA384SIZE;
	}

	if (sig->length != siglen) {
		DST_RET(DST_R_VERIFYFAILURE);
	}

	ecdsasig = ECDSA_SIG_new();
	if (ecdsasig == NULL) {
		DST_RET(ISC_R_NOMEMORY);
	}
	r = BN_bin2bn(cp, siglen / 2, NULL);
	cp += siglen / 2;
	s = BN_bin2bn(cp, siglen / 2, NULL);
	/* cp += siglen / 2; */
	ECDSA_SIG_set0(ecdsasig, r, s);

	status = i2d_ECDSA_SIG(ecdsasig, NULL);
	if (status < 0) {
		DST_RET(dst__openssl_toresult3(dctx->category, "i2d_ECDSA_SIG",
					       DST_R_VERIFYFAILURE));
	}

	sigder_len = (size_t)status;
	sigder = isc_mem_get(dctx->mctx, sigder_len);
	sigder_alloced = sigder_len;

	sigder_copy = sigder;
	status = i2d_ECDSA_SIG(ecdsasig, &sigder_copy);
	if (status < 0) {
		DST_RET(dst__openssl_toresult3(dctx->category, "i2d_ECDSA_SIG",
					       DST_R_VERIFYFAILURE));
	}

	status = EVP_DigestVerifyFinal(evp_md_ctx, sigder, sigder_len);

	switch (status) {
	case 1:
		ret = ISC_R_SUCCESS;
		break;
	case 0:
		ret = dst__openssl_toresult(DST_R_VERIFYFAILURE);
		break;
	default:
		ret = dst__openssl_toresult3(dctx->category,
					     "EVP_DigestVerifyFinal",
					     DST_R_VERIFYFAILURE);
		break;
	}

err:
	if (ecdsasig != NULL) {
		ECDSA_SIG_free(ecdsasig);
	}
	if (sigder != NULL && sigder_alloced != 0) {
		isc_mem_put(dctx->mctx, sigder, sigder_alloced);
	}

	return (ret);
}

static bool
opensslecdsa_compare(const dst_key_t *key1, const dst_key_t *key2) {
	bool ret;
	EVP_PKEY *pkey1 = key1->keydata.pkey;
	EVP_PKEY *pkey2 = key2->keydata.pkey;
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	EC_KEY *eckey1 = NULL;
	EC_KEY *eckey2 = NULL;
	const BIGNUM *priv1;
	const BIGNUM *priv2;
#else
	BIGNUM *priv1 = NULL;
	BIGNUM *priv2 = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	if (pkey1 == NULL && pkey2 == NULL) {
		return (true);
	} else if (pkey1 == NULL || pkey2 == NULL) {
		return (false);
	}

	/* `EVP_PKEY_eq` checks only the public key components and paramters. */
	if (EVP_PKEY_eq(pkey1, pkey2) != 1) {
		DST_RET(false);
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	eckey1 = EVP_PKEY_get1_EC_KEY(pkey1);
	eckey2 = EVP_PKEY_get1_EC_KEY(pkey2);
	if (eckey1 == NULL && eckey2 == NULL) {
		DST_RET(true);
	} else if (eckey1 == NULL || eckey2 == NULL) {
		DST_RET(false);
	}
	priv1 = EC_KEY_get0_private_key(eckey1);
	priv2 = EC_KEY_get0_private_key(eckey2);
#else
	EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_PRIV_KEY, &priv1);
	EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_PRIV_KEY, &priv2);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	if (priv1 != NULL || priv2 != NULL) {
		if (priv1 == NULL || priv2 == NULL || BN_cmp(priv1, priv2) != 0)
		{
			DST_RET(false);
		}
	}

	ret = true;

err:
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	if (eckey1 != NULL) {
		EC_KEY_free(eckey1);
	}
	if (eckey2 != NULL) {
		EC_KEY_free(eckey2);
	}
#else
	if (priv1 != NULL) {
		BN_clear_free(priv1);
	}
	if (priv2 != NULL) {
		BN_clear_free(priv2);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	return (ret);
}

static isc_result_t
opensslecdsa_generate(dst_key_t *key, int unused, void (*callback)(int)) {
	isc_result_t ret;
	int status;
	EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	EC_KEY *eckey = NULL;
#else
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *params_pkey = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */
	int group_nid;

	REQUIRE(key->key_alg == DST_ALG_ECDSA256 ||
		key->key_alg == DST_ALG_ECDSA384);
	UNUSED(unused);
	UNUSED(callback);

	if (key->key_alg == DST_ALG_ECDSA256) {
		group_nid = NID_X9_62_prime256v1;
		key->key_size = DNS_KEY_ECDSA256SIZE * 4;
	} else {
		group_nid = NID_secp384r1;
		key->key_size = DNS_KEY_ECDSA384SIZE * 4;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	eckey = EC_KEY_new_by_curve_name(group_nid);
	if (eckey == NULL) {
		DST_RET(dst__openssl_toresult2("EC_KEY_new_by_curve_name",
					       DST_R_OPENSSLFAILURE));
	}

	status = EC_KEY_generate_key(eckey);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EC_KEY_generate_key",
					       DST_R_OPENSSLFAILURE));
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		DST_RET(ISC_R_NOMEMORY);
	}
	if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
		DST_RET(ISC_R_FAILURE);
	}
#else
	/* Generate the key's parameters. */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_CTX_new_from_name",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_paramgen_init(ctx);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_paramgen_init",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, group_nid);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_CTX_set_ec_paramgen_"
					       "curve_nid",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_paramgen(ctx, &params_pkey);
	if (status != 1 || params_pkey == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_paramgen",
					       DST_R_OPENSSLFAILURE));
	}
	EVP_PKEY_CTX_free(ctx);

	/* Generate the key. */
	ctx = EVP_PKEY_CTX_new(params_pkey, NULL);
	if (ctx == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_CTX_new",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_keygen_init(ctx);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_keygen_init",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_keygen(ctx, &pkey);
	if (status != 1 || pkey == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_keygen",
					       DST_R_OPENSSLFAILURE));
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	key->keydata.pkey = pkey;
	pkey = NULL;
	ret = ISC_R_SUCCESS;

err:
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	if (eckey != NULL) {
		EC_KEY_free(eckey);
	}
#else
	if (params_pkey != NULL) {
		EVP_PKEY_free(params_pkey);
	}
	if (ctx != NULL) {
		EVP_PKEY_CTX_free(ctx);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	return (ret);
}

static bool
opensslecdsa_isprivate(const dst_key_t *key) {
	bool ret;
	EVP_PKEY *pkey;
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	EC_KEY *eckey;
#else
	BIGNUM *priv = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	REQUIRE(key->key_alg == DST_ALG_ECDSA256 ||
		key->key_alg == DST_ALG_ECDSA384);

	pkey = key->keydata.pkey;
	if (pkey == NULL) {
		return (false);
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	eckey = EVP_PKEY_get1_EC_KEY(pkey);

	ret = (eckey != NULL && EC_KEY_get0_private_key(eckey) != NULL);
	if (eckey != NULL) {
		EC_KEY_free(eckey);
	}
#else
	ret = (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) ==
		       1 &&
	       priv != NULL);
	if (priv != NULL) {
		BN_clear_free(priv);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	return (ret);
}

static void
opensslecdsa_destroy(dst_key_t *key) {
	EVP_PKEY *pkey = key->keydata.pkey;

	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
		key->keydata.pkey = NULL;
	}
}

static isc_result_t
opensslecdsa_todns(const dst_key_t *key, isc_buffer_t *data) {
	isc_result_t ret;
	EVP_PKEY *pkey;
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	EC_KEY *eckey = NULL;
	int len;
	unsigned char *cp;
#else
	int status;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	size_t keysize = 0;
	size_t len = 0;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */
	isc_region_t r;
	unsigned char buf[DNS_KEY_ECDSA384SIZE + 1];

	REQUIRE(key->keydata.pkey != NULL);

	pkey = key->keydata.pkey;

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	if (eckey == NULL) {
		DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
	}
	len = i2o_ECPublicKey(eckey, NULL);

	/* skip form */
	len--;
#else
	if (key->key_alg == DST_ALG_ECDSA256) {
		keysize = DNS_KEY_ECDSA256SIZE;
	} else if (key->key_alg == DST_ALG_ECDSA384) {
		keysize = DNS_KEY_ECDSA384SIZE;
	} else {
		DST_RET(ISC_R_NOTIMPLEMENTED);
	}

	len = keysize;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	isc_buffer_availableregion(data, &r);
	if (r.length < (unsigned int)len) {
		DST_RET(ISC_R_NOSPACE);
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	cp = buf;
	if (!i2o_ECPublicKey(eckey, &cp)) {
		DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
	}
	memmove(r.base, buf + 1, len);
#else
	status = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x);
	if (status != 1 || x == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_get_bn_param",
					       DST_R_OPENSSLFAILURE));
	}
	status = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
	if (status != 1 || y == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_get_bn_param",
					       DST_R_OPENSSLFAILURE));
	}
	BN_bn2bin_fixed(x, &buf[0], keysize / 2);
	BN_bn2bin_fixed(y, &buf[keysize / 2], keysize / 2);
	memmove(r.base, buf, len);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	isc_buffer_add(data, len);
	ret = ISC_R_SUCCESS;

err:
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	if (eckey != NULL) {
		EC_KEY_free(eckey);
	}
#else
	if (x != NULL) {
		BN_clear_free(x);
	}
	if (y != NULL) {
		BN_clear_free(y);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	return (ret);
}

static isc_result_t
opensslecdsa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_result_t ret;
	EVP_PKEY *pkey = NULL;
	isc_region_t r;
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	EC_KEY *eckey = NULL;
	const unsigned char *cp;
	unsigned int len;
	unsigned char buf[DNS_KEY_ECDSA384SIZE + 1];
	int group_nid;
#else
	size_t len;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	REQUIRE(key->key_alg == DST_ALG_ECDSA256 ||
		key->key_alg == DST_ALG_ECDSA384);

	if (key->key_alg == DST_ALG_ECDSA256) {
		len = DNS_KEY_ECDSA256SIZE;
	} else {
		len = DNS_KEY_ECDSA384SIZE;
	}

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		DST_RET(ISC_R_SUCCESS);
	}
	if (r.length != len) {
		DST_RET(DST_R_INVALIDPUBLICKEY);
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	if (key->key_alg == DST_ALG_ECDSA256) {
		group_nid = NID_X9_62_prime256v1;
	} else {
		group_nid = NID_secp384r1;
	}

	eckey = EC_KEY_new_by_curve_name(group_nid);
	if (eckey == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	buf[0] = POINT_CONVERSION_UNCOMPRESSED;
	memmove(buf + 1, r.base, len);
	cp = buf;
	if (o2i_ECPublicKey(&eckey, (const unsigned char **)&cp,
			    (long)len + 1) == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPUBLICKEY));
	}
	if (EC_KEY_check_key(eckey) != 1) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPUBLICKEY));
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		DST_RET(ISC_R_NOMEMORY);
	}
	if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
		EVP_PKEY_free(pkey);
		DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
	}
#else
	ret = raw_key_to_ossl(key->key_alg, 0, r.base, len, &pkey);
	if (ret != ISC_R_SUCCESS) {
		DST_RET(ret);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	isc_buffer_forward(data, len);
	key->keydata.pkey = pkey;
	key->key_size = len * 4;
	ret = ISC_R_SUCCESS;

err:
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	if (eckey != NULL) {
		EC_KEY_free(eckey);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */
	return (ret);
}

static isc_result_t
opensslecdsa_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t ret;
	EVP_PKEY *pkey;
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	EC_KEY *eckey = NULL;
	const BIGNUM *privkey = NULL;
#else
	int status;
	BIGNUM *privkey = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */
	dst_private_t priv;
	unsigned char *buf = NULL;
	unsigned short i;

	if (key->keydata.pkey == NULL) {
		DST_RET(DST_R_NULLKEY);
	}

	if (key->external) {
		priv.nelements = 0;
		DST_RET(dst__privstruct_writefile(key, &priv, directory));
	}

	pkey = key->keydata.pkey;
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	if (eckey == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_get1_EC_KEY",
					       DST_R_OPENSSLFAILURE));
	}
	privkey = EC_KEY_get0_private_key(eckey);
	if (privkey == NULL) {
		DST_RET(dst__openssl_toresult2("EC_KEY_get0_private_key",
					       DST_R_OPENSSLFAILURE));
	}
#else
	status = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
				       &privkey);
	if (status != 1 || privkey == NULL) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_get_bn_param",
					       DST_R_OPENSSLFAILURE));
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	buf = isc_mem_get(key->mctx, BN_num_bytes(privkey));

	i = 0;

	priv.elements[i].tag = TAG_ECDSA_PRIVATEKEY;
	priv.elements[i].length = BN_num_bytes(privkey);
	BN_bn2bin(privkey, buf);
	priv.elements[i].data = buf;
	i++;

	if (key->engine != NULL) {
		priv.elements[i].tag = TAG_ECDSA_ENGINE;
		priv.elements[i].length = (unsigned short)strlen(key->engine) +
					  1;
		priv.elements[i].data = (unsigned char *)key->engine;
		i++;
	}

	if (key->label != NULL) {
		priv.elements[i].tag = TAG_ECDSA_LABEL;
		priv.elements[i].length = (unsigned short)strlen(key->label) +
					  1;
		priv.elements[i].data = (unsigned char *)key->label;
		i++;
	}

	priv.nelements = i;
	ret = dst__privstruct_writefile(key, &priv, directory);

err:
	if (buf != NULL && privkey != NULL) {
		isc_mem_put(key->mctx, buf, BN_num_bytes(privkey));
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	if (eckey != NULL) {
		EC_KEY_free(eckey);
	}
#else
	if (privkey != NULL) {
		BN_clear_free(privkey);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	return (ret);
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
static isc_result_t
ecdsa_check(EC_KEY *eckey, EC_KEY *pubeckey) {
	const EC_POINT *pubkey;

	pubkey = EC_KEY_get0_public_key(eckey);
	if (pubkey != NULL) {
		return (ISC_R_SUCCESS);
	} else if (pubeckey != NULL) {
		pubkey = EC_KEY_get0_public_key(pubeckey);
		if (pubkey == NULL) {
			return (ISC_R_SUCCESS);
		}
		if (EC_KEY_set_public_key(eckey, pubkey) != 1) {
			return (ISC_R_SUCCESS);
		}
	}
	if (EC_KEY_check_key(eckey) == 1) {
		return (ISC_R_SUCCESS);
	}

	return (ISC_R_FAILURE);
}
#else
static isc_result_t
ecdsa_check(EVP_PKEY **pkey, EVP_PKEY *pubpkey) {
	isc_result_t ret = ISC_R_FAILURE;
	int status;
	size_t pkey_len = 0;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *priv = NULL;
	char groupname[80];
	unsigned char buf[DNS_KEY_ECDSA384SIZE + 1];
	size_t keysize;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey_new = NULL;

	/* Check if `pkey` has a public key. */
	status = EVP_PKEY_get_octet_string_param(*pkey, OSSL_PKEY_PARAM_PUB_KEY,
						 NULL, 0, &pkey_len);

	/* Check if `pubpkey` exists and that we can extract its public key. */
	if (pubpkey == NULL ||
	    EVP_PKEY_get_bn_param(pubpkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1 ||
	    x == NULL ||
	    EVP_PKEY_get_bn_param(pubpkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1 ||
	    y == NULL)
	{
		if (status != 1 || pkey_len == 0) {
			/* No public key both in `pkey` and in `pubpkey` */
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		} else {
			/*
			 * `pkey` has a public key, but there is no public key
			 * in `pubpkey` to check against.
			 */
			DST_RET(ISC_R_SUCCESS);
		}
	}

	/*
	 * If `pkey` doesn't have a public key then we will copy it from
	 * `pubpkey`.
	 */
	if (status != 1 || pkey_len == 0) {
		/*
		 * We can't (?) add a public key to an existing PKEY, so we
		 * have to create a new PKEY.
		 */

		keysize = (EVP_PKEY_bits(*pkey) + 7) / 8;
		/*
		 * The "raw" public key is created by combining the "x" and "y"
		 * parts.
		 */
		keysize *= 2;
		buf[0] = POINT_CONVERSION_UNCOMPRESSED;
		BN_bn2bin_fixed(x, &buf[1], keysize / 2);
		BN_bn2bin_fixed(y, &buf[1 + keysize / 2], keysize / 2);

		groupname[0] = '\0';
		status = EVP_PKEY_get_utf8_string_param(
			*pkey, OSSL_PKEY_PARAM_GROUP_NAME, groupname,
			sizeof groupname, NULL);
		if (status != 1 || strlen(groupname) == 0) {
			DST_RET(ISC_R_FAILURE);
		}
		status = EVP_PKEY_get_bn_param(*pkey, OSSL_PKEY_PARAM_PRIV_KEY,
					       &priv);
		if (status != 1) {
			DST_RET(ISC_R_FAILURE);
		}

		bld = OSSL_PARAM_BLD_new();
		if (bld == NULL) {
			DST_RET(ISC_R_FAILURE);
		}
		if (OSSL_PARAM_BLD_push_utf8_string(
			    bld, OSSL_PKEY_PARAM_GROUP_NAME, groupname, 0) != 1)
		{
			DST_RET(ISC_R_FAILURE);
		}
		if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
					   priv) != 1) {
			DST_RET(ISC_R_FAILURE);
		}
		if (OSSL_PARAM_BLD_push_octet_string(bld,
						     OSSL_PKEY_PARAM_PUB_KEY,
						     buf, 1 + keysize) != 1)
		{
			DST_RET(ISC_R_FAILURE);
		}
		params = OSSL_PARAM_BLD_to_param(bld);
		if (params == NULL) {
			DST_RET(ISC_R_FAILURE);
		}

		ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if (ctx == NULL) {
			DST_RET(ISC_R_FAILURE);
		}
		if (EVP_PKEY_fromdata_init(ctx) != 1) {
			DST_RET(ISC_R_FAILURE);
		}
		status = EVP_PKEY_fromdata(ctx, &pkey_new, EVP_PKEY_KEYPAIR,
					   params);
		if (status != 1 || pkey_new == NULL) {
			DST_RET(ISC_R_FAILURE);
		}

		/* Replace the old key with the new one. */
		EVP_PKEY_free(*pkey);
		*pkey = pkey_new;
	}

	if (EVP_PKEY_eq(*pkey, pubpkey) == 1) {
		DST_RET(ISC_R_SUCCESS);
	}

err:
	if (ctx != NULL) {
		EVP_PKEY_CTX_free(ctx);
	}
	if (params != NULL) {
		OSSL_PARAM_free(params);
	}
	if (bld != NULL) {
		OSSL_PARAM_BLD_free(bld);
	}
	if (priv != NULL) {
		BN_clear_free(priv);
	}
	if (x != NULL) {
		BN_clear_free(x);
	}
	if (y != NULL) {
		BN_clear_free(y);
	}

	return (ret);
}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
static isc_result_t
load_privkey_from_privstruct(EC_KEY *eckey, dst_private_t *priv,
			     int privkey_index) {
	BIGNUM *privkey = BN_bin2bn(priv->elements[privkey_index].data,
				    priv->elements[privkey_index].length, NULL);
	isc_result_t result = ISC_R_SUCCESS;

	if (privkey == NULL) {
		return (ISC_R_NOMEMORY);
	}

	if (!EC_KEY_set_private_key(eckey, privkey)) {
		result = ISC_R_NOMEMORY;
	}

	BN_clear_free(privkey);
	return (result);
}

static isc_result_t
eckey_to_pkey(EC_KEY *eckey, EVP_PKEY **pkey) {
	REQUIRE(pkey != NULL && *pkey == NULL);

	*pkey = EVP_PKEY_new();
	if (*pkey == NULL) {
		return (ISC_R_NOMEMORY);
	}
	if (!EVP_PKEY_set1_EC_KEY(*pkey, eckey)) {
		EVP_PKEY_free(*pkey);
		*pkey = NULL;
		return (dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	return (ISC_R_SUCCESS);
}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

static isc_result_t
finalize_eckey(dst_key_t *key,
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	       EC_KEY *eckey,
#endif
	       const char *engine, const char *label) {
	isc_result_t result = ISC_R_SUCCESS;
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	EVP_PKEY *pkey = NULL;

	REQUIRE(eckey != NULL);

	result = eckey_to_pkey(eckey, &pkey);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	key->keydata.pkey = pkey;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

	if (label != NULL) {
		key->label = isc_mem_strdup(key->mctx, label);
		key->engine = isc_mem_strdup(key->mctx, engine);
	}

	if (key->key_alg == DST_ALG_ECDSA256) {
		key->key_size = DNS_KEY_ECDSA256SIZE * 4;
	} else {
		key->key_size = DNS_KEY_ECDSA384SIZE * 4;
	}

	return (result);
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
static isc_result_t
dst__key_to_eckey(dst_key_t *key, EC_KEY **eckey) {
	int group_nid;

	REQUIRE(eckey != NULL && *eckey == NULL);

	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		group_nid = NID_X9_62_prime256v1;
		break;
	case DST_ALG_ECDSA384:
		group_nid = NID_secp384r1;
		break;
	default:
		UNREACHABLE();
	}

	*eckey = EC_KEY_new_by_curve_name(group_nid);
	if (*eckey == NULL) {
		return (dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	return (ISC_R_SUCCESS);
}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

static isc_result_t
opensslecdsa_fromlabel(dst_key_t *key, const char *engine, const char *label,
		       const char *pin);

static isc_result_t
opensslecdsa_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	dst_private_t priv;
	isc_result_t ret;
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	EC_KEY *eckey = NULL;
	EC_KEY *pubeckey = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */
	const char *engine = NULL;
	const char *label = NULL;
	int i, privkey_index = -1;
	bool finalize_key = false;

	REQUIRE(key->key_alg == DST_ALG_ECDSA256 ||
		key->key_alg == DST_ALG_ECDSA384);

	/* read private key file */
	ret = dst__privstruct_parse(key, DST_ALG_ECDSA256, lexer, key->mctx,
				    &priv);
	if (ret != ISC_R_SUCCESS) {
		goto err;
	}

	if (key->external) {
		if (priv.nelements != 0 || pub == NULL) {
			DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
		}
		key->keydata.pkey = pub->keydata.pkey;
		pub->keydata.pkey = NULL;
		DST_RET(ISC_R_SUCCESS);
	}

	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_ECDSA_ENGINE:
			engine = (char *)priv.elements[i].data;
			break;
		case TAG_ECDSA_LABEL:
			label = (char *)priv.elements[i].data;
			break;
		case TAG_ECDSA_PRIVATEKEY:
			privkey_index = i;
			break;
		default:
			break;
		}
	}

	if (privkey_index < 0) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}

	if (label != NULL) {
		ret = opensslecdsa_fromlabel(key, engine, label, NULL);
		if (ret != ISC_R_SUCCESS) {
			goto err;
		}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
		eckey = EVP_PKEY_get1_EC_KEY(key->keydata.pkey);
		if (eckey == NULL) {
			DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
		}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */
	} else {
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
		ret = dst__key_to_eckey(key, &eckey);
		if (ret != ISC_R_SUCCESS) {
			goto err;
		}

		ret = load_privkey_from_privstruct(eckey, &priv, privkey_index);
#else
		if (key->keydata.pkey != NULL) {
			EVP_PKEY_free(key->keydata.pkey);
			key->keydata.pkey = NULL;
		}

		ret = raw_key_to_ossl(key->key_alg, 1,
				      priv.elements[privkey_index].data,
				      priv.elements[privkey_index].length,
				      &key->keydata.pkey);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

		if (ret != ISC_R_SUCCESS) {
			goto err;
		}

		finalize_key = true;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	if (pub != NULL && pub->keydata.pkey != NULL) {
		pubeckey = EVP_PKEY_get1_EC_KEY(pub->keydata.pkey);
	}

	if (ecdsa_check(eckey, pubeckey) != ISC_R_SUCCESS) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}

	if (finalize_key) {
		ret = finalize_eckey(key, eckey, engine, label);
	}
#else
	if (ecdsa_check(&key->keydata.pkey,
			pub == NULL ? NULL : pub->keydata.pkey) !=
	    ISC_R_SUCCESS)
	{
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}

	if (finalize_key) {
		ret = finalize_eckey(key, engine, label);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */

err:
#if OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000
	if (pubeckey != NULL) {
		EC_KEY_free(pubeckey);
	}
	if (eckey != NULL) {
		EC_KEY_free(eckey);
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L || OPENSSL_API_LEVEL < 30000 */
	if (ret != ISC_R_SUCCESS) {
		key->keydata.generic = NULL;
	}

	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));

	return (ret);
}

static isc_result_t
opensslecdsa_fromlabel(dst_key_t *key, const char *engine, const char *label,
		       const char *pin) {
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
	isc_result_t ret = ISC_R_SUCCESS;
	ENGINE *e;
	EC_KEY *eckey = NULL;
	EC_KEY *pubeckey = NULL;
	int group_nid;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *pubpkey = NULL;

	REQUIRE(key->key_alg == DST_ALG_ECDSA256 ||
		key->key_alg == DST_ALG_ECDSA384);

	UNUSED(pin);

	if (engine == NULL || label == NULL) {
		return (DST_R_NOENGINE);
	}
	e = dst__openssl_getengine(engine);
	if (e == NULL) {
		DST_RET(DST_R_NOENGINE);
	}

	if (key->key_alg == DST_ALG_ECDSA256) {
		group_nid = NID_X9_62_prime256v1;
	} else {
		group_nid = NID_secp384r1;
	}

	/* Load private key. */
	pkey = ENGINE_load_private_key(e, label, NULL, NULL);
	if (pkey == NULL) {
		DST_RET(dst__openssl_toresult2("ENGINE_load_private_key",
					       DST_R_OPENSSLFAILURE));
	}
	/* Check base id, group nid */
	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}
	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	if (eckey == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey)) != group_nid) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}

	/* Load public key. */
	pubpkey = ENGINE_load_public_key(e, label, NULL, NULL);
	if (pubpkey == NULL) {
		DST_RET(dst__openssl_toresult2("ENGINE_load_public_key",
					       DST_R_OPENSSLFAILURE));
	}
	/* Check base id, group nid */
	if (EVP_PKEY_base_id(pubpkey) != EVP_PKEY_EC) {
		DST_RET(DST_R_INVALIDPUBLICKEY);
	}
	pubeckey = EVP_PKEY_get1_EC_KEY(pubpkey);
	if (pubeckey == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	if (EC_GROUP_get_curve_name(EC_KEY_get0_group(pubeckey)) != group_nid) {
		DST_RET(DST_R_INVALIDPUBLICKEY);
	}

	if (ecdsa_check(eckey, pubeckey) != ISC_R_SUCCESS) {
		DST_RET(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}

	key->label = isc_mem_strdup(key->mctx, label);
	key->engine = isc_mem_strdup(key->mctx, engine);
	key->key_size = EVP_PKEY_bits(pkey);
	key->keydata.pkey = pkey;
	pkey = NULL;

err:
	if (pubpkey != NULL) {
		EVP_PKEY_free(pubpkey);
	}
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
	if (pubeckey != NULL) {
		EC_KEY_free(pubeckey);
	}
	if (eckey != NULL) {
		EC_KEY_free(eckey);
	}

	return (ret);
#else
	UNUSED(key);
	UNUSED(engine);
	UNUSED(label);
	UNUSED(pin);
	return (DST_R_NOENGINE);
#endif /* !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
}

static dst_func_t opensslecdsa_functions = {
	opensslecdsa_createctx,
	NULL, /*%< createctx2 */
	opensslecdsa_destroyctx,
	opensslecdsa_adddata,
	opensslecdsa_sign,
	opensslecdsa_verify,
	NULL, /*%< verify2 */
	NULL, /*%< computesecret */
	opensslecdsa_compare,
	NULL, /*%< paramcompare */
	opensslecdsa_generate,
	opensslecdsa_isprivate,
	opensslecdsa_destroy,
	opensslecdsa_todns,
	opensslecdsa_fromdns,
	opensslecdsa_tofile,
	opensslecdsa_parse,
	NULL,			/*%< cleanup */
	opensslecdsa_fromlabel, /*%< fromlabel */
	NULL,			/*%< dump */
	NULL,			/*%< restore */
};

isc_result_t
dst__opensslecdsa_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);
	if (*funcp == NULL) {
		*funcp = &opensslecdsa_functions;
	}
	return (ISC_R_SUCCESS);
}
