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

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/serial.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/rbt.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/tsig.h>

#include "tsig_p.h"

#define TSIG_MAGIC	  ISC_MAGIC('T', 'S', 'I', 'G')
#define VALID_TSIG_KEY(x) ISC_MAGIC_VALID(x, TSIG_MAGIC)

#ifndef DNS_TSIG_MAXGENERATEDKEYS
#define DNS_TSIG_MAXGENERATEDKEYS 4096
#endif /* ifndef DNS_TSIG_MAXGENERATEDKEYS */

#define is_response(msg) ((msg->flags & DNS_MESSAGEFLAG_QR) != 0)

#define BADTIMELEN 6

static unsigned char hmacmd5_ndata[] = "\010hmac-md5\007sig-alg\003reg\003int";
static unsigned char hmacmd5_offsets[] = { 0, 9, 17, 21, 25 };

static dns_name_t const hmacmd5 = DNS_NAME_INITABSOLUTE(hmacmd5_ndata,
							hmacmd5_offsets);
const dns_name_t *dns_tsig_hmacmd5_name = &hmacmd5;

static unsigned char gsstsig_ndata[] = "\010gss-tsig";
static unsigned char gsstsig_offsets[] = { 0, 9 };
static dns_name_t const gsstsig = DNS_NAME_INITABSOLUTE(gsstsig_ndata,
							gsstsig_offsets);
const dns_name_t *dns_tsig_gssapi_name = &gsstsig;

/*
 * Since Microsoft doesn't follow its own standard, we will use this
 * alternate name as a second guess.
 */
static unsigned char gsstsigms_ndata[] = "\003gss\011microsoft\003com";
static unsigned char gsstsigms_offsets[] = { 0, 4, 14, 18 };
static dns_name_t const gsstsigms = DNS_NAME_INITABSOLUTE(gsstsigms_ndata,
							  gsstsigms_offsets);
const dns_name_t *dns_tsig_gssapims_name = &gsstsigms;

static unsigned char hmacsha1_ndata[] = "\011hmac-sha1";
static unsigned char hmacsha1_offsets[] = { 0, 10 };
static dns_name_t const hmacsha1 = DNS_NAME_INITABSOLUTE(hmacsha1_ndata,
							 hmacsha1_offsets);
const dns_name_t *dns_tsig_hmacsha1_name = &hmacsha1;

static unsigned char hmacsha224_ndata[] = "\013hmac-sha224";
static unsigned char hmacsha224_offsets[] = { 0, 12 };
static dns_name_t const hmacsha224 = DNS_NAME_INITABSOLUTE(hmacsha224_ndata,
							   hmacsha224_offsets);
const dns_name_t *dns_tsig_hmacsha224_name = &hmacsha224;

static unsigned char hmacsha256_ndata[] = "\013hmac-sha256";
static unsigned char hmacsha256_offsets[] = { 0, 12 };
static dns_name_t const hmacsha256 = DNS_NAME_INITABSOLUTE(hmacsha256_ndata,
							   hmacsha256_offsets);
const dns_name_t *dns_tsig_hmacsha256_name = &hmacsha256;

static unsigned char hmacsha384_ndata[] = "\013hmac-sha384";
static unsigned char hmacsha384_offsets[] = { 0, 12 };
static dns_name_t const hmacsha384 = DNS_NAME_INITABSOLUTE(hmacsha384_ndata,
							   hmacsha384_offsets);
const dns_name_t *dns_tsig_hmacsha384_name = &hmacsha384;

static unsigned char hmacsha512_ndata[] = "\013hmac-sha512";
static unsigned char hmacsha512_offsets[] = { 0, 12 };
static dns_name_t const hmacsha512 = DNS_NAME_INITABSOLUTE(hmacsha512_ndata,
							   hmacsha512_offsets);
const dns_name_t *dns_tsig_hmacsha512_name = &hmacsha512;

static const struct {
	const dns_name_t *name;
	unsigned int dstalg;
} known_algs[] = { { &hmacmd5, DST_ALG_HMACMD5 },
		   { &gsstsig, DST_ALG_GSSAPI },
		   { &gsstsigms, DST_ALG_GSSAPI },
		   { &hmacsha1, DST_ALG_HMACSHA1 },
		   { &hmacsha224, DST_ALG_HMACSHA224 },
		   { &hmacsha256, DST_ALG_HMACSHA256 },
		   { &hmacsha384, DST_ALG_HMACSHA384 },
		   { &hmacsha512, DST_ALG_HMACSHA512 } };

static isc_result_t
tsig_verify_tcp(isc_buffer_t *source, dns_message_t *msg);

static void
tsig_log(dns_tsigkey_t *key, int level, const char *fmt, ...)
	ISC_FORMAT_PRINTF(3, 4);

static void
cleanup_ring(dns_tsig_keyring_t *ring);
static void
tsigkey_free(dns_tsigkey_t *key);

bool
dns__tsig_algvalid(unsigned int alg) {
	return (alg == DST_ALG_HMACMD5 || alg == DST_ALG_HMACSHA1 ||
		alg == DST_ALG_HMACSHA224 || alg == DST_ALG_HMACSHA256 ||
		alg == DST_ALG_HMACSHA384 || alg == DST_ALG_HMACSHA512);
}

static void
tsig_log(dns_tsigkey_t *key, int level, const char *fmt, ...) {
	va_list ap;
	char message[4096];
	char namestr[DNS_NAME_FORMATSIZE];
	char creatorstr[DNS_NAME_FORMATSIZE];

	if (!isc_log_wouldlog(dns_lctx, level)) {
		return;
	}
	if (key != NULL) {
		dns_name_format(&key->name, namestr, sizeof(namestr));
	} else {
		strlcpy(namestr, "<null>", sizeof(namestr));
	}

	if (key != NULL && key->generated && key->creator) {
		dns_name_format(key->creator, creatorstr, sizeof(creatorstr));
	} else {
		strlcpy(creatorstr, "<null>", sizeof(creatorstr));
	}

	va_start(ap, fmt);
	vsnprintf(message, sizeof(message), fmt, ap);
	va_end(ap);
	if (key != NULL && key->generated) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC,
			      DNS_LOGMODULE_TSIG, level,
			      "tsig key '%s' (%s): %s", namestr, creatorstr,
			      message);
	} else {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC,
			      DNS_LOGMODULE_TSIG, level, "tsig key '%s': %s",
			      namestr, message);
	}
}

static void
remove_fromring(dns_tsigkey_t *tkey) {
	if (tkey->generated) {
		ISC_LIST_UNLINK(tkey->ring->lru, tkey, link);
		tkey->ring->generated--;
	}
	(void)dns_rbt_deletename(tkey->ring->keys, &tkey->name, false);
}

static void
adjust_lru(dns_tsigkey_t *tkey) {
	if (tkey->generated) {
		RWLOCK(&tkey->ring->lock, isc_rwlocktype_write);
		/*
		 * We may have been removed from the LRU list between
		 * removing the read lock and acquiring the write lock.
		 */
		if (ISC_LINK_LINKED(tkey, link) && tkey->ring->lru.tail != tkey)
		{
			ISC_LIST_UNLINK(tkey->ring->lru, tkey, link);
			ISC_LIST_APPEND(tkey->ring->lru, tkey, link);
		}
		RWUNLOCK(&tkey->ring->lock, isc_rwlocktype_write);
	}
}

/*
 * A supplemental routine just to add a key to ring.  Note that reference
 * counter should be counted separately because we may be adding the key
 * as part of creation of the key, in which case the reference counter was
 * already initialized.  Also note we don't need RWLOCK for the reference
 * counter: it's protected by a separate lock.
 */
static isc_result_t
keyring_add(dns_tsig_keyring_t *ring, const dns_name_t *name,
	    dns_tsigkey_t *tkey) {
	isc_result_t result;

	RWLOCK(&ring->lock, isc_rwlocktype_write);
	ring->writecount++;

	/*
	 * Do on the fly cleaning.  Find some nodes we might not
	 * want around any more.
	 */
	if (ring->writecount > 10) {
		cleanup_ring(ring);
		ring->writecount = 0;
	}

	result = dns_rbt_addname(ring->keys, name, tkey);
	if (result == ISC_R_SUCCESS && tkey->generated) {
		/*
		 * Add the new key to the LRU list and remove the least
		 * recently used key if there are too many keys on the list.
		 */
		ISC_LIST_APPEND(ring->lru, tkey, link);
		if (ring->generated++ > ring->maxgenerated) {
			remove_fromring(ISC_LIST_HEAD(ring->lru));
		}
	}
	RWUNLOCK(&ring->lock, isc_rwlocktype_write);

	return (result);
}

isc_result_t
dns_tsigkey_createfromkey(const dns_name_t *name, const dns_name_t *algorithm,
			  dst_key_t *dstkey, bool generated,
			  const dns_name_t *creator, isc_stdtime_t inception,
			  isc_stdtime_t expire, isc_mem_t *mctx,
			  dns_tsig_keyring_t *ring, dns_tsigkey_t **key) {
	dns_tsigkey_t *tkey;
	isc_result_t ret;
	unsigned int refs = 0;
	unsigned int dstalg = 0;

	REQUIRE(key == NULL || *key == NULL);
	REQUIRE(name != NULL);
	REQUIRE(algorithm != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(key != NULL || ring != NULL);

	tkey = isc_mem_get(mctx, sizeof(dns_tsigkey_t));

	dns_name_init(&tkey->name, NULL);
	dns_name_dup(name, mctx, &tkey->name);
	(void)dns_name_downcase(&tkey->name, &tkey->name, NULL);

	/* Check against known algorithm names */
	dstalg = dns__tsig_algfromname(algorithm);
	if (dstalg != 0) {
		/*
		 * 'algorithm' must be set to a static pointer
		 * so that dns__tsig_algallocated() can compare them.
		 */
		tkey->algorithm = dns__tsig_algnamefromname(algorithm);
		if (dstkey != NULL && dst_key_alg(dstkey) != dstalg) {
			ret = DNS_R_BADALG;
			goto cleanup_name;
		}
	} else {
		dns_name_t *tmpname;
		if (dstkey != NULL) {
			ret = DNS_R_BADALG;
			goto cleanup_name;
		}
		tmpname = isc_mem_get(mctx, sizeof(dns_name_t));
		dns_name_init(tmpname, NULL);
		dns_name_dup(algorithm, mctx, tmpname);
		(void)dns_name_downcase(tmpname, tmpname, NULL);
		tkey->algorithm = tmpname;
	}

	if (creator != NULL) {
		tkey->creator = isc_mem_get(mctx, sizeof(dns_name_t));
		dns_name_init(tkey->creator, NULL);
		dns_name_dup(creator, mctx, tkey->creator);
	} else {
		tkey->creator = NULL;
	}

	tkey->key = NULL;
	if (dstkey != NULL) {
		dst_key_attach(dstkey, &tkey->key);
	}
	tkey->ring = ring;

	if (key != NULL) {
		refs = 1;
	}
	if (ring != NULL) {
		refs++;
	}

	isc_refcount_init(&tkey->refs, refs);

	tkey->generated = generated;
	tkey->inception = inception;
	tkey->expire = expire;
	tkey->mctx = NULL;
	isc_mem_attach(mctx, &tkey->mctx);
	ISC_LINK_INIT(tkey, link);

	tkey->magic = TSIG_MAGIC;

	if (ring != NULL) {
		ret = keyring_add(ring, name, tkey);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_refs;
		}
	}

	/*
	 * Ignore this if it's a GSS key, since the key size is meaningless.
	 */
	if (dstkey != NULL && dst_key_size(dstkey) < 64 &&
	    dstalg != DST_ALG_GSSAPI) {
		char namestr[DNS_NAME_FORMATSIZE];
		dns_name_format(name, namestr, sizeof(namestr));
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC,
			      DNS_LOGMODULE_TSIG, ISC_LOG_INFO,
			      "the key '%s' is too short to be secure",
			      namestr);
	}

	if (key != NULL) {
		*key = tkey;
	}

	return (ISC_R_SUCCESS);

cleanup_refs:
	tkey->magic = 0;
	while (refs-- > 0) {
		isc_refcount_decrement0(&tkey->refs);
	}
	isc_refcount_destroy(&tkey->refs);

	if (tkey->key != NULL) {
		dst_key_free(&tkey->key);
	}
	if (tkey->creator != NULL) {
		dns_name_free(tkey->creator, mctx);
		isc_mem_put(mctx, tkey->creator, sizeof(dns_name_t));
	}
	if (dns__tsig_algallocated(tkey->algorithm)) {
		dns_name_t *tmpname;
		DE_CONST(tkey->algorithm, tmpname);
		if (dns_name_dynamic(tmpname)) {
			dns_name_free(tmpname, mctx);
		}
		isc_mem_put(mctx, tmpname, sizeof(dns_name_t));
	}
cleanup_name:
	dns_name_free(&tkey->name, mctx);
	isc_mem_put(mctx, tkey, sizeof(dns_tsigkey_t));

	return (ret);
}

/*
 * Find a few nodes to destroy if possible.
 */
static void
cleanup_ring(dns_tsig_keyring_t *ring) {
	isc_result_t result;
	dns_rbtnodechain_t chain;
	dns_name_t foundname;
	dns_fixedname_t fixedorigin;
	dns_name_t *origin;
	isc_stdtime_t now;
	dns_rbtnode_t *node;
	dns_tsigkey_t *tkey;

	/*
	 * Start up a new iterator each time.
	 */
	isc_stdtime_get(&now);
	dns_name_init(&foundname, NULL);
	origin = dns_fixedname_initname(&fixedorigin);

again:
	dns_rbtnodechain_init(&chain);
	result = dns_rbtnodechain_first(&chain, ring->keys, &foundname, origin);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
		dns_rbtnodechain_invalidate(&chain);
		return;
	}

	for (;;) {
		node = NULL;
		dns_rbtnodechain_current(&chain, &foundname, origin, &node);
		tkey = node->data;
		if (tkey != NULL) {
			if (tkey->generated &&
			    isc_refcount_current(&tkey->refs) == 1 &&
			    tkey->inception != tkey->expire &&
			    tkey->expire < now)
			{
				tsig_log(tkey, 2, "tsig expire: deleting");
				/* delete the key */
				dns_rbtnodechain_invalidate(&chain);
				remove_fromring(tkey);
				goto again;
			}
		}
		result = dns_rbtnodechain_next(&chain, &foundname, origin);
		if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
			dns_rbtnodechain_invalidate(&chain);
			return;
		}
	}
}

static void
destroyring(dns_tsig_keyring_t *ring) {
	isc_refcount_destroy(&ring->references);
	dns_rbt_destroy(&ring->keys);
	isc_rwlock_destroy(&ring->lock);
	isc_mem_putanddetach(&ring->mctx, ring, sizeof(dns_tsig_keyring_t));
}

/*
 * Look up the DST_ALG_ constant for a given name.
 */
unsigned int
dns__tsig_algfromname(const dns_name_t *algorithm) {
	int i;
	int n = sizeof(known_algs) / sizeof(*known_algs);
	for (i = 0; i < n; ++i) {
		const dns_name_t *name = known_algs[i].name;
		if (algorithm == name || dns_name_equal(algorithm, name)) {
			return (known_algs[i].dstalg);
		}
	}
	return (0);
}

/*
 * Convert an algorithm name into a pointer to the
 * corresponding pre-defined dns_name_t structure.
 */
const dns_name_t *
dns__tsig_algnamefromname(const dns_name_t *algorithm) {
	int i;
	int n = sizeof(known_algs) / sizeof(*known_algs);
	for (i = 0; i < n; ++i) {
		const dns_name_t *name = known_algs[i].name;
		if (algorithm == name || dns_name_equal(algorithm, name)) {
			return (name);
		}
	}
	return (NULL);
}

/*
 * Test whether the passed algorithm is NOT a pointer to one of the
 * pre-defined known algorithms (and therefore one that has been
 * dynamically allocated).
 *
 * This will return an incorrect result if passed a dynamically allocated
 * dns_name_t that happens to match one of the pre-defined names.
 */
bool
dns__tsig_algallocated(const dns_name_t *algorithm) {
	int i;
	int n = sizeof(known_algs) / sizeof(*known_algs);
	for (i = 0; i < n; ++i) {
		const dns_name_t *name = known_algs[i].name;
		if (algorithm == name) {
			return (false);
		}
	}
	return (true);
}

static isc_result_t
restore_key(dns_tsig_keyring_t *ring, isc_stdtime_t now, FILE *fp) {
	dst_key_t *dstkey = NULL;
	char namestr[1024];
	char creatorstr[1024];
	char algorithmstr[1024];
	char keystr[4096];
	unsigned int inception, expire;
	int n;
	isc_buffer_t b;
	dns_name_t *name, *creator, *algorithm;
	dns_fixedname_t fname, fcreator, falgorithm;
	isc_result_t result;
	unsigned int dstalg;

	n = fscanf(fp, "%1023s %1023s %u %u %1023s %4095s\n", namestr,
		   creatorstr, &inception, &expire, algorithmstr, keystr);
	if (n == EOF) {
		return (ISC_R_NOMORE);
	}
	if (n != 6) {
		return (ISC_R_FAILURE);
	}

	if (isc_serial_lt(expire, now)) {
		return (DNS_R_EXPIRED);
	}

	name = dns_fixedname_initname(&fname);
	isc_buffer_init(&b, namestr, strlen(namestr));
	isc_buffer_add(&b, strlen(namestr));
	result = dns_name_fromtext(name, &b, dns_rootname, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	creator = dns_fixedname_initname(&fcreator);
	isc_buffer_init(&b, creatorstr, strlen(creatorstr));
	isc_buffer_add(&b, strlen(creatorstr));
	result = dns_name_fromtext(creator, &b, dns_rootname, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	algorithm = dns_fixedname_initname(&falgorithm);
	isc_buffer_init(&b, algorithmstr, strlen(algorithmstr));
	isc_buffer_add(&b, strlen(algorithmstr));
	result = dns_name_fromtext(algorithm, &b, dns_rootname, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	dstalg = dns__tsig_algfromname(algorithm);
	if (dstalg == 0) {
		return (DNS_R_BADALG);
	}

	result = dst_key_restore(name, dstalg, DNS_KEYOWNER_ENTITY,
				 DNS_KEYPROTO_DNSSEC, dns_rdataclass_in,
				 ring->mctx, keystr, &dstkey);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	result = dns_tsigkey_createfromkey(name, algorithm, dstkey, true,
					   creator, inception, expire,
					   ring->mctx, ring, NULL);
	if (dstkey != NULL) {
		dst_key_free(&dstkey);
	}
	return (result);
}

static void
dump_key(dns_tsigkey_t *tkey, FILE *fp) {
	char *buffer = NULL;
	int length = 0;
	char namestr[DNS_NAME_FORMATSIZE];
	char creatorstr[DNS_NAME_FORMATSIZE];
	char algorithmstr[DNS_NAME_FORMATSIZE];
	isc_result_t result;

	REQUIRE(tkey != NULL);
	REQUIRE(fp != NULL);

	dns_name_format(&tkey->name, namestr, sizeof(namestr));
	dns_name_format(tkey->creator, creatorstr, sizeof(creatorstr));
	dns_name_format(tkey->algorithm, algorithmstr, sizeof(algorithmstr));
	result = dst_key_dump(tkey->key, tkey->mctx, &buffer, &length);
	if (result == ISC_R_SUCCESS) {
		fprintf(fp, "%s %s %u %u %s %.*s\n", namestr, creatorstr,
			tkey->inception, tkey->expire, algorithmstr, length,
			buffer);
	}
	if (buffer != NULL) {
		isc_mem_put(tkey->mctx, buffer, length);
	}
}

isc_result_t
dns_tsigkeyring_dumpanddetach(dns_tsig_keyring_t **ringp, FILE *fp) {
	isc_result_t result;
	dns_rbtnodechain_t chain;
	dns_name_t foundname;
	dns_fixedname_t fixedorigin;
	dns_name_t *origin;
	isc_stdtime_t now;
	dns_rbtnode_t *node;
	dns_tsigkey_t *tkey;
	dns_tsig_keyring_t *ring;

	REQUIRE(ringp != NULL && *ringp != NULL);

	ring = *ringp;
	*ringp = NULL;

	if (isc_refcount_decrement(&ring->references) > 1) {
		return (DNS_R_CONTINUE);
	}

	isc_stdtime_get(&now);
	dns_name_init(&foundname, NULL);
	origin = dns_fixedname_initname(&fixedorigin);
	dns_rbtnodechain_init(&chain);
	result = dns_rbtnodechain_first(&chain, ring->keys, &foundname, origin);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
		dns_rbtnodechain_invalidate(&chain);
		goto destroy;
	}

	for (;;) {
		node = NULL;
		dns_rbtnodechain_current(&chain, &foundname, origin, &node);
		tkey = node->data;
		if (tkey != NULL && tkey->generated && tkey->expire >= now) {
			dump_key(tkey, fp);
		}
		result = dns_rbtnodechain_next(&chain, &foundname, origin);
		if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
			dns_rbtnodechain_invalidate(&chain);
			if (result == ISC_R_NOMORE) {
				result = ISC_R_SUCCESS;
			}
			goto destroy;
		}
	}

destroy:
	destroyring(ring);
	return (result);
}

const dns_name_t *
dns_tsigkey_identity(const dns_tsigkey_t *tsigkey) {
	REQUIRE(tsigkey == NULL || VALID_TSIG_KEY(tsigkey));

	if (tsigkey == NULL) {
		return (NULL);
	}
	if (tsigkey->generated) {
		return (tsigkey->creator);
	} else {
		return (&tsigkey->name);
	}
}

isc_result_t
dns_tsigkey_create(const dns_name_t *name, const dns_name_t *algorithm,
		   unsigned char *secret, int length, bool generated,
		   const dns_name_t *creator, isc_stdtime_t inception,
		   isc_stdtime_t expire, isc_mem_t *mctx,
		   dns_tsig_keyring_t *ring, dns_tsigkey_t **key) {
	dst_key_t *dstkey = NULL;
	isc_result_t result;
	unsigned int dstalg = 0;

	REQUIRE(length >= 0);
	if (length > 0) {
		REQUIRE(secret != NULL);
	}

	dstalg = dns__tsig_algfromname(algorithm);
	if (dns__tsig_algvalid(dstalg)) {
		if (secret != NULL) {
			isc_buffer_t b;

			isc_buffer_init(&b, secret, length);
			isc_buffer_add(&b, length);
			result = dst_key_frombuffer(
				name, dstalg, DNS_KEYOWNER_ENTITY,
				DNS_KEYPROTO_DNSSEC, dns_rdataclass_in, &b,
				mctx, &dstkey);
			if (result != ISC_R_SUCCESS) {
				return (result);
			}
		}
	} else if (length > 0) {
		return (DNS_R_BADALG);
	}

	result = dns_tsigkey_createfromkey(name, algorithm, dstkey, generated,
					   creator, inception, expire, mctx,
					   ring, key);
	if (dstkey != NULL) {
		dst_key_free(&dstkey);
	}
	return (result);
}

void
dns_tsigkey_attach(dns_tsigkey_t *source, dns_tsigkey_t **targetp) {
	REQUIRE(VALID_TSIG_KEY(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->refs);
	*targetp = source;
}

static void
tsigkey_free(dns_tsigkey_t *key) {
	REQUIRE(VALID_TSIG_KEY(key));

	key->magic = 0;
	dns_name_free(&key->name, key->mctx);
	if (dns__tsig_algallocated(key->algorithm)) {
		dns_name_t *name;
		DE_CONST(key->algorithm, name);
		dns_name_free(name, key->mctx);
		isc_mem_put(key->mctx, name, sizeof(dns_name_t));
	}
	if (key->key != NULL) {
		dst_key_free(&key->key);
	}
	if (key->creator != NULL) {
		dns_name_free(key->creator, key->mctx);
		isc_mem_put(key->mctx, key->creator, sizeof(dns_name_t));
	}
	isc_mem_putanddetach(&key->mctx, key, sizeof(dns_tsigkey_t));
}

void
dns_tsigkey_detach(dns_tsigkey_t **keyp) {
	REQUIRE(keyp != NULL && VALID_TSIG_KEY(*keyp));
	dns_tsigkey_t *key = *keyp;
	*keyp = NULL;

	if (isc_refcount_decrement(&key->refs) == 1) {
		isc_refcount_destroy(&key->refs);
		tsigkey_free(key);
	}
}

void
dns_tsigkey_setdeleted(dns_tsigkey_t *key) {
	REQUIRE(VALID_TSIG_KEY(key));
	REQUIRE(key->ring != NULL);

	RWLOCK(&key->ring->lock, isc_rwlocktype_write);
	remove_fromring(key);
	RWUNLOCK(&key->ring->lock, isc_rwlocktype_write);
}

isc_result_t
dns_tsig_sign(dns_message_t *msg) {
	dns_tsigkey_t *key = NULL;
	dns_rdata_any_tsig_t tsig, querytsig;
	unsigned char data[128];
	isc_buffer_t databuf, sigbuf;
	isc_buffer_t *dynbuf = NULL;
	dns_name_t *owner = NULL;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *datalist = NULL;
	dns_rdataset_t *dataset = NULL;
	isc_region_t r;
	isc_stdtime_t now;
	isc_mem_t *mctx;
	dst_context_t *ctx = NULL;
	isc_result_t ret;
	unsigned char badtimedata[BADTIMELEN];
	unsigned int sigsize = 0;
	bool response;

	REQUIRE(msg != NULL);
	key = dns_message_gettsigkey(msg);
	REQUIRE(VALID_TSIG_KEY(key));

	/*
	 * If this is a response, there should be a TSIG in the query with the
	 * the exception if this is a TKEY request (see RFC 3645, Section 2.2).
	 */
	response = is_response(msg);
	if (response && msg->querytsig == NULL) {
		if (msg->tkey != 1) {
			return (DNS_R_EXPECTEDTSIG);
		}
	}

	mctx = msg->mctx;

	tsig.mctx = mctx;
	tsig.common.rdclass = dns_rdataclass_any;
	tsig.common.rdtype = dns_rdatatype_tsig;
	ISC_LINK_INIT(&tsig.common, link);
	dns_name_init(&tsig.algorithm, NULL);
	dns_name_clone(key->algorithm, &tsig.algorithm);

	if (msg->fuzzing) {
		now = msg->fuzztime;
	} else {
		isc_stdtime_get(&now);
	}

	tsig.timesigned = now + msg->timeadjust;
	tsig.fudge = DNS_TSIG_FUDGE;

	tsig.originalid = msg->id;

	isc_buffer_init(&databuf, data, sizeof(data));

	if (response) {
		tsig.error = msg->querytsigstatus;
	} else {
		tsig.error = dns_rcode_noerror;
	}

	if (tsig.error != dns_tsigerror_badtime) {
		tsig.otherlen = 0;
		tsig.other = NULL;
	} else {
		isc_buffer_t otherbuf;

		tsig.otherlen = BADTIMELEN;
		tsig.other = badtimedata;
		isc_buffer_init(&otherbuf, tsig.other, tsig.otherlen);
		isc_buffer_putuint48(&otherbuf, tsig.timesigned);
	}

	if ((key->key != NULL) && (tsig.error != dns_tsigerror_badsig) &&
	    (tsig.error != dns_tsigerror_badkey))
	{
		unsigned char header[DNS_MESSAGE_HEADERLEN];
		isc_buffer_t headerbuf;
		uint16_t digestbits;
		bool querytsig_ok = false;

		/*
		 * If it is a response, we assume that the request MAC
		 * has validated at this point. This is why we include a
		 * MAC length > 0 in the reply.
		 */
		ret = dst_context_create(key->key, mctx, DNS_LOGCATEGORY_DNSSEC,
					 true, 0, &ctx);
		if (ret != ISC_R_SUCCESS) {
			return (ret);
		}

		/*
		 * If this is a response, and if there was a TSIG in
		 * the query, digest the request's MAC.
		 *
		 * (Note: querytsig should be non-NULL for all
		 * responses except TKEY responses. Those may be signed
		 * with the newly-negotiated TSIG key even if the query
		 * wasn't signed.)
		 */
		if (response && msg->querytsig != NULL) {
			dns_rdata_t querytsigrdata = DNS_RDATA_INIT;

			INSIST(msg->verified_sig);

			ret = dns_rdataset_first(msg->querytsig);
			if (ret != ISC_R_SUCCESS) {
				goto cleanup_context;
			}
			dns_rdataset_current(msg->querytsig, &querytsigrdata);
			ret = dns_rdata_tostruct(&querytsigrdata, &querytsig,
						 NULL);
			if (ret != ISC_R_SUCCESS) {
				goto cleanup_context;
			}
			isc_buffer_putuint16(&databuf, querytsig.siglen);
			if (isc_buffer_availablelength(&databuf) <
			    querytsig.siglen) {
				ret = ISC_R_NOSPACE;
				goto cleanup_context;
			}
			isc_buffer_putmem(&databuf, querytsig.signature,
					  querytsig.siglen);
			isc_buffer_usedregion(&databuf, &r);
			ret = dst_context_adddata(ctx, &r);
			if (ret != ISC_R_SUCCESS) {
				goto cleanup_context;
			}
			querytsig_ok = true;
		}

		/*
		 * Digest the header.
		 */
		isc_buffer_init(&headerbuf, header, sizeof(header));
		dns_message_renderheader(msg, &headerbuf);
		isc_buffer_usedregion(&headerbuf, &r);
		ret = dst_context_adddata(ctx, &r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		/*
		 * Digest the remainder of the message.
		 */
		isc_buffer_usedregion(msg->buffer, &r);
		isc_region_consume(&r, DNS_MESSAGE_HEADERLEN);
		ret = dst_context_adddata(ctx, &r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		if (msg->tcp_continuation == 0) {
			/*
			 * Digest the name, class, ttl, alg.
			 */
			dns_name_toregion(&key->name, &r);
			ret = dst_context_adddata(ctx, &r);
			if (ret != ISC_R_SUCCESS) {
				goto cleanup_context;
			}

			isc_buffer_clear(&databuf);
			isc_buffer_putuint16(&databuf, dns_rdataclass_any);
			isc_buffer_putuint32(&databuf, 0); /* ttl */
			isc_buffer_usedregion(&databuf, &r);
			ret = dst_context_adddata(ctx, &r);
			if (ret != ISC_R_SUCCESS) {
				goto cleanup_context;
			}

			dns_name_toregion(&tsig.algorithm, &r);
			ret = dst_context_adddata(ctx, &r);
			if (ret != ISC_R_SUCCESS) {
				goto cleanup_context;
			}
		}
		/* Digest the timesigned and fudge */
		isc_buffer_clear(&databuf);
		if (tsig.error == dns_tsigerror_badtime && querytsig_ok) {
			tsig.timesigned = querytsig.timesigned;
		}
		isc_buffer_putuint48(&databuf, tsig.timesigned);
		isc_buffer_putuint16(&databuf, tsig.fudge);
		isc_buffer_usedregion(&databuf, &r);
		ret = dst_context_adddata(ctx, &r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		if (msg->tcp_continuation == 0) {
			/*
			 * Digest the error and other data length.
			 */
			isc_buffer_clear(&databuf);
			isc_buffer_putuint16(&databuf, tsig.error);
			isc_buffer_putuint16(&databuf, tsig.otherlen);

			isc_buffer_usedregion(&databuf, &r);
			ret = dst_context_adddata(ctx, &r);
			if (ret != ISC_R_SUCCESS) {
				goto cleanup_context;
			}

			/*
			 * Digest other data.
			 */
			if (tsig.otherlen > 0) {
				r.length = tsig.otherlen;
				r.base = tsig.other;
				ret = dst_context_adddata(ctx, &r);
				if (ret != ISC_R_SUCCESS) {
					goto cleanup_context;
				}
			}
		}

		ret = dst_key_sigsize(key->key, &sigsize);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}
		tsig.signature = isc_mem_get(mctx, sigsize);

		isc_buffer_init(&sigbuf, tsig.signature, sigsize);
		ret = dst_context_sign(ctx, &sigbuf);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_signature;
		}
		dst_context_destroy(&ctx);
		digestbits = dst_key_getbits(key->key);
		if (digestbits != 0) {
			unsigned int bytes = (digestbits + 7) / 8;
			if (querytsig_ok && bytes < querytsig.siglen) {
				bytes = querytsig.siglen;
			}
			if (bytes > isc_buffer_usedlength(&sigbuf)) {
				bytes = isc_buffer_usedlength(&sigbuf);
			}
			tsig.siglen = bytes;
		} else {
			tsig.siglen = isc_buffer_usedlength(&sigbuf);
		}
	} else {
		tsig.siglen = 0;
		tsig.signature = NULL;
	}

	dns_message_gettemprdata(msg, &rdata);
	isc_buffer_allocate(msg->mctx, &dynbuf, 512);
	ret = dns_rdata_fromstruct(rdata, dns_rdataclass_any,
				   dns_rdatatype_tsig, &tsig, dynbuf);
	if (ret != ISC_R_SUCCESS) {
		goto cleanup_dynbuf;
	}

	dns_message_takebuffer(msg, &dynbuf);

	if (tsig.signature != NULL) {
		isc_mem_put(mctx, tsig.signature, sigsize);
		tsig.signature = NULL;
	}

	dns_message_gettempname(msg, &owner);
	dns_name_copy(&key->name, owner);

	dns_message_gettemprdatalist(msg, &datalist);

	dns_message_gettemprdataset(msg, &dataset);
	datalist->rdclass = dns_rdataclass_any;
	datalist->type = dns_rdatatype_tsig;
	ISC_LIST_APPEND(datalist->rdata, rdata, link);
	dns_rdatalist_tordataset(datalist, dataset);
	msg->tsig = dataset;
	msg->tsigname = owner;

	/* Windows does not like the tsig name being compressed. */
	msg->tsigname->attributes |= DNS_NAMEATTR_NOCOMPRESS;

	return (ISC_R_SUCCESS);

cleanup_dynbuf:
	isc_buffer_free(&dynbuf);
	dns_message_puttemprdata(msg, &rdata);
cleanup_signature:
	if (tsig.signature != NULL) {
		isc_mem_put(mctx, tsig.signature, sigsize);
	}
cleanup_context:
	if (ctx != NULL) {
		dst_context_destroy(&ctx);
	}
	return (ret);
}

isc_result_t
dns_tsig_verify(isc_buffer_t *source, dns_message_t *msg,
		dns_tsig_keyring_t *ring1, dns_tsig_keyring_t *ring2) {
	dns_rdata_any_tsig_t tsig, querytsig;
	isc_region_t r, source_r, header_r, sig_r;
	isc_buffer_t databuf;
	unsigned char data[32];
	dns_name_t *keyname;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_stdtime_t now;
	isc_result_t ret;
	dns_tsigkey_t *tsigkey;
	dst_key_t *key = NULL;
	unsigned char header[DNS_MESSAGE_HEADERLEN];
	dst_context_t *ctx = NULL;
	isc_mem_t *mctx;
	uint16_t addcount, id;
	unsigned int siglen;
	unsigned int alg;
	bool response;

	REQUIRE(source != NULL);
	REQUIRE(DNS_MESSAGE_VALID(msg));
	tsigkey = dns_message_gettsigkey(msg);
	response = is_response(msg);

	REQUIRE(tsigkey == NULL || VALID_TSIG_KEY(tsigkey));

	msg->verify_attempted = 1;
	msg->verified_sig = 0;
	msg->tsigstatus = dns_tsigerror_badsig;

	if (msg->tcp_continuation) {
		if (tsigkey == NULL || msg->querytsig == NULL) {
			return (DNS_R_UNEXPECTEDTSIG);
		}
		return (tsig_verify_tcp(source, msg));
	}

	/*
	 * There should be a TSIG record...
	 */
	if (msg->tsig == NULL) {
		return (DNS_R_EXPECTEDTSIG);
	}

	/*
	 * If this is a response and there's no key or query TSIG, there
	 * shouldn't be one on the response.
	 */
	if (response && (tsigkey == NULL || msg->querytsig == NULL)) {
		return (DNS_R_UNEXPECTEDTSIG);
	}

	mctx = msg->mctx;

	/*
	 * If we're here, we know the message is well formed and contains a
	 * TSIG record.
	 */

	keyname = msg->tsigname;
	ret = dns_rdataset_first(msg->tsig);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}
	dns_rdataset_current(msg->tsig, &rdata);
	ret = dns_rdata_tostruct(&rdata, &tsig, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}
	dns_rdata_reset(&rdata);
	if (response) {
		ret = dns_rdataset_first(msg->querytsig);
		if (ret != ISC_R_SUCCESS) {
			return (ret);
		}
		dns_rdataset_current(msg->querytsig, &rdata);
		ret = dns_rdata_tostruct(&rdata, &querytsig, NULL);
		if (ret != ISC_R_SUCCESS) {
			return (ret);
		}
	}

	/*
	 * Do the key name and algorithm match that of the query?
	 */
	if (response &&
	    (!dns_name_equal(keyname, &tsigkey->name) ||
	     !dns_name_equal(&tsig.algorithm, &querytsig.algorithm)))
	{
		msg->tsigstatus = dns_tsigerror_badkey;
		tsig_log(msg->tsigkey, 2,
			 "key name and algorithm do not match");
		return (DNS_R_TSIGVERIFYFAILURE);
	}

	/*
	 * Get the current time.
	 */
	if (msg->fuzzing) {
		now = msg->fuzztime;
	} else {
		isc_stdtime_get(&now);
	}

	/*
	 * Find dns_tsigkey_t based on keyname.
	 */
	if (tsigkey == NULL) {
		ret = ISC_R_NOTFOUND;
		if (ring1 != NULL) {
			ret = dns_tsigkey_find(&tsigkey, keyname,
					       &tsig.algorithm, ring1);
		}
		if (ret == ISC_R_NOTFOUND && ring2 != NULL) {
			ret = dns_tsigkey_find(&tsigkey, keyname,
					       &tsig.algorithm, ring2);
		}
		if (ret != ISC_R_SUCCESS) {
			msg->tsigstatus = dns_tsigerror_badkey;
			ret = dns_tsigkey_create(keyname, &tsig.algorithm, NULL,
						 0, false, NULL, now, now, mctx,
						 NULL, &msg->tsigkey);
			if (ret != ISC_R_SUCCESS) {
				return (ret);
			}
			tsig_log(msg->tsigkey, 2, "unknown key");
			return (DNS_R_TSIGVERIFYFAILURE);
		}
		msg->tsigkey = tsigkey;
	}

	key = tsigkey->key;

	/*
	 * Check digest length.
	 */
	alg = dst_key_alg(key);
	ret = dst_key_sigsize(key, &siglen);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}
	if (dns__tsig_algvalid(alg)) {
		if (tsig.siglen > siglen) {
			tsig_log(msg->tsigkey, 2, "signature length too big");
			return (DNS_R_FORMERR);
		}
		if (tsig.siglen > 0 &&
		    (tsig.siglen < 10 || tsig.siglen < ((siglen + 1) / 2))) {
			tsig_log(msg->tsigkey, 2,
				 "signature length below minimum");
			return (DNS_R_FORMERR);
		}
	}

	if (tsig.siglen > 0) {
		uint16_t addcount_n;

		sig_r.base = tsig.signature;
		sig_r.length = tsig.siglen;

		ret = dst_context_create(key, mctx, DNS_LOGCATEGORY_DNSSEC,
					 false, 0, &ctx);
		if (ret != ISC_R_SUCCESS) {
			return (ret);
		}

		if (response) {
			isc_buffer_init(&databuf, data, sizeof(data));
			isc_buffer_putuint16(&databuf, querytsig.siglen);
			isc_buffer_usedregion(&databuf, &r);
			ret = dst_context_adddata(ctx, &r);
			if (ret != ISC_R_SUCCESS) {
				goto cleanup_context;
			}
			if (querytsig.siglen > 0) {
				r.length = querytsig.siglen;
				r.base = querytsig.signature;
				ret = dst_context_adddata(ctx, &r);
				if (ret != ISC_R_SUCCESS) {
					goto cleanup_context;
				}
			}
		}

		/*
		 * Extract the header.
		 */
		isc_buffer_usedregion(source, &r);
		memmove(header, r.base, DNS_MESSAGE_HEADERLEN);
		isc_region_consume(&r, DNS_MESSAGE_HEADERLEN);

		/*
		 * Decrement the additional field counter.
		 */
		memmove(&addcount, &header[DNS_MESSAGE_HEADERLEN - 2], 2);
		addcount_n = ntohs(addcount);
		addcount = htons((uint16_t)(addcount_n - 1));
		memmove(&header[DNS_MESSAGE_HEADERLEN - 2], &addcount, 2);

		/*
		 * Put in the original id.
		 */
		id = htons(tsig.originalid);
		memmove(&header[0], &id, 2);

		/*
		 * Digest the modified header.
		 */
		header_r.base = (unsigned char *)header;
		header_r.length = DNS_MESSAGE_HEADERLEN;
		ret = dst_context_adddata(ctx, &header_r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		/*
		 * Digest all non-TSIG records.
		 */
		isc_buffer_usedregion(source, &source_r);
		r.base = source_r.base + DNS_MESSAGE_HEADERLEN;
		r.length = msg->sigstart - DNS_MESSAGE_HEADERLEN;
		ret = dst_context_adddata(ctx, &r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		/*
		 * Digest the key name.
		 */
		dns_name_toregion(&tsigkey->name, &r);
		ret = dst_context_adddata(ctx, &r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		isc_buffer_init(&databuf, data, sizeof(data));
		isc_buffer_putuint16(&databuf, tsig.common.rdclass);
		isc_buffer_putuint32(&databuf, msg->tsig->ttl);
		isc_buffer_usedregion(&databuf, &r);
		ret = dst_context_adddata(ctx, &r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		/*
		 * Digest the key algorithm.
		 */
		dns_name_toregion(tsigkey->algorithm, &r);
		ret = dst_context_adddata(ctx, &r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		isc_buffer_clear(&databuf);
		isc_buffer_putuint48(&databuf, tsig.timesigned);
		isc_buffer_putuint16(&databuf, tsig.fudge);
		isc_buffer_putuint16(&databuf, tsig.error);
		isc_buffer_putuint16(&databuf, tsig.otherlen);
		isc_buffer_usedregion(&databuf, &r);
		ret = dst_context_adddata(ctx, &r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		if (tsig.otherlen > 0) {
			r.base = tsig.other;
			r.length = tsig.otherlen;
			ret = dst_context_adddata(ctx, &r);
			if (ret != ISC_R_SUCCESS) {
				goto cleanup_context;
			}
		}

		ret = dst_context_verify(ctx, &sig_r);
		if (ret == DST_R_VERIFYFAILURE) {
			ret = DNS_R_TSIGVERIFYFAILURE;
			tsig_log(msg->tsigkey, 2,
				 "signature failed to verify(1)");
			goto cleanup_context;
		} else if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}
		msg->verified_sig = 1;
	} else if (!response || (tsig.error != dns_tsigerror_badsig &&
				 tsig.error != dns_tsigerror_badkey))
	{
		tsig_log(msg->tsigkey, 2, "signature was empty");
		return (DNS_R_TSIGVERIFYFAILURE);
	}

	/*
	 * Here at this point, the MAC has been verified. Even if any of
	 * the following code returns a TSIG error, the reply will be
	 * signed and WILL always include the request MAC in the digest
	 * computation.
	 */

	/*
	 * Is the time ok?
	 */
	if (now + msg->timeadjust > tsig.timesigned + tsig.fudge) {
		msg->tsigstatus = dns_tsigerror_badtime;
		tsig_log(msg->tsigkey, 2, "signature has expired");
		ret = DNS_R_CLOCKSKEW;
		goto cleanup_context;
	} else if (now + msg->timeadjust < tsig.timesigned - tsig.fudge) {
		msg->tsigstatus = dns_tsigerror_badtime;
		tsig_log(msg->tsigkey, 2, "signature is in the future");
		ret = DNS_R_CLOCKSKEW;
		goto cleanup_context;
	}

	if (dns__tsig_algvalid(alg)) {
		uint16_t digestbits = dst_key_getbits(key);

		if (tsig.siglen > 0 && digestbits != 0 &&
		    tsig.siglen < ((digestbits + 7) / 8)) {
			msg->tsigstatus = dns_tsigerror_badtrunc;
			tsig_log(msg->tsigkey, 2,
				 "truncated signature length too small");
			ret = DNS_R_TSIGVERIFYFAILURE;
			goto cleanup_context;
		}
		if (tsig.siglen > 0 && digestbits == 0 && tsig.siglen < siglen)
		{
			msg->tsigstatus = dns_tsigerror_badtrunc;
			tsig_log(msg->tsigkey, 2, "signature length too small");
			ret = DNS_R_TSIGVERIFYFAILURE;
			goto cleanup_context;
		}
	}

	if (response && tsig.error != dns_rcode_noerror) {
		msg->tsigstatus = tsig.error;
		if (tsig.error == dns_tsigerror_badtime) {
			ret = DNS_R_CLOCKSKEW;
		} else {
			ret = DNS_R_TSIGERRORSET;
		}
		goto cleanup_context;
	}

	msg->tsigstatus = dns_rcode_noerror;
	ret = ISC_R_SUCCESS;

cleanup_context:
	if (ctx != NULL) {
		dst_context_destroy(&ctx);
	}

	return (ret);
}

static isc_result_t
tsig_verify_tcp(isc_buffer_t *source, dns_message_t *msg) {
	dns_rdata_any_tsig_t tsig, querytsig;
	isc_region_t r, source_r, header_r, sig_r;
	isc_buffer_t databuf;
	unsigned char data[32];
	dns_name_t *keyname;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_stdtime_t now;
	isc_result_t ret;
	dns_tsigkey_t *tsigkey;
	dst_key_t *key = NULL;
	unsigned char header[DNS_MESSAGE_HEADERLEN];
	uint16_t addcount, id;
	bool has_tsig = false;
	isc_mem_t *mctx;
	unsigned int siglen;
	unsigned int alg;

	REQUIRE(source != NULL);
	REQUIRE(msg != NULL);
	REQUIRE(dns_message_gettsigkey(msg) != NULL);
	REQUIRE(msg->tcp_continuation == 1);
	REQUIRE(msg->querytsig != NULL);

	msg->verified_sig = 0;
	msg->tsigstatus = dns_tsigerror_badsig;

	if (!is_response(msg)) {
		return (DNS_R_EXPECTEDRESPONSE);
	}

	mctx = msg->mctx;

	tsigkey = dns_message_gettsigkey(msg);
	key = tsigkey->key;

	/*
	 * Extract and parse the previous TSIG
	 */
	ret = dns_rdataset_first(msg->querytsig);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}
	dns_rdataset_current(msg->querytsig, &rdata);
	ret = dns_rdata_tostruct(&rdata, &querytsig, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}
	dns_rdata_reset(&rdata);

	/*
	 * If there is a TSIG in this message, do some checks.
	 */
	if (msg->tsig != NULL) {
		has_tsig = true;

		keyname = msg->tsigname;
		ret = dns_rdataset_first(msg->tsig);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_querystruct;
		}
		dns_rdataset_current(msg->tsig, &rdata);
		ret = dns_rdata_tostruct(&rdata, &tsig, NULL);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_querystruct;
		}

		/*
		 * Do the key name and algorithm match that of the query?
		 */
		if (!dns_name_equal(keyname, &tsigkey->name) ||
		    !dns_name_equal(&tsig.algorithm, &querytsig.algorithm))
		{
			msg->tsigstatus = dns_tsigerror_badkey;
			ret = DNS_R_TSIGVERIFYFAILURE;
			tsig_log(msg->tsigkey, 2,
				 "key name and algorithm do not match");
			goto cleanup_querystruct;
		}

		/*
		 * Check digest length.
		 */
		alg = dst_key_alg(key);
		ret = dst_key_sigsize(key, &siglen);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_querystruct;
		}
		if (dns__tsig_algvalid(alg)) {
			if (tsig.siglen > siglen) {
				tsig_log(tsigkey, 2,
					 "signature length too big");
				ret = DNS_R_FORMERR;
				goto cleanup_querystruct;
			}
			if (tsig.siglen > 0 &&
			    (tsig.siglen < 10 ||
			     tsig.siglen < ((siglen + 1) / 2))) {
				tsig_log(tsigkey, 2,
					 "signature length below minimum");
				ret = DNS_R_FORMERR;
				goto cleanup_querystruct;
			}
		}
	}

	if (msg->tsigctx == NULL) {
		ret = dst_context_create(key, mctx, DNS_LOGCATEGORY_DNSSEC,
					 false, 0, &msg->tsigctx);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_querystruct;
		}

		/*
		 * Digest the length of the query signature
		 */
		isc_buffer_init(&databuf, data, sizeof(data));
		isc_buffer_putuint16(&databuf, querytsig.siglen);
		isc_buffer_usedregion(&databuf, &r);
		ret = dst_context_adddata(msg->tsigctx, &r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		/*
		 * Digest the data of the query signature
		 */
		if (querytsig.siglen > 0) {
			r.length = querytsig.siglen;
			r.base = querytsig.signature;
			ret = dst_context_adddata(msg->tsigctx, &r);
			if (ret != ISC_R_SUCCESS) {
				goto cleanup_context;
			}
		}
	}

	/*
	 * Extract the header.
	 */
	isc_buffer_usedregion(source, &r);
	memmove(header, r.base, DNS_MESSAGE_HEADERLEN);
	isc_region_consume(&r, DNS_MESSAGE_HEADERLEN);

	/*
	 * Decrement the additional field counter if necessary.
	 */
	if (has_tsig) {
		uint16_t addcount_n;

		memmove(&addcount, &header[DNS_MESSAGE_HEADERLEN - 2], 2);
		addcount_n = ntohs(addcount);
		addcount = htons((uint16_t)(addcount_n - 1));
		memmove(&header[DNS_MESSAGE_HEADERLEN - 2], &addcount, 2);

		/*
		 * Put in the original id.
		 *
		 * XXX Can TCP transfers be forwarded?  How would that
		 * work?
		 */
		id = htons(tsig.originalid);
		memmove(&header[0], &id, 2);
	}

	/*
	 * Digest the modified header.
	 */
	header_r.base = (unsigned char *)header;
	header_r.length = DNS_MESSAGE_HEADERLEN;
	ret = dst_context_adddata(msg->tsigctx, &header_r);
	if (ret != ISC_R_SUCCESS) {
		goto cleanup_context;
	}

	/*
	 * Digest all non-TSIG records.
	 */
	isc_buffer_usedregion(source, &source_r);
	r.base = source_r.base + DNS_MESSAGE_HEADERLEN;
	if (has_tsig) {
		r.length = msg->sigstart - DNS_MESSAGE_HEADERLEN;
	} else {
		r.length = source_r.length - DNS_MESSAGE_HEADERLEN;
	}
	ret = dst_context_adddata(msg->tsigctx, &r);
	if (ret != ISC_R_SUCCESS) {
		goto cleanup_context;
	}

	/*
	 * Digest the time signed and fudge.
	 */
	if (has_tsig) {
		isc_buffer_init(&databuf, data, sizeof(data));
		isc_buffer_putuint48(&databuf, tsig.timesigned);
		isc_buffer_putuint16(&databuf, tsig.fudge);
		isc_buffer_usedregion(&databuf, &r);
		ret = dst_context_adddata(msg->tsigctx, &r);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}

		sig_r.base = tsig.signature;
		sig_r.length = tsig.siglen;
		if (tsig.siglen == 0) {
			if (tsig.error != dns_rcode_noerror) {
				msg->tsigstatus = tsig.error;
				if (tsig.error == dns_tsigerror_badtime) {
					ret = DNS_R_CLOCKSKEW;
				} else {
					ret = DNS_R_TSIGERRORSET;
				}
			} else {
				tsig_log(msg->tsigkey, 2, "signature is empty");
				ret = DNS_R_TSIGVERIFYFAILURE;
			}
			goto cleanup_context;
		}

		ret = dst_context_verify(msg->tsigctx, &sig_r);
		if (ret == DST_R_VERIFYFAILURE) {
			tsig_log(msg->tsigkey, 2,
				 "signature failed to verify(2)");
			ret = DNS_R_TSIGVERIFYFAILURE;
			goto cleanup_context;
		} else if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}
		msg->verified_sig = 1;

		/*
		 * Here at this point, the MAC has been verified. Even
		 * if any of the following code returns a TSIG error,
		 * the reply will be signed and WILL always include the
		 * request MAC in the digest computation.
		 */

		/*
		 * Is the time ok?
		 */
		if (msg->fuzzing) {
			now = msg->fuzztime;
		} else {
			isc_stdtime_get(&now);
		}

		if (now + msg->timeadjust > tsig.timesigned + tsig.fudge) {
			msg->tsigstatus = dns_tsigerror_badtime;
			tsig_log(msg->tsigkey, 2, "signature has expired");
			ret = DNS_R_CLOCKSKEW;
			goto cleanup_context;
		} else if (now + msg->timeadjust < tsig.timesigned - tsig.fudge)
		{
			msg->tsigstatus = dns_tsigerror_badtime;
			tsig_log(msg->tsigkey, 2, "signature is in the future");
			ret = DNS_R_CLOCKSKEW;
			goto cleanup_context;
		}

		alg = dst_key_alg(key);
		ret = dst_key_sigsize(key, &siglen);
		if (ret != ISC_R_SUCCESS) {
			goto cleanup_context;
		}
		if (dns__tsig_algvalid(alg)) {
			uint16_t digestbits = dst_key_getbits(key);

			if (tsig.siglen > 0 && digestbits != 0 &&
			    tsig.siglen < ((digestbits + 7) / 8)) {
				msg->tsigstatus = dns_tsigerror_badtrunc;
				tsig_log(msg->tsigkey, 2,
					 "truncated signature length "
					 "too small");
				ret = DNS_R_TSIGVERIFYFAILURE;
				goto cleanup_context;
			}
			if (tsig.siglen > 0 && digestbits == 0 &&
			    tsig.siglen < siglen) {
				msg->tsigstatus = dns_tsigerror_badtrunc;
				tsig_log(msg->tsigkey, 2,
					 "signature length too small");
				ret = DNS_R_TSIGVERIFYFAILURE;
				goto cleanup_context;
			}
		}

		if (tsig.error != dns_rcode_noerror) {
			msg->tsigstatus = tsig.error;
			if (tsig.error == dns_tsigerror_badtime) {
				ret = DNS_R_CLOCKSKEW;
			} else {
				ret = DNS_R_TSIGERRORSET;
			}
			goto cleanup_context;
		}
	}

	msg->tsigstatus = dns_rcode_noerror;
	ret = ISC_R_SUCCESS;

cleanup_context:
	/*
	 * Except in error conditions, don't destroy the DST context
	 * for unsigned messages; it is a running sum till the next
	 * TSIG signed message.
	 */
	if ((ret != ISC_R_SUCCESS || has_tsig) && msg->tsigctx != NULL) {
		dst_context_destroy(&msg->tsigctx);
	}

cleanup_querystruct:
	dns_rdata_freestruct(&querytsig);

	return (ret);
}

isc_result_t
dns_tsigkey_find(dns_tsigkey_t **tsigkey, const dns_name_t *name,
		 const dns_name_t *algorithm, dns_tsig_keyring_t *ring) {
	dns_tsigkey_t *key;
	isc_stdtime_t now;
	isc_result_t result;

	REQUIRE(tsigkey != NULL);
	REQUIRE(*tsigkey == NULL);
	REQUIRE(name != NULL);
	REQUIRE(ring != NULL);

	RWLOCK(&ring->lock, isc_rwlocktype_write);
	cleanup_ring(ring);
	RWUNLOCK(&ring->lock, isc_rwlocktype_write);

	isc_stdtime_get(&now);
	RWLOCK(&ring->lock, isc_rwlocktype_read);
	key = NULL;
	result = dns_rbt_findname(ring->keys, name, 0, NULL, (void *)&key);
	if (result == DNS_R_PARTIALMATCH || result == ISC_R_NOTFOUND) {
		RWUNLOCK(&ring->lock, isc_rwlocktype_read);
		return (ISC_R_NOTFOUND);
	}
	if (algorithm != NULL && !dns_name_equal(key->algorithm, algorithm)) {
		RWUNLOCK(&ring->lock, isc_rwlocktype_read);
		return (ISC_R_NOTFOUND);
	}
	if (key->inception != key->expire && isc_serial_lt(key->expire, now)) {
		/*
		 * The key has expired.
		 */
		RWUNLOCK(&ring->lock, isc_rwlocktype_read);
		RWLOCK(&ring->lock, isc_rwlocktype_write);
		remove_fromring(key);
		RWUNLOCK(&ring->lock, isc_rwlocktype_write);
		return (ISC_R_NOTFOUND);
	}
#if 0
	/*
	 * MPAXXX We really should look at the inception time.
	 */
	if (key->inception != key->expire &&
	    isc_serial_lt(key->inception, now)) {
		RWUNLOCK(&ring->lock, isc_rwlocktype_read);
		adjust_lru(key);
		return (ISC_R_NOTFOUND);
	}
#endif /* if 0 */
	isc_refcount_increment(&key->refs);
	RWUNLOCK(&ring->lock, isc_rwlocktype_read);
	adjust_lru(key);
	*tsigkey = key;
	return (ISC_R_SUCCESS);
}

static void
free_tsignode(void *node, void *_unused) {
	dns_tsigkey_t *key;

	REQUIRE(node != NULL);

	UNUSED(_unused);

	key = node;
	if (key->generated) {
		if (ISC_LINK_LINKED(key, link)) {
			ISC_LIST_UNLINK(key->ring->lru, key, link);
		}
	}
	dns_tsigkey_detach(&key);
}

isc_result_t
dns_tsigkeyring_create(isc_mem_t *mctx, dns_tsig_keyring_t **ringp) {
	isc_result_t result;
	dns_tsig_keyring_t *ring;

	REQUIRE(mctx != NULL);
	REQUIRE(ringp != NULL);
	REQUIRE(*ringp == NULL);

	ring = isc_mem_get(mctx, sizeof(dns_tsig_keyring_t));

	isc_rwlock_init(&ring->lock, 0, 0);
	ring->keys = NULL;
	result = dns_rbt_create(mctx, free_tsignode, NULL, &ring->keys);
	if (result != ISC_R_SUCCESS) {
		isc_rwlock_destroy(&ring->lock);
		isc_mem_put(mctx, ring, sizeof(dns_tsig_keyring_t));
		return (result);
	}

	ring->writecount = 0;
	ring->mctx = NULL;
	ring->generated = 0;
	ring->maxgenerated = DNS_TSIG_MAXGENERATEDKEYS;
	ISC_LIST_INIT(ring->lru);
	isc_mem_attach(mctx, &ring->mctx);
	isc_refcount_init(&ring->references, 1);

	*ringp = ring;
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_tsigkeyring_add(dns_tsig_keyring_t *ring, const dns_name_t *name,
		    dns_tsigkey_t *tkey) {
	isc_result_t result;

	result = keyring_add(ring, name, tkey);
	if (result == ISC_R_SUCCESS) {
		isc_refcount_increment(&tkey->refs);
	}

	return (result);
}

void
dns_tsigkeyring_attach(dns_tsig_keyring_t *source,
		       dns_tsig_keyring_t **target) {
	REQUIRE(source != NULL);
	REQUIRE(target != NULL && *target == NULL);

	isc_refcount_increment(&source->references);

	*target = source;
}

void
dns_tsigkeyring_detach(dns_tsig_keyring_t **ringp) {
	dns_tsig_keyring_t *ring;

	REQUIRE(ringp != NULL);
	REQUIRE(*ringp != NULL);

	ring = *ringp;
	*ringp = NULL;

	if (isc_refcount_decrement(&ring->references) == 1) {
		destroyring(ring);
	}
}

void
dns_keyring_restore(dns_tsig_keyring_t *ring, FILE *fp) {
	isc_stdtime_t now;
	isc_result_t result;

	isc_stdtime_get(&now);
	do {
		result = restore_key(ring, now, fp);
		if (result == ISC_R_NOMORE) {
			return;
		}
		if (result == DNS_R_BADALG || result == DNS_R_EXPIRED) {
			result = ISC_R_SUCCESS;
		}
	} while (result == ISC_R_SUCCESS);
}
