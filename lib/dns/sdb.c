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
#include <string.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/fixedname.h>
#include <dns/log.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatatype.h>
#include <dns/sdb.h>
#include <dns/types.h>

#include "rdatalist_p.h"

struct dns_sdbimplementation {
	const dns_sdbmethods_t *methods;
	void *driverdata;
	unsigned int flags;
	isc_mem_t *mctx;
	isc_mutex_t driverlock;
	dns_dbimplementation_t *dbimp;
};

struct dns_sdb {
	/* Unlocked */
	dns_db_t common;
	char *zone;
	dns_sdbimplementation_t *implementation;
	void *dbdata;

	/* Atomic */
	isc_refcount_t references;
};

struct dns_sdblookup {
	/* Unlocked */
	unsigned int magic;
	dns_sdb_t *sdb;
	ISC_LIST(dns_rdatalist_t) lists;
	ISC_LIST(isc_buffer_t) buffers;
	dns_name_t *name;
	ISC_LINK(dns_sdblookup_t) link;
	dns_rdatacallbacks_t callbacks;

	/* Atomic */
	isc_refcount_t references;
};

typedef struct dns_sdblookup dns_sdbnode_t;

struct dns_sdballnodes {
	dns_dbiterator_t common;
	ISC_LIST(dns_sdbnode_t) nodelist;
	dns_sdbnode_t *current;
	dns_sdbnode_t *origin;
};

typedef dns_sdballnodes_t sdb_dbiterator_t;

typedef struct sdb_rdatasetiter {
	dns_rdatasetiter_t common;
	dns_rdatalist_t *current;
} sdb_rdatasetiter_t;

#define SDB_MAGIC ISC_MAGIC('S', 'D', 'B', '-')

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define VALID_SDB(sdb) ((sdb) != NULL && (sdb)->common.impmagic == SDB_MAGIC)

#define SDBLOOKUP_MAGIC	      ISC_MAGIC('S', 'D', 'B', 'L')
#define VALID_SDBLOOKUP(sdbl) ISC_MAGIC_VALID(sdbl, SDBLOOKUP_MAGIC)
#define VALID_SDBNODE(sdbn)   VALID_SDBLOOKUP(sdbn)

/* These values are taken from RFC1537 */
#define SDB_DEFAULT_REFRESH 28800U  /* 8 hours */
#define SDB_DEFAULT_RETRY   7200U   /* 2 hours */
#define SDB_DEFAULT_EXPIRE  604800U /* 7 days */
#define SDB_DEFAULT_MINIMUM 86400U  /* 1 day */

/* This is a reasonable value */
#define SDB_DEFAULT_TTL (60 * 60 * 24)

#ifdef __COVERITY__
#define MAYBE_LOCK(sdb)	  LOCK(&sdb->implementation->driverlock)
#define MAYBE_UNLOCK(sdb) UNLOCK(&sdb->implementation->driverlock)
#else /* ifdef __COVERITY__ */
#define MAYBE_LOCK(sdb)                                          \
	do {                                                     \
		unsigned int flags = sdb->implementation->flags; \
		if ((flags & DNS_SDBFLAG_THREADSAFE) == 0)       \
			LOCK(&sdb->implementation->driverlock);  \
	} while (0)

#define MAYBE_UNLOCK(sdb)                                         \
	do {                                                      \
		unsigned int flags = sdb->implementation->flags;  \
		if ((flags & DNS_SDBFLAG_THREADSAFE) == 0)        \
			UNLOCK(&sdb->implementation->driverlock); \
	} while (0)
#endif /* ifdef __COVERITY__ */

static int dummy;

static isc_result_t
dns_sdb_create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
	       dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
	       void *driverarg, dns_db_t **dbp);

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdatatype_t covers, isc_stdtime_t now,
	     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset);

static isc_result_t
createnode(dns_sdb_t *sdb, dns_sdbnode_t **nodep);

static void
destroynode(dns_sdbnode_t *node);

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp);

static void
list_tordataset(dns_rdatalist_t *rdatalist, dns_db_t *db, dns_dbnode_t *node,
		dns_rdataset_t *rdataset);

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp);
static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator, const dns_name_t *name);
static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name);
static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name);

static dns_dbiteratormethods_t dbiterator_methods = {
	dbiterator_destroy, dbiterator_first, dbiterator_last,
	dbiterator_seek,    dbiterator_prev,  dbiterator_next,
	dbiterator_current, dbiterator_pause, dbiterator_origin
};

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp);
static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator);
static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator);
static void
rdatasetiter_current(dns_rdatasetiter_t *iterator, dns_rdataset_t *rdataset);

static dns_rdatasetitermethods_t rdatasetiter_methods = {
	rdatasetiter_destroy, rdatasetiter_first, rdatasetiter_next,
	rdatasetiter_current
};

/*
 * Functions used by implementors of simple databases
 */
isc_result_t
dns_sdb_register(const char *drivername, const dns_sdbmethods_t *methods,
		 void *driverdata, unsigned int flags, isc_mem_t *mctx,
		 dns_sdbimplementation_t **sdbimp) {
	dns_sdbimplementation_t *imp;
	isc_result_t result;

	REQUIRE(drivername != NULL);
	REQUIRE(methods != NULL);
	REQUIRE(methods->lookup != NULL || methods->lookup2 != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(sdbimp != NULL && *sdbimp == NULL);
	REQUIRE((flags &
		 ~(DNS_SDBFLAG_RELATIVEOWNER | DNS_SDBFLAG_RELATIVERDATA |
		   DNS_SDBFLAG_THREADSAFE | DNS_SDBFLAG_DNS64)) == 0);

	imp = isc_mem_get(mctx, sizeof(dns_sdbimplementation_t));
	imp->methods = methods;
	imp->driverdata = driverdata;
	imp->flags = flags;
	imp->mctx = NULL;
	isc_mem_attach(mctx, &imp->mctx);
	isc_mutex_init(&imp->driverlock);

	imp->dbimp = NULL;
	result = dns_db_register(drivername, dns_sdb_create, imp, mctx,
				 &imp->dbimp);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_mutex;
	}
	*sdbimp = imp;

	return (ISC_R_SUCCESS);

cleanup_mutex:
	isc_mutex_destroy(&imp->driverlock);
	isc_mem_put(mctx, imp, sizeof(dns_sdbimplementation_t));
	return (result);
}

void
dns_sdb_unregister(dns_sdbimplementation_t **sdbimp) {
	dns_sdbimplementation_t *imp;

	REQUIRE(sdbimp != NULL && *sdbimp != NULL);

	imp = *sdbimp;
	*sdbimp = NULL;
	dns_db_unregister(&imp->dbimp);
	isc_mutex_destroy(&imp->driverlock);

	isc_mem_putanddetach(&imp->mctx, imp, sizeof(dns_sdbimplementation_t));
}

static unsigned int
initial_size(unsigned int len) {
	unsigned int size;

	for (size = 1024; size < (64 * 1024); size *= 2) {
		if (len < size) {
			return (size);
		}
	}
	return (65535);
}

isc_result_t
dns_sdb_putrdata(dns_sdblookup_t *lookup, dns_rdatatype_t typeval,
		 dns_ttl_t ttl, const unsigned char *rdatap,
		 unsigned int rdlen) {
	dns_rdatalist_t *rdatalist;
	dns_rdata_t *rdata;
	isc_buffer_t *rdatabuf = NULL;
	isc_mem_t *mctx;
	isc_region_t region;

	mctx = lookup->sdb->common.mctx;

	rdatalist = ISC_LIST_HEAD(lookup->lists);
	while (rdatalist != NULL) {
		if (rdatalist->type == typeval) {
			break;
		}
		rdatalist = ISC_LIST_NEXT(rdatalist, link);
	}

	if (rdatalist == NULL) {
		rdatalist = isc_mem_get(mctx, sizeof(dns_rdatalist_t));
		dns_rdatalist_init(rdatalist);
		rdatalist->rdclass = lookup->sdb->common.rdclass;
		rdatalist->type = typeval;
		rdatalist->ttl = ttl;
		ISC_LIST_APPEND(lookup->lists, rdatalist, link);
	} else if (rdatalist->ttl != ttl) {
		return (DNS_R_BADTTL);
	}

	rdata = isc_mem_get(mctx, sizeof(dns_rdata_t));

	isc_buffer_allocate(mctx, &rdatabuf, rdlen);
	DE_CONST(rdatap, region.base);
	region.length = rdlen;
	isc_buffer_copyregion(rdatabuf, &region);
	isc_buffer_usedregion(rdatabuf, &region);
	dns_rdata_init(rdata);
	dns_rdata_fromregion(rdata, rdatalist->rdclass, rdatalist->type,
			     &region);
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	ISC_LIST_APPEND(lookup->buffers, rdatabuf, link);

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_sdb_putrr(dns_sdblookup_t *lookup, const char *type, dns_ttl_t ttl,
	      const char *data) {
	unsigned int datalen;
	dns_rdatatype_t typeval;
	isc_textregion_t r;
	isc_lex_t *lex = NULL;
	isc_result_t result;
	unsigned char *p = NULL;
	unsigned int size = 0; /* Init to suppress compiler warning */
	isc_mem_t *mctx;
	dns_sdbimplementation_t *imp;
	const dns_name_t *origin;
	isc_buffer_t b;
	isc_buffer_t rb;

	REQUIRE(VALID_SDBLOOKUP(lookup));
	REQUIRE(type != NULL);
	REQUIRE(data != NULL);

	mctx = lookup->sdb->common.mctx;

	DE_CONST(type, r.base);
	r.length = strlen(type);
	result = dns_rdatatype_fromtext(&typeval, &r);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	imp = lookup->sdb->implementation;
	if ((imp->flags & DNS_SDBFLAG_RELATIVERDATA) != 0) {
		origin = &lookup->sdb->common.origin;
	} else {
		origin = dns_rootname;
	}

	result = isc_lex_create(mctx, 64, &lex);
	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	datalen = strlen(data);
	size = initial_size(datalen);
	do {
		isc_buffer_constinit(&b, data, datalen);
		isc_buffer_add(&b, datalen);
		result = isc_lex_openbuffer(lex, &b);
		if (result != ISC_R_SUCCESS) {
			goto failure;
		}

		if (size >= 65535) {
			size = 65535;
		}
		p = isc_mem_get(mctx, size);
		isc_buffer_init(&rb, p, size);
		result = dns_rdata_fromtext(NULL, lookup->sdb->common.rdclass,
					    typeval, lex, origin, 0, mctx, &rb,
					    &lookup->callbacks);
		if (result != ISC_R_NOSPACE) {
			break;
		}

		/*
		 * Is the RR too big?
		 */
		if (size >= 65535) {
			break;
		}
		isc_mem_put(mctx, p, size);
		p = NULL;
		size *= 2;
	} while (result == ISC_R_NOSPACE);

	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	result = dns_sdb_putrdata(lookup, typeval, ttl, isc_buffer_base(&rb),
				  isc_buffer_usedlength(&rb));
failure:
	if (p != NULL) {
		isc_mem_put(mctx, p, size);
	}
	if (lex != NULL) {
		isc_lex_destroy(&lex);
	}

	return (result);
}

static isc_result_t
getnode(dns_sdballnodes_t *allnodes, const char *name, dns_sdbnode_t **nodep) {
	dns_name_t *newname;
	const dns_name_t *origin;
	dns_fixedname_t fnewname;
	dns_sdb_t *sdb = (dns_sdb_t *)allnodes->common.db;
	dns_sdbimplementation_t *imp = sdb->implementation;
	dns_sdbnode_t *sdbnode;
	isc_mem_t *mctx = sdb->common.mctx;
	isc_buffer_t b;
	isc_result_t result;

	newname = dns_fixedname_initname(&fnewname);

	if ((imp->flags & DNS_SDBFLAG_RELATIVERDATA) != 0) {
		origin = &sdb->common.origin;
	} else {
		origin = dns_rootname;
	}
	isc_buffer_constinit(&b, name, strlen(name));
	isc_buffer_add(&b, strlen(name));

	result = dns_name_fromtext(newname, &b, origin, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	if (allnodes->common.relative_names) {
		/* All names are relative to the root */
		unsigned int nlabels = dns_name_countlabels(newname);
		dns_name_getlabelsequence(newname, 0, nlabels - 1, newname);
	}

	sdbnode = ISC_LIST_HEAD(allnodes->nodelist);
	if (sdbnode == NULL || !dns_name_equal(sdbnode->name, newname)) {
		sdbnode = NULL;
		result = createnode(sdb, &sdbnode);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		sdbnode->name = isc_mem_get(mctx, sizeof(dns_name_t));
		dns_name_init(sdbnode->name, NULL);
		dns_name_dup(newname, mctx, sdbnode->name);
		ISC_LIST_PREPEND(allnodes->nodelist, sdbnode, link);
		if (allnodes->origin == NULL &&
		    dns_name_equal(newname, &sdb->common.origin)) {
			allnodes->origin = sdbnode;
		}
	}
	*nodep = sdbnode;
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_sdb_putnamedrr(dns_sdballnodes_t *allnodes, const char *name,
		   const char *type, dns_ttl_t ttl, const char *data) {
	isc_result_t result;
	dns_sdbnode_t *sdbnode = NULL;
	result = getnode(allnodes, name, &sdbnode);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	return (dns_sdb_putrr(sdbnode, type, ttl, data));
}

isc_result_t
dns_sdb_putnamedrdata(dns_sdballnodes_t *allnodes, const char *name,
		      dns_rdatatype_t type, dns_ttl_t ttl, const void *rdata,
		      unsigned int rdlen) {
	isc_result_t result;
	dns_sdbnode_t *sdbnode = NULL;
	result = getnode(allnodes, name, &sdbnode);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	return (dns_sdb_putrdata(sdbnode, type, ttl, rdata, rdlen));
}

isc_result_t
dns_sdb_putsoa(dns_sdblookup_t *lookup, const char *mname, const char *rname,
	       uint32_t serial) {
	char str[2 * DNS_NAME_MAXTEXT + 5 * (sizeof("2147483647")) + 7];
	int n;

	REQUIRE(mname != NULL);
	REQUIRE(rname != NULL);

	n = snprintf(str, sizeof(str), "%s %s %u %u %u %u %u", mname, rname,
		     serial, SDB_DEFAULT_REFRESH, SDB_DEFAULT_RETRY,
		     SDB_DEFAULT_EXPIRE, SDB_DEFAULT_MINIMUM);
	if (n >= (int)sizeof(str) || n < 0) {
		return (ISC_R_NOSPACE);
	}
	return (dns_sdb_putrr(lookup, "SOA", SDB_DEFAULT_TTL, str));
}

/*
 * DB routines
 */

static void
attach(dns_db_t *source, dns_db_t **targetp) {
	dns_sdb_t *sdb = (dns_sdb_t *)source;

	REQUIRE(VALID_SDB(sdb));

	isc_refcount_increment(&sdb->references);

	*targetp = source;
}

static void
destroy(dns_sdb_t *sdb) {
	dns_sdbimplementation_t *imp = sdb->implementation;

	isc_refcount_destroy(&sdb->references);

	if (imp != NULL && imp->methods->destroy != NULL) {
		MAYBE_LOCK(sdb);
		imp->methods->destroy(sdb->zone, imp->driverdata, &sdb->dbdata);
		MAYBE_UNLOCK(sdb);
	}

	isc_mem_free(sdb->common.mctx, sdb->zone);

	sdb->common.magic = 0;
	sdb->common.impmagic = 0;

	dns_name_free(&sdb->common.origin, sdb->common.mctx);

	isc_mem_putanddetach(&sdb->common.mctx, sdb, sizeof(dns_sdb_t));
}

static void
detach(dns_db_t **dbp) {
	dns_sdb_t *sdb = (dns_sdb_t *)(*dbp);

	REQUIRE(VALID_SDB(sdb));

	*dbp = NULL;

	if (isc_refcount_decrement(&sdb->references) == 1) {
		destroy(sdb);
	}
}

static isc_result_t
beginload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	UNUSED(db);
	UNUSED(callbacks);
	return (ISC_R_NOTIMPLEMENTED);
}

static isc_result_t
endload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	UNUSED(db);
	UNUSED(callbacks);
	return (ISC_R_NOTIMPLEMENTED);
}

static isc_result_t
dump(dns_db_t *db, dns_dbversion_t *version, const char *filename,
     dns_masterformat_t masterformat) {
	UNUSED(db);
	UNUSED(version);
	UNUSED(filename);
	UNUSED(masterformat);
	return (ISC_R_NOTIMPLEMENTED);
}

static void
currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	REQUIRE(versionp != NULL && *versionp == NULL);

	UNUSED(db);

	*versionp = (void *)&dummy;
	return;
}

static isc_result_t
newversion(dns_db_t *db, dns_dbversion_t **versionp) {
	UNUSED(db);
	UNUSED(versionp);

	return (ISC_R_NOTIMPLEMENTED);
}

static void
attachversion(dns_db_t *db, dns_dbversion_t *source,
	      dns_dbversion_t **targetp) {
	REQUIRE(source != NULL && source == (void *)&dummy);
	REQUIRE(targetp != NULL && *targetp == NULL);

	UNUSED(db);
	*targetp = source;
	return;
}

static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp, bool commit) {
	REQUIRE(versionp != NULL && *versionp == (void *)&dummy);
	REQUIRE(!commit);

	UNUSED(db);
	UNUSED(commit);

	*versionp = NULL;
}

static isc_result_t
createnode(dns_sdb_t *sdb, dns_sdbnode_t **nodep) {
	dns_sdbnode_t *node;

	node = isc_mem_get(sdb->common.mctx, sizeof(dns_sdbnode_t));

	node->sdb = NULL;
	attach((dns_db_t *)sdb, (dns_db_t **)&node->sdb);
	ISC_LIST_INIT(node->lists);
	ISC_LIST_INIT(node->buffers);
	ISC_LINK_INIT(node, link);
	node->name = NULL;
	dns_rdatacallbacks_init(&node->callbacks);

	isc_refcount_init(&node->references, 1);

	node->magic = SDBLOOKUP_MAGIC;

	*nodep = node;
	return (ISC_R_SUCCESS);
}

static void
destroynode(dns_sdbnode_t *node) {
	dns_rdatalist_t *list;
	dns_rdata_t *rdata;
	isc_buffer_t *b;
	dns_sdb_t *sdb;
	isc_mem_t *mctx;

	sdb = node->sdb;
	mctx = sdb->common.mctx;

	while (!ISC_LIST_EMPTY(node->lists)) {
		list = ISC_LIST_HEAD(node->lists);
		while (!ISC_LIST_EMPTY(list->rdata)) {
			rdata = ISC_LIST_HEAD(list->rdata);
			ISC_LIST_UNLINK(list->rdata, rdata, link);
			isc_mem_put(mctx, rdata, sizeof(dns_rdata_t));
		}
		ISC_LIST_UNLINK(node->lists, list, link);
		isc_mem_put(mctx, list, sizeof(dns_rdatalist_t));
	}

	while (!ISC_LIST_EMPTY(node->buffers)) {
		b = ISC_LIST_HEAD(node->buffers);
		ISC_LIST_UNLINK(node->buffers, b, link);
		isc_buffer_free(&b);
	}

	if (node->name != NULL) {
		dns_name_free(node->name, mctx);
		isc_mem_put(mctx, node->name, sizeof(dns_name_t));
	}

	node->magic = 0;
	isc_mem_put(mctx, node, sizeof(dns_sdbnode_t));
	detach((dns_db_t **)(void *)&sdb);
}

static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_sdbnode_t *node = NULL;
	isc_result_t result;
	isc_buffer_t b;
	char namestr[DNS_NAME_MAXTEXT + 1];
	dns_sdbimplementation_t *imp;
	dns_name_t relname;
	dns_name_t *name;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	imp = sdb->implementation;
	name = &sdb->common.origin;

	if (imp->methods->lookup2 != NULL) {
		if ((imp->flags & DNS_SDBFLAG_RELATIVEOWNER) != 0) {
			dns_name_init(&relname, NULL);
			name = &relname;
		}
	} else {
		isc_buffer_init(&b, namestr, sizeof(namestr));
		if ((imp->flags & DNS_SDBFLAG_RELATIVEOWNER) != 0) {
			dns_name_init(&relname, NULL);
			result = dns_name_totext(&relname, true, &b);
			if (result != ISC_R_SUCCESS) {
				return (result);
			}
		} else {
			result = dns_name_totext(name, true, &b);
			if (result != ISC_R_SUCCESS) {
				return (result);
			}
		}
		isc_buffer_putuint8(&b, 0);
	}

	result = createnode(sdb, &node);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	MAYBE_LOCK(sdb);
	if (imp->methods->lookup2 != NULL) {
		result = imp->methods->lookup2(&sdb->common.origin, name,
					       sdb->dbdata, node, NULL, NULL);
	} else {
		result = imp->methods->lookup(sdb->zone, namestr, sdb->dbdata,
					      node, NULL, NULL);
	}
	MAYBE_UNLOCK(sdb);
	if (result != ISC_R_SUCCESS &&
	    !(result == ISC_R_NOTFOUND && imp->methods->authority != NULL))
	{
		destroynode(node);
		return (result);
	}

	if (imp->methods->authority != NULL) {
		MAYBE_LOCK(sdb);
		result = imp->methods->authority(sdb->zone, sdb->dbdata, node);
		MAYBE_UNLOCK(sdb);
		if (result != ISC_R_SUCCESS) {
			destroynode(node);
			return (result);
		}
	}

	*nodep = node;
	return (ISC_R_SUCCESS);
}

static isc_result_t
findnodeext(dns_db_t *db, const dns_name_t *name, bool create,
	    dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo,
	    dns_dbnode_t **nodep) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_sdbnode_t *node = NULL;
	isc_result_t result;
	isc_buffer_t b;
	char namestr[DNS_NAME_MAXTEXT + 1];
	bool isorigin;
	dns_sdbimplementation_t *imp;
	dns_name_t relname;
	unsigned int labels;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	UNUSED(name);
	UNUSED(create);

	imp = sdb->implementation;

	isorigin = dns_name_equal(name, &sdb->common.origin);

	if (imp->methods->lookup2 != NULL) {
		if ((imp->flags & DNS_SDBFLAG_RELATIVEOWNER) != 0) {
			labels = dns_name_countlabels(name) -
				 dns_name_countlabels(&db->origin);
			dns_name_init(&relname, NULL);
			dns_name_getlabelsequence(name, 0, labels, &relname);
			name = &relname;
		}
	} else {
		isc_buffer_init(&b, namestr, sizeof(namestr));
		if ((imp->flags & DNS_SDBFLAG_RELATIVEOWNER) != 0) {
			labels = dns_name_countlabels(name) -
				 dns_name_countlabels(&db->origin);
			dns_name_init(&relname, NULL);
			dns_name_getlabelsequence(name, 0, labels, &relname);
			result = dns_name_totext(&relname, true, &b);
			if (result != ISC_R_SUCCESS) {
				return (result);
			}
		} else {
			result = dns_name_totext(name, true, &b);
			if (result != ISC_R_SUCCESS) {
				return (result);
			}
		}
		isc_buffer_putuint8(&b, 0);
	}

	result = createnode(sdb, &node);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	MAYBE_LOCK(sdb);
	if (imp->methods->lookup2 != NULL) {
		result = imp->methods->lookup2(&sdb->common.origin, name,
					       sdb->dbdata, node, methods,
					       clientinfo);
	} else {
		result = imp->methods->lookup(sdb->zone, namestr, sdb->dbdata,
					      node, methods, clientinfo);
	}
	MAYBE_UNLOCK(sdb);
	if (result != ISC_R_SUCCESS && !(result == ISC_R_NOTFOUND && isorigin &&
					 imp->methods->authority != NULL))
	{
		destroynode(node);
		return (result);
	}

	if (isorigin && imp->methods->authority != NULL) {
		MAYBE_LOCK(sdb);
		result = imp->methods->authority(sdb->zone, sdb->dbdata, node);
		MAYBE_UNLOCK(sdb);
		if (result != ISC_R_SUCCESS) {
			destroynode(node);
			return (result);
		}
	}

	*nodep = node;
	return (ISC_R_SUCCESS);
}

static isc_result_t
findext(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	dns_dbnode_t **nodep, dns_name_t *foundname,
	dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo,
	dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_dbnode_t *node = NULL;
	dns_fixedname_t fname;
	dns_rdataset_t xrdataset;
	dns_name_t *xname;
	unsigned int nlabels, olabels;
	isc_result_t result;
	unsigned int i;
	unsigned int flags;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(nodep == NULL || *nodep == NULL);
	REQUIRE(version == NULL || version == (void *)&dummy);

	UNUSED(options);

	if (!dns_name_issubdomain(name, &db->origin)) {
		return (DNS_R_NXDOMAIN);
	}

	olabels = dns_name_countlabels(&db->origin);
	nlabels = dns_name_countlabels(name);

	xname = dns_fixedname_initname(&fname);

	if (rdataset == NULL) {
		dns_rdataset_init(&xrdataset);
		rdataset = &xrdataset;
	}

	result = DNS_R_NXDOMAIN;
	flags = sdb->implementation->flags;
	i = (flags & DNS_SDBFLAG_DNS64) != 0 ? nlabels : olabels;
	for (; i <= nlabels; i++) {
		/*
		 * Look up the next label.
		 */
		dns_name_getlabelsequence(name, nlabels - i, i, xname);
		result = findnodeext(db, xname, false, methods, clientinfo,
				     &node);
		if (result == ISC_R_NOTFOUND) {
			/*
			 * No data at zone apex?
			 */
			if (i == olabels) {
				return (DNS_R_BADDB);
			}
			result = DNS_R_NXDOMAIN;
			continue;
		}
		if (result != ISC_R_SUCCESS) {
			return (result);
		}

		/*
		 * DNS64 zone's don't have DNAME or NS records.
		 */
		if ((flags & DNS_SDBFLAG_DNS64) != 0) {
			goto skip;
		}

		/*
		 * DNS64 zone's don't have DNAME or NS records.
		 */
		if ((flags & DNS_SDBFLAG_DNS64) != 0) {
			goto skip;
		}

		/*
		 * Look for a DNAME at the current label, unless this is
		 * the qname.
		 */
		if (i < nlabels) {
			result = findrdataset(db, node, version,
					      dns_rdatatype_dname, 0, now,
					      rdataset, sigrdataset);
			if (result == ISC_R_SUCCESS) {
				result = DNS_R_DNAME;
				break;
			}
		}

		/*
		 * Look for an NS at the current label, unless this is the
		 * origin or glue is ok.
		 */
		if (i != olabels && (options & DNS_DBFIND_GLUEOK) == 0) {
			result = findrdataset(db, node, version,
					      dns_rdatatype_ns, 0, now,
					      rdataset, sigrdataset);
			if (result == ISC_R_SUCCESS) {
				if (i == nlabels && type == dns_rdatatype_any) {
					result = DNS_R_ZONECUT;
					dns_rdataset_disassociate(rdataset);
					if (sigrdataset != NULL &&
					    dns_rdataset_isassociated(
						    sigrdataset)) {
						dns_rdataset_disassociate(
							sigrdataset);
					}
				} else {
					result = DNS_R_DELEGATION;
				}
				break;
			}
		}

		/*
		 * If the current name is not the qname, add another label
		 * and try again.
		 */
		if (i < nlabels) {
			destroynode(node);
			node = NULL;
			continue;
		}

	skip:
		/*
		 * If we're looking for ANY, we're done.
		 */
		if (type == dns_rdatatype_any) {
			result = ISC_R_SUCCESS;
			break;
		}

		/*
		 * Look for the qtype.
		 */
		result = findrdataset(db, node, version, type, 0, now, rdataset,
				      sigrdataset);
		if (result == ISC_R_SUCCESS) {
			break;
		}

		/*
		 * Look for a CNAME
		 */
		if (type != dns_rdatatype_cname) {
			result = findrdataset(db, node, version,
					      dns_rdatatype_cname, 0, now,
					      rdataset, sigrdataset);
			if (result == ISC_R_SUCCESS) {
				result = DNS_R_CNAME;
				break;
			}
		}

		result = DNS_R_NXRRSET;
		break;
	}

	if (rdataset == &xrdataset && dns_rdataset_isassociated(rdataset)) {
		dns_rdataset_disassociate(rdataset);
	}

	if (foundname != NULL) {
		dns_name_copy(xname, foundname);
	}

	if (nodep != NULL) {
		*nodep = node;
	} else if (node != NULL) {
		detachnode(db, &node);
	}

	return (result);
}

static isc_result_t
findzonecut(dns_db_t *db, const dns_name_t *name, unsigned int options,
	    isc_stdtime_t now, dns_dbnode_t **nodep, dns_name_t *foundname,
	    dns_name_t *dcname, dns_rdataset_t *rdataset,
	    dns_rdataset_t *sigrdataset) {
	UNUSED(db);
	UNUSED(name);
	UNUSED(options);
	UNUSED(now);
	UNUSED(nodep);
	UNUSED(foundname);
	UNUSED(dcname);
	UNUSED(rdataset);
	UNUSED(sigrdataset);

	return (ISC_R_NOTIMPLEMENTED);
}

static void
attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_sdbnode_t *node = (dns_sdbnode_t *)source;

	REQUIRE(VALID_SDB(sdb));

	UNUSED(sdb);

	isc_refcount_increment(&node->references);

	*targetp = source;
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_sdbnode_t *node;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(targetp != NULL && *targetp != NULL);

	UNUSED(sdb);

	node = (dns_sdbnode_t *)(*targetp);

	*targetp = NULL;

	if (isc_refcount_decrement(&node->references) == 1) {
		destroynode(node);
	}
}

static isc_result_t
expirenode(dns_db_t *db, dns_dbnode_t *node, isc_stdtime_t now) {
	UNUSED(db);
	UNUSED(node);
	UNUSED(now);
	UNREACHABLE();
}

static void
printnode(dns_db_t *db, dns_dbnode_t *node, FILE *out) {
	UNUSED(db);
	UNUSED(node);
	UNUSED(out);
	return;
}

static isc_result_t
createiterator(dns_db_t *db, unsigned int options,
	       dns_dbiterator_t **iteratorp) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	REQUIRE(VALID_SDB(sdb));

	sdb_dbiterator_t *sdbiter;
	isc_result_t result;
	dns_sdbimplementation_t *imp = sdb->implementation;

	if (imp->methods->allnodes == NULL) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	if ((options & DNS_DB_NSEC3ONLY) != 0 ||
	    (options & DNS_DB_NONSEC3) != 0) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	sdbiter = isc_mem_get(sdb->common.mctx, sizeof(sdb_dbiterator_t));

	sdbiter->common.methods = &dbiterator_methods;
	sdbiter->common.db = NULL;
	dns_db_attach(db, &sdbiter->common.db);
	sdbiter->common.relative_names = ((options & DNS_DB_RELATIVENAMES) !=
					  0);
	sdbiter->common.magic = DNS_DBITERATOR_MAGIC;
	ISC_LIST_INIT(sdbiter->nodelist);
	sdbiter->current = NULL;
	sdbiter->origin = NULL;

	MAYBE_LOCK(sdb);
	result = imp->methods->allnodes(sdb->zone, sdb->dbdata, sdbiter);
	MAYBE_UNLOCK(sdb);
	if (result != ISC_R_SUCCESS) {
		dbiterator_destroy((dns_dbiterator_t **)(void *)&sdbiter);
		return (result);
	}

	if (sdbiter->origin != NULL) {
		ISC_LIST_UNLINK(sdbiter->nodelist, sdbiter->origin, link);
		ISC_LIST_PREPEND(sdbiter->nodelist, sdbiter->origin, link);
	}

	*iteratorp = (dns_dbiterator_t *)sdbiter;

	return (ISC_R_SUCCESS);
}

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdatatype_t covers, isc_stdtime_t now,
	     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	REQUIRE(VALID_SDBNODE(node));

	dns_rdatalist_t *list;
	dns_sdbnode_t *sdbnode = (dns_sdbnode_t *)node;

	UNUSED(db);
	UNUSED(version);
	UNUSED(covers);
	UNUSED(now);
	UNUSED(sigrdataset);

	if (type == dns_rdatatype_rrsig) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	list = ISC_LIST_HEAD(sdbnode->lists);
	while (list != NULL) {
		if (list->type == type) {
			break;
		}
		list = ISC_LIST_NEXT(list, link);
	}
	if (list == NULL) {
		return (ISC_R_NOTFOUND);
	}

	list_tordataset(list, db, node, rdataset);

	return (ISC_R_SUCCESS);
}

static isc_result_t
allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     isc_stdtime_t now, dns_rdatasetiter_t **iteratorp) {
	sdb_rdatasetiter_t *iterator;

	REQUIRE(version == NULL || version == &dummy);

	UNUSED(version);
	UNUSED(now);

	iterator = isc_mem_get(db->mctx, sizeof(sdb_rdatasetiter_t));

	iterator->common.magic = DNS_RDATASETITER_MAGIC;
	iterator->common.methods = &rdatasetiter_methods;
	iterator->common.db = db;
	iterator->common.node = NULL;
	attachnode(db, node, &iterator->common.node);
	iterator->common.version = version;
	iterator->common.now = now;

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return (ISC_R_SUCCESS);
}

static isc_result_t
addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	    isc_stdtime_t now, dns_rdataset_t *rdataset, unsigned int options,
	    dns_rdataset_t *addedrdataset) {
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(now);
	UNUSED(rdataset);
	UNUSED(options);
	UNUSED(addedrdataset);

	return (ISC_R_NOTIMPLEMENTED);
}

static isc_result_t
subtractrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		 dns_rdataset_t *rdataset, unsigned int options,
		 dns_rdataset_t *newrdataset) {
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(rdataset);
	UNUSED(options);
	UNUSED(newrdataset);

	return (ISC_R_NOTIMPLEMENTED);
}

static isc_result_t
deleterdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	       dns_rdatatype_t type, dns_rdatatype_t covers) {
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(type);
	UNUSED(covers);

	return (ISC_R_NOTIMPLEMENTED);
}

static bool
issecure(dns_db_t *db) {
	UNUSED(db);

	return (false);
}

static unsigned int
nodecount(dns_db_t *db, dns_dbtree_t tree) {
	UNUSED(db);
	UNUSED(tree);

	return (0);
}

static bool
ispersistent(dns_db_t *db) {
	UNUSED(db);
	return (true);
}

static void
overmem(dns_db_t *db, bool over) {
	UNUSED(db);
	UNUSED(over);
}

static void
settask(dns_db_t *db, isc_task_t *task) {
	UNUSED(db);
	UNUSED(task);
}

static dns_dbmethods_t sdb_methods = {
	attach,		detach,
	beginload,	endload,
	dump,		currentversion,
	newversion,	attachversion,
	closeversion,	NULL, /* findnode */
	NULL,		      /* find */
	findzonecut,	attachnode,
	detachnode,	expirenode,
	printnode,	createiterator,
	findrdataset,	allrdatasets,
	addrdataset,	subtractrdataset,
	deleterdataset, issecure,
	nodecount,	ispersistent,
	overmem,	settask,
	getoriginnode, /* getoriginnode */
	NULL,	       /* transfernode */
	NULL,	       /* getnsec3parameters */
	NULL,	       /* findnsec3node */
	NULL,	       /* setsigningtime */
	NULL,	       /* getsigningtime */
	NULL,	       /* resigned */
	NULL,	       /* isdnssec */
	NULL,	       /* getrrsetstats */
	NULL,	       /* rpz_attach */
	NULL,	       /* rpz_ready */
	findnodeext,	findext,
	NULL, /* setcachestats */
	NULL, /* hashsize */
	NULL, /* nodefullname */
	NULL, /* getsize */
	NULL, /* setservestalettl */
	NULL, /* getservestalettl */
	NULL, /* setservestalerefresh */
	NULL, /* getservestalerefresh */
	NULL, /* setgluecachestats */
};

static isc_result_t
dns_sdb_create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
	       dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
	       void *driverarg, dns_db_t **dbp) {
	dns_sdb_t *sdb;
	isc_result_t result;
	char zonestr[DNS_NAME_MAXTEXT + 1];
	isc_buffer_t b;
	dns_sdbimplementation_t *imp;

	REQUIRE(driverarg != NULL);

	imp = driverarg;

	if (type != dns_dbtype_zone) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	sdb = isc_mem_get(mctx, sizeof(dns_sdb_t));
	memset(sdb, 0, sizeof(dns_sdb_t));

	dns_name_init(&sdb->common.origin, NULL);
	sdb->common.attributes = 0;
	sdb->common.methods = &sdb_methods;
	sdb->common.rdclass = rdclass;
	sdb->common.mctx = NULL;
	sdb->implementation = imp;

	isc_mem_attach(mctx, &sdb->common.mctx);

	result = dns_name_dupwithoffsets(origin, mctx, &sdb->common.origin);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_lock;
	}

	isc_buffer_init(&b, zonestr, sizeof(zonestr));
	result = dns_name_totext(origin, true, &b);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_origin;
	}
	isc_buffer_putuint8(&b, 0);

	sdb->zone = isc_mem_strdup(mctx, zonestr);

	sdb->dbdata = NULL;
	if (imp->methods->create != NULL) {
		MAYBE_LOCK(sdb);
		result = imp->methods->create(sdb->zone, argc, argv,
					      imp->driverdata, &sdb->dbdata);
		MAYBE_UNLOCK(sdb);
		if (result != ISC_R_SUCCESS) {
			goto cleanup_zonestr;
		}
	}

	isc_refcount_init(&sdb->references, 1);

	sdb->common.magic = DNS_DB_MAGIC;
	sdb->common.impmagic = SDB_MAGIC;

	*dbp = (dns_db_t *)sdb;

	return (ISC_R_SUCCESS);

cleanup_zonestr:
	isc_mem_free(mctx, sdb->zone);
cleanup_origin:
	dns_name_free(&sdb->common.origin, mctx);
cleanup_lock:
	isc_mem_putanddetach(&mctx, sdb, sizeof(dns_sdb_t));

	return (result);
}

/*
 * Rdataset Methods
 */

static void
disassociate(dns_rdataset_t *rdataset) {
	dns_dbnode_t *node = rdataset->private5;
	dns_sdbnode_t *sdbnode = (dns_sdbnode_t *)node;
	dns_db_t *db = (dns_db_t *)sdbnode->sdb;

	detachnode(db, &node);
	isc__rdatalist_disassociate(rdataset);
}

static void
rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target) {
	dns_dbnode_t *node = source->private5;
	dns_sdbnode_t *sdbnode = (dns_sdbnode_t *)node;
	dns_db_t *db = (dns_db_t *)sdbnode->sdb;
	dns_dbnode_t *tempdb = NULL;

	isc__rdatalist_clone(source, target);
	attachnode(db, node, &tempdb);
	source->private5 = tempdb;
}

static dns_rdatasetmethods_t sdb_rdataset_methods = {
	disassociate,
	isc__rdatalist_first,
	isc__rdatalist_next,
	isc__rdatalist_current,
	rdataset_clone,
	isc__rdatalist_count,
	isc__rdatalist_addnoqname,
	isc__rdatalist_getnoqname,
	NULL, /* addclosest */
	NULL, /* getclosest */
	NULL, /* settrust */
	NULL, /* expire */
	NULL, /* clearprefetch */
	NULL, /* setownercase */
	NULL, /* getownercase */
	NULL  /* addglue */
};

static void
list_tordataset(dns_rdatalist_t *rdatalist, dns_db_t *db, dns_dbnode_t *node,
		dns_rdataset_t *rdataset) {
	/*
	 * The sdb rdataset is an rdatalist with some additions.
	 *	- private1 & private2 are used by the rdatalist.
	 *	- private3 & private 4 are unused.
	 *	- private5 is the node.
	 */

	dns_rdatalist_tordataset(rdatalist, rdataset);

	rdataset->methods = &sdb_rdataset_methods;
	dns_db_attachnode(db, node, &rdataset->private5);
}

/*
 * Database Iterator Methods
 */
static void
dbiterator_destroy(dns_dbiterator_t **iteratorp) {
	sdb_dbiterator_t *sdbiter = (sdb_dbiterator_t *)(*iteratorp);
	dns_sdb_t *sdb = (dns_sdb_t *)sdbiter->common.db;

	while (!ISC_LIST_EMPTY(sdbiter->nodelist)) {
		dns_sdbnode_t *node;
		node = ISC_LIST_HEAD(sdbiter->nodelist);
		ISC_LIST_UNLINK(sdbiter->nodelist, node, link);
		destroynode(node);
	}

	dns_db_detach(&sdbiter->common.db);
	isc_mem_put(sdb->common.mctx, sdbiter, sizeof(sdb_dbiterator_t));

	*iteratorp = NULL;
}

static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator) {
	sdb_dbiterator_t *sdbiter = (sdb_dbiterator_t *)iterator;

	sdbiter->current = ISC_LIST_HEAD(sdbiter->nodelist);
	if (sdbiter->current == NULL) {
		return (ISC_R_NOMORE);
	} else {
		return (ISC_R_SUCCESS);
	}
}

static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator) {
	sdb_dbiterator_t *sdbiter = (sdb_dbiterator_t *)iterator;

	sdbiter->current = ISC_LIST_TAIL(sdbiter->nodelist);
	if (sdbiter->current == NULL) {
		return (ISC_R_NOMORE);
	} else {
		return (ISC_R_SUCCESS);
	}
}

static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator, const dns_name_t *name) {
	sdb_dbiterator_t *sdbiter = (sdb_dbiterator_t *)iterator;

	sdbiter->current = ISC_LIST_HEAD(sdbiter->nodelist);
	while (sdbiter->current != NULL) {
		if (dns_name_equal(sdbiter->current->name, name)) {
			return (ISC_R_SUCCESS);
		}
		sdbiter->current = ISC_LIST_NEXT(sdbiter->current, link);
	}
	return (ISC_R_NOTFOUND);
}

static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator) {
	sdb_dbiterator_t *sdbiter = (sdb_dbiterator_t *)iterator;

	sdbiter->current = ISC_LIST_PREV(sdbiter->current, link);
	if (sdbiter->current == NULL) {
		return (ISC_R_NOMORE);
	} else {
		return (ISC_R_SUCCESS);
	}
}

static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator) {
	sdb_dbiterator_t *sdbiter = (sdb_dbiterator_t *)iterator;

	sdbiter->current = ISC_LIST_NEXT(sdbiter->current, link);
	if (sdbiter->current == NULL) {
		return (ISC_R_NOMORE);
	} else {
		return (ISC_R_SUCCESS);
	}
}

static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name) {
	sdb_dbiterator_t *sdbiter = (sdb_dbiterator_t *)iterator;

	attachnode(iterator->db, sdbiter->current, nodep);
	if (name != NULL) {
		dns_name_copy(sdbiter->current->name, name);
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_SUCCESS);
}

static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator) {
	UNUSED(iterator);
	return (ISC_R_SUCCESS);
}

static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name) {
	UNUSED(iterator);
	dns_name_copy(dns_rootname, name);
	return (ISC_R_SUCCESS);
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)(*iteratorp);
	detachnode(sdbiterator->common.db, &sdbiterator->common.node);
	isc_mem_put(sdbiterator->common.db->mctx, sdbiterator,
		    sizeof(sdb_rdatasetiter_t));
	*iteratorp = NULL;
}

static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)iterator;
	dns_sdbnode_t *sdbnode = (dns_sdbnode_t *)iterator->node;

	if (ISC_LIST_EMPTY(sdbnode->lists)) {
		return (ISC_R_NOMORE);
	}
	sdbiterator->current = ISC_LIST_HEAD(sdbnode->lists);
	return (ISC_R_SUCCESS);
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)iterator;

	sdbiterator->current = ISC_LIST_NEXT(sdbiterator->current, link);
	if (sdbiterator->current == NULL) {
		return (ISC_R_NOMORE);
	} else {
		return (ISC_R_SUCCESS);
	}
}

static void
rdatasetiter_current(dns_rdatasetiter_t *iterator, dns_rdataset_t *rdataset) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)iterator;

	list_tordataset(sdbiterator->current, iterator->db, iterator->node,
			rdataset);
}
