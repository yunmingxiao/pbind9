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

#pragma once

#include <isc/bind9.h>
#include <isc/result.h>

/*! \file isc/types.h
 * \brief
 * OS-specific types, from the OS-specific include directories.
 */
#include <inttypes.h>
#include <stdbool.h>

#include <isc/offset.h>

/*
 * XXXDCL This is just for ISC_LIST and ISC_LINK, but gets all of the other
 * list macros too.
 */
#include <isc/list.h>

/* Core Types.  Alphabetized by defined type. */

typedef struct isc_astack isc_astack_t;		 /*%< Array-based fast stack */
typedef struct isc_buffer isc_buffer_t;		 /*%< Buffer */
typedef ISC_LIST(isc_buffer_t) isc_bufferlist_t; /*%< Buffer List */
typedef struct isc_constregion	   isc_constregion_t;	  /*%< Const region */
typedef struct isc_consttextregion isc_consttextregion_t; /*%< Const Text Region
							   */
typedef struct isc_counter isc_counter_t;		  /*%< Counter */
typedef int16_t		   isc_dscp_t;	       /*%< Diffserv code point */
typedef struct isc_event   isc_event_t;	       /*%< Event */
typedef ISC_LIST(isc_event_t) isc_eventlist_t; /*%< Event List */
typedef unsigned int	 isc_eventtype_t;      /*%< Event Type */
typedef uint32_t	 isc_fsaccess_t;       /*%< FS Access */
typedef struct isc_hash	 isc_hash_t;	       /*%< Hash */
typedef struct isc_httpd isc_httpd_t;	       /*%< HTTP client */
typedef void(isc_httpdfree_t)(isc_buffer_t *, void *); /*%< HTTP free function
							*/
typedef struct isc_httpdmgr isc_httpdmgr_t;	       /*%< HTTP manager */
typedef struct isc_httpdurl isc_httpdurl_t;	       /*%< HTTP URL */
typedef void(isc_httpdondestroy_t)(void *); /*%< Callback on destroying httpd */
typedef struct isc_interface	 isc_interface_t;     /*%< Interface */
typedef struct isc_interfaceiter isc_interfaceiter_t; /*%< Interface Iterator */
typedef struct isc_job		 isc_job_t;
typedef struct isc_lex		 isc_lex_t;	    /*%< Lex */
typedef struct isc_log		 isc_log_t;	    /*%< Log */
typedef struct isc_logcategory	 isc_logcategory_t; /*%< Log Category */
typedef struct isc_logconfig	 isc_logconfig_t;   /*%< Log Configuration */
typedef struct isc_logmodule	 isc_logmodule_t;   /*%< Log Module */
typedef struct isc_loop		 isc_loop_t;	    /*%< Event loop */
typedef struct isc_loopmgr	 isc_loopmgr_t;	    /*%< Event loop manager */
typedef struct isc_mem		 isc_mem_t;	    /*%< Memory */
typedef struct isc_mempool	 isc_mempool_t;	    /*%< Memory Pool */
typedef struct isc_netaddr	 isc_netaddr_t;	    /*%< Net Address */
typedef struct isc_netprefix	 isc_netprefix_t;   /*%< Net Prefix */
typedef struct isc_nm		 isc_nm_t;	    /*%< Network manager */
typedef struct isc_nmsocket	 isc_nmsocket_t; /*%< Network manager socket */
typedef struct isc_nmhandle	 isc_nmhandle_t; /*%< Network manager handle */
typedef struct isc_portset	 isc_portset_t;	 /*%< Port Set */
typedef struct isc_quota	 isc_quota_t;	 /*%< Quota */
typedef struct isc_ratelimiter	 isc_ratelimiter_t;   /*%< Rate Limiter */
typedef struct isc_region	 isc_region_t;	      /*%< Region */
typedef uint64_t		 isc_resourcevalue_t; /*%< Resource Value */
typedef struct isc_signal	 isc_signal_t;	      /*%< Signal handler */
typedef struct isc_sockaddr	 isc_sockaddr_t;      /*%< Socket Address */
typedef ISC_LIST(isc_sockaddr_t) isc_sockaddrlist_t;  /*%< Socket Address List
						       * */
typedef struct isc_stats      isc_stats_t;	      /*%< Statistics */
typedef int_fast64_t	      isc_statscounter_t;
typedef struct isc_symtab     isc_symtab_t;	/*%< Symbol Table */
typedef struct isc_task	      isc_task_t;	/*%< Task */
typedef struct isc_taskmgr    isc_taskmgr_t;	/*%< Task Manager */
typedef struct isc_textregion isc_textregion_t; /*%< Text Region */
typedef struct isc_time	      isc_time_t;	/*%< Time */
typedef struct isc_timer      isc_timer_t;	/*%< Timer */
typedef struct isc_work	      isc_work_t;	/*%< Work offloaded to an
						 *   external thread */

#if HAVE_LIBNGHTTP2
typedef struct isc_nm_http_endpoints isc_nm_http_endpoints_t;
/*%< HTTP endpoints set */
#endif /* HAVE_LIBNGHTTP2 */

typedef void (*isc_taskaction_t)(isc_task_t *, isc_event_t *);

/* The following cannot be listed alphabetically due to forward reference */
typedef isc_result_t(isc_httpdaction_t)(
	const char *url, isc_httpdurl_t *urlinfo, const char *querystring,
	const char *headers, void *arg, unsigned int *retcode,
	const char **retmsg, const char **mimetype, isc_buffer_t *body,
	isc_httpdfree_t **freecb, void **freecb_args);
typedef bool(isc_httpdclientok_t)(const isc_sockaddr_t *, void *);

/*% Resource */
typedef enum {
	isc_resource_coresize = 1,
	isc_resource_cputime,
	isc_resource_datasize,
	isc_resource_filesize,
	isc_resource_lockedmemory,
	isc_resource_openfiles,
	isc_resource_processes,
	isc_resource_residentsize,
	isc_resource_stacksize
} isc_resource_t;

/*% Statistics formats (text file or XML) */
typedef enum {
	isc_statsformat_file,
	isc_statsformat_xml,
	isc_statsformat_json
} isc_statsformat_t;

typedef enum isc_nmsocket_type {
	isc_nm_nonesocket = 0,
	isc_nm_udpsocket = 1 << 1,
	isc_nm_tcpsocket = 1 << 2,
	isc_nm_tcpdnssocket = 1 << 3,
	isc_nm_tlssocket = 1 << 4,
	isc_nm_tlsdnssocket = 1 << 5,
	isc_nm_httpsocket = 1 << 6,
	isc_nm_maxsocket,

	isc_nm_udplistener, /* Aggregate of nm_udpsocks */
	isc_nm_tcplistener,
	isc_nm_tlslistener,
	isc_nm_tcpdnslistener,
	isc_nm_tlsdnslistener,
	isc_nm_httplistener
} isc_nmsocket_type;

typedef isc_nmsocket_type isc_nmsocket_type_t;
