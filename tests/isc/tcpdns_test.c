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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/async.h>
#include <isc/loop.h>
#include <isc/nonce.h>
#include <isc/os.h>
#include <isc/quota.h>
#include <isc/refcount.h>
#include <isc/sockaddr.h>
#include <isc/util.h>
#include <isc/uv.h>

#include "uv_wrap.h"
#define KEEP_BEFORE

#include "netmgr_common.h"

#include <tests/isc.h>

/* TCPDNS */

static void
stop_listening(void *arg __attribute__((__unused__))) {
	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);
}

static void
start_listening(uint32_t nworkers, isc_nm_accept_cb_t accept_cb,
		isc_nm_recv_cb_t recv_cb) {
	isc_result_t result = isc_nm_listentcpdns(
		listen_nm, nworkers, &tcp_listen_addr, recv_cb, NULL, accept_cb,
		NULL, 128, NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_loop_teardown(mainloop, stop_listening, listen_sock);
}

static void
tcpdns_connect(isc_nm_t *nm) {
	isc_nm_tcpdnsconnect(nm, &tcp_connect_addr, &tcp_listen_addr,
			     connect_connect_cb, NULL, T_CONNECT);
}

ISC_LOOP_TEST_IMPL(tcpdns_noop) {
	start_listening(ISC_NM_LISTEN_ONE, noop_accept_cb, noop_recv_cb);

	connect_readcb = NULL;
	isc_refcount_increment0(&active_cconnects);
	isc_nm_tcpdnsconnect(connect_nm, &tcp_connect_addr, &tcp_listen_addr,
			     connect_success_cb, NULL, T_CONNECT);
}

ISC_LOOP_TEST_IMPL(tcpdns_noresponse) {
	start_listening(ISC_NM_LISTEN_ALL, noop_accept_cb, noop_recv_cb);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_tcpdnsconnect(connect_nm, &tcp_connect_addr, &tcp_listen_addr,
			     connect_connect_cb, NULL, T_CONNECT);
}

ISC_LOOP_TEST_IMPL(tcpdns_timeout_recovery) {
	/*
	 * Accept connections but don't send responses, forcing client
	 * reads to time out.
	 */
	noanswer = true;
	start_listening(ISC_NM_LISTEN_ONE, listen_accept_cb, listen_read_cb);

	/*
	 * Shorten all the TCP client timeouts to 0.05 seconds, connect,
	 * then sleep for at least a second for each 'tick'.
	 * timeout_retry_cb() will give up after five timeouts.
	 */
	connect_readcb = timeout_retry_cb;
	isc_nm_settimeouts(connect_nm, T_SOFT, T_SOFT, T_SOFT, T_SOFT);

	isc_async_run(isc_loop_current(loopmgr), stream_recv_send_connect,
		      tcpdns_connect);
}

ISC_LOOP_TEST_IMPL(tcpdns_recv_one) {
	start_listening(ISC_NM_LISTEN_ONE, listen_accept_cb, listen_read_cb);

	isc_async_run(isc_loop_current(loopmgr), stream_recv_send_connect,
		      tcpdns_connect);
}

ISC_LOOP_TEST_IMPL(tcpdns_recv_two) {
	start_listening(ISC_NM_LISTEN_ONE, listen_accept_cb, listen_read_cb);

	isc_async_run(isc_loop_current(loopmgr), stream_recv_send_connect,
		      tcpdns_connect);

	isc_async_run(isc_loop_current(loopmgr), stream_recv_send_connect,
		      tcpdns_connect);
}

ISC_LOOP_TEST_IMPL(tcpdns_recv_send) {
	start_listening(ISC_NM_LISTEN_ALL, listen_accept_cb, listen_read_cb);

	for (size_t i = 0; i < workers; i++) {
		isc_async_run(isc_loop_get(loopmgr, i),
			      stream_recv_send_connect, tcpdns_connect);
	}
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY_CUSTOM(tcpdns_noop, stream_noop_setup, stream_noop_teardown)
ISC_TEST_ENTRY_CUSTOM(tcpdns_noresponse, stream_noresponse_setup,
		      stream_noresponse_teardown)
ISC_TEST_ENTRY_CUSTOM(tcpdns_timeout_recovery, stream_timeout_recovery_setup,
		      stream_timeout_recovery_teardown)
ISC_TEST_ENTRY_CUSTOM(tcpdns_recv_one, stream_recv_one_setup,
		      stream_recv_one_teardown)
ISC_TEST_ENTRY_CUSTOM(tcpdns_recv_two, stream_recv_two_setup,
		      stream_recv_two_teardown)
ISC_TEST_ENTRY_CUSTOM(tcpdns_recv_send, stream_recv_send_setup,
		      stream_recv_send_teardown)

ISC_TEST_LIST_END
ISC_TEST_MAIN
