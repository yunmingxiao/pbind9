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

#include <errno.h>
#include <libgen.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/once.h>
#include <isc/quota.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/stdtime.h>
#include <isc/thread.h>
#include <isc/util.h>
#include <isc/uv.h>

#include "../openssl_shim.h"
#include "netmgr-int.h"

#define TLS_BUF_SIZE (UINT16_MAX)

static isc_result_t
tls_error_to_result(const int tls_err, const int tls_state, isc_tls_t *tls) {
	switch (tls_err) {
	case SSL_ERROR_ZERO_RETURN:
		return (ISC_R_EOF);
	case SSL_ERROR_SSL:
		if (tls != NULL && tls_state < TLS_IO &&
		    SSL_get_verify_result(tls) != X509_V_OK)
		{
			return (ISC_R_TLSBADPEERCERT);
		}
		return (ISC_R_TLSERROR);
	default:
		return (ISC_R_UNEXPECTED);
	}
}

static void
tls_failed_read_cb(isc_nmsocket_t *sock, const isc_result_t result);

static void
tls_do_bio(isc_nmsocket_t *sock, isc_region_t *received_data,
	   isc__nm_uvreq_t *send_data, bool finish);

static void
tls_readcb(isc_nmhandle_t *handle, isc_result_t result, isc_region_t *region,
	   void *cbarg);

static void
tls_close_direct(isc_nmsocket_t *sock);

static void
async_tls_do_bio(isc_nmsocket_t *sock);

static void
tls_init_listener_tlsctx(isc_nmsocket_t *listener, isc_tlsctx_t *ctx);

static void
tls_cleanup_listener_tlsctx(isc_nmsocket_t *listener);

static isc_tlsctx_t *
tls_get_listener_tlsctx(isc_nmsocket_t *listener, const int tid);

static void
tls_keep_client_tls_session(isc_nmsocket_t *sock);

static void
tls_try_shutdown(isc_tls_t *tls, const bool quite);

/*
 * The socket is closing, outerhandle has been detached, listener is
 * inactive, or the netmgr is closing: any operation on it should abort
 * with ISC_R_CANCELED.
 */
static bool
inactive(isc_nmsocket_t *sock) {
	return (!isc__nmsocket_active(sock) || atomic_load(&sock->closing) ||
		sock->outerhandle == NULL ||
		!isc__nmsocket_active(sock->outerhandle->sock) ||
		atomic_load(&sock->outerhandle->sock->closing) ||
		(sock->listener != NULL &&
		 !isc__nmsocket_active(sock->listener)) ||
		isc__nm_closing(sock->worker));
}

static void
tls_call_connect_cb(isc_nmsocket_t *sock, isc_nmhandle_t *handle,
		    const isc_result_t result) {
	if (sock->connect_cb == NULL) {
		return;
	}
	sock->connect_cb(handle, result, sock->connect_cbarg);
	if (result != ISC_R_SUCCESS) {
		isc__nmsocket_clearcb(handle->sock);
	}
}

static void
tls_senddone(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmsocket_tls_send_req_t *send_req =
		(isc_nmsocket_tls_send_req_t *)cbarg;
	isc_nmsocket_t *tlssock = NULL;
	bool finish = send_req->finish;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(VALID_NMSOCK(send_req->tlssock));

	tlssock = send_req->tlssock;
	send_req->tlssock = NULL;

	if (finish) {
		tls_try_shutdown(tlssock->tlsstream.tls, true);
	}

	if (send_req->cb != NULL) {
		INSIST(VALID_NMHANDLE(tlssock->statichandle));
		send_req->cb(send_req->handle, eresult, send_req->cbarg);
		isc_nmhandle_detach(&send_req->handle);
		/* The last handle has been just detached: close the underlying
		 * socket. */
		if (tlssock->statichandle == NULL) {
			finish = true;
		}
	}

	/* We are tying to avoid a memory allocation for small write
	 * requests. See the mirroring code in the tls_send_outgoing()
	 * function. */
	if (send_req->data.length > sizeof(send_req->smallbuf)) {
		isc_mem_put(handle->sock->worker->mctx, send_req->data.base,
			    send_req->data.length);
	} else {
		INSIST(&send_req->smallbuf[0] == send_req->data.base);
	}
	isc_mem_put(handle->sock->worker->mctx, send_req, sizeof(*send_req));
	tlssock->tlsstream.nsending--;

	if (finish && eresult == ISC_R_SUCCESS && tlssock->reading) {
		tls_failed_read_cb(tlssock, ISC_R_EOF);
	} else if (eresult == ISC_R_SUCCESS) {
		tls_do_bio(tlssock, NULL, NULL, false);
	} else if (eresult != ISC_R_SUCCESS &&
		   tlssock->tlsstream.state <= TLS_HANDSHAKE &&
		   !tlssock->tlsstream.server)
	{
		/*
		 * We are still waiting for the handshake to complete, but
		 * it isn't going to happen. Call the connect callback,
		 * passing the error code there.
		 *
		 * (Note: tls_failed_read_cb() calls the connect
		 * rather than the read callback in this case.
		 * XXX: clarify?)
		 */
		tls_failed_read_cb(tlssock, eresult);
	}

	isc__nmsocket_detach(&tlssock);
}

static void
tls_failed_read_cb(isc_nmsocket_t *sock, const isc_result_t result) {
	bool destroy = true;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(result != ISC_R_SUCCESS);

	if (!sock->tlsstream.server &&
	    (sock->tlsstream.state == TLS_INIT ||
	     sock->tlsstream.state == TLS_HANDSHAKE) &&
	    sock->connect_cb != NULL)
	{
		isc_nmhandle_t *handle = NULL;
		INSIST(sock->statichandle == NULL);
		handle = isc__nmhandle_get(sock, &sock->peer, &sock->iface);
		tls_call_connect_cb(sock, handle, result);
		isc__nmsocket_clearcb(sock);
		isc_nmhandle_detach(&handle);
	} else if (sock->recv_cb != NULL && sock->statichandle != NULL) {
		sock->recv_cb(sock->statichandle, result, NULL,
			      sock->recv_cbarg);
		if (result == ISC_R_TIMEDOUT &&
		    (sock->outerhandle == NULL ||
		     isc__nmsocket_timer_running(sock->outerhandle->sock)))
		{
			destroy = false;
		}
	}

	if (destroy) {
		isc__nmsocket_prep_destroy(sock);
	}
}

void
isc__nm_tls_failed_read_cb(isc_nmsocket_t *sock, isc_result_t result) {
	if (!inactive(sock) && sock->tlsstream.state == TLS_IO) {
		tls_do_bio(sock, NULL, NULL, true);
	} else if (sock->reading) {
		sock->reading = false;
		tls_failed_read_cb(sock, result);
	}
}

static void
async_tls_do_bio(isc_nmsocket_t *sock) {
	isc__netievent_tlsdobio_t *ievent =
		isc__nm_get_netievent_tlsdobio(sock->worker, sock);
	isc__nm_enqueue_ievent(sock->worker, (isc__netievent_t *)ievent);
}

static int
tls_send_outgoing(isc_nmsocket_t *sock, bool finish, isc_nmhandle_t *tlshandle,
		  isc_nm_cb_t cb, void *cbarg) {
	isc_nmsocket_tls_send_req_t *send_req = NULL;
	int pending;
	int rv;
	size_t len = 0;

	if (inactive(sock)) {
		if (cb != NULL) {
			INSIST(VALID_NMHANDLE(tlshandle));
			cb(tlshandle, ISC_R_CANCELED, cbarg);
		}
		return (0);
	}

	if (finish) {
		tls_try_shutdown(sock->tlsstream.tls, false);
		tls_keep_client_tls_session(sock);
	}

	pending = BIO_pending(sock->tlsstream.bio_out);
	if (pending <= 0) {
		return (pending);
	}

	/* TODO Should we keep track of these requests in a list? */
	if ((unsigned int)pending > TLS_BUF_SIZE) {
		pending = TLS_BUF_SIZE;
	}

	send_req = isc_mem_get(sock->worker->mctx, sizeof(*send_req));
	*send_req = (isc_nmsocket_tls_send_req_t){ .finish = finish,
						   .data.length = pending };

	/* Let's try to avoid a memory allocation for small write requests */
	if ((size_t)pending > sizeof(send_req->smallbuf)) {
		send_req->data.base = isc_mem_get(sock->worker->mctx, pending);
	} else {
		send_req->data.base = &send_req->smallbuf[0];
	}

	isc__nmsocket_attach(sock, &send_req->tlssock);
	if (cb != NULL) {
		send_req->cb = cb;
		send_req->cbarg = cbarg;
		isc_nmhandle_attach(tlshandle, &send_req->handle);
	}

	rv = BIO_read_ex(sock->tlsstream.bio_out, send_req->data.base, pending,
			 &len);
	/* There's something pending, read must succeed */
	RUNTIME_CHECK(rv == 1);

	INSIST(VALID_NMHANDLE(sock->outerhandle));

	sock->tlsstream.nsending++;
	isc_nm_send(sock->outerhandle, &send_req->data, tls_senddone, send_req);

	return (pending);
}

static int
tls_process_outgoing(isc_nmsocket_t *sock, bool finish,
		     isc__nm_uvreq_t *send_data) {
	int pending;

	bool received_shutdown = ((SSL_get_shutdown(sock->tlsstream.tls) &
				   SSL_RECEIVED_SHUTDOWN) != 0);
	bool sent_shutdown = ((SSL_get_shutdown(sock->tlsstream.tls) &
			       SSL_SENT_SHUTDOWN) != 0);

	if (received_shutdown && !sent_shutdown) {
		finish = true;
	}

	/* Data from TLS to network */
	if (send_data != NULL) {
		pending = tls_send_outgoing(sock, finish, send_data->handle,
					    send_data->cb.send,
					    send_data->cbarg);
	} else {
		pending = tls_send_outgoing(sock, finish, NULL, NULL, NULL);
	}

	return (pending);
}

static int
tls_try_handshake(isc_nmsocket_t *sock, isc_result_t *presult) {
	int rv = 0;
	isc_nmhandle_t *tlshandle = NULL;

	REQUIRE(sock->tlsstream.state == TLS_HANDSHAKE);

	if (SSL_is_init_finished(sock->tlsstream.tls) == 1) {
		return (0);
	}

	rv = SSL_do_handshake(sock->tlsstream.tls);
	if (rv == 1) {
		isc_result_t result = ISC_R_SUCCESS;
		INSIST(SSL_is_init_finished(sock->tlsstream.tls) == 1);
		INSIST(sock->statichandle == NULL);
		isc__nmsocket_log_tls_session_reuse(sock, sock->tlsstream.tls);
		tlshandle = isc__nmhandle_get(sock, &sock->peer, &sock->iface);
		if (sock->tlsstream.server) {
			if (sock->listener->accept_cb == NULL) {
				result = ISC_R_CANCELED;
			} else {
				result = sock->listener->accept_cb(
					tlshandle, result,
					sock->listener->accept_cbarg);
			}
		} else {
			tls_call_connect_cb(sock, tlshandle, result);
		}
		isc_nmhandle_detach(&tlshandle);
		sock->tlsstream.state = TLS_IO;

		if (presult != NULL) {
			*presult = result;
		}
	}

	return (rv);
}

static bool
tls_try_to_close_unused_socket(isc_nmsocket_t *sock) {
	if (sock->tlsstream.state > TLS_HANDSHAKE &&
	    sock->statichandle == NULL && sock->tlsstream.nsending == 0)
	{
		/*
		 * It seems that no action on the socket has been
		 * scheduled on some point after the handshake, let's
		 * close the connection.
		 */
		isc__nmsocket_prep_destroy(sock);
		return (true);
	}

	return (false);
}

static void
tls_do_bio(isc_nmsocket_t *sock, isc_region_t *received_data,
	   isc__nm_uvreq_t *send_data, bool finish) {
	isc_result_t result = ISC_R_SUCCESS;
	int pending, tls_status = SSL_ERROR_NONE;
	int rv = 0;
	size_t len = 0;
	int saved_errno = 0;
	bool was_reading;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());

	was_reading = sock->reading;
	/* We will resume read if TLS layer wants us to */
	if (sock->reading && sock->outerhandle) {
		REQUIRE(VALID_NMHANDLE(sock->outerhandle));
		isc_nm_read_stop(sock->outerhandle);
	}

	if (sock->tlsstream.state == TLS_INIT) {
		INSIST(received_data == NULL && send_data == NULL);
		if (sock->tlsstream.server) {
			SSL_set_accept_state(sock->tlsstream.tls);
		} else {
			SSL_set_connect_state(sock->tlsstream.tls);
		}
		sock->tlsstream.state = TLS_HANDSHAKE;
		rv = tls_try_handshake(sock, NULL);
		INSIST(SSL_is_init_finished(sock->tlsstream.tls) == 0);
	} else if (sock->tlsstream.state == TLS_CLOSED) {
		return;
	} else { /* initialised and doing I/O */
		if (received_data != NULL) {
			INSIST(send_data == NULL);
			rv = BIO_write_ex(sock->tlsstream.bio_in,
					  received_data->base,
					  received_data->length, &len);
			if (rv <= 0 || len != received_data->length) {
				result = ISC_R_TLSERROR;
#if defined(NETMGR_TRACE) && defined(NETMGR_TRACE_VERBOSE)
				saved_errno = errno;
#endif
				goto error;
			}

			/*
			 * Only after doing the IO we can check whether SSL
			 * handshake is done.
			 */
			if (sock->tlsstream.state == TLS_HANDSHAKE) {
				isc_result_t hs_result = ISC_R_UNSET;
				rv = tls_try_handshake(sock, &hs_result);
				if (sock->tlsstream.state == TLS_IO &&
				    hs_result != ISC_R_SUCCESS) {
					/*
					 * The accept callback has been called
					 * unsuccessfully. Let's try to shut
					 * down the TLS connection gracefully.
					 */
					INSIST(SSL_is_init_finished(
						       sock->tlsstream.tls) ==
					       1);
					INSIST(!atomic_load(&sock->client));
					finish = true;
				}
			}
		} else if (send_data != NULL) {
			INSIST(received_data == NULL);
			INSIST(sock->tlsstream.state > TLS_HANDSHAKE);
			bool received_shutdown =
				((SSL_get_shutdown(sock->tlsstream.tls) &
				  SSL_RECEIVED_SHUTDOWN) != 0);
			bool sent_shutdown =
				((SSL_get_shutdown(sock->tlsstream.tls) &
				  SSL_SENT_SHUTDOWN) != 0);
			rv = SSL_write_ex(sock->tlsstream.tls,
					  send_data->uvbuf.base,
					  send_data->uvbuf.len, &len);
			if (rv != 1 || len != send_data->uvbuf.len) {
				result = received_shutdown || sent_shutdown
						 ? ISC_R_CANCELED
						 : ISC_R_TLSERROR;
				send_data->cb.send(send_data->handle, result,
						   send_data->cbarg);
				send_data = NULL;
				return;
			}
		}

		/* Decrypt and pass data from network to client */
		if (sock->tlsstream.state >= TLS_IO && sock->recv_cb != NULL &&
		    was_reading && sock->statichandle != NULL && !finish)
		{
			uint8_t recv_buf[TLS_BUF_SIZE];
			INSIST(sock->tlsstream.state > TLS_HANDSHAKE);
			while ((rv = SSL_read_ex(sock->tlsstream.tls, recv_buf,
						 TLS_BUF_SIZE, &len)) == 1)
			{
				isc_region_t region;
				region = (isc_region_t){ .base = &recv_buf[0],
							 .length = len };

				INSIST(VALID_NMHANDLE(sock->statichandle));
				sock->recv_cb(sock->statichandle, ISC_R_SUCCESS,
					      &region, sock->recv_cbarg);
				/* The handle could have been detached in
				 * sock->recv_cb, making the sock->statichandle
				 * nullified (it happens in netmgr.c). If it is
				 * the case, then it means that we are not
				 * interested in keeping the connection alive
				 * anymore. Let's shut down the SSL session,
				 * send what we have in the SSL buffers,
				 * and close the connection.
				 */
				if (sock->statichandle == NULL) {
					finish = true;
					break;
				} else if (!sock->reading) {
					/*
					 * Reading has been paused from withing
					 * the context of read callback - stop
					 * processing incoming data.
					 */
					break;
				}
			}
		}
	}
	errno = 0;
	tls_status = SSL_get_error(sock->tlsstream.tls, rv);
	saved_errno = errno;

	/* See "BUGS" section at:
	 * https://www.openssl.org/docs/man1.1.1/man3/SSL_get_error.html
	 *
	 * It is mentioned there that when TLS status equals
	 * SSL_ERROR_SYSCALL AND errno == 0 it means that underlying
	 * transport layer returned EOF prematurely.  However, we are
	 * managing the transport ourselves, so we should just resume
	 * reading from the TCP socket.
	 *
	 * It seems that this case has been handled properly on modern
	 * versions of OpenSSL. That being said, the situation goes in
	 * line with the manual: it is briefly mentioned there that
	 * SSL_ERROR_SYSCALL might be returned not only in a case of
	 * low-level errors (like system call failures).
	 */
	if (tls_status == SSL_ERROR_SYSCALL && saved_errno == 0 &&
	    received_data == NULL && send_data == NULL && finish == false)
	{
		tls_status = SSL_ERROR_WANT_READ;
	}

	pending = tls_process_outgoing(sock, finish, send_data);
	if (pending > 0) {
		/* We'll continue in tls_senddone */
		return;
	}

	switch (tls_status) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		(void)tls_try_to_close_unused_socket(sock);
		return;
	case SSL_ERROR_WANT_WRITE:
		if (sock->tlsstream.nsending == 0) {
			/*
			 * Launch tls_do_bio asynchronously. If we're sending
			 * already the send callback will call it.
			 */
			async_tls_do_bio(sock);
		}
		return;
	case SSL_ERROR_WANT_READ:
		if (tls_try_to_close_unused_socket(sock) ||
		    sock->outerhandle == NULL) {
			return;
		}

		INSIST(VALID_NMHANDLE(sock->outerhandle));

		sock->reading = true;
		isc_nm_read(sock->outerhandle, tls_readcb, sock);
		return;
	default:
		result = tls_error_to_result(tls_status, sock->tlsstream.state,
					     sock->tlsstream.tls);
		break;
	}

error:
#if defined(NETMGR_TRACE) && defined(NETMGR_TRACE_VERBOSE)
	isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_NETMGR,
		      ISC_LOG_NOTICE,
		      "SSL error in BIO: %d %s (errno: %d). Arguments: "
		      "received_data: %p, "
		      "send_data: %p, finish: %s",
		      tls_status, isc_result_totext(result), saved_errno,
		      received_data, send_data, finish ? "true" : "false");
#endif
	tls_failed_read_cb(sock, result);
}

static void
tls_readcb(isc_nmhandle_t *handle, isc_result_t result, isc_region_t *region,
	   void *cbarg) {
	isc_nmsocket_t *tlssock = (isc_nmsocket_t *)cbarg;

	REQUIRE(VALID_NMSOCK(tlssock));
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(tlssock->tid == isc_tid());

	if (result != ISC_R_SUCCESS) {
		tls_failed_read_cb(tlssock, result);
		return;
	} else if (isc__nmsocket_closing(handle->sock)) {
		tls_failed_read_cb(tlssock, ISC_R_CANCELED);
		return;
	}

	tls_do_bio(tlssock, region, NULL, false);
}

static isc_result_t
initialize_tls(isc_nmsocket_t *sock, bool server) {
	REQUIRE(sock->tid == isc_tid());

	sock->tlsstream.bio_in = BIO_new(BIO_s_mem());
	if (sock->tlsstream.bio_in == NULL) {
		isc_tls_free(&sock->tlsstream.tls);
		return (ISC_R_TLSERROR);
	}
	sock->tlsstream.bio_out = BIO_new(BIO_s_mem());
	if (sock->tlsstream.bio_out == NULL) {
		BIO_free_all(sock->tlsstream.bio_in);
		sock->tlsstream.bio_in = NULL;
		isc_tls_free(&sock->tlsstream.tls);
		return (ISC_R_TLSERROR);
	}

	if (BIO_set_mem_eof_return(sock->tlsstream.bio_in, EOF) != 1 ||
	    BIO_set_mem_eof_return(sock->tlsstream.bio_out, EOF) != 1)
	{
		goto error;
	}

	SSL_set_bio(sock->tlsstream.tls, sock->tlsstream.bio_in,
		    sock->tlsstream.bio_out);
	sock->tlsstream.server = server;
	sock->tlsstream.nsending = 0;
	sock->tlsstream.state = TLS_INIT;
	return (ISC_R_SUCCESS);
error:
	isc_tls_free(&sock->tlsstream.tls);
	sock->tlsstream.bio_out = sock->tlsstream.bio_in = NULL;
	return (ISC_R_TLSERROR);
}

static isc_result_t
tlslisten_acceptcb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *tlslistensock = (isc_nmsocket_t *)cbarg;
	isc_nmsocket_t *tlssock = NULL;
	isc_tlsctx_t *tlsctx = NULL;

	/* If accept() was unsuccessful we can't do anything */
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(VALID_NMSOCK(tlslistensock));
	REQUIRE(tlslistensock->type == isc_nm_tlslistener);

	/*
	 * We need to create a 'wrapper' tlssocket for this connection.
	 */
	tlssock = isc_mem_get(handle->sock->worker->mctx, sizeof(*tlssock));
	isc__nmsocket_init(tlssock, handle->sock->worker, isc_nm_tlssocket,
			   &handle->sock->iface);

	/* We need to initialize SSL now to reference SSL_CTX properly */
	tlsctx = tls_get_listener_tlsctx(tlslistensock, isc_tid());
	RUNTIME_CHECK(tlsctx != NULL);
	isc_tlsctx_attach(tlsctx, &tlssock->tlsstream.ctx);
	tlssock->tlsstream.tls = isc_tls_create(tlssock->tlsstream.ctx);
	if (tlssock->tlsstream.tls == NULL) {
		atomic_store(&tlssock->closed, true);
		isc_tlsctx_free(&tlssock->tlsstream.ctx);
		isc__nmsocket_detach(&tlssock);
		return (ISC_R_TLSERROR);
	}

	isc__nmsocket_attach(tlslistensock, &tlssock->listener);
	isc_nmhandle_attach(handle, &tlssock->outerhandle);
	tlssock->peer = handle->sock->peer;
	tlssock->read_timeout =
		atomic_load(&handle->sock->worker->netmgr->init);

	/*
	 * Hold a reference to tlssock in the TCP socket: it will
	 * detached in isc__nm_tls_cleanup_data().
	 */
	handle->sock->tlsstream.tlssocket = tlssock;

	result = initialize_tls(tlssock, true);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	/* TODO: catch failure code, detach tlssock, and log the error */

	tls_do_bio(tlssock, NULL, NULL, false);
	return (result);
}

isc_result_t
isc_nm_listentls(isc_nm_t *mgr, uint32_t workers, isc_sockaddr_t *iface,
		 isc_nm_accept_cb_t accept_cb, void *accept_cbarg, int backlog,
		 isc_quota_t *quota, SSL_CTX *sslctx, isc_nmsocket_t **sockp) {
	isc_result_t result;
	isc_nmsocket_t *tlssock = NULL;
	isc_nmsocket_t *tsock = NULL;
	isc__networker_t *worker = &mgr->workers[isc_tid()];

	REQUIRE(VALID_NM(mgr));
	REQUIRE(isc_tid() == 0);

	if (isc__nm_closing(worker)) {
		return (ISC_R_SHUTTINGDOWN);
	}

	if (workers == 0) {
		workers = mgr->nloops;
	}
	REQUIRE(workers <= mgr->nloops);

	tlssock = isc_mem_get(worker->mctx, sizeof(*tlssock));

	isc__nmsocket_init(tlssock, worker, isc_nm_tlslistener, iface);
	tlssock->accept_cb = accept_cb;
	tlssock->accept_cbarg = accept_cbarg;
	tls_init_listener_tlsctx(tlssock, sslctx);
	tlssock->tlsstream.tls = NULL;

	/*
	 * tlssock will be a TLS 'wrapper' around an unencrypted stream.
	 * We set tlssock->outer to a socket listening for a TCP connection.
	 */
	result = isc_nm_listentcp(mgr, workers, iface, tlslisten_acceptcb,
				  tlssock, backlog, quota, &tlssock->outer);
	if (result != ISC_R_SUCCESS) {
		atomic_store(&tlssock->closed, true);
		isc__nmsocket_detach(&tlssock);
		return (result);
	}

	/* wait for listen result */
	isc__nmsocket_attach(tlssock->outer, &tsock);
	tlssock->result = result;
	atomic_store(&tlssock->active, true);
	INSIST(tlssock->outer->tlsstream.tlslistener == NULL);
	isc__nmsocket_attach(tlssock, &tlssock->outer->tlsstream.tlslistener);
	isc__nmsocket_detach(&tsock);
	INSIST(result != ISC_R_UNSET);

	if (result == ISC_R_SUCCESS) {
		atomic_store(&tlssock->listening, true);
		*sockp = tlssock;
	}

	return (result);
}

void
isc__nm_async_tlssend(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlssend_t *ievent = (isc__netievent_tlssend_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *req = ievent->req;

	REQUIRE(VALID_UVREQ(req));
	REQUIRE(sock->tid == isc_tid());

	UNUSED(worker);

	ievent->req = NULL;

	if (inactive(sock)) {
		req->cb.send(req->handle, ISC_R_CANCELED, req->cbarg);
		goto done;
	}

	tls_do_bio(sock, NULL, req, false);
done:
	isc__nm_uvreq_put(&req, sock);
	return;
}

void
isc__nm_tls_send(isc_nmhandle_t *handle, const isc_region_t *region,
		 isc_nm_cb_t cb, void *cbarg) {
	isc__netievent_tlssend_t *ievent = NULL;
	isc__nm_uvreq_t *uvreq = NULL;
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;

	REQUIRE(sock->type == isc_nm_tlssocket);

	if (inactive(sock)) {
		cb(handle, ISC_R_CANCELED, cbarg);
		return;
	}

	uvreq = isc__nm_uvreq_get(sock->worker, sock);
	isc_nmhandle_attach(handle, &uvreq->handle);
	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;
	uvreq->uvbuf.base = (char *)region->base;
	uvreq->uvbuf.len = region->length;

	/*
	 * We need to create an event and pass it using async channel
	 */
	ievent = isc__nm_get_netievent_tlssend(sock->worker, sock, uvreq);
	isc__nm_enqueue_ievent(sock->worker, (isc__netievent_t *)ievent);
}

void
isc__nm_tls_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));

	sock = handle->sock;
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->statichandle == handle);
	REQUIRE(sock->tid == isc_tid());

	if (inactive(sock)) {
		cb(handle, ISC_R_NOTCONNECTED, NULL, cbarg);
		return;
	}

	sock->recv_cb = cb;
	sock->recv_cbarg = cbarg;

	if (sock->reading) {
		return;
	}

	tls_do_bio(sock, NULL, NULL, false);
}

void
isc__nm_tls_read_stop(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	handle->sock->reading = false;

	if (handle->sock->outerhandle != NULL) {
		isc_nm_read_stop(handle->sock->outerhandle);
	}
}

static void
tls_close_direct(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	/*
	 * At this point we're certain that there are no
	 * external references, we can close everything.
	 */
	if (sock->outerhandle != NULL) {
		sock->reading = false;
		isc_nm_read_stop(sock->outerhandle);

		isc_nmhandle_close(sock->outerhandle);
		isc_nmhandle_detach(&sock->outerhandle);
	}

	if (sock->listener != NULL) {
		isc__nmsocket_detach(&sock->listener);
	}

	/* Further cleanup performed in isc__nm_tls_cleanup_data() */
	atomic_store(&sock->closed, true);
	atomic_store(&sock->active, false);
	sock->tlsstream.state = TLS_CLOSED;
}

void
isc__nm_tls_close(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tlssocket);

	if (!atomic_compare_exchange_strong(&sock->closing, &(bool){ false },
					    true)) {
		return;
	}

	if (sock->tid == isc_tid()) {
		/* no point in attempting to make the call asynchronous */
		tls_close_direct(sock);
	} else {
		isc__netievent_tlsclose_t *ievent =
			isc__nm_get_netievent_tlsclose(sock->worker, sock);
		isc__nm_enqueue_ievent(sock->worker,
				       (isc__netievent_t *)ievent);
	}
}

void
isc__nm_async_tlsclose(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlsclose_t *ievent = (isc__netievent_tlsclose_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(ievent->sock->tid == isc_tid());

	UNUSED(worker);

	tls_close_direct(sock);
}

void
isc__nm_tls_stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tlslistener);
	REQUIRE(sock->tlsstream.tls == NULL);
	REQUIRE(sock->tlsstream.ctx == NULL);

	if (!atomic_compare_exchange_strong(&sock->closing, &(bool){ false },
					    true)) {
		UNREACHABLE();
	}

	atomic_store(&sock->listening, false);
	atomic_store(&sock->closed, true);
	sock->recv_cb = NULL;
	sock->recv_cbarg = NULL;

	if (sock->outer != NULL) {
		isc_nm_stoplistening(sock->outer);
		isc__nmsocket_detach(&sock->outer);
	}
}

static void
tcp_connected(isc_nmhandle_t *handle, isc_result_t result, void *cbarg);

void
isc_nm_tlsconnect(isc_nm_t *mgr, isc_sockaddr_t *local, isc_sockaddr_t *peer,
		  isc_nm_cb_t cb, void *cbarg, isc_tlsctx_t *ctx,
		  isc_tlsctx_client_session_cache_t *client_sess_cache,
		  unsigned int timeout) {
	isc_nmsocket_t *nsock = NULL;
	isc__networker_t *worker = &mgr->workers[isc_tid()];

	REQUIRE(VALID_NM(mgr));

	if (isc__nm_closing(worker)) {
		cb(NULL, ISC_R_SHUTTINGDOWN, cbarg);
		return;
	}

	nsock = isc_mem_get(worker->mctx, sizeof(*nsock));
	isc__nmsocket_init(nsock, worker, isc_nm_tlssocket, local);
	nsock->connect_cb = cb;
	nsock->connect_cbarg = cbarg;
	nsock->connect_timeout = timeout;
	isc_tlsctx_attach(ctx, &nsock->tlsstream.ctx);
	atomic_init(&nsock->client, true);
	if (client_sess_cache != NULL) {
		INSIST(isc_tlsctx_client_session_cache_getctx(
			       client_sess_cache) == ctx);
		isc_tlsctx_client_session_cache_attach(
			client_sess_cache, &nsock->tlsstream.client_sess_cache);
	}

	isc_nm_tcpconnect(mgr, local, peer, tcp_connected, nsock,
			  nsock->connect_timeout);
}

static void
tcp_connected(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *tlssock = (isc_nmsocket_t *)cbarg;
	isc_nmhandle_t *tlshandle = NULL;
	isc__networker_t *worker = NULL;

	REQUIRE(VALID_NMSOCK(tlssock));

	worker = tlssock->worker;

	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	INSIST(VALID_NMHANDLE(handle));

	tlssock->iface = handle->sock->iface;
	tlssock->peer = handle->sock->peer;
	if (isc__nm_closing(worker)) {
		result = ISC_R_SHUTTINGDOWN;
		goto error;
	}

	/*
	 * We need to initialize SSL now to reference SSL_CTX properly.
	 */
	tlssock->tlsstream.tls = isc_tls_create(tlssock->tlsstream.ctx);
	if (tlssock->tlsstream.tls == NULL) {
		result = ISC_R_TLSERROR;
		goto error;
	}

	result = initialize_tls(tlssock, false);
	if (result != ISC_R_SUCCESS) {
		goto error;
	}
	tlssock->peer = isc_nmhandle_peeraddr(handle);
	isc_nmhandle_attach(handle, &tlssock->outerhandle);
	atomic_store(&tlssock->active, true);

	if (tlssock->tlsstream.client_sess_cache != NULL) {
		isc_tlsctx_client_session_cache_reuse_sockaddr(
			tlssock->tlsstream.client_sess_cache, &tlssock->peer,
			tlssock->tlsstream.tls);
	}

	/*
	 * Hold a reference to tlssock in the TCP socket: it will
	 * detached in isc__nm_tls_cleanup_data().
	 */
	handle->sock->tlsstream.tlssocket = tlssock;

	tls_do_bio(tlssock, NULL, NULL, false);
	return;
error:
	tlshandle = isc__nmhandle_get(tlssock, NULL, NULL);
	atomic_store(&tlssock->closed, true);
	tls_call_connect_cb(tlssock, tlshandle, result);
	isc_nmhandle_detach(&tlshandle);
	isc__nmsocket_detach(&tlssock);
}

void
isc__nm_async_tlsdobio(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlsdobio_t *ievent = (isc__netievent_tlsdobio_t *)ev0;

	UNUSED(worker);

	tls_do_bio(ievent->sock, NULL, NULL, false);
}

void
isc__nm_tls_cleanup_data(isc_nmsocket_t *sock) {
	if (sock->type == isc_nm_tcplistener &&
	    sock->tlsstream.tlslistener != NULL) {
		isc__nmsocket_detach(&sock->tlsstream.tlslistener);
	} else if (sock->type == isc_nm_tlslistener) {
		tls_cleanup_listener_tlsctx(sock);
	} else if (sock->type == isc_nm_tlssocket) {
		if (sock->tlsstream.tls != NULL) {
			/*
			 * Let's shut down the TLS session properly so that
			 * the session will remain resumable, if required.
			 */
			tls_try_shutdown(sock->tlsstream.tls, true);
			tls_keep_client_tls_session(sock);
			isc_tls_free(&sock->tlsstream.tls);
			/* These are destroyed when we free SSL */
			sock->tlsstream.bio_out = NULL;
			sock->tlsstream.bio_in = NULL;
		}
		if (sock->tlsstream.ctx != NULL) {
			isc_tlsctx_free(&sock->tlsstream.ctx);
		}
		if (sock->tlsstream.client_sess_cache != NULL) {
			INSIST(atomic_load(&sock->client));
			isc_tlsctx_client_session_cache_detach(
				&sock->tlsstream.client_sess_cache);
		}
	} else if (sock->type == isc_nm_tcpsocket &&
		   sock->tlsstream.tlssocket != NULL) {
		/*
		 * The TLS socket can't be destroyed until its underlying TCP
		 * socket is, to avoid possible use-after-free errors.
		 */
		isc__nmsocket_detach(&sock->tlsstream.tlssocket);
	}
}

void
isc__nm_tls_cleartimeout(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_tlssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));
		isc_nmhandle_cleartimeout(sock->outerhandle);
	}
}

void
isc__nm_tls_settimeout(isc_nmhandle_t *handle, uint32_t timeout) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_tlssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));
		isc_nmhandle_settimeout(sock->outerhandle, timeout);
	}
}

void
isc__nmhandle_tls_keepalive(isc_nmhandle_t *handle, bool value) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_tlssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));

		isc_nmhandle_keepalive(sock->outerhandle, value);
	}
}

void
isc__nmhandle_tls_setwritetimeout(isc_nmhandle_t *handle,
				  uint64_t write_timeout) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_tlssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));

		isc_nmhandle_setwritetimeout(sock->outerhandle, write_timeout);
	}
}

const char *
isc__nm_tls_verify_tls_peer_result_string(const isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_tlssocket);

	sock = handle->sock;
	if (sock->tlsstream.tls == NULL) {
		return (NULL);
	}

	return (isc_tls_verify_peer_result_string(sock->tlsstream.tls));
}

static void
tls_init_listener_tlsctx(isc_nmsocket_t *listener, isc_tlsctx_t *ctx) {
	size_t nworkers;

	REQUIRE(VALID_NMSOCK(listener));
	REQUIRE(ctx != NULL);

	nworkers =
		(size_t)isc_loopmgr_nloops(listener->worker->netmgr->loopmgr);
	INSIST(nworkers > 0);

	listener->tlsstream.listener_tls_ctx = isc_mem_get(
		listener->worker->mctx, sizeof(isc_tlsctx_t *) * nworkers);
	listener->tlsstream.n_listener_tls_ctx = nworkers;
	for (size_t i = 0; i < nworkers; i++) {
		listener->tlsstream.listener_tls_ctx[i] = NULL;
		isc_tlsctx_attach(ctx,
				  &listener->tlsstream.listener_tls_ctx[i]);
	}
}

static void
tls_cleanup_listener_tlsctx(isc_nmsocket_t *listener) {
	REQUIRE(VALID_NMSOCK(listener));

	if (listener->tlsstream.listener_tls_ctx == NULL) {
		return;
	}

	for (size_t i = 0; i < listener->tlsstream.n_listener_tls_ctx; i++) {
		isc_tlsctx_free(&listener->tlsstream.listener_tls_ctx[i]);
	}
	isc_mem_put(listener->worker->mctx,
		    listener->tlsstream.listener_tls_ctx,
		    sizeof(isc_tlsctx_t *) *
			    listener->tlsstream.n_listener_tls_ctx);
	listener->tlsstream.n_listener_tls_ctx = 0;
}

static isc_tlsctx_t *
tls_get_listener_tlsctx(isc_nmsocket_t *listener, const int tid) {
	REQUIRE(VALID_NMSOCK(listener));
	REQUIRE(tid >= 0);

	if (listener->tlsstream.listener_tls_ctx == NULL) {
		return (NULL);
	}

	return (listener->tlsstream.listener_tls_ctx[tid]);
}

void
isc__nm_async_tls_set_tlsctx(isc_nmsocket_t *listener, isc_tlsctx_t *tlsctx,
			     const int tid) {
	REQUIRE(tid >= 0);

	isc_tlsctx_free(&listener->tlsstream.listener_tls_ctx[tid]);
	isc_tlsctx_attach(tlsctx, &listener->tlsstream.listener_tls_ctx[tid]);
}

static void
tls_keep_client_tls_session(isc_nmsocket_t *sock) {
	/*
	 * Ensure that the isc_tls_t is being accessed from
	 * within the worker thread the socket is bound to.
	 */
	REQUIRE(sock->tid == isc_tid());
	if (sock->tlsstream.client_sess_cache != NULL &&
	    sock->tlsstream.client_session_saved == false)
	{
		INSIST(atomic_load(&sock->client));
		isc_tlsctx_client_session_cache_keep_sockaddr(
			sock->tlsstream.client_sess_cache, &sock->peer,
			sock->tlsstream.tls);
		sock->tlsstream.client_session_saved = true;
	}
}

static void
tls_try_shutdown(isc_tls_t *tls, const bool force) {
	if (force) {
		(void)SSL_set_shutdown(tls, SSL_SENT_SHUTDOWN);
	} else if ((SSL_get_shutdown(tls) & SSL_SENT_SHUTDOWN) == 0) {
		(void)SSL_shutdown(tls);
	}
}
