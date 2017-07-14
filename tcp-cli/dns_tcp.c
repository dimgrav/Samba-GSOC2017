/* TCP client-side DNS call handling.
 * 
 * --WORK IN PROGRESS--
 *
 * Copyright (C) 2017 Dimitrios Gravanis
 * 
 * Based on the existing work on Samba Unix SMB/CIFS implementation by
 * Kai Blin Copyright (C) 2011, Stefan Metzmacher Copyright (C) 2014
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "system/network.h"
#include <tevent.h>
#include "lib/tsocket/tsocket.h"
#include "libcli/dns/libdns.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/samba_util.h"
#include "libcli/util/error.h"
#include "librpc/gen_ndr/dns.h"
#include "libtcp/libtcp.h"

#define DNS_REQUEST_TIMEOUT 2

/* callbacks */
static void dns_tcp_req_recv_reply(struct tevent_req *subreq);
static void dns_tcp_req_done(struct tevent_req *subreq);

/* tcp request to send */
struct tevent_req *dns_tcp_req_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *server_addr_string,
					struct iovec *vector,
					size_t count)
{
	struct tevent_req *req, *subreq;
	struct dns_tcp_request_state *state;
	struct tsocket_address *local_addr, *server_addr;
	struct tstream_context *stream;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct dns_tcp_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;

	/* check for connected sockets and use if any */
	ret = tsocket_address_inet_from_strings(state, "ip", NULL, 0,
						&local_addr);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_from_strings(state, "ip", server_addr_string,
						DNS_SERVICE_PORT, &server_addr);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = tstream_inet_tcp_connect_send(mem_ctx, ev, local_addr, server_addr);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	state->tstream = stream;
	state->query_len = count;

	// dump_data(10, *vector, count); not sure how dump data works with pointers

	subreq = tstream_writev_send(mem_ctx, ev, stream, *vector, count);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	if (!tevent_req_set_endtime(req, ev,
				timeval_current_ofs(DNS_REQUEST_TIMEOUT, 0))) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	/* associate callback */
	tevent_req_set_callback(subreq, dns_tcp_req_recv_reply, req);
	
	return req;
}

/* wait to receive server response */
static void dns_tcp_req_recv_reply(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
						struct tevent_req);
	struct dns_tcp_request_state *state = tevent_req_data(req,
						struct dns_tcp_request_state);
	ssize_t len;
	int err = 0;

	len = tstream_writev_recv(subreq, &err);
	TALLOC_FREE(subreq);

	if (len == -1 && err != 0) {
		tevent_req_error(req, err);
		return;
	}

	if (len != state->query_len) {
		tevent_req_error(req, EIO);
		return;
	}

	// need help here on how to pass the vector
	subreq = tstream_readv_pdu_send(state, state->ev, state->stream, , );
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	/* associate callback */
	tevent_req_set_callback(subreq, dns_tcp_req_done, req);
}

/* callback status */
static void dns_tcp_req_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
						struct tevent_req);
	struct dns_tcp_request_state *state = tevent_req_data(req,
						struct dns_tcp_request_state);

	ssize_t len;
	int err = 0;

	len = tstream_readv_pdu_recv(subreq, &err);
	TALLOC_FREE(subreq);

	if (len == -1 && err != 0) {
		tevent_req_error(req, err);
		return;
	}

	state->reply_len = len;
	dump_data(10, state->reply, state->reply_len);
	tevent_req_done(req);
}

/*  receiver */
int dns_tcp_req_recv(struct tevent_req *req,
			 		TALLOC_CTX *mem_ctx,
			 		uint8_t **reply,
			 		size_t *reply_len)
{
	struct dns_tcp_request_state *state = tevent_req_data(req,
			struct dns_tcp_request_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		tevent_req_received(req);
		return err;
	}

	*reply = talloc_move(mem_ctx, &state->reply);
	*reply_len = state->reply_len;
	tevent_req_received(req);

	return 0;
}
