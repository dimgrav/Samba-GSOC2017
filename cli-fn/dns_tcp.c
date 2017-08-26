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
#include "libcli/util/tstream.h"
#include "source4/smbd/service_task.h"
#include "source4/smbd/service_stream.h"
#include "source4/lib/stream/packet.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/dns/libudp.h"
#include "libcli/dns/libtcp.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_werror.h"
#include "lib/util/samba_util.h"
#include "libcli/util/error.h"
#include "librpc/gen_ndr/dns.h"

#define DNS_REQUEST_TIMEOUT 2

/*** TCP Requests ***/

/* TCP callbacks */
void dns_tcp_req_recv_reply(struct tevent_req *subreq);
void dns_tcp_req_done(struct tevent_req *subreq);

/* tcp request to send */
struct tevent_req *dns_tcp_req_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *server_addr_string,
					struct iovec *vector,
					size_t count)
{
	struct tevent_req *req, *subreq, *socreq;
	struct dns_tcp_request_state *state;
	struct tsocket_address *local_address, *remote_address;
	struct tstream_context *stream;
	int req_ret, soc_ret, err;

	req = tevent_req_create(mem_ctx, &state, struct dns_tcp_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;

	/* check for connected sockets and use if any */
	req_ret = tsocket_address_inet_from_strings(state, "ip", NULL, 0,
						&local_address);
	if (req_ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	req_ret = tsocket_address_inet_from_strings(state, "ip", server_addr_string,
						DNS_SERVICE_PORT, &remote_address);
	if (req_ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	/* must be reviewed! */
	soc_ret = tstream_inet_tcp_connect_recv(socreq, err, mem_ctx, stream, NULL);
	TALLOC_FREE(socreq);
	if (soc_ret == -1 && err != 0) {
		tevent_req_error(socreq, err);
		return tevent_req_post(req, ev);
	}

	socreq = tstream_inet_tcp_connect_send(mem_ctx, ev, local_address, remote_address);
	if (tevent_req_nomem(socreq, req)) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(socreq, dns_tcp_req_send, req);

	state->tstream = stream;
	state->v_count = count;

	subreq = tstream_writev_send(mem_ctx, ev, stream, vector, count);
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

/* get buffer and wait to receive server response */
void dns_tcp_req_recv_reply(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
						struct tevent_req);
	struct dns_tcp_request_state *state = tevent_req_data(req,
						struct dns_tcp_request_state);
	ssize_t stream_len;
	int err = 0;
	NTSTATUS status;

	stream_len = tstream_writev_recv(subreq, &err);
	TALLOC_FREE(subreq);

	if (stream_len == -1 && err != 0) {
		tevent_req_error(req, err);
		return;
	}

	if (stream_len != state->v_count) {
		tevent_req_error(req, EIO);
		return;
	}

	/* response loop */
	struct dns_tcp_connection *dns_conn = tevent_req_callback_data(subreq,
			struct dns_tcp_connection);
	struct tsocket_address *local_address, *server_address;
	struct dns_client *dns = dns_conn->dns_socket->dns; // uses server iface
	struct dns_tcp_call *call;

	call = talloc(dns_conn, struct dns_tcp_call);
	if (call == NULL) {
		DEBUG(1, ("dns_tcp_req_recv_reply: NULL call\n"));
		return;
	}
	call->dns_conn = dns_conn;

	status = tstream_read_pdu_blob_recv(subreq, call, &call->in);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("tstream_read_pdu_blob_recv: error %s\n", nt_errstr(status)));
		return;
	}
	
	if (subreq == NULL) {
		DEBUG(1, ("dns_tcp_req_recv_reply: NULL subreq\n"));
		return;
	}
	tevent_req_set_callback(subreq, dns_tcp_req_done, call);
	TALLOC_FREE(subreq);
	
	subreq = tstream_read_pdu_blob_send(dns_conn,
					    dns_conn->conn->event.ctx,
					    dns_conn->tstream,
					    2, 
					    packet_full_request_u16,
					    dns_conn);
	/* loop callback */
	tevent_req_set_callback(subreq, dns_tcp_req_recv_reply, dns_conn);
}

/* callback status */
void dns_tcp_req_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
	struct dns_tcp_connection *dns_conn = tevent_req_callback_data(subreq,
			struct dns_tcp_connection);
	struct dns_tcp_call *call;
	
	WERROR err;
	/*
	err = dns_process_recv(subreq, call, &call->out);
	
	TALLOC_FREE(subreq);
	*/
	if (!W_ERROR_IS_OK(err)) {
		DEBUG(1, ("dns_req_done error: %s\n", win_errstr(err)));
		return;
	}
	
	TALLOC_FREE(subreq);
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

	/* tevent_req_is_unix_error defined in tevent_unix.h */
	if (tevent_req_is_unix_error(req, &err)) {
		tevent_req_received(req);
		return err;
	}

	*reply = talloc_move(mem_ctx, &state->reply);
	*reply_len = state->reply_len;
	tevent_req_received(req);

	return 0;
}
