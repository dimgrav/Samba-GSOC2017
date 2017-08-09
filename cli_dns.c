/*
   Unix SMB/CIFS implementation.

   DNS UDP/TCP call handler with socketwrapper support and TSIG generation

   Copyright (C) 2017 Dimitrios Gravanis <dimgrav@gmail.com>

   Based on: Small async DNS library for Samba with socketwrapper support

   Copyright (C) 2010 Kai Blin  <kai@samba.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* DNS call send/recv() */
#include "replace.h"
#include "system/network.h"
#include <tevent.h>
#include "lib/tsocket/tsocket.h"
#include "libcli/dns/libdns.h"
#include "libcli/dns/libtcp.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/samba_util.h"
#include "libcli/util/error.h"
#include "librpc/gen_ndr/dns.h"

#define DNS_REQUEST_TIMEOUT 2

/* TSIG generation */
#include "includes.h"
#include "lib/crypto/hmacmd5.h"
#include "libcli/util/ntstatus.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "libcli/dns/libtsig.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DNS

/*** UDP Requests ***/

/* UDP state struct */
struct dns_udp_request_state {
	struct tevent_context *ev;
	struct tdgram_context *dgram;
	size_t query_len;
	uint8_t *reply;
	size_t reply_len;
};

/* UDP callbacks */
static void dns_udp_request_get_reply(struct tevent_req *subreq);
static void dns_udp_request_done(struct tevent_req *subreq);

/* udp request to send */
struct tevent_req *dns_udp_request_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *server_addr_string,
					const uint8_t *query,
					size_t query_len)
{
	struct tevent_req *req, *subreq;
	struct dns_udp_request_state *state;
	struct tsocket_address *local_addr, *server_addr;
	struct tdgram_context *dgram;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct dns_udp_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;

	/* Use connected UDP sockets */
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

	ret = tdgram_inet_udp_socket(local_addr, server_addr, state, &dgram);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	state->dgram = dgram;
	state->query_len = query_len;

	dump_data(10, query, query_len);

	subreq = tdgram_sendto_send(state, ev, dgram, query, query_len, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	if (!tevent_req_set_endtime(req, ev,
				timeval_current_ofs(DNS_REQUEST_TIMEOUT, 0))) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, dns_udp_request_get_reply, req);
	return req;
}

/* wait for server reply */
static void dns_udp_request_get_reply(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
						struct tevent_req);
	struct dns_udp_request_state *state = tevent_req_data(req,
						struct dns_udp_request_state);
	ssize_t len;
	int err = 0;

	len = tdgram_sendto_recv(subreq, &err);
	TALLOC_FREE(subreq);

	if (len == -1 && err != 0) {
		tevent_req_error(req, err);
		return;
	}

	if (len != state->query_len) {
		tevent_req_error(req, EIO);
		return;
	}

	subreq = tdgram_recvfrom_send(state, state->ev, state->dgram);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, dns_udp_request_done, req);
}

/* callback status */
static void dns_udp_request_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
						struct tevent_req);
	struct dns_udp_request_state *state = tevent_req_data(req,
						struct dns_udp_request_state);

	ssize_t len;
	int err = 0;

	len = tdgram_recvfrom_recv(subreq, &err, state, &state->reply, NULL);
	TALLOC_FREE(subreq);

	if (len == -1 && err != 0) {
		tevent_req_error(req, err);
		return;
	}

	state->reply_len = len;
	dump_data(10, state->reply, state->reply_len);
	tevent_req_done(req);
}

/* receiver */
int dns_udp_request_recv(struct tevent_req *req,
			 TALLOC_CTX *mem_ctx,
			 uint8_t **reply,
			 size_t *reply_len)
{
	struct dns_udp_request_state *state = tevent_req_data(req,
			struct dns_udp_request_state);
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

/*** TCP Requests ***/

/* TCP callbacks */
static void dns_tcp_req_recv_reply(struct tevent_req *subreq);
static void dns_tcp_req_done(struct tevent_req *subreq);

/* terminate tcp conn with server */
static void dns_tcp_terminate_connection(struct dns_tcp_connection *dnsconn,
										const char *reason)
{
	stream_terminate_connection(dnsconn->conn, reason);
}

/* tcp request to send */
struct tevent_req *dns_tcp_req_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *server_addr_string,
					struct iovec *vector,
					size_t count)
{
	struct tevent_req *req, *subreq, *socreq;
	struct dns_tcp_request_state *state;
	struct tsocket_address *local_addr, *server_addr;
	struct tstream_context *stream;
	int req_ret, soc_ret, err = 0;

	req = tevent_req_create(mem_ctx, &state, struct dns_tcp_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;

	/* check for connected sockets and use if any */
	req_ret = tsocket_address_inet_from_strings(state, "ip", NULL, 0,
						&local_addr);
	if (req_ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	req_ret = tsocket_address_inet_from_strings(state, "ip", server_addr_string,
						DNS_SERVICE_PORT, &server_addr);
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

	socreq = tstream_inet_tcp_connect_send(mem_ctx, ev, local_addr, server_addr);
	if (tevent_req_nomem(socreq, req)) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(socreq, dns_tcp_req_send, req);

	state->tstream = stream;
	state->v_count = count;

	/* not sure how dump_data() works with pointers
	 * followed source4/heimdal/lib/roken/dumpdata.c
	 */
	dump_data(10, vector, count);

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
static void dns_tcp_req_recv_reply(struct tevent_req *subreq)
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
	struct dns_server *dns = dns_conn->dns_socket->dns; // uses the same iface with server
	struct dns_tcp_connection *dns_conn = tevent_req_callback_data(subreq,
			struct dns_tcp_connection);
	struct dns_tcp_call *call;

	call = talloc(dns_conn, struct dns_tcp_call);
	if (call == NULL) {
		dns_tcp_terminate_connection(dns_conn, "dns_tcp_req_recv_reply: "
				"no memory for dns_tcp_call!");
		return;
	}
	call->dns_conn = dns_conn;

	status = tstream_read_pdu_blob_recv(subreq, call, &call->in);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		dns_tcp_terminate_connection(dns_conn,
		"tstream_read_pdu_blob_recv(): error %s", nt_errstr(status));
		return;
	}

	subreq = dns_process_send(call, dns->task->event_ctx, dns, &call->in);
	if (subreq == NULL) {
		dns_tcp_terminate_connection(dns_conn,
		"dns_tcp_req_recv_reply: dns process send failure!");
		return;
	}
	tevent_req_set_callback(subreq, dns_tcp_req_done, call);

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
static void dns_tcp_req_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
	WERROR err = dns_process_recv(subreq, call, &call->out);
	TALLOC_FREE(subreq);

	if (!W_ERROR_IS_OK(err)) {
		DEBUG(1, ("dns_process error: %s\n", win_errstr(err)));
		dns_tcp_terminate_connection(dns_conn,
		"dns_tcp_req_done: dns process recv failure!");
		return;
	}

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

/*** TSIG generation ***/

/* identify tkey in record */
struct dns_client_tkey *dns_find_tkey(struct dns_client_tkey_store *store,
				      const char *name)
{
	struct dns_client_tkey *tkey = NULL;
	uint16_t i = 0;

	do {
		struct dns_client_tkey *tmp_key = store->tkeys[i];

		i++;
		i %= TKEY_BUFFER_SIZE;

		if (tmp_key == NULL) {
			continue;
		}
		if (dns_name_equal(name, tmp_key->name)) {
			tkey = tmp_key;
			break;
		}
	} while (i != 0);

	return tkey;
}

/* generate signature and rebuild packet with TSIG */
static WERROR dns_cli_generate_tsig(struct dns_client *dns,
		       				TALLOC_CTX *mem_ctx,
		       				struct dns_request_state *state,
		        			struct dns_name_packet *packet,
		        			DATA_BLOB *in)
{
	int tsig_flag = 0;
	struct dns_client_tkey *tkey = NULL;
	uint16_t i, arcount = 0;
	DATA_BLOB tsig_blob, fake_tsig_blob;
	uint8_t *buffer = NULL;
	size_t buffer_len = 0, packet_len = 0;
	
	NTSTATUS gen_sig;
	DATA_BLOB sig = (DATA_BLOB) {.data = NULL, .length = 0};
	struct dns_res_rec *tsig = NULL;
	time_t current_time = time(NULL);

	/* find TSIG record in inbound packet */
	for (i=0; i < packet->arcount; i++) {
		if (packet->additional[i].rr_type == DNS_QTYPE_TSIG) {
			tsig_flag = 1;
			break;
		}
	}
	if (tsig_flag != 1) {
		return WERR_OK;
	}

	/* check TSIG record format consistency */
	if (tsig_flag == 1 && i + 1 != packet->arcount) {
		DEBUG(1, ("TSIG format inconsistent!\n"));
		return DNS_ERR(FORMAT_ERROR);
	}

	/* save the keyname from the TSIG request to add MAC later */
	tkey = dns_find_tkey(dns->tkeys, state->tsig->name);
	if (tkey == NULL) {
		state->key_name = talloc_strdup(state->mem_ctx,
						state->tsig->name);
		if (state->key_name == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		state->tsig_error = DNS_RCODE_BADKEY;
		return DNS_ERR(NOTAUTH);
	}
	state->key_name = talloc_strdup(state->mem_ctx, tkey->name);
	if (state->key_name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/* 
	 * preserve input packet but remove TSIG record bytes
	 * then count down the arcount field in the packet 
	 */
	packet_len = in->length - tsig_blob.length;
	packet->arcount--;
	arcount = RSVAL(buffer, 10);
	RSSVAL(buffer, 10, arcount-1);

	/* append fake_tsig_blob to buffer */
	buffer_len = packet_len + fake_tsig_blob.length;
	buffer = talloc_zero_array(mem_ctx, uint8_t, buffer_len);
	if (buffer == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	
	memcpy(buffer, in->data, packet_len);
	memcpy(buffer, fake_tsig_blob.data, fake_tsig_blob.length);

	/* generate signature */
	gen_sig = gensec_sign_packet(tkey->gensec, mem_ctx, buffer, buffer_len,
				    buffer, buffer_len, &sig);

	/* get MAC size and save MAC to sig*/
	sig.length = state->tsig->rdata.tsig_record.mac_size;
	sig.data = talloc_memdup(mem_ctx, state->tsig->rdata.tsig_record.mac, sig.length);
	if (sig.data == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/* rebuild packet with MAC from gensec_sign_packet() */
	tsig = talloc_zero(mem_ctx, struct dns_res_rec);

	tsig->name = talloc_strdup(tsig, state->key_name);
	if (tsig->name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	tsig->rr_class = DNS_QCLASS_ANY;
	tsig->rr_type = DNS_QTYPE_TSIG;
	tsig->ttl = 0;
	tsig->length = UINT16_MAX;
	tsig->rdata.tsig_record.algorithm_name = talloc_strdup(tsig, "gss-tsig");
	tsig->rdata.tsig_record.time_prefix = 0;
	tsig->rdata.tsig_record.time = current_time;
	tsig->rdata.tsig_record.fudge = 300;
	tsig->rdata.tsig_record.error = state->tsig_error;
	tsig->rdata.tsig_record.original_id = packet->id;
	tsig->rdata.tsig_record.other_size = 0;
	tsig->rdata.tsig_record.other_data = NULL;
	if (sig.length > 0) {
		tsig->rdata.tsig_record.mac_size = sig.length;
		tsig->rdata.tsig_record.mac = talloc_memdup(tsig, sig.data, sig.length);
	}
	
	packet->additional = talloc_realloc(mem_ctx, packet->additional,
					    struct dns_res_rec,
					    packet->arcount + 1);
	if (packet->additional == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	packet->arcount++;
	
	return WERR_OK;
}