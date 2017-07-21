/* TCP client-side DNS structures.
 * 
 * --WORK IN PROGRESS--
 *
 * Copyright (C) 2017 Dimitrios Gravanis
 * 
 * Based on the existing work onSamba Unix SMB/CIFS implementation by
 * Kai Blin Copyright (C) 2011, Stefan Metzmacher Copyright (C) 2014.
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

#ifndef __LIBTCP_H__
#define __LIBTCP_H__

#include "source4/dns_server/dns_server.h"
#include "source4/dns_server/dnsserver_common.h"
#include "lib/tsocket/tsocket.h"

/** dns tcp definitions **/
struct tsocket_address;

struct dns_socket {
	struct dns_server *dns;
	struct tsocket_address *local_address;	
};

struct dns_tcp_request_state {
	struct tevent_context *ev;
	struct tstream_context *stream;
	size_t v_count;
	uint32_t *reply;
	size_t reply_len;
};

struct dns_tcp_connection {
	struct stream_connection *conn;
	struct dns_socket *dns_socket;
	struct tstream_context *tstream;
	struct tevent_queue *send_queue;
};

struct dns_tcp_call {
	struct dns_tcp_connection *dns_conn;
	DATA_BLOB in;
	DATA_BLOB out;
	uint8_t out_hdr[4];
	struct iovec out_iov[2];
};

/* dns tcp request buffer */
struct tevent_req *dns_tcp_req_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *server_addr_string,
					struct iovec *vector,
					size_t count);

/* dns tcp response */
int dns_tcp_req_recv(struct tevent_req *req,
			 TALLOC_CTX *mem_ctx,
			 uint8_t **reply,
			 size_t *reply_len);

#endif /*__LIBTCP_H__*/
