/* TCP client-side DNS structures.
 * 
 * Copyright (C) 2017 Dimitrios Gravanis
 * 
 * Based on the existing work on Samba Unix SMB/CIFS implementation by
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


/** DNS TCP definitions **/
struct tsocket_address;

struct dns_socket {
	struct dns_server *dns;
	struct tsocket_address *local_address;
};

struct dns_tcp_request_state {
	struct tevent_context *ev;
	struct tstream_context **tstream;
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

/** DNS TCP functions **/

/* Send an DNS request to a DNS server via TCP
 *
 *@param mem_ctx        	talloc memory context to use
 *@param ev             	tevent context to use
 *@param server_addr_string address of the server as a string
 *@param query          	dns query to send
 *@param count 				length of the iovector
 *@return tevent_req with the active request or NULL on out-of-memory
 */
struct tevent_req *dns_tcp_req_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *server_addr_string,
					struct iovec *vector,
					size_t count);

/* Receive the DNS response from the DNS server via TCP
 *
 *@param req       tevent_req struct returned from dns_request_send
 *@param mem_ctx   talloc memory context to use for the reply string
 *@param reply     buffer that will be allocated and filled with the dns reply
 *@param reply_len length of the reply buffer
 *@return 0/errno
 */
int dns_tcp_req_recv(struct tevent_req *req,
			 TALLOC_CTX *mem_ctx,
			 uint8_t **reply,
			 size_t *reply_len);

/* Callbacks */
void dns_tcp_req_recv_reply(struct tevent_req *subreq);
void dns_tcp_req_done(struct tevent_req *subreq);

#endif /*__LIBTCP_H__*/