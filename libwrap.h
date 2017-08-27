/* DNS UDP/TCP send/recv wrap library with TSIG generation.
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

#ifndef __LIBWRAP_H__
#define __LIBWRAP_H__

/* udp */
struct tevent_req *udp_req_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			const char *server_addr_string, const uint8_t *query, size_t query_len);

int udp_req_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
	uint8_t **reply, size_t *reply_len);

/* tcp */
struct tevent_req *tcp_req_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			const char *server_addr_string, struct iovec *vector, size_t count);

int tcp_req_recv(struct tevent_req *subreq, struct tevent_req *req,
	TALLOC_CTX *mem_ctx, uint8_t **reply, size_t *reply_len);

/* tsig gen */
WERROR tcp_cli_tsig_gen(struct dns_client_tkey_store *store, const char *name,
	   struct dns_client *dns, TALLOC_CTX *mem_ctx,v struct dns_request_state *state, 
	   struct dns_name_packet *packet,	DATA_BLOB *in);

#endif /* __LIBWRAP_H__ */