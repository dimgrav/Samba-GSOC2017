/* DNS UDP/TCP send/recv wrapping with TSIG generation.
 *
 * --WORK IN PROGRESS--
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

#include <tevent.h>
#include "replace.h"
#include "system/network.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/dns/libdns.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/samba_util.h"
#include "libcli/util/error.h"
#include "librpc/gen_ndr/dns.h"
#include "tcp-cli/libtcp.h"
#include "includes.h"
#include "lib/crypto/hmacmd5.h"
#include "system/network.h"
#include "libcli/util/ntstatus.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "gss-tsig/libtsig.h"
#include <string.h>
#include "libwrap.h"

/* wrap dns udp/tcp req send/recv() and tsig generation functions */

/* udp */
tevent_req *__wrap_udp_req_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
					const char *server_addr_string, const uint8_t *query, size_t query_len)
{
	return dns_udp_request_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *server_addr_string,
					const uint8_t *query,
					size_t query_len);
}

int __wrap_udp_req_recv(struct tevent_req *subreq, struct tevent_req *req,
			 		TALLOC_CTX *mem_ctx, uint8_t **reply, size_t *reply_len)
{
	void dns_udp_request_get_reply(tevent_req *subreq);

	void dns_udp_request_done(tevent_req *subreq);

	return dns_udp_request_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				uint8_t **reply, size_t *reply_len);
}

/* tcp */
tevent_req *__wrap_tcp_req_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
					const char *server_addr_string, struct iovec *vector, size_t count)
{
	return dns_tcp_req_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *server_addr_string,
					struct iovec *vector,
					size_t count);
}

int __wrap_tcp_req_recv(struct tevent_req *subreq, struct tevent_req *req,
			 		TALLOC_CTX *mem_ctx, uint8_t **reply, size_t *reply_len)
{
	void dns_tcp_req_recv_reply(tevent_req *subreq);

	void dns_tcp_req_done(tevent_req *subreq);

	return dns_tcp_req_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx, 
				uint8_t **reply, size_t *reply_len);
}

/* tsig gen */
WERROR __wrap_tcp_cli_tsig_gen(struct dns_client_tkey_store *store, const char *name,
					struct dns_client *dns, TALLOC_CTX *mem_ctx,
		       		struct dns_request_state *state, struct dns_name_packet *packet,
		        	DATA_BLOB *in)
{
	struct dns_client_tkey *dns_find_tkey(struct dns_client_tkey_store *store,
				    const char *name);

	return dns_cli_generate_tsig(struct dns_client *dns, TALLOC_CTX *mem_ctx,
		       		struct dns_request_state *state, struct dns_name_packet *packet,
		        	DATA_BLOB *in);
}
