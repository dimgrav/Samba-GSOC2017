/* DNS TCP send/recv wrap library with TSIG generation.
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

#ifndef __WRAP_DNS_TCP__
#define __WRAP_DNS_TCP__

#include "libcli/dns/libdns_tcp.h"
#include "libcli/dns/libcli_crypto.h"

/* to hide parameter types, do I have to define them all separately? */
tevent_req *__wrap_tcp_req_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
					const char *server_addr_string, struct iovec *vector, size_t count);

int __wrap_tcp_req_recv(struct tevent_req *subreq, struct tevent_req *req,
			 		TALLOC_CTX *mem_ctx, uint8_t **reply, size_t *reply_len);

WERROR __wrap_tcp_cli_tsig_gen(struct dns_client_tkey_store *store, const char *name,
					struct dns_client *dns, TALLOC_CTX *mem_ctx,
		       		struct dns_request_state *state, struct dns_name_packet *packet,
		        	DATA_BLOB *in);

#endif /* __WRAP_DNS_TCP__ */