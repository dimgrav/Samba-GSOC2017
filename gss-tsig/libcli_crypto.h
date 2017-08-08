/* GSS-TSIG client-side DNS structures and utilites.
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

#ifndef __DNS_CLIENT_H__
#define __DNS_CLIENT_H__

#include "librpc/gen_ndr/dns.h"
#include "librpc/gen_ndr/ndr_dnsp.h"

/* trying to wrap signature generation here, could use some help */

/* error handling */
uint8_t werr_to_dns_err(WERROR werr);
#define DNS_ERR(err_str) WERR_DNS_ERROR_RCODE_##err_str

/* client structures */
/* I am not sure if this is correct, does the client use dns server zones? */
struct dns_client_zone {
	struct dns_client_zone *prev, *next;
	const char *name;
	struct ldb_dn *dn;
};

struct dns_client {
	struct ldb_context *samdb;
	struct dns_client_zone *zones;
	struct dns_client_tkey_store *tkeys;
	struct cli_credentials *client_credentials;
	uint16_t max_payload;
};

struct dns_request_state {
	TALLOC_CTX *mem_ctx;
	uint16_t flags;
	bool authenticated;
	bool sign;
	char *key_name;
	struct dns_res_rec *tsig;
	uint16_t tsig_error;
};

/* transaction key */
#define TKEY_BUFFER_SIZE 128

struct dns_client_tkey {
	const char *name;
	enum dns_tkey_mode mode;
	const char *algorithm;
	struct auth_session_info *session_info;
	struct gensec_security *gensec;
	bool complete;
};

struct dns_client_tkey_store {
	struct dns_client_tkey **tkeys;
	uint16_t next_idx;
	uint16_t size;
};

struct dns_client_tkey *dns_find_tkey(struct dns_client_tkey_store *store,
				      const char *name)

bool dns_name_equal(const char *name1, const char *name2);

/* make empty tsig rdata packet copy */
WERROR dns_empty_tsig(TALLOC_CTX *mem_ctx,
					struct dns_res_rec *orig_record,
					struct dns_res_rec *empty_record);

/* generate signed packet */
WERROR dns_cli_generate_sig(struct dns_client *dns,
		       TALLOC_CTX *mem_ctx,
		       struct dns_name_packet *packet,
		       struct dns_request_state *state,
		       DATA_BLOB *in);

#endif /* __DNS_CLIENT_H__ */
