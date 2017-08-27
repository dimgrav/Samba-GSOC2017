/* GSS-TSIG client-side DNS structures and utilites.
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

#ifndef __LIBTSIG_H__
#define __LIBTSIG_H__

#include "librpc/gen_ndr/dns.h"
#include "librpc/gen_ndr/ndr_dnsp.h"


/** error definitions **/
uint8_t werr_to_dns_err(WERROR werr);
#define DNS_ERR(err_str) WERR_DNS_ERROR_RCODE_##err_str

/** client structures **/
struct dns_client_zone {
	struct dns_client_zone *prev, *next;
	const char *name;
	struct ldb_dn *dn;
};

struct dns_client {
	struct task_server *task;
	struct ldb_context *samdb;
	struct dns_client_zone *zones;
	struct dns_client_tkey_store *tkeys;
	struct cli_credentials *client_credentials;
	uint16_t max_payload;
};

struct dns_request_cli_state {
	TALLOC_CTX *mem_ctx;
	uint16_t flags;
	bool authenticated;
	bool sign;
	char *key_name;
	struct dns_res_rec *tsig;
	uint16_t tsig_error;
};

/** transaction key definitions **/
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

/** functions **/

/* Search for DNS key name in record to the expected name
 *
 *@param store 	dns_client_tkey_store to use for name search
 *@param name   name to match
 *@return tkey
 */
struct dns_client_tkey *dns_find_cli_tkey(struct dns_client_tkey_store *store,
				      const char *name);

/* Make a record copy with empty TSIG rdata
 *
 *@param mem_ctx        	talloc memory context to use
 *@param orig_record       	dns_res_rec struct to duplicate
 *@param empty_record		dns_res_rec struct with empty RDATA
 *@return WERR_OK/WERR_NOT_ENOUGH_MEMORY
 */
WERROR dns_empty_tsig(TALLOC_CTX *mem_ctx,
					struct dns_res_rec *orig_record,
					struct dns_res_rec *empty_record);

/* Sign packet and rebuild with TSIG
 *
 *@param dns 		dns_client structure with client internals
 *@param mem_ctx 	talloc memory context to use
 *@param packet 	dns_name_packet that is used
 *@param state 		packet state
 *@param in 		data and length of packet
 *@return WERR_OK/_NOT_ENOUGH_MEMORY/_FORMAT_ERROR/_NOTAUTH
 */
WERROR dns_cli_generate_sig(struct dns_client *dns,
		       TALLOC_CTX *mem_ctx,
		       struct dns_name_packet *packet,
		       struct dns_request_cli_state *state,
		       DATA_BLOB *in);

#endif /* __LIBTSIG_H__ */