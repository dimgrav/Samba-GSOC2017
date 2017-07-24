/* GSS-TSIG client-side handling for signed packets.
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

#include "includes.h"
#include "lib/crypto/hmacmd5.h"
#include "system/network.h"
#include "libcli/util/ntstatus.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "libcli_crypto.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DNS

/* 
 * make a copy of the original tsig record
 * with null rdata values (for future test purposes)
 * --- probably wrong use of memset(), all fields considered as pointers?  ---
 * will include WERROR handling for t allocations
 */
static WERROR dns_empty_tsig(TALLOC_CTX *mem_ctx,
					struct dns_res_rec *orig_record,
					struct dns_res_rec *empty_record)
{
	/* see /libprc/idl/dns.idl for PIDL tsig definition */
	empty_record->name = talloc_strdup(mem_ctx, orig_record->name);
	W_ERROR_HAVE_NO_MEMORY(empty_record->name);
	empty_record->rr_type = orig_record->rr_type;
	empty_record->rr_class = orig_record->rr_class;
	empty_record->ttl = orig_record->ttl;
	empty_record->length = orig_record->length;
	
	/* empty tsig rdata field in the new record */
	/* the smooth way! */
	empty_record->rdata.tsig_record.algorithm_name = talloc_strdup(mem_ctx, 
							orig_record->rdata.tsig_record.algorithm_name);
	W_ERROR_HAVE_NO_MEMORY(empty_record->rdata.tsig_record.algorithm_name);
	ZERO_STRUCT(empty_record->rdata.tsig_record);

	/* 
	---the long way---
	empty_record->rdata.tsig_record.algorithm_name = talloc_memdup(mem_ctx, 
							orig_record->rdata.tsig_record.algorithm_name, 0);
	memset(empty_record->rdata.tsig_record.time_prefix, 0, sizeof(uint16_t));
	memset(empty_record->rdata.tsig_record.time, 0, sizeof(uint32_t));
	memset(empty_record->rdata.tsig_record.fudge, 0, sizeof(uint16_t));
	memset(empty_record->rdata.tsig_record.mac_size, 0, sizeof(uint16_t));
	empty_record->rdata.tsig_record.mac = talloc_memdup(mem_ctx,
							orig_record->rdata.tsig_record.mac,
							empty_record->rdata.tsig_record.mac_size);
	memset(empty_record->rdata.tsig_record.original_id, 0, sizeof(uint16_t));
	memset(empty_record->rdata.tsig_record.error, 0, sizeof(uint16_t));
	memset(empty_record->rdata.tsig_record.other_size, 0, sizeof(uint16_t));
	empty_record->rdata.tsig_record.other_data = talloc_memdup(mem_ctx,
							orig_record->rdata.tsig_record.other_data,
							empty_record->rdata.tsig_record.other_size);
	*/

	return WERR_OK;
}

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