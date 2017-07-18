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

/* make a copy of the original tsig record
 * with null rdata values (for future test purposes)
 */
static WERROR dns_empty_tsig(TALLOC_CTX *mem_ctx,
					struct dns_res_rec *orig_record,
					struct dns_res_rec *empty_record)
{
	/* see /libprc/idl/dns.idl for PIDL tsig definition */
	empty_record->name = talloc_strdup(mem_ctx, orig_record->name);
	empty_record->rr_type = orig_record->rr_type;
	empty_record->rr_class = orig_record->rr_class;
	empty_record->ttl = orig_record->ttl;
	empty_record->length = orig_record->length;
	
	/* tsig rdata field in the new record */	
	empty_record->rdata.tsig_record.algorithm_name = talloc_strdup(mem_ctx, NULL);
	empty_record->rdata.tsig_record.time_prefix = NULL;
	empty_record->rdata.tsig_record.time = NULL;
	empty_record->rdata.tsig_record.fudge = NULL;
	empty_record->rdata.tsig_record.mac_size = NULL;
	empty_record->rdata.tsig_record.mac = talloc_memdup(mem_ctx, NULL, NULL);
	empty_record->rdata.tsig_record.original_id = NULL;
	empty_record->rdata.tsig_record.error = NULL;
	empty_record->rdata.tsig_record.other_size = NULL;
	empty_record->rdata.tsig_record.other_data = talloc_memdup(mem_ctx, NULL, NULL);

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

/* generate signature */
static WERROR dns_cli_generate_sig(struct dns_client *dns,
		       				TALLOC_CTX *mem_ctx,
		       				struct dns_request_state *state,
		        			struct dns_name_packet *packet,
		        			DATA_BLOB *in)
{
	NTSTATUS gen_sig;
	uint16_t i, arcount = 0;
	DATA_BLOB tsig_blob, fake_tsig_blob, sig;
	uint8_t *buffer = NULL;
	size_t buffer_len = 0, packet_len = 0;
	struct dns_client_tkey *tkey = NULL;

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

	/* preserve input packet but remove tsig record bytes */
	packet_len = in->length - tsig_blob.length;
	packet->arcount--;

	/* append fake_tsig_blob to buffer */
	buffer_len = packet_len + fake_tsig_blob.length;
	buffer = talloc_zero_array(mem_ctx, uint8_t, buffer_len);
	if (buffer == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	
	memcpy(buffer, in->data, packet_len);
	memcpy(buffer + packet_len, fake_tsig_blob.data, fake_tsig_blob.length);

	/* generate signature */
	gen_sig = gensec_sign_packet(tkey->gensec, mem_ctx, buffer, buffer_len,
				    buffer, buffer_len, &sig);

	/* get MAC size and save MAC to sig*/
	sig.length = state->tsig->rdata.tsig_record.mac_size;
	sig.data = talloc_memdup(mem_ctx, state->tsig->rdata.tsig_record.mac, sig.length);
	if (sig.data == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/* count down the arcount field in the buffer */
	arcount = RSVAL(buffer, 10);
	RSSVAL(buffer, 10, arcount-1);

	return WERROR;