/* GSS-TSIG client-side handling for signed packets.
 *
 * --WORK IN PROGRESS--
 *
 * Copyright (C) 2017 Dimitrios Gravanis
 * 
 * Based on the existing Samba Unix SMB/CIFS implementation.
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
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "libcli/util/ntstatus.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "libcli_crypto.h"

/* make a copy of the original tsig record to a new record */
static WERROR dns_copy_tsig(TALLOC_CTX *mem_ctx,
					struct dns_res_rec *orig_record,
					struct dns_res_rec *new_record)
{
	/* see /libprc/idl/dns.idl for PIDL tsig definition */
	new_record->name = talloc_strdup(mem_ctx, orig_record->name);
	new_record->rr_type = orig_record->rr_type;
	new_record->rr_class = orig_record->rr_class;
	new_record->ttl = orig_record->ttl;
	new_record->length = orig_record->length;
	
	/* copy original rdata field to the new record */	
	new_record->rdata.tsig_record.algorithm_name = talloc_strdup(mem_ctx,
							orig_record->rdata.tsig_record.algorithm_name);
	new_record->rdata.tsig_record.time_prefix = orig_record.tsig_record.time_prefix;
	new_record->rdata.tsig_record.time = orig_record.tsig_record.time;
	new_record->rdata.tsig_record.fudge = orig_record->rdata.tsig_record.fudge;
	new_record->rdata.tsig_record.mac_size = orig_record.rdata.tsig_record.mac_size;
	new_record->rdata.tsig_record.mac = talloc_memdup(mem_ctx,
							orig_record->rdata.tsig_record.mac,
							orig_record->rdata.tsig_record.mac_size);
	new_record->rdata.tsig_record.original_id = orig_record->rdata.tsig_record.original_id;
	new_record->rdata.tsig_record.error = orig_record->rdata.tsig_record.error;
	new_record->rdata.tsig_record.other_size = orig_record->rdata.tsig_record.other_size;
	new_record->rdata.tsig_record.other_data = talloc_memdup(mem_ctx,
							orig_record->rdata.tsig_record.other_data,
							orig_record->rdata.tsig_record.other_size);

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

/* validate transaction signature */
WERROR dns_validate_tsig(struct dns_client *dns,
		       		TALLOC_CTX *mem_ctx,
		        	struct dns_request_state *state,
		        	struct dns_name_packet *packet,
		        	DATA_BLOB *in)
{
	num ndr_err_code ndr_err;
	bool found_tsig = false;
	uint16_t i, arcount = 0;
	DATA_BLOB tsig_blob, fake_tsig_blob, sig;
	uint8_t *buffer = NULL;
	size_t buffer_len = 0, packet_len = 0;
	struct dns_client_tkey *tkey = NULL;
	struct dns_fake_tsig_rec *check_rec = talloc_zero(mem_ctx, struct dns_fake_tsig_rec);

	/* Find the first TSIG record in arcount */
	for (i=0; i < packet->arcount; i++) {
		if (packet->additional[i].rr_type == DNS_QTYPE_TSIG) {
			found_tsig = true;
			break;
		}
	}
	if (found_tsig && i + 1 != packet->arcount) {
		DEBUG(1, ("TSIG record not the last additional record!\n"));
		return DNS_ERR(FORMAT_ERROR);
	}
	
	/* sign reply */
	state->sign = true;

	state->tsig = talloc_zero(state->mem_ctx, struct dns_res_rec);
	if (state->tsig == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	packet->arcount--;

	tkey = dns_find_tkey(dns->tkeys, state->tsig->name);
	/*
	 * save the name used in the TSIG error response
	 * save the keyname from the TSIG request
	 */
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

	/* create and validate tsig check record */
	check_rec->name = talloc_strdup(check_rec, tkey->name);
	if (check_rec->name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	check_rec->rr_class = DNS_QCLASS_ANY;
	check_rec->ttl = 0;
	check_rec->algorithm_name = talloc_strdup(check_rec, tkey->algorithm);
	if (check_rec->algorithm_name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	check_rec->time_prefix = 0;
	check_rec->time = state->tsig->rdata.tsig_record.time;
	check_rec->fudge = state->tsig->rdata.tsig_record.fudge;
	check_rec->error = 0;
	check_rec->other_size = 0;
	check_rec->other_data = NULL;

	ndr_err = ndr_push_struct_blob(&tsig_blob, mem_ctx, state->tsig,
		(ndr_push_flags_fn_t)ndr_push_dns_res_rec);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("Failed to push packet: %s!\n",
			  ndr_errstr(ndr_err)));
		return DNS_ERR(SERVER_FAILURE);
	}

	ndr_err = ndr_push_struct_blob(&fake_tsig_blob, mem_ctx, check_rec,
		(ndr_push_flags_fn_t)ndr_push_dns_fake_tsig_rec);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("Failed to push packet: %s!\n",
			  ndr_errstr(ndr_err)));
		return DNS_ERR(SERVER_FAILURE);
	}

	/* preserve input packet but remove tsig record */
	packet_len = in->length - tsig_blob.length;
	/* append fake_tsig_blob to DATA_BLOB */
	buffer_len = packet_len + fake_tsig_blob.length;
	buffer = talloc_zero_array(mem_ctx, uint8_t, buffer_len);
	if (buffer == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	memcpy(buffer, in->data, packet_len);
	memcpy(buffer + packet_len, fake_tsig_blob.data, fake_tsig_blob.length);

	sig.length = state->tsig->rdata.tsig_record.mac_size;
	sig.data = talloc_memdup(mem_ctx, state->tsig->rdata.tsig_record.mac, sig.length);
	if (sig.data == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/* count down the arcount field in buffer */
	arcount = RSVAL(buffer, 10);
	RSSVAL(buffer, 10, arcount-1);

	status = gensec_check_packet(tkey->gensec, buffer, buffer_len,
				    buffer, buffer_len, &sig);
	if (NT_STATUS_EQUAL(NT_STATUS_ACCESS_DENIED, status)) {
		state->tsig_error = DNS_RCODE_BADSIG;
		return DNS_ERR(NOTAUTH);
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Verifying tsig failed: %s\n", nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	state->authenticated = true;
	return WERR_OK;
}

static WERROR dns_tsig_cli_add_mac(TALLOC_CTX *mem_ctx,
				   struct dns_request_state *state,
				   struct dns_name_packet *packet,
				   struct dns_client_tkey *tkey,
				   time_t current_time,
				   DATA_BLOB *_psig)
{
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	DATA_BLOB packet_blob, tsig_blob, sig;
	uint8_t *buffer = NULL;
	uint8_t *p = NULL;
	size_t buffer_len = 0;
	struct dns_fake_tsig_rec *check_rec = talloc_zero(mem_ctx,
			struct dns_fake_tsig_rec);
	size_t mac_size = 0;

	if (check_rec == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/* create and validate check packet buffer */
	check_rec->name = talloc_strdup(check_rec, tkey->name);
	if (check_rec->name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	check_rec->rr_class = DNS_QCLASS_ANY;
	check_rec->ttl = 0;
	check_rec->algorithm_name = talloc_strdup(check_rec, tkey->algorithm);
	if (check_rec->algorithm_name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	check_rec->time_prefix = 0;
	check_rec->time = current_time;
	check_rec->fudge = 300;
	check_rec->error = state->tsig_error;
	check_rec->other_size = 0;
	check_rec->other_data = NULL;

	ndr_err = ndr_push_struct_blob(&packet_blob, mem_ctx, packet,
		(ndr_push_flags_fn_t)ndr_push_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("Failed to push packet: %s!\n",
			  ndr_errstr(ndr_err)));
		return DNS_ERR(SERVER_FAILURE);
	}

	ndr_err = ndr_push_struct_blob(&tsig_blob, mem_ctx, check_rec,
		(ndr_push_flags_fn_t)ndr_push_dns_fake_tsig_rec);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("Failed to push packet: %s!\n",
			  ndr_errstr(ndr_err)));
		return DNS_ERR(SERVER_FAILURE);
	}

	if (state->tsig != NULL) {
		mac_size = state->tsig->rdata.tsig_record.mac_size;
	}

	buffer_len = mac_size;

	buffer_len += packet_blob.length;
	if (buffer_len < packet_blob.length) {
		return WERR_INVALID_PARAMETER;
	}
	buffer_len += tsig_blob.length;
	if (buffer_len < tsig_blob.length) {
		return WERR_INVALID_PARAMETER;
	}

	buffer = talloc_zero_array(mem_ctx, uint8_t, buffer_len);
	if (buffer == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	p = buffer;
	/* add MAC to packet buffer */
	if (mac_size > 0) {
		memcpy(p, state->tsig->rdata.tsig_record.mac, mac_size);
		p += mac_size;
	}

	memcpy(p, packet_blob.data, packet_blob.length);
	p += packet_blob.length;

	memcpy(p, tsig_blob.data, tsig_blob.length);

	status = gensec_sign_packet(tkey->gensec, mem_ctx, buffer, buffer_len,
				    buffer, buffer_len, &sig);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	*_psig = sig;
	return WERR_OK;
}

WERROR dns_cli_sign_tsig(struct dns_client *dns,
		     TALLOC_CTX *mem_ctx,
		     struct dns_request_state *state,
		     struct dns_name_packet *packet,
		     uint16_t error)
{
	// not yet implemented
}