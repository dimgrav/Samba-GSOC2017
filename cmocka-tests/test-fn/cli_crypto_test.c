/* Tests GSS-TSIG client-side handling for signed packets.
 * 
 * Copyright 2017 (c) Dimitrios Gravanis
 *
 * Uses cmocka C testing API.
 * Copyright 2013 (c) Andreas Schneider <asn@cynapses.org>
 *                    Jakub Hrozek <jakub.hrozek@gmail.com>
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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "libcli/dns/cli-fn/client_crypto.c"


/** test gss-tsig functionality **/

/* helper struct functions */
static struct dns_res_rec *test_record(void) {

	TALLOC_CTX *mem_ctx;
	struct dns_res_rec *test_rec;
	test_rec->name = "TEST_RECORD";
	test_rec->rr_type = DNS_QTYPE_TSIG;
	test_rec->rr_class = DNS_QCLASS_ANY;
	test_rec->ttl = 0;
	test_rec->length = UINT16_MAX;
	/* rdata */
	test_rec->rdata.tsig_record.algorithm_name = "gss-tsig";
	test_rec->rdata.tsig_record.time_prefix = 0;
	test_rec->rdata.tsig_record.time = 0;
	test_rec->rdata.tsig_record.fudge = 300;
	test_rec->rdata.tsig_record.mac_size = UINT16_MAX;
	test_rec->rdata.tsig_record.mac = NULL;
	test_rec->rdata.tsig_record.original_id = UINT16_MAX;
	test_rec->rdata.tsig_record.error = UINT16_MAX;
	test_rec->rdata.tsig_record.other_size = 0;
	test_rec->rdata.tsig_record.other_data = NULL;

	return test_rec;
};

static struct dns_client_tkey *test_tkey_name(void) {
	
	struct dns_client_tkey *test_tkey = NULL;
	test_tkey->name = "TEST_TKEY";

	return test_tkey;
};

/* calls fail() if assertions are false */
static void tkey_test(void **state)
{
	struct dns_client_tkey_store *test_store;
	const char *test_name = "TEST_TKEY";
	
	struct dns_client_tkey *testing;
	struct dns_client_tkey *verifier;

	testing = test_tkey_name();
	verifier  = dns_find_cli_tkey(test_store, test_name);

	assert_non_null(testing);
	assert_non_null(verifier);
	assert_string_equal(testing->name, verifier->name);
	
	TALLOC_FREE(testing);
	TALLOC_FREE(verifier);
	return;
}

/* calls fail() if test_werr not in werr_set */
static void gen_tsig_test(void **state)
{
	TALLOC_CTX *mem_ctx;
	DATA_BLOB *in_test = {NULL, SIZE_MAX};
	
	struct dns_client *test_client;
	test_client->samdb = NULL;
	test_client->zones = NULL;
	test_client->tkeys = NULL;
	test_client->client_credentials = NULL;
	test_client->max_payload = UINT16_MAX;
	
	struct dns_request_cli_state *test_state;
	test_state->flags = UINT16_MAX;
	test_state->authenticated = true;
	test_state->sign = true;
	test_state->key_name = "TKEY_NAME";
	test_state->tsig->name = "TSIG_RECORD";
	test_state->tsig->rr_type = DNS_QTYPE_TSIG;
	test_state->tsig->rr_class = DNS_QCLASS_ANY;
	test_state->tsig->ttl = 0;
	test_state->tsig->length = UINT16_MAX;
	test_state->tsig_error = UINT16_MAX;
	
	struct dns_name_packet *test_packet;
	test_packet->id = UINT16_MAX;
	test_packet->qdcount = UINT16_MAX;
	test_packet->ancount = UINT16_MAX;
	test_packet->nscount = UINT16_MAX;
	test_packet->arcount = UINT16_MAX;

	/* test error codes */
	WERROR test_werr = dns_cli_generate_tsig(test_client, mem_ctx,
								test_state, test_packet, in_test);

	/* expected WERROR output */
	assert_true(W_ERROR_IS_OK(test_werr));
	assert_true(W_ERROR_EQUAL(WERR_NOT_ENOUGH_MEMORY, test_werr));
	assert_true(W_ERROR_EQUAL(DNS_ERR(FORMAT_ERROR), test_werr));
	assert_true(W_ERROR_EQUAL(DNS_ERR(NOTAUTH), test_werr));

	TALLOC_FREE(mem_ctx);
	return;
}

/* run test suite */
int main(void)
{
	/* tests structure */
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(empty_sig_test),
		cmocka_unit_test(tkey_test),
		cmocka_unit_test(gen_tsig_test),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}