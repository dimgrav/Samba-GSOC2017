/* Tests GSS-TSIG client-side handling for signed packets.
 * 
 * --WORK IN PROGRESS--
 *
 * Copyright 2017 (c) Dimitrios Gravanis
 *
 * Uses cmocka C testing API.
 * Copyright 2013 (c) Andreas Schneider <asn@cynapses.org>
 *                    Jakub Hrozek <jakub.hrozek@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

#include "includes.h"
#include "lib/crypto/hmacmd5.h"
#include "system/network.h"
#include "libcli/util/ntstatus.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "libcli_crypto.h"

static const struct dns_res_rec *test_record(TALLOC_CTX *mem_ctx) {

	struct dns_res_rec *test_rec;
	/* unsure about talloc_set_name_const() here
	 * is there something more apropriate in talloc for
	 * assigning a specific string as a dns_res_rec->name?
	 */
	test_rec->name = talloc_set_name_const(mem_ctx, "TEST_RECORD");
	test_rec->rr_type = DNS_QTYPE_TSIG;
	test_rec->rr_class = DNS_QCLASS_ANY;
	test_rec->ttl = 0;
	test_rec->length = UINT16_MAX;
	/* rdata */
	test_rec->rdata.tsig_record.algorithm_name = talloc_set_name_const(mem_ctx, "ALG_NAME");
	test_rec->rdata.tsig_record.time_prefix = 0;
	test_rec->rdata.tsig_record.time = current_time;
	test_rec->rdata.tsig_record.fudge = 300;
	test_rec->rdata.tsig_record.mac_size = UINT16_MAX;
	test_rec->rdata.tsig_record.mac = NULL;
	test_rec->rdata.tsig_record.original_id = UINT16_MAX;
	test_rec->rdata.tsig_record.error = UINT16_MAX;
	test_rec->rdata.tsig_record.other_size = 0;
	test_rec->rdata.tsig_record.other_data = NULL;

	return test_rec;
};

static const struct dns_client_tkey *test_tkey_name() {
	
	struct dns_client_tkey *test_tkey = NULL;
	test_tkey->name = "TEST_TKEY";

	return test_tkey;
};

/* test suite */

/* 
 * calls fail() if assert_memory_equal() is false
 * error codes
 *  0 : test completed succesfully
 * -1 : record inconsistent/not null
 * -2 : wrong WERROR output
 */
static int empty_sig_test(void **state)
{
	/* pending */
	WERROR werror;
	struct dns_res_rec *orig_record = test_record(mem_ctx);
	struct dns_res_rec *empty_record = NULL;
	assert_memory_equal(orig_record, empty_record, sizeof(dns_res_rec));

	/* this should work for checking the entire tsig rdata field */
	if (empty_record->rdata.tsig_record != NULL) {
		return -1;
	}
	
	werror = dns_empty_tsig(mem_ctx, orig_record, empty_record);
	if (werror != WERR_OK) {
		return -2;
	}

	TALLOC_FREE(orig_record);
	TALLOC_FREE(empty_record);
	return 0;
}

/* 
 * error codes
 *  0 :	success: tkey name found in record and returned
 * -1 :	failure: tkey name not found
 */
static int tkey_test(void **state)
{
	/* pending */
	struct dns_client_tkey_store *test_store;
	const char *test_name = "TEST_TKEY";
	
	struct dns_client_tkey *testing = test_tkey_name();
	struct dns_client_tkey *verifier = dns_find_tkey(test_store, test_name);

	if (testing->name != verifier->name) {
		return -1;
	}

	return 0;
}

/* 
 * error codes
 *  0 -	success: packet signed with MAC and rebuilt
 * -1 -	failure: failed to rebuild packet
 */
static int gen_tsig_test(void **state)
{
	/* incomplete declarations */
	TALLOC_CTX *mem_ctx;
	DATA_BLOB in_test = (DATA_BLOB) {.data = NULL, .length = SIZE_MAX};
	struct dns_client *test_client;
	struct dns_request_state *test_state;
	struct dns_name_packet *test_packet;

	/* pending */

	/* test for TSIG search in packet */
	WERROR w_tsig_found = dns_cli_generate_tsig(test_client, mem_ctx,
									test_state, test_packet, in_test);
	if (w_tsig_found != WERR_OK)
	{
		/* code */
		return -1;
	}
	
	return 0;
}

/* run test suite */
int main(void)
{
	/* test structure */
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(empty_sig_test);
		cmocka_unit_test(tkey_test);
		cmocka_unit_test(gen_tsig_test);	
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}