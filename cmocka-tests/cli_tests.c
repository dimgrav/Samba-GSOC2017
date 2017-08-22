/* Unix SMB/CIFS implementation.
 * 
 * Test suite for:
 * DNS UDP/TCP call handler with socketwrapper support and TSIG generation
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

/* test requirements */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/* DNS call send/recv() */
#include "replace.h"
#include "system/network.h"
#include <tevent.h>
#include "lib/tsocket/tsocket.h"
#include "libcli/dns/libudp.h"
#include "libcli/dns/libtcp.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/samba_util.h"
#include "libcli/util/error.h"
#include "librpc/gen_ndr/dns.h"

/* TSIG generation */
#include "includes.h"
#include "lib/crypto/hmacmd5.h"
#include "libcli/util/ntstatus.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "libcli/dns/libtsig.h"

/** test tcp send/recv functionality **/

/* 
 * return codes
 *  0 :	(success) async tcp request sent
 * -1 :	failed to create tcp request
 */
static int test_req_send(void **state)
{
	/* incomplete */
	TALLOC_CTX *mem_ctx;
	struct tevent_context *test_ev;
	const char *test_server_addr_string = "TEST_SRVR_ADDR";
	struct iovec *test_vector;
	size_t test_count = SIZE_MAX;

	struct tevent_req *test_req = dns_tcp_req_send(mem_ctx, test_ev,
			test_server_addr_string, test_vector, test_count);

	int err;
	/* switch statement used in case more checks need to be added */
	switch (test_req) {
		case NULL:
			err = -1;
			fprintf(stderr, "NULL async TCP request: %s\n", strerror(err));
			return err;
		default:
			return 0;
	};

	TALLOC_FREE(mem_ctx);
}

/* 
 * calls fail() if test_subreq is NULL
 * prints error message to stderr stream
 */
static void test_req_recv_reply(void **state)
{
	/* pending */
	struct tevent_req *test_subreq;
	assert_non_null(test_subreq);
	dns_tcp_req_recv_reply(test_subreq);
	return;
}

/* 
 * calls fail() if test_subreq is NULL
 * prints error message to stderr stream
 */
static void test_req_done(void **state)
{
	/* pending */
	struct tevent_req *test_subreq;
	assert_non_null(test_subreq);
	dns_tcp_req_done(test_subreq);
	return;
}

/* 
 * return codes
 *  0 :	(success) async request received
 * -1 :	failed to receive request
 */
static int test_req_recv(void **state)
{
	/* incomplete */
	struct tevent_req *test_req;
	TALLOC_CTX *mem_ctx;
	uint8_t **test_reply = UINT8_MAX;
	size_t *test_reply_len = SIZE_MAX;

	/* pending */
	int test_rcv = dns_tcp_req_recv(test_req, mem_ctx, test_reply, test_reply_len);
	int err;

	if (test_rcv == 0) {
		return 0;
	} else {
		err = -1;
		fprintf(stderr, "Unexpected req recv failure: %s\n", strerror(err));
		return err;
	};

	TALLOC_FREE(mem_ctx);
}

/** test udp send/recv functionality **/

/* 
 * return codes
 *  0 :	(success) async udp request sent
 * -1 :	failed to create udp request
 */
static int test_request_send(void **state)
{
	/* pending */
	TALLOC_CTX *mem_ctx;
	struct tevent_context *test_ev;
	const char *test_server_addr_string = "TEST_SRVR_ADDR";
	const uint8_t *test_query = UINT8_MAX;
	size_t test_query_len = SIZE_MAX;

	struct tevent_req *test_req = dns_udp_request_send(mem_ctx, test_ev,
			test_server_addr_string, test_query, test_query_len);

	int err;
	if (test_req == NULL)
	{
		err = -1;
		fprintf(stderr, "NULL async UDP request: %s\n", strerror(err));
		return err;
	} else {
		return 0;
	}

	TALLOC_FREE(mem_ctx);
}

/* 
 * calls fail() if test_subreq is NULL
 * prints error message to stderr stream
 */
static void test_request_get_reply(void **state)
{
	/* pending */
	struct tevent_req *test_subreq;
	assert_non_null(test_subreq);
	dns_udp_request_get_reply(test_subreq);
	return;
}

/* 
 * calls fail() if test_subreq is NULL
 * prints error message to stderr stream
 */
static void test_request_done(void **state)
{
	/* pending */
	struct tevent_req *test_subreq;
	assert_non_null(test_subreq);
	dns_udp_request_done(test_subreq);
	return;
}

/* 
 * return codes
 *  0 :	(success) async request received
 * -1 :	failed to receive request
 */
static int test_request_recv(void **state)
{
	/* incomplete */
	struct tevent_req *test_req;
	TALLOC_CTX *mem_ctx;
	uint8_t **test_reply = UINT8_MAX;
	size_t *test_reply_len = SIZE_MAX;

	/* pending */
	int test_rcv = dns_udp_request_recv(test_req, mem_ctx, test_reply, test_reply_len);
	int err;

	if (test_rcv == 0) {
		return 0;
	} else {
		err = -1;
		fprintf(stderr, "Unexpected UDP request recv failure: %s\n", strerror(err));
		return err;
	};

	TALLOC_FREE(mem_ctx);
}

/** test gss-tsig functionality **/

/* helper structs */
static const struct dns_res_rec *test_record(TALLOC_CTX *mem_ctx) {

	struct dns_res_rec *test_rec;
	test_rec->name = "TEST_RECORD";
	test_rec->rr_type = DNS_QTYPE_TSIG;
	test_rec->rr_class = DNS_QCLASS_ANY;
	test_rec->ttl = 0;
	test_rec->length = UINT16_MAX;
	/* rdata */
	test_rec->rdata.tsig_record.algorithm_name = "gss-tsig";
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

static const struct dns_client_tkey *test_tkey_name(void) {
	
	struct dns_client_tkey *test_tkey = NULL;
	test_tkey->name = "TEST_TKEY";

	return test_tkey;
};

/* 
 * calls fail() if assertions are false
 * return codes
 *  0 : (success) test passed
 * -1 : record inconsistent/not null
 * -2 : unexpected WERROR output
 */
static int empty_sig_test(void **state)
{
	/* pending */
	int err;
	WERROR werror;
	struct dns_res_rec *orig_record = test_record(mem_ctx);
	struct dns_res_rec *empty_record = NULL;

	assert_null(empty_record);
	assert_memory_equal(orig_record, empty_record, sizeof(dns_res_rec));

	/* this should work for checking the entire tsig rdata field */
	if (empty_record->rdata.tsig_record != NULL) {
		err = -1;
		fprintf(stderr, "sig_test TSIG consistency error: %s\n", strerror(err));
		return err;
	}
	
	/* check WERROR output */
	werror = dns_empty_tsig(mem_ctx, orig_record, empty_record);
	if (werror != WERR_OK || werror != WERR_NOT_ENOUGH_MEMORY) {
		err = -2;
		fprintf(stderr, "sig_test unexpected WERROR: %s\n", strerror(err));
		return err;
	}

	TALLOC_FREE(orig_record);
	TALLOC_FREE(empty_record);
	return 0;
}

/* 
 * calls fail() if assertions are false
 * return codes
 *  0 : (success) tkey name found in record and returned
 * -1 :	tkey name not found
 */
static int tkey_test(void **state)
{
	/* pending */
	int err;
	struct dns_client_tkey_store *test_store;
	const char *test_name = "TEST_TKEY";
	
	struct dns_client_tkey *testing = test_tkey_name();
	struct dns_client_tkey *verifier = dns_find_cli_tkey(test_store, test_name);

	assert_non_null(testing);
	assert_non_null(verifier);
	assert_memory_equal(testing, verifier, sizeof(dns_client_tkey));

	if (testing->name != verifier->name) {
		err = -1;
		fprintf(stderr, "tkey_test name not found: %s\n", strerror(err));
		return err;
	}

	TALLOC_FREE(testing);
	TALLOC_FREE(verifier);
	return 0;
}

/* 
 * return codes
 *  0 :	(success) packet signed with MAC and rebuilt
 * -1 :	WERROR output (NOMEM)
 * -2 : DNS_ERR output
 * -3 : unexpected output
 */
static int gen_tsig_test(void **state)
{
	/* incomplete declarations */
	TALLOC_CTX *mem_ctx;
	DATA_BLOB in_test = (DATA_BLOB) {.data = NULL, .length = SIZE_MAX};
	
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
	test_state->key_name = "TKEY_NAME"
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
	WERROR test_err = dns_cli_generate_tsig(test_client, mem_ctx,
								test_state, test_packet, in_test);

	int err;
	switch (test_err) {
		case WERR_OK:
			return 0;
		case WERR_NOT_ENOUGH_MEMORY:
			err = -1;
			fprintf(stderr, "gen_tsig WERR_NOMEM: %s\n", strerror(err));
			return err;
		case DNS_ERR(FORMAT_ERROR):
		case DNS_ERR(NOTAUTH):
			err = -2;
			fprintf(stderr, "gen_tsig DNS_ERR: %s\n", strerror(err));
			return err;
		default:
			err = -3;
			fprintf(stderr, "gen_tsig unexpected ERROR: %s\n", strerror(err));
			return err;
	};

	TALLOC_FREE(mem_ctx);
}

/* run test suite */
int main(void)
{
	/* tests structure */
	const struct CMUnitTest client_tests[] = {
		/* tcp tests*/
		cmocka_unit_test(test_req_send);
		cmocka_unit_test(test_req_recv_reply);
		cmocka_unit_test(test_req_done);
		cmocka_unit_test(test_req_recv);
		/* udp tests*/
		cmocka_unit_test(test_request_send);
		cmocka_unit_test(test_request_get_reply);
		cmocka_unit_test(test_request_done);
		cmocka_unit_test(test_request_recv);
		/* gss-tsig tests*/
		cmocka_unit_test(empty_sig_test);
		cmocka_unit_test(tkey_test);
		cmocka_unit_test(gen_tsig_test);
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(client_tests, NULL, NULL);
}