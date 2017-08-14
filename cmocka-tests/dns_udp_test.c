/* Tests UDP client-side DNS call handling.
 * 
 * --WORK IN PROGRESS--
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
#include "foo.c"

#include "replace.h"
#include "system/network.h"
#include <tevent.h>
#include "lib/tsocket/tsocket.h"
#include "libdns.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/samba_util.h"
#include "libcli/util/error.h"
#include "librpc/gen_ndr/dns.h"

#define DNS_REQUEST_TIMEOUT 2

/* test suite */

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

/* run test suite */
int main(void)
{
	/* tests structure */
	const struct CMUnitTest udp_tests[] = {
		cmocka_unit_test(test_request_send);
		cmocka_unit_test(test_request_get_reply);
		cmocka_unit_test(test_request_done);
		cmocka_unit_test(test_request_recv);
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(udp_tests, NULL, NULL);
}
