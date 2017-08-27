/* Tests TCP client-side DNS call handling.
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
#include "libcli/dns/cli-fn/dns_tcp.c"


/** test tcp send/recv functionality **/

/* calls fail() if TCP test_req is NULL */
static void test_req_send(void **state)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *test_ev;
	const char *test_server_addr_string = "TEST_SRVR_ADDR";
	struct iovec *test_vector;
	size_t test_count = SIZE_MAX;

	struct tevent_req *test_req = dns_tcp_req_send(mem_ctx, test_ev,
			test_server_addr_string, test_vector, test_count);

	assert_non_null(test_req);
	TALLOC_FREE(mem_ctx);
	return;
}

/* calls fail() if test_subreq is NULL */
static void test_req_recv_reply(void **state)
{
	struct tevent_req *test_subreq;
	assert_non_null(test_subreq);
	dns_tcp_req_recv_reply(test_subreq);
	return;
}

/* calls fail() if test_subreq is NULL */
static void test_req_done(void **state)
{
	struct tevent_req *test_subreq;
	assert_non_null(test_subreq);
	dns_tcp_req_done(test_subreq);
	return;
}

/* calls fail() if test_rcv is not 0 */
static void test_req_recv(void **state)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_req *test_req;
	uint8_t **test_reply = UINT8_MAX;
	size_t *test_reply_len = SIZE_MAX;

	int test_rcv = dns_tcp_req_recv(test_req, mem_ctx, test_reply, test_reply_len);
	
	assert_int_equal(test_rcv, 0);
	TALLOC_FREE(mem_ctx);
	return;
}

/* run test suite */
int main(void)
{
	/* tests structure */
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_req_send),
		cmocka_unit_test(test_req_recv_reply),
		cmocka_unit_test(test_req_done),
		cmocka_unit_test(test_req_recv),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}