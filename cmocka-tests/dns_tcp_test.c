/* Tests TCP client-side DNS call handling.
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

#include "replace.h"
#include "system/network.h"
#include <tevent.h>
#include "lib/tsocket/tsocket.h"
#include "libcli/dns/libdns.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/samba_util.h"
#include "libcli/util/error.h"
#include "librpc/gen_ndr/dns.h"
#include "libtcp/libtcp.h"

#define DNS_REQUEST_TIMEOUT 2

/* 
 * return codes
 *  0 :	success
 * -1 :	failure
 */
static int test_req_send(void **state)
{
	/* incomplete */
	TALLOC_CTX *mem_ctx;
	struct tevent_context *test_ev;
	const char *test_server_addr_string;
	struct iovec *test_vector;
	size_t test_count;

	/* pending */
	return 0;
}

/* 
 * return codes
 *  0 :	success
 * -1 :	failure
 */
static int test_req_recv_reply(void **state)
{
	/* pending */
	return 0;
}

/* 
 * return codes
 *  0 :	success
 * -1 :	failure
 */
static int test_req_done(void **state)
{
	/* pending */
	return 0;
}

/* 
 * return codes
 *  0 :	(success) request received
 * -1 :	failed to receive request
 */
static int test_req_recv(void **state)
{
	/* incomplete */
	struct tevent_req *test_req;
	TALLOC_CTX *mem_ctx;
	uint8_t **test_reply;
	size_t *test_reply_len;

	/* pending */
	int test_rcv = dns_tcp_req_recv(test_req, mem_ctx, test_reply, test_reply_len);
	int err;

	if (test_rcv == 0) {
		return 0;
	} else {
		err = -1;
		fprintf(stderr, "Unexpected failure: %s\n", strerror(err));
		return err;
	};
}