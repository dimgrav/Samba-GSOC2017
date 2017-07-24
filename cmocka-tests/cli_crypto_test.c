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


#define group_test_setup()

/* test suite */

/* 
 * error codes
 *  0 -	success
 * -1 -	failure
 */
static int empty_sig_test(TALLOC_CTX *mem_ctx,
					struct dns_res_rec *orig_record,
					struct dns_res_rec *empty_record)
{
	/* pending */
	int status;

	expect_memory(dns_empty_tsig, orig_record, mem_ctx, sizeof(dns_res_rec));
	expect_memory(dns_empty_tsig, empty_record, mem_ctx, sizeof(dns_res_rec));

	will_return(dns_empty_tsig, WERR_OK);

	if (status != 0) {
		/* code */
		return -1;
	}

	return 0;
}

/* 
 * error codes
 *  0 -	success
 * -1 -	failure
 */
static int tkey_test(struct dns_client_tkey_store *store,
				      const char *name)
{
	/* pending */
	int status;

	will_return(dns_find_tkey, tkey);

	if (status != 0) {
		/* code */
		return -1;
	}

	return 0;
}

/* 
 * error codes
 *  0 -	success
 * -1 -	failure
 */
static int gen_tsig_test(struct dns_client *dns,
		       				TALLOC_CTX *mem_ctx,
		       				struct dns_request_state *state,
		        			struct dns_name_packet *packet,
		        			DATA_BLOB *in)
{
	/* pending */
	int status;

	will_return(dns_cli_generate_tsig, WERROR);

	if (status != 0)
	{
		/* code */
		return -1;
	}

	return 0;
}

/* run test suite */
int main(void)
{
	return cmocka_run_group_tests(tests, NULL, NULL);
}