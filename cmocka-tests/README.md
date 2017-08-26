## README: test suites

***WORK IN PROGRESS***

*Test suite cli_tests.c is not functional and currently NOT incorporated in Samba/wscript*/

Tests for the client features are divided in four different test suites:

*	cli_crypto_test: transaction key name search and GSS-TSIG signature generation
*	dns_tcp_test: individual DNS TCP send/receive request packet test
*	dns_udp_test: individual DNS UDP send/receive request packet test
*	cli_tests: complete test suite for libcli/dns/cli_dns.c

*See cli-fn for corresponding libraries*

### Configure and Build complete test suite

The Samba top-level wscript and wscript_build have been modified to recursively implement test suites in 
Samba builds. Running `$ waf configure && waf` in Samba top-level directory, takes care of creating the 
test executable and incorporating it during the building process.

### Configure and Build individual test suites

You can build and incorporate individual tests in Samba builds, by configuring Samba with the "ENABLE_SELFTEST" 
option:

`$ ./configure --enable-selftest`

### Configure and Build individual test suites (standalone)

Samba contributors, or anyone interested in the specific code, may wish to build the individual tests for 
feature testing and/or other development purposes. To do so:

In dns/cmocka-tests/test-fn/:
```
$ waf configure

$ waf
```
*default build directory is set to cmocka-tests/build-tests*

To clean "leftovers":

```
$ waf clean

$ waf distclean
```

