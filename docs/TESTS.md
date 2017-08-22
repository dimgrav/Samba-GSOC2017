## README: test suites

***WORK IN PROGRESS***

Tests for the client features are divided in four different test suites:

*	cli_crypto_test: transaction key name search and GSS-TSIG signature generation
*	dns_tcp_test: individual DNS TCP send/receive request packet test
*	dns_udp_test: individual DNS UDP send/receive request packet test
*	cli_tests: complete test suite for libcli/dns/cli_dns.c

*See cli-fn for corresponding libraries*

### Configure and Build test suites

*Samba uses [Waf](https://waf.io/) for package configuration, building and installation.*

*Check [The Waf Book](https://waf.io/book/#_projects_and_commands) for detailed information and tutorials.*

In dns/cmocka-tests:
`$ waf configure --option`

configure options

```
-o OUT, --out=OUT   build dir for the project

-t TOP, --top=TOP   src dir for the project

--prefix=PREFIX     installation prefix [default: '/usr/local/']

--download          try to download the tools if missing
```

*default build directory is set to cmocka-tests/build-tests*

In dns/cmocka-tests:
`$ waf build`

To clean "leftovers":

```
$ waf clean

$ waf distclean
```
