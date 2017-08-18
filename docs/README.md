# Client-side DNS call handling with GSS-TSIG
### Unix SMB/CIFS implementation
### Dimitrios Gravanis (C) 2017
### Based on existing work by Samba Team

--------------------------------------------------------
About
--------------------------------------------------------

***WORK IN PROGRESS***

For the Samba AD DC, libcli/dns is a library that allows the handling of DNS 
calls (send/receive requests) and generates GSS-TSIG type ecryption signature 
for signed packets, to accomodate encrypted client-server communication.

It consists of its respective function and structure libraries, that provide 
definitions for client-side functionality.

Tests suites are also available, that test individual features of cli_dns.c

--------------------------------------------------------
Content listing and descriptions
--------------------------------------------------------

1. cli-fn

	* client_crypto.c: GSS-TSIG client-side handling for signed packets
	* dns_tcp.c: TCP client-side DNS call handling
	* dns_udp.c: Small async DNS library for Samba with socketwrapper support

2. cmocka-tests

	* cli_crypto_test.c: Tests GSS-TSIG client-side handling for signed $
	* dns_tcp_test.c: Tests TCP client-side DNS call handling
	* dns_udp_test.c: Tests UDP client-side DNS call handling

3. cli_dns.c: DNS UDP/TCP call handler with socketwrapper support and TSIG generation

4. dns.h: Internal DNS query structures

5. libtcp.h: TCP client-side DNS structures

6. libtsig.h: GSS-TSIG client-side DNS structures and utilites

7. libudp.h: Small async DNS library for Samba with socketwrapper support

8. libwrap.h: DNS UDP/TCP send/recv wrap library with TSIG generation

9. wrap_cli.c: DNS UDP/TCP send/recv wrapping with TSIG generation

--------------------------------------------------------
CLI_DNS (with wrapper support)
--------------------------------------------------------

Handles TCP and UDP requests.

The client may use either TCP or UDP protocols to send a DNS name request to
the server, then handle the reception of the appropriate server response.

Features:

* UDP request send/receive
* TCP request send/receive
* GSS-TSIG generation
* DNS name packet parsing and signing

The library consists of cli_dns.c, that includes functions, and dns.h, libtcp.h, 
libtsig.h, libudp.h, that provide declarations, definitions and structures.

### Wrapping
wrap_cli.c provides multiple wrapping of the above functionality, to hide buffer
creation, DNS packet parsing and signature generation. Definitions of the wrapped
functions are provided in libwrap.h.
