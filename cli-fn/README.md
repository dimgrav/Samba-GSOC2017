## README: features

The individual function libraries that are incorporated in cli_dns.c, 
to provide client-side DNS call features. Each library comes with a 
corresponding test suite in libcli/dns/cmocka-tests/ directory.

Descriptions

* client_crypto.c: GSS-TSIG client-side handling for signed packets
* dns_tcp.c: TCP client-side DNS call handling
* dns_udp.c: Small async DNS library with socketwrapper support

It is highly recommended that the above libraries will be used for 
adding and testing features in  libcli/dns individually, **BEFORE** 
implementing any changes in libcli/cli_dns.c library.

*Associated headers are found in libcli/dns/*
