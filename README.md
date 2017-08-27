# Google Summer of Code 2017
### Project: improve libcli/dns
### Dimitrios Gravanis (C) 2017
### Organization: Samba

--------------------------------------------------------
Description
--------------------------------------------------------

Samba comes with its own asynchronous DNS parser framework developed for the internal DNS server. Basic calls have been implemented for a client-side library as well, but a more fleshed out implementation would be needed. The goal of this project is to implement more high-level calls handling DNS requests, such as UDP/TCP switchover and client-side GSS-TSIG cryptography. A test suite excercising all the functions is required and can be used to cross-check and complement the existing DNS server tests already shipped by Samba. This testsuite should use cmocka.

* Difficulty: Medium
* Language(s): C
* Mentors: Kai Blin, David Disseldorp
* Student: Dimitris Gravanis

--------------------------------------------------------
Important information
--------------------------------------------------------

This repository serves as a "mirror" to [dimgrav/samba fork](https://github.com/dimgrav/samba/tree/master/libcli/dns), in order to clearly reflect my personal work during the duration of GSoC 2017, for the Samba Active Directory/Domain Controller.

The developed code is ***NOT*** a standalone feature and requires integration to the rest of the Samba AD/DC source code to run.

The code patches are currently under review by Samba Team. To build Samba including the new code, please visit the fork listed in the "Links" section and clone it to your system.

--------------------------------------------------------
Links
--------------------------------------------------------

Samba fork with the integrated new code can be found [here](https://github.com/dimgrav/samba)

For more information on the project goals, read the GSoC proposal [here](https://summerofcode.withgoogle.com/projects/#6642229069217792).

The project timeline and development journal is documented in its dedicated [blogspot](https://dimgrav.blogspot.gr/).

Project wiki page in [Samba Wiki](https://wiki.samba.org/index.php/SoC/2017#Improve_libcli.2Fdns).
