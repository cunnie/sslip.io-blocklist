# sslip.io-blocklist

This file contains the blocklist used by [nip.io/sslip.io](https://sslip.io), a
DNS service which maps hostnames with an embedded IP address to that IP address
(e.g. `127.0.0.1.nip.io` → `127.0.0.1`). The service is sometimes abused by
phishers, scammers and grifters, hence the need for a blocklist.

When nip.io/sslip.io receives a DNS query for an IP address which appears in
this list, instead of returning the expected IP address, it returns the IP
address of a special webserver, <https://blocked.nip.io>, which warns the user
that the site has been blocked.
