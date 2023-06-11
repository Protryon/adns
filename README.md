
# adns

`adns` is an authoritative DNS nameserver written in Rust.

## Motivation

Back in 2016 I wrote [AvunaDNSD](https://github.com/Protryon/AvunaDNSD) which is a C version of `adns` with a few less features. That project was based on [AvunaHTTPD-Java](https://github.com/Protryon/AvunaHTTPD-Java/tree/master/src/org/avuna/httpd/dns) (containing a DNS server) which I wrote in 2015. AvunaDNSD has been the only one of these projects I still used, however it segfaulted about once a year and didn't support RFC2136 for integration with K8S [external-dns](https://github.com/kubernetes-sigs/external-dns). This project was born as a result, almost a decade later -- man I feel old now.

## Features

* Support for standard DNS RR types
* RFC2136 "dyndns" support
* AXFR zone transfers (outbound)
* TSIG authentication for RFC2136 and AXFR zone transfers
* Hot reloadable zones

### Potential Future Features

* DNSSEC support
* More zone providers (AXFR, [sled](https://crates.io/crates/sled), etc)
* Recursive resolver mode