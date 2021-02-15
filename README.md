# StatZone

[![Build Status][1]][2]

StatZone is a DNS zone file analyzer targeted at TLD zones.

After analyzing a zone, it returns counts for: IPv4 and IPv6 glue records,
NS records (total and uniques), DS records, DNSSEC signed domains, IDNs
domains, and total number of domains.

It is currently used to generate TLD Zone File Statistics on [StatDNS][3].

StatZone is written with security in mind and is running sandboxed on OpenBSD
(using pledge). Experimental seccomp support is available for selected
architectures and can be enabled by setting the `ENABLE_SECCOMP` variable
to `1` when invoking CMake. It has also been extensively fuzzed using AFL
and Honggfuzz.

## Dependencies

StatZone uses the CMake build system and requires uthash header files.

## Building

	mkdir build
	cd build
	cmake ..
	make

StatZone has been successfully built and tested on OpenBSD and Linux with
both Clang and GCC.

## Usage

	statzone [-hv] zonefile

If file is a single dash (`-'), statzone reads from the standard input.

The options are as follows:

	-h	Display usage.
	-v	Display version.

StatZone outputs results to **stdout**.

TLD zone files for .arpa can be found on [Internic FTP site][4], .se and
.nu zones are available through AXFR at zonedata.iis.se.

## Features

Currently implemented features:

- Counting IPv4 and IPv6 glue
- Counting name servers (total and unique)
- Counting DS records
- Counting DNSSEC signed domains
- Counting IDNs domains
- Counting domains

## License

StatZone is released under the BSD 2-Clause license. See `LICENSE` file for
details.

## Author

StatZone is developed by Frederic Cambus.

- Site: https://www.cambus.net

## Resources

GitHub: https://github.com/fcambus/statzone

[1]: https://api.travis-ci.org/fcambus/statzone.png?branch=master
[2]: https://travis-ci.org/fcambus/statzone
[3]: https://www.statdns.com
[4]: https://www.internic.net/domain/
