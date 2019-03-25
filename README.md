# StatZone

[![Build Status][1]][2]

StatZone is a DNS zone file analyzer targeted at TLD zones.

It is currently used to generate TLD Zone File Statistics on [StatDNS][3].

## Dependencies

StatZone uses the CMake build system and requires uthash header files.

## Building

        mkdir build
        cd build
        cmake ..
        make

## Usage

        statzone [-hv] file

If file is a single dash (`-'), statzone reads from the standard input.

Options are:

        -h Display usage
        -v Display version

StatZone outputs results to **stdout**.

Public zones (arpa, root) can be found on: ftp://ftp.internic.net/domain/

## Features

Currently implemented features:

- Counting IPv4 and IPv6 glue
- Counting name servers (total and unique)
- Counting DS records
- Counting DNSSEC signed domains
- Counting IDNs domains
- Counting domains

- Outputting name servers list + number of zones served for each name server

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
