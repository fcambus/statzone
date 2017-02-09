# StatZone

StatZone is a DNS zone file analyzer targeted at TLD zones. It is currently used to generate TLD Zone File Statistics on [StatDNS](http://www.statdns.com).

## Requirements

StatZone requires the following Go libraries:

- dns: DNS library in Go - https://github.com/miekg/dns

## Installation

Build and install with the `go` tool, all dependencies will be automatically fetched and compiled:

	go get -d -v ./... && go build -v ./...
	go install statzone

## Usage

StatZone takes the zone file to analyze as parameter:

	statzone zonefile

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

StatZone is released under the BSD 2-Clause license. See `LICENSE` file for details.

## Author

StatZone is developed by Frederic Cambus.

- Site: https://www.cambus.net

## Resources

GitHub: https://github.com/fcambus/statzone
