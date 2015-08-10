/*****************************************************************************/
/*                                                                           */
/* StatZone (c) by Frederic Cambus 2012-2015                                 */
/* http://www.statdns.com                                                    */
/*                                                                           */
/* Created: 2012/02/13                                                       */
/* Last Updated: 2015/08/10                                                  */
/*                                                                           */
/* StatZone is released under the BSD 3-Clause license.                      */
/* See LICENSE file for details.                                             */
/*                                                                           */
/*****************************************************************************/

package main

import (
	"bufio"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strconv"
	"strings"
)

type Domains struct {
	count    int
	idn      int
	previous string
	suffix   int
}

var rrParsed int

/* Return rdata */
func rdata(RR dns.RR) string {
	return strings.Replace(RR.String(), RR.Header().String(), "", -1)
}

func main() {
	header := `-------------------------------------------------------------------------------
                   StatZone (c) by Frederic Cambus 2012-2015
-------------------------------------------------------------------------------`

	fmt.Println(header + "\n")

	/* Check input parameters and show usage */
	if len(os.Args) != 2 {
		fmt.Println("USAGE:    statzone inputfile\n")
		fmt.Println("EXAMPLES: statzone arpa.zone\n")
		os.Exit(1)
	}

	inputFile := os.Args[1]

	fmt.Println("Parsing zone :", inputFile)

	domains := new(Domains)

	ns := map[string]int{}
	signed := map[string]int{}

	zoneFile, err := os.Open(inputFile)
	if err != nil {
		fmt.Println("ERROR : Can't open zone file.")
	}

	zone := dns.ParseZone(bufio.NewReader(zoneFile), "", "")

	var rrtypes [100]int

	for parsedLine := range zone {
		if parsedLine.RR != nil {
			rrtypes[parsedLine.RR.Header().Rrtype]++

			switch parsedLine.RR.Header().Rrtype {
			case dns.TypeDS:
				/* Increment Signed Domains counter */
				signed[parsedLine.RR.Header().Name]++
			case dns.TypeNS:
				/* Increment NS counter */
				ns[rdata(parsedLine)]++

				if parsedLine.RR.Header().Name != domains.previous { // Unique domain

					/* Increment Domain counter */
					domains.count++
					domains.previous = parsedLine.RR.Header().Name

					/* Check if the domain is an IDN */

					if strings.HasPrefix(strings.ToLower(parsedLine.RR.Header().Name), "xn--") {
						domains.idn++
					}

					/* Display progression */
					if domains.count%1000000 == 0 {
						fmt.Printf("*")
					} else if domains.count%100000 == 0 {
						fmt.Printf(".")
					}
				}
			}
		} else {
			fmt.Println("ERROR : A problem occured while parsing the zone file.")
		}

		/* Increment number of resource records parsed */
		rrParsed++
	}

	/* Don't count origin */
	domains.count--

	fmt.Println("\n---[ Parsing results ]---------------------------------------------------------\n")
	fmt.Println(rrParsed, "RRs parsed.")
	for loop := 0; loop < len(rrtypes); loop++ {
		rrtype := rrtypes[loop]
		if rrtype != 0 {
			fmt.Println(dns.TypeToString[uint16(loop)], "records :", rrtype)
		}
	}

	fmt.Println("\n---[ Results ]-----------------------------------------------------------------\n")
	fmt.Println("Domains : ", domains.count)
	fmt.Println("DNSSEC Signed : ", len(signed))

	fmt.Println("IDNs : ", domains.idn)
	fmt.Println("NS : ", len(ns))

	fmt.Println("\n---[ Creating result files ]---------------------------------------------------\n")

	/* Creating name servers list + number of zones served */
	fmt.Println("Creating :", inputFile+".csv")
	outputFile, outputError := os.OpenFile(inputFile+".csv", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if outputError != nil {
		fmt.Printf("ERROR : Can't create output file.\n")
		return
	}

	defer outputFile.Close()

	outputWriter := bufio.NewWriter(outputFile)

	for item := range ns {
		outputWriter.WriteString(strings.ToLower(strings.TrimRight(item, ".")) + ";" + strconv.Itoa(ns[item]) + "\n")
	}

	outputWriter.Flush()

	fmt.Println("\n---[ CSV values ]--------------------------------------------------------------\n")

	fmt.Println("IPv4 Glue ; IPv6 Glue ; NS ; Unique NS ; DS ; Signed ; IDNs ; Domains")
	fmt.Println(rrtypes[dns.TypeA], ";", rrtypes[dns.TypeAAAA], ";", rrtypes[dns.TypeNS], ";", len(ns), ";", rrtypes[dns.TypeDS], ";", len(signed), ";", domains.idn, ";", domains.count)
}
