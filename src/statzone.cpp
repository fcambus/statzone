/*
 * StatZone 1.1.0
 * Copyright (c) 2012-2021, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2021-04-03
 *
 * StatZone is released under the BSD 2-Clause license
 * See LICENSE file for details.
 */

#include <err.h>
#include <getopt.h>
#include <string.h>

#include <chrono>
#include <csignal>
#include <iostream>
#include <string>
#include <unordered_set>

#ifdef HAVE_SECCOMP
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include "seccomp.h"
#endif

#include "config.hpp"
#include "strtolower.hpp"

std::chrono::steady_clock::time_point begin, current, elapsed;
struct results results;

static void
usage()
{
	printf("statzone [-hv] zonefile\n\n" \
	    "The options are as follows:\n\n" \
	    "	-h	Display usage.\n" \
	    "	-v	Display version.\n");
}

static void
summary()
{
	/* Get current timer value */
	current = std::chrono::steady_clock::now();

	/* Print summary */
	std::cerr << "Processed " << results.processedLines << " lines in ";
	std::cerr << std::chrono::duration_cast<std::chrono::microseconds>(current - begin).count() / 1E6;
	std::cerr << " seconds." << std::endl;
}

#ifdef SIGINFO
void
siginfo_handler(int signum)
{
	summary();
}
#endif

int
main(int argc, char *argv[])
{
	std::unordered_set<std::string> signed_domains;
	std::unordered_set<std::string> unique_ns;

	int opt, token_count;

	char linebuffer[LINE_LENGTH_MAX];
	char *input;
	std::string domain, previous_domain;
	char *rdata, *token = nullptr, *token_lc = nullptr;

	FILE *zonefile;

#ifdef HAVE_SECCOMP
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("Can't initialize seccomp");
		return EXIT_FAILURE;
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &statzone)) {
		perror("Can't load seccomp filter");
		return EXIT_FAILURE;
	}
#endif

#ifdef SIGINFO
	signal(SIGINFO, siginfo_handler);
#endif

	while ((opt = getopt(argc, argv, "hv")) != -1) {
		switch (opt) {

		case 'h':
			usage();
			return EXIT_SUCCESS;

		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		}
	}

	if (optind < argc) {
		input = argv[optind];
	} else {
		usage();
		return EXIT_SUCCESS;
	}

	/* Starting timer */
	begin = std::chrono::steady_clock::now();

	/* Open zone file */
	if (!strcmp(input, "-")) {
		/* Read from standard input */
		zonefile = stdin;
	} else {
		/* Attempt to read from file */
		if (!(zonefile = fopen(input, "r"))) {
			perror("Can't open zone file");
			return EXIT_FAILURE;
		}
	}

	while (fgets(linebuffer, LINE_LENGTH_MAX, zonefile)) {
		if (!*linebuffer)
			continue;

		if (*linebuffer == ';') /* Comments */
			continue;

		if (*linebuffer == '$') /* Directives */
			continue;

		token_count = 0;
		token = strtok(linebuffer, " \t");

		if (token)
			domain = strtolower(token);

		while (token) {
			if (*token == ';') { /* Comments */
				token = nullptr;
				continue;
			}

			token_lc = strtolower(token);
			if (token_count && !strcmp(token_lc, "nsec")) {
				token = nullptr;
				continue;
			}

			if (token_count && !strcmp(token_lc, "nsec3")) {
				token = nullptr;
				continue;
			}

			if (token_count && !strcmp(token_lc, "rrsig")) {
				token = nullptr;
				continue;
			}

			if (token_count && !strcmp(token_lc, "a"))
				results.a++;

			if (token_count && !strcmp(token_lc, "aaaa"))
				results.aaaa++;

			if (token_count && !strcmp(token_lc, "ds")) {
				results.ds++;

				signed_domains.insert(domain);
			}

			if (!strcmp(token_lc, "ns")) {
				results.ns++;

				if (domain.compare(previous_domain)) {
					results.domains++;

					previous_domain = domain;

					if (!domain.compare(0, 4, "xn--"))
						results.idn++;
				}

				rdata = strtok(nullptr, "\n");

				if (rdata && strchr(rdata, ' '))
					rdata = strtok(nullptr, "\n");

				if (rdata)
					unique_ns.insert(rdata);
			}

			token = strtok(nullptr, " \t");
			token_count++;
		}

		results.processedLines++;
	}

	/* Don't count origin */
	if (results.domains)
		results.domains--;

	/* Printing CVS values */
	std::cout << "---[ CSV values ]--------------------------------------------------------------" << std::endl;
	std::cout << "IPv4 Glue,IPv6 Glue,NS,Unique NS,DS,Signed,IDNs,Domains" << std::endl;
	std::cout << results.a << ",";
	std::cout << results.aaaa << ",";
	std::cout << results.ns << ",";
	std::cout << unique_ns.size() << ",";
	std::cout << results.ds << ",";
	std::cout << signed_domains.size() << ",";
	std::cout << results.idn << ",";
	std::cout << results.domains << std::endl;

	/* Printing results */
	summary();

	/* Clean up */
	fclose(zonefile);

	return EXIT_SUCCESS;
}
