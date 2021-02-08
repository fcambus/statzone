/*
 * StatZone 1.0.4
 * Copyright (c) 2012-2021, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2021-02-08
 *
 * StatZone is released under the BSD 2-Clause license
 * See LICENSE file for details.
 */

#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#ifdef HAVE_SECCOMP
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include "seccomp.h"
#endif

#include <uthash.h>

#include "compat.h"
#include "config.h"
#include "strtolower.h"

struct timespec begin, current, elapsed;
struct results results;

static void
error(const char *str)
{
	errx(EXIT_FAILURE, "%s", str);
}

static void
usage()
{
	printf("USAGE: statzone [-hv] zonefile\n\n" \
	    "The options are as follows:\n\n" \
	    "	-h	Display usage\n" \
	    "	-v	Display version\n");
}

static void
summary()
{
	/* Stopping timer */
	clock_gettime(CLOCK_MONOTONIC, &current);
	timespecsub(&current, &begin, &elapsed);

	/* Print summary */
	fprintf(stderr, "Processed %" PRIu64 " lines in %f seconds.\n",
	    results.processedLines,
	    elapsed.tv_sec + elapsed.tv_nsec / 1E9);
}

int
main(int argc, char *argv[])
{
	FILE *zonefile;

	struct stat zonefile_stat;

	struct domain {
		char *domain;
		UT_hash_handle hh;
	};

	struct domain *ds = NULL, *signed_domains = NULL;
	struct domain *ns = NULL, *unique_ns = NULL;

	int opt, token_count;

	char lineBuffer[LINE_LENGTH_MAX];
	char *input, *domain, *previous_domain = NULL;
	char *rdata, *token = NULL, *token_lc = NULL;

	if (pledge("stdio rpath", NULL) == -1) {
		err(EXIT_FAILURE, "pledge");
	}

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
	signal(SIGINFO, summary);
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
	clock_gettime(CLOCK_MONOTONIC, &begin);

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

	/* Get zone file size */
	if (fstat(fileno(zonefile), &zonefile_stat)) {
		perror("Can't stat zone file");
		return EXIT_FAILURE;
	}

	while (fgets(lineBuffer, LINE_LENGTH_MAX, zonefile)) {
		if (!*lineBuffer)
			continue;

		if (*lineBuffer == ';') /* Comments */
			continue;

		if (*lineBuffer == '$') /* Directives */
			continue;

		token_count = 0;
		token = strtok(lineBuffer, " \t");

		if (token)
			domain = strtolower(token);

		while (token) {
			if (*token == ';') { /* Comments */
				token = NULL;
				continue;
			}

			token_lc = strtolower(token);
			if (token_count && !strcmp(token_lc, "nsec")) {
				token = NULL;
				continue;
			}

			if (token_count && !strcmp(token_lc, "nsec3")) {
				token = NULL;
				continue;
			}

			if (token_count && !strcmp(token_lc, "rrsig")) {
				token = NULL;
				continue;
			}

			if (token_count && !strcmp(token_lc, "a"))
				results.a++;

			if (token_count && !strcmp(token_lc, "aaaa"))
				results.aaaa++;

			if (token_count && !strcmp(token_lc, "ds")) {
				results.ds++;

				HASH_FIND_STR(signed_domains, domain, ds);

				if (!ds) {
					ds = malloc(sizeof(struct domain));
					if (ds == NULL)
						error("Memory allocation error.");

					ds->domain = strdup(domain);
					if (ds->domain == NULL)
						error("Memory allocation error.");

					HASH_ADD_STR(signed_domains, domain, ds);
				}
			}

			if (!strcmp(token_lc, "ns")) {
				results.ns++;

				if (previous_domain == NULL ||
				    strlen(previous_domain) != strlen(domain) ||
				    strncmp(domain, previous_domain, strlen(domain))) {
					results.domains++;
					free(previous_domain);
					previous_domain = strdup(domain);
					if (previous_domain == NULL)
						error("Memory allocation error.");

					if (!strncmp(domain, "xn--", 4))
						results.idn++;
				}

				rdata = strtok(NULL, "\n");

				if (rdata && strchr(rdata, ' '))
					rdata = strtok(NULL, "\n");

				if (rdata) {
					HASH_FIND_STR(unique_ns, rdata, ns);

					if (!ns) {
						ns = malloc(sizeof(struct domain));
						if (ns == NULL)
							error("Memory allocation error.");

						ns->domain = strdup(rdata);
						if (ns->domain == NULL)
							error("Memory allocation error.");

						HASH_ADD_STR(unique_ns, domain, ns);
					}
				}
			}

			token = strtok(NULL, " \t");
			token_count++;
		}

		results.processedLines++;
	}

	/* Don't count origin */
	if (results.domains)
		results.domains--;

	/* Printing CVS values */
	fprintf(stdout, "---[ CSV values ]--------------------------------------------------------------\n");
	fprintf(stdout, "IPv4 Glue,IPv6 Glue,NS,Unique NS,DS,Signed,IDNs,Domains\n");
	fprintf(stdout, "%" PRIu64 ",", results.a);
	fprintf(stdout, "%" PRIu64 ",", results.aaaa);
	fprintf(stdout, "%" PRIu64 ",", results.ns);
	fprintf(stdout, "%u,", HASH_COUNT(unique_ns));
	fprintf(stdout, "%" PRIu64 ",", results.ds);
	fprintf(stdout, "%u,", HASH_COUNT(signed_domains));
	fprintf(stdout, "%" PRIu64 ",", results.idn);
	fprintf(stdout, "%" PRIu64 "\n", results.domains);

	/* Printing results */
	summary();

	/* Clean up */
	free(previous_domain);
	fclose(zonefile);

	return EXIT_SUCCESS;
}
