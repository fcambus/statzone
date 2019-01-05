/*
 * StatZone
 * Copyright (c) 2012-2019, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2019-01-05
 *
 * StatZone is released under the BSD 2-Clause license
 * See LICENSE file for details.
 */

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <uthash.h>

#include "compat.h"
#include "config.h"
#include "strtolower.h"

struct timespec begin, end, elapsed;

char lineBuffer[LINE_LENGTH_MAX];

struct results results;

FILE *zoneFile;
struct stat zoneFileStat;

int8_t getoptFlag;

char *intputFile;

char *domain;
char *previousDomain = "";

struct my_struct {
    char *domain;
    UT_hash_handle hh;
};

struct my_struct *signedDomains = NULL;
struct my_struct *ds;

void
displayUsage() {
	printf("USAGE: statzone [options] inputfile\n\n" \
	       "Options are:\n\n" \
	       "	-h Display usage\n" \
	       "	-v Display version\n");
}

int
main(int argc, char *argv[]) {
	char *token = NULL;
	char *token_lc = NULL;

	while ((getoptFlag = getopt(argc, argv, "hv")) != -1) {
		switch(getoptFlag) {

		case 'h':
			displayUsage();
			return 0;

		case 'v':
			printf("%s\n", VERSION);
			return 0;
		}
	}

	if (optind < argc) {
		intputFile = argv[optind];
	} else {
		displayUsage();
		return 0;
	}

	argc -= optind;
	argv += optind;

	/* Starting timer */
	clock_gettime(CLOCK_MONOTONIC, &begin);

	/* Open log file */
	if (!strcmp(intputFile, "-")) {
		/* Read from standard input */
		zoneFile = stdin;
	} else {
		/* Attempt to read from file */
		if (!(zoneFile = fopen(intputFile, "r"))) {
			perror("Can't open log file");
			return 1;
		}
	}

	/* Get log file size */
	if (fstat(fileno(zoneFile), &zoneFileStat)) {
		perror("Can't stat log file");
		return 1;
	}

	while (fgets(lineBuffer, LINE_LENGTH_MAX, zoneFile)) {
		if (*lineBuffer) {
			token = strtok(lineBuffer, " \t");
			
			if (token)
				domain = strtolower(token);

			while (token) {
				token_lc = strtolower(token);
				if (!strcmp(token_lc, "nsec")) {
					token = NULL;
					continue;
				}

				if (!strcmp(token_lc, "nsec3")) {
					token = NULL;
					continue;
				}

				if (!strcmp(token_lc, "rrsig")) {
					token = NULL;
					continue;
				}

				if (!strcmp(token_lc, "a")) {
					results.a++;
				}

				if (!strcmp(token_lc, "aaaa")) {
					results.aaaa++;
				}

				if (!strcmp(token_lc, "ds")) {
					results.ds++;

					HASH_FIND_STR(signedDomains, domain, ds);

					if (!ds) {
						ds = malloc(sizeof(struct my_struct));
						ds->domain = domain;
						HASH_ADD_STR(signedDomains, domain, ds);
					}
				}

				if (!strcmp(token_lc, "ns")) {
					results.ns++;

					if (strncmp(domain, previousDomain, strlen(domain))) {
						results.domains++;
						previousDomain = strdup(domain);
                                		if (!strncmp(domain, "xn--", 4))
							results.idn++;
					}
				}

				token = strtok(NULL, " \t");
			}
		}

		results.processedLines++;
	}

	/* Don't count origin */
	results.domains--;

	/* Stopping timer */
	clock_gettime(CLOCK_MONOTONIC, &end);

	timespecsub(&end, &begin, &elapsed);
	results.runtime = elapsed.tv_sec + elapsed.tv_nsec / 1E9;

	/* Printing results */
	fprintf(stderr, "Processed %" PRIu64 " lines in %f seconds\n\n", results.processedLines, results.runtime);

	/* Printing CVS values */
	fprintf(stderr, "---[ CSV values ]--------------------------------------------------------------\n");
	fprintf(stderr, "IPv4 Glue ; IPv6 Glue ; NS ; Unique NS ; DS ; Signed ; IDNs ; Domains\n");
	fprintf(stderr, "%" PRIu64 " ; ", results.a);
	fprintf(stderr, "%" PRIu64 " ; ", results.aaaa);
	fprintf(stderr, "%" PRIu64 " ; ", results.ns);
	fprintf(stderr, "%" PRIu64 " ; ", results.ds);
	fprintf(stderr, "%" PRIu64 " ; ", HASH_COUNT(signedDomains));
	fprintf(stderr, "%" PRIu64 " ; ", results.idn);
	fprintf(stderr, "%" PRIu64, results.domains);

	/* Clean up */
	fclose(zoneFile);

	return 0;
}
