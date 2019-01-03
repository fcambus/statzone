/*
 * StatZone
 * Copyright (c) 2012-2019, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2019-01-03
 *
 * StatZone is released under the BSD 2-Clause license
 * See LICENSE file for details.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "config.h"

struct timespec begin, end, elapsed;

char lineBuffer[LINE_LENGTH_MAX];

struct results results;

FILE *zoneFile;
struct stat zoneFileStat;

int8_t getoptFlag;

char *intputFile;

void
displayUsage() {
	printf("USAGE: statzone [options] inputfile\n\n" \
	       "Options are:\n\n" \
	       "	-h Display usage\n" \
	       "	-v Display version\n");
}

int
main(int argc, char *argv[]) {
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
		if (lineBuffer)
			results.processedLines++;
	}

	/* Stopping timer */
	clock_gettime(CLOCK_MONOTONIC, &end);

	timespecsub(&end, &begin, &elapsed);
	results.runtime = elapsed.tv_sec + elapsed.tv_nsec / 1E9;

	/* Printing results */
	fprintf(stderr, "Processed %" PRIu64 " lines in %f seconds\n", results.processedLines, results.runtime);

	/* Clean up */
	fclose(zoneFile);

	return 0;
}
