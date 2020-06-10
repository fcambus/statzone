/*
 * StatZone 1.0.2
 * Copyright (c) 2012-2020, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2019-06-10
 *
 * StatZone is released under the BSD 2-Clause license
 * See LICENSE file for details.
 */

#ifndef CONFIG_H
#define CONFIG_H

#define VERSION "StatZone 1.0.2"

#define LINE_LENGTH_MAX 65536

struct results {
	uint64_t processedLines;
	uint64_t a;
	uint64_t aaaa;
	uint64_t ds;
	uint64_t ns;
	uint64_t domains;
	uint64_t idn;
};

#endif /* CONFIG_H */
