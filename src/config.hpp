/*
 * StatZone 1.0.5
 * Copyright (c) 2012-2021, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2021-03-30
 *
 * StatZone is released under the BSD 2-Clause license
 * See LICENSE file for details.
 */

#ifndef CONFIG_HPP
#define CONFIG_HPP

#define VERSION "StatZone 1.0.5"

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

#endif /* CONFIG_HPP */
