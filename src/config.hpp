/*
 * StatZone 1.1.2
 * Copyright (c) 2012-2025, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2021-11-16
 *
 * StatZone is released under the BSD 2-Clause license.
 * See LICENSE file for details.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CONFIG_HPP
#define CONFIG_HPP

#define VERSION "StatZone 1.1.2"

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
