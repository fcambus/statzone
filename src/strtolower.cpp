/*
 * StatZone 1.1.1
 * Copyright (c) 2012-2025, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2022-06-21
 *
 * StatZone is released under the BSD 2-Clause license.
 * See LICENSE file for details.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <cctype>
#include "strtolower.hpp"

char *
strtolower(char *str)
{
	char *p = str;

	while (*p) {
		*p = tolower((unsigned char)*p);
		p++;
	}

	return str;
}
