/*
 * StatZone 1.0.2
 * Copyright (c) 2012-2020, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2019-01-03
 *
 * StatZone is released under the BSD 2-Clause license
 * See LICENSE file for details.
 */

#include <ctype.h>
#include "strtolower.h"

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
