/*
 * log.h
 *
 * Error and logging interface.
 *
 * Copyright (C) 2011 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by as
 * published by the Free Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LOG_H
#define _LOG_H

#include <errno.h>
#include <stdio.h>

/* Stringify the expansion of a define */
#define XSTR(d) STR(d)
#define STR(s) #s

extern int opt_verbose;

#define PRINT_DBG 0x1
#define PRINT_ERR 0x2

#define __debind_print(type, fmt, args...)        \
	do {                                          \
		if (opt_verbose && (type & PRINT_DBG)) {  \
			fprintf(stderr, fmt, ## args);        \
		} else if (type & PRINT_ERR) {            \
			fprintf(stderr, fmt, ## args);        \
		}                                         \
	} while (0);

#define DBG(fmt, args...) __debind_print(PRINT_DBG, "DEBUG: " fmt \
		" [in %s() at " __FILE__ ":" XSTR(__LINE__) "]\n", ## args, __func__)
#define ERR(fmt, args...) __debind_print(PRINT_ERR, "Error: " fmt "\n", ## args)

#endif /* _LOG_H */
