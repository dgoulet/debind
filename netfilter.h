/*
 * netfilter.h
 *
 * Netfilter library interface header file.
 *
 * Copyright (C) 2011 - David Goulet <iam@truie.org>
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

#ifndef _NETFILTER_H
#define _NETFILTER_H

#include <stdio.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

int netfilter_init(void);
void netfilter_clean(void);
void netfilter_set_log(FILE *fp);
void netfilter_write_log(void);
void *netfilter_thread(void *data);

#endif /* _NETFILTER_H */
