/*
 * udp.h
 *
 * UDP protocol library interface header file.
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

#ifndef _UDP_H
#define _UDP_H

#include <netinet/in.h>

int udp_bind_socket(int sock, int port, char *ip);
int udp_create_socket(void);
ssize_t udp_recvfrom(int sock, void *buf, size_t len,
		struct sockaddr *src_addr);
ssize_t udp_sendto(int sock, const void *buf, size_t len,
		const struct sockaddr *dest_addr, socklen_t addrlen);

#endif /* _UDP_H */
