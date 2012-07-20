/*
 * udp.c
 *
 * UDP protocol library interface.
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

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "log.h"
#include "udp.h"

/*
 * Create generic UDP socket and returns it.
 */
int udp_create_socket(void)
{
	int sock;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		perror("socket udp");
		goto error;
	}

error:
	return sock;
}

/*
 * Bind(2) UDP socket.
 */
int udp_bind_socket(int sock, int port, char *ip)
{
	int ret = -1;
	struct sockaddr_in saddr;

	/* Zeroed socket addr */
	memset(&saddr, 0, sizeof(saddr));

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	if (ip != NULL) {
		saddr.sin_addr.s_addr = inet_addr(ip);
	} else {
		/* Default is to bind on localhost */
		saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}

	ret = bind(sock, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("bind udp");
		goto error;
	}

error:
	return ret;
}

/*
 * Send data over UDP socket.
 */
ssize_t udp_sendto(int sock, const void *buf, size_t len,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t ret;

	ret = sendto(sock, buf, len, 0, dest_addr, addrlen);
	if (ret < 0) {
		perror("sendto");
		goto error;
	}
	DBG("UDP DNS reply sent to client");

error:
	return ret;
}

/*
 * Receive data from UDP socket.
 */
ssize_t udp_recvfrom(int sock, void *buf, size_t len,
		struct sockaddr *src_addr)
{
	ssize_t recv_size;
	socklen_t addrlen = sizeof(struct sockaddr);

	/* Receive DNS UDP request */
	recv_size = recvfrom(sock, buf, len, 0, src_addr, &addrlen);
	if (recv_size < 0) {
		perror("recvfrom");
		recv_size = -errno;
		goto error;
	}
	DBG("UDP recvfrom size %ld", recv_size);

error:
	return recv_size;
}
