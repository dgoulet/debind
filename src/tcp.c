/*
 * tcp.c
 *
 * TCP protocol library interface.
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
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "tcp.h"

/*
 * Create TCP socket and connect(2) to it.
 */
int tcp_connect_socket(int sock, int port, char *ip)
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
		/* Default is to connect on localhost */
		saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}

	ret = connect(sock, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("connect");
		goto error;
	}

error:
	return ret;
}

/*
 * Create generic TCP socket and returns it.
 */
int tcp_create_socket(void)
{
	int sock;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket tcp");
		goto error;
	}

error:
	return sock;
}
