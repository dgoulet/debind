/*
 * ssh.h
 *
 * SSH library interface to libssh2 header file.
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

#ifndef _SSH_H
#define _SSH_H

#include <libssh2.h>
#include <limits.h>
#include <netinet/in.h>

struct ssh_session {
	int server_sock;
	int listen_sock;
	int forward_sock;
	int local_port;
	int host_port;
	char username[NAME_MAX];
	char *password;
	char host_ip[INET_ADDRSTRLEN];
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
};

struct ssh_session *ssh_init(char *host_ip, int host_port);
int ssh_setup_tunnel(struct ssh_session *ssh_info, const char *dns_ip);
int ssh_auth(struct ssh_session *ssh_info);

#endif /* _SSH_H */
