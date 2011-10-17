/*
 * ssh.c
 *
 * SSH library interface to libssh2.
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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "ssh.h"

enum {
    AUTH_NONE = 0,
    AUTH_PASSWORD,
    AUTH_PUBLICKEY
};

/*
 * SSH authentication using ssh agent.
 */
static int agent_auth(struct ssh_session *ssh_info)
{
	int ret;
	struct libssh2_agent_publickey *identity, *prev_identity = NULL;
	LIBSSH2_AGENT *agent = NULL;

	agent = libssh2_agent_init(ssh_info->session);
	if (agent == NULL) {
		ERR("Failure connecting to ssh-agent");
		ret = -1;
		goto error;
	}

	ret = libssh2_agent_connect(agent);
	if (ret < 0) {
		ERR("Failure connecting to ssh-agent");
		goto error;
	}

	ret = libssh2_agent_list_identities(agent);
	if (ret < 0) {
		ERR("Failure requesting identities to ssh-agent");
		goto error;
	}

	while (1) {
		ret = libssh2_agent_get_identity(agent,
				&identity, prev_identity);
		if (ret == 1) {
			/* Reach end of public key list */
			ret = -1;
			goto error;
		} else if (ret < 0) {
			/* Failure */
			goto error;
		}

		ret = libssh2_agent_userauth(agent, ssh_info->username, identity);
		if (ret < 0) {
			ERR("Authentication with username %s and public key"
					" %s failed!", ssh_info->username, identity->comment);
		} else {
			DBG("Authentication with username %s and public key"
					" %s succeeded!", ssh_info->username, identity->comment);
			break;
		}
		prev_identity = identity;
	}

error:
	if (agent) {
		libssh2_agent_disconnect(agent);
		libssh2_agent_free(agent);
	}
	return ret;
}

/*
 * Authenticate using public key.
 */
static int pubkey_auth(struct ssh_session *ssh_info)
{
	int ret;
	char *buf;
	char key_pub_file[PATH_MAX];
	char key_priv_file[PATH_MAX];

	/* Setup key files */
	snprintf(key_pub_file, PATH_MAX, "%s/.ssh/id_rsa.pub", getenv("HOME"));
	snprintf(key_priv_file, PATH_MAX, "%s/.ssh/id_rsa", getenv("HOME"));

	ssh_info->password = getpass("SSH key passphrase: ");

	ret = libssh2_userauth_publickey_fromfile_ex(ssh_info->session,
			ssh_info->username, strlen(ssh_info->username),
			key_pub_file, key_priv_file, ssh_info->password);
	if (ret < 0) {
		libssh2_session_last_error(ssh_info->session, &buf, NULL, 0);
		ERR("Error SSH key: %s", buf);
		goto error;
	}
	DBG("Authentication by public key succeeded.");

error:
	/* Clear from memory the password. */
	memset(ssh_info->password, 0, strlen(ssh_info->password));
	return ret;
}

/*
 * Authenticate using password.
 */
static int password_auth(struct ssh_session *ssh_info)
{
	int ret;

	ssh_info->password = getpass("SSH server password: ");

	ret = libssh2_userauth_password(ssh_info->session, ssh_info->username,
			ssh_info->password);
	if (ret < 0) {
		ERR("Wrong username/password");
		goto error;
	}
	DBG("Authentication by password succeeded.");

error:
	/* Clear from memory the password. */
	memset(ssh_info->password, 0, strlen(ssh_info->password));
	return ret;
}

/*
 * Handshake with the SSH server and init secure communication.
 */
static int startup(struct ssh_session *ssh_info)
{
	int ret, i;
	const char *fingerprint;

	/*
	 * ... start it up. This will trade welcome banners, exchange keys,
	 * and setup crypto, compression, and MAC layers
	 */
	ret = libssh2_session_handshake(ssh_info->session, ssh_info->server_sock);
	if (ret) {
		ERR("Error when starting up SSH session: %d", ret);
		goto error;
	}

	/*
	 * At this point we havn't yet authenticated. The first thing to do is
	 * check the hostkey's fingerprint against our known hosts Your app may
	 * have it hard coded, may go to a file, may present it to the user, that's
	 * your call
	 */
	fingerprint = libssh2_hostkey_hash(ssh_info->session, LIBSSH2_HOSTKEY_HASH_SHA1);
	if (fingerprint == NULL) {
		ERR("Returned hostkey hash is NULL");
		goto error;
	}
	DBG("Fingerprint: ");
	for (i = 0; i < 20; i++) {
		DBG("%02X ", (unsigned char)fingerprint[i]);
	}
	DBG("");

	return 0;

error:
	return -1;
}

/*
 * Create direct tcpip channel. Make it blocking to be able to wait on it.
 */
int ssh_setup_tunnel(struct ssh_session *ssh_info, const char *dns_ip)
{
	LIBSSH2_CHANNEL *channel = NULL;

	DBG("SSH preparing tunnel to %s:%d", dns_ip, 53);

	/* Tunnel traffic to google DNS */
	channel = libssh2_channel_direct_tcpip(ssh_info->session, dns_ip, 53);
    if (!channel) {
		char *buf;
		libssh2_session_last_error(ssh_info->session, &buf, NULL, 0);
		ERR("Direct tcpip: %s", buf);
        ERR("Could not open the direct-tcpip channel!\n"
				"(Note that this can be a problem at the server!"
				" Please review the server logs.)");
        goto error;
    }

	/* Block on channel read calls */
    libssh2_session_set_blocking(ssh_info->session, 1);

	ssh_info->channel = channel;

	return 0;

error:
	return -1;
}

/*
 * Authenticate using either ssh-agent, pubkey or password to SSH server.
 */
int ssh_auth(struct ssh_session *ssh_info)
{
	int ret, auth = AUTH_NONE;
	char *userauthlist;

	/* check what authentication methods are available */
	userauthlist = libssh2_userauth_list(ssh_info->session,
			ssh_info->username, strlen(ssh_info->username));
	if (userauthlist == NULL) {
		ERR("Failed to get the SSH userauth list");
		goto error;
	}
	DBG("Auth methods: %s", userauthlist);

	if (strstr(userauthlist, "publickey")) {
		auth |= AUTH_PUBLICKEY;
	}
	if (strstr(userauthlist, "password")) {
		auth |= AUTH_PASSWORD;
	}

	/* Try ssh-agent auth. */
	ret = agent_auth(ssh_info);
	if (ret >= 0) {
		goto end;
	}

	/* Fallback pubkey */
	if (auth & AUTH_PUBLICKEY) {
		ret = pubkey_auth(ssh_info);
		if (ret >= 0) {
			goto end;
		}
	}

	/* Fallback passowrd */
	if (auth & AUTH_PASSWORD) {
		ret = password_auth(ssh_info);
		if (ret >= 0) {
			goto end;
		}
	} else {
		ERR("Unsupported authentication methods");
	}

error:
	ERR("SSH authentication failed!");
	return -1;

end:
	DBG("SSH authentication success");
	return 0;
}

/*
 * Setup SSH connection to host.
 */
struct ssh_session *ssh_init(char *host_ip, int host_port)
{
	int ret, sock = -1;
	struct sockaddr_in saddr;
	struct ssh_session *ssh_session;
	LIBSSH2_SESSION *session = NULL;

	DBG("SSH setup on addr %s and port %d", host_ip, host_port);

	ssh_session = malloc(sizeof(struct ssh_session));
	if (ssh_session == NULL) {
		perror("malloc ssh session");
		goto error;
	}

	/* Init data struct */
	memset(ssh_session, 0, sizeof(struct ssh_session));

	ret = libssh2_init(0);
	if (ret < 0) {
		ERR("libssh2 initialization failed (%d)", ret);
		goto error;
	}

	/* Connect to SSH server */
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket ssh TCP");
		goto error;
	}
	DBG("SSH server sock %d", sock);

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = inet_addr(host_ip);
	saddr.sin_port = htons(host_port);

	ret = connect(sock, (struct sockaddr*)(&saddr), sizeof(struct sockaddr_in));
	if (ret < 0) {
		ERR("failed to connect!");
		goto error;
	}

	/* Create a session instance */
	session = libssh2_session_init();
	if (!session) {
		ERR("Could not initialize SSH session!");
		goto error;
	}

	ssh_session->session = session;
	ssh_session->server_sock = sock;
	strncpy(ssh_session->host_ip, host_ip, sizeof(ssh_session->host_ip));
	ssh_session->host_port = host_port;

	DBG("SSH setup done!");

	ret = startup(ssh_session);
	if (ret < 0) {
		goto error;
	}

	return ssh_session;

error:
	if (ssh_session) {
		if (ssh_session->session) {
			libssh2_session_disconnect(ssh_session->session,
					"Client disconnecting normally");
			libssh2_session_free(ssh_session->session);
		}
	}
	close(sock);
	return NULL;
}
