/*
 * main.c
 *
 * Debind main file.
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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <popt.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "debind.h"
#include "log.h"
#include "netfilter.h"
#include "ssh.h"
#include "tcp.h"
#include "udp.h"

int opt_verbose;

static char *local_ip;
static char *forward_ip;
static char *ssh_host;
static char *opt_logname;
static int opt_dnat;
static int local_port;
static int forward_port;
static int opt_netfilter = -1;
static int opt_rr_dns;
static const char *dns_ip;
static const char *progname;

static struct ssh_session *ssh_info = NULL;

enum {
	OPT_HELP = 1,
	OPT_PRINT_RR,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help", 'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"local-ip", 'l', POPT_ARG_STRING, &local_ip, 0, 0, 0},
	{"forward-ip", 'f', POPT_ARG_STRING, &forward_port, 0, 0, 0},
	{"local-port", 'p', POPT_ARG_INT, &local_port, 0, 0, 0},
	{"forward-port", 'P', POPT_ARG_INT, &forward_port, 0, 0, 0},
	{"ssh", 's', POPT_ARG_STRING, &ssh_host, 0, 0, 0},
	{"dns-ip", 'd', POPT_ARG_STRING, &dns_ip, 0, 0, 0},
	{"netfilter", 'n', POPT_ARG_INT, &opt_netfilter, 0, 0, 0},
	{"dnat", 'D', POPT_ARG_VAL, &opt_dnat, 1, 0, 0},
	{"log", 'L', POPT_ARG_STRING, &opt_logname, 0, 0, 0},
	{"rr-dns", 0, POPT_ARG_VAL, &opt_rr_dns, 1, 0, 0},
	{"print-rr", 0, POPT_ARG_NONE, 0, OPT_PRINT_RR, 0, 0},
	{"verbose", 'v', POPT_ARG_VAL, &opt_verbose, 1, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

static void usage(FILE *fp)
{
	fprintf(fp, "usage: %s [options]\n", progname);
	fprintf(fp, "\n");
	fprintf(fp, "  -h, --help            Show usage\n");
	fprintf(fp, "  -l, --local-ip        Local address to listen on for DNS queries\n");
	fprintf(fp, "                        [default: %s]\n", DEFAULT_LOCAL_IP);
	fprintf(fp, "  -p, --local-port      Local port to bind on for DNS queries\n");
	fprintf(fp, "                        [default: %d]\n", DEFAULT_LOCAL_PORT);
	fprintf(fp, "  -f, --forward-ip      Bind address for forward DNS TCP traffic\n");
	fprintf(fp, "                        [default: %s]\n", DEFAULT_FORWARD_IP);
	fprintf(fp, "  -P, --forward-port    Bind port for forward DNS TCP traffic\n");
	fprintf(fp, "                        [default: %d]\n", DEFAULT_FORWARD_PORT);
	fprintf(fp, "  -s, --ssh USER@HOST[:PORT]\n");
	fprintf(fp, "                        Automatic SSH forward session. HOST can be server name or IP\n");
	fprintf(fp, "                        Support ssh-agent, pubkey and password authentication\n");
	fprintf(fp, "  -d, --dns-ip          DNS server IP to forward queries\n");
	fprintf(fp, "                        [default: %s]\n", open_dns_list[0]);
	fprintf(fp, "  -n, --netfilter NUM_QUEUE\n");
	fprintf(fp, "                        Support for libnetfilter queue. Use 0 for NUM_QUEUE if not sure\n");
	fprintf(fp, "                        This option is used to log every DNS query in a text file.\n");
	fprintf(fp, "                        Use -L to set location or default is %s\n", DEFAULT_LOG_FILENAME);
	fprintf(fp, "  -D, --dnat            Use iptables to DNAT UDP port 53 to <local-port>\n");
	fprintf(fp, "                        -p udp --dport 53 -j DNAT --to <local-ip>:<local-port>\n");
	fprintf(fp, "  -L, --log FILENAME    Log every DNS query to FILENAME. Uses libnetfilter queue\n");
	fprintf(fp, "      --rr-dns          Round robin DNS server using predefined list. Use --print-rr for it.\n");
	fprintf(fp, "      --print-rr        Print available open DNS list\n");
	fprintf(fp, "  -v, --verbose         Debug mode for %s\n", progname);
	fprintf(fp, "\n");
	fprintf(fp, "To create your own SSH tunnel using the openssh client:\n");
	fprintf(fp, "$ ssh -L <local-port>:<forward-ip>:<forward-port> SRV_ADDR\n");
	fprintf(fp, "\n");
	fprintf(fp, "Then, run %s using the same exact values pass to the -L option.\n", progname);
	fprintf(fp, "\n");
	fprintf(fp, "GPLv2. Please use it, change it, contribute to it! Cheers!\n");
	fprintf(fp, "David Goulet <iam@truie.org>\n");
}

/*
 * Create TCP socket and connect to ip:port.
 *
 * Return connected socket.
 */
static int setup_forward_tcp(int port, char *ip)
{
	int ret, sock;

	sock = tcp_create_socket();
	if (sock < 0) {
		goto error;
	}

	ret = tcp_connect_socket(sock, port, ip);
	if (ret < 0) {
		ERR("Unable to connect to TCP tunnel");
		fprintf(stderr,
				"Recommended to use ssh -L %s:%d:%s:53 HOST for tunneling\n",
				ip, port, dns_ip);
		goto error;
	}

	return sock;

error:
	return -1;
}

/*
 * Setup UDP client socket and bind to it.
 *
 * Return bound socket.
 */
static int dns_client_setup(int port, char *ip)
{
	int ret, sock;

	sock = udp_create_socket();
	if (sock < 0) {
		goto error;
	}

	ret = udp_bind_socket(sock, port, ip);
	if (ret < 0) {
		goto error;
	}

	return sock;

error:
	return -1;
}

/*
 * Get DNS query using TCP transport layer.
 */
static ssize_t dig_tcp_request(int sock, char *buf, ssize_t buf_size,
		ssize_t len)
{
	int ret;
	ssize_t recv_size;

	while (1) {
		/* TCP send of DNS request */
		ret = send(sock, buf, len, 0);
		if (ret < 0) {
			perror("send dns");
			goto error;
		}
		DBG("TCP request sent");

		recv_size = recv(sock, buf, buf_size, 0);
		if (recv_size < 0) {
			perror("recv dns");
			goto error;
		} else if (recv_size == 0) {
			close(sock);
			/* Shutdown of the tcp socket. Reconnecting. */
			DBG("TCP forward connection closed, reconnecting");
			sock = setup_forward_tcp(forward_port, forward_ip);
			if (sock < 0) {
				/* TCP tunnel was shutdown for good */
				goto error;
			}
			continue;
		} else {
			DBG("TCP DNS reply received of size %ld", recv_size);
			break;
		}
	}

	return recv_size;

error:
	return -1;
}

/*
 * Get DNS query using SSH transport layer.
 */
static ssize_t dig_ssh_request(struct ssh_session *ssh_info,
		char *buf, size_t buf_size, ssize_t len)
{
	int ret;
	ssize_t recv_size;

	do {
		ret = libssh2_channel_write(ssh_info->channel, buf, len);
		if (ret < 0) {
			ERR("libssh2_channel_write: %d", ret);
			goto error;
		}
		DBG("DNS request of size %ld sent to ssh channel", len);

		recv_size = libssh2_channel_read(ssh_info->channel, buf, buf_size);
		if (recv_size < 0) {
			char *buf;
			ERR("SSH channel read failed");
			libssh2_session_last_error(ssh_info->session, &buf, NULL, 0);
			ERR("Failure: %s", buf);
		} else if (recv_size == 0) {
			ret = libssh2_channel_eof(ssh_info->channel);
			if (ret) {
				DBG("SSH server disconnected!");
				libssh2_channel_close(ssh_info->channel);
				libssh2_channel_free(ssh_info->channel);
				/* Create new channel */
				ret = ssh_setup_tunnel(ssh_info, dns_ip);
				if (ret < 0) {
					goto error;
				}
			}
		} else {
			DBG("DNS reply red from ssh channel (size: %ld)",
					recv_size);
			goto end;
		}
	} while (1);

end:
	return recv_size;

error:
	return -1;
}

/*
 * Wait on socket using recvfrom(2) for a UDP DNS request.
 */
static ssize_t dns_udp_recv_query(int sock, char *buf, size_t buf_size,
		struct sockaddr *src_addr)
{
	/*
	 * We clear the two first bytes in order to use that same buffer for the
	 * TCP request that needs the first two bytes used for the length of the
	 * DNS query.
	 */
	return udp_recvfrom(sock, buf + 2, buf_size, src_addr);
}

static ssize_t dns_udp_send_reply(int sock, char *buf, ssize_t len,
		struct sockaddr *dst_addr, socklen_t addrlen)
{
	/*
	 * Ignore the first two bytes. The buffer contains the TCP DNS request and
	 * must not use the first two bytes used for length.
	 */
	return udp_sendto(sock, buf + 2, len, dst_addr, addrlen);
}

/*
 * Parsing arguments using libpopt.
 */
static int parse_args(int argc, const char **argv)
{
	int opt;
	static poptContext pc;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stderr);
			goto error;
		case OPT_PRINT_RR:
		{
			int i;
			for (i = 0; i < open_dns_count; i++) {
				printf("%d) %s\n", i, open_dns_list[i]);
			}
			exit(EXIT_SUCCESS);
			break;
		}
		default:
			usage(stderr);
			goto error;
		}
	}

	return 0;

error:
	return -1;
}

/*
 * Parse SSH host command line option which is on the form:
 *    USER@HOST:[PORT]
 */
static int parse_ssh_host(char *host_ip, int *host_port, char *username)
{
	int ret;
	char buf[21];
	char srv_addr[INET_ADDRSTRLEN];
	struct hostent *host;

	ret = sscanf(ssh_host, "%[^'@']@%s", username, buf);
	if (ret == 2) {
		DBG("Username set to %s", username);
	} else {
		goto error;
	}

	ret = sscanf(buf, "%[^':']:%d", host_ip, host_port);
	if (ret == 2) {
		if (*host_port < 1 || *host_port > 65535) {
			DBG("Port number not valid");
			goto error;
		}
	} else if (ret != 1) {
		goto error;
	}

	if (inet_pton(AF_INET, host_ip, &srv_addr) == 0) {
		host = gethostbyname(host_ip);
		if (host == NULL) {
			ERR("Bad host/IP: %s", host_ip);
			goto error;
		}
		strncpy(host_ip, inet_ntoa(*((struct in_addr **)host->h_addr_list)[0]),
					INET_ADDRSTRLEN);
		host_ip[INET_ADDRSTRLEN - 1] = '\0';
	}

	return 0;

error:
	return -1;
}

/*
 * Default network values.
 */
static void init_default_values(void)
{
	local_ip = DEFAULT_LOCAL_IP;
	local_port = DEFAULT_LOCAL_PORT;
	forward_port = DEFAULT_FORWARD_PORT;
	forward_ip = DEFAULT_FORWARD_IP;
	/* Default, use Google server */
	dns_ip = open_dns_list[0];
}

/*
 * Create DNS TCP request from UDP payload.
 *
 * The TCP request adds the length of the query in the first two bytes.
 */
static void forge_tcp_request(char *buf, ssize_t *request_size)
{
	/* Adding payload length to forge TCP request */
	buf[1] = *request_size & 0xFF;
	buf[0] = *request_size >> 8 & 0xFF;

	*request_size += 2;

	DBG("DNS TCP request forged");
}

/*
 * Create DNS UDP request from TCP paylaod.
 *
 * The UDP request don't need the first two bytes.
 */
static void forge_udp_request(char *buf, ssize_t *request_size)
{
	/* Removing the first two bytes from payload to fit DNS UDP query */
	*request_size -= 2;

	/* TODO: change buf pointer position */

	DBG("DNS UDP request forged");
}

/*
 * Setup libssh2 for SSH forward to external DNS. This function init libssh2,
 * authenticate to the SSH server and create the SSH direct tcp channel.
 */
static struct ssh_session *setup_forward_ssh(char *ip, int port,
		char *username, const char *forward_dns_ip)
{
	int ret;
	struct ssh_session *ssh_info;

	/* Create ssh_info struct and ssh session */
	ssh_info = ssh_init(ip, port);
	if (ssh_info == NULL) {
		goto error;
	}

	/* Debug libssh2 library */
	/*
	libssh2_trace(ssh_info->session, LIBSSH2_TRACE_SOCKET | LIBSSH2_TRACE_TRANS |
			LIBSSH2_TRACE_KEX | LIBSSH2_TRACE_CONN | LIBSSH2_TRACE_AUTH |
			LIBSSH2_TRACE_ERROR);
	*/

	strncpy(ssh_info->username, username, NAME_MAX);

	ret = ssh_auth(ssh_info);
	if (ret < 0) {
		/* Fail to authenticate. Stopping process. */
		goto error;
	}

	/* Create SSH tunnel for DNS TCP request forward */
	ret = ssh_setup_tunnel(ssh_info, forward_dns_ip);
	if (ret < 0) {
		goto error;
	}

	return ssh_info;

error:
	return NULL;
}

/*
 * Cleanup data structures.
 */
static void cleanup(int code)
{
	int ret;
	char buf[1024];

	if (ssh_info) {
		close(ssh_info->forward_sock);
		close(ssh_info->listen_sock);
		if (ssh_info->channel) {
			libssh2_channel_free(ssh_info->channel);
		}

		if (ssh_info->session) {
			libssh2_session_disconnect(ssh_info->session,
					"Client disconnecting normally");
			libssh2_session_free(ssh_info->session);
		}

		free(ssh_info);
	}

	if (opt_dnat) {
		/* Remove DNAT rule */
		snprintf(buf, sizeof(buf), IPTABLE_DEL_DNAT, local_ip, local_port);
		ret = system(buf);
		if (ret != 0) {
			DBG("DNAT iptables command failed\n%s", buf);
		} else {
			DBG("UDP traffic on port 53 restored");
		}
	}

	if (opt_netfilter != -1) {
		snprintf(buf, sizeof(buf), IPTABLE_DEL_QUEUE,
				local_port, opt_netfilter);
		ret = system(buf);
		if (ret != 0) {
			DBG("NFQUEUE iptables command failed\n%s", buf);
		} else {
			DBG("Queuing UDP traffic on port 53 removed on queue num %d",
					opt_netfilter);
		}
	}

	/* Always last */
	if (code < 0) {
		exit(EXIT_FAILURE);
	} else {
		exit(EXIT_SUCCESS);
	}
}

/*
 * Signal handler.
 */
static void sighandler(int sig)
{
    switch (sig) {
    case SIGPIPE:
        return;
    case SIGINT:
		cleanup(-1);
        break;
    case SIGTERM:
		cleanup(-1);
        break;
    default:
        break;
    }
}

/*
 * Init signal handler and catched signals.
 */
static int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		perror("sigemptyset");
		return ret;
	}

	sa.sa_handler = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGINT, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGPIPE, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	return ret;
}

/*
 * Start logging thread which uses netfilter queue to log DNS queries.
 */
static int start_logging_thread(pthread_t *th)
{
	int ret = -1;
	FILE *log_fp;

	if (opt_logname != NULL) {
		log_fp = fopen(opt_logname, "a");
	} else {
		log_fp = fopen(DEFAULT_LOG_FILENAME, "a");
	}

	if (log_fp == NULL) {
		perror("fopen");
		goto error;
	}

	ret = pthread_create(th, NULL, netfilter_thread, (void *)log_fp);
	if (ret < 0) {
		perror("pthread_create logging thread");
	}

error:
	return ret;
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int ret, dns_index = -1, host_port = 22;
	int udp_client_sock = -1, tcp_dns_sock = -1;
	ssize_t recv_size;
	char buf[1024], host_ip[15], username[NAME_MAX];
	struct sockaddr_in saddr;
	pthread_t log_thread;
	void *status;

	progname = argv[0];

	ret = set_signal_handler();
	if (ret < 0) {
		goto error;
	}

	init_default_values();

	ret = parse_args(argc, (const char **)argv);
	if (ret < 0) {
		goto error;
	}

	if (ssh_host != NULL) {
		ret = parse_ssh_host(host_ip, &host_port, username);
		if (ret < 0) {
			usage(stderr);
			goto error;
		}

		/* Setup SSH forward tunneling */
		ssh_info = setup_forward_ssh(host_ip, host_port, username, dns_ip);
		if (ssh_info == NULL) {
			goto error;
		}
	} else {
		/* Connect to forward TCP server */
		tcp_dns_sock = setup_forward_tcp(forward_port, forward_ip);
		if (tcp_dns_sock < 0) {
			goto error;
		}
		DBG("Connected TCP tunnel on %s:%d",
				forward_ip, forward_port);
	}

	/* Logging is used with libnetfilter queue */
	if (opt_logname != NULL && opt_netfilter == -1) {
		opt_netfilter = DEFAULT_NETFILTER_QUEUE_NUM;
	}

	if (opt_netfilter != -1) {
		ret = snprintf(buf, sizeof(buf), IPTABLE_ADD_QUEUE,
				local_port, opt_netfilter);
		if (ret < 0) {
			perror("snprintf iptable rule");
			goto error;
		}
		ret = system(buf);
		if (ret != 0) {
			ERR("NFQUEUE iptables command failed\n%s", buf);
			goto error;
		}
		DBG("Queuing UDP traffic on port 53 on queue num %d",
				opt_netfilter);

		ret = start_logging_thread(&log_thread);
		if (ret < 0) {
			goto error;
		}
	}

	/*
	 * iptables DNAT option. This will redirect all UDP port 53 traffic to the
	 * local-port.
	 */
	if (opt_dnat) {
		/* Execute iptable rule */
		ret = snprintf(buf, sizeof(buf), IPTABLE_ADD_DNAT,
				local_ip, local_port);
		if (ret < 0) {
			perror("snprintf iptable rule");
			goto error;
		}

		ret = system(buf);
		if (ret != 0) {
			ERR("DNAT iptables command failed\n%s", buf);
			goto error;
		}
		DBG("Redirecting all UDP traffic on port 53 to %s:%d",
				local_ip, local_port);
	}

	/* Bind on local port to catch DNS request from client */
	udp_client_sock = dns_client_setup(local_port, local_ip);
	if (udp_client_sock < 0) {
		goto error;
	}
	fprintf(stderr, "Listening for DNS request on UDP port %d\n", local_port);

	while (1) {
		/* Reset buffer */
		memset(buf, 0, sizeof(buf));

		/* Receive DNS UDP request */
		recv_size = dns_udp_recv_query(udp_client_sock, buf, sizeof(buf),
				(struct sockaddr *) &saddr);
		if (recv_size < 0) {
			/* At this point... better clean exit */
			goto error;
		}

		/* Change buf to fit DNS TCP request */
		forge_tcp_request(buf, &recv_size);

		/*
		 * Make the DNS query on the TCP transport layer either using inprocess
		 * SSH or using an already created TCP tunnel (Ex: ssh -L ... on the
		 * command line).
		 */
		if (ssh_host != NULL) {
			/*
			 * Round robin option. We must create the ssh tunnel and close it
			 * at each DNS query.
			 */
			if (opt_rr_dns) {
				if ((open_dns_count - dns_index) == 0) {
					dns_index = 0;
				}

				/*
				 * We don't create a new SSH channel for the first run since it
				 * was created before the main loop hence the reason for
				 * dns_index being -1.
				 */
				if (dns_index != -1) {
					dns_ip = open_dns_list[dns_index];
					/*
					 * Create new SSH direct tcp channel. We don't care about
					 * the return value because on error, the next call will
					 * handle it.
					 */
					libssh2_channel_free(ssh_info->channel);
					ret = ssh_setup_tunnel(ssh_info, dns_ip);
					if (ret < 0) {
						continue;
					}
					DBG("Round robin DNS %s", dns_ip);
				}
				dns_index++;
			}
			recv_size = dig_ssh_request(ssh_info, buf, sizeof(buf),
					recv_size);
			if (ret < 0) {
				do {
					sleep(DEFAULT_RECONNECT_TIME);
					ret = ssh_setup_tunnel(ssh_info, dns_ip);
				} while (ret < 0);
				continue;
			}
		} else {
			recv_size = dig_tcp_request(tcp_dns_sock, buf, sizeof(buf),
					recv_size);
			if (recv_size < 0) {
				/* Connect to forward TCP server */
				do {
					/* Retry every DEFAULT_RECONNECT_TIME sec */
					sleep(DEFAULT_RECONNECT_TIME);
					tcp_dns_sock = setup_forward_tcp(forward_port, forward_ip);
				} while (tcp_dns_sock < 0);
				continue;
			}
		}

		/* Change buf to fit DNS UDP request */
		forge_udp_request(buf, &recv_size);

		ret = dns_udp_send_reply(udp_client_sock, buf, recv_size,
				(struct sockaddr *) &saddr, sizeof(saddr));
		if (ret < 0) {
			/* UDP client disconnected, continue serving */
			continue;
		}
	}

	/* Not suppose to get here */

error:
	ret = pthread_cancel(log_thread);
	if (ret == 0) {
		pthread_join(log_thread, &status);
	}
	close(tcp_dns_sock);
	close(udp_client_sock);

	cleanup(ret);

	return 0;
}
