/*
 * netfilter.c
 *
 * Netfilter library interface.
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
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include "dns.h"
#include "log.h"

static struct nfq_handle *handle;
static struct nfq_q_handle *queue_handle;

static char *pkt_buffer;

static FILE *log_file;

static uint32_t extract_payload(struct nfq_data *tb)
{
	uint32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(tb, &pkt_buffer);

	return id;
}

static int packet_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	DBG("Netfilter callback");
	uint32_t id = extract_payload(nfa);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void netfilter_set_log(FILE *fp)
{
	log_file = fp;
}

/*
 * Parse packet buffer and write it to log file.
 */
void netfilter_write_log(void)
{
	dns_log(log_file, pkt_buffer);
}

/* Return netfilter queue fd */
int netfilter_init(void)
{
	int ret;

	handle = nfq_open();
	if (handle == NULL) {
		ERR("Error during nfq_open()");
		goto error;
	}

	ret = nfq_unbind_pf(handle, AF_INET);
	if (ret < 0) {
		ERR("error during nfq_unbind_pf()");
		goto error;
	}

	ret = nfq_bind_pf(handle, AF_INET);
	if (ret < 0) {
		ERR("error during nfq_bind_pf()");
		goto error;
	}

	queue_handle = nfq_create_queue(handle,  0, &packet_handler, NULL);
	if (queue_handle == NULL) {
		ERR("Error during nfq_create_queue");
		goto error;
	}

	ret = nfq_set_mode(queue_handle, NFQNL_COPY_PACKET, 0xffff);
	if (ret < 0) {
		ERR("can't set packet_copy mode");
		goto error;
	}

	return nfq_fd(handle);

error:
	return -1;
}

void netfilter_clean(void)
{
	nfq_destroy_queue(queue_handle);
	nfq_close(handle);
	if (log_file) {
		fclose(log_file);
	}
}

void *netfilter_thread(void *data)
{
	int fd, ret;
	FILE *fp = (FILE *)data;
	char buf[1024];

	fd = netfilter_init();
	if (fd < 0) {
		goto error;
	}

	netfilter_set_log(fp);

	while (1) {
		ret = recv(fd, buf, sizeof(buf), 0);
		if (ret < 0) {
			fprintf(fp, "Error in the netfilter thread\n");
			goto error;
		}

		nfq_handle_packet(handle, buf, ret);
		netfilter_write_log();
	}

error:
	netfilter_clean();
	return NULL;
}
