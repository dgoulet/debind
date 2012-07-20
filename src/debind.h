/*
 * debind.h
 *
 * Debind basic defines for the main binary.
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

#ifndef _DEBIND_H
#define _DEBIND_H

#define DEFAULT_LOCAL_PORT             53
#define DEFAULT_LOCAL_IP               "127.0.0.1"
#define DEFAULT_FORWARD_PORT           1337
#define DEFAULT_FORWARD_IP             "127.0.0.1"

/* Logging is done via libnetfilter queue */
#define DEFAULT_LOG_FILENAME           "/tmp/dns-queries.log"
#define DEFAULT_NETFILTER_QUEUE_NUM    0

/* On connect error, this is the wait before reconnect default time */
#define DEFAULT_RECONNECT_TIME         30    /* sec */

/* Iptables rules used for DNAT DNS traffic */
#define IPTABLE_ADD_DNAT \
	"iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to %s:%d"
#define IPTABLE_DEL_DNAT \
	"iptables -t nat -D OUTPUT -p udp --dport 53 -j DNAT --to %s:%d"

/* Iptables rules used for netfilter queue logging */
#define IPTABLE_ADD_QUEUE \
	"iptables -A OUTPUT -p udp --dport %d -j NFQUEUE --queue-num %d"
#define IPTABLE_DEL_QUEUE \
	"iptables -D OUTPUT -p udp --dport %d -j NFQUEUE --queue-num %d"

/*
 * Open DNS list for round robin features. If you update this list, please
 * update counter below.
 */
const char *open_dns_list[] = {
	"8.8.8.8", "8.8.4.4",               /* Google */
	"156.154.70.1",                     /* Dnsadvantage */
	"208.67.222.222", "208.67.220.220", /* OpenDNS */
	"198.153.192.1", "198.153.194.1",   /* Norton */
};
const unsigned int open_dns_count = 7;

#endif /* _DEBIND_H */
