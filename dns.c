/*
 * dns.c
 *
 * Library used for DNS actions on packets.
 *
 * Copyright (C) 2011 - David Goulet <iam@truie.org>
 *                      Julien Desfossez <ju@klipix.org>
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

#include <stdio.h>
#include <string.h>
#include <time.h>

#define byte(x) (x & 0xff)

static void print_ip(FILE *fp, char *ip)
{
	fprintf(fp, "%d.%d.%d.%d", byte(ip[0]), byte(ip[1]), byte(ip[2]), byte(ip[3]));
}

static void print_port(FILE *fp, char *port)
{
	fprintf(fp, "%d", byte(port[0]) * 0x100 + byte(port[1]));
}

static void print_dns_type(FILE *fp, char *data)
{
	int type;

	type = byte(data[0]) * 0x100 + byte(data[1]);

	switch(type) {
	case 1:
		fprintf(fp, "A");
		break;
	case 2:
		fprintf(fp, "NS");
		break;
	case 5:
		fprintf(fp, "CNAME");
		break;
	case 6:
		fprintf(fp, "SOA");
		break;
	case 11:
		fprintf(fp, "WKS");
		break;
	case 12:
		fprintf(fp, "PTR");
		break;
	case 13:
		fprintf(fp, "HINFO");
		break;
	case 14:
		fprintf(fp, "MINFO");
		break;
	case 15:
		fprintf(fp, "MX");
		break;
	case 16:
		fprintf(fp, "TXT");
		break;
	case 28:
		fprintf(fp, "AAAA");
		break;
	default:
		fprintf(fp, "UNK (%d)", type);
		break;
	}
}

static void print_dns_name(FILE *fp, char *data, int len)
{
	int i = 0;

	do {
		if (data[i] < 0x21 || data[i] > 0x7e) {
			fprintf(fp, ".");
		} else {
			fprintf(fp, "%c", data[i]);
		}
		i++;
	} while (data[i] != '\0' && i < len);
}

void dns_log(FILE *fp, char *data)
{
	int name_len;
	time_t now;
	char *buf_time;

	now = time(NULL);
	buf_time = ctime(&now);

	buf_time[strlen(buf_time) - 1] = '\0';

	/* Log time */
	fprintf(fp, "%s: ", buf_time);

	fprintf(fp, "src: ");
	print_ip(fp, data + 12);
	fprintf(fp, ":");
	print_port(fp, data + 20);
	fprintf(fp, ", dst: ");
	print_ip(fp, data + 16);
	fprintf(fp, ":");
	print_port(fp, data + 22);

	/* RFC 1035 : labels must be 63 characters or less */
	name_len = strnlen(data + 41, 63);

	fprintf(fp, ", type: ");
	print_dns_type(fp, data + 41 + name_len + 1);

	fprintf(fp, ", name: ");
	print_dns_name(fp, data + 41, name_len);
	fprintf(fp, "\n");

	fflush(fp);
}
