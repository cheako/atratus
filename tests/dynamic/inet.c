/*
 * networking test
 *
 * Copyright (C)  2012 - 2013 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ok.h"

int test_inet_aton(void)
{
	struct in_addr in;

	OK(1 == inet_aton("127.0.0.1", &in));
	OK(in.s_addr == 127 + (1 << 24));
	OK(1 == inet_aton("192.168.254.1", &in));
	OK(in.s_addr == 192 + (168 << 8) + (254 << 16) + (1 << 24));
	OK(1 == inet_aton("0x7f.1", &in));
	OK(in.s_addr == 127 + (1 << 24));
	OK(0 == inet_aton("256.2", &in));
	OK(0 == inet_aton("256.256.256.1", &in));
	OK(0 == inet_aton("56.56.256.1", &in));
	OK(1 == inet_aton("127.1000", &in));
	OK(in.s_addr == 0xe803007f);
	OK(0 == inet_aton("127.1000.1000", &in));
	OK(1 == inet_aton("127.100.1000", &in));
	OK(in.s_addr == 0xe803647f);
	OK(0 == inet_aton("", &in));
	OK(0 == inet_aton("x", &in));
	OK(1 == inet_aton("1", &in));
	OK(in.s_addr == 0x01000000);
	OK(1 == inet_aton("0", &in));
	OK(in.s_addr == 0);

	return 1;
}

int test_inet_ntoa(void)
{
	struct in_addr in;

	in.s_addr = 127 + (1 << 24);
	OK(!strcmp(inet_ntoa(in), "127.0.0.1"));

	in.s_addr = 192 + (168 << 8) + (254 << 16) + (1 << 24);
	OK(!strcmp(inet_ntoa(in), "192.168.254.1"));

	return 1;
}

int test_inet_addr(void)
{
	OK((127 + (1 << 24)) == inet_addr("127.0.0.1"));
	OK((192 + (168 << 8) + (254 << 16) + (1 << 24)) ==
		inet_addr("192.168.254.1"));
	OK(~0 == inet_addr(""));

	return 1;
}

int test_inet_pton(void)
{
	unsigned char buffer[10];
	struct in_addr *inaddr = (void*) buffer;

	OK(1 == inet_pton(AF_INET, "127.0.0.1", buffer));
	OK(inaddr->s_addr == 0x0100007f);

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_inet_aton())
		return 1;

	if (!test_inet_ntoa())
		return 1;

	if (!test_inet_addr())
		return 1;

	if (!test_inet_pton())
		return 1;

	puts("OK");

	return 0;
}
