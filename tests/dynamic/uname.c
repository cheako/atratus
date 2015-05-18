/*
 * uname - Dump the system name
 *
 * Copyright (C)  2006-2012 Mike McCormack
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

int main(int argc, char **argv)
{
	struct utsname un;
	int r;

	memset(&un, 0, sizeof un);
	r = uname(&un);
	if (!r)
	{
		printf("sysname:    %s\n", un.sysname);
		printf("nodename:   %s\n", un.nodename);
		printf("release:    %s\n", un.release);
		printf("version:    %s\n", un.version);
		printf("machine:    %s\n", un.machine);
		printf("domainname: %s\n", un.domainname);
	}
	return 0;
}
