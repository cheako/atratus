/*
 * waitpid() test
 *
 * Copyright (C)  2013 Mike McCormack
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

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	int r;

	r = fork();
	if (r == 0)
	{
		while (1)
		{
		}
		_exit(0);
	}
	else
	{
		int child = r;
		int status;

		sleep(1);
		kill(child, SIGSTOP);
		sleep(1);
		status = 0;
		r = waitpid(-1, &status, WUNTRACED | WNOHANG);
		if (r != child)
			return 1;

		// status = 0000137f
		if (!WIFSTOPPED(status))
			return 1;
		if (WSTOPSIG(status) != SIGSTOP)
			return 1;

		sleep(1);
		kill(child, SIGCONT);
		sleep(1);

		kill(child, SIGTERM);
	}
	printf("ok\n");
	return 0;
}
