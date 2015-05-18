/*
 * signal handling test
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

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "ok.h"

int test_sig = -1;
siginfo_t test_info;

void test_handler(int sig)
{
	test_sig = sig;
}

int test_signal(void)
{
	struct sigaction sa = {{0}};
	struct sigaction old = {{0}};
	int r;

	sa.sa_handler = &test_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_restorer = 0;

	r = sigaction(SIGKILL, &sa, &old);
	OK(r == -1 && errno == EINVAL);

	r = sigaction(SIGUSR1, &sa, &old);
	OK(r == 0);

	OK(old.sa_handler == 0);
	OK(old.sa_flags == 0);
	OK(old.sa_restorer == 0);

	r = sigaction(SIGUSR1, &sa, NULL);
	OK(r == 0);

	r = sigaction(SIGUSR1, &sa, &old);
	OK(r == 0);

	OK(old.sa_handler == &test_handler);
	OK(old.sa_flags == 0);

	OK(test_sig == -1);

	r = kill(getpid(), SIGUSR1);
	OK(r == 0);

	OK(test_sig == SIGUSR1);

	return 1;
}

void test_handler2(int sig, siginfo_t *info, void *context)
{
	test_sig = sig;
	memcpy(&test_info, info, sizeof *info);
}

int test_sigaction(void)
{
	struct sigaction sa = {{0}};
	int r;

	sa.sa_sigaction = &test_handler2;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_restorer = 0;

	r = sigaction(SIGUSR1, &sa, NULL);
	OK(r == 0);

	test_sig = -1;

	r = kill(getpid(), SIGUSR1);
	OK(r == 0);

	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %1, %%ebx\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r)
	:"a"(37), "i"(SIGUSR1), "c"(1234), "d"(5678)
	:"memory");

	OK(test_sig == SIGUSR1);
	OK(test_info.si_signo == SIGUSR1);

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_signal())
		return 1;

	if (!test_sigaction())
		return 1;

	printf("OK\n");
	return 0;
}
