/*
 * basic dynamic linker
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

/*
 * TODO:
 *   - load libraries specified by DT_NEEDED
 *   - resolve symbols from symbol tables
 */

#include <sys/types.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/elf32.h>
#include <sys/elf_extra.h>
#include <limits.h>

#include "loader.h"
#include "string.h"
#include "stdlib.h"
#include "time.h"
#include "linux-errno.h"
#include "linux-defines.h"

#define NULL ((void *)0)

/*
 * errno should be per thread,
 * leave as global until we can load an ELF binary
 */
static int errno;
int verbose = 0;

#define EXPORT __attribute__((visibility("default")))

EXPORT char **environ;

EXPORT void abort(void);

static inline int set_errno(int r)
{
	if ((r & 0xfffff000) == 0xfffff000)
	{
		errno = -r;
		r = -1;
	}
	return r;
}

EXPORT void _exit(int status)
{
	while (1)
	{
		__asm__ __volatile__ (
			"\tpushl %%ebx\n"
			"\tmovl %%eax, %%ebx\n"
			"\tmov $1, %%eax\n"
			"\tint $0x80\n"
			"\tpopl %%ebx\n"
		:: "a"(status) : "memory");
	}
}

struct exit_fn
{
	void (*func) (void *);
	void *arg;
	void *dso_handle;
	struct exit_fn *next;
};

static struct exit_fn *first_exit_fn;

EXPORT void __cxa_atexit(void (*func) (void *), void * arg, void *dso_handle)
{
	struct exit_fn *efn;

	efn = malloc(sizeof *efn);
	if (!efn)
		abort();
	efn->func = func;
	efn->arg = arg;
	efn->dso_handle = dso_handle;

	efn->next = first_exit_fn;
	first_exit_fn = efn;
}

EXPORT void exit(int status)
{
	struct exit_fn *efn;

	/* call atexit functions */
	while ((efn = first_exit_fn))
	{
		efn->func(efn->arg);
		first_exit_fn = efn->next;
		free(efn);
	}

	_exit(status);
}

EXPORT int ioctl(int fd, int request, int value)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmovl $54, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd), "c"(request), "d"(value) : "memory");
	return set_errno(r);
}

EXPORT int read(int fd, void *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmovl $3, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd), "c"(buffer), "d"(length) : "memory");
	return set_errno(r);
}

int dl_write(int fd, const void *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $4, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd), "c"(buffer), "d"(length) : "memory");

	return set_errno(r);
}

EXPORT int write(int fd, const void *buffer, size_t length)
{
	return dl_write(fd, buffer, length);
}

EXPORT int open(const char *filename, int flags, int mode)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $5, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(filename), "c"(flags), "d"(mode)
	: "memory");

	return set_errno(r);
}

#define O_LARGEFILE 0100000

EXPORT int open64(const char *filename, int flags)
{
	return open(filename, flags | O_LARGEFILE, 0);
}

EXPORT off_t lseek(int fd, off_t offset, int whence)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $19, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd), "c"(offset), "d"(whence) : "memory");
	return set_errno(r);
}

typedef uint64_t off64_t;

EXPORT off64_t lseek64(int fd, off64_t offset, int whence)
{
	int r;
	unsigned int lo = (unsigned int) offset;
	unsigned int hi = (offset >> 32);
	off64_t result = 0;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $140, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(fd), "c"(hi), "d"(lo), "S"(&result), "D"(whence)
	: "memory");
	return set_errno(r);
}

EXPORT int close(int fd)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $6, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd) : "memory");

	return set_errno(r);
}

EXPORT int fork(void)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	: "=a"(r)
	: "a"(2)
	: "memory");
	return set_errno(r);
}

EXPORT int execve(const char *filename,
	char **argv,
	char **env)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $11, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(filename), "c"(argv), "d"(env)
	: "memory");

	return set_errno(r);
}

EXPORT int kill(pid_t pid, int signal)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $37, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(pid), "c"(signal) : "memory");
	return set_errno(r);
}

static int sys_getcwd(char *buf, size_t size)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $183, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(buf), "c"(size) : "memory");

	return set_errno(r);
}

EXPORT char *getcwd(char *buf, size_t size)
{
	int r;
	if (buf)
	{
		r = sys_getcwd(buf, size);
		if (r < 0)
		{
			set_errno(r);
			return NULL;
		}
		return buf;
	}

	if (size)
	{
		set_errno(-_L(EINVAL));
		return NULL;
	}

	size = 0x1000;
	buf = malloc(size);
	if (!buf)
		return NULL;
	while (1)
	{
		char *p;
		r = sys_getcwd(buf, size);
		if (r >= 0)
			break;

		if (r != -_L(ERANGE))
		{
			free(buf);
			buf = NULL;
			break;
		}

		size *= 2;
		p = realloc(buf, size);
		if (!p)
		{
			free(buf);
			buf = NULL;
			break;
		}

		buf = p;
	}

	return buf;
}

EXPORT int chdir(const char *path)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $12, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(path)
	: "memory");
	return set_errno(r);
}

EXPORT int getdents(int fd, void *de, int len)
{
	int r;
	__asm__ __volatile__(
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $141, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
		:"=a"(r)
		: "a"(fd), "c"(de), "d"(len)
		: "memory");
	return r;
}

EXPORT int getdents64(int fd, void *de, int len)
{
	int r;
	__asm__ __volatile__(
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $220, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
		:"=a"(r)
		: "a"(fd), "c"(de), "d"(len)
		: "memory");
	return r;
}

EXPORT int setuid(uid_t uid)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $23, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(uid)
	: "memory");
	return set_errno(r);
}

EXPORT int getuid(void)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $24, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r):: "memory");
	return set_errno(r);
}

EXPORT int setgid(gid_t gid)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $46, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(gid)
	: "memory");
	return set_errno(r);
}

EXPORT gid_t getgid(void)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $47, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r):: "memory");
	return set_errno(r);
}

EXPORT int geteuid(void)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $49, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r):: "memory");
	return set_errno(r);
}

EXPORT int getegid(void)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $50, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r):: "memory");
	return set_errno(r);
}

typedef int pid_t;
EXPORT pid_t getpid(void)
{
	pid_t r;
	__asm__ __volatile__ (
		"\tmov $20, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r):: "memory");
	return set_errno(r);
}

EXPORT pid_t getppid(void)
{
	pid_t r;
	__asm__ __volatile__ (
		"\tmov $64, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r):: "memory");
	return set_errno(r);
}

EXPORT int setreuid(int uid, int euid)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $70, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(uid), "c"(euid)
	: "memory");
	return set_errno(r);
}

EXPORT int setregid(int gid, int egid)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $71, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(gid), "c"(egid)
	: "memory");
	return set_errno(r);
}

EXPORT int pipe(int *fds)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $42, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(fds)
	: "memory");
	return set_errno(r);
}

EXPORT int waitpid(int pid, int *status, int options)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $7, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(pid), "c"(status), "d"(options)
	: "memory");
	return set_errno(r);
}

struct rusage;

EXPORT int wait3(int *status, int options, struct rusage *rusage)
{
	if (rusage)
		warn("wait3(): non-zero rusage\n");
	return waitpid(-1, status, options);
}

struct stat;

EXPORT int __xstat(int ver, const char *path, struct stat *st)
{
	int r;

	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $106, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(path), "c"(st) : "memory");
	return set_errno(r);
}

struct stat64;

EXPORT int __xstat64(int ver, const char *path, struct stat64 *st)
{
	int r;

	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $195, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(path), "c"(st) : "memory");
	return set_errno(r);
}

EXPORT int __lxstat64(int ver, const char *path, struct stat64 *st)
{
	int r;

	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $196, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(path), "c"(st) : "memory");
	return set_errno(r);
}

EXPORT int __fxstat64(int ver, int fd, struct stat64 *st)
{
	int r;

	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $197, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd), "c"(st) : "memory");
	return set_errno(r);
}

EXPORT int dup2(int oldfd, int newfd)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $63, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(oldfd), "c"(newfd) : "memory");

	return set_errno(r);
}

EXPORT time_t time(time_t *t)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmov %%eax, %%ebx\n"
		"\tmov $13, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(t) : "memory");
	return r;
}

struct timezone
{
	int tz_minuteswest;
	int tz_dsttime;
};

EXPORT int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmov %%eax, %%ebx\n"
		"\tmov $78, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(tv), "c"(tz) : "memory");
	return r;
}

void* sys_brk(void *addr)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmov %%eax, %%ebx\n"
		"\tmov $45, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(addr) : "memory");
	return (void*) set_errno(r);
}

EXPORT int fcntl(int fd, int cmd, int arg)
{
	int r;
	__asm__ __volatile__(
		"\tpushl %%ebx\n"
		"\tmov %%eax, %%ebx\n"
		"\tmov $55, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(fd), "c"(cmd), "d"(arg)
	: "memory");
	return set_errno(r);
}

typedef unsigned int mode_t;
EXPORT mode_t umask(mode_t mask)
{
	int r;
	__asm__ __volatile__(
		"\tpushl %%ebx\n"
		"\tmov %%eax, %%ebx\n"
		"\tmov $60, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(mask)
	: "memory");
	return set_errno(r);
}

struct pollfd
{
	int fd;
	short events;
	short revents;
};

EXPORT int poll(struct pollfd *pfds, int nfds, int timeout)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmov %%eax, %%ebx\n"
		"\tmov $168, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(pfds), "c"(nfds), "d"(timeout)
	: "memory");

	return set_errno(r);
}

int sys_select(void *args)
{
	int r;
	__asm__ __volatile__ (
		"\tmov %%eax, %%ebx\n"
		"\tmov $82, %%eax\n"
		"\tint $0x80\n"
	: "=a"(r)
	: "a"(args)
	: "memory");

	return set_errno(r);
}

EXPORT int select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout)
{
	struct {
		int nfds;
		fd_set *rfds;
		fd_set *wfds;
		fd_set *efds;
		struct timeval *tv;
	} args = { nfds, readfds, writefds, exceptfds, timeout };
	return sys_select(&args);
}

struct utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

EXPORT int uname(struct utsname *buf)
{
	int r;
	__asm__ __volatile__(
		"\tpushl %%ebx\n"
		"\tmov %%eax, %%ebx\n"
		"\tmov $122, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(buf)
	: "memory");
	return set_errno(r);
}

EXPORT int nanosleep(const struct timespec *req, struct timespec *rem)
{
	int r;
	__asm__ __volatile__(
		"\tpushl %%ebx\n"
		"\tmov %%eax, %%ebx\n"
		"\tmov $162, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	: "=a"(r)
	: "a"(req), "c"(rem)
	: "memory");
	return set_errno(r);
}

EXPORT int usleep(unsigned int usec)
{
	struct timeval tv;

	tv.tv_sec = usec / 1000000;
	tv.tv_usec = usec % 1000000;

	return select(0, NULL, NULL, NULL, &tv);
}

#define CTYPE_UPPER   (1 << 8)
#define CTYPE_LOWER   (1 << 9)
#define CTYPE_ALPHA   (1 << 10)
#define CTYPE_NUMERIC (1 << 11)
#define CTYPE_HEX     (1 << 12)
#define CTYPE_SPACE   (1 << 13)
#define CTYPE_PRINT   (1 << 14)
#define CTYPE_GRAPH   (1 << 15)
#define CTYPE_BLANK   (1 << 0)
#define CTYPE_CONTROL (1 << 1)
#define CTYPE_PUNCT   (1 << 2)
#define CTYPE_ALNUM   (1 << 3)

EXPORT int32_t ** __ctype_toupper_loc(void)
{
	static int a[128 + 256];
	static int *pa;

	if (!pa)
	{
		int i;
		pa = &a[128];
		for (i = 0; i < 256; i++)
		{
			int val = i;
			if (val >= 'a' && val <= 'z')
				val &= ~0x20;
			a[128 + i] = val;
			if (i >= 128)
				a[256 - i] = val;
		}
	}
	return &pa;
}

EXPORT int32_t ** __ctype_tolower_loc(void)
{
	static int a[128 + 256];
	static int *pa;

	if (!pa)
	{
		int i;
		pa = &a[128];
		for (i = 0; i < 256; i++)
		{
			int val = i;
			if (val >= 'a' && val <= 'z')
				val |= 0x20;
			a[128 + i] = val;
			if (i >= 128)
				a[256 - i] = val;
		}
	}
	return &pa;
}

EXPORT unsigned short ** __ctype_b_loc(void)
{
	static unsigned short a[128 + 256];
	static unsigned short *pa;

	if (!pa)
	{
		int i;
		pa = &a[128];
		for (i = 0; i < 256; i++)
		{
			unsigned short val = 0;
			if (i >= 'A' && i <= 'Z')
				val |= (CTYPE_UPPER | CTYPE_ALPHA | CTYPE_ALNUM);
			if (i >= 'a' && i <= 'z')
				val |= (CTYPE_LOWER | CTYPE_ALPHA | CTYPE_ALNUM);
			if (i >= '0' && i <= '9')
				val |= (CTYPE_NUMERIC | CTYPE_ALNUM);
			if ((i >= '0' && i <= '9') ||
			    (i >= 'a' && i <= 'f') ||
			    (i >= 'A' && i <= 'F'))
				val |= CTYPE_HEX;
			if (i == ' ' || i == '\t' || i == '\r' || i == '\n')
				val |= CTYPE_SPACE;
			if (i >= 0x20 && i <= 0x7f)
				val |= CTYPE_SPACE;

			a[128 + i] = val;
			if (i >= 128)
				a[256 - i] = val;
		}
	}

	return &pa;
}

unsigned int random_value;

EXPORT void srand(unsigned int seed)
{
	random_value = seed;
}

EXPORT int rand_r(unsigned int *seed)
{
	*seed ^= 0x0f00baa0;
	*seed += 0xfeedface;
	*seed = (*seed << 13) | (*seed >> 19);
	return *seed % INT_MAX;
}

EXPORT int rand(void)
{
	return rand_r(&random_value);
}

/* TODO: srandom/random use a better PRNG */
EXPORT void srandom(unsigned int seed)
{
	srand(seed);
}

EXPORT long int random()
{
	return rand();
}

EXPORT size_t strlen(const char *x)
{
	size_t n = 0;
	while (x[n])
		n++;
	return n;
}

EXPORT int strcmp(const char *a, const char *b)
{
	while (*a || *b)
	{
		if (*a == *b)
		{
			a++;
			b++;
			continue;
		}
		if (*a < *b)
			return -1;
		else
			return 1;
	}
	return 0;
}

EXPORT int strcoll(const char *a, const char *b)
{
	return strcmp(a, b);
}

EXPORT int strncmp(const char *a, const char *b, size_t n)
{
	int i;

	for (i = 0; i < n; i++)
	{
		if (a[i] == b[i])
			continue;
		if (a[i] < b[i])
			return -1;
		else
			return 1;
	}
	return 0;
}

EXPORT int memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *left = s1, *right = s2;
	int r = 0;
	int i;

	for (i = 0; r == 0 && i < n; i++)
		r = left[n] - right[n];

	return r;
}

struct _stdio_FILE
{
	int fd;
	char *read_buffer;
	size_t read_avail;
	size_t read_start;
	int flags;
	int fill[0x80/sizeof (int)];
};

/* make sure _stdio_FILE is 0x94 bytes */
typedef char static_test[sizeof (struct _stdio_FILE) == 0x94 ? 1 : -1];

typedef struct _stdio_FILE FILE;

#define STDIO_READ_BUFFER_SZ 0x1000
#define STDIO_READ_ERROR 1
#define STDIO_READ_EOF   2

static char __stdin_buffer[STDIO_READ_BUFFER_SZ];
static char __stdout_buffer[STDIO_READ_BUFFER_SZ];
static FILE __stdin_file = { 0, __stdin_buffer };
static FILE __stdout_file = { 1, __stdout_buffer };
static FILE __stderr_file = { 2, NULL };

static size_t stdio_read_to_buffer(FILE *f)
{
	int r;

	/* corruption or some calculation was bad */
	if ((f->read_start + f->read_avail) > STDIO_READ_BUFFER_SZ)
	{
		f->flags |= STDIO_READ_ERROR;
		return 0;
	}

	/* move everything to the start of the buffer */
	memmove(f->read_buffer,
		&f->read_buffer[f->read_start],
		f->read_avail);

	f->read_start = 0;

	r = read(f->fd,
		 &f->read_buffer[f->read_avail],
		 STDIO_READ_BUFFER_SZ - f->read_avail);
	if (r < 0)
	{
		f->flags |= STDIO_READ_ERROR;
		return 0;
	}
	else if (r == 0)
	{
		f->flags |= STDIO_READ_EOF;
		return 0;
	}

	f->read_avail += r;
	return r;
}

EXPORT FILE *stdin = &__stdin_file;
EXPORT FILE *stdout = &__stdout_file;
EXPORT FILE *stderr = &__stderr_file;

/* checks an fd is within the maximum fd set size */
EXPORT unsigned long int __fdelt_chk(unsigned long int fd)
{
	return fd;
}

EXPORT int fputs_unlocked(const char *str, FILE *stream)
{
	/* FIXME: use stream */
	int fd = stream->fd;
	size_t len = strlen(str);
	if (len != dl_write(fd, str, len))
		return EOF;
	return len;
}

EXPORT char *fgets_unlocked(char *s, int n, FILE *stream)
{
	int count = 0;

	if (n <= 0)
		return NULL;

	while (count < (n - 1))
	{
		if (stream->read_avail == 0 && !stdio_read_to_buffer(stream))
			break;

		if (!stream->read_avail)
			break;

		s[count] = stream->read_buffer[stream->read_start];
		stream->read_start++;
		stream->read_avail--;
		if (s[count] == '\n')
			break;
		count++;
	}

	if (count == 0)
		return NULL;

	s[count] = 0;

	return s;
}

EXPORT char *fgets(char *s, int n, FILE *stream)
{
	return fgets_unlocked(s, n, stream);
}

EXPORT int fputs(const char *str, FILE *stream)
{
	return fputs_unlocked(str, stream);
}

EXPORT FILE *fopen(const char *path, const char *mode)
{
	int fd;
	FILE *f;

	if (mode[0] == 'r' && mode[1] != '+')
	{
		fd = open(path, _L(O_RDONLY), 0);
		if (fd < 0)
			return NULL;
	}
	else if (mode[0] == 'w')
	{
		fd = open(path, _L(O_RDWR) | _L(O_CREAT), 0666);
		if (fd < 0)
			return NULL;
	}
	else
	{
		warn("unknown mode: fopen(%s)\n", mode);
		return NULL;
	}

	f = malloc(sizeof *f + STDIO_READ_BUFFER_SZ);
	if (!f)
	{
		dprintf("malloc failed\n");
		close(fd);
		return NULL;
	}

	f->fd = fd;
	f->flags = 0;
	f->read_buffer = (char*) &f[1];
	f->read_avail = 0;
	f->read_start = 0;

	return f;
}

EXPORT FILE *fopen64(const char *path, const char *mode)
{
	return fopen(path, mode);
}

EXPORT int fflush(FILE *stream)
{
	dprintf("fflush(%p)\n", stream);
	return 0;
}

EXPORT size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f)
{
	int r;

	/* TODO: handle buffering & file pointers correctly */
	r = write(f->fd, ptr, size * nmemb);
	if (r < 0)
		f->flags |= STDIO_READ_ERROR;
	else
		f->flags &= ~3;
	if (r != size * nmemb)
		return 0;

	return nmemb;
}

EXPORT size_t fread(void *ptr, size_t size, size_t nmemb, FILE *f)
{
	dprintf("fread(%p,%zd,%zd,%p)\n", ptr, size, nmemb, f);
	return 0;
}

EXPORT int fputc(int c, FILE *stream)
{
	char ch = c;
	return fwrite(&ch, 1, 1, stream);
}

EXPORT int putc_unlocked(int c, FILE *stream)
{
	char ch = c;

	if (1 != write(stream->fd, &ch, 1))
		return EOF;

	return c;
}

EXPORT int puts(const char *str)
{
	int r = fputs_unlocked(str, stdout);
	putc_unlocked('\n', stdout);
	return r + 1;
}

EXPORT int putchar_unlocked(int c)
{
	return putc_unlocked(c, stdout);
}

EXPORT int putchar(int c)
{
	return fputc(c, stdout);
}

EXPORT int _IO_putc(int c, FILE *stream)
{
	return fputc(c, stream);
}

EXPORT int getc_unlocked(FILE *stream)
{
	unsigned char ch;

	if (stream->read_avail == 0 &&
		!stdio_read_to_buffer(stream))
	{
		return EOF;
	}

	if (!stream->read_avail)
	{
		return EOF;
	}

	ch = stream->read_buffer[stream->read_start];

	stream->read_start++;
	stream->read_avail--;

	return ch;
}

EXPORT int getc(FILE *stream)
{
	return getc_unlocked(stream);
}

EXPORT int getchar(void)
{
	return getc(stdin);
}

EXPORT void clearerr(FILE *f)
{
	f->flags &= ~(STDIO_READ_ERROR | STDIO_READ_EOF);
}

EXPORT int ferror(FILE *f)
{
	return f->flags & STDIO_READ_ERROR;
}

EXPORT int feof(FILE *f)
{
	return f->flags & STDIO_READ_EOF;
}

EXPORT int fclose(FILE *f)
{
	if (f != stdin && f != stdout && f != stderr)
	{
		close(f->fd);
		f->fd = -1;
		f->flags = 0;

		free(f);
		return 0;
	}
	return -1;
}

#define DIR_MAGIC 0xd1aad1ab

typedef struct
{
	int magic;
	int fd;
	int available;
	int used;
	unsigned char buffer[0x1000];
} DIR;

EXPORT DIR *opendir(const char *name)
{
	int fd;
	DIR *dir;

	fd = open(name, _L(O_RDONLY), 0);
	if (fd < 0)
		return NULL;

	dir = malloc(sizeof *dir);
	if (dir)
	{
		dir->magic = DIR_MAGIC;
		dir->fd = fd;
		dir->available = 0;
		dir->used = 0;
	}
	else
		close(fd);

	return dir;
}

EXPORT struct dirent *readdir(DIR *dir)
{
	warn("readdir()\n");
	return NULL;
}

EXPORT struct linux_dirent64 *readdir64(DIR *dir)
{
	struct linux_dirent64 *de;
	int r;

	if (!dir || dir->magic != DIR_MAGIC)
		return NULL;

	if (dir->available == dir->used)
	{
		r = getdents64(dir->fd, dir->buffer, sizeof dir->buffer);
		if (r <= 0)
			return NULL;

		dir->available = r;
		dir->used = 0;

		de = (void*) dir->buffer;
	}
	else
	{
		de = (void*) (&dir->buffer[dir->used]);
		dir->used += de->d_reclen;
		de = (void*) (&dir->buffer[dir->used]);
	}

	return de;
}

EXPORT int closedir(DIR *dir)
{
	if (!dir || dir->magic != DIR_MAGIC)
		return -1;

	close(dir->fd);
	dir->magic = 0;
	free(dir);

	return 0;
}

EXPORT void perror(const char *s)
{
	__printf_chk(0, "%s: errno=%d\n", s, errno);
}

EXPORT char* setlocale(int category, const char *locale)
{
	warn("setlocale(%d,%s)\n", category, locale);
	return "en_US.UTF-8";
}

EXPORT char *bindtextdomain(const char *domain,
				 const char *dirname)
{
	warn("bindtextdomain(%s,%s)\n", domain, dirname);
	return NULL;
}

EXPORT char *textdomain(const char *domain)
{
	warn("textdomain(%s)\n", domain);
	return NULL;
}

EXPORT char *dcgettext(const char *domain,
			const char *msgid,
			int category)
{
	/* TODO: implement properly */
	return (char*) msgid;
}

/* ignore leap seconds... */
EXPORT struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	int days_per_year = 365; /* 4 years */
	int days_per_4_years = days_per_year * 4 + 1; /* 4 years */
	int days_per_100_years = days_per_4_years * 25 - 1; /* 100 years */
	int days_per_400_years = days_per_100_years * 4 + 1; /* 400 years */
	int days_1970til2000 = days_per_4_years * 7 + days_per_year * 2; /* 30 years */
	int yrs400, yrs100, yrs4, yrs;
	int mdays[] = {
		31, 28, 31, 30, 31, 30,
		31, 31, 30, 31, 30, 31
	};
	int i;
	time_t t = *timep;

	result->tm_sec = t % 60;
	t /= 60;
	result->tm_min = t % 60;
	t /= 60;
	result->tm_hour = t % 24;
	t /= 24;

	/* unix time starts in 1970, rebase from 1600 */
	t += (days_per_400_years - days_1970til2000);

	result->tm_wday = (t + 6) % 7;

	yrs400 = t / days_per_400_years;
	t %= days_per_400_years;
	yrs100 = t / days_per_100_years;
	t %= days_per_100_years;
	yrs4 = t / days_per_4_years;
	t %= days_per_4_years;
	yrs = t / days_per_year;
	t %= days_per_year;

	/* count from 1900 */
	result->tm_year = 1600 + (yrs400 * 400 + yrs100 * 100 + yrs4 * 4 + yrs) - 1900;
	result->tm_yday = t;
	result->tm_mon = 0;

	if (yrs == 0)
		mdays[1] = 29;
	for (i = 0; i < 12; i++)
	{
		if (t < mdays[i])
			break;
		t -= mdays[i];
		result->tm_mon++;
	}

	result->tm_mday = t + 1;

	return result;
}

EXPORT struct tm *localtime_r(const time_t *timep, struct tm *result)
{
	int offset = 60 * 60 * 10;	/* EST - Sydney time... */
	time_t t = *timep;

	t += offset;

	return gmtime_r(&t, result);
}

EXPORT struct tm *localtime(const time_t *timep)
{
	static struct tm result;

	return localtime_r(timep, &result);
}

static const char *time_wday[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *time_month[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

static const char *time_full_month[] = {
	"January", "Febuary", "March", "April", "May", "June",
	"July", "August", "September", "October", "November", "December",
};

EXPORT long __timezone;
EXPORT long __timezone;
EXPORT int __daylight;

EXPORT char *asctime_r(const struct tm *tm, char *out)
{
	int y = tm->tm_year + 1900;
	int n = 0;

	strcpy(out+n, time_wday[tm->tm_wday]);
	n += 3;
	out[n++] = ' ';
	strcpy(out+n, time_month[tm->tm_mon]);
	n += 3;
	out[n++] = ' ';
	out[n++] = (tm->tm_mday / 10) + '0';
	out[n++] = (tm->tm_mday % 10) + '0';
	out[n++] = ' ';
	out[n++] = (tm->tm_hour / 10) + '0';
	out[n++] = (tm->tm_hour % 10) + '0';
	out[n++] = ':';
	out[n++] = (tm->tm_min / 10) + '0';
	out[n++] = (tm->tm_min % 10) + '0';
	out[n++] = ':';
	out[n++] = (tm->tm_sec / 10) + '0';
	out[n++] = (tm->tm_sec % 10) + '0';
	out[n++] = ' ';
	out[n++] = (y / 1000) % 10 + '0';
	out[n++] = (y / 100) % 10 + '0';
	out[n++] = (y / 10) % 10 + '0';
	out[n++] = y % 10 + '0';
	out[n++] = '\n';
	out[n++] = 0;

	return out;
}

EXPORT char *asctime(struct tm *tm)
{
	static char out[64];
	return asctime_r(tm, out);
}

EXPORT char *ctime(const time_t *timep)
{
	return asctime(localtime(timep));
}

EXPORT size_t strftime(char *s, size_t max,
			const char *format,
			const struct tm *tm)
{
	int i, n = 0, len;
	int saw_percent = 0;

	for (i = 0; format[i]; i++)
	{
		if (!saw_percent)
		{
			if (format[i] == '%')
				saw_percent = 1;
			else if (n < max)
				s[n++] = format[i];
		}
		else
		{
			switch (format[i])
			{
			case 'a': /* abbreviated weekname day */
				if ((n + 3) > max)
					return 0;
				strcpy(&s[n], time_wday[tm->tm_wday]);
				n += 3;
				break;
			case 'b': /* abbreviated month name */
				if ((n + 3) > max)
					return 0;
				strcpy(&s[n], time_month[tm->tm_mon]);
				n += 3;
				break;
			case 'B':
				len = strlen(time_full_month[tm->tm_mon]);
				if ((n + len) > max)
					return 0;
				strcpy(&s[n], time_full_month[tm->tm_mon]);
				n += len;
				break;
			case 'e': /* day of month, 2 characters, leading space */
				if ((n + 2) > max)
					return 0;
				if (tm->tm_mday > 9)
					s[n++] = (tm->tm_mday / 10) + '0';
				else
					s[n++] = ' ';
				s[n++] = (tm->tm_mday % 10) + '0';
				break;
			case 'H':
				if ((n + 2) > max)
					return 0;
				s[n++] = (tm->tm_hour / 10) + '0';
				s[n++] = (tm->tm_hour % 10) + '0';
				break;
			case 'M':
				if ((n + 2) > max)
					return 0;
				s[n++] = (tm->tm_min / 10) + '0';
				s[n++] = (tm->tm_min % 10) + '0';
				break;
			case 'S':
				if ((n + 2) > max)
					return 0;
				s[n++] = (tm->tm_sec / 10) + '0';
				s[n++] = (tm->tm_sec % 10) + '0';
				break;
			case 'Z':
				if ((n + 3) > max)
					return 0;
				/* Australian Eastern standard time */
				s[n++] = 'E';
				s[n++] = 'S';
				s[n++] = 'T';
				break;
			case 'Y':
				if ((n + 4) > max)
					return 0;
				s[n++] = ((tm->tm_year + 1900) / 1000) % 10 + '0';
				s[n++] = ((tm->tm_year + 1900) / 100) % 10 + '0';
				s[n++] = ((tm->tm_year + 1900) / 10) % 10 + '0';
				s[n++] = ((tm->tm_year + 1900) / 1) % 10 + '0';
				break;
			default:
				dprintf("strftime(): %c unhandled\n", format[i]);
			}
			saw_percent = 0;
		}
	}

	if (n < max)
		s[n] = 0;
	else
		return 0;

	return n;
}

struct printf_output
{
	int (*fn)(struct printf_output *pfo, const char *str, size_t len);
	int width;
	int maxwidth;
	int left_justify;
	char pad;
	char *buffer;
	size_t max;
	size_t out_size;
	FILE *f;
};

static void pf_output(struct printf_output *pfo,
		 const char *buf, size_t len)
{
	int i;

	/* add characters for left or right justification */
	if (!pfo->left_justify)
		for (i = 0; (i + len) < pfo->width; i++)
			pfo->fn(pfo, &pfo->pad, 1);

	pfo->fn(pfo, buf, len);

	if (pfo->left_justify)
		for (i = 0; (i + len) < pfo->width; i++)
			pfo->fn(pfo, &pfo->pad, 1);
}

static void pf_decimal(int value, struct printf_output *pfo)
{
	char buf[32];
	int n = sizeof buf;
	int sign = 1;

	if (value < 0)
		sign = -1;

	while (value)
	{
		buf[--n] = '0' + (sign * value % 10);
		value /= 10;
	}

	if (n == sizeof buf)
		buf[--n] = '0';
	if (sign < 0)
		buf[--n] = '-';

	pf_output(pfo, &buf[n], sizeof buf - n);
}

static void pf_unsigned(unsigned int value, struct printf_output *pfo)
{
	char buf[32];
	int n = sizeof buf;

	while (value)
	{
		buf[--n] = '0' + value % 10;
		value /= 10;
	}

	if (n == sizeof buf)
		buf[--n] = '0';

	pf_output(pfo, &buf[n], sizeof buf - n);
}

static void pf_octal(int value, struct printf_output *pfo)
{
	char buf[32];
	int n = sizeof buf;

	while (value)
	{
		buf[--n] = '0' + value % 8;
		value /= 8;
	}

	if (n == sizeof buf)
		buf[--n] = '0';

	pf_output(pfo, &buf[n], sizeof buf - n);
}

static char to_hex(int value)
{
	if (value <= 9)
		return value + '0';
	else
		return value + 'a' - 10;
}

static void pf_hex(unsigned int value, struct printf_output *pfo)
{
	char buf[32];
	int n = sizeof buf;

	while (value)
	{
		unsigned int nybble = value & 15;
		buf[--n] = to_hex(nybble);
		value /= 16;
	}

	pf_output(pfo, &buf[n], sizeof buf - n);
}

static void pf_pointer(void *value, struct printf_output *pfo)
{
	int i;
	char buf[10];
	unsigned int x = (unsigned int) value;

	buf[0] = '0';
	buf[1] = 'x';

	for (i = 0; i < 8; i++)
		buf[2 + i] = to_hex((x >> (28 - i * 4)) & 0x0f);

	pf_output(pfo, buf, sizeof buf);
}

static void pf_string(const char *value, struct printf_output *pfo)
{
	size_t len;

	if (!value)
		value = "(null)";

	len = strlen(value);
	if (len > pfo->maxwidth)
		len = pfo->maxwidth;

	pf_output(pfo, value, len);
}

static void pf_char(char value, struct printf_output *pfo)
{
	pf_output(pfo, &value, 1);
}

static int internal_vsprintf(int flags, const char *str, va_list va,
				struct printf_output *pfo)
{
	const char *p = str;
	int lng;

	while (*p)
	{
		size_t len = 0;

		while (p[len] && p[len] != '%')
			len++;
		if (len)
		{
			pfo->fn(pfo, p, len);
			p += len;
			continue;
		}

		if (!*p)
			break;

		p++;

		pfo->width = 0;
		if (*p == '-')
		{
			pfo->left_justify = 1;
			p++;
		}
		else
			pfo->left_justify = 0;

		if (*p == '0')
		{
			pfo->pad = '0';
			p++;
		}
		else
			pfo->pad = ' ';
		if (*p == '*')
		{
			pfo->width = va_arg(va, int);
			p++;
		}
		else while (*p >= '0' && *p <= '9')
		{
			pfo->width *= 10;
			pfo->width += (*p - '0');
			p++;
		}

		if (*p == '.')
		{
			pfo->maxwidth = 0;
			p++;
			if (*p == '*')
			{
				pfo->maxwidth = va_arg(va, int);
				p++;
			}
			while (*p >= '0' && *p <= '9')
			{
				pfo->maxwidth *= 10;
				pfo->maxwidth += (*p - '0');
				p++;
			}
		}
		else
			pfo->maxwidth = INT_MAX;

		/* long */
		lng = 0;
		if (*p == 'l')
		{
			lng++;
			p++;
		}
		if (*p == 'l')
		{
			lng++;
			p++;
		}

		switch (*p)
		{
		case '%':
			pfo->fn(pfo, p, 1);
			p++;
			break;
		case 'd':
			if (lng > 1)
				pf_decimal(va_arg(va, long long int), pfo);
			else if (lng == 1)
				pf_decimal(va_arg(va, long int), pfo);
			else
				pf_decimal(va_arg(va, int), pfo);
			p++;
			break;
		case 'u':
			if (lng > 1)
				pf_unsigned(va_arg(va, unsigned long long int), pfo);
			else if (lng == 1)
				pf_unsigned(va_arg(va, unsigned long int), pfo);
			else
				pf_unsigned(va_arg(va, unsigned int), pfo);
			p++;
			break;
		case 'o':
			if (lng > 1)
				pf_octal(va_arg(va, long long int), pfo);
			else if (lng == 1)
				pf_octal(va_arg(va, long int), pfo);
			else
				pf_octal(va_arg(va, int), pfo);
			p++;
			break;
		case 'x':
			if (lng > 1)
				pf_hex(va_arg(va, unsigned long long int), pfo);
			if (lng)
				pf_hex(va_arg(va, unsigned long int), pfo);
			else
				pf_hex(va_arg(va, unsigned int), pfo);
			p++;
			break;
		case 'p':
			pf_pointer(va_arg(va, void*), pfo);
			p++;
			break;
		case 's':
			pf_string(va_arg(va, const char*), pfo);
			p++;
			break;
		case 'c':
			pf_char(va_arg(va, int), pfo);
			p++;
			break;
		default:
			warn("printf(): %c unhandled\n", *p);
			return 0;
		}
	}
	return pfo->out_size;
}

static int printf_chk_pfo(struct printf_output *pfo, const char *str, size_t len)
{
	dl_write(1, str, len);
	pfo->out_size += len;
	return 1;
}

EXPORT int vprintf(const char *str, va_list va)
{
	struct printf_output pfo =
	{
		.fn = &printf_chk_pfo,
		.out_size = 0,
		.buffer = NULL,
		.max = 0,
	};

	return internal_vsprintf(0, str, va, &pfo);
}

EXPORT int __vprintf_chk(int flag, const char *str, va_list va)
{
	return vprintf(str, va);
}

EXPORT int __printf_chk(int flag, const char *str, ...)
{
	va_list va;
	int r;

	va_start(va, str);

	r = __vprintf_chk(flag, str, va);

	va_end(va);

	return r;
}

static int snprintf_chk_pfo(struct printf_output *pfo, const char *str, size_t len)
{
	if (pfo->out_size + len < pfo->max)
		memcpy(&pfo->buffer[pfo->out_size], str, len);
	else if (pfo->out_size < pfo->max)
	{
		/* partial copy */
		memcpy(&pfo->buffer[pfo->out_size], str,
			 pfo->max - pfo->out_size);
	}
	pfo->out_size += len;
	return 1;
}

EXPORT int __vsprintf_chk(char *out, int flag, size_t maxlen, const char *str, va_list va)
{
	int r;
	struct printf_output pfo =
	{
		.fn = &snprintf_chk_pfo,
		.out_size = 0,
		.buffer = out,
		.max = maxlen,
	};

	r = internal_vsprintf(flag, str, va, &pfo);

	pfo.buffer[pfo.out_size] = 0;

	return r;
}

EXPORT int __sprintf_chk(char *out, int flag, size_t maxlen, const char *str, ...)
{
	va_list va;
	int r;

	va_start(va, str);
	r = __vsprintf_chk(out, flag, maxlen, str, va);
	va_end(va);

	return r;
}

EXPORT int __vsnprintf_chk(char *out, size_t maxlen, int flag,
			 size_t slen, const char *str, va_list va)
{
	int r;
	struct printf_output pfo =
	{
		.fn = &snprintf_chk_pfo,
		.out_size = 0,
		.buffer = out,
		.max = maxlen ? maxlen - 1 : 0,
	};

	if (slen < maxlen)
		die("snprintf overflow\n");

	r = internal_vsprintf(flag, str, va, &pfo);

	if (maxlen)
	{
		if (pfo.out_size < pfo.max)
			pfo.buffer[pfo.out_size] = 0;
		else
			pfo.buffer[pfo.max] = 0;
	}

	return r;
}

EXPORT int vsnprintf(char *out, size_t maxlen,
			const char *str, va_list va)
{
	return __vsnprintf_chk(out, maxlen, 0, INT_MAX, str, va);
}

EXPORT int __snprintf_chk(char *out, size_t maxlen, int flag,
			 size_t slen, const char *str, ...)
{
	va_list va;
	int r;

	va_start(va, str);
	r = __vsnprintf_chk(out, maxlen, flag, slen, str, va);
	va_end(va);

	return r;
}

static int fprintf_chk_pfo(struct printf_output *pfo, const char *str, size_t len)
{
	fwrite(str, len, 1, pfo->f);
	pfo->out_size += len;
	return 0;
}

EXPORT int __vfprintf_chk(FILE *stream, int flags, const char *fmt, va_list va)
{
	struct printf_output pfo =
	{
		.fn = &fprintf_chk_pfo,
		.out_size = 0,
		.buffer = NULL,
		.max = 0,
		.f = stream,
	};

	return internal_vsprintf(flags, fmt, va, &pfo);
}

EXPORT int __fprintf_chk(FILE *stream, int flags, const char *fmt, ...)
{
	va_list va;
	int r;

	va_start(va, fmt);
	r = __vfprintf_chk(stream, flags, fmt, va);
	va_end(va);
	return r;
}

static int vasprintf_chk_pfo(struct printf_output *pfo, const char *str, size_t len)
{
	if (pfo->out_size == 0)
	{
		pfo->buffer = malloc(len + 1);
	}
	else
	{
		void *t = realloc(pfo->buffer, pfo->out_size + len + 1);
		if (!t)
			return 0;
		pfo->buffer = t;
	}
	memcpy(&pfo->buffer[pfo->out_size], str, len);
	pfo->out_size += len;
	return 1;
}

EXPORT int __vasprintf_chk(char **strp, int flags, const char *fmt, va_list va)
{
	int r;
	struct printf_output pfo =
	{
		.fn = &vasprintf_chk_pfo,
		.out_size = 0,
		.buffer = NULL,
		.max = 0,
	};

	r = internal_vsprintf(flags, fmt, va, &pfo);

	pfo.buffer[pfo.out_size] = 0;

	*strp = pfo.buffer;

	return r;
}

EXPORT int __asprintf_chk(char **strp, int flags, const char *fmt, ...)
{
	va_list va;
	int r;

	va_start(va, fmt);
	r = __vasprintf_chk(strp, flags, fmt, va);
	va_end(va);

	return r;
}

void warn(const char *str, ...)
{
	va_list va;

	va_start(va, str);
	vprintf(str, va);
	va_end(va);
}

void dprintf(const char *str, ...)
{
	va_list va;

	if (!verbose)
		return;
	va_start(va, str);
	vprintf(str, va);
	va_end(va);
}

void die(const char *str, ...)
{
	va_list va;

	va_start(va, str);
	vprintf(str, va);
	va_end(va);

	abort();
}


#define STRTOX_IMPL							\
	int sign = 1;							\
									\
	value = 0;							\
									\
	while (*nptr == ' ' || *nptr == '\t')				\
		nptr++;							\
									\
	if (*nptr == '-')						\
	{								\
		nptr++;							\
		sign = -1;						\
	}								\
	else if (*nptr == '+')						\
		nptr++;							\
	else if ((base == 0 || base == 0x10) &&				\
		nptr[0] == '0' && (nptr[1] == 'x' || nptr[1] == 'X'))	\
	{								\
		nptr += 2;						\
		base = 0x10;						\
	}								\
									\
	/* TODO: handle other bases */					\
									\
	while (1)							\
	{ 								\
		int ch = *nptr; 					\
									\
		if (ch >= '0' && ch <= '9')				\
			ch -= '0';					\
		else if (ch >= 'A' && ch <= 'Z')			\
			ch -= ch - 'A' + 10;				\
		else if (ch >= 'a' && ch <= 'z')			\
			ch -= ch - 'a' + 10;				\
		else							\
			break;						\
									\
		if (ch >= base)						\
			break;						\
									\
		/* TODO: check overflow, set errno and return ULONG_MAX */ \
									\
		value *= base;						\
		value += ch;						\
		nptr++;							\
	}								\
									\
	value *= sign;							\
									\
	if (endptr)							\
		*endptr = (char*) nptr;					\
									\
	return value

EXPORT unsigned long strtoul(const char *nptr, char **endptr, int base)
{
	unsigned long value;
	STRTOX_IMPL;
}

EXPORT long long int strtoll(const char *nptr, char **endptr, int base)
{
	long long value;
	STRTOX_IMPL;
}

EXPORT long int strtol(const char *nptr, char **endptr, int base)
{
	long int value;
	STRTOX_IMPL;
}

EXPORT unsigned long long int strtoull(const char *nptr, char **endptr, int base)
{
	unsigned long long value;
	STRTOX_IMPL;
}

EXPORT char *strerror(int errno)
{
	static char buf[32];

	__sprintf_chk(buf, 0, sizeof buf, "errno=%u", errno);

	return buf;
}

EXPORT void abort(void)
{
	kill(getpid(), _L(SIGABRT));
	exit(1);
}

EXPORT int mallopt(int param, int value)
{
	switch (param)
	{
	case -1:
		dprintf("mallopt(M_TRIM_THRESHOLD,%d)\n", value);
		break;
	case -2:
		dprintf("mallopt(M_TOP_PAD,%d)\n", value);
		break;
	case -3:
		dprintf("mallopt(M_MMAP_THRESHOLD,%d)\n", value);
		break;
	default:
		dprintf("mallopt(%d,%d)\n", param, value);
	}
	return 0;
}

struct heap_block
{
	unsigned int magic:31;
	unsigned int used:1;
	struct heap_block *next;
	size_t sz;	/* size of this block including the header */
};

#define HEAP_MAGIC 0x79a7b3f1

static struct heap_block *first_block;

static void heap_split_block(struct heap_block *p, size_t sz)
{
	struct heap_block *next = p->next;
	size_t block_sz = sz + sizeof *p;

	/* too small, don't split */
	if (sz + 3 * sizeof *p > p->sz)
		return;

	p->next = (void*) (((char*)p) + block_sz);
	p->next->sz = p->sz - block_sz;
	p->next->used = 0;
	p->next->next = next;
	p->next->magic = HEAP_MAGIC;
	p->sz = block_sz;
}

static int heap_can_merge_next(struct heap_block *p)
{
	char *end = (char*)p + p->sz;
	return (p->next &&
		!p->next->used &&
		end == (char*) p->next);
}

static void heap_merge_next(struct heap_block *p)
{
	struct heap_block *next = p->next;

	dprintf("Merging %p with next %p\n", p, next);

	p->sz += next->sz;
	p->next = next->next;
	next->magic = 0x7fffffff;
	next->next = (void*) 0xffffffff;
	next->sz = 0;
}

static size_t heap_block_sz(struct heap_block *p)
{
	return p->sz - sizeof *p;
}

static void heap_compress(void)
{
	struct heap_block *p = first_block;

	while (p)
	{
		if (p->magic != HEAP_MAGIC)
		{
			die("heap magic wrong! %p %08x\n", p, p->magic);
		}
		if (p->next && p->next <= p)
		{
			die("heap not linear! %p -> %p\n", p, p->next);
		}
		if (p->sz < sizeof (*p))
		{
			die("heap block too small! %p\n", p);
		}
		if (!p->used)
		{
			/* merge blocks if they're contiguous */
			if (heap_can_merge_next(p))
			{
				heap_merge_next(p);
				continue;
			}
		}
		p = p->next;
	}
}

static void heap_free_block(struct heap_block *p)
{
	p->used = 0;
	heap_compress();
}

EXPORT void *malloc(size_t sz)
{
	struct heap_block **p;
	void *r;

	/* round the size */
	sz += (sizeof **p - 1);
	sz &= ~(sizeof **p - 1);

	for (p = &first_block; *p; p = &((*p)->next))
	{
		if ((*p)->magic != HEAP_MAGIC)
			die("malloc(): corrupt heap %p\n", *p);
		if ((*p)->used)
			continue;
		if (heap_block_sz(*p) >= sz)
			break;
	}

	/* extend brk() if necessary */
	if (!*p)
	{
		int brk_sz = (sz + sizeof **p + 0xfff) & ~0xfff;
		void *r;
		void *cur_brk;

		cur_brk = sys_brk(0);
		r = sys_brk((char*)cur_brk + brk_sz);
		if (!r)
			return NULL;

		*p = (void*)((char*)r - brk_sz);
		(*p)->magic = HEAP_MAGIC;
		(*p)->sz = brk_sz;
		(*p)->next = NULL;
		(*p)->used = 0;
	}

	/* split block (if necessary) */
	heap_split_block(*p, sz);

	(*p)->used = 1;
	r = ((*p) + 1);

	heap_compress();

	dprintf("malloc -> %p\n", r);

	return r;
}

EXPORT void *realloc(void *ptr, size_t mem)
{
	struct heap_block *p = ptr;
	void *nb;
	size_t old_size;

	if (!ptr)
	{
		nb = malloc(mem);
		goto out;
	}

	p--;

	if (p->magic != HEAP_MAGIC)
		die("realloc(): corrupt heap %p\n", ptr);

	if (!p->used)
		die("realloc(): memory not allocated %p\n", ptr);

	old_size = heap_block_sz(p);
	if (old_size >= mem)
	{
		nb = ptr;
		goto out;
	}

	/* merge with the next block if it's free */
	while (heap_can_merge_next(p))
		heap_merge_next(p);

	if (heap_block_sz(p) >= mem)
	{
		heap_split_block(p, mem);
		nb = &p[1];
		goto out;
	}

	/* allocate a totally new block */
	nb = malloc(mem);
	if (!nb)
	{
		nb = NULL;
		goto out;
	}

	memcpy(nb, &p[1], old_size);

	heap_free_block(p);

out:
	dprintf("realloc -> %p\n", nb);

	return nb;
}

EXPORT void free(void *ptr)
{
	struct heap_block *p = ptr;

	if (!ptr)
		return;

	p--;

	if (p->magic != HEAP_MAGIC)
		die("free(): corrupt heap %p\n", ptr);

	if (!p->used)
		die("realloc(): memory not allocated %p\n", ptr);

	heap_free_block(p);
}

EXPORT void *memset(void *s, int c, size_t n)
{
	unsigned char *uc = s;
	size_t i;

	for (i = 0; i < n; i++)
		uc[i] = c;
	return s;
}

EXPORT void *memcpy(void *dest, const void *src, size_t n)
{
	const unsigned char *sc = src;
	unsigned char *dc = dest;
	int i;

	for (i = 0; i < n; i++)
		dc[i] = sc[i];

	return dest;
}

EXPORT void *mempcpy(void *dest, const void *src, size_t n)
{
	memcpy(dest, src, n);
	return (char*) dest + n;
}

EXPORT void *__memcpy_chk(void *dest, const void *src, size_t n, size_t destsize)
{
	if (destsize < n)
		die("bad memcpy");
	return memcpy(dest, src, n);
}

EXPORT void *memmove(void *dest, const void *src, size_t n)
{
	const unsigned char *sc = src;
	unsigned char *dc = dest;
	int i;

	if (sc > dc)
	{
		for (i = 0; i < n; i++)
			dc[i] = sc[i];
	}
	else
	{
		for (i = 0; i < n; i++)
			dc[n - i - 1] = sc[n - i - 1];
	}

	return dest;
}

EXPORT int *__errno_location(void)
{
	return &errno;
}

EXPORT char *strrchr(const char *s, int c)
{
	int n = strlen(s) + 1;

	while (n)
	{
		n--;
		if (s[n] == c)
			return (char*) &s[n];
	}

	return NULL;
}

EXPORT char *strchr(const char *s, int c)
{
	while (*s)
	{
		if (*s == c)
			return (char*) s;
		s++;
	}
	if (!c)
		return (char*) s;
	return NULL;
}

EXPORT void *__rawmemchr(const void *s, int c)
{
	unsigned char *uc = (void*) s;
	size_t i;

	for (i = 0; ; i++)
		if (uc[i] == c)
			return &uc[i];

	return NULL;
}

EXPORT void *memchr(const void *s, int c, size_t n)
{
	unsigned char *uc = (void*) s;
	size_t i;

	for (i = 0; i < n; i++)
		if (uc[i] == c)
			return &uc[i];

	return NULL;
}

EXPORT void *memrchr(const void *s, int c, size_t n)
{
	unsigned char *uc = (void*) s;
	size_t i;

	for (i = n; i > 0; i--)
		if (uc[i - 1] == c)
			return &uc[i - 1];

	return NULL;
}

EXPORT char *strchrnul(const char *s, int c)
{
	while (*s)
	{
		if (*s == c)
			break;
		s++;
	}
	return (char*) s;
}

EXPORT char *strcpy(char *dest, const char *s)
{
	char *d = dest;
	while ((*d++ = *s++))
		;
	return dest;
}

EXPORT char *strncpy(char *dest, const char *s, size_t n)
{
	size_t i;
	for (i = 0; i < n && s[n]; i++)
		dest[n] = s[n];
	for ( ; i < n; i++)
		dest[n] = 0;
	return dest;
}

EXPORT char *__strcpy_chk(char *dest, const char *s, size_t destlen)
{
	size_t len = strlen(s) + 1;

	if (len > destlen)
		die("strcpy() overrun\n");

	memcpy(dest, s, len);
	return dest;
}

EXPORT char *stpcpy(char *d, const char *s)
{
	while ((*d++ = *s++))
		;
	return --d;
}

EXPORT char *strcat(char *dest, const char *src)
{
	strcpy(dest + strlen(dest), src);
	return dest;
}

EXPORT char *__strcat_chk(char *dest, const char *src, size_t destlen)
{
	size_t sl = strlen(src);
	size_t dl = strlen(dest);
	if (sl + dl >= destlen)
		die("strcat(): overrun\n");

	memcpy(&dest[dl], src, sl + 1);
	return dest;
}

EXPORT char *__strncat_chk(char *dest, const char *src,
			 size_t n, size_t destlen)
{
	size_t sl;
	size_t dl = strlen(dest);
	const char *end = memchr(src, '\0', n);

	if (end)
		sl = end - src;
	else
		sl = n;

	if (sl + dl >= destlen)
		die("strcat(): overrun\n");

	memcpy(&dest[dl], src, sl);
	dest[dl + sl] = 0;
	return dest;
}

EXPORT char *strdup(const char *str)
{
	size_t len = strlen(str) + 1;
	char *r = malloc(len);
	if (r)
		memcpy(r, str, len);
	return r;
}

EXPORT size_t strspn(const char *str, const char *accept)
{
	unsigned char ok[256] = {0};
	int i, r;

	for (i = 0; accept[i]; i++)
		ok[(unsigned char)accept[i]] = 1;

	r = 0;
	while (1)
	{
		unsigned char ch = (unsigned char)str[r];
		if (!ch)
			break;
		if (!ok[ch])
			break;
		r++;
	}

	return r;
}

EXPORT size_t strcspn(const char *str, const char *reject)
{
	unsigned char nak[256] = {0};
	int i, r;

	for (i = 0; reject[i]; i++)
		nak[(unsigned char)reject[i]] = 1;

	r = 0;
	while (1)
	{
		unsigned char ch = (unsigned char)str[r];
		if (!ch)
			break;
		if (nak[ch])
			break;
		r++;
	}

	return r;
}

EXPORT char *strpbrk(const char *s, const char *accept)
{
	unsigned char ok[256] = {0};
	int i;

	for (i = 0; accept[i]; i++)
		ok[(unsigned char)accept[i]] = 1;

	for (i = 0; s[i]; i++)
		if (ok[(unsigned char)s[i]])
			return (char*) &s[i];

	return NULL;
}

typedef int regoff_t;

typedef struct
{
} regex_t;

typedef struct
{
	regoff_t rm_so;
	regoff_t rm_eo;
} regmatch_t;

#define REG_NOMATCH 1

EXPORT int regcomp(regex_t *preg, const char *regex, int cflags)
{
	warn("regcomp(%p,%s,%08x)\n", preg, regex, cflags);
	return 0;
}

EXPORT int regexec(const regex_t *preg, const char *string, size_t nmatch,
			regmatch_t *matches, int eflags)
{
	int i;

	warn("regexec(%p,...)\n", preg);

	for (i = 0; i < nmatch; i++)
	{
		matches[i].rm_so = -1;
		matches[i].rm_eo = -1;
	}
	return REG_NOMATCH;
}

EXPORT void *bsearch(const void *key, const void *base,
			size_t nmemb, size_t size,
			int (*compar)(const void *a, const void* b))
{
	const void *p;
	size_t n;
	int r;

	while (1)
	{
		if (nmemb == 0)
			return NULL;

		n = nmemb/2;
		p = (const char*)base + n * size;

		r = compar(key, p);
		if (r == 0)
			return (void*) p;

		if (nmemb == 1)
			return NULL;

		if (r > 0)
		{
			base = p;
			nmemb -= n;
		}
		else
			nmemb = n;
	}
}

/* not quicksort, but anyway */
typedef int (*fn_compare)(const void *, const void *);
EXPORT void qsort(void *base, size_t nmemb, size_t size, fn_compare fn)
{
	size_t mid;
	unsigned char *a1, *a2, *end;

	if (nmemb <= 1)
		return;

	mid = nmemb/2;
	a1 = (unsigned char *)base;
	a2 = base + size * mid;
	end = base + size * nmemb;

	/* sort halves */
	if (size > 2)
	{
		qsort(a1, mid, size, fn);
		qsort(a2, nmemb - mid, size, fn);
	}

	while (a1 < a2 && a2 < end)
	{
		int r = fn(a1, a2);
		if (r < 0)
		{
			a1 += size;
		}
		else
		{
			unsigned char tmp[size];
			memcpy(tmp, a2, size);
			memmove(a1 + size, a1, a2 - a1);
			memcpy(a1, tmp, size);
			a1 += size;
			a2 += size;
		}
	}
}

EXPORT char **__environ;

EXPORT char *getenv(const char *name)
{
	char **p;
	size_t len = strlen(name);
	for (p = environ;
		*p;
		p++)
	{
		size_t n;
		char *x = strchr(*p, '=');
		if (!x)
			return NULL;

		n = x - *p;
		if (n != len)
			continue;

		if (!strncmp(name, *p, n))
			return *p + n + 1;
	}

	return NULL;
}

struct option
{
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

EXPORT int optind = 1;
EXPORT int opterr = 1;
EXPORT int optopt = '?';
EXPORT char *optarg;
static int nextchar;
static int opt_first_arg;

static const struct option *
getopt_find_longopt(const struct option *opt,
		 const char *str)
{
	while (opt->name)
	{
		if (!strcmp(opt->name, str))
			return opt;
		opt++;
	}
	return NULL;
}

void print_av(const char *prefix, const char **av)
{
	dprintf("%s: ", prefix);
	while (*av)
		dprintf("%s ", *av++);
	dprintf("\n");
}

/*
 *  Accumulate non-options at the end of the argv list
 *    tail foo -f bar
 *         ^      ^
 *         |      +-- pos   (4)
 *         |
 *         +--- optind      (2)
 *              group_count (1)
 */
static void opt_shuffle(const char **av, int pos, int group_count)
{
	const char *tmp;

	while (optind < (pos - group_count))
	{
		tmp = av[pos - 1];
		memmove(&av[optind + 1], &av[optind],
			 (pos - 2 + group_count - optind) *
				sizeof (const char *));
		av[optind] = tmp;
		optind++;
	}

	optind = pos;
	opt_first_arg = pos;
}

EXPORT int getopt_long(int argc, const char **argv,
		const char *optstring,
		const struct option *longopts, int *longindex)
{
	unsigned char opts[0x100] = {0};
	int stop = 0;
	int i = 0;
	unsigned char ch;
	int pos;
	int group_count = 0;

	/*
	 * store options by index
	 *  0  no option
	 *  1  option
	 *  2  option with arg
	 */
	if (optstring[i] == '+')
	{
		stop = 1;
		i++;
	}

	while (1)
	{
		ch = (unsigned char) optstring[i];
		if (ch == 0)
			break;
		opts[ch] = 1;
		i++;
		if (optstring[i] == ':')
		{
			opts[ch] = 2;
			i++;
		}
	}

	optarg = NULL;

	/* skip busybox style subprogram name */
	if (optind == 0)
		optind++;

	/* reset to the start */
	if (optind == 1)
		opt_first_arg = 1;
	pos = optind;

	if (optind >= argc)
	{
		optind = opt_first_arg;
		return -1;
	}

	if (nextchar == 0)
	{
		/*
		 * At the end, go back to the first non-option
		 * Incorrectly include an option args as a non-option.
		 */
		while (1)
		{
			if (pos >= argc)
			{
				optind = opt_first_arg;
				return -1;
			}

			if (argv[pos][0] == '-')
				break;
			pos++;
		}
		nextchar++;
		group_count++;

		/* long option */
		if (longopts && argv[pos][1] == '-')
		{
			const struct option *o;

			o = getopt_find_longopt(longopts, &argv[pos][2]);
			if (o)
			{
				nextchar = 0;
				pos++;
				if (o->flag)
					*(o->flag) = o->val;
				if (o->has_arg)
				{
					if (pos >= argc)
						return -1;
					optarg = (char*) argv[pos++];
					group_count++;
					optopt = 0;
				}
				else
					optopt = o->val;
				opt_shuffle(argv, pos, group_count);
				return optopt;
			}
			else
			{
				optopt = -1;
				return -1;
			}
		}
	}

	optopt = argv[pos][nextchar];
	if (optopt == '-' || optopt == 0)
		goto error;

	ch = (unsigned char) optopt;
	if (opts[ch] == 0)
	{
		optopt = '?';
		nextchar = 0;
		pos++;
		opt_shuffle(argv, pos, group_count);
		return optopt;
	}

	/* got an option, proceed to the next character */
	nextchar++;
	if (argv[pos][nextchar] == 0)
	{
		pos++;
		nextchar = 0;
	}

	/* handle option with an arg */
	if (opts[ch] == 2)
	{
		if (pos >= argc)
		{
			optopt = '?';
			if (opterr)
				dprintf("%s: option requires an argument -- '%c'\n",
					argv[0], optstring[i]);
			return -1;
		}
		else
		{
			optarg = (char*) &argv[pos][nextchar];
			pos++;
			group_count++;
			nextchar = 0;
		}
	}

	opt_shuffle(argv, pos, group_count);

	return optopt;

error:
	if (!stop)
	{
		optind++;
		nextchar = 0;
		optopt = -1;
	}
	return optopt;
}

EXPORT int getopt(int argc, const char **argv,
		  const char *optstring)
{
	return getopt_long(argc, argv, optstring, NULL, NULL);
}

struct passwd
{
	char *pw_name;
	char *pw_passwd;
	uid_t pw_uid;
	gid_t pw_gid;
	char *pw_gecos;
	char *pw_dir;
	char *pw_shell;
};

EXPORT struct passwd *getpwuid(uid_t uid)
{
	struct passwd *pw;
	const char str[] = "atratus\0*\0Atratus\0/\0/bin/sh";

	/* FIXME: read from /etc/passwd when ready */
	pw = malloc(sizeof *pw + sizeof str);
	memcpy(&pw[1], str, sizeof str);
	pw->pw_name = (char*) (&pw[1]);
	pw->pw_passwd = pw->pw_name + strlen(pw->pw_name) + 1;
	pw->pw_uid = uid;
	pw->pw_gid = uid;
	pw->pw_gecos = pw->pw_passwd + strlen(pw->pw_passwd) + 1;
	pw->pw_dir = pw->pw_gecos + strlen(pw->pw_gecos) + 1;
	pw->pw_shell = pw->pw_dir + strlen(pw->pw_dir) + 1;

	return pw;
}

/*typedef uint64_t dev_t;*/

EXPORT unsigned int gnu_dev_major(dev_t devid)
{
	return (devid >> 16);
}

EXPORT unsigned int gnu_dev_minor(dev_t devid)
{
	return (devid & 0xffff);
}

EXPORT int tcgetattr(int fd, struct termios *tios)
{
	return ioctl(fd, TIOCG, (int) tios);
}

EXPORT int tcsetattr(int fd, int optional_actions, struct termios *tios)
{
	/* TODO: do something with optional_actions */
	return ioctl(fd, TIOCS, (int) tios);
}

EXPORT pid_t tcgetpgrp(int fd)
{
	dprintf("tcgetpgrp(%d)\n", fd);
	return getpid();
}

EXPORT int tcsetpgrp(int fd, pid_t pgrp)
{
	dprintf("tcsetpgrp(%d, %d)\n", fd, pgrp);
	return 0;
}

EXPORT pid_t getpgrp(void)
{
	dprintf("getpgrp()\n");
	return getpid();
}

EXPORT int setpgid(pid_t pid, pid_t pgid)
{
	dprintf("setpgid(%d,%d)\n", pid, pgid);
	return 0;
}

EXPORT int isatty(int fd)
{
	struct termios tios;

	if (0 == tcgetattr(fd, &tios))
		return 1;
	return 0;
}

EXPORT int ttyname_r(int fd, char *buf, size_t buflen)
{
	const char name[] = "/dev/tty";
	if (!isatty(fd))
		return -1;

	if (buflen < sizeof name)
		return _L(ERANGE);

	strcpy(buf, name);

	return 0;
}

EXPORT char *ttyname(int fd)
{
	static char buf[0x1000];
	int r;
	r = ttyname_r(fd, buf, sizeof buf - 1);
	if (r < 0)
		return NULL;
	return buf;
}

/* jmpbuf is 156 bytes in size */
struct jmp_buf;

EXPORT int _setjmp(struct jmp_buf *buf);
__asm__ (
	"\n"
".text\n"
".globl _setjmp\n"
".type	_setjmp, @function\n"
"_setjmp:\n"
	"\tpush %ebx\n"
	"\tmovl 8(%esp), %eax\n"	/* jmpbuf */
	"\tmovl %ebx, (%eax)\n"
	"\tmovl %ecx, 4(%eax)\n"
	"\tmovl %edx, 8(%eax)\n"
	"\tmovl %esi, 12(%eax)\n"
	"\tmovl %edi, 16(%eax)\n"
	"\tmovl %ebp, 20(%eax)\n"
	"\tmovl %esp, 24(%eax)\n"
	"\tmovl 4(%esp), %ebx\n"		/* save the return address */
	"\tmovl %ebx, 28(%eax)\n"
	/* TODO: save floating point, debug registers, etc */
	"\txor %eax, %eax\n"		/* return 0 */
	"\tpopl %ebx\n"
	"\tret\n"
	"\t.size	_setjmp, .-_setjmp\n"
);

EXPORT void __longjmp_chk(struct jmp_buf *buf, int val);
__asm__ (
	"\n"
".text\n"
".globl __longjmp_chk\n"
".type	__longjmp_chk, @function\n"
"__longjmp_chk:\n"
	"\tmov 4(%esp), %eax\n"		/* eax hold pointer to jmpbuf */

	/* fetch old EIP, save it on the return stack */
	"\tmov 28(%eax), %ebx\n"	/* ebx the return EIP */
	"\tmov 24(%eax), %ecx\n"	/* ecx holds pointer to return stack */
	"\tmov %ebx, 4(%ecx)\n"		/* save return address on the return stack */

	/* fetch return value, save it on the "return" stack */
	"\tmov 8(%esp), %ebx\n"		/* val */
	"\tcmp $1, %ebx\n"		/* change 0 to 1 */
	"\tadc $0, %ebx\n"
	"\tmov %ebx, (%ecx)\n"		/* save the return value on the return stack */

	/* restore registers */
	"\tmov (%eax), %ebx\n"
	"\tmov 4(%eax), %ecx\n"
	"\tmov 8(%eax), %edx\n"
	"\tmov 12(%eax), %esi\n"
	"\tmov 16(%eax), %edi\n"
	"\tmov 20(%eax), %ebp\n"
	"\tmov 24(%eax), %esp\n"

	/* restore EAX and EIP */
	"\tpop %eax\n"
	"\tret\n"
	"\t.size	__longjmp_chk, .-__longjmp_chk\n"
);

EXPORT void longjmp(struct jmp_buf *buf, int val);
__asm__ (
	"\n"
".text\n"
".globl longjmp\n"
".type	longjmp, @function\n"
"longjmp:\n"
	"\tjmp __longjmp_chk\n"
	"\t.size	longjmp, .-longjmp\n"
);

#define SIG_DFL 0
#define SIG_IGN 1

#if 0 /* defined in sys/select.h, included by sys/types.h */
typedef struct {
	unsigned char val[1024/8];
} sigset_t;
#endif

struct sigaction
{
};

EXPORT int sigaction(int num, const struct sigaction *act,
			 struct sigaction *oldact)
{
	dprintf("sigaction(%d,%p,%p)\n", num, act, oldact);
	return 0;
}

EXPORT int sigfillset(sigset_t *set)
{
	dprintf("sigsetfill(%p)\n", set);
	return 0;
}

EXPORT int sigemptyset(sigset_t *set)
{
	dprintf("sigemptyset(%p)\n", set);
	return 0;
}

EXPORT int sigaddset(sigset_t *set, int num)
{
	dprintf("sigaddset(%p)\n", set);
	return 0;
}

EXPORT int sigdelset(sigset_t *set, int num)
{
	dprintf("sigaddset(%p)\n", set);
	return 0;
}

EXPORT int sigismember(const sigset_t *set, int num)
{
	dprintf("sigaddset(%p)\n", set);
	return 0;
}

EXPORT int signal(int num, void *handler)
{
	dprintf("signal(%d,%p)\n", num, handler);
	return SIG_DFL;
}

typedef void *sigjmp_buf;

EXPORT int __sigsetjmp(sigjmp_buf env, int savemask)
{
	dprintf("sigsetjmp(%p,%d)\n", env, savemask);
	return 0;
}

typedef int (*fn_main)(int, char * *, char * *);
typedef void (*fn_init)(void);
typedef void (*fn_fini)(void);
typedef void (*fn_rtld_fini)(void);

EXPORT int __libc_start_main(fn_main pmain,
			int argc, char **ubp_av,
			fn_init pinit, fn_fini pfini,
			fn_rtld_fini prtld_fini,
			void (* stack_end))
{
	int r;

	dprintf("%s called\n", __FUNCTION__);
	dprintf("main   %p\n", pmain);
	dprintf("argc   %d\n", argc);
	dprintf("ubp_av %p\n", ubp_av);
	dprintf("init   %p\n", pinit);
	dprintf("fini   %p\n", pfini);
	dprintf("stkend %p\n", stack_end);

	pinit();

	dprintf("init() done\n");

	r = pmain(argc, ubp_av, environ);
	dprintf("main() returned %d\n", r);
	exit(r);
}
