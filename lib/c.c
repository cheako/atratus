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

#include "loader.h"
#include "string.h"
#include "stdlib.h"
#include "time.h"

#define NULL ((void *)0)

#define O_RDONLY 0

/*
 * errno should be per thread,
 * leave as global until we can load an ELF binary
 */
static int errno;
static int verbose = 0;
extern char **ld_environment;

#define EXPORT __attribute__((visibility("default")))

static inline int set_errno(int r)
{
	if ((r & 0xfffff000) == 0xfffff000)
	{
		errno = -r;
		r = -1;
	}
	return r;
}

EXPORT void exit(int status)
{
	while (1)
	{
		__asm__ __volatile__ (
			"\tpushl %%ebx\n"
			"\tmov $1, %%eax\n"
			"\tint $0x80\n"
			"\tpopl %%ebx\n"
		:: "a"(status) : "memory");
	}
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

EXPORT int open(const char *filename, int flags)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $5, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(filename), "c"(flags) : "memory");

	return set_errno(r);
}

#define O_LARGEFILE 0100000

EXPORT int open64(const char *filename, int flags)
{
	return open(filename, flags | O_LARGEFILE);
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

EXPORT int getcwd(char *buf, size_t size)
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

EXPORT int getuid(void)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $24, %%eax\n"
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

struct stat64;

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

EXPORT int fputs_unlocked(const char *str, FILE *stream)
{
	/* FIXME: use stream */
	int fd = stream->fd;
	size_t len = strlen(str);
	if (len != dl_write(fd, str, len))
		return EOF;
	dl_write(1, "\n", 1);
	return len;
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
		fd = open(path, O_RDONLY);
		if (fd < 0)
			return NULL;
	}
	else
	{
		printf("unknown mode %s\n", mode);
		return NULL;
	}

	f = malloc(sizeof *f + STDIO_READ_BUFFER_SZ);
	if (!f)
	{
		printf("malloc failed\n");
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
	printf("fflush(%p)\n", stream);
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
	printf("fread(%p,%ld,%ld,%p)\n", ptr, size, nmemb, f);
	return 0;
}

EXPORT int puts(const char *str)
{
	return fputs(str, stdout);
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

EXPORT int putchar_unlocked(int c)
{
	return putc_unlocked(c, stdout);
}

EXPORT int putchar(int c)
{
	return fputc(c, stdout);
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

static const char *time_wday[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *time_month[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

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

EXPORT size_t strftime(char *s, size_t max,
			const char *format,
			const struct tm *tm)
{
	int i, n = 0;
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
				printf("strftime(): %c unhandled\n", format[i]);
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
	char pad;
	char *buffer;
	size_t max;
	size_t out_size;
	FILE *f;
};

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
	while (sizeof buf > n && sizeof buf - n < pfo->width)
		buf[--n] = pfo->pad;

	pfo->fn(pfo, &buf[n], sizeof buf - n);
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
	while (sizeof buf > n && sizeof buf - n < pfo->width)
		buf[--n] = pfo->pad;

	pfo->fn(pfo, &buf[n], sizeof buf - n);
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
	while (sizeof buf > n && sizeof buf - n < pfo->width)
		buf[--n] = pfo->pad;

	pfo->fn(pfo, &buf[n], sizeof buf - n);
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

	if (n == sizeof buf)
		buf[--n] = '0';
	while (sizeof buf > n && sizeof buf - n < pfo->width)
		buf[--n] = pfo->pad;

	pfo->fn(pfo, &buf[n], sizeof buf - n);
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

	pfo->fn(pfo, buf, sizeof buf);
}

static void pf_string(const char *value, struct printf_output *pfo)
{
	if (!value)
		value = "(null)";
	pfo->fn(pfo, value, strlen(value));
}

static void pf_char(char value, struct printf_output *pfo)
{
	pfo->fn(pfo, &value, 1);
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
		if (*p == '0')
		{
			pfo->pad = '0';
			p++;
		}
		else
			pfo->pad = ' ';
		while (*p >= '0' && *p <= '9')
		{
			pfo->width *= 10;
			pfo->width += (*p - '0');
			p++;
		}

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
			printf("%c unhandled\n", *p);
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

EXPORT int __printf_chk(int flag, const char *str, ...)
{
	va_list va;
	int r;
	struct printf_output pfo =
	{
		.fn = &printf_chk_pfo,
		.out_size = 0,
		.buffer = NULL,
		.max = 0,
	};

	va_start(va, str);

	r = internal_vsprintf(flag, str, va, &pfo);

	va_end(va);

	return r;
}

static int sprintf_chk_pfo(struct printf_output *pfo, const char *str, size_t len)
{
	memcpy(&pfo->buffer[pfo->out_size], str, len);
	pfo->out_size += len;
	return 1;
}

EXPORT int __sprintf_chk(char *out, int flag, size_t maxlen, const char *str, ...)
{
	va_list va;
	int r;
	struct printf_output pfo =
	{
		.fn = &sprintf_chk_pfo,
		.out_size = 0,
		.buffer = out,
		.max = maxlen,
	};

	va_start(va, str);

	r = internal_vsprintf(flag, str, va, &pfo);

	pfo.buffer[pfo.out_size] = 0;

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

EXPORT unsigned long strtoul(const char *nptr, char **endptr, int base)
{
	unsigned long value = 0;
	int sign = 1;

	if (*nptr == '-')
	{
		nptr++;
		sign = -1;
	}
	else if (*nptr == '+')
		nptr++;
	else if ((base == 0 || base == 0x10) &&
		nptr[0] == '0' && (nptr[1] == 'x' || nptr[1] == 'X'))
	{
		nptr += 2;
		base = 0x10;
	}

	// TODO: handle other bases

	while (1)
	{
		int ch = *nptr;

		if (ch >= '0' && ch <= '9')
			ch -= '0';
		else if (ch >= 'A' && ch <= 'Z')
			ch -= ch - 'A' + 10;
		else if (ch >= 'a' && ch <= 'z')
			ch -= ch - 'a' + 10;
		else
			break;

		if (ch >= base)
			break;

		// TODO: check overflow, set errno and return ULONG_MAX

		value *= base;
		value += ch;
		nptr++;
	}

	value *= sign;

	if (endptr)
		*endptr = (char*) nptr;

	return value;
}

EXPORT void abort(void)
{
	/* FIXME: send SIGABRT */
	exit(1);
}

EXPORT int mallopt(int param, int value)
{
	switch (param)
	{
	case -1:
		if (verbose)
			printf("mallopt(M_TRIM_THRESHOLD,%d)\n", value);
		break;
	case -2:
		if (verbose)
			printf("mallopt(M_TOP_PAD,%d)\n", value);
		break;
	case -3:
		if (verbose)
			printf("mallopt(M_MMAP_THRESHOLD,%d)\n", value);
		break;
	default:
		printf("mallopt(%d,%d)\n", param, value);
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
static void *heap_brk;

static void heap_split_block(struct heap_block *p, size_t sz)
{
	struct heap_block *next = p->next;
	size_t block_sz = sz + sizeof (*p);

	p->next = (void*) ((char*)(p + 1) + block_sz);
	p->next->sz = p->sz - block_sz;
	p->next->used = 0;
	p->next->next = next;
	p->next->magic = HEAP_MAGIC;
	p->sz = sz;
}

static void heap_compress(void)
{
	struct heap_block *p = first_block;

	while (p)
	{
		if (p->magic != HEAP_MAGIC)
		{
			printf("heap inconsistent!\n");
			exit(1);
		}
		if (!p->used)
		{
			char *end = (char*) (p+1) + p->sz;
			/* merge blocks if they're contiguous */
			if (p->next &&
			    !p->next->used &&
			    end == (char*) p->next)
			{
				p->sz += p->next->sz;
				p->next = p->next->next;
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
		{
			printf("malloc(): corrupt heap %p\n", *p);
			exit(1);
		}
		if ((*p)->used)
			continue;
		if ((*p)->sz >= (sz + sizeof **p))
			break;
	}

	/* extend brk() if necessary */
	if (!*p)
	{
		int brk_sz = (sz + sizeof **p + 0xfff) & ~0xfff;
		void *r;
		if (!heap_brk)
			heap_brk = sys_brk(0);
		r = sys_brk((char*)heap_brk + brk_sz);
		if (!r)
			return NULL;
		heap_brk = r;

		*p = (void*)((char*)r - brk_sz);
		(*p)->magic = HEAP_MAGIC;
		(*p)->sz = brk_sz;
		(*p)->next = NULL;
		(*p)->used = 0;
	}

	/* split block (if necessary) */
	heap_split_block(*p, sz);

	heap_compress();
	(*p)->used = 1;
	r = ((*p) + 1);

	return r;
}

EXPORT void *realloc(void *ptr, size_t mem)
{
	struct heap_block *p = ptr;
	char *end;
	void *nb;

	if (!ptr)
		return malloc(mem);

	p--;

	if (p->magic != HEAP_MAGIC)
	{
		printf("realloc(): corrupt heap %p\n", ptr);
		exit(1);
	}

	if (!p->used)
	{
		printf("realloc(): memory not allocated %p\n", ptr);
		exit(1);
	}

	if ((p->sz - sizeof (*p)) >= mem)
		return (p + 1);

	/* merge with the next block if it's free, adjacent and has enough space */
	end = (char*) (p + 1) + p->sz;
	if (p->next &&
	    !p->next->used &&
	    end == (char*) p->next &&
	    ((p->sz + p->next->sz - sizeof *p) >= mem))
	{
		printf("Merging %p with next\n", p);
		p->sz += p->next->sz;
		p->next = p->next->next;
		heap_split_block(p, mem);
		return (p + 1);
	}

	/* allocate a totally new block */
	nb = malloc(mem);
	if (!nb)
		return NULL;

	memcpy(nb, p + 1, p->sz - sizeof *p);

	heap_free_block(p);

	return nb;
}

EXPORT void free(void *ptr)
{
	struct heap_block *p = ptr;
	p--;

	if (p->magic != HEAP_MAGIC)
	{
		printf("free(): corrupt heap %p\n", ptr);
		exit(1);
	}

	if (!p->used)
	{
		printf("realloc(): memory not allocated %p\n", ptr);
		exit(1);
	}

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
	int n = strlen(s);

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

EXPORT char *stpcpy(char *d, const char *s)
{
	while ((*d++ = *s++))
		;
	return --d;
}

EXPORT char *strcat(char *dest, const char *src)
{
	return strcpy(dest + strlen(dest), src);
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

EXPORT char **__environ;

EXPORT char *getenv(const char *name)
{
	char **p;
	size_t len = strlen(name);
	for (p = ld_environment;
		*p;
		p++)
	{
		size_t n;
		char *x = strchr(*p, '=');
		if (!x)
			return NULL;

		n = *p - x;
		if (n != len)
			continue;

		if (!memcmp(name, *p, n))
			return *p;
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
EXPORT int opterr;
EXPORT int optopt = '?';
EXPORT char *optarg;
static int nextchar;

const struct option *getopt_find_longopt(const struct option *opt,
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

EXPORT int getopt_long(int argc, const char **argv,
		const char *optstring,
		const struct option *longopts, int *longindex)
{
	int stop = 0;
	int i = 0;

	optarg = NULL;

	if (optind == 0)
	{
		while (optind < argc && argv[optind][0] != '-')
			optind++;

		/* no options? go back to the start */
		if (optind == argc)
		{
			optind = 1;
			return -1;
		}
	}

	if (optind >= argc)
		return -1;

	if (optstring[i] == '+')
	{
		stop = 1;
		i++;
	}

	if (nextchar == 0)
	{
		if (argv[optind][0] != '-')
		{
			if (!stop)
				optind++;
			return -1;
		}
		nextchar++;

		/* long option */
		if (longopts && argv[optind][1] == '-')
		{
			const struct option *o;

			o = getopt_find_longopt(longopts, &argv[optind][2]);
			if (o)
			{
				nextchar = 0;
				optind++;
				if (o->flag)
					*(o->flag) = o->val;
				if (o->has_arg)
				{
					if (optind >= argc)
						return -1;
					optarg = (char*) argv[optind++];
					optopt = 0;
				}
				else
					optopt = o->val;
				return optopt;
			}
			else
			{
				optopt = -1;
				return -1;
			}
		}
	}

	optopt = argv[optind][nextchar];

	if (optopt == '-' || optopt == 0)
	{
		if (!stop)
		{
			optind++;
			nextchar = 0;
		}
		return -1;
	}

	for ( ; ; i++)
	{
		if (optstring[i] == 0)
		{
			optopt = '?';
			nextchar = 0;
			optind++;
			break;
		}
		if (optopt == optstring[i])
		{
			nextchar++;
			if (argv[optind][nextchar] == 0)
			{
				optind++;
				nextchar = 0;
			}
			if (optstring[i+1] == ':')
			{
				if (optind >= argc)
				{
					optopt = '?';
					printf("%s: option requires an argument -- '%c'\n",
						argv[0], optstring[i]);
				}
				else
				{
					optarg = (char*) &argv[optind][nextchar];
					optind++;
					nextchar = 0;
				}
			}
			break;
		}
	}

	return optopt;
}

EXPORT int getopt(int argc, const char **argv,
		  const char *optstring)
{
	return getopt_long(argc, argv, optstring, NULL, NULL);
}

EXPORT int isatty(int fd)
{
	printf("isatty()\n");
	return 1;
}

struct termios
{
	unsigned int c_iflag;
	unsigned int c_oflag;
	unsigned int c_cflag;
	unsigned int c_lflag;
	unsigned char c_line;
	unsigned char c_cc[32];
	int c_ispeed;
	int c_ospeed;
};

EXPORT int tcgetattr(int fd, struct termios *tios)
{
	printf("tcgetattr()\n");
	memset(&tios, 0, sizeof *tios);
	return 0;
}

EXPORT int tcsetattr(int fd, struct termios *tios)
{
	printf("tcsetattr()\n");
	return 0;
}

struct jmp_buf {
};

EXPORT int _setjmp(struct jmp_buf *buf)
{
	printf("setjmp(%p)\n", buf);
	return 0;
}

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
	printf("sigaction(%d,%p,%p)\n", num, act, oldact);
	return 0;
}

EXPORT int sigfillset(sigset_t *set)
{
	printf("sigsetfill(%p)\n", set);
	return 0;
}

EXPORT int sigemptyset(sigset_t *set)
{
	printf("sigemptyset(%p)\n", set);
	return 0;
}

EXPORT int sigaddset(sigset_t *set, int num)
{
	printf("sigaddset(%p)\n", set);
	return 0;
}

EXPORT int sigdelset(sigset_t *set, int num)
{
	printf("sigaddset(%p)\n", set);
	return 0;
}

EXPORT int sigismember(const sigset_t *set, int num)
{
	printf("sigaddset(%p)\n", set);
	return 0;
}

EXPORT int signal(int num, void *handler)
{
	printf("signal(%d,%p)\n", num, handler);
	return SIG_DFL;
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
	if (verbose)
	{
		printf("%s called\n", __FUNCTION__);
		printf("main   %p\n", pmain);
		printf("argc   %d\n", argc);
		printf("ubp_av %p\n", ubp_av);
		printf("init   %p\n", pinit);
		printf("fini   %p\n", pfini);
		printf("stkend %p\n", stack_end);
	}

	pinit();

	if (verbose)
		printf("init() done\n");

	pmain(argc, ubp_av, NULL);
	if (verbose)
		printf("main() done\n");
	exit(0);
}
