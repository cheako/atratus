/*
 * date - Print out the date/time from the time() syscall
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

#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

struct tm
{
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

void exit(int status)
{
	while (1)
	{
		__asm__ __volatile__ (
			"\tmov $1, %%eax\n"
			"\tint $0x80\n"
		:: "b"(status) : "memory");
	}
}

int read(int fd, void *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $3, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r): "b"(fd), "c"(buffer), "d"(length) : "memory");
	return r;
}

int write(int fd, const void *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $4, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r): "b"(fd), "c"(buffer), "d"(length) : "memory");

	return r;
}

int open(const char *filename, int flags)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(5), "b"(filename), "c"(flags) : "memory");

	return r;
}

int close(int fd)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(6), "b"(fd) : "memory");

	return r;
}

pid_t getpid(void)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(20) : "memory");
	return r;
}

int kill(pid_t pid, int signal)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(37), "b"(pid), "c"(signal) : "memory");
	return r;
}

time_t time(time_t *t)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(13), "b"(t) : "memory");
	return r;
}

/* ignore leap seconds... */
struct tm *gmtime_r(time_t t, struct tm *result)
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

size_t strlen(const char *str)
{
	size_t n = 0;
	while (str[n])
		n++;
	return n;
}

char *strcpy(char *dest, const char *s)
{
	char *d = dest;
	while ((*d++ = *s++))
		;
	return dest;
}

char *strcat(char *dest, const char *src)
{
	return strcpy(dest + strlen(dest), src);
}

char *asctime_r(const struct tm *tm, char *out)
{
	const char *wday[] = {
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
	};
	const char *month[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	};
	int y = tm->tm_year + 1900;
	int n = 0;

	strcpy(out+n, wday[tm->tm_wday]);
	n += 3;
	out[n++] = ' ';
	strcpy(out+n, month[tm->tm_mon]);
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

void _start(void)
{
	time_t r;
	struct tm tm;
	char buffer[100];

	r = time(NULL);
	gmtime_r(r, &tm);

	asctime_r(&tm, buffer);
	write(1, buffer, strlen(buffer));

	exit(0);
}
