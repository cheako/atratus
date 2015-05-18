#ifndef _VSNPRINTF_H_
#define _VSNPRINTF_H_

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>

static inline char hex2ascii(unsigned int val)
{
	if (val <= 9)
		return val + '0';
	return val + 'A' - 10;
}

static inline int toupper(int x)
{
	if (x >= 'a' && x <= 'z')
		x = x - 'a' + 'A';
	return x;
}

static inline int imax(int a, int b)
{
	if (a > b)
		return a;
	else
		return b;
}

int vprintf(const char *fmt, va_list ap);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);
int sprintf(char *buf, const char *cfmt, ...);
int vsprintf(char *buf, const char *cfmt, va_list ap);
int snprintf(char *str, size_t size, const char *format, ...);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);

#endif /* _VSNPRINTF_H_ */
