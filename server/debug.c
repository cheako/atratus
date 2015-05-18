#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

static FILE *debug_stream;
static int debug_verbose = 0;

int dprintf(const char *fmt, ...)
{
	va_list va;
	int n;
	if (!debug_verbose)
		return 0;
	va_start(va, fmt);
	n = vfprintf(debug_stream, fmt, va);
	va_end(va);
	fflush(debug_stream);
	return n;
}

void die(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	fprintf(stderr, fmt, va);
	va_end(va);
	exit(1);
}

void debug_set_file(const char *filename)
{
	debug_stream = fopen(filename, "a");
	if (!debug_stream)
	{
		fprintf(stderr, "failed to open %s\n", filename);
		exit(1);
	}
}

void debug_init(void)
{
	debug_stream = stderr;
}

void debug_set_verbose(int val)
{
	debug_verbose = val;
}

static char debug_printable(char x)
{
	if (x >= 0x20 && x < 0x7f)
		return x;
	return '.';
}

void debug_line_dump(void *p, unsigned int len)
{
	unsigned char *x = (unsigned char*) p;
	unsigned int i;
	char line[0x11];

	line[0x10] = 0;
	for (i = 0; i < 16; i++)
	{
		if (i < len)
		{
			line[i] = debug_printable(x[i]);
			printf("%02x ", x[i] );
		}
		else
		{
			line[i] = 0;
			printf("   ", x[i] );
		}
	}
	printf("   %s\n", line);
}
