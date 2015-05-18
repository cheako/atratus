#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include "minmax.h"
#include "debug.h"

#include "process.h"
#include "vm.h"

static FILE *debug_stream;
static int debug_verbose = 0;

int dprintf(const char *fmt, ...)
{
	va_list va;
	int n;
	if (!debug_verbose)
		return 0;
	va_start(va, fmt);
	if (debug_stream && current)
		fprintf(debug_stream, "%08x: ", (ULONG) current->id.UniqueThread);
	n = vfprintf(debug_stream, fmt, va);
	va_end(va);
	fflush(debug_stream);
	return n;
}

void die(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
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

void debug_mem_dump(void *p, size_t len)
{
	while (len)
	{
		size_t n = MIN(len, 0x10);
		debug_line_dump(p, n);

		p = (char*)p + n;
		len -= n;
	}
}

void debug_dump_regs(CONTEXT *regs)
{
	printf("EAX:%08lx EBX:%08lx ECX:%08lx EDX:%08lx\n",
		regs->Eax, regs->Ebx, regs->Ecx, regs->Edx);
	printf("ESI:%08lx EDI:%08lx EBP:%08lx ESP:%08lx\n",
		regs->Esi, regs->Edi, regs->Ebp, regs->Esp);
	printf("EIP:%08lx EFLAGS: %08lx\n", regs->Eip,
		regs->EFlags);
	printf("CS:%04lx DS:%04lx ES:%04lx SS:%04lx GS:%04lx FS:%04lx\n",
		regs->SegCs, regs->SegDs, regs->SegEs,
		regs->SegSs, regs->SegGs, regs->SegFs);
}

void debug_backtrace(struct process *context)
{
	uintptr_t frame, stack, x[2], i;
	int r;

	frame = context->regs.Ebp;
	stack = context->regs.Esp;

	r = vm_memcpy_from_process(context, &x[0], (void*) stack, sizeof x);
	if (r < 0)
	{
		fprintf(stderr, "sysret = %08lx\n", x[0]);
		return;
	}

	fprintf(stderr, "    %-8s %-8s  %-8s\n", "Esp", "Ebp", "Eip");
	for (i = 0; i < 0x10; i++)
	{
		fprintf(stderr, "%2ld: %08lx %08lx  ", i, stack, frame);
		if (stack > frame)
		{
			fprintf(stderr, "<invalid frame>\n");
			break;
		}

		r = vm_memcpy_from_process(context, &x[0], (void*) frame, sizeof x);
		if (r < 0)
		{
			fprintf(stderr, "<invalid>\n");
			break;
		}

		fprintf(stderr, "%08lx\n", x[1]);
		if (!x[1])
			break;

		/* next frame */
		stack = frame;
		frame = x[0];
	}
}
