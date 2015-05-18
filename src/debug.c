#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include "minmax.h"
#include "debug.h"

#include "process.h"
#include "vm.h"

#include <windows.h>

static FILE *debug_stream;
static int debug_verbose = 0;

int dprintf(const char *fmt, ...)
{
	va_list va;
	int n;
	uint32_t hr, min, sec, ms, ticks;

	if (!debug_verbose)
		return 0;

	ticks = GetTickCount();
	ms = (ticks % 1000);
	sec = ticks/1000;
	min = (sec / 60) % 60;
	hr = (sec / (60 * 60)) % 24;
	sec %= 60;

	va_start(va, fmt);
	if (debug_stream && current)
		fprintf(debug_stream, "%02d:%02d:%02d.%03d %08x: ",
			 hr, min, sec, ms,
			(ULONG)(uintptr_t) current->id.UniqueThread);
	n = vfprintf(debug_stream, fmt, va);
	va_end(va);
	fflush(debug_stream);
	return n;
}

void die(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	fprintf(stderr, "\n\n\nFatal error:\n\n");
	vfprintf(stderr, fmt, va);
	va_end(va);
	exit(1);
}

void debug_set_file(const char *filename)
{
	debug_stream = fopen(filename, "w");
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

int debug_get_verbose(void)
{
	return debug_verbose;
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

void debug_dump_regs(struct _L(ucontext) *regs)
{
	printf("EAX:%08x EBX:%08x ECX:%08x EDX:%08x\n",
		regs->eax, regs->ebx, regs->ecx, regs->edx);
	printf("ESI:%08x EDI:%08x EBP:%08x ESP:%08x\n",
		regs->esi, regs->edi, regs->ebp, regs->esp);
	printf("EIP:%08x EFLAGS: %08x\n", regs->eip,
		regs->eflags);
	printf("CS:%04x DS:%04x ES:%04x SS:%04x GS:%04x FS:%04x\n",
		regs->cs, regs->ds, regs->es,
		regs->ss, regs->gs, regs->fs);
}

void debug_log_regs(struct _L(ucontext) *regs)
{
	dprintf("EAX:%08x EBX:%08x ECX:%08x EDX:%08x\n",
		regs->eax, regs->ebx, regs->ecx, regs->edx);
	dprintf("ESI:%08x EDI:%08x EBP:%08x ESP:%08x\n",
		regs->esi, regs->edi, regs->ebp, regs->esp);
	dprintf("EIP:%08x EFLAGS: %08x\n", regs->eip,
		regs->eflags);
	dprintf("CS:%04x DS:%04x ES:%04x SS:%04x GS:%04x FS:%04x\n",
		regs->cs, regs->ds, regs->es,
		regs->ss, regs->gs, regs->fs);
}

void debug_backtrace(struct process *context)
{
	uint32_t frame, stack, x[2], i;
	int r;

	frame = context->regs.ebp;
	stack = context->regs.esp;

	r = vm_memcpy_from_process(context, &x[0], stack, sizeof x);
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

		r = vm_memcpy_from_process(context, &x[0], frame, sizeof x);
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
