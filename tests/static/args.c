/*
 * args - dump the command line, environment and auxv passed from the kernel
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
#include <unistd.h>
#include <elf.h>

#define AT_SECURE 23
#define AT_BASE_PLATFORM 24
#define AT_RANDOM 25
#define AT_EXECFN 31

void *__stack_chk_guard = 0;
void __stack_chk_fail_local(void) { return; }
void __stack_chk_fail(void) { return; }

volatile int g_testval = 0x1234;

static inline size_t sys_write(int fd, const void *buffer, size_t len)
{
	int ret;
	__asm__ __volatile__(
		"int $0x80"
                          : "=a" (ret) : "a" (SYS_write), "b" (fd), "c" (buffer), "d" (len));
	return ret;
}

static inline void sys_exit(int code)
{
	__asm__ __volatile__(
		"int $0x80"
			: : "a" (SYS_exit), "b" (code) );
}

static inline void *sys_brk(void *new_brk)
{
	void *ret;
	__asm__ __volatile__(
		"int $0x80"
		: "=a"(ret) : "a" (SYS_brk), "b" (new_brk));
	return ret;
}

struct user_desc {
	unsigned int entry_number;
	unsigned int base_addr;
	unsigned int limit;
	unsigned int seg_32bit:1;
	unsigned int contents:2;
	unsigned int read_exec_only:1;
	unsigned int limit_in_pages:1;
	unsigned int seg_not_present:1;
	unsigned int useable:1;
};

static inline int sys_set_thread_area(struct user_desc *ud)
{
	int r;
	__asm__ __volatile__(
		"int $0x80"
			: "=r" (r) : "a" (SYS_set_thread_area), "b" (ud) );
	return r;
}

static int _strlen(const char *x)
{
	int n = 0;
	while (x[n])
		n++;
	return n;
}

static void write_number(unsigned int x)
{
	char buffer[10];
	int i, n = 0;
	while (x || n == 0)
	{
		buffer[n] = (x % 10) + '0';
		x /= 10;
		n++;
	}
	for (i = 0; i < (n / 2); i++)
	{
		char t = buffer[i];
		buffer[i] = buffer[n - i - 1];
		buffer[n - i - 1] = t;
	}
	buffer[n] = 0;
	sys_write(1, buffer, n);
}

static void write_int(unsigned int x)
{
	char ch[9];
	int i;
	for (i = 0; i < 8; i++)
	{
		ch[i] = (x>>((7-i)*4))&0x0f;
		if (ch[i] < 10)
			ch[i] += '0';
		else
			ch[i] += 55;
	}
	ch[8] = '\n';
	sys_write(1, ch, 9);
}

void write_ptr(void *p)
{
	sys_write(1, "0x", 2);
	write_int((unsigned int)p);
}

void write_string(const char *str)
{
	sys_write(1, str, _strlen(str));
}

void dump_phdr(Elf32_Phdr *phdr)
{
	write_int(phdr->p_type);
	write_int(phdr->p_offset);
	write_int(phdr->p_vaddr);
	write_int(phdr->p_paddr);
	write_int(phdr->p_filesz);
	write_int(phdr->p_memsz);
	write_int(phdr->p_flags);
	write_int(phdr->p_align);
}

int get_aux_val(Elf32_auxv_t* aux, int t)
{
	int i;

	for (i=0; aux[i].a_type != AT_NULL; i++)
		if (aux[i].a_type == t)
			return aux[i].a_un.a_val;

	write_string("Not found\n");

	return 0;
}

void _main(int argc, char **argv, char **env, Elf32_auxv_t* aux)
{
	int i;

	for (i = 0; argv[i]; i++)
	{
		sys_write(1, "arg[", 4);
		write_number(i);
		sys_write(1, "]=", 2);
		sys_write(1, argv[i], _strlen(argv[i]));
		sys_write(1, "\n", 1);
	}

	for (i = 0; env[i]; i++)
	{
		sys_write(1, "env[", 4);
		write_number(i);
		sys_write(1, "]=", 2);
		sys_write(1, env[i], _strlen(env[i]));
		sys_write(1, "\n", 1);
	}

	sys_write(1, "aux:\n", 5);
	for (i=0; aux[i].a_type != AT_NULL; i++)
	{
		switch (aux[i].a_type)
		{
#define X(T) case T: \
	sys_write(1, #T ": ", sizeof #T); \
	break;
		X(AT_IGNORE)
		X(AT_EXECFD)
		X(AT_PHDR)
		X(AT_PHENT)
		X(AT_PHNUM)
		X(AT_PAGESZ)
		X(AT_BASE)
		X(AT_FLAGS)
		X(AT_ENTRY)
		X(AT_NOTELF)
		X(AT_UID)
		X(AT_EUID)
		X(AT_GID)
		X(AT_EGID)
		X(AT_PLATFORM)
		X(AT_HWCAP)
		X(AT_CLKTCK)
		//X(AT_VECTOR_SIZE_BASE)
		X(AT_SECURE)
		X(AT_BASE_PLATFORM)
		X(AT_RANDOM)
		X(AT_EXECFN)
		X(AT_SYSINFO)
		X(AT_SYSINFO_EHDR)
		default:
			sys_write(1, "unknown: ", 9);
			write_int(aux[i].a_type);
			break;
		}
		write_int(aux[i].a_un.a_val);
	}

	write_string("ELF program header: \n");
	dump_phdr((Elf32_Phdr *) get_aux_val(aux, AT_PHDR));

	if (g_testval != 0x1234)
	{
		write_string("test value wrong\n");
		sys_exit(1);
	}

	sys_exit(0);
}


__asm__ (
	"\n"
".globl _start\n"
"_start:\n"
	"\tmovl 0(%esp), %eax\n"
	"\tlea 4(%esp), %ebx\n"
	"\tmov %ebx, %ecx\n"
"1:\n"
	"\tcmpl $0, 0(%ecx)\n"
	"\tlea 4(%ecx), %ecx\n"
	"\tjnz 1b\n"
	"\tpush %ecx\n"
	"\tmov %ecx, %edx\n"
"2:\n"
	"\tcmpl $0, 0(%ecx)\n"
	"\tlea 4(%ecx), %ecx\n"
	"\tjnz 2b\n"
	"\tpush %ecx\n"
	"\tpush %edx\n"
	"\tpush %ebx\n"
	"\tpush %eax\n"
	"\tcall _main\n"
);
