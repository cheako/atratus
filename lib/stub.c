/*
 * Stub shared object loader
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

#include <sys/types.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/elf32.h>
#include <sys/elf_extra.h>
#include "loader.h"

#define NULL ((void *)0)

#define LD_DEBUG 0

static int ld_write(int fd, const char *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $4, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd), "c"(buffer), "d"(length) : "memory");

	return r;
}

static size_t ld_strlen(const char *x)
{
	int n = 0;
	while (x[n])
		n++;
	return n;
}

static void write_hex(unsigned int x)
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
	ld_write(1, ch, 9);
}

static void ld_write_dec(unsigned int x)
{
	char str[10];
	int i = sizeof str;

	str[--i] = 0;
	while (x)
	{
		str[--i] = '0' + (x % 10);
		x /= 10;
	}
	ld_write(1, &str[i], sizeof str - 1 - i);
}

static void ld_write_string(const char *str)
{
	ld_write(1, str, ld_strlen(str));
}

static void elf_apply_reloc(void *base, Elf32_Rel *rel)
{
	uint32_t *p = (uint32_t*)((char *)(base + rel->r_offset));

	(*p) += (uint32_t) base;
}

/*
 *     Declared              Actual
 *     -----------------------------
 *     return address    <-  argc
 *     dummy		 <-  argv[0]
 */
void _start(int dummy)
{
	int *p;
	char **argv;
	char **env;
	Elf32_Aux *auxv;
	void *ld_base = NULL;
	const Elf32_Ehdr *ehdr = NULL;
	const Elf32_Phdr *dynamic = NULL; /* dynamic section's program header */
	const Elf32_Dyn *dyn = NULL;
	struct 
	{
		Elf32_Word rel;
		Elf32_Word relsz;
	} dt = {0};
	int i;
	int err = __LINE__;
	int argc;
	void *entry;

	/*
	 * there's no return address, just a variable length list of pointers
	 *  argc, argv[0..n], env, auxv
	 *
	 * The following assumes p is a memory address on the stack...
	 */
	p = &dummy;
	p--;

	/* skip argc and argv */
	argc = *(p++);
	argv = (void*) p;

	/* skip env */
	p = &p[argc + 1];
	env = (void*) p;
	while (*p)
		p++;

	auxv = (void*) (++p);
	for (i = 0; auxv[i].a_type != AT_NULL; i++)
	{
		if (auxv[i].a_type == AT_BASE)
			ld_base = (void*) auxv[i].a_value;
	}

	/* check loader has a base address */
	if (!ld_base)
	{
		err = __LINE__;
		goto error;
	}

	ehdr = ld_base;

	/* check it's an ELF file */
	if (ehdr->e_ident[0] != 0x7f ||
	    ehdr->e_ident[1] != 'E' ||
	    ehdr->e_ident[2] != 'L' ||
	    ehdr->e_ident[3] != 'F')
	{
		err = __LINE__;
		goto error;
	}

	/* check it's dynamic */
	if (ehdr->e_type != ET_DYN)
	{
		err = __LINE__;
		goto error;
	}

	/* check it's i386 */
	if (ehdr->e_machine != EM_386)
	{
		err = __LINE__;
		goto error;
	}

	/* find the dynamic section */
	for (i = 0; i < ehdr->e_phnum; i++)
	{
		const Elf32_Phdr *phdr = (const void*)((const char*) ld_base +
					 ehdr->e_phoff + i * sizeof *phdr);

		if (phdr->p_type == PT_DYNAMIC)
			dynamic = phdr;
	}

	if (!dynamic)
	{
		err = __LINE__;
		goto error;
	}

	/* find the pointer to the relocation table */
	dyn = (void*)(dynamic->p_vaddr + ld_base);
	for (i = 0; dyn[i].d_tag != DT_NULL; i++)
	{
		switch (dyn[i].d_tag)
		{
#define X(name, field) case DT_##name: dt.field = dyn[i].d_un.d_val; break;
		X(REL, rel)
		X(RELSZ, relsz)
#undef X
		}
	}

	if (!dt.rel)
	{
		err = __LINE__;
		goto error;
	}

	/* relocate ourselves */
	for (i = 0; i < dt.relsz/sizeof (Elf32_Rel); i++)
	{
		Elf32_Rel *rel = (void*)((char*)ld_base + dt.rel);
		Elf32_Word symtype = ELF32_R_TYPE(rel[i].r_info);

		switch (symtype)
		{
		case R_386_RELATIVE:
			elf_apply_reloc(ld_base, &rel[i]);
			break;
		default:
			err = __LINE__;
			goto error;
		}
	}

	entry = ld_main(argc, argv, env, auxv);

	p = &dummy;
	if (!entry)
	{
		err = __LINE__;
		goto error;
	}

	__asm__ __volatile(
		/* blow all local variables away */
		"\tsub $4, %%ecx\n"
		"\tmov %%ecx, %%esp\n"

		/* jump to target exe start address */
		"\tpush %%eax\n"
		"\txor %%eax, %%eax\n"
		"\txor %%ebx, %%ebx\n"
		"\txor %%ecx, %%ecx\n"
		"\txor %%edx, %%edx\n"
		"\txor %%esi, %%esi\n"
		"\txor %%edi, %%edi\n"
		"\tret\n"

		::"a"(entry), "c"(p): "memory");

	err = 0;
error:
	ld_write_string("ld-linux.so.2 failed @");
	ld_write_dec(err);
	if (0) write_hex(err);
	__asm__ __volatile__ (
		"\tmov %%eax, %%ebx\n"
		"\tmov $1, %%eax\n"
		"\tint $0x80\n"
		::"a"(err): "memory");
}
