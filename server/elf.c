/*
 * ELF loader
 *
 * Copyright (C) 2011 - 2013 Mike McCormack
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
#include <stdint.h>
#include "ntapi.h"
#include <windows.h>
#include <psapi.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/fcntl.h>

#define alloca(sz) __builtin_alloca(sz)

#include "linux-errno.h"
#include "linux-defines.h"
#include "filp.h"

#include "sys/elf32.h"
#include "elf-av.h"

#include "process.h"
#include "minmax.h"
#include "debug.h"
#include "ntstatus.h"
#include "vm.h"
#include "elf.h"

#define DEFAULT_STACKSIZE 0x100000

/* TODO: remove these */
int sys_pread64(int fd, void *addr, size_t length, loff_t ofs);
int do_open(const char *file, int flags, int mode);
int kread(int fd, void *buf, size_t size, loff_t off);

struct elf_module
{
	int fd;
	void *base;
	uint32_t min_vaddr;
	uint32_t max_vaddr;
	Elf32_Ehdr ehdr;
	Elf32_Shdr *shdr;
	void *entry_point;
	int num_to_load;
	Elf32_Phdr to_load[8];
	char interpreter[0x40];	/* usually /lib/ld-linux.so.2 */
};

static int strv_count(char **str)
{
	int n = 0;
	while (str[n])
		n++;
	return n;
}

static int strv_length(char **str)
{
	int n = 0, length = 0;
	while (str[n])
		length += strlen(str[n++]) + 1;
	return length;
}

static int auxv_count(Elf32Aux *aux)
{
	int n = 0;
	while (aux[n].a_type)
		n++;
	return n;
}

int elf_alloc_vdso(struct process *proc, void **vdso)
{
	int r;
	void *addr = NULL;
	size_t sz = 0x1000;
	uint8_t code[] = {0xcd, 0x80, 0xc3};

	addr = vm_process_map(proc, 0, sz, _l_PROT_READ | _l_PROT_WRITE | _l_PROT_EXEC,
		 _l_MAP_PRIVATE|_l_MAP_ANONYMOUS, -1, 0);
	if (addr == _l_MAP_FAILED)
		return -_L(ENOMEM);

	*vdso = addr;

	/*
	 * write int80 instruction to it
	 * FIXME:
	 *  - VDSO is in ELF format, so needs an ELF header
	 *  - place high in memory
	 */
	r = vm_memcpy_to_process(proc, addr, code, sizeof code);
	if (r < 0)
		return r;

	dprintf("VDSO constructed at %p\n", addr);

	return 0;
}

/* stack:
	argc
	argv[0]
	...
	argv[argc]
	env[0]
	...
	env[n]
	NULL
	av[0]
	...
	av[n]
	NULL
*/
int elf_stack_setup(struct process *context,
		void *stack, size_t stack_size,
		char **argv, char **env,
		struct elf_module *m,
		struct elf_module *interp)
{
	Elf32Aux aux[30];
	int n = 0;
	int i;
	char *p;
	void **init_stack;
	int pointer_space;
	int string_space;
	int offset;
	unsigned char *addr;
	size_t sz;
	int r;
	void *vdso = NULL;
	void *entry_point;

	r = elf_alloc_vdso(context, &vdso);
	if (r < 0)
		return r;

	entry_point = (void*) m->base - m->min_vaddr + m->ehdr.e_entry;

	memset(&aux, 0, sizeof aux);
	aux[n].a_type = AT_PHDR;
	aux[n++].a_value = (int)&((BYTE*)m->base)[m->ehdr.e_phoff];
	aux[n].a_type = AT_PHENT;
	aux[n++].a_value = sizeof (Elf32_Phdr);
	aux[n].a_type = AT_PHNUM;
	aux[n++].a_value = m->ehdr.e_phnum;
	if (interp)
	{
		aux[n].a_type = AT_BASE;	/* interpreter (libc) address */
		aux[n++].a_value = (int) interp->base;
	}
	aux[n].a_type = AT_FLAGS;
	aux[n++].a_value = 0;
	aux[n].a_type = AT_PAGESZ;
	aux[n++].a_value = pagesize;
	aux[n].a_type = AT_ENTRY;
	aux[n++].a_value = (int)m->entry_point;
	aux[n].a_type = AT_UID;
	aux[n++].a_value = context->uid;
	aux[n].a_type = AT_EUID;
	aux[n++].a_value = context->euid;
	aux[n].a_type = AT_GID;
	aux[n++].a_value = context->gid;
	aux[n].a_type = AT_EGID;
	aux[n++].a_value = context->egid;
	aux[n].a_type = AT_SECURE;
	aux[n++].a_value = 0;
	aux[n].a_type = AT_SYSINFO;
	aux[n++].a_value = (int) vdso;
	assert(n <= sizeof aux/sizeof aux[0]);

	dprintf("entry is %p\n", m->entry_point);

	/* entry, &argc, argv[0..argc-1], NULL, env[0..], NULL, auxv[0..], NULL */
	int argc = strv_count(argv);
	pointer_space = (5 + argc
			   + strv_count(env)
			   + auxv_count(aux)*2);
	pointer_space *= sizeof (void*);

	/* env space rounded */
	string_space = (strv_length(argv) + strv_length(env) + 3) & ~3;

	dprintf("%08x bytes for strings\n", string_space);

	/*
	 * Construct stack in the heap then
	 * write everything to the client in one go
	 */
	p = malloc(pointer_space + string_space);
	if (!p)
		return -_L(ENOMEM);
	n = 0;

	/* base address on local heap */
	init_stack = (void**) p;

	/* base address in client address space */
	addr = (BYTE*) stack + stack_size - (pointer_space + string_space);

	/* offset from base address */
	offset = pointer_space;

	/* copy argc, argv arrays onto the allocated memory */
	init_stack[n++] = (void*) argc;
	for (i = 0; argv[i]; i++)
	{
		dprintf("adding arg %s at %p\n", argv[i], &addr[offset]);
		init_stack[n++] = &addr[offset];
		strcpy(&p[offset], argv[i]);
		offset += strlen(argv[i]) + 1;
	}
	init_stack[n++] = NULL;

	/* gcc optimizes out these assignments if volatile is not used */
	for (i = 0; env[i]; i++)
	{
		dprintf("adding env %s at %p\n", env[i], &addr[offset]);
		init_stack[n++] = &addr[offset];
		strcpy(&p[offset], env[i]);
		offset += strlen(env[i]) + 1;
	}
	init_stack[n++] = NULL;

	/* set the auxilary vector */
	for (i = 0; aux[i].a_type; i++)
	{
		init_stack[n++] = (void*) aux[i].a_type;
		init_stack[n++] = (void*) aux[i].a_value;
	}

	init_stack[n++] = NULL;

	sz = (pointer_space + string_space);
	r = vm_memcpy_to_process(context, addr, p, sz);
	free(p);
	if (r < 0)
	{
		printf("vm_memcpy_to_process failed\n");
		return r;
	}

	context->regs.Esp = (ULONG) addr;

	return 0;
}

const char *elf_interpreter_get(struct elf_module *m)
{
	if (!m)
		return NULL;
	if (!m->interpreter[0])
		return NULL;
	return m->interpreter;
}

unsigned int elf_entry_point_get(struct elf_module *m)
{
	return (unsigned int) (m->entry_point);
}

void elf_object_free(struct elf_module *m)
{
	if (!m)
		return;
	do_close(m->fd);
	free(m);
}

static unsigned int round_down_to_page(unsigned int addr)
{
	return addr &= ~pagemask;
}

static unsigned int round_up_to_page(unsigned int addr)
{
	return (addr + pagemask) & ~pagemask;
}

int elf_mmap_flags_get(int flags)
{
	int mapflags = 0;

	if (flags & PF_X)
		mapflags |= _l_PROT_EXEC;
	if (flags & PF_W)
		mapflags |= _l_PROT_WRITE;
	if (flags & PF_R)
		mapflags |= _l_PROT_READ;
	return mapflags;
}

void elf_map_flags_print(int flags)
{
	dprintf("map -> %s %s %s\n",
		flags & _l_PROT_READ ? "PROT_READ" : "",
		flags & _l_PROT_WRITE ? "PROT_WRITE" : "",
		flags & _l_PROT_EXEC ? "PROT_EXEC" : "");
}

int elf_object_map(struct process *proc, struct elf_module *m)
{
	int i;
	int r;

	dprintf("to load (%d)\n", m->num_to_load);
	dprintf("%-8s %-8s %-8s %-8s\n", "vaddr", "memsz", "offset", "filesz");
	for (i = 0; i < m->num_to_load; i++)
	{
		m->min_vaddr = MIN(round_down_to_page(m->to_load[i].p_vaddr), m->min_vaddr);
		m->max_vaddr = MAX(round_up_to_page(m->to_load[i].p_vaddr + m->to_load[i].p_memsz), m->max_vaddr);

		dprintf("%08x %08x %08x %08x\n",
			m->to_load[i].p_vaddr, m->to_load[i].p_memsz,
			m->to_load[i].p_offset, m->to_load[i].p_filesz);
	}

	dprintf("vaddr -> %08x-%08x\n", m->min_vaddr, m->max_vaddr);

	/* reserve memory for image */
	m->base = vm_process_map(proc, (void*)m->min_vaddr, m->max_vaddr - m->min_vaddr,
			_l_PROT_NONE, _l_MAP_ANONYMOUS|_l_MAP_PRIVATE, -1, 0);
	if (m->base == _l_MAP_FAILED)
	{
		dprintf("mmap failed\n");
		goto error;
	}
	dprintf("base = %p\n", m->base);

	for (i = 0; i < m->num_to_load; i++)
	{
		int mapflags = elf_mmap_flags_get(m->to_load[i].p_flags);
		void *p;
		unsigned int vaddr = round_down_to_page(m->to_load[i].p_vaddr);
		unsigned int vaddr_offset = (m->to_load[i].p_vaddr & pagemask);
		unsigned int memsz = round_up_to_page(vaddr_offset + m->to_load[i].p_memsz);
		unsigned int max_addr;

		elf_map_flags_print(mapflags);

		p = (void*)(m->base - m->min_vaddr + vaddr);

		dprintf("map at %p, offset %08x sz %08x\n", p, vaddr, memsz);
		/*
		 * Map anonymous memory then read the data in
		 * rather than mapping the file directly.
		 *
		 * The windows page granularity is different to that on Linux.
		 * The pages may need to be modified to apply relocations.
		 *
		 * nb. need MAP_FIXED to blow away our old mapping
		 */
		p = vm_process_map(proc, p, memsz,
			_l_PROT_READ | _l_PROT_WRITE | _l_PROT_EXEC,
			_l_MAP_FIXED|_l_MAP_PRIVATE|_l_MAP_ANONYMOUS, -1, 0);
		if (p == _l_MAP_FAILED)
		{
			fprintf(stderr, "mmap failed (%d)\n", -(int)p);
			goto error;
		}

		p = (void*)(m->base - m->min_vaddr + m->to_load[i].p_vaddr);
		dprintf("pread %08x bytes from %08x to %p\n",
			m->to_load[i].p_filesz, m->to_load[i].p_offset, p);
		r = sys_pread64(m->fd, p, m->to_load[i].p_filesz, m->to_load[i].p_offset);
		if (r != m->to_load[i].p_filesz)
		{
			fprintf(stderr, "read failed (%08x != %08x)\n",
				m->to_load[i].p_filesz, r);
			goto error;
		}

		/* remember highest address we mapped, use it for brk */
		max_addr = m->to_load[i].p_vaddr + m->to_load[i].p_memsz;
		max_addr = round_up(max_addr, pagesize);
		if (proc->brk < max_addr)
			proc->brk = max_addr;
		dprintf("brk at %08x\n", proc->brk);
	}

	m->entry_point = (void*) m->base - m->min_vaddr + m->ehdr.e_entry;

	return 0;
error:
	return -1;
}

struct elf_module *elf_module_load(const char *path)
{
	bool dynamic_seen = false;
	int r;
	int i;
	struct elf_module *m;

	m = malloc(sizeof *m);
	if (!m)
		return m;
	memset(m, 0, sizeof *m);

	m->base = _l_MAP_FAILED;
	m->min_vaddr = 0xfffff000;
	m->max_vaddr = 0;

	m->fd = do_open(path, _l_O_RDONLY, 0);
	if (m->fd < 0)
	{
		dprintf("open() failed\n");
		goto error;
	}

	r = kread(m->fd, &m->ehdr, sizeof m->ehdr, 0);
	if (r < 0)
	{
		dprintf("read() failed\n");
		goto error;
	}

	if (memcmp(&m->ehdr, ELFMAG, SELFMAG))
	{
		dprintf("not an ELF file\n");
		goto error;
	}

	if (m->ehdr.e_type != ET_EXEC &&
		m->ehdr.e_type != ET_REL &&
		m->ehdr.e_type != ET_DYN)
	{
		dprintf("not an ELF executable\n");
		goto error;
	}

	if (m->ehdr.e_machine != EM_386)
	{
		dprintf("not an i386 ELF executable\n");
		goto error;
	}

	dprintf("opened ELF file, entry=%08x\n", m->ehdr.e_entry);

	dprintf("Program headers (%d)\n", m->ehdr.e_phnum);
	dprintf("     %-15s %-8s %-8s %-8s %-8s %-8s %-8s\n",
		"type", "offset", "vaddr", "filesz",
		"memsz", "flags", "align");

	for (i = 0; i < m->ehdr.e_phnum; i++)
	{
		Elf32_Phdr phdr;
		r = kread(m->fd, &phdr, sizeof phdr,
			 m->ehdr.e_phoff + i * sizeof phdr);
		if (r < 0)
			break;

		dprintf("[%2d] %08x %08x %08x %08x %08x %08x\n", i,
			phdr.p_offset,
			phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz,
			phdr.p_flags, phdr.p_align);

		/* load segments */
		if (phdr.p_type == PT_LOAD)
		{
			if (m->num_to_load >= sizeof m->to_load/
						sizeof m->to_load[0])
			{
				dprintf("too many PT_LOAD entries\n");
				goto error;
			}

			memcpy(&m->to_load[m->num_to_load], &phdr, sizeof phdr);
			m->num_to_load++;
		}

		if (phdr.p_type == PT_DYNAMIC)
		{
			if (dynamic_seen)
			{
				fprintf(stderr, "two PT_DYNAMIC sections\n");
				goto error;
			}
			dynamic_seen = true;
		}
		if (phdr.p_type == PT_INTERP)
		{
			size_t sz = phdr.p_filesz;

			if (sz > sizeof m->interpreter - 1)
			{
				dprintf("interpreter name too big\n");
				goto error;
			}
			r = kread(m->fd, &m->interpreter, sz, phdr.p_offset);
			if (r != sz)
			{
				dprintf("interpreter name read failed\n");
				goto error;
			}
			m->interpreter[sz] = 0;
		}
	}

	return m;

error:
	do_close(m->fd);
	free(m);
	return NULL;
}
