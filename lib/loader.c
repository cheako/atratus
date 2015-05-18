/*
 * basic dynamic linker
 *
 * Copyright (C)  2006-2012 Mike McCormack
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

#include <sys/types.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/elf32.h>
#include <sys/elf_extra.h>

#include "loader.h"
#include "string.h"
#include "stdlib.h"
#include "debug.h"
#include "linux-defines.h"
#include "linux-errno.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

struct dt_info
{
	Elf32_Word init;
	Elf32_Word fini;
	Elf32_Word pltgot;
	Elf32_Word pltrel;
	Elf32_Word pltrelsz;
	Elf32_Word hash;
	Elf32_Word rela;
	Elf32_Word relasz;
	Elf32_Word rel;
	Elf32_Word relsz;
	Elf32_Word relent;
	Elf32_Word relcount;
	Elf32_Word textrel;
	Elf32_Word jmprel;
	Elf32_Word syment;
	Elf32_Word symtab;
	Elf32_Word strtab;
	Elf32_Word strsz;
	Elf32_Word verneed;
	Elf32_Word verneednum;
	Elf32_Word versym;
	Elf32_Word gnu_hash;
	Elf32_Word debug;
};

struct module_info
{
	unsigned int delta;
	unsigned int base;
	struct dt_info dt;
	const char *name;
};

static struct module_info modules[32];
static struct module_info *main_module = &modules[0];
static struct module_info *loader_module = &modules[1];
static int module_count = 2;
extern char **environ;
static int ldverbose = 0;

/*
 * bootstrapping functions
 */
static void *ldmemcpy(void *dest, const void *src, size_t n)
{
	const unsigned char *sc = src;
	unsigned char *dc = dest;
	int i;

	for (i = 0; i < n; i++)
		dc[i] = sc[i];

	return dest;
}

static int ldmemcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *left = s1, *right = s2;
	int r = 0;
	int i;

	for (i = 0; r == 0 && i < n; i++)
		r = left[i] - right[i];

	return r;
}

static int ldstrcmp(const char *a, const char *b)
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

/*static*/ int ldstrlen(const char *s)
{
	int n = 0;
	while (s[n])
		n++;
	return n;
}

static void ldexit(int status)
{
	while (1)
	{
		__asm__ __volatile__ (
			"\tint $0x80\n"
		:
		: "a"(1), "b"(status)
		: "memory");
	}
}

static int ldopen(const char *filename, int flags, int mode)
{
	int r;
	SYSCALL3(5, filename, flags, mode);
	return r;
}

static int ldread(int fd, void *buffer, size_t length)
{
	int r;
	SYSCALL3(3, fd, buffer, length);
	return r;
}

static int ldpread(int fd, void *buf, size_t count, off_t offset)
{
	int r;
	SYSCALL5(180, fd, buf, count, offset, 0);
	return r;
}

static int ldwrite(int fd, const void *buffer, size_t length)
{
	int r;
	SYSCALL3(4, fd, buffer, length);
	return r;
}

static void* ldmmap(void *start, size_t len, int prot, int flags, int fd, off_t offset)
{
	int r;
	unsigned long args[6];

	/* not enough free registers to pass 6 args in */
	args[0] = (unsigned long) start;
	args[1] = (unsigned long) len;
	args[2] = (unsigned long) prot;
	args[3] = (unsigned long) flags;
	args[4] = (unsigned long) fd;
	args[5] = (unsigned long) offset;

	__asm__ __volatile__(
		"\tpush %%ebx\n"
		"\tpush %%ebp\n"
		"\tmov (%%eax), %%ebx\n"
		"\tmov 4(%%eax), %%ecx\n"
		"\tmov 8(%%eax), %%edx\n"
		"\tmov 12(%%eax), %%esi\n"
		"\tmov 16(%%eax), %%edi\n"
		"\tmov 20(%%eax), %%ebp\n"
		"\tmov $192, %%eax\n"
		"\tint $0x80\n"
		"\tpop %%ebp\n"
		"\tpop %%ebx\n"
		: "=a"(r)
		: "a" (args)
		: "memory", "ecx", "edx", "esi", "edi"
	);

	if ((r & 0xfffff000) == 0xfffff000)
		return _L(MAP_FAILED);

	return (void*) r;
}

static int ldclose(int fd)
{
	int r;
	SYSCALL1(6, fd);
	return r;
}

static void ldvprintf(const char *str, va_list va)
{
	const char *p = str;
	char buffer[0x200];
	char *out = buffer;

	while (*p)
	{
		size_t len = 0;

		while (p[len] && p[len] != '%')
			len++;
		if (len)
		{
			ldmemcpy(out, p, len);
			out += len;
			p += len;
			continue;
		}

		if (!*p)
			break;

		p++;

		switch (*p)
		{
		case '%':
			*out++ = '%';
			p++;
			break;
		case 'p':
		case 'x':
			{
				unsigned int val = va_arg(va, unsigned int);
				int i;
				for (i = 0; i < 8; i++)
				{
					unsigned int rem = (val % 0x10);
					out[7 - i] = (rem > 9) ? (rem - 10 + 'A') : (rem + '0');
					val /= 0x10;
				}
				out += i;
			}
			p++;
			break;
		case 's':
			{
				const char *val = va_arg(va, const char*);
				while (*val)
					*out++ = *val++;
			}
			p++;
			break;
		case 'c':
			*out = va_arg(va, int);
			p++;
			break;
		default:
			ldwrite(2, "ldprintf ??\n", 10);
			ldexit(1);
		}
	}

	ldwrite(1, buffer, out - buffer);
}

static void ldprintf(const char *str, ...)
{
	va_list va;

	if (!ldverbose)
		return;

	va_start(va, str);
	ldvprintf(str, va);
	va_end(va);
}

static void lddie(const char *error, ...)
{
	va_list va;

	va_start(va, error);
	ldvprintf(error, va);
	va_end(va);

	ldexit(1);
}

static unsigned int ld_get_auxv(Elf32_Aux *auxv, int value)
{
	int i;

	for (i = 0; auxv[i].a_type != AT_NULL; i++)
		if (auxv[i].a_type == value)
			return auxv[i].a_value;

	return 0;
}

unsigned long elf_hash(const char *name)
{
	unsigned long h = 0, g;
	const uint8_t *p = (const uint8_t*) name;
	while (*p)
	{
		h = (h << 4) + *p++;
		g = (h & 0xf0000000);
		if (g)
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

uint32_t dl_new_hash(const char *s)
{
	uint32_t h = 5381;

	while (*s)
	{
		h = (h * 33) + *s;
		s++;
	}

	return h;
}

static const char *strtab_get(struct module_info *m, Elf32_Word ofs)
{
	return (const char*) (m->delta + m->dt.strtab + ofs);
}

Elf32_Sym *elf_hash_lookup(struct module_info *m,
				const char *symbol_name)
{
	Elf32_Word hash;
	struct {
		Elf32_Word nbuckets;
		Elf32_Word nchains;
		Elf32_Word buckets[1];
	} *dthash;
	Elf32_Word *chains;
	uint32_t index;
	uint32_t count;

	dthash = (void*)(m->dt.hash + m->delta);

	hash = elf_hash(symbol_name);

	index = dthash->buckets[hash % dthash->nbuckets];
	chains = &dthash->buckets[dthash->nbuckets];
	count = dthash->nchains;
	while (index != STN_UNDEF && count != 0)
	{
		const char *name;
		Elf32_Sym *sym;

		sym = (void*)(m->delta + m->dt.symtab);
		sym += index;

		name = strtab_get(m, sym->st_name);
#if 0
		if (elf_hash(name) != hash)
		{
			fprintf(stderr, "bad hash in chain\n");
			abort();
		}
#endif
		if (!ldstrcmp(name, symbol_name))
			return sym;

		index = chains[index];
		count--;
	}
	if (!count)
	{
		ldprintf("circular chain in ELF32 hash\n");
		ldexit(1);
	}

	return 0;
}

/* https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections */
Elf32_Sym *elf_gnu_hash_lookup(struct module_info *m,
				const char *symbol_name)
{
	struct {
		Elf32_Word	nbuckets;
		Elf32_Word	symndx;
		Elf32_Word	maskwords;
		Elf32_Word	shift2;
		Elf32_Word      data[1];
	} *gnuhash;
	Elf32_Word *chain, *buckets;

	Elf32_Sym *r = 0;
	Elf32_Word hash;
	Elf32_Word index;
	int last = 0;

	gnuhash = (void*)(m->delta + m->dt.gnu_hash);
	hash = dl_new_hash(symbol_name);

	/* TODO: use bloom filter here */

	buckets = &gnuhash->data[gnuhash->maskwords];
	index = buckets[hash % gnuhash->nbuckets];
	if (!index)
		return r;

	chain = &buckets[gnuhash->nbuckets];
	chain += (index - gnuhash->symndx);

	while (!last)
	{
		Elf32_Sym *sym;
		const char *name;

		last = *chain & 1;
		if ((*chain & ~1) == (hash & ~1))
		{
			sym = (void*)(m->delta + m->dt.symtab);
			sym += index;
			name = strtab_get(m, sym->st_name);
			if (!ldstrcmp(name, symbol_name))
			{
				r = sym;
				break;
			}
		}

		chain++;
		index++;
	}

	if (!r)
		ldprintf("symbol %s not found in %s\n",
			symbol_name, m->name);

	return r;
}

Elf32_Word module_get_symbol_address(struct module_info *m,
					const char *symbol_name)
{
	Elf32_Sym *r = 0;

	if (m->dt.gnu_hash)
		r = elf_gnu_hash_lookup(m, symbol_name);
	else if (m->dt.hash)
		r = elf_hash_lookup(m, symbol_name);

	if (r && r->st_size)
		return r->st_value;

	return 0;
}

static Elf32_Word ld_get_symbol_address_exclude(const char *sym,
					 struct module_info *exclude)
{
	Elf32_Word r;
	int i;

	/*
	 * search order...?
	 * main module first
	 * then libraries
	 */
	for (i = 0; i < module_count; i++)
	{
		if (exclude == &modules[i])
			continue;

		r = module_get_symbol_address(&modules[i], sym);
		if (r)
			return (modules[i].delta + r);
	}

	ldprintf("no symbol = %s\n", sym);

	return 0;
}

static Elf32_Word ld_get_symbol_address(const char *sym)
{
	return ld_get_symbol_address_exclude(sym, NULL);
}

void *__ld_dynamic_resolve(void *arg, unsigned int entry, void *callee)
{
	struct module_info *m = arg;
	Elf32_Word target;
	void *r = 0;
	Elf32_Rel *rel;
	Elf32_Word syminfo;
	Elf32_Word symtype;
	const char *symbol_name;
	Elf32_Sym *st;
	void **got_entry;

	ldprintf("%s arg=%p plt_entry=%x callee=%p\n",
		__FUNCTION__, arg, entry, callee);

	if (m->dt.pltrel != DT_REL)
		ldprintf("not DT_REL\n");
	rel = (void*) (m->delta + m->dt.jmprel + entry);

	syminfo = ELF32_R_SYM(rel->r_info);
	symtype = ELF32_R_TYPE(rel->r_info);
	if (symtype != R_386_JMP_SLOT)
		return 0;

	ldprintf("dt.symtab = %x\n", m->dt.symtab);
	ldprintf("syminfo = %x\n", syminfo);

	st = (Elf32_Sym*) (m->delta + m->dt.symtab);
	st += syminfo;

	ldprintf("st_name = %x offset = %x\n", st->st_name, rel->r_offset);
	symbol_name = (const char*) (m->delta + m->dt.strtab + st->st_name);
	ldprintf("symbol_name = %s\n", symbol_name);

	target = ld_get_symbol_address(symbol_name);
	if (!target)
	{
		/* FIXME: handle weak symbols */
		die("no such symbol (%s)\n", symbol_name);
	}

	r = (void*) target;

	ldprintf("dynamic resolve: %x -> %p\n", entry, r);

	/* patch the correct value into the GOT */
	got_entry = (void**)((char*)m->delta + rel->r_offset);

	/* patch the resolved address into the GOT */
	*got_entry = r;
	ldprintf("patched GOT at %p\n", got_entry);

	return r;
}

/* this address is patched into the GOT at offset 2 */
extern void __dynamic_resolve_trampoline(void);
__asm__ (
	"\n"
	"__dynamic_resolve_trampoline:\n"
	"\tcall __ld_dynamic_resolve\n"
	"\tadd $8, %esp\n"
	"\torl %eax, %eax\n"
	"\tjz skip\n"
	"\tpushl %eax\n"
	"skip:\n"
	"\tret\n"
);

void patch_got(struct module_info *m)
{
	int i;
	unsigned int *got = (void*) m->delta + m->dt.pltgot;

	ldprintf("PLTGOT:    %x\n", m->dt.pltgot);
	ldprintf("PLTRELSZ:  %x\n", m->dt.pltrelsz);

	if (!m->dt.pltrelsz)
		return;

	/* skip the first 3 entries, they're special */
	i = 1;
	got[i++] = (unsigned int) m;
	got[i++] = (unsigned int) &__dynamic_resolve_trampoline;

	for ( ; i < m->dt.pltrelsz/4; i++)
	{
		if (got[i])
			got[i] += m->delta;
	}
}

void elf_apply_reloc_glob_dat(struct module_info *m, int offset)
{
	Elf32_Rel *rel = (void*)(m->delta + m->dt.rel);
	Elf32_Word syminfo;
	Elf32_Sym *st;
	const char *symbol_name;
	Elf32_Word value;
	uint32_t *p;

	syminfo = ELF32_R_SYM(rel[offset].r_info);

	ldprintf("%x %x R_386_GLOB_DAT\n", rel->r_offset, syminfo);

	st = (Elf32_Sym*) (m->delta + m->dt.symtab);
	st += syminfo;

	symbol_name = (const char*) (m->delta + m->dt.strtab + st->st_name);

	p = (uint32_t*)(m->delta + rel[offset].r_offset);

	if (st->st_value && st->st_size)
	{
		/* has a value and size, so is defined */
		value = (uint32_t) (m->delta + st->st_value);

		ldprintf("R_386_GLOB_DAT: definition "
			"of %s (in %s) @%p -> %x\n",
			symbol_name, m->name, p, value);
	}
	else
	{
		ldprintf("%s used in %s\n", symbol_name, m->name);
		value = ld_get_symbol_address(symbol_name);

		ldprintf("R_386_GLOB_DAT: reference "
			"to %s (in %s) @%p -> %x\n",
			symbol_name, m->name, p, value);
	}

	*p = (uint32_t) value;
}

void ld_apply_reloc_copy(struct module_info *m, Elf32_Rel *rel)
{
	Elf32_Word syminfo = ELF32_R_SYM(rel->r_info);
	const char *symbol_name;
	Elf32_Sym *st = (Elf32_Sym*) (m->delta + m->dt.symtab);
	Elf32_Word value;
	void *src, *dest;

	st += syminfo;
	symbol_name = (const char*) (m->delta + m->dt.strtab + st->st_name);

	/* find the copy source */
	value = ld_get_symbol_address_exclude(symbol_name, m);
	if (!value)
	{
		ldprintf("symbol not found: %s\n", symbol_name);
		return;
	}

	src = (void*)value;
	dest = (void*)(st->st_value + m->delta);

	ldmemcpy(dest, (void*)src, st->st_size);

	ldprintf("R_386_COPY (%s) %p -> %p\n", symbol_name, src, dest);
}

static void ld_apply_reloc_32(struct module_info *m, Elf32_Rel *rel)
{
	Elf32_Word syminfo = ELF32_R_SYM(rel->r_info);
	const char *symbol_name;
	Elf32_Sym *st = (Elf32_Sym*) (m->delta + m->dt.symtab);
	Elf32_Word value;
	Elf32_Word *dest;

	st += syminfo;
	symbol_name = (const char*) (m->delta + m->dt.strtab + st->st_name);

	value = ld_get_symbol_address(symbol_name);
	if (!value)
	{
		ldprintf("symbol '%s' not found\n", symbol_name);
		ldexit(1);
	}

	value += main_module->delta;

	ldprintf("R_386_32 reloc applied %s -> %x\n",
		symbol_name, value);

	dest = (void*)(m->delta + rel->r_offset);
	*dest = value;
}

static void ld_apply_reloc_relative(struct module_info *m, Elf32_Rel *rel)
{
	Elf32_Word *dest;

	dest = (void*)(m->delta + rel->r_offset);

	ldprintf("R_386_RELATIVE: %x %x -> %x\n", dest, *dest, *dest + m->base);

	*dest += m->base;
}

static void ld_apply_symbol_value(struct module_info *m, Elf32_Rel *rel)
{
	Elf32_Word syminfo = ELF32_R_SYM(rel->r_info);
	const char *symbol_name;
	Elf32_Sym *st = (Elf32_Sym*) (m->delta + m->dt.symtab);
	Elf32_Word value;
	Elf32_Word *dest;

	st += syminfo;
	symbol_name = (const char*) (m->delta + m->dt.strtab + st->st_name);

	/* find the copy source */
	value = ld_get_symbol_address_exclude(symbol_name, m);
	if (!value)
	{
		ldprintf("symbol not found: %s\n", symbol_name);
		return;
	}

	dest = (void*)(m->delta + rel->r_offset);

	ldprintf("R_386_32 apply: %s at %x in %s\n", symbol_name, dest, m->name);

	(*dest) += value;
}

static void ld_apply_tls_dtpmod32(struct module_info *m, Elf32_Rel *rel)
{
	ldverbose++;
	ldprintf("warning: R_386_TLS_DTPMOD32 reloc unapplied\n");
	ldverbose--;
}

int ld_apply_relocations(struct module_info *m)
{
	int i;

	ldprintf("Applying relocs for %s\n", m->name);

	for (i = 0; i < m->dt.relsz/sizeof (Elf32_Rel); i++)
	{
		Elf32_Rel *rel = (void*)(m->dt.rel + m->delta);
		Elf32_Word syminfo = ELF32_R_SYM(rel[i].r_info);
		Elf32_Word symtype = ELF32_R_TYPE(rel[i].r_info);

		switch (symtype)
		{
		case R_386_GLOB_DAT:
			elf_apply_reloc_glob_dat(m, i);
			break;
		case R_386_COPY:
			ld_apply_reloc_copy(m, &rel[i]);
			break;
		case R_386_RELATIVE:
			if (syminfo)
				lddie("R_386_RELATIVE expects syminfo to be zero\n");
			ld_apply_reloc_relative(m, &rel[i]);
			break;
		case R_386_32: /* Add symbol value. */
			ld_apply_symbol_value(m, &rel[i]);
			break;
		case R_386_TLS_DTPMOD32:
			ld_apply_tls_dtpmod32(m, &rel[i]);
			break;
		default:
			/* FIXME */
			lddie("%s: %x %x %x (relocation type unknown, cannot be applied)\n",
				m->name, rel[i].r_offset, syminfo, symtype);
		}
	}

	return 0;
}

static int ld_apply_loader_relocations(struct module_info *m)
{
	int i;

	ldprintf("Applying relocs for %s\n", m->name);

	for (i = 0; i < m->dt.relsz/sizeof (Elf32_Rel); i++)
	{
		Elf32_Rel *rel = (void*)(m->dt.rel + m->delta);
		Elf32_Word syminfo = ELF32_R_SYM(rel[i].r_info);
		Elf32_Word symtype = ELF32_R_TYPE(rel[i].r_info);

		switch (symtype)
		{
		case R_386_RELATIVE:
			break;
		case R_386_32:
			ld_apply_reloc_32(m, &rel[i]);
			break;
		default:
			ldprintf("%x %x "
                               "(symbol type %x not supported)\n",
				rel[i].r_offset, syminfo, symtype);
			ldexit(1);
		}
	}

	return 0;
}

static void ld_add_needed(const char *name)
{
	int i, n;

	/* in the list already? */
	for (i = 0; i < module_count; i++)
		if (!ldstrcmp(name, modules[i].name))
			return;

	if (module_count > sizeof modules/sizeof modules[0])
		die("Too many libraries needed\n");

	n = module_count++;
	modules[n].name = name;

	ldprintf("need %s\n", modules[n].name);
}

void ld_read_dynamic_section(struct module_info *m, Elf32_Word dyn_offset)
{
	Elf32_Dyn *dyn = (void*)(m->delta + dyn_offset);
	int i;

	for (i = 0; dyn[i].d_tag != DT_NULL; i++)
	{
		switch (dyn[i].d_tag)
		{
#define X(name, field) case DT_##name: m->dt.field = dyn[i].d_un.d_val; break;
		X(INIT, init)
		X(FINI, fini)
		X(PLTGOT, pltgot)
		X(PLTREL, pltrel)
		X(PLTRELSZ, pltrelsz)
		X(HASH, hash)
		X(RELA, rela)
		X(RELASZ, relasz)
		X(REL, rel)
		X(RELSZ, relsz)
		X(RELENT, relent)
		X(RELCOUNT, relcount)
		X(TEXTREL, textrel)
		X(JMPREL, jmprel)
		X(SYMENT, syment)
		X(SYMTAB, symtab)
		X(STRTAB, strtab)
		X(STRSZ, strsz)
		X(VERNEED, verneed)
		X(VERNEEDNUM, verneednum)
		X(VERSYM, versym)
		X(GNU_HASH, gnu_hash)
		X(DEBUG, debug)
#undef X
		default:
			if (0)
			{
				ldprintf("[%x] %x %x\n", i,
					dyn[i].d_tag,
					dyn[i].d_un.d_val);
			}
		}
	}

	/* store DT_NEEDED sections after stringtab is valid */
	for (i = 0; dyn[i].d_tag != DT_NULL; i++)
	{
		if (dyn[i].d_tag != DT_NEEDED)
			continue;
		ld_add_needed(strtab_get(m, dyn[i].d_un.d_val));
	}
}

static const Elf32_Phdr* ld_find_dynamic_phdr(Elf32_Phdr *phdr, unsigned int phnum)
{
	const Elf32_Phdr *dynamic = NULL;
	int i;

	if (phdr == NULL || phnum == 0)
	{
		ldprintf("no program header?\n");
		return NULL;
	}

	/* find the dynamic section */
	for (i = 0; i < phnum; i++)
		if (phdr[i].p_type == PT_DYNAMIC)
			dynamic = &phdr[i];

	return dynamic;
}

const int pagesize = 0x1000;
const int pagemask = 0x0fff;

static unsigned int round_down_to_page(unsigned int addr)
{
	return addr &= ~pagemask;
}

static unsigned int round_up_to_page(unsigned int addr)
{
	return (addr + pagemask) & ~pagemask;
}

static int mmap_flags_from_elf(int flags)
{
	int mapflags = 0;

	if (flags & PF_X)
		mapflags |= _L(PROT_EXEC);
	if (flags & PF_W)
		mapflags |= _L(PROT_WRITE);
	if (flags & PF_R)
		mapflags |= _L(PROT_READ);
	return mapflags;
}

static int map_elf_object(struct module_info *m, Elf32_Ehdr *ehdr, int fd)
{
	int i;
	int r;
	int num_to_load = 0;
	Elf32_Phdr dynamic;
	Elf32_Phdr to_load[8];
	bool dynamic_seen = false;
	Elf32_Word min_vaddr = ~0;
	Elf32_Word max_vaddr = 0;
	unsigned char *base;

	ldprintf("Program headers (%x)\n", ehdr->e_phnum);
	ldprintf("     type     offset   vaddr    filesz   memsz    flags    align\n");

	for (i = 0; i < ehdr->e_phnum; i++)
	{
		Elf32_Phdr phdr;
		r = ldpread(fd, &phdr, sizeof phdr,
			 ehdr->e_phoff + i * sizeof phdr);
		if (r < 0)
			break;

		ldprintf("[%x] %x %x %x %x %x %x\n", i, phdr.p_offset,
			phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz,
			phdr.p_flags, phdr.p_align);

		/* load segments */
		if (phdr.p_type == PT_LOAD)
		{
			ldmemcpy(&to_load[num_to_load], &phdr, sizeof phdr);
			num_to_load++;
		}

		if (phdr.p_type == PT_DYNAMIC)
		{
			if (dynamic_seen)
			{
				lddie("two PT_DYNAMIC sections\n");
				goto error;
			}
			dynamic_seen = 1;
			ldmemcpy(&dynamic, &phdr, sizeof phdr);
		}
	}

	ldprintf("to load (%x)\n", num_to_load);
	ldprintf("vaddr    memsz    offset   filesz\n");
	for (i = 0; i < num_to_load; i++)
	{
		min_vaddr = MIN(round_down_to_page(to_load[i].p_vaddr), min_vaddr);
		max_vaddr = MAX(round_up_to_page(to_load[i].p_vaddr + to_load[i].p_memsz), max_vaddr);

		ldprintf("%x %x %x %x\n",
			to_load[i].p_vaddr, to_load[i].p_memsz,
			to_load[i].p_offset, to_load[i].p_filesz);
	}

	ldprintf("vaddr -> %x-%x\n", min_vaddr, max_vaddr);

	/* reserve memory for image */
	base = ldmmap((void*)min_vaddr, max_vaddr - min_vaddr,
			_L(PROT_NONE), _L(MAP_ANONYMOUS)|_L(MAP_PRIVATE), -1, 0);
	if (base == _L(MAP_FAILED))
		lddie("mmap\n");

	m->delta = (char*) base - (char*) min_vaddr;
	m->base = (unsigned int) base;

	ldprintf("base = %p\n", base);

	for (i = 0; i < num_to_load; i++)
	{
		int mapflags = mmap_flags_from_elf(to_load[i].p_flags);
		void *p;
		unsigned int vaddr = round_down_to_page(to_load[i].p_vaddr);
		unsigned int vaddr_offset = (to_load[i].p_vaddr & pagemask);
		unsigned int filesz = round_up_to_page(vaddr_offset + to_load[i].p_filesz);

		(void) mapflags;	/* FIXME: use these */

		p = (void*)(base - min_vaddr + vaddr);

		ldprintf("map at %p, offset %x sz %x\n", p, vaddr, filesz);
		/*
		 * Map anonymous memory then read the data in
		 * rather than mapping the file directly.
		 *
		 * The windows page granularity is different to that on Linux.
		 * The pages may need to be modified to apply relocations.
		 *
		 * nb. need MAP_FIXED to blow away our old mapping
		 */
		p = ldmmap(p, filesz, _L(PROT_READ)|_L(PROT_WRITE)|_L(PROT_EXEC),
			 _L(MAP_FIXED)|_L(MAP_PRIVATE)|_L(MAP_ANONYMOUS), -1, 0);
		if (p == _L(MAP_FAILED))
		{
			lddie("mmap");
			goto error;
		}
		r = ldpread(fd, base + to_load[i].p_vaddr,
			 to_load[i].p_filesz, to_load[i].p_offset);
		if (r != to_load[i].p_filesz)
		{
			lddie("read failed (%x != %x)\n",
				to_load[i].p_filesz, r);
			goto error;
		}
	}

	/* after all pages are mapped... */
	ld_read_dynamic_section(m, dynamic.p_vaddr);

	return 0;
error:
	return -1;
}

static int ld_load_module(struct module_info *m)
{
	int fd = -1;
	int r = -1;
	Elf32_Ehdr ehdr;

	/* TODO: support something like /etc/ld.so.conf */
	char path[0x100] = "/lib/";

	ldmemcpy(&path[5], m->name, ldstrlen(m->name)+1);

	fd = ldopen(path, _L(O_RDONLY), 0);
	if (fd < 0)
		lddie("failed to open %s\n", path);

	r = ldread(fd, &ehdr, sizeof ehdr);
	if (r < 0)
		lddie("%s read failed\n", path);

	if (ldmemcmp(&ehdr.e_ident, ELFMAG, SELFMAG))
		lddie("%s is not in ELF file\n", path);

	if (ehdr.e_type != ET_REL && ehdr.e_type != ET_DYN)
		lddie("%s is not an ELF library (%x)\n", path, ehdr.e_type);

	if (ehdr.e_machine != EM_386)
		lddie("%s is not for i386\n", path);

	if (0 > map_elf_object(m, &ehdr, fd))
		lddie("failed to map %s\n", path);

	ldprintf("opened ELF file %s, entry=%x\n", path, ehdr.e_entry);

	ldclose(fd);

	return r;
}

/*
 * This is the bigest hack in this program
 * We can't setup our own TLS, because Windows provides no syscall to do that.
 * However, Windows threads use %fs, so we can set %gs to the same selector
 *
 *   Offset     Windows TEB                   Linux
 *    0x00      SEH Exception list pointer    ELF TLS pointer
 *    0x04      Stack base address
 *    0x08      Stack limit address
 *    0x0c      Subsystem TIB
 *    0x10      FiberData/Version
 *    0x14      TIB Self pointer              Stack smashing protection value
 */
void ld_setup_gs(void)
{
	__asm__ __volatile__(
		"\tmovw %%fs, %%ax\n"
		"\tmovw %%ax, %%gs\n"
	:::"eax");
}

void *ld_main(int argc, char **argv, char **env, Elf32_Aux *auxv)
{
	unsigned int phnum = ld_get_auxv(auxv, AT_PHNUM);
	Elf32_Phdr *phdr = (void*) ld_get_auxv(auxv, AT_PHDR);
	void *entry = (void*) ld_get_auxv(auxv, AT_ENTRY);
	void *ld_base = (void*) ld_get_auxv(auxv, AT_BASE);
	const Elf32_Phdr *dynamic = NULL;
	Elf32_Ehdr *ehdr = ld_base;
	int i;

	ld_setup_gs();

	/* read the loader's dynamic section */
	loader_module->name = "ld.so";

	/* FIXME: assumes target load address is zero */
	loader_module->delta = (int) ld_base;

	dynamic = ld_find_dynamic_phdr((void*) (loader_module->delta + ehdr->e_phoff),
					ehdr->e_phnum);
	if (!dynamic)
		lddie("loader has no dynamic program header\n");

	ld_read_dynamic_section(loader_module, dynamic->p_vaddr);

	/* read the main exe's dynamic sectin */
	dynamic = ld_find_dynamic_phdr(phdr, phnum);
	if (!dynamic)
		lddie("target has no dynamic program header\n");

	main_module->name = "exe";

	ld_read_dynamic_section(main_module, dynamic->p_vaddr);

	/* TODO: not working yet */
	for (i = 2; i < module_count; i++)
	{
		int r = ld_load_module(&modules[i]);
		if (r < 0)
			lddie("failed to load %s\n", modules[i].name);
	}

	ldprintf("patching GOT\n");

	for (i = 0; i < module_count; i++)
	{
		if (i == 1)
			continue;
		patch_got(&modules[i]);
	}

	ld_apply_loader_relocations(loader_module);

	for (i = 0; i < module_count; i++)
	{
		if (i == 1)
			continue;
		ld_apply_relocations(&modules[i]);
	}

	environ = env;

	ldprintf("done returning to %p\n", entry);

	return entry;
}
