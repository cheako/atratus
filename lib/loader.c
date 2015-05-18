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

#define NULL ((void *)0)

static struct module_info loader_module;
static struct module_info main_module;
extern char **environ;

/*
 * errno should be per thread,
 * leave as global until we can load an ELF binary
 */

static unsigned int ld_get_auxv(Elf32_Aux *auxv, int value)
{
	int i;

	for (i = 0; auxv[i].a_type != AT_NULL; i++)
		if (auxv[i].a_type == value)
			return auxv[i].a_value;

	return 0;
}

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
	struct dt_info dt;
	const char *name;
};

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
		if (!strcmp(name, symbol_name))
			return sym;

		index = chains[index];
		count--;
	}
	if (!count)
		die("circular chain in ELF32 hash\n");

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
			if (!strcmp(name, symbol_name))
			{
				r = sym;
				break;
			}
		}

		chain++;
		index++;
	}

	if (!r)
		dprintf("symbol %s not found in %s\n",
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

	/*
	 * search order...?
	 * main module first
	 * then libraries
	 */
	if (exclude != &main_module)
	{
		r = module_get_symbol_address(&main_module, sym);
		if (r)
			return (main_module.delta + r);
	}

	if (exclude != &loader_module)
	{
		r = module_get_symbol_address(&loader_module, sym);
		if (r)
			return (loader_module.delta + r);
	}

	dprintf("no symbol = %s\n", sym);

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

	dprintf("%s arg=%p plt_entry=%08x callee=%p\n",
		__FUNCTION__, arg, entry, callee);

	if (m->dt.pltrel != DT_REL)
		dprintf("not DT_REL\n");
	rel = (void*) (m->dt.jmprel + entry);

	syminfo = ELF32_R_SYM(rel->r_info);
	symtype = ELF32_R_TYPE(rel->r_info);
	if (symtype != R_386_JMP_SLOT)
		return 0;

	dprintf("dt.symtab = %08x\n", m->dt.symtab);
	dprintf("syminfo = %08x\n", syminfo);

	st = (Elf32_Sym*) m->dt.symtab;
	st += syminfo;

	dprintf("st_name = %d offset = %08x\n", st->st_name, rel->r_offset);
	symbol_name = (const char*) m->dt.strtab + st->st_name;
	dprintf("symbol_name = %s\n", symbol_name);

	target = ld_get_symbol_address(symbol_name);
	if (!target)
	{
		// FIXME: handle weak symbols
		die("no such symbol (%s)\n", symbol_name);
	}

	r = (void*) target;

	dprintf("dynamic resolve: %08x -> %p\n", entry, r);

	/* patch the correct value into the GOT */
	got_entry = (void**)((char*)m->delta + rel->r_offset);

	/* patch the resolved address into the GOT */
	*got_entry = r;
	dprintf("patched GOT at %p\n", got_entry);

	return r;
}

// this address is patched into the GOT at offset 2
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

	/* TODO: apply delta between actual and intended load address */

	unsigned int *got = (void*) + m->dt.pltgot;
	dprintf("PLTGOT:    %08x\n", m->dt.pltgot);
	dprintf("PLTRELSZ:  %08x\n", m->dt.pltrelsz);

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

	dprintf("%08x %06x R_386_GLOB_DAT\n", rel->r_offset, syminfo);

	st = (Elf32_Sym*) m->dt.symtab;
	st += syminfo;

	symbol_name = (const char*) m->dt.strtab + st->st_name;

	p = (uint32_t*)(m->delta + rel[offset].r_offset);

	if (st->st_value && st->st_size)
	{
		/* has a value and size, so is defined */
		value = (uint32_t) (m->delta + st->st_value);

		dprintf("R_386_GLOB_DAT: definition "
			"of %s (in %s) @%p -> %08x\n",
			symbol_name, m->name, p, value);
	}
	else
	{
		dprintf("%s used in %s\n", symbol_name, m->name);
		value = ld_get_symbol_address(symbol_name);

		dprintf("R_386_GLOB_DAT: reference "
			"to %s (in %s) @%p -> %08x\n",
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
		dprintf("symbol not found: %s\n", symbol_name);
		return;
	}

	src = (void*)value;
	dest = (void*)(st->st_value + m->delta);

	memcpy(dest, (void*)src, st->st_size);

	dprintf("R_386_COPY (%s) %p -> %p\n", symbol_name, src, dest);
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
		die("symbol '%s' not found\n", symbol_name);

	value += main_module.delta;

	dprintf("R_386_32 reloc applied %s -> %08x\n",
		symbol_name, value);

	dest = (void*)(m->delta + rel->r_offset);
	*dest = value;
}

int ld_apply_relocations(struct module_info *m)
{
	int i;

	dprintf("Applying relocs for %s\n", m->name);

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
		default:
			/* FIXME */
			dprintf("%08x %06x %d (not applied)\n", rel[i].r_offset,
				syminfo, symtype);
		}
	}

	return 0;
}

static int ld_apply_loader_relocations(struct module_info *m)
{
	int i;

	dprintf("Applying relocs for %s\n", m->name);

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
			die("%08x %06x "
                               "(symbol type %d not supported)\n",
				rel[i].r_offset, syminfo, symtype);
		}
	}

	return 0;
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
				dprintf("[%2d] %08x %08x\n", i,
					dyn[i].d_tag,
					dyn[i].d_un.d_val);
			}
		}
	}
}

static const Elf32_Phdr* ld_find_dynamic_phdr(Elf32_Phdr *phdr, unsigned int phnum)
{
	const Elf32_Phdr *dynamic = NULL;
	int i;

	if (phdr == NULL || phnum == 0)
	{
		dprintf("no program header?\n");
		return NULL;
	}

	/* find the dynamic section */
	for (i = 0; i < phnum; i++)
		if (phdr[i].p_type == PT_DYNAMIC)
			dynamic = &phdr[i];

	return dynamic;
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

	ld_setup_gs();

	/* read the loader's dynamic section */
	loader_module.name = "ld.so";

	/* FIXME: assumes target load address is zero */
	loader_module.delta = (int) ld_base;

	dynamic = ld_find_dynamic_phdr((void*) (loader_module.delta + ehdr->e_phoff),
					ehdr->e_phnum);
	if (!dynamic)
	{
		dprintf("loader has no dynamic program header\n");
		goto error;
	}
	ld_read_dynamic_section(&loader_module, dynamic->p_vaddr);

	/* read the main exe's dynamic sectin */
	dynamic = ld_find_dynamic_phdr(phdr, phnum);
	if (!dynamic)
	{
		dprintf("target has no dynamic program header\n");
		goto error;
	}

	main_module.name = "exe";

	ld_read_dynamic_section(&main_module, dynamic->p_vaddr);

	dprintf("patching GOT\n");

	patch_got(&main_module);
	dprintf("done returning to %p\n", entry);

	ld_apply_loader_relocations(&loader_module);

	ld_apply_relocations(&main_module);

	environ = env;

	return entry;
error:
	return 0;
}
