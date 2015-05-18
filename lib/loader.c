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

#define NULL ((void *)0)

/*
 * errno should be per thread,
 * leave as global until we can load an ELF binary
 */
static int errno;
static int verbose = 0;
static struct module_info loader_module;
static struct module_info main_module;
static char **ld_environment;

#define EXPORT __attribute__((visibility("default")))

static inline int set_errno(int r)
{
	if ((r & 0xfffff000) == 0xfffff000)
	{
		errno = -r;
		r = -1;
	}
	return r;
}

EXPORT void exit(int status)
{
	while (1)
	{
		__asm__ __volatile__ (
			"\tpushl %%ebx\n"
			"\tmov $1, %%eax\n"
			"\tint $0x80\n"
			"\tpopl %%ebx\n"
		:: "a"(status) : "memory");
	}
}

EXPORT int ioctl(int fd, int request, int value)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmovl $54, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd), "c"(request), "d"(value) : "memory");
	return set_errno(r);
}

EXPORT int read(int fd, void *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmovl $3, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd), "c"(buffer), "d"(length) : "memory");
	return set_errno(r);
}

int dl_write(int fd, const void *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $4, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd), "c"(buffer), "d"(length) : "memory");

	return set_errno(r);
}

EXPORT int write(int fd, const void *buffer, size_t length)
{
	return dl_write(fd, buffer, length);
}

EXPORT int open(const char *filename, int flags)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $5, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(filename), "c"(flags) : "memory");

	return set_errno(r);
}

EXPORT int close(int fd)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $6, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(fd) : "memory");

	return set_errno(r);
}

EXPORT int getuid(void)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $24, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r):: "memory");

	return set_errno(r);
}

EXPORT int dup2(int oldfd, int newfd)
{
	int r;
	__asm__ __volatile__ (
		"\tpushl %%ebx\n"
		"\tmovl %%eax, %%ebx\n"
		"\tmov $63, %%eax\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
	:"=a"(r): "a"(oldfd), "c"(newfd) : "memory");

	return set_errno(r);
}

EXPORT size_t strlen(const char *x)
{
	size_t n = 0;
	while (x[n])
		n++;
	return n;
}

int dl_strcmp(const char *a, const char *b)
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

EXPORT int strcmp(const char *a, const char *b)
{
	return dl_strcmp(a, b);
}

EXPORT int strncmp(const char *a, const char *b, size_t n)
{
	int i;

	for (i = 0; i < n; i++)
	{
		if (a[i] == b[i])
			continue;
		if (a[i] < b[i])
			return -1;
		else
			return 1;
	}
	return 0;
}

EXPORT int memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *left = s1, *right = s2;
	int r = 0;
	int i;

	for (i = 0; r == 0 && i < n; i++)
		r = left[n] - right[n];

	return r;
}

EXPORT int puts(const char *str)
{
	size_t len = strlen(str);
	if (len != dl_write(1, str, len))
		return EOF;
	dl_write(1, "\n", 1);
	return len;
}

EXPORT int putchar(int c)
{
	char ch = c;

	if (1 != dl_write(1, &ch, 1))
		return EOF;

	return c;
}

EXPORT void abort(void)
{
	/* FIXME: send SIGABRT */
	exit(1);
}

EXPORT int mallopt(int param, int value)
{
	switch (param)
	{
	case -1:
		if (verbose)
			printf("mallopt(M_TRIM_THRESHOLD,%d)\n", value);
		break;
	case -2:
		if (verbose)
			printf("mallopt(M_TOP_PAD,%d)\n", value);
		break;
	case -3:
		if (verbose)
			printf("mallopt(M_MMAP_THRESHOLD,%d)\n", value);
		break;
	default:
		printf("mallopt(%d,%d)\n", param, value);
	}
	return 0;
}

EXPORT void *malloc(size_t sz)
{
	return NULL;
}

EXPORT int *__errno_location(void)
{
	return &errno;
}

EXPORT char *strrchr(const char *s, int c)
{
	int n = strlen(s);

	while (n)
	{
		n--;
		if (s[n] == c)
			return (char*) &s[n];
	}

	return NULL;
}

EXPORT char *strchr(const char *s, int c)
{
	while (*s)
	{
		if (*s == c)
			return (char*) s;
		s++;
	}
	return NULL;
}

EXPORT void *bsearch(const void *key, const void *base,
			size_t nmemb, size_t size,
			int (*compar)(const void *a, const void* b))
{
	const void *p;
	size_t n;
	int r;

	while (1)
	{
		if (nmemb == 0)
			return NULL;

		n = nmemb/2;
		p = (const char*)base + n * size;

		r = compar(key, p);
		if (r == 0)
			return (void*) p;

		if (nmemb == 1)
			return NULL;

		if (r > 0)
		{
			base = p;
			nmemb -= n;
		}
		else
			nmemb = n;
	}
}

EXPORT char *getenv(const char *name)
{
	char **p;
	size_t len = strlen(name);
	for (p = ld_environment;
		*p;
		p++)
	{
		size_t n;
		char *x = strchr(*p, '=');
		if (!x)
			return NULL;

		n = *p - x;
		if (n != len)
			continue;

		if (!memcmp(name, *p, n))
			return *p;
	}

	return NULL;
}

typedef int (*fn_main)(int, char * *, char * *);
typedef void (*fn_init)(void);
typedef void (*fn_fini)(void);
typedef void (*fn_rtld_fini)(void);

EXPORT int __libc_start_main(fn_main pmain,
			int argc, char **ubp_av,
			fn_init pinit, fn_fini pfini,
			fn_rtld_fini prtld_fini,
			void (* stack_end))
{
	if (verbose)
	{
		printf("%s called\n", __FUNCTION__);
		printf("main   %p\n", pmain);
		printf("argc   %d\n", argc);
		printf("ubp_av %p\n", ubp_av);
		printf("init   %p\n", pinit);
		printf("fini   %p\n", pfini);
		printf("stkend %p\n", stack_end);
	}

	pinit();

	if (verbose)
		printf("init() done\n");

	pmain(argc, ubp_av, NULL);
	if (verbose)
		printf("main() done\n");
	exit(0);
}

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

Elf32_Word elf_hash_lookup(struct module_info *m,
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
			return sym->st_value;

		index = chains[index];
		count--;
	}
	if (!count)
	{
		printf("circular chain in ELF32 hash\n");
		exit(1);
	}
	return 0;
}

/* https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections */
Elf32_Word elf_gnu_hash_lookup(struct module_info *m,
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

	Elf32_Word r = 0;
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
				r = sym->st_value;
				break;
			}
		}

		chain++;
		index++;
	}

	if (verbose && !r)
		printf("symbol %s not found in %s\n",
			symbol_name, m->name);

	return r;
}

Elf32_Word module_get_symbol_address(struct module_info *m,
					const char *symbol_name)
{
	Elf32_Word r = 0;

	if (m->dt.gnu_hash)
		r = elf_gnu_hash_lookup(m, symbol_name);
	else if (m->dt.hash)
		r = elf_hash_lookup(m, symbol_name);

	return r;
}

Elf32_Word ld_get_symbol_address(const char *sym)
{
	Elf32_Word r;

	r = module_get_symbol_address(&loader_module, sym);
	if (r)
		return (loader_module.delta + r);

	r = module_get_symbol_address(&main_module, sym);
	if (r)
		return (main_module.delta + r);

	if (verbose)
		printf("no symbol = %s\n", sym);

	return 0;
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

	if (verbose)
	{
		printf("%s arg=%p plt_entry=%08x callee=%p\n",
			__FUNCTION__, arg, entry, callee);
	}

	if (m->dt.pltrel != DT_REL)
		printf("not DT_REL\n");
	rel = (void*) (m->dt.jmprel + entry);

	syminfo = ELF32_R_SYM(rel->r_info);
	symtype = ELF32_R_TYPE(rel->r_info);
	if (symtype != R_386_JMP_SLOT)
		return 0;

	if (verbose)
	{
		printf("dt.symtab = %08x\n", m->dt.symtab);
		printf("syminfo = %08x\n", syminfo);
	}

	st = (Elf32_Sym*) m->dt.symtab;
	st += syminfo;

	if (verbose)
		printf("st_name = %d offset = %08x\n", st->st_name, rel->r_offset);
	symbol_name = (const char*) m->dt.strtab + st->st_name;
	if (verbose)
		printf("symbol_name = %s\n", symbol_name);

	target = ld_get_symbol_address(symbol_name);
	if (!target)
	{
		// FIXME: handle weak symbols
		printf("no such symbol (%s)\n", symbol_name);
		exit(1);
		return 0;
	}

	if (verbose)
		printf("dynamic resolve, symbol -> %s\n", symbol_name);

	r = (void*) target;

	if (verbose)
		printf("dynamic resolve: %08x -> %p\n", entry, r);

	/* patch the correct value into the GOT */
	got_entry = (void**)((char*)m->delta + rel->r_offset);

	/* patch the resolved address into the GOT */
	*got_entry = r;
	if (verbose)
		printf("patched GOT at %p\n", got_entry);

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
	if (verbose)
	{
		printf("PLTGOT:    %08x\n", m->dt.pltgot);
		printf("PLTRELSZ:  %08x\n", m->dt.pltrelsz);
	}

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

	if (verbose)
		printf("%08x %06x R_386_GLOB_DAT\n",
			rel->r_offset, syminfo);

	st = (Elf32_Sym*) m->dt.symtab;
	st += syminfo;

	symbol_name = (const char*) m->dt.strtab + st->st_name;

	p = (uint32_t*)(m->delta + rel[offset].r_offset);

	if (st->st_value && st->st_size)
	{
		/* has a value and size, so is defined */
		value = (uint32_t) (m->delta + st->st_value);

		if (verbose)
			printf("R_386_GLOB_DAT: definition "
				"of %s (in %s) @%p -> %08x\n",
				symbol_name, m->name, p, value);
	}
	else
	{
		if (verbose)
			printf("%s used in %s\n", symbol_name, m->name);
		value = ld_get_symbol_address(symbol_name);

		if (verbose)
			printf("R_386_GLOB_DAT: reference "
				"to %s (in %s) @%p -> %08x\n",
				symbol_name, m->name, p, value);
	}

	*p = (uint32_t) value;
}

int ld_apply_relocations(struct module_info *m)
{
	int i;

	if (verbose)
		printf("Applying relocs for %s\n", m->name);

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
			{
				const char *symbol_name;
				Elf32_Sym *st = (Elf32_Sym*) m->dt.symtab;
				st += syminfo;
				symbol_name = (const char*) (m->delta + m->dt.strtab + st->st_name);

				printf("R_386_COPY %s (not applied)\n", symbol_name);
			}
			break;
		default:
			/* FIXME */
			printf("%08x %06x %d (not applied)\n", rel[i].r_offset,
				syminfo, symtype);
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
				printf("[%2d] %08x %08x\n", i,
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
		printf("no program header?\n");
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

	ld_environment = env;

	/* read the loader's dynamic section */
	loader_module.name = "ld.so";

	/* FIXME: assumes target load address is zero */
	loader_module.delta = (int) ld_base;

	dynamic = ld_find_dynamic_phdr((void*) (loader_module.delta + ehdr->e_phoff),
					ehdr->e_phnum);
	if (!dynamic)
	{
		printf("loader has no dynamic program header\n");
		goto error;
	}
	ld_read_dynamic_section(&loader_module, dynamic->p_vaddr);

	/* read the main exe's dynamic sectin */
	dynamic = ld_find_dynamic_phdr(phdr, phnum);
	if (!dynamic)
	{
		printf("target has no dynamic program header\n");
		goto error;
	}

	main_module.name = "exe";

	ld_read_dynamic_section(&main_module, dynamic->p_vaddr);

	if (verbose)
		printf("patching GOT\n");

	patch_got(&main_module);
	if (verbose)
		printf("done returning to %p\n", entry);

	ld_apply_relocations(&main_module);

	return entry;
error:
	return 0;
}
