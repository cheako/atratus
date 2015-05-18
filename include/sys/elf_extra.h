#ifndef __ELF_EXTRA_H__
#define __ELF_EXTRA_H__

/* extra definitions, missing from FreeBSD elf_common.h */

#define DT_HIOS		0x6ffff000
#define DT_LOPROC	0x70000000
#define DT_HIPROC	0x7fffffff
#define DT_VALRNGLO	0x6ffffd00
#define DT_GNU_PRELINKED 0x6ffffdf5
#define DT_GNU_CONFLICTSZ 0x6ffffdf6
#define DT_GNU_LIBLISTSZ 0x6ffffdf7
#define DT_CHECKSUM	0x6ffffdf8
#define DT_PLTPADSZ	0x6ffffdf9
#define DT_MOVEENT	0x6ffffdfa
#define DT_MOVESZ	0x6ffffdfb
#define DT_FEATURE_1	0x6ffffdfc
#define DT_POSFLAG_1	0x6ffffdfd
#define DT_SYMINSZ	0x6ffffdfe
#define DT_SYMINENT	0x6ffffdff
#define DT_VALRNGHI	0x6ffffdff
#define DT_ADDRRNGLO	0x6ffffe00
#define DT_GNU_HASH	0x6ffffef5
#define DT_TLSDESC_PLT	0x6ffffef6
#define DT_TLSDESC_GOT	0x6ffffef7
#define DT_GNU_CONFLICT	0x6ffffef8
#define DT_GNU_LIBLIST	0x6ffffef9
#define DT_CONFIG	0x6ffffefa
#define DT_DEPAUDIT	0x6ffffefb
#define DT_AUDIT	0x6ffffefc
#define	DT_PLTPAD	0x6ffffefd
#define	DT_MOVETAB	0x6ffffefe
#define DT_SYMINFO	0x6ffffeff

#define DT_VERSYM	0x6ffffff0
#define DT_RELACOUNT	0x6ffffff9
#define DT_RELCOUNT	0x6ffffffa
#define DT_FLAGS_1	0x6ffffffb
#define	DT_VERDEF	0x6ffffffc
#define	DT_VERDEFNUM	0x6ffffffd
#define	DT_VERNEED	0x6ffffffe
#define	DT_VERNEEDNUM	0x6fffffff

typedef struct {
	Elf32_Word a_type;
	Elf32_Word a_value;
} Elf32_Aux;

#define AT_NULL 0
#define AT_IGNORE 1
#define AT_EXECFD 2
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_FLAGS 8
#define AT_ENTRY 9
#define AT_NOTELF 10
#define AT_UID 11
#define AT_EUID 12
#define AT_GID 13
#define AT_EGID 14
#define AT_PLATFORM 15
#define AT_HWCAP 16
#define AT_CLKTCK 17
#define AT_SECURE 23
#define AT_BASE_PLATFORM 24
#define AT_RANDOM 25
#define AT_EXECFN 31
#define AT_SYSINFO 32
#define AT_SYSINFO_EHDR 33

#endif /* __ELF_EXTRA_H__ */
