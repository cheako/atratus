
/* http://www.skyfree.org/linux/references/ELF_Format.pdf */

typedef unsigned short Elf32Half;
typedef unsigned int Elf32Off;
typedef unsigned int Elf32Word;
typedef unsigned int Elf32Addr;

#if 0
#define EINIDENT 16
typedef struct {
	unsigned char e_ident[EINIDENT];
	Elf32Half e_type;
	Elf32Half e_machine;
	Elf32Word e_version;
	Elf32Addr e_entry;
	Elf32Off e_phoff;
	Elf32Off e_shoff;
	Elf32Word e_flags;
	Elf32Half e_ehsize;
	Elf32Half e_phentsize;
	Elf32Half e_phnum;
	Elf32Half e_shentsize;
	Elf32Half e_shnum;
	Elf32Half e_shstrndx;
} Elf32Ehdr;

typedef struct{
	Elf32Word p_type;
	Elf32Off p_offset;
	Elf32Addr p_vaddr;
	Elf32Addr p_paddr;
	Elf32Word p_filesz;
	Elf32Word p_memsz;
	Elf32Word p_flags;
	Elf32Word p_align;
} Elf32Phdr;

typedef struct{
	Elf32Word shname;
	Elf32Word shtype;
	Elf32Word shflags;
	Elf32Addr shaddr;
	Elf32Off shoffset;
	Elf32Word shsize;
	Elf32Word shlink;
	Elf32Word shinfo;
	Elf32Word shaddralign;
	Elf32Word shentsize;
} Elf32Shdr;

typedef struct{
	Elf32Word stname;
	Elf32Addr stvalue;
	Elf32Word stsize;
	unsigned char stinfo;
	unsigned char stother;
	Elf32Half stshndx;
} Elf32Sym;
#endif

typedef struct {
	Elf32Word a_type;
	Elf32Word a_value;
} Elf32Aux;

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

#if 0
#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_SHLIB 5
#define PT_PHDR 6
#define PT_TLS 7
#define	PT_NUM 8
#define PT_LOOS 0x60000000
#define PT_GNU_EH_FRAME	0x6474e550
#define PT_GNU_STACK 0x6474e551
#define PT_GNU_RELRO 0x6474e552
#define PT_LOSUNW 0x6ffffffa
#define PT_SUNWBSS 0x6ffffffa
#define PT_SUNWSTACK 0x6ffffffb
#define PT_HISUNW 0x6fffffff
#define PT_HIOS 0x6fffffff
#define PT_LOPROC 0x70000000
#define PT_HIPROC 0x7fffffff
#endif

