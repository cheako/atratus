/*
 * atratus - Linux binary emulation for Windows
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
#include "filp.h"
#include "tty.h"
#include "pipe.h"

#include "sys/elf32.h"
#include "elf-av.h"

#include "process.h"

/* _l_ prefix is for Linux kernel ABI stuff */
#define _l_MAP_FAILED ((void*)-1)

#define _l_MAP_SHARED       1
#define _l_MAP_PRIVATE      2
#define _l_MAP_FIXED     0x10
#define _l_MAP_ANONYMOUS 0x20

#define _l_PROT_READ  1
#define _l_PROT_WRITE 2
#define _l_PROT_EXEC  4
#define _l_PROT_NONE  0

#define _l_O_RDONLY 0
#define _l_O_WRONLY 1
#define _l_O_RDWR 2
#define _l_O_CREAT 0x100

#define _l_WNOHANG (1)

#define _l_SIGCHLD (17)

struct _l_pollfd {
	int fd;
	short events;
	short revents;
};

struct _l_new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

struct process *current = NULL;
struct process *first_process;
static LPVOID wait_fiber;
static HANDLE loop_event;

static WCHAR stub_exe_name[MAX_PATH];

static const int pagesize = 0x1000;
static const int pagemask = 0x0fff;

/* non-standard stuff */
#define MIN(A, B) (((A) < (B)) ? (A) : (B))
#define MAX(A, B) (((A) > (B)) ? (A) : (B))

#define DEFAULT_STACKSIZE 0x100000

int nt_process_memcpy_from(void *local_addr, const void *client_addr, size_t size)
{
	NTSTATUS r;
	ULONG bytesRead = 0;

	r = NtReadVirtualMemory(current->process, client_addr,
				 local_addr, size, &bytesRead);
	if (r != STATUS_SUCCESS)
		return -_L(EFAULT);
	return bytesRead;
}

int nt_process_memcpy_to(void *client_addr, const void *local_addr, size_t size)
{
	NTSTATUS r;
	ULONG bytesWritten = 0;

	r = NtWriteVirtualMemory(current->process, client_addr,
				 local_addr, size, &bytesWritten);
	if (r != STATUS_SUCCESS)
		return -_L(EFAULT);
	return bytesWritten;
}

struct process_ops nt_process_ops =
{
	.memcpy_from = &nt_process_memcpy_from,
	.memcpy_to = &nt_process_memcpy_to,
};

struct process *context_from_client_id(CLIENT_ID *id)
{
	struct process *process;

	process = first_process;
	while (process)
	{
		if (process->id.UniqueThread == id->UniqueThread &&
		    process->id.UniqueProcess == id->UniqueProcess)
			return process;
		process = process->next_process;
	}
	return NULL;
}

extern void KiUserApcDispatcher(void);

int verbose = 0;

int dprintf(const char *fmt, ...) __attribute__((format(printf,1,2)));

int dprintf(const char *fmt, ...)
{
	va_list va;
	int n;
	if (!verbose)
		return 0;
	va_start(va, fmt);
	n = vprintf(fmt, va);
	va_end(va);
	return n;
}

const char *ntstatus_to_string(NTSTATUS r)
{
	switch (r)
	{
#define S(x) case x: return #x;
	S(STATUS_UNSUCCESSFUL)
	S(STATUS_NOT_IMPLEMENTED)
	S(STATUS_INVALID_INFO_CLASS)
	S(STATUS_INFO_LENGTH_MISMATCH)
	S(STATUS_ACCESS_VIOLATION)
	S(STATUS_INVALID_HANDLE)
	S(STATUS_INVALID_CID)
	S(STATUS_INVALID_PARAMETER)
	S(STATUS_NO_SUCH_FILE)
	S(STATUS_NO_MEMORY)
	S(STATUS_CONFLICTING_ADDRESSES)
	S(STATUS_UNABLE_TO_FREE_VM)
	S(STATUS_INVALID_SYSTEM_SERVICE)
	S(STATUS_ILLEGAL_INSTRUCTION)
	S(STATUS_INVALID_FILE_FOR_SECTION)
	S(STATUS_ACCESS_DENIED)
	S(STATUS_BUFFER_TOO_SMALL)
	S(STATUS_OBJECT_TYPE_MISMATCH)
	S(STATUS_NOT_COMMITTED)
#undef S
	default:
		return "unknown";
	}
}

/* mingw32's ntdll doesn't have these functions */
#define DECLARE(x) typeof(x) *p##x;
DECLARE(NtCreateWaitablePort)
DECLARE(DbgUiGetThreadDebugObject)
DECLARE(DbgUiConnectToDbg);
DECLARE(DbgUiWaitStateChange)
DECLARE(DbgUiContinue)
DECLARE(NtUnmapViewOfSection)
DECLARE(KiUserApcDispatcher)
#undef DECLARE

static BOOL dynamic_resolve(void)
{
	HMODULE ntdll;

	ntdll = GetModuleHandle("ntdll");
	if (ntdll)
	{
#define RESOLVE(name) \
		p##name = (void*) GetProcAddress(ntdll, #name); \
		if (!p##name) { \
			fprintf(stderr, "No %s\n", #name); \
			return FALSE; \
		}

		RESOLVE(NtCreateWaitablePort)
		RESOLVE(DbgUiGetThreadDebugObject)
		RESOLVE(DbgUiConnectToDbg)
		RESOLVE(DbgUiWaitStateChange)
		RESOLVE(DbgUiContinue)
		RESOLVE(NtUnmapViewOfSection)
		RESOLVE(KiUserApcDispatcher)
#undef RESOLVE
	}
	else
	{
		fprintf(stderr, "No ntdll\n");
		return FALSE;
	}

	return TRUE;
}

/* TODO: don't forward declare, move this to a separate file... */
struct module_info
{
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

int load_module(struct module_info *m, const char *path);
int map_elf_object(struct module_info *m, int fd);
void* sys_mmap(void *addr, ULONG len, int prot,
		int flags, int fd, off_t offset);
int sys_close(int fd);
NTSTATUS GetClientId(HANDLE thread, CLIENT_ID *id);
void dump_string_list(char **list);
void unlink_process(struct process *process);
void __stdcall SyscallHandler(PVOID param);

static char printable(char x)
{
	if (x >= 0x20 && x < 0x7f)
		return x;
	return '.';
}

static void dump_line(void *p, unsigned int len)
{
	unsigned char *x = (unsigned char*) p;
	unsigned int i;
	char line[0x11];

	for (i = 0; i < 16; i++)
	{
		if (i < len)
		{
			line[i] = printable(x[i]);
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

static void dump_user_mem(struct process *context,
			void *p, unsigned int len)
{
	unsigned char *x = (unsigned char*) p;
	unsigned char buffer[0x10];
	int extra;

	/* start on a 16 byte boundary */
	extra = ((int)x) & (16 - 1);
	x -= extra;
	len += extra;

	while (len)
	{
		ULONG sz = MIN(len, 16);
		ULONG bytesRead = 0;
		NTSTATUS r;

		printf("%p  ", x);
		r = NtReadVirtualMemory(context->process, x, buffer,
					sz, &bytesRead);
		if (r != STATUS_SUCCESS)
		{
			printf("<invalid>\n");
			break;
		}
		dump_line(buffer, bytesRead);
		if (bytesRead != sz)
			break;
		len -= sz;
		x += sz;
	}
}

void mem_state_to_string(DWORD State, char *string)
{
	switch (State)
	{
	case MEM_COMMIT:
		strcpy(string, "commit");
		break;
	case MEM_RESERVE:
		strcpy(string, "reserve");
		break;
	default:
		sprintf(string, "%08x", State);
	}
}

void mem_protect_to_string(DWORD Protect, char *string)
{
	switch (Protect)
	{
	case PAGE_NOACCESS:
		strcpy(string, "---");
		break;
	case PAGE_READONLY:
		strcpy(string, "r--");
		break;
	case PAGE_READWRITE:
		strcpy(string, "rw-");
		break;
	case PAGE_EXECUTE_READWRITE:
		strcpy(string, "rwx");
		break;
	case PAGE_EXECUTE_READ:
		strcpy(string, "r-x");
		break;
	case 0:
		string[0] = 0;
		break;
	default:
		sprintf(string, "%08x", Protect);
	}
}

void dump_address_space(void)
{
	PVOID Address = 0;
	NTSTATUS r;
	char state[10];
	char protect[10];

	printf("Address space details:\n");
	printf("%-17s %-8s %-8s %-8s %-8s %-8s\n",
		"Address range", "Base", "Protect",
		"State", "Protect", "Type");

	while (1)
	{
		MEMORY_BASIC_INFORMATION info;
		ULONG sz = 0;

		r = NtQueryVirtualMemory(current->process, Address,
					MemoryBasicInformation,
					&info, sizeof info, &sz);
		if (r != STATUS_SUCCESS)
			break;

		if (!info.RegionSize)
			break;

		Address = (BYTE*)Address + info.RegionSize;

		if (info.State == MEM_FREE)
			continue;

		mem_state_to_string(info.State, state);
		mem_protect_to_string(info.Protect, protect);

		printf("%08x-%08x %08x %08x %8s %8s %08x\n",
			info.BaseAddress,
			(char*)info.BaseAddress + info.RegionSize,
			info.AllocationBase, info.AllocationProtect,
			state, protect, info.Type);
	}
}

int strv_count(char **str)
{
	int n = 0;
	while (str[n])
		n++;
	return n;
}

int strv_length(char **str)
{
	int n = 0, length = 0;
	while (str[n])
		length += strlen(str[n++]) + 1;
	return length;
}

int auxv_count(Elf32Aux *aux)
{
	int n = 0;
	while (aux[n].a_type)
		n++;
	return n;
}

static inline unsigned long round_down(unsigned long val, unsigned long rounding)
{
	return val & ~(rounding - 1);
}

static inline unsigned long round_up(unsigned long val, unsigned long rounding)
{
	return (val + rounding - 1) & ~(rounding - 1);
}

void* get_process_peb(HANDLE process)
{
	PROCESS_BASIC_INFORMATION info;
	NTSTATUS r;
	ULONG sz;

	memset(&info, 0, sizeof info);
	r = NtQueryInformationProcess(process, ProcessBasicInformation,
				 &info, sizeof info, &sz);
	if (r == STATUS_SUCCESS)
		return info.PebBaseAddress;
	return NULL;
}

ULONG get_process_exit_code(HANDLE process)
{
	PROCESS_BASIC_INFORMATION info;
	NTSTATUS r;
	ULONG sz;

	memset(&info, 0, sizeof info);
	r = NtQueryInformationProcess(process, ProcessBasicInformation,
				 &info, sizeof info, &sz);
	if (r == STATUS_SUCCESS)
		return info.ExitStatus;
	return ~0;
}

ULONG get_thread_exit_code(HANDLE thread)
{
	THREAD_BASIC_INFORMATION info;
	NTSTATUS r;
	ULONG sz;

	r = NtQueryInformationThread(thread, ThreadBasicInformation,
				 &info, sizeof info, &sz);
	if (r == STATUS_SUCCESS)
		return info.ExitStatus;
	return ~0;
}

void dump_regs(struct process *context)
{
	printf("EAX:%08lx EBX:%08lx ECX:%08lx EDX:%08lx\n",
		context->regs.Eax, context->regs.Ebx, context->regs.Ecx, context->regs.Edx);
	printf("ESI:%08lx EDI:%08lx EBP:%08lx ESP:%08lx\n",
		context->regs.Esi, context->regs.Edi, context->regs.Ebp, context->regs.Esp);
	printf("EIP:%08lx EFLAGS: %08lx\n", context->regs.Eip,
		context->regs.EFlags);
	printf("CS:%04lx DS:%04lx ES:%04lx SS:%04lx GS:%04lx FS:%04lx\n",
		context->regs.SegCs, context->regs.SegDs, context->regs.SegEs,
		context->regs.SegSs, context->regs.SegGs, context->regs.SegFs);
}

/*
 * The purpose of patching NTDLL is to:
 *  - avoid pollution of the address space with NTDLL's requirements
 *  - avoid useless NTDLL setup (don't want to use NT services)
 *  - make the startup a little cleaner
 *
 * KiUserApcDispatcher looks like this:
 * bytes: e9 07 9f 73 8b ff d0 6a 01 57 e8 ...
 * .text:7C90E450 lea     edi, [esp+arg_C]
 * .text:7C90E454 pop     eax
 * .text:7C90E455 call    eax  <--- overwrite here
 * .text:7C90E457 push    1
 * .text:7C90E459 push    edi
 * .text:7C90E45A call    ZwContinue
 */
static NTSTATUS patch_apc_callback(struct process *context)
{
	HANDLE process = context->process;
	uint8_t nops[2] = { 0x90, 0x90 };
	ULONG sz = 0;
	NTSTATUS r;
	ULONG old_prot = 0;
	void *addr;
	void *p = (void*) ((char*)pKiUserApcDispatcher) + 5;

	/* TODO: read assembly and make sure we're clobbering the right code */

	/* make ntdll writeable */
	sz = sizeof nops;
	addr = p;
	r = NtProtectVirtualMemory(process, &addr, &sz,
				PAGE_READWRITE, &old_prot);
	if (r != STATUS_SUCCESS)
	{
		printf("failed to make writeable\n");
		return r;
	}

	/* patch */
	r = NtWriteVirtualMemory(process, p, nops, sizeof nops, &sz);
	if (r != STATUS_SUCCESS)
	{
		printf("failed to write memory\n");
		return r;
	}

	/* restore original protection */
	sz = 1;
	addr = p;
	r = NtProtectVirtualMemory(process, &addr, &sz,
				old_prot, &old_prot);
	if (r != STATUS_SUCCESS)
	{
		printf("failed to restore protection\n");
		return r;
	}

	dprintf("Patched KiUserApcDispatcher @%p\n", pKiUserApcDispatcher);

	return r;
}

NTSTATUS alloc_vdso(struct process *context, void **vdso)
{
	NTSTATUS r;
	void *addr = NULL;
	ULONG sz = 0x1000;
	uint8_t code[] = {0xcd, 0x80, 0xc3};
	ULONG old_prot;

	/* allocate one page */
	r = NtAllocateVirtualMemory(context->process, &addr, 0, &sz,
				MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if (r != STATUS_SUCCESS)
		return r;
	*vdso = addr;

	/*
	 * write int80 instruction to it
	 * FIXME:
	 *  - VDSO is in ELF format, so needs an ELF header
	 *  - place high in memory
	 */
	r = NtWriteVirtualMemory(context->process, addr,
				 code, sizeof code, &sz);

	/* make it read-only */
	sz = 0x1000;
	r = NtProtectVirtualMemory(context->process, &addr, &sz,
				PAGE_EXECUTE_READ, &old_prot);
	if (r != STATUS_SUCCESS)
		return r;

	dprintf("VDSO constructed at %p\n", *vdso);

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
NTSTATUS setup_stack(struct process *context,
		void *stack, size_t stack_size,
		char **argv, char **env,
		struct module_info *m,
		struct module_info *interp)
{
	Elf32Aux aux[30];
	int n = 0;
	int i;
	char *p;
	void **init_stack;
	int pointer_space;
	int string_space;
	int offset;
	BYTE *addr;
	ULONG sz;
	NTSTATUS r;
	void *vdso = NULL;
	void *entry_point;

	r = alloc_vdso(context, &vdso);
	if (r != STATUS_SUCCESS)
		return r;

	entry_point = (void*) m->base - m->min_vaddr + m->ehdr.e_entry;

	memset(&aux, 0, sizeof aux);
	aux[n].a_type = AT_PHDR;
	aux[n++].a_value = (int)&((BYTE*)m->base)[m->ehdr.e_phoff];
	aux[n].a_type = AT_PHENT;
	aux[n++].a_value = sizeof (Elf32_Phdr);
	aux[n].a_type = AT_PHNUM;
	aux[n++].a_value = m->ehdr.e_phnum;
	aux[n].a_type = AT_BASE;	/* interpreter (libc) address */
	aux[n++].a_value = (int) interp->base;
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
		return STATUS_NO_MEMORY;
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
	r = NtWriteVirtualMemory(context->process, addr,
				 p, sz, &sz);

	free(p);
	if (r != STATUS_SUCCESS)
	{
		printf("NtWriteVirtualMemory failed (r=%08lx %s)\n",
			r, ntstatus_to_string(r));
		return r;
	}

	context->regs.Esp = (ULONG) addr;

	return STATUS_SUCCESS;
}

struct process *alloc_process(void)
{
	struct process *context;
	context = malloc(sizeof *context);
	memset(context, 0, sizeof *context);

	/* init */
	context->ops = &nt_process_ops;
	context->process = INVALID_HANDLE_VALUE;
	context->thread = INVALID_HANDLE_VALUE;
	context->state = thread_running;

	/* insert at head of list */
	context->next_process = first_process;
	first_process = context;

	return context;
}

NTSTATUS create_nt_process(struct process *context,
			 HANDLE debugObject)
{
	HANDLE file = NULL, section = NULL;
	NTSTATUS r;
	OBJECT_ATTRIBUTES oa;
	VOID *peb;

	file = CreateFileW(stub_exe_name,
			GENERIC_READ | FILE_EXECUTE | SYNCHRONIZE,
			FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
			OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		r = STATUS_UNSUCCESSFUL;
		fprintf(stderr, "CreateFile() failed (r=%d)\n", GetLastError());
		goto end;
	}

	/* create a section for the executable */
	memset(&oa, 0, sizeof oa);
	oa.Length = sizeof oa;
	oa.RootDirectory = NULL;
	oa.ObjectName = NULL;
	oa.Attributes = OBJ_CASE_INSENSITIVE;

	section = NULL;
	r = NtCreateSection(&section, SECTION_ALL_ACCESS, &oa, 0,
				 PAGE_EXECUTE, SEC_IMAGE, file);
	if (r != STATUS_SUCCESS)
		goto end;

	memset(&oa, 0, sizeof oa);
	oa.Length = sizeof oa;
	oa.RootDirectory = NULL;
	oa.Attributes = OBJ_CASE_INSENSITIVE;

	context->process = NULL;
	r = NtCreateProcess(&context->process, PROCESS_ALL_ACCESS, &oa,
			NtCurrentProcess(), FALSE, section, debugObject, NULL);
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "NtCreateProcess failed %08lx (%s)\n",
			r, ntstatus_to_string(r));
		goto end;
	}

	peb = get_process_peb(context->process);

	/* setup the thread context */
	context->regs.ContextFlags = CONTEXT_FULL;
	r = NtGetContextThread(NtCurrentThread(), &context->regs);
	if (r != STATUS_SUCCESS)
		return r;

	/*
	 * Patch KiUserApcDispatch to not enter ntdll
	 * We don't want or need the stuff that ntdll does
	 * Jump directly to the program entry point
	 */
	r = patch_apc_callback(context);
	if (r != STATUS_SUCCESS)
		goto end;

end:
	NtClose(section);
	NtClose(file);

	return r;
}

void purge_address_space(void)
{
	PVOID Address = 0;
	NTSTATUS r;

	while (1)
	{
		MEMORY_BASIC_INFORMATION info;
		ULONG sz = 0;

		r = NtQueryVirtualMemory(current->process, Address,
					MemoryBasicInformation,
					&info, sizeof info, &sz);
		if (r != STATUS_SUCCESS)
			break;

		if (!info.RegionSize)
			break;

		Address = (BYTE*)Address + info.RegionSize;

		if (info.State == MEM_FREE)
			continue;

		if (info.Type == MEM_IMAGE)
			continue;

		sz = 0;
		r = NtFreeVirtualMemory(current->process,
				&info.BaseAddress, &sz,
				MEM_RELEASE);
		if (r != STATUS_SUCCESS)
		{
			// this will happen for the TEB, PEB
			// NT shared memory block, etc.
			dprintf("failed to free %p %08lx r=%08lx\n",
				info.BaseAddress, info.RegionSize, r);
		}
	}
}

int do_exec(const char *filename, char **argv, char **envp)
{
	struct module_info exe = {0};
	struct module_info interp = {0};
	int exe_fd = -1, interp_fd = -1, r;

	dprintf("exec %s\n", filename);
	dprintf("argv:\n");
	dump_string_list(argv);
	dprintf("envp:\n");
	dump_string_list(envp);

	/* load the elf object */
	exe_fd = load_module(&exe, filename);
	if (exe_fd < 0)
	{
		dprintf("load_module(%s) failed (r=%d)\n",
			filename, exe_fd);
		r = exe_fd;
		goto end;
	}

	/*
	 * load interpreter (in case of dynamically linked object)
	 */
	if (exe.interpreter[0])
	{
		interp_fd = load_module(&interp, exe.interpreter);
		if (interp_fd < 0)
		{
			dprintf("load_module(%s) failed (r=%d)\n",
				exe.interpreter, interp_fd);
			r = interp_fd;
			goto end;
		}
	}

	/*
	 * exec: point of no return
	 *
	 * Clean address space
	 */
	purge_address_space();

	r = map_elf_object(&exe, exe_fd);
	if (r < 0)
	{
		dprintf("failed to map executable\n");
		goto end;
	}

	if (interp_fd >= 0)
	{
		r = map_elf_object(&interp, interp_fd);
		if (r < 0)
		{
			dprintf("failed to map interpreter\n");
			goto end;
		}
	}

	/*
	 * allocate the stack
	 * Linux processes get just one page initially, it seems
	 */
	memset(&current->stack_info, 0, sizeof current->stack_info);

	/*
	 * TODO: implement and use MAP_GROWSDOWN here
	 *       and avoid using a fixed address (and size...)
	 */
	PVOID p = NULL;
	ULONG sz = 0x100000;
	p = (void*) 0x5ff00000;

	p = sys_mmap(p, sz, _l_PROT_READ | _l_PROT_WRITE | _l_PROT_EXEC,
		 _l_MAP_FIXED|_l_MAP_PRIVATE|_l_MAP_ANONYMOUS, -1, 0);
	if (p == _l_MAP_FAILED)
	{
		r = -(int)p;
		dprintf("map failed (r=%d)\n", r);
		goto end;
	}

	current->stack_info.StackBase = (void*) ((char*)p + sz);
	current->stack_info.StackLimit = (void*) p;

	/* copy startup information to the stack */
	r = setup_stack(current, p, sz, argv, envp, &exe, &interp);
	if (r != STATUS_SUCCESS)
	{
		r = -_L(EPERM);
		goto end;
	}

	/*
	 * libc makes assumptions about registers being zeroed
	 * ebx should be delta from load address to link address
	 */
	if (interp_fd >= 0)
		current->regs.Eip = (ULONG) interp.entry_point;
	else
		current->regs.Eip = (ULONG) exe.entry_point;

	dprintf("Eip = %08lx\n", current->regs.Eip);
	dprintf("Esp = %08lx\n", current->regs.Esp);
end:
	if (exe_fd)
		sys_close(exe_fd);
	if (interp_fd)
		sys_close(interp_fd);
	return r;
}

void dump_handles(void)
{
	dprintf("handles:\n");
	dprintf("process = %p\n", current->process);
	dprintf("thread  = %p\n", current->thread);

	dprintf("ids:\n");
	dprintf("process = %p\n", current->id.UniqueProcess);
	dprintf("thread  = %p\n", current->id.UniqueThread);
}

HANDLE hBreakEvent;

BOOL WINAPI break_handler(DWORD ctrl)
{
	SetEvent(hBreakEvent);
	return TRUE;
}

const char *debug_state_to_string(DBG_STATE state)
{
	switch (state)
	{
#define CASE(x) case x: return #x;
	CASE(DbgIdle)
	CASE(DbgReplyPending)
	CASE(DbgCreateThreadStateChange)
	CASE(DbgCreateProcessStateChange)
	CASE(DbgExitThreadStateChange)
	CASE(DbgExitProcessStateChange)
	CASE(DbgExceptionStateChange)
	CASE(DbgBreakpointStateChange)
	CASE(DbgSingleStepStateChange)
	CASE(DbgLoadDllStateChange)
	CASE(DbgUnloadDllStateChange)
#undef CASE
	default:
		return "DbgUnknownState...?";
	}
}

static NTSTATUS read_process_registers(struct process *context)
{
	NTSTATUS r;

	memset(&context->regs, 0, sizeof context->regs);
	context->regs.ContextFlags = CONTEXT_i386 | CONTEXT_FULL;
	r = NtGetContextThread(context->thread, &context->regs);
	if (r != STATUS_SUCCESS)
		fprintf(stderr, "NtThreadGetContext() failed %08lx\n", r);

	return r;
}

void backtrace(struct process *context)
{
	ULONG frame, stack, x[2], i;
	NTSTATUS r;
	ULONG bytesRead;

	frame = context->regs.Ebp;
	stack = context->regs.Esp;

	r = NtReadVirtualMemory(context->process, (void*) stack,
				 &x[0], sizeof x, &bytesRead);
	if (r != STATUS_SUCCESS)
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

		r = NtReadVirtualMemory(context->process, (void*) frame,
					&x[0], sizeof x, &bytesRead);
		if (r != STATUS_SUCCESS)
		{
			fprintf(stderr, "<invalid>\n");
			break;
		}

		fprintf(stderr, "%08lx\n", x[1]);
		if (!x[1])
			break;

		// next frame
		stack = frame;
		frame = x[0];
	}
}

void dump_exception(EXCEPTION_RECORD *er)
{
	int i;

	printf("Exception:\n");

	printf("Code:    %08lx\n", er->ExceptionCode);
	printf("Flags:   %08lx\n", er->ExceptionFlags);
	printf("Address: %08lx\n", er->ExceptionAddress);
	printf("Params:  %08lx\n", er->NumberParameters);
	for (i = 0; i < er->NumberParameters; i++)
		printf("[%d] -> %08lx\n", i,
			er->ExceptionInformation[i]);
}

void dump_stack(struct process *context)
{
	void *stack = (void*)context->regs.Esp;
	printf("stack @%p\n", stack);
	dump_user_mem(context, stack, 0x100);
}

NTSTATUS dump_tls(struct process *context)
{
	ULONG sz = 0;
	NTSTATUS r;
	THREAD_BASIC_INFORMATION info;

	r = NtQueryInformationThread(context->thread, ThreadBasicInformation,
				 &info, sizeof info, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	dump_user_mem(context, info.TebBaseAddress, 0x100);

	return r;
}

filp* filp_from_fd(int fd)
{
	assert(_L(EBADF) == 9);
	if (fd >= MAX_FDS)
		return NULL;
	if (fd < 0)
		return NULL;
	return current->handles[fd];
}

int alloc_fd(void)
{
	int newfd;

	for (newfd = 0; newfd < MAX_FDS; newfd++)
	{
		if (!current->handles[newfd])
			break;
	}

	if (newfd >= MAX_FDS)
		return -_L(ENOENT);

	return newfd;
}

int sys_fork(void)
{
	HANDLE parent = NULL;
	HANDLE debugObject;
	struct process *context;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS r;

	dprintf("fork()\n");

	/*
	 * NtCreateProcess needs a parent handle with
	 * PROCESS_CREATE_PROCESS to do a fork, otherwise
	 * it will succeed but create a blank address space
	 */
	parent = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE,
				FALSE, (DWORD) current->id.UniqueProcess);
	if (!parent)
	{
		dprintf("OpenProcess failed (r = %08lx)\n", GetLastError());
		return -_L(EPERM);
	}

	context = alloc_process();

	memset(&oa, 0, sizeof oa);
	oa.Length = sizeof oa;
	oa.RootDirectory = NULL;
	oa.Attributes = OBJ_CASE_INSENSITIVE;

	debugObject = pDbgUiGetThreadDebugObject();

	/*
	 * NT kernel supported fork
	 * Which versions of kernel does it work for?
	 */
	r = NtCreateProcess(&context->process, PROCESS_ALL_ACCESS, &oa,
			parent, FALSE, NULL, debugObject, NULL);
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "NtCreateProcess failed %08lx (%s)\n",
			r, ntstatus_to_string(r));
		return -_L(EPERM);
	}

	/* duplicate the stack info */
	context->stack_info = current->stack_info;

	/*
	 * TODO: deal with multiple threads here
	 * Suspend all (other) threads, duplicate them all and unsuspend
	 */

	/* copy fd set */
	memcpy(context->handles, current->handles, sizeof current->handles);

	/* copy the parent thread's context into this one's */
	context->regs = current->regs;

	context->fiber = CreateFiber(0, &SyscallHandler, context);
	if (!context->fiber)
	{
		r = STATUS_UNSUCCESSFUL;
		goto out;
	}

	/* create a thread to run in the process */
	r = NtCreateThread(&context->thread, THREAD_ALL_ACCESS, NULL,
			 context->process, &context->id,
			 &context->regs, &context->stack_info, TRUE);
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "NtCreateThread failed %08lx (%s)\n",
			r, ntstatus_to_string(r));
		goto out;
	}

	/* return the new PID */
	context->regs.Eax = 0;
	r = NtSetContextThread(context->thread, &context->regs);
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "NtSetContextThread() failed: %08lx\n", r);
		goto out;
	}

	/* go */
	r = NtResumeThread(context->thread, NULL);
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "NtResumeThread() failed: %08lx\n", r);
		goto out;
	}

	/* set the process parent */
	context->parent = current;

	/* chain siblings if they exist */
	context->sibling = current->child;
	current->child = context;

	dprintf("fork() good!\n");

	return (ULONG) context->id.UniqueProcess;
out:
	/* TODO: clean up properly on failure */
	return -_L(EPERM);
}

int sys_exit(int exit_code)
{
	dprintf("exit code %d\n", exit_code);
	NtTerminateProcess(current->process, exit_code);
	CloseHandle(current->process);
	/* TODO: close handles, other cleanup */
	current->exit_code = exit_code;
	current->state = thread_terminated;

	process_signal(current->parent, _l_SIGCHLD);

	unlink_process(current);

	return 0;
}

int sys_read(int fd, void *addr, size_t length)
{
	dprintf("read(%d,%p,%d)\n", fd, addr, length);

	filp *fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	return fp->ops->fn_read(fp, addr, length, &fp->offset);
}

int sys_pread64(int fd, void *addr, size_t length, loff_t ofs)
{
	dprintf("pread64(%d,%p,%d,%d)\n", fd, addr, length, (int)ofs);

	filp *fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	return fp->ops->fn_read(fp, addr, length, &ofs);
}

int sys_write(int fd, void *addr, size_t length)
{
	dprintf("write(%d,%p,%d)\n", fd, addr, length);

	filp *fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (!fp->ops->fn_write)
		return -_L(EPERM);

	return fp->ops->fn_write(fp, addr, length, &fp->offset);
}

char rootdir[MAX_PATH + 1];

char *unix2dos_path(const char *unixpath)
{
	char *ret;
	int n, i;

	ret = malloc(strlen(rootdir) + strlen(unixpath) + 2);
	if (ret)
	{
		strcpy(ret, rootdir);
		n = strlen(ret);

		/* append \ if necessary */
		if (n && ret[n - 1] != '\\')
		{
			ret[n++] = '\\';
			ret[n++] = 0;
		}

		/* append unix path, changing / to \ */
		for (i = 0; unixpath[i]; i++)
		{
			if (unixpath[i] == '/')
			{
				if (i != 0)
					ret[n++] = '\\';
			}
			else
				ret[n++] = unixpath[i];
		}
		ret[n] = 0;
	}

	dprintf("%s -> %s\n", unixpath, ret);

	return ret;
}

/*
 * It would be nice if there was a function to do this in one go in Windows
 * Other ways to achieve better performance:
 *  - issue an APC in the windows client (Wine style)
 *  - do this in the NT kernel in a driver
 */
NTSTATUS file_read_to_userland(HANDLE handle, void *buf,
				size_t size, loff_t *ofs)
{
	uint8_t buffer[0x1000];
	NTSTATUS r;
	DWORD bytesRead;
	int bytesCopied = 0;

	while (size)
	{
		LARGE_INTEGER pos;
		LARGE_INTEGER out;
		DWORD sz;

		pos.QuadPart = *ofs;

		r = SetFilePointerEx(handle, pos, &out, FILE_BEGIN);
		if (!r)
			break;

		if (size > sizeof buffer)
			sz = sizeof buffer;
		else
			sz = size;

		bytesRead = 0;
		r = ReadFile(handle, buffer, sz, &bytesRead, NULL);
		if (!r)
		{
			dprintf("ReadFile failed %ld\n", GetLastError());
			return -_L(EIO);
		}

		if (bytesRead == 0)
			break;

		r = NtWriteVirtualMemory(current->process, buf,
					 buffer, bytesRead, &sz);
		if (r != STATUS_SUCCESS)
		{
			if (bytesCopied)
				break;
			return -_L(EFAULT);
		}
		bytesCopied += bytesRead;
		buf = (char*) buf + bytesRead;
		size -= bytesRead;
		(*ofs) += bytesRead;
	}
	return bytesCopied;
}

int file_read(filp *f, void *buf, size_t size, loff_t *off)
{
	return file_read_to_userland(f->handle, buf, size, off);
}

/* read client file handle into "kernel" memory */
int kread(int fd, void *buf, size_t size, off_t off)
{
	LARGE_INTEGER pos;
	LARGE_INTEGER out;
	DWORD bytesRead = 1;
	BOOL r;
	filp *fp;

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	pos.QuadPart = off;

	r = SetFilePointerEx(fp->handle, pos, &out, FILE_BEGIN);
	if (!r)
		return -_L(EIO);

	r = ReadFile(fp->handle, buf, size, &bytesRead, NULL);
	if (!r)
		return -_L(EIO);

	return bytesRead;
}

int file_write(filp *f, const void *buf, size_t size, loff_t *off)
{
	uint8_t buffer[0x1000];
	DWORD bytesCopied = 0;

	while (size)
	{
		ULONG sz = size;
		DWORD bytesWritten;
		ULONG bytesRead = 0;
		NTSTATUS r;

		if (sz > sizeof buffer)
			sz = sizeof buffer;

		r = NtReadVirtualMemory(current->process, buf,
				 buffer, sz, &bytesRead);
		if (r != STATUS_SUCCESS)
			return -_L(EFAULT);

		bytesWritten = 0;
		r = WriteFile(f->handle, buf, bytesRead, &bytesWritten, NULL);
		if (!r)
		{
			fprintf(stderr, "ReadFile %p failed %ld\n",
				f->handle, GetLastError());
			return -_L(EIO);
		}

		/* move along */
		bytesCopied += bytesWritten;
		sz -= bytesWritten;
		buf = (char*) buf + bytesWritten;
		(*off) += bytesWritten;
	}

	return bytesCopied;
}

#define SECSPERDAY 86400
#define SECS_1601_TO_1970 ((369 * 365 + 89) * (ULONGLONG)SECSPERDAY)

int longlong_to_unixtime(ULONGLONG seconds, unsigned int *ns)
{
	if (ns)
		*ns = (seconds%10000000LL)*100LL;
	seconds /= 10000000LL;
	seconds -= SECS_1601_TO_1970;
	return seconds;
}

int file_stat(filp *f, struct stat64 *statbuf)
{
	IO_STATUS_BLOCK iosb;
	FILE_DIRECTORY_INFORMATION info;
	NTSTATUS r;

	r = NtQueryInformationFile(f->handle, &iosb, &info,
				 sizeof info, FileDirectoryInformation);
	if (r != STATUS_SUCCESS)
		return _L(EPERM);

	memset(statbuf, 0, sizeof *statbuf);
	statbuf->st_mode = 0755;

	if (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		statbuf->st_mode |= 040000;
	else
		statbuf->st_mode |= 0100000;
	statbuf->ctime = longlong_to_unixtime(info.ChangeTime.QuadPart,
				&statbuf->ctime_nsec);
	statbuf->mtime = longlong_to_unixtime(info.LastWriteTime.QuadPart,
				&statbuf->mtime_nsec);
	statbuf->atime = longlong_to_unixtime(info.LastAccessTime.QuadPart,
				&statbuf->atime_nsec);
	statbuf->st_size = info.AllocationSize.QuadPart;
	statbuf->st_blksize = 0x1000;

	return 0;
}

int file_getdents(filp *fp, void *de, unsigned int count, fn_add_dirent add_de)
{
	int ofs = 0;
	int r;
	unsigned char *p = (unsigned char*) de;
	NTSTATUS ret;
	IO_STATUS_BLOCK iosb;
	BYTE buffer[0x1000];
	BOOL first = TRUE;
	FILE_DIRECTORY_INFORMATION *info;
	WCHAR star[] = { '*', '.', '*', 0 };
	UNICODE_STRING mask;
	struct linux_dirent *prev_de = NULL;
	ULONG EntryOffset;

	mask.Length = sizeof star/sizeof (WCHAR);
	mask.MaximumLength = 0;
	mask.Buffer = star;

	if (count < sizeof *de)
		return -_L(EINVAL);

	while (1)
	{
		memset(buffer, 0, sizeof buffer);
		ret = NtQueryDirectoryFile(fp->handle, NULL, NULL, NULL, &iosb,
			buffer, sizeof buffer,
			FileDirectoryInformation, first, NULL /*&mask*/, 0);
		dprintf("NtQueryDirectoryFile -> %08lx\n", ret);
		if (ret != STATUS_SUCCESS)
			break;
		first = FALSE;

		EntryOffset = 0;
		do {
			info = (FILE_DIRECTORY_INFORMATION*) &buffer[EntryOffset];

			if (prev_de)
			{
				r = current->ops->memcpy_to(&prev_de->d_off, &ofs, sizeof ofs);
				if (r < 0)
					break;
			}
			de = (struct linux_dirent*)&p[ofs];
			r = add_de(de, info->FileName, info->FileNameLength/2, count - ofs);
			if (r < 0)
				break;
			ofs += r;

			prev_de = de;
			EntryOffset += info->NextEntryOffset;
		} while (info->NextEntryOffset);
	}

	dprintf("%d bytes added\n", ofs);

	return ofs;
}

int add_dirent(void *ptr, WCHAR* entry, USHORT entrylen, int avail)
{
	int name_len = WideCharToMultiByte(CP_UTF8, 0, entry, entrylen, NULL, 0, NULL, NULL);
	struct linux_dirent *de;

	/* add a trailing NUL and round up to multiple of 4 */
	int len = (name_len + sizeof *de + 4) & ~3;

	de = alloca(len);

	if (len > avail)
		return -1;

	de->d_ino = 0;
	de->d_off = 0;
	de->d_reclen = len;
	WideCharToMultiByte(CP_UTF8, 0, entry, entrylen, de->d_name, avail, NULL, NULL);
	de->d_name[name_len] = 0;

	dprintf("adding %s\n", de->d_name);

	return current->ops->memcpy_to(ptr, de, len);
}

int sys_getdents(int fd, struct linux_dirent *de, unsigned int count)
{
	filp *fp;

	dprintf("sys_getdents(%d,%p,%u)\n", fd, de, count);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (!fp->ops->fn_getdents)
		return -_L(ENOTDIR);

	return fp->ops->fn_getdents(fp, de, count, &add_dirent);
}

int add_dirent64(void *ptr, WCHAR* entry, USHORT entrylen, int avail)
{
	int name_len = WideCharToMultiByte(CP_UTF8, 0, entry, entrylen, NULL, 0, NULL, NULL);
	struct linux_dirent64 *de = ptr;

	/* add a trailing NUL and round up to multiple of 4 */
	int len = (name_len + sizeof *de + 4) & ~3;

	if (len > avail)
		return -1;

	de->d_ino = 0;
	de->d_off = 0;
	de->d_type = 0;
	de->d_reclen = len;
	WideCharToMultiByte(CP_UTF8, 0, entry, entrylen, de->d_name, avail, NULL, NULL);
	de->d_name[name_len] = 0;

	dprintf("added %s\n", de->d_name);

	return len;
}

int sys_getdents64(int fd, struct linux_dirent *de, unsigned int count)
{
	filp *fp;

	dprintf("sys_getdents64(%d,%p,%u)\n", fd, de, count);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (!fp->ops->fn_getdents)
		return -_L(ENOTDIR);

	return fp->ops->fn_getdents(fp, de, count, &add_dirent64);
}

static const struct filp_ops disk_file_ops = {
	.fn_read = &file_read,
	.fn_write = &file_write,
	.fn_stat = &file_stat,
	.fn_getdents = &file_getdents,
};

int do_open(const char *file, int flags, int mode)
{
	char *dospath;
	DWORD access;
	DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	DWORD create = 0;
	HANDLE handle;
	filp *fp;
	int fd;

	dprintf("open(\"%s\",%08x,%08x)\n", file, flags, mode);

	switch (flags & 3)
	{
	case _l_O_RDONLY:
		access = GENERIC_READ;
		break;
	case _l_O_WRONLY:
		access = GENERIC_WRITE;
		break;
	case _l_O_RDWR:
		access = GENERIC_READ | GENERIC_WRITE;
		break;
	default:
		fprintf(stderr, "bad open flags %08x\n", flags);
		return -_L(EINVAL);
	}

	if (flags & O_CREAT)
		create = CREATE_NEW;
	else
		create = OPEN_EXISTING;

	dospath = unix2dos_path(file);
	dprintf("CreateFile(%s,%08lx,%08lx,NULL,%08lx,...)\n",
		dospath, access, share, create);

	/* use FILE_FLAG_BACKUP_SEMANTICS for opening directories */
	handle = CreateFile(dospath, access, share, NULL,
			    create,
			    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
			    NULL);

	if (handle == INVALID_HANDLE_VALUE)
	{
		dprintf("failed to open %s (%ld)\n",
			dospath, GetLastError());
		free(dospath);
		return -_L(ENOENT);
	}

	free(dospath);

	fp = malloc(sizeof (*fp));
	if (!fp)
	{
		CloseHandle(handle);
		return -_L(ENOMEM);
	}

	memset(fp, 0, sizeof *fp);
	fp->ops = &disk_file_ops;
	fp->pgid = 0;
	fp->handle = handle;
	fp->offset = 0;

	fd = alloc_fd();
	if (fd < 0)
	{
		free(fp);
		CloseHandle(handle);
		return -_L(ENOMEM);
	}

	dprintf("handle -> %p\n", handle);
	dprintf("fd -> %d\n", fd);

	current->handles[fd] = fp;

	return fd;
}

// TODO: make this efficient... share memory with client?
int read_string(const char *ptr, char **out)
{
	char buffer[0x1000];
	NTSTATUS r;
	ULONG sz;
	size_t i = 0;

	while (1)
	{
		r = NtReadVirtualMemory(current->process, &ptr[i],
					&buffer[i], 1, &sz);
		if (r != STATUS_SUCCESS)
			return -_L(EFAULT);
		if (sz != 1)
			return -_L(EFAULT);
		if (buffer[i] == 0)
			break;
		i++;
		if (i >= sizeof buffer/sizeof buffer[0])
			return -_L(EINVAL);
	}

	*out = strdup(buffer);

	return 0;
}

int read_string_list(char ***out, const char **ptr)
{
	char *strings[100];
	NTSTATUS r;
	ULONG sz;
	size_t n = 0;
	void *p;

	while (1)
	{
		r = NtReadVirtualMemory(current->process, &ptr[n],
					&p, sizeof p, &sz);
		if (r != STATUS_SUCCESS || sz != sizeof p)
		{
			r = -_L(EFAULT);
			goto error;
		}
		if (p)
		{
			r = read_string(p, &strings[n]);
			if (r < 0)
				goto error;
		}
		else
		{
			strings[n] = p;
			break;
		}
		n++;
		r = -_L(EINVAL);
		if (n >= sizeof strings/sizeof strings[0])
			goto error;
	}

	r = -_L(ENOMEM);
	*out = malloc((n + 1) * sizeof strings[0]);
	if (!*out)
		goto error;

	memcpy(*out, strings, (n + 1) * sizeof strings[0]);

	return 0;
error:
	while (n)
		free(strings[--n]);
	return r;
}

void free_string_list(char **list)
{
	unsigned int n;
	if (!list)
		return;
	for (n = 0; list[n]; n++)
		free(list[n]);
	free(list);
}

void dump_string_list(char **list)
{
	unsigned int n;
	if (!list)
		return;
	for (n = 0; list[n]; n++)
		dprintf("[%u] = %s\n", n, list[n]);
}

int sys_open(const char *ptr, int flags, int mode)
{
	int r;
	char *filename = NULL;

	r = read_string(ptr, &filename);
	if (r < 0)
	{
		printf("open(%p=<invalid>,%08x,%08x)\n", ptr, flags, mode);
		return r;
	}

	r = do_open(filename, flags, mode);

	free(filename);

	return r;
}

int sys_close(int fd)
{
	filp *fp;

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (fp->handle)
		CloseHandle(fp->handle);
	current->handles[fd] = 0;

	return 0;
}

int sys_llseek(unsigned int fd, unsigned long offset_high,
	unsigned long offset_low, loff_t *result, unsigned int whence)
{
	filp* fp;
	LARGE_INTEGER pos;
	LARGE_INTEGER out;
	BOOL r;

	printf("llseek(%d,%lu,%lu,%p,%lu)\n", fd,
		offset_high, offset_low, result, whence);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	pos.LowPart = offset_low;
	pos.HighPart = offset_high;

	if (whence > 2)
		return -_L(EINVAL);

	r = SetFilePointerEx(fp->handle, pos, &out, whence);
	if (!r)
		return -_L(EIO);

	*result = out.QuadPart;

	return 0;
}

int sys_time(time_t *tloc)
{
	SYSTEMTIME st;
	FILETIME ft;
	ULONGLONG seconds;
	time_t t;

	dprintf("sys_time(%p)\n", tloc);

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft);
	seconds = (((ULONGLONG)ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
	seconds /= 10000000LL;
	seconds -= SECS_1601_TO_1970;
	t = (time_t)(seconds&0xffffffff);

	if (tloc)
	{
		// TODO: How is an error returned here?
		ULONG sz;
		NtWriteVirtualMemory(current->process, tloc,
					&t, sizeof t, &sz);
	}

	return (seconds&0xffffffff);
}

int sys_exec(const char *fn, const char **ap, const char **ep)
{
	int r;
	char *filename = NULL;
	char **argv = NULL;
	char **envp = NULL;

	r = read_string(fn, &filename);
	if (r < 0)
	{
		printf("exec(%p=<invalid>,%p,%p)\n", fn, ap, ep);
		goto error;
	}

	r = read_string_list(&argv, ap);
	if (r < 0)
	{
		printf("exec(%s,%p=<invalid>,%p)\n", filename, ap, ep);
		goto error;
	}

	r = read_string_list(&envp, ep);
	if (r < 0)
	{
		printf("exec(%s,%p,%p=<invalid>)\n", filename, argv, ep);
		goto error;
	}

	return do_exec(filename, argv, envp);

error:
	free_string_list(argv);
	free_string_list(envp);
	free(filename);
	return r;
}

int sys_getpid(void)
{
	// FIXME: first thread is process ID.
	ULONG pid = (ULONG)current->id.UniqueProcess;
	printf("getpid() -> %04x\n", pid);
	return pid;
}

int sys_kill(int pid, int sig)
{
	dprintf("kill(%d,%d)\n", pid, sig);
	exit(sig);
	return 0;
}

int sys_getcwd(char *buf, unsigned long size)
{
	const char *dir = "/";
	ULONG sz = 0;
	size_t len;
	NTSTATUS r;

	printf("getcwd(%p,%u)\n", buf, size);
	len = strlen(dir);
	if (len > size)
		len = size;
	r = NtWriteVirtualMemory(current->process, buf, dir, len, &sz);
	if (r != STATUS_SUCCESS)
	{
		printf("failed to write memory\n");
		return -_L(EFAULT);
	}

	return len;
}

/*
 * TODO
 *  - return error codes correctly
 *  - mmap vs. nt mapping size differences
 *  - handle state change differences
 *  - deal with MAP_FIXED correctly
 */
void* sys_mmap(void *addr, ULONG len, int prot, int flags, int fd, off_t offset)
{
	NTSTATUS r;
	DWORD AllocationType = 0;
	DWORD Protection;
	PVOID Address;
	MEMORY_BASIC_INFORMATION info;
	ULONG Size = 0;
	ULONG old_prot = 0;

	dprintf("mmap(%p,%08lx,%08x,%08x,%d,%08lx)\n",
		addr, len, prot, flags, fd, offset);

	if (fd != -1)
		return (void*) -_L(EINVAL);

	/* find current state of memory */
	Address = (void*)((int)addr & ~0xffff);
	r = NtQueryVirtualMemory(current->process, Address,
				MemoryBasicInformation,
				&info, sizeof info, &Size);
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "NtQueryVirtualMemory failed r=%08x %s\n",
			r, ntstatus_to_string(r));
		exit(1);
	}

	if (!(flags & _l_MAP_ANONYMOUS))
	{
		fprintf(stderr, "File mapping not supported yet\n");
		exit(1);
	}

	if (info.State == MEM_FREE)
	{
		/* round to 0x10000 */
		AllocationType = MEM_RESERVE | MEM_COMMIT;
		Protection = PAGE_NOACCESS;

		Address = (void*)((int)addr & ~0xffff);
		Size = len;
		Size += ((int)addr - (int)Address);
		Size = (Size + 0xffff) & ~0xffff;

		dprintf("NtAllocateVirtualMemory(%p,%08lx,%08lx,%08lx)\n",
			Address, Size, AllocationType, Protection);

		r = NtAllocateVirtualMemory(current->process, &Address,
					0, &Size, AllocationType, Protection);
		if (r != STATUS_SUCCESS)
		{
			printf("NtAllocateVirtualMemory failed (%08lx) %s\n",
				r, ntstatus_to_string(r));
			return _l_MAP_FAILED;
		}
		dprintf("NtAllocateVirtualMemory -> Address=%p Size=%08lx\n",
			Address, Size);

		/* handle case where no address was specificied */
		if (!addr)
			addr = Address;
	}
	else
	{
		/* clobber the address passed in */
		if (!(flags & _l_MAP_FIXED))
			addr = 0;
	}

	/*
	 * Can only change the protection within an allocated block.
	 * Crossing allocation boundaries will cause a
	 * STATUS_CONFLICTING_ADDRESS error.
	 */

	/* round to 0x1000 */
	Address = (void*)((int)addr & ~0xfff);
	Size = len;
	Size += ((int)addr - (int)Address);
	Size = (Size + 0xfff) & ~0xfff;

	Protection = PAGE_NOACCESS;
	if (prot & _l_PROT_EXEC)
		Protection = PAGE_EXECUTE_READWRITE;
	else if (prot & _l_PROT_WRITE)
		Protection = PAGE_READWRITE;
	else if (prot & _l_PROT_READ)
		Protection = PAGE_READONLY;

	dprintf("NtProtectVirtualMemory(%p,%08lx,%08lx)\n",
		Address, Size, Protection);

	r = NtProtectVirtualMemory(current->process, &Address, &Size,
				Protection, &old_prot);
	if (r != STATUS_SUCCESS)
	{
		printf("NtProtectVirtualMemory failed (%08lx) %s\n",
			r, ntstatus_to_string(r));
		return _l_MAP_FAILED;
	}

	dprintf("NtProtectVirtualMemory -> Address=%p Size=%08lx\n",
		Address, len);

	return addr;
}

int sys_select(int maxfd, void *readfds, void *writefds,
		void *exceptfds, void *tv)
{
	dprintf("select(%d,%p,%p,%p,%p)\n",
		maxfd, readfds, writefds, exceptfds, tv);
	return -_L(ENOSYS);
}

int sys_munmap(void *addr, size_t len)
{
	PVOID Address;
	ULONG Size;
	NTSTATUS r;

	/* round to 0x1000 */
	Address = (void*)((int)addr & ~0xfff);
	Size = len;
	Size += ((int)addr - (int)Address);
	Size = (Size + 0xfff) & ~0xfff;

	r = NtFreeVirtualMemory(current->process, &Address, &Size,
				MEM_DECOMMIT);
	if (r != STATUS_SUCCESS)
		return -1;

	return 0;
}

void* sys_brk(void *addr)
{
	dprintf("brk(%p)\n", addr);
	if (addr)
	{
		unsigned int target = (unsigned int) addr;
		unsigned int origin = (unsigned int) current->brk;
		void *p;

		target = round_up(target, pagesize);
		assert(!(origin&(pagesize - 1)));
		assert(!(target&(pagesize - 1)));
		if (target > origin)
		{
			p = sys_mmap((void*)origin, target - origin,
				_l_PROT_READ | _l_PROT_WRITE | _l_PROT_EXEC,
				_l_MAP_FIXED|_l_MAP_PRIVATE|_l_MAP_ANONYMOUS, -1, 0);
			if (!p)
				dprintf("failed to extend brk\n");
		}
		else if (target < origin)
		{
			fprintf(stderr, "FIXME: reduce brk?\n");
		}
		current->brk = (unsigned int) target;
	}
	return (void*) current->brk;
}

int sys_getuid(void)
{
	dprintf("getuid()\n");
	return current->uid;
}

int sys_geteuid(void)
{
	dprintf("geteuid()\n");
	return current->euid;
}

int sys_set_thread_area(void *ptr)
{
	struct user_desc desc;
	NTSTATUS r;
	ULONG sz = 0;

	dprintf("set_thread_area(%p)\n", ptr);

	r = NtReadVirtualMemory(current->process, ptr, &desc, sizeof desc, &sz);
	if (r != STATUS_SUCCESS)
		return -_L(EFAULT);

	/*
	 * Check we can deal with this thread area
	 */
	if (desc.entry_number != -1)
		return -_L(EINVAL);

	dprintf("base_addr    : %08x\n", desc.base_addr);
	dprintf("entry_number : %02x\n", desc.entry_number);
	dprintf("limit        : %08x\n", desc.limit);
	dprintf("seg_32bit    : %08x\n", desc.seg_32bit);

	if (desc.limit == 0xfff && desc.seg_32bit && desc.useable)
	{
		/*
		 * Special case hack:
		 *
		 * Not possible to allocate a segment descriptor in
		 * Windows user space but %fs is already setup to
		 * point to the Windows thread's TEB
		 * Reuse that...
		 */
		desc.entry_number = current->regs.SegFs >> 3;
	}
	else
	{
		if (current->vtls_entries >= MAX_VTLS_ENTRIES)
		{
			fprintf(stderr, "vtls entries exhausted\n");
			return -_L(EINVAL);
		}
		desc.entry_number = 0x80 + current->vtls_entries;
		memcpy(&current->vtls[current->vtls_entries], &desc, sizeof desc);
		current->vtls_entries++;
	}

	/*
	 * copy it back to userland
	 */
	r = NtWriteVirtualMemory(current->process, ptr,
				 &desc, sizeof desc.entry_number, &sz);
	if (r != STATUS_SUCCESS)
		return -1;

	return 0;
}

int sys_dup(int fd)
{
	filp *fp;
	int newfd;

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	newfd = alloc_fd();
	if (newfd >= 0)
		current->handles[newfd] = fp;

	return newfd;
}

int sys_ioctl(int fd, unsigned int cmd, unsigned long arg)
{
	filp* fp;
	int r;

	dprintf("ioctl(%d,%08x,%lx)\n", fd, cmd, arg);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_l_EBADF;

	if (fp->ops->fn_ioctl)
		return -_l_EINVAL;

	r = fp->ops->fn_ioctl(fp, cmd, arg);

	return r;
}

int sys_pipe(int *ptr)
{
	int fds[2];
	int r;

	dprintf("pipe(%p)\n", ptr);

	r = do_pipe(fds);
	if (r < 0)
		return r;

	r = current->ops->memcpy_to(ptr, fds, sizeof fds);
	if (r < 0)
	{
		sys_close(fds[0]);
		sys_close(fds[1]);
	}

	return r;
}

static struct process *find_zombie(struct process *parent)
{
	struct process *p;

	for (p = parent->child; p; p = p->sibling)
		if (p->state == thread_terminated)
			return p;

	return NULL;
}


static int process_reap_zombie(struct process *p)
{
	int exit_code = p->exit_code;

	process_free(p);

	return exit_code;
}

int sys_waitpid(int pid, int *stat_addr, int options)
{
	struct process *p;
	int r = -_l_ECHILD;
	int exit_code = 0;

	do {
		struct signal_waiter sw;

		p = find_zombie(current);
		if (p)
			break;

		if (options & _l_WNOHANG)
			break;

		sw.we.p = current;

		signal_waiter_add(&sw, _l_SIGCHLD);
		current->state = thread_stopped;
		yield();
		current->state = thread_running;
		signal_waiter_remove(&sw);
	} while (1);

	if (p)
	{
		/* TODO: handle WIFSIGNALED(), etc */
		exit_code = process_reap_zombie(p);
		r = current->ops->memcpy_to(stat_addr, &exit_code,
					 sizeof exit_code);
	}

	return r;
}

int sys_dup2(int oldfd, int newfd)
{
	filp* fp;

	dprintf("dup2(%d,%d)\n", oldfd, newfd);
	fp = filp_from_fd(oldfd);
	if (!fp)
		return -_L(EBADF);

	if (newfd < 0 || newfd > MAX_FDS)
		return -_L(EBADF);

	/* FIXME: dereference former newfd entry */

	current->handles[newfd] = fp;

	return 0;
}

struct poll_fd_list {
	filp *fp;
	poll_list *entry;
};

struct poll_timeout
{
	struct timeout t;
	struct process *p;
	int timed_out;
};

static void poll_timeout_waker(struct timeout *t)
{
	struct poll_timeout *pt = (void*) t;
	struct process *p = current;

	if (GetCurrentFiber() != wait_fiber)
	{
		fprintf(stderr, "bad yield at %d\n", __LINE__);
		exit(1);
	}
	pt->timed_out = 1;
	SwitchToFiber(pt->p->fiber);
	current = p;
}

int sys_nanosleep(struct timeval *in, struct timeval *out)
{
	struct poll_timeout pt;
	struct timeval req;
	int r;

	dprintf("nanosleep(%p,%p)\n", in, out);

	r = current->ops->memcpy_from(&req, in, sizeof req);
	if (r < 0)
		return r;

	pt.t.fn = &poll_timeout_waker;
	pt.p = current;

	timeout_add_tv(&pt.t, &req);
	current->state = thread_stopped;
	yield();
	current->state = thread_running;
	timeout_remove(&pt.t);

	return 0;
}

static int poll_check(filp **fps, struct _l_pollfd *fds, int nfds)
{
	int ready = 0;
	int i;

	for (i = 0; i < nfds; i++)
	{
		if (fps[i])
		{
			fds[i].revents = fps[i]->ops->fn_poll(fps[i]);
			if (fds[i].revents & fds[i].events)
				ready++;
		}
		else
		{
			fds[i].revents = _l_POLLERR;
			ready++;
		}
	}
	return ready;
}

int sys_poll(struct _l_pollfd *ptr, int nfds, int timeout)
{
	int r;
	int ready = -_L(EBADF);
	int i;
	struct wait_entry *wait_list;
	struct _l_pollfd *fds;
	filp **fps;
	struct poll_timeout pt;

	dprintf("poll(%p,%d,%d)\n", ptr, nfds, timeout);

	if (nfds < 0)
		return -_L(EINVAL);

	/* stack memory, no free needed */
	fds = alloca(nfds * sizeof fds[0]);
	memset(fds, 0, nfds * sizeof fds[0]);

	wait_list = alloca(nfds * sizeof wait_list[0]);
	memset(wait_list, 0, nfds * sizeof wait_list[0]);

	fps = alloca(nfds * sizeof fps[0]);
	memset(fps, 0, nfds * sizeof fps[0]);

	for (i = 0; i < nfds; i++)
	{
		dprintf("fd %d event %08x\n", fds[i].fd, fds[i].events);
		fps[i] = filp_from_fd(fds[i].fd);
	}

	ready = poll_check(fps, fds, nfds);
	if (ready || !timeout)
		goto end;

	pt.t.fn = &poll_timeout_waker;
	pt.p = current;
	pt.timed_out = 0;

	if (timeout)
		timeout_add_ms(&pt.t, timeout);

	for (i = 0; i < nfds; i++)
	{
		fps[i]->ops->fn_poll_add(fps[i], &wait_list[i]);
	}

	while (1)
	{
		ready = poll_check(fps, fds, nfds);
		if (ready || pt.timed_out)
			break;

		current->state = thread_stopped;
		yield();
		current->state = thread_running;
	}

	for (i = 0; i < nfds; i++)
	{
		fps[i]->ops->fn_poll_del(fps[i],
					&wait_list[i]);
	}

	if (timeout)
		timeout_remove(&pt.t);

end:
	/* copy back */
	r = current->ops->memcpy_to(ptr, fds, nfds * sizeof fds[0]);
	if (r < 0)
		return r;

	return ready;
}

int sys_newuname(struct _l_new_utsname *ptr)
{
	struct _l_new_utsname un;
	int r;

	dprintf("newuname(%p)\n", ptr);
	strcpy(un.sysname, "Linux");
	strcpy(un.nodename, "xli");
	strcpy(un.release, "2.6.36");
	strcpy(un.version, "xli v0.1");
	strcpy(un.machine, "i686");
	strcpy(un.domainname, "(none)");
	r = current->ops->memcpy_to(ptr, &un, sizeof un);
	if (r < 0)
		return r;
	return 0;
}

static inline void *ptr(int x)
{
	return (void*)x;
}

int do_syscall(int n, int a1, int a2, int a3, int a4, int a5, int a6)
{
	int r;

	switch (n)
	{
	case 1:
		r = sys_exit(a1);
		break;
	case 2:
		r = sys_fork();
		break;
	case 3:
		r = sys_read(a1, ptr(a2), a3);
		break;
	case 4:
		r = sys_write(a1, ptr(a2), a3);
		break;
	case 5:
		r = sys_open(ptr(a1), a2, a3);
		break;
	case 6:
		r = sys_close(a1);
		break;
	case 7:
		r = sys_waitpid(a1, ptr(a2), a3);
		break;
	case 11:
		r = sys_exec(ptr(a1), ptr(a2), ptr(a3));
		break;
	case 13:
		r = sys_time(ptr(a1));
		break;
	case 20:
		r = sys_getpid();
		break;
	case 24:
		r = sys_getuid();
		break;
#if 0
	case 33:
		r = sys_access(ptr(a1), a2);
		break;
#endif
	case 37:
		r = sys_kill(a1, a2);
		break;
	case 41:
		r = sys_dup(a1);
		break;
	case 42:
		r = sys_pipe(ptr(a1));
		break;
	case 45:
		r = (int)sys_brk(ptr(a1));
		break;
	case 54:
		r = sys_ioctl(a1, a2, a3);
		break;
	case 63:
		r = sys_dup2(a1, a2);
		break;
#if 0
	case 64:
		r = sys_getppid();
		break;
	case 65:
		r = sys_getpgrp();
		break;
#endif
	case 82:
		r = sys_select(a1, ptr(a2), ptr(a3), ptr(a4), ptr(a5));
		break;
	case 91:
		r = sys_munmap(ptr(a1), a2);
		break;
	case 122:
		r = sys_newuname(ptr(a1));
		break;
	case 140:
		r = sys_llseek(a1, a2, a3, ptr(a4), a5);
		break;
	case 141:
		r = sys_getdents(a1, ptr(a2), a3);
		break;
#if 0
	case 146:
		r = sys_writev(a1, ptr(a2), a3);
		break;
#endif
	case 162:
		r = sys_nanosleep(ptr(a1), ptr(a2));
		break;
	case 168:
		r = sys_poll(ptr(a1), a2, a3);
		break;
#if 0
	case 174:
		r = sys_rt_sigaction(a1, ptr(a2), ptr(a3), a4);
		break;
	case 175:
		r = sys_rt_sigprocmask(a1, ptr(a2), ptr(a3));
		break;
#endif
	case 180:
		r = sys_pread64(a1, ptr(a2), a3, a4);
		break;
	case 183:
		r = sys_getcwd(ptr(a1), a2);
		break;
	case 192:
		r = (int) sys_mmap(ptr(a1), a2, a3, a4, a5, a6);
		break;
#if 0
	case 195:
		r = sys_stat64(ptr(a1), ptr(a2));
		break;
	case 196:
		r = sys_lstat64(ptr(a1), ptr(a2));
		break;
	case 197:
		r = sys_fstat64(a1, ptr(a2));
		break;
#endif
	case 199:
		r = sys_getuid();
		break;
	case 201:
		r = sys_geteuid();
		break;
	case 220:
		r = sys_getdents64(a1, ptr(a2), a3);
		break;
#if 0
	case 221:
		r = sys_fcntl64(a1, a2, a3);
		break;
	case 240:
		r = sys_futex(ptr(a1), a2, a3, ptr(a4), a5, a6);
		break;
#endif
	case 243:
		r = sys_set_thread_area(ptr(a1));
		break;
#if 0
	case 252:
		r = sys_exit_group(a1);
		break;
#endif
	default:
		printf("unknown/invalid system call %d (%08x)\n", n, n);
		exit(1);
	}

	return r;
}

unsigned int round_down_to_page(unsigned int addr)
{
	return addr &= ~pagemask;
}

unsigned int round_up_to_page(unsigned int addr)
{
	return (addr + pagemask) & ~pagemask;
}

int mmap_flags_from_elf(int flags)
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

void print_map_flags(int flags)
{
	printf("map -> %s %s %s\n",
		flags & _l_PROT_READ ? "PROT_READ" : "",
		flags & _l_PROT_WRITE ? "PROT_WRITE" : "",
		flags & _l_PROT_EXEC ? "PROT_EXEC" : "");
}

int map_elf_object(struct module_info *m, int fd)
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
	m->base = sys_mmap((void*)m->min_vaddr, m->max_vaddr - m->min_vaddr,
			_l_PROT_NONE, _l_MAP_ANONYMOUS|_l_MAP_PRIVATE, -1, 0);
	if (m->base == _l_MAP_FAILED)
	{
		dprintf("mmap failed\n");
		goto error;
	}
	dprintf("base = %p\n", m->base);

	for (i = 0; i < m->num_to_load; i++)
	{
		int mapflags = mmap_flags_from_elf(m->to_load[i].p_flags);
		void *p;
		unsigned int vaddr = round_down_to_page(m->to_load[i].p_vaddr);
		unsigned int vaddr_offset = (m->to_load[i].p_vaddr & pagemask);
		unsigned int memsz = round_up_to_page(vaddr_offset + m->to_load[i].p_memsz);
		unsigned int max_addr;

		if (verbose)
			print_map_flags(mapflags);

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
		p = sys_mmap(p, memsz, _l_PROT_READ | _l_PROT_WRITE | _l_PROT_EXEC,
			 _l_MAP_FIXED|_l_MAP_PRIVATE|_l_MAP_ANONYMOUS, -1, 0);
		if (p == _l_MAP_FAILED)
		{
			fprintf(stderr, "mmap failed (%d)\n", -(int)p);
			goto error;
		}

		p = (void*)(m->base - m->min_vaddr + m->to_load[i].p_vaddr);
		dprintf("pread %08x bytes from %08x to %p\n",
			m->to_load[i].p_filesz, m->to_load[i].p_offset, p);
		r = sys_pread64(fd, p, m->to_load[i].p_filesz, m->to_load[i].p_offset);
		if (r != m->to_load[i].p_filesz)
		{
			fprintf(stderr, "read failed (%08x != %08x)\n",
				m->to_load[i].p_filesz, r);
			goto error;
		}

		/* remember highest address we mapped, use it for brk */
		max_addr = m->to_load[i].p_vaddr + m->to_load[i].p_memsz;
		max_addr = round_up(max_addr, pagesize);
		if (current->brk < max_addr)
			current->brk = max_addr;
		dprintf("brk at %08x\n", current->brk);
	}

	m->entry_point = (void*) m->base - m->min_vaddr + m->ehdr.e_entry;

	return 0;
error:
	return -1;
}

int load_module(struct module_info *m, const char *path)
{
	bool dynamic_seen = false;
	int fd = -1;
	int r;
	int i;

	m->base = _l_MAP_FAILED;
	m->min_vaddr = 0xfffff000;
	m->max_vaddr = 0;

	fd = do_open(path, _l_O_RDONLY, 0);
	if (fd < 0)
	{
		dprintf("open() failed\n");
		goto error;
	}

	r = kread(fd, &m->ehdr, sizeof m->ehdr, 0);
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
		r = kread(fd, &phdr, sizeof phdr,
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
			r = kread(fd, &m->interpreter, sz, phdr.p_offset);
			if (r != sz)
			{
				dprintf("interpreter name read failed\n");
				goto error;
			}
			m->interpreter[sz] = 0;
		}
	}

	return fd;
error:
	close(fd);
	return -1;
}


PULONG getwreg(int reg)
{
	switch (reg & 7)
	{
	case 0: return &current->regs.Eax;
	case 1: return &current->regs.Ecx;
	case 2: return &current->regs.Edx;
	case 3: return &current->regs.Ebx;
	case 4: return &current->regs.Esp;
	case 5: return &current->regs.Ebp;
	case 6: return &current->regs.Esi;
	case 7: return &current->regs.Edi;
	default:
		abort();
	}
}

ULONG getrm0(int rm)
{
	switch (rm & 7)
	{
	case 0: return current->regs.Eax;
	case 1: return current->regs.Ecx;
	case 2: return current->regs.Edx;
	case 3: return current->regs.Ebx;
	case 6: return current->regs.Esi;
	case 7: return current->regs.Edi;
	default:
		fprintf(stderr, "getrm0: unhandled\n");
		exit(1);
	}
}

ULONG getrm_value(int modrm)
{
	if ((modrm & 0xc0) == 0)
		return getrm0(modrm);
	fprintf(stderr, "getrm0: unhandled\n");
	exit(1);
	return 0;
}

void handle_mov_reg_to_seg_reg(uint8_t modrm)
{
	if ((modrm & 0xf8) != 0xe8)
	{
		fprintf(stderr, "unhandled mov\n");
		exit(1);
	}
	else
	{
		ULONG *reg = getwreg(modrm & 7);
		unsigned int x = ((*reg) >> 3) - 0x80;
		if (x >= MAX_VTLS_ENTRIES)
		{
			fprintf(stderr, "vtls out of range\n");
			exit(1);
		}
		current->vtls_selector = x;
	}
}

NTSTATUS handle_mov_eax_to_gs_addr(void)
{
	unsigned int offset = 0;
	NTSTATUS r;
	ULONG sz = 0;
	BYTE *tls;

	r = NtReadVirtualMemory(current->process,
				(char*) current->regs.Eip + 2,
				&offset, sizeof offset, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	tls = (BYTE*) current->vtls[current->vtls_selector].base_addr;
	tls += offset;
	r = NtWriteVirtualMemory(current->process, tls,
				&current->regs.Eax, 4, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	current->regs.Eip += 6;
	return r;
}

NTSTATUS handle_mov_gs_addr_to_eax(void)
{
	unsigned int offset = 0;
	NTSTATUS r;
	ULONG sz = 0;
	BYTE *tls;

	r = NtReadVirtualMemory(current->process,
				(char*) current->regs.Eip + 2,
				&offset, sizeof offset, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	tls = (BYTE*) current->vtls[current->vtls_selector].base_addr;
	tls += offset;
	r = NtReadVirtualMemory(current->process, tls,
				&current->regs.Eax, 4, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	current->regs.Eip += 6;
	return r;
}

NTSTATUS handle_movl_to_gs_reg(void)
{
	NTSTATUS r;
	ULONG sz = 0;
	BYTE *tls;
	struct {
		int8_t offset;
		uint32_t value;
	} __attribute__((__packed__)) buf;

	r = NtReadVirtualMemory(current->process,
				(char*) current->regs.Eip + 2,
				&buf, sizeof buf, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	tls = (BYTE*) current->vtls[current->vtls_selector].base_addr;
	tls += current->regs.Eax;
	tls += buf.offset;

	r = NtWriteVirtualMemory(current->process, tls,
				&buf.value, sizeof buf.value, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	current->regs.Eip += 7;
	return r;
}

NTSTATUS handle_imm32_to_gs_address(void)
{
	NTSTATUS r;
	ULONG sz = 0;
	BYTE *tls;
	struct {
		uint8_t modrm;
		int8_t offset;
		uint32_t value;
	} __attribute__((__packed__)) buf;
	uint32_t value;

	r = NtReadVirtualMemory(current->process,
				(char*) current->regs.Eip + 2,
				&buf, sizeof buf, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	if (buf.modrm != 0x3d)
	{
		fprintf(stderr, "unhandled instruction\n");
		return STATUS_UNSUCCESSFUL;
	}

	tls = (BYTE*) current->vtls[current->vtls_selector].base_addr;
	tls += buf.offset;

	r = NtReadVirtualMemory(current->process, tls,
				&value, sizeof value, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	/* set the flags */
	__asm__ __volatile__ (
		"\txor %%eax, %%eax\n"
		"\tcmpl %0, %1\n"
		"\tlahf\n"
		"\tmovb %%ah, (%2)\n"
	: : "r"(value), "r"(buf.value), "r"(&current->regs.EFlags) : "eax");

	current->regs.Eip += 8;

	return r;
}

NTSTATUS handle_reg_indirect_to_read(void)
{
	NTSTATUS r;
	ULONG sz = 0;
	BYTE *tls;
	struct {
		uint8_t modrm;
	} buf;
	ULONG *preg;

	r = NtReadVirtualMemory(current->process,
				(char*) current->regs.Eip + 2,
				&buf, sizeof buf, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	// 65 8b 38			mov    %gs:(%eax),%edi
	tls = (BYTE*) current->vtls[current->vtls_selector].base_addr;

	preg = getwreg(buf.modrm >> 3);

	tls += getrm_value(buf.modrm);
	r = NtReadVirtualMemory(current->process, tls,
				preg, sizeof *preg, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	current->regs.Eip += 3;

	return r;
}

NTSTATUS handle_reg_indirect_to_write(void)
{
	NTSTATUS r;
	ULONG sz = 0;
	BYTE *tls;
	struct {
		uint8_t modrm;
	} buf;
	ULONG *preg;

	r = NtReadVirtualMemory(current->process,
				(char*) current->regs.Eip + 2,
				&buf, sizeof buf, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	tls = (BYTE*) current->vtls[current->vtls_selector].base_addr;

	preg = getwreg(buf.modrm >> 3);

	tls += getrm_value(buf.modrm);
	r = NtWriteVirtualMemory(current->process, tls,
				preg, sizeof *preg, &sz);
	if (r != STATUS_SUCCESS)
		return r;

	current->regs.Eip += 3;

	return r;
}

typedef NTSTATUS (*EventHandlerFn)(DEBUGEE_EVENT *event,
				struct process *context);

static NTSTATUS OnDebuggerIdle(DEBUGEE_EVENT *event,
				struct process *context)
{
	return STATUS_SUCCESS;
}

static NTSTATUS OnDebuggerPendingReply(DEBUGEE_EVENT *event,
					 struct process *context)
{
	return STATUS_SUCCESS;
}

static NTSTATUS OnDebuggerCreateThread(DEBUGEE_EVENT *event,
					struct process *context)
{
	return STATUS_SUCCESS;
}

static NTSTATUS OnDebuggerCreateProcess(DEBUGEE_EVENT *event,
					struct process *context)
{
	return pDbgUiContinue(&event->ClientId, DBG_CONTINUE);
}

static NTSTATUS OnDebuggerExitThread(DEBUGEE_EVENT *event,
					struct process *context)
{
	return STATUS_SUCCESS;
}

static NTSTATUS OnDebuggerExitProcess(DEBUGEE_EVENT *event,
					struct process *context)
{
	return STATUS_SUCCESS;
}

static NTSTATUS OnDebuggerException(DEBUGEE_EVENT *event,
					struct process *context)
{
	EXCEPTION_RECORD *er = &event->Exception.ExceptionRecord;

	if (er->ExceptionCode == STATUS_ACCESS_VIOLATION)
	{
		CONTEXT *regs = &context->regs;
		unsigned char buffer[2];
		ULONG sz = 0;
		NTSTATUS r;

		r = NtReadVirtualMemory(context->process, (void*) context->regs.Eip,
					buffer, sizeof buffer, &sz);
		if (r != STATUS_SUCCESS)
		{
			fprintf(stderr, "failed to read instruction\n");
			goto fail;
		}
		if (buffer[0] == 0xcd && buffer[1] == 0x80)
		{
			/* fork() relies on pre-increment here */
			regs->Eip += 2;
			SwitchToFiber(context->fiber);
			/* syscall fiber will continue the client thread */
			return STATUS_SUCCESS;
		}
		// 8e e8			mov    %eax,%gs
		else if (buffer[0] == 0x8e)
		{
			handle_mov_reg_to_seg_reg(buffer[1]);
			regs->Eip += 2;
		}
		// 65 a3 14 00 00 00		mov    %eax,%gs:0x14
		else if (buffer[0] == 0x65 && buffer[1] == 0xa3)
		{
			r = handle_mov_eax_to_gs_addr();
			if (r != STATUS_SUCCESS)
				goto fail;
		}
		else if (buffer[0] == 0x65 && buffer[1] == 0xa1)
		{
			r = handle_mov_gs_addr_to_eax();
			if (r != STATUS_SUCCESS)
				goto fail;
		}
		// 65 c7 00 80 c4 1b 08		movl   $0x81bc480,%gs:(%eax)
		else if (buffer[0] == 0x65 && buffer[1] == 0xc7)
		{
			r = handle_movl_to_gs_reg();
			if (r != STATUS_SUCCESS)
				goto fail;
		}
		// 65 83 3d 0c 00 00 00 00    cmpl   $0x0,%gs:0xc
		else if (buffer[0] == 0x65 && buffer[1] == 0x83)
		{
			r = handle_imm32_to_gs_address();
			if (r != STATUS_SUCCESS)
				goto fail;
		}
		// 65 89 0b			mov    %ecx,%gs:(%ebx)
		else if (buffer[0] == 0x65 && buffer[1] == 0x89)
		{
			r = handle_reg_indirect_to_write();
			if (r != STATUS_SUCCESS)
				goto fail;
		}
		// 65 8b 03			mov    %gs:(%ebx),%eax
		// 65 8b 38			mov    %gs:(%eax),%edi
		else if (buffer[0] == 0x65 && buffer[1] == 0x8b)
		{
			r = handle_reg_indirect_to_read();
			if (r != STATUS_SUCCESS)
				goto fail;
		}
		else
		{
			fprintf(stderr, "not a syscall: %02x %02x\n",
				buffer[0], buffer[1]);
			goto fail;
		}

		context->regs.ContextFlags = CONTEXT_i386 |
					CONTEXT_CONTROL |
					CONTEXT_INTEGER;
		r = NtSetContextThread(context->thread, &context->regs);
		if (r != STATUS_SUCCESS)
		{
			fprintf(stderr, "failed to set registers back\n");
			return STATUS_UNSUCCESSFUL;
		}

	}
	else
	{
fail:
		dump_regs(context);
		dump_exception(er);
		dump_stack(context);
		dump_address_space();
		backtrace(context);
		exit(0);
	}

	if (context->state == thread_running)
		return pDbgUiContinue(&event->ClientId, DBG_CONTINUE);

	return STATUS_SUCCESS;
}

static NTSTATUS OnDebuggerBreakpoint(DEBUGEE_EVENT *event,
					struct process *context)
{
	// hook ptrace into here
	fprintf(stderr, "Breakpoint...\n");
	exit(1);

	return pDbgUiContinue(&event->ClientId, DBG_CONTINUE);
}

static NTSTATUS OnDebuggerSingleStep(DEBUGEE_EVENT *event,
					struct process *context)
{
	return STATUS_SUCCESS;
}

static NTSTATUS OnDebuggerLoadDll(DEBUGEE_EVENT *event,
					struct process *context)
{
	if (0)
	{
		PVOID Base = event->LoadDll.Base;
		char name[0x100];

		printf("dll base = %p\n", Base);
		if (GetMappedFileName(context->process, Base, name, sizeof name))
			printf("Filename -> %s\n", name);
		else
			printf("GetMappedFileName failed\n");
	}

	return pDbgUiContinue(&event->ClientId, DBG_EXCEPTION_NOT_HANDLED);
}

static NTSTATUS OnDebuggerUnloadDll(DEBUGEE_EVENT *event,
					struct process *context)
{
	return STATUS_SUCCESS;
}

static EventHandlerFn handlers[] =
{
	OnDebuggerIdle,			// DbgIdle,
	OnDebuggerPendingReply,		// DbgReplyPending,
	OnDebuggerCreateThread,		// DbgCreateThreadStateChange,
	OnDebuggerCreateProcess,	// DbgCreateProcessStateChange,
	OnDebuggerExitThread,		// DbgExitThreadStateChange,
	OnDebuggerExitProcess,		// DbgExitProcessStateChange,
	OnDebuggerException,		// DbgExceptionStateChange,
	OnDebuggerBreakpoint,		// DbgBreakpointStateChange,
	OnDebuggerSingleStep,		// DbgSingleStepStateChange,
	OnDebuggerLoadDll,		// DbgLoadDllStateChange,
	OnDebuggerUnloadDll,		// DbgUnloadDllStateChange
};

static NTSTATUS ReadDebugPort(HANDLE debugObject)
{
	struct process *context;
	NTSTATUS r;
	LARGE_INTEGER timeout;
	DEBUGEE_EVENT event = {0};

	// sometimes DbgUiWaitStateChange returns STATUS_TIMEOUT
	// but appears to succeed and do what we expect...
	timeout.QuadPart = 0;
	r = pDbgUiWaitStateChange(&event, &timeout);
	if (r == STATUS_TIMEOUT)
	{
		dprintf("DbgUiWaitStateChange() timeout\n");
		return STATUS_SUCCESS;
	}

	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "DbgUiWaitStateChange() r=%08lx\n", r);
		return r;
	}

	dprintf("NewState: %s\n", debug_state_to_string(event.NewState));

	if (event.NewState > sizeof handlers/sizeof handlers[0])
		return STATUS_UNSUCCESSFUL;

	context = context_from_client_id(&event.ClientId);
	if (!context)
	{
		printf("received event for unknown process\n");
		return STATUS_UNSUCCESSFUL;
	}

	/*
	 * needs to be at least 2 fibers
	 *  - one (per thread) for the syscall context
	 *  - one to wait on debugger state
	 */

	read_process_registers(context);
	return handlers[event.NewState](&event, context);
}

void __stdcall SyscallHandler(PVOID param)
{
	struct process *context = param;
	current = context;
	while (1)
	{
		CONTEXT *regs = &context->regs;
		ULONG r;

		r = do_syscall(regs->Eax, regs->Ebx,
				regs->Ecx, regs->Edx,
				regs->Esi, regs->Edi,
				regs->Ebp);
		regs->Eax = r;

		context->regs.ContextFlags = CONTEXT_i386 |
					CONTEXT_CONTROL |
					CONTEXT_INTEGER;
		r = NtSetContextThread(context->thread, &context->regs);
		if (r != STATUS_SUCCESS)
		{
			fprintf(stderr, "failed to set registers back\n");
			context->state = thread_terminated;
			/* FIXME: use kill here */
		}
		else
		{
			if (context->state == thread_running)
				pDbgUiContinue(&context->id, DBG_CONTINUE);
		}

		yield();
	}
}

NTSTATUS create_first_thread(struct process *context)
{
	NTSTATUS r;

	context->fiber = CreateFiber(0, &SyscallHandler, context);
	if (!context->fiber)
		return STATUS_UNSUCCESSFUL;

	/* create a thread to run in the process */
	context->regs.ContextFlags = CONTEXT_FULL;
	r = NtCreateThread(&context->thread, THREAD_ALL_ACCESS, NULL,
			 context->process, &context->id,
			 &context->regs, &context->stack_info, FALSE);
	return r;
}

NTSTATUS GetClientId(HANDLE thread, CLIENT_ID *id)
{
	NTSTATUS r;
	THREAD_BASIC_INFORMATION info;

	memset(&info, 0, sizeof info);

	r = NtQueryInformationThread(thread, ThreadBasicInformation,
				&info, sizeof info, NULL);
	if (r == STATUS_SUCCESS)
		*id = info.ClientId;

	return r;
}

DWORD GetThreadId(HANDLE thread)
{
	NTSTATUS r;
	CLIENT_ID id;

	r = GetClientId(thread, &id);
	if (r != STATUS_SUCCESS)
		return 0;

	return (DWORD) id.UniqueThread;
}

DWORD GetProcessId(HANDLE process)
{
	NTSTATUS r;
	PROCESS_BASIC_INFORMATION info;

	memset(&info, 0, sizeof info);

	r = NtQueryInformationProcess(process, ProcessBasicInformation,
					 &info, sizeof info, NULL);
	if (r != STATUS_SUCCESS)
		return 0;

	return info.UniqueProcessId;
}

void get_stub_name(void)
{
	static const WCHAR stub[] = L"linux.exe";
	DWORD len = 0;
	len = GetModuleFileNameW(NULL, stub_exe_name,
				sizeof stub_exe_name - sizeof stub);
	while (len > 0 && stub_exe_name[len - 1] != '\\')
		len--;
	lstrcpyW(&stub_exe_name[len], stub);
}

/* remove from active process list */
void unlink_process(struct process *process)
{
	struct process **p;
	for (p = &first_process; *p; p = &(*p)->next_process)
	{
		if (*p == process)
		{
			*p = (*p)->next_process;
			return;
		}
	}
	dprintf("unlink failed\n");
}

static void process_migrate_children_to_parent(struct process *p)
{
	struct process *t;

	/* migrate all children to parent of exitting process */
	while ((t = p->child))
	{
		/* remove from this process */
		p->child = t->sibling;

		/* add as parent's child */
		t->sibling = p->parent->child;
		p->parent->child = t;
	}
}

static void process_unlink_from_sibling_list(struct process *process)
{
	struct process **p;

	if (!process->parent)
		return;

	for (p = &(process->parent->child); *p; p = &(*p)->sibling)
	{
		if (*p == process)
		{
			*p = process->child;
			return;
		}
	}
	fprintf(stderr, "sibling list unlink failed\n");
	exit(1);
}

void process_free(struct process *process)
{
	process_migrate_children_to_parent(process);
	process_unlink_from_sibling_list(process);

	DeleteFiber(process->fiber);
	NtTerminateProcess(process->process, STATUS_UNSUCCESSFUL);
	CloseHandle(process->thread);
	CloseHandle(process->process);
	unlink_process(process);
}

void yield(void)
{
	struct process *p = current;
	if (GetCurrentFiber() == wait_fiber)
	{
		fprintf(stderr, "bad yield at %d\n", __LINE__);
		exit(1);
	}
	SwitchToFiber(wait_fiber);
	current = p;
}

/*
 * list of fibers ready to run
 * Singly linked with the last entry pointing to itself
 * Can be added from anywhere.
 * Always woken from the main loop
 */
static CRITICAL_SECTION ready_list_lock;
static struct process *first_ready;

/* this needs to be done from the main loop's context */
static void process_ready_list(void)
{
	while (1)
	{
		EnterCriticalSection(&ready_list_lock);
		struct process *p = first_ready;
		if (p)
		{
			if (p == p->next_ready)
				first_ready = NULL;
			else
				first_ready = p->next_ready;
			p->next_ready = NULL;
		}
		LeaveCriticalSection(&ready_list_lock);
		if (!p)
			break;
		SwitchToFiber(p->fiber);
	}
}

void ready_list_add(struct process *p)
{
	EnterCriticalSection(&ready_list_lock);

	/* first_ready is alway non-null if in ready list */
	if (!p->next_ready)
	{
		if (first_ready)
			p->next_ready = first_ready;
		else
			p->next_ready = p;
		first_ready = p;
	}

	LeaveCriticalSection(&ready_list_lock);
	SetEvent(loop_event);
}

/* move to process. timeouts are global, but signals are per process */
struct wait_list signal_waiters;

void signal_waiter_add(struct signal_waiter *sw, int signal)
{
	sw->signal = signal;
	wait_entry_append(&signal_waiters, &sw->we);
}

void signal_waiter_remove(struct signal_waiter *sw)
{
	wait_entry_remove(&signal_waiters, &sw->we);
}

void process_signal(struct process *p, int signal)
{
	struct signal_waiter *sw = (void*) signal_waiters.head;

	while (sw)
	{
		struct wait_entry *next = sw->we.next;
		if (sw->signal == signal)
			ready_list_add(sw->we.p);

		sw = (struct signal_waiter*) next;
	}
}

static struct timeout *timeout_head;

void timeout_now(struct timeval *tv)
{
	SYSTEMTIME st;
	FILETIME ft;
	ULONGLONG seconds;

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft);

	seconds = (((ULONGLONG)ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
	tv->tv_sec = seconds / 10000000LL;
	tv->tv_usec = (ft.dwLowDateTime / 10) % 1000000;
}

static void timeout_dprint_timeval(struct timeval *tv, const char *what)
{
	int t = tv->tv_sec;
	int seconds, minutes, hours;

	seconds = t % 60;
	t /= 60;
	minutes = t % 60;
	t /= 60;
	hours = t % 24;

	dprintf("%s -> %02d:%02d:%02d.%06ld\n", what,
		 hours, minutes, seconds, tv->tv_usec);
}

static int timeout_before(struct timeout *t1, struct timeout *t2)
{
	if (t1->tv.tv_sec < t2->tv.tv_sec)
		return 1;
	if (t1->tv.tv_sec > t2->tv.tv_sec)
		return 0;
	return (t1->tv.tv_usec < t2->tv.tv_usec);
}

void timeout_add_tv(struct timeout *t, struct timeval *ts)
{
	struct timeval now;

	timeout_now(&now);

	t->tv.tv_usec = now.tv_usec + ts->tv_usec;
	t->tv.tv_sec = now.tv_sec + ts->tv_usec;
	t->tv.tv_sec += t->tv.tv_usec / (1000 * 1000);
	t->tv.tv_usec %= (1000 * 1000);

	timeout_add(t);
}

void timeout_add_ms(struct timeout *t, int ms)
{
	struct timeval now;

	timeout_now(&now);

	t->tv.tv_usec = now.tv_usec + (ms%1000) * 1000;
	t->tv.tv_sec = now.tv_sec + (ms / 1000) + now.tv_usec / (1000 * 1000);
	t->tv.tv_usec %= (1000 * 1000);

	timeout_add(t);
}

void timeout_add(struct timeout *t)
{
	struct timeout **where = &timeout_head;

	while (*where && timeout_before(*where, t))
		where = &(*where)->next;

	t->next = *where;
	*where = t;
}

void timeout_remove(struct timeout *t)
{
	struct timeout **where = &timeout_head;

	while (*where && t != *where)
		where = &(*where)->next;

	*where = t->next;
}

DWORD timeout_get_next(void)
{
	struct timeval now;
	int t;

	if (!timeout_head)
		return INFINITE;

	timeout_now(&now);
	t = (timeout_head->tv.tv_usec - now.tv_usec + 999) / 1000;
	t += (timeout_head->tv.tv_sec - now.tv_sec) * 1000;

	if (0)
	{
		timeout_dprint_timeval(&now, "now");
		timeout_dprint_timeval(&timeout_head->tv, "next");
		dprintf("timeout -> %d\n", t);
	}

	if (t < 0)
		t = 0;


	return t;
}

void timeout_handle(void)
{
	timeout_head->fn(timeout_head);
}

int main(int argc, char **argv)
{
	HANDLE debugObject = 0;
	NTSTATUS r;
	struct process *context = alloc_process();
	filp *tty = NULL;
	int n = 1;

	InitializeCriticalSection(&ready_list_lock);

	GetCurrentDirectory(sizeof rootdir, rootdir);

	loop_event = CreateEvent(NULL, 0, 0, NULL);

	/* the initial environment */
	char *env[] =
	{
		"TERM=vt100",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		NULL,
	};

	if (!dynamic_resolve())
	{
		fprintf(stderr, "resolve failed\n");
		return 1;
	}

	get_stub_name();

	hBreakEvent = CreateEvent(0, 0, 0, 0);
	if (!hBreakEvent)
	{
		fprintf(stderr, "Failed to create event\n");
		return 1;
	}

	if (!SetConsoleCtrlHandler(break_handler, TRUE))
	{
		fprintf(stderr, "Failed to set ^C handler\n");
		return 1;
	}

	if (n < argc && !strcmp(argv[n], "-d"))
	{
		verbose = 1;
		n++;
	}

	if (n >= argc)
	{
		fprintf(stderr, "usage: %s prog ...\n", argv[0]);
		return 1;
	}

	/*
	 * Create a debugger port
	 * This is XP specific.  On Windows 2000, should use NtCreatePort()
	 */
	r = pDbgUiConnectToDbg();
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "DbgUiConnectToDbg() failed: %08lx\n", r);
		goto out;
	}

	debugObject = pDbgUiGetThreadDebugObject();

	/*
	 * TODO: create_nt_process should be sys_exec
	 * create new address space then
	 * sys_exec(argv, env);
	 */
	current = context;
	r = create_nt_process(context, debugObject);
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "create_nt_process failed with error %08lx\n", r);
		goto out;
	}

	/* allocate a console for the first process only */
	tty = get_console();
	context->handles[0] = tty;
	context->handles[1] = tty;
	context->handles[2] = tty;

	/* move exec into fiber */
	r = do_exec(argv[n], argv + n, env);
	if (r < 0)
	{
		fprintf(stderr, "Failed to start \'%s\'\n", argv[n]);
		goto out;
	}

	r = create_first_thread(context);
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "create_first_thread() failed: %08lx\n", r);
		goto out;
	}

	/*
	 * For simplicity, the concurrency model is * based on fibers.
	 * There is one fiber per client thread, and the client's
	 * syscall runs that fiber. The main loop (aka scheduler) also
	 * has a single fiber.
	 *
	 * There are two valid transitions:
	 *  - main loop fiber -> client fiber
	 *  - client fiber -> main loop fiber
	 *
	 * A client fiber cannot switch to another client fiber.
	 *
	 * This setup also reduces Windows OS resource usage, as
	 * only one thread is required for the scheduler + clients.
	 *
	 * On the down side, this setup is the equivilent of
	 * the old Linux Big Kernel Lock... and doesn't reap
	 * the benefits of SMP
	 */

	wait_fiber = ConvertThreadToFiber(NULL);

	while (first_process != NULL)
	{
		HANDLE handles[3];
		int n = 0;
		DWORD timeout;

		handles[n++] = hBreakEvent;
		handles[n++] = debugObject;
		handles[n++] = loop_event;

		timeout = timeout_get_next();

		r = WaitForMultipleObjects(n, handles, FALSE, timeout);
		if (r == WAIT_OBJECT_0)
		{
			fprintf(stderr,"User abort!\n");
			break;
		}
		else if (r == (WAIT_OBJECT_0 + 1))
		{
			r = ReadDebugPort(debugObject);
			if (r != STATUS_SUCCESS)
				break;
		}
		else if (r == WAIT_TIMEOUT)
		{
			timeout_handle();
		}

		/* wake fibers that are ready, in context of main loop */
		process_ready_list();
	}

out:
	while (first_process)
		process_free(first_process);

	CloseHandle(debugObject);
	CloseHandle(hBreakEvent);

	return r;
}
