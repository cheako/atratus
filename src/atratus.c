/*
 * atratus - Linux binary emulation for Windows
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
#include "pipe.h"

#include "sys/elf32.h"
#include "elf-av.h"

#include "process.h"
#include "tty.h"
#include "vt100.h"
#include "inet.h"
#include "minmax.h"
#include "debug.h"
#include "ntstatus.h"
#include "vm.h"
#include "elf.h"
#include "emulate.h"

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
LIST_ANCHOR(struct process) process_list;
LIST_ANCHOR(struct process) remote_break_list;
static LPVOID wait_fiber;
static HANDLE loop_event;
static HANDLE debugObject;

static WCHAR stub_exe_name[MAX_PATH];

#define DEFAULT_STACKSIZE 0x100000

static int vm_memcpy_from(void *local_addr, const void *client_addr, size_t size)
{
	return vm_memcpy_from_process(current, local_addr, client_addr, size);
}

static int vm_memcpy_to(void *client_addr, const void *local_addr, size_t size)
{
	return vm_memcpy_to_process(current, client_addr, local_addr, size);
}

struct process_ops nt_process_ops =
{
	.memcpy_from = &vm_memcpy_from,
	.memcpy_to = &vm_memcpy_to,
};

struct process *context_from_client_id(CLIENT_ID *id)
{
	struct process *process;

	process = LIST_HEAD(&process_list);
	while (process)
	{
		if (process->id.UniqueThread == id->UniqueThread &&
		    process->id.UniqueProcess == id->UniqueProcess)
			return process;
		process = LIST_NEXT(process, item);
	}
	return NULL;
}

BOOL WINAPI GetFileSizeEx(HANDLE handle, PLARGE_INTEGER Size);
extern void KiUserApcDispatcher(void);
extern void LdrInitializeThunk(void);

/* mingw32's ntdll doesn't have these functions */
#define DECLARE(x) typeof(x) *p##x;
DECLARE(NtContinue)
DECLARE(NtCreateWaitablePort)
DECLARE(DbgUiGetThreadDebugObject)
DECLARE(DbgUiConnectToDbg);
DECLARE(DbgUiWaitStateChange)
DECLARE(DbgUiContinue)
DECLARE(DbgUiIssueRemoteBreakin)
DECLARE(NtUnmapViewOfSection)
DECLARE(KiUserApcDispatcher)
DECLARE(LdrInitializeThunk)
DECLARE(NtSetLdtEntries)
DECLARE(NtRemoveProcessDebug);
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

		RESOLVE(NtContinue)
		RESOLVE(NtCreateWaitablePort)
		RESOLVE(DbgUiGetThreadDebugObject)
		RESOLVE(DbgUiConnectToDbg)
		RESOLVE(DbgUiWaitStateChange)
		RESOLVE(DbgUiContinue)
		RESOLVE(DbgUiIssueRemoteBreakin)
		RESOLVE(NtUnmapViewOfSection)
		RESOLVE(KiUserApcDispatcher)
		RESOLVE(LdrInitializeThunk)
		RESOLVE(NtSetLdtEntries)
		RESOLVE(NtRemoveProcessDebug)
#undef RESOLVE
	}
	else
	{
		fprintf(stderr, "No ntdll\n");
		return FALSE;
	}

	return TRUE;
}

void* sys_mmap(void *addr, size_t len, int prot,
		int flags, int fd, off_t offset);
static int do_close(int fd);
void dump_string_list(char **list);
void __stdcall SyscallHandler(PVOID param);
void process_deliver_signal(struct process *p);
void signal_queue_free(struct process *p);
void sys_sigreturn(void);
void sys_rt_sigreturn(void);

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
		debug_line_dump(buffer, bytesRead);
		if (bytesRead != sz)
			break;
		len -= sz;
		x += sz;
	}
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

static NTSTATUS patch_process(HANDLE process, void *where,
				const void *inst, size_t inst_sz)
{
	ULONG sz = 0;
	NTSTATUS r;
	ULONG old_prot = 0;
	void *addr;

	/* make ntdll writeable */
	sz = inst_sz;
	addr = where;
	r = NtProtectVirtualMemory(process, &addr, &sz,
				PAGE_READWRITE, &old_prot);
	if (r != STATUS_SUCCESS)
	{
		printf("failed to make writeable\n");
		return r;
	}

	/* patch */
	r = NtWriteVirtualMemory(process, where, inst, inst_sz, &sz);
	if (r != STATUS_SUCCESS)
	{
		printf("failed to write memory\n");
		return r;
	}

	if (sz != inst_sz)
	{
		printf("short write!\n");
		return STATUS_UNSUCCESSFUL;
	}

	/* restore original protection */
	sz = inst_sz;
	addr = where;
	r = NtProtectVirtualMemory(process, &addr, &sz,
				old_prot, &old_prot);
	if (r != STATUS_SUCCESS)
	{
		printf("failed to restore protection\n");
		return r;
	}

	return r;
}

/*
 * The purpose of patching NTDLL is to:
 *  - avoid pollution of the address space with NTDLL's requirements
 *  - avoid useless NTDLL setup (don't want to use NT services)
 *  - make the startup a little cleaner
 *
 * The patched KiUserApcDispatcher is intended to ignore the
 * APC that initializes NTDLL entirely.
 *
 * 0:   8d 7c 24 10             lea    0x10(%esp),%edi
 * 4:   6a 01                   push   $0x1
 * 6:   57                      push   %edi
 * 7:   e8 xx xx xx xx          call   NtContinue
 */
static NTSTATUS patch_apc_callback(struct process *context)
{
	NTSTATUS r;
	struct {
		uint8_t ops1[8];
		uint32_t offset;
	} __attribute__((__packed__)) inst = {
		{ 0x8d, 0x7c, 0x24, 0x10, 0x6a, 0x01, 0x57, 0xe8 }
	};

	inst.offset = (int) pNtContinue - (int) pKiUserApcDispatcher - sizeof inst;

	STATIC_ASSERT(sizeof inst == 12);

	r = patch_process(context->process, pKiUserApcDispatcher,
			&inst, sizeof inst);
	if (r != STATUS_SUCCESS)
		return r;

	dprintf("Patched KiUserApcDispatcher @%p\n", pKiUserApcDispatcher);

	return r;
}

/*
   0:   89 ff                   mov    %edi,%edi
   2:   55                      push   %ebp
   3:   89 e5                   mov    %esp,%ebp
   5:   6a 01                   push   $0x1
   7:   ff 75 08                pushl  0x8(%ebp)
   a:   e8 fc ff ff ff          call   0xb
 */
static NTSTATUS patch_ldr_thunk(struct process *context)
{
	NTSTATUS r;
	struct {
		uint8_t ops1[11];
		uint32_t offset;
	} __attribute__((__packed__)) inst = {{
		0x89, 0xff, 0x55, 0x89, 0xe5, 0x6a, 0x01, 0xff, 0x75, 0x08, 0xe8
	}};

	inst.offset = (int) pNtContinue - (int) pLdrInitializeThunk - sizeof inst;

	STATIC_ASSERT(sizeof inst == 15);

	r = patch_process(context->process, pLdrInitializeThunk,
			&inst, sizeof inst);
	if (r != STATUS_SUCCESS)
		return r;

	dprintf("Patched LdrInitializeThunk @%p\n", pLdrInitializeThunk);

	return r;
}

struct process *process_find(int pid)
{
	struct process *p;
	LIST_FOR_EACH(&process_list, p, item)
		if (process_getpid(p) == pid)
			return p;
	return NULL;
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
	context->state = thread_ready;
	context->umask = 0777;

	/* insert at head of list */
	LIST_ELEMENT_INIT(context, item);
	LIST_PREPEND(&process_list, context, item);

	LIST_ELEMENT_INIT(context, ready_item);
	LIST_ANCHOR_INIT(&context->signal_list);
	LIST_ELEMENT_INIT(context, remote_break_item);

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
		fprintf(stderr, "stub (%S) not found\n", stub_exe_name);
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
	 * Patch KiUserApcDispatcher to not enter ntdll
	 * We don't want or need the stuff that ntdll does
	 * Jump directly to the program entry point
	 */
	r = patch_apc_callback(context);
	if (r != STATUS_SUCCESS)
		goto end;

	/*
	 * Same as above, but for Windows 7
	 */
	r = patch_ldr_thunk(context);
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

	current->brk = 0;

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

static void do_close_on_exec(struct process *p)
{
	int i;

	for (i = 0; i < MAX_FDS; i++)
	{
		if (p->handles[i].flags & _L(O_CLOEXEC))
		{
			dprintf("exec, closing fd %d\n", i);
			do_close(i);
		}
	}
}

int do_exec(const char *filename, char **argv, char **envp)
{
	const char *interpreter = NULL;
	struct elf_module *exe = NULL;
	struct elf_module *interp = NULL;
	int r;

	dprintf("exec %s\n", filename);
	dprintf("argv:\n");
	dump_string_list(argv);
	dprintf("envp:\n");
	dump_string_list(envp);

	/* load the elf object */
	exe = elf_module_load(filename);
	if (!exe)
	{
		dprintf("elf_module_load(%s) failed\n", filename);
		r = -1;
		goto end;
	}

	/*
	 * load interpreter (in case of dynamically linked object)
	 */
	interpreter = elf_interpreter_get(exe);
	if (interpreter)
	{
		interp = elf_module_load(interpreter);
		if (!interp)
		{
			dprintf("elf_module_load(%s) failed\n", interpreter);
			r = -1;
			goto end;
		}
	}

	/*
	 * exec: point of no return
	 *
	 * Clean address space
	 */
	purge_address_space();

	r = elf_object_map(current, exe);
	if (r < 0)
	{
		dprintf("failed to map executable\n");
		goto end;
	}

	if (interp)
	{
		r = elf_object_map(current, interp);
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
	r = elf_stack_setup(current, p, sz, argv, envp, exe, interp);
	if (r < 0)
		goto end;

	/*
	 * libc makes assumptions about registers being zeroed
	 * ebx should be delta from load address to link address
	 */
	if (interp)
		current->regs.Eip = elf_entry_point_get(interp);
	else
		current->regs.Eip = elf_entry_point_get(exe);

	do_close_on_exec(current);

	dprintf("Eip = %08lx\n", current->regs.Eip);
	dprintf("Esp = %08lx\n", current->regs.Esp);
end:
	elf_object_free(exe);
	elf_object_free(interp);
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

struct fdinfo* fdinfo_from_fd(int fd)
{
	assert(_L(EBADF) == 9);
	if (fd >= MAX_FDS)
		return NULL;
	if (fd < 0)
		return NULL;
	return &current->handles[fd];
}

struct filp* filp_from_fd(int fd)
{
	struct fdinfo* fdinfo = fdinfo_from_fd(fd);
	if (!fdinfo)
		return NULL;
	return fdinfo->fp;
}

int alloc_fd_above(int start)
{
	int newfd;

	for (newfd = start; newfd < MAX_FDS; newfd++)
	{
		if (!current->handles[newfd].fp)
			break;
	}

	if (newfd >= MAX_FDS)
		return -_L(ENOENT);

	return newfd;
}

int alloc_fd(void)
{
	return alloc_fd_above(0);
}

void init_fp(struct filp *fp, const struct filp_ops *ops)
{
	memset(fp, 0, sizeof *fp);
	fp->ops = ops;
	fp->refcount = 1;
}

void copy_fd_set(struct process *to, struct process *from)
{
	int i;

	for (i = 0; i < MAX_FDS; i++)
	{
		to->handles[i].fp = from->handles[i].fp;
		to->handles[i].flags = from->handles[i].flags;
		if (to->handles[i].fp)
		{
			dprintf("cloning fd %d\n", i);
			to->handles[i].fp->refcount++;
		}
	}
}

void close_fd_set(struct process *p)
{
	int i;

	for (i = 0; i < MAX_FDS; i++)
	{
		struct filp *fp = p->handles[i].fp;
		if (fp)
			process_close_fd(p, i);
		p->handles[i].fp = NULL;
	}
}

static void process_vtls_copy(struct process *to, struct process *from)
{
	to->vtls_selector = from->vtls_selector;
	memcpy(to->vtls, from->vtls, sizeof from->vtls);
}

static int do_fork(struct process **newproc)
{
	HANDLE parent = NULL;
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

	/*
	 * shared memory mappings are marked to be dropped (by ViewUnmap)
	 * during a fork copy and remap them
	 *
	 * Note for the future (i.e. COW): The stack must be mapped.
	 * Without doing this, the process becomes unkillable in WinXP,
	 * probably because the kernel cannot push an exception CONTEXT
	 * onto the user stack and gives up in a bad state...
	 */
	vm_mappings_copy(context, current);

	/* duplicate the stack info */
	context->stack_info = current->stack_info;

	/*
	 * TODO: deal with multiple threads here
	 * Suspend all (other) threads, duplicate them all and unsuspend
	 */

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

	dprintf("fork: created thread %p:%p\n",
		context->id.UniqueProcess,
		context->id.UniqueThread);

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

	/* dup the fd set */
	copy_fd_set(context, current);

	context->cwd = strdup(current->cwd);
	context->cwdfp = current->cwdfp;
	context->cwdfp->refcount++;

	context->brk = current->brk;

	/* set the process parent */
	context->parent = current;

	/* chain siblings if they exist */
	LIST_ELEMENT_INIT(context, sibling);
	LIST_APPEND(&current->children, context, sibling);

	context->umask = current->umask;
	context->tty = current->tty;
	context->tty->refcount++;
	context->leader = current->leader;
	context->uid = current->uid;
	context->gid = current->gid;
	context->euid = current->euid;
	context->egid = current->egid;

	process_vtls_copy(context, current);

	dprintf("fork() good!\n");

	*newproc = context;

	return 0;
out:
	/* TODO: clean up properly on failure */
	return -_L(EPERM);
}

int sys_fork(void)
{
	struct process *process = NULL;
	int r = do_fork(&process);
	if (r < 0)
		return r;
	return (int) process->id.UniqueProcess;
}

/* see glibc-2.15/sysdeps/unix/sysv/linux/i386/clone.S */
int sys_clone(int flags, void *stack, void *ptidptr, int tls, void *ctidptr)
{
	struct process *process = NULL;
	size_t max_size = 0;
	int valid_flags = 0;
	void *ctid = NULL;
	void *ptid = NULL;
	int tid;
	int r;

	dprintf("clone(%08x,%p,%p,%08x,%p)\n", flags, stack, ptidptr, tls, ctidptr);

	/* lower 8 bits of flags are signal */
	valid_flags |= 0xff;
	valid_flags |= _L(CLONE_PARENT_SETTID);
	valid_flags |= _L(CLONE_CHILD_SETTID);
	valid_flags |= _L(CLONE_CHILD_CLEARTID);

	if (flags & ~valid_flags)
	{
		dprintf("clone(): threads not supported\n");
		return -_L(EPERM);
	}

	if (stack)
	{
		dprintf("clone(): non-zero stack not supported\n");
		return -_L(EPERM);
	}

	if (flags & (_L(CLONE_CHILD_CLEARTID) | _L(CLONE_CHILD_SETTID)))
	{
		r = vm_get_pointer(current, ctidptr, &ctid, &max_size);
		if (r < 0)
			return r;
		if (max_size < sizeof tid)
			return -_L(EFAULT);
	}

	if (flags & _L(CLONE_PARENT_SETTID))
	{
		r = vm_get_pointer(current, ptidptr, &ptid, &max_size);
		if (r < 0)
			return r;
		if (max_size < sizeof tid)
			return -_L(EFAULT);
	}

	r = do_fork(&process);
	if (r < 0)
		return r;

	tid = (int) process->id.UniqueProcess;
	if (ctid)
	{
		/* translate again, ctid maybe in the parent */
		int zero = 0;
		int *from = &zero;
		if (flags & _L(CLONE_CHILD_SETTID))
			from = &tid;
		vm_memcpy_to_process(process, ctidptr, from, sizeof *from);
	}

	if (ptid)
		memcpy(ptid, &tid, sizeof tid);

	return tid;
}

static void zombie_reaper(struct workitem *item)
{
	struct process *p;

	while (1)
	{
		LIST_FOR_EACH(&process_list, p, item)
			if (p->state == thread_terminated)
				break;

		if (!p)
			break;

		/* this removes the process from the list */
		LIST_REMOVE(&process_list, p, item);
		process_free(p);
	}
}

struct workitem zombie_reap_work =
{
	INVALID_ELEMENT, INVALID_ELEMENT, &zombie_reaper
};

void process_shutdown(struct process *p, int exit_code)
{
	/* TODO: close handles, other cleanup */
	if (p->state == thread_terminated)
	{
		dprintf("%p: Already shutdown\n", p);
		return;
	}
	p->exit_code = exit_code;
	p->state = thread_terminated;
	p->suspended = false;
	ready_list_add(p);
}

int sys_exit(int exit_code)
{
	dprintf("exit(%d)\n", exit_code);
	process_shutdown(current, exit_code);
	return 0;
}

int sys_exit_group(int exit_code)
{
	return sys_exit(exit_code);
}

static int internal_read(struct fdinfo *fdi, void *addr,
			size_t length, loff_t *ofs)
{
	int bytesCopied = 0;
	struct filp *fp = fdi->fp;

	if (!fp->ops->fn_read)
		return -_L(EPERM);

	while (length)
	{
		void *ptr = 0;
		size_t sz = 0;
		int r;

		r = vm_get_pointer(current, addr, &ptr, &sz);
		if (r < 0)
		{
			if (bytesCopied)
				break;
			return -_L(EFAULT);
		}

		sz = MIN(length, sz);

		r = fp->ops->fn_read(fp, ptr, sz, ofs,
				 !(fdi->flags & _L(O_NONBLOCK)));
		if (r <= 0)
		{
			if (bytesCopied)
				break;
			return r;
		}

		bytesCopied += r;
		addr = (char*) addr + r;
		length -= r;
		ofs += r;

		if (r != sz)
			break;
	}

	return bytesCopied;
}

int sys_read(int fd, void *addr, size_t length)
{
	struct fdinfo *fdi;

	dprintf("read(%d,%p,%d)\n", fd, addr, length);

	fdi = fdinfo_from_fd(fd);
	if (!fdi)
		return -_L(EBADF);

	if (!fdi->fp)
		return -_L(EBADF);

	return internal_read(fdi, addr, length, &fdi->fp->offset);
}

int sys_pread64(int fd, void *addr, size_t length, loff_t ofs)
{
	struct fdinfo *fdi;

	dprintf("pread64(%d,%p,%d,%d)\n", fd, addr, length, (int)ofs);

	fdi = fdinfo_from_fd(fd);
	if (!fdi)
		return -_L(EBADF);

	return internal_read(fdi, addr, length, &ofs);
}

int sys_write(int fd, void *addr, size_t length)
{
	struct fdinfo *fdi;
	struct filp *fp;

	dprintf("write(%d,%p,%d)\n", fd, addr, length);

	fdi = fdinfo_from_fd(fd);
	if (!fdi)
		return -_L(EBADF);

	fp = fdi->fp;
	if (!fp)
		return -_L(EBADF);

	if (!fp->ops->fn_write)
		return -_L(EPERM);

	return fp->ops->fn_write(fp, addr, length, &fp->offset,
				 !(fdi->flags & _L(O_NONBLOCK)));
}

int sys_writev(int fd, const struct iovec *ptr, int iovcnt)
{
	struct fdinfo *fdi;
	struct iovec *iov;
	int total = 0;
	struct filp *fp;
	int i, r;

	dprintf("writev(%d,%p,%d)\n", fd, ptr, iovcnt);

	fdi = fdinfo_from_fd(fd);
	if (!fdi)
		return -_L(EBADF);

	fp = fdi->fp;

	if (!fp->ops->fn_write)
		return -_L(EPERM);

	iov = alloca(iovcnt * sizeof *iov);
	if (!iov)
		return -_L(ENOMEM);

	r = current->ops->memcpy_from(iov, ptr, iovcnt * sizeof *iov);

	/* TODO:
	 * It would be better to construct an iov in write() and
	 * handle iovs in fp->ops->fn_write() instead of decode it
	 * here.
	 */
	for (i = 0; i < iovcnt; i++)
	{
		r = fp->ops->fn_write(fp, iov[i].iov_base, iov[i].iov_len,
					&fp->offset,
					!(fdi->flags & _L(O_NONBLOCK)));
		if (r < 0 && !total)
			return r;
		if (r <= 0)
			break;
		total += r;
	}

	return total;
}

void winfs_init(void);
void devfs_init(void);
void procfs_init(void);

struct fs *fs_first;

void fs_add(struct fs *fs)
{
	fs->next = fs_first;
	fs_first = fs;
}

static char *get_path(const char *file)
{
	char *path;

	if (file[0] == '/')
		return strdup(file);

	path = malloc(strlen(file) + strlen(current->cwd) + 2);

	strcpy(path, current->cwd);
	strcat(path, "/");
	strcat(path, file);

	/*
	 * FIXME: tidy path, remove:
	 *   .. . //
	 */

	return path;
}

struct filp *filp_open(const char *file, int flags, int mode, int follow_links)
{
	struct fs *fs;
	size_t len;
	char *path;
	struct filp *fp;

	path = get_path(file);

	for (fs = fs_first; fs; fs = fs->next)
	{
		len = strlen(fs->root);
		if (!strncmp(fs->root, path, len) &&
		    (path[len] == 0 || path[len] == '/'))
			break;
	}

	if (fs)
		fp = fs->open(fs, &path[len], flags, mode, follow_links);
	else
		fp = L_ERROR_PTR(ENOENT);

	free(path);

	return fp;
}

int do_open(const char *file, int flags, int mode)
{
	struct filp *fp;
	int r;
	int fd;

	fp = filp_open(file, flags, mode, 1);
	r = L_PTR_ERROR(fp);
	if (r < 0)
		return r;

	fd = alloc_fd();
	if (fd < 0)
	{
		filp_close(fp);
		return -_L(ENOMEM);
	}

	dprintf("fd %d fp %p\n", fd, fp);

	current->handles[fd].fp = fp;
	current->handles[fd].flags = flags;

	return fd;
}

int add_dirent(void *ptr, const char* entry, size_t name_len,
		int avail, unsigned long next_offset,
		char type, unsigned long ino)
{
	struct linux_dirent *de;
	int len = (name_len + 2 + sizeof *de + 3) & ~3;
	int r;
	char *t;

	de = alloca(len);
	if (len > avail)
		return -1;

	memset(de, 0, len);

	de->d_ino = ino;
	de->d_off = next_offset;
	de->d_reclen = len;
	memcpy(de->d_name, entry, name_len);
	de->d_name[name_len] = 0;
	t = (char*) de;
	t[len - 1] = type;

	dprintf("adding %s\n", de->d_name);

	r = current->ops->memcpy_to(ptr, de, len);
	if (r < 0)
		return r;

	return len;
}

int sys_getdents(int fd, struct linux_dirent *de, unsigned int count)
{
	struct filp *fp;

	dprintf("sys_getdents(%d,%p,%u)\n", fd, de, count);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (!fp->ops->fn_getdents)
		return -_L(ENOTDIR);

	return fp->ops->fn_getdents(fp, de, count, &add_dirent);
}

int add_dirent64(void *ptr, const char* entry, size_t name_len,
		int avail, unsigned long next_offset,
		char type, unsigned long ino)
{
	struct linux_dirent64 *de;
	int r;

	/* add a trailing NUL and round up to multiple of 8 */
	int len = (name_len + 1 + sizeof *de + 7) & ~7;
	if (len > avail)
		return -1;

	de = alloca(len);

	memset(de, 0, len);

	de->d_ino = ino;
	de->d_off = next_offset;
	de->d_type = type;
	de->d_reclen = len;
	memcpy(de->d_name, entry, name_len);

	dprintf("added %s\n", de->d_name);

	r = current->ops->memcpy_to(ptr, de, len);
	if (r < 0)
		return r;

	return len;
}

int sys_getdents64(int fd, struct linux_dirent *de, unsigned int count)
{
	struct filp *fp;

	dprintf("sys_getdents64(%d,%p,%u)\n", fd, de, count);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (!fp->ops->fn_getdents)
		return -_L(ENOTDIR);

	return fp->ops->fn_getdents(fp, de, count, &add_dirent64);
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
			r = vm_string_read(current, p, &strings[n]);
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

	r = vm_string_read(current, ptr, &filename);
	if (r < 0)
	{
		dprintf("open(%p=<invalid>,%08x,%08x)\n", ptr, flags, mode);
		return r;
	}

	dprintf("open(%s,%08x,%08x)\n", filename, flags, mode);

	r = do_open(filename, flags, mode);

	free(filename);

	return r;
}

int sys_creat(const char *ptr, int mode)
{
	int flags = _L(O_CREAT)|_L(O_WRONLY)|_L(O_TRUNC);
	char *filename = NULL;
	int r;

	r = vm_string_read(current, ptr, &filename);
	if (r < 0)
	{
		dprintf("creat(%p=<invalid>,%08x)\n", ptr, mode);
		return r;
	}

	dprintf("creat(%s,%08x)\n", filename, mode);

	r = do_open(filename, flags, mode);

	free(filename);

	return r;
}

static int do_openat(struct filp *dirp, const char *filename, int flags,
			int mode, int follow_links)
{
	struct filp *fp;
	int r, fd;

	if (!dirp->ops->fn_openat)
		return -_L(ENOTDIR);

	fp = dirp->ops->fn_openat(dirp, filename, flags, mode, 1);
	r = L_PTR_ERROR(fp);
	if (r < 0)
		return r;

	fd = alloc_fd();
	if (fd < 0)
	{
		filp_close(fp);
		return -_L(ENOMEM);
	}

	dprintf("fd %d fp %p\n", fd, fp);

	current->handles[fd].fp = fp;
	current->handles[fd].flags = flags;

	return fd;
}

int sys_openat(int fd, const char *ptr, int flags, int mode)
{
	char *filename = NULL;
	int r;
	struct filp *fp;

	r = vm_string_read(current, ptr, &filename);
	if (r < 0)
	{
		dprintf("openat(%p=<invalid>,%08x,%08x)\n", ptr, flags, mode);
		return r;
	}

	dprintf("openat(%d,%s,%08x,%08x)\n", fd, filename, flags, mode);

	if (fd == _L(AT_FDCWD))
	{
		fp = current->cwdfp;
		fp->refcount++;
	}
	else
	{
		fp = filp_from_fd(fd);
		if (!fp)
			return -_L(EBADF);
	}

	r = do_openat(fp, filename, flags, mode, 1);

	filp_close(fp);

	return r;
}

static int do_unlink(const char *filename)
{
	struct filp *fp;
	int r;

	dprintf("unlink(%s)\n", filename);

	fp = filp_open(filename, O_RDWR, 0, 0);
	r = L_PTR_ERROR(fp);
	if (r < 0)
		return r;

	if (fp->ops->fn_unlink)
		r = fp->ops->fn_unlink(fp);
	else
		r = -_L(EACCES);

	filp_close(fp);

	return r;
}

static int sys_unlink(const char *ptr)
{
	int r;
	char *filename = NULL;

	r = vm_string_read(current, ptr, &filename);
	if (r < 0)
	{
		dprintf("unlink(%p=<invalid>)\n", ptr);
		return r;
	}

	r = do_unlink(filename);
	free(filename);
	return r;
}

static int do_mkdir(const char *parent, const char *dir, int mode)
{
	struct filp *fp;
	int r;

	dprintf("mkdir(%s,%s,%08x)\n", parent, dir, mode);

	if (!parent)
		parent = current->cwd;

	fp = filp_open(parent, O_RDWR, 0, 1);
	r = L_PTR_ERROR(fp);
	if (r < 0)
		return r;

	if (fp->ops->fn_mkdir)
		r = fp->ops->fn_mkdir(fp, dir, mode);
	else
		r = -_L(EPERM);

	filp_close(fp);

	return r;
}

static int sys_mkdir(void *ptr, int mode)
{
	int r;
	char *dirname = NULL, *parent, *child, *p;

	r = vm_string_read(current, ptr, &dirname);
	if (r < 0)
	{
		dprintf("mkdir(%p=<invalid>)\n", ptr);
		return r;
	}

	/* split into filename and directory */
	p = strrchr(dirname, '/');
	if (p)
	{
		*p = '\0';
		p++;
		parent = dirname;
		child = p;
	}
	else
	{
		parent = NULL;
		child = dirname;
	}

	r = do_mkdir(parent, child, mode);
	free(dirname);
	return r;
}

static int do_rmdir(const char *dirname)
{
	struct filp *fp;
	int r;

	dprintf("rmdir(%s)\n", dirname);

	fp = filp_open(dirname, O_RDWR, 0, 1);
	r = L_PTR_ERROR(fp);
	if (r < 0)
		return r;

	if (fp->ops->fn_rmdir)
		r = fp->ops->fn_rmdir(fp);
	else
		r = -_L(EPERM);

	filp_close(fp);

	return r;
}

static int sys_rmdir(void *ptr)
{
	char *dirname = NULL;
	int r;

	r = vm_string_read(current, ptr, &dirname);
	if (r < 0)
	{
		dprintf("rmdir(%p=<invalid>)\n", ptr);
		return r;
	}

	r = do_rmdir(dirname);
	free(dirname);
	return r;
}

int process_close_fd(struct process *p, int fd)
{
	struct filp *fp;

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (fp->refcount < 0)
		die("reference to bad fd %d\n", fd);

	filp_close(fp);
	p->handles[fd].fp = NULL;
	p->handles[fd].flags = 0;

	return 0;
}

static int do_close(int fd)
{
	return process_close_fd(current, fd);
}

int sys_close(int fd)
{
	dprintf("close(%d)\n", fd);
	return do_close(fd);
}

int sys_llseek(unsigned int fd, unsigned long offset_high,
	unsigned long offset_low, loff_t *result, unsigned int whence)
{
	struct filp* fp;
	uint64_t pos;
	uint64_t out;
	int r;

	dprintf("llseek(%d,%lu,%lu,%p,%u)\n", fd,
		offset_high, offset_low, result, whence);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	pos = offset_low;
	pos |= ((uint64_t)offset_high << 32);

	if (whence > 2)
		return -_L(EINVAL);

	if (!fp->ops->fn_seek)
		return -_L(EPERM);

	r = fp->ops->fn_seek(fp, whence, pos, &out);
	if (r < 0)
		return r;

	return current->ops->memcpy_to(result, &out, sizeof *result);
}

int sys_lseek(unsigned int fd, long offset, unsigned int whence)
{
	int r;
	struct filp* fp;
	uint64_t out;

	dprintf("lseek(%d,%lu,%u)\n", fd, offset, whence);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (whence > 2)
		return -_L(EINVAL);

	if (!fp->ops->fn_seek)
		return -_L(EPERM);

	r = fp->ops->fn_seek(fp, whence, offset, &out);
	if (r < 0)
		return r;

	return (int) out;
}

static void gettimeval(struct timeval *tv)
{
	SYSTEMTIME st;
	FILETIME ft;
	ULONGLONG seconds;

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft);
	seconds = (((ULONGLONG)ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
	seconds /= 10LL;
	tv->tv_usec = seconds % 1000000LL;
	seconds /= 1000000LL;
	seconds -= SECS_1601_TO_1970;
	tv->tv_sec = (time_t)(seconds&0xffffffff);
}

int sys_time(time_t *tloc)
{
	struct timeval tv;

	dprintf("sys_time(%p)\n", tloc);

	timeout_now(&tv);

	if (tloc)
	{
		// TODO: How is an error returned here?
		current->ops->memcpy_to(tloc, &tv.tv_sec, sizeof tv.tv_sec);
	}

	return tv.tv_sec;
}

int sys_exec(const char *fn, const char **ap, const char **ep)
{
	int r;
	char *filename = NULL;
	char **argv = NULL;
	char **envp = NULL;

	r = vm_string_read(current, fn, &filename);
	if (r < 0)
	{
		dprintf("exec(%p=<invalid>,%p,%p)\n", fn, ap, ep);
		goto error;
	}

	r = read_string_list(&argv, ap);
	if (r < 0)
	{
		dprintf("exec(%s,%p=<invalid>,%p)\n", filename, ap, ep);
		goto error;
	}

	r = read_string_list(&envp, ep);
	if (r < 0)
	{
		dprintf("exec(%s,%p,%p=<invalid>)\n", filename, argv, ep);
		goto error;
	}

	return do_exec(filename, argv, envp);

error:
	free_string_list(argv);
	free_string_list(envp);
	free(filename);
	return r;
}

int process_getpid(struct process *p)
{
	return (int) p->id.UniqueProcess;
}

int sys_getpid(void)
{
	// FIXME: first thread is process ID.
	ULONG pid = (ULONG)current->id.UniqueProcess;
	dprintf("getpid() -> %04lx\n", pid);
	return process_getpid(current);
}

int sys_getppid(void)
{
	if (!current->parent)
		return 1;
	ULONG pid = (ULONG)current->parent->id.UniqueProcess;
	dprintf("getppid() -> %04lx\n", pid);
	return pid;
}

int sys_umask(int umask)
{
	int r = current->umask;
	current->umask = umask;
	return r;
}

int sys_kill(int pid, int sig)
{
	struct process *p;

	dprintf("kill(%d,%d)\n", pid, sig);

	p = process_find(pid);
	if (!p)
		return -_L(ESRCH);

	process_signal(p, sig);

	return 0;
}

int sys_getcwd(char *buf, unsigned long size)
{
	const char *dir = current->cwd;
	size_t len;
	int r;

	dprintf("getcwd(%p,%lu)\n", buf, size);
	len = strlen(dir) + 1;
	if (len > size)
		return -_L(ERANGE);
	r = current->ops->memcpy_to(buf, dir, len);
	if (r < 0)
		return r;
	return len;
}

static int do_chdir(const char *dir)
{
	struct filp *fp;
	int r;

	dprintf("chdir(%s)\n", dir);

	fp = filp_open(dir, O_RDONLY, 0, 1);
	r = L_PTR_ERROR(fp);
	if (r < 0)
		return r;

	/* store the directory pointer and its name */
	if (fp->ops->fn_getname)
	{
		char *name = NULL;

		r = fp->ops->fn_getname(fp, &name);
		if (r == 0)
		{
			free(current->cwd);
			current->cwd = name;
			filp_close(current->cwdfp);
			current->cwdfp = fp;
			dprintf("cwd set to %s\n", name);
		}
		else
			filp_close(fp);
	}
	else
	{
		r = -_L(ENOENT);
		filp_close(fp);
	}

	return r;
}

int sys_chdir(const void *ptr)
{
	int r;
	char *dirname = NULL;

	r = vm_string_read(current, ptr, &dirname);
	if (r < 0)
	{
		dprintf("chdir(%p=<invalid>)\n", ptr);
		return r;
	}

	r = do_chdir(dirname);

	free(dirname);

	return r;
}

void *sys_old_mmap(void *ptr)
{
	struct
	{
		void *addr;
		size_t len;
		int prot;
		int flags;
		int fd;
		off_t offset;
	} args;
	struct filp *fp = NULL;
	int r;

	dprintf("old_mmap(%p)\n", ptr);

	r = current->ops->memcpy_from(&args, ptr, sizeof args);
	if (r < 0)
		return L_ERROR_PTR(EFAULT);

	dprintf("mmap(%p,%08x,%08x,%08x,%d,%08lx)\n",
		args.addr, args.len, args.prot, args.flags, args.fd, args.offset);

	if (!(args.flags & _l_MAP_ANONYMOUS))
	{
		fp = filp_from_fd(args.fd);
		if (!fp)
			return L_ERROR_PTR(EBADF);
	}

	return vm_process_map(current, args.addr, args.len, args.prot, args.flags, fp, args.offset);
}

void* sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
	struct filp *fp = NULL;

	dprintf("mmap(%p,%08x,%08x,%08x,%d,%08lx)\n",
		addr, len, prot, flags, fd, offset);

	if (!(flags & _l_MAP_ANONYMOUS))
	{
		fp = filp_from_fd(fd);
		if (!fp)
			return L_ERROR_PTR(EBADF);
	}

	return vm_process_map(current, addr, len, prot, flags, fp, offset);
}

int sys_mprotect(void *addr, size_t len, int prot)
{
	dprintf("mprotect(%p,%08x,%08x)\n", addr, len, prot);
	return vm_process_map_protect(current, addr, len, prot);
}

int sys_gettimeofday(void *arg)
{
	struct timeval tv;
	int r;

	dprintf("sys_gettimeofday(%p)\n", arg);

	timeout_now(&tv);

	r = current->ops->memcpy_to(arg, &tv, sizeof tv);
	if (r < 0)
		return r;

	return 0;
}

int sys_munmap(void *addr, size_t len)
{
	dprintf("munmap(%p,%08x)\n", addr, len);
	return vm_process_unmap(current, addr, len);
}

int sys_socket(int domain, int type, int protocol)
{
	dprintf("socket(%d,%d,%d)\n", domain, type, protocol);

	switch (domain)
	{
	case _L(AF_INET):
		return inet4_socket(type, protocol);
	}
	return -_L(ENOSYS);
}

/* semi-documented at http://isomerica.net/~dpn/socketcall1.pdf */
int sys_socketcall(int call, unsigned long *argptr)
{
	int argcount[] = { 3, 3, 3, 2, 3, 3, 3, 4, 4, 4, 6, 6, 2, 5, 5, 3, 3 };
	unsigned long args[10];
	struct fdinfo *fdi;
	struct filp* fp;
	int r;

	dprintf("socketcall(%d,%p)\n", call, argptr);

	if (call < 1 || call > 17)
		return -_L(ENOSYS);

	r = current->ops->memcpy_from(args, argptr, sizeof args[0] * argcount[call - 1]);
	if (r < 0)
		return r;

	if (call == _L(SYS_SOCKET))
		return sys_socket(args[0], args[1], args[2]);

	fdi = fdinfo_from_fd(args[0]);
	if (!fdi)
		return -_L(EBADF);

	fp = fdi->fp;

	if (!fp->ops->fn_sockcall)
		return -_L(ENOTSOCK);

	return fp->ops->fn_sockcall(call, fp, args,
				 !(fdi->flags & _L(O_NONBLOCK)));
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
			if (p == _l_MAP_FAILED)
				dprintf("failed to extend brk\n");
			else
				current->brk = (unsigned int) target;
		}
	}
	return (void*) current->brk;
}

int sys_setuid(int uid)
{
	dprintf("setuid(%d)\n", uid);
	return 0;
}

int sys_getuid(void)
{
	dprintf("getuid() -> %d\n", current->uid);
	return current->uid;
}

int sys_geteuid(void)
{
	dprintf("geteuid() -> %d\n", current->euid);
	return current->euid;
}

int sys_setgid(int gid)
{
	dprintf("setgid(%d)\n", gid);
	return 0;
}

int sys_setreuid(int uid, int euid)
{
	dprintf("setreuid(%d, %d)\n", uid, euid);
	return 0;
}

int sys_setregid(int gid, int egid)
{
	dprintf("setregid(%d, %d)\n", gid, egid);
	return 0;
}

int sys_getgid(void)
{
	dprintf("getgid()\n");
	return current->gid;
}

int sys_getegid(void)
{
	dprintf("getegid()\n");
	return current->egid;
}

static int do_stat64(const char *file, struct stat64 *statbuf, BOOL follow_links)
{
	struct filp *fp;
	int r;

	dprintf("stat64(\"%s\",%p)\n", file, statbuf);

	fp = filp_open(file, O_RDONLY, 0, follow_links);
	r = L_PTR_ERROR(fp);
	if (r < 0)
		return r;

	if (!fp->ops->fn_stat)
		return -_L(EPERM);

	r = fp->ops->fn_stat(fp, statbuf);

	filp_close(fp);

	return r;
}

static int sys_access(const char *ptr, int mode)
{
	char *path = NULL;
	struct stat64 st;
	int r;

	r = vm_string_read(current, ptr, &path);
	if (r < 0)
	{
		dprintf("access(<invalid>,%08x)\n", mode);
		return r;
	}

	dprintf("access(\"%s\",%08x)\n", path, mode);

	r = do_stat64(path, &st, TRUE);
	if (r == 0)
	{
		if ((mode & W_OK) && !(st.st_mode & 0222))
			r = -_L(EACCES);
	}

	free(path);

	return r;
}

static int do_rename(const char *oldptr, const char *newptr)
{
	return -_L(EPERM);
}

static int sys_rename(const char *oldptr, const char *newptr)
{
	char *oldpath = NULL, *newpath = NULL;
	int r;

	r = vm_string_read(current, oldptr, &oldpath);
	if (r < 0)
		goto out;

	r = vm_string_read(current, newptr, &newpath);
	if (r < 0)
		goto out2;

	dprintf("rename(\"%s\",\"%s\")\n", oldpath, newpath);

	r = do_rename(oldptr, newptr);

	free(newpath);
out2:
	free(oldpath);
out:

	return r;
}

static void stat_from_stat64(struct stat *st, const struct stat64 *st64)
{
	memset(st, 0, sizeof *st);
#define X(field) st->st_##field = st64->st_##field;
	X(dev)
	X(ino)
	X(mode)
	X(nlink)
	X(uid)
	X(gid)
	X(rdev)
	X(size)
	X(blksize)
	X(blocks)
	X(atime)
	X(atime_nsec)
	X(mtime)
	X(mtime_nsec)
	X(ctime)
	X(ctime_nsec)
#undef X
}

int sys_stat(const char *ptr, struct stat *statbuf)
{
	struct stat64 st64;
	int r;
	char *path = NULL;

	r = vm_string_read(current, ptr, &path);
	if (r < 0)
	{
		dprintf("stat64(<invalid>,%p)\n", statbuf);
		return r;
	}

	dprintf("stat(\"%s\",%p)\n", path, statbuf);

	r = do_stat64(path, &st64, TRUE);
	if (r == 0)
	{
		struct stat st;
		stat_from_stat64(&st, &st64);
		r = current->ops->memcpy_to(statbuf, &st, sizeof st);
	}

	free(path);

	return r;
}

int sys_stat64(const char *ptr, struct stat64 *statbuf)
{
	struct stat64 st;
	int r;
	char *path = NULL;

	r = vm_string_read(current, ptr, &path);
	if (r < 0)
	{
		dprintf("stat64(<invalid>,%p)\n", statbuf);
		return r;
	}

	dprintf("stat64(\"%s\",%p)\n", path, statbuf);

	r = do_stat64(path, &st, TRUE);
	if (r == 0)
		r = current->ops->memcpy_to(statbuf, &st, sizeof st);

	free(path);

	return r;
}

int sys_ftruncate64(int fd, unsigned int offsethi, unsigned int offsetlo)
{
	uint64_t offset;
	struct filp* fp;
	int r;

	offset = offsethi;
	offset <<= 32;
	offset |= offsetlo;

	dprintf("ftruncate64(%d, %08llx)\n", fd, offset);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (!fp->ops->fn_truncate)
		return -_L(EPERM);

	r = fp->ops->fn_truncate(fp, offset);

	return r;
}

int sys_lstat64(const char *ptr, struct stat64 *statbuf)
{
	struct stat64 st;
	int r;
	char *path = NULL;

	r = vm_string_read(current, ptr, &path);
	if (r < 0)
	{
		dprintf("lstat64(<invalid>,%p)\n", statbuf);
		return r;
	}

	/* FIXME: links aren't supported */
	dprintf("lstat64(\"%s\",%p)\n", path, statbuf);

	r = do_stat64(path, &st, FALSE);
	if (r == 0)
		r = current->ops->memcpy_to(statbuf, &st, sizeof st);

	free(path);

	return r;
}

int sys_fstat(int fd, struct stat *statbuf)
{
	struct stat64 st64;
	struct filp* fp;
	int r;

	dprintf("fstat(%d,%p)\n", fd, statbuf);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (!fp->ops->fn_stat)
		return -_L(ENOENT);

	r = fp->ops->fn_stat(fp, &st64);
	if (r == 0)
	{
		struct stat st;
		stat_from_stat64(&st, &st64);
		r = current->ops->memcpy_to(statbuf, &st, sizeof st);
	}

	return r;
}

int sys_fstat64(int fd, struct stat64 *statbuf)
{
	struct stat64 st;
	struct filp* fp;
	int r;

	dprintf("fstat64(%d,%p)\n", fd, statbuf);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (!fp->ops->fn_stat)
		return -_L(ENOENT);

	r = fp->ops->fn_stat(fp, &st);
	if (r == 0)
		r = current->ops->memcpy_to(statbuf, &st, sizeof st);

	return r;
}

int sys_set_thread_area(void *ptr)
{
	struct user_desc desc;
	int r;

	dprintf("set_thread_area(%p)\n", ptr);

	r = current->ops->memcpy_from(&desc, ptr, sizeof desc);
	if (r < 0)
		return r;

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
	r = current->ops->memcpy_to(ptr, &desc, sizeof desc);
	if (r < 0)
		return r;

	return 0;
}

int sys_dup(int fd)
{
	struct filp *fp;
	int newfd;

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	newfd = alloc_fd();
	if (newfd >= 0)
	{
		struct fdinfo *fdi = &current->handles[newfd];
		fp->refcount++;
		fdi->fp = fp;
		fdi->flags = 0;
	}

	return newfd;
}

int sys_ioctl(int fd, unsigned int cmd, unsigned long arg)
{
	struct filp* fp;
	int r;

	dprintf("ioctl(%d,%08x,%lx)\n", fd, cmd, arg);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	if (!fp->ops->fn_ioctl)
		return -_L(EINVAL);

	r = fp->ops->fn_ioctl(fp, cmd, arg);

	return r;
}

/* allocate a new fd greater than 'start' */
static int sys_fcntl_fdup(struct filp *fp, int fd, int start)
{
	int newfd = alloc_fd_above(start);

	if (newfd < 0)
		return newfd;

	fp->refcount++;
	current->handles[newfd].fp = fp;
	current->handles[newfd].flags = 0;

	return newfd;
}

static int sys_fcntl_setfl(int fd, long arg)
{
	if (arg & _L(O_NONBLOCK))
		current->handles[fd].flags |= _L(O_NONBLOCK);
	else
		current->handles[fd].flags &= ~_L(O_NONBLOCK);

	if (arg & ~_L(O_NONBLOCK))
		dprintf("fcntl(): unknown fd flag %08lx\n", arg);

	return 0;
}

static int sys_fcntl_getfl(int fd)
{
	int r = current->handles[fd].flags;
	dprintf("fcntl(%d,F_GETFL) -> %08x\n", fd, r);
	return r;
}

static int do_fcntl(int fd, unsigned int cmd, unsigned long arg)
{
	struct filp* fp;
	int r;

	dprintf("fcntl(%d,%08x,%lx)\n", fd, cmd, arg);

	fp = filp_from_fd(fd);
	if (!fp)
		return -_L(EBADF);

	switch (cmd)
	{
	case _L(F_DUPFD):
		r = sys_fcntl_fdup(fp, fd, arg);
		break;
	case _L(F_SETFD):
		if (arg & _L(FD_CLOEXEC))
			current->handles[fd].flags |= _L(O_CLOEXEC);
		else
			current->handles[fd].flags &= ~_L(O_CLOEXEC);
		r = 0;
		break;
	case _L(F_GETFD):
		r = !!(current->handles[fd].flags & _L(O_CLOEXEC));
		break;
	case _L(F_GETFL):
		r = sys_fcntl_getfl(fd);
		break;
	case _L(F_SETFL):
		r = sys_fcntl_setfl(fd, arg);
		break;
	default:
		dprintf("unknown fcntl(%d, %08x, %08lx)\n",
			fd, cmd, arg);
		r = -_L(EINVAL);
	}

	return r;
}

int sys_fcntl(int fd, int cmd, long arg)
{
	dprintf("fcntl(%d,%08x,%lx)\n", fd, cmd, arg);

	return do_fcntl(fd, cmd, arg);
}

int sys_fcntl64(int fd, unsigned int cmd, unsigned long arg)
{
	dprintf("fcntl64(%d,%u,%lu)\n", fd, cmd, arg);

	return do_fcntl(fd, cmd, arg);
}

static int do_utimes(const char *filename, struct timeval *ptrtimes)
{
	struct filp *fp;
	int r;

	dprintf("utimes(%s,%p)\n", filename, ptrtimes);

	fp = filp_open(filename, O_RDWR, 0, 0);
	r = L_PTR_ERROR(fp);
	if (r < 0)
		return r;

	if (fp->ops->fn_utimes)
		r = fp->ops->fn_utimes(fp, ptrtimes);
	else
		r = -_L(EPERM);

	filp_close(fp);

	return r;
}

int sys_utimes(const char *ptr, struct timeval *ptrtimes)
{
	char *filename = NULL;
	struct timeval times[2];
	int r;

	if (ptrtimes)
	{
		r = current->ops->memcpy_from(times, ptrtimes, sizeof times);
		if (r < 0)
			return r;
		ptrtimes = times;
	}

	r = vm_string_read(current, ptr, &filename);
	if (r < 0)
	{
		dprintf("utimes(<invalid>,%p)\n", ptrtimes);
		return r;
	}

	r = do_utimes(filename, times);
	free(filename);

	return r;
}

static int do_pipe(int *fds)
{
	struct filp *fp[2];
	int r;
	int fd0, fd1;

	r = pipe_create(fp);
	if (r < 0)
		return r;

	fd0 = alloc_fd();
	if (fd0 < 0)
	{
		filp_close(fp[0]);
		filp_close(fp[1]);
		return -_L(EMFILE);
	}

	current->handles[fd0].fp = fp[0];
	current->handles[fd0].flags = 0;

	fd1 = alloc_fd();
	if (fd1 < 0)
	{
		do_close(fd0);
		filp_close(fp[1]);
		return -_L(EMFILE);
	}

	current->handles[fd1].fp = fp[1];
	current->handles[fd1].flags = 0;

	fds[0] = fd0;
	fds[1] = fd1;

	dprintf("fds[] -> %d, %d\n", fds[0], fds[1]);

	return 0;
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
		do_close(fds[0]);
		do_close(fds[1]);
	}

	return 0;
}

static struct process *find_zombie(struct process *parent)
{
	struct process *p;

	LIST_FOR_EACH(&parent->children, p, sibling)
		if (p->state == thread_terminated || p->suspended)
			return p;

	return NULL;
}

int sys_waitpid(int pid, int *stat_addr, int options)
{
	struct process *p = NULL;
	int r = -_L(ECHILD);
	int exit_code = 0;

	dprintf("waitpid(%d,%p,%08x)\n", pid, stat_addr, options);

	do {
		p = find_zombie(current);
		if (p)
			break;

		if (options & _L(WNOHANG))
		{
			r = 0;
			break;
		}

		if (process_pending_signal_check(current))
		{
			r = -_L(EINTR);
			break;
		}

		schedule();
		if (current->state == thread_terminated)
			return 0;
	} while (1);

	if (p)
	{
		/* TODO: handle WIFSIGNALED(), etc */
		int status = 0;
		status |= (p->exit_code & 0xff) << 8;
		if (p->suspended)
			status |= 0x7f;
		r = current->ops->memcpy_to(stat_addr, &status,
					 sizeof exit_code);
		if (r < 0)
			return r;
		r = (ULONG)p->id.UniqueProcess;
		if (p->state == thread_terminated)
			work_add(&zombie_reap_work);
	}

	dprintf("waitpid() -> %d\n", r);

	return r;
}

int sys_dup2(int oldfd, int newfd)
{
	struct filp* fp;

	dprintf("dup2(%d,%d)\n", oldfd, newfd);
	fp = filp_from_fd(oldfd);
	if (!fp)
		return -_L(EBADF);

	if (newfd == oldfd)
		return 0;

	if (newfd < 0 || newfd > MAX_FDS)
		return -_L(EBADF);

	fp->refcount++;

	do_close(newfd);

	current->handles[newfd].fp = fp;
	current->handles[newfd].flags = 0;

	return 0;
}

struct poll_fd_list {
	struct filp *fp;
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
		die("bad yield at %d\n", __LINE__);

	pt->timed_out = 1;
	SwitchToFiber(pt->p->fiber);
	current = p;
}

int sys_nanosleep(struct timespec *in, struct timeval *out)
{
	struct poll_timeout pt;
	struct timespec req;
	int r;

	dprintf("nanosleep(%p,%p)\n", in, out);

	r = current->ops->memcpy_from(&req, in, sizeof req);
	if (r < 0)
		return r;

	pt.t.fn = &poll_timeout_waker;
	pt.p = current;

	r = process_pending_signal_check(current);
	if (r < 0)
		return r;

	timeout_add_timespec(&pt.t, &req);
	schedule();
	timeout_remove(&pt.t);

	if (current->state == thread_terminated)
		return 0;

	if (out)
	{
		req.tv_sec = 0;
		req.tv_nsec = 0;
		current->ops->memcpy_to(out, &req, sizeof req);
	}

	if (!LIST_EMPTY(&current->signal_list))
		return -_L(EINTR);

	return 0;
}

static int poll_check(struct filp **fps, struct _l_pollfd *fds, int nfds)
{
	int ready = 0;
	int i;

	for (i = 0; i < nfds; i++)
	{
		if (fps[i])
		{
			int ev;
			if (!fps[i]->ops->fn_poll)
				continue;

			ev = fps[i]->ops->fn_poll(fps[i]);
			fds[i].revents = (ev & fds[i].events);
			if (fds[i].revents)
				ready++;
		}
		else
		{
			fds[i].revents = _L(POLLERR);
			ready++;
		}
	}
	return ready;
}

int do_poll(int nfds, struct _l_pollfd *fds, struct timeval *tv)
{
	struct wait_entry *wait_list;
	struct filp **fps;
	struct poll_timeout pt;
	int ready;
	int i;

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
	if (ready)
		return ready;

	pt.t.fn = &poll_timeout_waker;
	pt.p = current;
	pt.timed_out = 0;

	if (tv)
		timeout_add_tv(&pt.t, tv);

	for (i = 0; i < nfds; i++)
	{
		wait_list[i].p = current;
		if (fps[i]->ops->fn_poll_add)
			fps[i]->ops->fn_poll_add(fps[i], &wait_list[i]);
		else
			dprintf("%d is not pollable\n", fds[i].fd);
	}

	while (1)
	{
		ready = poll_check(fps, fds, nfds);
		if (ready || pt.timed_out)
			break;

		ready = process_pending_signal_check(current);
		if (ready)
			break;

		schedule();
		if (current->state == thread_terminated)
			return 0;
	}

	for (i = 0; i < nfds; i++)
	{
		if (fps[i]->ops->fn_poll_del)
			fps[i]->ops->fn_poll_del(fps[i], &wait_list[i]);
	}

	if (tv)
		timeout_remove(&pt.t);

	return ready;
}

int sys_poll(struct _l_pollfd *ptr, int nfds, int timeout)
{
	int r;
	int ready;
	struct _l_pollfd *fds;
	struct timeval tv = {0, 0};
	struct timeval *ptv = NULL;

	dprintf("poll(%p,%d,%d)\n", ptr, nfds, timeout);

	if (nfds < 0)
		return -_L(EINVAL);

	/* stack memory, no free needed */
	fds = alloca(nfds * sizeof fds[0]);
	memset(fds, 0, nfds * sizeof fds[0]);

	r = current->ops->memcpy_from(fds, ptr, nfds * sizeof fds[0]);
	if (r < 0)
		return r;

	if (timeout >= 0)
	{
		tv_from_ms(&tv, timeout);
		ptv = &tv;
	}

	ready = do_poll(nfds, fds, ptv);
	if (ready >= 0)
	{
		/* copy back */
		r = current->ops->memcpy_to(ptr, fds, nfds * sizeof fds[0]);
		if (r < 0)
			return r;
	}

	return ready;
}

static inline int fdset_has(struct fdset *fds, int fd)
{
	int n = sizeof fds->fds_bits[0] * 8;
	unsigned long int mask = 1 << (fd % n);
	return (fds->fds_bits[fd / n] & mask);
}

static inline void fdset_set(struct fdset *fds, int fd)
{
	int n = sizeof fds->fds_bits[0] * 8;
	unsigned long int mask = 1 << (fd % n);
	fds->fds_bits[fd / n] |= mask;
}

int do_select(int maxfd, void *rfds, void *wfds, void *efds, void *tvptr)
{
	struct fdset rdset, wrset, exset;
	int i, r, nfds, ready;
	struct _l_pollfd fds[_L(FD_SETSIZE)];
	struct timeval tv = {0, 0};

	dprintf("select(%d,%p,%p,%p,%p)\n",
		maxfd, rfds, wfds, efds, tvptr);

	if (maxfd < 0 || maxfd > _L(FD_SETSIZE))
		return -_L(EINVAL);

	if (tvptr)
	{
		r = current->ops->memcpy_from(&tv, tvptr, sizeof tv);
		if (r < 0)
			return -_L(EFAULT);
	}

	memset(&rdset, 0, sizeof rdset);
	memset(&wrset, 0, sizeof wrset);
	memset(&exset, 0, sizeof exset);

	if (rfds)
	{
		r = current->ops->memcpy_from(&rdset, rfds, sizeof rdset);
		if (r < 0)
			return -_L(EFAULT);
	}

	if (wfds)
	{
		r = current->ops->memcpy_from(&wrset, wfds, sizeof wrset);
		if (r < 0)
			return -_L(EFAULT);
	}

	if (efds)
	{
		r = current->ops->memcpy_from(&exset, efds, sizeof exset);
		if (r < 0)
			return -_L(EFAULT);
	}

	/* convert to an array of pollfds */
	nfds = 0;
	for (i = 0; i < _L(FD_SETSIZE); i++)
	{
		int events = 0;

		if (fdset_has(&rdset, i))
			events |= _l_POLLIN;
		if (fdset_has(&wrset, i))
			events |= _l_POLLOUT;
		if (fdset_has(&exset, i))
			events |= (_l_POLLERR | _l_POLLHUP);

		if (events)
		{
			fds[nfds].fd = i;
			fds[nfds].events = events;
			fds[nfds].revents = 0;
			nfds++;
		}
	}

	ready = do_poll(nfds, fds, tvptr ? &tv : NULL);
	if (ready >= 0)
	{
		memset(&rdset, 0, sizeof rdset);
		memset(&wrset, 0, sizeof wrset);
		memset(&exset, 0, sizeof exset);
		for (i = 0; i < nfds; i++)
		{
			int fd = fds[i].fd;
			if (fds[i].revents & _L(POLLIN))
				fdset_set(&rdset, fd);
			if (fds[i].revents & _L(POLLOUT))
				fdset_set(&wrset, fd);
			if (fds[i].revents & (_L(POLLERR)|_L(POLLHUP)))
				fdset_set(&exset, fd);
		}
		if (rfds)
			current->ops->memcpy_to(rfds, &rdset, sizeof rdset);
		if (wfds)
			current->ops->memcpy_to(wfds, &wrset, sizeof wrset);
		if (efds)
			current->ops->memcpy_to(efds, &exset, sizeof exset);
	}

	return ready;
}

int sys_select(void *select_args)
{
	struct {
		int nfds;
		struct fdset *rfds;
		struct fdset *wfds;
		struct fdset *efds;
		struct timeval *tv;
	} a;
	int r;

	r = current->ops->memcpy_from(&a, select_args, sizeof a);
	if (r < 0)
		return -_L(EFAULT);

	return do_select(a.nfds, a.rfds, a.wfds, a.efds, a.tv);
}

int sys_select_new(int maxfd, void *rfds, void *wfds, void *efds, void *tvptr)
{
	return do_select(maxfd, rfds, wfds, efds, tvptr);
}

static int do_symlink(const char *dir, const char *file,
			const char *newpath)
{
	struct filp *fp;
	int r;

	dprintf("do_symlink(%s,%s,%s)\n", dir, file, newpath);

	if (!dir)
		dir = current->cwd;

	fp = filp_open(dir, O_RDWR, 0, 1);
	r = L_PTR_ERROR(fp);
	if (r < 0)
		return -_L(ENOENT);

	if (fp->ops->fn_symlink)
		r = fp->ops->fn_symlink(fp, file, newpath);
	else
		r = -_L(EPERM);

	filp_close(fp);

	return r;
}

static int sys_symlink(const void *oldptr, const void *newptr)
{
	char *oldpath = NULL, *newpath = NULL, *p, *dir, *link;
	int r;

	r = vm_string_read(current, oldptr, &oldpath);
	if (r < 0)
	{
		dprintf("symlink(%p=<invalid>,%p)\n", oldptr, newptr);
		return r;
	}

	r = vm_string_read(current, newptr, &newpath);
	if (r < 0)
	{
		dprintf("symlink(%s,%p=<invalid>)\n", oldpath, newptr);
		free(oldpath);
		return r;
	}

	/* split into filename and directory */
	p = strrchr(oldpath, '/');
	if (p)
	{
		*p = '\0';
		p++;
		dir = oldpath;
		link = p;
	}
	else
	{
		dir = NULL;
		link = oldpath;
	}

	r = do_symlink(dir, link, newpath);

	free(oldpath);
	free(newpath);

	return r;
}

static int sys_link(const char *ptr1, const char *ptr2)
{
	/* TODO: can possibly support hard links on NTFS */
	dprintf("link() - hardlinks are unsupported\n");
	return -_L(EPERM);
}

static int do_readlink(const char *path, void *bufptr, size_t bufsize)
{
	char *buf = NULL;
	int r;
	struct filp *fp;

	dprintf("readlink(%s,%p,%zd)\n", path, bufptr, bufsize);

	fp = filp_open(path, O_RDONLY, 0, 0);
	r = L_PTR_ERROR(fp);
	if (r < 0)
		return r;

	if (fp->ops->fn_readlink)
	{
		r = fp->ops->fn_readlink(fp, &buf);
		if (r >= 0)
		{
			size_t len = strlen(buf);
			if (len > bufsize)
				len = bufsize;

			r = current->ops->memcpy_to(bufptr, buf, len);
			if (r == 0)
				r = len;

			free(buf);
		}
	}
	else
		r = -_L(EINVAL);

	filp_close(fp);

	return r;
}

int sys_readlink(void *pathptr, void *bufptr, size_t bufsize)
{
	char *path;
	int r;

	r = vm_string_read(current, pathptr, &path);
	if (r < 0)
	{
		dprintf("readlink(%p=<invalid>,%p,%zd)\n",
			pathptr, bufptr, bufsize);
	}

	r = do_readlink(path, bufptr, bufsize);

	free(path);

	return r;
}

int sys_newuname(struct _l_new_utsname *ptr)
{
	struct _l_new_utsname un;

	dprintf("newuname(%p)\n", ptr);
	strcpy(un.sysname, "Linux");
	strcpy(un.nodename, "atratus");
	strcpy(un.release, "2.6.36");
	strcpy(un.version, "atratus v0.1");
	strcpy(un.machine, "i686");
	strcpy(un.domainname, "(none)");

	return current->ops->memcpy_to(ptr, &un, sizeof un);
}

int sys_rt_sigaction(int sig, const struct l_sigaction *act,
		 struct l_sigaction *oact, size_t sigsetsize)
{
	struct l_sigaction sa;
	struct process *p = current;
	int r;

	memset(&sa, 0, sizeof sa);

	dprintf("rt_sigaction(%d,%p,%p,%d)\n", sig, act, oact, sigsetsize);

	if (sig == _L(SIGKILL) || sig == _L(SIGSTOP))
		return -_L(EINVAL);

	if (sig >= 0x100 || sig < 0)
		return -_L(EINVAL);

	if (oact)
	{
		r = vm_memcpy_to_process(p, oact, &p->sa[sig], sizeof sa);
		if (r < 0)
			return r;
	}

	if (act)
	{
		r = vm_memcpy_from_process(p, &sa, act, sizeof sa);
		if (r < 0)
			return r;

		dprintf("handler:  %p\n", sa.sa_handler);
		dprintf("flags:    %08lx\n", sa.sa_flags);
		dprintf("restorer: %p\n", sa.sa_restorer);

		/*
		 * set in glibc-2.15/sysdeps/unix/sysv/linux/i386/sigaction.c
		 * not returned by kernel
		 */
		sa.sa_flags &= ~_L(SA_RESTORER);

		/*
		 * TODO:
		 *  - check action flags and sanity
		 *  - observe sigsetsize
		 */

		memcpy(&p->sa[sig], &sa, sizeof sa);
	}

	return 0;
}

int sys_rt_sigprocmask(int how, const unsigned long *set, unsigned long *old)
{
	dprintf("rt_sigprocmask(%d,%p,%p)\n", how, set, old);
	if (old)
	{
		unsigned long zero = 0;
		current->ops->memcpy_to(old, &zero, sizeof zero);
	}
	return 0;
}

int sys_getpgrp(void)
{
	int pgid = process_getpid(current->leader);
	dprintf("getpgrp() -> %d\n", pgid);
	return pgid;
}

int process_is_child(struct process *parent, struct process *child)
{
	if (child == parent)
		return 0;
	while (child->parent)
	{
		if (child->parent == parent)
			return 1;
		child = child->parent;
	}
	return 0;
}

int sys_setpgid(int pid, int pgid)
{
	struct process *p;

	dprintf("setpgid(%d,%d)\n", pid, pgid);

	if (pgid < 0)
		return -_L(EINVAL);

	if (pid == 0)
		p = current;
	else
		p = process_find(pid);

	if (!p)
		return -_L(ESRCH);

	if (current != p && !process_is_child(current, p))
		return -_L(ESRCH);

	/* TODO: more checks here */

	p->leader = p;

	return 0;
}

static int do_futex_wait(unsigned int *uaddr, unsigned int val, struct timespec *ts)
{
	struct poll_timeout pt;

	dprintf("*uaddr = %08x\n", *uaddr);

	if (*uaddr != val)
		return -_L(EAGAIN);

	pt.t.fn = &poll_timeout_waker;
	pt.p = current;
	pt.timed_out = 0;

	if (ts)
		timeout_add_timespec(&pt.t, ts);

	while (*uaddr == val && !pt.timed_out)
	{
		int r;

		r = process_pending_signal_check(current);
		if (r < 0)
			return r;

		schedule();
		if (current->state == thread_terminated)
			return 0;
	}

	if (ts)
		timeout_remove(&pt.t);

	return *uaddr;
}

static int futex_wait(unsigned int *uaddr, unsigned int val, struct timespec *utime)
{
	struct timespec ts, *pts = NULL;
	void *ptr = NULL;
	size_t max_size = 0;
	int r;

	dprintf("FUTEX_WAIT %p %d %p\n", uaddr, val, utime);

	r = vm_get_pointer(current, uaddr, &ptr, &max_size);
	if (r < 0)
		return r;

	if (max_size < sizeof val)
		return -_L(EINVAL);

	if (utime)
	{
		r = vm_memcpy_from_process(current, &ts, utime, sizeof ts);
		if (r < 0)
			return r;
		pts = &ts;
	}

	return do_futex_wait(ptr, val, pts);
}

int sys_futex(unsigned int *uaddr, int op, unsigned int val,
	      struct timespec *utime, unsigned int uaddr2, unsigned int val3)
{
	dprintf("futex(%p,%d,%d,%p,%08x,%d)\n", uaddr, op, val, utime, uaddr2, val3);

	switch (op)
	{
	case _L(FUTEX_WAIT):
		return futex_wait(uaddr, val, utime);
	default:
		return -_L(ENOSYS);
	}
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
	case 8:
		r = sys_creat(ptr(a1), a2);
		break;
	case 9:
		r = sys_link(ptr(a1), ptr(a2));
		break;
	case 10:
		r = sys_unlink(ptr(a1));
		break;
	case 11:
		r = sys_exec(ptr(a1), ptr(a2), ptr(a3));
		break;
	case 12:
		r = sys_chdir(ptr(a1));
		break;
	case 13:
		r = sys_time(ptr(a1));
		break;
	case 19:
		r = sys_lseek(a1, a2, a3);
		break;
	case 20:
		r = sys_getpid();
		break;
	case 23:
		r = sys_setuid(a1);
		break;
	case 24:
		r = sys_getuid();
		break;
	case 33:
		r = sys_access(ptr(a1), a2);
		break;
	case 38:
		r = sys_rename(ptr(a1), ptr(a2));
		break;
	case 37:
		r = sys_kill(a1, a2);
		break;
	case 39:
		r = sys_mkdir(ptr(a1), a2);
		break;
	case 40:
		r = sys_rmdir(ptr(a1));
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
	case 46:
		r = sys_setgid(a1);
		break;
	case 47:
		r = sys_getgid();
		break;
	case 49:
		r = sys_geteuid();
		break;
	case 50:
		r = sys_getegid();
		break;
	case 54:
		r = sys_ioctl(a1, a2, a3);
		break;
	case 55:
		r = sys_fcntl(a1, a2, a3);
		break;
	case 57:
		r = sys_setpgid(a1, a2);
		break;
	case 60:
		r = sys_umask(a1);
		break;
	case 63:
		r = sys_dup2(a1, a2);
		break;
	case 64:
		r = sys_getppid();
		break;
	case 65:
		r = sys_getpgrp();
		break;
	case 70:
		r = sys_setreuid(a1, a2);
		break;
	case 71:
		r = sys_setregid(a1, a2);
		break;
	case 78:
		r = sys_gettimeofday(ptr(a1));
		break;
	case 82:
		r = sys_select(ptr(a1));
		break;
	case 83:
		r = sys_symlink(ptr(a1), ptr(a2));
		break;
	case 85:
		r = sys_readlink(ptr(a1), ptr(a2), a3);
		break;
	case 90:
		r = (int) sys_old_mmap(ptr(a1));
		break;
	case 91:
		r = sys_munmap(ptr(a1), a2);
		break;
	case 102:
		r = sys_socketcall(a1, ptr(a2));
		break;
	case 106:
		r = sys_stat(ptr(a1), ptr(a2));
		break;
	case 108:
		r = sys_fstat(a1, ptr(a2));
		break;
	case 120:
		r = sys_clone(a1, ptr(a2), ptr(a3), a4, ptr(a5));
		break;
	case 122:
		r = sys_newuname(ptr(a1));
		break;
	case 125:
		r = sys_mprotect(ptr(a1), a2, a3);
		break;
	case 140:
		r = sys_llseek(a1, a2, a3, ptr(a4), a5);
		break;
	case 141:
		r = sys_getdents(a1, ptr(a2), a3);
		break;
	case 142:
		r = sys_select_new(a1, ptr(a2), ptr(a3), ptr(a4), ptr(a5));
		break;
	case 146:
		r = sys_writev(a1, ptr(a2), a3);
		break;
	case 162:
		r = sys_nanosleep(ptr(a1), ptr(a2));
		break;
	case 168:
		r = sys_poll(ptr(a1), a2, a3);
		break;
	case 174:
		r = sys_rt_sigaction(a1, ptr(a2), ptr(a3), a4);
		break;
	case 175:
		r = sys_rt_sigprocmask(a1, ptr(a2), ptr(a3));
		break;
	case 180:
		r = sys_pread64(a1, ptr(a2), a3, a4);
		break;
	case 183:
		r = sys_getcwd(ptr(a1), a2);
		break;
	case 192:
		r = (int) sys_mmap(ptr(a1), a2, a3, a4, a5, a6);
		break;
	case 194:
		r = sys_ftruncate64(a1, a2, a3);
		break;
	case 195:
		r = sys_stat64(ptr(a1), ptr(a2));
		break;
	case 196:
		r = sys_lstat64(ptr(a1), ptr(a2));
		break;
	case 197:
		r = sys_fstat64(a1, ptr(a2));
		break;
	case 199:
		r = sys_getuid();
		break;
	case 200:
		r = sys_getgid();
		break;
	case 201:
		r = sys_geteuid();
		break;
	case 204:
		r = sys_setregid(a1, a2);
		break;
	case 213:
		r = sys_setuid(a1);
		break;
	case 214:
		r = sys_setgid(a1);
		break;
	case 220:
		r = sys_getdents64(a1, ptr(a2), a3);
		break;
	case 221:
		r = sys_fcntl64(a1, a2, a3);
		break;
	case 240:
		r = sys_futex(ptr(a1), a2, a3, ptr(a4), a5, a6);
		break;
	case 243:
		r = sys_set_thread_area(ptr(a1));
		break;
	case 252:
		r = sys_exit_group(a1);
		break;
	case 271:
		r = sys_utimes(ptr(a1), ptr(a2));
		break;
	case 295:
		r = sys_openat(a1, ptr(a2), a3, a4);
		break;
	default:
		dprintf("unknown/invalid system call %d (%08x)\n", n, n);
		r = -_L(ENOSYS);
	}

	if (r < 0)
		dprintf("syscall %d returned %d\n", n, r);

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

void process_continue(struct process *p)
{
	NTSTATUS r;

	process_deliver_signal(p);
	while (p->suspended && p->state != thread_terminated)
	{
		schedule();
		process_deliver_signal(p);
	}
	if (p->state == thread_terminated)
		return;

	p->regs.ContextFlags = CONTEXT_i386 | CONTEXT_FULL;
	r = NtSetContextThread(p->thread, &p->regs);
	if (r != STATUS_SUCCESS)
	{
		process_shutdown(p, _L(SIGSEGV));
		return;
	}

	if (p->state == thread_ready)
	{
		p->state = thread_running;
		r = pDbgUiContinue(&p->id, DBG_CONTINUE);
		if (r != STATUS_SUCCESS)
			process_shutdown(p, _L(SIGSEGV));
	}
}

static NTSTATUS OnDebuggerException(DEBUGEE_EVENT *event,
					struct process *context)
{
	EXCEPTION_RECORD *er = &event->Exception.ExceptionRecord;

	if (ELEMENT_IN_LIST(context, remote_break_item))
	{
		context->state = thread_interrupted;
		SwitchToFiber(context->fiber);
		return STATUS_SUCCESS;
	}

	context->state = thread_ready;

	if (er->ExceptionCode == STATUS_ACCESS_VIOLATION)
	{
		CONTEXT *regs = &context->regs;
		unsigned char buffer[2];

		if (0 > vm_memcpy_from_process(context, buffer,
					(void*) context->regs.Eip, sizeof buffer))
		{
			dprintf("failed to read instruction at %08lx\n",
				context->regs.Eip);
			process_signal(context, _L(SIGSEGV));
		}
		if (buffer[0] == 0xcd && buffer[1] == 0x80)
		{
			/* fork() relies on pre-increment here */
			regs->Eip += 2;
			SwitchToFiber(context->fiber);
			/* syscall fiber will continue the client thread */
			return STATUS_SUCCESS;
		}
		else if (!emulate_instruction(context, buffer))
		{
			dprintf("invalid instruction at %08lx\n",
				context->regs.Eip);
			/* queue a SIGILL */
			process_signal(context, _L(SIGILL));
		}

	}
	else
	{
		process_signal(context, _L(SIGILL));
	}

	process_continue(context);
	return STATUS_SUCCESS;
}

static NTSTATUS OnDebuggerBreakpoint(DEBUGEE_EVENT *event,
					struct process *context)
{
	// hook ptrace into here
	die("Breakpoint...\n");

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

NTSTATUS DebugCheckRemoteBreaks(void)
{
	NTSTATUS r;
	struct process *p;

	for (p = LIST_HEAD(&remote_break_list); p; )
	{
		struct process *next = LIST_NEXT(p, remote_break_item);

		r = read_process_registers(p);
		if (r == STATUS_SUCCESS)
		{
			current = p;
			dprintf("interrupted!\n");
			LIST_REMOVE(&remote_break_list, p, remote_break_item);
			if (p->state == thread_running)
				p->state = thread_interrupted;
			else
				dprintf("not running, state = %d\n", p->state);
			SwitchToFiber(p->fiber);
		}

		p = next;
	}

	return STATUS_SUCCESS;
}

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
		return STATUS_SUCCESS;

	if (r == STATUS_USER_APC)
		return STATUS_SUCCESS;

	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "DbgUiWaitStateChange() r=%08lx\n", r);
		return r;
	}

	if (event.NewState > sizeof handlers/sizeof handlers[0])
		return STATUS_UNSUCCESSFUL;

	context = context_from_client_id(&event.ClientId);
	if (!context)
	{
		dprintf("received event for unknown process %08x:%08x\n",
			(UINT)event.ClientId.UniqueProcess,
			(UINT)event.ClientId.UniqueThread);

		return DebugCheckRemoteBreaks();
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
	struct process *p = param;
	current = p;

	while (p->state != thread_terminated)
	{
		CONTEXT *regs = &p->regs;
		ULONG r;

		/* stopped by a signal or a syscall? */
		if (p->state != thread_interrupted)
		{
			if (regs->Eax == 119)
				sys_sigreturn();
			else if (regs->Eax == 173)
				sys_rt_sigreturn();
			else
			{
				r = do_syscall(regs->Eax, regs->Ebx,
						regs->Ecx, regs->Edx,
						regs->Esi, regs->Edi,
						regs->Ebp);
				regs->Eax = r;
			}

			if (p->state == thread_terminated)
				break;
		}
		else
			p->state = thread_ready;

		process_continue(p);
		if (p->state == thread_terminated)
			break;

		yield();
	}

	dprintf("%p: freeing resources\n", p);
	/* shutdown here */
	pNtRemoveProcessDebug(p->process, debugObject);
	NtTerminateThread(p->thread, 0);
	CloseHandle(p->thread);
	NtTerminateProcess(p->process, 0);
	CloseHandle(p->process);
	p->suspended = false;
	close_fd_set(p);
	vm_mappings_free(p);
	signal_queue_free(p);
	ready_list_remove(p);

	if (!p->parent)
		work_add(&zombie_reap_work);
	else
		process_signal(p->parent, _L(SIGCHLD));

	/* exiting from this fiber would cause the main thread to exit */
	SwitchToFiber(wait_fiber);
}

NTSTATUS create_first_thread(struct process *p)
{
	NTSTATUS r;

	p->fiber = CreateFiber(0, &SyscallHandler, p);
	if (!p->fiber)
		return STATUS_UNSUCCESSFUL;

	/* create a thread to run in the process */
	p->regs.ContextFlags = CONTEXT_FULL;
	r = NtCreateThread(&p->thread, THREAD_ALL_ACCESS, NULL,
			 p->process, &p->id,
			 &p->regs, &p->stack_info, FALSE);
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

static BOOL Is64Bit(void)
{
	BOOL (WINAPI *pfnIsWow64)(HANDLE, PBOOL);
	PVOID k32;
	BOOL wow64 = FALSE;
	BOOL r;

	k32 = GetModuleHandle("kernel32");
	if (!k32)
		return FALSE;

	pfnIsWow64 = GetProcAddress(k32, "IsWow64Process");
	if (!pfnIsWow64)
		return FALSE;

	r = pfnIsWow64(GetCurrentProcess(), &wow64);
	if (!r)
		return FALSE;

	dprintf("wow64 = %d\n", wow64);

	return wow64;
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

static void process_migrate_children_to_parent(struct process *p)
{
	struct process *t;

	if (!p->parent)
		return;

	if (p->parent == p)
		return;

	/* migrate all children to parent of exitting process */
	while ((t = LIST_HEAD(&p->children)))
	{
		/* remove from this process */
		LIST_REMOVE(&p->children, t, sibling);

		/* add as parent's child */
		LIST_APPEND(&p->parent->children, t, sibling);
	}
}

static void process_unlink_from_sibling_list(struct process *process)
{
	if (!process->parent)
		return;

	LIST_REMOVE(&process->parent->children, process, sibling);
}

void process_free(struct process *process)
{
	dprintf("freeing process %p\n", process);
	process_migrate_children_to_parent(process);
	process_unlink_from_sibling_list(process);
	DeleteFiber(process->fiber);
	free(process->cwd);
	process->cwd = NULL;
	filp_close(process->cwdfp);
	process->cwdfp = NULL;
	free(process);
}

void yield(void)
{
	struct process *p = current;
	if (GetCurrentFiber() == wait_fiber)
	{
		die("bad yield at %d\n", __LINE__);
	}
	SwitchToFiber(wait_fiber);
	current = p;
}

void schedule(void)
{
	if (current->state == thread_terminated)
		return;
	current->state = thread_stopped;
	yield();
	if (current->state != thread_terminated)
		current->state = thread_ready;
}

/*
 * list of fibers ready to run
 * Singly linked with the last entry pointing to itself
 * Can be added from anywhere.
 * Always woken from the main loop
 */
static CRITICAL_SECTION ready_list_lock;
LIST_ANCHOR(struct process)	ready_list;

/* this needs to be done from the main loop's context */
static void process_ready_list(void)
{
	while (1)
	{
		EnterCriticalSection(&ready_list_lock);
		struct process *p = NULL;
		if (!LIST_EMPTY(&ready_list))
		{
			p = LIST_HEAD(&ready_list);
			LIST_REMOVE(&ready_list, p, ready_item);
		}
		LeaveCriticalSection(&ready_list_lock);
		if (!p)
			break;
		if (p->state != thread_terminated)
			SwitchToFiber(p->fiber);
	}
}

void ready_list_remove(struct process *p)
{
	EnterCriticalSection(&ready_list_lock);
	if (ELEMENT_IN_LIST(p, ready_item))
		LIST_REMOVE(&ready_list, p, ready_item);
	LeaveCriticalSection(&ready_list_lock);
}

void ready_list_add(struct process *p)
{
	if (!p)
		return;

	EnterCriticalSection(&ready_list_lock);

	/* first_ready is alway non-null if in ready list */
	if (!ELEMENT_IN_LIST(p, ready_item))
	{
		LIST_APPEND(&ready_list, p, ready_item);
	}

	LeaveCriticalSection(&ready_list_lock);
	SetEvent(loop_event);
}

void process_queue_signal(struct process *p, int signal)
{
	struct sigqueue *sq;

	dprintf("%s(%p,%d)\n", __FUNCTION__, p, signal);
	/* TODO: only real time signals should be queued */

	sq = malloc(sizeof (struct sigqueue));
	sq->signal = signal;

	LIST_ELEMENT_INIT(sq, item);

	LIST_APPEND(&p->signal_list, sq, item);

	if (p->state == thread_stopped)
		ready_list_add(p);
	else
		dprintf("%p not stopped (state %d)\n", p, p->state);
}

void signal_queue_free(struct process *p)
{
	struct sigqueue *sq;
	while ((sq = LIST_HEAD(&p->signal_list)))
	{
		LIST_REMOVE(&p->signal_list, sq, item);
		free(sq);
	}
}

void signal_handle_default(struct process *p, int signal)
{
	/* see signal(7) */
	switch (signal)
	{
	case _L(SIGCHLD):
		break;
	case _L(SIGTSTP):
	case _L(SIGTTIN):
	case _L(SIGTTOU):
		p->suspended = true;
		break;
	default:
		process_shutdown(p, signal);
	}
}

struct ucontext
{
	uint16_t gs;
	uint16_t fs;
	uint16_t es;
	uint16_t ds;
	uint32_t edi;
	uint32_t esi;
	uint32_t ebp;
	uint32_t esp;
	uint32_t ebx;
	uint32_t edx;
	uint32_t ecx;
	uint32_t eax;
	uint32_t trapno;
	uint32_t err;
	uint32_t eip;
	uint16_t cs;
	uint32_t eflags;
	uint32_t esp_at_signal;
	uint16_t ss;
	void *fpustate;
	uint32_t oldmask;
	uint32_t cr2;
};

void signal_ucontext_from_process(struct process *p, struct ucontext *uc)
{
#define COPY(LR, WR) uc->LR = p->regs.WR
	COPY(gs, SegGs);
	COPY(fs, SegFs);
	COPY(es, SegEs);
	COPY(ds, SegDs);
	COPY(edi, Edi);
	COPY(esi, Esi);
	COPY(ebp, Ebp);
	COPY(esp, Esp);
	COPY(ebx, Ebx);
	COPY(edx, Edx);
	COPY(ecx, Ecx);
	COPY(eax, Eax);
	COPY(cs, SegCs);
	COPY(ss, SegSs);
	COPY(eip, Eip);
	COPY(eflags, EFlags);
#undef COPY
}

void signal_ucontext_to_process(struct process *p, struct ucontext *uc)
{
#define COPY(LR, WR) p->regs.WR = uc->LR
	COPY(gs, SegGs);
	COPY(fs, SegFs);
	COPY(es, SegEs);
	COPY(ds, SegDs);
	COPY(edi, Edi);
	COPY(esi, Esi);
	COPY(ebp, Ebp);
	COPY(esp, Esp);
	COPY(ebx, Ebx);
	COPY(edx, Edx);
	COPY(ecx, Ecx);
	COPY(eax, Eax);
	COPY(cs, SegCs);
	COPY(ss, SegSs);
	COPY(eip, Eip);
	COPY(eflags, EFlags);
#undef COPY
}

struct signal_stack_layout {
	void *ret;
	int signo;
	struct ucontext uc;
};

void sys_sigreturn(void)
{
	struct process *p = current;
	struct signal_stack_layout frame;
	void *stack;
	int r;

	dprintf("%s()\n", __FUNCTION__);

	stack = (void*)(p->regs.Esp - 8);

	r = vm_memcpy_from_process(p, &frame, stack, sizeof frame);
	if (r < 0)
	{
		dprintf("%s: can't read signal stack\n", __FUNCTION__);
		process_shutdown(p, _L(SIGSEGV));
	}

	signal_ucontext_to_process(p, &frame.uc);
}

struct sigaction_stack_layout {
	void *ret;
	int signo;
	struct l_siginfo_t *si_ptr;
	struct ucontext *uc_ptr;
	struct l_siginfo_t si;
	struct ucontext uc;
};

void sys_rt_sigreturn(void)
{
	struct process *p = current;
	struct sigaction_stack_layout frame;
	void *stack;
	int r;

	dprintf("%s(esp=%08lx)\n", __FUNCTION__, p->regs.Esp);

	stack = (void*)(p->regs.Esp - 4);

	r = vm_memcpy_from_process(p, &frame, stack, sizeof frame);
	if (r < 0)
	{
		dprintf("%s: can't read signal stack\n", __FUNCTION__);
		process_shutdown(current, _L(SIGSEGV));
	}

	signal_ucontext_to_process(p, &frame.uc);
}

/*
 * http://syprog.blogspot.com.au/2011/10/iterfacing-linux-signals.html
 * http://housel.livejournal.com/1557.html
 */
void signal_push_on_stack(struct process *p, struct sigqueue *sq)
{
	uint8_t *stack;
	int r;

	stack = (void*) p->regs.Esp;

	if (p->sa[sq->signal].sa_flags & _L(SA_SIGINFO))
	{
		struct sigaction_stack_layout frame = {0};
		stack -= sizeof frame;

		frame.si_ptr = &(((struct sigaction_stack_layout*) stack)->si);
		frame.uc_ptr = &(((struct sigaction_stack_layout*) stack)->uc);

		signal_ucontext_from_process(p, &frame.uc);

		frame.ret = p->sa[sq->signal].sa_restorer;
		frame.signo = sq->signal;
		frame.si.si_signo = sq->signal;
		r = vm_memcpy_to_process(p, stack, &frame, sizeof frame);
		if (r < 0)
		{
			process_shutdown(p, _L(SIGSEGV));
			return;
		}
	}
	else
	{
		struct signal_stack_layout frame = {0};
		stack -= sizeof frame;

		signal_ucontext_from_process(p, &frame.uc);

		frame.ret = p->sa[sq->signal].sa_restorer;
		frame.signo = sq->signal;
		r = vm_memcpy_to_process(p, stack, &frame, sizeof frame);
		if (r < 0)
		{
			process_shutdown(p, _L(SIGSEGV));
			return;
		}
	}

	p->regs.Eip = (uintptr_t) p->sa[sq->signal].sa_handler;
	p->regs.Esp = (uintptr_t) stack;
	dprintf("Entering signal handler at %p stack at %p\n",
		p->sa[sq->signal].sa_handler, stack);
}

void process_deliver_signal(struct process *p)
{
	struct sigqueue *sq;

	sq = LIST_HEAD(&p->signal_list);
	if (!sq)
		return;
	LIST_REMOVE(&p->signal_list, sq, item);

	if (p->sa[sq->signal].sa_handler == _L(SIG_DFL))
	{
		dprintf("signal %d: default action\n", sq->signal);
		signal_handle_default(p, sq->signal);
	}
	else if (p->sa[sq->signal].sa_handler == _L(SIG_IGN))
	{
		dprintf("signal %d: ignored\n", sq->signal);
	}
	else
	{
		dprintf("signal %d: delivering\n", sq->signal);
		signal_push_on_stack(p, sq);
	}

	free(sq);
}

int process_pending_signal_check(struct process *p)
{
	/* TODO: check masks */
	if (!LIST_EMPTY(&p->signal_list))
		return -_L(EINTR);
	return 0;
}

void process_signal(struct process *p, int signal)
{
	bool was_running;

	if (!p)
		return;

	if (signal < 0 || signal >= 0x100)
		die("signal %d out of range\n", signal);

	if (p->state == thread_terminated)
		return;

	was_running = (p->state == thread_running);

	p->exit_code = signal;
	switch (signal)
	{
	case _L(SIGKILL):
		process_shutdown(p, signal);
		break;
	case _L(SIGSTOP):
		p->suspended = true;
		break;
	case _L(SIGCONT):
		p->suspended = false;
		break;
	default:
		process_queue_signal(p, signal);
	}

	if (was_running && !ELEMENT_IN_LIST(p, remote_break_item))
	{
		NTSTATUS r;

		/* issue a break */
		dprintf("remote break!\n");
		r = pDbgUiIssueRemoteBreakin(p->process);
		if (r != STATUS_SUCCESS)
			die("DbgUiIssueRemoteBreakin failed %08lx\n", r);
		LIST_APPEND(&remote_break_list, p, remote_break_item);
	}
}

extern void process_signal_group(struct process *leader, int signal)
{
	struct process *p;

	LIST_FOR_EACH(&process_list, p, item)
		if (p->leader == leader || p == leader)
			process_signal(p, signal);
}

LIST_ANCHOR(struct timeout) timeout_list;

void timeout_now(struct timeval *tv)
{
	gettimeval(tv);
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
	t->tv.tv_sec = now.tv_sec + ts->tv_sec;
	t->tv.tv_sec += t->tv.tv_usec / (1000 * 1000);
	t->tv.tv_usec %= (1000 * 1000);

	timeout_add(t);
}

void timeout_add_timespec(struct timeout *t, struct timespec *ts)
{
	struct timeval now;

	timeout_now(&now);

	t->tv.tv_usec = now.tv_usec + (ts->tv_nsec+999)/1000;
	t->tv.tv_sec = now.tv_sec + ts->tv_sec;
	t->tv.tv_sec += t->tv.tv_usec / (1000 * 1000);
	t->tv.tv_usec %= (1000 * 1000);

	timeout_add(t);
}

void tv_from_ms(struct timeval *tv, int ms)
{
	tv->tv_usec = (ms % 1000) * 1000;
	tv->tv_sec = (ms / 1000);
}

void timeout_add_ms(struct timeout *t, int ms)
{
	struct timeval tv;
	tv_from_ms(&tv, ms);
	timeout_add_tv(t, &tv);
}

void timeout_add(struct timeout *t)
{
	LIST_ELEMENT_INIT(t, item);
	LIST_INSERT_ORDERED(&timeout_list, t, timeout_before, item);
	LIST_ASSERT_ORDERED(&timeout_list, timeout_before, item);
}

void timeout_remove(struct timeout *t)
{
	LIST_REMOVE(&timeout_list, t, item);
}

DWORD timeout_get_next(void)
{
	struct timeval now;
	int t;
	struct timeout *to = LIST_HEAD(&timeout_list);

	if (!to)
		return INFINITE;

	timeout_now(&now);
	t = (to->tv.tv_usec - now.tv_usec + 999) / 1000;
	t += (to->tv.tv_sec - now.tv_sec) * 1000;

	if (0)
	{
		timeout_dprint_timeval(&now, "now");
		timeout_dprint_timeval(&to->tv, "next");
		dprintf("timeout -> %d\n", t);
	}

	if (t < 0)
		t = 0;

	return t;
}

void timeout_handle(void)
{
	struct timeout *to = LIST_HEAD(&timeout_list);
	to->fn(to);
}

LIST_ANCHOR(struct workitem) workitem_list;

void work_add(struct workitem *item)
{
	EnterCriticalSection(&ready_list_lock);
	LIST_APPEND(&workitem_list, item, item);
	LeaveCriticalSection(&ready_list_lock);
	SetEvent(loop_event);
}

void work_process(void)
{
	while (true)
	{
		struct workitem *item;
		EnterCriticalSection(&ready_list_lock);
		item = LIST_HEAD(&workitem_list);
		if (item)
			LIST_REMOVE(&workitem_list, item, item)
		LeaveCriticalSection(&ready_list_lock);
		if (!item)
			break;

		item->fn(item);
	}
}

static void dump_selectors(void)
{
	DESCRIPTOR_TABLE_ENTRY info;
	NTSTATUS r;
	int i;

	STATIC_ASSERT(sizeof (NT_LDT_ENTRY) == 8);

	printf("Process selectors:\n");
	for (i = 0; i < 0x40; i++)
	{
		info.Selector = i;
		r = NtQueryInformationThread(NtCurrentThread(),
			ThreadDescriptorTableEntry, &info, sizeof info, NULL);
		if (r == STATUS_SUCCESS)
		{
			ULONG *Value = (void*) &info.Descriptor;
			printf("selector %04x -> %08x %08x\n", i,
				Value[0], Value[1]);
		}
	}
}

int main(int argc, char **argv)
{
	HANDLE debugObject = 0;
	NTSTATUS r;
	struct process *p = alloc_process();
	int n = 1;
	HANDLE console_in, console_out;
	HANDLE inet4_handle;
	DWORD console_mode = 0;
	BOOL backtrace_on_ctrl_c = 0;
	char *env[16];
	int envcount = 0;

	if (!dynamic_resolve())
	{
		fprintf(stderr, "resolve failed\n");
		return 1;
	}

	if (Is64Bit())
	{
		if (0)
			dump_selectors();
		fprintf(stderr, "Atratus doesn't work on 64-bit windows as yet\n");
		fprintf(stderr, "Press enter to continue...\n");
		getchar();
		return 0;
	}

	vm_init();

	p->cwd = strdup("/");
	p->uid = 1000;
	p->gid = 1000;
	p->euid = 1000;
	p->egid = 1000;

	InitializeCriticalSection(&ready_list_lock);

	loop_event = CreateEvent(NULL, 0, 0, NULL);

	/* the initial environment */
	env[envcount++] = "DISPLAY=:0";
	env[envcount++] = "TERM=vt100";
	env[envcount++] = "PS1=$ ";
	env[envcount++] = "PATH=/usr/local/bin:/usr/bin:/bin";
	env[envcount] = NULL;

	get_stub_name();

	debug_init();
	while (n < argc)
	{
		if (!strcmp(argv[n], "-d"))
		{
			debug_set_verbose(1);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "-D") && (n + 1) < argc)
		{
			debug_set_verbose(1);
			debug_set_file(argv[n+1]);
			n += 2;
			continue;
		}

		if (!strcmp(argv[n], "-c"))
		{
			backtrace_on_ctrl_c = 1;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "-e") && (n + 1) < argc)
		{
			if ((envcount + 1) >= sizeof env/sizeof env[0])
			{
				fprintf(stderr, "Too many environment variables");
				return 1;
			}
			if (!strchr(argv[n+1], '='))
			{
				fprintf(stderr, "To set environment, use: -e FOO=bar");
				return 1;
			}
			env[envcount++] = argv[n+1];
			env[envcount] = NULL;
			n += 2;
			continue;
		}

		break;
	}

	if (n >= argc)
	{
		fprintf(stderr, "usage: %s prog ...\n", argv[0]);
		return 1;
	}

	/*
	 * Logging should be enabled at this point
	 */
	inet4_handle = inet4_init();
	winfs_init();
	devfs_init();
	procfs_init();

	p->cwdfp = filp_open(p->cwd, O_RDONLY, 0, 0);
	if (L_PTR_ERROR(p->cwdfp) < 0)
	{
		fprintf(stderr,
			"Failed to open current working directory (%s)\n",
			p->cwd);
		goto out;
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
	current = p;
	r = create_nt_process(p, debugObject);
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "create_nt_process failed with error %08lx\n", r);
		goto out;
	}

	/*
	 * check if stdout is actually a console or not and
	 * allocate a console for the first process only
	 */
	console_in = GetStdHandle(STD_INPUT_HANDLE);
	console_out = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!GetConsoleMode(console_out, &console_mode))
		fprintf(stderr, "output not a console...\n");

	/* PGID of leader is its own PID */
	p->leader = p;
	current->tty = get_vt100_console(console_in, console_out, p->leader);

	p->handles[0].fp = current->tty;
	p->handles[0].flags = 0;
	p->tty->refcount++;

	p->handles[1].fp = current->tty;
	p->handles[1].flags = 0;
	p->tty->refcount++;

	p->handles[2].fp = current->tty;
	p->handles[2].flags = 0;
	current->tty->refcount++;

	/* move exec into fiber */
	r = do_exec(argv[n], argv + n, env);
	if (r < 0)
	{
		fprintf(stderr, "Failed to start \'%s\'\n", argv[n]);
		goto out;
	}

	r = create_first_thread(p);
	if (r != STATUS_SUCCESS)
	{
		fprintf(stderr, "create_first_thread() failed: %08lx\n", r);
		goto out;
	}

	/*
	 * For simplicity, the concurrency model is based on fibers.
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

	while (!LIST_EMPTY(&process_list))
	{
		HANDLE handles[4];
		int n = 0;
		DWORD timeout;

		handles[n++] = debugObject;
		handles[n++] = loop_event;
		handles[n++] = inet4_handle;

		timeout = timeout_get_next();

		r = MsgWaitForMultipleObjectsEx(n, handles, timeout,
					QS_ALLEVENTS, MWMO_ALERTABLE);
		if (r == (WAIT_OBJECT_0))
		{
			r = ReadDebugPort(debugObject);
			if (r != STATUS_SUCCESS)
				break;
		}
		else if (r == (WAIT_OBJECT_0 + 2))
		{
			inet4_process_events();
		}
		else if (r == WAIT_TIMEOUT)
		{
			timeout_handle();
		}

		/* pump the message loop until there's no more messages */
		while (1)
		{
			MSG msg;

			if (!PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
				break;
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}

		/* process work items in the main thread */
		work_process();

		/* wake fibers that are ready, in context of main loop */
		process_ready_list();
	}

out:
	while (!LIST_EMPTY(&process_list))
	{
		struct process *p = LIST_HEAD(&process_list);
		LIST_REMOVE(&process_list, p, item);
		process_free(p);
	}

	CloseHandle(debugObject);

	return 0;
}
