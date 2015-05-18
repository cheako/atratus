/*
 * Virtual Memory handling
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

#include "linux-errno.h"
#include "linux-defines.h"
#include "filp.h"
#include "process.h"
#include "minmax.h"
#include "debug.h"
#include "ntstatus.h"
#include "vm.h"

static HANDLE vm_section;
static uint64_t vm_offset;
static uint32_t vm_maxsize = 0x10000000;
static PVOID vm_address;

struct vm_mapping
{
	LIST_ELEMENT(struct vm_mapping, item);
	user_ptr_t              address;
	user_size_t		size;
	uint64_t		offset;
	int			protection[];
};

static void vm_mem_state_to_string(DWORD State, char *string)
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

static void vm_mem_protect_to_string(DWORD Protect, char *string)
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

static int vm_get_protection(int prot)
{
	DWORD Protection = PAGE_NOACCESS;
	if (prot & _l_PROT_EXEC)
		Protection = PAGE_EXECUTE_READWRITE;
	else if (prot & _l_PROT_WRITE)
		Protection = PAGE_READWRITE;
	else if (prot & _l_PROT_READ)
		Protection = PAGE_READONLY;
	return Protection;
}

void vm_init(void)
{
	OBJECT_ATTRIBUTES oa;
	NTSTATUS r;
	LARGE_INTEGER Size;
	LARGE_INTEGER Offset;
	SIZE_T mapped_size = 0;

	Size.QuadPart = vm_maxsize;

	memset(&oa, 0, sizeof oa);
	oa.Length = sizeof oa;
	oa.RootDirectory = NULL;
	oa.ObjectName = NULL;
	oa.Attributes = OBJ_CASE_INSENSITIVE;

	r = NtCreateSection(&vm_section, SECTION_ALL_ACCESS, &oa, &Size,
				PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0);
	if (r != STATUS_SUCCESS)
	{
		die("NtCreateSection failed (%08lx:%s)\n",
			r, ntstatus_to_string(r));
	}

	Offset.QuadPart = 0;
	r = NtMapViewOfSection(vm_section, NtCurrentProcess(),
				&vm_address, 0, 0, &Offset,
				&mapped_size, N(ViewUnmap), 0, PAGE_READWRITE);
	if (r != STATUS_SUCCESS)
	{
		die("NtMapViewOfSection failed (%08lx:%s)\n",
			r, ntstatus_to_string(r));
	}

	dprintf("Mapped %08lx bytes at %p\n", (ULONG)mapped_size, vm_address);
}

void vm_mappings_copy(struct process *to, struct process *from)
{
	struct vm_mapping *m, *mapping;
	NTSTATUS r;
	PVOID Address;
	SIZE_T Size;
	LARGE_INTEGER Offset;
	ULONG Protection;
	ULONG old_prot;
	int i;

	LIST_FOR_EACH(&from->mapping_list, m, item)
	{
		char *pto, *pfrom;
		int page_count = (m->size + 0xfff)/0x1000;

		mapping = malloc(sizeof *mapping + page_count * sizeof(int));

		mapping->address = m->address;
		mapping->size = m->size;
		mapping->offset = vm_offset;
		for (i = 0; i < page_count; i++)
			mapping->protection[i] = m->protection[i];
		vm_offset += m->size;

		if (vm_offset & 0xffff)
			die("vm: bad offset @%d!\n", __LINE__);
		if (vm_offset > vm_maxsize)
			die("vm: out of memory at %d\n", __LINE__);
		LIST_ELEMENT_INIT(mapping, item);
		LIST_APPEND(&to->mapping_list, mapping, item);

		/*
		 * Copy the mapping.
		 * TODO: Copy on write
		 */
		pto = (char*)vm_address + mapping->offset;
		pfrom = (char*)vm_address + m->offset;

		dprintf("%p -> %p (%08x)\n", pfrom, pto, m->size);

		memcpy(pto, pfrom, m->size);

		dprintf("Copying mapping %08x bytes at %08x, offset=%08lx\n",
			mapping->size, mapping->address,
			(unsigned long)mapping->offset);

		Offset.QuadPart = mapping->offset;
		Address = (void*)(uintptr_t) mapping->address;
		Size = mapping->size;
		r = NtMapViewOfSection(vm_section, to->process, &Address, 0,
					Size, &Offset, &Size, N(ViewUnmap), 0,
					PAGE_EXECUTE_READWRITE);
		if (r != STATUS_SUCCESS)
		{
			die("vm: NtMapViewOfSection failed (%08lx) %s\n",
				r, ntstatus_to_string(r));
		}

		/*
		 * TODO: this can be done more efficiently in chunks
		 */
		for (i = 0; i < page_count; i++)
		{
			Protection = vm_get_protection(mapping->protection[i]);
			Address = (char*)(uintptr_t) (mapping->address + i * 0x1000);
			Size = 0x1000;
			r = NtProtectVirtualMemory(to->process, &Address, &Size,
						Protection, &old_prot);
			if (r != STATUS_SUCCESS)
			{
				die("vm: NtProtectVirtualMemory failed (%08lx) %s\n",
					r, ntstatus_to_string(r));
			}

			if (Size != 0x1000)
				die("vm: Size changed at %d\n", __LINE__);
		}
	}
}

static struct vm_mapping *vm_mapping_find(struct process *p, user_ptr_t addr)
{
	struct vm_mapping *m;
	user_ptr_t start, end;

	LIST_FOR_EACH(&p->mapping_list, m, item)
	{
		start = m->address;
		end = m->address + m->size;
		if (start <= addr && addr < end)
			break;
	}

	return m;
}

static size_t vm_get_hole_size(struct process *p, user_ptr_t addr)
{
	struct vm_mapping *m;
	user_size_t max;
	user_size_t sz;

	/* assume Windows 2G memory model */
	if (addr >= 0x80000000)
		return 0;
	max = 0x80000000 - addr;

	LIST_FOR_EACH(&p->mapping_list, m, item)
	{
		if (m->address <= addr)
			continue;

		sz = m->address - addr;
		max = MIN(sz, max);
	}

	return max;
}

static int vm_change_protection(struct process *p, user_ptr_t addr,
				user_size_t size, int prot)
{
	DWORD Protection = vm_get_protection(prot);
	struct vm_mapping *m;
	PVOID Address = (void*) (uintptr_t) addr;
	SIZE_T sz = size;
	ULONG old_prot;
	NTSTATUS r;

	if (size & 0xfff)
		die("vm: bad size at %d\n", __LINE__);
	if ((ULONG)addr & 0xfff)
		die("vm: bad address at %d\n", __LINE__);

	r = NtProtectVirtualMemory(p->process, &Address, &sz,
				Protection, &old_prot);
	if (r != STATUS_SUCCESS)
	{
		dprintf("NtProtectVirtualMemory failed %08lx\n", r);
		return -1;
	}

	m = vm_mapping_find(p, addr);
	if (!m)
		die("vm: mapping not found at %d\n", __LINE__);

	while (size > 0)
	{
		int ofs = (addr - m->address)/0x1000;
		m->protection[ofs] = prot;
		size -= 0x1000;
		addr = addr + 0x1000;
	}

	return 0;
}

void vm_mappings_free(struct process *p)
{
	struct vm_mapping *m;

	while ((m = LIST_HEAD(&p->mapping_list)))
	{
		LIST_REMOVE(&p->mapping_list, m, item);
		free(m);
	}
}

int vm_get_pointer(struct process *p, user_ptr_t client_addr,
		void **addr, size_t *max_size)
{
	struct vm_mapping *m;
	unsigned int ofs;

	m = vm_mapping_find(p, client_addr);
	if (!m)
		return -_L(EFAULT);

	ofs = client_addr - m->address;

	*addr = (char*) vm_address + m->offset + ofs;
	*max_size = m->size - ofs;

	return 0;
}

int vm_memcpy_from_process(struct process *p, void *local_addr,
			user_ptr_t client_addr, user_size_t size)
{
	struct vm_mapping *m;
	unsigned int ofs;
	unsigned int n;

	while (size)
	{
		m = vm_mapping_find(p, client_addr);
		if (!m)
			return -_L(EFAULT);

		ofs = client_addr - m->address;
		if (ofs > m->size)
			die("vm: bad offset at %d\n", __LINE__);
		if (m->size < ofs + size)
			n = m->size - ofs;
		else
			n = size;

		if (n > size)
			die("vm: Bad size at %d", __LINE__);
		if (n == 0)
			die("vm: Bad size at %d", __LINE__);

		/* make sure page is readable by userspace */
		if (!(m->protection[ofs/0x1000] & _L(PROT_READ)))
			return -_L(EFAULT);

		memcpy(local_addr, vm_address + m->offset + ofs, n);

		size -= n;
		local_addr = (char*) local_addr + n;
		client_addr += n;
	}

	return 0;
}

int vm_memcpy_to_process(struct process *p, user_ptr_t client_addr,
				const void *local_addr, user_size_t size)
{
	struct vm_mapping *m;
	unsigned int ofs;
	unsigned int n;

	while (size)
	{
		m = vm_mapping_find(p, client_addr);
		if (!m)
			return -_L(EFAULT);

		ofs = client_addr - m->address;
		if (ofs > m->size)
			die("vm: bad offset at %d\n", __LINE__);
		if (m->size < ofs + size)
			n = m->size - ofs;
		else
			n = size;

		if (n > size)
			die("vm: Bad size at %d", __LINE__);
		if (n == 0)
			die("vm: Bad size at %d", __LINE__);

		/* make sure page is readable by userspace */
		if (!(m->protection[ofs/0x1000] & _L(PROT_WRITE)))
			return -_L(EFAULT);

		memcpy(vm_address + m->offset + ofs, local_addr, n);

		size -= n;
		local_addr = (const char*) local_addr + n;
		client_addr += n;
	}

	return 0;
}

/*
 * Move state of non-overlapping pages from
 * free to committed
 */
static user_ptr_t vm_allocate_pages(struct process *proc, user_ptr_t addr, user_size_t len, int prot)
{
	DWORD AllocationType = MEM_RESERVE | MEM_COMMIT;
	struct vm_mapping *mapping;
	LARGE_INTEGER Offset;
	DWORD Protection;
	int page_count;
	ULONG old_prot;
	user_ptr_t Address;
	PVOID RequestedAddress;
	SIZE_T Size;
	NTSTATUS r;
	int i;

	/* full access at reserve level */
	Protection = PAGE_EXECUTE_READWRITE;

	Address = addr & ~0xffff;
	Size = len;
	Size += (addr - Address);
	Size = (Size + 0xffff) & ~0xffff;

	Offset.QuadPart = vm_offset;

	dprintf("NtMapViewOfSection(%08x,%08lx,%08lx,%08lx)\n",
		Address, (ULONG) Size, AllocationType, Protection);

	page_count = (Size + 0xfff)/0x1000;
	mapping = malloc(sizeof *mapping + page_count * sizeof(int));
	if (!mapping)
		return _l_MAP_FAILED;

	RequestedAddress = (PVOID) (uintptr_t) Address;

	r = NtMapViewOfSection(vm_section, proc->process, &RequestedAddress, 0,
				Size, &Offset, &Size, N(ViewUnmap), 0, Protection);
	if (r != STATUS_SUCCESS)
	{
		dprintf("NtMapViewOfSection failed (%08lx) %s\n",
			r, ntstatus_to_string(r));
		return _l_MAP_FAILED;
	}
	dprintf("NtMapViewOfSection -> Address=%p Size=%08x\n",
		RequestedAddress, (uint32_t) Size);

	if (((uintptr_t)RequestedAddress) & ~0xffffffff)
		abort();

	Address = (user_ptr_t)(uintptr_t) RequestedAddress;

	mapping->address = Address;
	mapping->size = Size;
	mapping->offset = vm_offset;
	for (i = 0; i < page_count; i++)
		mapping->protection[i] = prot;

	dprintf("New mapping %08x bytes at %08x, offset=%08lx\n",
		mapping->size, mapping->address,
		(unsigned long)mapping->offset);

	LIST_ELEMENT_INIT(mapping, item);
	LIST_APPEND(&proc->mapping_list, mapping, item);

	vm_offset += Size;
	if (vm_offset & 0xffff)
		die("vm: bad offset @%d!\n", __LINE__);
	if (vm_offset > vm_maxsize)
		die("vm: out of memory at %d\n", __LINE__);

	/* restricted access after committing */
	Protection = vm_get_protection(prot);

	RequestedAddress = (PVOID) (uintptr_t) Address;
	r = NtProtectVirtualMemory(proc->process, &RequestedAddress, &Size,
				Protection, &old_prot);
	if ( r != STATUS_SUCCESS)
	{
		dprintf("NtProtectVirtualMemory failed (%08lx)\n", r);
		return _l_MAP_FAILED;
	}

	return Address;
}

/*
 * vm_allocate_fragmented_pages()
 *
 * TODO: This should be atomic.
 * if we fail in the middle for any reason,
 *   any mappings created should be destroyed
 */
static user_ptr_t vm_allocate_fragmented_pages(struct process *proc, user_ptr_t addr, user_size_t len, int prot)
{
	uint32_t delta = addr & pagemask;
	user_ptr_t base = addr;

	addr -= delta;
	len += delta;

	len = (len + pagemask) & ~pagemask;

	dprintf("Allocating fragmented pages at %08x len=%08x\n", addr, len);

	// TODO: atomic updates, avoid failing in the middle

	while (len > 0)
	{
		struct vm_mapping *m;
		user_size_t sz;

		m = vm_mapping_find(proc, addr);
		if (m)
		{
			user_size_t ofs = addr - m->address;
			int r;

			sz = MIN(len, m->size - ofs);

			r = vm_change_protection(proc, addr, sz, prot);
			if (r < 0)
				return -_L(EPERM);
		}
		else
		{
			sz = vm_get_hole_size(proc, addr);
			sz = MIN(sz, len);
			if (sz == 0)
				die("vm: bad size at %d\n", __LINE__);
			vm_allocate_pages(proc, addr, sz, prot);
		}

		len -= sz;
		addr += sz;
	}

	return base;
}

void vm_render_memory(struct process *proc, user_ptr_t addr,
			struct filp *fp, size_t len, loff_t offset)
{
	while (len)
	{
		size_t max_size = 0;
		void *ptr = 0;
		size_t size;
		int r;

		r = vm_get_pointer(proc, addr, &ptr, &max_size);
		if (r < 0)
			die("vm: failed to get pointer to memory %d\n", __LINE__);

		size = MIN(max_size, len);
		if (fp)
		{
			r = fp->ops->fn_read(fp, ptr, size, &offset, 1);
			if (r < 0)
				fprintf(stderr, "mmap failed to read file\n");

			/* eof */
			if (r == 0)
				fp = NULL;

			size = r;
		}
		else
			memset(ptr, 0, size);

		len -= size;
		addr += size;
	}
}

/*
 * TODO
 *  - return error codes correctly
 *  - mmap vs. nt mapping size differences
 *  - handle state change differences
 *  - deal with MAP_FIXED correctly
 */
user_ptr_t vm_process_map(struct process *proc, user_ptr_t addr, user_size_t len,
		 int prot, int flags, struct filp *fp, off_t offset)
{
	NTSTATUS r;
	user_ptr_t Address;
	MEMORY_BASIC_INFORMATION info;

	if (offset & pagemask)
		return -_L(EINVAL);

	if (flags & _L(MAP_SHARED))
		dprintf("warning: shared mappings not supported\n");

	memset(&info, 0, sizeof info);

	/* find current state of memory */
	Address = addr & ~0xffff;
	r = NtQueryVirtualMemory(proc->process, (void*)(uintptr_t)Address,
				MemoryBasicInformation,
				&info, sizeof info, NULL);
	if (r != STATUS_SUCCESS)
		die("NtQueryVirtualMemory failed r=%08lx %s\n",
			r, ntstatus_to_string(r));

	/*
	 * Check if something is allocated at this address
	 *
	 * Can only change the protection within an allocated block.
	 * Crossing allocation boundaries will cause a
	 * STATUS_CONFLICTING_ADDRESS error.
	 */
	if (info.RegionSize < len ||
	    info.State != MEM_FREE)
	{
		if (!(flags & _l_MAP_FIXED))
		{
			Address = vm_allocate_pages(proc, 0, len, prot);
		}
		else
		{
			/* partial allocate required */
			Address = vm_allocate_fragmented_pages(proc, addr, len, prot);
		}
	}
	else
	{
		/* no conflicts, go */
		Address = vm_allocate_pages(proc, addr, len, prot);
	}

	vm_render_memory(proc, (user_ptr_t) Address, fp, len, offset);

	if (Address == _l_MAP_FAILED)
		return Address;

	/* handle case where no address was specificied */
	if (!addr)
		addr = Address;

	dprintf("mmap -> %08x\n", addr);

	return addr;
}

int vm_process_map_protect(struct process *p, user_ptr_t addr,
			user_size_t len, int prot)
{
	addr &= ~pagemask;
	len = (len + pagemask) & ~pagemask;
	return vm_change_protection(p, addr, len, prot);
}

int vm_process_unmap(struct process *proc, user_ptr_t addr, user_size_t len)
{
	/* FIXME: implement */
	return 0;
}

int vm_string_read(struct process *proc, user_ptr_t addr, char **out)
{
	void *ptr;
	size_t len = 0;
	char *str;

	/* find length */
	while (1)
	{
		size_t max_sz = 0;
		void *p;
		int r;

		r = vm_get_pointer(proc, addr, &ptr, &max_sz);
		if (r < 0)
			return -_L(EFAULT);

		p = memchr(ptr, 0, max_sz);
		if (p)
		{
			len += ((char*) p - (char*) ptr);
			len ++;
			break;
		}
		else
			len += max_sz;
	}

	str = malloc(len);
	*out = str;

	/* copy data */
	while (len)
	{
		size_t max_sz = 0;
		size_t sz;
		int r;

		r = vm_get_pointer(proc, addr, &ptr, &max_sz);
		if (r < 0)
			return -_L(EFAULT);

		sz = MIN(max_sz, len);

		memcpy(str, ptr, sz);

		str += sz;
		addr += sz;
		len -= sz;
	}

	return 0;
}

void vm_dump_address_space(struct process *p)
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
		SIZE_T sz = 0;

		r = NtQueryVirtualMemory(p->process, Address,
					MemoryBasicInformation,
					&info, sizeof info, &sz);
		if (r != STATUS_SUCCESS)
			break;

		if (!info.RegionSize)
			break;

		Address = (BYTE*)Address + info.RegionSize;

		if (info.State == MEM_FREE)
			continue;

		vm_mem_state_to_string(info.State, state);
		vm_mem_protect_to_string(info.Protect, protect);

		printf("%08x-%08x %08x %08x %8s %8s %08x\n",
			info.BaseAddress,
			(char*)info.BaseAddress + info.RegionSize,
			info.AllocationBase, info.AllocationProtect,
			state, protect, info.Type);
	}
}
