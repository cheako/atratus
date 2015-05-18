/*
 * virtual memory interface
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

#ifndef ATRATUS_VM_H__
#define ATRATUS_VM_H__

void vm_init(void);
void vm_mappings_copy(struct process *to, struct process *from);
void vm_mappings_free(struct process *p);
int vm_memcpy_from_process(struct process *p, void *local_addr,
			const void *client_addr, size_t size);
int vm_memcpy_to_process(struct process *p, void *client_addr,
			const void *local_addr, size_t size);
void* vm_process_map(struct process *proc, void *addr, size_t len,
		 int prot, int flags, struct filp *fp, off_t offset);
int vm_process_map_protect(struct process *proc, void *addr,
			size_t len, int prot);
int vm_process_unmap(struct process *proc, void *addr, size_t len);
int vm_get_pointer(struct process *p, const void *client_addr,
		void **addr, size_t *max_size);
int vm_string_read(struct process *proc, const char *addr, char **out);
void vm_dump_address_space(struct process *p);

static inline unsigned long round_down(unsigned long val, unsigned long rounding)
{
	return val & ~(rounding - 1);
}

static inline unsigned long round_up(unsigned long val, unsigned long rounding)
{
	return (val + rounding - 1) & ~(rounding - 1);
}

static const int pagesize = 0x1000;
static const int pagemask = 0x0fff;

#endif /* ATRATUS_VM_H__ */
