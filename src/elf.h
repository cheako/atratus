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

#ifndef ATRATUS_ELF_H__
#define ATRATUS_ELF_H__

struct elf_module;

int elf_alloc_vdso(struct process *proc, void **vdso);
int elf_stack_setup(struct process *context,
		void *stack, size_t stack_size,
		char **argv, char **env,
		struct elf_module *m,
		struct elf_module *interp);
const char *elf_interpreter_get(struct elf_module *m);
unsigned int elf_entry_point_get(struct elf_module *m);
void elf_object_free(struct elf_module *m);
int elf_object_map(struct process *proc, struct elf_module *m);
struct elf_module *elf_module_load(const char *path);

#endif /* ATRATUS_ELF_H__ */
