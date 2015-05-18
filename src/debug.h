/*
 * Debuging interface
 *
 * Copyright (C)  2012 - 2013 Mike McCormack
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

#ifndef __ATRATUS_DEBUG_H__
#define __ATRATUS_DEBUG_H__

#define STATIC_ASSERT(expr) \
	do { \
		char _sa[(expr) ? 1 : -1]; \
		(void) _sa; \
	} while(0)

#include <windows.h>

void die(const char *fmt, ...) __attribute__((format(printf,1,2), noreturn));
int dprintf(const char *fmt, ...) __attribute__((format(printf,1,2)));
void debug_set_file(const char *filename);
void debug_set_verbose(int val);
void debug_init(void);
void debug_line_dump(void *p, unsigned int len);
void debug_mem_dump(void *p, size_t len);
void debug_dump_regs(CONTEXT *regs);
struct process;
void debug_backtrace(struct process *context);

#endif /* __ATRATUS_DEBUG_H__ */
