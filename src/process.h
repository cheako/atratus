/*
 * process definitions
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

#ifndef __ATRATUS_PROCESS_H__
#define __ATRATUS_PROCESS_H__

#include "ntapi.h"
#include <stdint.h>
#include <stdbool.h>

#include "linux-defines.h"

#include "list.h"

#define MAX_FDS 100
#define MAX_VTLS_ENTRIES 10

struct user_desc {
	unsigned int entry_number;
	unsigned int base_addr;
	unsigned int limit;
	unsigned int seg_32bit:1;
	unsigned int contents:2;
	unsigned int read_exec_only:1;
	unsigned int limit_in_pages:1;
	unsigned int seg_not_present:1;
	unsigned int useable:1;
};

typedef enum {
	thread_running,
	thread_ready,
	thread_stopped,
	thread_terminated,
} thread_state;

struct fdinfo
{
	struct filp *fp;
	int flags;
};

struct vm_mapping;
struct vm_mapping_list
{
	struct vm_mapping	*head, *tail;
};

struct sigqueue
{
	LIST_ELEMENT(struct sigqueue, item);
	int signal;
};

enum wake_reason_t
{
	wake_bad = 0,
	wake_exception = 1,
	wake_break_in = 2,
};

struct process
{
	HANDLE				process;
	HANDLE				thread;
	enum wake_reason_t		wake_reason;
	EXCEPTION_RECORD		exception;
	CONTEXT				winctx;
	struct _L(ucontext)		regs;
	int                             uid;
	int                             gid;
	int                             euid;
	int                             egid;
	struct process			*leader;
	user_ptr_t			brk;
	unsigned int			vtls_selector;
	unsigned int			vtls_entries;
	struct user_desc		vtls[MAX_VTLS_ENTRIES];
	struct fdinfo			handles[MAX_FDS];
	LIST_ELEMENT(struct process, item);
	struct process                  *parent;
	LIST_ANCHOR(struct process)	children;
	LIST_ELEMENT(struct process, sibling);
	LIST_ELEMENT(struct process, ready_item);
	LIST_ELEMENT(struct process, remote_break_item);
	CLIENT_ID			id;
	USER_STACK			stack_info;
	thread_state                    state;
	bool				suspended;
	unsigned int                    umask;
	int				exit_code;
	PVOID				fiber;
	char				*cwd;
	struct filp			*cwdfp;
	struct filp			*tty;
	LIST_ANCHOR(struct vm_mapping)	mapping_list;
	struct l_sigaction		sa[256];
	LIST_ANCHOR(struct sigqueue)	signal_list;
	int				ttyeof;
};

extern struct process *current;
extern void yield(void);
extern void schedule(void);

struct wait_entry
{
	LIST_ELEMENT(struct wait_entry, item);
	struct process *p;
};

struct timeout
{
	LIST_ELEMENT(struct timeout, item);
	struct timeval tv;
	void (*fn)(struct timeout *t);
};

extern void timeout_add(struct timeout *t);
extern void tv_from_ms(struct timeval *t, int ms);
extern void timeout_add_ms(struct timeout *t, int ms);
extern void timeout_add_tv(struct timeout *t, struct timeval *ts);
extern void timeout_add_timespec(struct timeout *t, struct _L(timespec) *ts);
extern void timeout_remove(struct timeout *t);
extern void timeout_now(struct timeval *tv);

struct workitem
{
	LIST_ELEMENT(struct workitem, item);
	void(*fn)(struct workitem*);
};

extern void work_add(struct workitem *item);

struct signal_waiter
{
	struct wait_entry we;
	int signal;
};

extern void signal_waiter_add(struct signal_waiter *sw, int signal);
extern void signal_waiter_remove(struct signal_waiter *sw);

extern void process_signal_group(struct process *p, int signal);
extern void process_signal(struct process *p, int signal);
extern void process_free(struct process *process);
extern int process_pending_signal_check(struct process *p);

/* add a fiber to wake in the main loop */
extern void ready_list_add(struct process *p);
extern void ready_list_remove(struct process *p);

extern int process_close_fd(struct process *p, int fd);
int process_getpid(struct process *p);
struct process *process_find(int pid);

#endif /* __ATRATUS_PROCESS_H__ */
