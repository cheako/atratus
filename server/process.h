#ifndef __ATRATUS_PROCESS_H__
#define __ATRATUS_PROCESS_H__

#include "ntapi.h"

#define MAX_FDS 100
#define MAX_VTLS_ENTRIES 10

struct process_ops
{
	int (*memcpy_from)(void *local_addr, const void *client_addr, size_t size);
	int (*memcpy_to)(void *client_addr, const void *local_addr, size_t size);
};

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
	thread_stopped,
	thread_terminated,
} thread_state;

struct process
{
	struct process_ops		*ops;
	HANDLE				process;
	HANDLE				thread;
	CONTEXT				regs;
	int                             uid;
	int                             gid;
	int                             euid;
	int                             egid;
	HANDLE				poll_event;
	int				brk;
	unsigned int			vtls_selector;
	unsigned int			vtls_entries;
	struct user_desc		vtls[MAX_VTLS_ENTRIES];
	filp				*handles[MAX_FDS];
	struct process                  *next_process;
	struct process                  *parent;
	struct process                  *child;
	struct process                  *sibling;
	struct process			*next_ready;
	CLIENT_ID			id;
	USER_STACK			stack_info;
	thread_state                    state;
	int				exit_code;
	PVOID				fiber;
};

extern struct process *current;
extern void yield(void);

struct wait_entry;

struct wait_list
{
	struct wait_entry *head;
	struct wait_entry *tail;
};

struct wait_entry
{
	struct wait_entry *next;
	struct wait_entry *prev;
	struct process *p;
};

static inline void wait_head_init(struct wait_list *wl)
{
	wl->head = NULL;
	wl->tail = NULL;
}

static inline void wait_entry_init(struct wait_entry *we)
{
	we->next = NULL;
	we->prev = NULL;
}

static inline void wait_entry_append(struct wait_list *list,
				struct wait_entry *entry)
{
	if (list->tail)
		list->tail->next = entry;
	else
		list->head = entry;
	entry->prev = list->tail;
	list->tail = entry;
	entry->next = NULL;
}

static inline void wait_entry_remove(struct wait_list *list,
				struct wait_entry *entry)
{
	if (list->tail == entry)
		list->tail = entry->prev;
	else
		entry->next->prev = entry->prev;

	if (list->head == entry)
		list->head = entry->next;
	else
		entry->prev->next = entry->next;

	entry->prev = NULL;
	entry->next = NULL;
}

static inline int wait_entry_in_list(struct wait_list *list,
		 struct wait_entry *entry)
{
	if (list->head == entry || list->tail == entry)
		return 1;
	return (entry->prev || entry->next);
}

struct timeout
{
	struct timeout *next;
	struct timeval tv;
	void (*fn)(struct timeout *t);
};

extern void timeout_add(struct timeout *t);
extern void timeout_add_ms(struct timeout *t, int ms);
extern void timeout_add_tv(struct timeout *t, struct timeval *ts);
extern void timeout_remove(struct timeout *t);

struct signal_waiter
{
	struct wait_entry we;
	int signal;
};

extern void signal_waiter_add(struct signal_waiter *sw, int signal);
extern void signal_waiter_remove(struct signal_waiter *sw);

extern void process_signal(struct process *p, int signal);
extern void process_free(struct process *process);

/* add a fiber to wake in the main loop */
extern void ready_list_add(struct process *p);

#endif /* __ATRATUS_PROCESS_H__ */
