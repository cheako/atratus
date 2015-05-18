/*
 * Filesystem definitions
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

#ifndef __FILP_H__
#define __FILP_H__

#include <stdint.h>
#include <stdbool.h>

#include "linux-defines.h"

typedef int64_t loff_t;

typedef struct _filp filp;
typedef struct _poll_list poll_list;

typedef int (*fn_add_dirent)(void *, const char* entry, size_t entrylen,
			 int avail, unsigned long dirofs, char type);
typedef void (*fn_wake)(filp *f, void *arg);

struct wait_entry;

struct filp_ops {
	int (*fn_read)(filp *f, void *buf, size_t size, loff_t *ofs, int block);
	int (*fn_write)(filp *f, const void *buf, size_t size, loff_t *ofs);
	int (*fn_stat)(filp *f, struct stat64 *statbuf);
	int (*fn_ioctl)(filp *f, int cmd, unsigned long arg);
	int (*fn_getdents)(filp *f, void *de, unsigned int count, fn_add_dirent fn);
	int (*fn_poll)(filp *f);
	void (*fn_poll_add)(filp *f, struct wait_entry *we);
	void (*fn_poll_del)(filp *f, struct wait_entry *we);
	void (*fn_close)(filp *f);
	int (*fn_truncate)(filp *f, uint64_t length);
	int (*fn_seek)(filp *f, int whence, uint64_t pos, uint64_t *newpos);
	int (*fn_sockcall)(int call, filp *fp, unsigned long *args, int block);
};

struct _filp {
	const struct filp_ops *ops;
	int pgid;
	HANDLE handle;
	poll_list *poll_first;
	loff_t offset;
	int refcount;
};

struct _poll_list {
	poll_list *next;
	int wait_events;
	int revents;
	fn_wake fn;
	void *arg;
};

struct fs
{
	char *root;
	struct fs *next;
	int (*open)(struct fs *fs, const char *subpath, int flags, int mode);
	int (*stat64)(struct fs *fs, const char *path,
			 struct stat64 *statbuf, bool follow_links);
	int (*utimes)(struct fs *fs, const char *path, struct timeval *times);
};

extern int alloc_fd(void);
extern void init_fp(filp *fp, const struct filp_ops *ops);
extern void fs_add(struct fs *fs);

#endif /* __FILP_H__ */
