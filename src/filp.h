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
#include "usertypes.h"

typedef int64_t loff_t;

typedef struct _poll_list poll_list;
struct filp;

typedef int (*fn_add_dirent)(user_ptr_t, const char* entry, size_t entrylen,
			int avail, unsigned long dirofs,
			char type, unsigned long ino);
typedef void (*fn_wake)(struct filp *f, void *arg);

struct wait_entry;

struct filp_ops {
	int (*fn_read)(struct filp *f, void *buf, user_size_t size, loff_t *ofs, int block);
	int (*fn_write)(struct filp *f, const void *buf, user_size_t size, loff_t *ofs, int block);
	int (*fn_stat)(struct filp *f, struct stat64 *statbuf);
	int (*fn_ioctl)(struct filp *f, int cmd, unsigned long arg);
	int (*fn_getdents)(struct filp *f, user_ptr_t de, unsigned int count, fn_add_dirent fn);
	int (*fn_poll)(struct filp *f);
	void (*fn_poll_add)(struct filp *f, struct wait_entry *we);
	void (*fn_poll_del)(struct filp *f, struct wait_entry *we);
	void (*fn_close)(struct filp *f);
	int (*fn_truncate)(struct filp *f, uint64_t length);
	int (*fn_seek)(struct filp *f, int whence, uint64_t pos, uint64_t *newpos);
	int (*fn_sockcall)(int call, struct filp *fp, unsigned long *args, int block);
	int (*fn_readlink)(struct filp *fp, char **buf);
	int (*fn_unlink)(struct filp *fp);
	int (*fn_utimes)(struct filp *fp, struct timeval *times);
	int (*fn_symlink)(struct filp *dir, const char *name, const char *newpath);
	int (*fn_getname)(struct filp *fp, char **name);
	int (*fn_mkdir)(struct filp *fp, const char *name, int mode);
	int (*fn_rmdir)(struct filp *fp);
	struct filp* (*fn_openat)(struct filp *f, const char *file, int flags, int mode, int follow_links);
};

struct filp {
	const struct filp_ops *ops;
	loff_t offset;
	int refcount;
};

static inline void filp_close(struct filp *fp)
{
	if (!fp)
		return;

	if (fp->refcount < 0)
		abort();

	if (--fp->refcount == 0)
	{
		if (fp->ops->fn_close)
			fp->ops->fn_close(fp);
		memset(fp, 0xff, sizeof *fp);
		free(fp);
	}
}

struct filp *filp_open(const char *file, int flags, int mode, int follow_links);

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
	struct filp *(*open)(struct fs *fs, const char *subpath, int flags,
			int mode, int follow_links);
};

extern int alloc_fd(void);
extern void init_fp(struct filp *fp, const struct filp_ops *ops);
extern void fs_add(struct fs *fs);

#endif /* __FILP_H__ */
