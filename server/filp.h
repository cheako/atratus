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
	int (*fn_read)(filp *f, void *buf, size_t size, loff_t *ofs);
	int (*fn_write)(filp *f, const void *buf, size_t size, loff_t *ofs);
	int (*fn_stat)(filp *f, struct stat64 *statbuf);
	int (*fn_ioctl)(filp *f, int cmd, unsigned long arg);
	int (*fn_getdents)(filp *f, void *de, unsigned int count, fn_add_dirent fn);
	int (*fn_poll)(filp *f);
	void (*fn_poll_add)(filp *f, struct wait_entry *we);
	void (*fn_poll_del)(filp *f, struct wait_entry *we);
	void (*fn_close)(filp *f);
};

struct _filp {
	const struct filp_ops *ops;
	int pgid;
	HANDLE handle;
	poll_list *poll_first;
	loff_t offset;
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
};

extern int alloc_fd(void);
extern void fs_add(struct fs *fs);

#endif /* __FILP_H__ */
