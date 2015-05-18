#ifndef __FILP_H__
#define __FILP_H__

#define _l_POLLIN 1
#define _l_POLLOUT 4
#define _l_POLLERR 8

typedef int64_t loff_t;

typedef struct _filp filp;
typedef struct _poll_list poll_list;

struct stat64 {
	unsigned long long st_dev;
	unsigned long long st_ino;
	unsigned int st_mode;
	unsigned int st_nlink;
	unsigned int st_uid;
	unsigned int st_gid;
	unsigned long long st_rdev;
	unsigned long long __pad1;
	long long st_size;
	int st_blksize;
	int __pad2;
	long long st_blocks;
	int atime;
	unsigned int atime_nsec;
	int mtime;
	unsigned int mtime_nsec;
	int ctime;
	unsigned int ctime_nsec;
	unsigned int __unused1;
	unsigned int __unused2;
};

struct linux_dirent {
	unsigned long  d_ino;
	unsigned long  d_off;
	unsigned short d_reclen;
	char           d_name[];
};

struct linux_dirent64 {
	unsigned long long d_ino;
	long long d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

typedef int (*fn_add_dirent)(void *, WCHAR* entry, USHORT entrylen, int avail);
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

#endif /* __FILP_H__ */
