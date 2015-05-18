#ifndef __LINUX_ERRNO_H__
#define __LINUX_ERRNO_H__

/* avoid any possible conflicts with mingw windows headers */
#define _L(err) _l_##err

#define _l_EPERM 1
#define _l_ENOENT 2
#define _l_ESRCH 3
#define _l_EIO 5
#define _l_EBADF 9
#define _l_ECHILD 10
#define _l_EAGAIN 11
#define _l_EWOULDBLOCK _l_EAGAIN
#define _l_ENOMEM 12
#define _l_EACCES 13
#define _l_EFAULT 14
#define _l_ENOTDIR 20
#define _l_EINVAL 22
#define _l_EMFILE 24
#define _l_ENOTTY 25
#define _l_ENOSPC 28
#define _l_ESPIPE 29
#define _l_ERANGE 34
#define _l_ENAMETOOLONG 36
#define _l_ENOSYS 38
#define _l_ELOOP 40
#define _l_ENOTSOCK 88
#define _l_EAFNOSUPPORT 97
#define _l_ETIMEDOUT 110
#define _l_EISCONN 106
#define _l_ENOTCONN 107
#define _l_ECONNREFUSED 111
#define _l_EALREADY 114
#define _l_EINPROGRESS 115

#endif
