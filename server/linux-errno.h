#ifndef __LINUX_ERRNO_H__
#define __LINUX_ERRNO_H__

/* avoid any possible conflicts with mingw windows headers */
#define _L(err) _l_##err

#define _l_EPERM 1
#define _l_ENOENT 2
#define _l_EIO 5
#define _l_EBADF 9
#define _l_ECHILD 10
#define _l_EAGAIN 11
#define _l_ENOMEM 12
#define _l_EACCES 13
#define _l_EFAULT 14
#define _l_ENOTDIR 20
#define _l_EINVAL 22
#define _l_ENOSYS 38

#endif
