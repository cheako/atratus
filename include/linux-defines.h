/* _l_ prefix is for Linux kernel ABI stuff */
#define _l_MAP_FAILED ((void*)-1)

#define _l_MAP_SHARED       1
#define _l_MAP_PRIVATE      2
#define _l_MAP_FIXED     0x10
#define _l_MAP_ANONYMOUS 0x20

#define _l_PROT_READ  1
#define _l_PROT_WRITE 2
#define _l_PROT_EXEC  4
#define _l_PROT_NONE  0

#define _l_O_RDONLY 0
#define _l_O_WRONLY 1
#define _l_O_RDWR 2
#define _l_O_CREAT 0x100

#define _l_WNOHANG (1)

#define _l_SIGCHLD (17)

#define _l_POLLIN 1
#define _l_POLLOUT 4
#define _l_POLLERR 8

#define _l_F_DUPFD 0
#define _l_F_GETFD 1
#define _l_F_SETFD 2

#define _l_SIGABRT 6
