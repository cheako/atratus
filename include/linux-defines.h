#ifndef __LINUX_ABI_H__
#define __LINUX_ABI_H__

#ifndef PACKED
#define PACKED __attribute__((__packed__))
#endif

/* _l_ prefix is for Linux kernel ABI stuff */
#define _l_MAP_FAILED ((void*)-1)

#define _l_FD_SETSIZE 1024

#define _l_MAP_SHARED       1
#define _l_MAP_PRIVATE      2
#define _l_MAP_FIXED     0x10
#define _l_MAP_ANONYMOUS 0x20

#define _l_PROT_READ  1
#define _l_PROT_WRITE 2
#define _l_PROT_EXEC  4
#define _l_PROT_NONE  0

#define _l_O_RDONLY (0x00)
#define _l_O_WRONLY (0x01)
#define _l_O_RDWR   (0x02)
#define _l_O_CREAT  (0x40)
#define _l_O_TRUNC  (0x200)
#define _l_O_NONBLOCK (0x800)
#define _l_O_CLOEXEC (0x80000)

#define _l_WNOHANG (1)

#define _l_SIGINT  (2)
#define _l_SIGILL  (4)
#define _l_SIGKILL (9)
#define _l_SIGSEGV (11)
#define _l_SIGTERM (15)
#define _l_SIGCHLD (17)
#define _l_SIGCONT (18)
#define _l_SIGSTOP (19)
#define _l_SIGTSTP (20)
#define _l_SIGTTIN (21)
#define _l_SIGTTOU (22)

#define _l_SIG_IGN ((void*) 1)
#define _l_SIG_DFL ((void*) 0)

#define _l_SA_NOCLDSTOP (1 << 0)
#define _l_SA_NOCLDWAIT (1 << 1)
#define _l_SA_SIGINFO (1 << 2)
#define _l_SA_RESTORER (1 << 26)
#define _l_SA_ONSTACK (1 << 27)
#define _l_SA_RESTART (1 << 28)
#define _l_SA_NODEFER (1 << 30)
#define _l_SA_RESETHAND (1 << 31)

#define _l_CLONE_VM (0x100)
#define _l_CLONE_PARENT_SETTID  (0x100000)
#define _l_CLONE_CHILD_CLEARTID (0x200000)
#define _l_CLONE_CHILD_SETTID  (0x1000000)

#define _l_FUTEX_WAIT 0
#define _l_FUTEX_WAKE 1

#define _l_POLLIN  (1 << 0)
#define _l_POLLPRI (1 << 1)
#define _l_POLLOUT (1 << 2)
#define _l_POLLERR (1 << 3)
#define _l_POLLHUP (1 << 4)

#define _l_F_DUPFD 0
#define _l_F_GETFD 1
#define _l_F_SETFD 2
#define _l_F_GETFL 3
#define _l_F_SETFL 4

#define _l_FD_CLOEXEC 1

#define _l_SIGABRT 6

#define _l_DT_DIR 4
#define _l_DT_REG 8
#define _l_DT_LNK 10

#define _l_AT_FDCWD (-100)

#define _l_F_OK 0
#define _l_X_OK 1
#define _l_W_OK 2
#define _l_R_OK 4

#define _l_PF_UNIX 1
#define _l_PF_INET 2
#define _l_PF_INET6 10

#define _l_AF_UNSPEC 0
#define _l_AF_INET _l_PF_INET
#define _l_AF_INET6 _l_PF_INET6

#define _l_SYS_SOCKET 1
#define _l_SYS_BIND 2
#define _l_SYS_CONNECT 3
#define _l_SYS_LISTEN 4
#define _l_SYS_ACCEPT 5
#define _l_SYS_GETSOCKNAME 6
#define _l_SYS_GETPEERNAME 7
#define _l_SYS_SOCKETPAIR 8
#define _l_SYS_SEND 9
#define _l_SYS_SENDTO 10
#define _l_SYS_RECV 11
#define _l_SYS_RECVFROM 12
#define _l_SYS_SHUTDOWN 13
#define _l_SYS_GETSOCKOPT 14
#define _l_SYS_SETSOCKOPT 15
#define _l_SYS_SENDMSG 16
#define _l_SYS_RECVMSG 17

#define _l_SOCK_STREAM 1
#define _l_SOCK_DGRAM 2

#define _l_SOL_SOCKET 1

#define _l_SO_DEBUG 1
#define _l_SO_REUSEADDR 2
#define _l_SO_TYPE 3
#define _l_SO_ERROR 4
#define _l_SO_DONTROUTE 5
#define _l_SO_BROADCAST 6
#define _l_SO_SNDBUF 7
#define _l_SO_RCVBUF 8
#define _l_SO_KEEPALIVE 9
#define _l_SO_OOBINLINE 10
#define _l_SO_NO_CHECK 11
#define _l_SO_PRIORITY 12
#define _l_SO_LINGER 13
#define _l_SO_BSDCOMPAT 14
#define _l_SO_SNDBUFFORCE 32
#define _l_SO_RCVBUFFORCE 33

#define _l_TCP_NODELAY 1
#define _l_TCP_MAXSEG 2
#define _l_TCP_CORK 3

#define _l_IPPROTO_IP 0
#define _l_IPPROTO_TCP 6
#define _l_IPPROTO_UDP 17

#define _l_SHUT_RD 0
#define _l_SHUT_WR 1
#define _l_SHUT_RDWR 2

#define _l_EAI_BADFLAGS (-1)
#define _l_EAI_NONAME (-2)
#define _l_EAI_AGAIN (-3)
#define _l_EAI_FAIL (-4)
#define _l_EAI_FAMILY (-6)

#define _l_MSG_OOB (1)
#define _l_MSG_DONTROUTE (4)
#define _l_MSG_DONTWAIT (0x40)

#define TIOCGPGRP  0x540F
#define TIOCSPGRP  0x5410
#define TIOCGWINSZ 0x5413

#define TIOCG     0x5401
#define TIOCS     0x5402
#define TCSETSW   0x5403
#define TCSETSF   0x5404
#define TCSETAW   0x5407
#define TCFLUSH   0x540b

#define VERASE 2
#define VINTR 0
#define VEOF 4
#define VSUSP 10

#define IGNBRK  (1 << 0)
#define BRKINT  (1 << 1)
#define IGNPAR  (1 << 2)
#define PARMRK  (1 << 3)
#define INPCK   (1 << 4)
#define ISTRIP  (1 << 5)
#define INLCR   (1 << 6)
#define IGNCR   (1 << 7)
#define ICRNL   (1 << 8)
#define IUCLC   (1 << 9)
#define IXON    (1 << 10)
#define IXANY   (1 << 11)
#define IXOFF   (1 << 12)
#define IMAXBEL (1 << 13)
#define IUTF8   (1 << 14)

#define ISIG   (1 << 0)
#define ICANON (1 << 1)
#define XCASE  (1 << 2)
#define ECHO   (1 << 3)
#define ECHOE  (1 << 4)
#define ECHOK  (1 << 5)
#define ECHONL (1 << 6)
#define NOFLSH (1 << 7)
#define TOSTOP (1 << 8)
#define ECHOCTL (1 << 9)
#define ECHOPRT (1 << 10)
#define ECHOKE (1 << 11)
#define FLUSHO (1 << 12)
#define PENDIN (1 << 14)
#define IEXTEN (1 << 15)

#define OPOST (1 << 0)
#define OLCUC (1 << 1)
#define ONLCR (1 << 2)
#define OCRNL (1 << 3)
#define ONOCR (1 << 4)
#define ONLRET (1 << 5)

#define CSIZE (0x30)
#define CS5 (0)
#define CS6 (0x10)
#define CS7 (0x20)
#define CS8 (0x30)
#define PARENB (0x100)
#define PARODD (0x200)

#define NCCS 19

struct iovec {
	void *iov_base;
	size_t iov_len;
};

struct termios
{
	unsigned int c_iflag;
	unsigned int c_oflag;
	unsigned int c_cflag;
	unsigned int c_lflag;
	unsigned char c_line;
	unsigned char c_cc[NCCS];
} PACKED;

struct winsize {
	unsigned short	ws_row;
	unsigned short	ws_col;
	unsigned short	ws_xpixel;
	unsigned short	ws_ypixel;
};

#ifdef WIN32
struct timespec
{
	unsigned int tv_sec;
	long tv_nsec;
};
#endif

struct fdset
{
	unsigned long fds_bits[1024/32];
};

struct stat {
	unsigned long st_dev;
	unsigned long st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned long st_rdev;
	unsigned long st_size;
	unsigned long st_blksize;
	unsigned long st_blocks;
	unsigned long st_atime;
	unsigned long st_atime_nsec;
	unsigned long st_mtime;
	unsigned long st_mtime_nsec;
	unsigned long st_ctime;
	unsigned long st_ctime_nsec;
	//unsigned long __unused1;
	//unsigned long __unused2;
};

/* be aware!
 * mingw32 packs stat64 differently to gcc on Linux without 
 */
struct stat64 {
	unsigned long long st_dev;
	int32_t __pad0;
	unsigned long st_ino;
	unsigned int st_mode;
	unsigned int st_nlink;
	unsigned long st_uid;
	unsigned long st_gid;
	unsigned long long st_rdev;
	int32_t __pad1;
	long long st_size;
	unsigned long st_blksize;
	unsigned long long st_blocks;
	int st_atime;
	unsigned int st_atime_nsec;
	int st_mtime;
	unsigned int st_mtime_nsec;
	int st_ctime;
	unsigned int st_ctime_nsec;
	//unsigned int __unused1;
	//unsigned int __unused2;
} PACKED;

struct linux_dirent {
	unsigned long  d_ino;
	unsigned long  d_off;
	unsigned short d_reclen;
	char           d_name[];
} PACKED;

struct linux_dirent64 {
	unsigned long long d_ino;
	long long d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
} PACKED;

typedef unsigned long l_sigset_t;

struct l_sigaction {
	void *sa_handler;
	unsigned long sa_flags;
	void *sa_restorer;
	l_sigset_t sa_mask;
} PACKED;

typedef uint32_t l_clock_t;

struct l_siginfo_t {
	int si_signo;
	int si_errno;
	int si_code;
	int si_trapno;
	int si_pid;
	int si_uid;
	l_clock_t si_status;
	l_clock_t si_uctime;
	int si_value;
	int si_int;
	void *si_ptr;
	int si_overrun;
	int si_timerid;
	void *si_addr;
	long si_band;
	int si_fd;
	short si_addr_lsb;
};

#define SECSPERDAY 86400
#define SECS_1601_TO_1970 ((369 * 365 + 89) * (ULONGLONG)SECSPERDAY)

#define SYSCALL0(num)			\
	__asm__ __volatile__ (		\
		"\tint $0x80\n"		\
	:"=a"(r)			\
	:"a"(num)			\
	:"memory")			\

#define SYSCALL_ASM(N)			\
	"\tpushl %%ebx\n"		\
	"\tmovl %%eax, %%ebx\n"		\
	"\tmov $" #N ", %%eax\n"	\
	"\tint $0x80\n"			\
	"\tpopl %%ebx\n"		\

#define SYSCALL1(num, a1)		\
	__asm__ __volatile__ (		\
	SYSCALL_ASM(num)		\
	:"=a"(r)			\
	:"a"(a1)			\
	:"memory")

#define SYSCALL2(num, a1, a2)		\
	__asm__ __volatile__ (		\
	SYSCALL_ASM(num)		\
	:"=a"(r)			\
	:"a"(a1),			\
         "c"(a2)			\
	:"memory")

#define SYSCALL3(num, a1, a2, a3)	\
	__asm__ __volatile__ (		\
	SYSCALL_ASM(num)		\
	:"=a"(r)			\
	:"a"(a1),			\
         "c"(a2),			\
         "d"(a3)			\
	:"memory")

#define SYSCALL4(num, a1, a2, a3, a4)	\
	__asm__ __volatile__ (		\
	SYSCALL_ASM(num)		\
	:"=a"(r)			\
	:"a"(a1),			\
         "c"(a2),			\
         "d"(a3),			\
         "S"(a4)			\
	:"memory")

#define SYSCALL5(num, a1, a2, a3, a4, a5) \
	__asm__ __volatile__ (		\
	SYSCALL_ASM(num)		\
	:"=a"(r)			\
	:"a"(a1),			\
         "c"(a2),			\
         "d"(a3),			\
         "S"(a4),			\
         "D"(a5)			\
	:"memory")

#endif
