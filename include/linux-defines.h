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

#define _l_O_RDONLY 0
#define _l_O_WRONLY 1
#define _l_O_RDWR 2
#define _l_O_CREAT 0x100

#define _l_WNOHANG (1)

#define _l_SIGCHLD (17)

#define _l_POLLIN  (1 << 0)
#define _l_POLLPRI (1 << 1)
#define _l_POLLOUT (1 << 2)
#define _l_POLLERR (1 << 3)
#define _l_POLLHUP (1 << 4)

#define _l_F_DUPFD 0
#define _l_F_GETFD 1
#define _l_F_SETFD 2

#define _l_SIGABRT 6

#define _l_DT_DIR 4
#define _l_DT_REG 8
#define _l_DT_LNK 10

#define TIOCGPGRP  0x540F
#define TIOCSPGRP  0x5410
#define TIOCGWINSZ 0x5413

#define TIOCG     0x5401
#define TIOCS     0x5402

#define VERASE 2
#define VEOF 4

#define IGNBRK  (1 << 0)
#define BRKINT  (1 << 1)
#define IGNPAR  (1 << 2)
#define PARMRK  (1 << 3)
#define INPCK   (1 << 4)
#define ISTRIP  (1 << 5)
#define INLCR   (1 << 6)
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

#define OPOST (1 << 0)
#define OLCUC (1 << 1)
#define ONLCR (1 << 2)
#define OCRNL (1 << 3)
#define ONOCR (1 << 4)
#define ONLRET (1 << 5)

#define NCCS 32

struct termios
{
	unsigned int c_iflag;
	unsigned int c_oflag;
	unsigned int c_cflag;
	unsigned int c_lflag;
	unsigned char c_line;
	unsigned char c_cc[NCCS];
	unsigned int c_ispeed;
	unsigned int c_ospeed;
};

struct winsize {
	unsigned short	ws_row;
	unsigned short	ws_col;
	unsigned short	ws_xpixel;
	unsigned short	ws_ypixel;
};

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
};

struct linux_dirent64 {
	unsigned long long d_ino;
	long long d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

#endif
