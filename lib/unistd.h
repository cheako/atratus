#ifndef __UNISTD_H__
#define __UNISTD_H__

extern void exit(int status);
extern int read(int fd, void *buffer, size_t length);
extern int write(int fd, const void *buffer, size_t length);
extern int open(const char *filename, int flags);
extern int close(int fd);

#endif /* __UNISTD_H__ */
