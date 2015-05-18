#ifndef __STRING_H__
#define __STRING_H__

#define EOF (-1)

extern int printf(const char *str, ...);

extern size_t strlen(const char *str);
extern int strcmp(const char *a, const char *b);
extern char *strcpy(char *dest, const char *s);
extern void *memcpy(void *dest, const void *src, size_t n);
extern void *memmove(void *dest, const void *src, size_t n);

#endif /* __STRING_H__ */
