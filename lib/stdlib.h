#ifndef __ATRATUS_STDLIB_H__
#define __ATRATUS_STDLIB_H__

#define NULL ((void *)0)

extern void exit(int status);
extern void *malloc(size_t sz);
extern void *realloc(void *ptr, size_t mem);
extern void free(void *ptr);

#endif // __ATRATUS_STDLIB_H__
