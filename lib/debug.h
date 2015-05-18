#ifndef __DEBUG_H__
#define __DEBUG_H__

extern void dprintf(const char *str, ...) __attribute__((format(printf,1,2)));
extern void die(const char *str, ...);
extern void warn(const char *str, ...);

#endif /* __DEBUG_H__ */
