#ifndef __ATRATUS_DEBUG_H__
#define __ATRATUS_DEBUG_H__

#define STATIC_ASSERT(expr) \
	do { \
		char _sa[(expr) ? 1 : -1]; \
		(void) _sa; \
	} while(0)

int dprintf(const char *fmt, ...);

#endif /* __ATRATUS_DEBUG_H__ */
