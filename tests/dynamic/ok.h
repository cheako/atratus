#ifndef __ATRATUS_TEST_OK__
#define __ATRATUS_TEST_OK__

#define OK(expr) \
	do { \
		if (!(expr)) \
		{ \
			printf("expression '%s' untrue at %d\n", \
				 #expr, __LINE__); \
			return 0; \
		} \
	} while (0)


#endif /* __ATRATUS_TEST_OK__ */
