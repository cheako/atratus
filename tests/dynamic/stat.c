#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	struct stat st;
	int r;

	memset(&st, 0, sizeof st);
	r = stat(argv[1], &st);
	if (r < 0)
		return 1;
	printf("mode %08x\n", st.st_mode);
	printf("size %08lx\n", st.st_size);

	return 0;
}
