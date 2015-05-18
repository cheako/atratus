#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	const char *newpath, *oldpath;
	int r;

	if (argc != 3)
	{
		fprintf(stderr, "%s <oldpath> <newpath>\n", argv[0]);
		return 1;
	}

	oldpath = argv[1];
	newpath = argv[2];
	r = symlink(oldpath, newpath);
	if (r != 0)
	{
		fprintf(stderr, "failed to create symlink %s\n", newpath);
		return 1;
	}

	return 0;
}
