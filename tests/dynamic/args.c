#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv, char **env)
{
	int i;

	for (i = 0; i < argc; i++)
		puts(argv[i]);

	printf("\nenvironment:\n");
	for (i = 0; env[i]; i++)
		printf("%s\n", env[i]);
	return 0;
}
