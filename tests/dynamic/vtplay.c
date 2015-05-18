#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

/*
 * Cat a file slowly to a terminal
 * Good for testing terminal with files from:
 *
 * http://artscene.textfiles.com/vt100
 */

int main(int argc, char **argv)
{
	char buf[10];
	int fd, r;

	if (argc != 2)
	{
		fprintf(stderr, "What, no files?\n");
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		return 1;
	while (1)
	{
		r = read(fd, buf, 1);
		if (r != 1)
			break;
		r = write(1, buf, 1);
		if (r != 1)
			break;
		poll(0, 0, 10);
	}
	close(fd);
	return 0;
}
