#include <sys/ioctl.h>
#include <termios.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	struct winsize ws;

	if (0 != ioctl(0, TIOCGWINSZ, &ws))
		return 1;
	printf("Size: %dx%d\n", ws.ws_col, ws.ws_row);
	return 0;
}
