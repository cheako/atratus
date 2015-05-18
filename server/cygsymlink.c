#include <windows.h>
#include <stdio.h>

int quiet;

int create_symlink(const char *path, const char *newpath)
{
	char buffer[0x1000] = "!<symlink>\377\376";
	DWORD bytesWritten;
	HANDLE handle;
	BOOL ok;
	UINT n;

	n = MultiByteToWideChar(CP_UTF8, 0, newpath, -1, 0, 0);
	if (n > (sizeof buffer - 12)/2)
	{
		if (!quiet)
			fprintf(stderr, "target too long\n");
		return FALSE;
	}

	n = MultiByteToWideChar(CP_UTF8, 0, newpath, -1,
				(WCHAR*)&buffer[12], sizeof buffer - 12);

	handle = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 
			FILE_ATTRIBUTE_SYSTEM, NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (!quiet)
			fprintf(stderr, "CreateFile failed %08x\n", GetLastError());
		return FALSE;
	}

	ok = WriteFile(handle, buffer, (n - 1) * 2 + 12, &bytesWritten, NULL);
	if (!ok)
		fprintf(stderr, "WriteFile failed %08x\n", GetLastError());

	CloseHandle(handle);

	return ok;
}

int main(int argc, char **argv)
{
	int r;
	int n = 0;

	if (argc >= 2 && !strcmp(argv[1], "-q"))
	{
		quiet = 1;
		n++;
	}

	if (argc - n != 3)
	{
		fprintf(stderr, "%s [-q] <path> <target>\n", argv[0]);
		return 1;
	}

	r = create_symlink(argv[n + 1], argv[n + 2]);
	if (r < 0)
		return 1;

	return 0;
}
