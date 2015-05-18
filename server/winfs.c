#include <windows.h>
#include <stdio.h>
#include "ntapi.h"
#include "filp.h"
#include "linux-errno.h"
#include "linux-defines.h"
#include "debug.h"
#include "process.h"

#define SECSPERDAY 86400
#define SECS_1601_TO_1970 ((369 * 365 + 89) * (ULONGLONG)SECSPERDAY)

static char rootdir[MAX_PATH + 1];

static int longlong_to_unixtime(ULONGLONG seconds, unsigned int *ns)
{
	if (ns)
		*ns = (seconds%10000000LL)*100LL;
	seconds /= 10000000LL;
	seconds -= SECS_1601_TO_1970;
	return seconds;
}

static int filetime_to_unixtime(FILETIME *ft, unsigned int *ns)
{
	ULONGLONG seconds;

	seconds = (((ULONGLONG)ft->dwHighDateTime) << 32) + ft->dwLowDateTime;
	return longlong_to_unixtime(seconds, ns);
}

static char *unix2dos_path(const char *unixpath)
{
	char *ret;
	int n, i;

	ret = malloc(strlen(rootdir) + strlen(unixpath) + 2);
	if (ret)
	{
		strcpy(ret, rootdir);
		n = strlen(ret);

		/* append \ if necessary */
		if (n && ret[n - 1] != '\\')
		{
			ret[n++] = '\\';
			ret[n++] = 0;
		}

		/* append unix path, changing / to \ */
		for (i = 0; unixpath[i]; i++)
		{
			if (unixpath[i] == '/')
			{
				if (i != 0)
					ret[n++] = '\\';
			}
			else
				ret[n++] = unixpath[i];
		}
		ret[n] = 0;
	}

	dprintf("%s -> %s\n", unixpath, ret);

	return ret;
}

static int winfs_stat64(struct fs *fs, const char *path,
			struct stat64 *statbuf, BOOL follow_links)
{
	WIN32_FILE_ATTRIBUTE_DATA info;
	BOOL r;
	char *dospath;

	dospath = unix2dos_path(path);
	r = GetFileAttributesEx(dospath, GetFileExInfoStandard, &info);
	free(dospath);
	if (!r)
		return -_L(ENOENT);

	memset(statbuf, 0, sizeof *statbuf);
	statbuf->st_mode = 0755;
	if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		statbuf->st_mode |= 040000;
	else
		statbuf->st_mode |= 0100000;
	statbuf->ctime = filetime_to_unixtime(&info.ftCreationTime,
				&statbuf->ctime_nsec);
	statbuf->mtime = filetime_to_unixtime(&info.ftLastWriteTime,
				&statbuf->mtime_nsec);
	statbuf->atime = filetime_to_unixtime(&info.ftLastAccessTime,
				&statbuf->atime_nsec);
	statbuf->st_size = info.nFileSizeLow;
	//statbuf->st_size += info.nFileSizeHigh * 0x100000000LL;
	statbuf->st_blksize = 0x1000;

	return 0;
}

static int file_stat(filp *f, struct stat64 *statbuf)
{
	IO_STATUS_BLOCK iosb;
	FILE_DIRECTORY_INFORMATION info;
	NTSTATUS r;

	r = NtQueryInformationFile(f->handle, &iosb, &info,
				 sizeof info, FileDirectoryInformation);
	if (r != STATUS_SUCCESS)
		return _L(EPERM);

	memset(statbuf, 0, sizeof *statbuf);
	statbuf->st_mode = 0755;

	if (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		statbuf->st_mode |= 040000;
	else
		statbuf->st_mode |= 0100000;
	statbuf->ctime = longlong_to_unixtime(info.ChangeTime.QuadPart,
				&statbuf->ctime_nsec);
	statbuf->mtime = longlong_to_unixtime(info.LastWriteTime.QuadPart,
				&statbuf->mtime_nsec);
	statbuf->atime = longlong_to_unixtime(info.LastAccessTime.QuadPart,
				&statbuf->atime_nsec);
	statbuf->st_size = info.AllocationSize.QuadPart;
	statbuf->st_blksize = 0x1000;

	return 0;
}

static int file_getdents(filp *fp, void *de, unsigned int count, fn_add_dirent add_de)
{
	int ofs = 0;
	int r;
	unsigned char *p = (unsigned char*) de;
	NTSTATUS ret;
	IO_STATUS_BLOCK iosb;
	BYTE buffer[0x1000];
	BOOL first = TRUE;
	FILE_DIRECTORY_INFORMATION *info;
	WCHAR star[] = { '*', '.', '*', 0 };
	UNICODE_STRING mask;
	struct linux_dirent *prev_de = NULL;
	ULONG EntryOffset;

	mask.Length = sizeof star/sizeof (WCHAR);
	mask.MaximumLength = 0;
	mask.Buffer = star;

	if (count < sizeof *de)
		return -_L(EINVAL);

	while (1)
	{
		memset(buffer, 0, sizeof buffer);
		ret = NtQueryDirectoryFile(fp->handle, NULL, NULL, NULL, &iosb,
			buffer, sizeof buffer,
			FileDirectoryInformation, first, NULL /*&mask*/, 0);
		dprintf("NtQueryDirectoryFile -> %08lx\n", ret);
		if (ret != STATUS_SUCCESS)
			break;
		first = FALSE;

		EntryOffset = 0;
		do {
			info = (FILE_DIRECTORY_INFORMATION*) &buffer[EntryOffset];

			if (prev_de)
			{
				r = current->ops->memcpy_to(&prev_de->d_off, &ofs, sizeof ofs);
				if (r < 0)
					break;
			}
			de = (struct linux_dirent*)&p[ofs];
			r = add_de(de, info->FileName, info->FileNameLength/2, count - ofs);
			if (r < 0)
				break;
			ofs += r;

			prev_de = de;
			EntryOffset += info->NextEntryOffset;
		} while (info->NextEntryOffset);
	}

	dprintf("%d bytes added\n", ofs);

	return ofs;
}

/*
 * It would be nice if there was a function to do this in one go in Windows
 * Other ways to achieve better performance:
 *  - issue an APC in the windows client (Wine style)
 *  - do this in the NT kernel in a driver
 */
static NTSTATUS file_read_to_userland(HANDLE handle, void *buf,
				size_t size, loff_t *ofs)
{
	uint8_t buffer[0x1000];
	NTSTATUS r;
	DWORD bytesRead;
	int bytesCopied = 0;

	while (size)
	{
		LARGE_INTEGER pos;
		LARGE_INTEGER out;
		DWORD sz;

		pos.QuadPart = *ofs;

		r = SetFilePointerEx(handle, pos, &out, FILE_BEGIN);
		if (!r)
			break;

		if (size > sizeof buffer)
			sz = sizeof buffer;
		else
			sz = size;

		bytesRead = 0;
		r = ReadFile(handle, buffer, sz, &bytesRead, NULL);
		if (!r)
		{
			dprintf("ReadFile failed %ld\n", GetLastError());
			return -_L(EIO);
		}

		if (bytesRead == 0)
			break;

		r = NtWriteVirtualMemory(current->process, buf,
					 buffer, bytesRead, &sz);
		if (r != STATUS_SUCCESS)
		{
			if (bytesCopied)
				break;
			return -_L(EFAULT);
		}
		bytesCopied += bytesRead;
		buf = (char*) buf + bytesRead;
		size -= bytesRead;
		(*ofs) += bytesRead;
	}
	return bytesCopied;
}

static int file_read(filp *f, void *buf, size_t size, loff_t *off)
{
	return file_read_to_userland(f->handle, buf, size, off);
}

static int file_write(filp *f, const void *buf, size_t size, loff_t *off)
{
	uint8_t buffer[0x1000];
	DWORD bytesCopied = 0;

	while (size)
	{
		ULONG sz = size;
		DWORD bytesWritten;
		ULONG bytesRead = 0;
		NTSTATUS r;

		if (sz > sizeof buffer)
			sz = sizeof buffer;

		r = NtReadVirtualMemory(current->process, buf,
				 buffer, sz, &bytesRead);
		if (r != STATUS_SUCCESS)
			return -_L(EFAULT);

		bytesWritten = 0;
		r = WriteFile(f->handle, buf, bytesRead, &bytesWritten, NULL);
		if (!r)
		{
			fprintf(stderr, "ReadFile %p failed %ld\n",
				f->handle, GetLastError());
			return -_L(EIO);
		}

		/* move along */
		bytesCopied += bytesWritten;
		sz -= bytesWritten;
		buf = (char*) buf + bytesWritten;
		(*off) += bytesWritten;
	}

	return bytesCopied;
}

static const struct filp_ops disk_file_ops = {
	.fn_read = &file_read,
	.fn_write = &file_write,
	.fn_stat = &file_stat,
	.fn_getdents = &file_getdents,
};

static int winfs_open(struct fs *fs, const char *file, int flags, int mode)
{
	char *dospath;
	DWORD access;
	DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	DWORD create = 0;
	HANDLE handle;
	filp *fp;
	int fd;

	dprintf("open(\"%s\",%08x,%08x)\n", file, flags, mode);

	switch (flags & 3)
	{
	case _L(O_RDONLY):
		access = GENERIC_READ;
		break;
	case _L(O_WRONLY):
		access = GENERIC_WRITE;
		break;
	case _L(O_RDWR):
		access = GENERIC_READ | GENERIC_WRITE;
		break;
	default:
		dprintf("bad open flags %08x\n", flags);
		return -_L(EINVAL);
	}

	if (flags & _L(O_CREAT))
		create = CREATE_NEW;
	else
		create = OPEN_EXISTING;

	dospath = unix2dos_path(file);
	dprintf("CreateFile(%s,%08lx,%08lx,NULL,%08lx,...)\n",
		dospath, access, share, create);

	/* use FILE_FLAG_BACKUP_SEMANTICS for opening directories */
	handle = CreateFile(dospath, access, share, NULL,
			    create,
			    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
			    NULL);

	if (handle == INVALID_HANDLE_VALUE)
	{
		dprintf("failed to open %s (%ld)\n",
			dospath, GetLastError());
		free(dospath);
		return -_L(ENOENT);
	}

	free(dospath);

	fp = malloc(sizeof (*fp));
	if (!fp)
	{
		CloseHandle(handle);
		return -_L(ENOMEM);
	}

	memset(fp, 0, sizeof *fp);
	fp->ops = &disk_file_ops;
	fp->pgid = 0;
	fp->handle = handle;
	fp->offset = 0;

	fd = alloc_fd();
	if (fd < 0)
	{
		free(fp);
		CloseHandle(handle);
		return -_L(ENOMEM);
	}

	dprintf("handle -> %p\n", handle);
	dprintf("fd -> %d\n", fd);

	current->handles[fd] = fp;

	return fd;
}

static struct fs winfs =
{
	.root = "/",
	.open = &winfs_open,
	.stat64 = &winfs_stat64,
};

void winfs_init(void)
{
	GetCurrentDirectory(sizeof rootdir, rootdir);
	fs_add(&winfs);
}
