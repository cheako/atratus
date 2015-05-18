/*
 * windows filesystem interface
 *
 * Copyright (C) 2011 - 2013 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include <windows.h>
#include <stdio.h>
#include "ntapi.h"
#include "filp.h"
#include "linux-errno.h"
#include "linux-defines.h"
#include "debug.h"
#include "process.h"
#include <limits.h>

static WCHAR rootdir[MAX_PATH + 1];

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

static void timeval_to_filetime(struct timeval *tv, FILETIME *ft)
{
	uint64_t t;

	t = tv->tv_sec;
	t += SECS_1601_TO_1970;
	t *= 10000000LL;
	t += tv->tv_usec * 10LL;

	ft->dwHighDateTime = (t >> 32);
	ft->dwLowDateTime = t & 0xffffffff;
}

static WCHAR *unix2dos_path(const char *unixpath)
{
	WCHAR *ret;
	int i, n, len;

	len = MultiByteToWideChar(CP_UTF8, 0, unixpath, -1, NULL, 0);

	ret = malloc((lstrlenW(rootdir) + len + 2)*sizeof (WCHAR));
	if (ret)
	{
		lstrcpyW(ret, rootdir);
		n = lstrlenW(ret);

		/* append \ if necessary */
		if (n && ret[n - 1] != '\\')
		{
			ret[n++] = '\\';
			ret[n] = 0;
		}

		MultiByteToWideChar(CP_UTF8, 0, unixpath, -1, ret + n, len + 1);

		/* change / to \ */
		for (i = n; ret[i]; i++)
			if (ret[i] == '/')
				ret[i] = '\\';
	}

	dprintf("%s -> %S\n", unixpath, ret);

	return ret;
}

/*
 * Detect a cygwin new style symlink
 *  - System attribute is set
 *  - file starts with "!<symlink>"
 */
bool winfs_is_link(LPCWSTR dospath, DWORD attributes)
{
	char buffer[10];
	DWORD count = 0;
	HANDLE handle;
	BOOL r;

	if (!(attributes & FILE_ATTRIBUTE_SYSTEM))
		return false;
	handle = CreateFileW(dospath, GENERIC_READ, FILE_SHARE_READ,
				 NULL, OPEN_EXISTING, 0, NULL);
	if (handle == INVALID_HANDLE_VALUE)
		return false;
	r = ReadFile(handle, buffer, sizeof buffer, &count, NULL);
	if (r && count == 10)
		r = !memcmp(buffer, "!<symlink>", sizeof buffer);

	CloseHandle(handle);

	return r;
}

static int winfs_stat64(struct fs *fs, const char *path,
			struct stat64 *statbuf, bool follow_links)
{
	WIN32_FILE_ATTRIBUTE_DATA info;
	BOOL r;
	WCHAR *dospath;

	dospath = unix2dos_path(path);
	if (!dospath)
		return -_L(ENOENT);

	r = GetFileAttributesExW(dospath, GetFileExInfoStandard, &info);
	free(dospath);
	if (!r)
		return -_L(ENOENT);

	memset(statbuf, 0, sizeof *statbuf);
	if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
		statbuf->st_mode = 0555;
	else
		statbuf->st_mode = 0755;
	statbuf->st_uid = current->uid;
	statbuf->st_gid = current->gid;
	if (winfs_is_link(dospath, info.dwFileAttributes))
		statbuf->st_mode |= 0120000;
	else if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		statbuf->st_mode |= 040000;
	else
		statbuf->st_mode |= 0100000;
	statbuf->st_ctime = filetime_to_unixtime(&info.ftCreationTime,
				&statbuf->st_ctime_nsec);
	statbuf->st_mtime = filetime_to_unixtime(&info.ftLastWriteTime,
				&statbuf->st_mtime_nsec);
	statbuf->st_atime = filetime_to_unixtime(&info.ftLastAccessTime,
				&statbuf->st_atime_nsec);
	statbuf->st_size = info.nFileSizeLow;
	//statbuf->st_size += info.nFileSizeHigh * 0x100000000LL;
	statbuf->st_blksize = 0x1000;
	statbuf->st_blocks = statbuf->st_size / 0x1000;

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
	if (info.FileAttributes & FILE_ATTRIBUTE_READONLY)
		statbuf->st_mode = 0555;
	else
		statbuf->st_mode = 0755;

	/* can't open a symlink, so don't check for a link */
	if (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		statbuf->st_mode |= 040000;
	else
		statbuf->st_mode |= 0100000;
	statbuf->st_ctime = longlong_to_unixtime(info.ChangeTime.QuadPart,
				&statbuf->st_ctime_nsec);
	statbuf->st_mtime = longlong_to_unixtime(info.LastWriteTime.QuadPart,
				&statbuf->st_mtime_nsec);
	statbuf->st_atime = longlong_to_unixtime(info.LastAccessTime.QuadPart,
				&statbuf->st_atime_nsec);
	statbuf->st_size = info.AllocationSize.QuadPart;
	statbuf->st_blksize = 0x1000;
	statbuf->st_blocks = statbuf->st_size / 0x1000;

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

		EntryOffset = 0;
		do {
			size_t len;
			char type;

			info = (FILE_DIRECTORY_INFORMATION*) &buffer[EntryOffset];
			EntryOffset += info->NextEntryOffset;

			len = WideCharToMultiByte(CP_UTF8, 0,
						info->FileName,
						info->FileNameLength/sizeof (WCHAR),
						NULL, 0, NULL, NULL);
			char name[len + 1];
			WideCharToMultiByte(CP_UTF8, 0,
					info->FileName,
					info->FileNameLength/sizeof (WCHAR),
					name, len + 1, NULL, NULL);

			if (winfs_is_link(info->FileName, info->FileAttributes))
				type = _L(DT_LNK);
			else if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				type = _L(DT_DIR);
			else
				type = _L(DT_REG);

			de = (struct linux_dirent*)&p[ofs];
			r = add_de(de, name, len, count - ofs,
				(first || info->NextEntryOffset) ? EntryOffset : INT_MAX,
				type);
			if (r < 0)
				break;
			ofs += r;

		} while (info->NextEntryOffset);
		first = FALSE;
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

static int file_read(filp *f, void *buf, size_t size, loff_t *off, int block)
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
		r = WriteFile(f->handle, buffer, bytesRead, &bytesWritten, NULL);
		if (!r)
		{
			dprintf("WriteFile %p failed %ld\n",
				f->handle, GetLastError());
			return -_L(EIO);
		}

		if (bytesWritten != bytesRead)
			break;

		/* move along */
		bytesCopied += bytesWritten;
		size -= bytesWritten;
		buf = (char*) buf + bytesWritten;
		(*off) += bytesWritten;
	}

	return bytesCopied;
}

static void winfs_close(filp *fp)
{
	if (fp->handle)
		CloseHandle(fp->handle);
}

static int winfs_truncate(filp *fp, uint64_t offset)
{
	LARGE_INTEGER where;
	BOOL r;

	where.QuadPart = offset;

	r = SetFilePointerEx(fp->handle, where, NULL, FILE_BEGIN);
	if (!r)
		return -_L(EPERM);

	r = SetEndOfFile(fp->handle);
	if (!r)
	{
		/* TODO: go back if we fail? */
		return -_L(EPERM);
	}

	return 0;
}

static int winfs_seek(filp *fp, int whence, uint64_t pos, uint64_t *newpos)
{
	LARGE_INTEGER Position;
	LARGE_INTEGER Result;
	BOOL r;

	Position.QuadPart = pos;
	Result.QuadPart = 0LL;

	r = SetFilePointerEx(fp->handle, Position, &Result, whence);
	if (!r)
		return -_L(EIO);

	if (newpos)
		*newpos = Result.QuadPart;

	return 0;
}

static const struct filp_ops disk_file_ops = {
	.fn_read = &file_read,
	.fn_write = &file_write,
	.fn_stat = &file_stat,
	.fn_getdents = &file_getdents,
	.fn_close = &winfs_close,
	.fn_truncate = &winfs_truncate,
	.fn_seek = &winfs_seek,
};

static int winfs_open(struct fs *fs, const char *file, int flags, int mode)
{
	WCHAR *dospath;
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
		create = CREATE_ALWAYS;
	else
		create = OPEN_EXISTING;

	dospath = unix2dos_path(file);
	dprintf("CreateFile(%S,%08lx,%08lx,NULL,%08lx,...)\n",
		dospath, access, share, create);

	/* use FILE_FLAG_BACKUP_SEMANTICS for opening directories */
	handle = CreateFileW(dospath, access, share, NULL, create,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
			NULL);

	if (handle == INVALID_HANDLE_VALUE)
	{
		dprintf("failed to open %S (%ld)\n",
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

	init_fp(fp, &disk_file_ops);
	fp->handle = handle;

	fd = alloc_fd();
	if (fd < 0)
	{
		free(fp);
		CloseHandle(handle);
		return -_L(ENOMEM);
	}

	dprintf("handle -> %p\n", handle);
	dprintf("fd -> %d\n", fd);

	current->handles[fd].fp = fp;
	current->handles[fd].flags = 0;

	return fd;
}

static int winfs_utimes(struct fs *fs, const char *path, struct timeval *times)
{
	FILETIME create_time, write_time;
	HANDLE handle;
	WCHAR *dospath;
	BOOL r = TRUE;

	if (times)
	{
		timeval_to_filetime(&times[0], &create_time);
		timeval_to_filetime(&times[1], &write_time);
	}
	else
	{
		SYSTEMTIME st;
		GetSystemTime(&st);
		SystemTimeToFileTime(&st, &create_time);
		write_time = create_time;
	}

	dospath = unix2dos_path(path);
	if (!dospath)
		return -_L(ENOENT);

	SetLastError(0);
	handle = CreateFileW(dospath, GENERIC_WRITE | GENERIC_READ,
			FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
			NULL);
	if (handle == INVALID_HANDLE_VALUE)
		return -_L(ENOENT);
	if (GetLastError() != ERROR_ALREADY_EXISTS)
		r = SetFileTime(handle, &create_time, NULL, &write_time);

	CloseHandle(handle);
	if (!r)
		return -_L(EPERM);

	return 0;
}

static struct fs winfs =
{
	.root = "/",
	.open = &winfs_open,
	.stat64 = &winfs_stat64,
	.utimes = &winfs_utimes,
};

void winfs_init(void)
{
	GetCurrentDirectoryW(sizeof rootdir/sizeof rootdir[0], rootdir);
	fs_add(&winfs);
}
