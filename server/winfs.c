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

static const char symlink_magic[] = {
	'!', '<', 's','y','m','l','i','n','k', '>'
};

static WCHAR rootdir[MAX_PATH + 1];

static const struct filp_ops winfs_file_ops;

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

static char *winfs_read_symlink_target(HANDLE handle)
{
	char buffer[0x100];
	DWORD bytes_read;
	DWORD ucs2_len, utf8_len;
	LARGE_INTEGER start;
	LPWSTR ucs2;
	char *ret;
	BOOL r;

	r = ReadFile(handle, buffer, sizeof buffer, &bytes_read, NULL);
	if (!r)
		return NULL;

	start.QuadPart = 0LL;
	SetFilePointerEx(handle, start, NULL, FILE_BEGIN);

	if (bytes_read < sizeof symlink_magic)
		return NULL;

	if (memcmp(buffer, symlink_magic, sizeof symlink_magic))
		return NULL;

	bytes_read -= sizeof symlink_magic;

	if ((bytes_read % 2) == 1)
		return NULL;

	ucs2_len = bytes_read/sizeof (WCHAR);
	ucs2 = (LPWSTR) &buffer[sizeof symlink_magic];
	if (ucs2[0] == 0xfeff && ucs2_len > 0)
	{
		ucs2++;
		ucs2_len--;
	}

	utf8_len = WideCharToMultiByte(CP_UTF8, 0,
					ucs2, ucs2_len,
					0, 0, NULL, NULL);

	ret = malloc(utf8_len + 1);

	utf8_len = WideCharToMultiByte(CP_UTF8, 0, ucs2, ucs2_len,
					ret, utf8_len, NULL, NULL);
	ret[utf8_len] = 0;

	return ret;
}

static char *winfs_get_symlink_target(HANDLE handle)
{
	BY_HANDLE_FILE_INFORMATION info;
	BOOL r;

	r = GetFileInformationByHandle(handle, &info);
	if (!r)
		return NULL;

	if (!(info.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM))
		return NULL;

	return winfs_read_symlink_target(handle);
}

/*
 * Detect a cygwin new style symlink
 *  - System attribute is set
 *  - file starts with "!<symlink>"
 */
static bool winfs_is_link(HANDLE dir, LPCWSTR name, USHORT name_length, DWORD attributes)
{
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING us;
	HANDLE handle = NULL;
	char *target;
	NTSTATUS r;

	if (!dir)
		return false;
	if (!(attributes & FILE_ATTRIBUTE_SYSTEM))
		return false;

	/* open relative to the directory */
	us.Buffer = (WCHAR*) name;
	us.Length = name_length;
	us.MaximumLength = 0;

	oa.Length = sizeof oa;
	oa.RootDirectory = dir;
	oa.ObjectName = &us;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	r = NtCreateFile(&handle, SYNCHRONIZE | FILE_READ_ACCESS, &oa, &iosb,
			0, 0, FILE_SHARE_READ, OPEN_EXISTING,
			FILE_RANDOM_ACCESS |
			FILE_NON_DIRECTORY_FILE |
			FILE_SYNCHRONOUS_IO_NONALERT,
			0, 0);
	if (r != STATUS_SUCCESS)
	{
		dprintf("NtCreateFile returned %08lx\n", r);
		return false;
	}

	target = winfs_read_symlink_target(handle);
	r = (target != NULL);
	free(target);

	CloseHandle(handle);

	return r;
}

static int winfs_stat(filp *f, struct stat64 *statbuf)
{
	BY_HANDLE_FILE_INFORMATION info;
	NTSTATUS r;
	bool is_link = false;
	size_t link_size = 0;

	r = GetFileInformationByHandle(f->handle, &info);
	if (!r)
	{
		dprintf("GetFileInformationByHandle failed (%08x)\n",
			GetLastError());
		return -_L(EPERM);
	}

	memset(statbuf, 0, sizeof *statbuf);
	if (info.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
	{
		char *target = winfs_read_symlink_target(f->handle);
		if (target)
		{
			is_link = true;
			link_size = strlen(target);
		}
		free(target);
	}

	if (is_link)
		statbuf->st_mode = 0120000;
	else
	{
		if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
			statbuf->st_mode = 0555;
		else
			statbuf->st_mode = 0755;

		if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			statbuf->st_mode |= 040000;
		else
			statbuf->st_mode |= 0100000;
	}
	statbuf->st_ctime = filetime_to_unixtime(&info.ftCreationTime,
				&statbuf->st_ctime_nsec);
	statbuf->st_mtime = filetime_to_unixtime(&info.ftLastWriteTime,
				&statbuf->st_mtime_nsec);
	statbuf->st_atime = filetime_to_unixtime(&info.ftLastAccessTime,
				&statbuf->st_atime_nsec);
	if (is_link)
	{
		statbuf->st_size = link_size;
	}
	else
	{
		statbuf->st_size = info.nFileSizeLow;
		statbuf->st_size += ((uint64_t)info.nFileSizeHigh << 32);
	}
	statbuf->st_blksize = 0x1000;
	statbuf->st_blocks = statbuf->st_size / 0x1000;

	return 0;
}

static int winfs_getdents(filp *fp, void *de, unsigned int count, fn_add_dirent add_de)
{
	int ofs = 0;
	int r;
	unsigned char *p = (unsigned char*) de;
	NTSTATUS ret;
	IO_STATUS_BLOCK iosb;
	BYTE buffer[0x1000];
	BOOL first = TRUE;
	FILE_DIRECTORY_INFORMATION *info;
	WCHAR star[] = { '*' };
	UNICODE_STRING mask;
	ULONG EntryOffset;

	mask.Length = sizeof star;
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

			if (winfs_is_link(fp->handle, info->FileName,
					info->FileNameLength, info->FileAttributes))
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
static NTSTATUS winfs_read_to_userland(HANDLE handle, void *buf,
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

static int winfs_read(filp *f, void *buf, size_t size, loff_t *off, int block)
{
	return winfs_read_to_userland(f->handle, buf, size, off);
}

static int winfs_write(filp *f, const void *buf, size_t size, loff_t *off)
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

static int winfs_readlink(filp *fp, char **buf)
{
	*buf = winfs_get_symlink_target(fp->handle);
	if (!*buf)
		return -_L(EINVAL);
	return 0;
}

static int winfs_unlink_handle(HANDLE handle)
{
	NTSTATUS r;
	IO_STATUS_BLOCK iosb;
	FILE_DISPOSITION_INFORMATION info;

	info.DeleteFile = TRUE;

	r = NtSetInformationFile(handle, &iosb,
				&info, sizeof info,
				FileDispositionInformation);

	dprintf("NtSetInformationFile -> %08x\n", r);

	return (r == STATUS_SUCCESS) ? 0 : -_L(EPERM);
}

static int winfs_unlink(filp *fp)
{
	return winfs_unlink_handle(fp->handle);
}

static int winfs_utimes(filp *fp, struct timeval *times)
{
	FILETIME create_time, write_time;
	BOOL r;

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

	r = SetFileTime(fp->handle, &create_time, NULL, &write_time);
	if (!r)
		return -_L(EPERM);

	return 0;
}

static int winfs_symlink(filp *dir, const char *name, const char *newpath)
{
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING us;
	char buffer[0x1000] = "!<symlink>\377\376";
	DWORD bytesWritten;
	WCHAR dospath[256];
	HANDLE handle = 0;
	UINT n;
	NTSTATUS r;
	int len;
	BOOL ok;
	int ret;

	if (strpbrk(name, "\\/"))
		return -_L(EPERM);

	len = MultiByteToWideChar(CP_UTF8, 0, name, -1,
				dospath, sizeof dospath);
	us.Buffer = dospath;
	us.MaximumLength = 0;
	us.Length = (len - 1) * sizeof (WCHAR);
	if (us.Length >= sizeof dospath)
		return -_L(ENAMETOOLONG);

	n = MultiByteToWideChar(CP_UTF8, 0, newpath, -1, 0, 0);
	if (n > (sizeof buffer - 12)/2)
		return -_L(ENAMETOOLONG);

	n = MultiByteToWideChar(CP_UTF8, 0, newpath, -1,
				(WCHAR*)&buffer[12], sizeof buffer - 12);

	oa.Length = sizeof oa;
	oa.RootDirectory = dir->handle;
	oa.ObjectName = &us;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	r = NtCreateFile(&handle, SYNCHRONIZE | FILE_WRITE_ACCESS | FILE_READ_ACCESS,
			&oa, &iosb, 0,
			FILE_ATTRIBUTE_SYSTEM, 0, FILE_CREATE,
			FILE_RANDOM_ACCESS |
			FILE_NON_DIRECTORY_FILE |
			FILE_SYNCHRONOUS_IO_NONALERT,
			0, 0);
	if (r != STATUS_SUCCESS)
	{
		dprintf("NtCreateFile failed %08x\n", r);
		return -_L(EPERM);
	}

	ok = WriteFile(handle, buffer, (n - 1) * 2 + 12, &bytesWritten, NULL);
	if (!ok)
	{
		winfs_unlink_handle(handle);
		ret = -_L(ENOSPC);
	}
	else
		ret = 0;

	CloseHandle(handle);

	return ret;
}

static int winfs_getname(filp *fp, char **name)
{
	NTSTATUS r;
	union {
		BYTE buffer[0x1000];
		FILE_NAME_INFORMATION NameInfo;
	} info;
	IO_STATUS_BLOCK iosb;
	int len, rootlen, i;
	char *p;
	LPWSTR subdir;
	int subdirlen;

	r = NtQueryInformationFile(fp->handle, &iosb,
				&info, sizeof info,
				FileNameInformation);
	if (r != STATUS_SUCCESS)
	{
		dprintf("NtQueryInformationFile failed %08x\n", r);
		return -_L(EPERM);
	}

	dprintf("handle %p name = %.*S\n",
		fp->handle,
		info.NameInfo.FileNameLength/2,
		info.NameInfo.FileName);

	/*
	 * Check we're under the root directory
	 * FileName has no drive letter, so drop first 2 chars
	 */
	rootlen = lstrlenW(rootdir) - 2;
	if (info.NameInfo.FileNameLength/2 < rootlen)
	{
		dprintf("name too short\n");
		return -_L(EPERM);
	}

	if (info.NameInfo.FileNameLength/2 == rootlen)
	{
		info.NameInfo.FileName[rootlen] = '\\';
		info.NameInfo.FileNameLength += 2;
	}

	if (info.NameInfo.FileName[rootlen] != '\\')
	{
		dprintf("filename length differs\n");
		return -_L(EPERM);
	}
	info.NameInfo.FileName[rootlen] = 0;

	if (lstrcmpiW(info.NameInfo.FileName, &rootdir[2]))
	{
		dprintf("filename not under root (%S != %S)\n",
			info.NameInfo.FileName, &rootdir[2]);
		return -_L(EPERM);
	}

	/* names start with a separator */
	info.NameInfo.FileName[rootlen] = '\\';
	subdir = &info.NameInfo.FileName[rootlen];
	subdirlen = info.NameInfo.FileNameLength/2 - rootlen;

	len = WideCharToMultiByte(CP_ACP, 0, subdir, subdirlen,
			NULL, 0, NULL, NULL);

	p = malloc(len + 1);
	if (!p)
		return -_L(ENOMEM);

	WideCharToMultiByte(CP_ACP, 0, subdir, subdirlen,
			p, len, NULL, NULL);
	p[len] = 0;

	/* make it... unix style */
	for (i = 0; i < len; i++)
		if (p[i] == '\\')
			p[i] = '/';

	dprintf("name -> %s\n", p);

	*name = p;

	return 0;
}

static int winfs_mkdir(filp *dir, const char *name, int mode)
{
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING us;
	WCHAR dospath[256];
	HANDLE handle = 0;
	NTSTATUS r;
	int len;

	dprintf("winfs_mkdir(%p,%s,%08x)\n", dir, name, mode);

	len = MultiByteToWideChar(CP_UTF8, 0, name, -1,
				dospath, sizeof dospath/sizeof dospath[0]);

	us.Buffer = dospath;
	us.MaximumLength = 0;
	us.Length = (len - 1) * sizeof (WCHAR);

	oa.Length = sizeof oa;
	oa.RootDirectory = dir->handle;
	oa.ObjectName = &us;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	dprintf("root = %p name = %.*S\n",
		oa.RootDirectory,
		us.Length / 2,
		us.Buffer);

	r = NtCreateFile(&handle, GENERIC_READ | GENERIC_WRITE | FILE_LIST_DIRECTORY,
			&oa, &iosb, 0,
			FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ, FILE_CREATE,
			FILE_DIRECTORY_FILE, 0, 0);
	if (r != STATUS_SUCCESS)
	{
		dprintf("NtCreateFile failed %08x\n", r);
		return -_L(EPERM);
	}

	NtClose(handle);

	return 0;
}

static int winfs_is_directory_handle(HANDLE handle)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS r;
	FILE_BASIC_INFORMATION info;

	r = NtQueryInformationFile(handle, &iosb,
				&info, sizeof info,
				FileBasicInformation);
	if (r != STATUS_SUCCESS)
		return -_L(EPERM);

	if (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		return 1;

	return 0;
}


static int winfs_rmdir(filp *dir)
{
	int r;

	r = winfs_is_directory_handle(dir->handle);
	if (r < 0)
		return r;
	if (r != 1)
		return -_L(ENOTDIR);

	return winfs_unlink_handle(dir->handle);
}

static filp *winfs_open(struct fs *fs, const char *file, int flags,
			int mode, int follow_links)
{
	WCHAR *dospath;
	DWORD access;
	DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	DWORD create = 0;
	HANDLE handle;
	filp *fp;

	dprintf("open(\"%s\",%08x,%08x)\n", file, flags, mode);

	switch (flags & 3)
	{
	case _L(O_RDONLY):
		access = GENERIC_READ;
		break;
	case _L(O_WRONLY):
		access = DELETE | GENERIC_WRITE;
		break;
	case _L(O_RDWR):
		access = DELETE | GENERIC_READ | GENERIC_WRITE;
		break;
	default:
		dprintf("bad open flags %08x\n", flags);
		return L_ERROR_PTR(EINVAL);
	}

	if (flags & _L(O_CREAT))
		create = CREATE_ALWAYS;
	else
		create = OPEN_EXISTING;

	dospath = unix2dos_path(file);
	while (1)
	{
		char *target;

		if (!dospath)
			return L_ERROR_PTR(ENOENT);

		dprintf("CreateFile(%S,%08lx,%08lx,NULL,%08lx,...)\n",
			dospath, access, share, create);

		/* FIXME: don't clobber symlinks when opening them */

		/* use FILE_FLAG_BACKUP_SEMANTICS for opening directories */
		handle = CreateFileW(dospath, access, share, NULL, create,
				FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
				NULL);
		if (handle == INVALID_HANDLE_VALUE)
		{
			access &= ~DELETE;
			handle = CreateFileW(dospath, access, share, NULL, create,
					FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
					NULL);
			if (handle == INVALID_HANDLE_VALUE)
			{
				dprintf("failed to open %S (%ld)\n",
					dospath, GetLastError());
				free(dospath);
				return L_ERROR_PTR(ENOENT);
			}
		}

		free(dospath);

		if (!follow_links)
			break;

		target = winfs_get_symlink_target(handle);
		if (!target)
			break;
		CloseHandle(handle);

		/* FIXME: only works for absolute paths */
		dprintf("symlink -> %s\n", target);
		dospath = unix2dos_path(target);
		free(target);
	}

	fp = malloc(sizeof (*fp));
	if (!fp)
	{
		CloseHandle(handle);
		return L_ERROR_PTR(ENOMEM);
	}

	init_fp(fp, &winfs_file_ops);
	fp->handle = handle;

	return fp;
}

/* FIXME: separate ops for a symlink? */
static const struct filp_ops winfs_file_ops = {
	.fn_read = &winfs_read,
	.fn_write = &winfs_write,
	.fn_stat = &winfs_stat,
	.fn_getdents = &winfs_getdents,
	.fn_close = &winfs_close,
	.fn_truncate = &winfs_truncate,
	.fn_seek = &winfs_seek,
	.fn_readlink = &winfs_readlink,
	.fn_unlink = &winfs_unlink,
	.fn_utimes = &winfs_utimes,
	.fn_symlink = &winfs_symlink,
	.fn_getname = &winfs_getname,
	.fn_mkdir = &winfs_mkdir,
	.fn_rmdir = &winfs_rmdir,
};

static struct fs winfs =
{
	.root = "/",
	.open = &winfs_open,
};

void winfs_init(void)
{
	GetCurrentDirectoryW(sizeof rootdir/sizeof rootdir[0], rootdir);

	if (rootdir[1] != ':')
		abort();

	fs_add(&winfs);
}
