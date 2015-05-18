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
#include "vm.h"
#include "minmax.h"

struct winfs_filp
{
	struct filp fp;
	HANDLE handle;
	int dir_count;
};

BOOL WINAPI GetFileSizeEx(HANDLE handle, PLARGE_INTEGER Size);

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
	LPWSTR ucs2;
	char *ret;
	BOOL r;
	OVERLAPPED ov;

	memset(&ov, 0, sizeof ov);

	r = ReadFile(handle, buffer, sizeof buffer, &bytes_read, &ov);
	if (!r)
	{
		if (GetLastError() != ERROR_IO_PENDING)
			return NULL;

		if (!GetOverlappedResult(handle, &ov, &bytes_read, TRUE))
			return NULL;
	}

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

static int winfs_stat(struct filp *fp, struct stat64 *statbuf)
{
	struct winfs_filp *wfp = (void*) fp;
	BY_HANDLE_FILE_INFORMATION info;
	NTSTATUS r;
	bool is_link = false;
	size_t link_size = 0;

	r = GetFileInformationByHandle(wfp->handle, &info);
	if (!r)
	{
		dprintf("GetFileInformationByHandle failed (%08lx)\n",
			GetLastError());
		return -_L(EPERM);
	}

	memset(statbuf, 0, sizeof *statbuf);
	if (info.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
	{
		char *target = winfs_read_symlink_target(wfp->handle);
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
	statbuf->st_nlink = info.nNumberOfLinks;
	statbuf->st_uid = current->uid;
	statbuf->st_gid = current->gid;

	/*
	 * NB. some software (e.g. glibc)
	 *     uses st_ino & st_dev to determine uniqueness.
	 *
	 * Would be nice to have 64bit inode numbers so we could do:
	 * statbuf->st_ino = (info.nFileIndexHigh << 32) | info.nFileIndexLow;
	 * the following might result in a collision.
	 *
	 * TODO: make st_dev unique across all filesystems
	 */
	statbuf->st_ino = info.nFileIndexLow;
	statbuf->st_dev = 1;

	return 0;
}

struct winfs_read_context
{
	struct process *p;
};

static NTAPI void winfs_dir_read_complete(PVOID ptr, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
	struct winfs_read_context *ctx = ptr;
	ready_list_add(ctx->p);
}

static int winfs_getdents(struct filp *fp, void *de, unsigned int count, fn_add_dirent add_de)
{
	struct winfs_filp *wfp = (void*) fp;
	int ofs = 0;
	int r;
	unsigned char *p = (unsigned char*) de;
	NTSTATUS ret;
	IO_STATUS_BLOCK iosb;
	BYTE buffer[0x1000];
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
		struct winfs_read_context ctx;
		unsigned long inode;

		ctx.p = current;

		memset(buffer, 0, sizeof buffer);
		ret = NtQueryDirectoryFile(wfp->handle, NULL,
			&winfs_dir_read_complete, &ctx, &iosb,
			buffer, sizeof buffer,
			FileDirectoryInformation, 0, NULL /*&mask*/, wfp->dir_count == 0);
		if (ret == STATUS_PENDING)
		{
			current->state = thread_stopped;
			yield();
			current->state = thread_running;

			ret = iosb.Status;
			dprintf("NtQueryDirectoryFile -> %08lx\n", ret);
		}
		else
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

			if (winfs_is_link(wfp->handle, info->FileName,
					info->FileNameLength, info->FileAttributes))
				type = _L(DT_LNK);
			else if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				type = _L(DT_DIR);
			else
				type = _L(DT_REG);

			/*
			 * Ensure the inode is non-zero.
			 * Zero inodes are considered deleted.
			 */
			inode = info->FileIndex;
			if (inode == 0)
				inode = wfp->dir_count + 1000;

			de = (struct linux_dirent*)&p[ofs];
			r = add_de(de, name, len, count - ofs,
				info->NextEntryOffset ? ++wfp->dir_count : INT_MAX,
				type, inode);
			if (r < 0)
				break;
			ofs += r;

		} while (info->NextEntryOffset);
	}

	dprintf("%d bytes added\n", ofs);

	return ofs;
}

static int winfs_read(struct filp *fp, void *buf, size_t size, loff_t *ofs, int block)
{
	struct winfs_filp *wfp = (void*) fp;
	int bytesCopied = 0;

	while (size)
	{
		OVERLAPPED ov;
		DWORD sz;
		DWORD bytesRead = 0;
		int r;

		memset(&ov, 0, sizeof ov);
		ov.OffsetHigh = (*ofs >> 32);
		ov.Offset = (*ofs & 0xffffffff);

		/*
		 * Something strange is going on here.
		 * GetOverlappedResult returns ERROR_INVALID_PARAMETER
		 * if we try to read over 0x10000 bytes.
		 * Looks like it might only happen on an SMB share,
		 * possibly something to do with VirtualBox ...
		 */
		sz = MIN(size, 0x10000);

		dprintf("reading %ld bytes at %08lx:%08lx to %p\n",
			sz, ov.OffsetHigh, ov.Offset, buf);

		r = ReadFile(wfp->handle, buf, sz, &bytesRead, &ov);
		if (!r && ((GetLastError() != ERROR_IO_PENDING) ||
			   !GetOverlappedResult(wfp->handle, &ov, &bytesRead, TRUE)))
		{
			DWORD err = GetLastError();

			if (err == ERROR_HANDLE_EOF)
			{
				LARGE_INTEGER fileSize;
				if (!GetFileSizeEx(wfp->handle, &fileSize))
					return -_L(EIO);
				size = (fileSize.QuadPart - *ofs);
				continue;
			}
			else
			{
				dprintf("ReadFile failed (%ld) at %d\n",
					err, __LINE__);
				return -_L(EIO);
			}
		}

		dprintf("bytesRead = %ld\n", bytesRead);

		if (bytesRead == 0)
			break;

		bytesCopied += bytesRead;
		buf = (char*) buf + bytesRead;
		size -= bytesRead;
		(*ofs) += bytesRead;
	}

	return bytesCopied;
}

static int winfs_write(struct filp *fp, const void *buf, size_t size, loff_t *ofs, int block)
{
	struct winfs_filp *wfp = (void*) fp;
	DWORD bytesCopied = 0;

	while (size)
	{
		OVERLAPPED ov;
		ULONG sz;
		DWORD bytesWritten;
		NTSTATUS r;
		void *ptr = NULL;
		size_t max_size = 0;

		r = vm_get_pointer(current, buf, &ptr, &max_size);
		if (r < 0)
		{
			if (bytesCopied)
				break;
			return -_L(EFAULT);
		}

		sz = size;
		if (sz > max_size)
			sz = max_size;

		memset(&ov, 0, sizeof ov);
		ov.OffsetHigh = (*ofs >> 32);
		ov.Offset = (*ofs & 0xffffffff);

		bytesWritten = 0;
		r = WriteFile(wfp->handle, ptr, sz, &bytesWritten, &ov);
		if (!r)
		{
			DWORD err = GetLastError();
			if (err == ERROR_IO_PENDING)
			{
				if (!GetOverlappedResult(wfp->handle, &ov,
							&bytesWritten, TRUE))
				{
					dprintf("WriteFile failed (%ld) at %d\n",
						err, __LINE__);
					return -_L(EIO);
				}

			}
			else
			{
				dprintf("WriteFile failed (%ld) at %d\n",
					err, __LINE__);
				return -_L(EIO);
			}
		}

		/* move along */
		bytesCopied += bytesWritten;
		size -= bytesWritten;
		buf = (char*) buf + bytesWritten;
		(*ofs) += bytesWritten;

		if (bytesWritten != sz)
			break;
	}

	return bytesCopied;
}

static void winfs_close(struct filp *fp)
{
	struct winfs_filp *wfp = (void*) fp;
	CloseHandle(wfp->handle);
}

static int winfs_truncate(struct filp *fp, uint64_t offset)
{
	struct winfs_filp *wfp = (void*) fp;
	LARGE_INTEGER where;
	BOOL r;

	where.QuadPart = offset;

	r = SetFilePointerEx(wfp->handle, where, NULL, FILE_BEGIN);
	if (!r)
		return -_L(EPERM);

	r = SetEndOfFile(wfp->handle);
	if (!r)
	{
		/* TODO: go back if we fail? */
		return -_L(EPERM);
	}

	return 0;
}

static int winfs_seek(struct filp *fp, int whence, uint64_t pos, uint64_t *newpos)
{
	struct winfs_filp *wfp = (void*) fp;
	LARGE_INTEGER Position;
	LARGE_INTEGER Result;
	BOOL r;

	Position.QuadPart = pos;
	Result.QuadPart = 0LL;

	r = SetFilePointerEx(wfp->handle, Position, &Result, whence);
	if (!r)
		return -_L(EIO);

	fp->offset = Result.QuadPart;
	if (newpos)
		*newpos = Result.QuadPart;

	return 0;
}

static int winfs_readlink(struct filp *fp, char **buf)
{
	struct winfs_filp *wfp = (void*) fp;
	*buf = winfs_get_symlink_target(wfp->handle);
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

	dprintf("NtSetInformationFile -> %08lx\n", r);

	return (r == STATUS_SUCCESS) ? 0 : -_L(EPERM);
}

static int winfs_unlink(struct filp *fp)
{
	struct winfs_filp *wfp = (void*) fp;
	return winfs_unlink_handle(wfp->handle);
}

static int winfs_utimes(struct filp *fp, struct timeval *times)
{
	struct winfs_filp *wfp = (void*) fp;
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

	r = SetFileTime(wfp->handle, &create_time, NULL, &write_time);
	if (!r)
		return -_L(EPERM);

	return 0;
}

static int winfs_symlink(struct filp *fp, const char *name, const char *newpath)
{
	struct winfs_filp *wfp = (void*) fp;
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
	oa.RootDirectory = wfp->handle;
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
		dprintf("NtCreateFile failed %08lx\n", r);
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

static int winfs_getname(struct filp *fp, char **name)
{
	struct winfs_filp *wfp = (void*) fp;
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

	r = NtQueryInformationFile(wfp->handle, &iosb,
				&info, sizeof info,
				FileNameInformation);
	if (r != STATUS_SUCCESS)
	{
		dprintf("NtQueryInformationFile failed %08lx\n", r);
		return -_L(EPERM);
	}

	dprintf("handle %p name = %.*S\n",
		wfp->handle,
		(int) info.NameInfo.FileNameLength/2,
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

static int winfs_mkdir(struct filp *fp, const char *name, int mode)
{
	struct winfs_filp *wfp = (void*) fp;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING us;
	WCHAR dospath[256];
	HANDLE handle = 0;
	NTSTATUS r;
	int len;

	dprintf("winfs_mkdir(%p,%s,%08x)\n", wfp, name, mode);

	len = MultiByteToWideChar(CP_UTF8, 0, name, -1,
				dospath, sizeof dospath/sizeof dospath[0]);

	us.Buffer = dospath;
	us.MaximumLength = 0;
	us.Length = (len - 1) * sizeof (WCHAR);

	oa.Length = sizeof oa;
	oa.RootDirectory = wfp->handle;
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
		dprintf("NtCreateFile failed %08lx\n", r);
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


static int winfs_rmdir(struct filp *fp)
{
	struct winfs_filp *wfp = (void*) fp;
	int r;

	r = winfs_is_directory_handle(wfp->handle);
	if (r < 0)
		return r;
	if (r != 1)
		return -_L(ENOTDIR);

	return winfs_unlink_handle(wfp->handle);
}

static struct filp *winfs_open(struct fs *fs, const char *file, int flags,
			int mode, int follow_links)
{
	WCHAR *dospath;
	DWORD access;
	DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	DWORD create = 0;
	HANDLE handle;
	struct winfs_filp *wfp;
	int symlink_count = 0;
	DWORD CreateFlags;
	char *target = NULL;

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

	while (1)
	{
		dospath = unix2dos_path(file);
		if (!dospath)
		{
			free(target);
			return L_ERROR_PTR(ENOENT);
		}

		dprintf("CreateFile(%S,%08lx,%08lx,NULL,%08lx,...)\n",
			dospath, access, share, create);

		/* FIXME: don't clobber symlinks when opening them */
		CreateFlags = FILE_ATTRIBUTE_NORMAL |
				FILE_FLAG_BACKUP_SEMANTICS |
				FILE_FLAG_OVERLAPPED;

		/* use FILE_FLAG_BACKUP_SEMANTICS for opening directories */
		handle = CreateFileW(dospath, access, share, NULL, create,
				CreateFlags, NULL);
		if (handle == INVALID_HANDLE_VALUE)
		{
			access &= ~DELETE;
			handle = CreateFileW(dospath, access, share, NULL, create,
					CreateFlags, NULL);
			if (handle == INVALID_HANDLE_VALUE)
			{
				dprintf("failed to open %S (%ld)\n",
					dospath, GetLastError());
				free(dospath);
				free(target);
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
		symlink_count++;
		if (symlink_count >= 256)
			return L_ERROR_PTR(ELOOP);

		/* target is relative to directory containing symlink */
		if (target[0] != '/')
		{
			char *p, *t = malloc(strlen(target) + strlen(file));
			strcpy(t, file);
			p = strrchr(t, '/');
			if (p)
				strcpy(p + 1, target);
			else
			{
				strcat(p, "/");
				strcat(p, target);
			}
			free(target);
			target = t;
		}

		/* FIXME: only works for absolute paths */
		dprintf("symlink -> %s\n", target);

		file = target;
	}
	free(target);

	wfp = malloc(sizeof (*wfp));
	if (!wfp)
	{
		CloseHandle(handle);
		return L_ERROR_PTR(ENOMEM);
	}

	init_fp(&wfp->fp, &winfs_file_ops);
	wfp->handle = handle;
	wfp->dir_count = 0;

	return &wfp->fp;
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
