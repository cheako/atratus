/*
 * inet - IPV4 protocol support (via Winsock2)
 *
 * Copyright (C) 2012 - 2013 Mike McCormack
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

#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include "ntapi.h"
#include <windows.h>
#include <mswsock.h>
#include <psapi.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <iphlpapi.h>

#ifndef alloca
#define alloca(sz) __builtin_alloca(sz)
#endif

#include "linux-errno.h"
#include "linux-defines.h"
#include "filp.h"
#include "process.h"
#include "vm.h"

#include "debug.h"

typedef size_t socklen_t;

/* missing in mingw32's mswsock */
static GUID GuidConnectEx = {
	0x25a207b9,0xddf3,0x4660,
	{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}
};
static GUID GuidAcceptEx = {
        0xb5367df1,0xcbac,0x11cf,
	{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}
};
static GUID GuidGetAcceptExSockaddrs = {
        0xb5367df2,0xcbac,0x11cf,
	{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}
};

typedef BOOL (WINAPI * LPFN_CONNECTEX)(SOCKET, const struct sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI * LPFN_ACCEPTEX)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);
typedef VOID (WINAPI * LPFN_GETACCEPTEXSOCKADDRS)(PVOID, DWORD, DWORD, DWORD, struct sockaddr **, LPINT, struct sockaddr **, LPINT);

#ifndef SO_UPDATE_CONNECT_CONTEXT
#define SO_UPDATE_CONNECT_CONTEXT     0x7010
#endif

enum socket_state
{
	ss_created,
	ss_bound,
	ss_listening,
	ss_accepting,
	ss_connecting,
	ss_connected,
	ss_disconnecting,
	ss_disconnected,
};

#define ACCEPTEX_ADDRSIZE (sizeof (struct sockaddr_in) + 16)

struct socket_filp
{
	struct filp fp;
	HANDLE handle;
	OVERLAPPED overlapped;
	struct process *thread;
	LIST_ELEMENT(struct socket_filp, item);
	LIST_ANCHOR(struct wait_entry) wl;
	enum socket_state state;
	int type;
	uint8_t buffer[ACCEPTEX_ADDRSIZE * 2];
	SOCKET incoming;
	int async_events;
};

static HANDLE inet_event;
static HWND inet_hwnd;
static LPFN_CONNECTEX pConnectEx;
static LPFN_ACCEPTEX pAcceptEx;
static LPFN_GETACCEPTEXSOCKADDRS pGetAcceptExSockaddrs;
static LIST_ANCHOR(struct socket_filp) inet_sockets;

static struct socket_filp *inet_alloc_socket(SOCKET s);
static int inet_alloc_fd(struct socket_filp *sfp, int flags);

static int WSAToErrno(const char *func)
{
	DWORD WsaError = WSAGetLastError();

	dprintf("%s returned error (%d)\n", func, WSAGetLastError());

	switch (WsaError)
	{
	case WSAEINVAL:
		return -_L(EINVAL);
	case WSAENOTSOCK:
		dprintf("WSAENOTSOCK\n");
		return -_L(ENOTSOCK);
	case WSAENOTCONN:
		dprintf("WSAENOTCONN\n");
		return -_L(ENOTCONN);
	default:
		dprintf("Unknown WSAError %ld\n", WsaError);
		return -1;
	}
}

static int inet_error_from_overlapped(struct socket_filp *sfp)
{
	SOCKET s = (SOCKET) sfp->handle;
	DWORD bytesTransferred = 0;
	DWORD err, flags = 0;
	BOOL r;

	dprintf("getting result for %p\n", sfp);
	r = WSAGetOverlappedResult(s, &sfp->overlapped,
				&bytesTransferred, FALSE, &flags);
	if (r)
	{
		dprintf("operation succeeded, %ld bytes transferred\n",
			bytesTransferred);
		return bytesTransferred;
	}

	err = GetLastError();
	switch (err)
	{
	case ERROR_TIMEOUT:
		return -_L(ETIMEDOUT);
	case ERROR_CONNECTION_REFUSED:
		return -_L(ECONNREFUSED);
	case ERROR_IO_PENDING:
		return -_L(EINTR);
	default:
		dprintf("unknown socket error %ld\n", err);
		return -_L(EACCES);
	}
}

static int inet_socket_wait_complete(struct socket_filp *sfp)
{
	/* wait for connect to complete */
	while (1)
	{
		if (HasOverlappedIoCompleted(&sfp->overlapped))
			break;

		if (process_pending_signal_check(current) ||
			current->state == thread_terminated)
		{
			WSACancelAsyncRequest(sfp->handle);
			return -_L(EINTR);
		}

		sfp->thread = current;
		schedule();
		sfp->thread = NULL;
	}


	return inet_error_from_overlapped(sfp);
}

static int inet_read(struct filp *fp, void *buf, user_size_t size, loff_t *off, int block)
{
	struct socket_filp *sfp = (struct socket_filp*) fp;
	DWORD bytesRead;
	int bytesCopied = 0;
	SOCKET s = (SOCKET) sfp->handle;
	WSABUF wsabuf;
	DWORD flags;
	int r;

	dprintf("inet_read(%p,%p,%d,%d)\n", sfp, buf, size, block);

	sfp->async_events &= ~FD_READ;

	wsabuf.buf = (void*) buf;
	wsabuf.len = size;
	bytesRead = 0;
	flags = 0;
	r = WSARecv(s, &wsabuf, 1, &bytesRead, &flags, &sfp->overlapped, NULL);
	if (r == SOCKET_ERROR)
	{
		int r;

		if (WSAGetLastError() != ERROR_IO_PENDING)
		{
			dprintf("WSARecv %p failed %ld\n",
				sfp->handle, GetLastError());
			if (bytesCopied)
				return bytesCopied;
			return WSAToErrno("inet_read");
		}

		r = inet_socket_wait_complete(sfp);
		if (r < 0)
		{
			if (bytesCopied)
				return bytesCopied;
			return r;
		}

		bytesRead = r;
	}

	return bytesRead;
}

static int inet_write(struct filp *fp, const void *buffer, user_size_t size, loff_t *off, int block)
{
	struct socket_filp *sfp = (struct socket_filp*) fp;
	SOCKET s = (SOCKET) sfp->handle;
	DWORD bytesWritten;
	WSABUF wsabuf;
	int r;

	dprintf("inet_write(%p,%p,%d)\n", sfp, buffer, size);

	wsabuf.buf = (char*) buffer;
	wsabuf.len = size;

	bytesWritten = 0;
	r = WSASend(s, &wsabuf, 1, &bytesWritten, 0, &sfp->overlapped, NULL);
	if (r == SOCKET_ERROR)
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			dprintf("WSASend %p failed %ld\n",
				sfp->handle, GetLastError());
			return -_L(EIO);
		}

		r = inet_socket_wait_complete(sfp);
		if (r < 0)
			return r;

		bytesWritten = r;
	}

	return bytesWritten;
}

static void inet_close(struct filp *fp)
{
	struct socket_filp *sfp = (struct socket_filp*) fp;
	SOCKET s = (SOCKET) sfp->handle;

	LIST_REMOVE(&inet_sockets, sfp, item);

	closesocket(s);
}

static int inet_set_reuseaddr(struct socket_filp *sfp,
				user_ptr_t optval, user_size_t optlen)
{
	SOCKET s = (SOCKET) sfp->handle;
	int val = 0;
	int r;

	if (optlen != sizeof val)
		return -_L(EINVAL);

	r = vm_memcpy_from_process(current, &val, optval, sizeof val);
	if (r < 0)
		return r;

	dprintf("reuseaddr(%p) -> %d\n", sfp, val);

	r = setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			(char*) &val, sizeof val);

	return (r == 0) ? 0 : -_L(EINVAL);
}

static int inet_set_keepalive(struct socket_filp *sfp,
				user_ptr_t optval,
				user_size_t optlen)
{
	SOCKET s = (SOCKET) sfp->handle;
	int val = 0;
	int r;

	if (optlen != sizeof val)
		return -_L(EINVAL);

	r = vm_memcpy_from_process(current, &val, optval, sizeof val);
	if (r < 0)
		return r;

	dprintf("keepalive(%p) -> %d\n", sfp, val);

	r = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
			(char*) &val, sizeof val);

	return (r == 0) ? 0 : -_L(EINVAL);
}

static int inet_setsockopt(struct socket_filp *sfp, int level, int optname,
				user_ptr_t optval, user_size_t optlen)
{
	dprintf("setsockopt(%p,%d,%d,%08x,%d)\n",
		sfp, level, optname, optval, optlen);

	if (level != _L(SOL_SOCKET))
	{
		dprintf("unknown setsockopt() level %d\n", level);
		return -_L(EINVAL);
	}

	switch (optname)
	{
	case _L(SO_REUSEADDR):
		return inet_set_reuseaddr(sfp, optval, optlen);
	case _L(SO_KEEPALIVE):
		return inet_set_keepalive(sfp, optval, optlen);
	default:
		dprintf("unknown socket option %d\n", optname);
	}

	return -_L(EINVAL);
}

static int inet_getsockopt(struct socket_filp *sfp, int level, int optname,
		 user_ptr_t optval, user_ptr_t optlen)
{
	dprintf("getsockopt(%p,%d,%d,%08x,%08x)\n",
		sfp, level, optname, optval, optlen);
	return -_L(EINVAL);
}

static int inet_connect(struct socket_filp *sfp,
			user_ptr_t addr, user_size_t addrlen, bool block)
{
	struct sockaddr_in sin;
	int r;
	SOCKET s = (SOCKET) sfp->handle;

	dprintf("connect(%p,%08x,%d) block=%d\n", sfp, addr, addrlen, block);

	if (addrlen != sizeof sin)
		return -_L(EINVAL);

	r = vm_memcpy_from_process(current, &sin, addr, addrlen);
	if (r < 0)
		return r;

	memset(&sin.sin_zero, 0, sizeof sin.sin_zero);

	if (sin.sin_family != AF_INET)
	{
		dprintf("wrong address family (%d)\n", sin.sin_family);
		return -_L(EAFNOSUPPORT);
	}

	/*
	 * bind the port to INADDR_ANY if it's not bound already
	 * Bad Win32 API design means there's no sane default and
	 * ConnectEx will return WSAEINVAL if the port is not bound.
	 */
	if (sfp->state == ss_created)
	{
		struct sockaddr_in any;

		memset(&any, 0, sizeof any);
		any.sin_family = AF_INET;
		any.sin_port = 0;
		any.sin_addr.s_addr = INADDR_ANY;
		bind(s, (void*) &any, sizeof any);
		sfp->state = ss_bound;
	}

	switch (sfp->state)
	{
	case ss_connecting:
		return -_L(EALREADY);
	case ss_bound:
		break;
	default:
		dprintf("socket in state %d\n", sfp->state);
		return -_L(EISCONN);
	}

	/*
	 * Check if we're trying to connect a UDP socket.
	 * This just sets a filter on received packets.
	 */
	if (sfp->type == SOCK_DGRAM)
	{
		uint8_t *p = (void*) &sin.sin_addr.s_addr;
		dprintf("Connecting UDP socket to %d.%d.%d.%d\n",
			p[0], p[1], p[2], p[3]);
		r = connect(s, (void*) &sin, sizeof sin);
		if (r != 0)
			return WSAToErrno("connect");
		return 0;
	}

	sfp->state = ss_connecting;

	dprintf("socket %p connecting to %ld.%ld.%ld.%ld:%d\n", sfp,
		(sin.sin_addr.s_addr >> 0) & 0xff,
		(sin.sin_addr.s_addr >> 8) & 0xff,
		(sin.sin_addr.s_addr >> 16) & 0xff,
		(sin.sin_addr.s_addr >> 24) & 0xff,
		ntohs(sin.sin_port));

	/* erg... */
	r = pConnectEx(s, (void*) &sin, sizeof sin,
			NULL, 0, NULL, &sfp->overlapped);
	if (!r)
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
			return WSAToErrno("ConnectEx");

		if (block)
			r = inet_socket_wait_complete(sfp);
		else
			return -_L(EWOULDBLOCK);
	}
	else
		r = 0;

	if (r == 0)
	{
		r = setsockopt(s, SOL_SOCKET,
				SO_UPDATE_CONNECT_CONTEXT,
				(const char*) &s, sizeof s);
		if (r != 0)
		{
			dprintf("SO_UPDATE_CONNECT_CONTEXT failed (%d)\n",
				WSAGetLastError());
		}

		sfp->state = ss_connected;
		sfp->async_events |= FD_WRITE;
	}
	else
		sfp->state = ss_disconnected;

	dprintf("connect -> %d\n", r);

	return r;
}

static int inet_bind(struct socket_filp *sfp, user_ptr_t addr, user_size_t addrlen)
{
	struct sockaddr_in sin;
	int r;
	SOCKET s = (SOCKET) sfp->handle;

	dprintf("bind(%p,%08x,%d)\n", sfp, addr, addrlen);

	if (addrlen != sizeof sin)
		return -_L(EINVAL);

	r = vm_memcpy_from_process(current, &sin, addr, addrlen);
	if (r < 0)
		return r;

	memset(&sin.sin_zero, 0, sizeof sin.sin_zero);

	if (sin.sin_family != AF_INET)
	{
		dprintf("wrong address family (%d)\n", sin.sin_family);
		return -_L(EAFNOSUPPORT);
	}

	dprintf("socket %p binding to %ld.%ld.%ld.%ld:%d\n", sfp,
		(sin.sin_addr.s_addr >> 0) & 0xff,
		(sin.sin_addr.s_addr >> 8) & 0xff,
		(sin.sin_addr.s_addr >> 16) & 0xff,
		(sin.sin_addr.s_addr >> 24) & 0xff,
		ntohs(sin.sin_port));

	r = bind(s, (void*) &sin, sizeof sin);
	if (r)
		return WSAToErrno("bind");

	sfp->state = ss_bound;

	return 0;
}

static int inet_listen(struct socket_filp *sfp, int backlog)
{
	SOCKET s = (SOCKET) sfp->handle;
	int r;

	r = listen(s, backlog);
	if (r)
		return WSAToErrno("listen");

	sfp->state = ss_listening;

	return 0;
}

static int inet_copy_accept_addr(struct socket_filp *sfp,
				DWORD recv_len,
				user_ptr_t addr, user_ptr_t addrlen)
{
	LPSOCKADDR local = NULL, remote = NULL;
	struct sockaddr_in *in_local, *in_remote;
	size_t len = sizeof (struct sockaddr_in);
	INT local_len, remote_len;
	unsigned short port;
	unsigned int sa;
	int r;

	dprintf("recvlen = %ld\n", recv_len);

	pGetAcceptExSockaddrs(sfp->buffer, recv_len,
				ACCEPTEX_ADDRSIZE,
				ACCEPTEX_ADDRSIZE,
				&local, &local_len,
				&remote, &remote_len);

	if (!remote || !local)
		return -_L(EINVAL);

	in_local = (void*) local;
	in_remote = (void*) remote;

	r = vm_memcpy_to_process(current, addr, in_remote, len);
	if (r < 0)
		return r;

	r = vm_memcpy_to_process(current, addrlen, &len, sizeof len);
	if (r < 0)
		return r;

	sa = in_local->sin_addr.s_addr;
	port = in_local->sin_port;
	dprintf("accept %p\n", sfp);
	dprintf("local: %d.%d.%d.%d:%d\n",
		(sa >> 0) & 0xff, (sa >> 8) & 0xff,
		(sa >> 16) & 0xff, (sa >> 24) & 0xff, ntohs(port));

	sa = in_remote->sin_addr.s_addr;
	port = in_remote->sin_port;
	dprintf("remote: %d.%d.%d.%d:%d\n",
		(sa >> 0) & 0xff, (sa >> 8) & 0xff,
		(sa >> 16) & 0xff, (sa >> 24) & 0xff, ntohs(port));

	return 0;
}

static int inet_accept(struct socket_filp *sfp,
			user_ptr_t addr, user_ptr_t addrlen,
			int block)
{
	SOCKET s = (SOCKET) sfp->handle;
	struct socket_filp *new_sfp;
	DWORD recv_len = 0;
	BOOL ret;
	size_t sl;
	int r;

	dprintf("accept(%p,%08x,%08x)\n", sfp, addr, addrlen);

	r = vm_memcpy_from_process(current, &sl, addrlen, sizeof sl);
	if (r < 0)
		return r;

	if (sl < sizeof (struct sockaddr_in))
		return -_L(EINVAL);

	if (sfp->state == ss_accepting)
	{
		if (!HasOverlappedIoCompleted(&sfp->overlapped))
			return -_L(EAGAIN);
		r = inet_error_from_overlapped(sfp);
		if (r < 0)
			return r;

		recv_len = r;

		goto accepted;
	}

	if (sfp->state != ss_listening)
	{
		dprintf("socket not listening\n");
		return -_L(EINVAL);
	}

	sfp->incoming = socket(AF_INET, SOCK_STREAM, 0);
	if (sfp->incoming == INVALID_SOCKET)
		return -_L(EMFILE);

	memset(sfp->buffer, 0, sizeof sfp->buffer);
	ret = pAcceptEx(s, sfp->incoming, sfp->buffer, 0,
			ACCEPTEX_ADDRSIZE, ACCEPTEX_ADDRSIZE,
			&recv_len, &sfp->overlapped);
	if (!ret)
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
		{
			closesocket(sfp->incoming);
			return WSAToErrno("ConnectEx");
		}

		sfp->state = ss_accepting;

		if (!block)
			return -_L(EAGAIN);
		r = inet_socket_wait_complete(sfp);
		if (r < 0)
			return r;

		recv_len = r;
	}

accepted:
	/*
	 * return parent socket to listening state
	 * so it can accept further connections
	 */
	sfp->state = ss_listening;

	r = inet_copy_accept_addr(sfp, recv_len, addr, addrlen);
	if (r < 0)
	{
		closesocket(sfp->incoming);
		return -_L(EFAULT);
	}
	else
	{
		r = setsockopt(sfp->incoming, SOL_SOCKET,
				SO_UPDATE_ACCEPT_CONTEXT,
				(const char*) &s, sizeof s);
		if (r != 0)
		{
			dprintf("SO_UPDATE_ACCEPT_CONTEXT failed (%d)\n",
				WSAGetLastError());
		}
	}

	new_sfp = inet_alloc_socket(sfp->incoming);
	if (!new_sfp)
		return -_L(ENOMEM);

	new_sfp->type = sfp->type;
	new_sfp->state = ss_connected;
	new_sfp->async_events |= FD_WRITE;

	return inet_alloc_fd(new_sfp, O_RDWR);
}

static int inet_shutdown(struct socket_filp *sfp, int how)
{
	SOCKET s = (SOCKET) sfp->handle;
	int r;

	dprintf("shutdown(%p,%d)\n", sfp, how);

	STATIC_ASSERT(_L(SHUT_RD) == SD_RECEIVE);
	STATIC_ASSERT(_L(SHUT_WR) == SD_SEND);
	STATIC_ASSERT(_L(SHUT_RDWR) == SD_BOTH);

	r = shutdown(s, how);
	if (r != 0)
		return WSAToErrno("shutdown");

	return 0;
}

static int inet_getpeername(struct socket_filp *sfp,
			user_ptr_t addr, user_ptr_t addrlen)
{
	SOCKET s = (SOCKET) sfp->handle;
	struct sockaddr_in sin;
	int len = sizeof sin;
	size_t maxlen = 0;
	int r;

	dprintf("getpeername(%p,%08x,%08x)\n", sfp, addr, addrlen);

	r = vm_memcpy_from_process(current, &maxlen, addrlen, sizeof (size_t));
	if (r < 0)
		return r;

	r = getpeername(s, (void*) &sin, &len);
	if (r != 0)
		return WSAToErrno("getpeername");

	if (len > maxlen)
		len = maxlen;

	r = vm_memcpy_to_process(current, addrlen, &len, sizeof (size_t));
	if (r < 0)
		return r;

	r = vm_memcpy_to_process(current, addr, &sin, len);
	if (r < 0)
		return r;

	return 0;
}

static int inet_getsockname(struct socket_filp *sfp,
			user_ptr_t addr, user_ptr_t addrlen)
{
	SOCKET s = (SOCKET) sfp->handle;
	struct sockaddr_in sin;
	int len = sizeof sin;
	size_t maxlen = 0;
	int r;

	dprintf("getsockname(%p,%08x,%08x)\n", sfp, addr, addrlen);

	r = vm_memcpy_from_process(current, &maxlen, addrlen, sizeof (size_t));
	if (r < 0)
		return r;

	r = getsockname(s, (void*) &sin, &len);
	if (r != 0)
		return WSAToErrno("getsockname");

	if (len > maxlen)
		len = maxlen;

	r = vm_memcpy_to_process(current, addrlen, &len, sizeof (size_t));
	if (r < 0)
		return r;

	r = vm_memcpy_to_process(current, addr, &sin, len);
	if (r < 0)
		return r;

	return 0;
}

static int inet_fill_wsabuf(struct process *p, user_ptr_t ptr, user_size_t len,
				WSABUF *buf, size_t bufcount)
{
	int r, n = 0;

	while (len)
	{
		void *bufptr = NULL;
		size_t max = 0;
		if (n >= bufcount)
		{
			dprintf("%s(): too many buffers\n", __FUNCTION__);
			return -_L(EFAULT);
		}
		r = vm_get_pointer(p, ptr, &bufptr, &max);
		if (r < 0)
			return r;
		buf[n].buf = bufptr;
		if (max > len)
			buf[n].len = len;
		else
			buf[n].len = max;
		len -= buf[n].len;
		n++;
	}

	return n;
}

static int inet_send(struct socket_filp *sfp,
			user_ptr_t ptr, user_size_t len, int flags)
{
	SOCKET s = (SOCKET) sfp->handle;
	struct process *p = current;
	WSABUF buf[10];
	DWORD bytesSent = 0;
	ULONG wsaFlags = 0;
	int r, n;

	dprintf("send(%p,%08x,%d,%08x)\n", sfp, ptr, len, flags);

	if (flags & _L(MSG_DONTROUTE))
		wsaFlags |= MSG_DONTROUTE;
	if (flags & _L(MSG_OOB))
		wsaFlags |= MSG_OOB;

	n = inet_fill_wsabuf(p, ptr, len, buf, sizeof buf/sizeof buf[0]);
	if (n < 0)
		return n;

	r = WSASend(s, buf, n, &bytesSent, wsaFlags, &sfp->overlapped, NULL);
	if (r == SOCKET_ERROR)
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			dprintf("WSASend %p failed %d\n",
				sfp->handle, WSAGetLastError());
			return -_L(EIO);
		}

		r = inet_socket_wait_complete(sfp);
		if (r < 0)
			return r;
	}

	dprintf("send(): wrote %ld bytes\n", bytesSent);

	return bytesSent;
}

static int inet_recvfrom(struct socket_filp *sfp, user_ptr_t ptr, user_size_t len,
			int flags, user_ptr_t src_addr, user_size_t addrlen)
{
	SOCKET s = (SOCKET) sfp->handle;
	struct process *p = current;
	ULONG wsaFlags = 0;
	WSABUF buf[10];
	DWORD bytesRead = 0;
	struct sockaddr_in *from;
	INT fromlen = 0;
	int n, r;
	unsigned int sa;

	dprintf("recvfrom(%p,%08x,%d,%08x,%08x,%08x)\n",
		 sfp, ptr, len, flags, src_addr, addrlen);

	if (flags & _L(MSG_DONTROUTE))
		wsaFlags |= MSG_DONTROUTE;
	if (flags & _L(MSG_OOB))
		wsaFlags |= MSG_OOB;

	n = inet_fill_wsabuf(p, ptr, len, buf, sizeof buf/sizeof buf[0]);
	if (n < 0)
		return n;

	r = vm_memcpy_from_process(p, &fromlen, addrlen, sizeof fromlen);
	if (r < 0)
		return r;

	from = alloca(fromlen);

	r = WSARecvFrom(s, buf, n, &bytesRead, &wsaFlags,
			(void*) from, &fromlen, &sfp->overlapped, NULL);
	if (r == SOCKET_ERROR)
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			dprintf("WSARecvFrom %p failed %d\n",
				sfp->handle, WSAGetLastError());
			return -_L(EIO);
		}

		r = inet_socket_wait_complete(sfp);
		if (r < 0)
			return r;
	}
	r = bytesRead;

	vm_memcpy_to_process(p, addrlen, &fromlen, sizeof addrlen);
	vm_memcpy_to_process(p, src_addr, from, fromlen);

	sa = from->sin_addr.s_addr;
	dprintf("recvfrom(): got %ld bytes from %d.%d.%d.%d\n",
		bytesRead,
		sa & 0xff, (sa >> 8) & 0xff,
		(sa >> 16) & 0xff, (sa >> 24) & 0xff);

	return r;
}

static int inet_recv(struct socket_filp *sfp,
			user_ptr_t ptr, user_size_t len, int flags)
{
	dprintf("recv(%p,%08x,%d,%08x)\n", sfp, ptr, len, flags);

	return -_L(ENOSYS);
}

static int inet_sendto(struct socket_filp *sfp, user_ptr_t ptr, user_size_t len,
			int flags, user_ptr_t src_addr, user_size_t addrlen)
{
	SOCKET s = (SOCKET) sfp->handle;
	struct process *p = current;
	struct sockaddr_in sin;
	DWORD bytesSent = 0;
	ULONG wsaFlags = 0;
	WSABUF buf[10];
	int n, r;

	dprintf("sendto(%p,%08x,%d,%08x,%08x,%d)\n",
		 sfp, ptr, len, flags, src_addr, addrlen);

	if (addrlen < sizeof sin)
		return -_L(EINVAL);

	r = vm_memcpy_from_process(p, &sin, src_addr, sizeof sin);
	if (r < 0)
		return r;

	n = inet_fill_wsabuf(p, ptr, len, buf, sizeof buf/sizeof buf[0]);
	if (n < 0)
		return n;

	if (flags & _L(MSG_DONTROUTE))
		wsaFlags |= MSG_DONTROUTE;
	if (flags & _L(MSG_OOB))
		wsaFlags |= MSG_OOB;

	r = WSASendTo(s, buf, n, &bytesSent, wsaFlags,
			(void*) &sin, sizeof sin,
			&sfp->overlapped, NULL);
	if (r == SOCKET_ERROR)
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			dprintf("WSASendTo %p failed %d\n",
				sfp->handle, WSAGetLastError());
			return -_L(EIO);
		}

		r = inet_socket_wait_complete(sfp);
		if (r < 0)
			return r;
	}

	return bytesSent;
}

static int inet_sockcall(int call, struct filp *fp, unsigned long *args, int block)
{
	struct socket_filp *sfp = (struct socket_filp*) fp;

	switch (call)
	{
	case _L(SYS_SETSOCKOPT):
		return inet_setsockopt(sfp, args[1], args[2],
					args[3], args[4]);
	case _L(SYS_CONNECT):
		return inet_connect(sfp, args[1], args[2], block);
	case _L(SYS_BIND):
		return inet_bind(sfp, args[1], args[2]);
	case _L(SYS_LISTEN):
		return inet_listen(sfp, args[1]);
	case _L(SYS_ACCEPT):
		return inet_accept(sfp, args[1], args[2], block);
	case _L(SYS_SHUTDOWN):
		return inet_shutdown(sfp, args[1]);
	case _L(SYS_GETPEERNAME):
		return inet_getpeername(sfp, args[1], args[2]);
	case _L(SYS_GETSOCKNAME):
		return inet_getsockname(sfp, args[1], args[2]);
	case _L(SYS_SEND):
		return inet_send(sfp, args[1], args[2], args[3]);
	case _L(SYS_RECVFROM):
		return inet_recvfrom(sfp, args[1], args[2], args[3],
					 args[4], args[5]);
	case _L(SYS_GETSOCKOPT):
		return inet_getsockopt(sfp, args[1], args[2],
					args[3], args[4]);
	case _L(SYS_SENDTO):
		return inet_sendto(sfp, args[1], args[2], args[3],
					args[4], args[5]);
	case _L(SYS_RECV):
		return inet_recv(sfp, args[1], args[2], args[3]);
	case _L(SYS_SOCKETPAIR):
	case _L(SYS_SENDMSG):
	case _L(SYS_RECVMSG):
		dprintf("socketcall(%d) unhandled\n", call);
		break;
	default:
		break;
	}
	return -_L(ENOSYS);
}

static void inet_poll_add(struct filp *f, struct wait_entry *we)
{
	struct socket_filp *sfp = (struct socket_filp*) f;

	LIST_APPEND(&sfp->wl, we, item);
}

static void inet_poll_del(struct filp *f, struct wait_entry *we)
{
	struct socket_filp *sfp = (struct socket_filp *) f;

	LIST_REMOVE(&sfp->wl, we, item);
}

static int inet_poll(struct filp *f)
{
	struct socket_filp *sfp = (struct socket_filp*) f;
	int events = 0;

	switch (sfp->state)
	{
	case ss_accepting:
	case ss_connecting:
		if (HasOverlappedIoCompleted(&sfp->overlapped))
			events |= _L(POLLIN);
		return events;
	case ss_disconnected:
	case ss_disconnecting:
		return _L(POLLHUP);
	default:
		break;
	}

	if (sfp->async_events & FD_ACCEPT)
		events |= _l_POLLIN;
	if (sfp->async_events & FD_CONNECT)
		events |= _l_POLLIN;
	if (sfp->async_events & FD_READ)
		events |= _l_POLLIN;
	if (sfp->async_events & FD_WRITE)
		events |= _l_POLLOUT;
	if (sfp->async_events & FD_CLOSE)
		events |= _l_POLLIN;

	return events;
}

static int inet_stat(struct filp *fp, struct stat64 *statbuf)
{
	return -_L(ESPIPE);
}

static int inet_seek(struct filp *fp, int whence,
			uint64_t pos, uint64_t *newpos)
{
	return -_L(ESPIPE);
}

static int inet_ioctl_nread(struct socket_filp *sfp, user_ptr_t arg)
{
	SOCKET s = (SOCKET) sfp->handle;
	unsigned long count = 0;
	DWORD bytesRead = 0;
	int r;

	r = WSAIoctl(s, FIONREAD, NULL, 0, &count, sizeof count,
			 &bytesRead, &sfp->overlapped, NULL);
	if (r == SOCKET_ERROR)
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			dprintf("WSARecvFrom %p failed %d\n",
				sfp->handle, WSAGetLastError());
			return -_L(EIO);
		}

		r = inet_socket_wait_complete(sfp);
		if (r < 0)
			return r;
	}


	dprintf("FIONREAD -> %ld\n", count);

	return vm_memcpy_to_process(current, arg, &count, sizeof count);
}

static int inet_ioctl(struct filp *f, int cmd, unsigned long arg)
{
	struct socket_filp *sfp = (struct socket_filp*) f;

	dprintf("ioctl(%p,%08x,%ld)\n", sfp, cmd, arg);

	switch (cmd)
	{
	case _L(FIONREAD):
		return inet_ioctl_nread(sfp, arg);
	default:
		dprintf("unknown socket ioctl %d\n", cmd);
		return -_L(EINVAL);
	}
}

static const struct filp_ops inet_ops = {
	.fn_read = &inet_read,
	.fn_write = &inet_write,
	.fn_close = &inet_close,
	.fn_sockcall = &inet_sockcall,
	.fn_poll = &inet_poll,
	.fn_poll_add = &inet_poll_add,
	.fn_poll_del = &inet_poll_del,
	.fn_stat = &inet_stat,
	.fn_seek = &inet_seek,
	.fn_ioctl = &inet_ioctl,
};

int inet4_socket(int type, int protocol)
{
	struct socket_filp *sfp;
	SOCKET s;
	int flags = O_RDWR;

	dprintf("socket(%d,%d)\n", type, protocol);

	STATIC_ASSERT(SOCK_STREAM == _L(SOCK_STREAM));
	STATIC_ASSERT(SOCK_DGRAM == _L(SOCK_DGRAM));
	STATIC_ASSERT(SOCK_RAW == _L(SOCK_RAW));

	STATIC_ASSERT(IPPROTO_IP == _L(IPPROTO_IP));
	STATIC_ASSERT(IPPROTO_TCP == _L(IPPROTO_TCP));
	STATIC_ASSERT(IPPROTO_ICMP == _L(IPPROTO_ICMP));

	if (type & _L(O_NONBLOCK))
	{
		flags |= _L(O_NONBLOCK);
		type &= ~_L(O_NONBLOCK);
	}

	switch (type)
	{
	case SOCK_STREAM:
		dprintf("SOCK_STREAM %s\n", flags ? "non-blocking" : "");
		if (protocol != _L(IPPROTO_IP) && protocol != _L(IPPROTO_TCP))
			return -_L(EINVAL);
		break;
	case SOCK_DGRAM:
		dprintf("SOCK_DGRAM %s\n", flags ? "non-blocking" : "");
		if (protocol != _L(IPPROTO_IP) && protocol != _L(IPPROTO_UDP))
			return -_L(EINVAL);
		break;
	case SOCK_RAW:
		dprintf("SOCK_RAW %s\n", flags ? "non-blocking" : "");
		break;
	default:
		dprintf("type %d protocol %d unsupported\n", type, protocol);
		return -_L(EINVAL);
	}


	s = WSASocket(AF_INET, type, protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (s == INVALID_SOCKET)
		return -_L(EINVAL);

	sfp = inet_alloc_socket(s);
	if (!sfp)
		return -_L(ENOMEM);

	sfp->type = type;

	return inet_alloc_fd(sfp, flags);
}

static struct socket_filp *inet_alloc_socket(SOCKET s)
{
	struct socket_filp *sfp;
	int r;

	sfp = malloc(sizeof (*sfp));
	if (!sfp)
	{
		closesocket(s);
		return NULL;
	}

	memset(sfp, 0, sizeof *sfp);

	sfp->overlapped.hEvent = inet_event;
	sfp->state = ss_created;

	init_fp(&sfp->fp, &inet_ops);
	sfp->handle = (HANDLE) s;

	LIST_APPEND(&inet_sockets, sfp, item);

	r = WSAAsyncSelect(s, inet_hwnd, WM_USER,
		FD_READ | FD_WRITE | FD_ACCEPT | FD_CONNECT | FD_CLOSE);
	if (r == SOCKET_ERROR)
	{
		dprintf("WSAAsync select failed (%d)\n", WSAGetLastError());
		closesocket(s);
		free(sfp);
		return NULL;
	}

	return sfp;
}

static int inet_alloc_fd(struct socket_filp *sfp, int flags)
{
	int fd;

	fd = alloc_fd();
	if (fd < 0)
	{
		inet_close(&sfp->fp);
		return -_L(ENOMEM);
	}

	dprintf("socket %p, fd %d, fp %p\n", sfp, fd, sfp);

	current->handles[fd].fp = &sfp->fp;
	current->handles[fd].flags = flags;

	return fd;
}

void inet4_process_events(void)
{
	struct socket_filp *sfp;

	ResetEvent(inet_event);

	LIST_FOR_EACH(&inet_sockets, sfp, item)
	{
		if (sfp->thread &&
			HasOverlappedIoCompleted(&sfp->overlapped))
		{
			dprintf("socket %p ready\n", sfp);
			ready_list_add(sfp->thread);
		}
	}
}

/*
 * Use insane API to get ConnectEx or AcceptEx function pointers
 * The whole winsock API appears to be designed to make backporting difficult
 */
static void inet4_resolve_functions(void)
{
	DWORD count;
	SOCKET s;
	int r;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
		return;

	r = WSAIoctl(s,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidConnectEx,
		sizeof (GuidConnectEx),
		&pConnectEx,
		sizeof pConnectEx,
		&count,
		NULL,
		NULL);
	if (r != 0)
		pConnectEx = 0;

	r = WSAIoctl(s,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidAcceptEx,
		sizeof (GuidAcceptEx),
		&pAcceptEx,
		sizeof pAcceptEx,
		&count,
		NULL,
		NULL);
	if (r != 0)
		pAcceptEx = 0;

	r = WSAIoctl(s,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidGetAcceptExSockaddrs,
		sizeof (GuidGetAcceptExSockaddrs),
		&pGetAcceptExSockaddrs,
		sizeof pGetAcceptExSockaddrs,
		&count,
		NULL,
		NULL);
	if (r != 0)
		pGetAcceptExSockaddrs = 0;

	close(s);
}

static void inet_on_async_select(WPARAM wParam, LPARAM lParam)
{
	struct socket_filp *sfp;

	dprintf("async_select %d %08x\n", (UINT) wParam, (UINT) lParam);

	LIST_FOR_EACH(&inet_sockets, sfp, item)
	{
		SOCKET s = (SOCKET) sfp->handle;
		if (s == wParam)
		{
			struct wait_entry *we;

			sfp->async_events |= lParam;

			if (sfp->thread)
				ready_list_add(sfp->thread);

			LIST_FOR_EACH(&sfp->wl, we, item)
				ready_list_add(we->p);

			return;
		}
	}

	dprintf("socket %d not found\n", (UINT) wParam);
}

/*
 * It would be preferable to be able to do overlapped I/O
 * to find out whether a socket is ready for reading or writing...
 */
static LRESULT CALLBACK
inet_wndproc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CREATE:
		return 0;
	case WM_USER:
		inet_on_async_select(wParam, lParam);
		return 0;
	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

static void inet4_create_message_window(void)
{
	WNDCLASS wndcls;

	memset(&wndcls, 0, sizeof wndcls);
	wndcls.lpszClassName = "ATRATUS_INET_MESSAGE_CLASS";
	wndcls.lpfnWndProc = &inet_wndproc;

	if (!RegisterClass(&wndcls))
	{
		dprintf("failed to register window class\n");
		exit(1);
	}

	inet_hwnd = CreateWindow(wndcls.lpszClassName,
			"ATRATUS_INET_MESSAGE_WINDOW",
			0, 0, 0, 1, 1, NULL, NULL, NULL, NULL);
	if (!inet_hwnd)
	{
		dprintf("failed to create window\n");
		exit(1);
	}

	dprintf("inet_hwnd = %p\n", inet_hwnd);
}

/*
 * Write out /etc/resolve.conf
 *
 * Can be improved by making this a file in /proc
 * and symlinking /etc/resolv.conf -> /proc/atratus/resolv.conf
 */
void inet4_write_resolv_conf(void)
{
	FIXED_INFO *fi;
	DWORD r;
	FILE *f;
	DWORD len = 0;
	IP_ADDR_STRING *ips;

	fi = malloc(sizeof *fi);
	len = sizeof *fi;

	r = GetNetworkParams(fi, &len);
	if (r != ERROR_SUCCESS)
		goto error;

	fi = realloc(fi, len);
	r = GetNetworkParams(fi, &len);
	if (r != ERROR_SUCCESS)
		goto error;

	f = fopen("etc/resolv.conf", "wb");
	if (!f)
		goto error;

	fprintf(f, "# automatically generated by atratus.exe\n\n");

	for (ips = &fi->DnsServerList; ips; ips = ips->Next)
		fprintf(f, "nameserver %s\n", ips->IpAddress.String);

	fprintf(f, "search %s\n", fi->DomainName);

	fclose(f);

error:
	free(fi);
}

HANDLE inet4_init(void)
{
	WSADATA wsaData;

	if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		fprintf(stderr, "WSAStartup failed\n");
		exit(1);
	}

	inet4_write_resolv_conf();

	inet4_resolve_functions();

	inet4_create_message_window();

	/*
	 * use single event flag for all overlapped operations
	 */
	inet_event = CreateEvent(NULL, TRUE, 0, NULL);

	return inet_event;
}
