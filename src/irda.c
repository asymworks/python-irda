/*
 * Copyright (C) 2011 Asymworks, LLC.  All Rights Reserved.
 * www.asymworks.com / info@asymworks.com
 *
 * This file is part of the jkDiveLog Package (jkdivelog.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * The majority of this IrDA driver package was adapted from libdivecomputer,
 * Copyright (C) 2008 Jef Driesen.  libdivecomputer can be found online at
 * http://www.divesoftware.org/libdc/
 */

#include <stddef.h> // size_t
#include <stdlib.h> // malloc, free
#include <stdio.h>	// snprintf
#include <time.h>   // clock

#if defined(_WIN32) || defined(WIN32)
#include <assert.h>			// assert
#include <stdio.h>			// _snprintf
#include <winsock2.h>
#include <windows.h>
#include <af_irda.h>
#else
#include <errno.h>			// errno
#include <fcntl.h>			// fcntl
#include <string.h>			// strerror
#include <sys/ioctl.h>		// ioctl
#include <sys/poll.h>		// poll
#include <sys/socket.h>		// socket
#include <linux/irda.h>		// irda
#include <linux/types.h>	// irda
#endif

#include "irda.h"

#if defined(_WIN32) || defined(WIN32) || defined(HAVE_POLL)
// Windows doesn't have a limit on file descriptor value in select()
#define IS_SELECTABLE(s) ((s)->timeout > 0)
#else
// POSIX however does not allow the file descriptor to be above FD_SETSIZE in select()
#define IS_SELECTABLE(s) ((((s)->fd >= 0) && ((s)->fd < FD_SETSIZE)) || ((s)->timeout > 0))
#endif

#if defined(_WIN32) || defined(WIN32)
typedef SOCKET			socket_t;
typedef int 			socklen_t;
#else
typedef int				socket_t;
#define INVALID_SOCKET	(socket_t)(-1)
#endif

struct _irda_t
{
	socket_t	fd;
	long		timeout;
};

int irda_errcode(void)
{
#if defined(_WIN32) || defined(WIN32)
	return WSAGetLastError();
#else
	return errno;
#endif
}

const char * irda_errmsg(void)
{
#if defined(_WIN32) || defined(WIN32)
	static char buffer[256] = { 0 };
	unsigned int size = sizeof(buffer) / sizeof(char);

	int errcode = WSAGetLastError();
	DWORD rc = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, errcode, 0, buffer, size, NULL);

	// Remove certain characters ('\r', '\n' and '.')
	// at the end of the error message.
	while (rc > 0 && (
			buffer[rc-1] == '\n' ||
			buffer[rc-1] == '\r' ||
			buffer[rc-1] == '.'))
	{
		buffer[rc-1] = '\0';
		rc--;
	}

	if (rc)
		return buffer;
	else
		return NULL;
#else
	return strerror(errno);
#endif
}

int irda_init(void)
{
#if defined(_WIN32) || defined(WIN32)
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
		return -1;

	// Confirm that the WinSock DLL supports 2.2.
	// Note that if the DLL supports versions greater
	// than 2.2 in addition to 2.2, it will still return
	// 2.2 in wVersion since that is the version we requested.
	if (LOBYTE (wsaData.wVersion) != 2 ||
		HIBYTE (wsaData.wVersion) != 2)
	{
		WSACleanup();
		return -1;
	}
#endif

	return 0;
}

int irda_cleanup(void)
{
#if defined(_WIN32) || defined(WIN32)
	if (WSACleanup() != 0)
		return -1;
#endif

	return 0;
}

#if defined(_WIN32) || defined(WIN32)
#define CHECK_IRDA_HANDLE(s) \
	if (s == NULL) \
	{ \
		SetLastError(ERROR_INVALID_HANDLE); \
		return -1; \
	}
#else
#define CHECK_IRDA_HANDLE(s) \
	if (s == NULL) \
	{ \
		errno = EINVAL; \
		return -1; \
	}
#endif

int irda_socket_open(irda_t * s)
{
	irda_t device;
	CHECK_IRDA_HANDLE(s)

	device = (irda_t)malloc(sizeof(struct _irda_t));
	if (device == NULL)
	{
#if defined(_WIN32) || defined(WIN32)
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
#else
		errno = ENOMEM;
#endif

		return -1;
	}

	device->timeout = -1;
	device->fd = socket(AF_IRDA, SOCK_STREAM, 0);
	if (device->fd == INVALID_SOCKET)
	{
		free (device);
		return -1;
	};

	*s = device;

	return 0;
}

int irda_socket_close(irda_t s)
{
	CHECK_IRDA_HANDLE(s)

	shutdown(s->fd, 0);

#if defined(_WIN32) || defined(WIN32)
	if (closesocket(s->fd) != 0)
#else
	if (close(s->fd) != 0)
#endif
	{
		free(s);
		return -1;
	}

	free(s);
	return 0;
}

int irda_socket_set_timeout(irda_t s, long timeout)
{
#if defined(_WIN32) || defined(WIN32)
	int noblock;
#else
	int delay_flag;
#endif

	CHECK_IRDA_HANDLE(s)

	if (timeout < 0)
		s->timeout = -1;
	else
		s->timeout = timeout;

#if defined(_WIN32) || defined(WIN32)
	noblock = (s->timeout >= 0);
	ioctlsocket(s->fd, FIONBIO, (u_long*)&noblock);
#else
	delay_flag = fcntl(s->fd, F_GETFL, 0);
	if (s->timeout < 0)
		delay_flag &= (~O_NONBLOCK);
	else
		delay_flag |= O_NONBLOCK;
	fcntl(s->fd, F_SETFL, delay_flag);
#endif

	return 0;
}

int irda_socket_timeout(irda_t s, long * timeout)
{
	CHECK_IRDA_HANDLE(s)

	* timeout = s->timeout;

	return 0;
}

#define DISCOVER_MAX_DEVICES 16	// Maximum number of devices.
#define DISCOVER_MAX_RETRIES 4	// Maximum number of retries.

#if defined(_WIN32) || defined(WIN32)
#define DISCOVER_BUFSIZE sizeof (DEVICELIST) + sizeof (IRDA_DEVICE_INFO) * (DISCOVER_MAX_DEVICES - 1)
#define NUMDEVICES numDevice
#else
#define DISCOVER_BUFSIZE sizeof (struct irda_device_list) +	sizeof (struct irda_device_info) * (DISCOVER_MAX_DEVICES - 1)
#define NUMDEVICES len
#endif

int irda_socket_discover(irda_t s, irda_callback_t cb, void * userdata)
{
	int rc = 0;
	unsigned int nretries = 0;
	unsigned char data[DISCOVER_BUFSIZE] = { 0 };

#if defined(_WIN32) || defined(WIN32)
	DEVICELIST * list = (DEVICELIST *)data;
	int size = sizeof(data);
#else
	struct irda_device_list * list = (struct irda_device_list *)data;
	socklen_t size = sizeof(data);
#endif

	CHECK_IRDA_HANDLE(s)

	while ((rc = getsockopt(s->fd, SOL_IRLMP, IRLMP_ENUMDEVICES, (char *)data, & size)) != 0 || list->NUMDEVICES == 0)
	{
		// Check for an error in getsockopt() other than socket timeout
#if defined(_WIN32) || defined(WIN32)
		if (rc != 0 && WSAGetLastError() != WSAEWOULDBLOCK)
#else
		if (rc != 0 && errno != EAGAIN)
#endif
			return -1;

		// Give up after DISCOVER_MAX_RETRIES
		if (nretries++ >= DISCOVER_MAX_RETRIES)
			return 0;

		// Size can be modified by getsockopt()
		size = sizeof (data);

		// Wait 1 second and retry
#if defined(_WIN32) || defined(WIN32)
		Sleep(1000);
#else
		sleep(1);
#endif
	}

	if (cb != NULL)
	{
		unsigned int i;

#if defined(_WIN32) || defined(WIN32)
		for (i = 0; i < list->numDevice; ++i) {
			unsigned int address =
						(list->Device[i].irdaDeviceID[0] << 24) +
						(list->Device[i].irdaDeviceID[1] << 16) +
						(list->Device[i].irdaDeviceID[2] <<  8) +
						(list->Device[i].irdaDeviceID[3]      );
			unsigned int hints =
						(list->Device[i].irdaDeviceHints1 << 8) +
						(list->Device[i].irdaDeviceHints2     );

			cb(address,
				list->Device[i].irdaDeviceName,
				list->Device[i].irdaCharSet,
				hints,
				userdata);
		}
#else
		for (i = 0; i < list->len; ++i) {
			unsigned int hints =
						(list->dev[i].hints[0] << 8) +
						(list->dev[i].hints[1]     );

			cb(list->dev[i].daddr,
				list->dev[i].info,
				list->dev[i].charset,
				hints,
				userdata);
		}
#endif
	}

	return list->NUMDEVICES;
}

/*
 * Taken from Python sockets library.
 *
 * Do a select()/poll() on the socket, if necessary (sock_timeout > 0).
 * The argument writing indicates the direction.
 * Returns 1 on timeout, -1 on error, 0 otherwise.
 */
int internal_select(irda_t s, int writing, long interval)
{
	int n;

	// If socket is non-blocking, nothing to do
	if ((s->timeout <= 0) || (s->fd < 0))
		return 0;

	// If interval is negative, "auto-timeout"
	if (interval < 0)
		return 1;

#ifdef HAVE_POLL
	{
		struct pollfd pollfd;
		pollfd.fd = s->fd;
		pollfd.events = writing ? POLLOUT : POLLIN;

		n = poll(& pollfd, 1, s->timeout);
	}
#else
	{
		fd_set fds;
		struct timeval tv;
		tv.tv_sec = interval / 1000;
		tv.tv_usec = (interval % 1000) * 1000;

		FD_ZERO(& fds);
		FD_SET(s->fd, &fds);

		if (writing)
			n = select(s->fd+1, NULL, & fds, NULL, & tv);
		else
			n = select(s->fd+1, & fds, NULL, NULL, & tv);
	}
#endif

	if (n < 0)
		return -1;
	if (n == 0)
		return 1;

	return 0;
}

long ms_time(void)
{
	clock_t t = clock();
	return (t * 1000 / CLOCKS_PER_SEC);
}

#if defined(_WIN32) || defined(WIN32)
#ifndef WSAEAGAIN
#define WSAEAGAIN WSAEWOULDBLOCK
#endif
#define CHECK_ERRNO(expected) \
	(WSAGetLastError() == WSA ## expected)
#else
#define CHECK_ERRNO(expected) \
	(errno == expected)
#endif

#define BEGIN_SELECT_LOOP(s) \
	{ \
		long deadline, interval = s->timeout; \
		int has_timeout = (s->timeout > 0); \
		if (has_timeout) \
			deadline = ms_time() + s->timeout; \
		while (1) { \
			errno = 0;

#define END_SELECT_LOOP(s) \
			if (! has_timeout || (! CHECK_ERRNO(EWOULDBLOCK) && ! CHECK_ERRNO(EAGAIN))) \
				break; \
			interval = deadline - ms_time(); \
		} \
	}

int internal_connect(irda_t s, const struct sockaddr * addr, socklen_t len, int * timeoutp)
{
	int rc, timeout;

	timeout = 0;
	rc = connect(s->fd, addr, len);

#if defined(_WIN32) || defined(WIN32)
	if (s->timeout > 0)
	{
		if ((rc < 0) && (WSAGetLastError() == WSAEWOULDBLOCK) && IS_SELECTABLE(s))
		{
			fd_set fds;
			fd_set fds_exc;
			struct timeval tv;
			tv.tv_sec = (s->timeout / 1000);
			tv.tv_usec = (s->timeout % 1000) * 1000;

			FD_ZERO(& fds);
			FD_SET(s->fd, & fds);
			FD_ZERO(& fds_exc);
			FD_SET(s->fd, & fds_exc);

			rc = select(s->fd+1, NULL, & fds, & fds_exc, & tv);
			if (rc == 0)
			{
				rc = WSAEWOULDBLOCK;
				timeout = 1;
			}
			else if (rc > 0)
			{
				if (FD_ISSET(s->fd, & fds))
					rc = 0;
				else
				{
					int rc_size = sizeof rc;
					assert(FD_ISSET(s->fd, & fds_exc));
					if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, (char *)(& rc), & rc_size) == 0)
						WSASetLastError(rc);
					else
						rc = WSAGetLastError();
				}
			}
		}
	}

	if (rc < 0)
		rc = WSAGetLastError();
#else
	if (s->timeout > 0)
	{
		if (rc < 0 && errno == EINPROGRESS && IS_SELECTABLE(s))
		{
			timeout = internal_select(s, 1, s->timeout);
			if (timeout == 0)
			{
				socklen_t rc_size = sizeof rc;
				(void)getsockopt(s->fd, SOL_SOCKET, SO_ERROR, & rc, & rc_size);
				if (rc == EISCONN)
					rc = 0;

				errno = rc;
			}
			else if (timeout == -1)
				rc = errno;
			else
				rc = EWOULDBLOCK;
		}
	}

	if (rc < 0)
		rc = errno;
#endif

	* timeoutp = timeout;
	return rc;
}

int irda_socket_connect_name(irda_t s, unsigned int address, const char * name, int * timeout)
{
#if defined(_WIN32) || defined(WIN32)
	SOCKADDR_IRDA peer;
#else
	struct sockaddr_irda peer;
#endif

	CHECK_IRDA_HANDLE(s)

#if defined(_WIN32) || defined(WIN32)
	peer.irdaAddressFamily = AF_IRDA;
	peer.irdaDeviceID[0] = (address >> 24) & 0xFF;
	peer.irdaDeviceID[1] = (address >> 16) & 0xFF;
	peer.irdaDeviceID[2] = (address >>  8) & 0xFF;
	peer.irdaDeviceID[3] = (address      ) & 0xFF;
    if (name)
		strncpy(peer.irdaServiceName, name, 25);
	else
		memset(peer.irdaServiceName, 0x00, 25);
#else
	peer.sir_family = AF_IRDA;
	peer.sir_addr = address;
	if (name)
		strncpy(peer.sir_name, name, 25);
	else
		memset(peer.sir_name, 0x00, 25);
#endif

	return internal_connect(s, (struct sockaddr *) &peer, sizeof(peer), timeout);
}

int irda_socket_connect_lsap(irda_t s, unsigned int address, unsigned int lsap, int * timeout)
{
#if defined(_WIN32) || defined(WIN32)
	SOCKADDR_IRDA peer;
#else
	struct sockaddr_irda peer;
#endif

	CHECK_IRDA_HANDLE(s)

#if defined(_WIN32) || defined(WIN32)
	peer.irdaAddressFamily = AF_IRDA;
	peer.irdaDeviceID[0] = (address >> 24) & 0xFF;
	peer.irdaDeviceID[1] = (address >> 16) & 0xFF;
	peer.irdaDeviceID[2] = (address >>  8) & 0xFF;
	peer.irdaDeviceID[3] = (address      ) & 0xFF;
	_snprintf(peer.irdaServiceName, 25, "LSAP-SEL%u", lsap);
#else
	peer.sir_family = AF_IRDA;
	peer.sir_addr = address;
	peer.sir_lsap_sel = lsap;
	memset(peer.sir_name, 0x00, 25);
#endif

	return internal_connect(s, (struct sockaddr *) &peer, sizeof(peer), timeout);
}

int irda_socket_available(irda_t s)
{
#if defined(_WIN32) || defined(WIN32)
	unsigned long bytes = 0;
#else
	int bytes = 0;
#endif

	CHECK_IRDA_HANDLE(s)

#if defined(_WIN32) || defined(WIN32)
	if (ioctlsocket(s->fd, FIONREAD, &bytes) != 0)
		return -1;
#else
	if (ioctl(s->fd, FIONREAD, &bytes) != 0)
		return -1;
#endif

	return bytes;
}

int irda_socket_read(irda_t s, void * data, size_t * size, int * timeoutp)
{
	int timeout;

#if defined(_WIN32) || defined(WIN32)
	int outlen = 0;
#else
	ssize_t outlen = 0;
#endif

	CHECK_IRDA_HANDLE(s)

	if (data == NULL || size == NULL)
	{
#if defined(_WIN32) || defined(WIN32)
		SetLastError(ERROR_INVALID_HANDLE);
		return -1;
#else
		errno = EINVAL;
		return -1;
#endif
	}

	if (! IS_SELECTABLE(s))
	{
#if defined(_WIN32) || defined(WIN32)
		SetLastError(ERROR_NOT_SUPPORTED);
		return -1;
#else
		errno = EINVAL;
		return -1;
#endif
	}

	BEGIN_SELECT_LOOP(s)
	timeout = internal_select(s, 0, interval);
	if (! timeout)
		outlen = recv(s->fd, (char *)data, (* size), 0);

	if (timeout == 1)
	{
		if (timeoutp != NULL)
			* timeoutp = 1;

		break;
	}
	END_SELECT_LOOP(s)

	if (outlen < 0)
		return -1;

	* size = (size_t)outlen;
	return 0;
}

int irda_socket_write(irda_t s, const void * data, size_t * size, int * timeoutp)
{
	int timeout = 0;

#if defined(_WIN32) || defined(WIN32)
	unsigned int nbytes = 0;
#else
	size_t nbytes = 0;
#endif

	CHECK_IRDA_HANDLE(s)

	if (data == NULL || size == NULL)
	{
#if defined(_WIN32) || defined(WIN32)
		SetLastError(ERROR_INVALID_HANDLE);
		return -1;
#else
		errno = EINVAL;
		return -1;
#endif
	}

	if (! IS_SELECTABLE(s))
	{
#if defined(_WIN32) || defined(WIN32)
		SetLastError(ERROR_NOT_SUPPORTED);
		return -1;
#else
		errno = EINVAL;
		return -1;
#endif
	}

	while (nbytes < (* size))
	{
		int n;

		BEGIN_SELECT_LOOP(s)
		timeout = internal_select(s, 1, interval);
		if (! timeout)
			n = send(s->fd, (char*)data + nbytes, (* size) - nbytes, 0);

		if (timeout == 1)
		{
			if (timeoutp != NULL)
				* timeoutp = 1;

			break;
		}
		END_SELECT_LOOP(s)

		if (n < 0)
		{
			// Error in send()
			if (size != NULL)
				* size = nbytes;

			return -1;
		}

		if (n == 0)
			break;

		nbytes += n;
	}

	* size = nbytes;
	return 0;
}
