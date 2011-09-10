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

#include <stdlib.h> // malloc, free
#include <stdio.h>	// snprintf

#ifdef MS_WINDOWS
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

#ifdef MS_WINDOWS
typedef SOCKET			 socket_t;
#else
typedef int				 socket_t;
#define INVALID_SOCKET	(socket_t)(-1)
#endif

struct irda_t
{
	socket_t	fd;
	long		timeout;
};

int irda_errcode(void)
{
#ifdef MS_WINDOWS
	return WSAGetLastError();
#else
	return errno;
#endif
}

const char * irda_errmsg(void)
{
#ifdef MS_WINDOWS
	static char buffer[256] = { 0 };
	unsigned int size = sizeof(buffer) / sizeof(char);

	DWORD errcode = WSAGetLastError();
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
#ifdef MS_WINDOWS
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
#ifdef MS_WINDOWS
	if (WSACleanup() != 0)
		return -1;
#endif

	return 0;
}

int irda_socket_open(irda_t * s)
{
	if (s == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	irda_t device = (irda_t)malloc(sizeof(irda_t));
	if (device == NULL)
		return -1;

	device->timeout = -1;
	device->fd = socket(AF_IRDA, SOCK_STREAM, 0);
	if (device->fd == INVALID_SOCKET)
	{
		free (device);
		return -1;
	}

	*s = device;

	return 0;
}

int irda_socket_close(irda_t s)
{
	if (s == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	shutdown(s->fd, 0);

#ifdef MS_WINDOWS
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
	if (s == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	if (timeout < 0)
		s->timeout = -1;
	else
		s->timeout = timeout;

#ifdef MS_WINDOWS
	int noblock = (s->timeout >= 0);
	ioctlsocket(s->fd, FIONBIO, (u_long*)&noblock);
#else
	int delay_flag = fcntl(s->fd, F_GETFL, 0);

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
	if (s == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	* timeout = s->timeout;

	return 0;
}

#define DISCOVER_MAX_DEVICES 16	// Maximum number of devices.
#define DISCOVER_MAX_RETRIES 4	// Maximum number of retries.

#ifdef MS_WINDOWS
#define DISCOVER_BUFSIZE sizeof (DEVICELIST) + sizeof (IRDA_DEVICE_INFO) * (DISCOVER_MAX_DEVICES - 1)
#else
#define DISCOVER_BUFSIZE sizeof (struct irda_device_list) +	sizeof (struct irda_device_info) * (DISCOVER_MAX_DEVICES - 1)
#endif

int irda_socket_discovery(irda_t s, irda_callback_t cb, void * userdata)
{
	if (s == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	unsigned char data[DISCOVER_BUFSIZE] = { 0 };
#ifdef MS_WINDOWS
	DEVICELIST * list = (DEVICELIST *)data;
	int size = sizeof(data);
#else
	struct irda_device_list * list = (struct irda_device_list *)data;
	socklen_t size = sizeof(data);
#endif

	int rc = 0;
	unsigned int nretries = 0;
	while ((rc = getsockopt(s->fd, SOL_IRLMP, IRLMP_ENUMDEVICES, (char *)data, & size)) != 0 ||
#ifdef MS_WINDOWS
		list->numDevice == 0)
#else
		list->len == 0)
#endif
	{
		// Check for an error in getsockopt() other than socket timeout
#ifdef MS_WINDOWS
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
#ifdef MS_WINDOWS
		Sleep(1000);
#else
		sleep(1);
#endif
	}

	if (cb != NULL)
	{
		unsigned int i;

#ifdef _WIN32
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

#ifdef MS_WINDOWS
	return list->numDevice;
#else
	return list->len;
#endif
}

int internal_connect(irda_t s, const struct sockaddr * addr, socklen_t len, int * timeout)
{
	int rc = connect(s->fd, addr, len);

	if (timeout != NULL)
		* timeout = 0;

	if (s->timeout > 0)
	{
		if (rc < 0 && errno == EINPROGRESS)
		{
			struct pollfd pollfd;
			pollfd.fd = s->fd;
			pollfd.events = POLLOUT;

			int rcpoll = poll(& pollfd, 1, s->timeout);
			if (rcpoll < 0)
				return -1;
			else if (rcpoll == 0)
			{
				if (timeout != NULL)
					* timeout = 1;

				return -1;
			}

			socklen_t rc_size = sizeof rc;
			(void)getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &rc, &rc_size);
			if ((rc != 0) && (rc != EISCONN))
				return -1;

		}
	}
	else if (rc < 0)
		return -1;

	return 0;
}

int irda_socket_connect_name(irda_t s, unsigned int address, const char * name, int * timeout)
{
	if (s == NULL)
	{
		errno = EINVAL;
		return -1;
	}

#ifdef MS_WINDOWS
	SOCKADDR_IRDA peer;
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
	struct sockaddr_irda peer;
	peer.sir_family = AF_IRDA;
	peer.sir_addr = address;
	if (name)
		strncpy(peer.sir_name, name, 25);
	else
		memset(peer.sir_name, 0x00, 25);
#endif

	if (internal_connect(s, (struct sockaddr *) &peer, sizeof(peer), timeout) != 0)
		return -1;

	return 0;
}

int irda_socket_connect_lsap(irda_t s, unsigned int address, unsigned int lsap, int * timeout)
{
	if (s == NULL)
	{
		errno = EINVAL;
		return -1;
	}

#ifdef MS_WINDOWS
	SOCKADDR_IRDA peer;
	peer.irdaAddressFamily = AF_IRDA;
	peer.irdaDeviceID[0] = (address >> 24) & 0xFF;
	peer.irdaDeviceID[1] = (address >> 16) & 0xFF;
	peer.irdaDeviceID[2] = (address >>  8) & 0xFF;
	peer.irdaDeviceID[3] = (address      ) & 0xFF;
	snprintf(peer.irdaServiceName, 25, "LSAP-SEL%u", lsap);
#else
	struct sockaddr_irda peer;
	peer.sir_family = AF_IRDA;
	peer.sir_addr = address;
	peer.sir_lsap_sel = lsap;
	memset(peer.sir_name, 0x00, 25);
#endif

	if (internal_connect(s, (struct sockaddr *) &peer, sizeof(peer), timeout) != 0)
		return -1;

	return 0;
}

int irda_socket_available(irda_t s)
{
	if (s == NULL)
	{
		errno = EINVAL;
		return -1;
	}

#ifdef MS_WINDOWS
	unsigned long bytes = 0;
	if (ioctlsocket(device->fd, FIONREAD, &bytes) != 0)
#else
	int bytes = 0;
	if (ioctl(s->fd, FIONREAD, &bytes) != 0)
#endif
		return -1;

	return bytes;
}

int irda_socket_read(irda_t s, void * data, ssize_t * size, int * timeout)
{
	if ((s == NULL) || (size == NULL))
	{
		errno = EINVAL;
		return -1;
	}

	struct pollfd pollfd;
	pollfd.fd = s->fd;
	pollfd.events = POLLIN;

	ssize_t nbytes = 0;
	while (nbytes < (* size))
	{
		int rc = poll(& pollfd, 1, s->timeout);
		if (rc < 0)
		{
			// Error during poll()
			* size = nbytes;
			return -1;
		}
		else if (rc == 0)
		{
			// Timeout during poll()
			if (timeout != NULL)
				* timeout = 1;
			break;
		}

		int n = recv (s->fd, (char *)data + nbytes, (* size) - nbytes, 0);
		if (n < 0)
		{
			// Error during recv()
			* size = nbytes;
			return -1;
		}
		else if (n == 0)
		{
			// EOF reached.
			break;
		}

		nbytes += n;
	}

	* size = nbytes;
	return 0;
}

int irda_socket_write(irda_t s, const void * data, ssize_t * size, int * timeout)
{
	if ((s == NULL) || (size == NULL))
	{
		errno = EINVAL;
		return -1;
	}

	struct pollfd pollfd;
	pollfd.fd = s->fd;
	pollfd.events = POLLOUT;

	ssize_t nbytes = 0;
	while (nbytes < (* size))
	{
		int rc = poll(& pollfd, 1, s->timeout);
		if (rc < 0)
		{
			// Error during poll()
			* size = nbytes;
			return -1;
		}
		else if (rc == 0)
		{
			// Timeout during poll()
			if (timeout != NULL)
				* timeout = 1;
			break;
		}

		int n = send (s->fd, (char*)data + nbytes, (* size) - nbytes, 0);
		if (n < 0)
		{
			// Error during send()
			* size = nbytes;
			return -1;
		}

		nbytes += n;
	}

	* size = nbytes;
	return 0;
}
