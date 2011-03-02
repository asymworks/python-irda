/*
 * Copyright (c) 2011, Jonathan Krauss <jkrauss@asymworks.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Asymworks, LLC nor the names of its contributors may
 *   be used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This module implements a very light interface to the IrDA Socket subsystem.
 * It is completely separate from, but inspired by, the Python sockets module
 * which as of Python 2.7/3.2 does not support IrDA.
 *
 * IrSocket Interface:
 *
 * irsocket.error --> exception raised for irsocket-specific errors
 * irsocket.timeout --> exception raised for timeouts
 * irsocket.irsocket() --> new irsocket object
 * irsocket.getdefaulttimeout() --> None | float
 * irsocket.setdefaulttimeout(None | float)
 *
 */

#include <Python.h>
#include "structmember.h"

#ifndef MS_WINDOWS
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/irda.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <fcntl.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <af_irda.h>
#endif

#include "irsocket.h"

#if defined(MS_WINDOWS)
#define SOCKETCLOSE closesocket
#endif

#ifndef SOCKETCLOSE
#define SOCKETCLOSE close
#endif

#ifndef O_NONBLOCK
# define O_NONBLOCK O_NDELAY
#endif

/* Static Socket Error Objects */
static PyObject * irsocket_error;
static PyObject * irsocket_timeout;

#ifdef Py_SOCKET_FD_CAN_BE_GE_FD_SETSIZE
/* Platform can select file descriptors beyond FD_SETSIZE */
#define IS_SELECTABLE(s) 1
#elif defined(HAVE_POLL)
/* Instead of select(), we'll use poll() since poll() works on any fd. */
#define IS_SELECTABLE(s) 1
/* Can we call select() with this socket without a buffer overrun? */
#else
/* POSIX says selecting file descriptors beyond FD_SETSIZE
   has undefined behaviour.  If there's no timeout left, we don't have to
   call select, so it's a safe, little white lie. */
#define IS_SELECTABLE(s) ((s)->sock_fd < FD_SETSIZE || s->sock_timeout <= 0.0)
#endif

static PyObject * select_error(void)
{
    PyErr_SetString(irsocket_error, "Unable to select() on IrDA socket");
    return NULL;
}

/* Convenience Function to set IrSocket Error */
static PyObject * set_error(void)
{
#ifdef MS_WINDOWS
	int err_no = WSAGetLastError();
	if (err_no)
		return PyErr_SetExcFromWindowsErr(irsocket_error, err_no);
#endif

	return PyErr_SetFromErrno(irsocket_error);
}

static long default_timeout = -1;

/* Set or Unset Blocking */
static int internal_setblocking(PyIrSocketSockObject * s, int block)
{
#ifndef MS_WINDOWS
	int delay_flag;
#endif

	Py_BEGIN_ALLOW_THREADS
#ifndef MS_WINDOWS
	delay_flag = fcntl(s->sock_fd, F_GETFL, 0);

	if (block)
		delay_flag &= (~O_NONBLOCK);
	else
		delay_flag |= O_NONBLOCK;

	fcntl(s->sock_fd, F_SETFL, delay_flag);
#else
	block = !block;
	ioctlsocket(s->sock_fd, FIONBIO, (u_long*)&block);
#endif
	Py_END_ALLOW_THREADS

	return 1;
}

/* Select the IrDA socket */
static int internal_select(PyIrSocketSockObject * s, int writing)
{
	int n;

	/* Nothing to do unless we're in timeout mode (not non-blocking) */
	if (s->sock_timeout <= 0)
		return 0;

	/* Guard against closed socket */
	if (s->sock_fd < 0)
		return 0;

	/* Prefer poll, if available, since you can poll() any fd
	 * which can't be done with select(). */
#ifdef HAVE_POLL
	{
		struct pollfd pollfd;
		int timeout;

		pollfd.fd = s->sock_fd;
		pollfd.events = writing ? POLLOUT : POLLIN;

		/* s->sock_timeout is in seconds, timeout in ms */
		timeout = (int)(s->sock_timeout);
		n = poll(&pollfd, 1, timeout);
	}
#else
	{
		/* Construct the arguments to select */
		fd_set fds;
		struct timeval tv;
		tv.tv_sec = (int)(s->sock_timeout / 1e3);
		tv.tv_usec = (int)((s->sock_timeout - tv.tv_sec) * 1e3);
		FD_ZERO(&fds);
		FD_SET(s->sock_fd, &fds);

		/* See if the socket is ready */
		if (writing)
			n = select(s->sock_fd+1, NULL, &fds, NULL, &tv);
		else
			n = select(s->sock_fd+1, &fds, NULL, NULL, &tv);
	}
#endif

	if (n < 0)
		return -1;
	if (n == 0)
		return 1;
	return 0;
}

/* Initialize a new irsocket instance */
PyMODINIT_FUNC init_irsock_obj(PyIrSocketSockObject * s, SOCKET_T fd,
	int family, int type, int proto)
{
	s->sock_fd = fd;
	s->sock_family = family;
	s->sock_type = type;
	s->sock_proto = proto;

	s->sock_timeout = default_timeout;

	s->errorhandler = &set_error;

	if (default_timeout >= 0.0)
		internal_setblocking(s, 0);
}

/* s.available() method. */
static PyObject * irsock_available(PyIrSocketSockObject * s)
{
	if (!IS_SELECTABLE(s))
		return select_error();

#ifdef MS_WINDOWS
	unsigned long bytes = 0;
	if (ioctlsocket(s->sock_fd, FIONREAD, &bytes) != 0)
	{
#else
	int bytes = 0;
	if (ioctl(s->sock_fd, FIONREAD, &bytes) != 0)
	{
#endif
		PyErr_SetString(irsocket_error, "ioctl() failed in irsocket.available()");
		return NULL;
	}

	return PyInt_FromLong((long)bytes);
}

PyDoc_STRVAR(available_doc,
"available() -> count\n\
\n\
Returns the number of bytes available to be read, or 0 if none.");

/* s.close() method.  The socket cannot be used after this method is called. */
static PyObject * irsock_close(PyIrSocketSockObject * s)
{
	SOCKET_T fd;

	if ((fd = s->sock_fd) != -1)
	{
		s->sock_fd = -1;
		Py_BEGIN_ALLOW_THREADS
		(void)SOCKETCLOSE(fd);
		Py_END_ALLOW_THREADS
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyDoc_STRVAR(close_doc,
"close()\n\
\n\
Close the socket.  It cannot be used after this call."
);

static int internal_connect(PyIrSocketSockObject * s, unsigned int addr, unsigned int lsap, int * timeoutp)
{
#ifdef MS_WINDOWS
	SOCKADDR_IRDA peer;
	peer.irdaAddressFamily = AF_IRDA;
	peer.irdaDeviceID[0] = (addr >> 24) & 0xFF;
	peer.irdaDeviceID[1] = (addr >> 16) & 0xFF;
	peer.irdaDeviceID[2] = (addr >>  8) & 0xFF;
	peer.irdaDeviceID[3] =  addr        & 0xFF;

	snprintf (peer.irdaServiceName, 25, "LSAP-SEL%u", lsap);
#else
	struct sockaddr_irda peer;
	peer.sir_family = AF_IRDA;
	peer.sir_addr = addr;
	peer.sir_lsap_sel = lsap;
	memset (peer.sir_name, 0x00, 25);
#endif

	int timeout;
	int res;

	res = connect(s->sock_fd, (struct sockaddr *) &peer, sizeof(peer));

#ifdef MS_WINDOWS

	if (s->sock_timeout > 0)
	{
		if (res < 0 && WSAGetLastError() == WSAEWOULDBLOCK && IS_SELECTABLE(s))
		{
			/* This is a mess.  Best solution: trust select */
			fd_set fds;
			fd_set fds_exc;
			struct timeval tv;
			tv.tv_sec = (int)s->sock_timeout;
			tv.tv_usec = (int)((s->sock_timeout - tv.tv_sec) * 1e6);
			FD_ZERO(&fds);
			FD_SET(s->sock_fd, &fds);
			FD_ZERO(&fds_exc);
			FD_SET(s->sock_fd, &fds_exc);
			res = select(s->sock_fd+1, NULL, &fds, &fds_exc, &tv);
			if (res == 0)
			{
				res = WSAEWOULDBLOCK;
				timeout = 1;
			}
			else if (res > 0)
			{
				if (FD_ISSET(s->sock_fd, &fds))
					res = 0;
				else {
					int res_size = sizeof res;
					assert(FD_ISSET(s->sock_fd, &fds_exc));
					if (0 == getsockopt(s->sock_fd, SOL_SOCKET, SO_ERROR, (char *)&res, &res_size))
						WSASetLastError(res);
					else
						res = WSAGetLastError();
				}
			}
		}
	}

	if (res < 0)
		res = WSAGetLastError();

#else

	if (s->sock_timeout > 0)
	{
		if (res < 0 && errno == EINPROGRESS && IS_SELECTABLE(s))
		{
			timeout = internal_select(s, 1);
			if (timeout == 0)
			{
				socklen_t res_size = sizeof res;
				(void)getsockopt(s->sock_fd, SOL_SOCKET, SO_ERROR, &res, &res_size);
				if (res == EISCONN)
					res = 0;

				errno = res;
			}
			else if (timeout == -1)
			{
				res = errno;
			}
			else
				res = EWOULDBLOCK;
		}
	}

	if (res < 0)
		res = errno;

#endif
    *timeoutp = timeout;

    return res;
}

/* s.connect(addr[, name]) method. */
static PyObject * irsock_connect(PyIrSocketSockObject * s, PyObject * args)
{
	int res;
	int timeout;
	unsigned int addr;
	unsigned int lsap = 1;

	if (! PyArg_ParseTuple(args, "l|l:connect", &addr, &lsap))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	res = internal_connect(s, addr, lsap, &timeout);
	Py_END_ALLOW_THREADS

	if (timeout == 1)
	{
		PyErr_SetString(irsocket_timeout, "Timed Out");
		return NULL;
	}

	if (res != 0)
		return s->errorhandler();

	Py_INCREF(Py_None);
	return Py_None;
}

PyDoc_STRVAR(connect_doc,
"connect(addr[, lsap])\n\
\n\
Connects the IrDA socket to the device given by the addr parameter. The\n\
optional lsap parameter specifies a service endpoint.");

/* s.connect_ex(addr[, name]) method. */
static PyObject * irsock_connect_ex(PyIrSocketSockObject * s, PyObject * args)
{
	int res;
	int timeout;
	unsigned int addr;
	unsigned int lsap = 1;

	if (! PyArg_ParseTuple(args, "l|l:connect_ex", &addr, &lsap))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	res = internal_connect(s, addr, lsap, &timeout);
	Py_END_ALLOW_THREADS

	if (timeout == 1)
	{
		PyErr_SetString(irsocket_timeout, "Timed Out");
		return NULL;
	}

#ifdef EINTR
    if (res == EINTR && PyErr_CheckSignals())
        return NULL;
#endif

	return PyInt_FromLong((long)res);
}

PyDoc_STRVAR(connect_ex_doc,
"connect_ex(addr[, name])\n\
\n\
Connects the IrDA socket to the device given by the addr parameter. The\n\
optional name parameter specifies a service endpoint.  The error code is\n\
returned, or zero if successful.");

/* s.enum_devices() method. */
#define DISCOVER_MAX_DEVICES 16 // Maximum number of devices.
#define DISCOVER_MAX_RETRIES 4  // Maximum number of retries.

#ifdef MS_WINDOWS
#define DISCOVER_BUFSIZE sizeof (DEVICELIST) + sizeof (IRDA_DEVICE_INFO) * (DISCOVER_MAX_DEVICES - 1)
#else
#define DISCOVER_BUFSIZE sizeof (struct irda_device_list) + sizeof (struct irda_device_info) * (DISCOVER_MAX_DEVICES - 1)
#endif

static PyObject * irsock_enum(PyIrSocketSockObject * s)
{
	unsigned char data[DISCOVER_BUFSIZE];
#ifdef MS_WINDOWS
	DEVICELIST * list = (DEVICELIST *)data;
	int size = sizeof(data);
#else
	struct irda_device_list * list = (struct irda_device_list *)data;
	socklen_t size = sizeof(data);
#endif

	if (!IS_SELECTABLE(s))
		return select_error();

	int rc = 0;
	unsigned int nretries = 0;
	while ((rc = getsockopt(s->sock_fd, SOL_IRLMP, IRLMP_ENUMDEVICES, (char *)data, &size)) != 0 ||
#ifdef MS_WINDOWS
		list->numDevice == 0)
#else
		list->len == 0)
#endif
	{
		if (rc != 0)
		{
#ifdef MS_WINDOWS
			if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
			if (errno != EAGAIN)
#endif
			{
				s->errorhandler();
				return NULL;
			}
		}

		if (nretries++ >= DISCOVER_MAX_RETRIES)
		{
			Py_INCREF(Py_None);
			return Py_None;
		}

		size = sizeof(data);

#ifdef MS_WINDOWS
		Sleep(1000);
#else
		sleep(1);
#endif
	}

	ssize_t len;

#ifdef MS_WINDOWS
	len = list->numDevice;
#else
	len = list->len;
#endif

	if (len == 0)
	{
		Py_INCREF(Py_None);
		return Py_None;
	}

	PyObject * l = PyList_New(len);
	unsigned int i;

	for (i = 0; i < len; ++i)
	{
#ifdef MS_WINDOWS
		unsigned int addr = (list->Device[i].irdaDeviceID[0] << 24) +
			(list->Device[i].irdaDeviceID[1] << 16) +
			(list->Device[i].irdaDeviceID[2] << 8) +
			(list->Device[i].irdaDeviceID[3]);
		unsigned int hints = (list->Device[i].irdaDeviceHints1 << 8) + list->Device[i].irdaDeviceHints2;
		unsigned int charset = list->Device[i].irdaCharSet;
		const char * name = list->Device[i].irdaDeviceName;
#else
		unsigned int addr = list->dev[i].daddr;
		unsigned int hints = (list->dev[i].hints[0] << 8) + list->dev[i].hints[1];
		unsigned int charset = list->dev[i].charset;
		const char * name = list->dev[i].info;
#endif

		PyObject * d = PyDict_New();
		PyDict_SetItemString(d, "addr", PyLong_FromLong(addr));
		PyDict_SetItemString(d, "name", PyString_FromString(name));
		PyDict_SetItemString(d, "hints", PyInt_FromLong(hints));
		PyDict_SetItemString(d, "charset", PyInt_FromLong(charset));
		PyList_SetItem(l, i, d);
	}

	return l;
}

PyDoc_STRVAR(enum_doc,
"enum_devices() -> list\n\
\n\
Enumerates devices on the IrDA interface.  Returns a list of dictionaries in\n\
the following format:\n\
\n\
[\n\
	{ 'addr' : <IrDA Address>, 'name' : <IrDA Name> },\n\
	{ 'addr' : <IrDA Address>, 'name' : <IrDA Name> },\n\
	...\n\
]\n\
The address or name can be passed to connect() or connect_ex() to connect to\n\
the specified IrDA device.");

/* s.fileno() method. */
static PyObject * irsock_fileno(PyIrSocketSockObject * s)
{
#if SIZEOF_SOCKET_T <= SIZEOF_LONG
	return PyInt_FromLong(s->sock_fd);
#else
	return PyLong_FromLongLong(s->sock_fd);
#endif
}

PyDoc_STRVAR(fileno_doc,
"fileno() -> integer\n\
\n\
Return the integer file descriptor of the socket.");

/* s.gettimeout() method. */
static PyObject * irsock_gettimeout(PyIrSocketSockObject * s)
{
    if (s->sock_timeout < 0)
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
    else
        return PyInt_FromLong(s->sock_timeout);
}

PyDoc_STRVAR(gettimeout_doc,
"gettimeout() -> timeout\n\
\n\
Returns the timeout in milliseconds associated with socket \n\
operations. A timeout of None indicates that timeouts on socket \n\
operations are disabled.");

/* s.recv(length[, flags]) method. */
static PyObject * irsock_recv(PyIrSocketSockObject * s, PyObject * args)
{
	int timeout;
	int recvlen;
	int flags = 0;
	ssize_t outlen;
	PyObject * buf;
	char * cbuf;

	if (! PyArg_ParseTuple(args, "i|i:recv", &recvlen, &flags))
		return NULL;

	if (recvlen < 0)
	{
		PyErr_SetString(PyExc_ValueError, "Negative buffer size in irsocket.recv()");
		return NULL;
	}

	if (! IS_SELECTABLE(s))
	{
		select_error();
		return NULL;
	}

	/* Allocate a new string. */
	buf = PyString_FromStringAndSize((char *) 0, recvlen);
	if (buf == NULL)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	cbuf = PyString_AS_STRING(buf);
	timeout = internal_select(s, 0);
	if (!timeout)
		outlen = recv(s->sock_fd, cbuf, recvlen, flags);
	Py_END_ALLOW_THREADS

	if (timeout == 1) {
		PyErr_SetString(irsocket_timeout, "Timed Out");
		Py_DECREF(buf);
		return NULL;
	}

	if (outlen < 0) {
		s->errorhandler();
		Py_DECREF(buf);
		return NULL;
	}

	if (outlen != recvlen)
	{
		if (_PyString_Resize(&buf, outlen) < 0)
			return NULL;
	}

	return buf;
}

PyDoc_STRVAR(recv_doc,
"recv(length[, flags]) -> data\n\
\n\
Enumerates devices on the IrDA interface.  Returns a list of dictionaries in\n\
the following format:\n\
\n\
[\n\
	{ 'addr' : <IrDA Address>, 'name' : <IrDA Name> },\n\
	{ 'addr' : <IrDA Address>, 'name' : <IrDA Name> },\n\
	...\n\
]\n\
The address or name can be passed to connect() or connect_ex() to connect to\n\
the specified IrDA device.");

/* s.send(data[, flags]) method. */
static PyObject * irsock_send(PyIrSocketSockObject * s, PyObject * args)
{
	char * buf;
	int len;
	int n = -1;
	int flags = 0;
	int timeout;
	Py_buffer pbuf;

	if (!PyArg_ParseTuple(args, "s*|i:send", &pbuf, &flags))
        return NULL;

	if (!IS_SELECTABLE(s)) {
		PyBuffer_Release(&pbuf);
		return select_error();
	}

	buf = pbuf.buf;
	len = pbuf.len;

	Py_BEGIN_ALLOW_THREADS
	timeout = internal_select(s, 1);
	if (! timeout)
	{
		n = send(s->sock_fd, buf, len, flags);
	}
	Py_END_ALLOW_THREADS

	PyBuffer_Release(&pbuf);

	if (timeout == 1)
	{
		PyErr_SetString(irsocket_timeout, "Timed Out");
		return NULL;
	}

	if (n < 0)
		return s->errorhandler();
	return PyInt_FromLong((long)n);
}

PyDoc_STRVAR(send_doc,
"send(data[, flags]) -> count\n\
\n\
Send a data string to the socket.  For the optional flags.\n\
argument, see the UNIX documentation.  Returns the number\n\
of bytes sent; this may be less than len(data) if the\n\
network is busy.");

/* s.sendall(data[, flags]) method. */
static PyObject * irsock_sendall(PyIrSocketSockObject * s, PyObject * args)
{
	char * buf;
	int len;
	int n = -1;
	int flags = 0;
	int timeout;
	int _errno;
	Py_buffer pbuf;

	if (!PyArg_ParseTuple(args, "s*|i:sendall", &pbuf, &flags))
        return NULL;

	if (!IS_SELECTABLE(s)) {
		PyBuffer_Release(&pbuf);
		return select_error();
	}

	buf = pbuf.buf;
	len = pbuf.len;

	do
	{
		Py_BEGIN_ALLOW_THREADS
		timeout = internal_select(s, 1);
		n = -1;
		if (! timeout)
		{
			n = send(s->sock_fd, buf, len, flags);
		}
		Py_END_ALLOW_THREADS

		if (timeout == 1)
		{
			PyBuffer_Release(&pbuf);
			PyErr_SetString(irsocket_timeout, "Timed Out");
			return NULL;
		}

		_errno = errno;

		if (PyErr_CheckSignals()) {
			PyBuffer_Release(&pbuf);
			return NULL;
		}

		if (n < 0)
		{
			if (_errno == EINTR)
				continue;
			else
				break;
		}

		buf += n;
		len -= n;
	} while (len > 0);
	PyBuffer_Release(&pbuf);

	if (n < 0)
		return s->errorhandler();

	Py_INCREF(Py_None);
	return Py_None;
}

PyDoc_STRVAR(sendall_doc,
"sendall(data[, flags])\n\
\n\
Send a data string to the socket.  For the optional flags.\n\
argument, see the UNIX documentation.  Equivalent to calling\n\
send() repeatedly until all data is sent.  If an error occurs\n\
it's impossible to tell how much data was sent.");

/* s.setblocking() method. */
static PyObject * irsock_setblocking(PyIrSocketSockObject * s, PyObject * arg)
{
    int block;

    block = PyInt_AsLong(arg);
    if (block == -1 && PyErr_Occurred())
        return NULL;

    s->sock_timeout = block ? -1 : 0;
    internal_setblocking(s, block);

    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(setblocking_doc,
"setblocking(flag)\n\
\n\
Set the socket to blocking (flag is true) or non-blocking (false).\n\
setblocking(True) is equivalent to settimeout(None);\n\
setblocking(False) is equivalent to settimeout(0).");

/* s.settimeout() method */
static PyObject * irsock_settimeout(PyIrSocketSockObject *s, PyObject * arg)
{
    double timeout;

    if (arg == Py_None)
        timeout = -1;
    else
    {
        timeout = PyLong_AsLong(arg);
        if (timeout < 0)
        {
            if (!PyErr_Occurred())
                PyErr_SetString(PyExc_ValueError, "Timeout value out of range");
            return NULL;
        }
    }

    s->sock_timeout = timeout;
    internal_setblocking(s, timeout < 0.0);

    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(settimeout_doc,
"settimeout(timeout)\n\
\n\
Set a timeout on socket operations.  'timeout' can be an integer,\n\
giving in milliseconds, or None.  Setting a timeout of None disables\n\
the timeout feature and is equivalent to setblocking(1).\n\
Setting a timeout of zero is the same as setblocking(0).");

/* List of irsocket Methods */
static PyMethodDef irsock_methods[] =
{
	{"available",		(PyCFunction)irsock_available,		METH_NOARGS,	available_doc},
	{"close",			(PyCFunction)irsock_close, 			METH_NOARGS, 	close_doc},
	{"connect",			(PyCFunction)irsock_connect,		METH_VARARGS,	connect_doc},
	{"connect_ex",		(PyCFunction)irsock_connect_ex,		METH_VARARGS,	connect_ex_doc},
	{"enum_devices",	(PyCFunction)irsock_enum,			METH_NOARGS,	enum_doc},
	{"fileno",			(PyCFunction)irsock_fileno,			METH_NOARGS,	fileno_doc},
	{"gettimeout",		(PyCFunction)irsock_gettimeout,		METH_NOARGS,	gettimeout_doc},
	{"recv",			(PyCFunction)irsock_recv,			METH_VARARGS,	recv_doc},
	{"send",			(PyCFunction)irsock_send,			METH_VARARGS,	send_doc},
	{"sendall",			(PyCFunction)irsock_sendall,		METH_VARARGS,	sendall_doc},
	{"setblocking",		(PyCFunction)irsock_setblocking,	METH_O,			setblocking_doc},
	{"settimeout",		(PyCFunction)irsock_settimeout,		METH_O,			settimeout_doc},
	{ NULL, NULL },
};

/* List of irsocket Members */
static PyMemberDef irsock_memberlist[] =
{
	{"family", T_INT, offsetof(PyIrSocketSockObject, sock_family), READONLY, "the socket family"},
	{"type", T_INT, offsetof(PyIrSocketSockObject, sock_type), READONLY, "the socket type"},
	{"proto", T_INT, offsetof(PyIrSocketSockObject, sock_proto), READONLY, "the socket protocol"},
	{"timeout", T_LONG, offsetof(PyIrSocketSockObject, sock_timeout), READONLY, "the socket timeout"},
	{ 0 },
};

/* irsocket Doc String */
PyDoc_STRVAR(irsock_doc,
"irsocket() -> IrDA Socket object\n\
\n\
Opens a new IrDA socket.  This will open a new socket with the AF_IRDA\
type with the stream (SOCK_STREAM) transfer type.\n\
\n\
Methods of socket objects (keyword arguments not allowed):\n\
\n\
available() -- number of bytes available to read\n\
close() -- close the socket\n\
connect(addr[, name]) -- connect the socket to an IrDA endpoint\n\
connect_ex(addr[, name]) -- connect, return an error code instead of an exception\n\
enum_devics() -- enumerate IrDA devices\n\
fileno() -- return underlying file descriptor\n\
gettimeout() -- return timeout or None\n\
recv(buflen[, flags]) -- receive data\n\
send(data[, flags]) -- send data, may not send all of it\n\
sendall(data[, flags]) -- send all data\n\
setblocking(0 | 1) -- set or clear the blocking I/O flag\n\
settimeout(None | float) -- set or clear the timeout\n\
\n\
[*] not available on all platforms!");

/* Deallocate an irsocket object */
static void irsock_dealloc(PyIrSocketSockObject * s)
{
	if (s->sock_fd != -1)
		(void)SOCKETCLOSE(s->sock_fd);
	Py_TYPE(s)->tp_free((PyObject *)s);
}

/* Dump an irsocket to a string description */
static PyObject * irsock_repr(PyIrSocketSockObject * s)
{
    char buf[512];
#if SIZEOF_SOCKET_T > SIZEOF_LONG
    if (s->sock_fd > LONG_MAX) {
        /* this can occur on Win64, and actually there is a special
           ugly printf formatter for decimal pointer length integer
           printing, only bother if necessary*/
        PyErr_SetString(PyExc_OverflowError,
                        "no printf formatter to display "
                        "the socket descriptor in decimal");
        return NULL;
    }
#endif
    PyOS_snprintf(
        buf, sizeof(buf),
        "<irsocket object, fd=%ld, family=%d, type=%d, protocol=%d>",
        (long)s->sock_fd, s->sock_family,
        s->sock_type,
        s->sock_proto);
    return PyString_FromString(buf);
}

/* Initialize a new irsocket object */
static int irsock_initobj(PyObject * self, PyObject * args, PyObject * kwds)
{
	PyIrSocketSockObject * s = (PyIrSocketSockObject *)self;
	SOCKET_T fd;
	int family = AF_IRDA;
	int type = SOCK_STREAM;
	int proto = 0;

	Py_BEGIN_ALLOW_THREADS
	fd = socket(family, type, proto);
	Py_END_ALLOW_THREADS

#ifdef MS_WINDOWS
	if (fd == INVALID_SOCKET)
#else
	if (fd < 0)
#endif
	{
		set_error();
		return -1;
	}

	init_irsock_obj(s, fd, family, type, proto);
	return 0;
}

/* Create a new, uninitialized irsocket object */
static PyObject * irsock_new(PyTypeObject * type, PyObject * args, PyObject * kwds)
{
	PyObject * new;

	new = type->tp_alloc(type, 0);
	if (new != NULL)
	{
		((PyIrSocketSockObject *)new)->sock_fd = -1;
		((PyIrSocketSockObject *)new)->sock_timeout = -1;
		((PyIrSocketSockObject *)new)->errorhandler = &set_error;
	}

	return new;
}

/* Type object for irsocket objects */
static PyTypeObject irsock_type =
{
	PyVarObject_HEAD_INIT(0, 0)
	"irsocket.irsocket",						/* tp_name */
	sizeof(PyIrSocketSockObject),				/* tp_basicsize */
	0,											/* tp_itemsize */
	(destructor)irsock_dealloc,					/* tp_dealloc */
	0,											/* tp_print */
	0,											/* tp_getattr */
	0,											/* tp_setattr */
	0,											/* tp_compare */
	(reprfunc)irsock_repr,						/* tp_repr */
	0,											/* tp_as_number */
	0,											/* tp_as_sequence */
	0,											/* tp_as_mapping */
	0,											/* tp_hash */
	0,											/* tp_call */
	0,											/* tp_str */
	PyObject_GenericGetAttr,					/* tp_getattro */
	0,											/* tp_setattro */
	0,											/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	irsock_doc,									/* tp_doc */
	0,											/* tp_traverse */
	0,											/* tp_clear */
	0,											/* tp_richcompare */
	0,											/* tp_weaklistoffset */
	0,											/* tp_iter */
	0,											/* tp_iternext */
	irsock_methods,								/* tp_methods */
	irsock_memberlist,							/* tp_members */
	0,											/* tp_getset */
	0,											/* tp_base */
	0,											/* tp_dict */
	0,											/* tp_descr_get */
	0,											/* tp_descr_set */
	0,											/* tp_dictoffset */
	irsock_initobj,								/* tp_init */
	PyType_GenericAlloc,						/* tp_alloc */
	irsock_new,									/* tp_new */
	PyObject_Del,								/* tp_free */
};

/* irsocket Module Method Table */
PyMethodDef irsocket_methods[] =
{
	{ NULL, NULL },
};

#ifdef MS_WINDOWS
#define OS_INIT_DEFINED

static void os_cleanup(void)
{
	WSACleanup();
}

static int os_init(void)
{
	WSADATA WSAData;
	WORD wVersionRequested = MAKEWORD (2, 2);
	int ret;
	char buf[100];

	if ((ret = WSAStartup (wVersionRequested, &wsaData)) != 0)
	{
		switch (ret)
		{
		case WSASYSNOTREADY:
			PyErr_SetString(PyExc_ImportError,
				"WSAStartup failed: network not ready");
			break;
		case WSAVERNOTSUPPORTED:
		case WSAEINVAL:
			PyErr_SetString(PyExc_ImportError,
				"WSAStartup failed: requested version not supported");
			break;
		default:
			PyOS_snprintf(buf, sizeof(buf),
				"WSAStartup failed: error code %d", ret);
			PyErr_SetString(PyExc_ImportError, buf);
			break;
		}

		return 0;	/* failure */
	}
	else
	{
		Py_AtExit(os_cleanup);
		return 1;	/* success */
	}
}

#endif

#ifndef OS_INIT_DEFINED
static int os_init(void)
{
	return 1;	/* success */
}
#endif

/* PyDoc for IrSocket */
PyDoc_STRVAR(irsocket_doc,
"IrDA Minimal Socket Interface\n\
\n\
Implements a minimal set of socket methods to communicate over the IrDA\
protocol."
);

/* Initialize the IrSocket Module */
void initirsocket(void)
{
	PyObject * m;

	/* OS IrDA Initialization */
	if (! os_init())
		return;

	/* Initialize irsock_type struct */
	if (PyType_Ready(&irsock_type) < 0)
		return;

	/* Register Python Module */
	m = Py_InitModule3(PyIrSocket_MODULE_NAME, irsocket_methods, irsocket_doc);

	if (m == NULL)
		return;

	/* Register irsocket.error */
	irsocket_error = PyErr_NewException("irsocket.error", PyExc_IOError, NULL);

	if (irsocket_error == NULL)
		return;
	Py_INCREF(irsocket_error);
    PyModule_AddObject(m, "error", irsocket_error);

    /* Register irsocket.timeout */
    irsocket_timeout = PyErr_NewException("irsocket.timeout", irsocket_error, NULL);

	if (irsocket_timeout == NULL)
		return;
	Py_INCREF(irsocket_timeout);
	PyModule_AddObject(m, "timeout", irsocket_timeout);

	/* Register irsocket object */
	Py_INCREF(&irsock_type);
	if (PyModule_AddObject(m, "irsocket", (PyObject *)&irsock_type) != 0)
		return;
}
