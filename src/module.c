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

#include <Python.h>
#include "irda.h"

/* IrDA Socket Object Information */
typedef struct {
    PyObject_HEAD
    irda_t 		socket; 				/* Socket Handle */
    uint32_t	irda_address;			/* IrDA Client Address */
    uint8_t		irda_lsap;				/* IrDA LSAP Endpoint */
} PyIrDASocketObject;

/* Static Socket Error Objects */
static PyObject * pyirda_error;
static PyObject * pyirda_timeout;

/* Convenience Function to set IrDA Error */
static PyObject * set_error(void)
{
#ifdef MS_WINDOWS
	int err_no = WSAGetLastError();
	if (err_no)
		return PyErr_SetExcFromWindowsErr(pyirda_error, err_no);
#endif

	return PyErr_SetFromErrno(pyirda_error);
}

void pyirda_discover_cb(unsigned int address, const char * name,
	unsigned int charset, unsigned int hints, void * userdata)
{
	PyObject * list = (PyObject *)userdata;

	// Assemble the Client Information Dictionary
	PyObject * d = PyDict_New();
	PyDict_SetItemString(d, "addr", PyLong_FromLong(address));
	PyDict_SetItemString(d, "name", PyString_FromString(name));
	PyDict_SetItemString(d, "charset", PyInt_FromLong(charset));
	PyDict_SetItemString(d, "hints", PyInt_FromLong(hints));

	// Append the Client to the List
	PyList_Append(list, d);
}

static PyObject * pyirda_discover(PyObject * m)
{
	// Create a temporary socket for the bus enumeration
	irda_t sock;

	if (irda_socket_open(& sock) != 0)
	{
		set_error();
		return NULL;
	}

	// Create the Result List
	PyObject * list = PyList_New(0);

	// Run the Enumeration
	int ndevs;

	Py_BEGIN_ALLOW_THREADS
	ndevs = irda_socket_discovery(sock, & pyirda_discover_cb, list);
	Py_END_ALLOW_THREADS

	// Handle Enumeration Error
	if (ndevs < 0)
	{
		set_error();
		irda_socket_close(sock);
		Py_DECREF(list);

		return NULL;
	}

	// Close temporary socket
	irda_socket_close(sock);

	return list;
}

PyDoc_STRVAR(pyirda_discover_doc,
"irda.discover() -> list\n\
\n\
Enumerates the devices found on the IrDA bus.  The return value is a list\n\
of dictionaries in the following format:\n\
\n\
[\n\
    'addr': <IrLAP Address>,\n\
    'name': <Device Name>,\n\
    'hints': <Device Hints>,\n\
    'charset': <Device Charset>\n\
]\n\
\n\
If no devices are present on the bus, an empty list is returned.\n\
\n\
To connect to an IrDA device, pass the 'addr' value from the desired device\n\
to the irda.irsocket constructor."
);

/* irsocket.address() method */
static PyObject * irsocket_address(PyIrDASocketObject * s)
{
	if (s->irda_address == 0)
	{
		Py_INCREF(Py_None);
		return Py_None;
	}

	return PyLong_FromLong(s->irda_address);
}

PyDoc_STRVAR(irsocket_address_doc,
"irsocket.address() -> long\n\
\n\
Return the address of the remote IrDA endpoint.  If the socket is not\n\
connected, None is returned.");

/* irsocket.available() method */
static PyObject * irsocket_available(PyIrDASocketObject * s)
{
	int bytes;

	Py_BEGIN_ALLOW_THREADS
	bytes = irda_socket_available(s->socket);
	Py_END_ALLOW_THREADS

	if (bytes < 0)
	{
		set_error();
		return NULL;
	}

	return PyInt_FromLong((long)bytes);
}

PyDoc_STRVAR(irsocket_available_doc,
"irsocket.available() -> count\n\
\n\
Returns the number of bytes available to be read, or 0 if none.");

/* irsocket.connect(addr[, lsap]) method */
static PyObject * irsocket_connect(PyIrDASocketObject * s, PyObject * args)
{
	int rc;
	int timeout = 0;
	unsigned int addr;
	unsigned int lsap = 1;

	if (! PyArg_ParseTuple(args, "l|l:connect", &addr, &lsap))
		return NULL;

	fprintf(stderr, "irsocket_connect(%p)\n", s->socket);

	//FIXME: Py_BEGIN_ALLOW_THREADS cause a seg fault...
	//Py_BEGIN_ALLOW_THREADS
	rc = irda_socket_connect_lsap(s->socket, (uint32_t)addr, (uint8_t)lsap, & timeout);
	//Py_END_ALLOW_THREADS

	if (timeout == 1)
	{
		PyErr_SetString(pyirda_timeout, "Timed Out");
		return NULL;
	}

	if (rc != 0)
		return set_error();

	Py_INCREF(Py_None);
	return Py_None;
}

PyDoc_STRVAR(irsocket_connect_doc,
"irsocket.connect(addr[, lsap])\n\
\n\
Connects the IrDA socket to the device given by the addr parameter. The\n\
optional lsap parameter specifies a service endpoint.");

/* s.connect_ex(addr[, name]) method */
static PyObject * irsocket_connect_ex(PyIrDASocketObject * s, PyObject * args)
{
	int res;
	int timeout = 0;
	unsigned int addr;
	unsigned int lsap = 1;

	if (! PyArg_ParseTuple(args, "l|l:connect_ex", &addr, &lsap))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	res = irda_socket_connect_lsap(s->socket, (uint32_t)addr, (uint8_t)lsap, &timeout);
	Py_END_ALLOW_THREADS

	if (timeout == 1)
	{
		PyErr_SetString(pyirda_timeout, "Timed Out");
		return NULL;
	}

#ifdef EINTR
    if (res == EINTR && PyErr_CheckSignals())
        return NULL;
#endif

	return PyInt_FromLong((long)errno);
}

PyDoc_STRVAR(irsocket_connect_ex_doc,
"irsocket.connect_ex(addr[, lsap])\n\
\n\
Connects the IrDA socket to the device given by the addr parameter. The\n\
optional lsap parameter specifies a service endpoint.  The error code is\n\
returned, or zero if successful.");

/* irsocket.lsap() method */
static PyObject * irsocket_lsap(PyIrDASocketObject * s)
{
	if (s->irda_lsap == 0)
	{
		Py_INCREF(Py_None);
		return Py_None;
	}

	return PyLong_FromLong(s->irda_lsap);
}

PyDoc_STRVAR(irsocket_lsap_doc,
"irsocket.lsap() -> byte\n\
\n\
Return the LSAP of the remote IrDA endpoint.  If the socket is not connected,\n\
or if the remote IrDA endpoint has no LSAP name, None is returned.");

/* irsocket.recv(length[, flags]) method */
static PyObject * irsocket_recv(PyIrDASocketObject * s, PyObject * args)
{
	int rc;
	int timeout;
	ssize_t recvlen;
	PyObject * buf;
	char * cbuf;

	if (args == Py_None)
	{
		PyErr_SetString(PyExc_ValueError, "Missing buffer size in irsocket.recv()");
		return NULL;
	}

	recvlen = PyInt_AsLong(args);
	if (recvlen < 0)
	{
		PyErr_SetString(PyExc_ValueError, "Negative buffer size in irsocket.recv()");
		return NULL;
	}

	/* Allocate a new string. */
	buf = PyString_FromStringAndSize((char *) 0, recvlen);
	if (buf == NULL)
		return NULL;

	cbuf = PyString_AS_STRING(buf);

	Py_BEGIN_ALLOW_THREADS
	rc = irda_socket_read(s->socket, cbuf, & recvlen, & timeout);
	Py_END_ALLOW_THREADS

	if (rc != 0)
	{
		set_error();
		Py_DECREF(buf);
		return NULL;
	}

	if (timeout == 1)
	{
		PyErr_SetString(pyirda_timeout, "Timed Out");
		Py_DECREF(buf);
		return NULL;
	}

	if (_PyString_Resize(&buf, recvlen) < 0)
		return NULL;

	return buf;
}

PyDoc_STRVAR(irsocket_recv_doc,
"irsocket.recv(size)\n\
\n\
Receive up to the given number of bytes from the IrDA socket.");

/* irsocket.send(data[, flags]) method. */
static PyObject * irsocket_send(PyIrDASocketObject * s, PyObject * args)
{
	char * buf;
	ssize_t len;
	int rc;
	int n = -1;
	int flags = 0;
	int timeout;

	if (args == Py_None)
	{
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (! PyString_AsStringAndSize(args, & buf, & len) == -1)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	rc = irda_socket_write(s->socket, buf, & len, & timeout);
	Py_END_ALLOW_THREADS

	if (rc != 0)
	{
		set_error();
		Py_DECREF(buf);
		return NULL;
	}

	if (timeout == 1)
	{
		PyErr_SetString(pyirda_timeout, "Timed Out");
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyDoc_STRVAR(irsocket_send_doc,
"irsocket.send(data)\n\
\n\
Send a data string to the socket.");

/* irsocket.set_blocking() method */
static PyObject * irsocket_set_blocking(PyIrDASocketObject * s, PyObject * arg)
{
    int block;

    block = PyInt_AsLong(arg);
    if (block == -1 && PyErr_Occurred())
        return NULL;

    if (irda_socket_set_timeout(s->socket, block ? -1 : 0) != 0)
    {
    	set_error();
    	return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(irsocket_set_blocking_doc,
"irsocket.set_blocking(flag)\n\
\n\
Set the socket to blocking (flag is true) or non-blocking (false).\n\
set_blocking(True) is equivalent to set_timeout(None);\n\
set_blocking(False) is equivalent to set_timeout(0).");

/* irsocket.settimeout() method */
static PyObject * irsocket_set_timeout(PyIrDASocketObject *s, PyObject * arg)
{
    long timeout;

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

    if (irda_socket_set_timeout(s->socket, timeout) != 0)
    {
		set_error();
		return NULL;
	}

    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(irsocket_set_timeout_doc,
"irsocket.set_timeout(timeout)\n\
\n\
Set a timeout on socket operations.  'timeout' can be an integer,\n\
giving in milliseconds, or None.  Setting a timeout of None disables\n\
the timeout feature and is equivalent to set_blocking(True).\n\
Setting a timeout of zero is the same as set_blocking(False).");

/* irsocket.timeout() method. */
static PyObject * irsocket_timeout(PyIrDASocketObject * s)
{
	long timeout;

	if (irda_socket_timeout(s->socket, & timeout) != 0)
	{
		set_error();
		return NULL;
	}

    if (timeout < 0)
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
    else
        return PyInt_FromLong(timeout);
}

PyDoc_STRVAR(irsocket_timeout_doc,
"irsocket.timeout() -> timeout\n\
\n\
Returns the timeout in milliseconds associated with socket \n\
operations. A timeout of None indicates that timeouts on socket \n\
operations are disabled.");

/* irsocket Class Method Table */
static PyMethodDef irsocket_methods[] =
{
	{"address", 		(PyCFunction)irsocket_address,		METH_NOARGS,	irsocket_address_doc},
	{"available", 		(PyCFunction)irsocket_available, 	METH_NOARGS, 	irsocket_available_doc},
	{"connect", 		(PyCFunction)irsocket_connect, 		METH_VARARGS, 	irsocket_connect_doc},
	{"connect_ex", 		(PyCFunction)irsocket_connect_ex, 	METH_VARARGS, 	irsocket_connect_ex_doc},
	{"lsap",			(PyCFunction)irsocket_lsap,			METH_NOARGS,	irsocket_lsap_doc},
	{"recv", 			(PyCFunction)irsocket_recv, 		METH_O, 		irsocket_recv_doc},
	{"send", 			(PyCFunction)irsocket_send, 		METH_O, 		irsocket_send_doc},
	{"set_blocking", 	(PyCFunction)irsocket_set_blocking, METH_O, 		irsocket_set_blocking_doc},
	{"set_timeout", 	(PyCFunction)irsocket_set_timeout, 	METH_O, 		irsocket_set_timeout_doc},
	{"timeout", 		(PyCFunction)irsocket_timeout, 		METH_NOARGS, 	irsocket_timeout_doc},
	{ NULL, NULL },
};

/* irsocket Class Doc String */
PyDoc_STRVAR(irsocket_doc,
"irsocket() -> IrDA Socket object\n\
\n\
Opens a new IrDA socket. This will open a new socket with the AF_IRDA\
type with the stream (SOCK_STREAM) transfer type.\n\
\n\
Methods of socket objects (keyword arguments not allowed):\n\
\n\
address() -- address of the remote IrDA endpoint\n\
available() -- number of bytes available to read\n\
connect(addr[, lsap]) -- connect the socket to an IrDA endpoint\n\
connect_ex(addr[, lsap]) -- connect, return an error code instead of an exception\n\
lsap() -- return LSAP selector of the remote IrDA endpoint\n\
recv(size) -- receive data\n\
send(data) -- send data\n\
set_blocking(0 | 1) -- set or clear the blocking I/O flag\n\
set_timeout(None | int) -- set or clear the timeout\n\
timeout() -- return timeout or None\n");

/* Deallocate an irsocket Object */
static void _irsocket_dealloc(PyIrDASocketObject * s)
{
	if (s->socket != NULL)
	{
		irda_socket_close(s->socket);
	}

	Py_TYPE(s)->tp_free((PyObject *)s);
}

/* Initialize a new irsocket object */
static int _irsocket_init(PyObject * self, PyObject * args, PyObject * kwds)
{
	PyIrDASocketObject * s = (PyIrDASocketObject *)self;

	int rc;

	Py_BEGIN_ALLOW_THREADS
	rc = irda_socket_open(& s->socket);
	Py_END_ALLOW_THREADS

	if (rc != 0)
	{
		set_error();
		return -1;
	}

	return 0;
}

/* Create a new, uninitialized irsocket object */
static PyObject * _irsocket_new(PyTypeObject * type, PyObject * args, PyObject * kwds)
{
	PyObject * new;

	new = type->tp_alloc(type, 0);
	if (new != NULL)
	{
		((PyIrDASocketObject *)new)->socket = NULL;
		((PyIrDASocketObject *)new)->irda_address = 0;
		((PyIrDASocketObject *)new)->irda_lsap = 0;
	}

	return new;
}

/* Dump an irsocket to a string description */
static PyObject * _irsocket_repr(PyIrDASocketObject * s)
{
    char buf[512];

    if ((s->socket != NULL) || (s->irda_address == 0))
    	return PyString_FromString("<irsocket object, not connected>");

    PyOS_snprintf(
        buf, sizeof(buf),
        "<irsocket object, address=%lu, lsap=%u>",
        s->irda_address,
        s->irda_lsap);
    return PyString_FromString(buf);
}

/* Type object for irsocket objects */
static PyTypeObject irsocket_type =
{
	PyVarObject_HEAD_INIT(0, 0)
	"irda.irsocket",							/* tp_name */
	sizeof(PyIrDASocketObject),					/* tp_basicsize */
	0,											/* tp_itemsize */
	(destructor)_irsocket_dealloc,				/* tp_dealloc */
	0,											/* tp_print */
	0,											/* tp_getattr */
	0,											/* tp_setattr */
	0,											/* tp_compare */
	(reprfunc)_irsocket_repr,					/* tp_repr */
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
	irsocket_doc,								/* tp_doc */
	0,											/* tp_traverse */
	0,											/* tp_clear */
	0,											/* tp_richcompare */
	0,											/* tp_weaklistoffset */
	0,											/* tp_iter */
	0,											/* tp_iternext */
	irsocket_methods,							/* tp_methods */
	0,											/* tp_members */
	0,											/* tp_getset */
	0,											/* tp_base */
	0,											/* tp_dict */
	0,											/* tp_descr_get */
	0,											/* tp_descr_set */
	0,											/* tp_dictoffset */
	_irsocket_init,								/* tp_init */
	PyType_GenericAlloc,						/* tp_alloc */
	_irsocket_new,								/* tp_new */
	PyObject_Del,								/* tp_free */
};

void os_cleanup()
{
	(void)irda_cleanup();
}

int os_init()
{
	if (irda_init() == 0)
	{
		Py_AtExit(os_cleanup);
		return 1;
	}

	return 0;
}

/* irda Module Method Table */
PyMethodDef pyirda_methods[] =
{
	{ "discover", (PyCFunction)pyirda_discover, METH_NOARGS, pyirda_discover_doc },
	{ NULL, NULL, 0, NULL },
};

/* irda Module Documentation */
PyDoc_STRVAR(pyirda_doc,
"IrDA Minimal Interface\n\
\n\
Implements a light interface to the IrDA subsystem on Linux and Windows\n\
suitable for communicating with Dive Computers"
);

PyMODINIT_FUNC initirda(void)
{
	if (! os_init())
		return;

	/* Initialize irsock_type struct */
	if (PyType_Ready(&irsocket_type) < 0)
		return;

	/* Initialize the Module */
	PyObject * m;
	m = Py_InitModule3("irda", pyirda_methods, pyirda_doc);
	if (m == NULL)
		return;

	/* Register the irda.error Exception Class */
	pyirda_error = PyErr_NewException("irda.error", PyExc_IOError, NULL);
	if (pyirda_error == NULL)
		return;
	Py_INCREF(pyirda_error);
	PyModule_AddObject(m, "error", pyirda_error);

	/* Register the irda.timeout Exception Class */
	pyirda_timeout = PyErr_NewException("irda.timeout", PyExc_IOError, NULL);
	if (pyirda_timeout == NULL)
		return;
	Py_INCREF(pyirda_timeout);
	PyModule_AddObject(m, "timeout", pyirda_timeout);

	/* Register the irsocket Class */
	Py_INCREF(&irsocket_type);
	if (PyModule_AddObject(m, "irsocket", (PyObject *)&irsocket_type) != 0)
		return;
}
