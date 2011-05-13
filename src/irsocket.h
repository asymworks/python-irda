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

#ifndef IRSOCKET_H_
#define IRSOCKET_H_

/* Python module name */
#define PyIrSocket_MODULE_NAME	"irsocket"

/* Abstract the socket file descriptor type */
#ifdef MS_WINDOWS
typedef SOCKET SOCKET_T;
# ifdef MS_WIN64
#  define SIZEOF_SOCKET_T 8
# else
#  define SIZEOF_SOCKET_T 4
# endif
#else
typedef int SOCKET_T;
# define SIZEOF_SOCKET_T SIZEOF_INT
#endif

/* IrDA Socket Object Information */
typedef struct {
    PyObject_HEAD
    SOCKET_T sock_fd;           		/* Socket file descriptor */
    int sock_family;            		/* Address family, always, AF_IRDA */
    int sock_type;              		/* Socket type, e.g., SOCK_STREAM */
    int sock_proto;             		/* Protocol type, usually 0 */
    PyObject * (* errorhandler)(void); 	/* Error handler  */
    long sock_timeout;                 	/* Operation timeout */
} PyIrSocketSockObject;

#endif /* IRSOCKET_H_ */
