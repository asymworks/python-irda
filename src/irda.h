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

#ifndef IRDA_H_
#define IRDA_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief IrDA Socket Handle Type
 */
typedef struct irda_t * irda_t;

/**
 * @brief IrDA Discovery Callback Function Type
 * @param [in] IrDA Client Address
 * @param [in] IrDA Client Endpoint Name
 * @param [in] IrDA Client Character Set
 * @param [in] IrDA Client Hints
 * @param [in] User Data
 */
typedef void (* irda_callback_t)(unsigned int, const char *, unsigned int, unsigned int, void *);

/**
 * @brief Return the most recent IrDA error code
 *
 * OS-specific wrapper which returns an OS error code corresponding to the last
 * failed IrDA function call.
 */
int irda_errcode(void);

/**
 * @brief Return the most recent IrDA error message
 *
 * OS-specific wrapper which returns an OS error message corresponding to the
 * last failed IrDA function call.
 */
const char * irda_errmsg(void);

/**
 * @brief Initialize IrDA Subsystem
 * @return 0 on success, -1 on failure
 *
 * This function provides OS-specific initialization for IrDA and should be
 * called prior to any other irda_* functions other than irda_errcode() and
 * irda_errmsg().
 */
int irda_init(void);

/**
 * @brief Shut down IrDA Subsystem
 * @return 0 on success, -1 on failure
 *
 * This function provides OS-specific shutdown for IrDA and should be
 * called after all other irda_* functions other than irda_errcode() and
 * irda_errmsg().
 */
int irda_cleanup(void);

/**
 * @brief Open an IrDA Socket
 * @param [out] Pointer an IrDA Socket Handle
 * @return 0 on success, -1 on failure
 *
 * Opens a new IrDA socket object.  This method will allocate memory for the
 * newly-created socket object; the memory must be freed by calling
 * irda_socket_close().  When created, the socket will default to blocking
 * reads.  Use irda_socket_set_timeout() to change timeout settings.
 */
int irda_socket_open(irda_t * s);

/**
 * @brief Close an IrDA Socket
 * @param [in] IrDA Socket Handle
 * @return 0 on success, -1 on failure
 *
 * Closes the specified IrDA socket object.  This method releases memory
 * allocated with irda_socket_open().
 */
int irda_socket_close(irda_t s);

/**
 * @brief Set the IrDA socket timeout
 * @param [in] IrDA Socket Handle
 * @param [in] Timeout value in milliseconds
 * @return 0 on success, -1 on failure
 */
int irda_socket_set_timeout(irda_t s, long timeout);

/**
 * @brief Return the IrDA socket timeout
 * @param [in] IrDA Socket Handle
 * @param [out] Timeout value in milliseconds
 * @return 0 on success, -1 on failure
 */
int irda_socket_timeout(irda_t s, long * timeout);

/**
 * @brief Discover devices on the IrDA bus
 * @param [in] IrDA Socket Handle
 * @param [in] Discovery Callback Function
 * @param [in] User Data passed to the Callback Function
 * @return Number of devices found or -1 on failure
 *
 * Enumerates all devices currently connected to the IrDA bus.  For each device
 * enumerated, the callback function will be invoked, passing the device details
 * and the user-defined data passed to this function.
 */
int irda_socket_discover(irda_t s, irda_callback_t cb, void * userdata);

/**
 * @brief Connect to an IrDA Client by Endpoint Name
 * @param [in] IrDA Socket Handle
 * @param [in] Client Address
 * @param [in] Endpoint Name
 * @param [out] Timeout Flag
 * @return 0 on success, -1 on failure
 *
 * Connects to the given IrDA client by address and endpoint name.  If the IrDA
 * socket is non-blocking and the connection times out, the timeout flag will be
 * set.
 */
int irda_socket_connect_name(irda_t s, unsigned int address, const char * name, int * timeout);

/**
 * @brief Connect to an IrDA Client by Endpoint LSAP
 * @param [in] IrDA Socket Handle
 * @param [in] Client Address
 * @param [in] Endpoint LSAP
 * @param [out] Timeout Flag
 * @return 0 on success, -1 on failure
 *
 * Connects to the given IrDA client by address and endpoint LSAP.  If the IrDA
 * socket is non-blocking and the connection times out, the timeout flag will be
 * set.
 */
int irda_socket_connect_lsap(irda_t s, unsigned int address, unsigned int lsap, int * timeout);

/**
 * @brief Get the number of bytes available for reading
 * @param [in] IrDA Socket Handle
 * @return Number of bytes available for reading, or -1 on failure
 */
int irda_socket_available(irda_t s);

/**
 * @brief Read data from the IrDA Socket
 * @param [in] IrDA Socket Handle
 * @param [in] Data Buffer Pointer
 * @param [in] Data Buffer Size
 * @param [out] Timeout Flag
 * @return 0 on success, -1 on failure
 *
 * Reads data from the IrDA socket, up to the given data buffer size.  The
 * caller is responsible for allocating and disposing of the data buffer.  If
 * the socket is non-blocking and a timeout occurs, the timeout flag will be
 * set.  The size parameter will be modified to correspond to the actual number
 * of bytes read.  In case of timeout or error this may be less than the passed
 * size value.
 */
int irda_socket_read(irda_t s, void * data, ssize_t * size, int * timeout);

/**
 * @brief Write data to the IrDA Socket
 * @param [in] IrDA Socket Handle
 * @param [in] Data Buffer Pointer
 * @param [in] Data Buffer Size
 * @param [out] Timeout Flag
 * @return 0 on success, -1 on failure
 *
 * Writes data to the IrDA socket, up to the given data buffer size.  The
 * caller is responsible for allocating and disposing of the data buffer.  If
 * the socket is non-blocking and a timeout occurs, the timeout flag will be
 * set.  The size parameter will be modified to correspond to the actual number
 * of bytes written.  In case of timeout or error this may be less than the
 * passed size value.
 */
int irda_socket_write(irda_t s, const void * data, ssize_t * size, int * timeout);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* IRDA_H_ */
