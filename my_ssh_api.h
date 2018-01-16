/*
 * my_ssh_api.h
 *
 *  Created on: 16 Jan 2018
 *      Author: lqy
 */

#ifndef MY_SSH_API_H_
#define MY_SSH_API_H_

#include <unistd.h>
#include <errno.h>

#include "ssh_api.h"

ssize_t ssh_read(struct ssh* ssh, u_char* type, const u_char** datap,
		size_t* len);

ssize_t ssh_write(struct ssh* ssh, u_char type, const u_char* data, size_t len);

ssize_t ssh_fill(struct ssh* ssh, int in_fd, int* errno_out);

ssize_t ssh_flush(struct ssh* ssh, int out_fd, int* errno_out);

#endif /* MY_SSH_API_H_ */
