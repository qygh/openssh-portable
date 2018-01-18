/*
 * my_ssh_api.c
 *
 *  Created on: 15 Jan 2018
 *      Author: lqy
 */

#include "my_ssh_api.h"

ssize_t ssh_read(struct ssh* ssh, u_char* type, const u_char** datap,
		size_t* len) {
	int ret = ssh_packet_next(ssh, type);
	//printf("ssh_read: ssh_packet_next returned %d, type: %u\n", ret, *type);
	if (ret < 0) {
		//printf("ssh_read: ssh_packet_next error\n");
		return -1;
	} else {
		if (*type != 0) {
			/* packet available */
			*datap = ssh_packet_payload(ssh, len);
			return *len;
		} else {
			/* packet unavailable */
			*datap = NULL;
			return 0;
		}
	}
}

ssize_t ssh_write(struct ssh* ssh, u_char type, const u_char* data, size_t len) {
	int ret = ssh_packet_put(ssh, type, data, len);
	//printf("ssh_write: ssh_packet_put returned %d\n", ret);
	if (ret < 0) {
		//printf("ssh_write: ssh_packet_put error\n");
		return -1;
	}

	return len;
}

ssize_t ssh_fill(struct ssh* ssh, int in_fd, int* errno_out) {
	char buffer[1024 * 16];

	/* read from in_fd and fill the SSH input byte stream */
	ssize_t sret = read(in_fd, buffer, sizeof(buffer));
	int errn = errno;
	//putchar('\n');
	//putchar('\n');
	//printf("ssh_fill: read() returned %zd\n", sret);
	//putchar('\n');
	//putchar('\n');
	if (sret <= 0) {
		/* error or EOF */
		if (errno_out != NULL) {
			*errno_out = errn;
		}
		return sret;
	} else {
		int ret = ssh_input_append(ssh, buffer, sret);
		//printf("ssh_fill: ssh_input_append(%zd) returned %d\n", sret, ret);
		if (ret < 0) {
			//printf("ssh_fill: ssh_input_append() error\n");
			if (errno_out != NULL) {
				*errno_out = errn;
			}
			return -1;
		}
	}

	return sret;
}

ssize_t ssh_flush(struct ssh* ssh, int out_fd, int* errno_out) {
	/* send SSH output byte stream */
	const u_char* b = NULL;
	size_t l = 0;
	b = ssh_output_ptr(ssh, &l);
	//printf("ssh_flush: ssh_output_ptr() returned %p, len: %zu\n", b, l);
	size_t bytes_sent = 0;
	while (bytes_sent < l) {
		ssize_t wret = write(out_fd, b + bytes_sent, l - bytes_sent);
		int errn = errno;
		//printf("ssh_flush: write returned %zd\n", wret);
		if (wret < 0) {
			//printf("ssh_flush: write() error, errno: %d\n", errn);
			if (errno_out != NULL) {
				*errno_out = errn;
			}
			return wret;
		} else {
			int ret = ssh_output_consume(ssh, wret);
			//printf("ssh_flush: ssh_output_consume returned %d\n", ret);
			if (ret < 0) {
				//printf("ssh_flush: ssh_output_consume error\n");
				if (errno_out != NULL) {
					*errno_out = errn;
				}
				return -1;
			}
		}
		bytes_sent += wret;
	}

	return bytes_sent;
}
