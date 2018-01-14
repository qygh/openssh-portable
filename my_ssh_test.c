/*
 * my_ssh_test.c
 *
 *  Created on: 8 Nov 2017
 *      Author: lqy
 */

#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <errno.h>
#include <stdint.h>

#include "ssh_api.h"

static int create_tcp_listening_socket(uint16_t port);

static int create_tcp_client_socket(char* hostname, char* port);

ssize_t ssh_read(struct ssh* ssh, u_char* type, const u_char** datap,
		size_t* len);

ssize_t ssh_write(struct ssh* ssh, u_char type, const u_char* data, size_t len);

ssize_t ssh_fill(struct ssh* ssh, int in_fd);

ssize_t ssh_flush(struct ssh* ssh, int out_fd);

ssize_t read_message_from_fd(int fd, u_char* type, u_char* buffer,
		size_t buffer_len);

ssize_t write_message_to_fd(int fd, u_char type, const u_char* data, size_t len);

ssize_t fd_read_full(int in_fd, u_char* buffer, size_t len);

ssize_t fd_write_full(int out_fd, const u_char* buffer, size_t len);

void print_ssh_message_type(unsigned char type);

struct ssh_forwarder_thread_arg {
	char* ssh_private_key_path;
	int real_client_fd;
	char* server_hostname;
	char* server_port;
	pthread_barrier_t* barrier;
};

void* ssh_forwarder(void* arg) {
	struct ssh_forwarder_thread_arg* oarg = arg;
	struct ssh_forwarder_thread_arg args_cpy = { 0 };

	//copy arguments onto thread's own stack
	memcpy(&args_cpy, oarg, sizeof(args_cpy));

	//finish copying arguments onto own stack and wait until main thread has called pthread_detach()
	if (args_cpy.barrier != NULL) {
		pthread_barrier_wait(args_cpy.barrier);
	}

	printf("thread ready for %d\n", args_cpy.real_client_fd);

	struct ssh_forwarder_thread_arg* args = &args_cpy;

	int ret = -1;

	int real_server_fd = -1;
	struct ssh* ssh_s = NULL;
	struct sshkey* sshkey = NULL;
	struct ssh* ssh_c = NULL;

	real_server_fd = create_tcp_client_socket(args->server_hostname,
			args->server_port);
	if (real_server_fd < 0) {
		fprintf(stderr, "create_tcp_client_socket() failed\n");

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*ignore SIGPIPE that can be possibly caused by writes to disconnected clients*/
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "signal() error for %d\n", args->real_client_fd);

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		//pthread_exit(NULL);
		return NULL;
	}
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "signal() error for %d\n", real_server_fd);

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*disable TCP delay*/
	/*{
	 int one = 1;
	 int ret = setsockopt(args->real_client_fd, IPPROTO_TCP, TCP_NODELAY,
	 &one, sizeof(one));
	 printf("setsockopt returned %d\n", ret);

	 ret = setsockopt(real_server_fd, IPPROTO_TCP, TCP_NODELAY, &one,
	 sizeof(one));
	 printf("setsockopt returned %d\n", ret);
	 }*/

	/*{
	 struct timeval timeout;
	 timeout.tv_sec = 1;
	 timeout.tv_usec = 0;

	 int ret = setsockopt(args->real_client_fd, SOL_SOCKET, SO_RCVTIMEO,
	 &timeout, sizeof(timeout));
	 printf("setsockopt returned %d\n", ret);

	 ret = setsockopt(real_server_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
	 sizeof(timeout));
	 printf("setsockopt returned %d\n", ret);
	 }*/

	/*set sockets to non-blocking*/
	if (fcntl(args->real_client_fd, F_SETFL, O_NONBLOCK) < 0
			|| fcntl(real_server_fd, F_SETFL, O_NONBLOCK) < 0) {
		fprintf(stderr, "fcntl() failed\n");

		close(args->real_client_fd);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*initialise SSH object*/
	ret = ssh_init(&ssh_s, 1, NULL);
	printf("ssh_init() returned %d, ssh: %p\n", ret, ssh_s);
	if (ret != 0) {
		printf("ssh_init() failed\n");

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*initialise SSH private key*/
	sshkey = key_load_private(args->ssh_private_key_path, "",
	NULL);
	printf("key_load_private() returned %p\n", sshkey);
	if (sshkey == NULL) {
		printf("key_load_private() failed\n");

		ssh_free(ssh_s);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*add SSH private key to SSH object*/
	ret = ssh_add_hostkey(ssh_s, sshkey);
	printf("ssh_add_hostkey() returned %d\n", ret);
	if (ret != 0) {
		printf("ssh_add_hostkey() failed\n");

		sshkey_free(sshkey);
		ssh_free(ssh_s);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*initialise SSH object*/
	ret = ssh_init(&ssh_c, 0, NULL);
	printf("ssh_init() returned %d, ssh: %p\n", ret, ssh_c);
	if (ret != 0) {
		printf("ssh_init() failed\n");

		ssh_free(ssh_c);
		sshkey_free(sshkey);
		ssh_free(ssh_s);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*set SSH host key verification function*/
	int verify_host_key(struct sshkey* sshkey, struct ssh* ssh) {
		return 0;
	}
	ret = ssh_set_verify_host_key_callback(ssh_c, verify_host_key);
	if (ret != 0) {
		printf("ssh_set_verify_host_key_callback() failed\n");

		ssh_free(ssh_c);
		sshkey_free(sshkey);
		ssh_free(ssh_s);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*poll the two sockets*/
	struct pollfd ufds[2];
	ufds[0].fd = args->real_client_fd;
	ufds[0].events = POLLIN;
	ufds[1].fd = real_server_fd;
	ufds[1].events = POLLIN;

	{
		u_char type = 0;
		const u_char* data = NULL;
		size_t len = 0;
		//ssize_t ret = 0;
		ssh_read(ssh_s, &type, &data, &len);
		ssh_flush(ssh_s, ufds[0].fd);
		ssh_read(ssh_c, &type, &data, &len);
		ssh_flush(ssh_c, ufds[1].fd);
	}

	int auth_success = 0;
	while (1) {
		ret = poll(ufds, 2, -1);

		if (ret < 0) {
			fprintf(stderr, "poll() failed\n");
		} else if (ret == 0) {
			//fprintf(stderr, "poll() timeout\n");
			/*ssize_t ret = ssh_flush(ssh_c, ufds[1].fd);
			 if (ret > 0) {
			 printf("ssh_flush(ssh_c) returned %zd\n", ret);
			 } else if (ret < 0) {
			 printf("ssh_flush(ssh_c) returned %zd\n", ret);
			 }

			 ret = ssh_flush(ssh_s, ufds[0].fd);
			 if (ret > 0) {
			 printf("ssh_flush(ssh_s) returned %zd\n", ret);
			 } else if (ret < 0) {
			 printf("ssh_flush(ssh_s) returned %zd\n", ret);
			 }*/

			//read from in_fd and fill the SSH input byte stream
			/*char buffer[8192];
			 ssize_t sret = read(ufds[1].fd, buffer, sizeof(buffer));
			 printf("ssh_read: read returned %zd\n", sret);
			 if (sret > 0) {
			 ret = ssh_input_append(ssh_c, buffer, sret);
			 printf("ssh_read: ssh_input_append(%zd) returned %d\n", sret,
			 ret);
			 if (ret < 0) {
			 printf("ssh_read: ssh_input_append error\n");
			 }
			 }

			 sret = read(ufds[0].fd, buffer, sizeof(buffer));
			 printf("ssh_read: read returned %zd\n", sret);
			 if (sret > 0) {
			 ret = ssh_input_append(ssh_s, buffer, sret);
			 printf("ssh_read: ssh_input_append(%zd) returned %d\n", sret,
			 ret);
			 if (ret < 0) {
			 printf("ssh_read: ssh_input_append error\n");
			 }
			 }*/
		} else {
			printf("poll() returned %d\n", ret);

			if (ufds[0].revents & POLLIN) {
				printf("\n------------------\n");

				printf("Data available from client\n");

				u_char type = 0;
				const u_char* data = NULL;
				size_t len = 0;
				ssize_t ret = 0;

				ret = ssh_fill(ssh_s, ufds[0].fd);
				printf("ssh_fill(ssh_s, %d) returned %zd\n", ufds[0].fd, ret);
				if (ret < 0) {
					if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
						printf("ssh_fill() would block\n");
					} else {
						printf("ssh_fill() failed\n");
						break;
					}
				}

				u_char should_loop = 1;
				while (1) {
					ret = ssh_read(ssh_s, &type, &data, &len);
					printf(
							"ssh_read(ssh_s) returned %zd, type: %u, data: %p, len: %zu\n",
							ret, type, data, len);
					print_ssh_message_type(type);
					if (ret < 0) {
						printf("ssh_read() failed\n");
						ssh_flush(ssh_s, ufds[0].fd);
						should_loop = 0;
						break;
					}
					if (type == 0) {
						printf("\n\nSSH_MSG_NONE\n\n");

						ret = ssh_flush(ssh_s, ufds[0].fd);
						printf("ssh_flush(ssh_s, %d) returned %zd\n",
								ufds[0].fd, ret);
						if (ret < 0) {
							printf("ssh_flush() failed\n");
							should_loop = 0;
							break;
						}

						should_loop = 1;
						break;
					}

					size_t i = 0;
					putchar('\n');
					for (i = 0; i < len; i++) {
						printf("%02x ", data[i]);
					}
					putchar('\n');

					putchar('\n');
					for (i = 0; i < len; i++) {
						putchar(data[i]);
					}
					putchar('\n');

					putchar('\n');

					ret = ssh_write(ssh_c, type, data, len);
					printf("ssh_write(ssh_c, %d) returned %zd\n", ufds[1].fd,
							ret);
					if (ret < 0) {
						printf("ssh_write() failed\n");
						should_loop = 0;
						break;
					}

					ret = ssh_flush(ssh_c, ufds[1].fd);
					printf("ssh_flush(ssh_c, %d) returned %zd\n", ufds[1].fd,
							ret);
					if (ret < 0) {
						printf("ssh_flush() failed\n");
						should_loop = 0;
						break;
					}
				}
				if (!should_loop) {
					break;
				}

				printf("\n++++++++++++++++++\n");
			}

			if (ufds[1].revents & POLLIN) {
				printf("\n------------------\n");

				printf("Data available from server\n");

				u_char type = 0;
				const u_char* data = NULL;
				size_t len = 0;
				ssize_t ret = 0;

				ret = ssh_fill(ssh_c, ufds[1].fd);
				printf("ssh_fill(ssh_c, %d) returned %zd\n", ufds[1].fd, ret);
				if (ret < 0) {
					if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
						printf("ssh_fill() would block\n");
					} else {
						printf("ssh_fill() failed\n");
						break;
					}
				}

				u_char should_loop = 1;
				while (1) {
					ret = ssh_read(ssh_c, &type, &data, &len);
					printf(
							"ssh_read(ssh_c) returned %zd, type: %u, data: %p, len: %zu\n",
							ret, type, data, len);
					print_ssh_message_type(type);
					if (ret < 0) {
						printf("ssh_read() failed\n");
						ssh_flush(ssh_s, ufds[0].fd);
						should_loop = 0;
						break;
					}
					if (type == 52) {
						auth_success = 1;
					} else if (type == 0) {
						printf("\n\nSSH_MSG_NONE\n\n");

						ret = ssh_flush(ssh_c, ufds[1].fd);
						printf("ssh_flush(ssh_c, %d) returned %zd\n",
								ufds[1].fd, ret);
						if (ret < 0) {
							printf("ssh_flush() failed\n");
							should_loop = 0;
							break;
						}

						should_loop = 1;
						break;
					}

					size_t i = 0;
					putchar('\n');
					for (i = 0; i < len; i++) {
						printf("%02x ", data[i]);
					}
					putchar('\n');

					putchar('\n');
					for (i = 0; i < len; i++) {
						putchar(data[i]);
					}
					putchar('\n');

					putchar('\n');

					ret = ssh_write(ssh_s, type, data, len);
					printf("ssh_write(ssh_s, %d) returned %zd\n", ufds[0].fd,
							ret);
					if (ret < 0) {
						printf("ssh_write() failed\n");
						should_loop = 0;
						break;
					}

					ret = ssh_flush(ssh_s, ufds[0].fd);
					printf("ssh_flush(ssh_s, %d) returned %zd\n", ufds[0].fd,
							ret);
					if (ret < 0) {
						printf("ssh_flush() failed\n");
						should_loop = 0;
						break;
					}
				}
				if (!should_loop) {
					break;
				}

				printf("\n++++++++++++++++++\n");
			}
		}
	}

	if (auth_success) {
		printf("Login succeeded\n");
	} else {
		printf("Login failed\n");
	}

	ssh_free(ssh_c);
	sshkey_free(sshkey);
	ssh_free(ssh_s);
	shutdown(args->real_client_fd, SHUT_RDWR);
	close(args->real_client_fd);
	shutdown(real_server_fd, SHUT_RDWR);
	close(real_server_fd);
	//pthread_exit(NULL);
	printf("thread for %d terminating\n", args->real_client_fd);
	return NULL;
}

void* ssh_decoder_c(void* arg) {
	struct ssh_forwarder_thread_arg* oarg = arg;
	struct ssh_forwarder_thread_arg args_cpy = { 0 };

	//copy arguments onto thread's own stack
	memcpy(&args_cpy, oarg, sizeof(args_cpy));

	//finish copying arguments onto own stack and wait until main thread has called pthread_detach()
	if (args_cpy.barrier != NULL) {
		pthread_barrier_wait(args_cpy.barrier);
	}

	printf("thread ready for %d\n", args_cpy.real_client_fd);

	struct ssh_forwarder_thread_arg* args = &args_cpy;

	int ret = -1;

	int real_server_fd = -1;
	struct ssh* ssh_s = NULL;
	struct sshkey* sshkey = NULL;

	real_server_fd = create_tcp_client_socket(args->server_hostname,
			args->server_port);
	if (real_server_fd < 0) {
		fprintf(stderr, "create_tcp_client_socket() failed\n");

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*ignore SIGPIPE that can be possibly caused by writes to disconnected clients*/
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "signal() error for %d\n", args->real_client_fd);

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		//pthread_exit(NULL);
		return NULL;
	}
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "signal() error for %d\n", real_server_fd);

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*set sockets to non-blocking*/
	if (fcntl(args->real_client_fd, F_SETFL, O_NONBLOCK) < 0
	/*|| fcntl(real_server_fd, F_SETFL, O_NONBLOCK) < 0*/) {
		fprintf(stderr, "fcntl() failed\n");

		close(args->real_client_fd);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*initialise SSH object*/
	ret = ssh_init(&ssh_s, 1, NULL);
	printf("ssh_init() returned %d, ssh: %p\n", ret, ssh_s);
	if (ret != 0) {
		printf("ssh_init() failed\n");

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*initialise SSH private key*/
	sshkey = key_load_private(args->ssh_private_key_path, "",
	NULL);
	printf("key_load_private() returned %p\n", sshkey);
	if (sshkey == NULL) {
		printf("key_load_private() failed\n");

		ssh_free(ssh_s);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*add SSH private key to SSH object*/
	ret = ssh_add_hostkey(ssh_s, sshkey);
	printf("ssh_add_hostkey() returned %d\n", ret);
	if (ret != 0) {
		printf("ssh_add_hostkey() failed\n");

		sshkey_free(sshkey);
		ssh_free(ssh_s);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*poll the two sockets*/
	struct pollfd ufds[2];
	ufds[0].fd = args->real_client_fd;
	ufds[0].events = POLLIN;
	ufds[1].fd = real_server_fd;
	ufds[1].events = POLLIN;

	{
		u_char type = 0;
		const u_char* data = NULL;
		size_t len = 0;
		//ssize_t ret = 0;
		ssh_read(ssh_s, &type, &data, &len);
		ssh_flush(ssh_s, ufds[0].fd);
	}

	while (1) {
		ret = poll(ufds, 2, -1);

		if (ret < 0) {
			fprintf(stderr, "poll() failed\n");
		} else if (ret == 0) {

		} else {
			printf("poll() returned %d\n", ret);

			if (ufds[0].revents & POLLIN) {
				printf("\n------------------\n");

				printf("Data available from client\n");

				u_char type = 0;
				const u_char* data = NULL;
				size_t len = 0;
				ssize_t ret = 0;

				ret = ssh_fill(ssh_s, ufds[0].fd);
				printf("ssh_fill(ssh_s, %d) returned %zd\n", ufds[0].fd, ret);
				if (ret < 0) {
					if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
						printf("ssh_fill() would block\n");
					} else {
						printf("ssh_fill() failed\n");
						break;
					}
				}

				u_char should_loop = 1;
				while (1) {
					ret = ssh_read(ssh_s, &type, &data, &len);
					printf(
							"ssh_read(ssh_s) returned %zd, type: %u, data: %p, len: %zu\n",
							ret, type, data, len);
					print_ssh_message_type(type);
					if (ret < 0) {
						printf("ssh_read() failed\n");
						ssh_flush(ssh_s, ufds[0].fd);
						should_loop = 0;
						break;
					}
					if (type == 90) {
						printf("\n\nSSH_MSG_CHANNEL_OPEN\n\n");
					} else if (type == 0) {
						printf("\n\nSSH_MSG_NONE\n\n");

						ret = ssh_flush(ssh_s, ufds[0].fd);
						printf("ssh_flush(ssh_s, %d) returned %zd\n",
								ufds[0].fd, ret);
						if (ret < 0) {
							printf("ssh_flush() failed\n");
							should_loop = 0;
							break;
						}

						should_loop = 1;
						break;
					}

					size_t i = 0;
					putchar('\n');
					for (i = 0; i < len; i++) {
						printf("%02x ", data[i]);
					}
					putchar('\n');

					putchar('\n');
					for (i = 0; i < len; i++) {
						putchar(data[i]);
					}
					putchar('\n');

					putchar('\n');

					ret = write_message_to_fd(ufds[1].fd, type, data, len);
					printf("write_message_to_fd(%d) returned %zd\n", ufds[1].fd,
							ret);
					if (ret < 0) {
						printf("write_message_to_fd() failed\n");
						should_loop = 0;
						break;
					}
				}
				if (!should_loop) {
					break;
				}

				printf("\n++++++++++++++++++\n");
			}

			if (ufds[1].revents & POLLIN) {
				printf("\n------------------\n");

				printf("Data available from server\n");

				u_char type = 0;
				u_char data[1024 * 64];
				size_t len = 0;
				ssize_t ret = 0;

				ret = read_message_from_fd(ufds[1].fd, &type, data,
						sizeof(data));
				printf("read_message_from_fd(%d) returned %zd\n", ufds[1].fd,
						ret);
				if (ret < 0) {
					printf("read_message_from_fd() failed\n");
					break;
				} else {
					len = ret;
				}

				size_t i = 0;
				putchar('\n');
				for (i = 0; i < len; i++) {
					printf("%02x ", data[i]);
				}
				putchar('\n');

				putchar('\n');
				for (i = 0; i < len; i++) {
					putchar(data[i]);
				}
				putchar('\n');

				putchar('\n');

				ret = ssh_write(ssh_s, type, data, len);
				printf("ssh_write(ssh_s, %d) returned %zd\n", ufds[0].fd, ret);
				if (ret < 0) {
					printf("ssh_write() failed\n");
					break;
				}

				ret = ssh_flush(ssh_s, ufds[0].fd);
				printf("ssh_flush(ssh_s, %d) returned %zd\n", ufds[0].fd, ret);
				if (ret < 0) {
					printf("ssh_flush() failed\n");
					break;
				}

				printf("\n++++++++++++++++++\n");
			}
		}
	}

	sshkey_free(sshkey);
	ssh_free(ssh_s);
	shutdown(args->real_client_fd, SHUT_RDWR);
	close(args->real_client_fd);
	shutdown(real_server_fd, SHUT_RDWR);
	close(real_server_fd);
	//pthread_exit(NULL);
	printf("thread for %d terminating\n", args->real_client_fd);
	return NULL;
}

void* ssh_decoder_s(void* arg) {
	struct ssh_forwarder_thread_arg* oarg = arg;
	struct ssh_forwarder_thread_arg args_cpy = { 0 };

	//copy arguments onto thread's own stack
	memcpy(&args_cpy, oarg, sizeof(args_cpy));

	//finish copying arguments onto own stack and wait until main thread has called pthread_detach()
	if (args_cpy.barrier != NULL) {
		pthread_barrier_wait(args_cpy.barrier);
	}

	printf("thread ready for %d\n", args_cpy.real_client_fd);

	struct ssh_forwarder_thread_arg* args = &args_cpy;

	int ret = -1;

	int real_server_fd = -1;
	struct ssh* ssh_c = NULL;

	real_server_fd = create_tcp_client_socket(args->server_hostname,
			args->server_port);
	if (real_server_fd < 0) {
		fprintf(stderr, "create_tcp_client_socket() failed\n");

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*ignore SIGPIPE that can be possibly caused by writes to disconnected clients*/
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "signal() error for %d\n", args->real_client_fd);

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		//pthread_exit(NULL);
		return NULL;
	}
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "signal() error for %d\n", real_server_fd);

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*set sockets to non-blocking*/
	if (/*fcntl(args->real_client_fd, F_SETFL, O_NONBLOCK) < 0
	 ||*/fcntl(real_server_fd, F_SETFL, O_NONBLOCK) < 0) {
		fprintf(stderr, "fcntl() failed\n");

		close(args->real_client_fd);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*initialise SSH object*/
	ret = ssh_init(&ssh_c, 0, NULL);
	printf("ssh_init() returned %d, ssh: %p\n", ret, ssh_c);
	if (ret != 0) {
		printf("ssh_init() failed\n");

		ssh_free(ssh_c);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*set SSH host key verification function*/
	int verify_host_key(struct sshkey* sshkey, struct ssh* ssh) {
		return 0;
	}
	ret = ssh_set_verify_host_key_callback(ssh_c, verify_host_key);
	if (ret != 0) {
		printf("ssh_set_verify_host_key_callback() failed\n");

		ssh_free(ssh_c);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*poll the two sockets*/
	struct pollfd ufds[2];
	ufds[0].fd = args->real_client_fd;
	ufds[0].events = POLLIN;
	ufds[1].fd = real_server_fd;
	ufds[1].events = POLLIN;

	{
		u_char type = 0;
		const u_char* data = NULL;
		size_t len = 0;
		//ssize_t ret = 0;
		ssh_read(ssh_c, &type, &data, &len);
		ssh_flush(ssh_c, ufds[0].fd);
	}

	while (1) {
		ret = poll(ufds, 2, -1);

		if (ret < 0) {
			fprintf(stderr, "poll() failed\n");
		} else if (ret == 0) {

		} else {
			printf("poll() returned %d\n", ret);

			if (ufds[0].revents & POLLIN) {
				printf("\n------------------\n");

				printf("Data available from client\n");

				u_char type = 0;
				u_char data[1024 * 64];
				size_t len = 0;
				ssize_t ret = 0;

				ret = read_message_from_fd(ufds[0].fd, &type, data,
						sizeof(data));
				printf("read_message_from_fd(%d) returned %zd\n", ufds[0].fd,
						ret);
				if (ret < 0) {
					printf("read_message_from_fd() failed\n");
					break;
				} else {
					len = ret;
				}

				size_t i = 0;
				putchar('\n');
				for (i = 0; i < len; i++) {
					printf("%02x ", data[i]);
				}
				putchar('\n');

				putchar('\n');
				for (i = 0; i < len; i++) {
					putchar(data[i]);
				}
				putchar('\n');

				putchar('\n');

				ret = ssh_write(ssh_c, type, data, len);
				printf("ssh_write(ssh_c, %d) returned %zd\n", ufds[1].fd, ret);
				if (ret < 0) {
					printf("ssh_write() failed\n");
					break;
				}

				ret = ssh_flush(ssh_c, ufds[1].fd);
				printf("ssh_flush(ssh_c, %d) returned %zd\n", ufds[1].fd, ret);
				if (ret < 0) {
					printf("ssh_flush() failed\n");
					break;
				}

				printf("\n++++++++++++++++++\n");
			}

			if (ufds[1].revents & POLLIN) {
				printf("\n------------------\n");

				printf("Data available from server\n");

				u_char type = 0;
				const u_char* data = NULL;
				size_t len = 0;
				ssize_t ret = 0;

				ret = ssh_fill(ssh_c, ufds[1].fd);
				printf("ssh_fill(ssh_c, %d) returned %zd\n", ufds[1].fd, ret);
				if (ret < 0) {
					if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
						printf("ssh_fill() would block\n");
					} else {
						printf("ssh_fill() failed\n");
						break;
					}
				}

				u_char should_loop = 1;
				while (1) {
					ret = ssh_read(ssh_c, &type, &data, &len);
					printf(
							"ssh_read(ssh_c) returned %zd, type: %u, data: %p, len: %zu\n",
							ret, type, data, len);
					print_ssh_message_type(type);
					if (ret < 0) {
						printf("ssh_read() failed\n");
						should_loop = 0;
						break;
					}
					if (type == 90) {
						printf("\n\nSSH_MSG_CHANNEL_OPEN\n\n");
					} else if (type == 0) {
						printf("\n\nSSH_MSG_NONE\n\n");

						ret = ssh_flush(ssh_c, ufds[1].fd);
						printf("ssh_flush(ssh_c, %d) returned %zd\n",
								ufds[1].fd, ret);
						if (ret < 0) {
							printf("ssh_flush() failed\n");
							should_loop = 0;
							break;
						}

						should_loop = 1;
						break;
					}

					size_t i = 0;
					putchar('\n');
					for (i = 0; i < len; i++) {
						printf("%02x ", data[i]);
					}
					putchar('\n');

					putchar('\n');
					for (i = 0; i < len; i++) {
						putchar(data[i]);
					}
					putchar('\n');

					putchar('\n');

					ret = write_message_to_fd(ufds[0].fd, type, data, len);
					printf("write_message_to_fd(%d) returned %zd\n", ufds[0].fd,
							ret);
					if (ret < 0) {
						printf("write_message_to_fd() failed\n");
						should_loop = 0;
						break;
					}
				}
				if (!should_loop) {
					break;
				}

				printf("\n++++++++++++++++++\n");
			}
		}
	}

	ssh_free(ssh_c);
	shutdown(args->real_client_fd, SHUT_RDWR);
	close(args->real_client_fd);
	shutdown(real_server_fd, SHUT_RDWR);
	close(real_server_fd);
	//pthread_exit(NULL);
	printf("thread for %d terminating\n", args->real_client_fd);
	return NULL;
}

int main(int argc, char* argv[]) {
	int mode = -1;

	char* private_key = NULL;
	char* port = NULL;
	char* dst_hostname = NULL;
	char* dst_port = NULL;

	char* argv0 = NULL;
	if (argc > 0) {
		argv0 = argv[0];
	} else {
		argv0 = " ";
	}

	if (argc < 6) {
		printf("Usage: %s e <private key> <port> <dst hostname> <dst port>\n",
				argv0);
		printf("       %s f <private key> <port> <dst hostname> <dst port>\n",
				argv0);
		printf("       %s g <private key> <port> <dst hostname> <dst port>\n",
				argv0);
		printf("       %s h <private key> <port> <dst hostname> <dst port>\n",
				argv0);
		return 1;
	}

	if (strcmp(argv[1], "e") == 0) {
		mode = 0;
		private_key = argv[2];
		port = argv[3];
		dst_hostname = argv[4];
		dst_port = argv[5];
	} else if (strcmp(argv[1], "f") == 0) {
		mode = 1;
		private_key = argv[2];
		port = argv[3];
		dst_hostname = argv[4];
		dst_port = argv[5];
	} else if (strcmp(argv[1], "g") == 0) {
		mode = 2;
		private_key = argv[2];
		port = argv[3];
		dst_hostname = argv[4];
		dst_port = argv[5];
	} else if (strcmp(argv[1], "h") == 0) {
		mode = 3;
		private_key = argv[2];
		port = argv[3];
		dst_hostname = argv[4];
		dst_port = argv[5];
	} else {
		printf("first argument is invalid\n");
		return 1;
	}

	if (mode == 0) {
		struct ssh_forwarder_thread_arg ssh_forwarder_thread_arg = { 0 };
		//pthread_t ssh_forwarder_thread;
		/*pthread_barrier_t* ssh_forwarder_thread_barrier = malloc(
		 sizeof(pthread_barrier_t));
		 if (ssh_forwarder_thread_barrier == NULL) {
		 fprintf(stderr, "malloc() for barrier failed\n");

		 return 1;
		 }
		 if (pthread_barrier_init(ssh_forwarder_thread_barrier, NULL, 2) < 0) {
		 fprintf(stderr, "pthread_barrier_init() failed\n");

		 free(ssh_forwarder_thread_barrier);
		 return 1;
		 }*/
		ssh_forwarder_thread_arg.ssh_private_key_path = private_key;
		ssh_forwarder_thread_arg.server_hostname = dst_hostname;
		ssh_forwarder_thread_arg.server_port = dst_port;
		ssh_forwarder_thread_arg.barrier = NULL;

		uint16_t portnum = strtol(port, NULL, 10);
		int sockfd = create_tcp_listening_socket(portnum);
		printf("create_tcp_listening_socket() returned %d\n", sockfd);
		if (sockfd < 0) {
			printf("create_tcp_listening_socket() failed\n");

			//free(ssh_forwarder_thread_barrier);
			return 1;
		}

		while (1) {
			int newfd = accept(sockfd, NULL, NULL);
			printf("accept() returned %d\n", newfd);
			if (newfd < 0) {
				printf("accept() failed\n");
				continue;
			}

			ssh_forwarder_thread_arg.real_client_fd = newfd;

			ssh_forwarder(&ssh_forwarder_thread_arg);

			/*if (pthread_create(&ssh_forwarder_thread, NULL, ssh_forwarder,
			 &ssh_forwarder_thread_arg) != 0) {
			 fprintf(stderr, "pthread_create() failed\n");

			 close(newfd);
			 continue;
			 }*/

			/*must be called to avoid memory leaks*/
			//pthread_detach(ssh_forwarder_thread);
			/*allow pthread_detach() to be called before new thread terminates and
			 wait until the thread finishes copying arguments onto its own stack*/
			//pthread_barrier_wait(ssh_forwarder_thread_barrier);
			//printf("thread created for %d\n", newfd);
		}
	} else if (mode == 1) {
		struct ssh_forwarder_thread_arg ssh_forwarder_thread_arg = { 0 };
		pthread_barrier_t* ssh_forwarder_thread_barrier = malloc(
				sizeof(pthread_barrier_t));
		if (ssh_forwarder_thread_barrier == NULL) {
			fprintf(stderr, "malloc() for barrier failed\n");

			return 1;
		}
		if (pthread_barrier_init(ssh_forwarder_thread_barrier, NULL, 2) < 0) {
			fprintf(stderr, "pthread_barrier_init() failed\n");

			free(ssh_forwarder_thread_barrier);
			return 1;
		}
		ssh_forwarder_thread_arg.ssh_private_key_path = private_key;
		ssh_forwarder_thread_arg.server_hostname = dst_hostname;
		ssh_forwarder_thread_arg.server_port = dst_port;
		ssh_forwarder_thread_arg.barrier = ssh_forwarder_thread_barrier;

		uint16_t portnum = strtol(port, NULL, 10);
		int sockfd = create_tcp_listening_socket(portnum);
		printf("create_tcp_listening_socket() returned %d\n", sockfd);
		if (sockfd < 0) {
			printf("create_tcp_listening_socket() failed\n");

			free(ssh_forwarder_thread_barrier);
			return 1;
		}

		while (1) {
			int newfd = accept(sockfd, NULL, NULL);
			printf("accept() returned %d\n", newfd);
			if (newfd < 0) {
				printf("accept() failed\n");
				continue;
			}

			ssh_forwarder_thread_arg.real_client_fd = newfd;

			pthread_t ssh_forwarder_thread;
			if (pthread_create(&ssh_forwarder_thread, NULL, ssh_forwarder,
					&ssh_forwarder_thread_arg) != 0) {
				fprintf(stderr, "pthread_create() failed\n");

				close(newfd);
				continue;
			}

			/*must be called to avoid memory leaks*/
			pthread_detach(ssh_forwarder_thread);
			/*allow pthread_detach() to be called before new thread terminates and
			 wait until the thread finishes copying arguments onto its own stack*/
			pthread_barrier_wait(ssh_forwarder_thread_barrier);
			printf("thread created for %d\n", newfd);
		}
	} else if (mode == 2) {
		struct ssh_forwarder_thread_arg ssh_forwarder_thread_arg = { 0 };
		pthread_barrier_t* ssh_forwarder_thread_barrier = malloc(
				sizeof(pthread_barrier_t));
		if (ssh_forwarder_thread_barrier == NULL) {
			fprintf(stderr, "malloc() for barrier failed\n");

			return 1;
		}
		if (pthread_barrier_init(ssh_forwarder_thread_barrier, NULL, 2) < 0) {
			fprintf(stderr, "pthread_barrier_init() failed\n");

			free(ssh_forwarder_thread_barrier);
			return 1;
		}
		ssh_forwarder_thread_arg.ssh_private_key_path = private_key;
		ssh_forwarder_thread_arg.server_hostname = dst_hostname;
		ssh_forwarder_thread_arg.server_port = dst_port;
		ssh_forwarder_thread_arg.barrier = ssh_forwarder_thread_barrier;

		uint16_t portnum = strtol(port, NULL, 10);
		int sockfd = create_tcp_listening_socket(portnum);
		printf("create_tcp_listening_socket() returned %d\n", sockfd);
		if (sockfd < 0) {
			printf("create_tcp_listening_socket() failed\n");

			free(ssh_forwarder_thread_barrier);
			return 1;
		}

		while (1) {
			int newfd = accept(sockfd, NULL, NULL);
			printf("accept() returned %d\n", newfd);
			if (newfd < 0) {
				printf("accept() failed\n");
				continue;
			}

			ssh_forwarder_thread_arg.real_client_fd = newfd;

			pthread_t ssh_forwarder_thread;
			if (pthread_create(&ssh_forwarder_thread, NULL, ssh_decoder_c,
					&ssh_forwarder_thread_arg) != 0) {
				fprintf(stderr, "pthread_create() failed\n");

				close(newfd);
				continue;
			}

			/*must be called to avoid memory leaks*/
			pthread_detach(ssh_forwarder_thread);
			/*allow pthread_detach() to be called before new thread terminates and
			 wait until the thread finishes copying arguments onto its own stack*/
			pthread_barrier_wait(ssh_forwarder_thread_barrier);
			printf("thread created for %d\n", newfd);
		}
	} else if (mode == 3) {
		struct ssh_forwarder_thread_arg ssh_forwarder_thread_arg = { 0 };
		pthread_barrier_t* ssh_forwarder_thread_barrier = malloc(
				sizeof(pthread_barrier_t));
		if (ssh_forwarder_thread_barrier == NULL) {
			fprintf(stderr, "malloc() for barrier failed\n");

			return 1;
		}
		if (pthread_barrier_init(ssh_forwarder_thread_barrier, NULL, 2) < 0) {
			fprintf(stderr, "pthread_barrier_init() failed\n");

			free(ssh_forwarder_thread_barrier);
			return 1;
		}
		ssh_forwarder_thread_arg.ssh_private_key_path = private_key;
		ssh_forwarder_thread_arg.server_hostname = dst_hostname;
		ssh_forwarder_thread_arg.server_port = dst_port;
		ssh_forwarder_thread_arg.barrier = ssh_forwarder_thread_barrier;

		uint16_t portnum = strtol(port, NULL, 10);
		int sockfd = create_tcp_listening_socket(portnum);
		printf("create_tcp_listening_socket() returned %d\n", sockfd);
		if (sockfd < 0) {
			printf("create_tcp_listening_socket() failed\n");

			free(ssh_forwarder_thread_barrier);
			return 1;
		}

		while (1) {
			int newfd = accept(sockfd, NULL, NULL);
			printf("accept() returned %d\n", newfd);
			if (newfd < 0) {
				printf("accept() failed\n");
				continue;
			}

			ssh_forwarder_thread_arg.real_client_fd = newfd;

			pthread_t ssh_forwarder_thread;
			if (pthread_create(&ssh_forwarder_thread, NULL, ssh_decoder_s,
					&ssh_forwarder_thread_arg) != 0) {
				fprintf(stderr, "pthread_create() failed\n");

				close(newfd);
				continue;
			}

			/*must be called to avoid memory leaks*/
			pthread_detach(ssh_forwarder_thread);
			/*allow pthread_detach() to be called before new thread terminates and
			 wait until the thread finishes copying arguments onto its own stack*/
			pthread_barrier_wait(ssh_forwarder_thread_barrier);
			printf("thread created for %d\n", newfd);
		}
	}

	return 0;
}

static int create_tcp_listening_socket(uint16_t port) {
	int sockfd = socket(PF_INET6, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("create_tcp_listening_socket(): socket() error");
		return -1;
	}

	//work with both IPv4 and IPv6
	int zero = 0;
	int soret = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &zero,
			sizeof(zero));
	if (soret < 0) {
		perror("create_tcp_listening_socket(): setsockopt() error");
		fprintf(stderr,
				"create_tcp_listening_socket(): Server might not work with IPv4 clients\n");
	}

	//reuse port
	int one = 1;
	soret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (soret < 0) {
		perror("create_tcp_listening_socket(): setsockopt() error");
	}

	//bind
	struct sockaddr_in6 sockaddr = { 0 };
	sockaddr.sin6_addr = in6addr_any;
	sockaddr.sin6_family = AF_INET6;
	sockaddr.sin6_port = htons(port);
	int ret = bind(sockfd, (struct sockaddr*) &sockaddr, sizeof(sockaddr));
	if (ret < 0) {
		perror("create_tcp_listening_socket(): bind() error");
		close(sockfd);
		return -1;
	}

	//listen
	ret = listen(sockfd, 20);
	if (ret < 0) {
		perror("create_tcp_listening_socket(): listen() error");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

static int create_tcp_client_socket(char* hostname, char* port) {
	struct addrinfo hints = { 0 };
	struct addrinfo* res = NULL;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int ret = getaddrinfo(hostname, port, &hints, &res);
	if (ret != 0) {
		fprintf(stderr, "getaddrinfo() error: %s\n", gai_strerror(ret));
		return -1;
	}

	int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd < 0) {
		fprintf(stderr, "socket() error\n");

		freeaddrinfo(res);
		return -1;
	}

	if (connect(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
		fprintf(stderr, "connect() error\n");

		close(sockfd);
		freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);

	return sockfd;
}

ssize_t ssh_read(struct ssh* ssh, u_char* type, const u_char** datap,
		size_t* len) {
	int ret = ssh_packet_next(ssh, type);
	printf("ssh_read: ssh_packet_next returned %d, type: %u\n", ret, *type);
	if (ret < 0) {
		printf("ssh_read: ssh_packet_next error\n");
		return -1;
	} else {
		if (*type != 0) {
			//packet available
			*datap = ssh_packet_payload(ssh, len);
			return *len;
		} else {
			//packet unavailable
			*datap = NULL;
			return 0;
		}
	}
}

ssize_t ssh_write(struct ssh* ssh, u_char type, const u_char* data, size_t len) {
	int ret = ssh_packet_put(ssh, type, data, len);
	printf("ssh_write: ssh_packet_put returned %d\n", ret);
	if (ret < 0) {
		printf("ssh_write: ssh_packet_put error\n");
		return -1;
	}

	return len;
}

ssize_t ssh_fill(struct ssh* ssh, int in_fd) {
	char buffer[1024 * 16];

	//read from in_fd and fill the SSH input byte stream
	ssize_t sret = read(in_fd, buffer, sizeof(buffer));
	int errn = errno;
	putchar('\n');
	putchar('\n');
	printf("ssh_fill: read() returned %zd\n", sret);
	putchar('\n');
	putchar('\n');
	if (sret < 0) {
		printf("ssh_fill: read() error\n");
		if (errn > 0) {
			return -errn;
		} else {
			return -1;
		}
	} else if (sret == 0) {
		//EOF
		printf("ssh_fill: read() EOF\n");
		return -1;
	} else {
		int ret = ssh_input_append(ssh, buffer, sret);
		printf("ssh_fill: ssh_input_append(%zd) returned %d\n", sret, ret);
		if (ret < 0) {
			printf("ssh_fill: ssh_input_append() error\n");
			return -1;
		}
	}

	return sret;
}

ssize_t ssh_flush(struct ssh* ssh, int out_fd) {
	//send SSH output byte stream
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
			printf("ssh_flush: write() error, errno: %d\n", errn);
			if (errn > 0) {
				return -errn;
			} else {
				return -1;
			}
		} else {
			int ret = ssh_output_consume(ssh, wret);
			//printf("ssh_flush: ssh_output_consume returned %d\n", ret);
			if (ret < 0) {
				//printf("ssh_flush: ssh_output_consume error\n");
				return -1;
			}
		}
		bytes_sent += wret;
	}

	return bytes_sent;
}

ssize_t read_message_from_fd(int fd, u_char* type, u_char* buffer,
		size_t buffer_len) {
	uint32_t message_length;
	uint8_t message_type;

	ssize_t ret = fd_read_full(fd, (u_char*) &message_length,
			sizeof(message_length));
	if (ret < 0) {
		return -1;
	}
	message_length = ntohl(message_length);
	if (message_length > buffer_len) {
		return -1;
	}

	ret = fd_read_full(fd, (u_char*) &message_type, sizeof(message_type));
	if (ret < 0) {
		return -1;
	}

	ret = fd_read_full(fd, buffer, message_length);
	if (ret < 0) {
		return -1;
	}

	*type = message_type;
	return message_length;
}

ssize_t write_message_to_fd(int fd, u_char type, const u_char* data, size_t len) {
	uint32_t len_n = htonl((uint32_t) len);
	uint8_t type_n = (uint8_t) type;

	ssize_t written = 0;

	ssize_t ret = fd_write_full(fd, (u_char*) &len_n, sizeof(len_n));
	printf("fd_write_full(%d) returned %zd\n", fd, ret);
	if (ret < 0) {
		printf("fd_write_full() failed\n");
		return -1;
	}
	written += ret;

	ret = fd_write_full(fd, &type_n, sizeof(type_n));
	printf("fd_write_full(%d) returned %zd\n", fd, ret);
	if (ret < 0) {
		printf("fd_write_full() failed\n");
		return -1;
	}
	written += ret;

	ret = fd_write_full(fd, data, len);
	printf("fd_write_full(%d) returned %zd\n", fd, ret);
	if (ret < 0) {
		printf("fd_write_full() failed\n");
		return -1;
	}
	written += ret;

	return written;
}

ssize_t fd_read_full(int in_fd, u_char* buffer, size_t len) {
	size_t bytes_read = 0;
	while (bytes_read < len) {
		ssize_t ret = read(in_fd, buffer + bytes_read, len - bytes_read);
		int errn = errno;
		//printf("ssh_flush: write returned %zd\n", wret);
		if (ret < 0) {
			printf("fd_read_full: read() error, errno: %d\n", errn);
			if (errn > 0) {
				return -errn;
			} else {
				return -1;
			}
		} else if (ret == 0) {
			printf("fd_read_full: read() EOF\n");
			return -1;
		}
		bytes_read += ret;
	}

	return bytes_read;
}

ssize_t fd_write_full(int out_fd, const u_char* buffer, size_t len) {
	size_t bytes_sent = 0;
	while (bytes_sent < len) {
		ssize_t wret = write(out_fd, buffer + bytes_sent, len - bytes_sent);
		int errn = errno;
		//printf("ssh_flush: write returned %zd\n", wret);
		if (wret < 0) {
			printf("fd_write_full: write() error, errno: %d\n", errn);
			if (errn > 0) {
				return -errn;
			} else {
				return -1;
			}
		}
		bytes_sent += wret;
	}

	return bytes_sent;
}

void print_ssh_message_type(unsigned char type) {
	char* msg_type = NULL;

	switch (type) {
	case 0:
		msg_type = "SSH_MSG_NONE";
		break;
	case 1:
		msg_type = "SSH_MSG_DISCONNECT";
		break;
	case 2:
		msg_type = "SSH_MSG_IGNORE | SSH_SMSG_PUBLIC_KEY";
		break;
	case 3:
		msg_type = "SSH_MSG_UNIMPLEMENTED | SSH_CMSG_SESSION_KEY";
		break;
	case 4:
		msg_type = "SSH_MSG_DEBUG | SSH_CMSG_USER";
		break;
	case 5:
		msg_type = "SSH_MSG_SERVICE_REQUEST | SSH_CMSG_AUTH_RHOSTS";
		break;
	case 6:
		msg_type = "SSH_MSG_SERVICE_ACCEPT | SSH_CMSG_AUTH_RSA";
		break;
	case 7:
		msg_type = "SSH_SMSG_AUTH_RSA_CHALLENGE";
		break;
	case 8:
		msg_type = "SSH_CMSG_AUTH_RSA_RESPONSE";
		break;
	case 9:
		msg_type = "SSH_CMSG_AUTH_PASSWORD";
		break;
	case 10:
		msg_type = "SSH_CMSG_REQUEST_PTY";
		break;
	case 11:
		msg_type = "SSH_CMSG_WINDOW_SIZE";
		break;
	case 12:
		msg_type = "SSH_CMSG_EXEC_SHELL";
		break;
	case 13:
		msg_type = "SSH_CMSG_EXEC_CMD";
		break;
	case 14:
		msg_type = "SSH_SMSG_SUCCESS";
		break;
	case 15:
		msg_type = "SSH_SMSG_FAILURE";
		break;
	case 16:
		msg_type = "SSH_CMSG_STDIN_DATA";
		break;
	case 17:
		msg_type = "SSH_SMSG_STDOUT_DATA";
		break;
	case 18:
		msg_type = "SSH_SMSG_STDERR_DATA";
		break;
	case 19:
		msg_type = "SSH_CMSG_EOF";
		break;
	case 20:
		msg_type = "SSH_MSG_KEXINIT | SSH_SMSG_EXITSTATUS";
		break;
	case 21:
		msg_type = "SSH_MSG_NEWKEYS | SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
		break;
	case 22:
		msg_type = "SSH_MSG_CHANNEL_OPEN_FAILURE";
		break;
	case 23:
		msg_type = "SSH_MSG_CHANNEL_DATA";
		break;
	case 24:
		msg_type = "SSH_MSG_CHANNEL_CLOSE";
		break;
	case 25:
		msg_type = "SSH_MSG_CHANNEL_CLOSE_CONFIRMATION";
		break;
	case 26:
		msg_type = "SSH_CMSG_X11_REQUEST_FORWARDING";
		break;
	case 27:
		msg_type = "SSH_SMSG_X11_OPEN";
		break;
	case 28:
		msg_type = "SSH_CMSG_PORT_FORWARD_REQUEST";
		break;
	case 29:
		msg_type = "SSH_MSG_PORT_OPEN";
		break;
	case 30:
		msg_type = "SSH_CMSG_AGENT_REQUEST_FORWARDING";
		break;
	case 31:
		msg_type = "SSH_SMSG_AGENT_OPEN";
		break;
	case 32:
		msg_type = "SSH_MSG_IGNORE";
		break;
	case 33:
		msg_type = "SSH_CMSG_EXIT_CONFIRMATION";
		break;
	case 34:
		msg_type = "SSH_CMSG_X11_REQUEST_FORWARDING";
		break;
	case 35:
		msg_type = "SSH_CMSG_AUTH_RHOSTS_RSA";
		break;
	case 36:
		msg_type = "SSH_MSG_DEBUG";
		break;
	case 37:
		msg_type = "SSH_CMSG_REQUEST_COMPRESSION";
		break;
	case 38:
		msg_type = "SSH_CMSG_MAX_PACKET_SIZE";
		break;
	case 39:
		msg_type = "SSH_CMSG_AUTH_TIS";
		break;
	case 40:
		msg_type = "SSH_SMSG_AUTH_TIS_CHALLENGE";
		break;
	case 41:
		msg_type = "SSH_CMSG_AUTH_TIS_RESPONSE";
		break;
	case 42:
		msg_type = "SSH_CMSG_AUTH_KERBEROS";
		break;
	case 43:
		msg_type = "SSH_SMSG_AUTH_KERBEROS_RESPONSE";
		break;
	case 44:
		msg_type = "SSH_CMSG_HAVE_KERBEROS_TGT";
		break;
	case 50:
		msg_type = "SSH_MSG_USERAUTH_REQUEST";
		break;
	case 51:
		msg_type = "SSH_MSG_USERAUTH_FAILURE";
		break;
	case 52:
		msg_type = "SSH_MSG_USERAUTH_SUCCESS";
		break;
	case 53:
		msg_type = "SSH_MSG_USERAUTH_BANNER";
		break;
	case 65:
		msg_type = "SSH_CMSG_HAVE_AFS_TOKEN";
		break;
	case 80:
		msg_type = "SSH_MSG_GLOBAL_REQUEST";
		break;
	case 81:
		msg_type = "SSH_MSG_REQUEST_SUCCESS";
		break;
	case 82:
		msg_type = "SSH_MSG_REQUEST_FAILURE";
		break;
	case 90:
		msg_type = "SSH_MSG_CHANNEL_OPEN";
		break;
	case 91:
		msg_type = "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
		break;
	case 92:
		msg_type = "SSH_MSG_CHANNEL_OPEN_FAILURE";
		break;
	case 93:
		msg_type = "SSH_MSG_CHANNEL_WINDOW_ADJUST";
		break;
	case 94:
		msg_type = "SSH_MSG_CHANNEL_DATA";
		break;
	case 95:
		msg_type = "SSH_MSG_CHANNEL_EXTENDED_DATA";
		break;
	case 96:
		msg_type = "SSH_MSG_CHANNEL_EOF";
		break;
	case 97:
		msg_type = "SSH_MSG_CHANNEL_CLOSE";
		break;
	case 98:
		msg_type = "SSH_MSG_CHANNEL_REQUEST";
		break;
	case 99:
		msg_type = "SSH_MSG_CHANNEL_SUCCESS";
		break;
	case 100:
		msg_type = "SSH_MSG_CHANNEL_FAILURE";
		break;
	default:
		msg_type = "SSH message type unknown";
		break;
	}

	printf("message type is %u: %s\n", type, msg_type);
}
