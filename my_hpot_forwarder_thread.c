/*
 * my_hpot_handler_thread.c
 *
 *  Created on: 11 Jan 2018
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

#include "my_ssh_api.h"
#include "my_vm_pool.h"

struct ssh_forwarder_thread_arg {
	char* ssh_private_key_path;
	int real_client_fd;
	struct my_vm_pool* vm_pool;
	//char* server_hostname;
	char* server_port;
	pthread_barrier_t* barrier;
};

void print_ssh_message_type(unsigned char type);

void* ssh_forwarder(void* arg) {
	struct ssh_forwarder_thread_arg* oarg = arg;
	struct ssh_forwarder_thread_arg args_cpy = { 0 };

	/* copy arguments onto thread's own stack */
	memcpy(&args_cpy, oarg, sizeof(args_cpy));

	/* finished copying arguments onto the thread's own stack and wait until main thread has called pthread_detach() */
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

	/* TODO request a VM from the VM pool */

	/* TODO error handling when VM is unavailable, fail to get IP address of VM or fail to establish TCP connection to VM */

	/* TODO implement a fake SSH server that never authenticates in error cases above */

	/* TODO implement actual logging */

	real_server_fd = create_tcp_client_socket(args->server_hostname,
			args->server_port);
	if (real_server_fd < 0) {
		fprintf(stderr, "create_tcp_client_socket() failed\n");

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/* ignore SIGPIPE that can be possibly caused by writes to disconnected sockets */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "signal() error for %d\n", args->real_client_fd);

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/* disable TCP delay */
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

	/* set sockets to non-blocking */
	if (fcntl(args->real_client_fd, F_SETFL, O_NONBLOCK) < 0
			|| fcntl(real_server_fd, F_SETFL, O_NONBLOCK) < 0) {
		fprintf(stderr, "fcntl() failed\n");

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/* initialise SSH object */
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

	/* initialise SSH private key */
	sshkey = key_load_private(args->ssh_private_key_path, "", NULL);
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

	/* add SSH private key to SSH object */
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

	/* initialise SSH object */
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

	/* set SSH host key verification function */
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

	/* poll the two sockets */
	struct pollfd ufds[2];
	ufds[0].fd = args->real_client_fd;
	ufds[0].events = POLLIN;
	ufds[1].fd = real_server_fd;
	ufds[1].events = POLLIN;

	{
		/* required to get OpenSSH working */
		u_char type = 0;
		const u_char* data = NULL;
		size_t len = 0;
		ssh_read(ssh_s, &type, &data, &len);
		ssh_flush(ssh_s, ufds[0].fd);
		ssh_read(ssh_c, &type, &data, &len);
		ssh_flush(ssh_c, ufds[1].fd);
	}

	while (1) {
		ret = poll(ufds, 2, -1);

		if (ret < 0) {
			fprintf(stderr, "poll() failed\n");
		} else if (ret == 0) {
			/* poll() timeout */
		} else {
			printf("poll() returned %d\n", ret);

			/* client socket readable */
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

			/* server socket readable */
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

	/* TODO release the VM */

	/* TODO SSH still causes memory leak */
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
