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

#include "ssh_api.h"

static int create_tcp_listening_socket(uint16_t port);

static int create_tcp_client_socket(char* hostname, char* port);

ssize_t ssh_read(struct ssh* ssh, int in_fd, int out_fd, u_char* type,
		const u_char** datap, size_t* len);

ssize_t ssh_write(struct ssh* ssh, int out_fd, u_char type, const u_char* data,
		size_t len);

ssize_t ssh_flush(struct ssh* ssh, int out_fd);

struct ssh_sender_thread_arg {
	struct ssh* ssh;
	int fd;
};

struct ssh_forwarder_thread_arg {
	char* ssh_private_key_path;
	int real_client_fd;
	char* server_hostname;
	char* server_port;
	pthread_barrier_t* barrier;
};

void* ssh_sender_thread(void* arg) {
	struct ssh_sender_thread_arg* args = arg;
	size_t ctr = 0;
	char data[16] = { 0 };
	sleep(3);

	while (1) {
		snprintf(data, sizeof(data), "%zu", ctr++);
		ssize_t ret = ssh_write(args->ssh, args->fd, 124, data, strlen(data));
		printf("ssh_write() returned %zd\n", ret);
		if (ret < 0) {
			printf("ssh_write() failed\n");
			exit(1);
		}
		sleep(2);
	}

	return NULL;
}

void* ssh_forwarder(void* arg) {
	struct ssh_forwarder_thread_arg* oarg = arg;
	struct ssh_forwarder_thread_arg args_cpy = { 0 };

	//copy arguments onto thread's own stack
	memcpy(&args_cpy, oarg, sizeof(args_cpy));

	//finish copying arguments onto own stack and wait until main thread has called pthread_detach()
	//pthread_barrier_wait(args_cpy.barrier);

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

		close(args->real_client_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*ignore SIGPIPE that can be possibly caused by writes to disconnected clients*/
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "signal() error for %d\n", args->real_client_fd);

		close(args->real_client_fd);
		//pthread_exit(NULL);
		return NULL;
	}
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "signal() error for %d\n", real_server_fd);

		close(args->real_client_fd);
		close(real_server_fd);
		//pthread_exit(NULL);
		return NULL;
	}

	/*disable TCP delay*/
	{
		int one = 1;
		int ret = setsockopt(args->real_client_fd, IPPROTO_TCP, TCP_NODELAY,
				&one, sizeof(one));
		printf("setsockopt returned %d\n", ret);

		//ret = setsockopt(real_server_fd, IPPROTO_TCP, TCP_NODELAY, &one,
		//		sizeof(one));
		//printf("setsockopt returned %d\n", ret);
	}

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

		close(args->real_client_fd);
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
		close(args->real_client_fd);
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
		sshkey_free(sshkey);
		ssh_free(ssh_s);
		close(args->real_client_fd);
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
		close(args->real_client_fd);
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
		ssize_t ret = 0;
		ssh_read(ssh_s, ufds[0].fd, ufds[0].fd, &type, &data, &len);
	}

	while (1) {
		ret = poll(ufds, 2, 1000);

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
			 }

			 //read from in_fd and fill the SSH input byte stream
			 char buffer[8192];
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
				printf("real_client_fd ready\n");

				u_char type = 0;
				const u_char* data = NULL;
				size_t len = 0;
				ssize_t ret = 0;

				ret = ssh_read(ssh_s, ufds[0].fd, ufds[0].fd, &type, &data,
						&len);
				printf("ssh_read(%d, %d) returned %zd\n", ufds[0].fd,
						ufds[0].fd, ret);
				if (ret < 0) {
					if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
						goto ufds1;
					} else {
						printf("ssh_read() failed\n");
						break;
					}
				}

				printf("type: %u, data: %p, len: %zu\n", type, data, len);
				if (type == 90) {
					printf("\n\nSSH_MSG_CHANNEL_OPEN\n\n");
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

				ret = ssh_write(ssh_c, ufds[1].fd, type, data, len);
				printf("ssh_write(%d) returned %zd\n", ufds[1].fd, ret);
				if (ret < 0) {
					printf("ssh_write() failed\n");
					break;
				}
			}

			ufds1: ;
			if (ufds[1].revents & POLLIN) {
				printf("real_server_fd ready\n");

				u_char type = 0;
				const u_char* data = NULL;
				size_t len = 0;
				ssize_t ret = 0;

				ret = ssh_read(ssh_c, ufds[1].fd, ufds[1].fd, &type, &data,
						&len);
				printf("ssh_read(%d, %d) returned %zd\n", ufds[1].fd,
						ufds[1].fd, ret);
				if (ret < 0) {
					if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
						continue;
					} else {
						printf("ssh_read() failed\n");
						break;
					}
				}

				printf("type: %u, data: %p, len: %zu\n", type, data, len);
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

				ret = ssh_write(ssh_s, ufds[0].fd, type, data, len);
				printf("ssh_write(%d) returned %zd\n", ufds[0].fd, ret);
				if (ret < 0) {
					printf("ssh_write() failed\n");
					break;
				}
			}
		}
	}

	ssh_free(ssh_c);
	sshkey_free(sshkey);
	ssh_free(ssh_s);
	close(args->real_client_fd);
	close(real_server_fd);
	//pthread_exit(NULL);
	printf("thread for %d terminating\n", args->real_client_fd);
	return NULL;
}

int main(int argc, char* argv[]) {
	int mode = -1;
	char* private_key = NULL;
	char* hostname = NULL;
	char* port = NULL;

	char* dst_hostname = NULL;
	char* dst_port = NULL;

	char* argv0 = NULL;
	if (argc > 0) {
		argv0 = argv[0];
	} else {
		argv0 = " ";
	}

	if (argc < 4) {
		printf("Usage: %s s <private key> <port>\n", argv0);
		printf("       %s c <hostname> <port>\n", argv0);
		printf("       %s f <private key> <port> <dst hostname> <dst port>\n",
				argv0);
		return 1;
	} else {
		if (strcmp(argv[1], "s") == 0) {
			mode = 1;
			private_key = argv[2];
			port = argv[3];
		} else if (strcmp(argv[1], "c") == 0) {
			mode = 0;
			hostname = argv[2];
			port = argv[3];
		} else if (strcmp(argv[1], "f") == 0) {
			if (argc < 6) {
				printf(
						"Usage: %s f <private key> <port> <dst hostname> <dst port>\n",
						argv0);
				return 1;
			}
			mode = 2;
			private_key = argv[2];
			port = argv[3];
			dst_hostname = argv[4];
			dst_port = argv[5];
		} else {
			printf("first argument must be either 's' or 'c'\n");
			return 1;
		}
	}

	if (mode == 2) {
		struct ssh_forwarder_thread_arg ssh_forwarder_thread_arg = { 0 };
		pthread_t ssh_forwarder_thread;
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
		/*initialise SSH object*/
		struct ssh* ssh = NULL;
		int ret = ssh_init(&ssh, 1, NULL);
		printf("ssh_init() returned %d, ssh: %p\n", ret, ssh);
		if (ret != 0) {
			printf("ssh_init() failed\n");
			ssh_free(ssh);
			return 1;
		}

		/*initialise SSH private key*/
		struct sshkey* sshkey = key_load_private(private_key, "",
		NULL);
		printf("key_load_private() returned %p\n", sshkey);
		if (sshkey == NULL) {
			printf("key_load_private() failed\n");
			ssh_free(ssh);
			return 1;
		}

		/*add SSH private key to SSH object*/
		ret = ssh_add_hostkey(ssh, sshkey);
		printf("ssh_add_hostkey() returned %d\n", ret);
		if (ret != 0) {
			printf("ssh_add_hostkey() failed\n");
			sshkey_free(sshkey);
			ssh_free(ssh);
			return 1;
		}

		uint16_t portnum = strtol(port, NULL, 10);
		int sockfd = create_tcp_listening_socket(portnum);
		printf("create_tcp_listening_socket() returned %d\n", sockfd);
		if (sockfd < 0) {
			printf("create_tcp_listening_socket() failed\n");
			sshkey_free(sshkey);
			ssh_free(ssh);
			return 1;
		}

		while (1) {
			int newfd = accept(sockfd, NULL, NULL);
			printf("accept() returned %d\n", newfd);
			if (newfd < 0) {
				printf("accept() failed\n");
				continue;
			}

			while (1) {
				u_char type = 0;
				const u_char* data = NULL;
				size_t len = 0;
				ssize_t ret = 0;

				ret = ssh_read(ssh, newfd, newfd, &type, &data, &len);
				printf("ssh_read() returned %zd\n", ret);
				if (ret == 0) {
					printf("ssh_read() EOF\n");
					exit(1);
				} else if (ret < 0) {
					printf("ssh_read() failed\n");
					exit(1);
				}

				printf("type: %u, data: %p, len: %zu\n", type, data, len);
				size_t i = 0;
				putchar('\n');
				for (i = 0; i < len; i++) {
					putchar(data[i]);
				}
				putchar('\n');

				putchar('\n');
				for (i = 0; i < len; i++) {
					printf("%02x ", data[i]);
				}
				putchar('\n');
				putchar('\n');

				ret = ssh_write(ssh, newfd, 123, "123", 3);
				printf("ssh_write() returned %zd\n", ret);
				if (ret < 0) {
					printf("ssh_write() failed\n");
					exit(1);
				}
			}
		}
	} else if (mode == 0) {
		/*initialise SSH object*/
		struct ssh* ssh = NULL;
		int ret = ssh_init(&ssh, 0, NULL);
		printf("ssh_init() returned %d, ssh: %p\n", ret, ssh);
		if (ret != 0) {
			printf("ssh_init() failed\n");
			ssh_free(ssh);
			return 1;
		}

		int verify_host_key(struct sshkey* sshkey, struct ssh* ssh) {
			return 0;
		}
		ret = ssh_set_verify_host_key_callback(ssh, verify_host_key);
		if (ret != 0) {
			printf("ssh_set_verify_host_key_callback() failed\n");
			ssh_free(ssh);
			return 1;
		}

		int sockfd = create_tcp_client_socket(hostname, port);
		printf("create_tcp_client_socket() returned %d\n", sockfd);
		if (sockfd < 0) {
			printf("create_tcp_client_socket() failed\n");
			ssh_free(ssh);
			return 1;
		}

		struct ssh_sender_thread_arg ssta = { ssh, sockfd };
		pthread_t thread;
		ret = pthread_create(&thread, NULL, ssh_sender_thread, &ssta);
		printf("pthread_create() returned %d\n", ret);
		if (ret < 0) {
			printf("pthread_create() failed\n");
			exit(1);
		}

		while (1) {
			u_char type = 0;
			const u_char* data = NULL;
			size_t len = 0;
			ssize_t ret = 0;

			ret = ssh_read(ssh, sockfd, sockfd, &type, &data, &len);
			printf("ssh_read() returned %zd\n", ret);
			if (ret == 0) {
				printf("ssh_read() EOF\n");
				exit(1);
			} else if (ret < 0) {
				printf("ssh_read() failed\n");
				exit(1);
			}

			printf("type: %u, data: %p, len: %zu\n", type, data, len);
			size_t i = 0;
			putchar('\n');
			for (i = 0; i < len; i++) {
				putchar(data[i]);
			}
			putchar('\n');

			putchar('\n');
			for (i = 0; i < len; i++) {
				printf("%02x ", data[i]);
			}
			putchar('\n');
			putchar('\n');

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

ssize_t ssh_read(struct ssh* ssh, int in_fd, int out_fd, u_char* type,
		const u_char** datap, size_t* len) {
	char buffer[8192] = { 0 };

	int ret = ssh_packet_next(ssh, type);
	printf("ssh_read: ssh_packet_next returned %d, type: %u\n", ret, *type);
	if (ret < 0) {
		printf("ssh_read: ssh_packet_next error\n");
		return -1;
	} else {
		//packet available
		if (*type != 0) {
			*datap = ssh_packet_payload(ssh, len);
			return *len;
		}
	}

	while (1) {
		ssize_t sret;
		int errn;

		//read from in_fd and fill the SSH input byte stream
		/*sret = read(in_fd, buffer, sizeof(buffer));
		 errn = errno;
		 printf("ssh_read: read returned %zd\n", sret);
		 if (sret < 0) {
		 printf("ssh_read: read error\n");
		 if (errn > 0) {
		 return -errn;
		 } else {
		 return -1;
		 }
		 } else if (sret == 0) {
		 //EOF
		 //printf("ssh_read: read EOF\n");
		 return 0;
		 } else {
		 ret = ssh_input_append(ssh, buffer, (size_t) sret);
		 printf("ssh_read: ssh_input_append(%zu) returned %d\n", sret, ret);
		 if (ret < 0) {
		 printf("ssh_read: ssh_input_append error\n");
		 return -1;
		 }
		 }*/

		ret = ssh_packet_next(ssh, type);
		printf("ssh_read: ssh_packet_next returned %d, type: %u\n", ret, *type);
		if (ret < 0) {
			printf("ssh_read: ssh_packet_next error\n");
			return -1;
		}

		//packet available
		if (*type != 0) {
			break;
		}

		//not enough data in SSH input stream
		//send SSH output byte stream
		const u_char* b = NULL;
		size_t l = 0;
		b = ssh_output_ptr(ssh, &l);
		printf("ssh_read: ssh_output_ptr() returned %p, len: %zu\n", b, l);
		size_t bytes_sent = 0;
		while (bytes_sent < l) {
			ssize_t wret = write(out_fd, b + bytes_sent, l - bytes_sent);
			int errn = errno;
			printf("ssh_read: write returned %zd\n", wret);
			if (wret < 0) {
				printf("ssh_read: write error, errno: %d\n", errn);
				if (errn > 0) {
					return -errn;
				} else {
					return -1;
				}
			} else {
				ret = ssh_output_consume(ssh, wret);
				printf("ssh_read: ssh_output_consume returned %d\n", ret);
				if (ret < 0) {
					printf("ssh_read: ssh_output_consume error\n");
					return -1;
				}
			}
			bytes_sent += wret;
		}

		//read from in_fd and fill the SSH input byte stream
		sret = read(in_fd, buffer, sizeof(buffer));
		errn = errno;
		putchar('\n');
		putchar('\n');
		printf("ssh_read: read returned %zd\n", sret);
		putchar('\n');
		putchar('\n');
		if (sret < 0) {
			printf("ssh_read: read error\n");
			if (errn > 0) {
				return -errn;
			} else {
				return -1;
			}
		} else if (sret == 0) {
			//EOF
			printf("ssh_read: read EOF\n");
			return -1;
		} else {
			ret = ssh_input_append(ssh, buffer, sret);
			printf("ssh_read: ssh_input_append(%zd) returned %d\n", sret, ret);
			if (ret < 0) {
				printf("ssh_read: ssh_input_append error\n");
				return -1;
			}
		}
	}

	//return packet type and payload to caller
	*datap = ssh_packet_payload(ssh, len);
	return *len;
}

ssize_t ssh_write(struct ssh* ssh, int out_fd, u_char type, const u_char* data,
		size_t len) {
	int ret = ssh_packet_put(ssh, type, data, len);
	printf("ssh_write: ssh_packet_put returned %d\n", ret);
	if (ret < 0) {
		printf("ssh_write: ssh_packet_put error\n");
		return -1;
	}

	//send SSH output byte stream
	const u_char* b = NULL;
	size_t l = 0;
	b = ssh_output_ptr(ssh, &l);
	printf("ssh_write: ssh_output_ptr() returned %p, len: %zu\n", b, l);
	size_t bytes_sent = 0;
	while (bytes_sent < l) {
		ssize_t wret = write(out_fd, b + bytes_sent, l - bytes_sent);
		int errn = errno;
		printf("ssh_write: write returned %zd\n", wret);
		if (wret < 0) {
			printf("ssh_write: write error, errno: %d\n", errn);
			if (errn > 0) {
				return -errn;
			} else {
				return -1;
			}
		} else {
			ret = ssh_output_consume(ssh, wret);
			printf("ssh_write: ssh_output_consume returned %d\n", ret);
			if (ret < 0) {
				printf("ssh_write: ssh_output_consume error\n");
				return -1;
			}
		}
		bytes_sent += wret;
	}

	return len;
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
			printf("ssh_flush: write error, errno: %d\n", errn);
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
