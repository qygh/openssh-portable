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
#include <unistd.h>
#include <pthread.h>

#include "ssh_api.h"

static int create_tcp_listening_socket(uint16_t port);

static int create_tcp_client_socket(char* hostname, char* port);

ssize_t ssh_read(struct ssh* ssh, int in_fd, int out_fd, u_char* type,
		const u_char** datap, size_t* len);

ssize_t ssh_write(struct ssh* ssh, int out_fd, u_char type, const u_char* data,
		size_t len);

struct ssh_sender_thread_arg {
	struct ssh* ssh;
	int fd;
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

int main(int argc, char* argv[]) {
	int server = 0;
	char* private_key = NULL;
	char* hostname = NULL;
	char* port = NULL;

	if (argc < 4) {
		char* argv0 = " ";
		if (argc > 0) {
			argv0 = argv[0];
		}
		printf("Usage: %s s <private key> <port>\n", argv0);
		printf("       %s c <hostname> <port>\n", argv0);
		return 1;
	} else {
		if (strcmp(argv[1], "s") == 0) {
			server = 1;
			private_key = argv[2];
			port = argv[3];
		} else if (strcmp(argv[1], "c") == 0) {
			server = 0;
			hostname = argv[2];
			port = argv[3];
		} else {
			printf("first argument must be either 's' or 'c'\n");
			return 1;
		}
	}

	/*initialise SSH object*/
	struct ssh* ssh = NULL;
	int ret = ssh_init(&ssh, server, NULL);
	printf("ssh_init() returned %d, ssh: %p\n", ret, ssh);
	if (ret != 0) {
		printf("ssh_init() failed\n");
		ssh_free(ssh);
		return 1;
	}

	if (server) {
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
	} else {
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
	}

	while (1) {
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
			printf("ssh_read: write returned %zd\n", wret);
			if (wret < 0) {
				printf("ssh_read: write error\n");
				return -1;
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
		ssize_t sret = read(in_fd, buffer, sizeof(buffer));
		printf("ssh_read: read returned %zd\n", sret);
		if (sret < 0) {
			printf("ssh_read: read error\n");
			return -1;
		} else if (sret == 0) {
			//EOF
			//printf("ssh_read: read EOF\n");
			return 0;
		} else {
			ret = ssh_input_append(ssh, buffer, sret);
			printf("ssh_read: ssh_input_append returned %d\n", ret);
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
		printf("ssh_write: write returned %zd\n", wret);
		if (wret < 0) {
			printf("ssh_write: write error\n");
			return -1;
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
