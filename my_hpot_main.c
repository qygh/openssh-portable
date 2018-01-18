/*
 * my_hpot_main.c
 *
 *  Created on: 18 Jan 2018
 *      Author: lqy
 */

#include "my_hpot_forwarder_thread.h"

static int create_tcp_listening_socket(uint16_t port);

int main(int argc, char* argv[]) {
	int mode = -1;
	char* private_key = NULL;
	char* port = NULL;
	uint32_t pool_size = 0;
	char* base_image_name = NULL;
	char* base_snapshot_name = NULL;
	char* vm_name_prefix = NULL;
	char* vm_nic_name = NULL;
	time_t idle_timeout = 0;

	char* argv0 = NULL;
	if (argc > 0) {
		argv0 = argv[0];
	} else {
		argv0 = " ";
	}

	if (argc < 10) {
		printf(
				"Usage: %s <mode 0/1> <private key> <listening port> <pool size> <base image name> <base snapshot name> <vm name prefix> <vm nic name> <idle timeout>\n",
				argv0);
		return 1;
	}

	if (strcmp(argv[1], "0") == 0) {
		mode = 0;
	} else if (strcmp(argv[1], "1") == 0) {
		mode = 1;
	} else {
		printf("mode argument is invalid\n");
		return 1;
	}
	private_key = argv[2];
	port = argv[3];
	pool_size = strtol(argv[4], NULL, 10);
	base_image_name = argv[5];
	base_snapshot_name = argv[6];
	vm_name_prefix = argv[7];
	vm_nic_name = argv[8];
	idle_timeout = strtol(argv[9], NULL, 10);

	struct my_vm_pool* vm_pool = my_vm_pool_new(pool_size, base_image_name,
			base_snapshot_name, vm_name_prefix, vm_nic_name, idle_timeout);
	if (vm_pool == NULL) {
		fprintf(stderr, "my_vm_pool_new() failed\n");

		my_vm_pool_free(vm_pool, 0);
		return 1;
	}
	printf("my_vm_pool_new() returned %p\n", vm_pool);

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
		ssh_forwarder_thread_arg.vm_pool = vm_pool;
		ssh_forwarder_thread_arg.server_port = "22";
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
		ssh_forwarder_thread_arg.vm_pool = vm_pool;
		ssh_forwarder_thread_arg.server_port = "22";
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

			/* must be called to avoid memory leaks */
			pthread_detach(ssh_forwarder_thread);
			/* allow pthread_detach() to be called before new thread terminates and
			 wait until the thread finishes copying arguments onto its own stack */
			pthread_barrier_wait(ssh_forwarder_thread_barrier);
			printf("thread created for %d\n", newfd);
		}
	}

	my_vm_pool_free(vm_pool, 0);

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
