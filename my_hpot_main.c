/*
 * my_hpot_main.c
 *
 *  Created on: 18 Jan 2018
 *      Author: lqy
 */

#include "my_hpot_forwarder_thread.h"
#include "my_hpot_cleanup_thread.h"

static int create_tcp_listening_socket(uint16_t port);

int main(int argc, char* argv[]) {
	char* argv0 = NULL;
	if (argc > 0) {
		argv0 = argv[0];
	} else {
		argv0 = " ";
	}

	if (argc < 2) {
		printf("Usage: %s <configuration file>\n", argv0);
		return 1;
	}

	struct my_hpot_config* mhc = my_hpot_config_new(argv[2]);
	if (mhc == NULL) {
		fprintf(stderr, "my_hpot_config_new() failed\n");
		return 1;
	}

	struct my_vm_pool* vm_pool = my_vm_pool_new(mhc->vm_pool_size,
			mhc->vm_base_image_name, mhc->vm_base_snapshot_name,
			mhc->vm_name_prefix, mhc->vm_idle_timeout);
	if (vm_pool == NULL) {
		fprintf(stderr, "my_vm_pool_new() failed\n");

		my_vm_pool_free(vm_pool, 0);
		my_hpot_config_free(mhc);
		return 1;
	}
	printf("my_vm_pool_new() returned %p\n", vm_pool);

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
	ssh_forwarder_thread_arg.hpot_config = mhc;
	ssh_forwarder_thread_arg.vm_pool = vm_pool;
	ssh_forwarder_thread_arg.barrier = ssh_forwarder_thread_barrier;

	int sockfd = create_tcp_listening_socket(mhc->listening_port);
	if (sockfd < 0) {
		fprintf(stderr, "create_tcp_listening_socket() failed\n");

		free(ssh_forwarder_thread_barrier);
		return 1;
	} else {
		printf("create_tcp_listening_socket() returned %d\n", sockfd);
	}

	{
		struct ssh_cleanup_thread_arg ssh_cleanup_thread_arg = { 0 };
		ssh_cleanup_thread_arg.vm_pool = vm_pool;
		ssh_cleanup_thread_arg.hpot_config = mhc;
		ssh_cleanup_thread_arg.barrier = ssh_forwarder_thread_barrier;

		pthread_t ssh_cleanup_thread;
		if (pthread_create(&ssh_cleanup_thread, NULL, hpot_cleanup,
				&ssh_cleanup_thread_arg) != 0) {
			fprintf(stderr, "pthread_create() failed\n");

			return 1;
		}

		/* must be called to avoid memory leaks */
		pthread_detach(ssh_cleanup_thread);
		/* allow pthread_detach() to be called before new thread terminates and
		 wait until the thread finishes copying arguments onto its own stack */
		pthread_barrier_wait(ssh_forwarder_thread_barrier);
		printf("clenaup thread created\n");
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
