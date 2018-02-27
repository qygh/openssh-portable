/*
 * my_hpot_handler_thread.c
 *
 *  Created on: 11 Jan 2018
 *      Author: lqy
 */

#include "my_hpot_forwarder_thread.h"

static int verify_host_key(struct sshkey* sshkey, struct ssh* ssh) {
	return 0;
}

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

	printf("thread for %d ready\n", args_cpy.real_client_fd);

	struct ssh_forwarder_thread_arg* args = &args_cpy;

	int ret = -1;

	int real_server_fd = -1;

	struct ssh* ssh_s = NULL;
	struct sshkey* sshkey_1 = NULL;

	struct sshkey* sshkey_2 = NULL;

	struct ssh* ssh_c = NULL;

	/* get client IP */
	struct sockaddr_in6 client_sa = { 0 };
	socklen_t client_sa_len = sizeof(client_sa);
	ret = getpeername(args->real_client_fd, (struct sockaddr*) &client_sa,
			&client_sa_len);
	if (ret < 0) {
		fprintf(stderr, "thread for %d: getpeername() failed\n",
				args->real_client_fd);

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		return NULL;
	} else {
		printf("getpeername() returned %d, client IP:\n", ret);
		uint8_t* addr = &(client_sa.sin6_addr);
		for (int i = 0; i < 16; i++) {
			printf("%u ", addr[i]);
		}
		putchar('\n');
		for (int i = 0; i < 16; i++) {
			printf("%02x ", addr[i]);
		}
		putchar('\n');
	}

	/* request a VM from the VM pool */
	/* TODO error handling when VM is unavailable, fail to get VM IP address or fail to establish TCP connection to VM */
	/* TODO implement a fake SSH server that never authenticates in error cases above */
	uint8_t client_ip[16] = { 0 };
	memcpy(client_ip, &(client_sa.sin6_addr), 16);
	uint32_t vm_id = 0;
	ret = my_vm_pool_request(args->vm_pool, client_ip, &vm_id);
	if (ret < 0) {
		fprintf(stderr, "thread for %d: my_vm_pool_request() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		return NULL;
	}

	uint8_t vm_ip[16] = { 0 };
	ret = my_vm_pool_get_vm_ip(args->vm_pool, vm_id,
			args->hpot_config->vm_nic_name, vm_ip);
	if (ret < 0) {
		fprintf(stderr, "thread for %d: my_vm_pool_get_vm_ip() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		my_vm_pool_release(args->vm_pool, vm_id);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		return NULL;
	} else {
		printf("my_vm_pool_get_vm_ip() returned %d, VM IP:\n", ret);
		for (int i = 0; i < 16; i++) {
			printf("%u ", vm_ip[i]);
		}
		putchar('\n');
		for (int i = 0; i < 16; i++) {
			printf("%02x ", vm_ip[i]);
		}
		putchar('\n');
	}

	/* create file logger */
	struct my_logger_file* logger_file = NULL;
	if (args->hpot_config->log_file_enabled) {
		logger_file = my_logger_file_new(args->hpot_config->log_file_prefix,
				vm_id, client_ip, vm_ip);
		if (logger_file == NULL) {
			fprintf(stderr, "thread for %d: my_logger_file_new() failed\n",
					args->real_client_fd);
			//TODO handle connection with fake SSH server

			my_vm_pool_release(args->vm_pool, vm_id);
			shutdown(args->real_client_fd, SHUT_RDWR);
			close(args->real_client_fd);
			return NULL;
		}
	}

	/* create SQL logger */
	struct my_logger_pqsql* logger_pqsql = NULL;
	if (args->hpot_config->log_pqsql_enabled) {
		logger_pqsql = my_logger_pqsql_new(
				args->hpot_config->log_pqsql_conninfo, vm_id, client_ip, vm_ip);
		if (logger_pqsql == NULL) {
			fprintf(stderr, "thread for %d: my_logger_pqsql_new() failed\n",
					args->real_client_fd);
			//TODO handle connection with fake SSH server

			my_logger_file_free(logger_file);
			my_vm_pool_release(args->vm_pool, vm_id);
			shutdown(args->real_client_fd, SHUT_RDWR);
			close(args->real_client_fd);
			return NULL;
		}
	}

	/* create socket to VM */
	struct sockaddr_in6 vm_sa = { 0 };
	vm_sa.sin6_family = AF_INET6;
	vm_sa.sin6_port = htons(args->hpot_config->vm_ssh_port);
	memcpy(&(vm_sa.sin6_addr), vm_ip, 16);
	real_server_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (real_server_fd < 0) {
		fprintf(stderr, "thread for %d: socket() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		my_logger_pqsql_free(logger_pqsql);
		my_logger_file_free(logger_file);
		my_vm_pool_release(args->vm_pool, vm_id);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		return NULL;
	} else {
		printf("socket() returned %d\n", real_server_fd);
	}

	/* SNAT source IP */
	if (args->hpot_config->iptables_snat_enabled) {
		char src_ip[INET6_ADDRSTRLEN] = { 0 };
		char dst_ip[INET6_ADDRSTRLEN] = { 0 };
		if (is_ip_ipv6(client_ip)) {
			const char* ret = inet_ntop(AF_INET6, client_ip, src_ip,
					sizeof(src_ip));
			const char* ret2 = inet_ntop(AF_INET6, vm_ip, dst_ip,
					sizeof(dst_ip));
			if (ret != NULL && ret2 != NULL) {
				char command[1024] = { 0 };
				snprintf(command, sizeof(command),
						"ip6tables -t nat -C POSTROUTING -d %s -j SNAT --to %s",
						dst_ip, src_ip);
				int ret3 = system(command);
				fprintf(stderr, "system(%s) returned %d\n", command, ret3);
				if (ret3 != 0) {
					/* rule does not exist */
					char command2[1024] = { 0 };
					snprintf(command2, sizeof(command2),
							"ip6tables -t nat -I POSTROUTING -d %s -j SNAT --to %s",
							dst_ip, src_ip);
					int ret4 = system(command2);
					if (ret4 != 0) {
						fprintf(stderr,
								"system(%s) returned %d, failed to add ip6tables rule\n",
								command2, ret4);
					}
				}
			}
		} else {
			const char* ret = inet_ntop(AF_INET, client_ip + 12, src_ip,
					sizeof(src_ip));
			const char* ret2 = inet_ntop(AF_INET, vm_ip + 12, dst_ip,
					sizeof(dst_ip));
			if (ret != NULL && ret2 != NULL) {
				char command[1024] = { 0 };
				snprintf(command, sizeof(command),
						"iptables -t nat -C POSTROUTING -d %s -j SNAT --to %s",
						dst_ip, src_ip);
				int ret3 = system(command);
				fprintf(stderr, "system(%s) returned %d\n", command, ret3);
				if (ret3 != 0) {
					/* rule does not exist */
					char command2[1024] = { 0 };
					snprintf(command2, sizeof(command2),
							"iptables -t nat -I POSTROUTING -d %s -j SNAT --to %s",
							dst_ip, src_ip);
					int ret4 = system(command2);
					if (ret4 != 0) {
						fprintf(stderr,
								"system(%s) returned %d, failed to add iptables rule\n",
								command2, ret4);
					}
				}
			}
		}
	}

	/* connect to VM */
	ret = connect(real_server_fd, (struct sockaddr*) &vm_sa, sizeof(vm_sa));
	if (ret < 0) {
		fprintf(stderr, "thread for %d: connect() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		my_logger_pqsql_free(logger_pqsql);
		my_logger_file_free(logger_file);
		my_vm_pool_release(args->vm_pool, vm_id);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		return NULL;
	} else {
		printf("connect() returned %d\n", ret);
	}

	/* ignore SIGPIPE that can be possibly caused by writes to disconnected sockets */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "thread for %d: signal() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		my_logger_pqsql_free(logger_pqsql);
		my_logger_file_free(logger_file);
		my_vm_pool_release(args->vm_pool, vm_id);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
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
		fprintf(stderr, "thread for %d: fcntl() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		my_logger_pqsql_free(logger_pqsql);
		my_logger_file_free(logger_file);
		my_vm_pool_release(args->vm_pool, vm_id);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		return NULL;
	}

	/* initialise SSH object */
	ret = ssh_init(&ssh_s, 1, NULL);
	printf("ssh_init() returned %d, ssh: %p\n", ret, ssh_s);
	if (ret != 0) {
		fprintf(stderr, "thread for %d: ssh_init() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		my_logger_pqsql_free(logger_pqsql);
		my_logger_file_free(logger_file);
		my_vm_pool_release(args->vm_pool, vm_id);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		return NULL;
	}

	printf("AAAA\n");

	/* initialise SSH private key */
	sshkey_1 = key_load_private(args->hpot_config->server_key1_path, "", NULL);
	if (sshkey_1 == NULL) {
		fprintf(stderr, "thread for %d: key_load_private() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		ssh_free(ssh_s);
		my_logger_pqsql_free(logger_pqsql);
		my_logger_file_free(logger_file);
		my_vm_pool_release(args->vm_pool, vm_id);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		return NULL;
	} else {
		printf("key_load_private() returned %p\n", sshkey_1);
	}

	printf("BBBB\n");

	/* add SSH private key to SSH object */
	ret = ssh_add_hostkey(ssh_s, sshkey_1);
	if (ret != 0) {
		fprintf(stderr, "thread for %d: ssh_add_hostkey() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		sshkey_free(sshkey_1);
		ssh_free(ssh_s);
		my_logger_pqsql_free(logger_pqsql);
		my_logger_file_free(logger_file);
		my_vm_pool_release(args->vm_pool, vm_id);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		return NULL;
	} else {
		printf("ssh_add_hostkey() returned %d\n", ret);
	}

	printf("CCCC\n");

	if (args->hpot_config->server_key2_enabled) {
		sshkey_2 = key_load_private(args->hpot_config->server_key2_path, "",
		NULL);
		if (sshkey_2 == NULL) {
			fprintf(stderr, "thread for %d: key_load_private() failed\n",
					args->real_client_fd);
			//TODO handle connection with fake SSH server

			sshkey_free(sshkey_1);
			ssh_free(ssh_s);
			my_logger_pqsql_free(logger_pqsql);
			my_logger_file_free(logger_file);
			my_vm_pool_release(args->vm_pool, vm_id);
			shutdown(args->real_client_fd, SHUT_RDWR);
			close(args->real_client_fd);
			shutdown(real_server_fd, SHUT_RDWR);
			close(real_server_fd);
			return NULL;
		} else {
			printf("key_load_private() returned %p\n", sshkey_2);
		}

		/* add SSH private key to SSH object */
		ret = ssh_add_hostkey(ssh_s, sshkey_2);
		if (ret != 0) {
			fprintf(stderr, "thread for %d: ssh_add_hostkey() failed\n",
					args->real_client_fd);
			//TODO handle connection with fake SSH server

			sshkey_free(sshkey_2);
			sshkey_free(sshkey_1);
			ssh_free(ssh_s);
			my_logger_pqsql_free(logger_pqsql);
			my_logger_file_free(logger_file);
			my_vm_pool_release(args->vm_pool, vm_id);
			shutdown(args->real_client_fd, SHUT_RDWR);
			close(args->real_client_fd);
			shutdown(real_server_fd, SHUT_RDWR);
			close(real_server_fd);
			return NULL;
		} else {
			printf("ssh_add_hostkey() returned %d\n", ret);
		}
	}

	printf("DDDD\n");

	/* initialise SSH object */
	ret = ssh_init(&ssh_c, 0, NULL);
	if (ret != 0) {
		fprintf(stderr, "thread for %d: ssh_init() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		if (sshkey_2 != NULL) {
			sshkey_free(sshkey_2);
		}
		sshkey_free(sshkey_1);
		ssh_free(ssh_s);
		my_logger_pqsql_free(logger_pqsql);
		my_logger_file_free(logger_file);
		my_vm_pool_release(args->vm_pool, vm_id);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		return NULL;
	} else {
		printf("ssh_init() returned %d, ssh: %p\n", ret, ssh_c);
	}

	printf("EEEE\n");

	/* set SSH host key verification function */
	ret = ssh_set_verify_host_key_callback(ssh_c, verify_host_key);
	if (ret != 0) {
		fprintf(stderr,
				"thread for %d: ssh_set_verify_host_key_callback() failed\n",
				args->real_client_fd);
		//TODO handle connection with fake SSH server

		ssh_free(ssh_c);
		if (sshkey_2 != NULL) {
			sshkey_free(sshkey_2);
		}
		sshkey_free(sshkey_1);
		ssh_free(ssh_s);
		my_logger_pqsql_free(logger_pqsql);
		my_logger_file_free(logger_file);
		my_vm_pool_release(args->vm_pool, vm_id);
		shutdown(args->real_client_fd, SHUT_RDWR);
		close(args->real_client_fd);
		shutdown(real_server_fd, SHUT_RDWR);
		close(real_server_fd);
		return NULL;
	}

	printf("FFFF\n");

	/* poll the two sockets */
	struct pollfd ufds[2];
	ufds[0].fd = args->real_client_fd;
	ufds[0].events = POLLIN;
	ufds[1].fd = real_server_fd;
	ufds[1].events = POLLIN;

	{
		u_char type = 0;
		const u_char* data = NULL;
		size_t len = 0;
		ssh_read(ssh_s, &type, &data, &len);
		ssh_flush(ssh_s, ufds[0].fd);
		ssh_read(ssh_c, &type, &data, &len);
		ssh_flush(ssh_c, ufds[1].fd);
	}

	printf("GGGG\n");

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
			/*printf("poll() returned %d\n", ret);*/

			if (ufds[0].revents & POLLIN) {
				/*printf("\n------------------\n");

				 printf("Data available from client\n");*/

				u_char type = 0;
				const u_char* data = NULL;
				size_t len = 0;
				ssize_t ret = 0;

				ret = ssh_fill(ssh_s, ufds[0].fd);
				/*printf("ssh_fill(ssh_s, %d) returned %zd\n", ufds[0].fd, ret);*/
				if (ret < 0) {
					if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
						printf("ssh_fill() would block\n");
					} else {
						fprintf(stderr, "thread for %d: ssh_fill() failed\n",
								args->real_client_fd);
						break;
					}
				}

				u_char should_loop = 1;
				while (1) {
					ret = ssh_read(ssh_s, &type, &data, &len);
					/*printf(
					 "ssh_read(ssh_s) returned %zd, type: %u, data: %p, len: %zu\n",
					 ret, type, data, len);
					 print_ssh_message_type(type);*/
					if (ret < 0) {
						fprintf(stderr, "thread for %d: ssh_read() failed\n",
								args->real_client_fd);
						ssh_flush(ssh_s, ufds[0].fd);
						should_loop = 0;
						break;
					}
					if (type == 0) {
						/*printf("\n\nSSH_MSG_NONE\n\n");*/

						ret = ssh_flush(ssh_s, ufds[0].fd);
						/*printf("ssh_flush(ssh_s, %d) returned %zd\n",
						 ufds[0].fd, ret);*/
						if (ret < 0) {
							fprintf(stderr,
									"thread for %d: ssh_flush() failed\n",
									args->real_client_fd);
							should_loop = 0;
							break;
						}

						should_loop = 1;
						break;
					}

					size_t i = 0;
					/*putchar('\n');
					 for (i = 0; i < len; i++) {
					 printf("%02x ", data[i]);
					 }
					 putchar('\n');

					 putchar('\n');
					 for (i = 0; i < len; i++) {
					 putchar(data[i]);
					 }
					 putchar('\n');

					 putchar('\n');*/

					/* write this message to logs */
					if (args->hpot_config->log_file_enabled) {
						ret = my_logger_file_write(logger_file, 1, type, len,
								data);
						if (ret < 0) {
							fprintf(stderr,
									"thread for %d: my_logger_file_write() failed\n",
									args->real_client_fd);
							should_loop = 0;
							break;
						}
					}

					if (args->hpot_config->log_pqsql_enabled) {
						ret = my_logger_pqsql_write(logger_pqsql, 1, type, len,
								data);
						if (ret < 0) {
							fprintf(stderr,
									"thread for %d: my_logger_pqsql_write() failed\n",
									args->real_client_fd);
							should_loop = 0;
							break;
						}
					}

					ret = ssh_write(ssh_c, type, data, len);
					/*printf("ssh_write(ssh_c, %d) returned %zd\n", ufds[1].fd,
					 ret);*/
					if (ret < 0) {
						fprintf(stderr, "thread for %d: ssh_write() failed\n",
								args->real_client_fd);
						should_loop = 0;
						break;
					}

					ret = ssh_flush(ssh_c, ufds[1].fd);
					/*printf("ssh_flush(ssh_c, %d) returned %zd\n", ufds[1].fd,
					 ret);*/
					if (ret < 0) {
						fprintf(stderr, "thread for %d: ssh_flush() failed\n",
								args->real_client_fd);
						should_loop = 0;
						break;
					}
				}
				if (!should_loop) {
					break;
				}

				/*printf("\n++++++++++++++++++\n");*/
			}

			if (ufds[1].revents & POLLIN) {
				/*printf("\n------------------\n");

				 printf("Data available from server\n");*/

				u_char type = 0;
				const u_char* data = NULL;
				size_t len = 0;
				ssize_t ret = 0;

				ret = ssh_fill(ssh_c, ufds[1].fd);
				/*printf("ssh_fill(ssh_c, %d) returned %zd\n", ufds[1].fd, ret);*/
				if (ret < 0) {
					if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
						printf("ssh_fill() would block\n");
					} else {
						fprintf(stderr, "thread for %d: ssh_fill() failed\n",
								args->real_client_fd);
						break;
					}
				}

				u_char should_loop = 1;
				while (1) {
					ret = ssh_read(ssh_c, &type, &data, &len);
					/*printf(
					 "ssh_read(ssh_c) returned %zd, type: %u, data: %p, len: %zu\n",
					 ret, type, data, len);
					 print_ssh_message_type(type);*/
					if (ret < 0) {
						fprintf(stderr, "thread for %d: ssh_read() failed\n",
								args->real_client_fd);
						ssh_flush(ssh_s, ufds[0].fd);
						should_loop = 0;
						break;
					}
					if (type == 52) {
						if (auth_success != 1) {
							auth_success = 1;
							printf("Auth succeeded first time\n");
							if (args->hpot_config->log_pqsql_enabled) {
								ret = my_logger_pqsql_set_login_success(
										logger_pqsql);
								if (ret < 0) {
									fprintf(stderr,
											"thread for %d: my_logger_pqsql_set_login_success() failed\n",
											args->real_client_fd);
									should_loop = 0;
									break;
								}
							}
						} else {
							printf("Auth succeeded again\n");
						}
					} else if (type == 0) {
						/*printf("\n\nSSH_MSG_NONE\n\n");*/

						ret = ssh_flush(ssh_c, ufds[1].fd);
						/*printf("ssh_flush(ssh_c, %d) returned %zd\n",
						 ufds[1].fd, ret);*/
						if (ret < 0) {
							fprintf(stderr,
									"thread for %d: ssh_flush() failed\n",
									args->real_client_fd);
							should_loop = 0;
							break;
						}

						should_loop = 1;
						break;
					}

					size_t i = 0;
					/*putchar('\n');
					 for (i = 0; i < len; i++) {
					 printf("%02x ", data[i]);
					 }
					 putchar('\n');

					 putchar('\n');
					 for (i = 0; i < len; i++) {
					 putchar(data[i]);
					 }
					 putchar('\n');

					 putchar('\n');*/

					/* write this message to logs */
					if (args->hpot_config->log_file_enabled) {
						ret = my_logger_file_write(logger_file, 1, type, len,
								data);
						if (ret < 0) {
							fprintf(stderr,
									"thread for %d: my_logger_file_write() failed\n",
									args->real_client_fd);
							should_loop = 0;
							break;
						}
					}

					if (args->hpot_config->log_pqsql_enabled) {
						ret = my_logger_pqsql_write(logger_pqsql, 1, type, len,
								data);
						if (ret < 0) {
							fprintf(stderr,
									"thread for %d: my_logger_pqsql_write() failed\n",
									args->real_client_fd);
							should_loop = 0;
							break;
						}
					}

					ret = ssh_write(ssh_s, type, data, len);
					/*printf("ssh_write(ssh_s, %d) returned %zd\n", ufds[0].fd,
					 ret);*/
					if (ret < 0) {
						fprintf(stderr, "thread for %d: ssh_write() failed\n",
								args->real_client_fd);
						should_loop = 0;
						break;
					}

					ret = ssh_flush(ssh_s, ufds[0].fd);
					/*printf("ssh_flush(ssh_s, %d) returned %zd\n", ufds[0].fd,
					 ret);*/
					if (ret < 0) {
						fprintf(stderr, "thread for %d: ssh_flush() failed\n",
								args->real_client_fd);
						should_loop = 0;
						break;
					}
				}
				if (!should_loop) {
					break;
				}

				/*printf("\n++++++++++++++++++\n");*/
			}
		}
	}

	if (auth_success) {
		printf("Login succeeded\n");
	} else {
		printf("Login failed\n");
	}

	ret = my_logger_pqsql_update_end_time(logger_pqsql);
	if (ret < 0) {
		fprintf(stderr,
				"thread for %d: my_logger_pqsql_update_end_time() failed\n",
				args->real_client_fd);
	}

	/* release the VM */
	ret = my_vm_pool_release(args->vm_pool, vm_id);
	if (ret < 0) {
		fprintf(stderr, "thread for %d: my_vm_pool_release() failed\n",
				args->real_client_fd);
	}

	/* TODO SSH still causes memory leak */

	ssh_free(ssh_c);
	if (sshkey_2 != NULL) {
		sshkey_free(sshkey_2);
	}
	sshkey_free(sshkey_1);
	ssh_free(ssh_s);
	my_logger_pqsql_free(logger_pqsql);
	my_logger_file_free(logger_file);
	my_vm_pool_release(args->vm_pool, vm_id);
	shutdown(args->real_client_fd, SHUT_RDWR);
	close(args->real_client_fd);
	shutdown(real_server_fd, SHUT_RDWR);
	close(real_server_fd);

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
