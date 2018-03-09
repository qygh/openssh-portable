/*
 * my_hpot_forwarder_thread.h
 *
 *  Created on: 18 Jan 2018
 *      Author: lqy
 */

#ifndef MY_HPOT_FORWARDER_THREAD_H_
#define MY_HPOT_FORWARDER_THREAD_H_

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
#include <ctype.h>

#include "my_ssh_api.h"
#include "my_vm_pool.h"
#include "my_logger_file.h"
#include "my_logger_pqsql.h"
#include "my_hpot_config.h"

struct ssh_forwarder_thread_arg {
	int real_client_fd;
	struct my_vm_pool* vm_pool;
	struct my_hpot_config* hpot_config;
	pthread_barrier_t* barrier;
};

void* ssh_forwarder(void* arg);

#endif /* MY_HPOT_FORWARDER_THREAD_H_ */
