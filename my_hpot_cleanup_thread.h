/*
 * my_hpot_cleanup_thread.h
 *
 *  Created on: 26 Feb 2018
 *      Author: lqy
 */

#ifndef MY_HPOT_CLEANUP_THREAD_H_
#define MY_HPOT_CLEANUP_THREAD_H_

#include "my_vm_pool.h"
#include "my_hpot_config.h"

struct ssh_cleanup_thread_arg {
	struct my_vm_pool* vm_pool;
	struct my_hpot_config* hpot_config;
	pthread_barrier_t* barrier;
};

void* hpot_cleanup(void* arg);

#endif /* MY_HPOT_CLEANUP_THREAD_H_ */
