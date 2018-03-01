/*
 * my_hpot_cleanup_thread.c
 *
 *  Created on: 24 Feb 2018
 *      Author: lqy
 */

#include "my_hpot_cleanup_thread.h"

void* hpot_cleanup(void* arg) {
	struct ssh_cleanup_thread_arg* oarg = arg;
	struct ssh_cleanup_thread_arg args_cpy = { 0 };

	/* copy arguments onto thread's own stack */
	memcpy(&args_cpy, oarg, sizeof(args_cpy));

	/* finished copying arguments onto the thread's own stack and wait until main thread has called pthread_detach() */
	if (args_cpy.barrier != NULL) {
		pthread_barrier_wait(args_cpy.barrier);
	}

	printf("cleanup thread ready\n");

	struct ssh_cleanup_thread_arg* args = &args_cpy;

	sleep(args->hpot_config->vm_idle_timeout);
	while (1) {
		printf("calling my_vm_pool_process_idle_timeout_vms()\n");
		int ret = my_vm_pool_process_idle_timeout_vms(args->vm_pool,
				args->hpot_config->iptables_snat_enabled);
		if (ret < 0) {
			fprintf(stderr,
					"hpot_cleanup(): my_vm_pool_process_idle_timeout_vms() failed\n");
		}
		sleep(args->hpot_config->vm_idle_timeout);
	}

	return NULL;
}
