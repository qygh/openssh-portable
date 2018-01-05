/*
 * my_vm_pool.c
 *
 *  Created on: 29 Dec 2017
 *      Author: lqy
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#include "my_lxd_api.h"

//gcc -g -O3 -Wall -Wextra my_vm_pool.c my_lxd_api.c my_curl_memory.c sds.c -lcurl -ljansson -lpthread -o my_vm_pool

enum my_vm_state {
	invalid,
	uncompromised_idle,
	uncompromised_connected,
	compromised_connected,
	compromised_idle,
	reinstalling
};

struct my_vm_instance {
	uint32_t id;
	uint32_t conn_count;
	enum my_vm_state vm_state;
	time_t last_disconn;
	pthread_rwlock_t lock;
};

struct my_vm_pool {
	uint32_t pool_size;
	char* base_image_name;
	char* base_snapshot_name;
	char* vm_name_prefix;
	char* vm_nic_name;
	time_t idle_timeout;
	struct my_vm_instance* pool;
	struct my_lxd_api* lxd_api;
};

struct my_vm_pool* my_vm_pool_new(uint32_t pool_size,
		const char* base_image_name, const char* base_snapshot_name,
		const char* vm_name_prefix, const char* vm_nic_name,
		time_t idle_timeout);

int my_vm_pool_request(struct my_vm_pool* vm_pool, uint8_t client_ip_addr[16],
		uint32_t* vm_id_out);

int my_vm_pool_release(struct my_vm_pool* vm_pool, uint32_t vm_id);

int my_vm_pool_get_vm_ip(struct my_vm_pool* vm_pool, const char* nic_name,
		uint8_t vm_ip_addr_out[16]);

int my_vm_pool_process_idle_timeout_vms(struct my_vm_pool* vm_pool);

int my_vm_pool_set_compromised(struct my_vm_pool* vm_pool, uint32_t vm_id);

void my_vm_pool_free(struct my_vm_pool* vm_pool, int delete_all_vm);

struct my_vm_pool* my_vm_pool_new(uint32_t pool_size,
		const char* base_image_name, const char* base_snapshot_name,
		const char* vm_name_prefix, const char* vm_nic_name,
		time_t idle_timeout) {
	if (pool_size < 1 || base_image_name == NULL || base_snapshot_name == NULL
			|| vm_name_prefix == NULL || vm_nic_name == NULL
			|| idle_timeout < 1) {
		return NULL;
	}

	struct my_vm_pool* mvp = malloc(sizeof(struct my_vm_pool));
	if (mvp == NULL) {
		return NULL;
	}

	mvp->pool_size = pool_size;
	mvp->base_image_name = strdup(base_image_name);
	if (mvp->base_image_name == NULL) {
		free(mvp);
		return NULL;
	}
	mvp->base_snapshot_name = strdup(base_snapshot_name);
	if (mvp->base_snapshot_name == NULL) {
		free(mvp->base_image_name);
		free(mvp);
		return NULL;
	}
	mvp->vm_name_prefix = strdup(vm_name_prefix);
	if (mvp->vm_name_prefix == NULL) {
		free(mvp->base_snapshot_name);
		free(mvp->base_image_name);
		free(mvp);
		return NULL;
	}
	mvp->vm_nic_name = strdup(vm_nic_name);
	if (mvp->vm_nic_name == NULL) {
		free(mvp->vm_name_prefix);
		free(mvp->base_snapshot_name);
		free(mvp->base_image_name);
		free(mvp);
		return NULL;
	}
	mvp->idle_timeout = idle_timeout;
	mvp->pool = calloc(mvp->pool_size, sizeof(struct my_vm_instance));
	if (mvp->pool == NULL) {
		free(mvp->vm_nic_name);
		free(mvp->vm_name_prefix);
		free(mvp->base_snapshot_name);
		free(mvp->base_image_name);
		free(mvp);
		return NULL;
	}
	mvp->lxd_api = my_lxd_api_new(NULL);
	if (mvp->lxd_api == NULL) {
		free(mvp->pool);
		free(mvp->vm_nic_name);
		free(mvp->vm_name_prefix);
		free(mvp->base_snapshot_name);
		free(mvp->base_image_name);
		free(mvp);
		return NULL;
	}

	/* initialise VMs */
	for (uint32_t i = 0; i < mvp->pool_size; i++) {
		mvp->pool[i].id = i;
		mvp->pool[i].conn_count = 0;
		mvp->pool[i].vm_state = invalid;
		if (pthread_rwlock_init(&(mvp->pool[i].lock), NULL) != 0) {
			//TODO fail
			exit(1);
		}

		/* name of VM */
		sds vm_name = sdscatprintf(sdsempty(), "%s-%u", mvp->vm_name_prefix, i);
		if (vm_name == NULL) {
			//TODO fail
			exit(1);
		}

		/* check if the VM already exists */
		int result = -1;
		int ret = my_lxd_api_container_exists(mvp->lxd_api, vm_name, &result);
		if (ret < 0) {
			//TODO fail
			sdsfree(vm_name);
			exit(1);
		}
		if (result) {
			/* VM exists */
			int result2 = -1;
			int ret2 = my_lxd_api_snapshot_exists(mvp->lxd_api, vm_name,
					mvp->base_snapshot_name, &result2);
			if (ret2 < 0) {
				//TODO fail
				sdsfree(vm_name);
				exit(1);
			}
			if (result2) {
				/* base snapshot exists */
				int ret3 = my_lxd_api_power_container(mvp->lxd_api, vm_name, 1);
				if (ret3 < 0) {
					//TODO fail
					sdsfree(vm_name);
					exit(1);
				}
				mvp->pool[i].vm_state = uncompromised_idle;
			} else {
				/* base snapshot does not exist */
				//TODO fail
				sdsfree(vm_name);
				exit(1);
			}
		} else {
			/* VM does not exist */
			int ret2 = my_lxd_api_create_container(mvp->lxd_api, vm_name,
					mvp->base_image_name);
			if (ret2 < 0) {
				//TODO fail
				sdsfree(vm_name);
				exit(1);
			} else {
				/* create base snapshot */
				int ret3 = my_lxd_api_create_snapshot(mvp->lxd_api, vm_name,
						mvp->base_snapshot_name);
				if (ret3 < 0) {
					//TODO fail
					sdsfree(vm_name);
					exit(1);
				} else {
					/* start VM */
					int ret4 = my_lxd_api_power_container(mvp->lxd_api, vm_name,
							1);
					if (ret4 < 0) {
						//TODO fail
						sdsfree(vm_name);
						exit(1);
					}
					mvp->pool[i].vm_state = uncompromised_idle;
				}
			}
		}
		sdsfree(vm_name);
	}

	return mvp;
}

int main(int argc, char* argv[]) {
	if (argc < 1) {
		return 1;
	}

	if (argc < 7) {
		printf(
				"Usage: %s <pool_size> <base_image_name> <base_snapshot_name> <vm_name_prefix> <vm_nic_name> <idle_timeout>\n",
				argv[0]);
		return 1;
	}

	struct my_vm_pool* mvp = my_vm_pool_new(strtol(argv[1], NULL, 10), argv[2],
			argv[3], argv[4], argv[5], strtol(argv[6], NULL, 10));
	if (mvp == NULL) {
		fprintf(stderr, "my_vm_pool_new() failed\n");
		return 1;
	}

	printf("my_vm_pool_new() returned %p\n", mvp);

	return 0;
}
