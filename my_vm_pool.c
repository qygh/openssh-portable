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
	uint8_t client_ip_addr[16];
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

static int is_ip_ipv6(uint8_t ip_addr[16]) {
	int zero_x_10 = 0;
	for (int i = 0; i < 10; i++) {
		if (ip_addr[i] != 0) {
			zero_x_10 = 0;
			break;
		} else {
			zero_x_10 = 1;
		}
	}

	int twofivefive_x_2 = 0;
	if (ip_addr[10] == 255 && ip_addr[11] == 255) {
		twofivefive_x_2 = 1;
	} else {
		twofivefive_x_2 = 0;
	}

	if (zero_x_10 && twofivefive_x_2) {
		return 0;
	} else {
		return 1;
	}
}

static int is_ip_same(uint8_t ip_addr_l[16], uint8_t ip_addr_r[16]) {
	return memcmp(ip_addr_l, ip_addr_r, 16) == 0;
}

struct my_vm_pool* my_vm_pool_new(uint32_t pool_size,
		const char* base_image_name, const char* base_snapshot_name,
		const char* vm_name_prefix, const char* vm_nic_name,
		time_t idle_timeout);

int my_vm_pool_request(struct my_vm_pool* vm_pool, uint8_t client_ip_addr[16],
		uint32_t* vm_id_out);

int my_vm_pool_release(struct my_vm_pool* vm_pool, uint32_t vm_id);

int my_vm_pool_get_vm_ip(struct my_vm_pool* vm_pool, uint32_t vm_id,
		const char* nic_name, uint8_t vm_ip_addr_out[16]);

int my_vm_pool_process_idle_timeout_vms(struct my_vm_pool* vm_pool);

int my_vm_pool_set_compromised(struct my_vm_pool* vm_pool, uint32_t vm_id);

void my_vm_pool_free(struct my_vm_pool* vm_pool, int delete_vm);

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
			my_vm_pool_free(mvp, 1);
			return NULL;
		}

		/* name of VM */
		sds vm_name = sdscatprintf(sdsempty(), "%s-%u", mvp->vm_name_prefix, i);
		if (vm_name == NULL) {
			pthread_rwlock_destroy(&(mvp->pool[i].lock));
			my_vm_pool_free(mvp, 1);
			return NULL;
		}

		/* check if the VM already exists */
		int result = -1;
		int ret = my_lxd_api_container_exists(mvp->lxd_api, vm_name, &result);
		if (ret < 0) {
			pthread_rwlock_destroy(&(mvp->pool[i].lock));
			sdsfree(vm_name);
			my_vm_pool_free(mvp, 1);
			return NULL;
		}
		if (result) {
			/* VM exists */
			int result2 = -1;
			int ret2 = my_lxd_api_snapshot_exists(mvp->lxd_api, vm_name,
					mvp->base_snapshot_name, &result2);
			if (ret2 < 0) {
				pthread_rwlock_destroy(&(mvp->pool[i].lock));
				sdsfree(vm_name);
				my_vm_pool_free(mvp, 1);
				return NULL;
			}
			if (result2) {
				/* base snapshot exists */
				int ret3 = my_lxd_api_power_container(mvp->lxd_api, vm_name, 1);
				if (ret3 < 0) {
					pthread_rwlock_destroy(&(mvp->pool[i].lock));
					sdsfree(vm_name);
					my_vm_pool_free(mvp, 1);
					return NULL;
				}
				mvp->pool[i].vm_state = uncompromised_idle;
			} else {
				/* base snapshot does not exist */
				pthread_rwlock_destroy(&(mvp->pool[i].lock));
				sdsfree(vm_name);
				my_vm_pool_free(mvp, 1);
				return NULL;
			}
		} else {
			/* VM does not exist */
			int ret2 = my_lxd_api_create_container(mvp->lxd_api, vm_name,
					mvp->base_image_name);
			if (ret2 < 0) {
				pthread_rwlock_destroy(&(mvp->pool[i].lock));
				sdsfree(vm_name);
				my_vm_pool_free(mvp, 1);
				return NULL;
			} else {
				/* create base snapshot */
				int ret3 = my_lxd_api_create_snapshot(mvp->lxd_api, vm_name,
						mvp->base_snapshot_name);
				if (ret3 < 0) {
					pthread_rwlock_destroy(&(mvp->pool[i].lock));
					sdsfree(vm_name);
					my_vm_pool_free(mvp, 1);
					return NULL;
				} else {
					/* start VM */
					int ret4 = my_lxd_api_power_container(mvp->lxd_api, vm_name,
							1);
					if (ret4 < 0) {
						pthread_rwlock_destroy(&(mvp->pool[i].lock));
						sdsfree(vm_name);
						my_vm_pool_free(mvp, 1);
						return NULL;
					}
					mvp->pool[i].vm_state = uncompromised_idle;
				}
			}
		}
		sdsfree(vm_name);
	}

	return mvp;
}

int my_vm_pool_request(struct my_vm_pool* vm_pool, uint8_t client_ip_addr[16],
		uint32_t* vm_id_out) {
	if (vm_pool == NULL || client_ip_addr == NULL || vm_id_out == NULL) {
		return -1;
	}

	int succeed = 0;
	for (uint32_t i = 0; i < vm_pool->pool_size; i++) {
		/*sds vm_name = sdscatprintf(sdsempty(), "%s-%u", vm_pool->vm_name_prefix,
		 i);
		 if (vm_name == NULL) {
		 continue;
		 }*/

		pthread_rwlock_wrlock(&(vm_pool->pool[i].lock));
		switch (vm_pool->pool[i].vm_state) {
		case invalid: {
			break;
		}

		case uncompromised_idle: {
			vm_pool->pool[i].conn_count = 1;
			memcpy(vm_pool->pool[i].client_ip_addr, client_ip_addr, 16);
			vm_pool->pool[i].vm_state = uncompromised_connected;
			*vm_id_out = vm_pool->pool[i].id;

			succeed = 1;
			break;
		}

		case uncompromised_connected: {
			if (!is_ip_same(vm_pool->pool[i].client_ip_addr, client_ip_addr)) {
				break;
			}

			if (vm_pool->pool[i].conn_count == 0xffffffff) {
				break;
			}

			vm_pool->pool[i].conn_count += 1;
			*vm_id_out = vm_pool->pool[i].id;

			succeed = 1;
			break;
		}

		case compromised_connected: {
			if (!is_ip_same(vm_pool->pool[i].client_ip_addr, client_ip_addr)) {
				break;
			}

			if (vm_pool->pool[i].conn_count == 0xffffffff) {
				break;
			}

			vm_pool->pool[i].conn_count += 1;
			*vm_id_out = vm_pool->pool[i].id;

			succeed = 1;
			break;
		}

		case compromised_idle: {
			if (!is_ip_same(vm_pool->pool[i].client_ip_addr, client_ip_addr)) {
				break;
			}

			vm_pool->pool[i].conn_count = 1;
			*vm_id_out = vm_pool->pool[i].id;

			succeed = 1;
			break;
		}

		case reinstalling: {
			break;
		}

		default: {
			break;
		}
		}
		pthread_rwlock_unlock(&(vm_pool->pool[i].lock));
		//sdsfree(vm_name);

		if (succeed) {
			break;
		}
	}

	if (!succeed) {
		return -1;
	}

	return 0;
}

int my_vm_pool_release(struct my_vm_pool* vm_pool, uint32_t vm_id) {
	if (vm_pool == NULL) {
		return -1;
	}

	if (vm_id + 1 > vm_pool->pool_size) {
		return -1;
	}

	int succeed = 0;
	pthread_rwlock_wrlock(&(vm_pool->pool[vm_id].lock));
	switch (vm_pool->pool[vm_id].vm_state) {
	case invalid: {
		break;
	}

	case uncompromised_idle: {
		break;
	}

	case uncompromised_connected: {
		if (vm_pool->pool[vm_id].conn_count == 0) {
			break;
		}

		vm_pool->pool[vm_id].conn_count -= 1;
		if (vm_pool->pool[vm_id].conn_count == 0) {
			vm_pool->pool[vm_id].vm_state = uncompromised_idle;
		}
		vm_pool->pool[vm_id].last_disconn = time(NULL);

		succeed = 1;
		break;
	}

	case compromised_connected: {
		if (vm_pool->pool[vm_id].conn_count == 0) {
			break;
		}

		vm_pool->pool[vm_id].conn_count -= 1;
		if (vm_pool->pool[vm_id].conn_count == 0) {
			vm_pool->pool[vm_id].vm_state = compromised_idle;
		}
		vm_pool->pool[vm_id].last_disconn = time(NULL);

		succeed = 1;
		break;
	}

	case compromised_idle: {
		break;
	}

	case reinstalling: {
		break;
	}

	default: {
		break;
	}
	}
	pthread_rwlock_unlock(&(vm_pool->pool[vm_id].lock));

	if (!succeed) {
		return -1;
	}

	return 0;
}

int my_vm_pool_get_vm_ip(struct my_vm_pool* vm_pool, uint32_t vm_id,
		const char* nic_name, uint8_t vm_ip_addr_out[16]) {
	if (vm_pool == NULL || nic_name == NULL || vm_ip_addr_out == NULL) {
		return -1;
	}

	if (vm_id + 1 > vm_pool->pool_size) {
		return -1;
	}

	int succeed = 0;
	pthread_rwlock_wrlock(&(vm_pool->pool[vm_id].lock));
	if (vm_pool->pool[vm_id].vm_state != invalid
			&& vm_pool->pool[vm_id].vm_state != reinstalling) {
		sds vm_name = sdscatprintf(sdsempty(), "%s-%u", vm_pool->vm_name_prefix,
				vm_id);
		if (vm_name != NULL) {
			int is_client_ip_ipv6 = is_ip_ipv6(
					vm_pool->pool[vm_id].client_ip_addr);
			int ret = my_lxd_api_get_container_ip(vm_pool->lxd_api, vm_name,
					nic_name, is_client_ip_ipv6, vm_ip_addr_out);
			if (ret >= 0) {
				succeed = 1;
			}
		}
		sdsfree(vm_name);
	}
	pthread_rwlock_unlock(&(vm_pool->pool[vm_id].lock));

	if (!succeed) {
		return -1;
	}

	return 0;
}

int my_vm_pool_process_idle_timeout_vms(struct my_vm_pool* vm_pool) {
	if (vm_pool == NULL) {
		return -1;
	}

	time_t call_time = time(NULL);

	int error = 0;
	for (uint32_t i = 0; i < vm_pool->pool_size; i++) {
		pthread_rwlock_wrlock(&(vm_pool->pool[i].lock));
		if (vm_pool->pool[i].vm_state == compromised_idle) {
			if (call_time - vm_pool->pool[i].last_disconn
					> vm_pool->idle_timeout) {
				sds vm_name = sdscatprintf(sdsempty(), "%s-%u",
						vm_pool->vm_name_prefix, i);
				if (vm_name == NULL) {
					error = 1;
					pthread_rwlock_unlock(&(vm_pool->pool[i].lock));
					continue;
				}

				sds snapshot_name = sdscatprintf(sdsempty(), "snapshot-%ld",
						vm_pool->pool[i].last_disconn);
				if (snapshot_name == NULL) {
					error = 1;
					sdsfree(vm_name);
					pthread_rwlock_unlock(&(vm_pool->pool[i].lock));
					continue;
				}

				int ret = my_lxd_api_create_snapshot(vm_pool->lxd_api, vm_name,
						snapshot_name);
				if (ret < 0) {
					error = 1;
					sdsfree(snapshot_name);
					sdsfree(vm_name);
					pthread_rwlock_unlock(&(vm_pool->pool[i].lock));
					continue;
				}

				ret = my_lxd_api_restore_snapshot(vm_pool->lxd_api, vm_name,
						vm_pool->base_snapshot_name);
				if (ret < 0) {
					error = 1;
					sdsfree(snapshot_name);
					sdsfree(vm_name);
					pthread_rwlock_unlock(&(vm_pool->pool[i].lock));
					continue;
				}

				ret = my_lxd_api_power_container(vm_pool->lxd_api, vm_name, 1);
				if (ret < 0) {
					error = 1;
					sdsfree(snapshot_name);
					sdsfree(vm_name);
					pthread_rwlock_unlock(&(vm_pool->pool[i].lock));
					continue;
				}

				sdsfree(snapshot_name);
				sdsfree(vm_name);
			}
		}
		pthread_rwlock_unlock(&(vm_pool->pool[i].lock));
	}

	if (error) {
		return -1;
	}

	return 0;
}

int my_vm_pool_set_compromised(struct my_vm_pool* vm_pool, uint32_t vm_id) {
	if (vm_pool == NULL) {
		return -1;
	}

	if (vm_id + 1 > vm_pool->pool_size) {
		return -1;
	}

	int succeed = 0;
	pthread_rwlock_wrlock(&(vm_pool->pool[vm_id].lock));
	if (vm_pool->pool[vm_id].vm_state == uncompromised_connected) {
		vm_pool->pool[vm_id].vm_state = compromised_connected;
		succeed = 1;
	}
	pthread_rwlock_unlock(&(vm_pool->pool[vm_id].lock));

	if (!succeed) {
		return -1;
	}

	return 0;
}

void my_vm_pool_free(struct my_vm_pool* vm_pool, int delete_vm) {
	if (vm_pool == NULL) {
		return;
	}

	if (delete_vm) {
		/* delete VMs */
		for (uint32_t i = 0; i < vm_pool->pool_size; i++) {
			sds vm_name = sdscatprintf(sdsempty(), "%s-%u",
					vm_pool->vm_name_prefix, i);
			if (vm_name == NULL) {
				continue;
			}

			if (vm_pool->pool[i].vm_state != invalid) {
				pthread_rwlock_wrlock(&(vm_pool->pool[i].lock));
				if (vm_pool->pool[i].vm_state != invalid) {
					my_lxd_api_power_container(vm_pool->lxd_api, vm_name, 0);
					my_lxd_api_delete_container(vm_pool->lxd_api, vm_name);
					vm_pool->pool[i].vm_state = invalid;
				}
				pthread_rwlock_unlock(&(vm_pool->pool[i].lock));
				pthread_rwlock_destroy(&(vm_pool->pool[i].lock));
			}

			sdsfree(vm_name);
		}
	} else {
		for (uint32_t i = 0; i < vm_pool->pool_size; i++) {
			if (vm_pool->pool[i].vm_state != invalid) {
				pthread_rwlock_wrlock(&(vm_pool->pool[i].lock));
				if (vm_pool->pool[i].vm_state != invalid) {
					vm_pool->pool[i].vm_state = invalid;
				}
				pthread_rwlock_unlock(&(vm_pool->pool[i].lock));
				pthread_rwlock_destroy(&(vm_pool->pool[i].lock));
			}
		}
	}

	free(vm_pool->base_image_name);
	free(vm_pool->base_snapshot_name);
	free(vm_pool->vm_name_prefix);
	free(vm_pool->vm_nic_name);
	free(vm_pool->pool);
	my_lxd_api_free(vm_pool->lxd_api);
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
