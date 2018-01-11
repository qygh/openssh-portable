/*
 * my_vm_pool.h
 *
 *  Created on: 8 Jan 2018
 *      Author: lqy
 */

#ifndef MY_VM_POOL_H_
#define MY_VM_POOL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#include "my_lxd_api.h"

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

#endif /* MY_VM_POOL_H_ */
