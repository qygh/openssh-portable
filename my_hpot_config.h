/*
 * my_hpot_config.h
 *
 *  Created on: 26 Feb 2018
 *      Author: lqy
 */

#ifndef MY_HPOT_CONFIG_H_
#define MY_HPOT_CONFIG_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <jansson.h>

struct my_hpot_config {
	char* server_key1_path;

	int server_key2_enabled;
	char* server_key2_path;

	uint16_t listening_port;

	uint32_t vm_pool_size;
	char* vm_base_image_name;
	char* vm_base_snapshot_name;
	char* vm_nic_name;
	char* vm_name_prefix;
	uint16_t vm_ssh_port;
	time_t vm_idle_timeout;

	int log_file_enabled;
	char* log_file_prefix;

	int log_pqsql_enabled;
	char* log_pqsql_conninfo;

	int iptables_snat_enabled;
};

struct my_hpot_config* my_hpot_config_new(const char* config_file_path);

void my_hpot_config_free(struct my_hpot_config* hpot_config);

#endif /* MY_HPOT_CONFIG_H_ */
