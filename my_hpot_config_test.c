/*
 * my_hpot_config_test.c
 *
 *  Created on: 26 Feb 2018
 *      Author: lqy
 */

#include "my_hpot_config.h"

int main(int argc, char* argv[]) {
	if (argc < 2) {
		fprintf(stderr, "configuration file path not specified\n");

		return 1;
	}

	struct my_hpot_config* mhc = my_hpot_config_new(argv[1]);
	if (mhc == NULL) {
		fprintf(stderr, "my_hpot_config_new() failed\n");

		return 1;
	}

	printf("server_key1_path: %s\n", mhc->server_key1_path);

	printf("server_key1_enabled: %d\n", mhc->server_key2_enabled);
	printf("server_key2_path: %s\n", mhc->server_key2_path);

	printf("listening_port: %u\n", mhc->listening_port);

	printf("vm_pool_size: %u\n", mhc->vm_pool_size);
	printf("vm_base_image_name: %s\n", mhc->vm_base_image_name);
	printf("vm_base_snapshot_name: %s\n", mhc->vm_base_snapshot_name);
	printf("vm_nic_name: %s\n", mhc->vm_nic_name);
	printf("vm_name_prefix: %s\n", mhc->vm_name_prefix);
	printf("vm_idle_timeout: %ld\n", (long) mhc->vm_idle_timeout);

	printf("log_file_enabled: %d\n", mhc->log_file_enabled);
	printf("log_file_prefix: %s\n", mhc->log_file_prefix);

	printf("log_pqsql_enabled: %d\n", mhc->log_pqsql_enabled);
	printf("log_pqsql_conninfo: %s\n", mhc->log_pqsql_conninfo);

	printf("iptables_snat_enabled: %d\n", mhc->iptables_snat_enabled);

	my_hpot_config_free(mhc);
	return 0;
}
