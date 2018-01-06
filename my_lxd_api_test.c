/*
 * my_lxd_api_test.c
 *
 *  Created on: 6 Jan 2018
 *      Author: lqy
 */

//gcc -g -O3 -Wall -Wextra my_lxd_api_test.c my_lxd_api.c my_curl_memory.c sds.c -lcurl -ljansson -o my_lxd_api
#include "my_lxd_api.h"

int main(int argc, char* argv[]) {
	if (argc < 1) {
		return 1;
	}

	if (argc < 3) {
		fprintf(stderr,
				"Usage: %s getip <container name> <nic name> <is ipv6>\n",
				argv[0]);
		fprintf(stderr, "       %s create <container name> <image name>\n",
				argv[0]);
		fprintf(stderr, "       %s power <container name> <on off>\n", argv[0]);
		fprintf(stderr,
				"       %s snapshot_create <container name> <snapshot name>\n",
				argv[0]);
		fprintf(stderr, "       %s container_exists <container name>\n",
				argv[0]);
		fprintf(stderr,
				"       %s snapshot_exists <container name> <snapshot name>\n",
				argv[0]);
		fprintf(stderr, "       %s delete <container name>\n", argv[0]);
		fprintf(stderr,
				"       %s snapshot_restore <container name> <snapshot name>\n",
				argv[0]);
		fprintf(stderr,
				"       %s snapshot_delete <container name> <snapshot name>\n",
				argv[0]);

		return 1;
	}

	struct my_lxd_api* mla = my_lxd_api_new(NULL);
	if (mla == NULL) {
		fprintf(stderr, "my_lxd_api_new() failed\n");

		return 1;
	}

	if (strcmp("getip", argv[1]) == 0 && argc == 5) {

		int is_ipv6 = strcmp("0", argv[4]);

		uint8_t addr[16] = { 0 };
		int ret = my_lxd_api_get_container_ip(mla, argv[2], argv[3], is_ipv6,
				addr);
		printf("my_lxd_api_get_container_ip() returned %d\n", ret);

		putchar('\n');
		for (int i = 0; i < 16; i++) {
			printf("%u ", addr[i]);
		}
		putchar('\n');
		for (int i = 0; i < 16; i++) {
			printf("%02x ", addr[i]);
		}
		putchar('\n');

	} else if (strcmp("create", argv[1]) == 0 && argc == 4) {

		int ret = my_lxd_api_create_container(mla, argv[2], argv[3]);
		printf("my_lxd_api_create_container() returned %d\n", ret);

	} else if (strcmp("power", argv[1]) == 0 && argc == 4) {

		int on_off = strcmp("0", argv[3]);

		int ret = my_lxd_api_power_container(mla, argv[2], on_off);
		printf("my_lxd_api_power_container() returned %d\n", ret);

	} else if (strcmp("snapshot_create", argv[1]) == 0 && argc == 4) {

		int ret = my_lxd_api_create_snapshot(mla, argv[2], argv[3]);
		printf("my_lxd_api_create_snapshot() returned %d\n", ret);

	} else if (strcmp("container_exists", argv[1]) == 0 && argc == 3) {

		int result = -1;
		int ret = my_lxd_api_container_exists(mla, argv[2], &result);
		printf("my_lxd_api_container_exists() returned %d\n", ret);
		printf("result: %d\n", result);

	} else if (strcmp("snapshot_exists", argv[1]) == 0 && argc == 4) {

		int result = -1;
		int ret = my_lxd_api_snapshot_exists(mla, argv[2], argv[3], &result);
		printf("my_lxd_api_snapshot_exists() returned %d\n", ret);
		printf("result: %d\n", result);

	} else if (strcmp("delete", argv[1]) == 0 && argc == 3) {

		int ret = my_lxd_api_delete_container(mla, argv[2]);
		printf("my_lxd_api_delete_container() returned %d\n", ret);

	} else if (strcmp("snapshot_restore", argv[1]) == 0 && argc == 4) {

		int ret = my_lxd_api_restore_snapshot(mla, argv[2], argv[3]);
		printf("my_lxd_api_restore_snapshot() returned %d\n", ret);

	} else if (strcmp("snapshot_delete", argv[1]) == 0 && argc == 4) {

		int ret = my_lxd_api_delete_snapshot(mla, argv[2], argv[3]);
		printf("my_lxd_api_delete_snapshot() returned %d\n", ret);

	} else {

		fprintf(stderr, "Invalid command\n");

	}

	my_lxd_api_free(mla);
	return 0;
}
