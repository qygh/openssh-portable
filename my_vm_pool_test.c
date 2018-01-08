/*
 * my_vm_pool_test.c
 *
 *  Created on: 6 Jan 2018
 *      Author: lqy
 */

#include <stdio.h>
#include <stdlib.h>

#include "my_vm_pool.h"

//gcc -g -O3 -Wall -Wextra my_vm_pool_test.c my_vm_pool.c my_lxd_api.c my_curl_memory.c sds.c -lcurl -ljansson -lpthread -o my_vm_pool

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

		my_vm_pool_free(mvp, 0);
		return 1;
	}
	printf("my_vm_pool_new() returned %p\n", mvp);

	/* 1 */
	uint32_t vm_id;
	uint8_t ip[16] = { 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	int ret = my_vm_pool_request(mvp, ip, &vm_id);
	if (ret < 0) {
		fprintf(stderr, "my_vm_pool_request() failed\n");

		my_vm_pool_free(mvp, 0);
		return 1;
	}
	printf("my_vm_pool_request() returned %d, vm_id: %u\n", ret, vm_id);

	uint8_t vm_ip[16];
	ret = my_vm_pool_get_vm_ip(mvp, vm_id, argv[5], vm_ip);
	if (ret < 0) {
		fprintf(stderr, "my_vm_pool_get_vm_ip() failed\n");

		my_vm_pool_free(mvp, 0);
		return 1;
	}
	printf("my_vm_pool_get_vm_ip() returned %d, IP:\n", ret);
	putchar('\n');
	for (int i = 0; i < 16; i++) {
		printf("%u ", vm_ip[i]);
	}
	putchar('\n');
	for (int i = 0; i < 16; i++) {
		printf("%02x ", vm_ip[i]);
	}
	putchar('\n');

	/* 2 */
	uint32_t vm_id_2;
	ret = my_vm_pool_request(mvp, ip, &vm_id_2);
	if (ret < 0) {
		fprintf(stderr, "my_vm_pool_request() failed\n");

		my_vm_pool_free(mvp, 0);
		return 1;
	}
	printf("my_vm_pool_request() returned %d, vm_id: %u\n", ret, vm_id_2);

	uint8_t vm_ip_2[16];
	ret = my_vm_pool_get_vm_ip(mvp, vm_id_2, argv[5], vm_ip_2);
	if (ret < 0) {
		fprintf(stderr, "my_vm_pool_get_vm_ip() failed\n");

		my_vm_pool_free(mvp, 0);
		return 1;
	}
	printf("my_vm_pool_get_vm_ip() returned %d, IP:\n", ret);
	putchar('\n');
	for (int i = 0; i < 16; i++) {
		printf("%u ", vm_ip_2[i]);
	}
	putchar('\n');
	for (int i = 0; i < 16; i++) {
		printf("%02x ", vm_ip_2[i]);
	}
	putchar('\n');

	/* 3 */
	uint32_t vm_id_3;
	uint8_t ip_3[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	ret = my_vm_pool_request(mvp, ip_3, &vm_id_3);
	if (ret < 0) {
		fprintf(stderr, "my_vm_pool_request() failed\n");

		my_vm_pool_free(mvp, 0);
		return 1;
	}
	printf("my_vm_pool_request() returned %d, vm_id: %u\n", ret, vm_id_3);

	uint8_t vm_ip_3[16];
	ret = my_vm_pool_get_vm_ip(mvp, vm_id_3, argv[5], vm_ip_3);
	if (ret < 0) {
		fprintf(stderr, "my_vm_pool_get_vm_ip() failed\n");

		my_vm_pool_free(mvp, 0);
		return 1;
	}
	printf("my_vm_pool_get_vm_ip() returned %d, IP:\n", ret);
	putchar('\n');
	for (int i = 0; i < 16; i++) {
		printf("%u ", vm_ip_3[i]);
	}
	putchar('\n');
	for (int i = 0; i < 16; i++) {
		printf("%02x ", vm_ip_3[i]);
	}
	putchar('\n');

	my_vm_pool_free(mvp, 0);
	return 0;
}
