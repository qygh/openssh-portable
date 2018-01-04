/*
 * my_lxd_api.h
 *
 *  Created on: 4 Jan 2018
 *      Author: lqy
 */

#ifndef MY_LXD_API_H_
#define MY_LXD_API_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <curl/curl.h>
#include <jansson.h>

#include "sds.h"

#define DEFAULT_LXD_UNIX_SOCKET_PATH "/var/lib/lxd/unix.socket"

struct my_lxd_api {
	char* lxd_unix_socket_path;
	CURL* curl;
	pthread_mutex_t curl_lock;
};

struct my_lxd_api* my_lxd_api_new(const char* lxd_unix_socket_path);

static int my_lxd_api_wait_operation(struct my_lxd_api* lxd_api,
		const char* operation_uri);

int my_lxd_api_container_exists(struct my_lxd_api* lxd_api,
		const char* container_name, int* result_out);

int my_lxd_api_create_container(struct my_lxd_api* lxd_api,
		const char* container_name, const char* source_image_alias);

int my_lxd_api_snapshot_exists(struct my_lxd_api* lxd_api,
		const char* container_name, const char* snapshot_name, int* result_out);

int my_lxd_api_create_snapshot(struct my_lxd_api* lxd_api,
		const char* container_name, const char* snapshot_name);

int my_lxd_api_restore_snapshot(struct my_lxd_api* lxd_api,
		const char* container_name, const char* snapshot_name);

int my_lxd_api_delete_snapshot(struct my_lxd_api* lxd_api,
		const char* container_name, const char* snapshot_name);

int my_lxd_api_power_container(struct my_lxd_api* lxd_api,
		const char* container_name, int on_off);

int my_lxd_api_delete_container(struct my_lxd_api* lxd_api,
		const char* container_name);

int my_lxd_api_get_container_ip(struct my_lxd_api* lxd_api,
		const char* container_name, const char* nic_name, int is_ipv6,
		uint8_t ip_addr_out[16]);

void my_lxd_api_free(struct my_lxd_api* lxd_api);

#endif /* MY_LXD_API_H_ */
