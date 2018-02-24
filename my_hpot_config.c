/*
 * my_hpot_config.c
 *
 *  Created on: 24 Feb 2018
 *      Author: lqy
 */

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
	time_t vm_idle_timeout;

	int log_file_enabled;
	char* log_file_prefix;

	int log_pqsql_enabled;
	char* log_pqsql_conninfo;

	int iptables_snat_enabled;
};

static void free_all_config_strings(struct my_hpot_config* mhc) {
	free(mhc->server_key1_path);
	free(mhc->server_key2_path);
	free(mhc->vm_base_image_name);
	free(mhc->vm_base_snapshot_name);
	free(mhc->vm_nic_name);
	free(mhc->vm_name_prefix);
	free(mhc->log_file_prefix);
	free(mhc->log_pqsql_conninfo);
}

struct my_hpot_config* my_hpot_config_new(const char* config_file_path) {
	if (config_file_path == NULL) {
		return NULL;
	}

	struct my_hpot_config* mhc = malloc(sizeof(struct my_hpot_config));
	if (mhc == NULL) {
		return NULL;
	}
	mhc->server_key1_path = NULL;
	mhc->server_key2_path = NULL;
	mhc->vm_base_image_name = NULL;
	mhc->vm_base_snapshot_name = NULL;
	mhc->vm_nic_name = NULL;
	mhc->vm_name_prefix = NULL;
	mhc->log_file_prefix = NULL;
	mhc->log_pqsql_conninfo = NULL;

	json_error_t j_error;
	json_t* j_root = json_load_file(config_file_path, 0, &j_error);
	if (j_root == NULL) {
		fprintf(stderr,
				"my_hpot_config_new(): json_load_file() error on line %d: %s\n",
				j_error.line, j_error.text);

		free(mhc);
		return NULL;
	}

	{
		json_t* j_status = json_object_get(j_root, "server_key1_path");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'server_key1_path'\n");

			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_string(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'server_key1_path' is not string\n");

			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		const char* str = json_string_value(j_status);
		if (str == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): 'server_key1_path' is null\n");

			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->server_key1_path = strdup(str);
		if (mhc->server_key1_path == NULL) {
			fprintf(stderr, "my_hpot_config_new(): strdup() failed\n");

			json_decref(j_root);
			free(mhc);
			return NULL;
		}
	}

	{
		json_t* j_status = json_object_get(j_root, "server_key2_enabled");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'server_key2_enabled'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_boolean(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'server_key2_enabled' is not boolean\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->server_key2_enabled = json_boolean_value(j_status);
	}

	if (mhc->server_key2_enabled) {
		json_t* j_status = json_object_get(j_root, "server_key2_path");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'server_key2_path'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_string(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'server_key2_path' is not string\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		const char* str = json_string_value(j_status);
		if (str == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): 'server_key2_path' is null\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->server_key2_path = strdup(str);
		if (mhc->server_key2_path == NULL) {
			fprintf(stderr, "my_hpot_config_new(): strdup() failed\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
	}

	{
		json_t* j_status = json_object_get(j_root, "listening_port");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'listening_port'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_integer(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'listening_port' is not integer\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		int port = json_integer_value(j_status);
		if (port < 0 || port > 65535) {
			fprintf(stderr,
					"my_hpot_config_new(): 'listening_port' is not in range [0, 65535]\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->listening_port = port;
	}

	{
		json_t* j_status = json_object_get(j_root, "vm_pool_size");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'vm_pool_size'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_integer(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'vm_pool_size' is not integer\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		json_int_t pool_size = json_integer_value(j_status);
		if (pool_size <= 0) {
			fprintf(stderr,
					"my_hpot_config_new(): 'vm_pool_size' is not greater than 0\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->vm_pool_size = pool_size;
	}

	{
		json_t* j_status = json_object_get(j_root, "vm_base_image_name");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'vm_base_image_name'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_string(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'vm_base_image_name' is not string\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		const char* str = json_string_value(j_status);
		if (str == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): 'vm_base_image_name' is null\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->vm_base_image_name = strdup(str);
		if (mhc->vm_base_image_name == NULL) {
			fprintf(stderr, "my_hpot_config_new(): strdup() failed\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
	}

	{
		json_t* j_status = json_object_get(j_root, "vm_base_snapshot_name");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'vm_base_snapshot_name'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_string(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'vm_base_snapshot_name' is not string\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		const char* str = json_string_value(j_status);
		if (str == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): 'vm_base_snapshot_name' is null\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->vm_base_snapshot_name = strdup(str);
		if (mhc->vm_base_snapshot_name == NULL) {
			fprintf(stderr, "my_hpot_config_new(): strdup() failed\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
	}

	{
		json_t* j_status = json_object_get(j_root, "vm_nic_name");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'vm_nic_name'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_string(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'vm_nic_name' is not string\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		const char* str = json_string_value(j_status);
		if (str == NULL) {
			fprintf(stderr, "my_hpot_config_new(): 'vm_nic_name' is null\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->vm_nic_name = strdup(str);
		if (mhc->vm_nic_name == NULL) {
			fprintf(stderr, "my_hpot_config_new(): strdup() failed\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
	}

	{
		json_t* j_status = json_object_get(j_root, "vm_name_prefix");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'vm_name_prefix'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_string(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'vm_name_prefix' is not string\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		const char* str = json_string_value(j_status);
		if (str == NULL) {
			fprintf(stderr, "my_hpot_config_new(): 'vm_name_prefix' is null\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->vm_name_prefix = strdup(str);
		if (mhc->vm_name_prefix == NULL) {
			fprintf(stderr, "my_hpot_config_new(): strdup() failed\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
	}

	{
		json_t* j_status = json_object_get(j_root, "vm_idle_timeout");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'vm_idle_timeout'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_integer(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'vm_idle_timeout' is not integer\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->vm_idle_timeout = json_integer_value(j_status);
		if (mhc->vm_idle_timeout <= 0) {
			fprintf(stderr,
					"my_hpot_config_new(): 'vm_idle_timeout' is not greater than 0\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
	}

	{
		json_t* j_status = json_object_get(j_root, "log_file_enabled");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'log_file_enabled'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_boolean(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'log_file_enabled' is not boolean\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->log_file_enabled = json_boolean_value(j_status);
	}

	if (mhc->log_file_enabled) {
		json_t* j_status = json_object_get(j_root, "log_file_prefix");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'log_file_prefix'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_string(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'log_file_prefix' is not string\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		const char* str = json_string_value(j_status);
		if (str == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): 'log_file_prefix' is null\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->log_file_prefix = strdup(str);
		if (mhc->log_file_prefix == NULL) {
			fprintf(stderr, "my_hpot_config_new(): strdup() failed\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
	}

	{
		json_t* j_status = json_object_get(j_root, "log_pqsql_enabled");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'log_pqsql_enabled'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_boolean(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'log_pqsql_enabled' is not boolean\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->log_pqsql_enabled = json_boolean_value(j_status);
	}

	if (mhc->log_pqsql_enabled) {
		json_t* j_status = json_object_get(j_root, "log_pqsql_conninfo");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'log_pqsql_conninfo'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_string(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'log_pqsql_conninfo' is not string\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		const char* str = json_string_value(j_status);
		if (str == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): 'log_pqsql_conninfo' is null\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->log_pqsql_conninfo = strdup(str);
		if (mhc->log_pqsql_conninfo == NULL) {
			fprintf(stderr, "my_hpot_config_new(): strdup() failed\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
	}

	{
		json_t* j_status = json_object_get(j_root, "iptables_snat_enabled");
		if (j_status == NULL) {
			fprintf(stderr,
					"my_hpot_config_new(): failed to get 'iptables_snat_enabled'\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		if (!json_is_boolean(j_status)) {
			fprintf(stderr,
					"my_hpot_config_new(): 'iptables_snat_enabled' is not boolean\n");

			free_all_config_strings(mhc);
			json_decref(j_root);
			free(mhc);
			return NULL;
		}
		mhc->iptables_snat_enabled = json_boolean_value(j_status);
	}

	json_decref(j_root);
	return mhc;
}

void my_hpot_config_free(struct my_hpot_config* hpot_config) {
	if (hpot_config == NULL) {
		return;
	}

	free_all_config_strings(hpot_config);
	free(hpot_config);
}

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
