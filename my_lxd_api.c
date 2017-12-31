/*
 * my_lxd_api.c
 *
 *  Created on: 30 Dec 2017
 *      Author: lqy
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>

#include "sds.h"

#define DEFAULT_LXD_UNIX_SOCKET_PATH "/var/lib/lxd/unix.socket"

struct my_lxd_api {
	char* lxd_unix_socket_path;
	CURL* curl;
};

struct my_curl_memory {
	char* mem;
	size_t size;
};

struct my_curl_memory* my_curl_memory_new() {
	struct my_curl_memory* mcm = malloc(sizeof(struct my_curl_memory));
	if (mcm == NULL) {
		return NULL;
	}

	mcm->mem = NULL;
	mcm->size = 0;
	return mcm;
}

size_t my_curl_memory_write(void* data, size_t size, size_t nmemb,
		struct my_curl_memory* mcm) {
	printf("my_curl_memory_write(%p, %zu, %zu, %p) called\n", data, size, nmemb,
			mcm);

	size_t datalen = size * nmemb;

	char* oldmem = mcm->mem;
	mcm->mem = realloc(mcm->mem, mcm->size + datalen + 1);
	if (mcm->mem == NULL) {
		fprintf(stderr, "my_curl_memory_write(): realloc() failed\n");
		mcm->mem = oldmem;
		return 0;
	}

	memcpy((mcm->mem) + (mcm->size), data, datalen);
	mcm->size += datalen;
	/* make printing easier in case data is a string */
	mcm->mem[mcm->size] = 0;

	return datalen;
}

void my_curl_memory_clear(struct my_curl_memory* mcm) {
	if (mcm == NULL) {
		return;
	}

	free(mcm->mem);
	mcm->mem = NULL;
	mcm->size = 0;
}

void my_curl_memory_free(struct my_curl_memory* mcm) {
	if (mcm == NULL) {
		return;
	}

	free(mcm->mem);
	mcm->mem = NULL;
	mcm->size = 0;

	free(mcm);
}

struct my_lxd_api* my_lxd_api_new(const char* lxd_unix_socket_path);

void my_lxd_api_create_container();

void my_lxd_api_create_snapshot();

void my_lxd_api_power_container();

void my_lxd_delete_container();

int my_lxd_api_get_container_ip(const char* container_name,
		const char* nic_name, int is_ipv6, uint8_t ip_addr_out[16]);

void my_lxd_api_free(struct my_lxd_api* lxd_api);

/* */

struct my_lxd_api* my_lxd_api_new(const char* lxd_unix_socket_path) {
	struct my_lxd_api* mla = malloc(sizeof(struct my_lxd_api));
	if (mla == NULL) {
		return NULL;
	}

	char* lusp;
	if (lxd_unix_socket_path == NULL) {
		lusp = strdup(DEFAULT_LXD_UNIX_SOCKET_PATH);
	} else {
		lusp = strdup(lxd_unix_socket_path);
	}
	if (lusp == NULL) {
		fprintf(stderr, "lusp error\n");

		free(mla);
		return NULL;
	}
	mla->lxd_unix_socket_path = lusp;

	CURL* curl = curl_easy_init();
	if (curl == NULL) {
		fprintf(stderr, "curl error\n");

		free(mla->lxd_unix_socket_path);
		free(mla);
		return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_curl_memory_write);
	mla->curl = curl;

	return mla;
}

int my_lxd_api_get_container_ip(struct my_lxd_api* lxd_api,
		const char* container_name, const char* nic_name, int is_ipv6,
		uint8_t ip_addr_out[16]) {
	if (lxd_api == NULL || container_name == NULL || nic_name == NULL
			|| ip_addr_out == NULL) {
		return -1;
	}

	sds url = sdscatprintf(sdsempty(),
			"http://example.com/1.0/containers/%s/state", container_name);
	if (url == NULL) {
		return -1;
	}

	struct my_curl_memory* mcm = my_curl_memory_new();
	if (mcm == NULL) {
		sdsfree(url);

		return -1;
	}
	curl_easy_setopt(lxd_api->curl, CURLOPT_URL, url);
	curl_easy_setopt(lxd_api->curl, CURLOPT_WRITEDATA, mcm);

	CURLcode cret = curl_easy_perform(lxd_api->curl);
	if (cret != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(cret));

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	long response_code;
	cret = curl_easy_getinfo(lxd_api->curl, CURLINFO_RESPONSE_CODE,
			&response_code);
	if (cret != CURLE_OK) {
		fprintf(stderr, "curl_easy_getinfo() failed: %s\n",
				curl_easy_strerror(cret));

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	fprintf(stderr, "Response code: %ld\n", response_code);

	fprintf(stderr, "Data: \n");
	fprintf(stderr, "%s\n", mcm->mem);

	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	if (!json_is_object(jroot)) {
		fprintf(stderr, "error: root is not an object\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	json_t* jmetadata = json_object_get(jroot, "metadata");
	if (jmetadata == NULL) {
		fprintf(stderr, "failed to get metadata\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	json_decref(jroot);
	my_curl_memory_free(mcm);
	sdsfree(url);
	return 0;
}
