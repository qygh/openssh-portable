/*
 * my_lxd_api.c
 *
 *  Created on: 30 Dec 2017
 *      Author: lqy
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <curl/curl.h>
#include <jansson.h>

#include "sds.h"

//gcc -O3 -Wall -Wextra my_lxd_api.c sds.c -lcurl -ljansson -o my_lxd_api

#define DEFAULT_LXD_UNIX_SOCKET_PATH "/var/lib/lxd/unix.socket"

struct my_lxd_api {
	char* lxd_unix_socket_path;
	CURL* curl;
	pthread_mutex_t curl_lock;
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

int my_lxd_api_create_container(struct my_lxd_api* lxd_api,
		const char* container_name, const char* source_image);

void my_lxd_api_create_snapshot();

void my_lxd_api_power_container();

void my_lxd_delete_container();

int my_lxd_api_get_container_ip(struct my_lxd_api* lxd_api,
		const char* container_name, const char* nic_name, int is_ipv6,
		uint8_t ip_addr_out[16]);

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
	curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, lusp);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_curl_memory_write);
	mla->curl = curl;

	if (pthread_mutex_init(&mla->curl_lock, NULL) != 0) {
		fprintf(stderr, "pthread_mutex_init() failed\n");

		curl_easy_cleanup(mla->curl);
		free(mla->lxd_unix_socket_path);
		free(mla);
		return NULL;
	}

	return mla;
}

//curl -s --unix-socket /var/lib/lxd/unix.socket -X POST -d '{"name": "xenial", "source": {"type": "image", "alias": "16.04"}}' a/1.0/containers
int my_lxd_api_create_container(struct my_lxd_api* lxd_api,
		const char* container_name, const char* source_image) {
	if (lxd_api == NULL || container_name == NULL || source_image == NULL) {
		return -1;
	}

	const char* url = "http://example.com/1.0/containers";

	sds req =
			sdscatprintf(sdsempty(),
					"{\"name\": \"%s\", \"source\": {\"type\": \"image\", \"alias\": \"%s\"}}",
					container_name, source_image);
	if (req == NULL) {
		return -1;
	}

	struct my_curl_memory* mcm = my_curl_memory_new();
	if (mcm == NULL) {
		sdsfree(req);

		return -1;
	}

	pthread_mutex_lock(&lxd_api->curl_lock);
	curl_easy_setopt(lxd_api->curl, CURLOPT_URL, url);
	curl_easy_setopt(lxd_api->curl, CURLOPT_WRITEDATA, mcm);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, req);

	CURLcode cret = curl_easy_perform(lxd_api->curl);
	if (cret != CURLE_OK) {
		pthread_mutex_unlock(&lxd_api->curl_lock);

		fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(cret));

		my_curl_memory_free(mcm);
		sdsfree(req);
		return -1;
	}

	long response_code;
	cret = curl_easy_getinfo(lxd_api->curl, CURLINFO_RESPONSE_CODE,
			&response_code);
	pthread_mutex_unlock(&lxd_api->curl_lock);
	if (cret != CURLE_OK) {
		fprintf(stderr, "curl_easy_getinfo() failed: %s\n",
				curl_easy_strerror(cret));

		my_curl_memory_free(mcm);
		sdsfree(req);
		return -1;
	}

	fprintf(stderr, "Response code: %ld\n", response_code);
	fprintf(stderr, "Data: \n%s\n", mcm->mem);

	my_curl_memory_free(mcm);
	sdsfree(req);
	return 0;
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

	pthread_mutex_lock(&lxd_api->curl_lock);
	curl_easy_setopt(lxd_api->curl, CURLOPT_URL, url);
	curl_easy_setopt(lxd_api->curl, CURLOPT_WRITEDATA, mcm);

	CURLcode cret = curl_easy_perform(lxd_api->curl);
	if (cret != CURLE_OK) {
		pthread_mutex_unlock(&lxd_api->curl_lock);

		fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(cret));

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	long response_code;
	cret = curl_easy_getinfo(lxd_api->curl, CURLINFO_RESPONSE_CODE,
			&response_code);
	pthread_mutex_unlock(&lxd_api->curl_lock);
	if (cret != CURLE_OK) {
		fprintf(stderr, "curl_easy_getinfo() failed: %s\n",
				curl_easy_strerror(cret));

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	fprintf(stderr, "Response code: %ld\n", response_code);
	fprintf(stderr, "Data: \n%s\n", mcm->mem);

	/* get the IP address of the container */

	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

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

	json_t* jnetwork = json_object_get(jmetadata, "network");
	if (jnetwork == NULL) {
		fprintf(stderr, "failed to get network\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	json_t* jnic = json_object_get(jnetwork, nic_name);
	if (jnic == NULL) {
		fprintf(stderr, "failed to get %s\n", nic_name);

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	json_t* jaddresses = json_object_get(jnic, "addresses");
	if (jaddresses == NULL) {
		fprintf(stderr, "failed to get addresses\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	if (!json_is_array(jaddresses)) {
		fprintf(stderr, "error: addresses is not an array\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	int found = 0;
	for (size_t i = 0; i < json_array_size(jaddresses); i++) {
		json_t* jaddress = json_array_get(jaddresses, i);
		if (jaddress == NULL) {
			fprintf(stderr, "error: failed to get address from array\n");

			json_decref(jroot);
			my_curl_memory_free(mcm);
			sdsfree(url);
			return -1;
		}

		json_t* jscope = json_object_get(jaddress, "scope");
		if (jscope == NULL) {
			fprintf(stderr, "error: failed to get scope from address\n");

			json_decref(jroot);
			my_curl_memory_free(mcm);
			sdsfree(url);
			return -1;
		}
		if (strcmp("global", json_string_value(jscope)) != 0) {
			continue;
		}

		json_t* jfamily = json_object_get(jaddress, "family");
		if (jfamily == NULL) {
			fprintf(stderr, "error: failed to get family from address\n");

			json_decref(jroot);
			my_curl_memory_free(mcm);
			sdsfree(url);
			return -1;
		}
		if (is_ipv6 && strcmp("inet6", json_string_value(jfamily)) != 0) {
			continue;
		}
		if (!is_ipv6 && strcmp("inet", json_string_value(jfamily)) != 0) {
			continue;
		}

		json_t* jaddr = json_object_get(jaddress, "address");
		const char* addr = json_string_value(jaddr);
		if (addr == NULL) {
			fprintf(stderr, "error: failed to get IP address string\n");

			json_decref(jroot);
			my_curl_memory_free(mcm);
			sdsfree(url);
			return -1;
		}
		int ret;
		if (is_ipv6) {
			ret = inet_pton(AF_INET6, addr, ip_addr_out);
		} else {
			/* IPv4-mapped IPv6 address */
			memset(ip_addr_out, 0, 16);
			ip_addr_out[10] = 0xff;
			ip_addr_out[11] = 0xff;
			ret = inet_pton(AF_INET, addr, ip_addr_out + 12);
		}
		if (ret != 1) {
			fprintf(stderr,
					"error: inet_pton() failed to convert %s to binary IP address\n",
					addr);

			json_decref(jroot);
			my_curl_memory_free(mcm);
			sdsfree(url);
			return -1;
		}
		found = 1;
		printf("\n\nIP address: %s\n\n", addr);
		inet_pton(AF_INET6, addr, ip_addr_out);

	}
	if (!found) {
		fprintf(stderr, "error: IP address not found\n");

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

void my_lxd_api_free(struct my_lxd_api* lxd_api) {
	if (lxd_api == NULL) {
		return;
	}

	free(lxd_api->lxd_unix_socket_path);
	curl_easy_cleanup(lxd_api->curl);
	pthread_mutex_destroy(&lxd_api->curl_lock);

	lxd_api->lxd_unix_socket_path = NULL;
	lxd_api->curl = NULL;

	free(lxd_api);
}

int main(int argc, char* argv[]) {
	if (argc < 1) {
		return 1;
	}

	if (argc < 4) {
		fprintf(stderr, "Usage: %s <container name> <nic name> <is ipv6>\n",
				argv[0]);

		return 1;
	}

	struct my_lxd_api* mla = my_lxd_api_new(NULL);
	if (mla == NULL) {
		fprintf(stderr, "my_lxd_api_new() failed\n");

		return 1;
	}

	int is_ipv6 = strcmp("0", argv[3]);

	uint8_t addr[16] = { 0 };
	int ret = my_lxd_api_get_container_ip(mla, argv[1], argv[2], is_ipv6, addr);
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

	if (argc >= 6) {
		ret = my_lxd_api_create_container(mla, argv[4], argv[5]);
		printf("my_lxd_api_create_container() returned %d\n", ret);
	}

	my_lxd_api_free(mla);
	return 0;
}
