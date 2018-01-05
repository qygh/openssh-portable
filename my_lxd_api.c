/*
 * my_lxd_api.c
 *
 *  Created on: 30 Dec 2017
 *      Author: lqy
 */

#include "my_curl_memory.h"
#include "my_lxd_api.h"

//gcc -g -O3 -Wall -Wextra my_lxd_api.c my_curl_memory.c sds.c -lcurl -ljansson -o my_lxd_api

static int my_lxd_api_wait_operation(struct my_lxd_api* lxd_api,
		const char* operation_uri) {
	if (lxd_api == NULL || operation_uri == NULL) {
		return -1;
	}

	sds url = sdscatprintf(sdsempty(), "http://example.com%s/wait",
			operation_uri);
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

	/* parse JSON */
	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* check status code */
	json_t* jstatus = json_object_get(jroot, "status_code");
	if (jstatus == NULL) {
		fprintf(stderr, "failed to get status_code\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}
	if (json_integer_value(jstatus) != 200) {
		fprintf(stderr, "status_code is not 200\n");

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

int my_lxd_api_container_exists(struct my_lxd_api* lxd_api,
		const char* container_name, int* result_out) {
	if (lxd_api == NULL || container_name == NULL || result_out == NULL) {
		return -1;
	}

	sds url = sdscatprintf(sdsempty(), "http://example.com/1.0/containers/%s",
			container_name);
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

	/* check response code */
	if (response_code == 404) {
		*result_out = 0;

		my_curl_memory_free(mcm);
		sdsfree(url);
		return 0;
	}

	/* parse JSON */
	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* check status code */
	json_t* jstatus = json_object_get(jroot, "status_code");
	if (jstatus == NULL) {
		fprintf(stderr, "failed to get status_code\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}
	if (json_integer_value(jstatus) != 200) {
		fprintf(stderr, "status_code is not 200\n");

		*result_out = 0;
	} else {
		*result_out = 1;
	}

	json_decref(jroot);
	my_curl_memory_free(mcm);
	sdsfree(url);
	return 0;
}

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
		const char* container_name, const char* source_image_alias) {
	if (lxd_api == NULL || container_name == NULL || source_image_alias == NULL) {
		return -1;
	}

	const char* url = "http://example.com/1.0/containers";

	sds req =
			sdscatprintf(sdsempty(),
					"{\"name\": \"%s\", \"source\": {\"type\": \"image\", \"alias\": \"%s\"}}",
					container_name, source_image_alias);
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
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, NULL);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POST, 0);
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

	/* parse JSON */
	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(req);
		return -1;
	}

	/* check status code */
	json_t* jstatus = json_object_get(jroot, "status_code");
	if (jstatus == NULL) {
		fprintf(stderr, "failed to get status_code\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(req);
		return -1;
	}
	if (json_integer_value(jstatus) != 100) {
		fprintf(stderr, "status_code is not 100\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(req);
		return -1;
	}

	/* get operation */
	json_t* joperation = json_object_get(jroot, "operation");
	if (joperation == NULL) {
		fprintf(stderr, "failed to get operation\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(req);
		return -1;
	}

	/* wait for operation to complete */
	if (my_lxd_api_wait_operation(lxd_api, json_string_value(joperation)) < 0) {
		fprintf(stderr, "failed to wait for operation to complete\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(req);
		return -1;
	}

	json_decref(jroot);
	my_curl_memory_free(mcm);
	sdsfree(req);
	return 0;
}

int my_lxd_api_snapshot_exists(struct my_lxd_api* lxd_api,
		const char* container_name, const char* snapshot_name, int* result_out) {
	if (lxd_api == NULL || container_name == NULL || snapshot_name == NULL
			|| result_out == NULL) {
		return -1;
	}

	sds url = sdscatprintf(sdsempty(),
			"http://example.com/1.0/containers/%s/snapshots/%s", container_name,
			snapshot_name);
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

	/* check response code */
	if (response_code == 404) {
		*result_out = 0;

		my_curl_memory_free(mcm);
		sdsfree(url);
		return 0;
	}

	/* parse JSON */
	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* check status code */
	json_t* jstatus = json_object_get(jroot, "status_code");
	if (jstatus == NULL) {
		fprintf(stderr, "failed to get status_code\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}
	if (json_integer_value(jstatus) != 200) {
		fprintf(stderr, "status_code is not 200\n");

		*result_out = 0;
	} else {
		*result_out = 1;
	}

	json_decref(jroot);
	my_curl_memory_free(mcm);
	sdsfree(url);
	return 0;
}

int my_lxd_api_create_snapshot(struct my_lxd_api* lxd_api,
		const char* container_name, const char* snapshot_name) {
	if (lxd_api == NULL || container_name == NULL || snapshot_name == NULL) {
		return -1;
	}

	sds url = sdscatprintf(sdsempty(),
			"http://example.com/1.0/containers/%s/snapshots", container_name);
	if (url == NULL) {
		return -1;
	}

	sds req = sdscatprintf(sdsempty(), "{\"name\": \"%s\"}", snapshot_name);
	if (req == NULL) {
		sdsfree(url);

		return -1;
	}

	struct my_curl_memory* mcm = my_curl_memory_new();
	if (mcm == NULL) {
		sdsfree(url);
		sdsfree(req);

		return -1;
	}

	pthread_mutex_lock(&lxd_api->curl_lock);
	curl_easy_setopt(lxd_api->curl, CURLOPT_URL, url);
	curl_easy_setopt(lxd_api->curl, CURLOPT_WRITEDATA, mcm);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, req);

	CURLcode cret = curl_easy_perform(lxd_api->curl);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, NULL);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POST, 0);
	if (cret != CURLE_OK) {
		pthread_mutex_unlock(&lxd_api->curl_lock);

		fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(cret));

		my_curl_memory_free(mcm);
		sdsfree(url);
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
		sdsfree(url);
		sdsfree(req);
		return -1;
	}

	fprintf(stderr, "Response code: %ld\n", response_code);
	fprintf(stderr, "Data: \n%s\n", mcm->mem);

	/* parse JSON */
	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(url);
		sdsfree(req);
		return -1;
	}

	/* check status code */
	json_t* jstatus = json_object_get(jroot, "status_code");
	if (jstatus == NULL) {
		fprintf(stderr, "failed to get status_code\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		sdsfree(req);
		return -1;
	}
	if (json_integer_value(jstatus) != 100) {
		fprintf(stderr, "status_code is not 100\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		sdsfree(req);
		return -1;
	}

	/* get operation */
	json_t* joperation = json_object_get(jroot, "operation");
	if (joperation == NULL) {
		fprintf(stderr, "failed to get operation\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		sdsfree(req);
		return -1;
	}

	/* wait for operation to complete */
	if (my_lxd_api_wait_operation(lxd_api, json_string_value(joperation)) < 0) {
		fprintf(stderr, "failed to wait for operation to complete\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		sdsfree(req);
		return -1;
	}

	json_decref(jroot);
	my_curl_memory_free(mcm);
	sdsfree(url);
	sdsfree(req);
	return 0;
}

int my_lxd_api_restore_snapshot(struct my_lxd_api* lxd_api,
		const char* container_name, const char* snapshot_name) {
	if (lxd_api == NULL || container_name == NULL || snapshot_name == NULL) {
		return -1;
	}

	sds url = sdscatprintf(sdsempty(), "http://example.com/1.0/containers/%s",
			container_name);
	if (url == NULL) {
		return -1;
	}

	sds req = sdscatprintf(sdsempty(), "{\"restore\": \"%s\"}", snapshot_name);
	if (req == NULL) {
		sdsfree(url);

		return -1;
	}

	struct my_curl_memory* mcm = my_curl_memory_new();
	if (mcm == NULL) {
		sdsfree(url);
		sdsfree(req);

		return -1;
	}

	pthread_mutex_lock(&lxd_api->curl_lock);
	curl_easy_setopt(lxd_api->curl, CURLOPT_URL, url);
	curl_easy_setopt(lxd_api->curl, CURLOPT_WRITEDATA, mcm);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, req);
	curl_easy_setopt(lxd_api->curl, CURLOPT_CUSTOMREQUEST, "PUT");

	CURLcode cret = curl_easy_perform(lxd_api->curl);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, NULL);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POST, 0);
	curl_easy_setopt(lxd_api->curl, CURLOPT_CUSTOMREQUEST, NULL);
	if (cret != CURLE_OK) {
		pthread_mutex_unlock(&lxd_api->curl_lock);

		fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(cret));

		my_curl_memory_free(mcm);
		sdsfree(url);
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
		sdsfree(url);
		sdsfree(req);
		return -1;
	}

	fprintf(stderr, "Response code: %ld\n", response_code);
	fprintf(stderr, "Data: \n%s\n", mcm->mem);

	/* parse JSON */
	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(url);
		sdsfree(req);
		return -1;
	}

	/* check status code */
	json_t* jstatus = json_object_get(jroot, "status_code");
	if (jstatus == NULL) {
		fprintf(stderr, "failed to get status_code\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		sdsfree(req);
		return -1;
	}
	if (json_integer_value(jstatus) != 100) {
		fprintf(stderr, "status_code is not 100\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		sdsfree(req);
		return -1;
	}

	/* get operation */
	json_t* joperation = json_object_get(jroot, "operation");
	if (joperation == NULL) {
		fprintf(stderr, "failed to get operation\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		sdsfree(req);
		return -1;
	}

	/* wait for operation to complete */
	if (my_lxd_api_wait_operation(lxd_api, json_string_value(joperation)) < 0) {
		fprintf(stderr, "failed to wait for operation to complete\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		sdsfree(req);
		return -1;
	}

	json_decref(jroot);
	my_curl_memory_free(mcm);
	sdsfree(url);
	sdsfree(req);
	return 0;
}

int my_lxd_api_delete_snapshot(struct my_lxd_api* lxd_api,
		const char* container_name, const char* snapshot_name) {
	if (lxd_api == NULL || container_name == NULL || snapshot_name == NULL) {
		return -1;
	}

	sds url = sdscatprintf(sdsempty(),
			"http://example.com/1.0/containers/%s/snapshots/%s", container_name,
			snapshot_name);
	if (url == NULL) {
		return -1;
	}

	const char* req = "{}";

	struct my_curl_memory* mcm = my_curl_memory_new();
	if (mcm == NULL) {
		sdsfree(url);

		return -1;
	}

	pthread_mutex_lock(&lxd_api->curl_lock);
	curl_easy_setopt(lxd_api->curl, CURLOPT_URL, url);
	curl_easy_setopt(lxd_api->curl, CURLOPT_WRITEDATA, mcm);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, req);
	curl_easy_setopt(lxd_api->curl, CURLOPT_CUSTOMREQUEST, "DELETE");

	CURLcode cret = curl_easy_perform(lxd_api->curl);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, NULL);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POST, 0);
	curl_easy_setopt(lxd_api->curl, CURLOPT_CUSTOMREQUEST, NULL);
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

	/* parse JSON */
	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* check status code */
	json_t* jstatus = json_object_get(jroot, "status_code");
	if (jstatus == NULL) {
		fprintf(stderr, "failed to get status_code\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}
	if (json_integer_value(jstatus) != 100) {
		fprintf(stderr, "status_code is not 100\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* get operation */
	json_t* joperation = json_object_get(jroot, "operation");
	if (joperation == NULL) {
		fprintf(stderr, "failed to get operation\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* wait for operation to complete */
	if (my_lxd_api_wait_operation(lxd_api, json_string_value(joperation)) < 0) {
		fprintf(stderr, "failed to wait for operation to complete\n");

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

int my_lxd_api_power_container(struct my_lxd_api* lxd_api,
		const char* container_name, int on_off) {
	if (lxd_api == NULL || container_name == NULL) {
		return -1;
	}

	sds url = sdscatprintf(sdsempty(),
			"http://example.com/1.0/containers/%s/state", container_name);
	if (url == NULL) {
		return -1;
	}

	const char* req = NULL;
	if (on_off) {
		req = "{\"action\": \"start\", \"force\": true}";
	} else {
		req = "{\"action\": \"stop\", \"force\": true}";
	}

	struct my_curl_memory* mcm = my_curl_memory_new();
	if (mcm == NULL) {
		sdsfree(url);

		return -1;
	}

	pthread_mutex_lock(&lxd_api->curl_lock);
	curl_easy_setopt(lxd_api->curl, CURLOPT_URL, url);
	curl_easy_setopt(lxd_api->curl, CURLOPT_WRITEDATA, mcm);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, req);
	curl_easy_setopt(lxd_api->curl, CURLOPT_CUSTOMREQUEST, "PUT");

	CURLcode cret = curl_easy_perform(lxd_api->curl);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, NULL);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POST, 0);
	curl_easy_setopt(lxd_api->curl, CURLOPT_CUSTOMREQUEST, NULL);
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

	/* parse JSON */
	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* check status code */
	json_t* jstatus = json_object_get(jroot, "status_code");
	if (jstatus == NULL) {
		fprintf(stderr, "failed to get status_code\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}
	if (json_integer_value(jstatus) != 100) {
		fprintf(stderr, "status_code is not 100\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* get operation */
	json_t* joperation = json_object_get(jroot, "operation");
	if (joperation == NULL) {
		fprintf(stderr, "failed to get operation\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* wait for operation to complete */
	if (my_lxd_api_wait_operation(lxd_api, json_string_value(joperation)) < 0) {
		fprintf(stderr, "failed to wait for operation to complete\n");

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

int my_lxd_api_delete_container(struct my_lxd_api* lxd_api,
		const char* container_name) {
	if (lxd_api == NULL || container_name == NULL) {
		return -1;
	}

	sds url = sdscatprintf(sdsempty(), "http://example.com/1.0/containers/%s",
			container_name);
	if (url == NULL) {
		return -1;
	}

	const char* req = "{}";

	struct my_curl_memory* mcm = my_curl_memory_new();
	if (mcm == NULL) {
		sdsfree(url);

		return -1;
	}

	pthread_mutex_lock(&lxd_api->curl_lock);
	curl_easy_setopt(lxd_api->curl, CURLOPT_URL, url);
	curl_easy_setopt(lxd_api->curl, CURLOPT_WRITEDATA, mcm);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, req);
	curl_easy_setopt(lxd_api->curl, CURLOPT_CUSTOMREQUEST, "DELETE");

	CURLcode cret = curl_easy_perform(lxd_api->curl);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POSTFIELDS, NULL);
	curl_easy_setopt(lxd_api->curl, CURLOPT_POST, 0);
	curl_easy_setopt(lxd_api->curl, CURLOPT_CUSTOMREQUEST, NULL);
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

	/* parse JSON */
	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* check status code */
	json_t* jstatus = json_object_get(jroot, "status_code");
	if (jstatus == NULL) {
		fprintf(stderr, "failed to get status_code\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}
	if (json_integer_value(jstatus) != 100) {
		fprintf(stderr, "status_code is not 100\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* get operation */
	json_t* joperation = json_object_get(jroot, "operation");
	if (joperation == NULL) {
		fprintf(stderr, "failed to get operation\n");

		json_decref(jroot);
		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* wait for operation to complete */
	if (my_lxd_api_wait_operation(lxd_api, json_string_value(joperation)) < 0) {
		fprintf(stderr, "failed to wait for operation to complete\n");

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

	/* parse JSON */
	json_error_t jerror;
	json_t* jroot = json_loads(mcm->mem, 0, &jerror);
	if (jroot == NULL) {
		fprintf(stderr, "error: on line %d: %s\n", jerror.line, jerror.text);

		my_curl_memory_free(mcm);
		sdsfree(url);
		return -1;
	}

	/* get the IP address of the container */
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

/*
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
*/
