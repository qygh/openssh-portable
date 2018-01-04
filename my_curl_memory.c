/*
 * my_curl_memory.c
 *
 *  Created on: 4 Jan 2018
 *      Author: lqy
 */

#include "my_curl_memory.h"

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
