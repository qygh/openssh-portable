/*
 * my_curl_memory.h
 *
 *  Created on: 4 Jan 2018
 *      Author: lqy
 */

#ifndef MY_CURL_MEMORY_H_
#define MY_CURL_MEMORY_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct my_curl_memory {
	char* mem;
	size_t size;
};

struct my_curl_memory* my_curl_memory_new();

size_t my_curl_memory_write(void* data, size_t size, size_t nmemb,
		struct my_curl_memory* mcm);

void my_curl_memory_clear(struct my_curl_memory* mcm);

void my_curl_memory_free(struct my_curl_memory* mcm);

#endif /* MY_CURL_MEMORY_H_ */
