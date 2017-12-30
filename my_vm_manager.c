/*
 * my_vm_manager.c
 *
 *  Created on: 21 Dec 2017
 *      Author: lqy
 */

//void my_vm_manager_new();
//void my_vm_manager_free();
//gcc -O3 -Wall -Wextra my_vm_manager.c -lcurl -ljansson -o my_vm_manager
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>

/* forward refs */
void print_json(json_t *root);
void print_json_aux(json_t *element, int indent);
void print_json_indent(int indent);
const char *json_plural(int count);
void print_json_object(json_t *element, int indent);
void print_json_array(json_t *element, int indent);
void print_json_string(json_t *element, int indent);
void print_json_integer(json_t *element, int indent);
void print_json_real(json_t *element, int indent);
void print_json_true(json_t *element, int indent);
void print_json_false(json_t *element, int indent);
void print_json_null(json_t *element, int indent);
/* */

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

void print_json(json_t *root) {
	print_json_aux(root, 0);
}

void print_json_aux(json_t *element, int indent) {
	switch (json_typeof(element)) {
	case JSON_OBJECT:
		print_json_object(element, indent);
		break;
	case JSON_ARRAY:
		print_json_array(element, indent);
		break;
	case JSON_STRING:
		print_json_string(element, indent);
		break;
	case JSON_INTEGER:
		print_json_integer(element, indent);
		break;
	case JSON_REAL:
		print_json_real(element, indent);
		break;
	case JSON_TRUE:
		print_json_true(element, indent);
		break;
	case JSON_FALSE:
		print_json_false(element, indent);
		break;
	case JSON_NULL:
		print_json_null(element, indent);
		break;
	default:
		fprintf(stderr, "unrecognized JSON type %d\n", json_typeof(element));
	}
}

void print_json_indent(int indent) {
	int i;
	for (i = 0; i < indent; i++) {
		putchar(' ');
	}
}

const char *json_plural(int count) {
	return count == 1 ? "" : "s";
}

void print_json_object(json_t *element, int indent) {
	size_t size;
	const char *key;
	json_t *value;

	print_json_indent(indent);
	size = json_object_size(element);

	printf("JSON Object of %ld pair%s:\n", size, json_plural(size));
	json_object_foreach(element, key, value)
	{
		print_json_indent(indent + 2);
		printf("JSON Key: \"%s\"\n", key);
		print_json_aux(value, indent + 2);
	}

}

void print_json_array(json_t *element, int indent) {
	size_t i;
	size_t size = json_array_size(element);
	print_json_indent(indent);

	printf("JSON Array of %ld element%s:\n", size, json_plural(size));
	for (i = 0; i < size; i++) {
		print_json_aux(json_array_get(element, i), indent + 2);
	}
}

void print_json_string(json_t *element, int indent) {
	print_json_indent(indent);
	printf("JSON String: \"%s\"\n", json_string_value(element));
}

void print_json_integer(json_t *element, int indent) {
	print_json_indent(indent);
	printf("JSON Integer: \"%" JSON_INTEGER_FORMAT "\"\n",
			json_integer_value(element));
}

void print_json_real(json_t *element, int indent) {
	print_json_indent(indent);
	printf("JSON Real: %f\n", json_real_value(element));
}

void print_json_true(json_t *element, int indent) {
	(void) element;
	print_json_indent(indent);
	printf("JSON True\n");
}

void print_json_false(json_t *element, int indent) {
	(void) element;
	print_json_indent(indent);
	printf("JSON False\n");
}

void print_json_null(json_t *element, int indent) {
	(void) element;
	print_json_indent(indent);
	printf("JSON Null\n");
}

json_t* load_json(const char* text) {
	json_t* root;
	json_error_t error;

	root = json_loads(text, 0, &error);

	if (root) {
		return root;
	} else {
		fprintf(stderr, "json error on line %d: %s\n", error.line, error.text);
		return NULL;
	}
}

int main(void) {
	CURL *curl;
	CURLcode res;
	long response_code;

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL,
				"http://example.com/1.0/containers/xenial/state");
		curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH,
				"/var/lib/lxd/unix.socket");

		struct my_curl_memory* mcm = my_curl_memory_new();
		if (mcm == NULL) {
			curl_easy_cleanup(curl);
			return 1;
		}

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_curl_memory_write);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, mcm);

		/* example.com is redirected, figure out the redirection! */

		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));
		} else {
			res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
					&response_code);
			if (res == CURLE_OK) {
				fprintf(stderr, "Response code: %ld\n", response_code);

				printf("Data: \n");
				printf("%s\n", mcm->mem);

				json_t* j = load_json(mcm->mem);
				if (j != NULL) {
					print_json(j);
					json_decref(j);
				}

			} else {
				fprintf(stderr, "curl_easy_getinfo() failed: %s\n",
						curl_easy_strerror(res));
			}
		}

		/* always cleanup */
		curl_easy_cleanup(curl);
		my_curl_memory_free(mcm);
	}
	return 0;
}
