/*
 * my_logger_file.h
 *
 *  Created on: 13 Feb 2018
 *      Author: lqy
 */

#ifndef MY_LOGGER_FILE_H_
#define MY_LOGGER_FILE_H_

#include <stdio.h>
#include <stdlib.h>

#include "sds.h"

struct my_logger_file {
	uint32_t vm_id;
	time_t create_time;
	FILE* log_fp;
};

struct my_logger_file* my_logger_file_new(const char* prefix, uint32_t vm_id,
		const uint8_t client_ip_addr[16], const uint8_t vm_ip_addr[16]);

int my_logger_file_write(struct my_logger_file* logger_file,
		int is_direction_c2s, unsigned char message_type, size_t message_length,
		const unsigned char* message_data);

void my_logger_file_free(struct my_logger_file* logger_file);

#endif /* MY_LOGGER_FILE_H_ */
