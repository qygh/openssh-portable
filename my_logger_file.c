/*
 * my_logger_file.c
 *
 *  Created on: 12 Feb 2018
 *      Author: lqy
 */

#include "my_logger_file.h"

struct my_logger_file* my_logger_file_new(const char* prefix, uint32_t vm_id,
		const uint8_t client_ip_addr[16], const uint8_t vm_ip_addr[16]) {
	if (client_ip_addr == NULL || vm_ip_addr == NULL) {
		return NULL;
	}
	if (prefix == NULL) {
		prefix = "";
	}

	struct my_logger_file* mlf = malloc(sizeof(struct my_logger_file));
	if (mlf == NULL) {
		return NULL;
	}

	mlf->vm_id = vm_id;
	mlf->create_time = time(NULL);

	/* generate name of log file */
	sds log_filename = sdscatprintf(sdsempty(), "%s_%u_%ld", prefix,
			(unsigned int) mlf->vm_id, (long) mlf->create_time);
	if (log_filename == NULL) {
		free(mlf);

		return NULL;
	}

	/* create file */
	FILE* log_fp = fopen(log_filename, "a");
	if (log_fp == NULL) {
		sdsfree(log_filename);
		free(mlf);

		return NULL;
	}
	sdsfree(log_filename);

	mlf->log_fp = log_fp;

	/* write first line (time, vm_id, client_ip, vm_ip) of log */
	{
		int ret;

		ret = fprintf(log_fp, "%ld,%u,", (long) mlf->create_time,
				(unsigned int) mlf->vm_id);
		if (ret < 0) {
			fclose(log_fp);
			free(mlf);

			return NULL;
		}

		for (int i = 0; i < 16; i++) {
			ret = fprintf(log_fp, "%02x", client_ip_addr[i]);
			if (ret < 0) {
				fclose(log_fp);
				free(mlf);

				return NULL;
			}
		}

		ret = fprintf(log_fp, ",");
		if (ret < 0) {
			fclose(log_fp);
			free(mlf);

			return NULL;
		}

		for (int i = 0; i < 16; i++) {
			ret = fprintf(log_fp, "%02x", vm_ip_addr[i]);
			if (ret < 0) {
				fclose(log_fp);
				free(mlf);

				return NULL;
			}
		}

		ret = fprintf(log_fp, "\n");
		if (ret < 0) {
			fclose(log_fp);
			free(mlf);

			return NULL;
		}

		ret = fflush(log_fp);
		if (ret != 0) {
			fclose(log_fp);
			free(mlf);

			return NULL;
		}
	}

	return mlf;
}

int my_logger_file_write(struct my_logger_file* logger_file,
		int is_direction_c2s, unsigned char message_type, size_t message_length,
		const unsigned char* message_data) {
	if (logger_file == NULL) {
		return -1;
	}
	if (message_length > 0 && message_data == NULL) {
		return -1;
	}

	char* direction = NULL;
	if (is_direction_c2s) {
		direction = "c2s";
	} else {
		direction = "s2c";
	}

	/* write (time, direction, message_type, message_length, message_data_hex) to log */
	int ret;
	ret = fprintf(logger_file->log_fp, "%ld,%s,%u,%zu,", (long) time(NULL),
			direction, message_type, message_length);
	if (ret < 0) {
		return -1;
	}

	for (size_t i = 0; i < message_length; i++) {
		ret = fprintf(logger_file->log_fp, "%02x", message_data[i]);
		if (ret < 0) {
			return -1;
		}
	}

	ret = fprintf(logger_file->log_fp, "\n");
	if (ret < 0) {
		return -1;
	}

	ret = fflush(logger_file->log_fp);
	if (ret != 0) {
		return -1;
	}

	return 0;
}

void my_logger_file_free(struct my_logger_file* logger_file) {
	if (logger_file == NULL) {
		return;
	}

	/* flush and close the log file */
	fflush(logger_file->log_fp);
	fclose(logger_file->log_fp);
	free(logger_file);
}
