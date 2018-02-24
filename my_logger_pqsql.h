/*
 * my_logger_pqsql.h
 *
 *  Created on: 24 Feb 2018
 *      Author: lqy
 */

#ifndef MY_LOGGER_PQSQL_H_
#define MY_LOGGER_PQSQL_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <libpq-fe.h>

struct my_logger_pqsql {
	uint32_t vm_id;
	uint32_t vm_id_netord;
	time_t create_time;
	char create_time_text[50];
	PGconn* pq_conn;
	int64_t session_id_netord;
};

struct my_logger_pqsql* my_logger_pqsql_new(const char* pq_conninfo,
		uint32_t vm_id, const uint8_t client_ip_addr[16],
		const uint8_t vm_ip_addr[16]);

int my_logger_pqsql_write(struct my_logger_pqsql* logger_pqsql,
		int is_direction_c2s, unsigned char message_type, size_t message_length,
		const unsigned char* message_data);

int my_logger_pqsql_set_login_success(struct my_logger_pqsql* logger_pqsql);

int my_logger_pqsql_update_end_time(struct my_logger_pqsql* logger_pqsql);

void my_logger_pqsql_free(struct my_logger_pqsql* logger_pqsql);

#endif /* MY_LOGGER_PQSQL_H_ */
