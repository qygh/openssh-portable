/*
 * my_logger_pqsql.c
 *
 *  Created on: 15 Feb 2018
 *      Author: lqy
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libpq-fe.h>

struct my_logger_pqsql {

};

int main(int argc, char* argv[]) {
	const char* conninfo = NULL;

	if (argc > 1) {
		conninfo = argv[1];
	} else {
		conninfo = "dbname = postgres";
	}

	PGconn* conn = PQconnectdb(conninfo);
	PGresult* res;

	if (PQstatus(conn) != CONNECTION_OK) {
		fprintf(stderr, "Connection to database failed: %s",
				PQerrorMessage(conn));
		PQfinish(conn);
		return 1;
	}

	PQfinish(conn);
	return 0;
}

struct my_logger_file* my_logger_pqsql_new(const char* prefix, uint32_t vm_id,
		const uint8_t client_ip_addr[16], const uint8_t vm_ip_addr[16]) {
	return NULL;
}

int my_logger_pqsql_write(struct my_logger_pqsql* logger_pqsql,
		int is_direction_c2s, unsigned char message_type, size_t message_length,
		const unsigned char* message_data) {
	return -1;
}

void my_logger_file_free(struct my_logger_file* logger_file) {

}
