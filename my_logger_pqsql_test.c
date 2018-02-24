/*
 * my_logger_pqsql_test.c
 *
 *  Created on: 24 Feb 2018
 *      Author: lqy
 */

#include "my_logger_pqsql.h"

int main(int argc, char* argv[]) {
	const char* conninfo = NULL;

	if (argc > 1) {
		conninfo = argv[1];
	} else {
		conninfo = "dbname = postgres";
	}

	uint32_t vm_id = 500;
	char c_ip[16] = { 0 };
	char v_ip[16] = { 0 };
	c_ip[0] = 1;
	v_ip[10] = 2;

	struct my_logger_pqsql* mlp = my_logger_pqsql_new(conninfo, vm_id, c_ip,
			v_ip);
	if (mlp == NULL) {
		fprintf(stderr, "my_logger_pqsql_new() failed\n");
		return 1;
	}

	char data[5] = { 1, 2, 3, 4, 5 };
	int ret = my_logger_pqsql_write(mlp, 1, 3, 3, data);
	if (ret < 0) {
		fprintf(stderr, "my_logger_pqsql_write() failed\n");

		my_logger_pqsql_free(mlp);
		return 1;
	}

	ret = my_logger_pqsql_write(mlp, 0, 9, 5, data);
	if (ret < 0) {
		fprintf(stderr, "my_logger_pqsql_write() failed\n");

		my_logger_pqsql_free(mlp);
		return 1;
	}

	ret = my_logger_pqsql_write(mlp, 1, 27, 0, data);
	if (ret < 0) {
		fprintf(stderr, "my_logger_pqsql_write() failed\n");

		my_logger_pqsql_free(mlp);
		return 1;
	}

	ret = my_logger_pqsql_write(mlp, 1, 81, 0, NULL);
	if (ret < 0) {
		fprintf(stderr, "my_logger_pqsql_write() failed\n");

		my_logger_pqsql_free(mlp);
		return 1;
	}

	ret = my_logger_pqsql_set_login_success(mlp);
	if (ret < 0) {
		fprintf(stderr, "my_logger_pqsql_set_login_success() failed\n");

		my_logger_pqsql_free(mlp);
		return 1;
	}

	ret = my_logger_pqsql_update_end_time(mlp);
	if (ret < 0) {
		fprintf(stderr, "my_logger_pqsql_update_end_time() failed\n");

		my_logger_pqsql_free(mlp);
		return 1;
	}

	my_logger_pqsql_free(mlp);
	return 0;
}
