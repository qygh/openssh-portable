/*
 * my_logger_pqsql.c
 *
 *  Created on: 15 Feb 2018
 *      Author: lqy
 */

#include "my_logger_pqsql.h"

struct my_logger_pqsql* my_logger_pqsql_new(const char* pq_conninfo,
		uint32_t vm_id, const uint8_t client_ip_addr[16],
		const uint8_t vm_ip_addr[16]) {
	if (pq_conninfo == NULL || client_ip_addr == NULL || vm_ip_addr == NULL) {
		return NULL;
	}

	struct my_logger_pqsql* mlp = malloc(sizeof(struct my_logger_pqsql));
	if (mlp == NULL) {
		return NULL;
	}

	mlp->vm_id = vm_id;
	mlp->vm_id_netord = htonl(mlp->vm_id);
	mlp->create_time = time(NULL);
	snprintf(mlp->create_time_text, sizeof(mlp->create_time_text), "%ld",
			(long) (mlp->create_time));

	/* connect to database */
	PGconn* conn = PQconnectdb(pq_conninfo);
	if (PQstatus(conn) != CONNECTION_OK) {
		fprintf(stderr,
				"my_logger_pqsql_new(): Connection to database failed: %s",
				PQerrorMessage(conn));
		PQfinish(conn);
		free(mlp);

		return NULL;
	}

	mlp->pq_conn = conn;

	/* insert into session table */
	{
		char* query =
				"INSERT INTO sessions (start_time, vm_id, client_ip, vm_ip, end_time, success)" " "
						"VALUES (to_timestamp($1), $2, $3, $4, to_timestamp($1), false) RETURNING session_id";

		int n_params = 4;
		const char* values[n_params];
		int lengths[n_params];
		int formats[n_params];

		values[0] = mlp->create_time_text;
		lengths[0] = 0;
		formats[0] = 0;

		values[1] = (char*) &(mlp->vm_id_netord);
		lengths[1] = sizeof(mlp->vm_id_netord);
		formats[1] = 1;

		char c_ip_text[INET6_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET6, client_ip_addr, c_ip_text, sizeof(c_ip_text));
		values[2] = c_ip_text;
		lengths[2] = 0;
		formats[2] = 0;

		char v_ip_text[INET6_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET6, vm_ip_addr, v_ip_text, sizeof(v_ip_text));
		values[3] = v_ip_text;
		lengths[3] = 0;
		formats[3] = 0;

		PGresult* res = PQexecParams(mlp->pq_conn, query, n_params, NULL,
				values, lengths, formats, 1);
		if (PQresultStatus(res) != PGRES_TUPLES_OK) {
			fprintf(stderr, "my_logger_pqsql_new(): PQexecParams() failed: %s",
					PQerrorMessage(conn));
			PQclear(res);
			PQfinish(conn);
			free(mlp);

			return NULL;
		}

		/* get session_id */
		int64_t* session_id = (int64_t*) PQgetvalue(res, 0, 0);
		if (session_id == NULL) {
			fprintf(stderr, "my_logger_pqsql_new(): PQgetvalue() failed\n");
			PQclear(res);
			PQfinish(conn);
			free(mlp);

			return NULL;
		}
		mlp->session_id_netord = *session_id;

		PQclear(res);
	}

	return mlp;
}

int my_logger_pqsql_write(struct my_logger_pqsql* logger_pqsql,
		int is_direction_c2s, unsigned char message_type, size_t message_length,
		const unsigned char* message_data) {
	if (logger_pqsql == NULL || (message_length > 0 && message_data == NULL)) {
		return -1;
	}

	char zero = 0;
	if (message_length == 0 && message_data == NULL) {
		message_data = &zero;
	}

	/* insert into message table */
	{
		char* query =
				"INSERT INTO messages (session_id, start_time, vm_id, time, direction_c2s, message_type, message_length, message_data)" " "
						"VALUES ($1, to_timestamp($2), $3, to_timestamp($4), $5, $6, $7, $8)";

		int n_params = 8;
		const char* values[n_params];
		int lengths[n_params];
		int formats[n_params];

		values[0] = (char*) &(logger_pqsql->session_id_netord);
		lengths[0] = sizeof(logger_pqsql->session_id_netord);
		formats[0] = 1;

		values[1] = logger_pqsql->create_time_text;
		lengths[1] = 0;
		formats[1] = 0;

		values[2] = (char*) &(logger_pqsql->vm_id_netord);
		lengths[2] = sizeof(logger_pqsql->vm_id_netord);
		formats[2] = 1;

		char time_text[50];
		snprintf(time_text, sizeof(time_text), "%ld", (long) time(NULL));
		values[3] = time_text;
		lengths[3] = 0;
		formats[3] = 0;

		char* c2s = NULL;
		if (is_direction_c2s) {
			c2s = "true";
		} else {
			c2s = "false";
		}
		values[4] = c2s;
		lengths[4] = 0;
		formats[4] = 0;

		uint16_t msg_type = htons(message_type);
		values[5] = (char*) &msg_type;
		lengths[5] = sizeof(msg_type);
		formats[5] = 1;

		char len[50];
		snprintf(len, sizeof(len), "%zu", message_length);
		values[6] = len;
		lengths[6] = 0;
		formats[6] = 0;

		values[7] = message_data;
		lengths[7] = message_length;
		formats[7] = 1;

		PGresult* res = PQexecParams(logger_pqsql->pq_conn, query, n_params,
		NULL, values, lengths, formats, 0);
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			fprintf(stderr,
					"my_logger_pqsql_write(): PQexecParams() failed: %s",
					PQerrorMessage(logger_pqsql->pq_conn));
			PQclear(res);

			return -1;
		}
		PQclear(res);
	}

	return 0;
}

int my_logger_pqsql_set_login_success(struct my_logger_pqsql* logger_pqsql) {
	if (logger_pqsql == NULL) {
		return -1;
	}

	/* update 'success' in session table */
	{
		char* query = "UPDATE sessions SET success = true" " "
				"WHERE session_id = $1";

		int n_params = 1;
		const char* values[n_params];
		int lengths[n_params];
		int formats[n_params];

		values[0] = (char*) &(logger_pqsql->session_id_netord);
		lengths[0] = sizeof(logger_pqsql->session_id_netord);
		formats[0] = 1;

		PGresult* res = PQexecParams(logger_pqsql->pq_conn, query, n_params,
		NULL, values, lengths, formats, 0);
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			fprintf(stderr,
					"my_logger_pqsql_set_login_success(): PQexecParams() failed: %s",
					PQerrorMessage(logger_pqsql->pq_conn));
			PQclear(res);

			return -1;
		}
		PQclear(res);
	}

	return 0;
}

int my_logger_pqsql_update_end_time(struct my_logger_pqsql* logger_pqsql) {
	if (logger_pqsql == NULL) {
		return -1;
	}

	/* update 'end_time' in session table */
	{
		char* query = "UPDATE sessions SET end_time = to_timestamp($1)" " "
				"WHERE session_id = $2";

		int n_params = 2;
		const char* values[n_params];
		int lengths[n_params];
		int formats[n_params];

		char time_text[50];
		snprintf(time_text, sizeof(time_text), "%ld", (long) time(NULL));
		values[0] = time_text;
		lengths[0] = 0;
		formats[0] = 0;

		values[1] = (char*) &(logger_pqsql->session_id_netord);
		lengths[1] = sizeof(logger_pqsql->session_id_netord);
		formats[1] = 1;

		PGresult* res = PQexecParams(logger_pqsql->pq_conn, query, n_params,
		NULL, values, lengths, formats, 0);
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			fprintf(stderr,
					"my_logger_pqsql_update_end_time(): PQexecParams() failed: %s",
					PQerrorMessage(logger_pqsql->pq_conn));
			PQclear(res);

			return -1;
		}
		PQclear(res);
	}

	return 0;
}

void my_logger_pqsql_free(struct my_logger_pqsql* logger_pqsql) {
	if (logger_pqsql == NULL) {
		return;
	}

	PQfinish(logger_pqsql->pq_conn);
	free(logger_pqsql);
}
