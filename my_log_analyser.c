/*
 * my_db_analyser.c
 *
 *  Created on: 15 Mar 2018
 *      Author: lqy
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <libpq-fe.h>

int main(int argc, char* argv[]) {
	char* pq_conninfo = NULL;

	if (argc < 1) {
		fprintf(stderr, "Usage: <pq_conninfo>\n");
		return 1;
	} else if (argc < 2) {
		fprintf(stderr, "Usage: %s <pq_conninfo>\n", argv[0]);
		return 1;
	} else {
		pq_conninfo = argv[1];
	}

	/* connect to database */
	PGconn* conn = PQconnectdb(pq_conninfo);
	if (PQstatus(conn) != CONNECTION_OK) {
		fprintf(stderr, "PQconnectdb(): Connection to database failed: %s",
				PQerrorMessage(conn));
		PQfinish(conn);
		return 1;
	}

	PGresult *res = PQexec(conn, "SELECT * FROM sessions");
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		fprintf(stderr, "PQexec() failed: %s", PQerrorMessage(conn));
		PQclear(res);
		PQfinish(conn);
		return 1;
	}

	int rows = PQntuples(res);
	for (int i = 0; i < rows; i++) {
		printf("%s %s %s %s %s %s %s\n", PQgetvalue(res, i, 0),
				PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
				PQgetvalue(res, i, 3), PQgetvalue(res, i, 4),
				PQgetvalue(res, i, 5), PQgetvalue(res, i, 6));
	}

	PQclear(res);
	PQfinish(conn);

	return 0;
}
