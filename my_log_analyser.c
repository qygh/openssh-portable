/*
 * my_db_analyser.c
 *
 *  Created on: 15 Mar 2018
 *      Author: lqy
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <libpq-fe.h>

void print_ssh_message_type(unsigned char type);

int main(int argc, char* argv[]) {
	char* pq_conninfo = NULL;
	size_t session_id = 0;

	if (argc < 1) {
		fprintf(stderr, "Usage: <pq_conninfo> <session_id>\n");
		return 1;
	} else if (argc < 3) {
		fprintf(stderr, "Usage: %s <pq_conninfo> <session_id>\n", argv[0]);
		return 1;
	} else {
		pq_conninfo = argv[1];
		session_id = strtol(argv[2], NULL, 10);
	}

	/* connect to database */
	PGconn* conn = PQconnectdb(pq_conninfo);
	if (PQstatus(conn) != CONNECTION_OK) {
		fprintf(stderr, "PQconnectdb(): Connection to database failed: %s",
				PQerrorMessage(conn));
		PQfinish(conn);
		return 1;
	}

	/* session table */
	char session_qry[2048] = { 0 };
	snprintf(session_qry, sizeof(session_qry),
			"SELECT * FROM sessions WHERE session_id = %zu", session_id);
	PGresult *res = PQexec(conn, session_qry);
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

	putchar('\n');

	/* message table */
	//9225 9288
	char message_qry[2048] = { 0 };
	snprintf(message_qry, sizeof(message_qry),
			"SELECT * FROM messages WHERE session_id = %zu", session_id);
	res = PQexec(conn, message_qry);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		fprintf(stderr, "PQexec() failed: %s", PQerrorMessage(conn));
		PQclear(res);
		PQfinish(conn);
		return 1;
	}

	rows = PQntuples(res);
	for (int i = 0; i < rows; i++) {
		char* session_id = PQgetvalue(res, i, 0);
		char* session_date = PQgetvalue(res, i, 1);
		char* vm_id = PQgetvalue(res, i, 2);
		char* message_date = PQgetvalue(res, i, 3);
		char* c2s = PQgetvalue(res, i, 4);
		char* message_type = PQgetvalue(res, i, 5);
		char* message_length = PQgetvalue(res, i, 6);
		char* message = PQgetvalue(res, i, 7);
		size_t message_strlen = strlen(message);

		printf(
				"session_id: %s, session_date: %s, vm_id: %s,\nmessage_date: %s, c2s: %s, message_type: %s, message_length: %s,\nmessage: %s\n",
				session_id, session_date, vm_id, message_date, c2s,
				message_type, message_length, message);
		{
			unsigned char message_type_b = strtol(message_type, NULL, 10);
			print_ssh_message_type(message_type_b);

			size_t message_length_b = strtol(message_length, NULL, 10);
			if (message_length_b * 2 + 2 == message_strlen) {
				printf("\nprintable message:\n");
				putchar('\n');
				for (size_t i = 0; i < message_length_b; i++) {
					char s[3] = { message[2 + 2 * i], message[2 + 2 * i + 1],
							'\0' };
					char b = (char) strtol(s, NULL, 16);
					if (isprint(b)) {
						putchar(b);
					}
				}
				putchar('\n');
			}
		}
		putchar('\n');
		putchar('\n');
	}
	PQclear(res);

	PQfinish(conn);

	return 0;
}

void print_ssh_message_type(unsigned char type) {
	char* msg_type = NULL;

	switch (type) {
	case 0:
		msg_type = "SSH_MSG_NONE";
		break;
	case 1:
		msg_type = "SSH_MSG_DISCONNECT";
		break;
	case 2:
		msg_type = "SSH_MSG_IGNORE | SSH_SMSG_PUBLIC_KEY";
		break;
	case 3:
		msg_type = "SSH_MSG_UNIMPLEMENTED | SSH_CMSG_SESSION_KEY";
		break;
	case 4:
		msg_type = "SSH_MSG_DEBUG | SSH_CMSG_USER";
		break;
	case 5:
		msg_type = "SSH_MSG_SERVICE_REQUEST | SSH_CMSG_AUTH_RHOSTS";
		break;
	case 6:
		msg_type = "SSH_MSG_SERVICE_ACCEPT | SSH_CMSG_AUTH_RSA";
		break;
	case 7:
		msg_type = "SSH_SMSG_AUTH_RSA_CHALLENGE";
		break;
	case 8:
		msg_type = "SSH_CMSG_AUTH_RSA_RESPONSE";
		break;
	case 9:
		msg_type = "SSH_CMSG_AUTH_PASSWORD";
		break;
	case 10:
		msg_type = "SSH_CMSG_REQUEST_PTY";
		break;
	case 11:
		msg_type = "SSH_CMSG_WINDOW_SIZE";
		break;
	case 12:
		msg_type = "SSH_CMSG_EXEC_SHELL";
		break;
	case 13:
		msg_type = "SSH_CMSG_EXEC_CMD";
		break;
	case 14:
		msg_type = "SSH_SMSG_SUCCESS";
		break;
	case 15:
		msg_type = "SSH_SMSG_FAILURE";
		break;
	case 16:
		msg_type = "SSH_CMSG_STDIN_DATA";
		break;
	case 17:
		msg_type = "SSH_SMSG_STDOUT_DATA";
		break;
	case 18:
		msg_type = "SSH_SMSG_STDERR_DATA";
		break;
	case 19:
		msg_type = "SSH_CMSG_EOF";
		break;
	case 20:
		msg_type = "SSH_MSG_KEXINIT | SSH_SMSG_EXITSTATUS";
		break;
	case 21:
		msg_type = "SSH_MSG_NEWKEYS | SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
		break;
	case 22:
		msg_type = "SSH_MSG_CHANNEL_OPEN_FAILURE";
		break;
	case 23:
		msg_type = "SSH_MSG_CHANNEL_DATA";
		break;
	case 24:
		msg_type = "SSH_MSG_CHANNEL_CLOSE";
		break;
	case 25:
		msg_type = "SSH_MSG_CHANNEL_CLOSE_CONFIRMATION";
		break;
	case 26:
		msg_type = "SSH_CMSG_X11_REQUEST_FORWARDING";
		break;
	case 27:
		msg_type = "SSH_SMSG_X11_OPEN";
		break;
	case 28:
		msg_type = "SSH_CMSG_PORT_FORWARD_REQUEST";
		break;
	case 29:
		msg_type = "SSH_MSG_PORT_OPEN";
		break;
	case 30:
		msg_type = "SSH_CMSG_AGENT_REQUEST_FORWARDING";
		break;
	case 31:
		msg_type = "SSH_SMSG_AGENT_OPEN";
		break;
	case 32:
		msg_type = "SSH_MSG_IGNORE";
		break;
	case 33:
		msg_type = "SSH_CMSG_EXIT_CONFIRMATION";
		break;
	case 34:
		msg_type = "SSH_CMSG_X11_REQUEST_FORWARDING";
		break;
	case 35:
		msg_type = "SSH_CMSG_AUTH_RHOSTS_RSA";
		break;
	case 36:
		msg_type = "SSH_MSG_DEBUG";
		break;
	case 37:
		msg_type = "SSH_CMSG_REQUEST_COMPRESSION";
		break;
	case 38:
		msg_type = "SSH_CMSG_MAX_PACKET_SIZE";
		break;
	case 39:
		msg_type = "SSH_CMSG_AUTH_TIS";
		break;
	case 40:
		msg_type = "SSH_SMSG_AUTH_TIS_CHALLENGE";
		break;
	case 41:
		msg_type = "SSH_CMSG_AUTH_TIS_RESPONSE";
		break;
	case 42:
		msg_type = "SSH_CMSG_AUTH_KERBEROS";
		break;
	case 43:
		msg_type = "SSH_SMSG_AUTH_KERBEROS_RESPONSE";
		break;
	case 44:
		msg_type = "SSH_CMSG_HAVE_KERBEROS_TGT";
		break;
	case 50:
		msg_type = "SSH_MSG_USERAUTH_REQUEST";
		break;
	case 51:
		msg_type = "SSH_MSG_USERAUTH_FAILURE";
		break;
	case 52:
		msg_type = "SSH_MSG_USERAUTH_SUCCESS";
		break;
	case 53:
		msg_type = "SSH_MSG_USERAUTH_BANNER";
		break;
	case 65:
		msg_type = "SSH_CMSG_HAVE_AFS_TOKEN";
		break;
	case 80:
		msg_type = "SSH_MSG_GLOBAL_REQUEST";
		break;
	case 81:
		msg_type = "SSH_MSG_REQUEST_SUCCESS";
		break;
	case 82:
		msg_type = "SSH_MSG_REQUEST_FAILURE";
		break;
	case 90:
		msg_type = "SSH_MSG_CHANNEL_OPEN";
		break;
	case 91:
		msg_type = "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
		break;
	case 92:
		msg_type = "SSH_MSG_CHANNEL_OPEN_FAILURE";
		break;
	case 93:
		msg_type = "SSH_MSG_CHANNEL_WINDOW_ADJUST";
		break;
	case 94:
		msg_type = "SSH_MSG_CHANNEL_DATA";
		break;
	case 95:
		msg_type = "SSH_MSG_CHANNEL_EXTENDED_DATA";
		break;
	case 96:
		msg_type = "SSH_MSG_CHANNEL_EOF";
		break;
	case 97:
		msg_type = "SSH_MSG_CHANNEL_CLOSE";
		break;
	case 98:
		msg_type = "SSH_MSG_CHANNEL_REQUEST";
		break;
	case 99:
		msg_type = "SSH_MSG_CHANNEL_SUCCESS";
		break;
	case 100:
		msg_type = "SSH_MSG_CHANNEL_FAILURE";
		break;
	default:
		msg_type = "SSH message type unknown";
		break;
	}

	printf("message type is %u: %s\n", type, msg_type);
}
