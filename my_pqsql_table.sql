CREATE TABLE sessions ( 
	session_id BIGSERIAL, 
	start_time TIMESTAMP NOT NULL, 
	vm_id      INT NOT NULL, 
	client_ip  INET NOT NULL, 
	vm_ip      INET NOT NULL, 
	end_time   TIMESTAMP NOT NULL, 
	success    BOOLEAN NOT NULL, 
	CONSTRAINT prok PRIMARY KEY(session_id) 
); 

CREATE TABLE messages ( 
	session_id     BIGINT NOT NULL, 
	start_time     TIMESTAMP NOT NULL, 
	vm_id          INT NOT NULL, 
	time           TIMESTAMP NOT NULL, 
	direction_c2s  BOOLEAN NOT NULL, 
	message_type   SMALLINT NOT NULL, 
	message_length BIGINT NOT NULL, 
	message_data   BYTEA NOT NULL, 
	CONSTRAINT fork FOREIGN KEY(session_id) REFERENCES sessions(session_id) 
);
