#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "build_server.h"
#include "inspection.h"
#include "signature_fragment.h"
#include "reversible_sketch.h"
#include "rule.h"
#include "memory_pool.h"
#include "client_user_token.h"
#include "list.h"

#define TOKENS_IN_ONE_PACKET 70

void handle_client(struct reversible_sketch * rs,  int client_socket_fd){
	struct client_user_token received_tokens[BATCH_SIZE * 2];
	struct client_user_token file_end_token;
	memset(&file_end_token, 0, sizeof(struct client_user_token));
	char buffer[TOKENS_IN_ONE_PACKET * sizeof(struct client_user_token)];

	int count = 0;
	int bytes_received = 0;
	uint32_t matched_tokens_count = 0;
	uint32_t unmatched_tokens_count = 0;
	while(1){
		count = recv(client_socket_fd, buffer, TOKENS_IN_ONE_PACKET * sizeof(struct client_user_token), 0);
		if(count <= 0){
			// connection may be closed
			break;
		} else {
			char * ptr = (char *) received_tokens;
			memcpy(ptr + bytes_received, buffer, count);
			bytes_received += count;
			if(bytes_received % sizeof(struct client_user_token) == 0){
				int tokens_received = bytes_received / sizeof(struct client_user_token);
				if(memcmp(&file_end_token, &(received_tokens[tokens_received - 1]), sizeof(struct client_user_token)) == 0){
					// end of a file
					//batch_inspection(received_tokens, tokens_received - 1, rs, pool, &matched_rules_list);
					// lookup the tokens
					int i;
					for(i = 0;i < tokens_received - 1;i++){
						struct list_node * node = lookup_encrypted_token(rs, received_tokens[i].token);
						if(node){
							matched_tokens_count++;
						} else {
							unmatched_tokens_count++;
						}
					}

					matched_tokens_count = htonl(matched_tokens_count);
					unmatched_tokens_count = htonl(unmatched_tokens_count);
					write(client_socket_fd, &matched_tokens_count, sizeof(uint32_t));
					write(client_socket_fd, &unmatched_tokens_count, sizeof(uint32_t));

					count = 0;
					bytes_received = 0;
					matched_tokens_count = 0;
					unmatched_tokens_count = 0;
				}
			} else if(bytes_received > BATCH_SIZE * sizeof(struct client_user_token)){
				int i = 0;
				for(i = 0;i < BATCH_SIZE;i++){
					received_tokens[i].offset = htonl(received_tokens[i].offset);
				}
				// lookup the tokens
				for(i = 0;i < BATCH_SIZE;i++){
					struct list_node * node = lookup_encrypted_token(rs, received_tokens[i].token);
					if(node){
						matched_tokens_count++;
					} else {
						unmatched_tokens_count++;
					}
				}
				char * ptr = (char *) received_tokens;
				memcpy(ptr, ptr + BATCH_SIZE * sizeof(struct client_user_token), bytes_received - BATCH_SIZE * sizeof(struct client_user_token));
				bytes_received -= BATCH_SIZE * sizeof(struct client_user_token);
			}
		}
	}
}

int main(int argc, char ** args){
	if(argc != 3){
		fprintf(stderr, "usage: %s rules_file_name port\n", args[0]);
		return 0;
	}

	// build reversible sketch from file
	struct memory_pool pool;
	initialize_memory_pool(&pool);
	fprintf(stderr, "initialized memory_pool\n");

	struct double_list rules_list;
	initialize_double_list(&rules_list);
	struct reversible_sketch rs;
	initialize_reversible_sketch(&rs);
	fprintf(stderr, "reversible sketch initialized\n");
	//print_reversible_sketch(&rs);

	//uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	SHA256_CTX ctx;
	fprintf(stderr, "before read_rules_from_file\n");
	int number_of_rules = read_rules_from_file(args[1], &rs, &rules_list, NULL, &ctx, &pool);
	fprintf(stderr, "after read_rules_from_file\n");

	// create server socket
	int server_socket_fd;
	int client_socket_fd;
	struct sockaddr_in server_address;
	struct sockaddr_in client_address;
	unsigned int server_port = atoi(args[2]);
	if((server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		fprintf(stderr, "create server socket failed\n");
		return 0;
	} else {
		fprintf(stderr, "created server socket\n");
	}
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(server_port);
	// bind to the local address
	if(bind(server_socket_fd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0){
		fprintf(stderr, "bind server socket failed\n");
		return 0;
	} else {
		fprintf(stderr, "binded server socket\n");
	}
	// listen for the incoming connection
	if(listen(server_socket_fd, 10) < 0){
		fprintf(stderr, "listen server socket failed\n");
		return 0;
	}

	while(1){
		// wait for the client to connect
		unsigned int client_address_len = sizeof(client_address);
		if((client_socket_fd = accept(server_socket_fd, (struct sockaddr *) &client_address, &client_address_len)) < 0){
			fprintf(stderr, "accept client connection failed\n");
			return 0;
		}
		fprintf(stderr, "accepted client connection\n");

		handle_client(&rs, client_socket_fd);
	}
	return 0;
}
